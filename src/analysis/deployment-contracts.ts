import path from 'node:path';
import ts from 'typescript';
import type {
  AnalysisFile,
  DiagnosticRecord,
  EvidenceReference,
  FindingRecord,
  SourceLocation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { boundedTypeScriptDiagnosticMessage, parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';

export const DEPLOYMENT_CONTRACT_ANALYSIS_VERSION = '1.3.0';

const PRODUCER = 'atlas/deployment-contracts';
const JAVASCRIPT_LANGUAGES = new Set(['javascript', 'javascript-jsx', 'typescript', 'typescript-tsx']);
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const TERRAFORM_NAME = /^[A-Za-z_][A-Za-z0-9_-]*$/u;
export const MAX_DEPLOYMENT_CONTRACT_OBSERVATIONS = 25_000;
export const MAX_DEPLOYMENT_VARIANT_EVIDENCE = 64;
const DOCKER_AUTOMATIC_ARGUMENTS = new Set([
  'BUILDPLATFORM',
  'BUILDOS',
  'BUILDARCH',
  'BUILDVARIANT',
  'TARGETPLATFORM',
  'TARGETOS',
  'TARGETARCH',
  'TARGETVARIANT'
]);

type ContractNamespace = 'environment' | 'terraform-variable';
type ObservationRole = 'declaration' | 'consumer';
type SourceKind =
  | 'javascript-process-env'
  | 'javascript-import-meta-env'
  | 'dotenv-example'
  | 'docker-arg'
  | 'docker-env'
  | 'docker-reference'
  | 'compose-environment'
  | 'compose-interpolation'
  | 'workflow-env'
  | 'workflow-env-reference'
  | 'terraform-variable'
  | 'terraform-var-reference';

interface Anchor {
  file: AnalysisFile;
  location: SourceLocation;
}

interface Observation extends Anchor {
  namespace: ContractNamespace;
  role: ObservationRole;
  name: string;
  sourceKind: SourceKind;
}

interface AnalysisState {
  observations: Observation[];
  diagnostics: DiagnosticRecord[];
  uncertainNamespaces: Set<ContractNamespace>;
  observationLimitReached: boolean;
}

interface SourceLine {
  text: string;
  start: number;
  end: number;
}

interface ShellWord {
  text: string;
  start: number;
  end: number;
}

function scriptKind(filePath: string): ts.ScriptKind {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (lower.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (lower.endsWith('.ts') || lower.endsWith('.mts') || lower.endsWith('.cts')) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

interface SourceContext {
  source: string;
  lineStarts: number[];
  lines?: SourceLine[];
}

const SOURCE_CONTEXTS = new WeakMap<AnalysisFile, SourceContext>();

function sourceContext(file: AnalysisFile): SourceContext {
  const cached = SOURCE_CONTEXTS.get(file);
  if (cached) return cached;
  const source = file.content.toString('utf8');
  const lineStarts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) lineStarts.push(index + 1);
  }
  const context = { source, lineStarts };
  SOURCE_CONTEXTS.set(file, context);
  return context;
}

function lineAndColumn(context: SourceContext, offset: number): { line: number; column: number } {
  const bounded = Math.min(Math.max(offset, 0), context.source.length);
  let low = 0;
  let high = context.lineStarts.length;
  while (low + 1 < high) {
    const middle = Math.floor((low + high) / 2);
    if (context.lineStarts[middle]! <= bounded) low = middle;
    else high = middle;
  }
  return { line: low + 1, column: bounded - context.lineStarts[low]! + 1 };
}

function anchorAt(file: AnalysisFile, start: number, end: number): Anchor {
  const context = sourceContext(file);
  const beginning = lineAndColumn(context, start);
  const finish = lineAndColumn(context, Math.max(start + 1, end));
  return {
    file,
    location: {
      line: beginning.line,
      column: beginning.column,
      endLine: finish.line,
      endColumn: finish.column
    }
  };
}

function sourceLines(source: string): SourceLine[] {
  const lines: SourceLine[] = [];
  let start = 0;
  for (let index = 0; index <= source.length; index += 1) {
    if (index !== source.length && source[index] !== '\n') continue;
    if (index === source.length && start === source.length && source.endsWith('\n')) break;
    const rawEnd = index > start && source[index - 1] === '\r' ? index - 1 : index;
    lines.push({ text: source.slice(start, rawEnd), start, end: rawEnd });
    start = index + 1;
  }
  return lines;
}

function sourceLinesForFile(file: AnalysisFile): SourceLine[] {
  const context = sourceContext(file);
  context.lines ??= sourceLines(context.source);
  return context.lines;
}

function evidence(observation: Anchor & { sourceKind?: SourceKind }, basis?: string): EvidenceReference {
  return {
    level: 2,
    producer: PRODUCER,
    producerVersion: DEPLOYMENT_CONTRACT_ANALYSIS_VERSION,
    basis: basis ?? observation.sourceKind ?? 'syntax-only-deployment-contract-evidence',
    path: observation.file.record.path,
    line: observation.location.line,
    column: observation.location.column,
    recordIds: [observation.file.record.id]
  };
}

function addDiagnostic(
  state: AnalysisState,
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  anchor: Anchor,
  basis: string,
  uncertainNamespace?: ContractNamespace
): void {
  if (uncertainNamespace) state.uncertainNamespaces.add(uncertainNamespace);
  state.diagnostics.push({
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({
      producer: PRODUCER,
      version: DEPLOYMENT_CONTRACT_ANALYSIS_VERSION,
      code,
      path: anchor.file.record.path,
      location: anchor.location
    })).slice(0, 24)}`,
    code,
    severity,
    message,
    path: anchor.file.record.path,
    location: anchor.location,
    evidence: evidence(anchor, basis)
  });
}

function addObservation(
  state: AnalysisState,
  file: AnalysisFile,
  namespace: ContractNamespace,
  role: ObservationRole,
  nameValue: string,
  sourceKind: SourceKind,
  start: number,
  end: number
): void {
  const name = nameValue.normalize('NFC');
  const valid = namespace === 'environment' ? ENVIRONMENT_NAME.test(name) : TERRAFORM_NAME.test(name);
  if (!valid) {
    addDiagnostic(
      state,
      namespace === 'environment'
        ? 'DEPLOYMENT_CONTRACT_UNSUPPORTED_ENVIRONMENT_NAME'
        : 'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_NAME',
      'warning',
      namespace === 'environment'
        ? 'A deployment environment name is outside the supported portable identifier subset; related mismatch claims were suppressed.'
        : 'A Terraform variable name is outside the supported portable identifier subset; related mismatch claims were suppressed.',
      anchorAt(file, start, end),
      'unsupported-contract-name',
      namespace
    );
    return;
  }
  if (state.observations.length >= MAX_DEPLOYMENT_CONTRACT_OBSERVATIONS) {
    if (!state.observationLimitReached) {
      state.observationLimitReached = true;
      state.uncertainNamespaces.add('environment');
      state.uncertainNamespaces.add('terraform-variable');
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_RESOURCE_LIMIT',
        'warning',
        `Deployment-contract extraction exceeded the ${MAX_DEPLOYMENT_CONTRACT_OBSERVATIONS}-observation limit; mismatch findings were suppressed.`,
        anchorAt(file, start, end),
        'deployment-contract-observation-limit'
      );
    }
    return;
  }
  state.observations.push({
    ...anchorAt(file, start, end),
    namespace,
    role,
    name,
    sourceKind
  });
}

function isProcessEnv(node: ts.Node): node is ts.PropertyAccessExpression {
  return ts.isPropertyAccessExpression(node) &&
    node.name.text === 'env' &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'process';
}

function isImportMetaEnv(node: ts.Node): node is ts.PropertyAccessExpression {
  return ts.isPropertyAccessExpression(node) &&
    node.name.text === 'env' &&
    ts.isMetaProperty(node.expression) &&
    node.expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
    node.expression.name.text === 'meta';
}

function parseJavaScript(file: AnalysisFile, state: AnalysisState): void {
  const source = sourceContext(file).source;
  const parsedSource = parseBoundedTypeScript(
    file.record.path,
    source,
    scriptKind(file.record.path)
  );
  if (parsedSource.state === 'rejected') {
    addDiagnostic(
      state,
      'DEPLOYMENT_CONTRACT_UNSUPPORTED_JAVASCRIPT_SYNTAX',
      'warning',
      boundedTypeScriptDiagnosticMessage(parsedSource.reason),
      {
        file,
        location: { line: 1, column: 1, endLine: 1, endColumn: 1 }
      },
      'typescript-ast-resource-limit',
      'environment'
    );
    return;
  }
  const sourceFile = parsedSource.sourceFile;
  const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.DiagnosticWithLocation[] }).parseDiagnostics ?? [];
  if (parseDiagnostics.length > 0) {
    const first = parseDiagnostics[0]!;
    const start = first.start ?? 0;
    addDiagnostic(
      state,
      'DEPLOYMENT_CONTRACT_UNSUPPORTED_JAVASCRIPT_SYNTAX',
      'warning',
      'JavaScript or TypeScript syntax could not be parsed completely; environment mismatch claims were suppressed.',
      anchorAt(file, start, start + Math.max(first.length ?? 1, 1)),
      'typescript-parser-diagnostic',
      'environment'
    );
  }

  function visit(node: ts.Node): void {
    if (ts.isPropertyAccessExpression(node) && isProcessEnv(node.expression)) {
      addObservation(
        state,
        file,
        'environment',
        'consumer',
        node.name.text,
        'javascript-process-env',
        node.name.getStart(sourceFile),
        node.name.getEnd()
      );
      return;
    }
    if (ts.isElementAccessExpression(node) && isProcessEnv(node.expression)) {
      const argument = node.argumentExpression;
      if (argument && ts.isStringLiteralLike(argument)) {
        addObservation(
          state,
          file,
          'environment',
          'consumer',
          argument.text,
          'javascript-process-env',
          argument.getStart(sourceFile) + 1,
          Math.max(argument.getStart(sourceFile) + 2, argument.getEnd() - 1)
        );
      } else {
        const anchor = argument ?? node;
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_DYNAMIC_ENV_ACCESS',
          'warning',
          'A computed process.env access may refer to any environment name; environment mismatch claims were suppressed.',
          anchorAt(file, anchor.getStart(sourceFile), anchor.getEnd()),
          'computed-process-env-access',
          'environment'
        );
        if (argument) visit(argument);
      }
      return;
    }
    if (isProcessEnv(node)) {
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_DYNAMIC_ENV_ACCESS',
        'warning',
        'A whole-object process.env access may refer to any environment name; environment mismatch claims were suppressed.',
        anchorAt(file, node.getStart(sourceFile), node.getEnd()),
        'whole-process-env-access',
        'environment'
      );
      return;
    }
    if (ts.isPropertyAccessExpression(node) && isImportMetaEnv(node.expression)) {
      addObservation(
        state,
        file,
        'environment',
        'consumer',
        node.name.text,
        'javascript-import-meta-env',
        node.name.getStart(sourceFile),
        node.name.getEnd()
      );
      return;
    }
    if (ts.isElementAccessExpression(node) && isImportMetaEnv(node.expression)) {
      const argument = node.argumentExpression;
      if (argument && ts.isStringLiteralLike(argument)) {
        addObservation(
          state,
          file,
          'environment',
          'consumer',
          argument.text,
          'javascript-import-meta-env',
          argument.getStart(sourceFile) + 1,
          Math.max(argument.getStart(sourceFile) + 2, argument.getEnd() - 1)
        );
      } else {
        const anchor = argument ?? node;
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_DYNAMIC_IMPORT_META_ENV_ACCESS',
          'warning',
          'A computed import.meta.env access may refer to any environment name; environment mismatch claims were suppressed.',
          anchorAt(file, anchor.getStart(sourceFile), anchor.getEnd()),
          'computed-import-meta-env-access',
          'environment'
        );
        if (argument) visit(argument);
      }
      return;
    }
    if (isImportMetaEnv(node)) {
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_DYNAMIC_IMPORT_META_ENV_ACCESS',
        'warning',
        'A whole-object import.meta.env access may refer to any environment name; environment mismatch claims were suppressed.',
        anchorAt(file, node.getStart(sourceFile), node.getEnd()),
        'whole-import-meta-env-access',
        'environment'
      );
      return;
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
}

function quoteClosed(value: string, quote: string): boolean {
  let escaped = false;
  for (let index = 1; index < value.length; index += 1) {
    const current = value[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (current === '\\') {
      escaped = true;
      continue;
    }
    if (current === quote) return true;
  }
  return false;
}

function parseDotenv(file: AnalysisFile, state: AnalysisState): void {
  const source = file.content.toString('utf8');
  let multilineQuote: string | undefined;
  for (const line of sourceLinesForFile(file)) {
    if (multilineQuote) {
      if (quoteClosed(`${multilineQuote}${line.text}`, multilineQuote)) multilineQuote = undefined;
      continue;
    }
    const trimmed = line.text.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const declaration = line.text.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/u);
    if (!declaration || declaration[1] === undefined || declaration.index === undefined) {
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOTENV_SYNTAX',
        'warning',
        'An environment example line does not use a supported literal NAME=value declaration; environment mismatch claims were suppressed.',
        anchorAt(file, line.start, Math.max(line.start + 1, line.end)),
        'unsupported-dotenv-declaration',
        'environment'
      );
      continue;
    }
    const nameOffset = line.text.indexOf(declaration[1], declaration.index);
    addObservation(
      state,
      file,
      'environment',
      'declaration',
      declaration[1],
      'dotenv-example',
      line.start + nameOffset,
      line.start + nameOffset + declaration[1].length
    );
    const equals = line.text.indexOf('=', nameOffset + declaration[1].length);
    const value = line.text.slice(equals + 1).trimStart();
    if ((value.startsWith('"') || value.startsWith("'")) && !quoteClosed(value, value[0]!)) {
      multilineQuote = value[0];
    }
  }
  if (multilineQuote) {
    addDiagnostic(
      state,
      'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOTENV_SYNTAX',
      'warning',
      'An environment example contains an unterminated quoted value; environment mismatch claims were suppressed.',
      anchorAt(file, Math.max(0, source.length - 1), source.length),
      'unterminated-dotenv-value',
      'environment'
    );
  }
}

function shellWords(value: string): ShellWord[] | undefined {
  const words: ShellWord[] = [];
  let index = 0;
  while (index < value.length) {
    while (index < value.length && /\s/u.test(value[index]!)) index += 1;
    if (index >= value.length) break;
    const start = index;
    let text = '';
    let quote: string | undefined;
    let escaped = false;
    while (index < value.length) {
      const current = value[index]!;
      if (escaped) {
        text += current;
        escaped = false;
        index += 1;
        continue;
      }
      if (current === '\\') {
        escaped = true;
        index += 1;
        continue;
      }
      if (quote) {
        if (current === quote) quote = undefined;
        else text += current;
        index += 1;
        continue;
      }
      if (current === '"' || current === "'") {
        quote = current;
        index += 1;
        continue;
      }
      if (/\s/u.test(current)) break;
      text += current;
      index += 1;
    }
    if (escaped || quote) return undefined;
    words.push({ text, start, end: index });
  }
  return words;
}

function dockerLogicalLines(source: string): Array<{ text: string; offsets: number[]; start: number; end: number }> | undefined {
  const lines = sourceLines(source);
  const firstContent = lines.find((line) => line.text.trim().length > 0);
  if (firstContent && /^#\s*escape\s*=/iu.test(firstContent.text) && !/^#\s*escape\s*=\s*\\\s*$/iu.test(firstContent.text)) {
    return undefined;
  }
  const logical: Array<{ text: string; offsets: number[]; start: number; end: number }> = [];
  let text = '';
  let offsets: number[] = [];
  let start = 0;
  for (const line of lines) {
    if (!text && /^\s*#/u.test(line.text)) continue;
    if (!text) start = line.start;
    const continuation = /\\\s*$/u.exec(line.text);
    const retainedEnd = continuation?.index ?? line.text.length;
    for (let index = 0; index < retainedEnd; index += 1) {
      text += line.text[index]!;
      offsets.push(line.start + index);
    }
    if (continuation) {
      text += ' ';
      offsets.push(line.start + retainedEnd);
      continue;
    }
    if (text.trim()) logical.push({ text, offsets, start, end: line.end });
    text = '';
    offsets = [];
  }
  return text ? undefined : logical;
}

function dockerAnchor(file: AnalysisFile, logical: { offsets: number[]; start: number; end: number }, start: number, end: number): Anchor {
  const absoluteStart = logical.offsets[start] ?? logical.start;
  const absoluteEnd = (logical.offsets[Math.max(start, end - 1)] ?? Math.max(absoluteStart, logical.end - 1)) + 1;
  return anchorAt(file, absoluteStart, absoluteEnd);
}

function matchingBrace(value: string, opening: number): number | undefined {
  let depth = 1;
  for (let index = opening + 1; index < value.length; index += 1) {
    if (value[index] === '{') depth += 1;
    else if (value[index] === '}') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function scanDollarReferences(
  file: AnalysisFile,
  value: string,
  baseOffset: number,
  sourceKind: 'docker-reference' | 'compose-interpolation',
  state: AnalysisState,
  offsetMap?: number[]
): void {
  let quote: string | undefined;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const current = value[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (current === '\\') {
      escaped = true;
      continue;
    }
    if (quote === "'") {
      if (current === "'") quote = undefined;
      continue;
    }
    if (current === "'") {
      quote = current;
      continue;
    }
    if (current === '"') {
      quote = quote === '"' ? undefined : '"';
      continue;
    }
    if (current === '#' && (index === 0 || /\s/u.test(value[index - 1]!))) break;
    if (current !== '$') continue;
    if (value[index + 1] === '$') {
      index += 1;
      continue;
    }
    const absolute = (local: number): number => offsetMap?.[baseOffset + local] ?? baseOffset + local;
    if (value[index + 1] === '{') {
      const closing = matchingBrace(value, index + 1);
      if (closing === undefined) {
        addDiagnostic(
          state,
          sourceKind === 'docker-reference'
            ? 'DEPLOYMENT_CONTRACT_DYNAMIC_DOCKER_REFERENCE'
            : 'DEPLOYMENT_CONTRACT_DYNAMIC_COMPOSE_INTERPOLATION',
          'warning',
          'A deployment interpolation is malformed or computed; environment mismatch claims were suppressed.',
          anchorAt(file, absolute(index), absolute(Math.min(value.length, index + 2))),
          'unsupported-deployment-interpolation',
          'environment'
        );
        return;
      }
      const body = value.slice(index + 2, closing);
      const nameMatch = body.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:(?::?[-+?]).*)?$/su);
      if (!nameMatch || nameMatch[1] === undefined) {
        addDiagnostic(
          state,
          sourceKind === 'docker-reference'
            ? 'DEPLOYMENT_CONTRACT_DYNAMIC_DOCKER_REFERENCE'
            : 'DEPLOYMENT_CONTRACT_DYNAMIC_COMPOSE_INTERPOLATION',
          'warning',
          'A deployment interpolation uses a computed or unsupported name; environment mismatch claims were suppressed.',
          anchorAt(file, absolute(index), absolute(closing) + 1),
          'computed-deployment-interpolation',
          'environment'
        );
      } else {
        const nameStart = index + 2;
        addObservation(
          state,
          file,
          'environment',
          'consumer',
          nameMatch[1],
          sourceKind,
          absolute(nameStart),
          absolute(nameStart + nameMatch[1].length - 1) + 1
        );
      }
      index = closing;
      continue;
    }
    const match = value.slice(index + 1).match(/^([A-Za-z_][A-Za-z0-9_]*)/u);
    if (!match || match[1] === undefined) continue;
    const nameStart = index + 1;
    addObservation(
      state,
      file,
      'environment',
      'consumer',
      match[1],
      sourceKind,
      absolute(nameStart),
      absolute(nameStart + match[1].length - 1) + 1
    );
    index += match[1].length;
  }
}

function parseDockerfile(file: AnalysisFile, state: AnalysisState): void {
  const source = file.content.toString('utf8');
  const logicalLines = dockerLogicalLines(source);
  if (!logicalLines) {
    addDiagnostic(
      state,
      'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
      'warning',
      'The Dockerfile uses an unsupported escape directive or unterminated continuation; environment mismatch claims were suppressed.',
      anchorAt(file, 0, Math.max(1, Math.min(source.length, 1))),
      'unsupported-dockerfile-line-structure',
      'environment'
    );
    return;
  }
  for (const logical of logicalLines) {
    const instruction = logical.text.match(/^\s*([A-Za-z]+)(?:\s+(.*))?$/su);
    if (!instruction || instruction[1] === undefined || instruction.index === undefined) {
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
        'warning',
        'A Dockerfile instruction could not be parsed conservatively; environment mismatch claims were suppressed.',
        dockerAnchor(file, logical, 0, Math.max(1, logical.text.length)),
        'unsupported-dockerfile-instruction',
        'environment'
      );
      continue;
    }
    const name = instruction[1].toUpperCase();
    const body = instruction[2] ?? '';
    const bodyStart = logical.text.indexOf(body, instruction.index + instruction[1].length);
    const words = shellWords(body);
    if ((name === 'ARG' || name === 'ENV') && !words) {
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
        'warning',
        'A Dockerfile ARG or ENV instruction has unsupported quoting; environment mismatch claims were suppressed.',
        dockerAnchor(file, logical, bodyStart, Math.max(bodyStart + 1, logical.text.length)),
        'unsupported-dockerfile-argument-syntax',
        'environment'
      );
      continue;
    }
    if (name === 'ARG') {
      if (!words || words.length !== 1) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
          'warning',
          'A Dockerfile ARG instruction is not one literal name declaration; environment mismatch claims were suppressed.',
          dockerAnchor(file, logical, bodyStart, Math.max(bodyStart + 1, logical.text.length)),
          'unsupported-docker-arg-declaration',
          'environment'
        );
      } else {
        const declaration = words[0]!.text.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:=.*)?$/su);
        if (!declaration || declaration[1] === undefined) {
          addDiagnostic(
            state,
            'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
            'warning',
            'A Dockerfile ARG instruction is not one literal name declaration; environment mismatch claims were suppressed.',
            dockerAnchor(file, logical, bodyStart + words[0]!.start, bodyStart + words[0]!.end),
            'unsupported-docker-arg-declaration',
            'environment'
          );
        } else {
          const nameIndex = bodyStart + words[0]!.start;
          addObservation(
            state,
            file,
            'environment',
            'declaration',
            declaration[1],
            'docker-arg',
            logical.offsets[nameIndex] ?? logical.start,
            (logical.offsets[nameIndex + declaration[1].length - 1] ?? logical.start) + 1
          );
        }
      }
    } else if (name === 'ENV') {
      if (!words || words.length === 0) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
          'warning',
          'A Dockerfile ENV instruction has no supported literal declaration; environment mismatch claims were suppressed.',
          dockerAnchor(file, logical, bodyStart, Math.max(bodyStart + 1, logical.text.length)),
          'unsupported-docker-env-declaration',
          'environment'
        );
      } else if (words[0]!.text.includes('=')) {
        for (const word of words) {
          const declaration = word.text.match(/^([A-Za-z_][A-Za-z0-9_]*)=/su);
          if (!declaration || declaration[1] === undefined) {
            addDiagnostic(
              state,
              'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
              'warning',
              'A Dockerfile ENV assignment is not a supported literal NAME=value declaration; environment mismatch claims were suppressed.',
              dockerAnchor(file, logical, bodyStart + word.start, bodyStart + word.end),
              'unsupported-docker-env-declaration',
              'environment'
            );
            continue;
          }
          const nameIndex = bodyStart + word.start;
          addObservation(
            state,
            file,
            'environment',
            'declaration',
            declaration[1],
            'docker-env',
            logical.offsets[nameIndex] ?? logical.start,
            (logical.offsets[nameIndex + declaration[1].length - 1] ?? logical.start) + 1
          );
        }
      } else {
        const declaration = words[0]!.text;
        if (!ENVIRONMENT_NAME.test(declaration)) {
          addDiagnostic(
            state,
            'DEPLOYMENT_CONTRACT_UNSUPPORTED_DOCKERFILE_SYNTAX',
            'warning',
            'A legacy Dockerfile ENV instruction does not start with one supported literal name; environment mismatch claims were suppressed.',
            dockerAnchor(file, logical, bodyStart + words[0]!.start, bodyStart + words[0]!.end),
            'unsupported-legacy-docker-env-declaration',
            'environment'
          );
        } else {
          const nameIndex = bodyStart + words[0]!.start;
          addObservation(
            state,
            file,
            'environment',
            'declaration',
            declaration,
            'docker-env',
            logical.offsets[nameIndex] ?? logical.start,
            (logical.offsets[nameIndex + declaration.length - 1] ?? logical.start) + 1
          );
        }
      }
    }
    scanDollarReferences(file, body, bodyStart, 'docker-reference', state, logical.offsets);
  }
}

function yamlVisibleLine(value: string): string {
  let quote: string | undefined;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const current = value[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (current === '\\' && quote === '"') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (current === quote) quote = undefined;
      continue;
    }
    if (current === '"' || current === "'") quote = current;
    else if (current === '#' && (index === 0 || /\s/u.test(value[index - 1]!))) return value.slice(0, index);
  }
  return value;
}

function parseYamlDeclarationBlocks(
  file: AnalysisFile,
  state: AnalysisState,
  blockName: 'environment' | 'env',
  sourceKind: 'compose-environment' | 'workflow-env',
  diagnosticCode: string,
  allowList: boolean
): void {
  let blockIndent: number | undefined;
  let entryIndent: number | undefined;
  let scalarIndent: number | undefined;
  for (const line of sourceLinesForFile(file)) {
    if (line.text.includes('\t')) {
      addDiagnostic(
        state,
        diagnosticCode,
        'warning',
        'A deployment YAML file uses tab indentation; environment mismatch claims were suppressed.',
        anchorAt(file, line.start, Math.max(line.start + 1, line.end)),
        'unsupported-yaml-indentation',
        'environment'
      );
      continue;
    }
    const visible = yamlVisibleLine(line.text);
    if (!visible.trim()) continue;
    const indent = visible.match(/^ */u)![0].length;
    if (scalarIndent !== undefined) {
      if (indent > scalarIndent) continue;
      scalarIndent = undefined;
    }
    if (blockIndent !== undefined && indent > blockIndent) {
      if (entryIndent === undefined) entryIndent = indent;
      if (indent !== entryIndent) {
        addDiagnostic(
          state,
          diagnosticCode,
          'warning',
          'An environment mapping contains nested or irregular YAML syntax; environment mismatch claims were suppressed.',
          anchorAt(file, line.start + indent, Math.max(line.start + indent + 1, line.end)),
          'unsupported-yaml-environment-mapping',
          'environment'
        );
        continue;
      }
      const content = visible.slice(indent).trimEnd();
      let name: string | undefined;
      let localNameOffset = 0;
      let value = '';
      if (allowList && content.startsWith('-')) {
        const item = content.slice(1).trimStart();
        const unquoted = (item.startsWith('"') && item.endsWith('"')) || (item.startsWith("'") && item.endsWith("'"))
          ? item.slice(1, -1)
          : item;
        const match = unquoted.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:=.*)?$/su);
        name = match?.[1];
        localNameOffset = visible.indexOf(name ?? '', indent);
      } else {
        const match = content.match(/^(?:"([A-Za-z_][A-Za-z0-9_]*)"|'([A-Za-z_][A-Za-z0-9_]*)'|([A-Za-z_][A-Za-z0-9_]*))\s*:\s*(.*)$/su);
        name = match?.[1] ?? match?.[2] ?? match?.[3];
        value = match?.[4] ?? '';
        localNameOffset = visible.indexOf(name ?? '', indent);
      }
      if (!name || localNameOffset < 0) {
        addDiagnostic(
          state,
          diagnosticCode,
          'warning',
          'An environment mapping entry does not have one supported literal name; environment mismatch claims were suppressed.',
          anchorAt(file, line.start + indent, Math.max(line.start + indent + 1, line.end)),
          'unsupported-yaml-environment-entry',
          'environment'
        );
        continue;
      }
      addObservation(
        state,
        file,
        'environment',
        'declaration',
        name,
        sourceKind,
        line.start + localNameOffset,
        line.start + localNameOffset + name.length
      );
      if (/^[>|]/u.test(value.trim())) scalarIndent = indent;
      continue;
    }
    blockIndent = undefined;
    entryIndent = undefined;
    const blockPattern = new RegExp(`^\\s*(?:-\\s+)?${blockName}\\s*:\\s*(.*)$`, 'u');
    const block = visible.match(blockPattern);
    if (!block) {
      if (/:[ \t]*[>|][+-]?[0-9]?[ \t]*$/u.test(visible)) scalarIndent = indent;
      continue;
    }
    if ((block[1] ?? '').trim()) {
      addDiagnostic(
        state,
        diagnosticCode,
        'warning',
        'An inline or anchored environment mapping is outside the supported YAML subset; environment mismatch claims were suppressed.',
        anchorAt(file, line.start + indent, Math.max(line.start + indent + 1, line.end)),
        'unsupported-inline-yaml-environment-mapping',
        'environment'
      );
      continue;
    }
    blockIndent = indent;
  }
}

function isComposePath(filePath: string): boolean {
  const basename = path.posix.basename(filePath).toLowerCase();
  return /^(?:docker-)?compose(?:\.[^.]+)*\.ya?ml$/u.test(basename);
}

function isWorkflowPath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.startsWith('.github/workflows/') && /\.ya?ml$/u.test(lower);
}

function parseCompose(file: AnalysisFile, state: AnalysisState): void {
  parseYamlDeclarationBlocks(
    file,
    state,
    'environment',
    'compose-environment',
    'DEPLOYMENT_CONTRACT_UNSUPPORTED_COMPOSE_ENVIRONMENT',
    true
  );
  for (const line of sourceLinesForFile(file)) {
    scanDollarReferences(file, yamlVisibleLine(line.text), line.start, 'compose-interpolation', state);
  }
}

function parseWorkflowExpressions(file: AnalysisFile, state: AnalysisState): void {
  for (const line of sourceLinesForFile(file)) {
    const visible = yamlVisibleLine(line.text);
    let cursor = 0;
    while (cursor < visible.length) {
    const opening = visible.indexOf('${{', cursor);
    if (opening === -1) break;
    const closing = visible.indexOf('}}', opening + 3);
    if (closing === -1) {
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_DYNAMIC_WORKFLOW_ENV_REFERENCE',
        'warning',
        'A GitHub Actions expression is unterminated; environment mismatch claims were suppressed.',
        anchorAt(file, line.start + opening, line.start + Math.min(visible.length, opening + 3)),
        'unterminated-workflow-expression',
        'environment'
      );
      return;
    }
    const expression = visible.slice(opening + 3, closing);
    const covered = new Set<number>();
    const dotPattern = /\benv\.([A-Za-z_][A-Za-z0-9_]*)\b/gu;
    for (const match of expression.matchAll(dotPattern)) {
      if (match.index === undefined || match[1] === undefined) continue;
      const nameOffset = match.index + match[0].indexOf(match[1]);
      addObservation(
        state,
        file,
        'environment',
        'consumer',
        match[1],
        'workflow-env-reference',
        line.start + opening + 3 + nameOffset,
        line.start + opening + 3 + nameOffset + match[1].length
      );
      for (let index = match.index; index < match.index + match[0].length; index += 1) covered.add(index);
    }
    const bracketPattern = /\benv\s*\[\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1\s*\]/gu;
    for (const match of expression.matchAll(bracketPattern)) {
      if (match.index === undefined || match[2] === undefined) continue;
      const nameOffset = match.index + match[0].indexOf(match[2]);
      addObservation(
        state,
        file,
        'environment',
        'consumer',
        match[2],
        'workflow-env-reference',
        line.start + opening + 3 + nameOffset,
        line.start + opening + 3 + nameOffset + match[2].length
      );
      for (let index = match.index; index < match.index + match[0].length; index += 1) covered.add(index);
    }
    for (const match of expression.matchAll(/\benv\b/gu)) {
      if (match.index === undefined || covered.has(match.index)) continue;
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_DYNAMIC_WORKFLOW_ENV_REFERENCE',
        'warning',
        'A GitHub Actions expression accesses env dynamically or as a whole object; environment mismatch claims were suppressed.',
        anchorAt(file, line.start + opening + 3 + match.index, line.start + opening + 3 + match.index + match[0].length),
        'dynamic-workflow-env-reference',
        'environment'
      );
    }
    cursor = closing + 2;
    }
  }
}

function parseWorkflow(file: AnalysisFile, state: AnalysisState): void {
  parseYamlDeclarationBlocks(
    file,
    state,
    'env',
    'workflow-env',
    'DEPLOYMENT_CONTRACT_UNSUPPORTED_WORKFLOW_ENVIRONMENT',
    false
  );
  parseWorkflowExpressions(file, state);
}

function skipHclWhitespace(source: string, initial: number, end: number): number {
  let index = initial;
  while (index < end && /\s/u.test(source[index]!)) index += 1;
  return index;
}

function hclIdentifier(source: string, start: number, end: number): { value: string; end: number } | undefined {
  const match = source.slice(start, end).match(/^([A-Za-z_][A-Za-z0-9_-]*)/u);
  return match?.[1] ? { value: match[1], end: start + match[1].length } : undefined;
}

function scanHclRange(
  file: AnalysisFile,
  source: string,
  start: number,
  end: number,
  state: AnalysisState,
  allowDeclarations: boolean
): void {
  let index = start;
  while (index < end) {
    if (/\s/u.test(source[index]!)) {
      index += 1;
      continue;
    }
    if (source[index] === '#' || (source[index] === '/' && source[index + 1] === '/')) {
      const newline = source.indexOf('\n', index + 1);
      index = newline === -1 || newline >= end ? end : newline + 1;
      continue;
    }
    if (source[index] === '/' && source[index + 1] === '*') {
      const closing = source.indexOf('*/', index + 2);
      if (closing === -1 || closing >= end) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_SYNTAX',
          'warning',
          'A Terraform block comment is unterminated; Terraform variable mismatch claims were suppressed.',
          anchorAt(file, index, Math.min(end, index + 2)),
          'unterminated-terraform-comment',
          'terraform-variable'
        );
        return;
      }
      index = closing + 2;
      continue;
    }
    if (source[index] === '"') {
      const quoteStart = index;
      index += 1;
      let closed = false;
      while (index < end) {
        if (source[index] === '\\') {
          index += 2;
          continue;
        }
        if ((source[index] === '$' || source[index] === '%') && source[index + 1] === '{') {
          const closing = matchingBrace(source, index + 1);
          if (closing === undefined || closing >= end) {
            addDiagnostic(
              state,
              'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_SYNTAX',
              'warning',
              'A Terraform string template is unterminated; Terraform variable mismatch claims were suppressed.',
              anchorAt(file, index, Math.min(end, index + 2)),
              'unterminated-terraform-template',
              'terraform-variable'
            );
            return;
          }
          scanHclRange(file, source, index + 2, closing, state, false);
          index = closing + 1;
          continue;
        }
        if (source[index] === '"') {
          index += 1;
          closed = true;
          break;
        }
        index += 1;
      }
      if (!closed) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_SYNTAX',
          'warning',
          'A Terraform quoted string is unterminated; Terraform variable mismatch claims were suppressed.',
          anchorAt(file, quoteStart, Math.min(end, quoteStart + 1)),
          'unterminated-terraform-string',
          'terraform-variable'
        );
        return;
      }
      continue;
    }
    if (source[index] === '<' && source[index + 1] === '<') {
      const marker = source.slice(index, end).match(/^<<(-?)([A-Za-z_][A-Za-z0-9_]*)[^\n]*\n/u);
      if (!marker || marker[2] === undefined) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_SYNTAX',
          'warning',
          'A Terraform heredoc marker is unsupported; Terraform variable mismatch claims were suppressed.',
          anchorAt(file, index, Math.min(end, index + 2)),
          'unsupported-terraform-heredoc',
          'terraform-variable'
        );
        return;
      }
      const bodyStart = index + marker[0].length;
      const terminatorPattern = new RegExp(`^${marker[1] === '-' ? '[ \\t]*' : ''}${marker[2]}[ \\t]*$`, 'u');
      let terminatorStart: number | undefined;
      let terminatorEnd: number | undefined;
      let lineStart = bodyStart;
      while (lineStart <= end) {
        const newline = source.indexOf('\n', lineStart);
        const lineBoundary = newline === -1 || newline > end ? end : newline;
        const rawEnd = lineBoundary > lineStart && source[lineBoundary - 1] === '\r'
          ? lineBoundary - 1
          : lineBoundary;
        if (terminatorPattern.test(source.slice(lineStart, rawEnd))) {
          terminatorStart = lineStart;
          terminatorEnd = rawEnd;
          break;
        }
        if (newline === -1 || newline >= end) break;
        lineStart = newline + 1;
      }
      if (terminatorStart === undefined || terminatorEnd === undefined) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_SYNTAX',
          'warning',
          'A Terraform heredoc is unterminated; Terraform variable mismatch claims were suppressed.',
          anchorAt(file, index, Math.min(end, index + marker[0].length)),
          'unterminated-terraform-heredoc',
          'terraform-variable'
        );
        return;
      }
      let templateCursor = bodyStart;
      while (templateCursor < terminatorStart) {
        const dollar = source.indexOf('${', templateCursor);
        const directive = source.indexOf('%{', templateCursor);
        const opening = dollar === -1 ? directive : directive === -1 ? dollar : Math.min(dollar, directive);
        if (opening === -1 || opening >= terminatorStart) break;
        const closing = matchingBrace(source, opening + 1);
        if (closing === undefined || closing >= terminatorStart) {
          addDiagnostic(
            state,
            'DEPLOYMENT_CONTRACT_UNSUPPORTED_TERRAFORM_SYNTAX',
            'warning',
            'A Terraform heredoc template is malformed; Terraform variable mismatch claims were suppressed.',
            anchorAt(file, opening, Math.min(terminatorStart, opening + 2)),
            'unterminated-terraform-heredoc-template',
            'terraform-variable'
          );
          return;
        }
        scanHclRange(file, source, opening + 2, closing, state, false);
        templateCursor = closing + 1;
      }
      index = terminatorEnd;
      continue;
    }
    const identifier = hclIdentifier(source, index, end);
    if (!identifier) {
      index += 1;
      continue;
    }
    const wordStart = index;
    index = identifier.end;
    if (identifier.value === 'var') {
      const next = skipHclWhitespace(source, index, end);
      if (source[next] === '.') {
        const nameStart = skipHclWhitespace(source, next + 1, end);
        const name = hclIdentifier(source, nameStart, end);
        if (name) {
          addObservation(
            state,
            file,
            'terraform-variable',
            'consumer',
            name.value,
            'terraform-var-reference',
            nameStart,
            name.end
          );
          index = name.end;
          continue;
        }
      }
      addDiagnostic(
        state,
        'DEPLOYMENT_CONTRACT_DYNAMIC_TERRAFORM_VARIABLE',
        'warning',
        'A Terraform var access is computed or whole-object; Terraform variable mismatch claims were suppressed.',
        anchorAt(file, wordStart, identifier.end),
        'dynamic-terraform-var-reference',
        'terraform-variable'
      );
      continue;
    }
    if (allowDeclarations && identifier.value === 'variable') {
      const lineStart = source.lastIndexOf('\n', wordStart - 1) + 1;
      if (source.slice(lineStart, wordStart).trim()) continue;
      const labelStart = skipHclWhitespace(source, index, end);
      if (source[labelStart] !== '"') {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_DYNAMIC_TERRAFORM_VARIABLE',
          'warning',
          'A Terraform variable block does not use one literal quoted name; Terraform variable mismatch claims were suppressed.',
          anchorAt(file, wordStart, identifier.end),
          'dynamic-terraform-variable-declaration',
          'terraform-variable'
        );
        continue;
      }
      let labelEnd = labelStart + 1;
      while (labelEnd < end && source[labelEnd] !== '"' && source[labelEnd] !== '\n') {
        if (source[labelEnd] === '\\') labelEnd += 2;
        else labelEnd += 1;
      }
      const name = source.slice(labelStart + 1, labelEnd);
      const brace = skipHclWhitespace(source, labelEnd + 1, end);
      if (labelEnd >= end || source[labelEnd] !== '"' || source[brace] !== '{' || !TERRAFORM_NAME.test(name)) {
        addDiagnostic(
          state,
          'DEPLOYMENT_CONTRACT_DYNAMIC_TERRAFORM_VARIABLE',
          'warning',
          'A Terraform variable block does not use one supported literal name; Terraform variable mismatch claims were suppressed.',
          anchorAt(file, wordStart, Math.min(end, Math.max(identifier.end, labelEnd))),
          'dynamic-terraform-variable-declaration',
          'terraform-variable'
        );
        continue;
      }
      addObservation(
        state,
        file,
        'terraform-variable',
        'declaration',
        name,
        'terraform-variable',
        labelStart + 1,
        labelEnd
      );
    }
  }
}

function parseTerraform(file: AnalysisFile, state: AnalysisState): void {
  const source = file.content.toString('utf8');
  scanHclRange(file, source, 0, source.length, state, true);
}

function observationOrder(left: Observation, right: Observation): number {
  return compareCanonicalText(left.namespace, right.namespace) ||
    compareCanonicalText(left.name, right.name) ||
    compareCanonicalText(left.role, right.role) ||
    compareCanonicalText(left.file.record.path, right.file.record.path) ||
    left.location.line - right.location.line ||
    left.location.column - right.location.column ||
    compareCanonicalText(left.sourceKind, right.sourceKind);
}

function findingId(ruleId: string, namespace: ContractNamespace, name: string): string {
  return `finding:${sha256(canonicalJson({
    producer: PRODUCER,
    version: DEPLOYMENT_CONTRACT_ANALYSIS_VERSION,
    ruleId,
    namespace,
    name
  })).slice(0, 24)}`;
}

function normalizedContractName(value: string): string {
  return value.normalize('NFC').toLowerCase().replace(/[^a-z0-9]/gu, '');
}

function findingFor(
  namespace: ContractNamespace,
  name: string,
  role: 'missing-declaration' | 'unused-declaration',
  observations: Observation[],
  namingVariantEvidence: Observation[] = [],
  namingVariantCount = namingVariantEvidence.length
): FindingRecord {
  const ordered = [...observations].sort(observationOrder);
  const orderedVariants = [...namingVariantEvidence].sort(observationOrder);
  const primary = ordered[0]!;
  const terraform = namespace === 'terraform-variable';
  const missing = role === 'missing-declaration';
  const ruleId = terraform
    ? missing
      ? 'contract/terraform-variable-missing-declaration-v1'
      : 'contract/terraform-variable-unused-declaration-v1'
    : missing
      ? 'contract/deployment-env-missing-declaration-v1'
      : 'contract/deployment-env-unused-declaration-v1';
  const evidencePaths = [...new Set([...ordered, ...orderedVariants].map((entry) => entry.file.record.path))].sort(compareCanonicalText);
  return {
    schemaVersion: SCHEMA_VERSION,
    id: findingId(ruleId, namespace, name),
    category: 'contract-mismatch',
    ruleId,
    status: 'candidate',
    severity: missing ? 'medium' : 'low',
    confidence: missing ? 'medium' : 'low',
    title: terraform
      ? missing
        ? `Terraform variable has no literal declaration: ${name}`
        : `Terraform declaration has no supported literal var. consumer: ${name}`
      : missing
        ? `Deployment environment name has no literal declaration: ${name}`
        : `Deployment environment declaration has no literal consumer: ${name}`,
    description: terraform
      ? missing
        ? `${name} is referenced through literal var.${name} syntax, but no supported literal Terraform variable block declares it.`
        : `${name} is declared by a literal Terraform variable block, but no supported literal var.${name} reference was observed.${namingVariantCount ? ` ${namingVariantCount} similarly named declaration or consumer observation(s) remain counter-evidence and require interface tracing.` : ''} This establishes declaration/interface drift only; it does not establish that the underlying capability is inert.`
      : missing
        ? `${name} is consumed by supported literal deployment or application syntax, but no supported literal environment declaration was observed.`
        : `${name} is declared by supported environment-contract syntax, but no supported literal consumer was observed.`,
    path: primary.file.record.path,
    relatedPaths: evidencePaths.filter((pathValue) => pathValue !== primary.file.record.path),
    signals: [
      missing ? 'literal-name-consumer' : 'literal-name-declaration',
      missing ? 'no-supported-literal-declaration' : 'no-supported-literal-consumer',
      ...(terraform && !missing ? ['capability-status-not-inferred'] : []),
      ...(namingVariantCount ? ['naming-variant-counter-evidence'] : []),
      ...[...new Set(ordered.map((entry) => entry.sourceKind))].sort(compareCanonicalText)
    ],
    evidence: [...ordered, ...orderedVariants].map((entry) => evidence(entry)),
    nextValidation: terraform
      ? 'Confirm generated modules, normalized environment-name variants, SSM or secret parameter paths, variable aliases, documentation, module boundaries, and the effective Terraform configuration before changing the variable contract.'
      : 'Confirm generated configuration, runtime injection, shell/framework consumers, CI contexts, and deployment boundaries before changing the environment contract.'
  };
}

/**
 * Correlates only literal deployment and IaC names. Values are never copied into
 * findings, diagnostics, IDs, evidence, or other returned data.
 */
export function detectDeploymentContractMismatches(
  files: AnalysisFile[]
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const state: AnalysisState = {
    observations: [],
    diagnostics: [],
    uncertainNamespaces: new Set(),
    observationLimitReached: false
  };
  const orderedFiles = [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  for (const file of orderedFiles) {
    const lowerPath = file.record.path.toLowerCase();
    const basename = path.posix.basename(lowerPath);
    if (JAVASCRIPT_LANGUAGES.has(file.record.language)) parseJavaScript(file, state);
    else if (file.record.language === 'dotenv-template' || /^\.env(?:\..+)?\.(?:example|template)$/u.test(basename)) parseDotenv(file, state);
    else if (basename === 'dockerfile' || basename.startsWith('dockerfile.')) parseDockerfile(file, state);
    else if (isComposePath(file.record.path)) parseCompose(file, state);
    else if (isWorkflowPath(file.record.path)) parseWorkflow(file, state);
    else if (file.record.language === 'tf' || lowerPath.endsWith('.tf')) parseTerraform(file, state);
  }

  const uniqueObservations = [...new Map(
    state.observations.map((entry) => [canonicalJson({
      namespace: entry.namespace,
      role: entry.role,
      name: entry.name,
      sourceKind: entry.sourceKind,
      path: entry.file.record.path,
      location: entry.location
    }), entry])
  ).values()].sort(observationOrder);
  const grouped = new Map<string, { declarations: Observation[]; consumers: Observation[] }>();
  const environmentByNormalizedName = new Map<string, Observation[]>();
  for (const observation of uniqueObservations) {
    const key = `${observation.namespace}\0${observation.name}`;
    const group = grouped.get(key) ?? { declarations: [], consumers: [] };
    group[observation.role === 'declaration' ? 'declarations' : 'consumers'].push(observation);
    grouped.set(key, group);
    if (observation.namespace === 'environment') {
      const normalized = normalizedContractName(observation.name);
      const matches = environmentByNormalizedName.get(normalized) ?? [];
      matches.push(observation);
      environmentByNormalizedName.set(normalized, matches);
    }
  }
  const normalizedEnvironmentNames = [...environmentByNormalizedName.keys()].sort(compareCanonicalText);

  function terraformVariants(name: string): { observations: Observation[]; count: number } {
    const normalized = normalizedContractName(name);
    if (normalized.length < 6) return { observations: [], count: 0 };
    const matchingNames = new Set<string>();
    for (let length = 6; length < normalized.length; length += 1) {
      const prefix = normalized.slice(0, length);
      if (environmentByNormalizedName.has(prefix)) matchingNames.add(prefix);
    }
    let low = 0;
    let high = normalizedEnvironmentNames.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (compareCanonicalText(normalizedEnvironmentNames[middle]!, normalized) < 0) low = middle + 1;
      else high = middle;
    }
    for (let index = low; index < normalizedEnvironmentNames.length; index += 1) {
      const candidate = normalizedEnvironmentNames[index]!;
      if (!candidate.startsWith(normalized)) break;
      if (candidate !== normalized && candidate.length >= 6) matchingNames.add(candidate);
    }
    let count = 0;
    const observations: Observation[] = [];
    for (const candidate of [...matchingNames].sort(compareCanonicalText)) {
      const values = environmentByNormalizedName.get(candidate) ?? [];
      count += values.length;
      for (const value of values) {
        if (observations.length < MAX_DEPLOYMENT_VARIANT_EVIDENCE) observations.push(value);
      }
    }
    return { observations, count };
  }
  const findings: FindingRecord[] = [];
  for (const namespace of ['environment', 'terraform-variable'] as const) {
    if (state.uncertainNamespaces.has(namespace)) continue;
    const names = [...new Set(uniqueObservations.filter((entry) => entry.namespace === namespace).map((entry) => entry.name))]
      .sort(compareCanonicalText);
    for (const name of names) {
      const group = grouped.get(`${namespace}\0${name}`)!;
      const declarations = group.declarations;
      const consumers = group.consumers;
      const implicitlyDeclaredDockerArgument = namespace === 'environment' &&
        DOCKER_AUTOMATIC_ARGUMENTS.has(name) &&
        consumers.every((entry) => entry.sourceKind === 'docker-reference');
      if (consumers.length > 0 && declarations.length === 0 && !implicitlyDeclaredDockerArgument) {
        findings.push(findingFor(namespace, name, 'missing-declaration', consumers));
      } else if (declarations.length > 0 && consumers.length === 0) {
        const variants = namespace === 'terraform-variable'
          ? terraformVariants(name)
          : { observations: [], count: 0 };
        findings.push(findingFor(
          namespace,
          name,
          'unused-declaration',
          declarations,
          variants.observations,
          variants.count
        ));
      }
    }
  }

  const deduplicatedFindings = [...new Map(findings.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  const deduplicatedDiagnostics = [...new Map(state.diagnostics.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings: deduplicatedFindings, diagnostics: deduplicatedDiagnostics };
}
