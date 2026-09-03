import path from 'node:path';
import ts from 'typescript';
import type {
  AnalysisFile,
  DiagnosticRecord,
  EvidenceReference,
  FindingRecord,
  ResolvedProfile,
  SourceLocation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { boundedTypeScriptDiagnosticMessage, parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesAnyGlob, normalizeTargetRelative } from '../util/paths.js';

export const PLATFORM_RESIDUAL_ANALYSIS_VERSION = '1.0.0';

const PRODUCER = 'atlas/platform-residuals';

interface Anchor {
  file: AnalysisFile;
  location: SourceLocation;
}

interface LiteralReference extends Anchor {
  kind: string;
  candidates: string[];
  targetType: 'file' | 'directory' | 'local-action';
}

interface Line {
  text: string;
  start: number;
  number: number;
}

function id(prefix: 'finding' | 'diagnostic', material: unknown): string {
  return `${prefix}:${sha256(canonicalJson(material)).slice(0, 24)}`;
}

function position(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  for (let index = 0; index < Math.min(offset, source.length); index += 1) {
    if (source[index] === '\n') {
      line += 1;
      column = 1;
    } else column += 1;
  }
  return { line, column };
}

function anchorAt(file: AnalysisFile, start: number, end: number): Anchor {
  const source = file.content.toString('utf8');
  const first = position(source, start);
  const last = position(source, Math.max(start + 1, end));
  return {
    file,
    location: {
      line: first.line,
      column: first.column,
      endLine: last.line,
      endColumn: last.column
    }
  };
}

function evidence(value: Anchor, basis: string): EvidenceReference {
  return {
    level: 1,
    producer: PRODUCER,
    producerVersion: PLATFORM_RESIDUAL_ANALYSIS_VERSION,
    basis,
    path: value.file.record.path,
    line: value.location.line,
    column: value.location.column,
    recordIds: [value.file.record.id]
  };
}

function diagnostic(
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  value: Anchor,
  basis: string,
  material: unknown
): DiagnosticRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: id('diagnostic', {
      code,
      path: value.file.record.path,
      line: value.location.line,
      column: value.location.column,
      material
    }),
    code,
    severity,
    message,
    path: value.file.record.path,
    location: value.location,
    evidence: evidence(value, basis)
  };
}

function sourceLines(source: string): Line[] {
  const result: Line[] = [];
  let start = 0;
  let number = 1;
  while (start <= source.length) {
    const newline = source.indexOf('\n', start);
    const end = newline === -1 ? source.length : newline;
    result.push({ text: source.slice(start, end).replace(/\r$/u, ''), start, number });
    if (newline === -1) break;
    start = newline + 1;
    number += 1;
  }
  return result;
}

function stripYamlComment(value: string): string {
  let quote: '"' | "'" | undefined;
  for (let index = 0; index < value.length; index += 1) {
    const current = value[index]!;
    if (quote) {
      if (current === quote) {
        if (quote === "'" && value[index + 1] === "'") index += 1;
        else quote = undefined;
      } else if (quote === '"' && current === '\\') index += 1;
    } else if (current === '"' || current === "'") quote = current;
    else if (current === '#' && (index === 0 || /\s/u.test(value[index - 1]!))) return value.slice(0, index).trimEnd();
  }
  return value.trimEnd();
}

function yamlScalar(value: string): { state: 'literal' | 'dynamic' | 'empty'; value?: string } {
  const trimmed = stripYamlComment(value).trim();
  if (!trimmed) return { state: 'empty' };
  if (/\$\{|\$\(|\{\{|^\*|^&|^[>|[]/u.test(trimmed)) return { state: 'dynamic' };
  if (trimmed.startsWith('"')) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      return typeof parsed === 'string' ? { state: 'literal', value: parsed.normalize('NFC') } : { state: 'dynamic' };
    } catch {
      return { state: 'dynamic' };
    }
  }
  if (trimmed.startsWith("'")) {
    if (!trimmed.endsWith("'") || trimmed.length < 2) return { state: 'dynamic' };
    return { state: 'literal', value: trimmed.slice(1, -1).replaceAll("''", "'").normalize('NFC') };
  }
  if (/\s/u.test(trimmed)) return { state: 'dynamic' };
  return { state: 'literal', value: trimmed.normalize('NFC') };
}

function normalizeLocalPath(base: string, rawValue: string): string | undefined {
  const value = rawValue.replaceAll('\\', '/').normalize('NFC');
  if (!value || value.includes('\0') || value.includes(':') || value.startsWith('/') || value.startsWith('//')) return undefined;
  const normalized = path.posix.normalize(path.posix.join(base, value));
  if (normalized === '..' || normalized.startsWith('../') || normalized === '.') return normalized === '.' ? '.' : undefined;
  try {
    return normalizeTargetRelative(normalized.replace(/^\.\//u, ''));
  } catch {
    return undefined;
  }
}

function yamlBlockScalarOnLine(file: AnalysisFile, line: Line): Anchor | undefined {
  const match = line.text.match(/:\s*[>|](?:[+-]?[1-9]?|[1-9]?[+-]?)\s*(?:#.*)?$/u);
  return match?.index === undefined
    ? undefined
    : anchorAt(file, line.start + match.index, line.start + line.text.length);
}

function fileCandidates(value: string): string[] {
  if (path.posix.extname(value)) return [value];
  return [
    value,
    `${value}.js`, `${value}.cjs`, `${value}.mjs`, `${value}.ts`, `${value}.d.ts`, `${value}.json`,
    `${value}/index.js`, `${value}/index.cjs`, `${value}/index.mjs`, `${value}/index.ts`
  ];
}

function reference(
  file: AnalysisFile,
  start: number,
  end: number,
  kind: string,
  candidates: string[],
  targetType: LiteralReference['targetType']
): LiteralReference {
  return { ...anchorAt(file, start, end), kind, candidates: [...new Set(candidates)], targetType };
}

function parseGithubWorkflow(file: AnalysisFile, diagnostics: DiagnosticRecord[]): LiteralReference[] {
  const source = file.content.toString('utf8');
  const references: LiteralReference[] = [];
  let blockScalarIndent: number | undefined;
  for (const line of sourceLines(source)) {
    const indentation = line.text.length - line.text.trimStart().length;
    if (blockScalarIndent !== undefined) {
      if (!line.text.trim() || indentation > blockScalarIndent) continue;
      blockScalarIndent = undefined;
    }
    const blockScalar = yamlBlockScalarOnLine(file, line);
    if (blockScalar) {
      blockScalarIndent = indentation;
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN',
        'info',
        'A workflow YAML block body was excluded from path parsing so embedded script text cannot be mistaken for workflow structure.',
        blockScalar,
        'yaml-block-scalar-content-excluded',
        { path: file.record.path, line: line.number }
      ));
      continue;
    }
    const match = line.text.match(/^\s*(?:-\s*)?(uses|working-directory)\s*:\s*(.*?)\s*$/u);
    if (!match || match[1] === undefined || match[2] === undefined || match.index === undefined) continue;
    const scalar = yamlScalar(match[2]);
    const valueStart = line.start + line.text.indexOf(match[2]);
    const valueAnchor = anchorAt(file, valueStart, valueStart + match[2].length);
    if (scalar.state === 'dynamic') {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_DYNAMIC_REFERENCE',
        'warning',
        `A GitHub workflow ${match[1]} value is dynamic; Atlas made no stale-path claim for it.`,
        valueAnchor,
        'dynamic-github-workflow-reference',
        { key: match[1], line: line.number }
      ));
      continue;
    }
    if (scalar.state !== 'literal' || scalar.value === undefined) continue;
    if (match[1] === 'uses') {
      if (!scalar.value.startsWith('./')) continue;
      const normalized = normalizeLocalPath('.', scalar.value);
      if (!normalized) {
        diagnostics.push(diagnostic(
          'CLEANUP_PLATFORM_REFERENCE_ESCAPE',
          'warning',
          'A local workflow action reference is not a portable target-relative path; Atlas suppressed it.',
          valueAnchor,
          'non-portable-local-action-path',
          { line: line.number }
        ));
        continue;
      }
      if (/\.ya?ml$/iu.test(normalized)) {
        references.push(reference(file, valueStart, valueStart + match[2].length, 'github-local-workflow', [normalized], 'file'));
      } else {
        references.push(reference(
          file,
          valueStart,
          valueStart + match[2].length,
          'github-local-action',
          [`${normalized}/action.yml`, `${normalized}/action.yaml`, `${normalized}/Dockerfile`],
          'local-action'
        ));
      }
    } else {
      const normalized = normalizeLocalPath('.', scalar.value);
      if (normalized) references.push(reference(file, valueStart, valueStart + match[2].length, 'github-working-directory', [normalized], 'directory'));
      else diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_ESCAPE',
        'warning',
        'A workflow working-directory is not a portable target-relative path; Atlas suppressed it.',
        valueAnchor,
        'non-portable-workflow-directory',
        { line: line.number }
      ));
    }
  }
  return references;
}

function parseCompose(file: AnalysisFile, diagnostics: DiagnosticRecord[]): LiteralReference[] {
  const source = file.content.toString('utf8');
  const references: LiteralReference[] = [];
  const base = path.posix.dirname(file.record.path) === '.' ? '.' : path.posix.dirname(file.record.path);
  let envFileIndent: number | undefined;
  let buildIndent: number | undefined;
  let blockScalarIndent: number | undefined;
  for (const line of sourceLines(source)) {
    if (!line.text.trim() || line.text.trimStart().startsWith('#')) continue;
    const indentation = line.text.length - line.text.trimStart().length;
    if (blockScalarIndent !== undefined) {
      if (indentation > blockScalarIndent) continue;
      blockScalarIndent = undefined;
    }
    const blockScalar = yamlBlockScalarOnLine(file, line);
    if (blockScalar) {
      blockScalarIndent = indentation;
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN',
        'info',
        'A Compose YAML block body was excluded from path parsing so embedded text cannot be mistaken for Compose structure.',
        blockScalar,
        'yaml-block-scalar-content-excluded',
        { path: file.record.path, line: line.number }
      ));
      continue;
    }
    if (envFileIndent !== undefined && indentation <= envFileIndent) envFileIndent = undefined;
    if (buildIndent !== undefined && indentation <= buildIndent) buildIndent = undefined;
    const envHeader = line.text.match(/^\s*env_file\s*:\s*(.*?)\s*$/u);
    const buildHeader = line.text.match(/^\s*build\s*:\s*(.*?)\s*$/u);
    let kind: string | undefined;
    let raw: string | undefined;
    let targetType: LiteralReference['targetType'] = 'file';
    if (envHeader?.[1] !== undefined) {
      if (!envHeader[1].trim()) envFileIndent = indentation;
      else {
        kind = 'compose-env-file';
        raw = envHeader[1];
      }
    } else if (envFileIndent !== undefined && indentation > envFileIndent) {
      const item = line.text.match(/^\s*-\s*(.*?)\s*$/u);
      if (item?.[1] !== undefined) {
        kind = 'compose-env-file';
        raw = item[1];
      }
    }
    if (buildHeader?.[1] !== undefined) {
      if (!buildHeader[1].trim()) buildIndent = indentation;
      else {
        kind = 'compose-build-context';
        raw = buildHeader[1];
        targetType = 'directory';
      }
    } else if (buildIndent !== undefined && indentation > buildIndent) {
      const context = line.text.match(/^\s*context\s*:\s*(.*?)\s*$/u);
      if (context?.[1] !== undefined) {
        kind = 'compose-build-context';
        raw = context[1];
        targetType = 'directory';
      }
      const dockerfile = line.text.match(/^\s*dockerfile\s*:/u);
      if (dockerfile) diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN',
        'info',
        'Compose dockerfile paths depend on build-context association; this bounded analyzer does not claim them stale.',
        anchorAt(file, line.start + (dockerfile.index ?? 0), line.start + line.text.length),
        'compose-dockerfile-context-uncertain',
        { line: line.number }
      ));
    }
    if (!kind || raw === undefined) continue;
    const scalar = yamlScalar(raw);
    const valueStart = line.start + line.text.indexOf(raw);
    const valueAnchor = anchorAt(file, valueStart, valueStart + raw.length);
    if (scalar.state !== 'literal' || scalar.value === undefined) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_DYNAMIC_REFERENCE',
        'warning',
        'A Compose path reference is dynamic or structurally unsupported; Atlas made no stale-path claim for it.',
        valueAnchor,
        'dynamic-compose-path-reference',
        { kind, line: line.number }
      ));
      continue;
    }
    const normalized = normalizeLocalPath(base, scalar.value);
    if (normalized) references.push(reference(file, valueStart, valueStart + raw.length, kind, [normalized], targetType));
    else diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_REFERENCE_ESCAPE',
      'warning',
      'A Compose reference is external or escapes the target; Atlas suppressed it.',
      valueAnchor,
      'external-or-non-portable-compose-reference',
      { kind, line: line.number }
    ));
  }
  return references;
}

function maskHclComments(source: string): string {
  const characters = source.split('');
  let state: 'normal' | 'string' | 'line' | 'block' = 'normal';
  for (let index = 0; index < characters.length; index += 1) {
    const current = characters[index]!;
    const next = characters[index + 1];
    if (state === 'line') {
      if (current === '\n' || current === '\r') state = 'normal';
      else characters[index] = ' ';
    } else if (state === 'block') {
      if (current === '*' && next === '/') {
        characters[index] = characters[index + 1] = ' ';
        index += 1;
        state = 'normal';
      } else if (current !== '\n' && current !== '\r') characters[index] = ' ';
    } else if (state === 'string') {
      if (current === '\\') index += 1;
      else if (current === '"') state = 'normal';
    } else if (current === '"') state = 'string';
    else if (current === '#' || current === '/' && next === '/') {
      characters[index] = ' ';
      if (current === '/') {
        characters[index + 1] = ' ';
        index += 1;
      }
      state = 'line';
    } else if (current === '/' && next === '*') {
      characters[index] = characters[index + 1] = ' ';
      index += 1;
      state = 'block';
    }
  }
  return characters.join('');
}

function maskQuotedStrings(source: string): string {
  const characters = source.split('');
  let quoted = false;
  for (let index = 0; index < characters.length; index += 1) {
    const current = characters[index]!;
    if (!quoted) {
      if (current === '"') {
        characters[index] = ' ';
        quoted = true;
      }
    } else if (current === '\\') {
      characters[index] = ' ';
      if (index + 1 < characters.length) characters[++index] = ' ';
    } else {
      if (current === '"') quoted = false;
      if (current !== '\n' && current !== '\r') characters[index] = ' ';
    }
  }
  return characters.join('');
}

function hclCodeAt(source: string, offset: number): boolean {
  let quoted = false;
  for (let index = 0; index < Math.min(offset, source.length); index += 1) {
    if (source[index] === '\\' && quoted) index += 1;
    else if (source[index] === '"') quoted = !quoted;
  }
  return !quoted;
}

function hclLexicallyBalanced(source: string): boolean {
  let state: 'normal' | 'string' | 'line' | 'block' = 'normal';
  for (let index = 0; index < source.length; index += 1) {
    const current = source[index]!;
    const next = source[index + 1];
    if (state === 'line') {
      if (current === '\n' || current === '\r') state = 'normal';
    } else if (state === 'block') {
      if (current === '*' && next === '/') {
        index += 1;
        state = 'normal';
      }
    } else if (state === 'string') {
      if (current === '\\') index += 1;
      else if (current === '"') state = 'normal';
    } else if (current === '"') state = 'string';
    else if (current === '#' || current === '/' && next === '/') {
      if (current === '/') index += 1;
      state = 'line';
    } else if (current === '/' && next === '*') {
      index += 1;
      state = 'block';
    }
  }
  return state === 'normal' || state === 'line';
}

function parseTerraform(file: AnalysisFile, diagnostics: DiagnosticRecord[]): LiteralReference[] {
  const source = file.content.toString('utf8');
  if (!hclLexicallyBalanced(source)) {
    const endAnchor = anchorAt(file, Math.max(0, source.length - 1), source.length);
    diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_CONFIG_PARSE_UNCERTAIN',
      'warning',
      'A Terraform file has an unterminated string or block comment; Atlas suppressed its path-reference claims.',
      endAnchor,
      'unterminated-terraform-lexical-construct',
      { path: file.record.path }
    ));
    return [];
  }
  const masked = maskHclComments(source);
  const structural = maskQuotedStrings(masked);
  const references: LiteralReference[] = [];
  const base = path.posix.dirname(file.record.path) === '.' ? '.' : path.posix.dirname(file.record.path);
  const heredoc = structural.match(/<<-?\s*[A-Za-z_][A-Za-z0-9_]*/u);
  if (heredoc?.index !== undefined) {
    diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN',
      'warning',
      'A Terraform file contains a heredoc body; this bounded parser suppressed its path-reference claims to avoid treating embedded text as HCL.',
      anchorAt(file, heredoc.index, heredoc.index + heredoc[0].length),
      'unsupported-terraform-heredoc',
      { line: position(source, heredoc.index).line }
    ));
    return references;
  }
  const literalFunctionStarts = new Set<number>();
  const literalFunction = /\b(file|templatefile)\s*\(\s*"((?:\\.|[^"\\])*)"/gu;
  for (const match of masked.matchAll(literalFunction)) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
    if (!hclCodeAt(masked, match.index)) continue;
    literalFunctionStarts.add(match.index);
    const raw = match[2].replaceAll('\\"', '"').normalize('NFC');
    const quoteOffset = match.index + match[0].indexOf('"');
    const valueAnchor = anchorAt(file, quoteOffset, quoteOffset + match[2].length + 2);
    if (!raw.startsWith('${path.module}/') || /\$\{(?!path\.module\})/u.test(raw)) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN',
        'info',
        'A Terraform file function does not use the supported literal ${path.module}/... form; Atlas made no stale-path claim.',
        valueAnchor,
        'terraform-file-base-uncertain',
        { functionName: match[1], line: valueAnchor.location.line }
      ));
      continue;
    }
    const normalized = normalizeLocalPath(base, raw.slice('${path.module}/'.length));
    if (normalized) references.push(reference(file, quoteOffset, quoteOffset + match[2].length + 2, `terraform-${match[1]}`, [normalized], 'file'));
    else diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_REFERENCE_ESCAPE',
      'warning',
      'A Terraform file reference escapes the target boundary; Atlas suppressed it.',
      valueAnchor,
      'terraform-path-escape',
      { functionName: match[1], line: valueAnchor.location.line }
    ));
  }
  const functionMention = /\b(file|templatefile)\s*\(/gu;
  for (const match of masked.matchAll(functionMention)) {
    if (match.index === undefined || literalFunctionStarts.has(match.index)) continue;
    if (!hclCodeAt(masked, match.index)) continue;
    const valueAnchor = anchorAt(file, match.index, match.index + match[0].length);
    diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_DYNAMIC_REFERENCE',
      'warning',
      'A Terraform file function has a computed argument; Atlas made no stale-path claim for it.',
      valueAnchor,
      'dynamic-terraform-file-reference',
      { functionName: match[1], line: valueAnchor.location.line }
    ));
  }

  const modulePattern = /\bmodule\s+"(?:\\.|[^"\\])*"\s*\{/gu;
  for (const moduleMatch of masked.matchAll(modulePattern)) {
    if (moduleMatch.index === undefined) continue;
    if (!hclCodeAt(masked, moduleMatch.index)) continue;
    const opening = moduleMatch.index + moduleMatch[0].lastIndexOf('{');
    let depth = 1;
    let closing = opening + 1;
    while (closing < structural.length && depth > 0) {
      if (structural[closing] === '{') depth += 1;
      else if (structural[closing] === '}') depth -= 1;
      closing += 1;
    }
    const moduleAnchor = anchorAt(file, moduleMatch.index, opening);
    if (depth !== 0) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN',
        'warning',
        'A Terraform module block is unterminated; Atlas suppressed its source reference.',
        moduleAnchor,
        'unterminated-terraform-module-block',
        { line: moduleAnchor.location.line }
      ));
      continue;
    }
    const body = masked.slice(opening + 1, closing - 1);
    const mentions = [...body.matchAll(/\bsource\s*=/gu)].filter((entry) => entry.index !== undefined && hclCodeAt(body, entry.index));
    const sources = [...body.matchAll(/\bsource\s*=\s*"((?:\\.|[^"\\])*)"/gu)]
      .filter((entry) => entry.index !== undefined && hclCodeAt(body, entry.index));
    if (mentions.length !== 1 || sources.length !== 1 || sources[0]?.index === undefined || sources[0]?.[1] === undefined) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_DYNAMIC_REFERENCE',
        'warning',
        'A Terraform module does not have exactly one literal source; Atlas made no stale-path claim for it.',
        moduleAnchor,
        'dynamic-or-ambiguous-terraform-module-source',
        { line: moduleAnchor.location.line }
      ));
      continue;
    }
    const sourceValue = sources[0][1].normalize('NFC');
    if (!sourceValue.startsWith('./') && !sourceValue.startsWith('../')) continue;
    const sourceOffset = opening + 1 + sources[0].index + sources[0][0].indexOf('"');
    const valueAnchor = anchorAt(file, sourceOffset, sourceOffset + sourceValue.length + 2);
    if (sourceValue.includes('${')) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_DYNAMIC_REFERENCE',
        'warning',
        'A Terraform local module source contains interpolation; Atlas made no stale-path claim for it.',
        valueAnchor,
        'interpolated-terraform-module-source',
        { line: valueAnchor.location.line }
      ));
      continue;
    }
    const normalized = normalizeLocalPath(base, sourceValue);
    if (normalized) references.push(reference(file, sourceOffset, sourceOffset + sourceValue.length + 2, 'terraform-local-module', [normalized], 'directory'));
    else diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_REFERENCE_ESCAPE',
      'warning',
      'A Terraform module source escapes the target boundary; Atlas suppressed it.',
      valueAnchor,
      'terraform-module-path-escape',
      { line: valueAnchor.location.line }
    ));
  }
  return references;
}

function jsonProperty(object: ts.ObjectLiteralExpression, requested: string): ts.PropertyAssignment | undefined {
  return object.properties.find((property): property is ts.PropertyAssignment => {
    if (!ts.isPropertyAssignment(property)) return false;
    const name = property.name;
    return (ts.isStringLiteralLike(name) || ts.isIdentifier(name)) && name.text === requested;
  });
}

function jsonAnchor(file: AnalysisFile, sourceFile: ts.JsonSourceFile, node: ts.Node): Anchor {
  return { file, location: locationFor(sourceFile, node) };
}

function parseJsonReferences(file: AnalysisFile, diagnostics: DiagnosticRecord[]): LiteralReference[] {
  const source = file.content.toString('utf8');
  const references: LiteralReference[] = [];
  const parsedSource = parseBoundedTypeScript(file.record.path, source, ts.ScriptKind.JSON);
  if (parsedSource.state === 'rejected') {
    diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_CONFIG_PARSE_UNCERTAIN',
      'warning',
      boundedTypeScriptDiagnosticMessage(parsedSource.reason),
      anchorAt(file, 0, 1),
      'typescript-ast-resource-limit',
      { path: file.record.path, reason: parsedSource.reason }
    ));
    return references;
  }
  const sourceFile = parsedSource.sourceFile as ts.JsonSourceFile;
  const parseDiagnostics = (sourceFile as ts.JsonSourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
  if (parseDiagnostics.length || !sourceFile.statements[0] || !ts.isExpressionStatement(sourceFile.statements[0]) || !ts.isObjectLiteralExpression(sourceFile.statements[0].expression)) {
    diagnostics.push(diagnostic(
      'CLEANUP_PLATFORM_CONFIG_PARSE_UNCERTAIN',
      'warning',
      'A supported JSON configuration file could not be parsed; Atlas suppressed its path-reference claims.',
      anchorAt(file, parseDiagnostics[0]?.start ?? 0, (parseDiagnostics[0]?.start ?? 0) + 1),
      'json-config-parse-failure',
      { path: file.record.path }
    ));
    return references;
  }
  const root = sourceFile.statements[0].expression;
  const base = path.posix.dirname(file.record.path) === '.' ? '.' : path.posix.dirname(file.record.path);
  function addString(node: ts.StringLiteralLike, kind: string, targetType: LiteralReference['targetType'], candidatesFor: (value: string) => string[]): void {
    const value = node.text.normalize('NFC');
    if (value.includes('*') || value.includes('${')) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_DYNAMIC_REFERENCE',
        'warning',
        'A JSON configuration path contains a pattern or interpolation; Atlas made no stale-path claim for it.',
        jsonAnchor(file, sourceFile, node),
        'dynamic-json-config-reference',
        { kind, line: locationForJson(sourceFile, node).line }
      ));
      return;
    }
    const normalized = normalizeLocalPath(base, value);
    if (!normalized) return;
    references.push({ ...jsonAnchor(file, sourceFile, node), kind, candidates: candidatesFor(normalized), targetType });
  }
  const basename = path.posix.basename(file.record.path).toLowerCase();
  if (basename === 'package.json') {
    for (const key of ['main', 'module', 'types', 'typings']) {
      const initializer = jsonProperty(root, key)?.initializer;
      if (initializer && ts.isStringLiteralLike(initializer)) addString(initializer, `package-${key}`, 'file', fileCandidates);
    }
    const bin = jsonProperty(root, 'bin')?.initializer;
    if (bin && ts.isStringLiteralLike(bin)) addString(bin, 'package-bin', 'file', fileCandidates);
    else if (bin && ts.isObjectLiteralExpression(bin)) {
      for (const property of bin.properties) {
        if (ts.isPropertyAssignment(property) && ts.isStringLiteralLike(property.initializer)) addString(property.initializer, 'package-bin', 'file', fileCandidates);
      }
    }
  } else if (/^tsconfig(?:\.[^.]+)?\.json$/u.test(basename)) {
    const extension = jsonProperty(root, 'extends')?.initializer;
    const extensionValues = extension && ts.isStringLiteralLike(extension)
      ? [extension]
      : extension && ts.isArrayLiteralExpression(extension)
        ? extension.elements.filter(ts.isStringLiteralLike)
        : [];
    for (const value of extensionValues) {
      if (value.text.startsWith('.')) addString(value, 'tsconfig-extends', 'file', (candidate) => path.posix.extname(candidate) ? [candidate] : [`${candidate}.json`, `${candidate}/tsconfig.json`]);
    }
    const filesValue = jsonProperty(root, 'files')?.initializer;
    if (filesValue && ts.isArrayLiteralExpression(filesValue)) {
      for (const value of filesValue.elements) if (ts.isStringLiteralLike(value)) addString(value, 'tsconfig-file', 'file', (candidate) => [candidate]);
    }
    const projectReferences = jsonProperty(root, 'references')?.initializer;
    if (projectReferences && ts.isArrayLiteralExpression(projectReferences)) {
      for (const element of projectReferences.elements) {
        if (!ts.isObjectLiteralExpression(element)) continue;
        const value = jsonProperty(element, 'path')?.initializer;
        if (value && ts.isStringLiteralLike(value)) addString(value, 'tsconfig-project-reference', 'file', (candidate) =>
          path.posix.extname(candidate) ? [candidate] : [`${candidate}/tsconfig.json`]
        );
      }
    }
  }
  return references;
}

function locationForJson(sourceFile: ts.JsonSourceFile, node: ts.Node): SourceLocation {
  return locationForTs(sourceFile, node);
}

function locationForTs(sourceFile: ts.SourceFile, node: ts.Node): SourceLocation {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return { line: start.line + 1, column: start.character + 1, endLine: end.line + 1, endColumn: end.character + 1 };
}

function locationFor(sourceFile: ts.SourceFile, node: ts.Node): SourceLocation {
  return locationForTs(sourceFile, node);
}

function withinIncludedBoundary(candidate: string, profile: ResolvedProfile): boolean {
  return profile.includeRoots.some((root) => root === '.' || candidate === root || candidate.startsWith(`${root}/`));
}

function boundaryUncertainty(
  candidates: string[],
  targetType: LiteralReference['targetType'],
  profile: ResolvedProfile,
  boundaryDiagnostics: DiagnosticRecord[]
): { code: string; path?: string } | undefined {
  for (const candidate of candidates) {
    const coveragePath = targetType === 'local-action' ? path.posix.dirname(candidate) : candidate;
    if (!withinIncludedBoundary(coveragePath, profile)) return { code: 'OUTSIDE_INCLUDED_BOUNDARY', path: coveragePath };
    if (coveragePath !== '.' && matchesAnyGlob(coveragePath, profile.exclude)) return { code: 'EXCLUDED_FROM_BOUNDARY', path: coveragePath };
    for (const entry of boundaryDiagnostics) {
      if (!entry.path) continue;
      if (
        entry.path === coveragePath || coveragePath.startsWith(`${entry.path}/`) ||
        targetType === 'directory' && entry.path.startsWith(`${coveragePath}/`)
      ) return { code: entry.code, path: entry.path };
    }
  }
  return undefined;
}

function referenceExists(referenceValue: LiteralReference, paths: Set<string>): boolean {
  if (referenceValue.targetType === 'directory') {
    return referenceValue.candidates.some((candidate) =>
      candidate === '.' || paths.has(candidate) || [...paths].some((filePath) => filePath.startsWith(`${candidate}/`))
    );
  }
  return referenceValue.candidates.some((candidate) => paths.has(candidate));
}

export function detectPlatformResidualCandidates(
  files: AnalysisFile[],
  profile: ResolvedProfile,
  boundaryDiagnostics: DiagnosticRecord[] = []
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const orderedFiles = [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  const diagnostics: DiagnosticRecord[] = [];
  const references: LiteralReference[] = [];
  for (const file of orderedFiles) {
    const lower = file.record.path.toLowerCase();
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/u.test(lower)) references.push(...parseGithubWorkflow(file, diagnostics));
    if (/(?:^|\/)(?:docker-)?compose(?:\.[^.]+)?\.ya?ml$/u.test(lower)) references.push(...parseCompose(file, diagnostics));
    if (lower.endsWith('.tf')) references.push(...parseTerraform(file, diagnostics));
    const basename = path.posix.basename(lower);
    if (basename === 'package.json' || /^tsconfig(?:\.[^.]+)?\.json$/u.test(basename)) references.push(...parseJsonReferences(file, diagnostics));
  }
  references.sort((left, right) =>
    compareCanonicalText(left.file.record.path, right.file.record.path) ||
    left.location.line - right.location.line || left.location.column - right.location.column ||
    compareCanonicalText(left.kind, right.kind)
  );

  const paths = new Set(orderedFiles.map((file) => file.record.path));
  const caseFolded = new Map(orderedFiles.map((file) => [file.record.path.toLowerCase(), file.record.path]));
  const findings: FindingRecord[] = [];
  for (const value of references) {
    if (referenceExists(value, paths)) continue;
    const differentlyCased = value.targetType === 'directory'
      ? undefined
      : value.candidates.map((candidate) => caseFolded.get(candidate.toLowerCase())).find(Boolean);
    if (differentlyCased) {
      const ruleId = 'dead-code/platform-reference-case-mismatch-v1';
      findings.push({
        schemaVersion: SCHEMA_VERSION,
        id: id('finding', { ruleId, from: value.file.record.path, location: value.location, actual: differentlyCased }),
        category: 'dead-code-candidate',
        ruleId,
        status: 'candidate',
        severity: 'low',
        confidence: 'high',
        title: `Review case-mismatched platform reference: ${value.candidates[0]}`,
        description: `The literal ${value.kind} reference to ${value.candidates[0]} differs in case from the exact snapshot path, which can fail on case-sensitive deployment filesystems.`,
        path: value.file.record.path,
        relatedPaths: [differentlyCased],
        signals: ['literal-local-platform-reference', 'case-insensitive-match-only', 'exact-path-match-absent'],
        evidence: [evidence(value, `literal-${value.kind}-reference`)],
        nextValidation: 'Confirm the platform path-resolution rules and deployed filesystem, then correct the reference casing if the paths are intended to match.'
      });
      continue;
    }
    const uncertainty = boundaryUncertainty(value.candidates, value.targetType, profile, boundaryDiagnostics);
    if (uncertainty) {
      diagnostics.push(diagnostic(
        'CLEANUP_PLATFORM_REFERENCE_BOUNDARY_UNCERTAIN',
        'warning',
        'A literal platform/config reference has no snapshot target, but the relevant path is excluded, skipped, or outside the included boundary; Atlas suppressed the stale-reference claim.',
        value,
        'incomplete-reference-target-census',
        { kind: value.kind, uncertainty }
      ));
      continue;
    }
    const ruleId = 'dead-code/stale-literal-platform-reference-v1';
    const expectedPath = value.targetType === 'local-action'
      ? path.posix.dirname(value.candidates[0]!)
      : value.candidates[0]!;
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: id('finding', { ruleId, from: value.file.record.path, location: value.location, kind: value.kind, candidates: value.candidates }),
      category: 'dead-code-candidate',
      ruleId,
      status: 'candidate',
      severity: 'low',
      confidence: value.targetType === 'directory' ? 'medium' : 'high',
      title: `Review stale literal platform reference: ${expectedPath}`,
      description: `A literal local ${value.kind} reference to ${expectedPath} has no matching included target in the relevant snapshot boundary. Atlas did not execute or interpolate the configuration.`,
      path: value.file.record.path,
      relatedPaths: [],
      signals: [
        'literal-local-platform-reference',
        'referenced-path-absent-from-snapshot',
        'relevant-snapshot-boundary-complete',
        'no-source-execution-or-interpolation'
      ],
      evidence: [evidence(value, `literal-${value.kind}-reference`)],
      nextValidation: 'Check generated artifacts, runtime-created paths, alternate build contexts, platform-specific resolution, ignored files, and deployment inventory before removing or changing the reference.'
    });
  }

  const uniqueFindings = [...new Map(findings.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  const uniqueDiagnostics = [...new Map(diagnostics.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings: uniqueFindings, diagnostics: uniqueDiagnostics };
}
