import path from 'node:path';
import ts from 'typescript';
import type {
  AnalysisFile,
  DiagnosticRecord,
  EvidenceReference,
  FindingImpactContext,
  FindingKind,
  FindingMappingContext,
  FindingRecord,
  RelationshipRecord,
  ResolvedProfile,
  SourceLocation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesAnyGlob } from '../util/paths.js';

export const OPERATIONAL_RISK_ANALYSIS_VERSION = '1.3.2';

export const OPERATIONAL_RULE_IDS = {
  silentEmpty: 'operational/silent-empty-instrument-v1',
  hostContainerPath: 'operational/host-container-path-divergence-v1',
  guardBypass: 'operational/guard-bypass-v1',
  vocabularyDrift: 'contract/vocabulary-drift-v1',
  clockDateBasis: 'operational/clock-date-basis-v1',
  resultCollapse: 'operational/result-collapse-v1',
  duplicateGuard: 'operational/duplicate-guard-fragment-v1',
  seededDictionary: 'contract/seeded-dictionary-id-coupling-v1',
  accidentalProtection: 'latent/accidental-protection-v1'
} as const;

export type OperationalRuleId = typeof OPERATIONAL_RULE_IDS[keyof typeof OPERATIONAL_RULE_IDS];

export const OPERATIONAL_RULE_CATALOG = [
  { ruleId: OPERATIONAL_RULE_IDS.silentEmpty, family: 'silent-empty-instrument', kind: 'defect-candidate' },
  { ruleId: OPERATIONAL_RULE_IDS.hostContainerPath, family: 'host-container-path-divergence', kind: 'defect-candidate' },
  { ruleId: OPERATIONAL_RULE_IDS.guardBypass, family: 'guard-bypass-inventory', kind: 'review-inventory' },
  { ruleId: OPERATIONAL_RULE_IDS.vocabularyDrift, family: 'duplicate-live-vocabulary', kind: 'defect-candidate' },
  { ruleId: OPERATIONAL_RULE_IDS.clockDateBasis, family: 'clock-and-date-basis', kind: 'defect-candidate' },
  { ruleId: OPERATIONAL_RULE_IDS.resultCollapse, family: 'result-collapse', kind: 'defect-candidate' },
  { ruleId: OPERATIONAL_RULE_IDS.duplicateGuard, family: 'duplicate-guard-fragment', kind: 'review-inventory' },
  { ruleId: OPERATIONAL_RULE_IDS.seededDictionary, family: 'seeded-dictionary-coupling', kind: 'defect-candidate' },
  { ruleId: OPERATIONAL_RULE_IDS.accidentalProtection, family: 'latent-accidental-protection', kind: 'latent-hazard' }
] as const;

const PRODUCER = 'atlas/operational-risks';
const SCRIPT_EXTENSIONS = /\.(?:[cm]?[jt]sx?)$/iu;
const TEST_PATH = /(?:^|\/)(?:__tests__|test|tests|spec|specs|fixtures)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/iu;
const SEMANTIC_FIELD = /(?:status|state|role|mode|type|action|category|kind)$/u;
const NON_PRODUCT_SOURCE_ROOT = /^(?:corpus|docs|examples|reference)(?:\/|$)/iu;
const DISABLED_WORKFLOW_ARTIFACT = /(?:^|\/)\.github\/workflows\/[^/]+\.disabled$/iu;

function isOperationalInput(file: AnalysisFile): boolean {
  if (file.record.kind === 'documentation' || NON_PRODUCT_SOURCE_ROOT.test(file.record.path)) return false;
  return file.record.lifecycle?.state !== 'mothballed';
}

function isProductionConsumer(file: AnalysisFile): boolean {
  if (!isOperationalInput(file) || file.record.kind === 'test' || TEST_PATH.test(file.record.path)) return false;
  return !/(?:^|\/)(?:e2e|fixtures|migrations?|seeders?|scripts?)(?:\/|$)/iu.test(file.record.path);
}

export type OperationalImpactContext = FindingImpactContext;

export type OperationalFindingKind = FindingKind;

export type OperationalFindingRecord = FindingRecord & {
  kind: OperationalFindingKind;
  patternKey: string;
  instanceCount: 1;
  impactContext: OperationalImpactContext;
};

export interface OperationalObservation {
  schemaVersion: 1;
  id: string;
  ruleId: OperationalRuleId;
  state: 'detected' | 'uncertain';
  path: string;
  location: SourceLocation;
  fingerprint: string;
  evidence: EvidenceReference;
}

export interface OperationalRiskResult {
  findings: OperationalFindingRecord[];
  diagnostics: DiagnosticRecord[];
  observations: OperationalObservation[];
  containerCoverage: ContainerCoverageRecord[];
}

/** Positive, source-anchored proof that a container test service maps a test file. */
export interface ContainerCoverageRecord {
  schemaVersion: 1;
  id: string;
  ruleId: typeof OPERATIONAL_RULE_IDS.hostContainerPath;
  composePath: string;
  service: string;
  buildContext?: string;
  dockerfile?: string;
  workingDirectory?: string;
  hostRoot: string;
  containerRoot: string;
  sourcePath: string;
  containerPath: string;
  sourceKind: PathMap['sourceKind'];
  selection: 'broad-test-command' | 'explicit-test-path';
  evidence: EvidenceReference;
}

interface Anchor {
  file: AnalysisFile;
  start: number;
  end: number;
}

interface ParsedFile {
  file: AnalysisFile;
  source: string;
  sourceFile: ts.SourceFile;
  parseDiagnostics: readonly ts.Diagnostic[];
}

interface AnalysisState {
  findings: OperationalFindingRecord[];
  diagnostics: DiagnosticRecord[];
  observations: OperationalObservation[];
  containerCoverage: ContainerCoverageRecord[];
  reachablePaths?: Set<string>;
  entrypointPaths: string[];
}

interface FindingOptions {
  kind: OperationalFindingKind;
  severity: FindingRecord['severity'];
  confidence: FindingRecord['confidence'];
  title: string;
  description: string;
  signals: string[];
  nextValidation: string;
  patternMaterial: unknown;
  related?: Anchor[];
  mechanism?: string;
  mappingContext?: FindingMappingContext;
}

interface PathMap {
  hostRoot: string;
  containerRoot: string;
  sourceKind: 'bind-mount' | 'docker-copy';
  contextId: string;
  composePath: string;
  service: string;
  buildContext?: string;
  dockerfile?: string;
  workingDirectory?: string;
  selectors: string[];
  anchor: Anchor;
}

interface ComposeServiceContext {
  composeFile: AnalysisFile;
  composeDirectory: string;
  service: string;
  anchor: Anchor;
  buildContext?: string;
  dockerfile?: string;
  buildTarget?: string;
  workingDirectory?: string;
  selectors: string[];
  volumes: Array<{ hostRoot: string; containerRoot: string; anchor: Anchor }>;
}

interface VocabularyFact {
  fieldKey: string;
  signature: string;
  size: number;
  mechanism: string;
  anchor: Anchor;
}

interface WriterCall {
  sinkKey: string;
  guarded: boolean;
  anchor: Anchor;
  declaration?: {
    writerId: string;
    method: string;
    protectingBoundaryIds: string[];
    traversedBoundaryIds: string[];
  };
}

interface ImportBinding {
  targetPath: string;
  exportedName: string;
}

interface LexicalBinding {
  name: string;
  nameNode: ts.Identifier;
  declaration: ts.Node;
  scope: ts.Node;
  importSpecifier?: string;
  importedName?: string;
}

type LexicalBindingIndex = ReadonlyMap<string, readonly LexicalBinding[]>;

interface SeedDictionary {
  fieldKey: string;
  ids: Map<number, string>;
  names: Set<string>;
  literalNames: Set<string>;
  anchor: Anchor;
}

function stableHash(value: unknown): string {
  return sha256(canonicalJson(value));
}

const INSTANCE_LOCATION_KEYS = new Set(['path', 'offset', 'start', 'end', 'line', 'column', 'bypass']);

function patternIdentityMaterial(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(patternIdentityMaterial);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([key]) => !INSTANCE_LOCATION_KEYS.has(key))
      .sort(([left], [right]) => compareCanonicalText(left, right))
      .map(([key, entry]) => [key, patternIdentityMaterial(entry)])
  );
}

function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (filePath.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (/\.(?:ts|mts|cts)$/u.test(filePath)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function lineAndColumn(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  for (let index = 0; index < Math.max(0, Math.min(offset, source.length)); index += 1) {
    if (source.charCodeAt(index) === 10) {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

function location(anchor: Anchor): SourceLocation {
  const source = anchor.file.content.toString('utf8');
  const start = lineAndColumn(source, anchor.start);
  const end = lineAndColumn(source, Math.max(anchor.start + 1, anchor.end));
  return { line: start.line, column: start.column, endLine: end.line, endColumn: end.column };
}

function nodeAnchor(parsed: ParsedFile, node: ts.Node): Anchor {
  return {
    file: parsed.file,
    start: node.getStart(parsed.sourceFile),
    end: node.getEnd()
  };
}

function evidence(anchor: Anchor, basis: string): EvidenceReference {
  const position = location(anchor);
  return {
    level: 1,
    producer: PRODUCER,
    producerVersion: OPERATIONAL_RISK_ANALYSIS_VERSION,
    basis,
    path: anchor.file.record.path,
    line: position.line,
    column: position.column,
    recordIds: [anchor.file.record.id]
  };
}

function inferredSurfaces(filePath: string): string[] {
  const lower = filePath.toLowerCase();
  const values: string[] = [];
  if (/(?:^|\/)(?:routes?|controllers?|api)(?:\/|$)/u.test(lower)) values.push('http-route');
  if (/(?:^|\/)(?:cli|bin|scripts?)(?:\/|$)/u.test(lower)) values.push('cli');
  if (/(?:dockerfile|compose|webpack|vite|rollup|build)/u.test(lower)) values.push('build');
  if (TEST_PATH.test(lower)) values.push('test');
  if (/(?:^|\/)migrations?(?:\/|$)/u.test(lower)) values.push('migration');
  if (/(?:^|\/)seeders?(?:\/|$)/u.test(lower)) values.push('seeder');
  return [...new Set(values)].sort(compareCanonicalText);
}

function impactContext(state: AnalysisState, anchor: Anchor): OperationalImpactContext {
  const reachability: FindingImpactContext['reachability'] = state.reachablePaths === undefined
    ? 'unknown'
    : state.reachablePaths.has(anchor.file.record.path)
      ? 'reachable'
      : 'unreachable';
  const mountedSurfaces = inferredSurfaces(anchor.file.record.path);
  const scope = mountedSurfaces.includes('test')
    ? 'test' as const
    : mountedSurfaces.includes('migration')
      ? 'migration' as const
      : mountedSurfaces.includes('seeder')
        ? 'seeder' as const
        : mountedSurfaces.includes('cli')
          ? 'cli' as const
          : mountedSurfaces.includes('build')
            ? 'build' as const
            : mountedSurfaces.includes('http-route')
              ? 'production' as const
              : undefined;
  return {
    reachability,
    ...(scope ? { scope } : {}),
    entrypoints: [...state.entrypointPaths],
    mountedSurfaces,
    ...(anchor.file.record.lifecycle ? { lifecycle: anchor.file.record.lifecycle.state } : {}),
    featureGate: 'unknown',
    summary: reachability === 'reachable'
      ? 'The path is statically reachable from a configured entrypoint; runtime activation was not observed.'
      : reachability === 'unreachable'
        ? 'The path is outside the configured static closure; dynamic and runtime activation remain possible.'
        : 'No complete configured static reachability closure was available for this finding.',
    limitations: [
      'Static source evidence only; runtime deployment, traffic, data occupancy, and user impact were not observed.'
    ]
  };
}

function findingCategory(kind: OperationalFindingKind): FindingRecord['category'] {
  if (kind === 'review-inventory') return 'review-inventory';
  if (kind === 'latent-hazard') return 'latent-hazard';
  return 'operational-defect';
}

function mechanismFromPatternMaterial(value: unknown): string | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const mechanism = (value as Record<string, unknown>).mechanism;
  return typeof mechanism === 'string' && mechanism.length > 0 ? mechanism : undefined;
}

function mappingContextFor(mapping: PathMap): FindingMappingContext {
  return {
    id: `mapping-context:${stableHash(mapping.contextId).slice(0, 24)}`,
    composePath: mapping.composePath,
    service: mapping.service,
    sourceKind: mapping.sourceKind,
    hostRoot: mapping.hostRoot || '.',
    containerRoot: mapping.containerRoot,
    ...(mapping.buildContext !== undefined ? { buildContext: mapping.buildContext || '.' } : {}),
    ...(mapping.dockerfile !== undefined ? { dockerfile: mapping.dockerfile } : {}),
    ...(mapping.workingDirectory !== undefined ? { workingDirectory: mapping.workingDirectory } : {})
  };
}

function mappingContextDescription(description: string, count: number): string {
  return `${description} Atlas observed this source defect under ${count} distinct static mapping context(s); ` +
    'the mappingContexts field enumerates them deterministically because they share one source fix.';
}

function orderedMappingContexts(values: FindingMappingContext[]): FindingMappingContext[] {
  return [...new Map(values.map((value) => [canonicalJson(value), value])).values()]
    .sort((left, right) => compareCanonicalText(canonicalJson(left), canonicalJson(right)));
}

function orderedEvidence(values: EvidenceReference[]): EvidenceReference[] {
  return [...new Map(values.map((value) => [canonicalJson(value), value])).values()]
    .sort((left, right) => compareCanonicalText(canonicalJson(left), canonicalJson(right)));
}

function addFinding(
  state: AnalysisState,
  ruleId: OperationalRuleId,
  primary: Anchor,
  options: FindingOptions
): void {
  const related = [...(options.related ?? [])]
    .filter((entry) => entry.file.record.path !== primary.file.record.path || entry.start !== primary.start)
    .sort((left, right) => compareCanonicalText(left.file.record.path, right.file.record.path) || left.start - right.start);
  const relatedPaths = [...new Set(related.map((entry) => entry.file.record.path))].sort(compareCanonicalText);
  const primaryLocation = location(primary);
  const mechanism = options.mechanism ?? mechanismFromPatternMaterial(options.patternMaterial);
  const patternKey = `${ruleId}:${stableHash(options.mappingContext ? {
    kind: options.kind,
    mechanism,
    anchor: { path: primary.file.record.path, line: primaryLocation.line }
  } : {
    kind: options.kind,
    signals: [...options.signals].sort(compareCanonicalText),
    material: patternIdentityMaterial(options.patternMaterial)
  }).slice(0, 20)}`;
  const id = `finding:${stableHash(options.mappingContext ? {
    producer: PRODUCER,
    version: OPERATIONAL_RISK_ANALYSIS_VERSION,
    ruleId,
    patternKey,
    path: primary.file.record.path,
    line: primaryLocation.line
  } : {
    producer: PRODUCER,
    version: OPERATIONAL_RISK_ANALYSIS_VERSION,
    ruleId,
    patternKey,
    path: primary.file.record.path,
    location: primaryLocation,
    relatedPaths,
    signals: [...options.signals].sort(compareCanonicalText)
  }).slice(0, 24)}`;
  if (options.mappingContext) {
    const existing = state.findings.find((finding) => finding.id === id);
    if (existing) {
      const contexts = orderedMappingContexts([...(existing.mappingContexts ?? []), options.mappingContext]);
      existing.mappingContexts = contexts;
      existing.title = `${options.title} (${contexts.length} mapping context${contexts.length === 1 ? '' : 's'})`;
      existing.description = mappingContextDescription(options.description, contexts.length);
      existing.relatedPaths = [...new Set([...existing.relatedPaths, ...relatedPaths])].sort(compareCanonicalText);
      existing.signals = [...new Set([...existing.signals, ...options.signals])].sort(compareCanonicalText);
      existing.evidence = orderedEvidence([
        ...existing.evidence,
        evidence(primary, 'source-anchored-operational-risk'),
        ...related.map((entry) => evidence(entry, 'corroborating-source-anchored-operational-risk'))
      ]);
      addObservation(state, ruleId, 'detected', primary, { findingId: id, patternKey });
      return;
    }
  }
  const mappingContexts = options.mappingContext ? [options.mappingContext] : undefined;
  const record: FindingRecord = {
    schemaVersion: SCHEMA_VERSION,
    id,
    category: findingCategory(options.kind),
    ruleId,
    status: 'candidate',
    severity: options.severity,
    confidence: options.confidence,
    title: options.mappingContext ? `${options.title} (1 mapping context)` : options.title,
    description: options.mappingContext ? mappingContextDescription(options.description, 1) : options.description,
    path: primary.file.record.path,
    location: primaryLocation,
    relatedPaths,
    signals: [...new Set(options.signals)].sort(compareCanonicalText),
    evidence: [
      evidence(primary, 'source-anchored-operational-risk'),
      ...related.map((entry) => evidence(entry, 'corroborating-source-anchored-operational-risk'))
    ],
    nextValidation: options.nextValidation,
    ...(mechanism ? { mechanism } : {}),
    ...(mappingContexts ? { mappingContexts } : {})
  };
  const finding = Object.assign(record, {
    kind: options.kind,
    patternKey,
    instanceCount: 1 as const,
    impactContext: impactContext(state, primary)
  }) as OperationalFindingRecord;
  state.findings.push(finding);
  addObservation(state, ruleId, 'detected', primary, { findingId: id, patternKey });
}

function addObservation(
  state: AnalysisState,
  ruleId: OperationalRuleId,
  observationState: OperationalObservation['state'],
  anchor: Anchor,
  material: unknown
): void {
  const position = location(anchor);
  const fingerprint = stableHash({ ruleId, material });
  state.observations.push({
    schemaVersion: SCHEMA_VERSION,
    id: `observation:${stableHash({ ruleId, observationState, path: anchor.file.record.path, position, fingerprint }).slice(0, 24)}`,
    ruleId,
    state: observationState,
    path: anchor.file.record.path,
    location: position,
    fingerprint,
    evidence: evidence(anchor, observationState === 'detected' ? 'detected-static-pattern' : 'static-analysis-uncertainty')
  });
}

function addDiagnostic(
  state: AnalysisState,
  ruleId: OperationalRuleId,
  code: string,
  message: string,
  anchor: Anchor,
  material: unknown
): void {
  const position = location(anchor);
  state.diagnostics.push({
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${stableHash({ producer: PRODUCER, version: OPERATIONAL_RISK_ANALYSIS_VERSION, code, path: anchor.file.record.path, position, material }).slice(0, 24)}`,
    code,
    severity: 'info',
    message,
    path: anchor.file.record.path,
    location: position,
    evidence: evidence(anchor, 'unsupported-or-incomplete-operational-pattern')
  });
  addObservation(state, ruleId, 'uncertain', anchor, { code, material });
}

function addInputDiagnostic(
  state: AnalysisState,
  ruleId: OperationalRuleId,
  code: string,
  message: string,
  anchor: Anchor | undefined,
  material: unknown
): void {
  if (anchor) {
    addDiagnostic(state, ruleId, code, message, anchor, material);
    return;
  }
  state.diagnostics.push({
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${stableHash({ producer: PRODUCER, version: OPERATIONAL_RISK_ANALYSIS_VERSION, code, material }).slice(0, 24)}`,
    code,
    severity: 'info',
    message,
    evidence: {
      level: 1,
      producer: PRODUCER,
      producerVersion: OPERATIONAL_RISK_ANALYSIS_VERSION,
      basis: 'unsupported-or-incomplete-operational-pattern'
    }
  });
}

function parseScriptFiles(files: AnalysisFile[]): ParsedFile[] {
  return files
    .filter((file) => SCRIPT_EXTENSIONS.test(file.record.path) || /^(?:javascript|typescript)/u.test(file.record.language))
    .flatMap((file) => {
      const source = file.content.toString('utf8');
      const parsedSource = parseBoundedTypeScript(file.record.path, source, scriptKind(file.record.path));
      return parsedSource.state === 'ready' ? [{
        file,
        source,
        sourceFile: parsedSource.sourceFile
      }] : [];
    })
    .map((entry) => ({
      ...entry,
      parseDiagnostics: (entry.sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? []
    }))
    .sort((left, right) => compareCanonicalText(left.file.record.path, right.file.record.path));
}

function walk(node: ts.Node, visit: (node: ts.Node) => void): void {
  visit(node);
  node.forEachChild((child) => walk(child, visit));
}

function containingScope(node: ts.Node): ts.Node {
  let current: ts.Node = node;
  while (current.parent && !ts.isFunctionLike(current.parent) && !ts.isSourceFile(current.parent)) current = current.parent;
  return current.parent ?? current;
}

function bindingIdentifiers(name: ts.BindingName): ts.Identifier[] {
  if (ts.isIdentifier(name)) return [name];
  return name.elements.flatMap((element) => ts.isOmittedExpression(element) ? [] : bindingIdentifiers(element.name));
}

function lexicalBindingsFor(parsed: ParsedFile): Map<string, LexicalBinding[]> {
  const bindings = new Map<string, LexicalBinding[]>();
  const add = (binding: LexicalBinding): void => {
    const current = bindings.get(binding.name) ?? [];
    current.push(binding);
    bindings.set(binding.name, current);
  };
  walk(parsed.sourceFile, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier) && node.importClause) {
      if (node.importClause.name) add({
        name: node.importClause.name.text,
        nameNode: node.importClause.name,
        declaration: node.importClause,
        scope: parsed.sourceFile,
        importSpecifier: node.moduleSpecifier.text,
        importedName: 'default'
      });
      const named = node.importClause.namedBindings;
      if (named && ts.isNamespaceImport(named)) add({
        name: named.name.text,
        nameNode: named.name,
        declaration: named,
        scope: parsed.sourceFile,
        importSpecifier: node.moduleSpecifier.text,
        importedName: '*'
      });
      if (named && ts.isNamedImports(named)) {
        for (const element of named.elements) add({
          name: element.name.text,
          nameNode: element.name,
          declaration: element,
          scope: parsed.sourceFile,
          importSpecifier: node.moduleSpecifier.text,
          importedName: element.propertyName?.text ?? element.name.text
        });
      }
      return;
    }
    if (ts.isFunctionDeclaration(node) && node.name) add({
      name: node.name.text,
      nameNode: node.name,
      declaration: node,
      scope: lexicalDeclarationContainer(node)
    });
    if (ts.isFunctionExpression(node) && node.name) add({
      name: node.name.text,
      nameNode: node.name,
      declaration: node,
      scope: node
    });
    if (ts.isClassDeclaration(node) && node.name) add({
      name: node.name.text,
      nameNode: node.name,
      declaration: node,
      scope: lexicalDeclarationContainer(node)
    });
    if (ts.isClassExpression(node) && node.name) add({
      name: node.name.text,
      nameNode: node.name,
      declaration: node,
      scope: node
    });
    if (ts.isParameter(node)) {
      for (const nameNode of bindingIdentifiers(node.name)) add({
        name: nameNode.text,
        nameNode,
        declaration: node,
        scope: node.parent
      });
    }
    if (ts.isCatchClause(node) && node.variableDeclaration) {
      for (const nameNode of bindingIdentifiers(node.variableDeclaration.name)) add({
        name: nameNode.text,
        nameNode,
        declaration: node.variableDeclaration,
        scope: node.block
      });
    }
    if (!ts.isVariableDeclaration(node) || !ts.isVariableDeclarationList(node.parent)) return;
    const scope = (node.parent.flags & ts.NodeFlags.BlockScoped) !== 0
      ? lexicalDeclarationContainer(node)
      : containingScope(node);
    const initializer = node.initializer && unwrapExpression(node.initializer);
    const required = initializer && ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression) &&
      initializer.expression.text === 'require' && initializer.arguments[0] && ts.isStringLiteralLike(initializer.arguments[0])
      ? initializer.arguments[0].text
      : undefined;
    for (const nameNode of bindingIdentifiers(node.name)) {
      let importedName: string | undefined;
      if (required) {
        if (ts.isIdentifier(node.name)) importedName = '*';
        else {
          let binding: ts.Node = nameNode;
          while (binding.parent && !ts.isBindingElement(binding) && binding.parent !== node) binding = binding.parent;
          if (ts.isBindingElement(binding)) importedName = propertyName(binding.propertyName) ?? nameNode.text;
        }
      }
      add({
        name: nameNode.text,
        nameNode,
        declaration: node,
        scope,
        ...(required && importedName ? { importSpecifier: required, importedName } : {})
      });
    }
  });
  return bindings;
}

function lexicalScopeDistance(reference: ts.Node, scope: ts.Node): number | undefined {
  let distance = 0;
  let current: ts.Node | undefined = reference;
  while (current) {
    if (current === scope) return distance;
    current = current.parent;
    distance += 1;
  }
  return undefined;
}

function resolvedLexicalBinding(
  reference: ts.Identifier,
  bindings: LexicalBindingIndex
): LexicalBinding | undefined {
  const visible = (bindings.get(reference.text) ?? []).flatMap((binding) => {
    const distance = lexicalScopeDistance(reference, binding.scope);
    return distance === undefined ? [] : [{ binding, distance }];
  });
  const minimum = Math.min(...visible.map((entry) => entry.distance));
  if (!Number.isFinite(minimum)) return undefined;
  const nearest = visible.filter((entry) => entry.distance === minimum);
  return nearest.length === 1 ? nearest[0]!.binding : undefined;
}

function lexicalBindingKey(parsed: ParsedFile, binding: LexicalBinding): string {
  return `${parsed.file.record.path}#binding:${binding.nameNode.getStart(parsed.sourceFile)}`;
}

function propertyName(node: ts.PropertyName | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isIdentifier(node) || ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return node.text;
  return undefined;
}

function callName(expression: ts.LeftHandSideExpression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return undefined;
}

function literalStrings(node: ts.Expression): { values: string[]; complete: boolean } | undefined {
  const value = unwrapExpression(node);
  if (!ts.isArrayLiteralExpression(value)) return undefined;
  const values: string[] = [];
  let complete = true;
  for (const element of value.elements) {
    if (ts.isStringLiteralLike(element)) values.push(element.text.normalize('NFC'));
    else complete = false;
  }
  return { values, complete };
}

function computeReachability(
  files: AnalysisFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile | undefined
): { reachablePaths?: Set<string>; entrypointPaths: string[] } {
  if (!profile || profile.entrypoints.length === 0) return { entrypointPaths: [] };
  const entrypointPaths = files
    .filter((file) => matchesAnyGlob(file.record.path, profile.entrypoints))
    .map((file) => file.record.path)
    .sort(compareCanonicalText);
  if (entrypointPaths.length === 0) return { entrypointPaths: [] };
  const outgoing = new Map<string, string[]>();
  for (const relationship of relationships) {
    if (relationship.resolution !== 'resolved' || relationship.typeOnly || !relationship.toPath) continue;
    const current = outgoing.get(relationship.fromPath) ?? [];
    current.push(relationship.toPath);
    outgoing.set(relationship.fromPath, current);
  }
  const reachablePaths = new Set<string>();
  const queue = [...entrypointPaths];
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (reachablePaths.has(current)) continue;
    reachablePaths.add(current);
    for (const target of outgoing.get(current) ?? []) if (!reachablePaths.has(target)) queue.push(target);
  }
  return { reachablePaths, entrypointPaths };
}

function isLoggingCall(node: ts.Identifier): boolean {
  const call = node.parent;
  if (!ts.isCallExpression(call)) return false;
  const expression = call.expression;
  return ts.isPropertyAccessExpression(expression) && /^(?:log|info|debug|warn|error)$/u.test(expression.name.text);
}

function isEnforcingUse(node: ts.Identifier): boolean {
  let current: ts.Node = node;
  for (let depth = 0; depth < 4 && current.parent; depth += 1) {
    const parent = current.parent;
    if (ts.isIfStatement(parent) || ts.isConditionalExpression(parent) || ts.isWhileStatement(parent) || ts.isDoStatement(parent)) return true;
    if (ts.isReturnStatement(parent) || ts.isThrowStatement(parent)) return true;
    if (ts.isBinaryExpression(parent)) {
      const kind = parent.operatorToken.kind;
      if (
        kind === ts.SyntaxKind.EqualsEqualsToken || kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        kind === ts.SyntaxKind.ExclamationEqualsToken || kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
        kind === ts.SyntaxKind.GreaterThanToken || kind === ts.SyntaxKind.GreaterThanEqualsToken ||
        kind === ts.SyntaxKind.LessThanToken || kind === ts.SyntaxKind.LessThanEqualsToken
      ) return true;
    }
    if (ts.isCallExpression(parent)) {
      const text = parent.expression.getText();
      if (/(?:^|\.)(?:assert|exit|fail|reject)$/u.test(text)) return true;
      return false;
    }
    current = parent;
  }
  return false;
}

function detectSilentEmpty(files: AnalysisFile[], parsedFiles: ParsedFile[], state: AnalysisState): void {
  const flagPattern = /--passWithNoTests\b|--allow-no-tests\b|--no-error-on-unmatched-pattern\b/giu;
  for (const file of files) {
    if (file.record.kind === 'documentation' || DISABLED_WORKFLOW_ARTIFACT.test(file.record.path)) continue;
    const source = file.content.toString('utf8');
    for (const match of source.matchAll(flagPattern)) {
      const anchor = { file, start: match.index, end: match.index + match[0].length };
      addFinding(state, OPERATIONAL_RULE_IDS.silentEmpty, anchor, {
        kind: 'defect-candidate', severity: 'high', confidence: 'high',
        title: 'A verification command can report success without observing work',
        description: 'A supported command option permits an empty or non-running verification result to exit successfully.',
        signals: ['zero-observation-success-enabled'],
        nextValidation: 'Remove the permissive option or assert a minimum discovered and executed count before accepting success.',
        patternMaterial: { mechanism: 'zero-observation-success' }
      });
    }
    const lines = source.split(/\r?\n/u);
    const persistentShellScope = file.record.language === 'shell' || /\.(?:ba|z|k)?sh$/iu.test(file.record.path);
    let pipefailActive = false;
    let offset = 0;
    for (const line of lines) {
      const enablesPipefail = /(?:set\s+(?:-[A-Za-z]*o\s+pipefail|-euo\s+pipefail)|bash\s+-o\s+pipefail)/u.test(line);
      if (persistentShellScope && enablesPipefail) pipefailActive = true;
      const masked = /\|\s*(?:tail|head|grep\s+-c|tee|sort)\b[^;\r\n]*(?:&&|\|\|)/u.exec(line) ??
        /\bif\s+[^;\r\n]*\|\s*(?:tail|head|grep\s+-c|tee|sort)\b[^;\r\n]*;?\s*then\b/u.exec(line);
      const protectedPipeline = pipefailActive || enablesPipefail || /\bPIPESTATUS\b/u.test(line);
      if (masked?.index !== undefined && !protectedPipeline) {
        const anchor = { file, start: offset + masked.index, end: offset + masked.index + masked[0].length };
        addFinding(state, OPERATIONAL_RULE_IDS.silentEmpty, anchor, {
          kind: 'defect-candidate', severity: 'high', confidence: 'high',
          title: 'A shell gate tests the formatter at the end of a pipeline',
          description: 'Without pipefail or explicit pipeline-status handling in this shell scope, the conditional observes the final formatting command rather than the checker.',
          signals: ['conditional-uses-terminal-pipeline-status', 'pipefail-not-observed'],
          nextValidation: 'Enable pipefail in the same shell scope or capture and test the checker process status explicitly.',
          patternMaterial: { mechanism: 'pipeline-status-mask' }
        });
      }
      offset += line.length + 1;
    }
  }

  for (const parsed of parsedFiles) {
    walk(parsed.sourceFile, (node) => {
      if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
      const name = node.name.text;
      if (!/(?:count|matches|offenders|violations|failures|errors)$/iu.test(name)) return;
      const initializer = node.initializer.getText(parsed.sourceFile);
      if (!/(?:\.length\b|\bcount\s*\()/u.test(initializer)) return;
      const scope = containingScope(node);
      const uses: ts.Identifier[] = [];
      walk(scope, (candidate) => {
        if (ts.isIdentifier(candidate) && candidate.text === name && candidate !== node.name) uses.push(candidate);
      });
      if (uses.length === 0 || !uses.every(isLoggingCall) || uses.some(isEnforcingUse)) return;
      const anchor = nodeAnchor(parsed, node);
      addFinding(state, OPERATIONAL_RULE_IDS.silentEmpty, anchor, {
        kind: 'defect-candidate', severity: 'high', confidence: 'high',
        title: 'An observed count is reported but does not enforce the gate',
        description: 'The count is only consumed by logging and is not compared, asserted, returned, thrown, or used to set an unsuccessful exit status.',
        signals: ['observation-count-only-logged', 'no-enforcement-use-observed'],
        nextValidation: 'Define the acceptable count and make the command fail when the invariant is violated.',
        patternMaterial: { mechanism: 'non-enforced-count' }
      });
    });
  }
}

function portableRoot(value: string): string {
  const normalized = value.trim().replace(/^['"]|['"]$/gu, '').replace(/\\/gu, '/').replace(/^\.\//u, '');
  return normalized === '.' ? '' : normalized.replace(/\/$/u, '');
}

interface ComposeLine {
  text: string;
  trimmed: string;
  indent: number;
  offset: number;
}

function composeLines(file: AnalysisFile): ComposeLine[] {
  let offset = 0;
  return file.content.toString('utf8').split(/\r?\n/u).map((text) => {
    const line = {
      text,
      trimmed: text.trim(),
      indent: /^\s*/u.exec(text)?.[0].replace(/\t/gu, '  ').length ?? 0,
      offset
    };
    offset += text.length + 1;
    return line;
  });
}

function composeScalar(value: string): string {
  return value.replace(/\s+#.*$/u, '').trim().replace(/^(['"])(.*)\1$/u, '$2').trim();
}

function composeShortBind(
  value: string,
  file: AnalysisFile,
  line: ComposeLine
): ComposeServiceContext['volumes'][number] | undefined {
  const scalar = composeScalar(value.replace(/^-\s*/u, ''));
  if (scalar.includes('${')) {
    if (/:(?:\s*['"])?\//u.test(scalar)) {
      return {
        hostRoot: `\0dynamic:${scalar}`,
        containerRoot: '',
        anchor: { file, start: line.offset, end: line.offset + line.text.length }
      };
    }
    return undefined;
  }
  // In Compose short syntax, only ./ and ../ sources are unambiguously host
  // binds. Bare names are named volumes and a single absolute path is an
  // anonymous container volume; neither describes a repository mapping.
  const mapping = /^(\.{1,2}(?:\/[^:'"\s]+)*)\s*:\s*(\/[^:'"\s]+)(?::[^\s#]+)?$/u.exec(scalar);
  if (!mapping) return undefined;
  return {
    hostRoot: mapping[1]!,
    containerRoot: path.posix.normalize(mapping[2]!),
    anchor: { file, start: line.offset, end: line.offset + line.text.length }
  };
}

function composeServiceContexts(file: AnalysisFile): ComposeServiceContext[] {
  const lines = composeLines(file);
  const servicesIndex = lines.findIndex((line) => /^services\s*:\s*(?:#.*)?$/u.test(line.trimmed));
  if (servicesIndex < 0) return [];
  const servicesIndent = lines[servicesIndex]!.indent;
  const boundaryIndex = lines.findIndex((line, index) =>
    index > servicesIndex && line.trimmed.length > 0 && !line.trimmed.startsWith('#') && line.indent <= servicesIndent);
  const servicesEnd = boundaryIndex < 0 ? lines.length : boundaryIndex;
  const candidateLines = lines.slice(servicesIndex + 1, servicesEnd)
    .filter((line) => line.trimmed.length > 0 && !line.trimmed.startsWith('#') && line.indent > servicesIndent);
  const serviceIndent = candidateLines[0]?.indent;
  if (serviceIndent === undefined) return [];
  const headers = lines
    .map((line, index) => ({ line, index }))
    .filter(({ line, index }) => index > servicesIndex && index < servicesEnd &&
      line.indent === serviceIndent && /^[A-Za-z0-9_.-]+\s*:\s*(?:#.*)?$/u.test(line.trimmed));
  const contexts: ComposeServiceContext[] = [];
  for (let headerIndex = 0; headerIndex < headers.length; headerIndex += 1) {
    const header = headers[headerIndex]!;
    const end = headers[headerIndex + 1]?.index ?? servicesEnd;
    const block = lines.slice(header.index + 1, end);
    const propertyIndent = block.find((line) =>
      line.trimmed.length > 0 && !line.trimmed.startsWith('#') && line.indent > serviceIndent)?.indent;
    const service = header.line.trimmed.replace(/\s*:\s*(?:#.*)?$/u, '');
    const context: ComposeServiceContext = {
      composeFile: file,
      composeDirectory: path.posix.dirname(file.record.path),
      service,
      anchor: { file, start: header.line.offset, end: header.line.offset + header.line.text.length },
      selectors: [],
      volumes: []
    };
    for (let index = 0; index < block.length; index += 1) {
      const line = block[index]!;
      if (propertyIndent === undefined || line.indent !== propertyIndent) continue;
      const scalarBuild = /^build\s*:\s*(.+)$/u.exec(line.trimmed);
      if (scalarBuild && !/^build\s*:\s*(?:\{|\[)/u.test(line.trimmed)) {
        context.buildContext = composeScalar(scalarBuild[1]!);
      }
      if (/^build\s*:\s*(?:#.*)?$/u.test(line.trimmed)) {
        for (const nested of block.slice(index + 1)) {
          if (nested.trimmed.length === 0 || nested.trimmed.startsWith('#')) continue;
          if (nested.indent <= line.indent) break;
          const buildContext = /^context\s*:\s*(.+)$/u.exec(nested.trimmed);
          const dockerfile = /^dockerfile\s*:\s*(.+)$/u.exec(nested.trimmed);
          const target = /^target\s*:\s*(.+)$/u.exec(nested.trimmed);
          if (buildContext) context.buildContext = composeScalar(buildContext[1]!);
          if (dockerfile) context.dockerfile = composeScalar(dockerfile[1]!);
          if (target) context.buildTarget = composeScalar(target[1]!);
        }
      }
      const workingDirectory = /^working_dir\s*:\s*['"]?(\/[^'"\s#]+)['"]?/u.exec(line.trimmed);
      if (workingDirectory) context.workingDirectory = path.posix.normalize(workingDirectory[1]!);
      const selector = /^(?:command|entrypoint)\s*:\s*(.*)$/u.exec(line.trimmed);
      if (selector) {
        context.selectors.push(selector[1]!);
        for (const nested of block.slice(index + 1)) {
          if (nested.trimmed.length === 0 || nested.trimmed.startsWith('#')) continue;
          if (nested.indent <= line.indent) break;
          context.selectors.push(nested.trimmed);
        }
      }
      const inlineVolumes = /^volumes\s*:\s*(.+)$/u.exec(line.trimmed);
      if (inlineVolumes) {
        for (const item of inlineVolumes[1]!.matchAll(/['"]([^'"]+)['"]/gu)) {
          const volume = composeShortBind(item[1]!, file, line);
          if (volume) context.volumes.push(volume);
        }
      }
      if (!/^volumes\s*:\s*(?:#.*)?$/u.test(line.trimmed)) continue;
      const volumeLines = block.slice(index + 1);
      for (let volumeIndex = 0; volumeIndex < volumeLines.length; volumeIndex += 1) {
        const nested = volumeLines[volumeIndex]!;
        if (nested.trimmed.length === 0 || nested.trimmed.startsWith('#')) continue;
        if (nested.indent <= line.indent) break;
        if (!nested.trimmed.startsWith('-')) continue;
        const longType = /^-\s*type\s*:\s*bind\s*(?:#.*)?$/u.test(nested.trimmed);
        if (longType) {
          let source: string | undefined;
          let target: string | undefined;
          for (const field of volumeLines.slice(volumeIndex + 1)) {
            if (field.trimmed.length === 0 || field.trimmed.startsWith('#')) continue;
            if (field.indent <= nested.indent) break;
            const sourceMatch = /^(?:source|src)\s*:\s*(.+)$/u.exec(field.trimmed);
            const targetMatch = /^(?:target|dst|destination)\s*:\s*(.+)$/u.exec(field.trimmed);
            if (sourceMatch) source = composeScalar(sourceMatch[1]!);
            if (targetMatch) target = composeScalar(targetMatch[1]!);
          }
          if (source && target?.startsWith('/')) {
            const volume = composeShortBind(`- ${source}:${target}`, file, nested);
            if (volume) context.volumes.push(volume);
          }
          continue;
        }
        const volume = composeShortBind(nested.trimmed, file, nested);
        if (volume) context.volumes.push(volume);
      }
    }
    contexts.push(context);
  }
  return contexts;
}

function repositoryRelativePath(base: string, value: string): string | undefined {
  const normalized = portableRoot(value);
  if (/^(?:\/|[A-Za-z]:[\\/])/u.test(value.trim())) return undefined;
  const resolved = path.posix.normalize(path.posix.join(base === '.' ? '' : base, normalized));
  if (resolved === '..' || resolved.startsWith('../')) return undefined;
  return resolved === '.' ? '' : resolved;
}

interface DockerLine {
  text: string;
  offset: number;
}

interface DockerStage {
  name?: string;
  base: string;
  lines: DockerLine[];
}

function dockerStages(file: AnalysisFile): DockerStage[] {
  const stages: DockerStage[] = [];
  let current: DockerStage | undefined;
  let offset = 0;
  for (const text of file.content.toString('utf8').split(/\r?\n/u)) {
    const from = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*(?:#.*)?$/iu.exec(text);
    if (from) {
      current = {
        base: from[1]!,
        ...(from[2] ? { name: from[2]!.toLowerCase() } : {}),
        lines: []
      };
      stages.push(current);
    } else if (current) {
      current.lines.push({ text, offset });
    }
    offset += text.length + 1;
  }
  return stages;
}

function effectiveDockerStageIndexes(stages: DockerStage[], target: string | undefined): Set<number> | undefined {
  if (stages.length === 0) return new Set();
  const targetIndex = target === undefined
    ? stages.length - 1
    : stages.findIndex((stage) => stage.name === target.toLowerCase());
  if (targetIndex < 0) return undefined;
  const selected = new Set<number>();
  const include = (index: number): void => {
    if (selected.has(index)) return;
    selected.add(index);
    const base = stages[index]!.base.toLowerCase();
    const parent = stages.findIndex((stage, candidate) => candidate < index && stage.name === base);
    if (parent >= 0) include(parent);
  };
  include(targetIndex);
  return selected;
}

type DockerCopy =
  | { state: 'host-copy'; source: string; destination: string; start: number; length: number }
  | { state: 'stage-copy' }
  | { state: 'unsupported' }
  | { state: 'none' };

function dockerCopy(line: DockerLine): DockerCopy {
  const match = /^\s*(?:COPY|ADD)\s+(.+)$/iu.exec(line.text);
  if (!match) return { state: 'none' };
  let body = match[1]!.replace(/\s+#.*$/u, '').trim();
  let stageCopy = false;
  while (body.startsWith('--')) {
    const flag = /^(--[^\s]+)\s*/u.exec(body);
    if (!flag) return { state: 'unsupported' };
    if (/^--from=/iu.test(flag[1]!)) stageCopy = true;
    body = body.slice(flag[0].length);
  }
  if (stageCopy) return { state: 'stage-copy' };
  let values: string[];
  if (body.startsWith('[')) {
    try {
      const parsed = JSON.parse(body) as unknown;
      if (!Array.isArray(parsed) || !parsed.every((entry) => typeof entry === 'string')) return { state: 'unsupported' };
      values = parsed;
    } catch {
      return { state: 'unsupported' };
    }
  } else {
    values = body.split(/\s+/u);
  }
  if (values.length !== 2 || values.some((value) => value.includes('$'))) return { state: 'unsupported' };
  return {
    state: 'host-copy',
    source: values[0]!,
    destination: values[1]!,
    start: line.offset + (match.index ?? 0),
    length: match[0].length
  };
}

function parseBoundContainerMaps(
  files: AnalysisFile[],
  state: AnalysisState,
  availableFiles: AnalysisFile[] = files
): PathMap[] {
  const maps: PathMap[] = [];
  const contexts = files
    .filter((file) => /^(?:docker-)?compose(?:\.[^.]+)*\.ya?ml$/u.test(path.posix.basename(file.record.path.toLowerCase())))
    .flatMap(composeServiceContexts);
  const filesByPath = new Map(availableFiles.map((file) => [file.record.path, file]));
  for (const context of contexts) {
    const buildRoot = context.buildContext === undefined
      ? undefined
      : repositoryRelativePath(context.composeDirectory, context.buildContext);
    const dockerfilePath = buildRoot === undefined
      ? undefined
      : repositoryRelativePath(buildRoot, context.dockerfile ?? 'Dockerfile');
    const contextId = `${context.composeFile.record.path}#${context.service}#${buildRoot ?? 'no-build'}#${dockerfilePath ?? 'no-dockerfile'}#${context.buildTarget ?? 'default-target'}`;
    for (const volume of context.volumes) {
      if (volume.hostRoot.startsWith('\0dynamic:')) {
        addDiagnostic(
          state,
          OPERATIONAL_RULE_IDS.hostContainerPath,
          'OPERATIONAL_CONTAINER_MAPPING_UNSUPPORTED',
          'A dynamic repository bind mount could not be resolved statically.',
          volume.anchor,
          { mechanism: 'dynamic-repository-bind', context: stableHash(contextId) }
        );
        continue;
      }
      const bindSource = /^(?:\.{1,2})(?:\/|$)/u.test(volume.hostRoot) || volume.hostRoot === '.';
      const hostRoot = bindSource ? repositoryRelativePath(context.composeDirectory, volume.hostRoot) : undefined;
      if (hostRoot === undefined) continue;
      maps.push({
        hostRoot,
        containerRoot: volume.containerRoot,
        sourceKind: 'bind-mount',
        contextId,
        composePath: context.composeFile.record.path,
        service: context.service,
        ...(buildRoot !== undefined ? { buildContext: buildRoot } : {}),
        ...(dockerfilePath !== undefined ? { dockerfile: dockerfilePath } : {}),
        ...(context.workingDirectory !== undefined ? { workingDirectory: context.workingDirectory } : {}),
        selectors: context.selectors,
        anchor: volume.anchor
      });
    }
    if (context.buildContext === undefined) continue;
    if (buildRoot === undefined || dockerfilePath === undefined || context.buildContext.includes('${')) {
      addDiagnostic(
        state,
        OPERATIONAL_RULE_IDS.hostContainerPath,
        'OPERATIONAL_DOCKER_BUILD_CONTEXT_UNKNOWN',
        'A Compose service build context could not be resolved statically, so Docker COPY paths were not used.',
        context.anchor,
        { mechanism: 'docker-build-context-unknown', context: stableHash(contextId) }
      );
      continue;
    }
    const dockerfile = filesByPath.get(dockerfilePath);
    if (!dockerfile) {
      addDiagnostic(
        state,
        OPERATIONAL_RULE_IDS.hostContainerPath,
        'OPERATIONAL_DOCKERFILE_UNRESOLVED',
        'A Compose build refers to a Dockerfile that was not available for analysis.',
        context.anchor,
        { mechanism: 'dockerfile-unresolved', context: stableHash(contextId) }
      );
      continue;
    }
    if (!isOperationalInput(dockerfile)) continue;
    const stages = dockerStages(dockerfile);
    const selectedStages = effectiveDockerStageIndexes(stages, context.buildTarget);
    if (selectedStages === undefined) {
      addDiagnostic(
        state,
        OPERATIONAL_RULE_IDS.hostContainerPath,
        'OPERATIONAL_DOCKER_TARGET_UNRESOLVED',
        'A Compose build target does not name a stage in its Dockerfile, so Docker COPY paths were not used.',
        context.anchor,
        { mechanism: 'docker-target-unresolved', context: stableHash(contextId) }
      );
      continue;
    }
    const stageWorkdirs = new Map<string, string>();
    const dockerSelectors: string[] = [];
    const selectedStageIndex = context.buildTarget === undefined
      ? stages.length - 1
      : stages.findIndex((stage) => stage.name === context.buildTarget!.toLowerCase());
    let selectedStageWorkingDirectory: string | undefined;
    for (let stageIndex = 0; stageIndex < stages.length; stageIndex += 1) {
      if (!selectedStages.has(stageIndex)) continue;
      const stage = stages[stageIndex]!;
      let workdir = stageWorkdirs.get(stage.base.toLowerCase()) ?? '/';
      for (const dockerLine of stage.lines) {
        const workdirMatch = /^\s*WORKDIR\s+([^\s#]+)\s*(?:#.*)?$/iu.exec(dockerLine.text);
        if (workdirMatch && !workdirMatch[1]!.includes('$')) {
          workdir = workdirMatch[1]!.startsWith('/')
            ? path.posix.normalize(workdirMatch[1]!)
            : path.posix.resolve(workdir, workdirMatch[1]!);
        }
        const runtime = /^\s*(?:CMD|ENTRYPOINT)\s+(.+)$/iu.exec(dockerLine.text);
        if (runtime) dockerSelectors.push(runtime[1]!);
        const copy = dockerCopy(dockerLine);
        if (copy.state === 'host-copy') {
          const hostRoot = repositoryRelativePath(buildRoot, copy.source);
          if (hostRoot !== undefined) {
            maps.push({
              hostRoot,
              containerRoot: copy.destination.startsWith('/')
                ? path.posix.normalize(copy.destination)
                : path.posix.resolve(workdir, copy.destination),
              sourceKind: 'docker-copy',
              contextId,
              composePath: context.composeFile.record.path,
              service: context.service,
              buildContext: buildRoot,
              dockerfile: dockerfilePath,
              selectors: context.selectors,
              anchor: { file: dockerfile, start: copy.start, end: copy.start + copy.length }
            });
          }
        } else if (copy.state === 'unsupported') {
          addDiagnostic(
            state,
            OPERATIONAL_RULE_IDS.hostContainerPath,
            'OPERATIONAL_DOCKER_COPY_UNSUPPORTED',
            'A dynamic or multi-source Docker copy in the selected target stage was not used for a path-divergence claim.',
            { file: dockerfile, start: dockerLine.offset, end: dockerLine.offset + dockerLine.text.length },
            { mechanism: 'unsupported-docker-copy', context: stableHash(contextId) }
          );
        }
      }
      if (stageIndex === selectedStageIndex) selectedStageWorkingDirectory = workdir;
      if (stage.name) stageWorkdirs.set(stage.name, workdir);
    }
    const effectiveWorkingDirectory = context.workingDirectory ?? selectedStageWorkingDirectory;
    if (effectiveWorkingDirectory !== undefined) {
      for (const mapping of maps.filter((entry) => entry.contextId === contextId)) {
        mapping.workingDirectory = effectiveWorkingDirectory;
      }
    }
    if (context.selectors.length === 0) context.selectors.push(...dockerSelectors);
  }
  return maps.sort((left, right) => compareCanonicalText(left.contextId, right.contextId) ||
    right.hostRoot.length - left.hostRoot.length || compareCanonicalText(left.sourceKind, right.sourceKind) ||
    compareCanonicalText(left.containerRoot, right.containerRoot));
}

function pathMatchesMap(filePath: string, mapping: PathMap): boolean {
  return mapping.hostRoot === '' || filePath === mapping.hostRoot || filePath.startsWith(`${mapping.hostRoot}/`);
}

function mappedContainerPath(filePath: string, mapping: PathMap): string {
  const suffix = mapping.hostRoot === ''
    ? filePath
    : filePath === mapping.hostRoot ? '' : filePath.slice(mapping.hostRoot.length + 1);
  return suffix ? path.posix.join(mapping.containerRoot, suffix) : mapping.containerRoot;
}

type BoundMapResolution =
  | { state: 'resolved'; mapping: PathMap }
  | { state: 'ambiguous'; mappings: PathMap[] }
  | { state: 'undefined' };

function resolveBoundMap(filePath: string, maps: PathMap[]): BoundMapResolution {
  const perContext: PathMap[] = [];
  for (const contextId of [...new Set(maps.map((mapping) => mapping.contextId))]) {
    const candidates = maps.filter((mapping) => mapping.contextId === contextId && pathMatchesMap(filePath, mapping));
    if (candidates.length === 0) continue;
    const longest = Math.max(...candidates.map((mapping) => mapping.hostRoot.length));
    const specific = candidates.filter((mapping) => mapping.hostRoot.length === longest);
    const binds = specific.filter((mapping) => mapping.sourceKind === 'bind-mount');
    const effective = binds.length > 0 ? binds : specific;
    if (new Set(effective.map((mapping) => mappedContainerPath(filePath, mapping))).size > 1) {
      return { state: 'ambiguous', mappings: effective };
    }
    // Runtime bind mounts overlay image-layer COPY content. Prefer the bind
    // explicitly when both describe the same host/container mapping.
    perContext.push(effective.sort((left, right) =>
      Number(left.sourceKind !== 'bind-mount') - Number(right.sourceKind !== 'bind-mount') ||
      compareCanonicalText(left.containerRoot, right.containerRoot))[0]!);
  }
  if (perContext.length === 0) return { state: 'undefined' };
  if (new Set(perContext.map((mapping) => mappedContainerPath(filePath, mapping))).size > 1) {
    return { state: 'ambiguous', mappings: perContext };
  }
  return { state: 'resolved', mapping: perContext.sort((left, right) =>
    Number(left.sourceKind !== 'bind-mount') - Number(right.sourceKind !== 'bind-mount') ||
    compareCanonicalText(left.contextId, right.contextId))[0]! };
}

function boundHostToContainer(filePath: string, maps: PathMap[]): string | undefined {
  const resolution = resolveBoundMap(filePath, maps);
  if (resolution.state !== 'resolved') return undefined;
  return mappedContainerPath(filePath, resolution.mapping);
}

function containerCommandSelection(
  filePath: string,
  mapping: PathMap
): ContainerCoverageRecord['selection'] | undefined {
  const relative = mapping.hostRoot === '' ? filePath : filePath.slice(mapping.hostRoot.length).replace(/^\//u, '');
  const candidates = [filePath, relative, path.posix.basename(filePath), path.posix.join(mapping.containerRoot, relative)]
    .filter((value) => value.length > 0)
    .map((value) => value.toLowerCase());
  for (const selector of mapping.selectors) {
    const normalized = selector.replace(/\\/gu, '/').toLowerCase();
    if (candidates.some((candidate) => normalized.includes(candidate))) return 'explicit-test-path';
    const command = normalized.replace(/[\[\]{},'"\-]+/gu, ' ').replace(/\s+/gu, ' ').trim();
    if (/(?:^|\s)(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test(?::[a-z0-9_.-]+)?|jest|vitest|node\s+test|playwright\s+test)(?:\s|$)/u.test(command)) {
      return 'broad-test-command';
    }
  }
  return undefined;
}

function isPathResolveCall(node: ts.CallExpression): boolean {
  return ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'resolve' &&
    ts.isIdentifier(node.expression.expression) && /^(?:path|nodePath|pathModule)$/u.test(node.expression.expression.text) &&
    node.arguments[0] !== undefined && ts.isIdentifier(node.arguments[0]) && node.arguments[0].text === '__dirname';
}

function isFilesystemLiteralCall(node: ts.CallExpression): boolean {
  const name = callName(node.expression) ?? '';
  if (!/^(?:glob|globSync|readdir|readdirSync|readFile|readFileSync|existsSync)$/u.test(name)) return false;
  if (ts.isPropertyAccessExpression(node.expression) && (!ts.isIdentifier(node.expression.expression) ||
    !/^(?:fs|nodeFs)$/u.test(node.expression.expression.text))) return false;
  return node.arguments[0] !== undefined && ts.isStringLiteralLike(node.arguments[0]);
}

function addContainerCoverage(
  state: AnalysisState,
  parsed: ParsedFile,
  mapping: PathMap,
  containerPath: string,
  selection: ContainerCoverageRecord['selection']
): void {
  const material = {
    composePath: mapping.composePath,
    service: mapping.service,
    ...(mapping.buildContext !== undefined ? { buildContext: mapping.buildContext } : {}),
    ...(mapping.dockerfile !== undefined ? { dockerfile: mapping.dockerfile } : {}),
    ...(mapping.workingDirectory !== undefined ? { workingDirectory: mapping.workingDirectory } : {}),
    hostRoot: mapping.hostRoot,
    containerRoot: mapping.containerRoot,
    sourcePath: parsed.file.record.path,
    containerPath,
    sourceKind: mapping.sourceKind,
    selection
  };
  const id = `container-coverage:${stableHash(material).slice(0, 24)}`;
  if (state.containerCoverage.some((entry) => entry.id === id)) return;
  state.containerCoverage.push({
    schemaVersion: SCHEMA_VERSION,
    id,
    ruleId: OPERATIONAL_RULE_IDS.hostContainerPath,
    ...material,
    evidence: evidence(mapping.anchor, 'resolved-container-test-path')
  });
}

function referencedRepositoryPaths(
  parsed: ParsedFile,
  filesByPath: ReadonlyMap<string, AnalysisFile>
): Array<{ referencedPath: string; anchor: Anchor }> {
  const references: Array<{ referencedPath: string; anchor: Anchor }> = [];
  walk(parsed.sourceFile, (node) => {
    if (!ts.isStringLiteralLike(node)) return;
    const referencedPath = portableRoot(node.text);
    if (!referencedPath.includes('/') || referencedPath === parsed.file.record.path || !filesByPath.has(referencedPath)) return;
    references.push({ referencedPath, anchor: nodeAnchor(parsed, node) });
  });
  return references.sort((left, right) => compareCanonicalText(left.referencedPath, right.referencedPath) ||
    left.anchor.start - right.anchor.start);
}

function detectBoundHostContainerPaths(
  parsedFiles: ParsedFile[],
  maps: PathMap[],
  files: AnalysisFile[],
  state: AnalysisState
): void {
  const mapsByContext = new Map<string, PathMap[]>();
  for (const mapping of maps) {
    const values = mapsByContext.get(mapping.contextId) ?? [];
    values.push(mapping);
    mapsByContext.set(mapping.contextId, values);
  }
  const filesByPath = new Map(files.map((file) => [file.record.path, file]));
  for (const parsed of parsedFiles) {
    const calls: ts.CallExpression[] = [];
    walk(parsed.sourceFile, (node) => {
      if (ts.isCallExpression(node) && (isPathResolveCall(node) || isFilesystemLiteralCall(node))) calls.push(node);
    });
    const isTest = parsed.file.record.kind === 'test' || TEST_PATH.test(parsed.file.record.path);
    for (const [contextId, contextMaps] of [...mapsByContext.entries()].sort((left, right) => compareCanonicalText(left[0], right[0]))) {
      const representative = contextMaps[0]!;
      const selection = isTest ? containerCommandSelection(parsed.file.record.path, representative) : undefined;
      if (isTest && selection === undefined) continue;
      if (isTest && !contextMaps.some((mapping) => pathMatchesMap(parsed.file.record.path, mapping))) continue;
      if (!isTest && !contextMaps.some((mapping) => pathMatchesMap(parsed.file.record.path, mapping))) continue;
      const resolution = resolveBoundMap(parsed.file.record.path, contextMaps);
      const sourceAnchor = calls[0] === undefined
        ? { file: parsed.file, start: 0, end: Math.max(1, Math.min(parsed.file.content.length, parsed.file.record.path.length)) }
        : nodeAnchor(parsed, calls[0]);
      if (resolution.state === 'ambiguous') {
        addDiagnostic(
          state,
          OPERATIONAL_RULE_IDS.hostContainerPath,
          'OPERATIONAL_CONTAINER_MAPPING_AMBIGUOUS',
          'Multiple mappings in one Compose service/build context resolve this code path differently, so Atlas made no path-divergence claim.',
          sourceAnchor,
          { mechanism: 'ambiguous-source-container-map', context: stableHash(contextId) }
        );
        continue;
      }
      if (resolution.state === 'undefined') {
        if (isTest) {
          addDiagnostic(
            state,
            OPERATIONAL_RULE_IDS.hostContainerPath,
            'OPERATIONAL_CONTAINER_MAPPING_UNDEFINED',
            'A container test service selects this test, but its source path has no supported runtime mapping.',
            sourceAnchor,
            { mechanism: 'selected-test-container-map-undefined', context: stableHash(contextId) }
          );
        }
        continue;
      }
      const mapping = resolution.mapping;
      const fileContainerPath = mappedContainerPath(parsed.file.record.path, mapping);
      if (isTest && selection) {
        addContainerCoverage(state, parsed, mapping, fileContainerPath, selection);
        if (contextMaps.some((entry) => entry.sourceKind === 'bind-mount')) {
          for (const reference of referencedRepositoryPaths(parsed, filesByPath)) {
            const referenceResolution = resolveBoundMap(reference.referencedPath, contextMaps);
            if (referenceResolution.state !== 'resolved' || referenceResolution.mapping.sourceKind !== 'docker-copy') continue;
            addFinding(state, OPERATIONAL_RULE_IDS.hostContainerPath, reference.anchor, {
              kind: 'defect-candidate', severity: 'high', confidence: 'high',
              title: 'A container check reads a repository file available only from image COPY',
              description: 'The selected test mixes live bind-mounted inputs with a referenced file that is only present in the image layer, so a no-rebuild rerun can inspect stale bytes.',
              signals: ['container-read-depends-on-build-copy', 'mixed-live-and-image-filesystem', 'docker-copy'],
              nextValidation: 'Bind-mount the referenced repository path into the location the check reads, or require an image rebuild before the check runs.',
              patternMaterial: {
                mechanism: 'copy-only-runtime-source',
                context: stableHash(contextId),
                sourcePath: stableHash(reference.referencedPath)
              },
              mechanism: 'copy-only-runtime-source',
              mappingContext: mappingContextFor(referenceResolution.mapping),
              related: [mapping.anchor, referenceResolution.mapping.anchor]
            });
          }
        }
      }
      for (const node of calls.filter(isPathResolveCall)) {
        const segments: string[] = [];
        const dynamic = node.arguments.slice(1).some((argument) => {
          if (ts.isStringLiteralLike(argument)) {
            segments.push(argument.text);
            return false;
          }
          return true;
        });
        if (dynamic) {
          addDiagnostic(state, OPERATIONAL_RULE_IDS.hostContainerPath, 'OPERATIONAL_CONTAINER_PATH_DYNAMIC',
            'A dynamic __dirname path could not be compared across host and container layouts.', nodeAnchor(parsed, node),
            { mechanism: 'dynamic-dirname-path', context: stableHash(mapping.contextId) });
          continue;
        }
        const hostResolved = path.posix.resolve('/', path.posix.dirname(parsed.file.record.path), ...segments).replace(/^\//u, '');
        const containerResolved = path.posix.resolve(path.posix.dirname(fileContainerPath), ...segments);
        if (boundHostToContainer(hostResolved, contextMaps) === containerResolved) continue;
        addFinding(state, OPERATIONAL_RULE_IDS.hostContainerPath, nodeAnchor(parsed, node), {
          kind: 'defect-candidate', severity: 'high', confidence: 'high',
          title: 'A literal path resolves differently in host and container layouts',
          description: 'Literal __dirname arithmetic disagrees with one statically bound Compose service/build context.',
          signals: ['literal-host-container-resolution-diverges', mapping.sourceKind],
          nextValidation: 'Resolve the path from a checked landmark or express it relative to the declared container root, then assert a known file exists.',
          patternMaterial: { mechanism: 'dirname-divergence', context: stableHash(mapping.contextId), mapping: stableHash(`${mapping.hostRoot}\0${mapping.containerRoot}`) },
          mechanism: 'dirname-divergence',
          mappingContext: mappingContextFor(mapping),
          related: [mapping.anchor]
        });
      }
      for (const node of calls.filter(isFilesystemLiteralCall)) {
        const first = node.arguments[0]!;
        const literalPath = portableRoot((first as ts.StringLiteralLike).text);
        const candidates = contextMaps.filter((entry) => {
          const localRoot = path.posix.basename(entry.hostRoot);
          return localRoot.length > 0 && (literalPath === localRoot || literalPath.startsWith(`${localRoot}/`));
        });
        const roots = [...new Set(candidates.map((entry) => entry.hostRoot.length))].sort((left, right) => right - left);
        const sameSpecificity = roots[0] === undefined ? [] : candidates.filter((entry) => entry.hostRoot.length === roots[0]);
        const bindCandidates = sameSpecificity.filter((entry) => entry.sourceKind === 'bind-mount');
        const specific = bindCandidates.length > 0 ? bindCandidates : sameSpecificity;
        if (new Set(specific.map((entry) => mappedContainerPath(entry.hostRoot, entry))).size > 1) {
          addDiagnostic(state, OPERATIONAL_RULE_IDS.hostContainerPath, 'OPERATIONAL_CONTAINER_MAPPING_AMBIGUOUS',
            'Multiple mappings in one Compose service/build context fit this literal path.', nodeAnchor(parsed, first),
            { mechanism: 'ambiguous-literal-container-map', context: stableHash(mapping.contextId) });
          continue;
        }
        const literalMapping = specific.sort((left, right) =>
          Number(left.sourceKind !== 'bind-mount') - Number(right.sourceKind !== 'bind-mount'))[0];
        if (!literalMapping) continue;
        const localRoot = path.posix.basename(literalMapping.hostRoot);
        const suffix = literalPath === localRoot ? '' : literalPath.slice(localRoot.length + 1);
        const expected = suffix ? path.posix.join(literalMapping.containerRoot, suffix) : literalMapping.containerRoot;
        const observed = path.posix.resolve(literalMapping.containerRoot, literalPath);
        if (expected === observed) continue;
        addFinding(state, OPERATIONAL_RULE_IDS.hostContainerPath, nodeAnchor(parsed, first), {
          kind: 'defect-candidate', severity: 'high', confidence: 'medium',
          title: 'A host-rooted scan path disagrees with the container mount root',
          description: 'A literal filesystem path repeats the host root beneath one statically bound container root.',
          signals: ['host-rooted-literal-used-under-container-root', literalMapping.sourceKind],
          nextValidation: 'Express the path relative to the container work root and require a known-positive landmark or file count.',
          patternMaterial: {
            mechanism: 'host-rooted-literal',
            context: stableHash(literalMapping.contextId),
            mapping: stableHash(`${literalMapping.hostRoot}\0${literalMapping.containerRoot}`),
            literalShape: stableHash(literalPath)
          },
          mechanism: 'host-rooted-literal',
          mappingContext: mappingContextFor(literalMapping),
          related: [literalMapping.anchor]
        });
      }
    }
  }
}

function configuredGuardPatterns(profile: ResolvedProfile | undefined): string[] {
  return profile?.operationalRisks?.guardPaths ?? [];
}

function importBindingsFor(
  parsed: ParsedFile,
  relationships: RelationshipRecord[]
): Map<string, ImportBinding> {
  const bindings = new Map<string, ImportBinding>();
  const resolvedTarget = (specifier: string): string | undefined => {
    const matches = relationships.filter((relationship) => (
      relationship.fromPath === parsed.file.record.path &&
      relationship.specifier === specifier &&
      relationship.resolution === 'resolved' &&
      relationship.toPath
    ));
    const targets = [...new Set(matches.map((relationship) => relationship.toPath!))];
    return targets.length === 1 ? targets[0] : undefined;
  };
  walk(parsed.sourceFile, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier) && node.importClause) {
      const targetPath = resolvedTarget(node.moduleSpecifier.text);
      if (!targetPath) return;
      if (node.importClause.name) bindings.set(node.importClause.name.text, { targetPath, exportedName: 'default' });
      const named = node.importClause.namedBindings;
      if (named && ts.isNamespaceImport(named)) bindings.set(named.name.text, { targetPath, exportedName: '*' });
      if (named && ts.isNamedImports(named)) {
        for (const element of named.elements) {
          bindings.set(element.name.text, { targetPath, exportedName: element.propertyName?.text ?? element.name.text });
        }
      }
    }
    if (!ts.isVariableDeclaration(node) || !node.initializer || !ts.isCallExpression(node.initializer)) return;
    const call = node.initializer;
    if (!ts.isIdentifier(call.expression) || call.expression.text !== 'require') return;
    const specifier = call.arguments[0];
    if (!specifier || !ts.isStringLiteralLike(specifier)) return;
    const targetPath = resolvedTarget(specifier.text);
    if (!targetPath) return;
    if (ts.isIdentifier(node.name)) bindings.set(node.name.text, { targetPath, exportedName: '*' });
    if (ts.isObjectBindingPattern(node.name)) {
      for (const element of node.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        bindings.set(element.name.text, {
          targetPath,
          exportedName: propertyName(element.propertyName) ?? element.name.text
        });
      }
    }
  });
  return bindings;
}

function receiverParts(expression: ts.Expression): string[] | undefined {
  if (ts.isIdentifier(expression)) return [expression.text];
  if (expression.kind === ts.SyntaxKind.ThisKeyword) return ['this'];
  if (ts.isPropertyAccessExpression(expression)) {
    const parent = receiverParts(expression.expression);
    return parent ? [...parent, expression.name.text] : undefined;
  }
  return undefined;
}

function resolvedWriterSink(
  parsed: ParsedFile,
  receiver: ts.Expression,
  method: string,
  bindings: ReadonlyMap<string, ImportBinding>
): string {
  const parts = receiverParts(receiver) ?? [receiver.getText(parsed.sourceFile)];
  const binding = bindings.get(parts[0]!);
  if (!binding) return `${parsed.file.record.path}#local:${parts.join('.')}.${method}`;
  const suffix = parts.slice(1);
  const exported = binding.exportedName === '*'
    ? suffix.join('.')
    : [binding.exportedName, ...suffix].join('.');
  return `${binding.targetPath}#${exported}.${method}`;
}

function resolvedImportedWriterCall(
  node: ts.CallExpression,
  bindings: ReadonlyMap<string, ImportBinding>
): { targetPath: string; method: string } | undefined {
  if (ts.isIdentifier(node.expression)) {
    const binding = bindings.get(node.expression.text);
    if (!binding || binding.exportedName === '*' || binding.exportedName === 'default') return undefined;
    return { targetPath: binding.targetPath, method: binding.exportedName };
  }
  if (!ts.isPropertyAccessExpression(node.expression)) return undefined;
  const parts = receiverParts(node.expression.expression);
  if (!parts?.length) return undefined;
  const binding = bindings.get(parts[0]!);
  if (!binding) return undefined;
  return { targetPath: binding.targetPath, method: node.expression.name.text };
}

const SQL_EXECUTION_METHOD = /^(?:query|execute|exec|raw|run|queryRaw|executeRaw|\$queryRaw|\$executeRaw)$/iu;
const DATABASE_RECEIVER_NAME = /^(?:(?:db|database|sql|sequelize|knex|prisma|client|connection|pool|queryInterface|entityManager|manager|repository|repo|model)|[A-Za-z_$][\w$]*(?:db|database|sql|sequelize|knex|prisma|client|connection|pool|repository|repo|model))$/iu;

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) || ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) || ts.isNonNullExpression(current) || ts.isSatisfiesExpression(current)
  ) current = current.expression;
  return current;
}

function lexicalDeclarationContainer(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node.parent;
  while (current && !ts.isSourceFile(current)) {
    if (ts.isBlock(current) || ts.isCaseBlock(current) || ts.isForStatement(current) ||
      ts.isForInStatement(current) || ts.isForOfStatement(current)) return current;
    current = current.parent;
  }
  return current ?? node.getSourceFile();
}

function immutableInitializerFor(
  parsed: ParsedFile,
  identifier: ts.Identifier
): ts.Expression | undefined {
  const referenceScope = containingScope(identifier);
  if (ts.isFunctionLike(referenceScope) && referenceScope.parameters.some((parameter) =>
    parameter.name.getText(parsed.sourceFile).split(/[^A-Za-z0-9_$]+/u).includes(identifier.text))) return undefined;
  const candidates: Array<{ initializer: ts.Expression; local: boolean; span: number; start: number }> = [];
  let mutableLocal = false;
  walk(parsed.sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || node.name.text !== identifier.text ||
      !ts.isVariableDeclarationList(node.parent)) return;
    const declarationScope = containingScope(node);
    if (declarationScope !== referenceScope && !ts.isSourceFile(declarationScope)) return;
    const container = lexicalDeclarationContainer(node);
    if (container.getStart(parsed.sourceFile) > identifier.getStart(parsed.sourceFile) ||
      container.getEnd() < identifier.getEnd()) return;
    if (node.getStart(parsed.sourceFile) >= identifier.getStart(parsed.sourceFile) ||
      (declarationScope === referenceScope && ((node.parent.flags & ts.NodeFlags.Const) === 0 || !node.initializer))) {
      mutableLocal = true;
      return;
    }
    if (!node.initializer || (node.parent.flags & ts.NodeFlags.Const) === 0) return;
    candidates.push({
      initializer: node.initializer,
      local: declarationScope === referenceScope,
      span: container.getEnd() - container.getStart(parsed.sourceFile),
      start: node.getStart(parsed.sourceFile)
    });
  });
  if (mutableLocal) return undefined;
  return candidates
    .sort((left, right) => Number(right.local) - Number(left.local) || left.span - right.span || right.start - left.start)[0]?.initializer;
}

function completeSqlLiteral(
  expression: ts.Expression,
  parsed: ParsedFile,
  seenIdentifiers = new Set<string>()
): string | undefined {
  const value = unwrapExpression(expression);
  if (ts.isStringLiteralLike(value)) return value.text;
  if (ts.isTemplateExpression(value)) {
    return `${value.head.text}${value.templateSpans.map((span) => `\0${span.literal.text}`).join('')}`;
  }
  if (!ts.isIdentifier(value) || seenIdentifiers.has(value.text)) return undefined;
  const initializer = immutableInitializerFor(parsed, value);
  if (!initializer) return undefined;
  const nextSeen = new Set(seenIdentifiers);
  nextSeen.add(value.text);
  return completeSqlLiteral(initializer, parsed, nextSeen);
}

function sqlWriteCall(
  node: ts.CallExpression,
  parsed: ParsedFile
): { operation: string; relation: string; anchor: Anchor } | undefined {
  if (!ts.isPropertyAccessExpression(node.expression) || !SQL_EXECUTION_METHOD.test(node.expression.name.text)) return undefined;
  const receiver = receiverParts(node.expression.expression)?.at(-1);
  if (!receiver || !DATABASE_RECEIVER_NAME.test(receiver)) return undefined;
  const argument = node.arguments[0];
  if (!argument) return undefined;
  const sql = completeSqlLiteral(argument, parsed);
  if (sql === undefined) return undefined;
  return sqlWriteLiteral(sql, nodeAnchor(parsed, argument));
}

function sqlWriteLiteral(
  sql: string,
  anchor: Anchor
): { operation: string; relation: string; anchor: Anchor } | undefined {
  const match = /\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+["`]?([A-Za-z_][\w.]*)(?=\s|["`.;(]|$)/iu.exec(sql);
  if (!match) return undefined;
  return {
    operation: match[1]!.replace(/\s+/gu, '-').toLowerCase(),
    relation: match[2]!.toLowerCase().split('.').at(-1)!,
    anchor
  };
}

function sqlWriteTaggedTemplate(
  node: ts.TaggedTemplateExpression,
  parsed: ParsedFile
): { operation: string; relation: string; anchor: Anchor } | undefined {
  if (!ts.isPropertyAccessExpression(node.tag) || !SQL_EXECUTION_METHOD.test(node.tag.name.text)) return undefined;
  const receiver = receiverParts(node.tag.expression)?.at(-1);
  if (!receiver || !DATABASE_RECEIVER_NAME.test(receiver)) return undefined;
  const sql = completeSqlLiteral(node.template, parsed);
  return sql === undefined ? undefined : sqlWriteLiteral(sql, nodeAnchor(parsed, node.template));
}

function hasPrecedingGuardCall(scope: ts.Node, writer: ts.Node, parsed: ParsedFile): boolean {
  let guarded = false;
  const writerBranch = branchSignature(writer, parsed);
  walkSameFunction(scope, scope, (candidate) => {
    if (guarded || !ts.isCallExpression(candidate) || candidate.getStart(parsed.sourceFile) >= writer.getStart(parsed.sourceFile)) return;
    const called = candidate.expression.getText(parsed.sourceFile);
    if (!/(?:^|\.)(?:validate|authorize|ensure|assert|checkPermission|requireRole)[A-Za-z0-9_]*$/u.test(called)) return;
    const guardBranch = branchSignature(candidate, parsed);
    if (guardBranch === '' || writerBranch === guardBranch || writerBranch.startsWith(`${guardBranch}/`)) guarded = true;
  });
  return guarded;
}

function collectFallbackWriterCalls(
  parsedFiles: ParsedFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile | undefined
): WriterCall[] {
  const calls: WriterCall[] = [];
  const configured = configuredGuardPatterns(profile);
  for (const parsed of parsedFiles.filter((entry) => isProductionConsumer(entry.file))) {
    const bindings = importBindingsFor(parsed, relationships);
    walk(parsed.sourceFile, (node) => {
      if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
      const method = node.expression.name.text;
      if (!/^(?:create|update|destroy|delete|insert|bulkCreate|bulkUpdate)$/u.test(method)) return;
      const receiverExpression = node.expression.expression;
      const receiver = receiverExpression.getText(parsed.sourceFile);
      if (!/(?:repository|repo|model|dao)$/iu.test(receiver.split('.').at(-1) ?? '')) return;
      const guarded = /(?:^|\/)(?:services?|guards?|validators?|authorization|auth)(?:\/|$)/iu.test(parsed.file.record.path) ||
        (configured.length > 0 && matchesAnyGlob(parsed.file.record.path, configured));
      calls.push({
        sinkKey: resolvedWriterSink(parsed, receiverExpression, method.toLowerCase(), bindings),
        guarded,
        anchor: nodeAnchor(parsed, node)
      });
    });
    walk(parsed.sourceFile, (node) => {
      const sqlWrite = ts.isCallExpression(node)
        ? sqlWriteCall(node, parsed)
        : ts.isTaggedTemplateExpression(node) ? sqlWriteTaggedTemplate(node, parsed) : undefined;
      if (!sqlWrite) return;
      const scope = containingScope(node);
      const guarded = /(?:^|\/)(?:services?|guards?|validators?|authorization|auth)(?:\/|$)/iu.test(parsed.file.record.path) ||
        (configured.length > 0 && matchesAnyGlob(parsed.file.record.path, configured)) ||
        hasPrecedingGuardCall(scope, node, parsed);
      calls.push({
        sinkKey: `sql:${sqlWrite.operation}:${sqlWrite.relation}`,
        guarded,
        anchor: sqlWrite.anchor
      });
    });
  }
  return calls;
}

function resolvedRelationshipAdjacency(relationships: RelationshipRecord[]): Map<string, string[]> {
  const outgoing = new Map<string, Set<string>>();
  for (const relationship of relationships) {
    if (relationship.resolution !== 'resolved' || !relationship.toPath || relationship.typeOnly) continue;
    const targets = outgoing.get(relationship.fromPath) ?? new Set<string>();
    targets.add(relationship.toPath);
    outgoing.set(relationship.fromPath, targets);
  }
  return new Map([...outgoing].map(([source, targets]) => [
    source,
    [...targets].sort(compareCanonicalText)
  ]));
}

function relationshipClosure(start: string, outgoing: ReadonlyMap<string, readonly string[]>): Set<string> {
  const visited = new Set<string>();
  const pending = [start];
  while (pending.length) {
    const current = pending.pop()!;
    if (visited.has(current)) continue;
    visited.add(current);
    for (const target of outgoing.get(current) ?? []) {
      if (!visited.has(target)) pending.push(target);
    }
  }
  return visited;
}

function collectDeclaredWriterCalls(
  parsedFiles: ParsedFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile
): WriterCall[] {
  const protectedWriters = profile.operationalRisks?.protectedWriters ?? [];
  const boundaries = profile.operationalRisks?.boundaries ?? [];
  if (!protectedWriters.length || !boundaries.length) return [];

  const writerBySink = new Map<string, (typeof protectedWriters)[number]>();
  for (const writer of protectedWriters) {
    for (const method of writer.methods) writerBySink.set(`${writer.module}\0${method}`, writer);
  }
  const outgoing = resolvedRelationshipAdjacency(relationships);
  const boundaryClosure = new Map(boundaries.map((boundary) => [
    boundary.id,
    relationshipClosure(boundary.module, outgoing)
  ]));
  const protectingBoundaries = new Map(protectedWriters.map((writer) => [
    writer.id,
    boundaries.filter((boundary) => (
      boundary.protects.includes(writer.id) && boundaryClosure.get(boundary.id)?.has(writer.module)
    ))
  ]));

  const calls: WriterCall[] = [];
  for (const parsed of parsedFiles.filter((entry) => isProductionConsumer(entry.file))) {
    const bindings = importBindingsFor(parsed, relationships);
    walk(parsed.sourceFile, (node) => {
      if (!ts.isCallExpression(node)) return;
      const resolved = resolvedImportedWriterCall(node, bindings);
      if (!resolved) return;
      const writer = writerBySink.get(`${resolved.targetPath}\0${resolved.method}`);
      if (!writer) return;
      const protecting = protectingBoundaries.get(writer.id) ?? [];
      const traversed = protecting.filter((boundary) => (
        boundaryClosure.get(boundary.id)?.has(parsed.file.record.path)
      ));
      calls.push({
        sinkKey: `declared:${writer.id}:${resolved.method}`,
        guarded: traversed.length > 0,
        anchor: nodeAnchor(parsed, node),
        declaration: {
          writerId: writer.id,
          method: resolved.method,
          protectingBoundaryIds: protecting.map((boundary) => boundary.id).sort(compareCanonicalText),
          traversedBoundaryIds: traversed.map((boundary) => boundary.id).sort(compareCanonicalText)
        }
      });
    });
  }
  return calls;
}

function collectWriterCalls(
  parsedFiles: ParsedFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile | undefined
): WriterCall[] {
  const hasDeclarations = Boolean(
    profile?.operationalRisks?.boundaries?.length &&
    profile.operationalRisks.protectedWriters?.length
  );
  return hasDeclarations
    ? collectDeclaredWriterCalls(parsedFiles, relationships, profile!)
    : collectFallbackWriterCalls(parsedFiles, relationships, profile);
}

function detectGuardBypass(
  parsedFiles: ParsedFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile | undefined,
  state: AnalysisState
): void {
  const groups = new Map<string, WriterCall[]>();
  for (const call of collectWriterCalls(parsedFiles, relationships, profile)) {
    const current = groups.get(call.sinkKey) ?? [];
    current.push(call);
    groups.set(call.sinkKey, current);
  }
  for (const [sinkKey, calls] of [...groups].sort(([left], [right]) => compareCanonicalText(left, right))) {
    const guarded = calls.filter((entry) => entry.guarded).sort((left, right) => compareCanonicalText(left.anchor.file.record.path, right.anchor.file.record.path));
    const bypasses = calls.filter((entry) => !entry.guarded).sort((left, right) => compareCanonicalText(left.anchor.file.record.path, right.anchor.file.record.path));
    const declaration = calls.find((entry) => entry.declaration)?.declaration;
    if (bypasses.length === 0 || (!declaration && guarded.length === 0)) continue;
    for (const bypass of bypasses) {
      const declared = bypass.declaration ?? declaration;
      addFinding(state, OPERATIONAL_RULE_IDS.guardBypass, bypass.anchor, {
        kind: 'review-inventory', severity: 'high', confidence: declared ? 'high' : 'medium',
        title: declared
          ? 'A caller bypasses a declared protected-writer boundary'
          : 'A low-level writer has both guarded and direct caller paths',
        description: declared
          ? `Atlas found ${calls.length} resolved direct caller instance(s) for declared protected writer ${declared.writerId}; this caller does not traverse a boundary declared to protect it.`
          : `Atlas found ${calls.length} direct caller instance(s) for one low-level writer; at least one is on a guard/service path and at least one is not.`,
        signals: declared
          ? ['caller-inventory-not-policy-verdict', 'declared-protected-writer', 'direct-low-level-writer-call', 'resolved-boundary-graph-bypass']
          : ['direct-low-level-writer-call', 'comparison-path-traverses-guard-or-service', 'caller-inventory-not-policy-verdict'],
        nextValidation: declared
          ? 'Review the declared writer invariant and route this caller through one of its named boundary modules.'
          : 'Confirm the required boundary, then review every direct caller before treating the guard as complete.',
        patternMaterial: {
          mechanism: 'guard-bypass',
          sink: stableHash(sinkKey),
          bypass: bypass.anchor.file.record.path,
          ...(declared ? {
            writer: stableHash(declared.writerId),
            method: stableHash(declared.method),
            boundaries: declared.protectingBoundaryIds.map(stableHash)
          } : {})
        },
        related: guarded.map((entry) => entry.anchor)
      });
    }
  }
}

function nameTokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/gu, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter(Boolean)
    .map((token) => {
      if (token === 'statuses') return 'status';
      if (token === 'categories') return 'category';
      if (token !== 'status' && token.endsWith('s')) return token.slice(0, -1);
      return token;
    });
}

function semanticFieldKey(name: string): string | undefined {
  const ignored = new Set([
    'allowed', 'valid', 'supported', 'values', 'value', 'names', 'name', 'list', 'set', 'enum', 'enums',
    'body', 'query', 'param', 'params', 'parameter', 'parameters', 'field', 'fields'
  ]);
  const tokens = nameTokens(name).filter((token) => !ignored.has(token));
  let semanticIndex = -1;
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    if (SEMANTIC_FIELD.test(tokens[index]!)) {
      semanticIndex = index;
      break;
    }
  }
  if (semanticIndex === -1) return undefined;
  return tokens.slice(0, semanticIndex + 1).join('-');
}

const GENERIC_VOCABULARY_OWNERS = new Set([
  'action', 'entry', 'entity', 'event', 'flag', 'item', 'object', 'record', 'session', 'target', 'value'
]);

function contextualFieldKey(
  fieldKey: string | undefined,
  filePath: string,
  domainHint?: string,
  contextHint?: string
): string | undefined {
  if (!fieldKey) return undefined;
  if (contextHint) return `${stableHash(contextHint).slice(0, 16)}-${fieldKey}`;
  const fieldTokens = fieldKey.split('-');
  const ownerTokens = fieldTokens.slice(0, -1);
  if (ownerTokens.length > 0 && ownerTokens.some((token) => !GENERIC_VOCABULARY_OWNERS.has(token))) {
    return fieldKey;
  }
  const genericContext = new Set([
    'model', 'service', 'controller', 'repository', 'repo', 'route', 'routes', 'validator', 'dto',
    'schema', 'migration', 'seed', 'seeder', 'script', 'index', 'util', 'utils', 'helper', 'test', 'spec'
  ]);
  const pathHint = path.posix.basename(filePath).split('.')[0] ?? '';
  const domain = nameTokens(domainHint ?? pathHint).filter((token) => (
    !genericContext.has(token) && !SEMANTIC_FIELD.test(token)
  ));
  return domain.length ? `${domain.join('-')}-${fieldKey}` : undefined;
}

function vocabularySubsetDeclaration(name: string): boolean {
  const tokens = nameTokens(name);
  return tokens.some((token) => [
    'active', 'blocked', 'excluded', 'filter', 'filtered', 'non', 'required', 'selected', 'terminal'
  ].includes(token));
}

function validatorSelector(node: ts.CallExpression): { kind: 'body' | 'param' | 'query'; field: string } | undefined {
  let selector: { kind: 'body' | 'param' | 'query'; field: string } | undefined;
  walk(node.expression, (candidate) => {
    if (selector || !ts.isCallExpression(candidate) || !ts.isIdentifier(candidate.expression) ||
      !/^(?:body|param|query)$/u.test(candidate.expression.text)) return;
    const field = candidate.arguments[0];
    if (!field || !ts.isStringLiteralLike(field)) return;
    selector = { kind: candidate.expression.text as 'body' | 'param' | 'query', field: field.text };
  });
  return selector;
}

function enclosingRouteContext(node: ts.Node, parsed: ParsedFile): string | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current && !ts.isSourceFile(current) && !ts.isFunctionLike(current)) {
    if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression) &&
      /^(?:delete|get|patch|post|put)$/u.test(current.expression.name.text)) {
      const route = current.arguments[0];
      if (route && ts.isStringLiteralLike(route)) {
        return `${current.expression.name.text}:${route.text}:${parsed.file.record.path}`;
      }
    }
    current = current.parent;
  }
  return undefined;
}

function liveVocabularyFile(file: AnalysisFile): boolean {
  return isOperationalInput(file) && file.record.kind !== 'test' &&
    !/(?:^|\/)(?:tests?|__tests__|fixtures|e2e|migrations?|seeders?)(?:\/|$)/iu.test(file.record.path);
}

function enclosingSqlRelation(source: string, offset: number): string | undefined {
  const prefix = source.slice(0, offset);
  const candidates = [...prefix.matchAll(/\b(?:CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|ALTER\s+TABLE)\s+["`]?([A-Za-z_][\w.]*)/giu)];
  const latest = candidates.at(-1);
  if (!latest || latest.index === undefined || latest.index < prefix.lastIndexOf(';')) return undefined;
  return latest[1];
}

function signatureForValues(values: string[]): string {
  return stableHash([...new Set(values.map((value) => value.normalize('NFC')))].sort(compareCanonicalText));
}

function addVocabularyFact(
  facts: VocabularyFact[],
  fieldKey: string | undefined,
  values: string[],
  complete: boolean,
  mechanism: string,
  anchor: Anchor,
  state: AnalysisState
): void {
  if (!fieldKey || values.length < 2) return;
  if (!complete) {
    addDiagnostic(
      state,
      OPERATIONAL_RULE_IDS.vocabularyDrift,
      'OPERATIONAL_VOCABULARY_DYNAMIC_SET',
      'A vocabulary-shaped declaration contains dynamic members, so Atlas did not compare it as a complete set.',
      anchor,
      { mechanism }
    );
    return;
  }
  const unique = [...new Set(values)];
  if (unique.length < 2) return;
  facts.push({ fieldKey, signature: signatureForValues(unique), size: unique.length, mechanism, anchor });
}

function nearestPropertyName(node: ts.Node): string | undefined {
  let current: ts.Node | undefined = node;
  while (current && !ts.isSourceFile(current)) {
    if (ts.isPropertyAssignment(current) || ts.isPropertyDeclaration(current) || ts.isMethodDeclaration(current)) {
      return propertyName(current.name);
    }
    current = current.parent;
  }
  return undefined;
}

function switchHasRejectingDefault(node: ts.SwitchStatement): boolean {
  const defaultClause = node.caseBlock.clauses.find((clause) => ts.isDefaultClause(clause));
  const first = defaultClause?.statements[0];
  if (!first) return false;
  if (ts.isThrowStatement(first)) return true;
  return ts.isBlock(first) && first.statements[0] !== undefined && ts.isThrowStatement(first.statements[0]);
}

function collectVocabularyFacts(
  parsedFiles: ParsedFile[],
  files: AnalysisFile[],
  state: AnalysisState,
  seedDictionaries: SeedDictionary[] = []
): VocabularyFact[] {
  const facts: VocabularyFact[] = [];
  for (const parsed of parsedFiles.filter((entry) => liveVocabularyFile(entry.file))) {
    walk(parsed.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const values = literalStrings(node.initializer);
        if (values && !vocabularySubsetDeclaration(node.name.text)) addVocabularyFact(
          facts,
          contextualFieldKey(semanticFieldKey(node.name.text), parsed.file.record.path),
          values.values,
          values.complete,
          'literal-array',
          nodeAnchor(parsed, node),
          state
        );
      }
      if (ts.isTypeAliasDeclaration(node) && ts.isUnionTypeNode(node.type)) {
        const values: string[] = [];
        let complete = true;
        for (const type of node.type.types) {
          if (ts.isLiteralTypeNode(type) && ts.isStringLiteralLike(type.literal)) values.push(type.literal.text);
          else complete = false;
        }
        addVocabularyFact(
          facts,
          contextualFieldKey(semanticFieldKey(node.name.text), parsed.file.record.path),
          values,
          complete,
          'typescript-union',
          nodeAnchor(parsed, node),
          state
        );
      }
      if (ts.isSwitchStatement(node)) {
        const values: string[] = [];
        let literalCases = true;
        for (const clause of node.caseBlock.clauses) {
          if (ts.isDefaultClause(clause)) continue;
          if (ts.isStringLiteralLike(clause.expression)) values.push(clause.expression.text);
          else literalCases = false;
        }
        const expressionName = ts.isPropertyAccessExpression(node.expression)
          ? `${node.expression.expression.getText(parsed.sourceFile)}_${node.expression.name.text}`
          : node.expression.getText(parsed.sourceFile);
        const fieldKey = contextualFieldKey(semanticFieldKey(expressionName), parsed.file.record.path);
        const anchor = nodeAnchor(parsed, node);
        if (!literalCases || !switchHasRejectingDefault(node)) {
          if (fieldKey && values.length >= 2) {
            addDiagnostic(
              state,
              OPERATIONAL_RULE_IDS.vocabularyDrift,
              'OPERATIONAL_VOCABULARY_SWITCH_COMPLETENESS_UNKNOWN',
              'Switch cases are subset evidence and do not establish a complete vocabulary without literal cases and an unconditional rejecting default.',
              anchor,
              { mechanism: 'switch-cases-subset' }
            );
          }
          return;
        }
        addVocabularyFact(
          facts,
          fieldKey,
          values,
          true,
          'switch-cases',
          anchor,
          state
        );
      }
      if (ts.isCallExpression(node) && /^(?:isIn|oneOf)$/u.test(callName(node.expression) ?? '') && node.arguments[0]) {
        let argument = node.arguments[0]!;
        if (ts.isArrayLiteralExpression(argument) && argument.elements.length === 1 && ts.isArrayLiteralExpression(argument.elements[0]!)) {
          argument = argument.elements[0] as ts.ArrayLiteralExpression;
        }
        const values = literalStrings(argument);
        if (values) {
          const selector = validatorSelector(node);
          if (selector?.kind === 'query') return;
          const receiver = selector?.field ?? (ts.isPropertyAccessExpression(node.expression)
            ? node.expression.expression.getText(parsed.sourceFile)
            : '');
          const key = contextualFieldKey(
            semanticFieldKey(nearestPropertyName(node) ?? receiver),
            parsed.file.record.path,
            undefined,
            enclosingRouteContext(node, parsed)
          );
          addVocabularyFact(facts, key, values.values, values.complete, 'validator-set', nodeAnchor(parsed, node), state);
        }
      }
    });
  }
  for (const file of files.filter((entry) => liveVocabularyFile(entry) && (/\.sql$/iu.test(entry.record.path) || entry.record.language === 'sql'))) {
    const source = file.content.toString('utf8');
    const patterns = [
      { mechanism: 'sql-check-in', regex: /CHECK\s*\(\s*([A-Za-z_][\w]*)\s+IN\s*\(([^)]+)\)\s*\)/giu },
      { mechanism: 'sql-enum', regex: /([A-Za-z_][\w]*)\s+(?:[A-Za-z_][\w]*\.)?ENUM\s*\(([^)]+)\)/giu }
    ];
    for (const { mechanism, regex } of patterns) {
      for (const match of source.matchAll(regex)) {
        const rawValues = match[2]!.match(/'(?:''|[^'])*'|"(?:""|[^"])*"/gu) ?? [];
        const values = rawValues.map((value) => value.slice(1, -1));
        const residue = match[2]!.replace(/'(?:''|[^'])*'|"(?:""|[^"])*"|[\s,]/gu, '');
        addVocabularyFact(
          facts,
          contextualFieldKey(
            semanticFieldKey(match[1]!),
            file.record.path,
            enclosingSqlRelation(source, match.index ?? 0)
          ),
          values,
          residue.length === 0,
          mechanism,
          { file, start: match.index, end: match.index + match[0].length },
          state
        );
      }
    }
  }
  for (const dictionary of seedDictionaries) {
    addVocabularyFact(
      facts,
      dictionary.fieldKey,
      [...dictionary.literalNames],
      true,
      'seed-dictionary',
      dictionary.anchor,
      state
    );
  }
  return facts;
}

function detectVocabularyDrift(
  parsedFiles: ParsedFile[],
  files: AnalysisFile[],
  state: AnalysisState,
  seedDictionaries: SeedDictionary[] = []
): void {
  const groups = new Map<string, VocabularyFact[]>();
  for (const fact of collectVocabularyFacts(parsedFiles, files, state, seedDictionaries)) {
    const current = groups.get(fact.fieldKey) ?? [];
    current.push(fact);
    groups.set(fact.fieldKey, current);
  }
  for (const [fieldKey, rawFacts] of [...groups].sort(([left], [right]) => compareCanonicalText(left, right))) {
    const facts = [...new Map(rawFacts.map((fact) => [`${fact.anchor.file.record.path}\0${fact.anchor.start}\0${fact.signature}`, fact])).values()]
      .sort((left, right) => compareCanonicalText(left.anchor.file.record.path, right.anchor.file.record.path) || left.anchor.start - right.anchor.start);
    const signatures = [...new Set(facts.map((fact) => fact.signature))];
    if (facts.length < 2 || signatures.length < 2) continue;
    const primary = facts[0]!;
    addFinding(state, OPERATIONAL_RULE_IDS.vocabularyDrift, primary.anchor, {
      kind: 'defect-candidate', severity: 'high', confidence: 'medium',
      title: 'Multiple complete literal vocabularies disagree for one field',
      description: `${facts.length} source-anchored vocabulary definitions for one normalized field contain ${signatures.length} distinct member-set signatures. Literal members were not retained.`,
      signals: ['complete-literal-vocabularies-disagree', ...[...new Set(facts.map((fact) => fact.mechanism))]],
      nextValidation: 'Confirm these definitions govern the same concept, then select one authoritative vocabulary and derive the others from it.',
      patternMaterial: { mechanism: 'vocabulary-drift', field: stableHash(fieldKey), signatures: signatures.sort(compareCanonicalText) },
      related: facts.slice(1).map((fact) => fact.anchor)
    });
  }
}

function regexAnchor(file: AnalysisFile, match: RegExpMatchArray): Anchor {
  return { file, start: match.index ?? 0, end: (match.index ?? 0) + match[0].length };
}

const RELATIVE_CALENDAR_BEHAVIOR = /(?:book|schedul|availab|calendar|upcoming|recent|future|past|currentDay|today|dateWindow|timeWindow|activeOn|validAt)/iu;
const UTC_INSTANT_FLOW = /(?:audit|createdAt|updatedAt|completedAt|timestamp|duration|expiry|expiresAt|expiration|ttl|elapsed)/iu;

function isCalendarCarrier(name: string): boolean {
  return /^(?:today|date|day|month|year|localDate|calendarDate|businessDate|serviceDate|bookingDate|scheduledDate|dateWindow|timeWindow)$/iu.test(name) ||
    /(?:Today|Date|Day|Month|Year|Window)$/u.test(name) || /_(?:today|date|day|month|year|window)$/iu.test(name);
}

function expressionContainsNode(expression: ts.Expression, target: ts.Node): boolean {
  return expression.getStart() <= target.getStart() && expression.getEnd() >= target.getEnd();
}

function directCalendarCall(node: ts.Node, scope: ts.Node, parsed: ParsedFile): ts.CallExpression | undefined {
  let current: ts.Node = node;
  while (current !== scope && current.parent) {
    const parent = current.parent;
    if (ts.isCallExpression(parent) && parent.arguments.some((argument) => expressionContainsNode(argument, node)) &&
      RELATIVE_CALENDAR_BEHAVIOR.test(parent.expression.getText(parsed.sourceFile)) &&
      !UTC_INSTANT_FLOW.test(parent.expression.getText(parsed.sourceFile))) return parent;
    current = parent;
  }
  return undefined;
}

function dateSensitiveTestScope(
  node: ts.Node,
  parsed: ParsedFile
): { scope: ts.Node; control: string; consumer: ts.CallExpression } | undefined {
  const scope = containingScope(node);
  const scopeText = scope.getText(parsed.sourceFile);
  if (!/\b(?:expect|assert|should)\b/u.test(scopeText)) return undefined;
  const direct = directCalendarCall(node, scope, parsed);
  const carrier = clockCarrier(node, scope);
  let consumer = direct;
  if (!consumer && carrier) {
    walkSameFunction(scope, scope, (candidate) => {
      if (consumer || !ts.isCallExpression(candidate) ||
        candidate.getStart(parsed.sourceFile) <= node.getEnd() ||
        !RELATIVE_CALENDAR_BEHAVIOR.test(candidate.expression.getText(parsed.sourceFile)) ||
        UTC_INSTANT_FLOW.test(candidate.expression.getText(parsed.sourceFile))) return;
      const used = candidate.arguments.some((argument) => expressionContainsIdentifier(argument, carrier.text));
      if (used) consumer = candidate;
    });
  }
  if (!consumer) return undefined;
  return {
    scope,
    control: stableHash(callName(consumer.expression) ?? consumer.expression.getText(parsed.sourceFile)),
    consumer
  };
}

function isTestInvocation(node: ts.Node): node is ts.CallExpression {
  if (!ts.isCallExpression(node)) return false;
  const name = callName(node.expression) ?? '';
  return /^(?:it|test|describe)$/u.test(name);
}

function isFrozenClockControl(node: ts.Node, parsed: ParsedFile): boolean {
  if (ts.isCallExpression(node)) {
    const called = node.expression.getText(parsed.sourceFile);
    if (/(?:^|\.)(?:useFakeTimers|setSystemTime|useFakeClock|setMockDate)$/u.test(called) ||
      /^(?:MockDate\.set|sinon\.useFakeTimers)$/u.test(called)) return true;
    if (/(?:^|\.)spyOn$/u.test(called) && node.arguments.length >= 2 &&
      node.arguments[0]?.getText(parsed.sourceFile) === 'Date' &&
      ts.isStringLiteralLike(node.arguments[1]!) && node.arguments[1]!.text === 'now') return true;
  }
  return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    node.left.getText(parsed.sourceFile) === 'Date.now';
}

function containsFrozenClockControl(node: ts.Node, parsed: ParsedFile, before: number, includeNested = false): boolean {
  let found = false;
  const visit = (candidate: ts.Node): void => {
    if (!found && candidate.getStart(parsed.sourceFile) < before && isFrozenClockControl(candidate, parsed)) found = true;
  };
  if (includeNested) walk(node, visit);
  else walkSameFunction(node, node, visit);
  return found;
}

function hasApplicableFrozenClock(node: ts.Node, scope: ts.Node, parsed: ParsedFile): boolean {
  if (containsFrozenClockControl(scope, parsed, node.getStart(parsed.sourceFile))) return true;
  let testCall: ts.CallExpression | undefined;
  let current: ts.Node | undefined = node;
  while (current?.parent) {
    if (isTestInvocation(current.parent)) {
      testCall = current.parent;
      break;
    }
    current = current.parent;
  }
  if (!testCall) return false;
  let statement: ts.Node = testCall;
  while (statement.parent && !ts.isSourceFile(statement.parent) && !ts.isBlock(statement.parent)) statement = statement.parent;
  const container = statement.parent;
  if (!container || (!ts.isSourceFile(container) && !ts.isBlock(container))) return false;
  return container.statements.some((candidate) => {
    if (candidate.getStart(parsed.sourceFile) >= statement.getStart(parsed.sourceFile)) return false;
    if (ts.isExpressionStatement(candidate) && isTestInvocation(candidate.expression)) return false;
    if (ts.isFunctionDeclaration(candidate)) return false;
    const setupHook = ts.isExpressionStatement(candidate) && ts.isCallExpression(candidate.expression) &&
      /^(?:beforeEach|beforeAll)$/u.test(callName(candidate.expression.expression) ?? '');
    return containsFrozenClockControl(candidate, parsed, candidate.getEnd(), setupHook);
  });
}

interface SqlSegment {
  file: AnalysisFile;
  source: string;
  start: number;
  intent: string;
}

function sqlRelations(source: string): Set<string> {
  return new Set([...source.matchAll(/\b(?:FROM|JOIN|UPDATE|INTO)\s+["`]?([A-Za-z_][\w.]*)/giu)]
    .map((match) => match[1]!.toLowerCase().split('.').at(-1)!)
    .sort(compareCanonicalText));
}

interface SqlRelationBinding {
  table: string;
  reference: string;
}

function sqlRelationBindings(source: string): SqlRelationBinding[] {
  const normalized = normalizedSqlIdentifiers(source);
  const pattern = /\b(?:FROM|JOIN|UPDATE|INTO)\s+([A-Za-z_][\w.]*)(?:\s+(?:AS\s+)?((?!(?:CROSS|FULL|GROUP|HAVING|INNER|JOIN|LEFT|LIMIT|OFFSET|ON|ORDER|OUTER|RETURNING|RIGHT|SET|UNION|VALUES|WHERE)\b)[A-Za-z_][\w]*))?/giu;
  return [...normalized.matchAll(pattern)].map((match) => {
    const table = match[1]!.toLowerCase().split('.').at(-1)!;
    return { table, reference: (match[2] ?? table).toLowerCase() };
  });
}

function hasUnmodeledCommaRelation(source: string): boolean {
  const clause = /\bFROM\b([\s\S]*?)(?:\bWHERE\b|\bGROUP\b|\bORDER\b|\bHAVING\b|\bLIMIT\b|\bUNION\b|;|$)/iu.exec(source)?.[1];
  return clause?.includes(',') ?? false;
}

interface SqlColumnPredicate {
  qualifier?: string;
  index: number;
  length: number;
}

function sqlColumnPredicates(
  source: string,
  column: string,
  operators: string,
  includeReverse = true
): SqlColumnPredicate[] {
  const escaped = column.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const patterns = [new RegExp(
    `(?<![A-Za-z0-9_.])(?:([A-Za-z_][\\w]*)\\.)?${escaped}\\b\\s*(?:${operators})`,
    'giu'
  )];
  if (includeReverse) patterns.push(new RegExp(
    `[^\\s,;(]+\\s*(?:${operators})\\s*(?:([A-Za-z_][\\w]*)\\.)?${escaped}\\b`,
    'giu'
  ));
  const matches = patterns.flatMap((pattern) => [...source.matchAll(pattern)].map((match) => ({
    ...(match[1] ? { qualifier: match[1].toLowerCase() } : {}),
    index: match.index ?? 0,
    length: match[0].length
  })));
  return matches.filter((entry, index) => matches.findIndex((candidate) => candidate.index === entry.index) === index)
    .sort((left, right) => left.index - right.index);
}

function sqlRelationSignature(source: string): string {
  return stableHash([...sqlRelations(source)]);
}

function sqlSegments(files: AnalysisFile[], parsedFiles: ParsedFile[]): SqlSegment[] {
  const segments: SqlSegment[] = [];
  const addSegments = (file: AnalysisFile, source: string, startOffset: number, intent: string): void => {
    const executable = stripSqlComments(source);
    let start = 0;
    for (let index = 0; index <= executable.length; index += 1) {
      if (index !== executable.length && executable[index] !== ';') continue;
      const value = executable.slice(start, index + (index < executable.length ? 1 : 0));
      if (/\b(?:select|update|delete|where)\b/iu.test(value)) {
        segments.push({ file, source: value, start: startOffset + start, intent });
      }
      start = index + 1;
    }
  };
  for (const file of files.filter((entry) => isProductionConsumer(entry) &&
    (/\.sql$/iu.test(entry.record.path) || entry.record.language === 'sql'))) {
    addSegments(file, file.content.toString('utf8'), 0, file.record.path);
  }
  for (const parsed of parsedFiles.filter((entry) => isProductionConsumer(entry.file))) {
    walk(parsed.sourceFile, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        SQL_EXECUTION_METHOD.test(node.expression.name.text)) {
        const receiver = receiverParts(node.expression.expression)?.at(-1);
        const argument = node.arguments[0];
        if (!receiver || !DATABASE_RECEIVER_NAME.test(receiver) || !argument) return;
        const source = completeSqlLiteral(argument, parsed);
        if (source !== undefined) {
          addSegments(parsed.file, source, argument.getStart(parsed.sourceFile) + 1,
            `${parsed.file.record.path} ${node.expression.name.text}`);
        }
        return;
      }
      if (ts.isTaggedTemplateExpression(node) && ts.isPropertyAccessExpression(node.tag) &&
        SQL_EXECUTION_METHOD.test(node.tag.name.text)) {
        const receiver = receiverParts(node.tag.expression)?.at(-1);
        if (!receiver || !DATABASE_RECEIVER_NAME.test(receiver)) return;
        const source = completeSqlLiteral(node.template, parsed);
        if (source !== undefined) {
          addSegments(parsed.file, source, node.template.getStart(parsed.sourceFile) + 1,
            `${parsed.file.record.path} ${node.tag.name.text}`);
        }
        return;
      }
      if (!ts.isVariableDeclaration(node) || !node.initializer) return;
      if (!/(?:^|\/)(?:repositories?|queries?|data)(?:\/|\.|$)/iu.test(parsed.file.record.path)) return;
      const name = node.name.getText(parsed.sourceFile);
      const source = completeSqlLiteral(node.initializer, parsed);
      if (source !== undefined && /(?:query|sql|statement|select|window|range|open|closed)/iu.test(`${name} ${parsed.file.record.path}`)) {
        addSegments(parsed.file, source, node.initializer.getStart(parsed.sourceFile) + 1,
          `${parsed.file.record.path} ${name}`);
      }
    });
  }
  return segments.sort((left, right) => compareCanonicalText(left.file.record.path, right.file.record.path) || left.start - right.start);
}

function normalizedSqlIdentifiers(source: string): string {
  return source.replace(/"([A-Za-z_][\w]*)"|`([A-Za-z_][\w]*)`|\[([A-Za-z_][\w]*)\]/gu,
    (_match, quoted: string | undefined, backticked: string | undefined, bracketed: string | undefined) =>
      quoted ?? backticked ?? bracketed ?? '');
}

function hasUnmodeledSqlDisjunction(source: string): boolean {
  const withoutQuotedValues = source.replace(
    /'(?:''|[^'])*'|"(?:""|[^"])*"|`(?:``|[^`])*`|\[(?:\]\]|[^\]])*\]/gu,
    ' '
  );
  return /\bOR\b/iu.test(withoutQuotedValues);
}

function hasDateWindowIntent(segment: SqlSegment, column: string): boolean {
  return /(?:appointment|booking|visit|schedule|availability|calendar|window|range|interval|period|upcoming|future)/iu
    .test(`${segment.intent} ${column} ${[...sqlRelations(segment.source)].join(' ')}`);
}

function hasExplicitClockInjection(scope: ts.Node, node: ts.Node, parsed: ParsedFile): boolean {
  let current: ts.Node = node;
  while (current !== scope && current.parent) {
    const parent = current.parent;
    if (ts.isParameter(parent) && /\b(?:now|clock|asOf)\b/iu.test(parent.name.getText(parsed.sourceFile))) return true;
    if (ts.isBinaryExpression(parent) &&
      (parent.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || parent.operatorToken.kind === ts.SyntaxKind.BarBarToken)) {
      const other = expressionContainsNode(parent.left, node) ? parent.right : parent.left;
      if (/\b(?:now|clock|asOf)\b/iu.test(other.getText(parsed.sourceFile))) return true;
    }
    current = parent;
  }
  return false;
}

function clockCarrier(node: ts.Node, scope: ts.Node): ts.Identifier | undefined {
  let current: ts.Node = node;
  while (current !== scope && current.parent) {
    const parent = current.parent;
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name) && parent.initializer &&
      parent.initializer.getStart() <= node.getStart() && parent.initializer.getEnd() >= node.getEnd()) return parent.name;
    current = parent;
  }
  return undefined;
}

function injectedTestClockControl(
  node: ts.Node,
  scope: ts.Node,
  consumer: ts.CallExpression
): boolean {
  const carrier = clockCarrier(node, scope);
  let injected = false;
  walkSameFunction(consumer, consumer, (candidate) => {
    if (injected) return;
    if (ts.isPropertyAssignment(candidate)) {
      const name = propertyName(candidate.name) ?? '';
      if (!/^(?:asOf|clock|currentDate|currentTime|now|referenceDate|testDate)$/u.test(name)) return;
      if (expressionContainsNode(candidate.initializer, node) ||
        (carrier && expressionContainsIdentifier(candidate.initializer, carrier.text))) injected = true;
      return;
    }
    if (ts.isShorthandPropertyAssignment(candidate) && carrier && candidate.name.text === carrier.text &&
      /^(?:asOf|clock|currentDate|currentTime|now|referenceDate|testDate)$/u.test(candidate.name.text)) {
      injected = true;
    }
  });
  return injected;
}

function expressionHasTenantReference(expression: ts.Expression): boolean {
  let found = false;
  walkSameFunction(expression, expression, (node) => {
    if (ts.isIdentifier(node) && /^tenant(?:Id|ID|_id)?$/u.test(node.text)) found = true;
  });
  return found;
}

function expressionContainsBinding(
  expression: ts.Expression,
  binding: LexicalBinding,
  bindings: LexicalBindingIndex
): boolean {
  let found = false;
  walkSameFunction(expression, expression, (candidate) => {
    if (found || !ts.isIdentifier(candidate)) return;
    if (ts.isPropertyAssignment(candidate.parent) && candidate.parent.name === candidate) return;
    if (ts.isPropertyAccessExpression(candidate.parent) && candidate.parent.name === candidate) return;
    if (resolvedLexicalBinding(candidate, bindings)?.nameNode === binding.nameNode) found = true;
  });
  return found;
}

function processClockFlowsWithTenant(
  node: ts.Node,
  parsed: ParsedFile,
  bindings: LexicalBindingIndex
): { control: string } | undefined {
  const scope = containingScope(node);
  const scopeText = scope.getText(parsed.sourceFile);
  if (!/\btenant(?:Id|ID|_id)?\b/u.test(scopeText)) return undefined;
  if (hasExplicitClockInjection(scope, node, parsed)) return undefined;

  const carrier = clockCarrier(node, scope);
  const carrierBinding = carrier
    ? (bindings.get(carrier.text) ?? []).find((binding) => binding.nameNode === carrier)
    : undefined;
  if (carrier && !carrierBinding) return undefined;
  if (carrier && UTC_INSTANT_FLOW.test(carrier.text)) return undefined;
  let qualifyingCall: ts.CallExpression | undefined;
  walkSameFunction(scope, scope, (candidate) => {
    if (qualifyingCall || !ts.isCallExpression(candidate)) return;
    const called = candidate.expression.getText(parsed.sourceFile);
    if (/(?:^|\.)(?:log|info|debug|warn|error)$/u.test(called)) return;
    if (UTC_INSTANT_FLOW.test(called)) return;
    if (/\b(?:tenantLocal|zonedTime|timeZone|timezone|localDateFor|(?:to|resolve|get)(?:Tenant|Local)[A-Za-z]*Date)\b/u.test(called)) return;
    const hasTenant = candidate.arguments.some(expressionHasTenantReference);
    const hasClock = carrierBinding
      ? candidate.getStart(parsed.sourceFile) > node.getEnd() &&
        candidate.arguments.some((argument) => expressionContainsBinding(argument, carrierBinding, bindings))
      : candidate.arguments.some((argument) => argument === node || argument.getStart(parsed.sourceFile) <= node.getStart(parsed.sourceFile) && argument.getEnd() >= node.getEnd());
    const calendarSensitive = RELATIVE_CALENDAR_BEHAVIOR.test(called) || (carrier !== undefined && isCalendarCarrier(carrier.text));
    if (hasTenant && hasClock && calendarSensitive) qualifyingCall = candidate;
  });
  if (!qualifyingCall) return undefined;
  return { control: stableHash(callName(qualifyingCall.expression) ?? qualifyingCall.expression.getText(parsed.sourceFile)) };
}

function detectClockDateBasis(files: AnalysisFile[], parsedFiles: ParsedFile[], state: AnalysisState): void {
  for (const parsed of parsedFiles.filter((entry) => entry.file.record.kind === 'test' || TEST_PATH.test(entry.file.record.path))) {
    walk(parsed.sourceFile, (node) => {
      if (!ts.isNewExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== 'Date') return;
      const first = node.arguments?.[0];
      if (!first || !ts.isStringLiteralLike(first) || !/^20\d{2}-\d{2}-\d{2}(?:[T ].*)?$/u.test(first.text)) return;
      const context = dateSensitiveTestScope(node, parsed);
      if (!context || hasApplicableFrozenClock(node, context.scope, parsed) ||
        injectedTestClockControl(node, context.scope, context.consumer)) return;
      const anchor = nodeAnchor(parsed, first);
      addFinding(state, OPERATIONAL_RULE_IDS.clockDateBasis, anchor, {
        kind: 'defect-candidate', severity: 'medium', confidence: 'high',
        title: 'A time-sensitive test uses an absolute date without controlling the clock',
        description: 'A supported time-sensitive test scope constructs an absolute calendar value but has no local fake-clock or Date.now control.',
        signals: ['absolute-test-date', 'clock-control-not-observed', 'time-sensitive-test-scope'],
        nextValidation: 'Freeze the clock in this test scope or derive the fixture from the controlled test date and assert the intended boundary.',
        patternMaterial: { mechanism: 'absolute-test-date' }
      });
    });
  }

  const querySegments = sqlSegments(files, parsedFiles);
  for (const segment of querySegments) {
    const normalized = normalizedSqlIdentifiers(segment.source);
    const lowerBounds = [
      ...normalized.matchAll(/\b([A-Za-z_][\w.]*(?:date|_at))\s*>=?\s*[^\s,;)]+/giu),
      ...normalized.matchAll(/[^\s,;(]+\s*<=?\s*\b([A-Za-z_][\w.]*(?:date|_at))\b/giu)
    ].sort((left, right) => (left.index ?? 0) - (right.index ?? 0));
    for (const match of lowerBounds) {
      const column = match[1]!;
      const terminal = column.toLowerCase().split('.').at(-1)!;
      if (/^(?:current_date|current_timestamp|localtimestamp|sysdate)$/u.test(terminal)) continue;
      const escaped = column.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
      const upper = new RegExp(`(?:\\b${escaped}\\s*<=?|[^\\s,;(]+\\s*>=?\\s*\\b${escaped}\\b)`, 'iu');
      const anchor = {
        file: segment.file,
        start: segment.start + (match.index ?? 0),
        end: segment.start + (match.index ?? 0) + match[0].length
      };
      if (hasUnmodeledSqlDisjunction(segment.source)) {
        addDiagnostic(
          state,
          OPERATIONAL_RULE_IDS.clockDateBasis,
          'OPERATIONAL_DATE_WINDOW_BOOLEAN_UNMODELED',
          'A lower-bounded date predicate contains OR semantics that Atlas does not model, so no open-ended-range claim was made.',
          anchor,
          { mechanism: 'date-window-boolean-uncertain', field: stableHash(column.toLowerCase()) }
        );
        continue;
      }
      if (upper.test(normalized)) continue;
      if (!hasDateWindowIntent(segment, column)) {
        addDiagnostic(
          state,
          OPERATIONAL_RULE_IDS.clockDateBasis,
          'OPERATIONAL_DATE_WINDOW_SEMANTICS_UNCLEAR',
          'A lower-bounded date predicate was observed, but no supported bounded-window intent was established.',
          anchor,
          { mechanism: 'open-ended-date-range-uncertain', field: stableHash(column.toLowerCase()) }
        );
        continue;
      }
      addFinding(state, OPERATIONAL_RULE_IDS.clockDateBasis, anchor, {
        kind: 'defect-candidate', severity: 'medium', confidence: 'medium',
        title: 'A date range has a lower bound without a supported upper bound',
        description: 'A supported window-shaped SQL query constrains a date field from below, while no conjunctive upper bound for that field was observed.',
        signals: ['date-lower-bound-observed', 'date-upper-bound-not-observed', 'date-window-intent-observed'],
        nextValidation: 'Confirm the intended interval and add an explicit upper bound when future-dated rows must be excluded.',
        patternMaterial: {
          mechanism: 'open-ended-date-range',
          field: stableHash(column.toLowerCase()),
          relation: sqlRelationSignature(segment.source)
        }
      });
    }
  }

  for (const parsed of parsedFiles.filter((entry) => isProductionConsumer(entry.file))) {
    const bindings = lexicalBindingsFor(parsed);
    walk(parsed.sourceFile, (node) => {
      const processClock = (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Date' && (node.arguments?.length ?? 0) === 0) ||
        (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === 'Date' && node.expression.name.text === 'now');
      if (!processClock) return;
      const flow = processClockFlowsWithTenant(node, parsed, bindings);
      if (!flow) return;
      const anchor = nodeAnchor(parsed, node);
      addFinding(state, OPERATIONAL_RULE_IDS.clockDateBasis, anchor, {
        kind: 'defect-candidate', severity: 'high', confidence: 'medium',
        title: 'Tenant-scoped logic reads the process clock directly',
        description: 'A function that references tenant context also reads Date directly, and no supported tenant-local time resolver was observed in that scope.',
        signals: ['process-clock-read', 'tenant-context', 'local-time-resolver-not-observed'],
        nextValidation: 'Pass an explicit clock and tenant-local date resolver through this path, then test the UTC boundary.',
        patternMaterial: { mechanism: 'tenant-process-clock' }
      });
    });
  }

  const dateColumns: Array<{ table: string; column: string; timeColumns: string[]; anchor: Anchor }> = [];
  for (const file of files.filter((entry) => /\.sql$/iu.test(entry.record.path) || entry.record.language === 'sql')) {
    const source = file.content.toString('utf8');
    for (const table of source.matchAll(/CREATE\s+TABLE\s+[^\s(]+\s*\(([\s\S]*?)\)\s*;/giu)) {
      const body = table[1]!;
      const times = [...body.matchAll(/\b([A-Za-z_][\w]*)\s+TIME\b/giu)].map((entry) => entry[1]!);
      if (times.length === 0) continue;
      for (const date of body.matchAll(/\b([A-Za-z_][\w]*)\s+DATE\b/giu)) {
        dateColumns.push({
          table: table[0]!.match(/CREATE\s+TABLE\s+["`]?([^\s("`]+)/iu)?.[1]?.toLowerCase() ?? 'unknown-table',
          column: date[1]!,
          timeColumns: times,
          anchor: { file, start: (table.index ?? 0) + date.index, end: (table.index ?? 0) + date.index + date[0].length }
        });
      }
    }
  }
  for (const segment of querySegments) {
    const relationBindings = sqlRelationBindings(segment.source);
    if (relationBindings.length === 0 || hasUnmodeledCommaRelation(segment.source)) continue;
    for (const dateColumn of dateColumns) {
      const table = dateColumn.table.split('.').at(-1)!;
      let dateMatch: SqlColumnPredicate | undefined;
      let dateRelation: SqlRelationBinding | undefined;
      for (const predicate of sqlColumnPredicates(segment.source, dateColumn.column, '[<>]=?|BETWEEN\\b', false)) {
        const matchingDateRelations = predicate.qualifier
          ? relationBindings.filter((relation) => relation.table === table && relation.reference === predicate.qualifier)
          : relationBindings.length === 1 && relationBindings[0]!.table === table
            ? [relationBindings[0]!]
            : [];
        if (matchingDateRelations.length !== 1) continue;
        dateMatch = predicate;
        dateRelation = matchingDateRelations[0]!;
        break;
      }
      if (!dateMatch || !dateRelation) continue;
      let matchingTimePredicate = false;
      let ambiguousTimePredicate = false;
      for (const column of dateColumn.timeColumns) {
        for (const predicate of sqlColumnPredicates(
          segment.source,
          column,
          '<=|>=|<>|!=|=|<|>|BETWEEN\\b|IN\\s*\\('
        )) {
          if (!predicate.qualifier) {
            if (relationBindings.length === 1) matchingTimePredicate = true;
            else ambiguousTimePredicate = true;
            continue;
          }
          const matchingRelations = relationBindings.filter((relation) => relation.reference === predicate.qualifier);
          if (matchingRelations.length !== 1) {
            ambiguousTimePredicate = true;
            continue;
          }
          if (matchingRelations[0] === dateRelation) matchingTimePredicate = true;
        }
      }
      if (matchingTimePredicate || ambiguousTimePredicate) continue;
      const anchor = {
        file: segment.file,
        start: segment.start + dateMatch.index,
        end: segment.start + dateMatch.index + dateMatch.length
      };
      addFinding(state, OPERATIONAL_RULE_IDS.clockDateBasis, anchor, {
        kind: 'defect-candidate', severity: 'medium', confidence: 'medium',
        title: 'A DATE predicate omits a declared sibling TIME field',
        description: 'The schema declares separate DATE and TIME fields, while this supported predicate constrains only the DATE field.',
        signals: ['separate-date-and-time-columns', 'date-only-bound-observed'],
        nextValidation: 'Confirm whether the boundary is time-sensitive and, if so, compare a composed timestamp or constrain both columns.',
        patternMaterial: {
          mechanism: 'date-without-time',
          table: stableHash(dateColumn.table),
          column: stableHash(dateColumn.column.toLowerCase())
        },
        related: [dateColumn.anchor]
      });
    }
  }
}

interface ReturnContract {
  key: string;
  aliases: string[];
  name: string;
  keys: Set<string>;
  possibleDiscriminatorKeys: Set<string>;
  anchor: Anchor;
}

type RuntimeFunction = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction;
type ResultFunction = RuntimeFunction | ts.MethodDeclaration;

const RESULT_DISCRIMINATOR_KEY = /^(?:suppressed|skipped|status|reason|errors?)$/u;

function declaredFunctionName(node: RuntimeFunction): string | undefined {
  if ('name' in node && node.name && ts.isIdentifier(node.name)) return node.name.text;
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (ts.isPropertyAssignment(parent)) return propertyName(parent.name);
  return undefined;
}

function functionBindingIdentifier(node: RuntimeFunction): ts.Identifier | undefined {
  if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) return node.parent.name;
  return (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) && node.name ? node.name : undefined;
}

function exportedFunctionNames(node: RuntimeFunction, name: string): string[] {
  const declaration = ts.isVariableDeclaration(node.parent)
    ? node.parent.parent.parent
    : node;
  if (!ts.canHaveModifiers(declaration)) return [];
  const modifiers = ts.getModifiers(declaration) ?? [];
  if (!modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) return [];
  return [modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword) ? 'default' : name];
}

function resultFunctionIdentity(
  parsed: ParsedFile,
  node: ResultFunction
): { key: string; aliases: string[]; name: string } | undefined {
  if (ts.isMethodDeclaration(node)) {
    const name = propertyName(node.name);
    return name
      ? { key: `${parsed.file.record.path}#method:${node.name.getStart(parsed.sourceFile)}`, aliases: [], name }
      : undefined;
  }
  const name = declaredFunctionName(node);
  const bindingIdentifier = functionBindingIdentifier(node);
  return name && bindingIdentifier
    ? {
        key: `${parsed.file.record.path}#binding:${bindingIdentifier.getStart(parsed.sourceFile)}`,
        aliases: exportedFunctionNames(node, name).map((exportedName) => `${parsed.file.record.path}#${exportedName}`),
        name
      }
    : undefined;
}

function collectReturnContracts(parsedFiles: ParsedFile[]): ReturnContract[] {
  const contracts: ReturnContract[] = [];
  for (const parsed of parsedFiles) {
    walk(parsed.sourceFile, (node) => {
      if (
        !ts.isFunctionDeclaration(node) && !ts.isFunctionExpression(node) && !ts.isArrowFunction(node) &&
        !ts.isMethodDeclaration(node)
      ) return;
      const identity = resultFunctionIdentity(parsed, node);
      if (!identity) return;
      const returnedObjects: ts.ObjectLiteralExpression[] = [];
      let complete = true;
      if (ts.isArrowFunction(node) && ts.isObjectLiteralExpression(node.body)) {
        returnedObjects.push(node.body);
      } else if (node.body) {
        walkSameFunction(node.body, node.body, (candidate) => {
          if (!ts.isReturnStatement(candidate)) return;
          const returned = candidate.expression && unwrapExpression(candidate.expression);
          if (!returned || !ts.isObjectLiteralExpression(returned)) {
            complete = false;
            return;
          }
          returnedObjects.push(returned);
        });
      }
      if (!complete || returnedObjects.length === 0) return;
      const shapes = returnedObjects.map((object) => new Set(object.properties.flatMap((property) => {
        if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) return [];
        const key = propertyName(property.name);
        return key ? [key] : [];
      })));
      const keys = new Set([...shapes[0]!].filter((key) => shapes.every((shape) => shape.has(key))));
      const possibleDiscriminatorKeys = new Set(
        shapes.flatMap((shape) => [...shape].filter((key) => RESULT_DISCRIMINATOR_KEY.test(key)))
      );
      if (keys.has('success') && possibleDiscriminatorKeys.size > 0) {
        const discriminatorIndex = shapes.findIndex((shape) => [...shape].some((key) => RESULT_DISCRIMINATOR_KEY.test(key)));
        contracts.push({
          ...identity,
          keys,
          possibleDiscriminatorKeys,
          anchor: nodeAnchor(parsed, returnedObjects[Math.max(0, discriminatorIndex)]!)
        });
      }
    });
  }
  return contracts;
}

function calledContractKey(
  parsed: ParsedFile,
  call: ts.CallExpression,
  bindings: LexicalBindingIndex,
  relationships: RelationshipRecord[]
): string | undefined {
  const importedKey = (binding: LexicalBinding, suffix: string[]): string | undefined => {
    if (!binding.importSpecifier || !binding.importedName) return undefined;
    const targets = [...new Set(relationships.filter((relationship) => (
      relationship.fromPath === parsed.file.record.path &&
      relationship.specifier === binding.importSpecifier &&
      relationship.resolution === 'resolved' &&
      relationship.toPath
    )).map((relationship) => relationship.toPath!))];
    if (targets.length !== 1) return undefined;
    const exported = binding.importedName === '*'
      ? suffix.join('.')
      : [binding.importedName, ...suffix].join('.');
    return exported ? `${targets[0]}#${exported}` : undefined;
  };
  if (ts.isIdentifier(call.expression)) {
    const binding = resolvedLexicalBinding(call.expression, bindings);
    if (!binding) return undefined;
    return importedKey(binding, []) ?? lexicalBindingKey(parsed, binding);
  }
  if (!ts.isPropertyAccessExpression(call.expression)) return undefined;
  const localContainer = receiverContainer(call.expression.expression, bindings);
  const localKey = localContainer
    ? localMethodKey(parsed, localContainer, call.expression.name.text)
    : undefined;
  if (localKey) return localKey;
  const parts = receiverParts(call.expression.expression);
  if (!parts) return undefined;
  let root: ts.Expression = call.expression.expression;
  while (ts.isPropertyAccessExpression(root)) root = root.expression;
  if (!ts.isIdentifier(root)) return undefined;
  const binding = resolvedLexicalBinding(root, bindings);
  return binding ? importedKey(binding, [...parts.slice(1), call.expression.name.text]) : undefined;
}

function accessedResultKeys(
  parsed: ParsedFile,
  call: ts.CallExpression,
  bindings: LexicalBindingIndex
): Set<string> {
  const keys = new Set<string>();
  let resultExpression: ts.Expression = call;
  let parent: ts.Node = call.parent;
  if (ts.isAwaitExpression(parent)) {
    resultExpression = parent;
    parent = parent.parent;
  }
  if (ts.isPropertyAccessExpression(parent) && parent.expression === resultExpression) keys.add(parent.name.text);
  if (ts.isVariableDeclaration(parent)) {
    if (ts.isObjectBindingPattern(parent.name)) {
      for (const element of parent.name.elements) keys.add(propertyName(element.propertyName) ?? element.name.getText(parsed.sourceFile));
    } else if (ts.isIdentifier(parent.name)) {
      const declarationBinding = (bindings.get(parent.name.text) ?? []).find((binding) => binding.nameNode === parent.name);
      if (!declarationBinding) return keys;
      const scope = containingScope(parent);
      walk(scope, (candidate) => {
        if (ts.isPropertyAccessExpression(candidate) && ts.isIdentifier(candidate.expression) &&
          resolvedLexicalBinding(candidate.expression, bindings)?.nameNode === declarationBinding.nameNode) {
          keys.add(candidate.name.text);
        }
      });
    }
  }
  return keys;
}

function walkSameFunction(node: ts.Node, root: ts.Node, visit: (node: ts.Node) => void): void {
  visit(node);
  node.forEachChild((child) => {
    if (child !== root && ts.isFunctionLike(child)) return;
    walkSameFunction(child, root, visit);
  });
}

function numericValue(expression: ts.Expression | undefined): number | undefined {
  if (!expression) return undefined;
  const value = unwrapExpression(expression);
  if (ts.isNumericLiteral(value)) return Number(value.text);
  if (ts.isPrefixUnaryExpression(value) && value.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(value.operand)) {
    return -Number(value.operand.text);
  }
  return undefined;
}

function unwrapAwaitedExpression(expression: ts.Expression): ts.Expression {
  let value = unwrapExpression(expression);
  while (ts.isAwaitExpression(value)) value = unwrapExpression(value.expression);
  return value;
}

interface HttpResponseChain {
  root: string;
  calls: Array<{ name: string; arguments: readonly ts.Expression[] }>;
}

function httpResponseChain(node: ts.CallExpression, parsed: ParsedFile): HttpResponseChain | undefined {
  const calls: HttpResponseChain['calls'] = [];
  let current: ts.Expression = node;
  while (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
    calls.push({ name: current.expression.name.text, arguments: current.arguments });
    current = unwrapExpression(current.expression.expression);
  }
  const root = current.getText(parsed.sourceFile);
  if (!/^(?:res|response|reply)$/u.test(root) || !calls.some((call) => /^(?:end|json|send)$/u.test(call.name))) {
    return undefined;
  }
  return { root, calls };
}

function expressionIsExplicitFailure(expression: ts.Expression): boolean {
  const value = unwrapAwaitedExpression(expression);
  if (ts.isStringLiteralLike(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
    return /(?:denied|error|fail|forbidden|invalid|reject|sorry|unauthori[sz]ed|unavailable)/iu.test(value.text);
  }
  if (ts.isNewExpression(value) && ts.isIdentifier(value.expression) && /Error$/u.test(value.expression.text)) return true;
  if (!ts.isObjectLiteralExpression(value)) return false;
  return value.properties.some((property) => {
    if (!ts.isPropertyAssignment(property)) return false;
    const name = propertyName(property.name) ?? '';
    if (/^(?:error|errors|reason)$/u.test(name)) return true;
    if (/^(?:ok|success)$/u.test(name) && property.initializer.kind === ts.SyntaxKind.FalseKeyword) return true;
    if (/^(?:status|type|kind)$/u.test(name) && ts.isStringLiteralLike(property.initializer)) {
      return /^(?:denied|error|failed|failure|forbidden|invalid|rejected|unavailable)$/iu.test(property.initializer.text);
    }
    return /^(?:status|statusCode)$/u.test(name) && (numericValue(property.initializer) ?? 0) >= 400;
  });
}

function enclosingCatchClause(node: ts.Node): ts.CatchClause | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current)) {
    if (ts.isCatchClause(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function responseBuilderSignalsFailure(
  expression: ts.Expression,
  responseCall: ts.CallExpression,
  parsed: ParsedFile
): boolean {
  const value = unwrapAwaitedExpression(expression);
  if (!ts.isCallExpression(value) || !ts.isPropertyAccessExpression(value.expression)) return false;
  const receiver = unwrapExpression(value.expression.expression);
  if (!ts.isIdentifier(receiver)) return false;
  const caught = enclosingCatchClause(responseCall);
  if (!caught) return false;
  let found = false;
  walkSameFunction(caught.block, caught.block, (candidate) => {
    if (found || candidate.getStart(parsed.sourceFile) >= responseCall.getStart(parsed.sourceFile) ||
      !ts.isCallExpression(candidate) || !ts.isPropertyAccessExpression(candidate.expression)) return;
    const candidateReceiver = unwrapExpression(candidate.expression.expression);
    if (!ts.isIdentifier(candidateReceiver) || candidateReceiver.text !== receiver.text) return;
    if (candidate.arguments.some((argument) => expressionIsExplicitFailure(argument))) found = true;
  });
  return found;
}

function isHttpErrorResponseCall(node: ts.CallExpression, parsed: ParsedFile): boolean {
  const chain = httpResponseChain(node, parsed);
  if (!chain) return false;
  for (const call of chain.calls) {
    if (!/^(?:code|status)$/u.test(call.name)) continue;
    const status = numericValue(call.arguments[0]);
    if (status !== undefined && status >= 400) return true;
    const statusText = call.arguments[0]?.getText(parsed.sourceFile) ?? '';
    if (/(?:BAD_REQUEST|UNAUTHORIZED|FORBIDDEN|NOT_FOUND|CONFLICT|UNPROCESSABLE|ERROR|FAIL|INTERNAL_SERVER)/iu.test(statusText)) {
      return true;
    }
  }
  const terminal = chain.calls.find((call) => /^(?:end|json|send)$/u.test(call.name));
  return terminal?.arguments.some((argument) =>
    expressionIsExplicitFailure(argument) || responseBuilderSignalsFailure(argument, node, parsed)
  ) ?? false;
}

function returnIsFailure(node: ts.ReturnStatement, parsed: ParsedFile): 'safe' | 'unknown' | 'absent' {
  const expression = node.expression;
  if (!expression || expression.kind === ts.SyntaxKind.UndefinedKeyword) return 'absent';
  const value = unwrapAwaitedExpression(expression);
  if (value.kind === ts.SyntaxKind.FalseKeyword || value.kind === ts.SyntaxKind.NullKeyword) return 'safe';
  if (ts.isObjectLiteralExpression(value)) {
    for (const property of value.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const name = propertyName(property.name);
      if (/^(?:success|ok)$/u.test(name ?? '') && property.initializer.kind === ts.SyntaxKind.FalseKeyword) return 'safe';
      if (/^(?:error|errors|reason)$/u.test(name ?? '')) return 'safe';
      if (/^(?:status|type|kind)$/u.test(name ?? '') && ts.isStringLiteralLike(property.initializer) &&
        /^(?:failed|failure|error|rejected)$/iu.test(property.initializer.text)) return 'safe';
      if (/^(?:status|statusCode)$/u.test(name ?? '') && (numericValue(property.initializer) ?? 0) >= 400) return 'safe';
    }
  }
  if (ts.isArrayLiteralExpression(value)) return value.elements.length === 0 ? 'absent' : 'unknown';
  if (ts.isNewExpression(value) && ts.isIdentifier(value.expression) && value.expression.text === 'Error') return 'safe';
  if (ts.isCallExpression(value)) {
    const called = callName(value.expression) ?? '';
    if (/^(?:reject|err|error|fail|failure|left)$/iu.test(called) || isHttpErrorResponseCall(value, parsed)) return 'safe';
    if (/(?:fallback|default|cached|recover|continue|resume|skip)/iu.test(called)) return 'safe';
  }
  if (ts.isIdentifier(value) && /(?:fallback|default|cached|recover|continue|resume|skip)/iu.test(value.text)) return 'safe';
  return 'unknown';
}

function caughtErrorName(clause: ts.CatchClause): string | undefined {
  const name = clause.variableDeclaration?.name;
  return name && ts.isIdentifier(name) ? name.text : undefined;
}

function expressionContainsIdentifier(expression: ts.Expression, name: string): boolean {
  let found = false;
  walkSameFunction(expression, expression, (node) => {
    if (!ts.isIdentifier(node) || node.text !== name) return;
    if (ts.isPropertyAssignment(node.parent) && node.parent.name === node) return;
    if (ts.isPropertyAccessExpression(node.parent) && node.parent.name === node) return;
    found = true;
  });
  return found;
}

function forwardsCaughtError(node: ts.CallExpression, errorName: string | undefined): boolean {
  const called = callName(node.expression) ?? '';
  if (!/^(?:next|callback|done)$/u.test(called)) return false;
  if (errorName && node.arguments.some((argument) => expressionContainsIdentifier(argument, errorName))) return true;
  return called === 'next' && node.arguments.some((argument) => {
    const value = unwrapAwaitedExpression(argument);
    return (ts.isNewExpression(value) && ts.isIdentifier(value.expression) && /Error$/u.test(value.expression.text)) ||
      (ts.isIdentifier(value) && /^(?:err|error|exception)$/iu.test(value.text));
  });
}

function localMethodKey(
  parsed: ParsedFile,
  container: ts.ClassLikeDeclaration | ts.ObjectLiteralExpression,
  methodName: string
): string | undefined {
  const members = (ts.isObjectLiteralExpression(container) ? container.properties : container.members).filter((member): member is ts.MethodDeclaration =>
    ts.isMethodDeclaration(member) && propertyName(member.name) === methodName
  );
  return members.length === 1
    ? `${parsed.file.record.path}#method:${members[0]!.name.getStart(parsed.sourceFile)}`
    : undefined;
}

function receiverContainer(
  receiver: ts.Expression,
  bindings: LexicalBindingIndex
): ts.ClassLikeDeclaration | ts.ObjectLiteralExpression | undefined {
  const value = unwrapExpression(receiver);
  if (value.kind === ts.SyntaxKind.ThisKeyword) {
    let current: ts.Node | undefined = value.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isClassDeclaration(current) || ts.isClassExpression(current) || ts.isObjectLiteralExpression(current)) return current;
      current = current.parent;
    }
    return undefined;
  }
  if (!ts.isIdentifier(value)) return undefined;
  const binding = resolvedLexicalBinding(value, bindings);
  if (!binding) return undefined;
  if (ts.isClassDeclaration(binding.declaration) || ts.isClassExpression(binding.declaration)) return binding.declaration;
  if (!ts.isVariableDeclaration(binding.declaration) || !binding.declaration.initializer) return undefined;
  const initializer = unwrapExpression(binding.declaration.initializer);
  if (ts.isObjectLiteralExpression(initializer) || ts.isClassExpression(initializer)) return initializer;
  if (!ts.isNewExpression(initializer)) return undefined;
  const constructor = unwrapExpression(initializer.expression);
  if (ts.isClassExpression(constructor)) return constructor;
  if (!ts.isIdentifier(constructor)) return undefined;
  const constructorBinding = resolvedLexicalBinding(constructor, bindings);
  return constructorBinding &&
    (ts.isClassDeclaration(constructorBinding.declaration) || ts.isClassExpression(constructorBinding.declaration))
    ? constructorBinding.declaration
    : undefined;
}

function throwingHelperCallKey(
  call: ts.CallExpression,
  parsed: ParsedFile,
  bindings: LexicalBindingIndex
): string | undefined {
  if (ts.isIdentifier(call.expression)) {
    const binding = resolvedLexicalBinding(call.expression, bindings);
    return binding ? lexicalBindingKey(parsed, binding) : undefined;
  }
  if (!ts.isPropertyAccessExpression(call.expression)) return undefined;
  const container = receiverContainer(call.expression.expression, bindings);
  return container ? localMethodKey(parsed, container, call.expression.name.text) : undefined;
}

type CatchPathOutcome = 'safe' | 'unknown' | 'continues' | 'swallowed';

function expressionHandlesCaughtFailure(
  expression: ts.Expression,
  errorName: string | undefined,
  parsed: ParsedFile,
  throwingHelpers: ReadonlySet<string>,
  bindings: LexicalBindingIndex
): boolean {
  const value = unwrapAwaitedExpression(expression);
  if (ts.isCallExpression(value)) {
    const text = value.expression.getText(parsed.sourceFile);
    if (text === 'process.exit' && numericValue(value.arguments[0]) !== undefined && numericValue(value.arguments[0]) !== 0) return true;
    if (forwardsCaughtError(value, errorName) || isHttpErrorResponseCall(value, parsed)) return true;
    if (throwingHelpers.has(throwingHelperCallKey(value, parsed, bindings) ?? '') &&
      (!errorName || value.arguments.some((argument) => expressionContainsIdentifier(argument, errorName)))) return true;
    return /^(?:sendError|respondError|respondWithError|recordFailure|markFailed)$/iu.test(callName(value.expression) ?? '') &&
      (!errorName || value.arguments.some((argument) => expressionContainsIdentifier(argument, errorName)));
  }
  if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    ts.isPropertyAccessExpression(value.left)) {
    const target = value.left.getText(parsed.sourceFile);
    const assigned = numericValue(value.right);
    return (target === 'process.exitCode' && assigned !== undefined && assigned !== 0) ||
      (/\.statusCode$/u.test(target) && assigned !== undefined && assigned >= 400);
  }
  return false;
}

function catchStatementOutcomes(
  statement: ts.Statement,
  errorName: string | undefined,
  parsed: ParsedFile,
  throwingHelpers: ReadonlySet<string>,
  bindings: LexicalBindingIndex
): Set<CatchPathOutcome> {
  if (ts.isBlock(statement)) return catchBlockOutcomes(statement, errorName, parsed, throwingHelpers, bindings);
  if (ts.isThrowStatement(statement) || ts.isContinueStatement(statement) || ts.isBreakStatement(statement)) {
    return new Set(['safe']);
  }
  if (ts.isReturnStatement(statement)) {
    if (statement.expression && expressionHandlesCaughtFailure(statement.expression, errorName, parsed, throwingHelpers, bindings)) {
      return new Set(['safe']);
    }
    const outcome = returnIsFailure(statement, parsed);
    return new Set([outcome === 'safe' ? 'safe' : outcome === 'unknown' ? 'unknown' : 'swallowed']);
  }
  if (ts.isExpressionStatement(statement) &&
    expressionHandlesCaughtFailure(statement.expression, errorName, parsed, throwingHelpers, bindings)) {
    return new Set(['safe']);
  }
  if (ts.isIfStatement(statement)) {
    const outcomes = catchStatementOutcomes(statement.thenStatement, errorName, parsed, throwingHelpers, bindings);
    const alternate = statement.elseStatement
      ? catchStatementOutcomes(statement.elseStatement, errorName, parsed, throwingHelpers, bindings)
      : new Set<CatchPathOutcome>(['continues']);
    return new Set([...outcomes, ...alternate]);
  }
  if (ts.isSwitchStatement(statement) || ts.isTryStatement(statement)) return new Set(['unknown']);
  return new Set(['continues']);
}

function catchBlockOutcomes(
  block: ts.Block,
  errorName: string | undefined,
  parsed: ParsedFile,
  throwingHelpers: ReadonlySet<string>,
  bindings: LexicalBindingIndex
): Set<CatchPathOutcome> {
  let outcomes = new Set<CatchPathOutcome>(['continues']);
  for (const statement of block.statements) {
    const next = new Set<CatchPathOutcome>();
    for (const outcome of outcomes) {
      if (outcome !== 'continues') next.add(outcome);
      else for (const branchOutcome of catchStatementOutcomes(statement, errorName, parsed, throwingHelpers, bindings)) next.add(branchOutcome);
    }
    outcomes = next;
  }
  return outcomes;
}

function isStructuredParseCall(node: ts.CallExpression, parsed: ParsedFile): boolean {
  return /^(?:JSON\.parse|yaml\.parse|YAML\.parse)$/u.test(node.expression.getText(parsed.sourceFile));
}

function parseOnlyTryBlock(block: ts.Block, parsed: ParsedFile): boolean {
  let parsesStructuredText = false;
  let unsupportedOperation = false;
  walkSameFunction(block, block, (candidate) => {
    if (unsupportedOperation) return;
    if (ts.isCallExpression(candidate)) {
      if (isStructuredParseCall(candidate, parsed)) parsesStructuredText = true;
      else unsupportedOperation = true;
      return;
    }
    if (ts.isAwaitExpression(candidate) || ts.isYieldExpression(candidate) || ts.isNewExpression(candidate) ||
      ts.isThrowStatement(candidate) || ts.isDeleteExpression(candidate) ||
      ts.isPrefixUnaryExpression(candidate) &&
        (candidate.operator === ts.SyntaxKind.PlusPlusToken || candidate.operator === ts.SyntaxKind.MinusMinusToken) ||
      ts.isPostfixUnaryExpression(candidate)) {
      unsupportedOperation = true;
      return;
    }
    if (ts.isBinaryExpression(candidate) &&
      candidate.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      candidate.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
      unsupportedOperation = true;
      return;
    }
    if (!ts.isReturnStatement(candidate)) return;
    const value = candidate.expression && unwrapExpression(candidate.expression);
    if (!value) {
      unsupportedOperation = true;
      return;
    }
    if (ts.isCallExpression(value) && isStructuredParseCall(value, parsed)) return;
    if (ts.isIdentifier(value)) {
      const initializer = immutableInitializerFor(parsed, value);
      if (initializer && ts.isCallExpression(unwrapExpression(initializer)) &&
        isStructuredParseCall(unwrapExpression(initializer) as ts.CallExpression, parsed)) return;
    }
    unsupportedOperation = true;
  });
  return parsesStructuredText && !unsupportedOperation;
}

function intentionalParseProbeCatch(clause: ts.CatchClause, parsed: ParsedFile): boolean {
  if (clause.block.statements.length > 0) return false;
  let loop: ts.Node | undefined = clause.parent;
  while (loop && !ts.isFunctionLike(loop) && !ts.isSourceFile(loop) &&
    !ts.isForStatement(loop) && !ts.isForInStatement(loop) && !ts.isForOfStatement(loop) &&
    !ts.isWhileStatement(loop) && !ts.isDoStatement(loop)) loop = loop.parent;
  if (!loop || ts.isFunctionLike(loop) || ts.isSourceFile(loop)) return false;
  return parseOnlyTryBlock(clause.parent.tryBlock, parsed);
}

function locallyProvenThrowingHelpers(parsed: ParsedFile): Set<string> {
  const bindings = new Set<string>();
  walk(parsed.sourceFile, (node) => {
    const runtime = ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node);
    if (!runtime && !ts.isMethodDeclaration(node)) return;
    const body = node.body;
    if (!body || !ts.isBlock(body)) return;
    const finalStatement = body.statements.at(-1);
    if (!finalStatement || !ts.isThrowStatement(finalStatement)) return;
    let hasReturn = false;
    walkSameFunction(body, body, (candidate) => {
      if (ts.isReturnStatement(candidate)) hasReturn = true;
    });
    if (hasReturn) return;
    if (ts.isMethodDeclaration(node)) {
      bindings.add(`${parsed.file.record.path}#method:${node.name.getStart(parsed.sourceFile)}`);
      return;
    }
    const identifier = functionBindingIdentifier(node);
    if (identifier) bindings.add(`${parsed.file.record.path}#binding:${identifier.getStart(parsed.sourceFile)}`);
  });
  return bindings;
}

function catchOutcome(
  clause: ts.CatchClause,
  parsed: ParsedFile,
  throwingHelpers: ReadonlySet<string>,
  bindings: LexicalBindingIndex
): 'safe' | 'swallowed' | 'unknown' {
  if (intentionalParseProbeCatch(clause, parsed)) return 'safe';
  const outcomes = catchBlockOutcomes(clause.block, caughtErrorName(clause), parsed, throwingHelpers, bindings);
  if (outcomes.has('continues') || outcomes.has('swallowed')) return 'swallowed';
  return outcomes.has('unknown') ? 'unknown' : 'safe';
}

function returnedOperation(expression: ts.Expression, parsed: ParsedFile): boolean {
  let value = unwrapAwaitedExpression(expression);
  if (ts.isCallExpression(value)) return true;
  if (!ts.isIdentifier(value)) return false;
  const initializer = immutableInitializerFor(parsed, value);
  if (!initializer) return false;
  value = unwrapAwaitedExpression(initializer);
  return ts.isCallExpression(value);
}

function catchHasResultObligation(clause: ts.CatchClause, parsed: ParsedFile): boolean {
  const tryStatement = clause.parent;
  if (!ts.isTryStatement(tryStatement)) return false;
  let obligated = false;
  walkSameFunction(tryStatement.tryBlock, tryStatement.tryBlock, (node) => {
    if (ts.isReturnStatement(node) && node.expression && returnedOperation(node.expression, parsed)) obligated = true;
  });
  return obligated;
}

function runtimeScope(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node;
  while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current)) current = current.parent;
  return (current && (ts.isFunctionLike(current) || ts.isSourceFile(current))) ? current : node.getSourceFile();
}

function branchSignature(node: ts.Node, parsed: ParsedFile): string {
  const parts: string[] = [];
  let current: ts.Node = node;
  const scope = runtimeScope(node);
  while (current !== scope && current.parent) {
    const parent = current.parent;
    if (ts.isIfStatement(parent)) {
      if (current === parent.thenStatement) parts.push(`if:${parent.getStart(parsed.sourceFile)}:then`);
      if (current === parent.elseStatement) parts.push(`if:${parent.getStart(parsed.sourceFile)}:else`);
    } else if (ts.isConditionalExpression(parent)) {
      if (current === parent.whenTrue) parts.push(`conditional:${parent.getStart(parsed.sourceFile)}:true`);
      if (current === parent.whenFalse) parts.push(`conditional:${parent.getStart(parsed.sourceFile)}:false`);
    } else if (ts.isBinaryExpression(parent) && current === parent.right &&
      (parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        parent.operatorToken.kind === ts.SyntaxKind.BarBarToken)) {
      parts.push(`logical:${parent.getStart(parsed.sourceFile)}:${parent.operatorToken.kind}`);
    } else if (ts.isCatchClause(parent) && current === parent.block) {
      parts.push(`catch:${parent.getStart(parsed.sourceFile)}`);
    } else if (ts.isCaseClause(parent) || ts.isDefaultClause(parent)) {
      parts.push(`case:${parent.getStart(parsed.sourceFile)}`);
    }
    current = parent;
  }
  return parts.reverse().join('/');
}

function errorConditionPolarity(expression: ts.Expression, parsed: ParsedFile): 'true' | 'false' | 'unknown' {
  const text = expression.getText(parsed.sourceFile);
  if (/!\s*(?:error|failure|failed|exception|rejected)\b/iu.test(text) ||
    /\b(?:errors?|failures?)\b\s*(?:={2,3}|<=?)\s*0\b/iu.test(text) ||
    /\b(?:error|failure|failed|exception|rejected)\b\s*(?:={2,3})\s*(?:null|undefined|false)\b/iu.test(text) ||
    /^\s*(?:success|ok)\s*$/iu.test(text)) return 'false';
  if (/!\s*(?:success|ok)\b/iu.test(text) ||
    /\b(?:errors?|failures?)\b\s*(?:>|>=|!==?)\s*0\b/iu.test(text) ||
    /\b(?:error|failure|failed|exception|rejected|fatal)\b/iu.test(text)) return 'true';
  return 'unknown';
}

function hasErrorPathContext(node: ts.CallExpression, parsed: ParsedFile): boolean {
  let current: ts.Node | undefined = node;
  let caught = false;
  const scope = runtimeScope(node);
  while (current && current !== scope && current.parent) {
    const parent: ts.Node = current.parent;
    if (ts.isCatchClause(parent)) caught = true;
    if (ts.isIfStatement(parent) && (current === parent.thenStatement || current === parent.elseStatement)) {
      const polarity = errorConditionPolarity(parent.expression, parsed);
      if (polarity !== 'unknown') {
        const errorBranch = current === parent.thenStatement ? polarity === 'true' : polarity === 'false';
        if (!errorBranch) return false;
        return true;
      }
    }
    current = parent;
  }
  if (caught) return true;
  if (ts.isFunctionLike(scope) && ts.isCallExpression(scope.parent) && scope.parent.arguments.some((argument) => argument === scope) &&
    ts.isPropertyAccessExpression(scope.parent.expression) && scope.parent.expression.name.text === 'catch') return true;
  const argumentsText = node.arguments.map((argument) => argument.getText(parsed.sourceFile)).join(' ')
    .replace(/\b(?:0|no)\s+(?:errors?|failures?|exceptions?)\b/giu, '');
  return /(?:\berrors?\b|fail|exception|reject|fatal)/iu.test(argumentsText);
}

function isSuccessfulExit(node: ts.Node, parsed: ParsedFile): boolean {
  if (ts.isCallExpression(node) && node.expression.getText(parsed.sourceFile) === 'process.exit') {
    return numericValue(node.arguments[0]) === 0;
  }
  return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    node.left.getText(parsed.sourceFile) === 'process.exitCode' && numericValue(node.right) === 0;
}

function hasTerminationBetween(stdout: ts.Node, exit: ts.Node, parsed: ParsedFile): boolean {
  const scope = runtimeScope(stdout);
  const branch = branchSignature(stdout, parsed);
  let terminated = false;
  walkSameFunction(scope, scope, (candidate) => {
    if (terminated || candidate.getStart(parsed.sourceFile) <= stdout.getEnd() ||
      candidate.getStart(parsed.sourceFile) >= exit.getStart(parsed.sourceFile)) return;
    const exitsProcess = ts.isCallExpression(candidate) && candidate.expression.getText(parsed.sourceFile) === 'process.exit';
    if ((ts.isReturnStatement(candidate) || ts.isThrowStatement(candidate) || exitsProcess) && branchSignature(candidate, parsed) === branch) {
      terminated = true;
    }
  });
  return terminated;
}

function detectCliSuccessOnError(parsed: ParsedFile, state: AnalysisState): void {
  if (!isProductionConsumer(parsed.file) ||
    !/(?:^|\/)(?:cli|bin)(?:\/|$)|(?:^|\/)cli\.[cm]?[jt]sx?$/iu.test(parsed.file.record.path)) return;
  const stdoutWrites: ts.CallExpression[] = [];
  const successfulExits: ts.Node[] = [];
  walk(parsed.sourceFile, (node) => {
    if (ts.isCallExpression(node) && /^(?:console\.log|process\.stdout\.write)$/u.test(node.expression.getText(parsed.sourceFile)) &&
      hasErrorPathContext(node, parsed)) stdoutWrites.push(node);
    if (isSuccessfulExit(node, parsed)) successfulExits.push(node);
  });
  for (const stdout of stdoutWrites) {
    const scope = runtimeScope(stdout);
    const branch = branchSignature(stdout, parsed);
    if (!successfulExits.some((exit) =>
      exit.getStart(parsed.sourceFile) > stdout.getEnd() &&
      runtimeScope(exit) === scope && branchSignature(exit, parsed) === branch &&
      !hasTerminationBetween(stdout, exit, parsed))) continue;
    addFinding(state, OPERATIONAL_RULE_IDS.resultCollapse, nodeAnchor(parsed, stdout), {
      kind: 'defect-candidate', severity: 'high', confidence: 'high',
      title: 'A CLI error path writes to stdout and records a successful exit',
      description: 'A supported local error-path shape reports through stdout and explicitly selects exit status zero.',
      signals: ['error-written-to-stdout', 'successful-exit-status-on-error-path'],
      nextValidation: 'Write diagnostics to stderr and return a nonzero exit status that the caller must observe.',
      patternMaterial: { mechanism: 'cli-success-on-error' }
    });
  }
}

interface DurableWriterContract {
  key: string;
  aliases: string[];
  persistedParameterIndexes: Set<number>;
  mutationAnchors: Anchor[];
}

interface BoundResultCall {
  call: ts.CallExpression;
  contract: ReturnContract;
}

interface BranchArm {
  control: string;
  arm: string;
}

function referencesLexicalBinding(
  node: ts.Node,
  nameNode: ts.Identifier,
  bindings: LexicalBindingIndex
): boolean {
  let found = false;
  walkSameFunction(node, node, (candidate) => {
    if (found || !ts.isIdentifier(candidate) || candidate === nameNode || candidate.text !== nameNode.text) return;
    if (resolvedLexicalBinding(candidate, bindings)?.nameNode === nameNode) found = true;
  });
  return found;
}

function bindingIsReassigned(
  body: ts.Block,
  nameNode: ts.Identifier,
  bindings: LexicalBindingIndex
): boolean {
  let reassigned = false;
  walkSameFunction(body, body, (candidate) => {
    if (reassigned) return;
    const assigned = ts.isBinaryExpression(candidate) &&
      candidate.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      candidate.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      ? candidate.left
      : (ts.isPrefixUnaryExpression(candidate) || ts.isPostfixUnaryExpression(candidate)) &&
          (candidate.operator === ts.SyntaxKind.PlusPlusToken || candidate.operator === ts.SyntaxKind.MinusMinusToken)
        ? candidate.operand
        : undefined;
    const value = assigned && unwrapExpression(assigned);
    if (value && ts.isIdentifier(value) &&
      resolvedLexicalBinding(value, bindings)?.nameNode === nameNode) reassigned = true;
  });
  return reassigned;
}

function collectDurableWriterContracts(parsedFiles: ParsedFile[]): Map<string, DurableWriterContract[]> {
  const byKey = new Map<string, DurableWriterContract[]>();
  const add = (key: string, contract: DurableWriterContract): void => {
    const current = byKey.get(key) ?? [];
    current.push(contract);
    byKey.set(key, current);
  };
  for (const parsed of parsedFiles) {
    const bindings = lexicalBindingsFor(parsed);
    walk(parsed.sourceFile, (node) => {
      if (
        !ts.isFunctionDeclaration(node) && !ts.isFunctionExpression(node) && !ts.isArrowFunction(node) &&
        !ts.isMethodDeclaration(node)
      ) return;
      if (!node.body || !ts.isBlock(node.body)) return;
      const identity = resultFunctionIdentity(parsed, node);
      if (!identity) return;
      const mutations: ts.CallExpression[] = [];
      walkSameFunction(node.body, node.body, (candidate) => {
        if (ts.isCallExpression(candidate) && mutationBoundary(candidate, parsed)) mutations.push(candidate);
      });
      if (mutations.length === 0) return;
      const persistedParameterIndexes = new Set<number>();
      node.parameters.forEach((parameter, index) => {
        if (!ts.isIdentifier(parameter.name) || bindingIsReassigned(node.body as ts.Block, parameter.name, bindings)) return;
        if (mutations.some((mutation) => mutation.arguments.some((argument) =>
          referencesLexicalBinding(argument, parameter.name as ts.Identifier, bindings)))) {
          persistedParameterIndexes.add(index);
        }
      });
      if (persistedParameterIndexes.size === 0) return;
      const contract: DurableWriterContract = {
        key: identity.key,
        aliases: identity.aliases,
        persistedParameterIndexes,
        mutationAnchors: mutations.map((mutation) => nodeAnchor(parsed, mutation))
      };
      for (const key of [contract.key, ...contract.aliases]) add(key, contract);
    });
  }
  return byKey;
}

function semanticWords(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/gu, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter(Boolean);
}

function successOutcomeFamily(value: string): string | undefined {
  const words = semanticWords(value);
  if (words.some((word) => /^(?:error|failed|failure|suppressed|skipped|unsent)$/u.test(word)) ||
    words.some((word, index) => word === 'not' && words[index + 1] === 'sent')) return undefined;
  if (words.some((word) => /^(?:sent|delivered|notified|confirmed)$/u.test(word))) {
    return 'delivery';
  }
  if (words.some((word) => /^(?:success|succeeded|completed|processed)$/u.test(word))) {
    return 'completion';
  }
  return undefined;
}

function staticStringValue(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  const value = unwrapExpression(expression);
  return ts.isStringLiteralLike(value) ? value.text : undefined;
}

function callableOutcomeFamily(name: string): string | undefined {
  const words = semanticWords(name);
  if (words.some((word) => /^(?:send|deliver|notify|confirm)$/u.test(word))) return 'delivery';
  if (words.some((word) => /^(?:succeed|complete|process)$/u.test(word))) return 'completion';
  return undefined;
}

function branchArms(node: ts.Node, parsed: ParsedFile): BranchArm[] {
  const arms: BranchArm[] = [];
  const scope = runtimeScope(node);
  let current: ts.Node = node;
  while (current !== scope && current.parent) {
    const parent = current.parent;
    if (ts.isIfStatement(parent)) {
      if (current === parent.thenStatement) arms.push({ control: `if:${parent.getStart(parsed.sourceFile)}`, arm: 'then' });
      if (current === parent.elseStatement) arms.push({ control: `if:${parent.getStart(parsed.sourceFile)}`, arm: 'else' });
    } else if (ts.isConditionalExpression(parent)) {
      if (current === parent.whenTrue) arms.push({ control: `conditional:${parent.getStart(parsed.sourceFile)}`, arm: 'true' });
      if (current === parent.whenFalse) arms.push({ control: `conditional:${parent.getStart(parsed.sourceFile)}`, arm: 'false' });
    } else if (ts.isBinaryExpression(parent) && current === parent.right &&
      (parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        parent.operatorToken.kind === ts.SyntaxKind.BarBarToken)) {
      arms.push({ control: `logical:${parent.getStart(parsed.sourceFile)}`, arm: String(parent.operatorToken.kind) });
    } else if (ts.isTryStatement(parent)) {
      if (current === parent.tryBlock) arms.push({ control: `try:${parent.getStart(parsed.sourceFile)}`, arm: 'try' });
      if (current === parent.catchClause) arms.push({ control: `try:${parent.getStart(parsed.sourceFile)}`, arm: 'catch' });
      if (current === parent.finallyBlock) arms.push({ control: `try:${parent.getStart(parsed.sourceFile)}`, arm: 'finally' });
    } else if ((ts.isCaseClause(current) || ts.isDefaultClause(current)) && ts.isCaseBlock(parent) &&
      ts.isSwitchStatement(parent.parent)) {
      arms.push({
        control: `switch:${parent.parent.getStart(parsed.sourceFile)}`,
        arm: `case:${current.getStart(parsed.sourceFile)}`
      });
    }
    current = parent;
  }
  return arms;
}

function branchesAreCompatible(left: ts.Node, right: ts.Node, parsed: ParsedFile): boolean {
  const rightArms = new Map(branchArms(right, parsed).map((entry) => [entry.control, entry.arm]));
  return branchArms(left, parsed).every((entry) =>
    !rightArms.has(entry.control) || rightArms.get(entry.control) === entry.arm);
}

function pathTerminatesBeforeWrite(call: ts.CallExpression, write: ts.CallExpression, parsed: ParsedFile): boolean {
  const callArms = new Map(branchArms(call, parsed).map((entry) => [entry.control, entry.arm]));
  const scope = runtimeScope(call);
  let terminated = false;
  walkSameFunction(scope, scope, (candidate) => {
    if (terminated || candidate.getStart(parsed.sourceFile) <= call.getEnd() ||
      candidate.getEnd() > write.getStart(parsed.sourceFile)) return;
    const exitsProcess = ts.isCallExpression(candidate) && candidate.expression.getText(parsed.sourceFile) === 'process.exit';
    if (!ts.isReturnStatement(candidate) && !ts.isThrowStatement(candidate) && !exitsProcess) return;
    const terminatingArms = branchArms(candidate, parsed);
    if (terminatingArms.every((entry) => callArms.get(entry.control) === entry.arm)) terminated = true;
  });
  return terminated;
}

function nodeContains(container: ts.Node, candidate: ts.Node): boolean {
  return container.getStart() <= candidate.getStart() && container.getEnd() >= candidate.getEnd();
}

function statementAlwaysTerminates(statement: ts.Statement): boolean {
  if (ts.isReturnStatement(statement) || ts.isThrowStatement(statement)) return true;
  if (ts.isBlock(statement)) {
    const last = statement.statements.at(-1);
    return last !== undefined && statementAlwaysTerminates(last);
  }
  if (ts.isIfStatement(statement) && statement.elseStatement) {
    return statementAlwaysTerminates(statement.thenStatement) && statementAlwaysTerminates(statement.elseStatement);
  }
  return ts.isExpressionStatement(statement) && ts.isCallExpression(statement.expression) &&
    statement.expression.expression.getText() === 'process.exit';
}

function discriminatorUseControlsWrite(use: ts.Node, write: ts.CallExpression): boolean {
  const scope = runtimeScope(use);
  let current: ts.Node = use;
  while (current !== scope && current.parent) {
    const parent = current.parent;
    if (ts.isIfStatement(parent) && nodeContains(parent.expression, use)) {
      if (nodeContains(parent.thenStatement, write) ||
        (parent.elseStatement !== undefined && nodeContains(parent.elseStatement, write))) return true;
      if (parent.getEnd() <= write.getStart() && (
        statementAlwaysTerminates(parent.thenStatement) ||
        (parent.elseStatement !== undefined && statementAlwaysTerminates(parent.elseStatement))
      )) return true;
    }
    if (ts.isConditionalExpression(parent) && nodeContains(parent.condition, use) && (
      nodeContains(parent.whenTrue, write) || nodeContains(parent.whenFalse, write)
    )) return true;
    if (ts.isSwitchStatement(parent) && nodeContains(parent.expression, use)) {
      if (nodeContains(parent.caseBlock, write)) return true;
      if (parent.getEnd() <= write.getStart() && parent.caseBlock.clauses.some((clause) => {
        const last = clause.statements.at(-1);
        return last !== undefined && statementAlwaysTerminates(last);
      })) return true;
    }
    if ((ts.isWhileStatement(parent) || ts.isDoStatement(parent)) && nodeContains(parent.expression, use) &&
      nodeContains(parent.statement, write)) return true;
    if (ts.isForStatement(parent) && parent.condition && nodeContains(parent.condition, use) &&
      nodeContains(parent.statement, write)) return true;
    if (ts.isBinaryExpression(parent) && current === parent.left &&
      (parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        parent.operatorToken.kind === ts.SyntaxKind.BarBarToken) && nodeContains(parent.right, write)) return true;
    current = parent;
  }
  return false;
}

function bindingControlsWrite(
  nameNode: ts.Identifier,
  call: ts.CallExpression,
  write: ts.CallExpression,
  parsed: ParsedFile,
  bindings: LexicalBindingIndex
): boolean {
  const declarationBinding = (bindings.get(nameNode.text) ?? []).find((binding) => binding.nameNode === nameNode);
  if (!declarationBinding) return false;
  const scope = containingScope(nameNode);
  let controls = false;
  walkSameFunction(scope, scope, (candidate) => {
    if (controls || !ts.isIdentifier(candidate) || candidate === nameNode ||
      candidate.getStart(parsed.sourceFile) <= call.getEnd() ||
      candidate.getStart(parsed.sourceFile) >= write.getStart(parsed.sourceFile) ||
      resolvedLexicalBinding(candidate, bindings)?.nameNode !== declarationBinding.nameNode) return;
    if (discriminatorUseControlsWrite(candidate, write)) controls = true;
  });
  return controls;
}

function resultFlowBeforeWrite(
  call: ts.CallExpression,
  write: ts.CallExpression,
  contract: ReturnContract,
  parsed: ParsedFile,
  bindings: LexicalBindingIndex
): 'unchecked' | 'handled' | 'unknown' {
  let resultNode: ts.Node = call;
  while (
    ts.isAwaitExpression(resultNode.parent) || ts.isParenthesizedExpression(resultNode.parent) ||
    ts.isAsExpression(resultNode.parent) || ts.isTypeAssertionExpression(resultNode.parent) ||
    ts.isNonNullExpression(resultNode.parent) || ts.isSatisfiesExpression(resultNode.parent)
  ) resultNode = resultNode.parent;
  const parent = resultNode.parent;
  if (ts.isExpressionStatement(parent)) return 'unchecked';
  if (ts.isPropertyAccessExpression(parent) && parent.expression === resultNode) {
    if (!contract.possibleDiscriminatorKeys.has(parent.name.text)) return 'unchecked';
    if (discriminatorUseControlsWrite(parent, write)) return 'handled';
    let valueNode: ts.Node = parent;
    while (
      ts.isParenthesizedExpression(valueNode.parent) || ts.isAsExpression(valueNode.parent) ||
      ts.isTypeAssertionExpression(valueNode.parent) || ts.isNonNullExpression(valueNode.parent) ||
      ts.isSatisfiesExpression(valueNode.parent)
    ) valueNode = valueNode.parent;
    return ts.isVariableDeclaration(valueNode.parent) && ts.isIdentifier(valueNode.parent.name) &&
      bindingControlsWrite(valueNode.parent.name, call, write, parsed, bindings)
      ? 'handled'
      : 'unchecked';
  }
  if (!ts.isVariableDeclaration(parent)) return 'unknown';
  if (ts.isObjectBindingPattern(parent.name)) {
    for (const element of parent.name.elements) {
      const key = propertyName(element.propertyName) ?? element.name.getText(parsed.sourceFile);
      if (!contract.possibleDiscriminatorKeys.has(key) || !ts.isIdentifier(element.name)) continue;
      if (bindingControlsWrite(element.name, call, write, parsed, bindings)) return 'handled';
    }
    return 'unchecked';
  }
  if (!ts.isIdentifier(parent.name)) return 'unknown';
  const declarationBinding = (bindings.get(parent.name.text) ?? []).find((binding) => binding.nameNode === parent.name);
  if (!declarationBinding) return 'unknown';
  let handled = false;
  let unknown = false;
  const scope = containingScope(parent);
  walkSameFunction(scope, scope, (candidate) => {
    if (handled || unknown || !ts.isIdentifier(candidate) || candidate === parent.name ||
      candidate.getStart(parsed.sourceFile) <= call.getEnd() ||
      candidate.getStart(parsed.sourceFile) >= write.getStart(parsed.sourceFile) ||
      resolvedLexicalBinding(candidate, bindings)?.nameNode !== declarationBinding.nameNode) return;
    const use = candidate.parent;
    if (ts.isPropertyAccessExpression(use) && use.expression === candidate) {
      if (contract.possibleDiscriminatorKeys.has(use.name.text) && discriminatorUseControlsWrite(use, write)) handled = true;
      return;
    }
    if (ts.isElementAccessExpression(use) && use.expression === candidate) {
      const key = staticStringValue(use.argumentExpression);
      if (key && contract.possibleDiscriminatorKeys.has(key)) {
        if (discriminatorUseControlsWrite(use, write)) handled = true;
      }
      else unknown = true;
      return;
    }
    unknown = true;
  });
  return handled ? 'handled' : unknown ? 'unknown' : 'unchecked';
}

function uniqueAnchors(anchors: Anchor[]): Anchor[] {
  return [...new Map(anchors.map((anchor) => [
    `${anchor.file.record.path}\0${anchor.start}\0${anchor.end}`,
    anchor
  ])).values()];
}

function detectDurableSuccessSideEffects(
  parsed: ParsedFile,
  calls: BoundResultCall[],
  durableWriters: ReadonlyMap<string, DurableWriterContract[]>,
  relationships: RelationshipRecord[],
  bindings: LexicalBindingIndex,
  state: AnalysisState
): void {
  if (!isProductionConsumer(parsed.file) || calls.length === 0) return;
  const writes: Array<{
    call: ts.CallExpression;
    writer: DurableWriterContract;
    outcomeFamily: string;
    literal: string;
  }> = [];
  walk(parsed.sourceFile, (node) => {
    if (!ts.isCallExpression(node)) return;
    if (mutationBoundary(node, parsed)) {
      for (const argument of node.arguments) {
        const literal = staticStringValue(argument);
        const outcomeFamily = literal && successOutcomeFamily(literal);
        if (!literal || !outcomeFamily) continue;
        writes.push({
          call: node,
          writer: {
            key: `${parsed.file.record.path}#direct-mutation:${node.expression.getText(parsed.sourceFile)}`,
            aliases: [],
            persistedParameterIndexes: new Set(),
            mutationAnchors: [nodeAnchor(parsed, node)]
          },
          outcomeFamily,
          literal
        });
        return;
      }
    }
    const key = calledContractKey(parsed, node, bindings, relationships);
    if (!key) return;
    const candidates = durableWriters.get(key) ?? [];
    if (candidates.length !== 1) return;
    const writer = candidates[0]!;
    for (const index of writer.persistedParameterIndexes) {
      const literal = staticStringValue(node.arguments[index]);
      const outcomeFamily = literal && successOutcomeFamily(literal);
      if (!literal || !outcomeFamily) continue;
      writes.push({ call: node, writer, outcomeFamily, literal });
      break;
    }
  });
  for (const write of writes) {
    const eligible = calls.filter(({ call, contract }) => {
      if (call.getEnd() >= write.call.getStart(parsed.sourceFile) || runtimeScope(call) !== runtimeScope(write.call)) return false;
      if (callableOutcomeFamily(contract.name) !== write.outcomeFamily || !branchesAreCompatible(call, write.call, parsed)) return false;
      if (pathTerminatesBeforeWrite(call, write.call, parsed)) return false;
      return resultFlowBeforeWrite(call, write.call, contract, parsed, bindings) === 'unchecked';
    });
    if (eligible.length === 0) continue;
    const related = uniqueAnchors([
      ...eligible.flatMap(({ call, contract }) => [nodeAnchor(parsed, call), contract.anchor]),
      ...write.writer.mutationAnchors
    ]);
    const discriminatorKeys = [...new Set(eligible.flatMap(({ contract }) => [...contract.possibleDiscriminatorKeys]))]
      .sort(compareCanonicalText);
    addFinding(state, OPERATIONAL_RULE_IDS.resultCollapse, nodeAnchor(parsed, write.call), {
      kind: 'defect-candidate', severity: 'high', confidence: 'high',
      title: 'A durable success outcome is written without checking a result discriminator',
      description: 'A supported result can report suppression or another discriminated outcome, while a later durable write persists a success-shaped literal without consulting that discriminator.',
      signals: ['durable-success-write-without-discriminator-branch', 'rich-result-contract', 'success-outcome-literal'],
      nextValidation: 'Inspect the result discriminator before persisting the successful outcome, and record the actual suppressed, skipped, failed, or delivered state.',
      patternMaterial: {
        mechanism: 'durable-success-side-effect',
        outcomeFamily: write.outcomeFamily,
        sink: stableHash(write.writer.key),
        discriminatorShape: stableHash(discriminatorKeys)
      },
      related
    });
  }
}

function detectResultCollapse(
  parsedFiles: ParsedFile[],
  relationships: RelationshipRecord[],
  state: AnalysisState
): void {
  const contracts = collectReturnContracts(parsedFiles);
  const durableWriters = collectDurableWriterContracts(parsedFiles);
  const byKey = new Map<string, ReturnContract[]>();
  for (const contract of contracts) {
    for (const key of [contract.key, ...contract.aliases]) {
      const current = byKey.get(key) ?? [];
      current.push(contract);
      byKey.set(key, current);
    }
  }
  for (const parsed of parsedFiles) {
    const bindings = lexicalBindingsFor(parsed);
    const throwingHelpers = locallyProvenThrowingHelpers(parsed);
    const boundResultCalls: BoundResultCall[] = [];
    walk(parsed.sourceFile, (node) => {
      if (ts.isCallExpression(node) && isProductionConsumer(parsed.file)) {
        const key = calledContractKey(parsed, node, bindings, relationships);
        if (key) {
          const candidates = byKey.get(key) ?? [];
          if (candidates.length > 1) {
            addDiagnostic(
              state,
              OPERATIONAL_RULE_IDS.resultCollapse,
              'OPERATIONAL_RESULT_CONTRACT_AMBIGUOUS',
              'Multiple functions share a result-producing name, so Atlas did not bind this caller to one return contract.',
              nodeAnchor(parsed, node),
              { mechanism: 'ambiguous-function-name' }
            );
          } else if (candidates.length === 1) {
            const contract = candidates[0]!;
            boundResultCalls.push({ call: node, contract });
            const used = accessedResultKeys(parsed, node, bindings);
            if (used.size === 1 && used.has('success') &&
              [...contract.keys].some((contractKey) => RESULT_DISCRIMINATOR_KEY.test(contractKey))) {
              addFinding(state, OPERATIONAL_RULE_IDS.resultCollapse, nodeAnchor(parsed, node), {
                kind: 'defect-candidate', severity: 'high', confidence: 'high',
                title: 'A caller collapses a discriminated result to its success boolean',
                description: 'The callee returns success plus additional outcome discriminators, while this supported direct caller reads success alone.',
                signals: ['rich-result-contract', 'caller-reads-success-only'],
                nextValidation: 'Handle the suppressed, skipped, status, reason, or error discriminator before recording the operation as completed.',
                patternMaterial: {
                  mechanism: 'result-collapse',
                  contractShape: stableHash([...contract.keys].sort(compareCanonicalText)),
                  contractIdentity: stableHash(contract.key)
                },
                related: [contract.anchor]
              });
            }
          }
        }
      }
      if (ts.isCatchClause(node)) {
        if (!isProductionConsumer(parsed.file) || !catchHasResultObligation(node, parsed)) return;
        const outcome = catchOutcome(node, parsed, throwingHelpers, bindings);
        if (outcome === 'unknown') {
          addDiagnostic(
            state,
            OPERATIONAL_RULE_IDS.resultCollapse,
            'OPERATIONAL_CATCH_OUTCOME_UNKNOWN',
            'A catch returns a value whose failure semantics could not be established, so Atlas made no swallowed-outcome claim.',
            nodeAnchor(parsed, node),
            { mechanism: 'unknown-catch-return' }
          );
          return;
        }
        if (outcome === 'safe') return;
        addFinding(state, OPERATIONAL_RULE_IDS.resultCollapse, nodeAnchor(parsed, node), {
          kind: 'defect-candidate', severity: 'medium', confidence: 'high',
          title: 'A catch block does not preserve a distinguishable failure outcome',
          description: 'The catch neither rethrows, returns a failure value, nor writes through a supported durable failure channel.',
          signals: ['caught-error-not-propagated', 'durable-failure-outcome-not-observed'],
          nextValidation: 'Rethrow, return a typed failure, or persist a durable failure state that callers are required to handle.',
          patternMaterial: {
            mechanism: 'swallowed-catch'
          }
        });
      }
    });
    detectDurableSuccessSideEffects(parsed, boundResultCalls, durableWriters, relationships, bindings, state);
    detectCliSuccessOnError(parsed, state);
  }
}

function normalizedGuardFragment(value: string): string {
  return value
    .replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/gu, (literal) =>
      `string:${stableHash(literal.slice(1, -1)).slice(0, 16)}`)
    .replace(/\b\d+(?:\.\d+)?\b/gu, (literal) => `number:${stableHash(literal).slice(0, 16)}`)
    .replace(/\s+/gu, '')
    .toLowerCase();
}

function stripSqlComments(source: string): string {
  let output = '';
  let quote = '';
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]!;
    const next = source[index + 1];
    if (quote) {
      output += character;
      if (character === quote && source[index - 1] !== '\\') quote = '';
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      output += character;
      continue;
    }
    if (character === '-' && next === '-') {
      while (index < source.length && source[index] !== '\n') {
        output += ' ';
        index += 1;
      }
      if (index < source.length) output += '\n';
      continue;
    }
    if (character === '/' && next === '*') {
      output += '  ';
      index += 2;
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) {
        output += source[index] === '\n' ? '\n' : ' ';
        index += 1;
      }
      if (index < source.length) {
        output += '  ';
        index += 1;
      }
      continue;
    }
    output += character;
  }
  return output;
}

function isDuplicateGuardInput(file: AnalysisFile): boolean {
  return isProductionConsumer(file) &&
    !/(?:^|\/)(?:__mocks__|mocks?|stubs?|fixtures?)(?:\/|$)|\.(?:mock|fixture)\.[cm]?[jt]sx?$/iu.test(file.record.path);
}

function detectDuplicateGuards(parsedFiles: ParsedFile[], files: AnalysisFile[], state: AnalysisState): void {
  const groups = new Map<string, Anchor[]>();
  function add(raw: string, anchor: Anchor): void {
    if (!/\btenant(?:Id|ID|_id)?\b|\b(?:auth|authorization|authorized|permission|role|scope|access|owner)(?:[A-Z_]|\b)/iu.test(raw)) return;
    const normalized = normalizedGuardFragment(raw);
    const semanticTokens = raw.match(/[A-Za-z_$][\w$]*/gu) ?? [];
    const comparisons = raw.match(/===?|!==?|<=?|>=?|\b(?:IN|EXISTS|LIKE|IS)\b/giu) ?? [];
    if (normalized.length < 20 || semanticTokens.length < 4 || comparisons.length === 0) return;
    const signature = stableHash(normalized);
    const current = groups.get(signature) ?? [];
    current.push(anchor);
    groups.set(signature, current);
  }
  for (const parsed of parsedFiles.filter((entry) => isDuplicateGuardInput(entry.file))) {
    walk(parsed.sourceFile, (node) => {
      if (ts.isIfStatement(node)) add(node.expression.getText(parsed.sourceFile), nodeAnchor(parsed, node.expression));
    });
  }
  for (const file of files.filter((entry) => isDuplicateGuardInput(entry) && (/\.sql$/iu.test(entry.record.path) || entry.record.language === 'sql'))) {
    const source = stripSqlComments(file.content.toString('utf8'));
    for (const match of source.matchAll(/\bWHERE\b\s+([\s\S]*?)(?=\b(?:GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|RETURNING|UNION)\b|;|$)/giu)) {
      add(match[1]!, regexAnchor(file, match));
    }
  }
  for (const [signature, rawAnchors] of [...groups].sort(([left], [right]) => compareCanonicalText(left, right))) {
    const anchors = [...new Map(rawAnchors.map((anchor) => [`${anchor.file.record.path}\0${anchor.start}`, anchor])).values()]
      .sort((left, right) => compareCanonicalText(left.file.record.path, right.file.record.path) || left.start - right.start);
    if (anchors.length < 2 || new Set(anchors.map((anchor) => anchor.file.record.path)).size < 2) continue;
    addFinding(state, OPERATIONAL_RULE_IDS.duplicateGuard, anchors[0]!, {
      kind: 'review-inventory', severity: 'medium', confidence: 'high',
      title: 'A guard-shaped fragment is duplicated across authored files',
      description: `${anchors.length} statement-level guard fragments have the same normalized token signature and can drift independently.`,
      signals: ['normalized-guard-fragment-duplicate', 'multiple-authored-locations'],
      nextValidation: 'Confirm the fragments enforce one invariant, then centralize the guard or give every copy an explicit regression test.',
      patternMaterial: { mechanism: 'duplicate-guard', signature },
      related: anchors.slice(1)
    });
  }
}

function normalizedDictionaryName(value: string): string {
  return value.normalize('NFC').toLowerCase().replace(/[^a-z0-9]+/gu, '');
}

function dictionaryFieldKey(table: string): string | undefined {
  const key = semanticFieldKey(table) ?? semanticFieldKey(table.replace(/ies$/u, 'y').replace(/s$/u, ''));
  if (!key) return undefined;
  return key.split('-').filter((token) => !['generated', 'contract', 'temp', 'tmp', 'dim'].includes(token)).join('-');
}

function splitSqlValues(value: string): string[] {
  const values: string[] = [];
  let current = '';
  let quote = '';
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (quote) {
      current += character;
      if (character === quote && value[index - 1] !== '\\') quote = '';
    } else if (character === "'" || character === '"') {
      quote = character;
      current += character;
    } else if (character === ',') {
      values.push(current.trim());
      current = '';
    } else current += character;
  }
  values.push(current.trim());
  return values;
}

function unquote(value: string): string | undefined {
  const trimmed = value.trim();
  if ((trimmed.startsWith("'") && trimmed.endsWith("'")) || (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
    return trimmed.slice(1, -1);
  }
  return undefined;
}

function collectSeedDictionaries(
  files: AnalysisFile[],
  state: AnalysisState,
  reportDiagnostics = true
): SeedDictionary[] {
  const dictionaries: SeedDictionary[] = [];
  for (const file of files) {
    const source = file.content.toString('utf8');
    {
      for (const insert of source.matchAll(/INSERT\s+INTO\s+["`]?(?:[A-Za-z_][\w]*\.)?([A-Za-z_][\w]*)["`]?\s*\(([^)]+)\)\s*VALUES\s*([\s\S]*?);/giu)) {
        const columns = splitSqlValues(insert[2]!).map((entry) => entry.replace(/["`]/gu, '').trim().toLowerCase());
        const idIndex = columns.findIndex((entry) => entry === 'id' || entry.endsWith('_id'));
        const nameIndex = columns.findIndex((entry) => /^(?:name|label|code|status)$/u.test(entry));
        const fieldKey = dictionaryFieldKey(insert[1]!);
        if (idIndex === -1 || nameIndex === -1 || !fieldKey) continue;
        const ids = new Map<number, string>();
        const literalNames = new Set<string>();
        let complete = true;
        for (const row of insert[3]!.matchAll(/\(([^()]*)\)/gu)) {
          const values = splitSqlValues(row[1]!);
          const id = Number(values[idIndex]);
          const name = values[nameIndex] === undefined ? undefined : unquote(values[nameIndex]!);
          if (!Number.isSafeInteger(id) || name === undefined) complete = false;
          else {
            ids.set(id, normalizedDictionaryName(name));
            literalNames.add(name);
          }
        }
        const anchor = regexAnchor(file, insert);
        if (!complete || ids.size === 0) {
          if (reportDiagnostics) {
            addDiagnostic(
              state,
              OPERATIONAL_RULE_IDS.seededDictionary,
              'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE',
              'A seed dictionary was not fully literal, so Atlas did not use it for integer/name coupling claims.',
              anchor,
              { mechanism: 'incomplete-sql-seed' }
            );
          }
        } else {
          dictionaries.push({ fieldKey, ids, names: new Set(ids.values()), literalNames, anchor });
        }
      }
    }
    for (const insert of source.matchAll(/bulkInsert\s*\(\s*['"]([^'"]+)['"]\s*,\s*\[([\s\S]*?)\]\s*[,)]/gu)) {
      const fieldKey = dictionaryFieldKey(insert[1]!);
      if (!fieldKey) continue;
      const ids = new Map<number, string>();
      const literalNames = new Set<string>();
      let complete = !/\.\.\.|\$\{/u.test(insert[2]!);
      for (const object of insert[2]!.matchAll(/\{([\s\S]*?)\}/gu)) {
        const idMatch = /\bid\s*:\s*(\d+)\b/u.exec(object[1]!);
        const nameMatch = /\b(?:name|label|code|status)\s*:\s*(['"])(.*?)\1/u.exec(object[1]!);
        if (!idMatch || !nameMatch) complete = false;
        else {
          ids.set(Number(idMatch[1]!), normalizedDictionaryName(nameMatch[2]!));
          literalNames.add(nameMatch[2]!);
        }
      }
      const anchor = regexAnchor(file, insert);
      if (!complete || ids.size === 0) {
        if (reportDiagnostics) {
          addDiagnostic(
            state,
            OPERATIONAL_RULE_IDS.seededDictionary,
            'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE',
            'A seed dictionary was not fully literal, so Atlas did not use it for integer/name coupling claims.',
            anchor,
            { mechanism: 'incomplete-orm-seed' }
          );
        }
      } else dictionaries.push({ fieldKey, ids, names: new Set(ids.values()), literalNames, anchor });
    }
    for (const dynamicInsert of source.matchAll(/bulkInsert\s*\(\s*['"]([^'"]+)['"]\s*,\s*(?!\[)([A-Za-z_$][\w$]*)/gu)) {
      if (!dictionaryFieldKey(dynamicInsert[1]!)) continue;
      if (reportDiagnostics) {
        addDiagnostic(
          state,
          OPERATIONAL_RULE_IDS.seededDictionary,
          'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE',
          'A dynamically supplied seed dictionary was not used for integer/name coupling claims.',
          regexAnchor(file, dynamicInsert),
          { mechanism: 'dynamic-orm-seed' }
        );
      }
    }
  }
  return dictionaries;
}

function nearestVariableName(node: ts.Node): string | undefined {
  let current: ts.Node | undefined = node;
  while (current && !ts.isSourceFile(current)) {
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) return current.name.text;
    current = current.parent;
  }
  return undefined;
}

function selectDictionary(fieldKey: string | undefined, dictionaries: SeedDictionary[]): SeedDictionary | undefined {
  if (!fieldKey) return undefined;
  const exact = dictionaries.filter((entry) => entry.fieldKey === fieldKey || entry.fieldKey.endsWith(`-${fieldKey}`) || fieldKey.endsWith(`-${entry.fieldKey}`));
  if (exact.length === 1) return exact[0];
  if (exact.length > 1) return undefined;
  const semantic = fieldKey.split('-').at(-1);
  const suffixMatches = semantic
    ? dictionaries.filter((entry) => entry.fieldKey.split('-').at(-1) === semantic)
    : [];
  return suffixMatches.length === 1 ? suffixMatches[0] : undefined;
}

function symbolicSeedMapping(node: ts.PropertyAssignment, filePath: string): boolean {
  const name = propertyName(node.name)?.toLowerCase();
  if (!name || ['id', 'name', 'label', 'code', 'status', 'key', 'value'].includes(name) || nameTokens(name).includes('id')) {
    return false;
  }
  if (ts.isArrayLiteralExpression(node.parent.parent)) return false;
  const variableTokens = nameTokens(nearestVariableName(node) ?? '');
  const mapperModule = /(?:^|[-_.])(?:map|mapper)(?:[-_.]|$)/iu.test(path.posix.basename(filePath));
  return variableTokens.includes('id') || (variableTokens.includes('map') && mapperModule);
}

function seedCouplingCandidateAnchor(parsedFiles: ParsedFile[]): Anchor | undefined {
  for (const parsed of parsedFiles) {
    let anchor: Anchor | undefined;
    walk(parsed.sourceFile, (node) => {
      if (anchor) return;
      if (ts.isPropertyAssignment(node) && ts.isNumericLiteral(node.initializer) && symbolicSeedMapping(node, parsed.file.record.path)) {
        const variableName = nearestVariableName(node);
        if (semanticFieldKey(variableName ?? '')) anchor = nodeAnchor(parsed, node);
        return;
      }
      if (!ts.isCallExpression(node)) return;
      const name = callName(node.expression) ?? '';
      const first = node.arguments[0];
      if (/find[A-Za-z0-9_]*(?:ByName|ByCode)$/u.test(name) && first && ts.isStringLiteralLike(first)) {
        anchor = nodeAnchor(parsed, node);
        return;
      }
      if ((parsed.file.record.kind === 'test' || TEST_PATH.test(parsed.file.record.path)) &&
        name === 'toBe' && first && ts.isNumericLiteral(first) && seedAssertionFieldKey(node)) {
        anchor = nodeAnchor(parsed, node);
      }
    });
    if (anchor) return anchor;
  }
  return undefined;
}

function seedAssertionFieldKey(node: ts.CallExpression): string | undefined {
  if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== 'toBe') return undefined;
  const expectation = unwrapExpression(node.expression.expression);
  if (!ts.isCallExpression(expectation) || callName(expectation.expression) !== 'expect' || expectation.arguments.length !== 1) {
    return undefined;
  }
  const subject = unwrapExpression(expectation.arguments[0]!);
  let fieldName: string | undefined;
  let ownerName: string | undefined;
  if (ts.isPropertyAccessExpression(subject)) {
    fieldName = subject.name.text;
    ownerName = subject.expression.getText(subject.getSourceFile());
  }
  else if (ts.isElementAccessExpression(subject) && subject.argumentExpression && ts.isStringLiteralLike(subject.argumentExpression)) {
    fieldName = subject.argumentExpression.text;
    ownerName = subject.expression.getText(subject.getSourceFile());
  } else if (ts.isIdentifier(subject)) fieldName = subject.text;
  if (!fieldName || nameTokens(fieldName).at(-1) !== 'id') return undefined;
  return semanticFieldKey(fieldName) ?? semanticFieldKey(ownerName ?? '');
}

function detectSeedCoupling(
  files: AnalysisFile[],
  parsedFiles: ParsedFile[],
  profile: ResolvedProfile | undefined,
  state: AnalysisState
): void {
  const candidateAnchor = seedCouplingCandidateAnchor(parsedFiles);
  const sourcePatterns = profile?.operationalRisks?.seedDictionarySources ?? [];
  if (sourcePatterns.length === 0) {
    if (candidateAnchor) {
      addDiagnostic(
        state,
        OPERATIONAL_RULE_IDS.seededDictionary,
        'OPERATIONAL_SEED_DICTIONARY_SOURCE_REQUIRED',
        'Seeded-dictionary coupling candidates were observed, but no operationalRisks.seedDictionarySources were configured; this rule is incomplete rather than clear.',
        candidateAnchor,
        { mechanism: 'seed-dictionary-source-required' }
      );
    }
    return;
  }
  const sourceFiles = files.filter((file) => matchesAnyGlob(file.record.path, sourcePatterns));
  if (sourceFiles.length === 0) {
    if (candidateAnchor) {
      addDiagnostic(
        state,
        OPERATIONAL_RULE_IDS.seededDictionary,
        'OPERATIONAL_SEED_DICTIONARY_SOURCE_UNRESOLVED',
        'Configured seed-dictionary sources matched no analyzed files; this rule is incomplete rather than clear.',
        candidateAnchor,
        { mechanism: 'seed-dictionary-source-unresolved', patterns: sourcePatterns.map(stableHash) }
      );
    }
    return;
  }
  const dictionaries = collectSeedDictionaries(sourceFiles, state);
  if (dictionaries.length === 0) {
    if (candidateAnchor) {
      addDiagnostic(
        state,
        OPERATIONAL_RULE_IDS.seededDictionary,
        'OPERATIONAL_SEED_DICTIONARY_UNAVAILABLE',
        'Configured seed-dictionary sources yielded no complete literal ID/name dictionary; this rule is incomplete rather than clear.',
        candidateAnchor,
        { mechanism: 'seed-dictionary-unavailable', sources: sourceFiles.map((file) => stableHash(file.record.path)) }
      );
    }
    return;
  }
  for (const parsed of parsedFiles) {
    walk(parsed.sourceFile, (node) => {
      if (ts.isPropertyAssignment(node) && ts.isNumericLiteral(node.initializer) && symbolicSeedMapping(node, parsed.file.record.path)) {
        const symbolicName = propertyName(node.name);
        const variableName = nearestVariableName(node);
        const fieldKey = semanticFieldKey(variableName ?? '');
        const dictionary = selectDictionary(fieldKey, dictionaries);
        if (!symbolicName || !dictionary) return;
        const id = Number(node.initializer.text);
        const actualName = dictionary.ids.get(id);
        if (actualName === undefined || actualName === normalizedDictionaryName(symbolicName)) return;
        addFinding(state, OPERATIONAL_RULE_IDS.seededDictionary, nodeAnchor(parsed, node), {
          kind: 'defect-candidate', severity: 'high', confidence: 'high',
          title: 'A symbolic dictionary mapping points at an ID with a different seeded name',
          description: 'A literal integer mapping and the complete literal seed dictionary disagree after normalized name comparison. Names and integer values were not retained in the finding.',
          signals: ['literal-symbol-to-id-map', 'seeded-id-name-mismatch'],
          nextValidation: 'Resolve the dictionary entry by stable name and remove the duplicated integer mapping.',
          patternMaterial: { mechanism: 'seed-id-name-mismatch', field: stableHash(dictionary.fieldKey) },
          related: [dictionary.anchor]
        });
      }
      if (ts.isCallExpression(node)) {
        const name = callName(node.expression) ?? '';
        const first = node.arguments[0];
        if (/find[A-Za-z0-9_]*(?:ByName|ByCode)$/u.test(name) && first && ts.isStringLiteralLike(first)) {
          const fieldKey = semanticFieldKey(name);
          const dictionary = selectDictionary(fieldKey, dictionaries);
          if (dictionary && !dictionary.names.has(normalizedDictionaryName(first.text))) {
            addFinding(state, OPERATIONAL_RULE_IDS.seededDictionary, nodeAnchor(parsed, node), {
              kind: 'defect-candidate', severity: 'high', confidence: 'high',
              title: 'A literal dictionary lookup name is absent from the complete seed set',
              description: 'A supported literal name lookup has no normalized match in the complete literal seed dictionary. The lookup value was not retained.',
              signals: ['literal-dictionary-name-lookup', 'name-absent-from-complete-seed'],
              nextValidation: 'Use an existing governed name or add the intended seed entry and migration before relying on the lookup.',
              patternMaterial: { mechanism: 'seed-name-missing', field: stableHash(dictionary.fieldKey) },
              related: [dictionary.anchor]
            });
          }
        }
        if ((parsed.file.record.kind === 'test' || TEST_PATH.test(parsed.file.record.path)) && name === 'toBe' && first && ts.isNumericLiteral(first)) {
          const fieldKey = seedAssertionFieldKey(node);
          const dictionary = selectDictionary(fieldKey, dictionaries);
          const expectedId = Number(first.text);
          if (dictionary && dictionary.ids.has(expectedId)) {
            addFinding(state, OPERATIONAL_RULE_IDS.seededDictionary, nodeAnchor(parsed, node), {
              kind: 'defect-candidate', severity: 'medium', confidence: 'high',
              title: 'A test couples a seeded dictionary field to an integer literal',
              description: 'The assertion compares a dictionary-backed field with an integer literal instead of resolving the governed entry by name.',
              signals: ['test-asserts-seeded-integer-id'],
              nextValidation: 'Resolve the expected entry by stable name and assert its resulting identity or behavior.',
              patternMaterial: { mechanism: 'seed-test-integer-coupling', field: stableHash(dictionary.fieldKey) },
              related: [dictionary.anchor]
            });
          }
        }
      }
    });
  }
}

function isNontrivialInitializer(node: ts.Expression): boolean {
  return !ts.isStringLiteralLike(node) && !ts.isNumericLiteral(node) &&
    node.kind !== ts.SyntaxKind.TrueKeyword && node.kind !== ts.SyntaxKind.FalseKeyword &&
    node.kind !== ts.SyntaxKind.NullKeyword && !ts.isArrowFunction(node) && !ts.isFunctionExpression(node);
}

function protectionName(value: string): boolean {
  const words = value.replace(/([a-z0-9])([A-Z])/gu, '$1 $2').split(/[^A-Za-z0-9]+/u).filter(Boolean).map((word) => word.toLowerCase());
  if (words.includes('tenant') && words.some((word) => /^(?:name|label|title|display|upper|lower|formatted)$/u.test(word)) &&
    !words.some((word) => /^(?:id|scope|role|permission|auth|authorization|access|guard|status)$/u.test(word))) return false;
  return words.some((word) => /^(?:status|scope|tenant|auth|authorization|authorized|permission|security|access|guard|role)$/u.test(word)) ||
    /^tenant(?:Id|ID|_id)$/u.test(value);
}

function protectionProducer(initializer: ts.Expression, parsed: ParsedFile): boolean {
  const value = unwrapAwaitedExpression(initializer);
  if (ts.isCallExpression(value)) {
    const called = callName(value.expression) ?? '';
    if (/(?:assert|ensure|enforce|require|authorizeOrThrow|throwIf)/iu.test(called)) return false;
    const resolver = /(?:resolve|lookup|find|get|load|derive|map|parse|calculate|compute|check|validate|authorize)/iu.test(called);
    return resolver && protectionName(called);
  }
  if (ts.isElementAccessExpression(value) || ts.isPropertyAccessExpression(value)) {
    return protectionName(value.expression.getText(parsed.sourceFile)) ||
      (ts.isPropertyAccessExpression(value) && protectionName(value.name.text));
  }
  return false;
}

function mutationBoundary(node: ts.CallExpression, parsed: ParsedFile): boolean {
  const called = callName(node.expression) ?? '';
  if (/^(?:persist|save|store|write|mutate|insert|upsert|create|update|delete|destroy|bulkCreate|bulkUpdate)$/iu.test(called)) {
    if (ts.isIdentifier(node.expression)) return true;
    if (ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression.getText(parsed.sourceFile);
      return /(?:store|repository|repo|model|dao|db|database|client|connection|collection|table)$/iu.test(receiver.split('.').at(-1) ?? '');
    }
  }
  if (!ts.isPropertyAccessExpression(node.expression) || !SQL_EXECUTION_METHOD.test(node.expression.name.text)) return false;
  const receiver = receiverParts(node.expression.expression)?.at(-1);
  const sql = node.arguments[0] ? completeSqlLiteral(node.arguments[0], parsed) : undefined;
  return receiver !== undefined && DATABASE_RECEIVER_NAME.test(receiver) && sql !== undefined &&
    /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/iu.test(sql);
}

function identifierInputs(node: ts.Node): Set<string> {
  const names = new Set<string>();
  walkSameFunction(node, node, (candidate) => {
    if (!ts.isIdentifier(candidate)) return;
    if (ts.isPropertyAccessExpression(candidate.parent) && candidate.parent.name === candidate) return;
    if (ts.isPropertyAssignment(candidate.parent) && candidate.parent.name === candidate) return;
    if (ts.isCallExpression(candidate.parent) && candidate.parent.expression === candidate) return;
    names.add(candidate.text);
  });
  return names;
}

function nestedFunctionShadows(identifier: ts.Identifier, scope: ts.Node, name: string): boolean {
  let current: ts.Node | undefined = identifier.parent;
  while (current && current !== scope) {
    if (ts.isFunctionLike(current)) {
      if (current.parameters.some((parameter) => parameter.name.getText().split(/[^A-Za-z0-9_$]+/u).includes(name))) return true;
      let declared = false;
      walkSameFunction(current, current, (candidate) => {
        if (ts.isVariableDeclaration(candidate) && candidate.name.getText().split(/[^A-Za-z0-9_$]+/u).includes(name)) declared = true;
      });
      if (declared) return true;
    }
    current = current.parent;
  }
  return false;
}

function isReadOfProtectionLocal(candidate: ts.Identifier, declaration: ts.VariableDeclaration, scope: ts.Node): boolean {
  if (candidate.getStart() <= declaration.getEnd() || candidate === declaration.name) return false;
  if (ts.isPropertyAccessExpression(candidate.parent) && candidate.parent.name === candidate) return false;
  if (ts.isPropertyAssignment(candidate.parent) && candidate.parent.name === candidate) return false;
  if ((ts.isVariableDeclaration(candidate.parent) || ts.isParameter(candidate.parent) || ts.isBindingElement(candidate.parent)) &&
    candidate.parent.name === candidate) return false;
  if (ts.isBinaryExpression(candidate.parent) && candidate.parent.left === candidate &&
    candidate.parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
    candidate.parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) return false;
  return !nestedFunctionShadows(candidate, scope, candidate.text);
}

function detectAccidentalProtection(parsedFiles: ParsedFile[], state: AnalysisState): void {
  for (const parsed of parsedFiles.filter((entry) => isProductionConsumer(entry.file))) {
    walk(parsed.sourceFile, (node) => {
      if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
      const variableName = node.name.text;
      if (!protectionName(variableName) || !isNontrivialInitializer(node.initializer) || !protectionProducer(node.initializer, parsed)) return;
      const scope = containingScope(node);
      if (ts.isSourceFile(scope)) return;
      let uses = 0;
      walk(scope, (candidate) => {
        if (ts.isIdentifier(candidate) && candidate.text === variableName && isReadOfProtectionLocal(candidate, node, scope)) uses += 1;
      });
      if (uses !== 0) return;
      const initializerInputs = identifierInputs(node.initializer);
      let boundary: ts.CallExpression | undefined;
      const declarationBranch = branchSignature(node, parsed);
      walkSameFunction(scope, scope, (candidate) => {
        if (boundary || !ts.isCallExpression(candidate) || candidate.getStart(parsed.sourceFile) <= node.getEnd() ||
          !mutationBoundary(candidate, parsed)) return;
        const boundaryBranch = branchSignature(candidate, parsed);
        if (declarationBranch !== '' && boundaryBranch !== declarationBranch && !boundaryBranch.startsWith(`${declarationBranch}/`)) return;
        const boundaryInputs = new Set(candidate.arguments.flatMap((argument) => [...identifierInputs(argument)]));
        if ([...initializerInputs].some((input) => boundaryInputs.has(input))) boundary = candidate;
      });
      if (!boundary) return;
      const anchor = nodeAnchor(parsed, node);
      addFinding(state, OPERATIONAL_RULE_IDS.accidentalProtection, anchor, {
        kind: 'latent-hazard', severity: 'info', confidence: 'high',
        title: 'A protection-shaped computed value is never consumed',
        description: 'A resolver computes a protection-shaped local from data that continues to a downstream mutation, but the computed value is never consumed.',
        signals: ['protection-shaped-value-computed', 'lexically-unconsumed-local', 'downstream-mutation-boundary'],
        nextValidation: 'Confirm whether the value was intended to guard or persist state; make that mechanism explicit or remove the misleading computation.',
        patternMaterial: { mechanism: 'unconsumed-protection', field: stableHash(variableName.toLowerCase()) },
        related: [nodeAnchor(parsed, boundary)]
      });
    });
  }
}

function deduplicateAndSort<T extends { id: string }>(values: T[]): T[] {
  return [...new Map(values.map((value) => [value.id, value])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
}

/**
 * Performs bounded, static-only checks for operational defect mechanisms.
 * Target code is parsed as data and is never imported, evaluated, or executed.
 */
export function detectOperationalRisks(
  files: AnalysisFile[],
  relationships: RelationshipRecord[] = [],
  profile?: ResolvedProfile
): OperationalRiskResult {
  const orderedFiles = [...files]
    .filter(isOperationalInput)
    .sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  const parsedCandidates = parseScriptFiles(orderedFiles);
  const reachability = computeReachability(orderedFiles, relationships, profile);
  const state: AnalysisState = {
    findings: [],
    diagnostics: [],
    observations: [],
    containerCoverage: [],
    entrypointPaths: reachability.entrypointPaths,
    ...(reachability.reachablePaths ? { reachablePaths: reachability.reachablePaths } : {})
  };
  for (const parsed of parsedCandidates) {
    if (parsed.parseDiagnostics.length === 0) continue;
    const first = parsed.parseDiagnostics[0]!;
    const anchor = {
      file: parsed.file,
      start: first.start ?? 0,
      end: (first.start ?? 0) + Math.max(1, first.length ?? 1)
    };
    for (const ruleId of Object.values(OPERATIONAL_RULE_IDS)) {
      addDiagnostic(
        state,
        ruleId,
        'OPERATIONAL_SOURCE_PARSE_INCOMPLETE',
        'A source file has parser diagnostics and was excluded from AST-dependent operational claims.',
        anchor,
        { mechanism: 'source-parse-incomplete', ruleId }
      );
    }
  }
  const parsedFiles = parsedCandidates.filter((parsed) => parsed.parseDiagnostics.length === 0);
  const seedDictionaryPatterns = profile?.operationalRisks?.seedDictionarySources ?? [];
  const seedDictionaryFiles = seedDictionaryPatterns.length === 0
    ? []
    : orderedFiles.filter((file) => matchesAnyGlob(file.record.path, seedDictionaryPatterns));
  const seedDictionaries = collectSeedDictionaries(seedDictionaryFiles, state, false);

  detectSilentEmpty(orderedFiles, parsedFiles, state);
  detectBoundHostContainerPaths(parsedFiles, parseBoundContainerMaps(orderedFiles, state, files), orderedFiles, state);
  detectGuardBypass(parsedFiles, relationships, profile, state);
  detectVocabularyDrift(parsedFiles, orderedFiles, state, seedDictionaries);
  detectClockDateBasis(orderedFiles, parsedFiles, state);
  detectResultCollapse(parsedFiles, relationships, state);
  detectDuplicateGuards(parsedFiles, orderedFiles, state);
  detectSeedCoupling(orderedFiles, parsedFiles, profile, state);
  detectAccidentalProtection(parsedFiles, state);
  if (!state.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.accidentalProtection)) {
    const diagnosticFile = parsedFiles.find((entry) => isProductionConsumer(entry.file)) ?? parsedFiles[0];
    addInputDiagnostic(
      state,
      OPERATIONAL_RULE_IDS.accidentalProtection,
      'OPERATIONAL_ACCIDENTAL_PROTECTION_INPUT_INCOMPLETE',
      'No supported accidental-protection finding was detected. The bounded lexical heuristic does not establish absence across interprocedural or runtime flows, so this rule is incomplete rather than clear.',
      diagnosticFile ? nodeAnchor(diagnosticFile, diagnosticFile.sourceFile) : undefined,
      { mechanism: 'zero-supported-accidental-protection-signal' }
    );
  }

  return {
    findings: deduplicateAndSort(state.findings),
    diagnostics: deduplicateAndSort(state.diagnostics),
    observations: deduplicateAndSort(state.observations),
    containerCoverage: deduplicateAndSort(state.containerCoverage)
  };
}
