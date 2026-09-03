import { loadRunArtifacts, type LoadedRun } from './artifacts.js';
import { AtlasError } from './errors.js';
import { assertSchema } from './schema-validator.js';
import type {
  DiagnosticRecord,
  FileRecord,
  FindingRecord,
  RelationshipRecord,
  RunRecord
} from './types.js';
import { compareCanonicalText } from './util/canonical.js';
import { normalizeTargetRelative } from './util/paths.js';

const MAX_NEIGHBORHOOD_DEPTH = 8;
const MAX_NEIGHBORHOOD_NODES = 1_000;
const MAX_NEIGHBORHOOD_RELATIONSHIPS = 5_000;
const MAX_NEIGHBORHOOD_EDGE_VISITS = 50_000;

export type InspectionDirection = 'incoming' | 'outgoing' | 'both';

export interface InspectOptions {
  file?: string;
  symbol?: string;
  finding?: string;
  neighborhood?: string;
  depth?: number;
  direction?: InspectionDirection;
}

interface InspectionBase {
  schemaVersion: 1;
  runId: string;
  snapshotId: string;
}

export interface InspectionSummary extends InspectionBase {
  kind: 'summary';
  targetId: string;
  profileId: string;
  counts: RunRecord['counts'];
  findingsByCategory: Record<string, number>;
  diagnosticsByCode: Record<string, number>;
}

export interface FileInspection extends InspectionBase {
  kind: 'file';
  file: FileRecord;
  outgoing: RelationshipRecord[];
  incoming: RelationshipRecord[];
  findings: FindingRecord[];
  diagnostics: DiagnosticRecord[];
}

export interface SymbolInspectionMatch {
  file: FileRecord;
  matchedSymbols: string[];
  outgoing: RelationshipRecord[];
  incoming: RelationshipRecord[];
  findings: FindingRecord[];
  diagnostics: DiagnosticRecord[];
}

export interface SymbolInspection extends InspectionBase {
  kind: 'symbol';
  symbol: string;
  matches: SymbolInspectionMatch[];
}

export interface FindingInspection extends InspectionBase {
  kind: 'finding';
  finding: FindingRecord;
  files: FileRecord[];
  relationships: RelationshipRecord[];
  diagnostics: DiagnosticRecord[];
}

export interface NeighborhoodInspection extends InspectionBase {
  kind: 'neighborhood';
  seed: { id: string; path: string };
  direction: InspectionDirection;
  requestedDepth: number;
  nodes: Array<{ distance: number; file: FileRecord }>;
  relationships: RelationshipRecord[];
  boundaryRelationshipIds: string[];
  diagnostics: DiagnosticRecord[];
  findings: FindingRecord[];
  coverage: {
    maxNodes: number;
    maxRelationships: number;
    truncated: boolean;
    unresolvedRelationshipIds: string[];
  };
}

export type InspectionResult =
  | InspectionSummary
  | FileInspection
  | SymbolInspection
  | FindingInspection
  | NeighborhoodInspection;

function selectFile(loaded: LoadedRun, selector: string): FileRecord {
  if (!selector || selector.length > 4_096) throw new AtlasError('INVALID_FILE_SELECTOR', 'File selector must contain between 1 and 4096 characters.');
  const normalizedSelector = selector.startsWith('file_sha256_')
    ? selector
    : normalizeTargetRelative(selector);
  const file = loaded.files.find((entry) => entry.path === normalizedSelector || entry.id === normalizedSelector);
  if (!file) throw new AtlasError('FILE_NOT_FOUND', `No file record matches ${selector}.`);
  return file;
}

function findingPaths(finding: FindingRecord): string[] {
  return [...new Set([
    ...(finding.path ? [finding.path] : []),
    ...finding.relatedPaths,
    ...finding.evidence.flatMap((evidence) => evidence.path ? [evidence.path] : []),
    ...(finding.instances ?? []).flatMap((instance) => [
      ...(instance.path ? [instance.path] : []),
      ...instance.relatedPaths,
      ...instance.evidence.flatMap((evidence) => evidence.path ? [evidence.path] : [])
    ])
  ])];
}

function findingEvidenceRecordIds(finding: FindingRecord): string[] {
  return [
    ...finding.evidence,
    ...(finding.instances ?? []).flatMap((instance) => instance.evidence)
  ].flatMap((evidence) => evidence.recordIds ?? []);
}

function relatedToFile(loaded: LoadedRun, file: FileRecord): Omit<FileInspection, keyof InspectionBase | 'kind' | 'file'> {
  return {
    outgoing: loaded.relationships.filter((relationship) => relationship.from === file.id),
    incoming: loaded.relationships.filter((relationship) => relationship.to === file.id),
    findings: loaded.findings.filter((finding) => findingPaths(finding).includes(file.path)),
    diagnostics: loaded.diagnostics.filter((entry) => entry.path === file.path)
  };
}

function inspectionBase(loaded: LoadedRun): InspectionBase {
  return {
    schemaVersion: 1,
    runId: loaded.run.runId,
    snapshotId: loaded.snapshot.snapshotId
  };
}

function summaryInspection(loaded: LoadedRun): InspectionSummary {
  const findingsByCategory = Object.fromEntries(
    [...new Set(loaded.findings.map((finding) => finding.category))]
      .sort(compareCanonicalText)
      .map((category) => [category, loaded.findings.filter((finding) => finding.category === category).length])
  );
  const diagnosticsByCode = Object.fromEntries(
    [...new Set(loaded.diagnostics.map((entry) => entry.code))]
      .sort(compareCanonicalText)
      .map((code) => [code, loaded.diagnostics.filter((entry) => entry.code === code).length])
  );
  return {
    ...inspectionBase(loaded),
    kind: 'summary',
    targetId: loaded.run.targetId,
    profileId: loaded.run.profileId,
    counts: loaded.run.counts,
    findingsByCategory,
    diagnosticsByCode
  };
}

function fileInspection(loaded: LoadedRun, selector: string): FileInspection {
  const file = selectFile(loaded, selector);
  return { ...inspectionBase(loaded), kind: 'file', file, ...relatedToFile(loaded, file) };
}

function symbolInspection(loaded: LoadedRun, symbol: string): SymbolInspection {
  if (!symbol || symbol.length > 1_024 || symbol.trim() !== symbol) {
    throw new AtlasError('INVALID_SYMBOL_SELECTOR', 'Symbol selector must be a non-blank exact symbol name of at most 1024 characters.');
  }
  const matches = loaded.files
    .filter((file) => file.symbols.includes(symbol))
    .map((file) => ({ file, matchedSymbols: [symbol], ...relatedToFile(loaded, file) }))
    .sort((left, right) => compareCanonicalText(left.file.path, right.file.path));
  if (!matches.length) throw new AtlasError('SYMBOL_NOT_FOUND', `No exported symbol record exactly matches ${symbol}.`);
  return { ...inspectionBase(loaded), kind: 'symbol', symbol, matches };
}

function findingInspection(loaded: LoadedRun, findingId: string): FindingInspection {
  const finding = loaded.findings.find((entry) => entry.id === findingId);
  if (!finding) throw new AtlasError('FINDING_NOT_FOUND', `No finding record matches ${findingId}.`);
  const paths = new Set<string>(findingPaths(finding));
  const evidenceRecordIds = new Set(findingEvidenceRecordIds(finding));
  const files = loaded.files.filter((file) => paths.has(file.path));
  const relationships = loaded.relationships.filter((relationship) =>
    paths.has(relationship.fromPath) || (relationship.toPath ? paths.has(relationship.toPath) : false) || evidenceRecordIds.has(relationship.id)
  );
  const diagnostics = loaded.diagnostics.filter((diagnostic) =>
    (diagnostic.path ? paths.has(diagnostic.path) : false) || evidenceRecordIds.has(diagnostic.id)
  );
  return { ...inspectionBase(loaded), kind: 'finding', finding, files, relationships, diagnostics };
}

function touchesSelectedDirection(
  relationship: RelationshipRecord,
  selected: Set<string>,
  direction: InspectionDirection
): boolean {
  return (
    ((direction === 'outgoing' || direction === 'both') && selected.has(relationship.from)) ||
    ((direction === 'incoming' || direction === 'both') && Boolean(relationship.to && selected.has(relationship.to)))
  );
}

function neighborhoodInspection(
  loaded: LoadedRun,
  selector: string,
  requestedDepth: number,
  direction: InspectionDirection
): NeighborhoodInspection {
  if (!Number.isSafeInteger(requestedDepth) || requestedDepth < 0 || requestedDepth > MAX_NEIGHBORHOOD_DEPTH) {
    throw new AtlasError('INVALID_NEIGHBORHOOD_DEPTH', `Neighborhood depth must be an integer between 0 and ${MAX_NEIGHBORHOOD_DEPTH}.`);
  }
  if (!['incoming', 'outgoing', 'both'].includes(direction)) {
    throw new AtlasError('INVALID_NEIGHBORHOOD_DIRECTION', 'Neighborhood direction must be incoming, outgoing, or both.');
  }
  const seed = selectFile(loaded, selector);
  const fileById = new Map(loaded.files.map((file) => [file.id, file]));
  const adjacentTargets = new Map<string, string[]>();
  const appendTarget = (from: string, to: string): void => {
    const targets = adjacentTargets.get(from) ?? [];
    targets.push(to);
    adjacentTargets.set(from, targets);
  };
  for (const relationship of loaded.relationships) {
    if (relationship.resolution !== 'resolved' || !relationship.to) continue;
    if (direction === 'outgoing' || direction === 'both') appendTarget(relationship.from, relationship.to);
    if (direction === 'incoming' || direction === 'both') appendTarget(relationship.to, relationship.from);
  }
  const distances = new Map<string, number>([[seed.id, 0]]);
  let frontier = [seed.id];
  let truncated = false;
  let edgeVisits = 0;
  traversal: for (let depth = 0; depth < requestedDepth && frontier.length; depth += 1) {
    const next = new Set<string>();
    for (const currentId of [...frontier].sort(compareCanonicalText)) {
      for (const targetId of adjacentTargets.get(currentId) ?? []) {
        if (edgeVisits >= MAX_NEIGHBORHOOD_EDGE_VISITS) {
          truncated = true;
          break traversal;
        }
        edgeVisits += 1;
        if (distances.has(targetId)) continue;
        if (distances.size >= MAX_NEIGHBORHOOD_NODES) {
          truncated = true;
          continue;
        }
        if (fileById.has(targetId)) {
          distances.set(targetId, depth + 1);
          next.add(targetId);
        }
      }
    }
    frontier = [...next];
  }
  const selected = new Set(distances.keys());
  const relevantRelationships = loaded.relationships.filter((relationship) => touchesSelectedDirection(relationship, selected, direction));
  if (relevantRelationships.length > MAX_NEIGHBORHOOD_RELATIONSHIPS) truncated = true;
  const relationships = relevantRelationships.slice(0, MAX_NEIGHBORHOOD_RELATIONSHIPS);
  const boundaryRelationshipIds = relationships
    .filter((relationship) => relationship.resolution !== 'resolved' || !relationship.to || !selected.has(relationship.from) || !selected.has(relationship.to))
    .map((relationship) => relationship.id)
    .sort(compareCanonicalText);
  if (!truncated) {
    truncated = relationships.some((relationship) =>
      relationship.resolution === 'resolved' && Boolean(relationship.to) &&
      (!selected.has(relationship.from) || !selected.has(relationship.to!))
    );
  }
  const selectedPaths = new Set([...selected].flatMap((id) => {
    const file = fileById.get(id);
    return file ? [file.path] : [];
  }));
  const nodes = [...distances]
    .flatMap(([id, distance]) => {
      const file = fileById.get(id);
      return file ? [{ distance, file }] : [];
    })
    .sort((left, right) => left.distance - right.distance || compareCanonicalText(left.file.path, right.file.path));
  const diagnostics = loaded.diagnostics.filter((diagnostic) => diagnostic.path ? selectedPaths.has(diagnostic.path) : false);
  const findings = loaded.findings.filter((finding) => findingPaths(finding).some((path) => selectedPaths.has(path)));
  return {
    ...inspectionBase(loaded),
    kind: 'neighborhood',
    seed: { id: seed.id, path: seed.path },
    direction,
    requestedDepth,
    nodes,
    relationships,
    boundaryRelationshipIds,
    diagnostics,
    findings,
    coverage: {
      maxNodes: MAX_NEIGHBORHOOD_NODES,
      maxRelationships: MAX_NEIGHBORHOOD_RELATIONSHIPS,
      truncated,
      unresolvedRelationshipIds: relationships
        .filter((relationship) => relationship.resolution !== 'resolved')
        .map((relationship) => relationship.id)
        .sort(compareCanonicalText)
    }
  };
}

function normalizeOptions(selector?: string | InspectOptions): InspectOptions {
  if (typeof selector === 'string') return { file: selector };
  return selector ?? {};
}

/** @internal Derives an inspection only from a caller's already verified run artifacts. */
export async function inspectLoadedRun(loaded: LoadedRun, selector?: string | InspectOptions): Promise<InspectionResult> {
  const options = normalizeOptions(selector);
  const selectors = [options.file, options.symbol, options.finding, options.neighborhood].filter((value) => value !== undefined);
  if (selectors.length > 1) throw new AtlasError('INSPECT_SELECTOR_CONFLICT', 'Choose exactly one of file, symbol, finding, or neighborhood.');
  if (!options.neighborhood && (options.depth !== undefined || options.direction !== undefined)) {
    throw new AtlasError('INSPECT_SELECTOR_CONFLICT', 'Depth and direction are only valid with a neighborhood selector.');
  }
  let result: InspectionResult;
  if (options.file !== undefined) result = fileInspection(loaded, options.file);
  else if (options.symbol !== undefined) result = symbolInspection(loaded, options.symbol);
  else if (options.finding !== undefined) result = findingInspection(loaded, options.finding);
  else if (options.neighborhood !== undefined) {
    result = neighborhoodInspection(loaded, options.neighborhood, options.depth ?? 1, options.direction ?? 'both');
  } else result = summaryInspection(loaded);
  await assertSchema('inspect-response', result, 'Inspection response');
  return result;
}

export async function inspectRun(runDirectory: string, selector?: string | InspectOptions): Promise<InspectionResult> {
  return inspectLoadedRun(await loadRunArtifacts(runDirectory), selector);
}

function countEntries(value: Record<string, number>): string {
  const entries = Object.entries(value);
  return entries.length ? entries.map(([key, count]) => `${terminalText(key)}=${count}`).join(', ') : 'none';
}

function terminalText(value: string): string {
  return value.replace(
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu,
    (character) => `\\u{${character.codePointAt(0)!.toString(16).toUpperCase()}}`
  );
}

function relationshipLine(relationship: RelationshipRecord): string {
  const target = relationship.toPath
    ? terminalText(relationship.toPath)
    : `[${terminalText(relationship.resolution)}: ${terminalText(relationship.specifier)}]`;
  return `  ${terminalText(relationship.fromPath)} --${terminalText(relationship.type)}${relationship.typeOnly ? ' [type-only]' : ''}--> ${target} @ ${relationship.location.line}:${relationship.location.column}`;
}

/** Render only normalized run evidence. Source bodies and absolute target paths are never loaded. */
export function renderInspectionText(result: InspectionResult): string {
  const header = [
    `Atlas inspection: ${terminalText(result.kind)}`,
    `Run: ${terminalText(result.runId)}`,
    `Snapshot: ${terminalText(result.snapshotId)}`
  ];
  if (result.kind === 'summary') {
    return [...header,
      `Target: ${terminalText(result.targetId)}`,
      `Profile: ${terminalText(result.profileId)}`,
      `Counts: files=${result.counts.files}, relationships=${result.counts.relationships}, findings=${result.counts.findings}, diagnostics=${result.counts.diagnostics}`,
      `Findings: ${countEntries(result.findingsByCategory)}`,
      `Diagnostics: ${countEntries(result.diagnosticsByCode)}`
    ].join('\n') + '\n';
  }
  if (result.kind === 'file') {
    return [...header,
      `File: ${terminalText(result.file.path)}`,
      `ID: ${terminalText(result.file.id)}`,
      `Classification: ${terminalText(result.file.kind)}/${terminalText(result.file.language)}`,
      `Symbols: ${result.file.symbols.map(terminalText).join(', ') || 'none'}`,
      `Relationships: incoming=${result.incoming.length}, outgoing=${result.outgoing.length}`,
      ...[...result.outgoing, ...result.incoming].map(relationshipLine),
      `Findings: ${result.findings.length}`,
      `Diagnostics: ${result.diagnostics.length}`
    ].join('\n') + '\n';
  }
  if (result.kind === 'symbol') {
    return [...header,
      `Symbol: ${terminalText(result.symbol)}`,
      `Matches: ${result.matches.length}`,
      ...result.matches.map((match) => `  ${terminalText(match.file.path)} (${terminalText(match.file.id)})`)
    ].join('\n') + '\n';
  }
  if (result.kind === 'finding') {
    return [...header,
      `Finding: ${terminalText(result.finding.id)}`,
      `Rule: ${terminalText(result.finding.ruleId)}`,
      `Severity/confidence: ${terminalText(result.finding.severity)}/${terminalText(result.finding.confidence)}`,
      `Title: ${terminalText(result.finding.title)}`,
      `Path: ${terminalText(result.finding.path ?? 'none')}`,
      `Related files: ${result.files.map((file) => terminalText(file.path)).join(', ') || 'none'}`,
      `Evidence records: ${result.relationships.length + result.diagnostics.length}`,
      `Next validation: ${terminalText(result.finding.nextValidation)}`
    ].join('\n') + '\n';
  }
  return [...header,
    `Seed: ${terminalText(result.seed.path)} (${terminalText(result.seed.id)})`,
    `Direction/depth: ${terminalText(result.direction)}/${result.requestedDepth}`,
    `Coverage: nodes=${result.nodes.length}/${result.coverage.maxNodes}, relationships=${result.relationships.length}/${result.coverage.maxRelationships}, truncated=${result.coverage.truncated}`,
    'Nodes:',
    ...result.nodes.map((node) => `  [${node.distance}] ${terminalText(node.file.path)}`),
    'Relationships:',
    ...result.relationships.map(relationshipLine),
    `Boundary relationships: ${result.boundaryRelationshipIds.length}`,
    `Unresolved relationships: ${result.coverage.unresolvedRelationshipIds.length}`,
    `Findings: ${result.findings.length}`,
    `Diagnostics: ${result.diagnostics.length}`
  ].join('\n') + '\n';
}
