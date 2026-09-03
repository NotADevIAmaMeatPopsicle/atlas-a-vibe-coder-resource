import { randomUUID } from 'node:crypto';
import {
  access,
  lstat,
  mkdir,
  realpath,
  rename,
  rm,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { AtlasError } from '../errors.js';
import {
  HARD_MAX_BOUNDARY_ENTRIES,
  HARD_MAX_FILE_BYTES,
  HARD_MAX_INCLUDED_FILES,
  HARD_MAX_TOTAL_BYTES
} from '../limits.js';
import { assertSchema } from '../schema-validator.js';
import {
  MAX_HISTORICAL_REFERENCE_DEPTH,
  MAX_HISTORICAL_TEXT_LINES,
  MAX_VERIFIER_ARTIFACT_BYTES,
  MAX_VERIFIER_DIRECTORY_ENTRIES,
  MAX_VERIFIER_MANIFEST_BYTES,
  MAX_VERIFIER_NESTING_DEPTH,
  MAX_VERIFIER_TOTAL_BYTES,
  addToBoundedCount,
  assertAggregateByteLimit,
  assertNestingDepth,
  assertTextLineLimit,
  parseBoundedJsonLines,
  readBoundedDirectoryEntries,
  readBoundedRegularFile
} from '../security/bounded-artifacts.js';
import { assertPortableDataSafe } from '../security/portable-data.js';
import {
  canonicalJson,
  canonicalJsonLines,
  compareCanonicalText,
  prettyCanonicalJson,
  sha256
} from '../util/canonical.js';
import {
  isInside,
  normalizeTargetRelative,
  resolveForContainment,
  toPosixPath
} from '../util/paths.js';
import {
  HISTORICAL_EVIDENCE_PRODUCER_VERSION,
  type HistoricalAnchorFreshness,
  type HistoricalEvidenceArtifactManifest,
  type HistoricalEvidenceCitation,
  type HistoricalEvidenceIndex,
  type HistoricalEvidenceIndexResult,
  type HistoricalEvidencePathAnchor,
  type HistoricalEvidenceQueryHit,
  type HistoricalEvidenceQueryResult,
  type HistoricalEvidenceRecord,
  type HistoricalEvidenceReferenceVerification,
  type HistoricalEvidenceScopeAnchor,
  type HistoricalEvidenceSource,
  type HistoricalReviewerIdentity,
  type HistoricalTraceMetadata,
  type VerifiedHistoricalEvidenceIndex
} from './types.js';

export * from './types.js';

const REFERENCE_AGGREGATE_ALGORITHM = 'sha256(path\\0bytes\\0sha256 joined by LF, paths sorted lexically)';
const INDEX_ARTIFACTS = ['index.json', 'records.jsonl', 'artifact-digests.json'] as const;
const HASHED_INDEX_ARTIFACTS = ['index.json', 'records.jsonl'] as const;
const TRACE_INDEX_PATH = 'traces/trace-index.json';
const TARGET_FILE_INVENTORY_PATH = 'registry/file-registry.json';
const MAX_QUERY_CHARACTERS = 4096;
const MAX_QUERY_HITS = 100;
const MAX_HISTORICAL_INDEX_RECORDS = 50_000;
const MAX_HISTORICAL_ANCHORS = 250_000;
const REVIEWER_UNAVAILABLE_REASON = 'No structured reviewer identity is recorded in the preserved artifact.';
const FRESHNESS_UNAVAILABLE_REASON = 'The preserved artifact does not record a per-anchor revalidation against source bytes; the source HEAD is provenance only.';
const INTERPRETATION = {
  usage: 'historical-navigation-context-only',
  claimBodiesImported: false,
  validatedFindingsCreated: false
} as const;

interface ReferenceFileEntry {
  path: string;
  bytes: number;
  sha256: string;
}

interface PreservedReferenceManifest {
  schemaVersion: 1;
  capturedAt: string;
  referencePath: string;
  sourceObservation: {
    repositoryPath: string;
    atlasPath: string;
    gitHead: string;
    branch: string | null;
    detached: boolean;
    dirtyStatusSha256: string;
    dirtyStatusLineCount: number;
    note: string;
  };
  fileCount: number;
  totalBytes: number;
  aggregateAlgorithm: string;
  aggregateSha256: string;
  sourceAggregateSha256: string;
  files: ReferenceFileEntry[];
}

interface VerifiedReference {
  referenceRoot: string;
  manifestPath: string;
  manifest: PreservedReferenceManifest;
  manifestSha256: string;
  entries: Map<string, ReferenceFileEntry>;
  summary: HistoricalEvidenceReferenceVerification;
}

interface TraceIndexEntry {
  id: string;
  label: string;
  clusterId: string;
  lifecycle: string;
  summary: string;
  artifact: string;
}

interface TraceIndexDocument {
  schemaVersion: 1;
  purpose: string;
  traces: TraceIndexEntry[];
}

interface MarkdownMetadata {
  title: string;
  titleLine: number;
  scopeAnchors: HistoricalEvidenceScopeAnchor[];
  pathAnchors: HistoricalEvidencePathAnchor[];
  reviewerIdentity: HistoricalReviewerIdentity;
}

interface ScoredField {
  field: HistoricalEvidenceQueryHit['matchedFields'][number];
  text: string;
  weight: number;
  citations: HistoricalEvidenceCitation[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function stringField(value: Record<string, unknown>, key: string, label: string): string {
  const candidate = value[key];
  if (typeof candidate !== 'string' || !candidate) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', `${label}.${key} must be a non-empty string.`);
  }
  return candidate;
}

function integerField(value: Record<string, unknown>, key: string, label: string): number {
  const candidate = value[key];
  if (!Number.isSafeInteger(candidate) || (candidate as number) < 0) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', `${label}.${key} must be a non-negative integer.`);
  }
  return candidate as number;
}

function assertDigest(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/u.test(value)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', `${label} must be a lowercase SHA-256 digest.`);
  }
}

function assertObjectKeys(value: Record<string, unknown>, expected: string[], label: string): void {
  const actual = Object.keys(value).sort(compareCanonicalText);
  const sortedExpected = [...expected].sort(compareCanonicalText);
  if (canonicalJson(actual) !== canonicalJson(sortedExpected)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', `${label} has unexpected or missing fields.`);
  }
}

function parseReferenceManifest(value: unknown): PreservedReferenceManifest {
  if (!isRecord(value)) throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest must be a JSON object.');
  assertObjectKeys(value, [
    'schemaVersion',
    'capturedAt',
    'referencePath',
    'sourceObservation',
    'fileCount',
    'totalBytes',
    'aggregateAlgorithm',
    'aggregateSha256',
    'sourceAggregateSha256',
    'files'
  ], 'Reference manifest');
  if (value.schemaVersion !== 1) throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest schemaVersion must be 1.');
  const capturedAt = stringField(value, 'capturedAt', 'Reference manifest');
  if (!Number.isFinite(Date.parse(capturedAt))) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest capturedAt must be an ISO timestamp.');
  }
  const referencePath = stringField(value, 'referencePath', 'Reference manifest');
  if (normalizeTargetRelative(referencePath) !== referencePath) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest referencePath is not canonical.');
  }
  const aggregateAlgorithm = stringField(value, 'aggregateAlgorithm', 'Reference manifest');
  if (aggregateAlgorithm !== REFERENCE_AGGREGATE_ALGORITHM) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest uses an unsupported aggregate algorithm.');
  }
  const aggregateSha256 = stringField(value, 'aggregateSha256', 'Reference manifest');
  const sourceAggregateSha256 = stringField(value, 'sourceAggregateSha256', 'Reference manifest');
  assertDigest(aggregateSha256, 'Reference manifest aggregateSha256');
  assertDigest(sourceAggregateSha256, 'Reference manifest sourceAggregateSha256');
  if (aggregateSha256 !== sourceAggregateSha256) {
    throw new AtlasError('REFERENCE_MANIFEST_MISMATCH', 'Reference and captured source aggregate digests differ.');
  }

  if (!isRecord(value.sourceObservation)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest sourceObservation must be an object.');
  }
  const observation = value.sourceObservation;
  assertObjectKeys(observation, [
    'repositoryPath',
    'atlasPath',
    'gitHead',
    'branch',
    'detached',
    'dirtyStatusSha256',
    'dirtyStatusLineCount',
    'note'
  ], 'Reference manifest sourceObservation');
  const repositoryPath = stringField(observation, 'repositoryPath', 'Reference manifest sourceObservation');
  const networkOrDevicePath = /^[\\/]{2}/u.test(repositoryPath);
  const localAbsolutePath = process.platform === 'win32'
    ? /^[A-Za-z]:[\\/]/u.test(repositoryPath) && path.win32.isAbsolute(repositoryPath)
    : path.posix.isAbsolute(repositoryPath);
  if (networkOrDevicePath || !localAbsolutePath) {
    throw new AtlasError(
      'REFERENCE_MANIFEST_INVALID',
      'Reference manifest source repositoryPath must be a local absolute path for this host.'
    );
  }
  const atlasPath = stringField(observation, 'atlasPath', 'Reference manifest sourceObservation');
  if (normalizeTargetRelative(atlasPath) !== atlasPath) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest source atlasPath is not canonical.');
  }
  const gitHead = stringField(observation, 'gitHead', 'Reference manifest sourceObservation');
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(gitHead)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest source gitHead is invalid.');
  }
  if (observation.branch !== null && (typeof observation.branch !== 'string' || !observation.branch)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest source branch must be null or a non-empty string.');
  }
  if (typeof observation.detached !== 'boolean') {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest source detached must be boolean.');
  }
  if (observation.detached !== (observation.branch === null)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest source branch and detached state disagree.');
  }
  const dirtyStatusSha256 = stringField(observation, 'dirtyStatusSha256', 'Reference manifest sourceObservation');
  assertDigest(dirtyStatusSha256, 'Reference manifest dirtyStatusSha256');
  const dirtyStatusLineCount = integerField(observation, 'dirtyStatusLineCount', 'Reference manifest sourceObservation');
  const note = stringField(observation, 'note', 'Reference manifest sourceObservation');

  if (!Array.isArray(value.files) || !value.files.length) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest files must be a non-empty array.');
  }
  if (value.files.length > HARD_MAX_INCLUDED_FILES) {
    throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Reference manifest exceeds ${HARD_MAX_INCLUDED_FILES} files.`);
  }
  const files = value.files.map((candidate, index): ReferenceFileEntry => {
    if (!isRecord(candidate)) throw new AtlasError('REFERENCE_MANIFEST_INVALID', `Reference file ${index + 1} must be an object.`);
    assertObjectKeys(candidate, ['path', 'bytes', 'sha256'], `Reference file ${index + 1}`);
    const filePath = stringField(candidate, 'path', `Reference file ${index + 1}`);
    if (normalizeTargetRelative(filePath) !== filePath) {
      throw new AtlasError('REFERENCE_MANIFEST_INVALID', `Reference file path is not canonical: ${filePath}`);
    }
    const bytes = integerField(candidate, 'bytes', `Reference file ${index + 1}`);
    if (bytes > HARD_MAX_FILE_BYTES) {
      throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Reference file exceeds ${HARD_MAX_FILE_BYTES} bytes: ${filePath}`);
    }
    const fileSha256 = stringField(candidate, 'sha256', `Reference file ${index + 1}`);
    assertDigest(fileSha256, `Reference file ${index + 1} sha256`);
    return { path: filePath, bytes, sha256: fileSha256 };
  });
  const filePaths = files.map((entry) => entry.path);
  if (new Set(filePaths).size !== filePaths.length) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Reference manifest contains duplicate file paths.');
  }
  const fileCount = integerField(value, 'fileCount', 'Reference manifest');
  const totalBytes = integerField(value, 'totalBytes', 'Reference manifest');
  if (fileCount > HARD_MAX_INCLUDED_FILES || totalBytes > HARD_MAX_TOTAL_BYTES) {
    throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', 'Reference manifest exceeds historical-evidence resource limits.');
  }
  if (fileCount !== files.length || totalBytes !== files.reduce((total, entry) => total + entry.bytes, 0)) {
    throw new AtlasError('REFERENCE_MANIFEST_MISMATCH', 'Reference manifest summary differs from its file inventory.');
  }
  const aggregate = sha256(files.map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}`).join('\n'));
  if (aggregate !== aggregateSha256) {
    throw new AtlasError('REFERENCE_MANIFEST_MISMATCH', 'Reference manifest aggregate differs from its file inventory.');
  }
  return {
    schemaVersion: 1,
    capturedAt,
    referencePath,
    sourceObservation: {
      repositoryPath,
      atlasPath,
      gitHead,
      branch: observation.branch as string | null,
      detached: observation.detached,
      dirtyStatusSha256,
      dirtyStatusLineCount,
      note
    },
    fileCount,
    totalBytes,
    aggregateAlgorithm,
    aggregateSha256,
    sourceAggregateSha256,
    files
  };
}

async function exists(value: string): Promise<boolean> {
  try {
    await access(value);
    return true;
  } catch {
    return false;
  }
}

async function hashFile(filePath: string): Promise<{ bytes: number; sha256: string }> {
  const content = await readBoundedRegularFile(filePath, {
    maxBytes: HARD_MAX_FILE_BYTES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    invalidCode: 'REFERENCE_CHANGED',
    label: `Reference file ${filePath}`
  });
  return { bytes: content.length, sha256: sha256(content) };
}

async function inventoryReference(referenceRoot: string): Promise<ReferenceFileEntry[]> {
  const entries: ReferenceFileEntry[] = [];
  let boundaryEntries = 0;
  let totalBytes = 0;
  async function walk(directory: string, depth: number): Promise<void> {
    const children = await readBoundedDirectoryEntries(directory, {
      maxEntries: HARD_MAX_BOUNDARY_ENTRIES - boundaryEntries,
      resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
      label: 'Historical reference tree'
    });
    boundaryEntries += children.length;
    children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const child of children) {
      const absolutePath = path.join(directory, child.name);
      if (child.isSymbolicLink()) {
        throw new AtlasError('REFERENCE_ENTRY_UNSUPPORTED', `Reference symlinks and junctions are not allowed: ${absolutePath}`);
      }
      if (child.isDirectory()) {
        if (depth >= MAX_HISTORICAL_REFERENCE_DEPTH) {
          throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Reference tree exceeds ${MAX_HISTORICAL_REFERENCE_DEPTH} directory levels.`);
        }
        await walk(absolutePath, depth + 1);
        continue;
      }
      if (!child.isFile()) {
        throw new AtlasError('REFERENCE_ENTRY_UNSUPPORTED', `Unsupported reference entry: ${absolutePath}`);
      }
      const relativePath = toPosixPath(path.relative(referenceRoot, absolutePath));
      if (normalizeTargetRelative(relativePath) !== relativePath) {
        throw new AtlasError('REFERENCE_ENTRY_UNSUPPORTED', `Reference path is not portable: ${relativePath}`);
      }
      if (entries.length >= HARD_MAX_INCLUDED_FILES) {
        throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Reference tree exceeds ${HARD_MAX_INCLUDED_FILES} files.`);
      }
      const hashed = await hashFile(absolutePath);
      if (hashed.bytes > HARD_MAX_TOTAL_BYTES - totalBytes) {
        throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Reference tree exceeds ${HARD_MAX_TOTAL_BYTES} bytes.`);
      }
      totalBytes += hashed.bytes;
      entries.push({ path: relativePath, ...hashed });
    }
  }
  await walk(referenceRoot, 0);
  return entries;
}

export async function verifyHistoricalEvidenceReference(options: {
  referencePath: string;
  manifestPath: string;
}): Promise<HistoricalEvidenceReferenceVerification> {
  return (await verifyReference(options)).summary;
}

async function verifyReference(options: {
  referencePath: string;
  manifestPath: string;
}): Promise<VerifiedReference> {
  const referenceRoot = await realpath(path.resolve(options.referencePath));
  const referenceMetadata = await lstat(referenceRoot);
  if (!referenceMetadata.isDirectory() || referenceMetadata.isSymbolicLink()) {
    throw new AtlasError('REFERENCE_ROOT_INVALID', 'Historical evidence reference root must be a regular directory.');
  }
  const manifestPath = await realpath(path.resolve(options.manifestPath));
  const manifestMetadata = await lstat(manifestPath);
  if (!manifestMetadata.isFile() || manifestMetadata.isSymbolicLink()) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Historical evidence reference manifest must be a regular file.');
  }
  if (isInside(referenceRoot, manifestPath)) {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'The preservation manifest must be outside the reference tree it seals.');
  }
  const rawManifest = await readBoundedRegularFile(manifestPath, {
    maxBytes: MAX_VERIFIER_MANIFEST_BYTES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    invalidCode: 'REFERENCE_MANIFEST_INVALID',
    label: 'Historical evidence reference manifest'
  });
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawManifest.toString('utf8')) as unknown;
  } catch {
    throw new AtlasError('REFERENCE_MANIFEST_INVALID', 'Historical evidence reference manifest is not valid JSON.');
  }
  const manifest = parseReferenceManifest(parsed);
  const observed = await inventoryReference(referenceRoot);
  if (observed.length !== manifest.files.length) {
    throw new AtlasError('REFERENCE_MANIFEST_MISMATCH', 'Reference file count differs from the immutable preservation manifest.');
  }
  for (let index = 0; index < observed.length; index += 1) {
    const actual = observed[index]!;
    const expected = manifest.files[index]!;
    if (actual.path !== expected.path || actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) {
      throw new AtlasError('REFERENCE_MANIFEST_MISMATCH', `Reference entry differs from the immutable preservation manifest: ${actual.path}`);
    }
  }
  const totalBytes = observed.reduce((total, entry) => total + entry.bytes, 0);
  const aggregateSha256 = sha256(observed.map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}`).join('\n'));
  if (totalBytes !== manifest.totalBytes || aggregateSha256 !== manifest.aggregateSha256) {
    throw new AtlasError('REFERENCE_MANIFEST_MISMATCH', 'Reference aggregate differs from the immutable preservation manifest.');
  }
  return {
    referenceRoot,
    manifestPath,
    manifest,
    manifestSha256: sha256(rawManifest),
    entries: new Map(manifest.files.map((entry) => [entry.path, entry])),
    summary: {
      status: 'passed',
      referencePath: referenceRoot,
      manifestPath,
      manifestSha256: sha256(rawManifest),
      fileCount: observed.length,
      totalBytes,
      aggregateSha256,
      sourceGitHead: manifest.sourceObservation.gitHead
    }
  };
}

async function readVerifiedReferenceFile(reference: VerifiedReference, relativePath: string): Promise<Buffer> {
  const normalized = normalizeTargetRelative(relativePath);
  const expected = reference.entries.get(normalized);
  if (!expected) throw new AtlasError('REFERENCE_ARTIFACT_MISSING', `Preservation manifest does not contain required artifact: ${normalized}`);
  const absolutePath = path.join(reference.referenceRoot, ...normalized.split('/'));
  const resolved = await realpath(absolutePath);
  if (!isInside(reference.referenceRoot, resolved)) {
    throw new AtlasError('REFERENCE_PATH_ESCAPE', `Reference artifact resolves outside the preserved tree: ${normalized}`);
  }
  const content = await readBoundedRegularFile(resolved, {
    maxBytes: HARD_MAX_FILE_BYTES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    invalidCode: 'REFERENCE_CHANGED',
    label: `Reference artifact ${normalized}`
  });
  if (content.length !== expected.bytes || sha256(content) !== expected.sha256) {
    throw new AtlasError('REFERENCE_CHANGED', `Reference artifact changed after manifest verification: ${normalized}`);
  }
  return content;
}

async function targetFileInventory(reference: VerifiedReference): Promise<ReadonlySet<string> | undefined> {
  if (!reference.entries.has(TARGET_FILE_INVENTORY_PATH)) return undefined;
  const content = await readVerifiedReferenceFile(reference, TARGET_FILE_INVENTORY_PATH);
  let value: unknown;
  try {
    value = JSON.parse(content.toString('utf8')) as unknown;
  } catch {
    throw new AtlasError('HISTORICAL_FILE_INVENTORY_INVALID', 'Preserved target file inventory is not valid JSON.');
  }
  if (!isRecord(value)) {
    throw new AtlasError('HISTORICAL_FILE_INVENTORY_INVALID', 'Preserved target file inventory must be an object.');
  }
  const keys = Object.keys(value).sort(compareCanonicalText);
  if (
    canonicalJson(keys) !== canonicalJson(['generatedAt', 'records', 'schemaVersion']) ||
    value.schemaVersion !== 1 || typeof value.generatedAt !== 'string' || !Array.isArray(value.records) || !value.records.length
  ) {
    throw new AtlasError('HISTORICAL_FILE_INVENTORY_INVALID', 'Preserved target file inventory header is invalid.');
  }
  if (value.records.length > HARD_MAX_INCLUDED_FILES) {
    throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Preserved target file inventory exceeds ${HARD_MAX_INCLUDED_FILES} records.`);
  }
  const paths = new Set<string>();
  for (const [index, candidate] of value.records.entries()) {
    if (!isRecord(candidate) || typeof candidate.path !== 'string') {
      throw new AtlasError('HISTORICAL_FILE_INVENTORY_INVALID', `Target file inventory record ${index + 1} has no path.`);
    }
    let normalized: string;
    try {
      normalized = normalizeTargetRelative(candidate.path);
    } catch {
      throw new AtlasError('HISTORICAL_FILE_INVENTORY_INVALID', `Target file inventory record ${index + 1} has an invalid path.`);
    }
    if (normalized !== candidate.path || /[?*{}\[\]]/u.test(normalized) || paths.has(normalized)) {
      throw new AtlasError('HISTORICAL_FILE_INVENTORY_INVALID', `Target file inventory record ${index + 1} has a non-canonical or duplicate path.`);
    }
    paths.add(normalized);
  }
  return paths;
}

function cleanHeading(value: string): string {
  return value
    .replace(/`([^`]+)`/gu, '$1')
    .replace(/\[([^\]]+)\]\([^)]*\)/gu, '$1')
    .replace(/[*_~]/gu, '')
    .replace(/\s+#+\s*$/u, '')
    .trim()
    .normalize('NFC');
}

function canonicalPathAnchor(
  rawValue: string,
  targetFilePaths?: ReadonlySet<string>
): Omit<HistoricalEvidencePathAnchor, 'mentions'> | undefined {
  let candidate = rawValue.trim().normalize('NFC');
  if (!candidate || /\s/u.test(candidate) || candidate.includes('://') || candidate.startsWith('/') || candidate.startsWith('~')) return undefined;
  candidate = candidate
    .replace(/^\.\//u, '')
    .replace(/[),.;]+$/u, '');
  let targetStartLine: number | undefined;
  let targetEndLine: number | undefined;
  const hashRange = /#L(\d+)(?:-L?(\d+))?$/iu.exec(candidate);
  const colonRange = hashRange ? undefined : /:(\d+)(?:[-–](\d+))?$/u.exec(candidate);
  const range = hashRange ?? colonRange;
  if (range) {
    targetStartLine = Number(range[1]);
    targetEndLine = Number(range[2] ?? range[1]);
    if (
      !Number.isSafeInteger(targetStartLine) || !Number.isSafeInteger(targetEndLine) ||
      targetStartLine < 1 || targetEndLine < targetStartLine
    ) return undefined;
    candidate = candidate.slice(0, range.index);
  }
  if (!/^[A-Za-z0-9._@+{}\[\]*?/-]+$/u.test(candidate)) return undefined;
  if (candidate.split('/').some((segment) => !segment || segment === '.' || segment === '..')) return undefined;
  let normalized: string;
  try {
    normalized = normalizeTargetRelative(candidate);
  } catch {
    return undefined;
  }
  const lastSegment = normalized.split('/').at(-1)!;
  const hasPatternSyntax = /[?*{}\[\]]/u.test(normalized);
  const inventoryFile = !hasPatternSyntax && targetFilePaths?.has(normalized) === true;
  const extensionFile = normalized.includes('/') && !hasPatternSyntax && /\.[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(lastSegment);
  const kind: HistoricalEvidencePathAnchor['kind'] = inventoryFile || extensionFile ? 'file' : 'directory-or-pattern';
  if (!normalized.includes('/') && !inventoryFile) return undefined;
  if (targetStartLine !== undefined && kind !== 'file') return undefined;
  return {
    path: normalized,
    kind,
    ...(targetStartLine === undefined ? {} : { targetStartLine, targetEndLine: targetEndLine! })
  };
}

function reviewerIdentity(lines: string[], artifact: ReferenceFileEntry): HistoricalReviewerIdentity {
  const boundary = lines.findIndex((line, index) => index > 0 && /^##\s+/u.test(line));
  const limit = Math.min(boundary === -1 ? lines.length : boundary, 40);
  for (let index = 0; index < limit; index += 1) {
    const line = lines[index]!;
    const match = /^(?:Reviewer(?: identity)?|Reviewed by):\s*(.+?)\s*$/iu.exec(line);
    if (!match) continue;
    const identity = match[1]!.trim().normalize('NFC');
    if (!identity || /^(?:unknown|unavailable|not recorded)$/iu.test(identity)) break;
    if (identity.length > 256 || /[\u0000-\u001f\u007f-\u009f]/u.test(identity)) {
      throw new AtlasError('HISTORICAL_METADATA_INVALID', `Structured reviewer identity is invalid in ${artifact.path}.`);
    }
    return {
      status: 'recorded',
      identity,
      reason: 'Identity was copied from an explicit structured reviewer metadata line; no independent identity validation was performed.',
      citation: {
        path: artifact.path,
        sha256: artifact.sha256,
        line: index + 1,
        column: line.indexOf(match[1]!) + 1,
        basis: 'reviewer-metadata'
      }
    };
  }
  return { status: 'unavailable', identity: null, reason: REVIEWER_UNAVAILABLE_REASON };
}

function parseMarkdownMetadata(
  content: Buffer,
  artifact: ReferenceFileEntry,
  targetFilePaths?: ReadonlySet<string>
): MarkdownMetadata {
  const text = content.toString('utf8').replace(/^\uFEFF/u, '').replace(/\r\n?/gu, '\n').normalize('NFC');
  if (text.includes('\0')) throw new AtlasError('HISTORICAL_METADATA_INVALID', `Historical Markdown contains a NUL byte: ${artifact.path}`);
  assertTextLineLimit(text, {
    maxLines: MAX_HISTORICAL_TEXT_LINES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    label: `Historical Markdown ${artifact.path}`
  });
  const lines = text.split('\n');
  let title: string | undefined;
  let titleLine = 0;
  const scopeAnchors: HistoricalEvidenceScopeAnchor[] = [];
  const paths = new Map<string, HistoricalEvidencePathAnchor>();
  let anchorCount = 0;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    const headingMatch = /^(#{1,6})\s+(.+?)\s*$/u.exec(line);
    if (headingMatch) {
      const heading = cleanHeading(headingMatch[2]!);
      const level = headingMatch[1]!.length;
      if (!title && level === 1 && heading) {
        title = heading;
        titleLine = index + 1;
      }
      if (level > 1 && heading && /\b(?:scope|coverage|boundary|boundaries|bounded|inclusion|exclusion)\b/iu.test(heading)) {
        anchorCount += 1;
        if (anchorCount > MAX_HISTORICAL_ANCHORS) {
          throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical Markdown exceeds ${MAX_HISTORICAL_ANCHORS} anchors: ${artifact.path}`);
        }
        scopeAnchors.push({ heading, level, line: index + 1, column: level + 2 });
      }
    }
    const inlineCode = /`([^`\r\n]+)`/gu;
    for (const match of line.matchAll(inlineCode)) {
      const before = match.index === 0 ? '' : line[match.index! - 1];
      const afterIndex = match.index! + match[0].length;
      const after = afterIndex >= line.length ? '' : line[afterIndex];
      if (before === '`' || after === '`') continue;
      const parsed = canonicalPathAnchor(match[1]!, targetFilePaths);
      if (!parsed) continue;
      anchorCount += 1;
      if (anchorCount > MAX_HISTORICAL_ANCHORS) {
        throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical Markdown exceeds ${MAX_HISTORICAL_ANCHORS} anchors: ${artifact.path}`);
      }
      const mention = { line: index + 1, column: match.index! + 2 };
      const pathKey = `${parsed.path}\0${parsed.targetStartLine ?? ''}\0${parsed.targetEndLine ?? ''}`;
      const existing = paths.get(pathKey);
      if (existing) existing.mentions.push(mention);
      else paths.set(pathKey, { ...parsed, mentions: [mention] });
    }
  }
  if (!title) throw new AtlasError('HISTORICAL_METADATA_INVALID', `Historical Markdown is missing a level-one title: ${artifact.path}`);
  scopeAnchors.sort((left, right) => left.line - right.line || left.column - right.column || compareCanonicalText(left.heading, right.heading));
  const pathAnchors = [...paths.values()].sort((left, right) => (
    compareCanonicalText(left.path, right.path) ||
    (left.targetStartLine ?? 0) - (right.targetStartLine ?? 0) ||
    (left.targetEndLine ?? 0) - (right.targetEndLine ?? 0)
  ));
  for (const anchor of pathAnchors) {
    anchor.mentions.sort((left, right) => left.line - right.line || left.column - right.column);
  }
  return {
    title,
    titleLine,
    scopeAnchors,
    pathAnchors,
    reviewerIdentity: reviewerIdentity(lines, artifact)
  };
}

function parseTraceIndex(content: Buffer, artifact: ReferenceFileEntry): Array<TraceIndexEntry & { line: number; column: number }> {
  const text = content.toString('utf8').replace(/\r\n?/gu, '\n');
  assertTextLineLimit(text, {
    maxLines: MAX_HISTORICAL_TEXT_LINES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    label: `Historical trace index ${artifact.path}`
  });
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', 'Preserved trace index is not valid JSON.');
  }
  if (!isRecord(value)) throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', 'Preserved trace index must be an object.');
  const keys = Object.keys(value).sort(compareCanonicalText);
  if (canonicalJson(keys) !== canonicalJson(['purpose', 'schemaVersion', 'traces'])) {
    throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', 'Preserved trace index has unexpected or missing fields.');
  }
  if (value.schemaVersion !== 1 || typeof value.purpose !== 'string' || !value.purpose || !Array.isArray(value.traces)) {
    throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', 'Preserved trace index header is invalid.');
  }
  if (value.traces.length > HARD_MAX_INCLUDED_FILES) {
    throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Preserved trace index exceeds ${HARD_MAX_INCLUDED_FILES} entries.`);
  }
  const document = value as unknown as TraceIndexDocument;
  const lines = text.split('\n');
  const sourceLocations = new Map<string, Array<{ line: number; column: number }>>();
  const idPattern = /"id": ("(?:\\.|[^"\\])*")/gu;
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    for (const match of lines[lineIndex]!.matchAll(idPattern)) {
      let id: unknown;
      try {
        id = JSON.parse(match[1]!) as unknown;
      } catch {
        continue;
      }
      if (typeof id !== 'string') continue;
      const locations = sourceLocations.get(id) ?? [];
      locations.push({ line: lineIndex + 1, column: match.index! + 1 });
      sourceLocations.set(id, locations);
    }
  }
  const traces = document.traces.map((candidate, index) => {
    if (!isRecord(candidate)) throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', `Trace entry ${index + 1} must be an object.`);
    const entryKeys = Object.keys(candidate).sort(compareCanonicalText);
    if (canonicalJson(entryKeys) !== canonicalJson(['artifact', 'clusterId', 'id', 'label', 'lifecycle', 'summary'])) {
      throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', `Trace entry ${index + 1} has unexpected or missing fields.`);
    }
    const entry: TraceIndexEntry = {
      id: stringField(candidate, 'id', `Trace entry ${index + 1}`),
      label: stringField(candidate, 'label', `Trace entry ${index + 1}`),
      clusterId: stringField(candidate, 'clusterId', `Trace entry ${index + 1}`),
      lifecycle: stringField(candidate, 'lifecycle', `Trace entry ${index + 1}`),
      summary: stringField(candidate, 'summary', `Trace entry ${index + 1}`),
      artifact: stringField(candidate, 'artifact', `Trace entry ${index + 1}`)
    };
    if (normalizeTargetRelative(entry.artifact) !== entry.artifact || !/^traces\/[^/]+\.md$/u.test(entry.artifact)) {
      throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', `Trace entry ${entry.id} has a non-canonical artifact path.`);
    }
    const matches = sourceLocations.get(entry.id) ?? [];
    if (matches.length !== 1) {
      throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', `Trace entry ${entry.id} does not have one unambiguous source location.`);
    }
    return {
      ...entry,
      line: matches[0]!.line,
      column: matches[0]!.column
    };
  });
  const ids = traces.map((entry) => entry.id);
  const artifacts = traces.map((entry) => entry.artifact);
  if (new Set(ids).size !== ids.length || new Set(artifacts).size !== artifacts.length) {
    throw new AtlasError('HISTORICAL_TRACE_INDEX_INVALID', 'Trace index IDs and artifact paths must be unique.');
  }
  return traces.sort((left, right) => compareCanonicalText(left.id, right.id));
}

function recordIdentity(record: Omit<HistoricalEvidenceRecord, 'id' | 'schemaVersion'>): string {
  return `historical_record_sha256_${sha256(canonicalJson({ domain: 'atlas.historical-evidence.record.v1', ...record }))}`;
}

function indexIdentity(material: Omit<HistoricalEvidenceIndex, 'indexId' | 'schemaVersion' | 'artifacts'>, records: HistoricalEvidenceRecord[]): string {
  return `historical_evidence_sha256_${sha256(canonicalJson({
    domain: 'atlas.historical-evidence.index.v1',
    ...material,
    records
  }))}`;
}

function historicalRecordAnchorCount(record: HistoricalEvidenceRecord): number {
  return record.scopeAnchors.length + record.pathAnchors.reduce(
    (total, anchor) => total + anchor.mentions.length,
    0
  );
}

function assertHistoricalRecordResourceLimits(records: readonly unknown[]): void {
  let aggregateAnchors = 0;
  let pathDefinitions = 0;
  for (const candidate of records) {
    if (!isRecord(candidate)) continue;
    const scopeAnchors = candidate.scopeAnchors;
    if (Array.isArray(scopeAnchors)) aggregateAnchors += scopeAnchors.length;
    const pathAnchors = candidate.pathAnchors;
    if (Array.isArray(pathAnchors)) {
      pathDefinitions += pathAnchors.length;
      if (pathDefinitions > MAX_HISTORICAL_ANCHORS) {
        throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence index exceeds ${MAX_HISTORICAL_ANCHORS} aggregate anchors.`);
      }
      for (const pathAnchor of pathAnchors) {
        if (isRecord(pathAnchor) && Array.isArray(pathAnchor.mentions)) aggregateAnchors += pathAnchor.mentions.length;
        if (aggregateAnchors > MAX_HISTORICAL_ANCHORS) break;
      }
    }
    if (aggregateAnchors > MAX_HISTORICAL_ANCHORS) {
      throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence index exceeds ${MAX_HISTORICAL_ANCHORS} aggregate anchors.`);
    }
  }
}

function anchorFreshness(): HistoricalAnchorFreshness {
  return {
    status: 'unavailable',
    checkedAgainstSourceHead: null,
    reason: FRESHNESS_UNAVAILABLE_REASON
  };
}

function makeRecord(options: {
  kind: 'review' | 'trace';
  artifact: ReferenceFileEntry;
  markdown: MarkdownMetadata;
  trace?: HistoricalTraceMetadata;
}): HistoricalEvidenceRecord {
  const material: Omit<HistoricalEvidenceRecord, 'id' | 'schemaVersion'> = {
    kind: options.kind,
    artifact: options.artifact,
    title: options.markdown.title,
    titleLine: options.markdown.titleLine,
    scopeAnchors: options.markdown.scopeAnchors,
    pathAnchors: options.markdown.pathAnchors,
    reviewerIdentity: options.markdown.reviewerIdentity,
    anchorFreshness: anchorFreshness(),
    interpretation: INTERPRETATION,
    ...(options.trace ? { trace: options.trace } : {})
  };
  return { schemaVersion: 1, id: recordIdentity(material), ...material };
}

function sourceProjection(reference: VerifiedReference): HistoricalEvidenceSource {
  return {
    referencePath: reference.manifest.referencePath,
    manifestFileName: path.basename(reference.manifestPath),
    manifestSha256: reference.manifestSha256,
    referenceAggregateSha256: reference.manifest.aggregateSha256,
    sourceAggregateSha256: reference.manifest.sourceAggregateSha256,
    referenceFileCount: reference.manifest.fileCount,
    referenceTotalBytes: reference.manifest.totalBytes,
    sourceGitHead: reference.manifest.sourceObservation.gitHead,
    sourceAtlasPath: reference.manifest.sourceObservation.atlasPath,
    sourceDirtyStatusSha256: reference.manifest.sourceObservation.dirtyStatusSha256,
    sourceDirtyStatusLineCount: reference.manifest.sourceObservation.dirtyStatusLineCount
  };
}

function safeTemporaryPath(parent: string, candidate: string): boolean {
  return path.dirname(candidate) === parent && path.basename(candidate).startsWith('.atlas-historical-evidence-tmp-');
}

async function removeTemporary(parent: string, candidate: string): Promise<void> {
  if (!safeTemporaryPath(parent, candidate) || path.resolve(parent) === path.resolve(candidate)) {
    throw new AtlasError('UNSAFE_TEMP_PATH', 'Refusing to remove an unsafe historical-evidence temporary path.');
  }
  await rm(candidate, { recursive: true, force: true });
}

function samePath(left: string, right: string): boolean {
  return path.relative(path.resolve(left), path.resolve(right)) === '';
}

function sameDirectoryIdentity(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function assertWorkspaceOutput(options: {
  workspacePath: string;
  reference: VerifiedReference;
}): Promise<{ workspacePath: string; outputRoot: string; sourceTargetRoot: string }> {
  const workspacePath = await resolveForContainment(options.workspacePath);
  const outputRoot = await resolveForContainment(path.join(workspacePath, 'historical-evidence'));
  // The source path is imported provenance and may be stale or hostile. Keep
  // its containment check lexical so a mapped drive or reparse point cannot
  // turn manifest validation into an SMB/device lookup.
  const sourceTargetRoot = path.resolve(options.reference.manifest.sourceObservation.repositoryPath);
  if (!isInside(workspacePath, outputRoot)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Historical-evidence output resolves outside the selected workspace.');
  }
  if (isInside(options.reference.referenceRoot, outputRoot)) {
    throw new AtlasError('HISTORICAL_WORKSPACE_INSIDE_REFERENCE', 'Historical-evidence output must be outside the immutable reference tree.');
  }
  if (isInside(sourceTargetRoot, outputRoot)) {
    throw new AtlasError('HISTORICAL_WORKSPACE_INSIDE_TARGET', 'Historical-evidence output must be outside the observed source target repository.');
  }
  return { workspacePath, outputRoot, sourceTargetRoot };
}

async function exactArtifactContent(directory: string, expected: Map<string, Buffer>): Promise<boolean> {
  for (const [name, content] of expected) {
    const observed = await readBoundedRegularFile(path.join(directory, name), {
      maxBytes: name === 'artifact-digests.json' ? MAX_VERIFIER_MANIFEST_BYTES : MAX_VERIFIER_ARTIFACT_BYTES,
      resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
      invalidCode: 'HISTORICAL_DETERMINISM_CONFLICT',
      label: `Historical-evidence artifact ${name}`
    });
    if (!observed.equals(content)) return false;
  }
  return true;
}

export async function createHistoricalEvidenceIndex(options: {
  referencePath: string;
  manifestPath: string;
  workspacePath: string;
}): Promise<HistoricalEvidenceIndexResult> {
  const reference = await verifyReference({ referencePath: options.referencePath, manifestPath: options.manifestPath });
  const { workspacePath, outputRoot, sourceTargetRoot } = await assertWorkspaceOutput({ workspacePath: options.workspacePath, reference });
  const reviewEntries = reference.manifest.files
    .filter((entry) => /^reviews\/[^/]+\.md$/u.test(entry.path))
    .sort((left, right) => compareCanonicalText(left.path, right.path));
  if (!reviewEntries.length) throw new AtlasError('HISTORICAL_REVIEWS_MISSING', 'Preserved reference contains no reviews/*.md artifacts.');
  const traceIndexEntry = reference.entries.get(TRACE_INDEX_PATH);
  if (!traceIndexEntry) throw new AtlasError('HISTORICAL_TRACE_INDEX_MISSING', `Preserved reference is missing ${TRACE_INDEX_PATH}.`);
  const traceIndexContent = await readVerifiedReferenceFile(reference, TRACE_INDEX_PATH);
  const namedTraces = parseTraceIndex(traceIndexContent, traceIndexEntry);
  if (!namedTraces.length) throw new AtlasError('HISTORICAL_TRACES_MISSING', 'Preserved trace index contains no named trace entries.');
  const targetFilePaths = await targetFileInventory(reference);

  const records: HistoricalEvidenceRecord[] = [];
  let aggregateAnchors = 0;
  const appendRecord = (record: HistoricalEvidenceRecord): void => {
    aggregateAnchors = addToBoundedCount(aggregateAnchors, historicalRecordAnchorCount(record), {
      maxCount: MAX_HISTORICAL_ANCHORS,
      resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
      label: 'Historical-evidence anchors'
    });
    records.push(record);
  };
  for (const artifact of reviewEntries) {
    const markdown = parseMarkdownMetadata(await readVerifiedReferenceFile(reference, artifact.path), artifact, targetFilePaths);
    appendRecord(makeRecord({ kind: 'review', artifact, markdown }));
  }
  for (const namedTrace of namedTraces) {
    const artifact = reference.entries.get(namedTrace.artifact);
    if (!artifact) {
      throw new AtlasError('HISTORICAL_TRACE_ARTIFACT_MISSING', `Trace index artifact is not sealed by the preservation manifest: ${namedTrace.artifact}`);
    }
    const markdown = parseMarkdownMetadata(await readVerifiedReferenceFile(reference, artifact.path), artifact, targetFilePaths);
    appendRecord(makeRecord({
      kind: 'trace',
      artifact,
      markdown,
      trace: {
        id: namedTrace.id,
        label: namedTrace.label,
        clusterId: namedTrace.clusterId,
        lifecycle: namedTrace.lifecycle,
        historicalUnvalidatedSummary: namedTrace.summary,
        citation: {
          path: TRACE_INDEX_PATH,
          sha256: traceIndexEntry.sha256,
          line: namedTrace.line,
          column: namedTrace.column,
          basis: 'trace-index-entry'
        }
      }
    }));
  }
  records.sort((left, right) => compareCanonicalText(left.id, right.id));
  if (records.length > MAX_HISTORICAL_INDEX_RECORDS) {
    throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence index exceeds ${MAX_HISTORICAL_INDEX_RECORDS} records.`);
  }
  const counts: HistoricalEvidenceIndex['counts'] = {
    reviews: records.filter((record) => record.kind === 'review').length,
    traces: records.filter((record) => record.kind === 'trace').length,
    records: records.length,
    scopeAnchors: records.reduce((total, record) => total + record.scopeAnchors.length, 0),
    pathAnchors: records.reduce((total, record) => total + record.pathAnchors.length, 0)
  };
  const material: Omit<HistoricalEvidenceIndex, 'indexId' | 'schemaVersion' | 'artifacts'> = {
    producer: { name: 'atlas/historical-evidence', version: HISTORICAL_EVIDENCE_PRODUCER_VERSION },
    source: sourceProjection(reference),
    policy: {
      reviewSelection: 'reviews/*.md',
      traceSelection: 'named-entries-from-traces/trace-index.json',
      claimBodiesImported: false,
      validatedFindingsCreated: false,
      defaultTrust: 'historical-unvalidated-context'
    },
    counts
  };
  const indexId = indexIdentity(material, records);
  const index: HistoricalEvidenceIndex = {
    schemaVersion: 1,
    indexId,
    ...material,
    artifacts: [...INDEX_ARTIFACTS]
  };
  await assertSchema('historical-evidence-index', index, 'Historical-evidence index');
  for (let recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
    await assertSchema('historical-evidence-record', records[recordIndex], `Historical-evidence record ${recordIndex + 1}`);
  }
  assertPortableDataSafe({ index, records }, 'Historical-evidence index');
  const indexContent = Buffer.from(prettyCanonicalJson(index));
  const recordsContent = Buffer.from(canonicalJsonLines(records));
  const manifest: HistoricalEvidenceArtifactManifest = {
    schemaVersion: 1,
    indexId,
    artifacts: [
      { path: 'index.json', bytes: indexContent.length, sha256: sha256(indexContent) },
      { path: 'records.jsonl', bytes: recordsContent.length, sha256: sha256(recordsContent) }
    ]
  };
  await assertSchema('historical-evidence-artifact-manifest', manifest, 'Historical-evidence artifact manifest');
  const manifestContent = Buffer.from(prettyCanonicalJson(manifest));
  for (const [name, content] of [['index.json', indexContent], ['records.jsonl', recordsContent]] as const) {
    if (content.length > MAX_VERIFIER_ARTIFACT_BYTES) {
      throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence artifact exceeds ${MAX_VERIFIER_ARTIFACT_BYTES} bytes: ${name}`);
    }
  }
  if (manifestContent.length > MAX_VERIFIER_MANIFEST_BYTES) {
    throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence artifact manifest exceeds ${MAX_VERIFIER_MANIFEST_BYTES} bytes.`);
  }
  assertAggregateByteLimit([indexContent.length, recordsContent.length, manifestContent.length], {
    maxBytes: MAX_VERIFIER_TOTAL_BYTES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    label: 'Historical-evidence artifacts'
  });
  const artifacts = new Map<string, Buffer>([
    ['index.json', indexContent],
    ['records.jsonl', recordsContent],
    ['artifact-digests.json', manifestContent]
  ]);

  if (isInside(reference.referenceRoot, workspacePath) || isInside(sourceTargetRoot, workspacePath)) {
    throw new AtlasError(
      isInside(reference.referenceRoot, workspacePath) ? 'HISTORICAL_WORKSPACE_INSIDE_REFERENCE' : 'HISTORICAL_WORKSPACE_INSIDE_TARGET',
      'Historical-evidence workspace must be outside the immutable reference and observed source target.'
    );
  }
  await mkdir(outputRoot, { recursive: true });
  const canonicalOutputRoot = await realpath(outputRoot);
  if (!isInside(workspacePath, canonicalOutputRoot) || isInside(reference.referenceRoot, canonicalOutputRoot) || isInside(sourceTargetRoot, canonicalOutputRoot)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Historical-evidence output root changed during containment validation.');
  }
  const directory = path.join(canonicalOutputRoot, indexId);
  if (await exists(directory)) {
    const verified = await verifyExpectedHistoricalEvidenceIndex(canonicalOutputRoot, indexId);
    if (verified.index.indexId !== indexId || !(await exactArtifactContent(verified.directory, artifacts))) {
      throw new AtlasError('HISTORICAL_DETERMINISM_CONFLICT', `Historical-evidence index ${indexId} exists with different content.`);
    }
    return {
      status: 'reused',
      directory: verified.directory,
      indexId,
      counts,
      referenceVerification: reference.summary
    };
  }
  const temporaryDirectory = path.join(canonicalOutputRoot, `.atlas-historical-evidence-tmp-${randomUUID().replaceAll('-', '')}`);
  let temporaryCreated = false;
  try {
    if (!safeTemporaryPath(canonicalOutputRoot, temporaryDirectory)) throw new AtlasError('UNSAFE_TEMP_PATH', 'Unsafe historical-evidence temporary path.');
    await mkdir(temporaryDirectory, { recursive: false });
    temporaryCreated = true;
    for (const name of INDEX_ARTIFACTS) await writeFile(path.join(temporaryDirectory, name), artifacts.get(name)!, { flag: 'wx' });
    await verifyAndLoadHistoricalEvidenceIndex(temporaryDirectory);
    if (await exists(directory)) {
      const verified = await verifyExpectedHistoricalEvidenceIndex(canonicalOutputRoot, indexId);
      if (verified.index.indexId !== indexId || !(await exactArtifactContent(verified.directory, artifacts))) {
        throw new AtlasError('HISTORICAL_DETERMINISM_CONFLICT', `Historical-evidence index ${indexId} appeared with different content.`);
      }
      await removeTemporary(canonicalOutputRoot, temporaryDirectory);
      temporaryCreated = false;
      return {
        status: 'reused',
        directory: verified.directory,
        indexId,
        counts,
        referenceVerification: reference.summary
      };
    }
    await rename(temporaryDirectory, directory);
    temporaryCreated = false;
    const verified = await verifyExpectedHistoricalEvidenceIndex(canonicalOutputRoot, indexId);
    return {
      status: 'completed',
      directory: verified.directory,
      indexId,
      counts,
      referenceVerification: reference.summary
    };
  } finally {
    if (temporaryCreated && await exists(temporaryDirectory)) await removeTemporary(canonicalOutputRoot, temporaryDirectory);
  }
}

function parseJson<T>(content: string, label: string): T {
  try {
    const value = JSON.parse(content) as T;
    assertNestingDepth(value, {
      maxDepth: MAX_VERIFIER_NESTING_DEPTH,
      resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
      label
    });
    return value;
  } catch (error) {
    if (error instanceof AtlasError) throw error;
    throw new AtlasError('HISTORICAL_INDEX_INVALID', `${label} is not valid JSON.`);
  }
}

function parseJsonLines<T>(content: string, label: string): T[] {
  try {
    return parseBoundedJsonLines<T>(content, {
      maxRecords: MAX_HISTORICAL_INDEX_RECORDS,
      maxDepth: MAX_VERIFIER_NESTING_DEPTH,
      resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
      label
    });
  } catch (error) {
    if (error instanceof AtlasError) throw error;
    throw new AtlasError('HISTORICAL_INDEX_INVALID', `${label} is not valid JSON Lines.`);
  }
}

function assertCitation(citation: HistoricalEvidenceCitation, record: HistoricalEvidenceRecord): void {
  normalizeTargetRelative(citation.path);
  if (citation.basis === 'trace-index-entry') {
    if (record.kind !== 'trace' || citation.path !== TRACE_INDEX_PATH) {
      throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', `Trace-index citation is invalid for ${record.id}.`);
    }
  } else if (citation.path !== record.artifact.path || citation.sha256 !== record.artifact.sha256) {
    throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', `Artifact citation provenance differs for ${record.id}.`);
  }
}

function assertRecordIntegrity(record: HistoricalEvidenceRecord): void {
  const { id, schemaVersion, ...material } = record;
  if (schemaVersion !== 1 || id !== recordIdentity(material)) {
    throw new AtlasError('HISTORICAL_INDEX_IDENTITY', `Historical-evidence record identity differs: ${id}`);
  }
  if (record.kind === 'review' && !/^reviews\/[^/]+\.md$/u.test(record.artifact.path)) {
    throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', `Review record has an invalid artifact path: ${id}`);
  }
  if (record.kind === 'trace' && (!record.trace || !/^traces\/[^/]+\.md$/u.test(record.artifact.path))) {
    throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', `Trace record is incomplete: ${id}`);
  }
  if (record.kind === 'review' && record.trace) {
    throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', `Review record unexpectedly has trace metadata: ${id}`);
  }
  if (record.interpretation.claimBodiesImported || record.interpretation.validatedFindingsCreated || record.interpretation.usage !== INTERPRETATION.usage) {
    throw new AtlasError('HISTORICAL_INDEX_TRUST', `Historical record attempts to elevate unvalidated claims: ${id}`);
  }
  if (record.anchorFreshness.status !== 'unavailable' || record.anchorFreshness.checkedAgainstSourceHead !== null) {
    throw new AtlasError('HISTORICAL_INDEX_TRUST', `Historical record overstates anchor freshness: ${id}`);
  }
  if (record.reviewerIdentity.status === 'unavailable') {
    if (record.reviewerIdentity.identity !== null || record.reviewerIdentity.citation) {
      throw new AtlasError('HISTORICAL_INDEX_TRUST', `Unavailable reviewer identity is inconsistent: ${id}`);
    }
  } else if (!record.reviewerIdentity.identity || !record.reviewerIdentity.citation) {
    throw new AtlasError('HISTORICAL_INDEX_TRUST', `Recorded reviewer identity lacks provenance: ${id}`);
  }
  if (record.reviewerIdentity.citation) assertCitation(record.reviewerIdentity.citation, record);
  const sortedScopes = [...record.scopeAnchors].sort((left, right) => left.line - right.line || left.column - right.column || compareCanonicalText(left.heading, right.heading));
  if (canonicalJson(sortedScopes) !== canonicalJson(record.scopeAnchors)) {
    throw new AtlasError('HISTORICAL_INDEX_ORDER', `Scope anchors are not ordered for ${id}.`);
  }
  const sortedPaths = [...record.pathAnchors].sort((left, right) => (
    compareCanonicalText(left.path, right.path) ||
    (left.targetStartLine ?? 0) - (right.targetStartLine ?? 0) ||
    (left.targetEndLine ?? 0) - (right.targetEndLine ?? 0)
  ));
  const anchorKey = (anchor: HistoricalEvidencePathAnchor): string => (
    `${anchor.path}\0${anchor.targetStartLine ?? ''}\0${anchor.targetEndLine ?? ''}`
  );
  if (canonicalJson(sortedPaths.map(anchorKey)) !== canonicalJson(record.pathAnchors.map(anchorKey))) {
    throw new AtlasError('HISTORICAL_INDEX_ORDER', `Path anchors are not ordered for ${id}.`);
  }
  const uniquePaths = new Set<string>();
  for (const anchor of record.pathAnchors) {
    const key = anchorKey(anchor);
    const hasStart = anchor.targetStartLine !== undefined;
    const hasEnd = anchor.targetEndLine !== undefined;
    if (
      normalizeTargetRelative(anchor.path) !== anchor.path || uniquePaths.has(key) || !anchor.mentions.length ||
      hasStart !== hasEnd ||
      (hasStart && (
        anchor.kind !== 'file' || !Number.isSafeInteger(anchor.targetStartLine) ||
        !Number.isSafeInteger(anchor.targetEndLine) || anchor.targetStartLine! < 1 ||
        anchor.targetEndLine! < anchor.targetStartLine!
      ))
    ) {
      throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', `Path anchor is invalid for ${id}.`);
    }
    uniquePaths.add(key);
    const sortedMentions = [...anchor.mentions].sort((left, right) => left.line - right.line || left.column - right.column);
    if (canonicalJson(sortedMentions) !== canonicalJson(anchor.mentions)) {
      throw new AtlasError('HISTORICAL_INDEX_ORDER', `Path-anchor mentions are not ordered for ${id}.`);
    }
  }
  if (record.trace) assertCitation(record.trace.citation, record);
}

export async function verifyAndLoadHistoricalEvidenceIndex(directoryValue: string): Promise<VerifiedHistoricalEvidenceIndex> {
  const requestedDirectory = path.resolve(directoryValue);
  let requestedMetadata;
  try {
    requestedMetadata = await lstat(requestedDirectory);
  } catch {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index is missing or unreadable.');
  }
  if (!requestedMetadata.isDirectory() || requestedMetadata.isSymbolicLink()) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index must be a regular directory.');
  }
  const directory = await realpath(requestedDirectory);
  if (!samePath(directory, requestedDirectory)) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index path must be canonical and cannot traverse a symlink or junction.');
  }
  const resolvedMetadata = await lstat(directory);
  if (
    !resolvedMetadata.isDirectory() || resolvedMetadata.isSymbolicLink() ||
    !sameDirectoryIdentity(requestedMetadata, resolvedMetadata)
  ) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index directory identity changed during verification.');
  }
  const names = (await readBoundedDirectoryEntries(directory, {
    maxEntries: MAX_VERIFIER_DIRECTORY_ENTRIES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    label: 'Historical-evidence index directory'
  }))
    .map((entry) => {
      if (!entry.isFile() || entry.isSymbolicLink()) {
        throw new AtlasError('HISTORICAL_INDEX_INVALID', `Historical-evidence index contains an unsupported entry: ${entry.name}`);
      }
      return entry.name;
    })
    .sort(compareCanonicalText);
  const expectedNames = [...INDEX_ARTIFACTS].sort(compareCanonicalText);
  if (canonicalJson(names) !== canonicalJson(expectedNames)) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index artifact set is incomplete or contains extras.');
  }
  const manifestBytes = await readBoundedRegularFile(path.join(directory, 'artifact-digests.json'), {
    maxBytes: MAX_VERIFIER_MANIFEST_BYTES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    invalidCode: 'HISTORICAL_INDEX_INVALID',
    label: 'Historical-evidence artifact manifest'
  });
  const rawManifest = manifestBytes.toString('utf8');
  const manifest = parseJson<HistoricalEvidenceArtifactManifest>(rawManifest, 'Historical-evidence artifact manifest');
  await assertSchema('historical-evidence-artifact-manifest', manifest, 'Historical-evidence artifact manifest');
  if (rawManifest !== prettyCanonicalJson(manifest)) {
    throw new AtlasError('HISTORICAL_INDEX_CANONICAL', 'Historical-evidence artifact manifest is not canonically serialized.');
  }
  const manifestPaths = manifest.artifacts.map((artifact) => artifact.path);
  if (canonicalJson(manifestPaths) !== canonicalJson([...HASHED_INDEX_ARTIFACTS])) {
    throw new AtlasError('HISTORICAL_INDEX_ORDER', 'Historical-evidence artifact manifest is not in canonical order.');
  }
  for (const artifact of manifest.artifacts) {
    if (artifact.bytes > MAX_VERIFIER_ARTIFACT_BYTES) {
      throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence artifact exceeds ${MAX_VERIFIER_ARTIFACT_BYTES} declared bytes: ${artifact.path}`);
    }
  }
  assertAggregateByteLimit([manifestBytes.length, ...manifest.artifacts.map((artifact) => artifact.bytes)], {
    maxBytes: MAX_VERIFIER_TOTAL_BYTES,
    resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
    label: 'Historical-evidence artifacts'
  });
  const content = new Map<string, Buffer>();
  let observedBytes = manifestBytes.length;
  for (const artifact of manifest.artifacts) {
    const observed = await readBoundedRegularFile(path.join(directory, artifact.path), {
      maxBytes: MAX_VERIFIER_ARTIFACT_BYTES,
      resourceCode: 'HISTORICAL_RESOURCE_LIMIT',
      invalidCode: 'HISTORICAL_INDEX_INVALID',
      label: `Historical-evidence artifact ${artifact.path}`
    });
    if (observed.length > MAX_VERIFIER_TOTAL_BYTES - observedBytes) {
      throw new AtlasError('HISTORICAL_RESOURCE_LIMIT', `Historical-evidence artifacts exceed ${MAX_VERIFIER_TOTAL_BYTES} observed bytes.`);
    }
    observedBytes += observed.length;
    content.set(artifact.path, observed);
    if (observed.length !== artifact.bytes || sha256(observed) !== artifact.sha256) {
      throw new AtlasError('HISTORICAL_INDEX_DIGEST', `Historical-evidence artifact digest differs: ${artifact.path}`);
    }
  }
  const rawIndex = content.get('index.json')!.toString('utf8');
  const rawRecords = content.get('records.jsonl')!.toString('utf8');
  const index = parseJson<HistoricalEvidenceIndex>(rawIndex, 'Historical-evidence index');
  const records = parseJsonLines<HistoricalEvidenceRecord>(rawRecords, 'Historical-evidence records');
  assertHistoricalRecordResourceLimits(records);
  await assertSchema('historical-evidence-index', index, 'Historical-evidence index');
  for (let recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
    await assertSchema('historical-evidence-record', records[recordIndex], `Historical-evidence record ${recordIndex + 1}`);
  }
  if (rawIndex !== prettyCanonicalJson(index) || rawRecords !== canonicalJsonLines(records)) {
    throw new AtlasError('HISTORICAL_INDEX_CANONICAL', 'Historical-evidence artifacts are not canonically serialized.');
  }
  if (manifest.indexId !== index.indexId) throw new AtlasError('HISTORICAL_INDEX_IDENTITY', 'Index and artifact manifest IDs differ.');
  const recordIds = records.map((record) => record.id);
  if (new Set(recordIds).size !== recordIds.length) throw new AtlasError('HISTORICAL_INDEX_INTEGRITY', 'Historical-evidence record IDs are not unique.');
  const sortedRecordIds = [...recordIds].sort(compareCanonicalText);
  if (canonicalJson(sortedRecordIds) !== canonicalJson(recordIds)) {
    throw new AtlasError('HISTORICAL_INDEX_ORDER', 'Historical-evidence records are not in canonical order.');
  }
  for (const record of records) assertRecordIntegrity(record);
  const observedCounts: HistoricalEvidenceIndex['counts'] = {
    reviews: records.filter((record) => record.kind === 'review').length,
    traces: records.filter((record) => record.kind === 'trace').length,
    records: records.length,
    scopeAnchors: records.reduce((total, record) => total + record.scopeAnchors.length, 0),
    pathAnchors: records.reduce((total, record) => total + record.pathAnchors.length, 0)
  };
  if (canonicalJson(observedCounts) !== canonicalJson(index.counts)) {
    throw new AtlasError('HISTORICAL_INDEX_COUNT', 'Historical-evidence index counts differ from its records.');
  }
  const { indexId, schemaVersion, artifacts, ...material } = index;
  if (schemaVersion !== 1 || canonicalJson(artifacts) !== canonicalJson([...INDEX_ARTIFACTS]) || indexId !== indexIdentity(material, records)) {
    throw new AtlasError('HISTORICAL_INDEX_IDENTITY', 'Historical-evidence index identity differs from its canonical content.');
  }
  if (
    index.policy.claimBodiesImported || index.policy.validatedFindingsCreated ||
    index.policy.defaultTrust !== 'historical-unvalidated-context'
  ) throw new AtlasError('HISTORICAL_INDEX_TRUST', 'Historical-evidence index overstates the trust of preserved claims.');
  assertPortableDataSafe({ index, records }, 'Historical-evidence index');
  const finalMetadata = await lstat(requestedDirectory);
  if (
    !finalMetadata.isDirectory() || finalMetadata.isSymbolicLink() ||
    !sameDirectoryIdentity(requestedMetadata, finalMetadata) ||
    !samePath(await realpath(requestedDirectory), directory)
  ) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index directory identity changed during verification.');
  }
  return {
    directory,
    index,
    records,
    manifest,
    manifestSha256: sha256(manifestBytes),
    summary: {
      status: 'passed',
      indexId,
      records: observedCounts.records,
      reviews: observedCounts.reviews,
      traces: observedCounts.traces,
      artifacts: 3,
      referenceAggregateSha256: index.source.referenceAggregateSha256,
      sourceGitHead: index.source.sourceGitHead
    }
  };
}

async function verifyExpectedHistoricalEvidenceIndex(
  canonicalOutputRoot: string,
  indexId: string
): Promise<VerifiedHistoricalEvidenceIndex> {
  const expectedDirectory = path.join(canonicalOutputRoot, indexId);
  if (
    !samePath(path.dirname(expectedDirectory), canonicalOutputRoot) ||
    path.basename(expectedDirectory) !== indexId
  ) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index is not the exact expected output child.');
  }
  const verified = await verifyAndLoadHistoricalEvidenceIndex(expectedDirectory);
  if (
    !samePath(verified.directory, expectedDirectory) ||
    !samePath(path.dirname(verified.directory), canonicalOutputRoot)
  ) {
    throw new AtlasError('HISTORICAL_INDEX_INVALID', 'Historical-evidence index resolved outside its exact expected output child.');
  }
  return verified;
}

export async function verifyHistoricalEvidenceIndex(directoryValue: string): Promise<VerifiedHistoricalEvidenceIndex['summary']> {
  return (await verifyAndLoadHistoricalEvidenceIndex(directoryValue)).summary;
}

function queryTerms(value: string): string[] {
  return [...new Set(value.toLowerCase().split(/[^a-z0-9_./:@-]+/u).filter(Boolean))].sort(compareCanonicalText);
}

function normalizeQuery(value: string): string {
  const query = value.normalize('NFC').trim();
  if (!query || query.length > MAX_QUERY_CHARACTERS || /[\u0000-\u001f\u007f-\u009f]/u.test(query)) {
    throw new AtlasError('INVALID_HISTORICAL_QUERY', `Historical-evidence query must contain 1-${MAX_QUERY_CHARACTERS} printable characters.`);
  }
  return query;
}

function normalizeLimit(value: number | undefined): number {
  const limit = value ?? 20;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_QUERY_HITS) {
    throw new AtlasError('INVALID_HISTORICAL_LIMIT', `Historical-evidence result limit must be between 1 and ${MAX_QUERY_HITS}.`);
  }
  return limit;
}

function scoreValue(terms: string[], value: string, weight: number): number {
  const normalized = value.toLowerCase();
  let score = 0;
  for (const term of terms) {
    if (normalized === term) score += weight * 5;
    else if (normalized.includes(term)) score += weight;
  }
  return score;
}

function uniqueCitations(values: HistoricalEvidenceCitation[]): HistoricalEvidenceCitation[] {
  const valuesByKey = new Map<string, HistoricalEvidenceCitation>();
  for (const value of values) {
    const key = `${value.path}\0${value.sha256}\0${value.line}\0${value.column}\0${value.basis}`;
    valuesByKey.set(key, value);
  }
  return [...valuesByKey.values()].sort((left, right) =>
    compareCanonicalText(left.path, right.path) ||
    left.line - right.line ||
    left.column - right.column ||
    compareCanonicalText(left.basis, right.basis)
  );
}

function scoreRecord(record: HistoricalEvidenceRecord, terms: string[]): HistoricalEvidenceQueryHit | undefined {
  const titleCitation: HistoricalEvidenceCitation = {
    path: record.artifact.path,
    sha256: record.artifact.sha256,
    line: record.titleLine,
    column: 1,
    basis: 'title'
  };
  const fields: ScoredField[] = [
    { field: 'title', text: record.title, weight: 30, citations: [titleCitation] },
    {
      field: 'artifact-path',
      text: record.artifact.path,
      weight: 24,
      citations: [{ ...titleCitation, basis: 'artifact-path' }]
    },
    ...record.scopeAnchors.map((anchor): ScoredField => ({
      field: 'scope-heading',
      text: anchor.heading,
      weight: 16,
      citations: [{
        path: record.artifact.path,
        sha256: record.artifact.sha256,
        line: anchor.line,
        column: anchor.column,
        basis: 'scope-heading'
      }]
    })),
    ...record.pathAnchors.map((anchor): ScoredField => ({
      field: 'path-anchor',
      text: anchor.path,
      weight: 22,
      citations: anchor.mentions.map((mention) => ({
        path: record.artifact.path,
        sha256: record.artifact.sha256,
        line: mention.line,
        column: mention.column,
        basis: 'path-anchor'
      }))
    }))
  ];
  if (record.trace) {
    fields.push(
      { field: 'trace-id', text: record.trace.id, weight: 35, citations: [record.trace.citation] },
      { field: 'trace-label', text: record.trace.label, weight: 30, citations: [record.trace.citation] },
      { field: 'trace-cluster', text: record.trace.clusterId, weight: 20, citations: [record.trace.citation] },
      { field: 'trace-lifecycle', text: record.trace.lifecycle, weight: 14, citations: [record.trace.citation] },
      { field: 'trace-summary', text: record.trace.historicalUnvalidatedSummary, weight: 10, citations: [record.trace.citation] }
    );
  }
  const bestByField = new Map<HistoricalEvidenceQueryHit['matchedFields'][number], {
    score: number;
    citation: HistoricalEvidenceCitation;
  }>();
  for (const field of fields) {
    const fieldScore = scoreValue(terms, field.text, field.weight);
    if (!fieldScore) continue;
    const previous = bestByField.get(field.field);
    if (!previous || fieldScore > previous.score) {
      bestByField.set(field.field, { score: fieldScore, citation: field.citations[0]! });
    }
  }
  const score = [...bestByField.values()].reduce((total, match) => total + match.score, 0);
  if (!score) return undefined;
  return {
    kind: record.kind,
    id: record.id,
    score,
    title: record.title,
    artifact: record.artifact,
    matchedFields: [...bestByField.keys()].sort(compareCanonicalText),
    citations: uniqueCitations([...bestByField.values()].map((match) => match.citation)),
    reviewerIdentity: record.reviewerIdentity,
    anchorFreshness: record.anchorFreshness,
    interpretation: record.interpretation,
    ...(record.trace ? { trace: record.trace } : {})
  };
}

/** @internal Queries only the caller's already verified historical index. */
export async function queryLoadedHistoricalEvidence(
  verified: VerifiedHistoricalEvidenceIndex,
  queryValue: string,
  options: { limit?: number; kinds?: Array<'review' | 'trace'> } = {}
): Promise<HistoricalEvidenceQueryResult> {
  const query = normalizeQuery(queryValue);
  const limit = normalizeLimit(options.limit);
  const terms = queryTerms(query);
  const kinds = options.kinds ?? ['review', 'trace'];
  if (!kinds.length || kinds.some((kind) => kind !== 'review' && kind !== 'trace') || new Set(kinds).size !== kinds.length) {
    throw new AtlasError('INVALID_HISTORICAL_KIND', 'Historical-evidence kinds must be a non-empty unique subset of review and trace.');
  }
  const hits = verified.records
    .filter((record) => kinds.includes(record.kind))
    .map((record) => scoreRecord(record, terms))
    .filter((hit): hit is HistoricalEvidenceQueryHit => Boolean(hit))
    .sort((left, right) => right.score - left.score || compareCanonicalText(left.id, right.id));
  const selected = hits.slice(0, limit);
  const result: HistoricalEvidenceQueryResult = {
    schemaVersion: 1,
    indexId: verified.index.indexId,
    query,
    answer: {
      kind: selected.length ? 'matches' : 'abstention',
      text: selected.length
        ? `Found ${selected.length} cited historical navigation record${selected.length === 1 ? '' : 's'}. These records are unvalidated context, not current findings; anchor freshness may be unavailable.`
        : 'No historical navigation metadata matched this query. This is an abstention, not evidence that the concept is absent.'
    },
    provenance: verified.index.source,
    interpretation: INTERPRETATION,
    hits: selected,
    truncated: hits.length > selected.length
  };
  await assertSchema('historical-evidence-query', result, 'Historical-evidence query response');
  assertPortableDataSafe(result, 'Historical-evidence query response');
  return result;
}

export async function queryHistoricalEvidence(
  indexDirectory: string,
  queryValue: string,
  options: { limit?: number; kinds?: Array<'review' | 'trace'> } = {}
): Promise<HistoricalEvidenceQueryResult> {
  return queryLoadedHistoricalEvidence(
    await verifyAndLoadHistoricalEvidenceIndex(indexDirectory),
    queryValue,
    options
  );
}
