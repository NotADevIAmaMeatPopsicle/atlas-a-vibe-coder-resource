import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, open, readFile, readlink, realpath } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { TextDecoder } from 'node:util';
import { writeImmutableCanonicalReport, type ImmutableReportWriteResult } from './acceptance/report-output.js';
import { discoverGitRepository } from './discovery/index.js';
import { AtlasError } from './errors.js';
import { findingReviewIdentity, findingSourcePaths } from './finding-identity.js';
import { HARD_MAX_FILE_BYTES, HARD_MAX_INCLUDED_FILES, HARD_MAX_TOTAL_BYTES } from './limits.js';
import { assertSchema } from './schema-validator.js';
import { resolveTrustedGitExecutable } from './security/git-executable.js';
import { assertPortableDataSafe } from './security/portable-data.js';
import { assertTargetDescriptorSeparated } from './targets.js';
import type { FindingDispositionDiagnosticProjection, FindingRecord, TargetConfig } from './types.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';
import { normalizeTargetRelative } from './util/paths.js';
import { verifyAndLoadRunDirectory } from './verify.js';

export const CHANGED_FINDINGS_VERSION = '1.1.0';

const MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024;
const GIT_TIMEOUT_MS = 30_000;
const MAX_CHANGED_FINGERPRINT_BYTES = HARD_MAX_TOTAL_BYTES * 4;
const MAX_CHANGED_FINGERPRINT_OPERATIONS = HARD_MAX_INCLUDED_FILES * 4;
const MAX_CHANGED_FINGERPRINT_MS = 120_000;
const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });
const SAFE_GIT_CONFIG: readonly string[] = [
  'core.fsmonitor=false',
  'core.untrackedCache=false',
  `core.hooksPath=${NULL_DEVICE}`,
  `core.excludesFile=${NULL_DEVICE}`,
  'maintenance.auto=false',
  'gc.auto=0',
  'protocol.allow=never',
  'protocol.file.allow=never',
  'submodule.recurse=false',
  'fetch.recurseSubmodules=false',
  'diff.ignoreSubmodules=all',
  'credential.helper=',
  'core.askPass=',
  'core.pager=',
  'pager.status=false',
  'color.ui=false',
  'core.quotePath=false'
];

export interface ChangedFindingMatch {
  reviewIdentity: string;
  matchedPaths: string[];
  finding: FindingRecord;
}

export interface ChangedDispositionMatch extends FindingDispositionDiagnosticProjection {
  matchedPaths: string[];
}

export interface ChangedFindingsReport {
  schemaVersion: 1;
  reportId: string;
  kind: 'atlas-changed-findings-report';
  producer: { id: 'atlas/changed-findings'; version: string };
  target: { id: string };
  run: {
    runId: string;
    snapshotId: string;
    artifactManifestDigest: string;
  };
  comparison: {
    requestedRef: string;
    resolvedCommit: string;
    headCommit: string;
  };
  changedPaths: string[];
  counts: {
    changedPaths: number;
    runFindings: number;
    matchingFindings: number;
    matchingFindingInstances: number;
    matchingDispositions: number;
  };
  matchingFindings: ChangedFindingMatch[];
  matchingDispositions: ChangedDispositionMatch[];
}

export interface ChangedFindingsOptions {
  runDirectory: string;
  targetConfigPath: string;
  since: string;
}

export interface WriteChangedFindingsOptions extends ChangedFindingsOptions {
  outputPath: string;
}

interface ResolvedTargetDescriptor {
  configPath: string;
  configDigest: string;
  target: TargetConfig;
  targetRoot: string;
}

interface GitCommandResult {
  exitCode: number;
  stdout: Buffer;
}

interface PathFingerprint {
  kind: 'file' | 'directory' | 'symlink' | 'other' | 'missing';
  digest?: string;
  bytes?: number;
}

interface FingerprintBudget {
  bytes: number;
  operations: number;
  deadline: number;
}

function gitEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith('GIT_') && value !== undefined) environment[key] = value;
  }
  return {
    ...environment,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_SYSTEM: NULL_DEVICE,
    GIT_CONFIG_GLOBAL: NULL_DEVICE,
    GIT_ATTR_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: '',
    GIT_PAGER: '',
    LC_ALL: 'C',
    LANG: 'C',
    TZ: 'UTC'
  };
}

async function runGit(repositoryPath: string, command: readonly string[]): Promise<GitCommandResult> {
  const gitExecutable = await resolveTrustedGitExecutable([repositoryPath]);
  if (!gitExecutable) {
    throw new AtlasError('CHANGED_SCOPE_GIT_UNAVAILABLE', 'Git is unavailable, so changed-path scope cannot be computed.');
  }
  const argumentsList = [
    '--no-optional-locks',
    '--no-replace-objects',
    ...SAFE_GIT_CONFIG.flatMap((entry) => ['-c', entry]),
    '-C',
    repositoryPath,
    ...command
  ];
  return new Promise((resolve, reject) => {
    execFile(gitExecutable, argumentsList, {
      cwd: repositoryPath,
      env: gitEnvironment(),
      encoding: 'buffer',
      maxBuffer: MAX_GIT_OUTPUT_BYTES,
      timeout: GIT_TIMEOUT_MS,
      windowsHide: true,
      shell: false
    }, (error, stdout) => {
      const output = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? '');
      if (!error) {
        resolve({ exitCode: 0, stdout: output });
        return;
      }
      const processError = error as NodeJS.ErrnoException & { code?: string | number; killed?: boolean };
      if (typeof processError.code === 'number') {
        resolve({ exitCode: processError.code, stdout: output });
        return;
      }
      reject(new AtlasError(
        'CHANGED_SCOPE_GIT_UNAVAILABLE',
        processError.code === 'ENOENT'
          ? 'Git is unavailable, so changed-path scope cannot be computed.'
          : processError.killed || processError.code === 'ETIMEDOUT'
            ? 'A bounded Git changed-path query exceeded its execution limit.'
            : processError.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
              ? 'A Git changed-path query exceeded its output limit.'
              : 'Git changed-path state could not be read safely.'
      ));
    });
  });
}

function decodeText(value: Buffer): string {
  return STRICT_UTF8.decode(value).normalize('NFC');
}

function decodeLine(value: Buffer): string {
  return decodeText(value).replace(/[\r\n]+$/u, '');
}

function nulFields(value: Buffer): string[] {
  if (value.length === 0) return [];
  if (value[value.length - 1] !== 0) {
    throw new AtlasError('CHANGED_SCOPE_GIT_OUTPUT', 'Git emitted a non-terminated changed-path stream.');
  }
  const fields: string[] = [];
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== 0) continue;
    fields.push(decodeText(value.subarray(start, index)));
    start = index + 1;
  }
  return fields;
}

async function resolveTargetDescriptor(targetConfigPathValue: string): Promise<ResolvedTargetDescriptor> {
  const requestedPath = path.resolve(targetConfigPathValue);
  const requestedMetadata = await lstat(requestedPath);
  if (!requestedMetadata.isFile() || requestedMetadata.isSymbolicLink()) {
    throw new AtlasError('INVALID_CONFIG', 'Target descriptor must be a regular file, not a link.');
  }
  if (requestedMetadata.nlink !== 1) {
    throw new AtlasError('TARGET_DESCRIPTOR_MULTIPLE_LINKS', 'Target descriptor must have exactly one filesystem link.');
  }
  const configPath = await realpath(requestedPath);
  const content = await readFile(configPath);
  const rawTarget = JSON.parse(content.toString('utf8')) as unknown;
  await assertSchema('target', rawTarget, 'Target configuration');
  const target = rawTarget as TargetConfig;
  const configuredTargetPath = path.isAbsolute(target.path)
    ? target.path
    : path.resolve(path.dirname(configPath), target.path);
  const targetRoot = await realpath(configuredTargetPath);
  if (!(await lstat(targetRoot)).isDirectory()) {
    throw new AtlasError('INVALID_CONFIG', 'Target path must resolve to a directory.');
  }
  assertTargetDescriptorSeparated(requestedPath, targetRoot);
  assertTargetDescriptorSeparated(configPath, targetRoot);
  return { configPath, configDigest: sha256(content), target, targetRoot };
}

function assertRequestedRef(value: string): string {
  const normalized = value.normalize('NFC');
  if (!normalized || normalized.length > 1024 || normalized.startsWith('-') || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new AtlasError('CHANGED_SCOPE_REF_INVALID', '--since must be a non-empty Git revision without control characters or a leading dash.');
  }
  return normalized;
}

async function resolveCommit(targetRoot: string, requestedRef: string): Promise<string> {
  const result = await runGit(targetRoot, ['rev-parse', '--verify', '--quiet', `${requestedRef}^{commit}`]);
  const resolved = result.exitCode === 0 ? decodeLine(result.stdout) : '';
  if (!/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(resolved)) {
    throw new AtlasError('CHANGED_SCOPE_REF_UNRESOLVED', 'The requested --since revision does not resolve to a local commit.');
  }
  return resolved;
}

function portableGitPath(rawPath: string, origins: Map<string, string>): string {
  if (rawPath.includes('\\')) {
    throw new AtlasError('CHANGED_SCOPE_GIT_PATH', 'Git emitted a path with a non-portable separator.');
  }
  let normalized: string;
  try {
    normalized = normalizeTargetRelative(rawPath);
  } catch {
    throw new AtlasError('CHANGED_SCOPE_GIT_PATH', 'Git emitted a path that cannot be represented portably.');
  }
  const prior = origins.get(normalized);
  if (prior !== undefined && prior !== rawPath) {
    throw new AtlasError('CHANGED_SCOPE_GIT_PATH', 'Distinct Git paths collide after portable normalization.');
  }
  origins.set(normalized, rawPath);
  return normalized;
}

function parseNameStatus(output: Buffer, origins: Map<string, string>): string[] {
  const fields = nulFields(output);
  const paths: string[] = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++]!;
    if (!/^(?:[AMDTUXB]|[RC][0-9]{1,3})$/u.test(status)) {
      throw new AtlasError('CHANGED_SCOPE_GIT_OUTPUT', 'Git emitted an unsupported changed-path status.');
    }
    if (status.startsWith('R') || status.startsWith('C')) {
      const originalPath = fields[index++];
      const currentPath = fields[index++];
      if (originalPath === undefined || currentPath === undefined) {
        throw new AtlasError('CHANGED_SCOPE_GIT_OUTPUT', 'Git emitted an incomplete rename/copy record.');
      }
      portableGitPath(originalPath, origins);
      paths.push(portableGitPath(currentPath, origins));
      continue;
    }
    const currentPath = fields[index++];
    if (currentPath === undefined) {
      throw new AtlasError('CHANGED_SCOPE_GIT_OUTPUT', 'Git emitted an incomplete changed-path record.');
    }
    const normalized = portableGitPath(currentPath, origins);
    if (status !== 'D') paths.push(normalized);
  }
  return paths;
}

async function changedPathCandidates(
  targetRoot: string,
  resolvedCommit: string,
  headCommit: string
): Promise<string[]> {
  const diffOptions = ['--name-status', '-z', '--find-renames=50%', '--no-ext-diff', '--no-textconv', '--ignore-submodules=all'];
  const [committed, staged, unstaged, untracked] = await Promise.all([
    runGit(targetRoot, ['diff', ...diffOptions, resolvedCommit, headCommit, '--']),
    runGit(targetRoot, ['diff', '--cached', ...diffOptions, headCommit, '--']),
    runGit(targetRoot, ['diff', ...diffOptions, '--']),
    runGit(targetRoot, ['ls-files', '--others', '--exclude-standard', '--full-name', '-z'])
  ]);
  if ([committed, staged, unstaged, untracked].some((entry) => entry.exitCode !== 0)) {
    throw new AtlasError('CHANGED_SCOPE_GIT_UNAVAILABLE', 'Git could not compute the complete changed-path scope.');
  }
  const origins = new Map<string, string>();
  const untrackedPaths = nulFields(untracked.stdout).map((entry) => portableGitPath(entry, origins));
  return [...new Set([
    ...parseNameStatus(committed.stdout, origins),
    ...parseNameStatus(staged.stdout, origins),
    ...parseNameStatus(unstaged.stdout, origins),
    ...untrackedPaths
  ])].sort(compareCanonicalText);
}

function changedScopeResourceLimit(message: string): AtlasError {
  return new AtlasError('CHANGED_SCOPE_RESOURCE_LIMIT', message);
}

function assertFingerprintTime(budget: FingerprintBudget): void {
  if (performance.now() >= budget.deadline) {
    throw changedScopeResourceLimit(`Changed-path hashing exceeded the ${MAX_CHANGED_FINGERPRINT_MS}-millisecond limit.`);
  }
}

async function fileDigest(
  handle: Awaited<ReturnType<typeof open>>,
  expectedBytes: number,
  budget: FingerprintBudget
): Promise<string> {
  const digest = createHash('sha256');
  const controller = new AbortController();
  const remaining = budget.deadline - performance.now();
  if (remaining <= 0) assertFingerprintTime(budget);
  const timer = setTimeout(() => controller.abort(), Math.max(1, remaining));
  let observedBytes = 0;
  try {
    for await (const chunk of handle.createReadStream({ autoClose: false, signal: controller.signal })) {
      observedBytes += (chunk as Buffer).length;
      if (observedBytes > expectedBytes || observedBytes > HARD_MAX_FILE_BYTES) {
        throw changedScopeResourceLimit(`A changed file exceeded the ${HARD_MAX_FILE_BYTES}-byte limit while it was being hashed.`);
      }
      digest.update(chunk as Buffer);
    }
  } catch (error) {
    if (controller.signal.aborted) assertFingerprintTime(budget);
    throw error;
  } finally {
    clearTimeout(timer);
  }
  if (observedBytes !== expectedBytes) {
    throw new AtlasError('CHANGED_SCOPE_TARGET_CHANGED', 'The target changed while changed-path scope was being computed.');
  }
  return digest.digest('hex');
}

async function fingerprintPath(
  targetRoot: string,
  relativePath: string,
  budget: FingerprintBudget
): Promise<PathFingerprint> {
  assertFingerprintTime(budget);
  if (budget.operations >= MAX_CHANGED_FINGERPRINT_OPERATIONS) {
    throw changedScopeResourceLimit(`Changed-path hashing exceeds the ${MAX_CHANGED_FINGERPRINT_OPERATIONS}-operation limit.`);
  }
  budget.operations += 1;
  const absolutePath = path.join(targetRoot, ...relativePath.split('/'));
  let before: Awaited<ReturnType<typeof lstat>>;
  try {
    before = await lstat(absolutePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'missing' };
    throw error;
  }
  if (before.isSymbolicLink()) {
    const link = await readlink(absolutePath);
    const after = await lstat(absolutePath);
    if (before.mtimeMs !== after.mtimeMs || before.size !== after.size) {
      throw new AtlasError('CHANGED_SCOPE_TARGET_CHANGED', 'The target changed while changed-path scope was being computed.');
    }
    return { kind: 'symlink', bytes: before.size, digest: sha256(link) };
  }
  if (before.isFile()) {
    if (before.size > HARD_MAX_FILE_BYTES) {
      throw changedScopeResourceLimit(`A changed file exceeds the ${HARD_MAX_FILE_BYTES}-byte limit.`);
    }
    if (before.size > MAX_CHANGED_FINGERPRINT_BYTES - budget.bytes) {
      throw changedScopeResourceLimit(`Changed-path hashing exceeds the ${MAX_CHANGED_FINGERPRINT_BYTES}-byte aggregate limit.`);
    }
    const handle = await open(absolutePath, 'r');
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
        throw new AtlasError('CHANGED_SCOPE_TARGET_CHANGED', 'The target changed before changed-path content could be read.');
      }
      budget.bytes += opened.size;
      const digest = await fileDigest(handle, opened.size, budget);
      const [after, pathAfter] = await Promise.all([handle.stat(), lstat(absolutePath)]);
      if (
        !after.isFile() || !pathAfter.isFile() ||
        opened.dev !== after.dev || opened.ino !== after.ino ||
        opened.dev !== pathAfter.dev || opened.ino !== pathAfter.ino ||
        opened.mtimeMs !== after.mtimeMs || opened.size !== after.size ||
        opened.mtimeMs !== pathAfter.mtimeMs || opened.size !== pathAfter.size
      ) {
        throw new AtlasError('CHANGED_SCOPE_TARGET_CHANGED', 'The target changed while changed-path scope was being computed.');
      }
      return { kind: 'file', bytes: opened.size, digest };
    } finally {
      await handle.close();
    }
  }
  if (before.isDirectory()) {
    return { kind: 'directory', bytes: before.size, digest: sha256(`${before.mtimeMs}`) };
  }
  return { kind: 'other', bytes: before.size, digest: sha256(`${before.mode}:${before.mtimeMs}`) };
}

async function fingerprintPaths(
  targetRoot: string,
  paths: readonly string[],
  budget: FingerprintBudget
): Promise<Map<string, PathFingerprint>> {
  if (paths.length > HARD_MAX_INCLUDED_FILES) {
    throw changedScopeResourceLimit(`Changed-path hashing exceeds the ${HARD_MAX_INCLUDED_FILES}-path limit.`);
  }
  const result = new Map<string, PathFingerprint>();
  for (const relativePath of paths) result.set(relativePath, await fingerprintPath(targetRoot, relativePath, budget));
  return result;
}

function mapMaterial(values: ReadonlyMap<string, PathFingerprint>): unknown {
  return [...values.entries()].map(([pathValue, fingerprint]) => ({ path: pathValue, ...fingerprint }));
}

function assertRunSnapshotMatches(
  verified: Awaited<ReturnType<typeof verifyAndLoadRunDirectory>>,
  fingerprints: ReadonlyMap<string, PathFingerprint>
): void {
  for (const expected of verified.artifacts.snapshot.files) {
    const observed = fingerprints.get(expected.path);
    if (
      observed?.kind !== 'file' ||
      observed.bytes !== expected.bytes ||
      observed.digest !== expected.sha256
    ) {
      throw new AtlasError(
        'CHANGED_SCOPE_RUN_STALE',
        'The selected target no longer matches the verified run snapshot; create a fresh run before filtering changed findings.'
      );
    }
  }
}

function assertReadyDiscovery(discovery: Awaited<ReturnType<typeof discoverGitRepository>>): string {
  const headCommit = discovery.repository?.head.objectId;
  if (discovery.state !== 'ready' || !headCommit) {
    throw new AtlasError(
      'CHANGED_SCOPE_GIT_UNAVAILABLE',
      'Changed-path scope requires a supported Git worktree with a resolvable HEAD and complete status discovery.'
    );
  }
  return headCommit;
}

function matchingFindings(findings: readonly FindingRecord[], changedPaths: readonly string[]): ChangedFindingMatch[] {
  const changed = new Set(changedPaths);
  return findings.flatMap((finding) => {
    const matchedPaths = findingSourcePaths(finding).filter((sourcePath) => changed.has(sourcePath));
    return matchedPaths.length ? [{
      reviewIdentity: findingReviewIdentity(finding),
      matchedPaths,
      finding
    }] : [];
  }).sort((left, right) =>
    compareCanonicalText(left.reviewIdentity, right.reviewIdentity) ||
    compareCanonicalText(left.finding.id, right.finding.id)
  );
}

function matchingDispositions(
  diagnostics: Awaited<ReturnType<typeof verifyAndLoadRunDirectory>>['artifacts']['diagnostics'],
  changedPaths: readonly string[]
): ChangedDispositionMatch[] {
  const changed = new Set(changedPaths);
  return diagnostics.flatMap((diagnostic) => {
    const disposition = diagnostic.disposition;
    if (diagnostic.code !== 'FINDING_DISPOSITION_APPLIED' || disposition?.state !== 'applied') return [];
    const matchedPaths = disposition.anchors.map((anchor) => anchor.path)
      .filter((anchorPath) => changed.has(anchorPath))
      .sort(compareCanonicalText);
    return matchedPaths.length ? [{ ...disposition, matchedPaths }] : [];
  }).sort((left, right) =>
    compareCanonicalText(left.reviewId, right.reviewId) || compareCanonicalText(left.findingId, right.findingId)
  );
}

export async function createChangedFindingsReport(options: ChangedFindingsOptions): Promise<ChangedFindingsReport> {
  const requestedRef = assertRequestedRef(options.since);
  const verified = await verifyAndLoadRunDirectory(options.runDirectory);
  const targetBefore = await resolveTargetDescriptor(options.targetConfigPath);
  if (targetBefore.target.id !== verified.artifacts.run.targetId) {
    throw new AtlasError(
      'CHANGED_SCOPE_TARGET_MISMATCH',
      `Target descriptor ID ${targetBefore.target.id} does not match run target ID ${verified.artifacts.run.targetId}.`
    );
  }

  const discoveryBefore = await discoverGitRepository(targetBefore.targetRoot);
  const headCommit = assertReadyDiscovery(discoveryBefore);
  if (canonicalJson(discoveryBefore) !== canonicalJson(verified.artifacts.discovery)) {
    throw new AtlasError(
      'CHANGED_SCOPE_RUN_STALE',
      'The selected target Git state does not match the verified run; create a fresh run before filtering changed findings.'
    );
  }
  const snapshotPaths = verified.artifacts.snapshot.files.map((file) => file.path);
  const fingerprintBudget: FingerprintBudget = {
    bytes: 0,
    operations: 0,
    deadline: performance.now() + MAX_CHANGED_FINGERPRINT_MS
  };
  const snapshotBefore = await fingerprintPaths(targetBefore.targetRoot, snapshotPaths, fingerprintBudget);
  assertRunSnapshotMatches(verified, snapshotBefore);
  const resolvedCommit = await resolveCommit(targetBefore.targetRoot, requestedRef);
  const candidatesBefore = await changedPathCandidates(targetBefore.targetRoot, resolvedCommit, headCommit);
  const fingerprintsBefore = await fingerprintPaths(targetBefore.targetRoot, candidatesBefore, fingerprintBudget);

  const candidatesAfter = await changedPathCandidates(targetBefore.targetRoot, resolvedCommit, headCommit);
  const fingerprintsAfter = await fingerprintPaths(targetBefore.targetRoot, candidatesAfter, fingerprintBudget);
  const resolvedCommitAfter = await resolveCommit(targetBefore.targetRoot, requestedRef);
  const discoveryAfter = await discoverGitRepository(targetBefore.targetRoot);
  const snapshotAfter = await fingerprintPaths(targetBefore.targetRoot, snapshotPaths, fingerprintBudget);
  const targetAfter = await resolveTargetDescriptor(options.targetConfigPath);
  if (
    canonicalJson(discoveryAfter) !== canonicalJson(discoveryBefore) ||
    canonicalJson(mapMaterial(snapshotAfter)) !== canonicalJson(mapMaterial(snapshotBefore)) ||
    canonicalJson(candidatesAfter) !== canonicalJson(candidatesBefore) ||
    canonicalJson(mapMaterial(fingerprintsAfter)) !== canonicalJson(mapMaterial(fingerprintsBefore)) ||
    resolvedCommitAfter !== resolvedCommit ||
    targetAfter.configPath !== targetBefore.configPath ||
    targetAfter.configDigest !== targetBefore.configDigest ||
    targetAfter.targetRoot !== targetBefore.targetRoot ||
    canonicalJson(targetAfter.target) !== canonicalJson(targetBefore.target)
  ) {
    throw new AtlasError('CHANGED_SCOPE_TARGET_CHANGED', 'The target changed while changed-path scope was being computed.');
  }
  assertRunSnapshotMatches(verified, snapshotAfter);

  const changedPaths = candidatesBefore.filter((candidate) => fingerprintsBefore.get(candidate)?.kind !== 'missing');
  const matches = matchingFindings(verified.artifacts.findings, changedPaths);
  const dispositions = matchingDispositions(verified.artifacts.diagnostics, changedPaths);
  const withoutIdentity = {
    schemaVersion: 1 as const,
    kind: 'atlas-changed-findings-report' as const,
    producer: { id: 'atlas/changed-findings' as const, version: CHANGED_FINDINGS_VERSION },
    target: { id: targetBefore.target.id },
    run: {
      runId: verified.artifacts.run.runId,
      snapshotId: verified.artifacts.run.snapshotId,
      artifactManifestDigest: verified.manifestSha256
    },
    comparison: { requestedRef, resolvedCommit, headCommit },
    changedPaths,
    counts: {
      changedPaths: changedPaths.length,
      runFindings: verified.artifacts.findings.length,
      matchingFindings: matches.length,
      matchingFindingInstances: matches.reduce((total, entry) => total + (entry.finding.instanceCount ?? 1), 0),
      matchingDispositions: dispositions.length
    },
    matchingFindings: matches,
    matchingDispositions: dispositions
  };
  const report: ChangedFindingsReport = {
    ...withoutIdentity,
    reportId: `changed_findings_sha256_${sha256(canonicalJson({ domain: 'atlas.changed-findings.v1', ...withoutIdentity }))}`
  };
  await assertSchema('changed-findings', report, 'Changed findings report');
  assertPortableDataSafe(report, 'Atlas changed findings report');
  return report;
}

export async function writeChangedFindingsReport(
  options: WriteChangedFindingsOptions,
  report?: ChangedFindingsReport
): Promise<ImmutableReportWriteResult> {
  const resolvedReport = report ?? await createChangedFindingsReport(options);
  await assertSchema('changed-findings', resolvedReport, 'Changed findings report');
  assertPortableDataSafe(resolvedReport, 'Atlas changed findings report');
  const target = await resolveTargetDescriptor(options.targetConfigPath);
  return writeImmutableCanonicalReport(
    options.outputPath,
    resolvedReport,
    [options.runDirectory, target.targetRoot]
  );
}
