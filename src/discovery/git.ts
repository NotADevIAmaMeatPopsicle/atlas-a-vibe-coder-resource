import { execFile } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { resolveTrustedGitExecutable } from '../security/git-executable.js';
import { compareCanonicalText } from '../util/canonical.js';
import { normalizeTargetRelative } from '../util/paths.js';
import type {
  GitDeltaState,
  GitDiscoveryDiagnostic,
  GitDiscoveryOptions,
  GitDiscoveryResult,
  GitDiscoverySeverity,
  GitIndexEntry,
  GitPathKind,
  GitPathRecord,
  GitRepositoryRecord,
  GitTrackingState
} from './types.js';

const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
export const GIT_DISCOVERY_VERSION = '1.0.0';
const DEFAULT_MAX_RECORDS = 200_000;
const DEFAULT_TIMEOUT_MS = 30_000;
const MIN_OUTPUT_BYTES = 1024;
const MAX_OUTPUT_BYTES = 512 * 1024 * 1024;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 300_000;
const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

const SAFE_CONFIG: readonly string[] = [
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
  'core.quotePath=false',
  'status.submoduleSummary=false'
];

interface GitCommandResult {
  exitCode: number;
  stdout: Buffer;
}

class GitProcessError extends Error {
  readonly reason: 'missing' | 'timeout' | 'output-limit' | 'failed';

  constructor(reason: GitProcessError['reason']) {
    super(reason);
    this.name = 'GitProcessError';
    this.reason = reason;
  }
}

interface MutablePathRecord {
  path: string;
  kind: GitPathKind;
  tracking: GitTrackingState;
  indexStatus: GitDeltaState;
  worktreeStatus: GitDeltaState;
  conflicted: boolean;
  indexEntries: GitIndexEntry[];
  originalPath?: string;
  similarity?: number;
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}.`);
  }
  return resolved;
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
    GIT_EDITOR: '',
    GIT_SEQUENCE_EDITOR: '',
    LC_ALL: 'C',
    LANG: 'C',
    TZ: 'UTC'
  };
}

async function runGit(
  repositoryPath: string,
  command: readonly string[],
  limits: { maxOutputBytes: number; timeoutMs: number }
): Promise<GitCommandResult> {
  const gitExecutable = await resolveTrustedGitExecutable([repositoryPath]);
  if (!gitExecutable) throw new GitProcessError('missing');
  const configArguments = SAFE_CONFIG.flatMap((entry) => ['-c', entry]);
  const argumentsList = [
    '--no-optional-locks',
    '--no-replace-objects',
    '--literal-pathspecs',
    ...configArguments,
    '-C',
    repositoryPath,
    ...command
  ];
  return new Promise((resolve, reject) => {
    execFile(gitExecutable, argumentsList, {
      cwd: repositoryPath,
      env: gitEnvironment(),
      encoding: 'buffer',
      maxBuffer: limits.maxOutputBytes,
      timeout: limits.timeoutMs,
      windowsHide: true,
      shell: false
    }, (error, stdout) => {
      const output = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? '');
      if (!error) {
        resolve({ exitCode: 0, stdout: output });
        return;
      }
      const processError = error as NodeJS.ErrnoException & { code?: string | number; killed?: boolean };
      if (processError.code === 'ENOENT') {
        reject(new GitProcessError('missing'));
        return;
      }
      if (processError.killed || processError.code === 'ETIMEDOUT') {
        reject(new GitProcessError('timeout'));
        return;
      }
      if (processError.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
        reject(new GitProcessError('output-limit'));
        return;
      }
      if (typeof processError.code === 'number') {
        resolve({ exitCode: processError.code, stdout: output });
        return;
      }
      reject(new GitProcessError('failed'));
    });
  });
}

function diagnostic(
  code: string,
  severity: GitDiscoverySeverity,
  message: string,
  pathValue?: string
): GitDiscoveryDiagnostic {
  return pathValue === undefined ? { code, severity, message } : { code, severity, message, path: pathValue };
}

function emptyResult(
  state: GitDiscoveryResult['state'],
  diagnostics: GitDiscoveryDiagnostic[]
): GitDiscoveryResult {
  return {
    schemaVersion: 1,
    provider: 'git',
    state,
    records: [],
    diagnostics: sortDiagnostics(diagnostics)
  };
}

function sortDiagnostics(values: GitDiscoveryDiagnostic[]): GitDiscoveryDiagnostic[] {
  return [...values].sort((left, right) =>
    compareCanonicalText(left.code, right.code) ||
    compareCanonicalText(left.path ?? '', right.path ?? '') ||
    compareCanonicalText(left.message, right.message)
  );
}

function decodeText(value: Buffer): string {
  return STRICT_UTF8.decode(value).normalize('NFC');
}

function decodeLine(value: Buffer): string {
  return decodeText(value).replace(/[\r\n]+$/, '');
}

function nulFields(value: Buffer): string[] {
  if (value.length === 0) return [];
  if (value[value.length - 1] !== 0) throw new TypeError('Git emitted a non-terminated record stream.');
  const fields: string[] = [];
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== 0) continue;
    fields.push(decodeText(value.subarray(start, index)));
    start = index + 1;
  }
  return fields;
}

function sameFilesystemLocation(left: string, right: string): boolean {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

async function existsAsDirectory(value: string): Promise<boolean> {
  try {
    return (await lstat(value)).isDirectory();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function mapDelta(value: string): GitDeltaState {
  switch (value) {
    case '.': return 'clean';
    case 'A': return 'added';
    case 'M': return 'modified';
    case 'D': return 'deleted';
    case 'R': return 'renamed';
    case 'C': return 'copied';
    case 'T': return 'type-changed';
    case 'U': return 'unmerged';
    default: return 'unknown';
  }
}

function splitStatusRecord(value: string, fieldCount: number): { fields: string[]; path: string } | undefined {
  const fields: string[] = [];
  let cursor = 0;
  for (let field = 0; field < fieldCount; field += 1) {
    const boundary = value.indexOf(' ', cursor);
    if (boundary === -1) return undefined;
    fields.push(value.slice(cursor, boundary));
    cursor = boundary + 1;
  }
  if (cursor >= value.length) return undefined;
  return { fields, path: value.slice(cursor) };
}

function portablePath(
  rawValue: string,
  origins: Map<string, string>,
  collisions: Set<string>,
  diagnostics: GitDiscoveryDiagnostic[]
): string | undefined {
  let normalized: string;
  try {
    if (rawValue.includes('\\')) throw new TypeError('Backslashes are not portable Git path separators.');
    normalized = normalizeTargetRelative(rawValue);
  } catch {
    diagnostics.push(diagnostic(
      'GIT_PATH_NOT_PORTABLE',
      'error',
      'A repository path cannot be represented as a canonical portable relative path.'
    ));
    return undefined;
  }
  const existing = origins.get(normalized);
  if (existing !== undefined && existing !== rawValue) {
    collisions.add(normalized);
    diagnostics.push(diagnostic(
      'GIT_PATH_NORMALIZATION_COLLISION',
      'error',
      'Distinct repository paths collide after portable Unicode normalization.',
      normalized
    ));
    return undefined;
  }
  origins.set(normalized, rawValue);
  return normalized;
}

function ensureMutableRecord(
  records: Map<string, MutablePathRecord>,
  pathValue: string,
  tracking: GitTrackingState,
  defaultStatus: GitDeltaState
): MutablePathRecord {
  const existing = records.get(pathValue);
  if (existing) {
    if (existing.tracking !== 'tracked' && tracking === 'tracked') existing.tracking = tracking;
    return existing;
  }
  const created: MutablePathRecord = {
    path: pathValue,
    kind: 'file',
    tracking,
    indexStatus: defaultStatus,
    worktreeStatus: defaultStatus,
    conflicted: false,
    indexEntries: []
  };
  records.set(pathValue, created);
  return created;
}

function parseIndexEntries(
  output: Buffer,
  records: Map<string, MutablePathRecord>,
  origins: Map<string, string>,
  collisions: Set<string>,
  diagnostics: GitDiscoveryDiagnostic[],
  defaultStatus: GitDeltaState
): void {
  for (const value of nulFields(output)) {
    const tab = value.indexOf('\t');
    if (tab === -1) {
      diagnostics.push(diagnostic('GIT_INDEX_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported index record.'));
      continue;
    }
    const metadata = value.slice(0, tab).split(' ');
    if (metadata.length !== 3) {
      diagnostics.push(diagnostic('GIT_INDEX_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported index record.'));
      continue;
    }
    const [mode, objectId, stageText] = metadata as [string, string, string];
    const stageNumber = Number(stageText);
    if (!/^[0-7]{6}$/.test(mode) || !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(objectId) ||
        !Number.isInteger(stageNumber) || stageNumber < 0 || stageNumber > 3) {
      diagnostics.push(diagnostic('GIT_INDEX_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported index record.'));
      continue;
    }
    const pathValue = portablePath(value.slice(tab + 1), origins, collisions, diagnostics);
    if (!pathValue) continue;
    const record = ensureMutableRecord(records, pathValue, 'tracked', defaultStatus);
    const entry: GitIndexEntry = {
      mode,
      objectId,
      stage: stageNumber as 0 | 1 | 2 | 3
    };
    record.indexEntries.push(entry);
    if (mode === '160000') record.kind = 'gitlink';
    if (stageNumber !== 0) {
      record.conflicted = true;
      record.indexStatus = 'unmerged';
      record.worktreeStatus = 'unmerged';
    }
  }
}

function parsePathList(
  output: Buffer,
  tracking: 'untracked' | 'ignored',
  records: Map<string, MutablePathRecord>,
  origins: Map<string, string>,
  collisions: Set<string>,
  diagnostics: GitDiscoveryDiagnostic[]
): void {
  for (const rawValue of nulFields(output)) {
    const isDirectory = rawValue.endsWith('/');
    const pathValue = portablePath(isDirectory ? rawValue.slice(0, -1) : rawValue, origins, collisions, diagnostics);
    if (!pathValue) continue;
    if (records.has(pathValue)) continue;
    records.set(pathValue, {
      path: pathValue,
      kind: isDirectory ? 'directory' : 'file',
      tracking,
      indexStatus: tracking,
      worktreeStatus: tracking,
      conflicted: false,
      indexEntries: []
    });
  }
}

function parseStatus(
  output: Buffer,
  records: Map<string, MutablePathRecord>,
  origins: Map<string, string>,
  collisions: Set<string>,
  diagnostics: GitDiscoveryDiagnostic[]
): void {
  const entries = nulFields(output);
  for (let index = 0; index < entries.length; index += 1) {
    const value = entries[index]!;
    if (value.startsWith('1 ')) {
      const parsed = splitStatusRecord(value, 8);
      if (!parsed || parsed.fields[0] !== '1') {
        diagnostics.push(diagnostic('GIT_STATUS_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported status record.'));
        continue;
      }
      const pathValue = portablePath(parsed.path, origins, collisions, diagnostics);
      const xy = parsed.fields[1];
      if (!pathValue || !xy || xy.length !== 2) continue;
      const record = ensureMutableRecord(records, pathValue, 'tracked', 'clean');
      record.indexStatus = mapDelta(xy[0]!);
      record.worktreeStatus = mapDelta(xy[1]!);
      if (parsed.fields[2]?.startsWith('S')) record.kind = 'gitlink';
      continue;
    }
    if (value.startsWith('2 ')) {
      const parsed = splitStatusRecord(value, 9);
      const rawOriginalPath = entries[index + 1];
      if (!parsed || parsed.fields[0] !== '2' || rawOriginalPath === undefined) {
        diagnostics.push(diagnostic('GIT_STATUS_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported rename status record.'));
        continue;
      }
      index += 1;
      const pathValue = portablePath(parsed.path, origins, collisions, diagnostics);
      const originalPath = portablePath(rawOriginalPath, origins, collisions, diagnostics);
      const xy = parsed.fields[1];
      if (!pathValue || !originalPath || !xy || xy.length !== 2) continue;
      const record = ensureMutableRecord(records, pathValue, 'tracked', 'clean');
      record.indexStatus = mapDelta(xy[0]!);
      record.worktreeStatus = mapDelta(xy[1]!);
      record.originalPath = originalPath;
      if (parsed.fields[2]?.startsWith('S')) record.kind = 'gitlink';
      const score = parsed.fields[8];
      if (score && /^[RC][0-9]{1,3}$/.test(score)) {
        const similarity = Number(score.slice(1));
        if (similarity >= 0 && similarity <= 100) record.similarity = similarity;
      }
      continue;
    }
    if (value.startsWith('u ')) {
      const parsed = splitStatusRecord(value, 10);
      if (!parsed || parsed.fields[0] !== 'u') {
        diagnostics.push(diagnostic('GIT_STATUS_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported conflict status record.'));
        continue;
      }
      const pathValue = portablePath(parsed.path, origins, collisions, diagnostics);
      if (!pathValue) continue;
      const record = ensureMutableRecord(records, pathValue, 'tracked', 'unmerged');
      record.indexStatus = 'unmerged';
      record.worktreeStatus = 'unmerged';
      record.conflicted = true;
      if (parsed.fields[2]?.startsWith('S')) record.kind = 'gitlink';
      continue;
    }
    diagnostics.push(diagnostic('GIT_STATUS_RECORD_UNSUPPORTED', 'error', 'Git emitted an unsupported status record.'));
  }
}

function finalizeRecords(
  records: Map<string, MutablePathRecord>,
  collisions: Set<string>,
  maxRecords: number,
  diagnostics: GitDiscoveryDiagnostic[]
): GitPathRecord[] {
  const values = [...records.values()]
    .filter((record) => !collisions.has(record.path))
    .map((record): GitPathRecord => {
      const indexEntries = [...record.indexEntries].sort((left, right) =>
        left.stage - right.stage ||
        compareCanonicalText(left.mode, right.mode) ||
        compareCanonicalText(left.objectId, right.objectId)
      );
      return {
        path: record.path,
        kind: record.kind,
        tracking: record.tracking,
        indexStatus: record.indexStatus,
        worktreeStatus: record.worktreeStatus,
        conflicted: record.conflicted,
        indexEntries,
        ...(record.originalPath === undefined ? {} : { originalPath: record.originalPath }),
        ...(record.similarity === undefined ? {} : { similarity: record.similarity })
      };
    })
    .sort((left, right) => compareCanonicalText(left.path, right.path));
  if (values.length > maxRecords) {
    diagnostics.push(diagnostic(
      'GIT_RECORD_LIMIT_EXCEEDED',
      'error',
      'Repository discovery exceeded the configured portable record limit.'
    ));
    return [];
  }
  return values;
}

function processFailureResult(error: unknown): GitDiscoveryResult {
  if (error instanceof GitProcessError) {
    if (error.reason === 'missing') {
      return emptyResult('unsupported', [diagnostic(
        'GIT_EXECUTABLE_UNAVAILABLE',
        'error',
        'Git is unavailable, so repository provenance could not be discovered.'
      )]);
    }
    if (error.reason === 'timeout') {
      return emptyResult('unsupported', [diagnostic(
        'GIT_DISCOVERY_TIMEOUT',
        'error',
        'A bounded Git discovery query exceeded its execution limit.'
      )]);
    }
    if (error.reason === 'output-limit') {
      return emptyResult('unsupported', [diagnostic(
        'GIT_DISCOVERY_OUTPUT_LIMIT',
        'error',
        'A bounded Git discovery query exceeded its output limit.'
      )]);
    }
  }
  return emptyResult('unsupported', [diagnostic(
    'GIT_DISCOVERY_FAILED',
    'error',
    'Git repository provenance could not be read safely.'
  )]);
}

/**
 * Discovers portable Git provenance without running target code, hooks, package
 * managers, submodules, network protocols, fsmonitor commands, or external filters.
 * The target repository is never written by this operation.
 */
export async function discoverGitRepository(
  targetPath: string,
  options: GitDiscoveryOptions = {}
): Promise<GitDiscoveryResult> {
  const maxOutputBytes = boundedInteger(
    options.maxOutputBytes,
    DEFAULT_MAX_OUTPUT_BYTES,
    MIN_OUTPUT_BYTES,
    MAX_OUTPUT_BYTES,
    'maxOutputBytes'
  );
  const maxRecords = boundedInteger(options.maxRecords, DEFAULT_MAX_RECORDS, 1, 1_000_000, 'maxRecords');
  const timeoutMs = boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS, 'timeoutMs');
  const limits = { maxOutputBytes, timeoutMs };
  const diagnostics: GitDiscoveryDiagnostic[] = [];

  let repositoryPath: string;
  try {
    repositoryPath = await realpath(path.resolve(targetPath));
    if (!(await lstat(repositoryPath)).isDirectory()) {
      return emptyResult('unsupported', [diagnostic(
        'GIT_TARGET_UNSUPPORTED',
        'error',
        'The discovery target is not a directory.'
      )]);
    }
  } catch {
    return emptyResult('unsupported', [diagnostic(
      'GIT_TARGET_UNAVAILABLE',
      'error',
      'The discovery target directory is unavailable.'
    )]);
  }

  let gitMarker;
  try {
    gitMarker = await lstat(path.join(repositoryPath, '.git'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      return emptyResult('unsupported', [diagnostic(
        'GIT_METADATA_UNREADABLE',
        'error',
        'Git metadata could not be inspected safely.'
      )]);
    }
    const resemblesBareRepository =
      await existsAsDirectory(path.join(repositoryPath, 'objects')) &&
      await existsAsDirectory(path.join(repositoryPath, 'refs'));
    return resemblesBareRepository
      ? emptyResult('unsupported', [diagnostic(
          'GIT_BARE_REPOSITORY_UNSUPPORTED',
          'error',
          'Bare Git repositories are not supported by worktree discovery.'
        )])
      : emptyResult('not-git', [diagnostic(
          'GIT_NOT_REPOSITORY',
          'info',
          'The target directory is not a Git worktree root.'
        )]);
  }
  if (gitMarker.isSymbolicLink() || (!gitMarker.isDirectory() && !gitMarker.isFile())) {
    return emptyResult('unsupported', [diagnostic(
      'GIT_METADATA_LAYOUT_UNSUPPORTED',
      'error',
      'The worktree uses an unsupported Git metadata layout.'
    )]);
  }

  try {
    const inside = await runGit(repositoryPath, ['rev-parse', '--is-inside-work-tree'], limits);
    if (inside.exitCode !== 0 || decodeLine(inside.stdout) !== 'true') {
      return emptyResult('unsupported', [diagnostic(
        'GIT_WORKTREE_UNREADABLE',
        'error',
        'The target Git worktree could not be read safely.'
      )]);
    }
    const topLevel = await runGit(repositoryPath, ['rev-parse', '--show-toplevel'], limits);
    if (topLevel.exitCode !== 0 || !sameFilesystemLocation(await realpath(decodeLine(topLevel.stdout)), repositoryPath)) {
      return emptyResult('unsupported', [diagnostic(
        'GIT_TARGET_NOT_WORKTREE_ROOT',
        'error',
        'The target directory is not the root of its Git worktree.'
      )]);
    }

    const objectFormatResult = await runGit(repositoryPath, ['rev-parse', '--show-object-format=storage'], limits);
    const objectFormatText = objectFormatResult.exitCode === 0 ? decodeLine(objectFormatResult.stdout) : '';
    if (objectFormatText !== 'sha1' && objectFormatText !== 'sha256') {
      return emptyResult('unsupported', [diagnostic(
        'GIT_OBJECT_FORMAT_UNSUPPORTED',
        'error',
        'The repository uses an unsupported Git object format.'
      )]);
    }

    const headResult = await runGit(repositoryPath, ['rev-parse', '--verify', '--quiet', 'HEAD^{commit}'], limits);
    const branchResult = await runGit(repositoryPath, ['symbolic-ref', '--quiet', '--short', 'HEAD'], limits);
    const objectId = headResult.exitCode === 0 ? decodeLine(headResult.stdout) : undefined;
    const branch = branchResult.exitCode === 0 ? decodeLine(branchResult.stdout).normalize('NFC') : undefined;
    if (objectId !== undefined && !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(objectId)) {
      return emptyResult('unsupported', [diagnostic(
        'GIT_HEAD_UNSUPPORTED',
        'error',
        'The repository HEAD cannot be represented portably.'
      )]);
    }
    if (objectId === undefined && branch === undefined) {
      return emptyResult('unsupported', [diagnostic(
        'GIT_HEAD_UNSUPPORTED',
        'error',
        'The repository HEAD cannot be represented portably.'
      )]);
    }
    const repository: GitRepositoryRecord = {
      root: '.',
      objectFormat: objectFormatText,
      head: objectId === undefined
        ? { state: 'unborn', branch: branch! }
        : branch === undefined
          ? { state: 'detached', objectId }
          : { state: 'attached', objectId, branch }
    };

    const dangerousFilterResult = await runGit(repositoryPath, [
      'config',
      '--null',
      '--name-only',
      '--get-regexp',
      '^filter\\..*\\.(clean|smudge|process)$'
    ], limits);
    if (dangerousFilterResult.exitCode !== 0 && dangerousFilterResult.exitCode !== 1) {
      return emptyResult('unsupported', [diagnostic(
        'GIT_CONFIG_UNREADABLE',
        'error',
        'Repository configuration could not be inspected safely.'
      )]);
    }
    const hasExternalFilter = dangerousFilterResult.exitCode === 0 && nulFields(dangerousFilterResult.stdout).length > 0;
    if (hasExternalFilter) {
      diagnostics.push(diagnostic(
        'GIT_EXTERNAL_FILTER_STATUS_UNAVAILABLE',
        'warning',
        'Tracked worktree status was not inspected because repository configuration defines an external content filter.'
      ));
    }

    const [indexResult, untrackedResult, ignoredResult] = await Promise.all([
      runGit(repositoryPath, ['ls-files', '--cached', '--stage', '--full-name', '-z'], limits),
      runGit(repositoryPath, ['ls-files', '--others', '--exclude-standard', '--directory', '--no-empty-directory', '--full-name', '-z'], limits),
      runGit(repositoryPath, ['ls-files', '--others', '--ignored', '--exclude-standard', '--directory', '--no-empty-directory', '--full-name', '-z'], limits)
    ]);
    if (indexResult.exitCode !== 0 || untrackedResult.exitCode !== 0 || ignoredResult.exitCode !== 0) {
      return emptyResult('unsupported', [diagnostic(
        'GIT_PATH_DISCOVERY_UNAVAILABLE',
        'error',
        'Repository paths could not be discovered safely.'
      )]);
    }

    const records = new Map<string, MutablePathRecord>();
    const origins = new Map<string, string>();
    const collisions = new Set<string>();
    parseIndexEntries(
      indexResult.stdout,
      records,
      origins,
      collisions,
      diagnostics,
      hasExternalFilter ? 'unknown' : 'clean'
    );
    parsePathList(untrackedResult.stdout, 'untracked', records, origins, collisions, diagnostics);
    parsePathList(ignoredResult.stdout, 'ignored', records, origins, collisions, diagnostics);

    if (!hasExternalFilter) {
      const statusResult = await runGit(repositoryPath, [
        'status',
        '--porcelain=v2',
        '-z',
        '--untracked-files=no',
        '--ignore-submodules=all',
        '--find-renames=50%'
      ], limits);
      if (statusResult.exitCode !== 0) {
        diagnostics.push(diagnostic(
          'GIT_TRACKED_STATUS_UNAVAILABLE',
          'warning',
          'Tracked index and worktree status could not be inspected with the supported Git protocol.'
        ));
        for (const record of records.values()) {
          if (record.tracking === 'tracked') {
            record.indexStatus = 'unknown';
            record.worktreeStatus = 'unknown';
          }
        }
      } else {
        parseStatus(statusResult.stdout, records, origins, collisions, diagnostics);
      }
    }

    const finalizedRecords = finalizeRecords(records, collisions, maxRecords, diagnostics);
    const hasError = diagnostics.some((entry) => entry.severity === 'error');
    const isPartial = diagnostics.length > 0;
    return {
      schemaVersion: 1,
      provider: 'git',
      state: hasError ? 'unsupported' : isPartial ? 'partial' : 'ready',
      repository,
      records: hasError ? [] : finalizedRecords,
      diagnostics: sortDiagnostics(diagnostics)
    };
  } catch (error) {
    return processFailureResult(error);
  }
}
