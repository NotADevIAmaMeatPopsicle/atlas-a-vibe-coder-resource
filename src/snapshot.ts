import { lstat, readFile, readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { AtlasError } from './errors.js';
import { snapshotIdentity } from './identity.js';
import {
  HARD_MAX_BOUNDARY_ENTRIES,
  HARD_MAX_INCLUDED_FILES,
  HARD_MAX_TOTAL_BYTES
} from './limits.js';
import type { GitDiscoveryResult } from './discovery/types.js';
import type {
  DiagnosticRecord,
  FileKind,
  FileLifecycleDeclaration,
  FileRecord,
  PatternExpectation,
  ProfilePatternObservation,
  ResolvedProfile,
  ScannedFile,
  SnapshotRecord
} from './types.js';
import { JS_TS_ADAPTER_VERSION, SCHEMA_VERSION } from './types.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';
import {
  DEFAULT_EXCLUDED_DIRECTORIES,
  isInside,
  matchesAnyGlob,
  normalizeFilesystemRelative,
  normalizeIncludeRoot,
  normalizeTargetRelative
} from './util/paths.js';

export const CORE_CENSUS_VERSION = '1.3.0';

const PROFILE_LIFECYCLE_LIMITATION = 'Lifecycle is a static profile declaration and has not been validated against runtime deployment, traffic, or use.';
const UNSPECIFIED_LIFECYCLE_LIMITATION = 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.';

const SOURCE_EXTENSIONS = new Map([
  ['.js', 'javascript'],
  ['.jsx', 'javascript-jsx'],
  ['.mjs', 'javascript'],
  ['.cjs', 'javascript'],
  ['.ts', 'typescript'],
  ['.tsx', 'typescript-tsx'],
  ['.mts', 'typescript'],
  ['.cts', 'typescript']
]);

function evidence(pathValue?: string) {
  return {
    level: 0 as const,
    producer: 'atlas/core-census',
    producerVersion: CORE_CENSUS_VERSION,
    basis: 'filesystem-census',
    ...(pathValue ? { path: pathValue } : {})
  };
}

function diagnostic(code: string, severity: DiagnosticRecord['severity'], message: string, pathValue?: string): DiagnosticRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({ code, message, path: pathValue ?? null })).slice(0, 24)}`,
    code,
    severity,
    message,
    ...(pathValue ? { path: pathValue } : {}),
    evidence: evidence(pathValue)
  };
}

function languageFor(relativePath: string): string {
  const basename = path.posix.basename(relativePath).toLowerCase();
  if (/^\.env(?:\..+)?\.(?:example|template)$/.test(basename)) return 'dotenv-template';
  const extension = path.posix.extname(relativePath).toLowerCase();
  if (SOURCE_EXTENSIONS.has(extension)) return SOURCE_EXTENSIONS.get(extension)!;
  if (extension === '.json') return 'json';
  if (extension === '.md' || extension === '.mdx') return 'markdown';
  if (extension === '.yaml' || extension === '.yml') return 'yaml';
  if (extension === '.html') return 'html';
  if (extension === '.css' || extension === '.scss' || extension === '.less') return 'stylesheet';
  if (extension === '.sql') return 'sql';
  if (extension === '.py') return 'python';
  if (extension === '.sh' || extension === '.ps1') return 'shell';
  return extension ? extension.slice(1) : 'unknown';
}

function kindFor(relativePath: string, language: string): FileKind {
  const lower = relativePath.toLowerCase();
  const segments = lower.split('/');
  if (
    segments.some((segment) => ['test', 'tests', '__tests__', 'e2e'].includes(segment)) ||
    /(?:^|\.)((?:spec)|(?:test))\.[^.]+$/.test(path.posix.basename(lower))
  ) return 'test';
  if (SOURCE_EXTENSIONS.has(path.posix.extname(lower))) return 'source';
  if (language === 'markdown') return 'documentation';
  if (
    language === 'json' || language === 'yaml' || language === 'dotenv-template' ||
    /(?:^|\/)(?:dockerfile|tsconfig|jsconfig|package\.json)/.test(lower)
  ) return 'configuration';
  return 'other';
}

function isBinary(content: Buffer): boolean {
  return content.subarray(0, Math.min(content.length, 8192)).includes(0);
}

function excluded(relativePath: string, profile: ResolvedProfile): boolean {
  const segments = relativePath.split('/');
  if (segments.some((segment) => DEFAULT_EXCLUDED_DIRECTORIES.has(segment))) return true;
  return matchesAnyGlob(relativePath, profile.exclude);
}

function engineExcluded(relativePath: string): boolean {
  return relativePath.split('/').some((segment) => DEFAULT_EXCLUDED_DIRECTORIES.has(segment));
}

function profilePatternObservations(
  profile: ResolvedProfile,
  includedPaths: string[],
  observedBoundaryFilePaths: string[]
): ProfilePatternObservation[] {
  const configured = profile.patternExpectations ?? [];
  const explicitlyOwned = new Set(configured.map((entry) => `${entry.collection}\0${entry.pattern}`));
  const generated = new Map<string, PatternExpectation>();
  const addRequiredExpectation = (
    collection: PatternExpectation['collection'],
    pattern: string,
    idPrefix: string
  ): void => {
    const ownershipKey = `${collection}\0${pattern}`;
    if (explicitlyOwned.has(ownershipKey) || generated.has(ownershipKey)) return;
    generated.set(ownershipKey, {
      id: `atlas:${idPrefix}:${sha256(ownershipKey).slice(0, 16)}`,
      collection,
      pattern,
      minMatches: 1
    });
  };
  for (const root of profile.includeRoots) addRequiredExpectation('includeRoots', root, 'required-include-root');
  for (const exclusion of profile.explicitExclude ?? []) {
    addRequiredExpectation('exclude', exclusion, 'required-exclude');
  }
  for (const entrypoint of profile.entrypoints) {
    addRequiredExpectation('entrypoints', entrypoint, 'required-entrypoint');
  }
  for (const exemption of profile.deadCodeExemptions) {
    addRequiredExpectation('deadCodeExemptions', exemption, 'required-dead-code-exemption');
  }
  for (const fixturePattern of profile.fixturePatterns ?? []) {
    addRequiredExpectation('fixturePatterns', fixturePattern, 'required-fixture-boundary');
  }
  for (const guardPath of profile.operationalRisks?.guardPaths ?? []) {
    addRequiredExpectation('guardPaths', guardPath, 'required-guard-boundary');
  }
  for (const seedDictionarySource of profile.operationalRisks?.seedDictionarySources ?? []) {
    addRequiredExpectation('seedDictionarySources', seedDictionarySource, 'required-seed-dictionary-source');
  }
  for (const loaderRule of profile.loaderRules ?? []) {
    if (!loaderRule.required) continue;
    for (const loaderPath of loaderRule.loaderPaths) {
      addRequiredExpectation('loaderPaths', loaderPath, 'required-loader-path');
    }
    for (const loadedPattern of loaderRule.loadedPatterns) {
      addRequiredExpectation('loadedPatterns', loadedPattern, 'required-loaded-pattern');
    }
  }
  const expectations: PatternExpectation[] = [
    ...configured,
    ...generated.values()
  ];
  return expectations.map((expectation) => {
    const candidates = expectation.collection === 'exclude' ? observedBoundaryFilePaths : includedPaths;
    const matches = candidates.filter((candidate) => {
      if (
        (expectation.collection === 'includeRoots' || expectation.collection === 'exclude') &&
        !/[?*{}\[\]]/u.test(expectation.pattern)
      ) {
        return expectation.pattern === '.' || candidate === expectation.pattern || candidate.startsWith(`${expectation.pattern}/`);
      }
      return candidate !== '.' && matchesAnyGlob(candidate, [expectation.pattern]);
    });
    const withinMaximum = expectation.maxMatches === undefined || matches.length <= expectation.maxMatches;
    return {
      id: expectation.id,
      collection: expectation.collection,
      pattern: expectation.pattern,
      minMatches: expectation.minMatches,
      ...(expectation.maxMatches === undefined ? {} : { maxMatches: expectation.maxMatches }),
      actualMatches: matches.length,
      status: matches.length >= expectation.minMatches && withinMaximum ? 'passed' as const : 'failed' as const,
      samplePaths: matches.slice(0, 32)
    };
  }).sort((left, right) => compareCanonicalText(left.id, right.id));
}

function lifecycleFor(relativePath: string, profile: ResolvedProfile): FileLifecycleDeclaration {
  const matches = profile.lifecycleRules.filter((rule) => rule.paths.some((root) => (
    relativePath === root || relativePath.startsWith(`${root}/`)
  )));
  if (matches.length > 1) {
    throw new AtlasError('INVALID_CONFIG', `Lifecycle rules overlap for target path: ${relativePath}`);
  }
  const match = matches[0];
  if (!match) {
    return {
      state: 'unspecified',
      basis: 'no-profile-match',
      uncertainty: 'not-runtime-validated',
      limitation: UNSPECIFIED_LIFECYCLE_LIMITATION
    };
  }
  return {
    state: match.state,
    basis: 'profile-path-rule',
    ruleId: match.id,
    uncertainty: 'not-runtime-validated',
    limitation: PROFILE_LIFECYCLE_LIMITATION
  };
}

async function assertContained(targetRoot: string, absolutePath: string, relativePath: string): Promise<string> {
  const resolved = await realpath(absolutePath);
  if (!isInside(targetRoot, resolved)) {
    throw new AtlasError('PATH_ESCAPE', `Resolved path escapes target root: ${relativePath}`);
  }
  return resolved;
}

function gitlinkBoundaryPaths(discovery: GitDiscoveryResult | undefined): string[] {
  const boundaries = new Set<string>();
  for (const record of discovery?.records ?? []) {
    if (record.kind !== 'gitlink') continue;
    try {
      const normalized = normalizeTargetRelative(record.path);
      if (normalized === record.path) boundaries.add(normalized);
    } catch {
      // Discovery is schema-checked by production callers. Ignore malformed
      // optional evidence rather than allowing it to expand the scan boundary.
    }
  }
  return [...boundaries].sort((left, right) =>
    left.split('/').length - right.split('/').length || compareCanonicalText(left, right)
  );
}

function boundaryIntersectsIncludes(boundary: string, includeRoots: string[]): boolean {
  return includeRoots.some((includeRoot) =>
    includeRoot === '.' || boundary === includeRoot ||
    boundary.startsWith(`${includeRoot}/`) || includeRoot.startsWith(`${boundary}/`)
  );
}

function pathAtOrBelowBoundary(relativePath: string, boundary: string): boolean {
  const comparedPath = process.platform === 'win32' ? relativePath.toLowerCase() : relativePath;
  const comparedBoundary = process.platform === 'win32' ? boundary.toLowerCase() : boundary;
  return comparedPath === comparedBoundary || comparedPath.startsWith(`${comparedBoundary}/`);
}

type IncludeRootFilesystemBoundary =
  | { kind: 'nested-git'; path: string }
  | { kind: 'symlink'; path: string };

export async function buildSnapshot(
  targetRoot: string,
  targetId: string,
  profile: ResolvedProfile,
  gitDiscovery?: GitDiscoveryResult
): Promise<{
  snapshot: SnapshotRecord;
  files: ScannedFile[];
  diagnostics: DiagnosticRecord[];
  profileObservations: ProfilePatternObservation[];
}> {
  const files: ScannedFile[] = [];
  const diagnostics: DiagnosticRecord[] = [];
  const observedPaths = new Set<string>();
  const observedBoundaryPaths = new Set<string>();
  const observedBoundaryFilePaths = new Set<string>();
  const caseFolded = new Map<string, string>();
  const recordedNestedGitBoundaries = new Set<string>();
  const recordedIncludeRootSymlinks = new Set<string>();
  const gitlinkBoundaries = gitlinkBoundaryPaths(gitDiscovery);
  let totalIncludedBytes = 0;

  function recordBoundaryPath(relativePath: string): void {
    if (observedBoundaryPaths.has(relativePath)) return;
    observedBoundaryPaths.add(relativePath);
    if (observedBoundaryPaths.size > HARD_MAX_BOUNDARY_ENTRIES) {
      throw new AtlasError('RESOURCE_LIMIT', `Target boundary exceeds ${HARD_MAX_BOUNDARY_ENTRIES} entries.`);
    }
  }

  function gitlinkBoundaryFor(relativePath: string): string | undefined {
    return gitlinkBoundaries.find((boundary) => pathAtOrBelowBoundary(relativePath, boundary));
  }

  function recordNestedGitBoundary(relativePath: string): void {
    if (recordedNestedGitBoundaries.has(relativePath)) return;
    recordedNestedGitBoundaries.add(relativePath);
    recordBoundaryPath(relativePath);
    diagnostics.push(diagnostic(
      'NESTED_GIT_REPOSITORY_SKIPPED',
      'warning',
      'Nested Git worktrees and gitlinks are separate targets and were not included in the parent snapshot.',
      relativePath
    ));
  }

  function recordIncludeRootSymlink(relativePath: string, directIncludeRoot: boolean): void {
    if (recordedIncludeRootSymlinks.has(relativePath)) return;
    recordedIncludeRootSymlinks.add(relativePath);
    recordBoundaryPath(relativePath);
    diagnostics.push(diagnostic(
      'SYMLINK_SKIPPED',
      'warning',
      directIncludeRoot
        ? 'An include root cannot be a symbolic link or junction.'
        : 'Symbolic links and junctions are excluded by the deny policy.',
      relativePath
    ));
  }

  async function hasGitMarker(absoluteDirectory: string): Promise<boolean> {
    try {
      await lstat(path.join(absoluteDirectory, '.git'));
      return true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ENOTDIR') return false;
      throw error;
    }
  }

  async function filesystemBoundaryForIncludeRoot(relativeRoot: string): Promise<IncludeRootFilesystemBoundary | undefined> {
    if (relativeRoot === '.') return undefined;
    const segments = relativeRoot.split('/');
    let absoluteCursor = targetRoot;
    for (let index = 0; index < segments.length; index += 1) {
      absoluteCursor = path.join(absoluteCursor, segments[index]!);
      let metadata;
      try {
        metadata = await lstat(absoluteCursor);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'ENOENT' || code === 'ENOTDIR') return undefined;
        throw error;
      }
      const relativeCursor = segments.slice(0, index + 1).join('/');
      if (metadata.isSymbolicLink()) return { kind: 'symlink', path: relativeCursor };
      if (!metadata.isDirectory()) return undefined;
      if (await hasGitMarker(absoluteCursor)) return { kind: 'nested-git', path: relativeCursor };
    }
    return undefined;
  }

  async function addFile(absolutePath: string, relativePathValue: string): Promise<void> {
    const relativePath = normalizeFilesystemRelative(relativePathValue);
    recordBoundaryPath(relativePath);
    observedBoundaryFilePaths.add(relativePath);
    if (excluded(relativePath, profile)) return;
    const gitlinkBoundary = gitlinkBoundaryFor(relativePath);
    if (gitlinkBoundary) {
      recordNestedGitBoundary(gitlinkBoundary);
      return;
    }
    if (observedPaths.has(relativePath)) return;
    const metadata = await lstat(absolutePath);
    if (metadata.isSymbolicLink()) {
      diagnostics.push(diagnostic('SYMLINK_SKIPPED', 'warning', 'Symbolic links and junctions are excluded by the deny policy.', relativePath));
      return;
    }
    if (!metadata.isFile()) {
      diagnostics.push(diagnostic('UNSUPPORTED_ENTRY', 'warning', 'Non-file filesystem entry was skipped.', relativePath));
      return;
    }
    await assertContained(targetRoot, absolutePath, relativePath);
    if (metadata.size > profile.maxFileBytes) {
      diagnostics.push(diagnostic('FILE_TOO_LARGE', 'warning', `File exceeds maxFileBytes (${profile.maxFileBytes}).`, relativePath));
      return;
    }
    if (files.length >= HARD_MAX_INCLUDED_FILES) {
      throw new AtlasError('RESOURCE_LIMIT', `Target includes more than ${HARD_MAX_INCLUDED_FILES} files.`);
    }
    if (totalIncludedBytes + metadata.size > HARD_MAX_TOTAL_BYTES) {
      throw new AtlasError('RESOURCE_LIMIT', `Target included bytes exceed ${HARD_MAX_TOTAL_BYTES}.`);
    }
    const content = await readFile(absolutePath);
    const afterRead = await stat(absolutePath);
    if (afterRead.size !== metadata.size || afterRead.mtimeMs !== metadata.mtimeMs) {
      throw new AtlasError('TARGET_CHANGED', `Target file changed while it was being read: ${relativePath}`);
    }
    const folded = relativePath.toLowerCase();
    const caseCollision = caseFolded.get(folded);
    if (caseCollision && caseCollision !== relativePath) {
      throw new AtlasError('CASE_COLLISION', `Target contains paths that differ only by case: ${caseCollision}, ${relativePath}`);
    }
    caseFolded.set(folded, relativePath);
    observedPaths.add(relativePath);
    totalIncludedBytes += content.length;
    const language = isBinary(content) ? 'binary' : languageFor(relativePath);
    const record: FileRecord = {
      schemaVersion: SCHEMA_VERSION,
      id: `file_sha256_${sha256(canonicalJson({ domain: 'atlas.file.v1', targetId, path: relativePath }))}`,
      path: relativePath,
      sha256: sha256(content),
      bytes: content.length,
      kind: kindFor(relativePath, language),
      language,
      symbols: [],
      environmentVariables: [],
      lifecycle: lifecycleFor(relativePath, profile),
      evidence: evidence(relativePath)
    };
    files.push({ record, absolutePath, content, observedMtimeMs: metadata.mtimeMs });
  }

  async function walkDirectory(absoluteDirectory: string, relativeDirectory: string): Promise<void> {
    const gitlinkBoundary = gitlinkBoundaryFor(relativeDirectory);
    if (gitlinkBoundary) {
      recordNestedGitBoundary(gitlinkBoundary);
      return;
    }
    const directoryMetadata = await lstat(absoluteDirectory);
    if (directoryMetadata.isSymbolicLink()) {
      diagnostics.push(diagnostic('SYMLINK_SKIPPED', 'warning', 'Symbolic links and junctions are excluded by the deny policy.', relativeDirectory));
      return;
    }
    await assertContained(targetRoot, absoluteDirectory, relativeDirectory);
    if (relativeDirectory !== '.' && await hasGitMarker(absoluteDirectory)) {
      recordNestedGitBoundary(relativeDirectory);
      return;
    }
    const children = await readdir(absoluteDirectory, { withFileTypes: true });
    children.sort((left, right) => compareCanonicalText(left.name, right.name));
    for (const child of children) {
      const relativePath = normalizeFilesystemRelative(path.join(relativeDirectory, child.name));
      recordBoundaryPath(relativePath);
      if (child.isFile()) observedBoundaryFilePaths.add(relativePath);
      const absolutePath = path.join(absoluteDirectory, child.name);
      if (excluded(relativePath, profile)) {
        if (
          child.isDirectory() && !child.isSymbolicLink() && !engineExcluded(relativePath) &&
          (profile.explicitExclude ?? []).length > 0
        ) {
          await censusExcludedDirectory(absolutePath, relativePath);
        }
        continue;
      }
      if (child.isSymbolicLink()) {
        diagnostics.push(diagnostic('SYMLINK_SKIPPED', 'warning', 'Symbolic links and junctions are excluded by the deny policy.', relativePath));
      } else if (child.isDirectory()) {
        await walkDirectory(absolutePath, relativePath);
      } else {
        await addFile(absolutePath, relativePath);
      }
    }
  }

  async function censusExcludedDirectory(absoluteDirectory: string, relativeDirectory: string): Promise<void> {
    const gitlinkBoundary = gitlinkBoundaryFor(relativeDirectory);
    if (gitlinkBoundary || engineExcluded(relativeDirectory)) return;
    const metadata = await lstat(absoluteDirectory);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) return;
    await assertContained(targetRoot, absoluteDirectory, relativeDirectory);
    if (await hasGitMarker(absoluteDirectory)) return;
    const children = await readdir(absoluteDirectory, { withFileTypes: true });
    children.sort((left, right) => compareCanonicalText(left.name, right.name));
    for (const child of children) {
      const relativePath = normalizeFilesystemRelative(path.join(relativeDirectory, child.name));
      recordBoundaryPath(relativePath);
      if (child.isFile()) observedBoundaryFilePaths.add(relativePath);
      if (child.isDirectory() && !child.isSymbolicLink() && !engineExcluded(relativePath)) {
        await censusExcludedDirectory(path.join(absoluteDirectory, child.name), relativePath);
      }
    }
  }

  for (const boundary of gitlinkBoundaries) {
    if (boundaryIntersectsIncludes(boundary, profile.includeRoots) && !excluded(boundary, profile)) {
      recordNestedGitBoundary(boundary);
    }
  }

  for (const includeRoot of profile.includeRoots) {
    const relativeRoot = normalizeIncludeRoot(includeRoot);
    recordBoundaryPath(relativeRoot);
    const gitlinkBoundary = relativeRoot === '.' ? undefined : gitlinkBoundaryFor(relativeRoot);
    if (gitlinkBoundary) {
      recordNestedGitBoundary(gitlinkBoundary);
      continue;
    }
    const filesystemBoundary = await filesystemBoundaryForIncludeRoot(relativeRoot);
    if (filesystemBoundary?.kind === 'nested-git') {
      recordNestedGitBoundary(filesystemBoundary.path);
      continue;
    }
    if (filesystemBoundary?.kind === 'symlink') {
      recordIncludeRootSymlink(filesystemBoundary.path, filesystemBoundary.path === relativeRoot);
      continue;
    }
    const absoluteRoot = relativeRoot === '.' ? targetRoot : path.resolve(targetRoot, ...relativeRoot.split('/'));
    if (!isInside(targetRoot, absoluteRoot)) throw new AtlasError('PATH_ESCAPE', `Include root escapes target: ${relativeRoot}`);
    try {
      const metadata = await lstat(absoluteRoot);
      if (metadata.isSymbolicLink()) {
        diagnostics.push(diagnostic('SYMLINK_SKIPPED', 'warning', 'An include root cannot be a symbolic link or junction.', relativeRoot));
      } else if (metadata.isDirectory()) {
        await walkDirectory(absoluteRoot, relativeRoot);
      } else {
        await addFile(absoluteRoot, relativeRoot);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new AtlasError('PROFILE_PATTERN_ZERO_MATCH', `Configured include root does not exist: ${relativeRoot}`);
      } else {
        throw error;
      }
    }
  }

  files.sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  diagnostics.sort((left, right) => compareCanonicalText(left.id, right.id));
  const profileObservations = profilePatternObservations(
    profile,
    files.map((file) => file.record.path),
    [...observedBoundaryFilePaths].sort(compareCanonicalText)
  );
  const failedObservations = profileObservations.filter((entry) => entry.status === 'failed');
  if (failedObservations.length) {
    const zeroMatch = failedObservations.find((entry) => entry.actualMatches === 0 && entry.minMatches > 0);
    const rendered = failedObservations.map((entry) => {
      const maximum = entry.maxMatches === undefined ? '' : `..${entry.maxMatches}`;
      return `${entry.id} (${entry.collection}:${entry.pattern}) expected ${entry.minMatches}${maximum}, observed ${entry.actualMatches}`;
    }).join('; ');
    throw new AtlasError(
      zeroMatch ? 'PROFILE_PATTERN_ZERO_MATCH' : 'PROFILE_PATTERN_COUNT_MISMATCH',
      `Profile pattern coverage failed: ${rendered}`
    );
  }
  const withoutIdentity: Omit<SnapshotRecord, 'snapshotId'> = {
    schemaVersion: SCHEMA_VERSION,
    targetId,
    boundary: {
      includeRoots: [...profile.includeRoots],
      exclude: [...profile.exclude],
      maxFileBytes: profile.maxFileBytes,
      symlinkPolicy: 'deny'
    },
    boundaryDiagnostics: diagnostics.map((entry) => ({
      id: entry.id,
      code: entry.code,
      severity: entry.severity,
      ...(entry.path ? { path: entry.path } : {})
    })),
    files: files.map(({ record }) => ({ id: record.id, path: record.path, sha256: record.sha256, bytes: record.bytes }))
  };
  const snapshot: SnapshotRecord = { ...withoutIdentity, snapshotId: snapshotIdentity(withoutIdentity) };
  return { snapshot, files, diagnostics, profileObservations };
}

export async function verifyTargetUnchanged(files: ScannedFile[]): Promise<void> {
  for (const file of files) {
    let metadata;
    let content;
    try {
      [metadata, content] = await Promise.all([stat(file.absolutePath), readFile(file.absolutePath)]);
    } catch {
      throw new AtlasError('TARGET_CHANGED', `Target file disappeared during the scan: ${file.record.path}`);
    }
    if (metadata.mtimeMs !== file.observedMtimeMs || content.length !== file.record.bytes || sha256(content) !== file.record.sha256) {
      throw new AtlasError('TARGET_CHANGED', `Target file changed during the scan: ${file.record.path}`);
    }
  }
}

export function adapterEvidence(pathValue: string, basis: string, line?: number, column?: number) {
  return {
    level: 1 as const,
    producer: 'atlas/js-ts-adapter',
    producerVersion: JS_TS_ADAPTER_VERSION,
    basis,
    path: pathValue,
    ...(line !== undefined ? { line } : {}),
    ...(column !== undefined ? { column } : {})
  };
}
