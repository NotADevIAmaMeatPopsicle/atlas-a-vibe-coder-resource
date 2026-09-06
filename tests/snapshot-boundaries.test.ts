import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { discoverGitRepository } from '../src/discovery/index.js';
import { buildSnapshot, CORE_CENSUS_VERSION } from '../src/snapshot.js';
import type { ResolvedProfile } from '../src/types.js';

const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

const PROFILE: ResolvedProfile = {
  schemaVersion: 1,
  id: 'nested-git-boundary-test',
  includeRoots: ['.'],
  exclude: [],
  entrypoints: [],
  aliases: {},
  envExampleFiles: [],
  platformRoots: [],
  deadCodeExemptions: [],
  lifecycleRules: [],
  maxFileBytes: 1_000_000
};

function runGit(repositoryPath: string, command: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('git', [
      '-c', 'user.name=Atlas Tests',
      '-c', 'user.email=atlas-tests@example.invalid',
      '-c', 'commit.gpgSign=false',
      '-c', `core.hooksPath=${NULL_DEVICE}`,
      '-C', repositoryPath,
      ...command
    ], {
      encoding: 'utf8',
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' },
      windowsHide: true
    }, (error, stdout) => error ? reject(error) : resolve(stdout));
  });
}

async function gitIsAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    execFile('git', ['--version'], { windowsHide: true }, (error) => resolve(!error));
  });
}

const hasGit = await gitIsAvailable();

async function initializeRepository(root: string): Promise<void> {
  await mkdir(root, { recursive: true });
  await runGit(root, ['init', '-b', 'main']);
  await runGit(root, ['config', 'core.autocrlf', 'false']);
}

function nestedBoundaryPaths(result: Awaited<ReturnType<typeof buildSnapshot>>): string[] {
  return result.diagnostics
    .filter((entry) => entry.code === 'NESTED_GIT_REPOSITORY_SKIPPED')
    .map((entry) => entry.path!)
    .sort();
}

test('snapshot excludes nested Git directory and gitfile worktree markers as separate targets', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-snapshot-nested-git-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'src', 'index.ts'), 'export const parent = true;\n');

  const nestedRepository = path.join(root, 'vendor', 'repository-marker');
  await initializeRepository(nestedRepository);
  await writeFile(path.join(nestedRepository, 'private.ts'), 'export const nested = "first";\n');

  const gitfileWorktree = path.join(root, 'vendor', 'gitfile-marker');
  await mkdir(gitfileWorktree, { recursive: true });
  await writeFile(path.join(gitfileWorktree, '.git'), 'gitdir: ../separate-target-metadata\n');
  await writeFile(path.join(gitfileWorktree, 'private.ts'), 'export const worktree = "first";\n');

  const first = await buildSnapshot(root, 'nested-marker-target', PROFILE);
  assert.deepEqual(first.files.map((file) => file.record.path), ['src/index.ts']);
  assert.deepEqual(nestedBoundaryPaths(first), ['vendor/gitfile-marker', 'vendor/repository-marker']);
  assert.deepEqual(
    first.snapshot.boundaryDiagnostics.map((entry) => entry.path).sort(),
    ['vendor/gitfile-marker', 'vendor/repository-marker']
  );
  assert(first.files.every((file) => file.record.evidence.producerVersion === CORE_CENSUS_VERSION));

  const explicitNestedFile = await buildSnapshot(root, 'nested-marker-target', {
    ...PROFILE,
    includeRoots: ['vendor/repository-marker/private.ts'],
    patternExpectations: [{
      id: 'intentionally-boundary-only-nested-file',
      collection: 'includeRoots',
      pattern: 'vendor/repository-marker/private.ts',
      minMatches: 0,
      maxMatches: 0
    }]
  });
  assert.deepEqual(explicitNestedFile.files, []);
  assert.deepEqual(nestedBoundaryPaths(explicitNestedFile), ['vendor/repository-marker']);

  const separateTarget = await buildSnapshot(nestedRepository, 'approved-separate-target', PROFILE);
  assert.deepEqual(separateTarget.files.map((file) => file.record.path), ['private.ts']);
  assert.deepEqual(nestedBoundaryPaths(separateTarget), []);

  await writeFile(path.join(nestedRepository, 'private.ts'), 'export const nested = "second";\n');
  await writeFile(path.join(gitfileWorktree, 'private.ts'), 'export const worktree = "second";\n');
  const changedChildren = await buildSnapshot(root, 'nested-marker-target', PROFILE);
  assert.equal(changedChildren.snapshot.snapshotId, first.snapshot.snapshotId);

  const additionalWorktree = path.join(root, 'vendor', 'additional-marker');
  await mkdir(additionalWorktree, { recursive: true });
  await writeFile(path.join(additionalWorktree, '.git'), 'gitdir: ../additional-target-metadata\n');
  await writeFile(path.join(additionalWorktree, 'private.ts'), 'export const additional = true;\n');
  const expandedBoundary = await buildSnapshot(root, 'nested-marker-target', PROFILE);
  assert.notEqual(expandedBoundary.snapshot.snapshotId, first.snapshot.snapshotId);
  assert.deepEqual(nestedBoundaryPaths(expandedBoundary), [
    'vendor/additional-marker',
    'vendor/gitfile-marker',
    'vendor/repository-marker'
  ]);
});

test('snapshot uses parent Git gitlink evidence to exclude a markerless child checkout', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-snapshot-gitlink-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await initializeRepository(root);
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'src', 'index.ts'), 'export const parent = true;\n');
  await runGit(root, ['add', '--', 'src/index.ts']);
  await runGit(root, ['commit', '-m', 'parent snapshot']);
  const head = (await runGit(root, ['rev-parse', 'HEAD'])).trim();

  const markerlessGitlink = path.join(root, 'vendor', 'module');
  await mkdir(markerlessGitlink, { recursive: true });
  await writeFile(path.join(markerlessGitlink, 'private.ts'), 'export const nested = "first";\n');
  await runGit(root, ['update-index', '--add', '--cacheinfo', `160000,${head},vendor/module`]);

  const discovery = await discoverGitRepository(root);
  assert.equal(discovery.records.find((entry) => entry.path === 'vendor/module')?.kind, 'gitlink');
  const withoutGitEvidence = await buildSnapshot(root, 'gitlink-target', PROFILE);
  assert(withoutGitEvidence.files.some((file) => file.record.path === 'vendor/module/private.ts'));

  const first = await buildSnapshot(root, 'gitlink-target', PROFILE, discovery);
  assert.deepEqual(first.files.map((file) => file.record.path), ['src/index.ts']);
  assert.deepEqual(nestedBoundaryPaths(first), ['vendor/module']);
  await writeFile(path.join(markerlessGitlink, 'private.ts'), 'export const nested = "second";\n');
  const changedChild = await buildSnapshot(root, 'gitlink-target', PROFILE, discovery);
  assert.equal(changedChild.snapshot.snapshotId, first.snapshot.snapshotId);
});

test('explicit include roots cannot traverse an ancestor link into a nested Git target', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-snapshot-linked-include-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const nestedRepository = path.join(root, 'nested-repository');
  await mkdir(path.join(nestedRepository, '.git'), { recursive: true });
  await writeFile(path.join(nestedRepository, 'private.ts'), 'export const nested = true;\n');
  try {
    await symlink(
      nestedRepository,
      path.join(root, 'nested-alias'),
      process.platform === 'win32' ? 'junction' : 'dir'
    );
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'EPERM' || code === 'EACCES' || code === 'ENOTSUP') {
      context.skip(`Filesystem did not permit link creation: ${String(error)}`);
      return;
    }
    throw error;
  }

  const result = await buildSnapshot(root, 'linked-include-target', {
    ...PROFILE,
    includeRoots: ['nested-alias/private.ts'],
    patternExpectations: [{
      id: 'intentionally-boundary-only-linked-file',
      collection: 'includeRoots',
      pattern: 'nested-alias/private.ts',
      minMatches: 0,
      maxMatches: 0
    }]
  });
  assert.deepEqual(result.files, []);
  assert.deepEqual(
    result.diagnostics.map((entry) => ({ code: entry.code, path: entry.path })),
    [{ code: 'SYMLINK_SKIPPED', path: 'nested-alias' }]
  );
});

test('Windows filesystem case cannot bypass a Git-discovered gitlink boundary', {
  skip: process.platform !== 'win32'
}, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-snapshot-gitlink-case-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'Vendor', 'Module'), { recursive: true });
  await writeFile(path.join(root, 'Vendor', 'Module', 'private.ts'), 'export const nested = true;\n');
  const zeroObjectId = '0'.repeat(40);
  const discovery = {
    schemaVersion: 1 as const,
    provider: 'git' as const,
    state: 'ready' as const,
    repository: {
      root: '.' as const,
      objectFormat: 'sha1' as const,
      head: { state: 'detached' as const, objectId: zeroObjectId }
    },
    records: [{
      path: 'vendor/module',
      kind: 'gitlink' as const,
      tracking: 'tracked' as const,
      indexStatus: 'clean' as const,
      worktreeStatus: 'clean' as const,
      conflicted: false,
      indexEntries: [{ mode: '160000', objectId: zeroObjectId, stage: 0 as const }]
    }],
    diagnostics: []
  };

  const result = await buildSnapshot(root, 'gitlink-case-target', {
    ...PROFILE,
    patternExpectations: [{
      id: 'intentionally-boundary-only-root',
      collection: 'includeRoots',
      pattern: '.',
      minMatches: 0,
      maxMatches: 0
    }]
  }, discovery);
  assert.deepEqual(result.files, []);
  assert.deepEqual(nestedBoundaryPaths(result), ['vendor/module']);
});
