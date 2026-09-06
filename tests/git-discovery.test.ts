import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { discoverGitRepository } from '../src/discovery/index.js';
import { lookupMemory, scanProject, verifyRunDirectory } from '../src/index.js';
import type { GitPathRecord } from '../src/discovery/index.js';
import type { GitDiscoveryResult } from '../src/discovery/types.js';
import { readJson, writeCanonicalJson } from '../src/util/canonical.js';

const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

function runGit(
  repositoryPath: string,
  command: string[],
  acceptedExitCodes: number[] = [0]
): Promise<{ exitCode: number; stdout: string }> {
  const argumentsList = [
    '-c', 'user.name=Atlas Tests',
    '-c', 'user.email=atlas-tests@example.invalid',
    '-c', 'commit.gpgSign=false',
    '-c', `core.hooksPath=${NULL_DEVICE}`,
    '-C', repositoryPath,
    ...command
  ];
  return new Promise((resolve, reject) => {
    execFile('git', argumentsList, {
      encoding: 'utf8',
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' },
      windowsHide: true
    }, (error, stdout) => {
      const processError = error as (Error & { code?: unknown }) | null;
      const exitCode = processError && typeof processError.code === 'number'
        ? processError.code
        : error ? -1 : 0;
      if (!acceptedExitCodes.includes(exitCode)) {
        reject(error ?? new Error(`Git exited with ${exitCode}.`));
        return;
      }
      resolve({ exitCode, stdout });
    });
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

function byPath(records: GitPathRecord[]): Map<string, GitPathRecord> {
  return new Map(records.map((record) => [record.path, record]));
}

async function assertMissing(value: string): Promise<void> {
  await assert.rejects(stat(value), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
}

test('Git discovery returns deterministic portable provenance for worktree and index states', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-git-discovery-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await initializeRepository(root);
  await writeFile(path.join(root, '.gitignore'), '*.log\nignored-directory/\n', 'utf8');
  await writeFile(path.join(root, 'clean.txt'), 'clean\n', 'utf8');
  await writeFile(path.join(root, 'modified.txt'), 'before\n', 'utf8');
  await writeFile(path.join(root, 'deleted.txt'), 'delete me\n', 'utf8');
  await writeFile(path.join(root, 'old-name.txt'), 'rename me\n', 'utf8');
  await writeFile(path.join(root, 'conflict.txt'), 'base\n', 'utf8');
  await runGit(root, ['add', '--', '.gitignore', 'clean.txt', 'modified.txt', 'deleted.txt', 'old-name.txt', 'conflict.txt']);
  await runGit(root, ['commit', '-m', 'base']);

  await runGit(root, ['checkout', '-b', 'side']);
  await writeFile(path.join(root, 'conflict.txt'), 'side\n', 'utf8');
  await runGit(root, ['add', '--', 'conflict.txt']);
  await runGit(root, ['commit', '-m', 'side']);
  await runGit(root, ['checkout', 'main']);
  await writeFile(path.join(root, 'conflict.txt'), 'main\n', 'utf8');
  await runGit(root, ['add', '--', 'conflict.txt']);
  await runGit(root, ['commit', '-m', 'main']);
  await runGit(root, ['merge', '--no-edit', 'side'], [0, 1]);

  await writeFile(path.join(root, 'modified.txt'), 'after\n', 'utf8');
  await rm(path.join(root, 'deleted.txt'));
  await runGit(root, ['mv', '--', 'old-name.txt', 'renamed.txt']);
  await writeFile(path.join(root, 'untracked.txt'), 'new\n', 'utf8');
  await writeFile(path.join(root, 'ignored.log'), 'ignored\n', 'utf8');
  await mkdir(path.join(root, 'untracked-directory'));
  await writeFile(path.join(root, 'untracked-directory', 'nested.txt'), 'untracked nested\n', 'utf8');
  await mkdir(path.join(root, 'ignored-directory'));
  await writeFile(path.join(root, 'ignored-directory', 'nested.txt'), 'ignored nested\n', 'utf8');
  const head = (await runGit(root, ['rev-parse', 'HEAD'])).stdout.trim();
  await runGit(root, ['update-index', '--add', '--cacheinfo', `160000,${head},vendor/module`]);

  const first = await discoverGitRepository(root);
  const second = await discoverGitRepository(root);
  assert.deepEqual(second, first);
  assert.equal(first.state, 'ready');
  assert.deepEqual(first.diagnostics, []);
  assert.equal(first.repository?.root, '.');
  assert.equal(first.repository?.objectFormat, head.length === 64 ? 'sha256' : 'sha1');
  assert.deepEqual(first.repository?.head, { state: 'attached', objectId: head, branch: 'main' });

  const records = byPath(first.records);
  assert.deepEqual(
    { index: records.get('clean.txt')?.indexStatus, worktree: records.get('clean.txt')?.worktreeStatus },
    { index: 'clean', worktree: 'clean' }
  );
  assert.deepEqual(
    { index: records.get('modified.txt')?.indexStatus, worktree: records.get('modified.txt')?.worktreeStatus },
    { index: 'clean', worktree: 'modified' }
  );
  assert.equal(records.get('deleted.txt')?.worktreeStatus, 'deleted');
  assert.deepEqual(
    {
      index: records.get('renamed.txt')?.indexStatus,
      worktree: records.get('renamed.txt')?.worktreeStatus,
      from: records.get('renamed.txt')?.originalPath,
      similarity: records.get('renamed.txt')?.similarity
    },
    { index: 'renamed', worktree: 'clean', from: 'old-name.txt', similarity: 100 }
  );
  assert.deepEqual(
    {
      index: records.get('conflict.txt')?.indexStatus,
      worktree: records.get('conflict.txt')?.worktreeStatus,
      conflicted: records.get('conflict.txt')?.conflicted,
      stages: records.get('conflict.txt')?.indexEntries.map((entry) => entry.stage)
    },
    { index: 'unmerged', worktree: 'unmerged', conflicted: true, stages: [1, 2, 3] }
  );
  assert.deepEqual(
    {
      kind: records.get('vendor/module')?.kind,
      mode: records.get('vendor/module')?.indexEntries[0]?.mode,
      objectId: records.get('vendor/module')?.indexEntries[0]?.objectId
    },
    { kind: 'gitlink', mode: '160000', objectId: head }
  );
  assert.deepEqual(
    { tracking: records.get('untracked.txt')?.tracking, worktree: records.get('untracked.txt')?.worktreeStatus },
    { tracking: 'untracked', worktree: 'untracked' }
  );
  assert.deepEqual(
    { tracking: records.get('ignored.log')?.tracking, worktree: records.get('ignored.log')?.worktreeStatus },
    { tracking: 'ignored', worktree: 'ignored' }
  );
  assert.deepEqual(
    { kind: records.get('untracked-directory')?.kind, tracking: records.get('untracked-directory')?.tracking },
    { kind: 'directory', tracking: 'untracked' }
  );
  assert.deepEqual(
    { kind: records.get('ignored-directory')?.kind, tracking: records.get('ignored-directory')?.tracking },
    { kind: 'directory', tracking: 'ignored' }
  );
  assert(!records.has('untracked-directory/nested.txt'));
  assert(!records.has('ignored-directory/nested.txt'));
  assert(!first.records.some((record) => record.path === 'old-name.txt'));
  assert(first.records.every((record, index, values) => index === 0 || values[index - 1]!.path < record.path));

  const serialized = JSON.stringify(first);
  const escapedRoot = JSON.stringify(path.resolve(root)).slice(1, -1);
  assert(!serialized.includes(path.resolve(root)));
  assert(!serialized.includes(escapedRoot));
});

for (const executableName of ['git.com', 'git.exe']) {
  test(`Git discovery never executes a target-root ${executableName} on Windows`, {
    skip: !hasGit || process.platform !== 'win32'
  }, async (context) => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-git-executable-boundary-'));
    context.after(async () => rm(root, { recursive: true, force: true }));
    await initializeRepository(root);
    await writeFile(path.join(root, 'tracked.txt'), 'tracked\n', 'utf8');
    await runGit(root, ['add', '--', 'tracked.txt']);
    await runGit(root, ['commit', '-m', 'initial']);

    const marker = path.join(root, 'target-git-executed.txt');
    const loader = path.join(root, 'target-git-loader.cjs');
    await writeFile(
      loader,
      "require('node:fs').writeFileSync(process.env.ATLAS_GIT_EXEC_MARKER, 'executed');\n",
      'utf8'
    );
    await copyFile(process.execPath, path.join(root, executableName));

    const originalNodeOptions = process.env.NODE_OPTIONS;
    const originalMarker = process.env.ATLAS_GIT_EXEC_MARKER;
    try {
      process.env.NODE_OPTIONS = `--require=${loader}`;
      process.env.ATLAS_GIT_EXEC_MARKER = marker;
      const result = await discoverGitRepository(root);
      assert.equal(result.state, 'ready');
      await assertMissing(marker);
    } finally {
      if (originalNodeOptions === undefined) delete process.env.NODE_OPTIONS;
      else process.env.NODE_OPTIONS = originalNodeOptions;
      if (originalMarker === undefined) delete process.env.ATLAS_GIT_EXEC_MARKER;
      else process.env.ATLAS_GIT_EXEC_MARKER = originalMarker;
    }
  });
}

test('Git discovery disables repository-configured fsmonitor and optional index writes', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-git-fsmonitor-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await initializeRepository(root);
  await writeFile(path.join(root, 'tracked.txt'), 'tracked\n', 'utf8');
  await runGit(root, ['add', '--', 'tracked.txt']);
  await runGit(root, ['commit', '-m', 'initial']);

  const marker = path.join(root, 'fsmonitor-invoked.txt');
  const helper = path.join(root, process.platform === 'win32' ? 'fsmonitor.cmd' : 'fsmonitor.sh');
  if (process.platform === 'win32') {
    await writeFile(helper, '@echo off\r\n> "%~dp0fsmonitor-invoked.txt" echo invoked\r\n', 'utf8');
  } else {
    await writeFile(helper, '#!/bin/sh\nprintf invoked > "$(dirname "$0")/fsmonitor-invoked.txt"\nprintf "{}"\n', 'utf8');
    await chmod(helper, 0o755);
  }
  await runGit(root, ['config', 'core.fsmonitor', helper]);
  const before = await stat(path.join(root, '.git', 'index'), { bigint: true });
  const result = await discoverGitRepository(root);
  const after = await stat(path.join(root, '.git', 'index'), { bigint: true });

  assert.equal(result.state, 'ready');
  await assertMissing(marker);
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeNs, before.mtimeNs);
});

test('Git discovery refuses tracked status when an external content filter is configured', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-git-filter-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await initializeRepository(root);
  await writeFile(path.join(root, '.gitattributes'), 'payload.txt filter=evil\n', 'utf8');
  await writeFile(path.join(root, 'payload.txt'), 'payload\n', 'utf8');
  await runGit(root, ['add', '--', '.gitattributes', 'payload.txt']);
  await runGit(root, ['commit', '-m', 'initial']);

  const marker = path.join(root, 'filter-invoked.txt');
  const helper = path.join(root, process.platform === 'win32' ? 'evil-filter.cmd' : 'evil-filter.sh');
  if (process.platform === 'win32') {
    await writeFile(helper, '@echo off\r\n> "%~dp0filter-invoked.txt" echo invoked\r\nmore\r\n', 'utf8');
  } else {
    await writeFile(helper, '#!/bin/sh\nprintf invoked > "$(dirname "$0")/filter-invoked.txt"\ncat\n', 'utf8');
    await chmod(helper, 0o755);
  }
  await runGit(root, ['config', 'filter.evil.process', helper]);

  const result = await discoverGitRepository(root);
  assert.equal(result.state, 'partial');
  assert(result.diagnostics.some((entry) => entry.code === 'GIT_EXTERNAL_FILTER_STATUS_UNAVAILABLE'));
  const payload = byPath(result.records).get('payload.txt');
  assert.equal(payload?.tracking, 'tracked');
  assert.equal(payload?.indexStatus, 'unknown');
  assert.equal(payload?.worktreeStatus, 'unknown');
  await assertMissing(marker);
});

test('Git discovery explicitly distinguishes non-Git, bare, unborn, and detached targets', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-git-boundaries-'));
  context.after(async () => rm(root, { recursive: true, force: true }));

  const plain = path.join(root, 'plain');
  await mkdir(plain);
  const nonGit = await discoverGitRepository(plain);
  assert.equal(nonGit.state, 'not-git');
  assert.deepEqual(nonGit.diagnostics.map((entry) => entry.code), ['GIT_NOT_REPOSITORY']);

  const bare = path.join(root, 'bare.git');
  await mkdir(bare);
  await runGit(bare, ['init', '--bare']);
  const unsupportedBare = await discoverGitRepository(bare);
  assert.equal(unsupportedBare.state, 'unsupported');
  assert.deepEqual(unsupportedBare.diagnostics.map((entry) => entry.code), ['GIT_BARE_REPOSITORY_UNSUPPORTED']);

  const unbornRoot = path.join(root, 'unborn');
  await initializeRepository(unbornRoot);
  const unborn = await discoverGitRepository(unbornRoot);
  assert.equal(unborn.state, 'ready');
  assert.deepEqual(unborn.repository?.head, { state: 'unborn', branch: 'main' });

  await writeFile(path.join(unbornRoot, 'tracked.txt'), 'tracked\n', 'utf8');
  await runGit(unbornRoot, ['add', '--', 'tracked.txt']);
  await runGit(unbornRoot, ['commit', '-m', 'initial']);
  const head = (await runGit(unbornRoot, ['rev-parse', 'HEAD'])).stdout.trim();
  await runGit(unbornRoot, ['checkout', '--detach', head]);
  const detached = await discoverGitRepository(unbornRoot);
  assert.deepEqual(detached.repository?.head, { state: 'detached', objectId: head });
});

test('scan identity and verification bind the complete Git discovery ledger', { skip: !hasGit }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-git-run-binding-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const repository = path.join(root, 'repository');
  await initializeRepository(repository);
  await mkdir(path.join(repository, 'src'));
  await writeFile(path.join(repository, 'src', 'index.ts'), 'export const stable = true;\n');
  await runGit(repository, ['add', '--', 'src/index.ts']);
  await runGit(repository, ['commit', '-m', 'stable snapshot']);
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'git-bound-target',
    path: './repository',
    consent: { agentReview: false, export: false, projectMemory: true }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'git-bound-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  });

  const main = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath: path.join(root, 'workspace-main')
  });
  await runGit(repository, ['switch', '-c', 'alternate']);
  const alternate = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath: path.join(root, 'workspace-alternate')
  });

  assert.equal(main.run.snapshotId, alternate.run.snapshotId);
  assert.notEqual(main.run.runId, alternate.run.runId);
  assert.notEqual(main.run.discovery.digest, alternate.run.discovery.digest);
  const mainDiscovery = await readJson<GitDiscoveryResult>(path.join(main.runDirectory, 'discovery.json'));
  const alternateDiscovery = await readJson<GitDiscoveryResult>(path.join(alternate.runDirectory, 'discovery.json'));
  assert.equal(mainDiscovery.repository?.head.branch, 'main');
  assert.equal(alternateDiscovery.repository?.head.branch, 'alternate');
  const staleMemory = await lookupMemory({
    runDirectory: main.runDirectory,
    workspacePath: path.join(root, 'workspace-main'),
    targetConfigPath,
    profilePath,
    query: 'stable'
  });
  assert.equal(staleMemory.freshness.status, 'stale');
  assert.deepEqual(staleMemory.freshness.reasons, ['git-provenance']);
  assert.equal((await verifyRunDirectory(main.runDirectory)).status, 'passed');
  assert.equal((await verifyRunDirectory(alternate.runDirectory)).status, 'passed');
});
