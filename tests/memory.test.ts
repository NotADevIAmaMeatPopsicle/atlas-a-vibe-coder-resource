import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { handleMemoryServiceRequest, lookupMemory, scanProject } from '../src/index.js';

async function fixture(projectMemory = true): Promise<{
  root: string;
  targetRoot: string;
  targetConfigPath: string;
  profilePath: string;
  workspacePath: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-memory-'));
  const targetRoot = path.join(root, 'target');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await writeFile(path.join(targetRoot, 'src', 'index.ts'), [
    "import { format } from './format.js';",
    'export const ready = format("ready");',
    ''
  ].join('\n'));
  await writeFile(path.join(targetRoot, 'src', 'format.ts'), 'export const format = (value: string) => value;\n');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'memory-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory }
  }, null, 2)}\n`);
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'memory-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  }, null, 2)}\n`);
  return { root, targetRoot, targetConfigPath, profilePath, workspacePath };
}

test('memory lookup is cited, target-bound, and reports byte freshness', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: value.targetConfigPath,
    profilePath: value.profilePath,
    workspacePath: value.workspacePath
  });
  const scope = {
    runDirectory: scan.runDirectory,
    workspacePath: value.workspacePath,
    targetConfigPath: value.targetConfigPath,
    profilePath: value.profilePath
  };

  const current = await lookupMemory({ ...scope, query: 'ready', limit: 5 });
  assert.equal(current.targetId, 'memory-target');
  assert.equal(current.freshness.status, 'current');
  assert.equal(current.authorization.sourceContentIncluded, false);
  assert.equal(current.authorization.secretValuesCollected, false);
  assert.equal(current.authorization.projectMemoryConsent, true);
  assert.equal(current.answer.kind, 'matches');
  assert(current.hits.length > 0);
  assert(current.hits.every((hit) => hit.evidence.length > 0));

  await writeFile(path.join(value.targetRoot, 'src', 'index.ts'), 'export const changed = true;\n');
  const stale = await lookupMemory({ ...scope, query: 'ready' });
  assert.equal(stale.freshness.status, 'stale');
  assert.deepEqual(stale.freshness.changedPaths, ['src/index.ts']);
  assert(stale.answer.text.includes('stale'));
});

test('the stdio request contract cannot change its fixed target scope', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: value.targetConfigPath,
    profilePath: value.profilePath,
    workspacePath: value.workspacePath
  });
  const scope = {
    runDirectory: scan.runDirectory,
    workspacePath: value.workspacePath,
    targetConfigPath: value.targetConfigPath,
    profilePath: value.profilePath
  };
  const response = await handleMemoryServiceRequest(scope, {
    id: 'request-1',
    method: 'memory.lookup',
    params: { query: 'format', limit: 2 }
  });
  assert.equal(response.id, 'request-1');
  assert.equal(response.result.targetId, 'memory-target');

  await assert.rejects(
    handleMemoryServiceRequest(scope, {
      id: 'request-2',
      method: 'memory.lookup',
      params: { query: 'format', targetConfigPath: 'another-target.json' }
    }),
    (error: unknown) => (error as { code?: string }).code === 'INVALID_MEMORY_REQUEST'
  );
});

test('memory lookup rejects a descriptor rebound to the same target ID', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: value.targetConfigPath,
    profilePath: value.profilePath,
    workspacePath: value.workspacePath
  });
  const otherTarget = path.join(value.root, 'other-target');
  const otherConfig = path.join(value.root, 'other-target.json');
  await mkdir(path.join(otherTarget, 'src'), { recursive: true });
  await writeFile(path.join(otherTarget, 'src', 'index.ts'), 'export const impostor = true;\n');
  await writeFile(otherConfig, `${JSON.stringify({
    schemaVersion: 1,
    id: 'memory-target',
    path: './other-target',
    consent: { agentReview: false, export: false, projectMemory: true }
  }, null, 2)}\n`);

  await assert.rejects(
    lookupMemory({
      runDirectory: scan.runDirectory,
      workspacePath: value.workspacePath,
      targetConfigPath: otherConfig,
      profilePath: value.profilePath,
      query: 'impostor'
    }),
    (error: unknown) => (error as { code?: string }).code === 'TARGET_REGISTRATION_CONFLICT'
  );
});

test('memory lookup is deny-by-default without dedicated target consent', async (context) => {
  const value = await fixture(false);
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: value.targetConfigPath,
    profilePath: value.profilePath,
    workspacePath: value.workspacePath
  });
  await assert.rejects(
    lookupMemory({
      runDirectory: scan.runDirectory,
      workspacePath: value.workspacePath,
      targetConfigPath: value.targetConfigPath,
      profilePath: value.profilePath,
      query: 'ready'
    }),
    (error: unknown) => (error as { code?: string }).code === 'MEMORY_NOT_AUTHORIZED'
  );
});
