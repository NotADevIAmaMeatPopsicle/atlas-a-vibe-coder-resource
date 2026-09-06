import assert from 'node:assert/strict';
import { link, mkdir, mkdtemp, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  listTargetRegistrations,
  loadTargetRegistration,
  registerTarget,
  scanProject
} from '../src/index.js';
import { AtlasError } from '../src/errors.js';
import { verifyTargetRegistrationBinding } from '../src/targets.js';
import { readJson } from '../src/util/canonical.js';

async function writeTarget(root: string, name: string, id: string): Promise<{
  targetRoot: string;
  targetConfigPath: string;
}> {
  const targetRoot = path.join(root, name);
  const targetConfigPath = path.join(root, `${name}.target.json`);
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await writeFile(path.join(targetRoot, 'src', 'index.ts'), 'export const ready = true;\n');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id,
    path: `./${name}`,
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`);
  return { targetRoot, targetConfigPath };
}

test('target registrations are immutable, canonical, and deterministically listed', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-targets-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const firstTarget = await writeTarget(root, 'first', 'shared-id');
  const secondTarget = await writeTarget(root, 'second', 'shared-id');
  const workspacePath = path.join(root, 'workspace');

  const first = await registerTarget({
    targetConfigPath: firstTarget.targetConfigPath,
    workspacePath
  });
  assert.equal(first.reused, false);
  assert.equal(first.registration.targetRoot, await realpath(firstTarget.targetRoot));
  assert.equal(first.registration.targetConfigPath, await realpath(firstTarget.targetConfigPath));

  const reused = await registerTarget({
    targetConfigPath: firstTarget.targetConfigPath,
    workspacePath
  });
  assert.equal(reused.reused, true);
  assert.deepEqual(reused.registration, first.registration);
  assert.deepEqual(await listTargetRegistrations(workspacePath), [first.registration]);
  assert.deepEqual(await loadTargetRegistration(workspacePath, 'shared-id'), first.registration);

  await assert.rejects(
    registerTarget({ targetConfigPath: secondTarget.targetConfigPath, workspacePath }),
    (error: unknown) => (error as { code?: string }).code === 'TARGET_REGISTRATION_CONFLICT'
  );
  assert.deepEqual(await listTargetRegistrations(workspacePath), [first.registration]);
});

test('scans register their target before publishing a run', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-scan-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const target = await writeTarget(root, 'project', 'scan-target');
  const profilePath = path.join(root, 'profile.json');
  const workspacePath = path.join(root, 'workspace');
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'source-only',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  }, null, 2)}\n`);

  const result = await scanProject({
    targetConfigPath: target.targetConfigPath,
    profilePath,
    workspacePath
  });
  const registration = await loadTargetRegistration(workspacePath, 'scan-target');
  const stored = await readJson<unknown>(path.join(workspacePath, 'targets', 'scan-target', 'registration.json'));
  assert.equal(result.run.targetId, registration.targetId);
  assert.deepEqual(stored, registration);
});

test('target registration rejects a workspace inside the target', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-boundary-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const target = await writeTarget(root, 'project', 'inside-test');
  await assert.rejects(
    registerTarget({
      targetConfigPath: target.targetConfigPath,
      workspacePath: path.join(target.targetRoot, '.atlas-workspace')
    }),
    (error: unknown) => (error as { code?: string }).code === 'WORKSPACE_INSIDE_TARGET'
  );
});

test('target registration rejects an operator-consent descriptor inside the untrusted target', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-descriptor-boundary-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(path.join(targetRoot, 'config'), { recursive: true });
  const targetConfigPath = path.join(targetRoot, 'config', 'target.json');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'target-owned-consent',
    path: '..',
    consent: { agentReview: true, export: true, projectMemory: true }
  }, null, 2)}\n`);

  await assert.rejects(
    registerTarget({ targetConfigPath, workspacePath }),
    (error: unknown) => error instanceof AtlasError && error.code === 'TARGET_DESCRIPTOR_INSIDE_TARGET'
  );
  await assert.rejects(stat(path.join(workspacePath, 'targets')), /ENOENT/);
});

test('target registration rejects a target-owned junction alias to an external descriptor', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-descriptor-alias-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const policyRoot = path.join(root, 'policy');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(targetRoot);
  await mkdir(policyRoot);
  const externalDescriptor = path.join(policyRoot, 'target.json');
  await writeFile(externalDescriptor, `${JSON.stringify({
    schemaVersion: 1,
    id: 'aliased-consent',
    path: targetRoot,
    consent: { agentReview: true, export: true, projectMemory: true }
  }, null, 2)}\n`);
  const targetOwnedAlias = path.join(targetRoot, 'policy-link');
  await symlink(policyRoot, targetOwnedAlias, process.platform === 'win32' ? 'junction' : 'dir');

  await assert.rejects(
    registerTarget({ targetConfigPath: path.join(targetOwnedAlias, 'target.json'), workspacePath }),
    (error: unknown) => error instanceof AtlasError && error.code === 'TARGET_DESCRIPTOR_INSIDE_TARGET'
  );
});

test('legacy target-owned registrations are rejected when a bound operation revalidates them', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-descriptor-legacy-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  const targetId = 'legacy-target-owned-consent';
  await mkdir(targetRoot);
  const targetConfigPath = path.join(targetRoot, 'target.json');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: targetId,
    path: '.',
    consent: { agentReview: true, export: true, projectMemory: true }
  }, null, 2)}\n`);
  const registrationDirectory = path.join(workspacePath, 'targets', targetId);
  await mkdir(registrationDirectory, { recursive: true });
  await writeFile(path.join(registrationDirectory, 'registration.json'), `${JSON.stringify({
    schemaVersion: 1,
    targetId,
    targetRoot: await realpath(targetRoot),
    targetConfigPath: await realpath(targetConfigPath),
    consent: { agentReview: true, export: true, projectMemory: true }
  }, null, 2)}\n`);

  await assert.rejects(
    verifyTargetRegistrationBinding({
      workspacePath,
      targetId,
      targetRoot,
      targetConfigPath,
      consent: { agentReview: true, export: true, projectMemory: true }
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'TARGET_DESCRIPTOR_INSIDE_TARGET'
  );
});

test('registration rejects a descriptor with a target-controlled hard-link alias', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-descriptor-hardlink-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const target = await writeTarget(root, 'target', 'hard-linked-consent');
  await link(target.targetConfigPath, path.join(target.targetRoot, 'consent-alias.json'));

  await assert.rejects(
    registerTarget({ targetConfigPath: target.targetConfigPath, workspacePath: path.join(root, 'workspace') }),
    (error: unknown) => error instanceof AtlasError && error.code === 'TARGET_DESCRIPTOR_MULTIPLE_LINKS'
  );
});

test('registered consent is a maximum that target-controlled edits cannot escalate', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-target-consent-escalation-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const repositoryRoot = path.join(root, 'repository');
  const targetRoot = path.join(repositoryRoot, 'src');
  const targetConfigPath = path.join(repositoryRoot, 'target.json');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(path.join(repositoryRoot, '.git'), { recursive: true });
  await mkdir(targetRoot);
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'nested-target-consent',
    path: './src',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`);
  const registered = await registerTarget({ targetConfigPath, workspacePath });
  assert.deepEqual(registered.registration.consent, {
    agentReview: false,
    export: false,
    projectMemory: false
  });

  const escalatedConsent = { agentReview: true, export: true, projectMemory: true };
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'nested-target-consent',
    path: './src',
    consent: escalatedConsent
  }, null, 2)}\n`);
  await assert.rejects(
    verifyTargetRegistrationBinding({
      workspacePath,
      targetId: 'nested-target-consent',
      targetRoot,
      targetConfigPath,
      consent: escalatedConsent
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'TARGET_CONSENT_ESCALATION'
  );
});
