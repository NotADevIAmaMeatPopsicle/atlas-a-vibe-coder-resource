import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadConfiguration } from '../src/config.js';
import { profileDigest } from '../src/identity.js';
import { scanProject } from '../src/run.js';
import { assertSchema } from '../src/schema-validator.js';
import { buildSnapshot } from '../src/snapshot.js';
import { canonicalJson, writeCanonicalJson } from '../src/util/canonical.js';

async function fixture(): Promise<{
  root: string;
  profilePath: string;
  targetConfigPath: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-lifecycle-test-'));
  const target = path.join(root, 'target');
  await mkdir(path.join(target, 'frontends', 'customer-dashboard'), { recursive: true });
  await mkdir(path.join(target, 'frontends', 'legacy-admin'), { recursive: true });
  await mkdir(path.join(target, 'src'), { recursive: true });
  await mkdir(path.join(target, 'docs'), { recursive: true });
  await writeFile(path.join(target, 'frontends', 'customer-dashboard', 'main.ts'), 'export const customer = true;\n');
  await writeFile(path.join(target, 'frontends', 'legacy-admin', 'main.ts'), 'export const portal = true;\n');
  await writeFile(path.join(target, 'src', 'server.ts'), 'export const backend = true;\n');
  await writeFile(path.join(target, 'docs', 'README.md'), '# Lifecycle fixture\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'lifecycle-fixture',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'lifecycle-profile',
    includeRoots: ['.'],
    exclude: [],
    lifecycleRules: [
      { id: 'customer-ui', state: 'active', paths: ['frontends//customer-dashboard'] },
      { id: 'legacy-admin', state: 'mothballed', paths: ['frontends/legacy-admin'] },
      { id: 'shared-backend', state: 'shared', paths: ['src'] }
    ]
  });
  return { root, profilePath, targetConfigPath };
}

test('ordered lifecycle rules normalize deterministically and every snapshot file has an explicit declaration', async (context) => {
  const testFixture = await fixture();
  context.after(async () => rm(testFixture.root, { recursive: true, force: true }));
  const firstConfiguration = await loadConfiguration(testFixture.targetConfigPath, testFixture.profilePath);
  assert.deepEqual(firstConfiguration.profile.lifecycleRules.map((rule) => rule.id), [
    'customer-ui',
    'legacy-admin',
    'shared-backend'
  ]);
  assert.deepEqual(firstConfiguration.profile.lifecycleRules[0]?.paths, ['frontends/customer-dashboard']);

  const first = await buildSnapshot(
    firstConfiguration.targetRoot,
    firstConfiguration.target.id,
    firstConfiguration.profile
  );
  const second = await buildSnapshot(
    firstConfiguration.targetRoot,
    firstConfiguration.target.id,
    firstConfiguration.profile
  );
  assert.equal(canonicalJson(second.snapshot), canonicalJson(first.snapshot));
  assert.equal(
    canonicalJson(second.files.map((file) => file.record)),
    canonicalJson(first.files.map((file) => file.record))
  );

  const files = new Map(first.files.map((file) => [file.record.path, file.record]));
  assert.deepEqual(files.get('frontends/customer-dashboard/main.ts')?.lifecycle, {
    state: 'active',
    basis: 'profile-path-rule',
    ruleId: 'customer-ui',
    uncertainty: 'not-runtime-validated',
    limitation: 'Lifecycle is a static profile declaration and has not been validated against runtime deployment, traffic, or use.'
  });
  assert.equal(files.get('frontends/legacy-admin/main.ts')?.lifecycle?.state, 'mothballed');
  assert.equal(files.get('src/server.ts')?.lifecycle?.state, 'shared');
  assert.deepEqual(files.get('docs/README.md')?.lifecycle, {
    state: 'unspecified',
    basis: 'no-profile-match',
    uncertainty: 'not-runtime-validated',
    limitation: 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.'
  });
  await Promise.all(first.files.map((file) => assertSchema('file', file.record)));
  const legacyFile = structuredClone(first.files[0]!.record);
  delete legacyFile.lifecycle;
  legacyFile.evidence.producerVersion = '1.1.0';
  await assertSchema('file', legacyFile);
  const malformedCurrentFile = structuredClone(first.files[0]!.record);
  delete malformedCurrentFile.lifecycle;
  await assert.rejects(assertSchema('file', malformedCurrentFile), /schema validation.*lifecycle/iu);

  const firstDigest = profileDigest(firstConfiguration.profile);
  await writeCanonicalJson(testFixture.profilePath, {
    schemaVersion: 1,
    id: 'lifecycle-profile',
    includeRoots: ['.'],
    exclude: [],
    lifecycleRules: [...firstConfiguration.profile.lifecycleRules].reverse()
  });
  const reorderedConfiguration = await loadConfiguration(testFixture.targetConfigPath, testFixture.profilePath);
  assert.deepEqual(reorderedConfiguration.profile.lifecycleRules.map((rule) => rule.id), [
    'shared-backend',
    'legacy-admin',
    'customer-ui'
  ]);
  assert.notEqual(profileDigest(reorderedConfiguration.profile), firstDigest);
});

test('configuration rejects lifecycle path rules with equal or ancestor overlaps', async (context) => {
  const testFixture = await fixture();
  context.after(async () => rm(testFixture.root, { recursive: true, force: true }));
  await writeCanonicalJson(testFixture.profilePath, {
    schemaVersion: 1,
    id: 'overlapping-lifecycle-profile',
    includeRoots: ['.'],
    lifecycleRules: [
      { id: 'broad-source', state: 'shared', paths: ['src'] },
      { id: 'specific-source', state: 'active', paths: ['src/server.ts'] }
    ]
  });
  await assert.rejects(
    loadConfiguration(testFixture.targetConfigPath, testFixture.profilePath),
    /Lifecycle paths must not overlap.*src.*src\/server\.ts/u
  );
});

test('scan rejects a whitespace-only lifecycle rule ID before publishing viewer-bound records', async (context) => {
  const testFixture = await fixture();
  context.after(async () => rm(testFixture.root, { recursive: true, force: true }));
  await writeCanonicalJson(testFixture.profilePath, {
    schemaVersion: 1,
    id: 'blank-lifecycle-rule-profile',
    includeRoots: ['.'],
    lifecycleRules: [
      { id: '   ', state: 'active', paths: ['src'] }
    ]
  });

  await assert.rejects(
    scanProject({
      targetConfigPath: testFixture.targetConfigPath,
      profilePath: testFixture.profilePath,
      workspacePath: path.join(testFixture.root, 'workspace')
    }),
    /schema validation.*lifecycleRules.*id|non-whitespace/iu
  );
});
