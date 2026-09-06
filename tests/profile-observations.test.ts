import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadConfiguration } from '../src/config.js';
import { AtlasError } from '../src/errors.js';
import { buildSnapshot } from '../src/snapshot.js';
import type { ResolvedProfile } from '../src/types.js';

function profile(overrides: Partial<ResolvedProfile> = {}): ResolvedProfile {
  return {
    schemaVersion: 1,
    id: 'profile-observation-fixture',
    includeRoots: ['.'],
    exclude: [],
    explicitExclude: [],
    entrypoints: [],
    aliases: {},
    envExampleFiles: [],
    platformRoots: [],
    deadCodeExemptions: [],
    fixturePatterns: [],
    loaderRules: [],
    patternExpectations: [],
    ruleExpectations: [],
    lifecycleRules: [],
    maxFileBytes: 1_000_000,
    ...overrides
  };
}

test('profile expectations count authored exclusions before pruning', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-profile-observation-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'reports', 'nested'), { recursive: true });
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'reports', 'one.json'), '{}\n');
  await writeFile(path.join(root, 'reports', 'nested', 'two.json'), '{}\n');
  await writeFile(path.join(root, 'src', 'index.ts'), 'export {};\n');

  const result = await buildSnapshot(root, 'target', profile({
    exclude: ['reports/**'],
    explicitExclude: ['reports/**'],
    patternExpectations: [{
      id: 'generated-reports',
      collection: 'exclude',
      pattern: 'reports/**',
      minMatches: 2,
      maxMatches: 2
    }]
  }));

  assert.deepEqual(result.files.map((file) => file.record.path), ['src/index.ts']);
  assert.deepEqual(result.profileObservations.find((entry) => entry.id === 'generated-reports'), {
    id: 'generated-reports',
    collection: 'exclude',
    pattern: 'reports/**',
    minMatches: 2,
    maxMatches: 2,
    actualMatches: 2,
    status: 'passed',
    samplePaths: ['reports/nested/two.json', 'reports/one.json']
  });
  assert(result.profileObservations.some((entry) => entry.id.startsWith('atlas:required-include-root:') && entry.status === 'passed'));
});

test('automatic exclusion controls census excluded directory contents without a hand-written expectation', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-auto-exclude-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'reports', 'nested'), { recursive: true });
  await mkdir(path.join(root, 'archive'), { recursive: true });
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'reports', 'nested', 'result.json'), '{}\n');
  await writeFile(path.join(root, 'archive', 'result.json'), '{}\n');
  await writeFile(path.join(root, 'src', 'index.ts'), 'export {};\n');

  const result = await buildSnapshot(root, 'target', profile({
    exclude: ['archive', 'reports/**'],
    explicitExclude: ['archive', 'reports/**']
  }));

  const observation = result.profileObservations.find((entry) => (
    entry.collection === 'exclude' && entry.pattern === 'reports/**'
  ));
  assert.equal(observation?.status, 'passed');
  assert.equal(observation?.actualMatches, 1);
  assert.deepEqual(observation?.samplePaths, ['reports/nested/result.json']);
  const exactDirectoryObservation = result.profileObservations.find((entry) => (
    entry.collection === 'exclude' && entry.pattern === 'archive'
  ));
  assert.equal(exactDirectoryObservation?.status, 'passed');
  assert.equal(exactDirectoryObservation?.actualMatches, 1);
  assert.deepEqual(exactDirectoryObservation?.samplePaths, ['archive/result.json']);
});

test('required zero-match and overbroad profile patterns stop snapshot publication', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-profile-failure-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'src', 'one.ts'), 'export {};\n');
  await writeFile(path.join(root, 'src', 'two.ts'), 'export {};\n');

  await assert.rejects(
    buildSnapshot(root, 'target', profile({
      deadCodeExemptions: ['src/migrations/**']
    })),
    (error: unknown) => error instanceof AtlasError && error.code === 'PROFILE_PATTERN_ZERO_MATCH'
  );

  for (const missing of [
    { exclude: ['reports/**'], explicitExclude: ['reports/**'] },
    { entrypoints: ['src/missing-entry.ts'] },
    { fixturePatterns: ['tests/fixtures/*.fixture.ts'] },
    { operationalRisks: { guardPaths: ['src/missing-guards/**'], seedDictionarySources: [] } }
  ]) {
    await assert.rejects(
      buildSnapshot(root, 'target', profile(missing)),
      (error: unknown) => error instanceof AtlasError && error.code === 'PROFILE_PATTERN_ZERO_MATCH'
    );
  }

  const optedOut = await buildSnapshot(root, 'target', profile({
    exclude: ['reports/**'],
    explicitExclude: ['reports/**'],
    patternExpectations: [{
      id: 'optional-reports',
      collection: 'exclude',
      pattern: 'reports/**',
      minMatches: 0
    }]
  }));
  assert.equal(optedOut.profileObservations.find((entry) => entry.id === 'optional-reports')?.status, 'passed');

  await assert.rejects(
    buildSnapshot(root, 'target', profile({
      entrypoints: ['src/*.ts'],
      patternExpectations: [{
        id: 'single-entrypoint',
        collection: 'entrypoints',
        pattern: 'src/*.ts',
        minMatches: 1,
        maxMatches: 1
      }]
    })),
    (error: unknown) => error instanceof AtlasError && error.code === 'PROFILE_PATTERN_COUNT_MISMATCH'
  );
});

test('empty or fully excluded include roots do not satisfy required coverage', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-empty-include-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'empty'));
  await mkdir(path.join(root, 'excluded'));
  await writeFile(path.join(root, 'excluded', 'only.ts'), 'export {};\n');

  await assert.rejects(
    buildSnapshot(root, 'target', profile({ includeRoots: ['empty'] })),
    (error: unknown) => error instanceof AtlasError && error.code === 'PROFILE_PATTERN_ZERO_MATCH'
  );
  await assert.rejects(
    buildSnapshot(root, 'target', profile({
      includeRoots: ['excluded'],
      exclude: ['excluded/**'],
      explicitExclude: ['excluded/**']
    })),
    (error: unknown) => error instanceof AtlasError && error.code === 'PROFILE_PATTERN_ZERO_MATCH'
  );
});

test('every pattern in a required loader rule receives an automatic nonzero control', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-required-loader-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'src', 'models'), { recursive: true });
  await writeFile(path.join(root, 'src', 'models', 'index.js'), 'module.exports = {};\n');
  await writeFile(path.join(root, 'src', 'models', 'user.js'), 'module.exports = {};\n');

  await assert.rejects(
    buildSnapshot(root, 'target', profile({
      includeRoots: ['src'],
      loaderRules: [{
        id: 'mixed-loader',
        kind: 'sequelize-models',
        loaderPaths: ['src/models/index.js', 'src/models/missing.js'],
        loadedPatterns: ['src/models/*.js', 'src/missing-models/*.js'],
        scope: 'production',
        required: true
      }]
    })),
    (error: unknown) => error instanceof AtlasError && error.code === 'PROFILE_PATTERN_ZERO_MATCH'
  );
});

test('configuration rejects expectations that do not own a configured pattern', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-profile-config-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  await mkdir(targetRoot);
  const targetPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeFile(targetPath, JSON.stringify({
    schemaVersion: 1,
    id: 'target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }));
  await writeFile(profilePath, JSON.stringify({
    schemaVersion: 1,
    id: 'profile',
    includeRoots: ['.'],
    patternExpectations: [{
      id: 'typo',
      collection: 'entrypoints',
      pattern: 'src/missing.ts',
      minMatches: 1
    }]
  }));

  await assert.rejects(
    loadConfiguration(targetPath, profilePath),
    (error: unknown) => error instanceof AtlasError && error.code === 'INVALID_CONFIG'
  );
});

test('configuration rejects rule expectations outside the operational catalog', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-rule-expectation-config-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  await mkdir(targetRoot);
  await writeFile(path.join(targetRoot, 'index.ts'), 'export {};\n');
  const targetPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeFile(targetPath, JSON.stringify({
    schemaVersion: 1,
    id: 'target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }));
  await writeFile(profilePath, JSON.stringify({
    schemaVersion: 1,
    id: 'profile',
    includeRoots: ['.'],
    ruleExpectations: [{ ruleId: 'contract/not-a-catalogued-rule-v1', minFindings: 1 }]
  }));

  await assert.rejects(
    loadConfiguration(targetPath, profilePath),
    (error: unknown) => error instanceof AtlasError && error.code === 'INVALID_CONFIG'
  );
});
