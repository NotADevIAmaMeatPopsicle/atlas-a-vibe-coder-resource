import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadConfiguration } from '../src/config.js';
import { AtlasError } from '../src/errors.js';

async function writeConfigurationFixture(
  root: string,
  operationalRisks: Record<string, unknown>
): Promise<{ targetPath: string; profilePath: string }> {
  const targetRoot = path.join(root, 'target');
  await mkdir(targetRoot, { recursive: true });
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
    operationalRisks
  }));
  return { targetPath, profilePath };
}

test('operational boundary and protected-writer declarations normalize deterministically', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-operational-profile-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await writeConfigurationFixture(root, {
    guardPaths: ['src//services/**', 'src/services/**'],
    boundaries: [{
      id: 'appointment-boundary',
      module: 'src//services/appointment.service.ts',
      protects: ['writer-z', 'writer-a']
    }],
    protectedWriters: [
      { id: 'writer-z', module: 'src//repositories/z.ts', methods: ['update', 'create'] },
      { id: 'writer-a', module: 'src/repositories/a.ts', methods: ['destroy'] }
    ]
  });

  const { profile } = await loadConfiguration(fixture.targetPath, fixture.profilePath);
  assert.deepEqual(profile.operationalRisks, {
    guardPaths: ['src/services/**'],
    seedDictionarySources: [],
    boundaries: [{
      id: 'appointment-boundary',
      module: 'src/services/appointment.service.ts',
      protects: ['writer-a', 'writer-z']
    }],
    protectedWriters: [
      { id: 'writer-a', module: 'src/repositories/a.ts', methods: ['destroy'] },
      { id: 'writer-z', module: 'src/repositories/z.ts', methods: ['create', 'update'] }
    ]
  });
});

test('operational contracts reject unknown writer references and ambiguous writer methods', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-operational-profile-invalid-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const unknown = await writeConfigurationFixture(root, {
    boundaries: [{ id: 'boundary', module: 'src/boundary.ts', protects: ['missing'] }],
    protectedWriters: [{ id: 'writer', module: 'src/repository.ts', methods: ['create'] }]
  });
  await assert.rejects(
    loadConfiguration(unknown.targetPath, unknown.profilePath),
    (error: unknown) => error instanceof AtlasError && error.code === 'INVALID_CONFIG' && /unknown writer/u.test(error.message)
  );

  const ambiguousRoot = path.join(root, 'ambiguous');
  const ambiguous = await writeConfigurationFixture(ambiguousRoot, {
    boundaries: [{ id: 'boundary', module: 'src/boundary.ts', protects: ['first', 'second'] }],
    protectedWriters: [
      { id: 'first', module: 'src/repository.ts', methods: ['create'] },
      { id: 'second', module: 'src/repository.ts', methods: ['create'] }
    ]
  });
  await assert.rejects(
    loadConfiguration(ambiguous.targetPath, ambiguous.profilePath),
    (error: unknown) => error instanceof AtlasError && error.code === 'INVALID_CONFIG' && /both own/u.test(error.message)
  );
});

test('operational contracts require paired declarations and exact module paths', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-operational-profile-schema-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const unpaired = await writeConfigurationFixture(root, {
    boundaries: [{ id: 'boundary', module: 'src/boundary.ts', protects: ['writer'] }]
  });
  await assert.rejects(
    loadConfiguration(unpaired.targetPath, unpaired.profilePath),
    (error: unknown) => error instanceof AtlasError && error.code === 'SCHEMA_VALIDATION'
  );

  const globRoot = path.join(root, 'glob');
  const glob = await writeConfigurationFixture(globRoot, {
    boundaries: [{ id: 'boundary', module: 'src/services/**', protects: ['writer'] }],
    protectedWriters: [{ id: 'writer', module: 'src/repository.ts', methods: ['create'] }]
  });
  await assert.rejects(
    loadConfiguration(glob.targetPath, glob.profilePath),
    (error: unknown) => error instanceof AtlasError && error.code === 'SCHEMA_VALIDATION'
  );
});
