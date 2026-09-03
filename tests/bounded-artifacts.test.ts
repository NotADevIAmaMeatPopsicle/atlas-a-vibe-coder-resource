import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  createHistoricalEvidenceIndex,
  createRunViewer,
  decodeViewerDataScript,
  scanProject,
  verifyHistoricalEvidenceIndex,
  verifyRunDirectory,
  verifyRunViewer
} from '../src/index.js';
import { AtlasError } from '../src/errors.js';
import { HARD_MAX_FILE_BYTES } from '../src/limits.js';
import {
  MAX_VERIFIER_ARTIFACT_BYTES,
  addToBoundedCount,
  parseBoundedJsonLines,
  readBoundedJsonFile,
  readBoundedDirectoryEntries,
  readBoundedRegularFile
} from '../src/security/bounded-artifacts.js';
import { canonicalJsonLines, prettyCanonicalJson, sha256 } from '../src/util/canonical.js';

function hasCode(code: string): (error: unknown) => boolean {
  return (error) => error instanceof AtlasError && error.code === code;
}

test('bounded artifact primitives accept their limit and reject the next unit', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-bounds-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'four-bytes.txt');
  await writeFile(file, '1234');
  assert.equal((await readBoundedRegularFile(file, {
    maxBytes: 4,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    invalidCode: 'TEST_INVALID',
    label: 'Test file'
  })).toString('utf8'), '1234');
  await assert.rejects(readBoundedRegularFile(file, {
    maxBytes: 3,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    invalidCode: 'TEST_INVALID',
    label: 'Test file'
  }), hasCode('TEST_RESOURCE_LIMIT'));

  const directory = path.join(root, 'directory');
  await mkdir(directory);
  await writeFile(path.join(directory, 'a'), 'a');
  await writeFile(path.join(directory, 'b'), 'b');
  assert.equal((await readBoundedDirectoryEntries(directory, {
    maxEntries: 2,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test directory'
  })).length, 2);
  await assert.rejects(readBoundedDirectoryEntries(directory, {
    maxEntries: 1,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test directory'
  }), hasCode('TEST_RESOURCE_LIMIT'));

  assert.deepEqual(parseBoundedJsonLines('{"n":1}\n{"n":2}\n', {
    maxRecords: 2,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test records'
  }), [{ n: 1 }, { n: 2 }]);
  assert.throws(() => parseBoundedJsonLines('{"n":1}\n{"n":2}\n{"n":3}\n', {
    maxRecords: 2,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test records'
  }), hasCode('TEST_RESOURCE_LIMIT'));
  assert.throws(() => parseBoundedJsonLines('{"nested":{"too":{"far":true}}}\n', {
    maxRecords: 1,
    maxDepth: 1,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test records'
  }), hasCode('TEST_RESOURCE_LIMIT'));

  const json = path.join(root, 'bounded.json');
  await writeFile(json, '{"ok":true}');
  assert.deepEqual(await readBoundedJsonFile(json, {
    maxBytes: 11,
    maxDepth: 2,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    invalidCode: 'TEST_INVALID',
    label: 'Test JSON'
  }), { ok: true });
  await assert.rejects(readBoundedJsonFile(json, {
    maxBytes: 10,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    invalidCode: 'TEST_INVALID',
    label: 'Test JSON'
  }), hasCode('TEST_RESOURCE_LIMIT'));

  assert.equal(addToBoundedCount(1, 1, {
    maxCount: 2,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test aggregate'
  }), 2);
  assert.throws(() => addToBoundedCount(2, 1, {
    maxCount: 2,
    resourceCode: 'TEST_RESOURCE_LIMIT',
    label: 'Test aggregate'
  }), hasCode('TEST_RESOURCE_LIMIT'));

  let deeplyNestedJson = '0';
  for (let depth = 0; depth < 130; depth += 1) deeplyNestedJson = `{"value":${deeplyNestedJson}}`;
  const deeplyNestedViewer = `globalThis.__ATLAS_VIEWER_DATA_B64__="${Buffer.from(deeplyNestedJson).toString('base64')}";\n`;
  assert.throws(() => decodeViewerDataScript(deeplyNestedViewer), hasCode('VIEWER_RESOURCE_LIMIT'));
});

async function createScanFixture(root: string): Promise<{
  runDirectory: string;
  workspacePath: string;
  targetConfigPath: string;
}> {
  const target = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), 'export const answer = 42;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeFile(targetConfigPath, prettyCanonicalJson({
    schemaVersion: 1,
    id: 'bounded-test-target',
    path: './target',
    consent: { agentReview: true, export: true, projectMemory: false }
  }));
  await writeFile(profilePath, prettyCanonicalJson({
    schemaVersion: 1,
    id: 'bounded-test-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    envExampleFiles: [],
    maxFileBytes: 100_000
  }));
  const result = await scanProject({ targetConfigPath, profilePath, workspacePath });
  return { runDirectory: result.runDirectory, workspacePath, targetConfigPath };
}

test('run and viewer verifiers reject oversized manifest claims before artifact reads', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-verifier-limits-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createScanFixture(root);
  const viewerDirectory = path.join(root, 'viewer');
  await createRunViewer({ ...fixture, outputDirectory: viewerDirectory });
  assert.equal((await verifyRunDirectory(fixture.runDirectory)).status, 'passed');
  assert.equal((await verifyRunViewer(viewerDirectory)).status, 'passed');

  const oversizedRun = path.join(root, 'oversized-run');
  await cp(fixture.runDirectory, oversizedRun, { recursive: true });
  const runManifestPath = path.join(oversizedRun, 'artifact-digests.json');
  const runManifest = JSON.parse(await readFile(runManifestPath, 'utf8')) as { artifacts: Array<{ bytes: number }> };
  runManifest.artifacts[0]!.bytes = MAX_VERIFIER_ARTIFACT_BYTES + 1;
  await writeFile(runManifestPath, prettyCanonicalJson(runManifest));
  await assert.rejects(verifyRunDirectory(oversizedRun), hasCode('VERIFY_RESOURCE_LIMIT'));

  const oversizedHealthRun = path.join(root, 'oversized-health-run');
  await cp(fixture.runDirectory, oversizedHealthRun, { recursive: true });
  const healthPath = path.join(oversizedHealthRun, 'analysis-health.json');
  const health = JSON.parse(await readFile(healthPath, 'utf8')) as { profilePatterns: unknown[] };
  health.profilePatterns = Array.from({ length: 10_001 }, () => health.profilePatterns[0]);
  const healthContent = Buffer.from(prettyCanonicalJson(health));
  await writeFile(healthPath, healthContent);
  const healthManifestPath = path.join(oversizedHealthRun, 'artifact-digests.json');
  const healthManifest = JSON.parse(await readFile(healthManifestPath, 'utf8')) as {
    artifacts: Array<{ path: string; bytes: number; sha256: string }>;
  };
  const healthDigest = healthManifest.artifacts.find((artifact) => artifact.path === 'analysis-health.json')!;
  healthDigest.bytes = healthContent.length;
  healthDigest.sha256 = sha256(healthContent);
  await writeFile(healthManifestPath, prettyCanonicalJson(healthManifest));
  await assert.rejects(verifyRunDirectory(oversizedHealthRun), hasCode('VERIFY_RESOURCE_LIMIT'));

  const viewerManifestPath = path.join(viewerDirectory, 'viewer-manifest.json');
  const viewerManifest = JSON.parse(await readFile(viewerManifestPath, 'utf8')) as { artifacts: Array<{ bytes: number }> };
  viewerManifest.artifacts[0]!.bytes = MAX_VERIFIER_ARTIFACT_BYTES + 1;
  await writeFile(viewerManifestPath, prettyCanonicalJson(viewerManifest));
  await assert.rejects(verifyRunViewer(viewerDirectory), hasCode('VIEWER_RESOURCE_LIMIT'));
});

test('run verification rejects deeply nested JSON before canonicalization', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-verifier-depth-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createScanFixture(root);
  const runPath = path.join(fixture.runDirectory, 'run.json');
  const manifestPath = path.join(fixture.runDirectory, 'artifact-digests.json');
  let nested = 'true';
  for (let depth = 0; depth < 130; depth += 1) nested = `{"nested":${nested}}`;
  const runContent = Buffer.from(`{"extra":${nested}}\n`);
  await writeFile(runPath, runContent);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as {
    artifacts: Array<{ path: string; bytes: number; sha256: string }>;
  };
  const runEntry = manifest.artifacts.find((entry) => entry.path === 'run.json')!;
  runEntry.bytes = runContent.length;
  runEntry.sha256 = sha256(runContent);
  await writeFile(manifestPath, prettyCanonicalJson(manifest));

  await assert.rejects(verifyRunDirectory(fixture.runDirectory), hasCode('VERIFY_RESOURCE_LIMIT'));
});

interface ReferenceEntry {
  path: string;
  bytes: number;
  sha256: string;
}

async function createHistoricalFixture(root: string): Promise<{
  referencePath: string;
  manifestPath: string;
  workspacePath: string;
}> {
  const referencePath = path.join(root, 'reference');
  const sourceTarget = path.join(root, 'source-target');
  const workspacePath = path.join(root, 'historical-workspace');
  await mkdir(path.join(referencePath, 'reviews'), { recursive: true });
  await mkdir(path.join(referencePath, 'traces'), { recursive: true });
  await mkdir(sourceTarget);
  const artifacts = new Map<string, string>([
    ['reviews/review.md', '# Review\n\n## Scope\n\n`src/index.ts` remains historical context.\n'],
    ['traces/trace-index.json', prettyCanonicalJson({
      schemaVersion: 1,
      purpose: 'Historical navigation test.',
      traces: [{
        id: 'trace-1',
        label: 'Trace one',
        clusterId: 'cluster-1',
        lifecycle: 'historical',
        summary: 'Historical test trace.',
        artifact: 'traces/trace.md'
      }]
    })],
    ['traces/trace.md', '# Trace\n\n## Scope\n\n`src/index.ts` is the historical anchor.\n']
  ]);
  const entries: ReferenceEntry[] = [];
  for (const [relativePath, text] of artifacts) {
    const content = Buffer.from(text);
    await writeFile(path.join(referencePath, ...relativePath.split('/')), content);
    entries.push({ path: relativePath, bytes: content.length, sha256: sha256(content) });
  }
  entries.sort((left, right) => left.path.localeCompare(right.path, 'en'));
  const aggregateSha256 = sha256(entries.map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}`).join('\n'));
  const manifestPath = path.join(root, 'reference-manifest.json');
  await writeFile(manifestPath, prettyCanonicalJson({
    schemaVersion: 1,
    capturedAt: '2026-01-01T00:00:00.000Z',
    referencePath: 'reference',
    sourceObservation: {
      repositoryPath: sourceTarget,
      atlasPath: 'Atlas',
      gitHead: '0'.repeat(40),
      branch: 'main',
      detached: false,
      dirtyStatusSha256: '0'.repeat(64),
      dirtyStatusLineCount: 0,
      note: 'Synthetic bounded-verifier fixture.'
    },
    fileCount: entries.length,
    totalBytes: entries.reduce((total, entry) => total + entry.bytes, 0),
    aggregateAlgorithm: 'sha256(path\\0bytes\\0sha256 joined by LF, paths sorted lexically)',
    aggregateSha256,
    sourceAggregateSha256: aggregateSha256,
    files: entries
  }));
  return { referencePath, manifestPath, workspacePath };
}

test('historical reference and index verification enforce declared byte limits', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-historical-limits-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createHistoricalFixture(root);
  const result = await createHistoricalEvidenceIndex(fixture);
  assert.equal((await verifyHistoricalEvidenceIndex(result.directory)).status, 'passed');

  const oversizedReferenceManifest = JSON.parse(await readFile(fixture.manifestPath, 'utf8')) as {
    files: Array<{ bytes: number }>;
  };
  oversizedReferenceManifest.files[0]!.bytes = HARD_MAX_FILE_BYTES + 1;
  await writeFile(fixture.manifestPath, prettyCanonicalJson(oversizedReferenceManifest));
  await assert.rejects(createHistoricalEvidenceIndex(fixture), hasCode('HISTORICAL_RESOURCE_LIMIT'));

  const aggregateIndex = path.join(root, 'aggregate-anchor-index');
  await cp(result.directory, aggregateIndex, { recursive: true });
  const baseRecord = JSON.parse((await readFile(path.join(aggregateIndex, 'records.jsonl'), 'utf8')).split('\n')[0]!) as {
    scopeAnchors: unknown[];
    pathAnchors: unknown[];
  };
  const recordWithMentions = (count: number): typeof baseRecord => ({
    ...baseRecord,
    scopeAnchors: [],
    pathAnchors: [{ mentions: Array.from({ length: count }, () => ({ line: 1, column: 1 })) }]
  });
  const aggregateRecords = Buffer.from(canonicalJsonLines([
    recordWithMentions(125_000),
    recordWithMentions(125_001)
  ]));
  await writeFile(path.join(aggregateIndex, 'records.jsonl'), aggregateRecords);
  const aggregateManifestPath = path.join(aggregateIndex, 'artifact-digests.json');
  const aggregateManifest = JSON.parse(await readFile(aggregateManifestPath, 'utf8')) as {
    artifacts: Array<{ path: string; bytes: number; sha256: string }>;
  };
  const aggregateRecordsDigest = aggregateManifest.artifacts.find((artifact) => artifact.path === 'records.jsonl')!;
  aggregateRecordsDigest.bytes = aggregateRecords.length;
  aggregateRecordsDigest.sha256 = sha256(aggregateRecords);
  await writeFile(aggregateManifestPath, prettyCanonicalJson(aggregateManifest));
  await assert.rejects(verifyHistoricalEvidenceIndex(aggregateIndex), hasCode('HISTORICAL_RESOURCE_LIMIT'));

  const indexManifestPath = path.join(result.directory, 'artifact-digests.json');
  const indexManifest = JSON.parse(await readFile(indexManifestPath, 'utf8')) as { artifacts: Array<{ bytes: number }> };
  indexManifest.artifacts[0]!.bytes = MAX_VERIFIER_ARTIFACT_BYTES + 1;
  await writeFile(indexManifestPath, prettyCanonicalJson(indexManifest));
  await assert.rejects(verifyHistoricalEvidenceIndex(result.directory), hasCode('HISTORICAL_RESOURCE_LIMIT'));
});
