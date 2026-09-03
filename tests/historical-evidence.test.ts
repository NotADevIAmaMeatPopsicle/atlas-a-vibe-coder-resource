import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  createHistoricalEvidenceIndex,
  queryHistoricalEvidence,
  verifyHistoricalEvidenceIndex,
  verifyHistoricalEvidenceReference
} from '../src/index.js';
import { sha256 } from '../src/util/canonical.js';

const CLI_PATH = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const SOURCE_HEAD = '0123456789abcdef0123456789abcdef01234567';

interface Fixture {
  root: string;
  referencePath: string;
  manifestPath: string;
  sourceTargetPath: string;
  workspacePath: string;
}

async function inventory(root: string): Promise<Array<{ path: string; bytes: number; sha256: string }>> {
  const entries: Array<{ path: string; bytes: number; sha256: string }> = [];
  async function walk(directory: string): Promise<void> {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const child of children) {
      const absolutePath = path.join(directory, child.name);
      if (child.isDirectory()) await walk(absolutePath);
      else if (child.isFile()) {
        const content = await readFile(absolutePath);
        entries.push({
          path: path.relative(root, absolutePath).split(path.sep).join('/'),
          bytes: content.length,
          sha256: sha256(content)
        });
      }
    }
  }
  await walk(root);
  return entries;
}

async function writeManifest(fixture: Omit<Fixture, 'manifestPath' | 'workspacePath'>, manifestPath: string): Promise<void> {
  const files = await inventory(fixture.referencePath);
  const aggregateSha256 = sha256(files.map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}`).join('\n'));
  const manifest = {
    schemaVersion: 1,
    capturedAt: '2026-08-21T17:59:33.895Z',
    referencePath: 'reference/example-project/2026-01-01',
    sourceObservation: {
      repositoryPath: fixture.sourceTargetPath,
      atlasPath: 'docs/codebase-atlas',
      gitHead: SOURCE_HEAD,
      branch: null,
      detached: true,
      dirtyStatusSha256: sha256('fixture status'),
      dirtyStatusLineCount: 2,
      note: 'Fixture preservation observation.'
    },
    fileCount: files.length,
    totalBytes: files.reduce((total, entry) => total + entry.bytes, 0),
    aggregateAlgorithm: 'sha256(path\\0bytes\\0sha256 joined by LF, paths sorted lexically)',
    aggregateSha256,
    sourceAggregateSha256: aggregateSha256,
    files
  };
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

async function fixture(): Promise<Fixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-historical-evidence-'));
  const referencePath = path.join(root, 'reference');
  const sourceTargetPath = path.join(root, 'source-target');
  const manifestPath = path.join(root, 'reference-manifest.json');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(path.join(referencePath, 'reviews'), { recursive: true });
  await mkdir(path.join(referencePath, 'traces'), { recursive: true });
  await mkdir(path.join(referencePath, 'registry'), { recursive: true });
  await mkdir(sourceTargetPath, { recursive: true });
  await writeFile(path.join(referencePath, 'reviews', 'PAYMENTS-REVIEW.md'), [
    '# Payments Boundary Review',
    'Reviewer: Ada Example',
    '',
    '## Scope and coverage',
    '',
    'The preserved review cites `src/payments/index.ts:12-20`, `src/payments/index.ts#L30-L31`, and `src/payments/ledger.ts`.',
    'Inventory-backed anchors include `README.md:7-9`, `package.json#L4`, `.env.example:3`, `Dockerfile.backend#L2-L4`, and `scripts/hooks/pre-push:11-12`.',
    'Inline prose such as `production:12`, `not/a/real/file:2`, and `this-is-not-a-file` is not target evidence.',
    'DO-NOT-INDEX-THIS-CLAIM-BODY says a critical defect exists.',
    ''
  ].join('\n'));
  await writeFile(path.join(referencePath, 'traces', 'LOGIN-TRACE.md'), [
    '# Login Runtime Trace',
    '',
    '## Bounded runtime flow',
    '',
    'The trace points to `src/auth/login.ts#L4-L12`.',
    ''
  ].join('\n'));
  await writeFile(path.join(referencePath, 'traces', 'trace-index.json'), `${JSON.stringify({
    schemaVersion: 1,
    purpose: 'Named historical trace metadata.',
    traces: [{
      id: 'login-runtime',
      label: 'Login runtime',
      clusterId: 'authentication',
      lifecycle: 'historical active surface',
      summary: 'Preserved login flow metadata for navigation.',
      artifact: 'traces/LOGIN-TRACE.md'
    }]
  }, null, 2)}\n`);
  await writeFile(path.join(referencePath, 'registry', 'file-registry.json'), `${JSON.stringify({
    schemaVersion: 1,
    generatedAt: '2026-08-21T08:40:05.311Z',
    records: [
      { path: '.env.example' },
      { path: 'Dockerfile.backend' },
      { path: 'README.md' },
      { path: 'package.json' },
      { path: 'scripts/hooks/pre-push' }
    ]
  }, null, 2)}\n`);
  await writeFile(path.join(referencePath, 'UNSELECTED.txt'), 'The full manifest still seals unselected files.\n');
  await writeManifest({ root, referencePath, sourceTargetPath }, manifestPath);
  return { root, referencePath, manifestPath, sourceTargetPath, workspacePath };
}

function runCli(argumentsList: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...argumentsList], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolve({
      code,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8')
    }));
  });
}

test('historical evidence is content-addressed, cited, explicit about trust, and excludes review claim bodies', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));

  const referenceVerification = await verifyHistoricalEvidenceReference({
    referencePath: value.referencePath,
    manifestPath: value.manifestPath
  });
  assert.equal(referenceVerification.status, 'passed');
  assert.equal(referenceVerification.fileCount, 5);
  assert.equal(referenceVerification.sourceGitHead, SOURCE_HEAD);

  const created = await createHistoricalEvidenceIndex({
    referencePath: value.referencePath,
    manifestPath: value.manifestPath,
    workspacePath: value.workspacePath
  });
  assert.equal(created.status, 'completed');
  assert.deepEqual(created.counts, { reviews: 1, traces: 1, records: 2, scopeAnchors: 2, pathAnchors: 9 });
  const verification = await verifyHistoricalEvidenceIndex(created.directory);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.sourceGitHead, SOURCE_HEAD);
  assert.equal(verification.records, 2);

  const indexText = await readFile(path.join(created.directory, 'index.json'), 'utf8');
  const recordsText = await readFile(path.join(created.directory, 'records.jsonl'), 'utf8');
  assert(!indexText.includes(value.sourceTargetPath), 'host-local source path must not leak into portable index');
  assert(!recordsText.includes('DO-NOT-INDEX-THIS-CLAIM-BODY'));
  const records = recordsText.trimEnd().split('\n').map((line) => JSON.parse(line) as {
    kind: string;
    artifact: { path: string; sha256: string };
    pathAnchors: Array<{ path: string; targetStartLine?: number; targetEndLine?: number }>;
    reviewerIdentity: { status: string; identity: string | null };
    anchorFreshness: { status: string; checkedAgainstSourceHead: string | null };
    interpretation: { claimBodiesImported: boolean; validatedFindingsCreated: boolean };
  });
  const review = records.find((record) => record.kind === 'review')!;
  const trace = records.find((record) => record.kind === 'trace')!;
  assert.equal(review.artifact.path, 'reviews/PAYMENTS-REVIEW.md');
  assert.equal(review.artifact.sha256.length, 64);
  assert.deepEqual(review.pathAnchors.map(({ path: anchorPath, targetStartLine, targetEndLine }) => ({
    path: anchorPath,
    ...(targetStartLine === undefined ? {} : { targetStartLine, targetEndLine })
  })), [
    { path: '.env.example', targetStartLine: 3, targetEndLine: 3 },
    { path: 'Dockerfile.backend', targetStartLine: 2, targetEndLine: 4 },
    { path: 'README.md', targetStartLine: 7, targetEndLine: 9 },
    { path: 'package.json', targetStartLine: 4, targetEndLine: 4 },
    { path: 'scripts/hooks/pre-push', targetStartLine: 11, targetEndLine: 12 },
    { path: 'src/payments/index.ts', targetStartLine: 12, targetEndLine: 20 },
    { path: 'src/payments/index.ts', targetStartLine: 30, targetEndLine: 31 },
    { path: 'src/payments/ledger.ts' }
  ]);
  assert.equal(review.reviewerIdentity.status, 'recorded');
  assert.equal(review.reviewerIdentity.identity, 'Ada Example');
  assert.equal(trace.reviewerIdentity.status, 'unavailable');
  assert.equal(trace.reviewerIdentity.identity, null);
  assert.equal(trace.anchorFreshness.status, 'unavailable');
  assert.equal(trace.anchorFreshness.checkedAgainstSourceHead, null);
  assert.deepEqual(trace.pathAnchors, [{
    path: 'src/auth/login.ts',
    kind: 'file',
    targetStartLine: 4,
    targetEndLine: 12,
    mentions: [{ line: 5, column: 22 }]
  }]);
  assert.equal(trace.interpretation.claimBodiesImported, false);
  assert.equal(trace.interpretation.validatedFindingsCreated, false);
  assert(!review.pathAnchors.some(({ path: anchorPath }) =>
    ['production', 'not/a/real/file', 'this-is-not-a-file'].includes(anchorPath)
  ));

  const paymentQuery = await queryHistoricalEvidence(created.directory, 'src/payments/index.ts', { kinds: ['review'], limit: 5 });
  assert.equal(paymentQuery.answer.kind, 'matches');
  assert.equal(paymentQuery.provenance.sourceGitHead, SOURCE_HEAD);
  assert.equal(paymentQuery.interpretation.validatedFindingsCreated, false);
  assert.equal(paymentQuery.hits.length, 1);
  assert(paymentQuery.hits[0]!.matchedFields.includes('path-anchor'));
  assert(paymentQuery.hits[0]!.citations.some((citation) => citation.basis === 'path-anchor' && citation.line === 6));

  const traceQuery = await queryHistoricalEvidence(created.directory, 'preserved login flow', { kinds: ['trace'] });
  assert.equal(traceQuery.hits.length, 1);
  assert(traceQuery.hits[0]!.matchedFields.includes('trace-summary'));
  assert(traceQuery.hits[0]!.citations.some((citation) => citation.path === 'traces/trace-index.json'));
  assert.equal(traceQuery.hits[0]!.anchorFreshness.status, 'unavailable');

  const abstention = await queryHistoricalEvidence(created.directory, 'not-present-anywhere');
  assert.equal(abstention.answer.kind, 'abstention');
  assert.deepEqual(abstention.hits, []);

  const reused = await createHistoricalEvidenceIndex({
    referencePath: value.referencePath,
    manifestPath: value.manifestPath,
    workspacePath: value.workspacePath
  });
  assert.equal(reused.status, 'reused');
  assert.equal(reused.indexId, created.indexId);

  await writeFile(path.join(created.directory, 'records.jsonl'), `${recordsText}\n`, 'utf8');
  await assert.rejects(
    verifyHistoricalEvidenceIndex(created.directory),
    (error: unknown) => (error as { code?: string }).code === 'HISTORICAL_INDEX_DIGEST'
  );
});

test('manifest verification precedes writes and workspaces inside reference or source target are rejected', async (context) => {
  const changed = await fixture();
  context.after(async () => rm(changed.root, { recursive: true, force: true }));
  await writeFile(path.join(changed.referencePath, 'UNSELECTED.txt'), 'changed after preservation\n');
  await assert.rejects(
    createHistoricalEvidenceIndex({
      referencePath: changed.referencePath,
      manifestPath: changed.manifestPath,
      workspacePath: changed.workspacePath
    }),
    (error: unknown) => (error as { code?: string }).code === 'REFERENCE_MANIFEST_MISMATCH'
  );
  await assert.rejects(readFile(path.join(changed.workspacePath, 'historical-evidence', 'index.json')));

  const contained = await fixture();
  context.after(async () => rm(contained.root, { recursive: true, force: true }));
  await assert.rejects(
    createHistoricalEvidenceIndex({
      referencePath: contained.referencePath,
      manifestPath: contained.manifestPath,
      workspacePath: path.join(contained.referencePath, 'workspace')
    }),
    (error: unknown) => (error as { code?: string }).code === 'HISTORICAL_WORKSPACE_INSIDE_REFERENCE'
  );
  await assert.rejects(
    createHistoricalEvidenceIndex({
      referencePath: contained.referencePath,
      manifestPath: contained.manifestPath,
      workspacePath: path.join(contained.sourceTargetPath, 'workspace')
    }),
    (error: unknown) => (error as { code?: string }).code === 'HISTORICAL_WORKSPACE_INSIDE_TARGET'
  );

  const networkPath = await fixture();
  context.after(async () => rm(networkPath.root, { recursive: true, force: true }));
  const manifest = JSON.parse(await readFile(networkPath.manifestPath, 'utf8')) as {
    sourceObservation: { repositoryPath: string };
  };
  for (const repositoryPath of [
    '\\\\example.invalid\\share\\atlas',
    '//example.invalid/share/atlas',
    '\\\\?\\UNC\\example.invalid\\share\\atlas',
    '\\\\.\\PIPE\\atlas'
  ]) {
    manifest.sourceObservation.repositoryPath = repositoryPath;
    await writeFile(networkPath.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await assert.rejects(
      createHistoricalEvidenceIndex({
        referencePath: networkPath.referencePath,
        manifestPath: networkPath.manifestPath,
        workspacePath: networkPath.workspacePath
      }),
      (error: unknown) => (error as { code?: string }).code === 'REFERENCE_MANIFEST_INVALID'
    );
  }
  if (process.platform === 'win32') {
    manifest.sourceObservation.repositoryPath = 'Z:\\atlas-stale-source-path';
    await writeFile(networkPath.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const created = await createHistoricalEvidenceIndex({
      referencePath: networkPath.referencePath,
      manifestPath: networkPath.manifestPath,
      workspacePath: networkPath.workspacePath
    });
    assert.equal(created.status, 'completed');
  }
});

test('historical index creation and verification reject a canonical-child junction to a valid external index', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const created = await createHistoricalEvidenceIndex({
    referencePath: value.referencePath,
    manifestPath: value.manifestPath,
    workspacePath: value.workspacePath
  });
  const validExternalIndex = path.join(value.root, 'valid-external-index');
  await rename(created.directory, validExternalIndex);
  try {
    await symlink(
      validExternalIndex,
      created.directory,
      process.platform === 'win32' ? 'junction' : 'dir'
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EPERM') {
      context.skip('Junction/symlink creation is unavailable in this environment.');
      return;
    }
    throw error;
  }

  await assert.rejects(
    verifyHistoricalEvidenceIndex(created.directory),
    (error: unknown) => (error as { code?: string }).code === 'HISTORICAL_INDEX_INVALID'
  );
  await assert.rejects(
    createHistoricalEvidenceIndex({
      referencePath: value.referencePath,
      manifestPath: value.manifestPath,
      workspacePath: value.workspacePath
    }),
    (error: unknown) => (error as { code?: string }).code === 'HISTORICAL_INDEX_INVALID'
  );
  assert.equal((await verifyHistoricalEvidenceIndex(validExternalIndex)).status, 'passed');
});

test('historical-evidence CLI indexes, verifies, and queries the immutable corpus', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const indexResult = await runCli([
    'historical-evidence', 'index',
    '--reference', value.referencePath,
    '--manifest', value.manifestPath,
    '--workspace', value.workspacePath
  ]);
  assert.equal(indexResult.code, 0, indexResult.stderr);
  assert.equal(indexResult.stderr, '');
  const indexed = JSON.parse(indexResult.stdout) as { directory: string; status: string; indexId: string };
  assert.equal(indexed.status, 'completed');
  assert.match(indexed.indexId, /^historical_evidence_sha256_[a-f0-9]{64}$/u);

  const verifyResult = await runCli(['historical-evidence', 'verify', indexed.directory]);
  assert.equal(verifyResult.code, 0, verifyResult.stderr);
  assert.equal((JSON.parse(verifyResult.stdout) as { status: string }).status, 'passed');

  const queryResult = await runCli([
    'historical-evidence', 'query', indexed.directory,
    '--text', 'login runtime',
    '--kind', 'trace',
    '--limit', '1'
  ]);
  assert.equal(queryResult.code, 0, queryResult.stderr);
  const query = JSON.parse(queryResult.stdout) as {
    hits: Array<{ kind: string; citations: unknown[]; interpretation: { validatedFindingsCreated: boolean } }>;
  };
  assert.equal(query.hits.length, 1);
  assert.equal(query.hits[0]!.kind, 'trace');
  assert(query.hits[0]!.citations.length > 0);
  assert.equal(query.hits[0]!.interpretation.validatedFindingsCreated, false);
});
