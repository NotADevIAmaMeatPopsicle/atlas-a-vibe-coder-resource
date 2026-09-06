import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  applyFindingDispositions,
  findingDispositionAnalysisMarker,
  loadFindingDispositionLedger,
  MAX_FINDING_DISPOSITION_LEDGER_BYTES,
  type FindingDispositionLedger
} from '../src/finding-dispositions.js';
import { AtlasError } from '../src/errors.js';
import { findingReviewIdentity } from '../src/finding-diff.js';
import { assertSchema } from '../src/schema-validator.js';
import type { FileRecord, FindingRecord } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { canonicalJson, canonicalJsonLines, readJson, readJsonLines, sha256, writeCanonicalJson } from '../src/util/canonical.js';
import { scanProject } from '../src/run.js';
import { verifyAndLoadRunDirectory } from '../src/verify.js';
import { createRunViewer, decodeViewerDataScript, verifyRunViewer, type ViewerData } from '../src/viewer/index.js';
import { buildViewerBundle } from '../src/viewer/bundle.js';
import type { ArtifactManifest, DiagnosticRecord } from '../src/types.js';

const TARGET_ID = 'disposition-test-target';
const PROFILE_ID = 'disposition-test-profile';
const PROFILE_DIGEST = sha256('disposition-test-profile');
const SOURCE = 'export const current = true;\n';
const SOURCE_SHA = sha256(SOURCE);
const FINDING_ID = `finding:${'a'.repeat(24)}`;

function file(filePath = 'src/current.ts', digest = SOURCE_SHA): FileRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `file_sha256_${sha256(canonicalJson({ domain: 'atlas.file.v1', targetId: TARGET_ID, path: filePath }))}`,
    path: filePath,
    sha256: digest,
    bytes: Buffer.byteLength(SOURCE),
    kind: 'source',
    language: 'typescript',
    symbols: [],
    environmentVariables: [],
    evidence: {
      level: 0,
      producer: 'atlas/test',
      producerVersion: '1.0.0',
      basis: 'test-file',
      path: filePath
    }
  };
}

function finding(): FindingRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: FINDING_ID,
    category: 'contract-mismatch',
    ruleId: 'contract/test-v1',
    status: 'candidate',
    severity: 'medium',
    confidence: 'high',
    title: 'Test finding',
    description: 'A test finding.',
    path: 'src/current.ts',
    relatedPaths: [],
    signals: ['test-signal'],
    evidence: [{
      level: 1,
      producer: 'atlas/test',
      producerVersion: '1.0.0',
      basis: 'test-finding',
      path: 'src/current.ts',
      line: 1,
      column: 1
    }],
    nextValidation: 'Review the test finding.'
  };
}

function ledger(overrides: Partial<FindingDispositionLedger['entries'][string]> = {}): FindingDispositionLedger {
  const reviewIdentity = findingReviewIdentity(finding());
  return {
    schemaVersion: 1,
    kind: 'atlas-finding-disposition-ledger',
    targetId: TARGET_ID,
    profileId: PROFILE_ID,
    profileDigest: PROFILE_DIGEST,
    entries: {
      [reviewIdentity]: {
        findingId: FINDING_ID,
        disposition: 'intentional contract',
        reviewer: 'Test Reviewer',
        date: '2026-08-22',
        evidence: ['Decision TEST-1'],
        anchors: [{ path: 'src/current.ts', sha256: SOURCE_SHA }],
        ...overrides
      }
    }
  };
}

async function writeLedger(value: unknown): Promise<{ root: string; ledgerPath: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-dispositions-'));
  const ledgerPath = path.join(root, 'ledger.json');
  await writeFile(ledgerPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return { root, ledgerPath };
}

test('disposition ledger schema requires the review record and exact source anchors', async () => {
  await assertSchema('finding-disposition-ledger', ledger(), 'Disposition ledger fixture');
  await assert.rejects(
    assertSchema('finding-disposition-ledger', ledger({ anchors: [] }), 'Empty disposition anchors'),
    (error: unknown) => error instanceof AtlasError && error.code === 'SCHEMA_VALIDATION'
  );
  await assert.rejects(
    assertSchema('finding-disposition-ledger', ledger({ disposition: 'approved' as never }), 'Unknown disposition'),
    (error: unknown) => error instanceof AtlasError && error.code === 'SCHEMA_VALIDATION'
  );
  await assert.rejects(
    assertSchema('finding-disposition-ledger', {
      ...ledger(),
      entries: { 'EXAMPLE-REVIEW-1': Object.values(ledger().entries)[0] }
    }, 'Unstable disposition key'),
    (error: unknown) => error instanceof AtlasError && error.code === 'SCHEMA_VALIDATION'
  );
});

test('ledger loading validates target binding, duplicate identities, and canonical set ordering', async (context) => {
  const reordered = ledger({
    evidence: ['Zulu evidence', 'Alpha evidence'],
    anchors: [
      { path: 'src/other.ts', sha256: sha256('other') },
      { path: 'src/current.ts', sha256: SOURCE_SHA }
    ]
  });
  const fixture = await writeLedger(reordered);
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const loaded = await loadFindingDispositionLedger(fixture.ledgerPath, {
    targetId: TARGET_ID,
    profileId: PROFILE_ID,
    profileDigest: PROFILE_DIGEST
  });
  const reviewIdentity = findingReviewIdentity(finding());
  assert.deepEqual(loaded.ledger.entries[reviewIdentity]?.evidence, ['Alpha evidence', 'Zulu evidence']);
  assert.deepEqual(loaded.ledger.entries[reviewIdentity]?.anchors.map((entry) => entry.path), [
    'src/current.ts',
    'src/other.ts'
  ]);
  assert.equal(findingDispositionAnalysisMarker(loaded.digest), `finding-dispositions-v1.1.0+sha256.${loaded.digest}`);

  await assert.rejects(
    loadFindingDispositionLedger(fixture.ledgerPath, {
      targetId: 'another-target',
      profileId: PROFILE_ID,
      profileDigest: PROFILE_DIGEST
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'DISPOSITION_TARGET_MISMATCH'
  );
  await assert.rejects(
    loadFindingDispositionLedger(fixture.ledgerPath, {
      targetId: TARGET_ID,
      profileId: PROFILE_ID,
      profileDigest: sha256('changed-profile')
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'DISPOSITION_PROFILE_MISMATCH'
  );

  const duplicated = ledger({
    anchors: [
      { path: 'src/current.ts', sha256: SOURCE_SHA },
      { path: 'src/current.ts', sha256: sha256('different') }
    ]
  });
  const duplicateFixture = await writeLedger(duplicated);
  context.after(async () => rm(duplicateFixture.root, { recursive: true, force: true }));
  await assert.rejects(
    loadFindingDispositionLedger(duplicateFixture.ledgerPath, {
      targetId: TARGET_ID,
      profileId: PROFILE_ID,
      profileDigest: PROFILE_DIGEST
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'DISPOSITION_LEDGER_INVALID'
  );

  const duplicateFinding = ledger();
  duplicateFinding.entries[`finding_review_sha256_${'d'.repeat(64)}`] = {
    ...Object.values(duplicateFinding.entries)[0]!,
    anchors: [{ path: 'src/other.ts', sha256: sha256('other') }]
  };
  const duplicateFindingFixture = await writeLedger(duplicateFinding);
  context.after(async () => rm(duplicateFindingFixture.root, { recursive: true, force: true }));
  await assert.rejects(
    loadFindingDispositionLedger(duplicateFindingFixture.ledgerPath, {
      targetId: TARGET_ID,
      profileId: PROFILE_ID,
      profileDigest: PROFILE_DIGEST
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'DISPOSITION_LEDGER_INVALID'
  );
});

test('ledger loading rejects an oversized file before JSON buffering', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-dispositions-size-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const ledgerPath = path.join(root, 'oversized.json');
  const handle = await open(ledgerPath, 'w');
  await handle.truncate(MAX_FINDING_DISPOSITION_LEDGER_BYTES + 1);
  await handle.close();
  await assert.rejects(
    loadFindingDispositionLedger(ledgerPath, {
      targetId: TARGET_ID,
      profileId: PROFILE_ID,
      profileDigest: PROFILE_DIGEST
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'DISPOSITION_LEDGER_RESOURCE_LIMIT'
  );
});

test('current disposition anchors suppress the matching finding with an auditable diagnostic', async () => {
  const result = applyFindingDispositions(ledger(), [finding()], [file()]);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.appliedReviewIds, [findingReviewIdentity(finding())]);
  assert.deepEqual(result.staleReviewIds, []);
  assert.deepEqual(result.suppressedFindingInstancesByRule, { 'contract/test-v1': 1 });
  assert.equal(result.diagnostics.length, 1);
  assert.equal(result.diagnostics[0]?.code, 'FINDING_DISPOSITION_APPLIED');
  assert.equal(result.diagnostics[0]?.path, 'src/current.ts');
  assert.deepEqual(result.diagnostics[0]?.disposition, {
    reviewId: findingReviewIdentity(finding()),
    findingId: finding().id,
    title: finding().title,
    ruleId: finding().ruleId,
    disposition: 'intentional contract',
    reviewer: 'Test Reviewer',
    date: '2026-08-22',
    evidence: ['Decision TEST-1'],
    anchors: [{ path: 'src/current.ts', sha256: SOURCE_SHA }],
    state: 'applied'
  });
  await assertSchema('diagnostic', result.diagnostics[0], 'Applied-disposition diagnostic');
});

test('stable review identity, not the recorded finding ID, selects the current finding', () => {
  const current = { ...finding(), id: `finding:${'c'.repeat(24)}` };
  assert.equal(findingReviewIdentity(current), findingReviewIdentity(finding()));
  const result = applyFindingDispositions(ledger(), [current], [file()]);
  assert.deepEqual(result.findings, []);
  assert.equal(result.diagnostics[0]?.code, 'FINDING_DISPOSITION_APPLIED');
  assert.match(result.diagnostics[0]?.message ?? '', new RegExp(current.id, 'u'));
  assert.equal(result.diagnostics[0]?.disposition?.findingId, current.id);
});

test('legacy and occurrence-qualified keys fail closed when current identity multiplicity differs', () => {
  const first = finding();
  const second = { ...finding(), id: `finding:${'b'.repeat(24)}` };
  const reviewIdentity = findingReviewIdentity(first);
  const legacyDuplicate = applyFindingDispositions(ledger(), [second, first], [file()]);
  assert.deepEqual(legacyDuplicate.findings.map((entry) => entry.id), [second.id, first.id]);
  assert.equal(legacyDuplicate.appliedReviewIds.length, 0);
  assert.equal(legacyDuplicate.diagnostics[0]?.code, 'FINDING_DISPOSITION_ANCHOR_MISMATCH');
  assert.match(legacyDuplicate.diagnostics[0]?.message ?? '', /omits the required occurrence suffix/u);

  const baseEntry = Object.values(ledger().entries)[0]!;
  const suffixedSingleton: FindingDispositionLedger = {
    ...ledger(),
    entries: { [`${reviewIdentity}:occurrence:1`]: baseEntry }
  };
  const singleton = applyFindingDispositions(suffixedSingleton, [first], [file()]);
  assert.deepEqual(singleton.findings, [first]);
  assert.equal(singleton.appliedReviewIds.length, 0);
  assert.match(singleton.diagnostics[0]?.message ?? '', /occurrence-qualified key for a singleton/u);
});

test('occurrence-qualified review keys can disposition duplicate stable identities independently', async () => {
  const first = finding();
  const second = { ...finding(), id: `finding:${'b'.repeat(24)}` };
  const reviewIdentity = findingReviewIdentity(first);
  assert.equal(findingReviewIdentity(second), reviewIdentity);
  const baseEntry = Object.values(ledger().entries)[0]!;
  const multi: FindingDispositionLedger = {
    ...ledger(),
    entries: {
      [`${reviewIdentity}:occurrence:1`]: { ...baseEntry, findingId: first.id },
      [`${reviewIdentity}:occurrence:2`]: { ...baseEntry, findingId: second.id }
    }
  };

  await assertSchema('finding-disposition-ledger', multi, 'Duplicate-identity disposition ledger');
  const result = applyFindingDispositions(multi, [second, first], [file()]);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.appliedReviewIds, [
    `${reviewIdentity}:occurrence:1`,
    `${reviewIdentity}:occurrence:2`
  ]);
});

test('changed or missing source anchors make a disposition stale and retain the finding', async () => {
  const changed = applyFindingDispositions(ledger(), [finding()], [file('src/current.ts', sha256('changed'))]);
  assert.deepEqual(changed.findings, [finding()]);
  assert.deepEqual(changed.appliedReviewIds, []);
  assert.deepEqual(changed.staleReviewIds, [findingReviewIdentity(finding())]);
  assert.equal(changed.diagnostics[0]?.code, 'FINDING_DISPOSITION_STALE');
  assert.match(changed.diagnostics[0]?.message ?? '', /changed: src\/current\.ts/u);

  const missing = applyFindingDispositions(ledger(), [finding()], []);
  assert.deepEqual(missing.findings, [finding()]);
  assert.equal(missing.diagnostics[0]?.code, 'FINDING_DISPOSITION_STALE');
  assert.match(missing.diagnostics[0]?.message ?? '', /missing from this scan: src\/current\.ts/u);
});

test('fresh anchors unrelated to a referenced finding never suppress it', () => {
  const unrelated = file('src/unrelated.ts');
  const result = applyFindingDispositions(
    ledger({ anchors: [{ path: unrelated.path, sha256: unrelated.sha256 }] }),
    [finding()],
    [file(), unrelated]
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.diagnostics[0]?.code, 'FINDING_DISPOSITION_ANCHOR_MISMATCH');
});

test('a disposition must anchor every current headline, related, and evidence source path', () => {
  const related = file('src/related.ts', sha256('related'));
  const current = {
    ...finding(),
    relatedPaths: [related.path],
    evidence: [
      ...finding().evidence,
      { ...finding().evidence[0]!, path: related.path }
    ]
  };
  const reviewIdentity = findingReviewIdentity(current);
  const incomplete: FindingDispositionLedger = {
    ...ledger(),
    entries: { [reviewIdentity]: Object.values(ledger().entries)[0]! }
  };
  const retained = applyFindingDispositions(incomplete, [current], [file(), related]);
  assert.deepEqual(retained.findings, [current]);
  assert.equal(retained.diagnostics[0]?.code, 'FINDING_DISPOSITION_ANCHOR_MISMATCH');

  const complete: FindingDispositionLedger = {
    ...incomplete,
    entries: {
      [reviewIdentity]: {
        ...Object.values(incomplete.entries)[0]!,
        anchors: [
          { path: 'src/current.ts', sha256: SOURCE_SHA },
          { path: related.path, sha256: related.sha256 }
        ]
      }
    }
  };
  assert.deepEqual(applyFindingDispositions(complete, [current], [file(), related]).findings, []);
  const changedRelated = applyFindingDispositions(
    complete,
    [current],
    [file(), file(related.path, sha256('related changed'))]
  );
  assert.deepEqual(changedRelated.findings, [current]);
  assert.equal(changedRelated.diagnostics[0]?.code, 'FINDING_DISPOSITION_STALE');
});

test('disposition evaluation is deterministic across finding and file input order', () => {
  const secondFinding = { ...finding(), id: `finding:${'b'.repeat(24)}`, path: 'src/other.ts' };
  const first = applyFindingDispositions(ledger(), [finding(), secondFinding], [file('src/other.ts'), file()]);
  const second = applyFindingDispositions(ledger(), [secondFinding, finding()], [file(), file('src/other.ts')]);
  assert.equal(canonicalJson(first), canonicalJson(second));
});

test('scan disposition integration suppresses current findings and re-surfaces them after anchored code changes', { timeout: 120_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-disposition-scan-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  const ledgerPath = path.join(root, 'dispositions.json');
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await writeFile(
    path.join(targetRoot, 'src', 'index.ts'),
    "import './missing.js';\nexport const ready = true;\n",
    'utf8'
  );
  await writeFile(path.join(targetRoot, 'package.json'), '{"scripts":{"test":"vitest --passWithNoTests"}}\n', 'utf8');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: TARGET_ID,
    path: './target',
    consent: { agentReview: true, export: true, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'disposition-test-profile',
    includeRoots: ['package.json', 'src'],
    entrypoints: ['src/index.ts'],
    maxFileBytes: 1_000_000
  }, null, 2)}\n`, 'utf8');

  const baseline = await scanProject({ targetConfigPath, profilePath, workspacePath });
  const baselineFindings = await readJsonLines<FindingRecord>(path.join(baseline.runDirectory, 'findings.jsonl'));
  const candidate = baselineFindings.find((entry) => entry.ruleId === 'operational/silent-empty-instrument-v1');
  assert(candidate, 'Expected the passWithNoTests fixture to produce an operational finding.');
  assert(candidate.reviewId, 'Expected findings.jsonl to publish the exact disposition ledger key.');
  assert(candidate.reviewAnchors?.length, 'Expected findings.jsonl to publish source-hash anchors.');
  const reviewIdentity = candidate.reviewId;
  await writeFile(ledgerPath, `${JSON.stringify({
    schemaVersion: 1,
    kind: 'atlas-finding-disposition-ledger',
    targetId: TARGET_ID,
    profileId: baseline.run.profileId,
    profileDigest: baseline.run.profileDigest,
    entries: {
      [reviewIdentity]: {
        findingId: candidate.id,
        disposition: 'intentional contract',
        reviewer: 'Test Reviewer',
        date: '2026-08-22',
        evidence: ['Decision TEST-1'],
        anchors: candidate.reviewAnchors
      }
    }
  }, null, 2)}\n`, 'utf8');

  const suppressed = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath,
    dispositionLedgerPath: ledgerPath
  });
  const suppressedRun = await verifyAndLoadRunDirectory(suppressed.runDirectory);
  assert.equal(suppressedRun.artifacts.findings.some((entry) => findingReviewIdentity(entry) === reviewIdentity), false);
  assert.equal(suppressedRun.artifacts.diagnostics.some((entry) => entry.code === 'FINDING_DISPOSITION_APPLIED'), true);
  assert.equal(suppressedRun.artifacts.run.analyses.some((entry) => /^finding-dispositions-v1\.1\.0\+sha256\./u.test(entry)), true);
  const healthRule = suppressedRun.artifacts.analysisHealth?.rules.find(
    (entry) => entry.ruleId === 'operational/silent-empty-instrument-v1'
  );
  assert.equal(healthRule?.target?.suppressedFindingInstances, candidate.instanceCount ?? 1);
  const viewerDirectory = path.join(root, 'viewer');
  await createRunViewer({
    runDirectory: suppressed.runDirectory,
    workspacePath,
    targetConfigPath,
    outputDirectory: viewerDirectory
  });
  assert.equal((await verifyRunViewer(viewerDirectory)).status, 'passed');

  const visibleFinding = suppressedRun.artifacts.findings[0];
  assert(visibleFinding, 'Expected at least one non-dispositioned finding for collision checks.');
  const tamperedRunDirectory = path.join(root, 'tampered-omitted-review-run');
  await cp(suppressed.runDirectory, tamperedRunDirectory, { recursive: true });
  const tamperedDiagnostics = await readJsonLines<DiagnosticRecord>(
    path.join(tamperedRunDirectory, 'diagnostics.jsonl')
  );
  const appliedDiagnostic = tamperedDiagnostics.find((entry) => entry.code === 'FINDING_DISPOSITION_APPLIED');
  assert(appliedDiagnostic?.disposition);
  appliedDiagnostic.disposition.findingId = visibleFinding.id;
  const tamperedDiagnosticContent = canonicalJsonLines(tamperedDiagnostics);
  await writeFile(path.join(tamperedRunDirectory, 'diagnostics.jsonl'), tamperedDiagnosticContent, 'utf8');
  const tamperedManifestPath = path.join(tamperedRunDirectory, 'artifact-digests.json');
  const tamperedManifest = await readJson<ArtifactManifest>(tamperedManifestPath);
  const diagnosticManifestEntry = tamperedManifest.artifacts.find((entry) => entry.path === 'diagnostics.jsonl');
  assert(diagnosticManifestEntry);
  diagnosticManifestEntry.bytes = Buffer.byteLength(tamperedDiagnosticContent);
  diagnosticManifestEntry.sha256 = sha256(tamperedDiagnosticContent);
  await writeCanonicalJson(tamperedManifestPath, tamperedManifest);
  await assert.rejects(
    verifyAndLoadRunDirectory(tamperedRunDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VERIFY_IDENTITY'
  );

  const tamperedViewerData = structuredClone(decodeViewerDataScript(
    await readFile(path.join(viewerDirectory, 'atlas-data.js'), 'utf8')
  )) as ViewerData;
  const projectedDisposition = tamperedViewerData.diagnostics
    .find((entry) => entry.code === 'FINDING_DISPOSITION_APPLIED')?.disposition;
  assert(projectedDisposition);
  projectedDisposition.findingId = visibleFinding.id;
  const tamperedViewerDirectory = path.join(root, 'tampered-omitted-review-viewer');
  const tamperedViewerBundle = buildViewerBundle(tamperedViewerData);
  await mkdir(tamperedViewerDirectory, { recursive: true });
  await Promise.all([...tamperedViewerBundle.artifacts].map(([name, content]) =>
    writeFile(path.join(tamperedViewerDirectory, name), content)
  ));
  await assert.rejects(
    verifyRunViewer(tamperedViewerDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const repeated = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath,
    dispositionLedgerPath: ledgerPath
  });
  assert.equal(repeated.reused, true);
  assert.equal(repeated.run.runId, suppressed.run.runId);

  await writeFile(
    path.join(targetRoot, 'package.json'),
    '{"name":"changed-with-same-finding","scripts":{"test":"vitest --passWithNoTests"}}\n',
    'utf8'
  );
  const stale = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath,
    dispositionLedgerPath: ledgerPath
  });
  const staleRun = await verifyAndLoadRunDirectory(stale.runDirectory);
  assert.equal(staleRun.artifacts.findings.some((entry) => findingReviewIdentity(entry) === reviewIdentity), true);
  assert.equal(staleRun.artifacts.diagnostics.some((entry) => entry.code === 'FINDING_DISPOSITION_STALE'), true);
  const staleHealthRule = staleRun.artifacts.analysisHealth?.rules.find(
    (entry) => entry.ruleId === 'operational/silent-empty-instrument-v1'
  );
  assert.equal(staleHealthRule?.target?.suppressedFindingInstances, undefined);
});
