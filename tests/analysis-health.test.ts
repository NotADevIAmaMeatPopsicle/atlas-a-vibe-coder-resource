import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS,
  ANALYSIS_HEALTH_RUN_ARTIFACTS,
  LEGACY_HASHED_RUN_ARTIFACTS,
  LEGACY_RUN_ARTIFACTS,
  OPERATIONAL_ANALYSIS_MARKER_PREFIX,
  PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX,
  TRIAGE_HASHED_RUN_ARTIFACTS,
  TRIAGE_REPORT_ANALYSIS_MARKER,
  TRIAGE_REPORT_ARTIFACT_NAME,
  TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER,
  analysisHealthMarker,
  profileObservationsAnalysisMarker
} from '../src/artifact-contract.js';
import { runIdentity } from '../src/identity.js';
import { OPERATIONAL_ANALYSIS_MARKER } from '../src/regression/incidents.js';
import { scanProject } from '../src/run.js';
import { assertSchema } from '../src/schema-validator.js';
import type { AnalysisHealthRecord, ArtifactManifest, FindingRecord, RuleExpectation, RunRecord } from '../src/types.js';
import { compareCanonicalText, readJson, readJsonLines, sha256, writeCanonicalJson } from '../src/util/canonical.js';
import { verifyAndLoadRunDirectory, verifyRunDirectory } from '../src/verify.js';
import { renderTriageReportForMarker } from '../src/triage-report.js';

const CATALOG_DIGEST = 'a'.repeat(64);
const CORPUS_DIGEST = 'b'.repeat(64);

async function createCurrentRun(
  root: string,
  fixtureName: string,
  ruleExpectations: RuleExpectation[] = [],
  exclude: string[] = []
): Promise<string> {
  const fixtureRoot = path.join(root, fixtureName);
  const target = path.join(fixtureRoot, 'target');
  const targetConfigPath = path.join(fixtureRoot, 'target.json');
  const profilePath = path.join(fixtureRoot, 'profile.json');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), 'export const value = 1;\n', 'utf8');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'analysis-health-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'analysis-health-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts'],
    exclude,
    ruleExpectations
  });
  const scan = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath: path.join(fixtureRoot, 'workspace')
  });
  return scan.runDirectory;
}

async function createRunWithoutHealth(
  root: string,
  fixtureName: string,
  retainOperationalMarker: boolean
): Promise<string> {
  const runDirectory = await createCurrentRun(root, fixtureName);
  const run = await readJson<RunRecord>(path.join(runDirectory, 'run.json'));
  run.analyses = run.analyses.filter((analysis) =>
    !analysis.startsWith('analysis-health-v1') &&
    !analysis.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX) &&
    analysis !== TRIAGE_REPORT_ANALYSIS_MARKER &&
    (retainOperationalMarker || !analysis.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX))
  );
  run.artifacts = [...LEGACY_RUN_ARTIFACTS];
  delete run.counts.findingInstances;
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  await writeCanonicalJson(path.join(runDirectory, 'run.json'), run);
  await rm(path.join(runDirectory, 'analysis-health.json'));
  await rm(path.join(runDirectory, TRIAGE_REPORT_ARTIFACT_NAME));
  await sealRun(runDirectory, LEGACY_HASHED_RUN_ARTIFACTS);
  return runDirectory;
}

async function createLegacyRun(root: string): Promise<string> {
  return createRunWithoutHealth(root, 'legacy-source', false);
}

async function createDowngradedCurrentRun(root: string): Promise<string> {
  return createRunWithoutHealth(root, 'downgraded-current-source', true);
}

function buildHealth(run: RunRecord): AnalysisHealthRecord {
  return {
    schemaVersion: 1,
    runId: run.runId,
    snapshotId: run.snapshotId,
    producer: { id: 'atlas/analysis-health', version: '1.0.0' },
    catalogDigest: CATALOG_DIGEST,
    corpusDigest: CORPUS_DIGEST,
    status: 'complete',
    profilePatterns: [{
      id: 'include-src',
      collection: 'include-root',
      pattern: 'src',
      expected: { minimum: 1, maximum: 1 },
      observed: 1,
      status: 'passed'
    }],
    rules: [{
      ruleId: 'regression/example-v1',
      state: 'enabled',
      controls: {
        total: 1,
        passed: 1,
        failed: 0,
        expectedObservations: 1,
        observedObservations: 1
      }
    }],
    incidents: [{
      id: 'incident-example',
      family: 'silent-empty-instrument',
      ruleId: 'regression/example-v1',
      mechanismId: 'example-mechanism',
      broken: { expectedMinimum: 1, observed: 1, outcome: 'detected' },
      fixed: { expectedMaximum: 0, observed: 0, outcome: 'silent' },
      status: 'passed'
    }],
    recall: { numerator: 1, denominator: 1 },
    fixedCaseSilence: { numerator: 1, denominator: 1 }
  };
}

async function sealRun(runDirectory: string, artifactPaths: readonly string[]): Promise<void> {
  const run = await readJson<RunRecord>(path.join(runDirectory, 'run.json'));
  const artifacts = await Promise.all(artifactPaths.map(async (artifactPath) => {
    const content = await readFile(path.join(runDirectory, artifactPath));
    return { path: artifactPath, bytes: content.length, sha256: sha256(content) };
  }));
  artifacts.sort((left, right) => compareCanonicalText(left.path, right.path));
  const manifest: ArtifactManifest = { schemaVersion: 1, runId: run.runId, artifacts };
  await writeCanonicalJson(path.join(runDirectory, 'artifact-digests.json'), manifest);
}

async function resealCurrentRun(runDirectory: string): Promise<void> {
  const [run, findings, diagnostics] = await Promise.all([
    readJson<RunRecord>(path.join(runDirectory, 'run.json')),
    readJsonLines<FindingRecord>(path.join(runDirectory, 'findings.jsonl')),
    readJsonLines<import('../src/types.js').DiagnosticRecord>(path.join(runDirectory, 'diagnostics.jsonl'))
  ]);
  if (run.artifacts.includes(TRIAGE_REPORT_ARTIFACT_NAME)) {
    const triageMarker = run.analyses.find((analysis) => analysis.startsWith('triage-report-v'));
    assert(triageMarker);
    await writeFile(
      path.join(runDirectory, TRIAGE_REPORT_ARTIFACT_NAME),
      renderTriageReportForMarker(triageMarker, run, findings, diagnostics),
      'utf8'
    );
    await sealRun(runDirectory, TRIAGE_HASHED_RUN_ARTIFACTS);
    return;
  }
  await sealRun(runDirectory, ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS);
}

async function optInToAnalysisHealth(source: string, destination: string): Promise<AnalysisHealthRecord> {
  await cp(source, destination, { recursive: true });
  const run = await readJson<RunRecord>(path.join(destination, 'run.json'));
  run.analyses = [
    ...run.analyses,
    analysisHealthMarker('1.0.0', CATALOG_DIGEST, CORPUS_DIGEST)
  ].sort(compareCanonicalText);
  run.artifacts = [...ANALYSIS_HEALTH_RUN_ARTIFACTS];
  const findings = await readJsonLines<FindingRecord>(path.join(destination, 'findings.jsonl'));
  run.counts.findingInstances = findings.reduce((total, finding) => total + (finding.instanceCount ?? 1), 0);
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  const health = buildHealth(run);
  await writeCanonicalJson(path.join(destination, 'run.json'), run);
  await writeCanonicalJson(path.join(destination, 'analysis-health.json'), health);
  await resealCurrentRun(destination);
  return health;
}

async function mutateHealth(
  source: string,
  destination: string,
  mutate: (health: AnalysisHealthRecord) => void
): Promise<void> {
  await cp(source, destination, { recursive: true });
  const healthPath = path.join(destination, 'analysis-health.json');
  const health = await readJson<AnalysisHealthRecord>(healthPath);
  mutate(health);
  await writeCanonicalJson(healthPath, health);
  await resealCurrentRun(destination);
}

async function mutateCurrentRun(
  source: string,
  destination: string,
  mutate: (run: RunRecord, health: AnalysisHealthRecord) => void
): Promise<void> {
  await cp(source, destination, { recursive: true });
  const [run, health] = await Promise.all([
    readJson<RunRecord>(path.join(destination, 'run.json')),
    readJson<AnalysisHealthRecord>(path.join(destination, 'analysis-health.json'))
  ]);
  mutate(run, health);
  run.analyses = run.analyses.map((entry) => entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX)
    ? profileObservationsAnalysisMarker(health.profilePatterns)
    : entry);
  run.analyses.sort(compareCanonicalText);
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  health.runId = run.runId;
  await writeCanonicalJson(path.join(destination, 'run.json'), run);
  await writeCanonicalJson(path.join(destination, 'analysis-health.json'), health);
  await resealCurrentRun(destination);
}

test('verification accepts legacy and analysis-health-v1 artifact sets', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-valid-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const legacy = await createLegacyRun(root);

  const verifiedLegacy = await verifyAndLoadRunDirectory(legacy);
  assert.equal(verifiedLegacy.summary.artifacts, 8);
  assert.equal(verifiedLegacy.summary.healthState, 'legacy-not-recorded');
  assert.equal(verifiedLegacy.summary.healthStatus, 'not-recorded');
  assert.equal(verifiedLegacy.artifacts.analysisHealth, undefined);

  const current = path.join(root, 'analysis-health-run');
  const health = await optInToAnalysisHealth(legacy, current);
  const verifiedCurrent = await verifyAndLoadRunDirectory(current);
  assert.equal(verifiedCurrent.summary.artifacts, 9);
  assert.equal(verifiedCurrent.summary.healthState, 'recorded');
  assert.equal(verifiedCurrent.summary.healthStatus, 'complete');
  assert.deepEqual(verifiedCurrent.artifacts.analysisHealth, health);
});

test('current scans publish a recomputable triage Markdown artifact', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-triage-artifact-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'triage-current');
  const verified = await verifyAndLoadRunDirectory(current);
  assert.equal(verified.summary.artifacts, 10);
  assert(verified.artifacts.run.analyses.includes(TRIAGE_REPORT_ANALYSIS_MARKER));
  assert.match(verified.artifacts.triageReport ?? '', /^# Atlas triage report\n/u);

  const tampered = path.join(root, 'triage-tampered');
  await cp(current, tampered, { recursive: true });
  await writeFile(path.join(tampered, TRIAGE_REPORT_ARTIFACT_NAME), '# Atlas triage report\n\ntampered\n', 'utf8');
  await sealRun(tampered, TRIAGE_HASHED_RUN_ARTIFACTS);
  await assert.rejects(
    verifyRunDirectory(tampered),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_CONTENT'
  );
});

test('verification preserves the immutable triage-report v1.0.0 projection', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-triage-v1-compatibility-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'triage-v1-source');
  const legacyTriage = path.join(root, 'triage-v1-run');
  await cp(current, legacyTriage, { recursive: true });
  const [run, health] = await Promise.all([
    readJson<RunRecord>(path.join(legacyTriage, 'run.json')),
    readJson<AnalysisHealthRecord>(path.join(legacyTriage, 'analysis-health.json'))
  ]);
  health.producer.version = '1.3.1';
  delete health.recall.tier;
  delete health.realTargetEvaluation;
  run.analyses = run.analyses.map((analysis) =>
    analysis === TRIAGE_REPORT_ANALYSIS_MARKER
      ? TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER
      : analysis.startsWith('analysis-health-v1')
        ? analysisHealthMarker('1.3.1', health.catalogDigest, health.corpusDigest)
        : analysis.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX)
          ? 'operational-risks-v1.3.1'
          : analysis
  ).sort(compareCanonicalText);
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  health.runId = run.runId;
  await writeCanonicalJson(path.join(legacyTriage, 'run.json'), run);
  await writeCanonicalJson(path.join(legacyTriage, 'analysis-health.json'), health);
  await resealCurrentRun(legacyTriage);

  const verified = await verifyAndLoadRunDirectory(legacyTriage);
  assert(verified.artifacts.run.analyses.includes(TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER));
  assert.match(verified.artifacts.triageReport ?? '', /Producer: `atlas\/triage-report@1\.0\.0`/u);
  assert.doesNotMatch(verified.artifacts.triageReport ?? '', /retained only in `diagnostics\.jsonl`/u);
});

test('current analysis health rejects a legacy triage projection downgrade', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-triage-current-downgrade-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'triage-current-source');
  const downgraded = path.join(root, 'triage-current-downgraded');
  await cp(current, downgraded, { recursive: true });
  const [run, health] = await Promise.all([
    readJson<RunRecord>(path.join(downgraded, 'run.json')),
    readJson<AnalysisHealthRecord>(path.join(downgraded, 'analysis-health.json'))
  ]);
  run.analyses = run.analyses.map((analysis) =>
    analysis === TRIAGE_REPORT_ANALYSIS_MARKER ? TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER : analysis
  ).sort(compareCanonicalText);
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  health.runId = run.runId;
  await writeCanonicalJson(path.join(downgraded, 'run.json'), run);
  await writeCanonicalJson(path.join(downgraded, 'analysis-health.json'), health);
  await resealCurrentRun(downgraded);

  await assert.rejects(
    verifyAndLoadRunDirectory(downgraded),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );
});

test('current run identity binds canonical profile observations, including excluded-only counts', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-profile-observation-identity-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixtureName = 'excluded-count';
  const fixtureRoot = path.join(root, fixtureName);
  const excludedDirectory = path.join(fixtureRoot, 'target', 'src', 'generated');
  await mkdir(excludedDirectory, { recursive: true });
  await writeFile(path.join(excludedDirectory, 'one.ts'), 'export const one = 1;\n', 'utf8');

  const firstDirectory = await createCurrentRun(root, fixtureName, [], ['src/generated/**']);
  const [firstRun, firstHealth] = await Promise.all([
    readJson<RunRecord>(path.join(firstDirectory, 'run.json')),
    readJson<AnalysisHealthRecord>(path.join(firstDirectory, 'analysis-health.json'))
  ]);
  const firstObservation = firstHealth.profilePatterns.find((entry) => entry.pattern === 'src/generated/**');
  assert.equal(firstObservation?.observed, 1);
  assert.deepEqual(firstObservation?.samplePaths, ['src/generated/one.ts']);
  assert.equal(
    firstRun.analyses.find((entry) => entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX)),
    profileObservationsAnalysisMarker(firstHealth.profilePatterns)
  );

  await writeFile(path.join(excludedDirectory, 'two.ts'), 'export const two = 2;\n', 'utf8');
  const second = await scanProject({
    targetConfigPath: path.join(fixtureRoot, 'target.json'),
    profilePath: path.join(fixtureRoot, 'profile.json'),
    workspacePath: path.join(fixtureRoot, 'workspace')
  });
  const secondHealth = await readJson<AnalysisHealthRecord>(path.join(second.runDirectory, 'analysis-health.json'));
  const secondObservation = secondHealth.profilePatterns.find((entry) => entry.pattern === 'src/generated/**');
  assert.equal(secondObservation?.observed, 2);
  assert.deepEqual(secondObservation?.samplePaths, ['src/generated/one.ts', 'src/generated/two.ts']);
  assert.equal(second.run.snapshotId, firstRun.snapshotId);
  assert.notEqual(second.run.runId, firstRun.runId);
  assert.equal(second.reused, false);

  const mismatched = path.join(root, 'mismatched-profile-patterns');
  await mutateHealth(second.runDirectory, mismatched, (health) => {
    health.profilePatterns.find((entry) => entry.pattern === 'src/generated/**')!.observed += 1;
  });
  await assert.rejects(
    verifyRunDirectory(mismatched),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );

  const missingSamples = path.join(root, 'missing-profile-samples');
  await mutateCurrentRun(second.runDirectory, missingSamples, (_run, health) => {
    delete health.profilePatterns.find((entry) => entry.pattern === 'src/generated/**')!.samplePaths;
  });
  await assert.rejects(
    verifyRunDirectory(missingSamples),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_COUNT'
  );

  const unsortedSamples = path.join(root, 'unsorted-profile-samples');
  await mutateCurrentRun(second.runDirectory, unsortedSamples, (_run, health) => {
    health.profilePatterns.find((entry) => entry.pattern === 'src/generated/**')!.samplePaths!.reverse();
  });
  await assert.rejects(
    verifyRunDirectory(unsortedSamples),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_ORDER'
  );

  const duplicateSamples = path.join(root, 'duplicate-profile-samples');
  await mutateCurrentRun(second.runDirectory, duplicateSamples, (_run, health) => {
    health.profilePatterns.find((entry) => entry.pattern === 'src/generated/**')!.samplePaths = [
      'src/generated/one.ts',
      'src/generated/one.ts'
    ];
  });
  await assert.rejects(
    verifyRunDirectory(duplicateSamples),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );

  const overboundedSamples = path.join(root, 'overbounded-profile-samples');
  await mutateCurrentRun(second.runDirectory, overboundedSamples, (_run, health) => {
    const observation = health.profilePatterns.find((entry) => entry.pattern === 'src/generated/**')!;
    observation.observed = 33;
    observation.samplePaths = Array.from(
      { length: 33 },
      (_entry, index) => `src/generated/sample-${String(index).padStart(2, '0')}.ts`
    );
  });
  await assert.rejects(
    verifyRunDirectory(overboundedSamples),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );
});

test('current analysis health requires exactly the bundled operational-risk marker', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-operational-marker-binding-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'current-marker');

  const missing = path.join(root, 'missing-operational-marker');
  await mutateCurrentRun(current, missing, (run) => {
    run.analyses = run.analyses.filter((entry) => !entry.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX));
  });
  await assert.rejects(
    verifyRunDirectory(missing),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );

  const arbitrary = path.join(root, 'arbitrary-operational-marker');
  await mutateCurrentRun(current, arbitrary, (run) => {
    run.analyses = run.analyses.map((entry) => entry.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX)
      ? 'operational-risks-v999.0.0'
      : entry);
  });
  await assert.rejects(
    verifyRunDirectory(arbitrary),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );

  const duplicate = path.join(root, 'duplicate-operational-marker');
  await mutateCurrentRun(current, duplicate, (run) => {
    run.analyses.push('operational-risks-v0.0.0');
  });
  await assert.rejects(
    verifyRunDirectory(duplicate),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_DUPLICATE'
  );

  const verified = await verifyAndLoadRunDirectory(current);
  assert.deepEqual(
    verified.artifacts.run.analyses.filter((entry) => entry.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX)),
    [OPERATIONAL_ANALYSIS_MARKER]
  );

  const previous = path.join(root, 'previous-supported-pair');
  await mutateCurrentRun(current, previous, (run, health) => {
    health.producer.version = '1.3.1';
    delete health.recall.tier;
    delete health.realTargetEvaluation;
    run.analyses = run.analyses.map((entry) => {
      if (entry.startsWith('analysis-health-v1')) {
        return analysisHealthMarker('1.3.1', health.catalogDigest, health.corpusDigest);
      }
      return entry.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX) ? 'operational-risks-v1.3.1' : entry;
    });
  });
  assert.equal((await verifyRunDirectory(previous)).status, 'passed');

  const olderSupported = path.join(root, 'older-supported-pair');
  await mutateCurrentRun(current, olderSupported, (run, health) => {
    health.producer.version = '1.3.0';
    delete health.recall.tier;
    delete health.realTargetEvaluation;
    run.analyses = run.analyses.map((entry) => {
      if (entry.startsWith('analysis-health-v1')) {
        return analysisHealthMarker('1.3.0', health.catalogDigest, health.corpusDigest);
      }
      return entry.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX) ? 'operational-risks-v1.3.0' : entry;
    });
  });
  assert.equal((await verifyRunDirectory(olderSupported)).status, 'passed');

  const earliestSupported = path.join(root, 'earliest-supported-pair');
  await mutateCurrentRun(current, earliestSupported, (run, health) => {
    health.producer.version = '1.2.0';
    delete health.recall.tier;
    delete health.realTargetEvaluation;
    run.analyses = run.analyses.map((entry) => {
      if (entry.startsWith('analysis-health-v1')) {
        return analysisHealthMarker('1.2.0', health.catalogDigest, health.corpusDigest);
      }
      return entry.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX) ? 'operational-risks-v1.2.2' : entry;
    });
  });
  assert.equal((await verifyRunDirectory(earliestSupported)).status, 'passed');

  const mismatchedPrevious = path.join(root, 'mismatched-previous-pair');
  await mutateCurrentRun(current, mismatchedPrevious, (run, health) => {
    health.producer.version = '1.3.1';
    delete health.recall.tier;
    delete health.realTargetEvaluation;
    run.analyses = run.analyses.map((entry) => entry.startsWith('analysis-health-v1')
      ? analysisHealthMarker('1.3.1', health.catalogDigest, health.corpusDigest)
      : entry);
  });
  await assert.rejects(
    verifyRunDirectory(mismatchedPrevious),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );
});

test('analysis-health marker, artifact, and exact directory set are mutually required', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-set-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const legacy = await createLegacyRun(root);

  const downgradedCurrent = await createDowngradedCurrentRun(root);
  await assert.rejects(
    verifyRunDirectory(downgradedCurrent),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_ARTIFACT_SET'
  );

  const missingHealth = path.join(root, 'missing-health');
  await cp(legacy, missingHealth, { recursive: true });
  const markedRun = await readJson<RunRecord>(path.join(missingHealth, 'run.json'));
  markedRun.analyses = [
    ...markedRun.analyses,
    analysisHealthMarker('1.0.0', CATALOG_DIGEST, CORPUS_DIGEST)
  ].sort(compareCanonicalText);
  markedRun.artifacts = [...ANALYSIS_HEALTH_RUN_ARTIFACTS];
  markedRun.runId = runIdentity({
    snapshotId: markedRun.snapshotId,
    targetId: markedRun.targetId,
    profileId: markedRun.profileId,
    profileDigest: markedRun.profileDigest,
    tool: markedRun.tool,
    adapters: markedRun.adapters,
    discovery: markedRun.discovery,
    analyses: markedRun.analyses
  });
  await writeCanonicalJson(path.join(missingHealth, 'run.json'), markedRun);
  await sealRun(missingHealth, LEGACY_HASHED_RUN_ARTIFACTS);
  await assert.rejects(
    verifyRunDirectory(missingHealth),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_ARTIFACT_SET'
  );

  const unknownExtra = path.join(root, 'unknown-extra');
  await cp(legacy, unknownExtra, { recursive: true });
  await writeFile(path.join(unknownExtra, 'unknown.json'), '{}\n', 'utf8');
  await assert.rejects(
    verifyRunDirectory(unknownExtra),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_ARTIFACT_SET'
  );
});

test('analysis health verification checks aggregate counts, rule references, and digest binding', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-semantics-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const legacy = await createLegacyRun(root);
  const valid = path.join(root, 'valid');
  await optInToAnalysisHealth(legacy, valid);

  const badRecall = path.join(root, 'bad-recall');
  await mutateHealth(valid, badRecall, (health) => { health.recall.numerator = 0; });
  await assert.rejects(
    verifyRunDirectory(badRecall),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_COUNT'
  );

  const missingRule = path.join(root, 'missing-rule');
  await mutateHealth(valid, missingRule, (health) => { health.incidents[0]!.ruleId = 'regression/missing-v1'; });
  await assert.rejects(
    verifyRunDirectory(missingRule),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_REFERENTIAL_INTEGRITY'
  );

  const unboundCatalog = path.join(root, 'unbound-catalog');
  await mutateHealth(valid, unboundCatalog, (health) => { health.catalogDigest = 'c'.repeat(64); });
  await assert.rejects(
    verifyRunDirectory(unboundCatalog),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );
});

test('analysis health is schema-validated after its manifest digest is verified', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-schema-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const legacy = await createLegacyRun(root);
  const valid = path.join(root, 'valid');
  await optInToAnalysisHealth(legacy, valid);
  const invalid = path.join(root, 'invalid');
  await mutateHealth(valid, invalid, (health) => { health.rules[0]!.controls.failed = -1; });
  await assert.rejects(
    verifyRunDirectory(invalid),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );
});

test('current analysis health cannot substitute self-declared catalog and corpus digests', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-bundle-binding-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'current-binding');
  const [run, health] = await Promise.all([
    readJson<RunRecord>(path.join(current, 'run.json')),
    readJson<AnalysisHealthRecord>(path.join(current, 'analysis-health.json'))
  ]);
  health.catalogDigest = 'c'.repeat(64);
  health.corpusDigest = 'd'.repeat(64);
  run.analyses = run.analyses.map((analysis) => analysis.startsWith('analysis-health-v1')
    ? analysisHealthMarker(health.producer.version, health.catalogDigest, health.corpusDigest)
    : analysis
  ).sort(compareCanonicalText);
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  health.runId = run.runId;
  await writeCanonicalJson(path.join(current, 'run.json'), run);
  await writeCanonicalJson(path.join(current, 'analysis-health.json'), health);
  await resealCurrentRun(current);

  await assert.rejects(
    verifyRunDirectory(current),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );
});

test('current operational runs cannot downgrade analysis health or substitute coherent control outcomes', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-current-controls-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'current-controls');

  const downgraded = path.join(root, 'downgraded-health-producer');
  await cp(current, downgraded, { recursive: true });
  const downgradedRun = await readJson<RunRecord>(path.join(downgraded, 'run.json'));
  const downgradedHealth = await readJson<AnalysisHealthRecord>(path.join(downgraded, 'analysis-health.json'));
  downgradedHealth.producer.version = '1.1.0';
  delete downgradedHealth.recall.tier;
  delete downgradedHealth.realTargetEvaluation;
  downgradedRun.analyses = downgradedRun.analyses.map((analysis) =>
    analysis.startsWith('analysis-health-v1')
      ? analysisHealthMarker(
          downgradedHealth.producer.version,
          downgradedHealth.catalogDigest,
          downgradedHealth.corpusDigest
        )
      : analysis
  ).sort(compareCanonicalText);
  downgradedRun.runId = runIdentity({
    snapshotId: downgradedRun.snapshotId,
    targetId: downgradedRun.targetId,
    profileId: downgradedRun.profileId,
    profileDigest: downgradedRun.profileDigest,
    tool: downgradedRun.tool,
    adapters: downgradedRun.adapters,
    discovery: downgradedRun.discovery,
    analyses: downgradedRun.analyses
  });
  downgradedHealth.runId = downgradedRun.runId;
  await writeCanonicalJson(path.join(downgraded, 'run.json'), downgradedRun);
  await writeCanonicalJson(path.join(downgraded, 'analysis-health.json'), downgradedHealth);
  await resealCurrentRun(downgraded);
  await assert.rejects(
    verifyRunDirectory(downgraded),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );

  const substituted = path.join(root, 'substituted-control-results');
  await mutateHealth(current, substituted, (health) => {
    const incident = health.incidents[0]!;
    const rule = health.rules.find((entry) => entry.ruleId === incident.ruleId)!;
    incident.broken.observed += 1;
    rule.controls.observedObservations += 1;
  });
  await assert.rejects(
    verifyRunDirectory(substituted),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_IDENTITY'
  );
});

test('public run verification exposes a valid legacy incomplete health status', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-summary-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const legacy = await createLegacyRun(root);
  const complete = path.join(root, 'complete-old-health');
  await optInToAnalysisHealth(legacy, complete);
  const incomplete = path.join(root, 'incomplete-old-health');
  await mutateHealth(complete, incomplete, (health) => {
    const incident = health.incidents[0]!;
    const rule = health.rules[0]!;
    incident.broken.observed = 0;
    incident.broken.outcome = 'missed';
    incident.status = 'failed';
    rule.controls.passed = 0;
    rule.controls.failed = 1;
    rule.controls.observedObservations = 0;
    rule.state = 'disabled';
    health.recall.numerator = 0;
    health.status = 'incomplete';
  });

  const summary = await verifyRunDirectory(incomplete);
  assert.equal(summary.status, 'passed');
  assert.equal(summary.healthState, 'recorded');
  assert.equal(summary.healthStatus, 'incomplete');
});

test('current analysis health records normalized target accounting and verifies finding-instance totals', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-analysis-health-target-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const expectation: RuleExpectation = {
    ruleId: 'operational/result-collapse-v1',
    minObservations: 0,
    maxObservations: 0,
    minFindings: 0,
    maxFindings: 0
  };
  const current = await createCurrentRun(root, 'target-accounting', [expectation]);
  const [health, findings] = await Promise.all([
    readJson<AnalysisHealthRecord>(path.join(current, 'analysis-health.json')),
    readJsonLines<FindingRecord>(path.join(current, 'findings.jsonl'))
  ]);
  assert.equal(health.producer.version, '1.3.2');
  assert.equal(health.recall.tier, 'synthetic');
  assert.deepEqual(health.realTargetEvaluation, {
    tier: 'real-target',
    result: 'not-recorded-in-run',
    reportContract: 'real-target-corpus-report.schema.json'
  });
  assert(health.rules.every((rule) => rule.target !== undefined));
  const expectedRule = health.rules.find((rule) => rule.ruleId === expectation.ruleId);
  assert.deepEqual(expectedRule?.target?.expectations, {
    minimumDetectedObservations: 0,
    maximumPossibleObservations: 0,
    minimumFindingInstances: 0,
    maximumFindingInstances: 0
  });
  for (const rule of health.rules) {
    assert.equal(
      rule.target?.findingInstances,
      findings.filter((finding) => finding.ruleId === rule.ruleId)
        .reduce((total, finding) => total + (finding.instanceCount ?? 1), 0)
    );
  }
  await verifyRunDirectory(current);

  const missingSyntheticTier = path.join(root, 'missing-synthetic-tier');
  await mutateHealth(current, missingSyntheticTier, (record) => {
    delete record.recall.tier;
  });
  await assert.rejects(
    verifyRunDirectory(missingSyntheticTier),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );

  const missingRealTargetPointer = path.join(root, 'missing-real-target-pointer');
  await mutateHealth(current, missingRealTargetPointer, (record) => {
    delete record.realTargetEvaluation;
  });
  await assert.rejects(
    verifyRunDirectory(missingRealTargetPointer),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );

  const mismatched = path.join(root, 'mismatched-target-count');
  await mutateHealth(current, mismatched, (record) => {
    const target = record.rules[0]?.target;
    assert(target);
    target.findingInstances += 1;
  });
  await assert.rejects(
    verifyRunDirectory(mismatched),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_COUNT'
  );

  const missingCurrentTarget = path.join(root, 'missing-current-target');
  await mutateHealth(current, missingCurrentTarget, (record) => {
    delete record.rules[0]!.target;
  });
  await assert.rejects(
    verifyRunDirectory(missingCurrentTarget),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_COUNT'
  );
});

test('current runs must declare the verified finding-instance total', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-finding-instance-count-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const current = await createCurrentRun(root, 'missing-instance-count');
  const run = await readJson<RunRecord>(path.join(current, 'run.json'));
  delete run.counts.findingInstances;
  await writeCanonicalJson(path.join(current, 'run.json'), run);
  await resealCurrentRun(current);

  await assert.rejects(
    verifyRunDirectory(current),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );
});

test('finding instance schema matches verifier singleton and aggregate semantics', async () => {
  const base: FindingRecord = {
    schemaVersion: 1,
    id: `finding:${'1'.repeat(24)}`,
    category: 'operational-defect',
    ruleId: 'operational/example-v1',
    status: 'candidate',
    severity: 'low',
    confidence: 'high',
    title: 'Example finding',
    description: 'Schema contract fixture.',
    relatedPaths: [],
    signals: ['example'],
    evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'fixture' }],
    nextValidation: 'Inspect the example.'
  };
  await assertSchema('finding', { ...base, instanceCount: 1 }, 'Explicit singleton finding');
  await assert.rejects(
    assertSchema('finding', {
      ...base,
      instances: [{
        id: `finding:${'2'.repeat(24)}`,
        severity: 'low',
        confidence: 'high',
        relatedPaths: [],
        signals: ['example'],
        evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'fixture' }]
      }]
    }, 'Aggregate missing instance count'),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );
  await assert.rejects(
    assertSchema('finding', { ...base, instanceCount: 2 }, 'Unmaterialized aggregate'),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );
});
