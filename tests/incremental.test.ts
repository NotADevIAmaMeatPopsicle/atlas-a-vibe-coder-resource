import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { HASHED_RUN_ARTIFACTS } from '../src/artifact-contract.js';
import { runIdentity } from '../src/identity.js';
import {
  incrementalBatchPlanIdentity,
  incrementalPlanIdentity,
  planIncrementalAnalysis,
  planIncrementalAnalysisBatch
} from '../src/incremental/index.js';
import { scanProject } from '../src/run.js';
import { renderTriageReport } from '../src/triage-report.js';
import type { AnalysisHealthRecord, ArtifactManifest, DiagnosticRecord, ExecutionRecord, FindingRecord, RunRecord } from '../src/types.js';
import { canonicalJson, compareCanonicalText, readJson, readJsonLines, sha256, writeCanonicalJson } from '../src/util/canonical.js';
import type { GitDiscoveryResult } from '../src/discovery/types.js';

interface Fixture {
  root: string;
  targetRoot: string;
  targetConfigPath: string;
  profilePath: string;
  workspacePath: string;
  targetId: string;
  paths: {
    app: string;
    index: string;
    dependency: string;
    unrelated: string;
  };
}

async function createFixture(root: string, name: string, targetId: string): Promise<Fixture> {
  const targetRoot = path.join(root, name);
  const targetConfigPath = path.join(root, `${name}.target.json`);
  const profilePath = path.join(root, `${name}.profile.json`);
  const workspacePath = path.join(root, 'workspace');
  const prefix = name.replace(/[^A-Za-z0-9]/gu, '_');
  const paths = {
    app: `src/${prefix}-app.ts`,
    index: `src/${prefix}-index.ts`,
    dependency: `src/${prefix}-dependency.ts`,
    unrelated: `src/${prefix}-unrelated.ts`
  };
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await writeFile(path.join(targetRoot, ...paths.dependency.split('/')), 'export const dependency = 1;\n', 'utf8');
  await writeFile(path.join(targetRoot, ...paths.index.split('/')), [
    `import { dependency } from './${prefix}-dependency.js';`,
    'export const indexed = dependency;',
    ''
  ].join('\n'), 'utf8');
  await writeFile(path.join(targetRoot, ...paths.app.split('/')), [
    `import { indexed } from './${prefix}-index.js';`,
    'console.log(indexed);',
    ''
  ].join('\n'), 'utf8');
  await writeFile(path.join(targetRoot, ...paths.unrelated.split('/')), 'export const unrelated = true;\n', 'utf8');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: targetId,
    path: `./${name}`,
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: `${targetId}-profile`,
    includeRoots: ['src'],
    entrypoints: [paths.app]
  }, null, 2)}\n`, 'utf8');
  return { root, targetRoot, targetConfigPath, profilePath, workspacePath, targetId, paths };
}

async function scan(fixture: Fixture) {
  return scanProject({
    targetConfigPath: fixture.targetConfigPath,
    profilePath: fixture.profilePath,
    workspacePath: fixture.workspacePath
  });
}

function planOptions(fixture: Fixture, baselineRunDirectory: string, nextRunDirectory: string) {
  return {
    workspacePath: fixture.workspacePath,
    targetId: fixture.targetId,
    baselineRunDirectory,
    nextRunDirectory
  };
}

async function deriveCanonicalRun(options: {
  fixture: Fixture;
  sourceRunDirectory: string;
  sourceAttemptPath: string;
  addAnalysis?: string;
  discoveryState?: GitDiscoveryResult['state'];
}): Promise<string> {
  const run = await readJson<RunRecord>(path.join(options.sourceRunDirectory, 'run.json'));
  const discovery = await readJson<GitDiscoveryResult>(path.join(options.sourceRunDirectory, 'discovery.json'));
  if (options.addAnalysis) run.analyses = [...run.analyses, options.addAnalysis].sort(compareCanonicalText);
  if (options.discoveryState) {
    discovery.state = options.discoveryState;
    run.discovery.state = options.discoveryState;
    run.discovery.digest = sha256(canonicalJson(discovery));
  }
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
  const temporary = path.join(options.fixture.workspacePath, 'runs', `.tmp-derived-${run.runId}`);
  const destination = path.join(options.fixture.workspacePath, 'runs', run.runId);
  await cp(options.sourceRunDirectory, temporary, { recursive: true });
  await writeCanonicalJson(path.join(temporary, 'run.json'), run);
  await writeCanonicalJson(path.join(temporary, 'discovery.json'), discovery);
  const analysisHealth = await readJson<AnalysisHealthRecord>(path.join(temporary, 'analysis-health.json'));
  analysisHealth.runId = run.runId;
  await writeCanonicalJson(path.join(temporary, 'analysis-health.json'), analysisHealth);
  const [findings, diagnostics] = await Promise.all([
    readJsonLines<FindingRecord>(path.join(temporary, 'findings.jsonl')),
    readJsonLines<DiagnosticRecord>(path.join(temporary, 'diagnostics.jsonl'))
  ]);
  await writeFile(path.join(temporary, 'triage.md'), renderTriageReport(run, findings, diagnostics), 'utf8');
  const manifest: ArtifactManifest = {
    schemaVersion: 1,
    runId: run.runId,
    artifacts: await Promise.all(HASHED_RUN_ARTIFACTS.map(async (artifactPath) => {
      const content = await readFile(path.join(temporary, artifactPath));
      return { path: artifactPath, bytes: content.length, sha256: sha256(content) };
    }))
  };
  manifest.artifacts.sort((left, right) => compareCanonicalText(left.path, right.path));
  await writeCanonicalJson(path.join(temporary, 'artifact-digests.json'), manifest);
  await rename(temporary, destination);

  const sourceAttempt = await readJson<ExecutionRecord>(options.sourceAttemptPath);
  const attemptId = `att_20990101T000000Z_${sha256(run.runId).slice(0, 32)}`;
  const derivedAttempt: ExecutionRecord = {
    ...sourceAttempt,
    attemptId,
    runId: run.runId,
    startedAt: '2099-01-01T00:00:00.000Z',
    finishedAt: '2099-01-01T00:00:01.000Z',
    status: 'reused'
  };
  delete derivedAttempt.error;
  await writeCanonicalJson(path.join(options.fixture.workspacePath, 'attempts', `${attemptId}.json`), derivedAttempt);
  return destination;
}

test('unchanged verified runs produce an all-hit deterministic plan without target writes', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-unchanged-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createFixture(root, 'project', 'unchanged-target');
  const scanned = await scan(fixture);
  const observedPath = path.join(fixture.targetRoot, ...fixture.paths.dependency.split('/'));
  const before = await stat(observedPath);

  const first = await planIncrementalAnalysis(planOptions(fixture, scanned.runDirectory, scanned.runDirectory));
  const second = await planIncrementalAnalysis(planOptions(fixture, scanned.runDirectory, scanned.runDirectory));
  const after = await stat(observedPath);
  assert.deepEqual(second, first);
  const { planId, ...identityMaterial } = first;
  assert.equal(planId, incrementalPlanIdentity(identityMaterial));
  assert.deepEqual(first.paths, { added: [], changed: [], removed: [] });
  assert.deepEqual(first.evidenceEdges, { added: [], changed: [], removed: [] });
  assert.deepEqual(first.impact.seedPaths, []);
  assert.deepEqual(first.impact.reverseDependencyClosurePaths, []);
  assert.equal(first.compatibility.incrementalReuseEligible, true);
  assert.deepEqual(first.compatibility.fullRebuildReasons, []);
  assert.deepEqual(first.cache.missRequiredPaths, []);
  assert.deepEqual(first.cache.evictedPaths, []);
  assert.equal(first.cache.hitEligiblePaths.length, 4);
  assert.equal(first.baseline.runId, first.next.runId);
  assert.equal(first.baseline.artifactManifestDigest, first.next.artifactManifestDigest);
  assert.equal(after.mtimeMs, before.mtimeMs);
});

test('a source change propagates through reverse dependencies and changed evidence', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-change-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createFixture(root, 'project', 'change-target');
  const baseline = await scan(fixture);
  await writeFile(path.join(fixture.targetRoot, ...fixture.paths.dependency.split('/')), [
    "import './missing.js';",
    'export const dependency = 2;',
    ''
  ].join('\n'), 'utf8');
  const next = await scan(fixture);

  const plan = await planIncrementalAnalysis(planOptions(fixture, baseline.runDirectory, next.runDirectory));
  assert.deepEqual(plan.paths, { added: [], changed: [fixture.paths.dependency], removed: [] });
  assert(plan.evidenceEdges.added.some((edge) =>
    edge.fromPath === fixture.paths.dependency && edge.resolution === 'unresolved-internal'
  ));
  assert.deepEqual(plan.impact.reverseDependencyClosurePaths, [
    fixture.paths.app,
    fixture.paths.dependency,
    fixture.paths.index
  ].sort(compareCanonicalText));
  assert.deepEqual(plan.cache.missRequiredPaths, plan.impact.reverseDependencyClosurePaths);
  assert.deepEqual(plan.cache.hitEligiblePaths, [fixture.paths.unrelated]);
  assert(plan.impact.affectedRecords.nextDiagnosticIds.length > 0);
  assert(plan.impact.affectedRecords.nextFindingIds.length > 0);
  assert.equal(plan.compatibility.incrementalReuseEligible, true);
});

test('removal evicts the old path and invalidates dependents through the old and new edge union', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-removal-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createFixture(root, 'project', 'removal-target');
  const baseline = await scan(fixture);
  await rm(path.join(fixture.targetRoot, ...fixture.paths.dependency.split('/')));
  const next = await scan(fixture);

  const plan = await planIncrementalAnalysis(planOptions(fixture, baseline.runDirectory, next.runDirectory));
  assert.deepEqual(plan.paths.removed, [fixture.paths.dependency]);
  assert.deepEqual(plan.cache.evictedPaths, [fixture.paths.dependency]);
  assert(plan.evidenceEdges.changed.some((edge) =>
    edge.before.toPath === fixture.paths.dependency && edge.after.resolution === 'unresolved-internal'
  ));
  assert.deepEqual(plan.impact.reverseDependencyClosurePaths, [
    fixture.paths.app,
    fixture.paths.dependency,
    fixture.paths.index
  ].sort(compareCanonicalText));
  assert.deepEqual(plan.compatibility.fullRebuildReasons, ['PROFILE_OBSERVATIONS_CHANGED']);
  assert.deepEqual(plan.cache.missRequiredPaths, [
    fixture.paths.app,
    fixture.paths.index,
    fixture.paths.unrelated
  ].sort(compareCanonicalText));
  assert.deepEqual(plan.cache.hitEligiblePaths, []);
});

test('excluded-only profile observation changes have a dedicated full-rebuild reason', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-profile-observations-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createFixture(root, 'project', 'profile-observation-target');
  const excludedDirectory = path.join(fixture.targetRoot, 'src', 'generated');
  await mkdir(excludedDirectory, { recursive: true });
  await writeFile(path.join(excludedDirectory, 'one.ts'), 'export const one = 1;\n', 'utf8');
  await writeFile(fixture.profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: `${fixture.targetId}-profile`,
    includeRoots: ['src'],
    exclude: ['src/generated/**'],
    entrypoints: [fixture.paths.app]
  }, null, 2)}\n`, 'utf8');
  const baseline = await scan(fixture);

  await writeFile(path.join(excludedDirectory, 'two.ts'), 'export const two = 2;\n', 'utf8');
  const next = await scan(fixture);
  const plan = await planIncrementalAnalysis(planOptions(fixture, baseline.runDirectory, next.runDirectory));

  assert.deepEqual(plan.paths, { added: [], changed: [], removed: [] });
  assert.deepEqual(plan.compatibility.fullRebuildReasons, ['PROFILE_OBSERVATIONS_CHANGED']);
  assert.equal(plan.compatibility.incrementalReuseEligible, false);
  assert.deepEqual(plan.cache.hitEligiblePaths, []);
  assert.deepEqual(plan.cache.missRequiredPaths, Object.values(fixture.paths).sort(compareCanonicalText));
});

test('profile, analyzer, and discovery incompatibility produce explicit full-rebuild reasons', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-compatibility-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createFixture(root, 'project', 'compatibility-target');
  const baseline = await scan(fixture);

  await writeFile(fixture.profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: `${fixture.targetId}-profile`,
    includeRoots: ['src'],
    entrypoints: [fixture.paths.app],
    deadCodeExemptions: [fixture.paths.unrelated]
  }, null, 2)}\n`, 'utf8');
  const changedProfile = await scan(fixture);
  const profilePlan = await planIncrementalAnalysis(planOptions(fixture, baseline.runDirectory, changedProfile.runDirectory));
  assert.deepEqual(profilePlan.compatibility.fullRebuildReasons, [
    'PROFILE_DIGEST_CHANGED',
    'PROFILE_OBSERVATIONS_CHANGED'
  ]);
  assert.equal(profilePlan.compatibility.incrementalReuseEligible, false);
  assert.deepEqual(profilePlan.cache.hitEligiblePaths, []);
  assert.equal(profilePlan.cache.missRequiredPaths.length, 4);

  const synthetic = await deriveCanonicalRun({
    fixture,
    sourceRunDirectory: baseline.runDirectory,
    sourceAttemptPath: baseline.attemptPath,
    addAnalysis: 'synthetic-analyzer-v999',
    discoveryState: 'unsupported'
  });
  const compatibilityPlan = await planIncrementalAnalysis(planOptions(fixture, baseline.runDirectory, synthetic));
  assert.deepEqual(compatibilityPlan.compatibility.fullRebuildReasons, [
    'ANALYZER_SET_CHANGED',
    'DISCOVERY_STATE_CHANGED'
  ]);
  assert.equal(compatibilityPlan.compatibility.incrementalReuseEligible, false);
  assert.deepEqual(compatibilityPlan.cache.hitEligiblePaths, []);
  assert.equal(compatibilityPlan.cache.missRequiredPaths.length, 4);
});

test('tampered canonical-run inputs are rejected before a plan is returned', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-tamper-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const fixture = await createFixture(root, 'project', 'tamper-target');
  const baseline = await scan(fixture);
  await writeFile(path.join(fixture.targetRoot, ...fixture.paths.dependency.split('/')), 'export const dependency = 9;\n', 'utf8');
  const next = await scan(fixture);
  await writeFile(path.join(next.runDirectory, 'files.jsonl'), '{"forged":true}\n', 'utf8');

  await assert.rejects(
    planIncrementalAnalysis(planOptions(fixture, baseline.runDirectory, next.runDirectory)),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_DIGEST'
  );
});

test('workspace batch planning is deterministic and strictly isolates registered targets', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incremental-batch-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const alpha = await createFixture(root, 'alpha-project', 'alpha-target');
  const beta = await createFixture(root, 'beta-project', 'beta-target');
  const alphaBaseline = await scan(alpha);
  const betaBaseline = await scan(beta);
  await writeFile(path.join(alpha.targetRoot, ...alpha.paths.dependency.split('/')), 'export const dependency = 11;\n', 'utf8');
  await writeFile(path.join(beta.targetRoot, ...beta.paths.unrelated.split('/')), 'export const unrelated = 22;\n', 'utf8');
  const alphaNext = await scan(alpha);
  const betaNext = await scan(beta);
  const targets = [
    {
      targetId: beta.targetId,
      baselineRunDirectory: betaBaseline.runDirectory,
      nextRunDirectory: betaNext.runDirectory
    },
    {
      targetId: alpha.targetId,
      baselineRunDirectory: alphaBaseline.runDirectory,
      nextRunDirectory: alphaNext.runDirectory
    }
  ];

  const first = await planIncrementalAnalysisBatch({ workspacePath: alpha.workspacePath, targets });
  const second = await planIncrementalAnalysisBatch({ workspacePath: alpha.workspacePath, targets: [...targets].reverse() });
  assert.deepEqual(second, first);
  const { batchPlanId, ...identityMaterial } = first;
  assert.equal(batchPlanId, incrementalBatchPlanIdentity(identityMaterial));
  assert.deepEqual(first.plans.map((plan) => plan.targetId), ['alpha-target', 'beta-target']);
  assert.deepEqual(first.plans[0]?.paths.changed, [alpha.paths.dependency]);
  assert.deepEqual(first.plans[1]?.paths.changed, [beta.paths.unrelated]);
  assert(!canonicalJson(first.plans[0]).includes(beta.paths.unrelated));
  assert(!canonicalJson(first.plans[1]).includes(alpha.paths.dependency));

  await assert.rejects(
    planIncrementalAnalysis({
      workspacePath: alpha.workspacePath,
      targetId: alpha.targetId,
      baselineRunDirectory: alphaBaseline.runDirectory,
      nextRunDirectory: betaNext.runDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'INCREMENTAL_TARGET_MISMATCH'
  );
});
