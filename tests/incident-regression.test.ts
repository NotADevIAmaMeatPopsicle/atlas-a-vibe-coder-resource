import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assertSchema } from '../src/schema-validator.js';
import {
  buildAnalysisHealthRecord,
  enforceRuleExpectations,
  evaluateOperationalControls,
  OPERATIONAL_MECHANISM_CATALOG
} from '../src/regression/incidents.js';
import type { ResolvedProfile } from '../src/types.js';
import type { OperationalRiskResult } from '../src/analysis/operational-risks.js';
import { canonicalJson } from '../src/util/canonical.js';

test('the labeled broken/fixed corpus covers every operational rule with full recall', async () => {
  const first = await evaluateOperationalControls();
  const second = await evaluateOperationalControls();
  assert.equal(canonicalJson(first.rules), canonicalJson(second.rules));
  assert.equal(canonicalJson(first.incidents), canonicalJson(second.incidents));
  assert.equal(first.rules.length, 9);
  assert.equal(first.incidents.length, 21);
  assert.deepEqual(
    first.incidents.map((incident) => `${incident.ruleId}\0${incident.mechanismId}`).sort(),
    OPERATIONAL_MECHANISM_CATALOG.map((mechanism) => `${mechanism.ruleId}\0${mechanism.mechanismId}`).sort()
  );
  assert(first.rules.every((rule) => rule.state === 'enabled'));
  assert(first.incidents.every((incident) =>
    incident.broken.outcome === 'detected' &&
    incident.fixed.outcome === 'silent' &&
    incident.status === 'passed'
  ));

  const targetRuleId = 'operational/result-collapse-v1' as const;
  const targetEvidence = { level: 1 as const, producer: 'test', producerVersion: '1', basis: 'fixture' };
  const operational = {
    findings: [{
      schemaVersion: 1,
      id: `finding:${'3'.repeat(24)}`,
      category: 'operational-defect',
      ruleId: targetRuleId,
      kind: 'defect-candidate',
      patternKey: 'result-collapse:test',
      instanceCount: 1,
      impactContext: {
        reachability: 'unknown',
        entrypoints: [],
        mountedSurfaces: [],
        featureGate: 'unknown',
        summary: 'Static fixture.',
        limitations: []
      },
      status: 'candidate',
      severity: 'medium',
      confidence: 'high',
      title: 'Fixture finding',
      description: 'Fixture operational finding.',
      relatedPaths: [],
      signals: ['fixture'],
      evidence: [targetEvidence],
      nextValidation: 'Inspect the fixture.'
    }],
    diagnostics: [],
    containerCoverage: [],
    observations: [
      {
        schemaVersion: 1,
        id: 'observation:detected',
        ruleId: targetRuleId,
        state: 'detected',
        path: 'src/example.ts',
        location: { line: 1, column: 1, endLine: 1, endColumn: 2 },
        fingerprint: 'detected',
        evidence: targetEvidence
      },
      {
        schemaVersion: 1,
        id: 'observation:uncertain',
        ruleId: targetRuleId,
        state: 'uncertain',
        path: 'src/example.ts',
        location: { line: 2, column: 1, endLine: 2, endColumn: 2 },
        fingerprint: 'uncertain',
        evidence: targetEvidence
      }
    ]
  } satisfies OperationalRiskResult;
  const health = buildAnalysisHealthRecord({
    runId: `run_sha256_${'1'.repeat(64)}`,
    snapshotId: `snapshot_sha256_${'2'.repeat(64)}`,
    profileObservations: [{
      id: 'required-include-root:src',
      collection: 'includeRoots',
      pattern: 'src',
      minMatches: 1,
      actualMatches: 4,
      status: 'passed',
      samplePaths: ['src/index.ts']
    }],
    controls: first,
    operational,
    ruleExpectations: [{
      ruleId: targetRuleId,
      minObservations: 1,
      maxObservations: 2,
      minFindings: 1,
      maxFindings: 2
    }]
  });
  assert.deepEqual(health.recall, { tier: 'synthetic', numerator: 21, denominator: 21 });
  assert.deepEqual(health.realTargetEvaluation, {
    tier: 'real-target',
    result: 'not-recorded-in-run',
    reportContract: 'real-target-corpus-report.schema.json'
  });
  assert.deepEqual(health.fixedCaseSilence, { numerator: 21, denominator: 21 });
  assert.equal(health.status, 'complete');
  assert.deepEqual(health.rules.find((rule) => rule.ruleId === targetRuleId)?.target, {
    inputStatus: 'complete',
    detectedObservations: 1,
    uncertainObservations: 1,
    findingInstances: 1,
    expectations: {
      minimumDetectedObservations: 1,
      maximumPossibleObservations: 2,
      minimumFindingInstances: 1,
      maximumFindingInstances: 2
    }
  });
  assert(health.rules.filter((rule) => rule.ruleId !== targetRuleId).every((rule) =>
    rule.target?.inputStatus === 'complete' &&
    rule.target?.detectedObservations === 0 &&
    rule.target.uncertainObservations === 0 &&
    rule.target.findingInstances === 0 &&
    rule.target.expectations === undefined
  ));
  await assertSchema('analysis-health', health, 'Generated analysis health');

  const incomplete = buildAnalysisHealthRecord({
    runId: `run_sha256_${'4'.repeat(64)}`,
    snapshotId: `snapshot_sha256_${'5'.repeat(64)}`,
    profileObservations: [],
    controls: first,
    operational: {
      findings: [],
      observations: [],
      containerCoverage: [],
      diagnostics: [{
        schemaVersion: 1,
        id: `diagnostic:${'6'.repeat(24)}`,
        code: 'OPERATIONAL_SEED_DICTIONARY_SOURCE_REQUIRED',
        severity: 'warning',
        message: 'A configured dictionary is required.',
        evidence: targetEvidence
      }]
    },
    ruleExpectations: []
  });
  assert.equal(incomplete.status, 'incomplete');
  assert.equal(
    incomplete.rules.find((rule) => rule.ruleId === 'contract/seeded-dictionary-id-coupling-v1')?.target?.inputStatus,
    'incomplete'
  );
});

test('a broken control may exceed its declared minimum without disabling the rule', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incident-minimum-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const corpusPath = path.join(root, 'manifest.json');
  const sourcePath = path.resolve('corpus/incidents/synthetic-operational-risks/manifest.json');
  const corpus = JSON.parse(await readFile(sourcePath, 'utf8')) as {
    cases: Array<{ id: string; broken: { files: Array<{ path: string; content: string }> } }>;
  };
  const incident = corpus.cases.find((entry) => entry.id === 'silent-empty-pass-with-no-tests');
  assert(incident);
  incident.broken.files[0]!.content = JSON.stringify({
    scripts: { test: 'vitest --passWithNoTests --allow-no-tests' }
  });
  await writeFile(corpusPath, `${JSON.stringify(corpus, null, 2)}\n`, 'utf8');

  const controls = await evaluateOperationalControls(corpusPath);
  const rule = controls.rules.find((entry) => entry.ruleId === 'operational/silent-empty-instrument-v1');
  const evaluatedIncident = controls.incidents.find((entry) => entry.id === incident.id);
  assert.equal(rule?.state, 'enabled');
  assert.equal(rule?.controls.expectedObservations, 3);
  assert.equal(rule?.controls.observedObservations, 4);
  assert.equal(evaluatedIncident?.status, 'passed');
});

test('disabled rules retain their measured missed and regressed control outcomes', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incident-disabled-outcomes-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const sourcePath = path.resolve('corpus/incidents/synthetic-operational-risks/manifest.json');
  const corpus = JSON.parse(await readFile(sourcePath, 'utf8')) as {
    cases: Array<{
      id: string;
      expected: { brokenMinimum: number };
      broken: { files: Array<{ path: string; content: string }> };
      fixed: { files: Array<{ path: string; content: string }> };
    }>;
  };
  const missed = corpus.cases.find((entry) => entry.id === 'silent-empty-pass-with-no-tests');
  const regressed = corpus.cases.find((entry) => entry.id === 'pipeline-terminal-status-mask');
  assert(missed && regressed);
  missed.expected.brokenMinimum = 2;
  regressed.fixed = structuredClone(regressed.broken);
  const corpusPath = path.join(root, 'manifest.json');
  await writeFile(corpusPath, `${JSON.stringify(corpus, null, 2)}\n`, 'utf8');

  const controls = await evaluateOperationalControls(corpusPath);
  const rule = controls.rules.find((entry) => entry.ruleId === 'operational/silent-empty-instrument-v1');
  const missedResult = controls.incidents.find((entry) => entry.id === missed.id);
  const regressedResult = controls.incidents.find((entry) => entry.id === regressed.id);
  assert.equal(rule?.state, 'disabled');
  assert.deepEqual(missedResult?.broken, { expectedMinimum: 2, observed: 1, outcome: 'missed' });
  assert.deepEqual(missedResult?.fixed, { expectedMaximum: 0, observed: 0, outcome: 'silent' });
  assert.equal(missedResult?.status, 'failed');
  assert.deepEqual(regressedResult?.broken, { expectedMinimum: 1, observed: 1, outcome: 'detected' });
  assert.deepEqual(regressedResult?.fixed, { expectedMaximum: 0, observed: 1, outcome: 'regressed' });
  assert.equal(regressedResult?.status, 'failed');
});

test('a different mechanism under the same rule cannot satisfy a control', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incident-mechanism-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const sourcePath = path.resolve('corpus/incidents/synthetic-operational-risks/manifest.json');
  const corpus = JSON.parse(await readFile(sourcePath, 'utf8')) as {
    cases: Array<{ id: string; broken: { files: Array<{ path: string; content: string }> } }>;
  };
  const incident = corpus.cases.find((entry) => entry.id === 'silent-empty-pass-with-no-tests');
  assert(incident);
  incident.broken.files = [{ path: 'scripts/gate.sh', content: 'checker | tail -10 && commit-result\n' }];
  const corpusPath = path.join(root, 'manifest.json');
  await writeFile(corpusPath, `${JSON.stringify(corpus, null, 2)}\n`, 'utf8');

  const controls = await evaluateOperationalControls(corpusPath);
  const evaluated = controls.incidents.find((entry) => entry.id === incident.id);
  assert.deepEqual(evaluated?.broken, { expectedMinimum: 1, observed: 0, outcome: 'missed' });
  assert.equal(evaluated?.status, 'failed');
});

test('corpus validation requires zero fixed findings and a case for every mechanism', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-incident-contract-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const sourcePath = path.resolve('corpus/incidents/synthetic-operational-risks/manifest.json');
  const original = JSON.parse(await readFile(sourcePath, 'utf8')) as {
    cases: Array<{ mechanismId: string; expected: { fixedMaximum: number } }>;
  };

  const nonzeroFixed = structuredClone(original);
  nonzeroFixed.cases[0]!.expected.fixedMaximum = 1;
  const nonzeroPath = path.join(root, 'nonzero-fixed.json');
  await writeFile(nonzeroPath, `${JSON.stringify(nonzeroFixed, null, 2)}\n`, 'utf8');
  await assert.rejects(
    evaluateOperationalControls(nonzeroPath),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );

  const missingMechanism = structuredClone(original);
  missingMechanism.cases = missingMechanism.cases.filter((entry) => entry.mechanismId !== 'pipeline-status-mask');
  const missingPath = path.join(root, 'missing-mechanism.json');
  await writeFile(missingPath, `${JSON.stringify(missingMechanism, null, 2)}\n`, 'utf8');
  await assert.rejects(
    evaluateOperationalControls(missingPath),
    (error: unknown) => (error as { code?: string }).code === 'INVALID_CORPUS'
  );
});

test('rule observation expectations count detections separately and bound uncertainty conservatively', () => {
  const profile = (bounds: Pick<NonNullable<ResolvedProfile['ruleExpectations']>[number], 'minObservations' | 'maxObservations'>): ResolvedProfile => ({
    schemaVersion: 1,
    id: 'expectation-profile',
    includeRoots: ['.'],
    exclude: [],
    entrypoints: [],
    aliases: {},
    envExampleFiles: [],
    platformRoots: [],
    deadCodeExemptions: [],
    lifecycleRules: [],
    maxFileBytes: 1_000_000,
    ruleExpectations: [{ ruleId: 'operational/result-collapse-v1', ...bounds }]
  });
  const result = {
    findings: [],
    diagnostics: [],
    containerCoverage: [],
    observations: [{
      schemaVersion: 1,
      id: 'observation:uncertain',
      ruleId: 'operational/result-collapse-v1',
      state: 'uncertain',
      path: 'src/example.ts',
      location: { line: 1, column: 1, endLine: 1, endColumn: 2 },
      fingerprint: 'uncertain',
      evidence: { level: 1, producer: 'test', producerVersion: '1', basis: 'uncertainty' }
    }]
  } satisfies OperationalRiskResult;

  assert.throws(
    () => enforceRuleExpectations(profile({ minObservations: 1 }), result),
    /detected observations 0 < 1 \(1 uncertain\)/u
  );
  assert.throws(
    () => enforceRuleExpectations(profile({ maxObservations: 0 }), result),
    /possible observations 1 > 0 \(1 uncertain\)/u
  );
  assert.doesNotThrow(() => enforceRuleExpectations(profile({ minObservations: 0, maxObservations: 1 }), result));
});
