import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeJavaScriptTypeScript } from '../src/adapters/js-ts.js';
import { detectCleanupCandidates } from '../src/analysis/cleanup.js';
import { findingInstanceCount, postprocessFindings } from '../src/analysis/finding-postprocess.js';
import { detectMismatches } from '../src/analysis/mismatches.js';
import { analyzeReachability } from '../src/analysis/reachability.js';
import { assertSchema } from '../src/schema-validator.js';
import type { AnalysisFile, FindingRecord, ResolvedProfile } from '../src/types.js';
import { sha256 } from '../src/util/canonical.js';

function file(filePath: string, source = 'export {};\n'): AnalysisFile {
  const content = Buffer.from(source);
  return {
    record: {
      schemaVersion: 1,
      id: `file_sha256_${sha256(`fixture:${filePath}`)}`,
      path: filePath,
      sha256: sha256(content),
      bytes: content.length,
      kind: 'source',
      language: 'typescript',
      symbols: [],
      environmentVariables: [],
      lifecycle: {
        state: 'active',
        basis: 'profile-path-rule',
        ruleId: 'active-source',
        uncertainty: 'not-runtime-validated',
        limitation: 'Static fixture declaration.'
      },
      evidence: { level: 0, producer: 'test', producerVersion: '1', basis: 'fixture', path: filePath }
    },
    content
  };
}

function finding(idDigit: string, table: string, column: string, modelPath: string): FindingRecord {
  return {
    schemaVersion: 1,
    id: `finding:${idDigit.repeat(24)}`,
    category: 'contract-mismatch',
    ruleId: 'contract/data-enum-v1',
    subject: {
      kind: 'data-contract',
      table,
      column,
      dimension: 'enum-members',
      model: 'sequelize',
      storage: 'sequelize-migration'
    },
    status: 'candidate',
    severity: 'high',
    confidence: 'high',
    title: `Enum differs: ${table}.${column}`,
    description: 'Irreversible enum signatures differ.',
    path: modelPath,
    relatedPaths: ['src/migrations/001.js'],
    signals: ['hashed-literal-sequelize-enum-signatures-disagree'],
    evidence: [{ level: 2, producer: 'test', producerVersion: '1', basis: 'fixture', path: modelPath }],
    nextValidation: 'Inspect the source-located declarations.'
  };
}

test('repeated data-contract instances aggregate before headline counting with static impact context', async () => {
  const files = [file('src/models/a.ts'), file('src/models/b.ts')];
  const result = postprocessFindings([
    finding('a', 'appointments', 'status', 'src/models/a.ts'),
    finding('b', 'bookings', 'state', 'src/models/b.ts')
  ], files, {
    entrypoints: [
      { path: 'src/server.ts', scope: 'production' },
      { path: 'tests/runner.ts', scope: 'test' }
    ],
    reachablePaths: new Set(['src/models/a.ts']),
    gatedPaths: new Set(),
    pathContexts: new Map([[
      'src/models/a.ts',
      { entrypointPaths: ['src/server.ts'], scopes: ['production'] }
    ]])
  });

  assert.equal(result.length, 1);
  assert.equal(result[0]?.instanceCount, 2);
  assert.equal(result[0]?.instances?.length, 2);
  assert.equal(result[0]?.subject, undefined);
  assert.equal(findingInstanceCount(result), 2);
  assert.equal(result[0]?.impactContext?.reachability, 'mixed');
  assert.equal(result[0]?.impactContext?.scope, undefined);
  assert.deepEqual(result[0]?.impactContext?.entrypoints, ['src/server.ts']);
  assert.match(result[0]?.impactContext?.summary ?? '', /2 source-located instance/u);
  assert.deepEqual(result[0]?.instances?.map((instance) => instance.impactContext?.reachability).sort(), ['reachable', 'unreachable']);
  assert.deepEqual(result[0]?.instances?.map((instance) => instance.severity), ['high', 'low']);
  assert(result[0]?.instances?.every((instance) => instance.confidence === 'high'));
  assert.equal(result[0]?.severityCalibration?.basis, 'static-production-path-no-observed-feature-gate');
  assert.equal(result[0]?.severityCalibration?.runtimeReachability, 'not-evaluated');
  assert.equal(result[0]?.impactContext?.featureGate, 'not-observed');
  await assertSchema('finding', result[0], 'Aggregated finding');
});

test('static reachability is one headline pattern with source-located instances', () => {
  const first = file('src/legacy-a.ts');
  const second = file('src/legacy-b.ts');
  const dead = (idDigit: string, source: AnalysisFile): FindingRecord => ({
    schemaVersion: 1,
    id: `finding:${idDigit.repeat(24)}`,
    category: 'dead-code-candidate',
    ruleId: 'dead-code/static-reachability-v1',
    status: 'candidate',
    severity: 'info',
    confidence: 'medium',
    title: `Review possible unused source: ${source.record.path}`,
    description: 'No modeled path reaches this file.',
    path: source.record.path,
    relatedPaths: [],
    signals: ['no-inbound-resolved-runtime-static-import', 'unreachable-from-configured-entrypoints'],
    evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'reachability', path: source.record.path }],
    nextValidation: 'Confirm activation.'
  });
  const result = postprocessFindings([dead('e', first), dead('f', second)], [first, second]);
  assert.equal(result.length, 1);
  assert.equal(result[0]?.instanceCount, 2);
  assert.deepEqual(result[0]?.instances?.map((entry) => entry.path).sort(), ['src/legacy-a.ts', 'src/legacy-b.ts']);
});

test('aggregates expose a primary location, order production before tests, and cap ranked entrypoints', () => {
  const production = finding('a', 'appointments', 'status', 'z-src/models/status.ts');
  production.evidence[0] = { ...production.evidence[0]!, line: 7, column: 3 };
  const testFinding = finding('b', 'bookings', 'state', 'tests/status.test.ts');
  testFinding.evidence[0] = { ...testFinding.evidence[0]!, line: 2, column: 5 };
  const entrypoints = [
    { path: 'tests/a.test.ts', scope: 'test' as const },
    { path: 'tests/b.test.ts', scope: 'test' as const },
    { path: 'tests/c.test.ts', scope: 'test' as const },
    { path: 'tests/d.test.ts', scope: 'test' as const },
    { path: 'tests/e.test.ts', scope: 'test' as const },
    { path: 'tests/f.test.ts', scope: 'test' as const },
    { path: 'tests/g.test.ts', scope: 'test' as const },
    { path: 'tests/h.test.ts', scope: 'test' as const },
    { path: 'src/server.ts', scope: 'production' as const }
  ];
  const allEntrypoints = entrypoints.map((entry) => entry.path);
  const result = postprocessFindings([testFinding, production], [
    file('z-src/models/status.ts'),
    file('tests/status.test.ts')
  ], {
    entrypoints,
    reachablePaths: new Set(['z-src/models/status.ts', 'tests/status.test.ts']),
    gatedPaths: new Set(),
    pathContexts: new Map([
      ['z-src/models/status.ts', { entrypointPaths: allEntrypoints, scopes: ['production'] }],
      ['tests/status.test.ts', { entrypointPaths: allEntrypoints, scopes: ['test'] }]
    ])
  });

  assert.equal(result.length, 1);
  assert.equal(result[0]?.path, 'z-src/models/status.ts');
  assert.deepEqual(result[0]?.location, { line: 7, column: 3, endLine: 7, endColumn: 3 });
  assert.deepEqual(result[0]?.instances?.map((instance) => instance.path), [
    'z-src/models/status.ts',
    'tests/status.test.ts'
  ]);
  assert.equal(result[0]?.impactContext?.entrypoints[0], 'src/server.ts');
  assert.equal(result[0]?.impactContext?.entrypoints.length, 8);
  assert.equal(result[0]?.impactContext?.entrypointRemainder, 1);
});

test('a broken reference inside an unreachable file becomes cleanup evidence', () => {
  const source = file('src/debug.ts');
  const cleanup: FindingRecord = {
    schemaVersion: 1,
    id: `finding:${'c'.repeat(24)}`,
    category: 'dead-code-candidate',
    ruleId: 'dead-code/static-reachability-v1',
    status: 'candidate',
    severity: 'info',
    confidence: 'medium',
    title: 'Review possible unused source',
    description: 'No modeled path reaches this file.',
    path: source.record.path,
    relatedPaths: [],
    signals: ['no-inbound-resolved-runtime-static-import', 'unreachable-from-configured-entrypoints'],
    evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'reachability', path: source.record.path }],
    nextValidation: 'Confirm activation.'
  };
  const broken: FindingRecord = {
    ...cleanup,
    id: `finding:${'d'.repeat(24)}`,
    category: 'contract-mismatch',
    ruleId: 'contract/unresolved-internal-import-v1',
    severity: 'high',
    confidence: 'high',
    title: 'Unresolved import',
    description: 'Import does not resolve.',
    signals: ['unresolved-internal-module-specifier'],
    nextValidation: 'Repair import.'
  };
  const result = postprocessFindings([cleanup, broken], [source], {
    entrypoints: [{ path: 'src/server.ts', scope: 'production' }],
    reachablePaths: new Set(['src/server.ts']),
    gatedPaths: new Set()
  });
  assert.equal(result.length, 1);
  assert(result[0]?.signals.includes('contains-unresolved-internal-reference'));
  assert.match(result[0]?.description ?? '', /file-level cleanup evidence/u);
});

test('all broken references in one unreachable file are retained as cleanup evidence', () => {
  const source = file('src/debug.ts');
  const cleanup: FindingRecord = {
    schemaVersion: 1,
    id: `finding:${'c'.repeat(24)}`,
    category: 'dead-code-candidate',
    ruleId: 'dead-code/static-reachability-v1',
    status: 'candidate',
    severity: 'info',
    confidence: 'medium',
    title: 'Review possible unused source',
    description: 'No modeled path reaches this file.',
    path: source.record.path,
    relatedPaths: [],
    signals: ['no-inbound-resolved-runtime-static-import', 'unreachable-from-configured-entrypoints'],
    evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'reachability', path: source.record.path }],
    nextValidation: 'Confirm activation.'
  };
  const broken = (idDigit: string, line: number, relatedPath: string): FindingRecord => ({
    schemaVersion: 1,
    id: `finding:${idDigit.repeat(24)}`,
    category: 'contract-mismatch',
    ruleId: 'contract/unresolved-internal-import-v1',
    status: 'candidate',
    severity: 'high',
    confidence: 'high',
    title: 'Unresolved import',
    description: 'Import does not resolve.',
    path: source.record.path,
    relatedPaths: [relatedPath],
    signals: ['unresolved-internal-module-specifier'],
    evidence: [{
      level: 1,
      producer: 'test',
      producerVersion: '1',
      basis: 'unresolved-import',
      path: source.record.path,
      line,
      column: 1,
      recordIds: [`relationship:${idDigit.repeat(24)}`]
    }],
    nextValidation: 'Repair import.'
  });
  const firstBroken = broken('d', 1, 'src/missing-a.ts');
  const secondBroken = broken('e', 2, 'src/missing-b.ts');
  const result = postprocessFindings([cleanup, secondBroken, firstBroken], [source]);

  assert.equal(result.length, 1);
  assert(result[0]?.signals.includes('contains-unresolved-internal-reference'));
  assert.deepEqual(result[0]?.relatedPaths, ['src/missing-a.ts', 'src/missing-b.ts']);
  assert.deepEqual(
    result[0]?.evidence
      .filter((entry) => entry.basis === 'unresolved-import')
      .flatMap((entry) => entry.recordIds ?? []),
    [`relationship:${'d'.repeat(24)}`, `relationship:${'e'.repeat(24)}`]
  );
  assert.deepEqual(
    result[0]?.evidence.filter((entry) => entry.basis === 'unresolved-import').map((entry) => entry.line),
    [1, 2]
  );
  assert(!result.some((entry) => entry.ruleId === 'contract/unresolved-internal-import-v1'));
});

test('unreachable-reference cleanup reclassification follows real reachability and preserves incomplete-loader uncertainty', () => {
  const profile = (loaderRules: ResolvedProfile['loaderRules'] = []): ResolvedProfile => ({
    schemaVersion: 1,
    id: 'unreachable-import-integration',
    includeRoots: ['.'],
    exclude: [],
    entrypoints: ['src/server.ts'],
    aliases: {},
    envExampleFiles: [],
    platformRoots: [],
    deadCodeExemptions: [],
    loaderRules,
    lifecycleRules: [],
    maxFileBytes: 1_000_000
  });
  const files = [
    file('src/server.ts', 'export const server = true;\n'),
    file('src/debug.ts', "import missing from './missing.js';\nvoid missing;\n"),
    file('src/plugins/debug.ts', "import missing from './missing.js';\nvoid missing;\n")
  ];

  const plainProfile = profile();
  const plainGraph = analyzeJavaScriptTypeScript(files, plainProfile);
  const plainReachability = analyzeReachability(files, plainGraph.relationships, plainProfile);
  const plain = postprocessFindings([
    ...detectCleanupCandidates(files, plainGraph.relationships, plainProfile, [], plainReachability).findings,
    ...detectMismatches(files, plainGraph.relationships, plainProfile).findings
  ], files, plainReachability);
  assert(plain.some((entry) => entry.path === 'src/debug.ts' && entry.signals.includes('contains-unresolved-internal-reference')));
  assert(!plain.some((entry) => entry.path === 'src/debug.ts' && entry.ruleId === 'contract/unresolved-internal-import-v1'));

  const loaderProfile = profile([{
    id: 'unresolved-plugin-loader',
    kind: 'custom',
    loaderPaths: ['src/missing-loader.ts'],
    loadedPatterns: ['src/plugins/*.ts'],
    scope: 'production',
    required: true
  }]);
  const loaderGraph = analyzeJavaScriptTypeScript(files, loaderProfile);
  const loaderReachability = analyzeReachability(files, loaderGraph.relationships, loaderProfile);
  const underIncompleteLoader = postprocessFindings([
    ...detectCleanupCandidates(files, loaderGraph.relationships, loaderProfile, [], loaderReachability).findings,
    ...detectMismatches(files, loaderGraph.relationships, loaderProfile).findings
  ], files, loaderReachability);
  assert(loaderReachability.gatedPaths.has('src/plugins/debug.ts'));
  assert(underIncompleteLoader.some((entry) =>
    entry.path === 'src/plugins/debug.ts' &&
    entry.ruleId === 'contract/unresolved-internal-import-v1' &&
    entry.impactContext?.reachability === 'coverage-incomplete'
  ));
  assert(!underIncompleteLoader.some((entry) =>
    entry.path === 'src/plugins/debug.ts' && entry.signals.includes('contains-unresolved-internal-reference')
  ));
});

test('severity calibration applies deterministic static-only ceilings without upgrading detector severity', async () => {
  const evaluate = (
    filePath: string,
    source: string,
    reachability: 'reachable' | 'unreachable' | 'unknown',
    scope?: 'production' | 'test' | 'cli'
  ) => {
    const sourceFile = file(filePath, source);
    const candidate = finding('9', 'appointments', 'status', filePath);
    return postprocessFindings([candidate], [sourceFile], reachability === 'unknown' ? undefined : {
      entrypoints: scope ? [{ path: `${scope}/entry.ts`, scope }] : [],
      reachablePaths: new Set(reachability === 'reachable' ? [filePath] : []),
      gatedPaths: new Set(),
      ...(scope ? { pathContexts: new Map([[
        filePath,
        { entrypointPaths: [`${scope}/entry.ts`], scopes: [scope] }
      ]]) } : {})
    })[0]!;
  };

  const production = evaluate('src/services/live.ts', 'export const live = true;\n', 'reachable', 'production');
  assert.equal(production.severity, 'high');
  assert.equal(production.severityCalibration?.basis, 'static-production-path-no-observed-feature-gate');

  const gated = evaluate('src/routes/gated.ts', 'export const enabled = process.env.FEATURE_FLAG;\n', 'reachable', 'production');
  assert.equal(gated.severity, 'medium');
  assert.equal(gated.severityCalibration?.basis, 'static-production-path-feature-gated');

  const cli = evaluate('scripts/admin/check.ts', 'export const check = true;\n', 'reachable', 'cli');
  assert.equal(cli.severity, 'medium');
  assert.equal(cli.severityCalibration?.basis, 'static-non-production-path');

  const testOnly = evaluate('tests/check.test.ts', 'export const check = true;\n', 'reachable', 'test');
  assert.equal(testOnly.severity, 'low');
  assert.equal(testOnly.severityCalibration?.basis, 'static-test-only-path');

  const routeNamedTest = evaluate('tests/routes/check.test.ts', 'export const check = true;\n', 'reachable', 'test');
  assert.equal(routeNamedTest.severity, 'low');
  assert.equal(routeNamedTest.severityCalibration?.basis, 'static-test-only-path');

  const routeNamedCli = evaluate('scripts/routes/check.ts', 'export const check = true;\n', 'reachable', 'cli');
  assert.equal(routeNamedCli.severity, 'medium');
  assert.equal(routeNamedCli.severityCalibration?.basis, 'static-non-production-path');

  const unreachable = evaluate('src/legacy.ts', 'export const legacy = true;\n', 'unreachable');
  assert.equal(unreachable.severity, 'low');
  assert.equal(unreachable.severityCalibration?.basis, 'static-unreachable-path');

  const mothballedFile = file('src/mothballed.ts', 'export const old = true;\n');
  mothballedFile.record.lifecycle = {
    state: 'mothballed',
    basis: 'profile-path-rule',
    ruleId: 'mothballed-test',
    uncertainty: 'not-runtime-validated',
    limitation: 'Test lifecycle declaration.'
  };
  const mothballed = postprocessFindings([
    finding('6', 'appointments', 'status', 'src/mothballed.ts')
  ], [mothballedFile], {
    entrypoints: [{ path: 'src/server.ts', scope: 'production' }],
    reachablePaths: new Set(['src/mothballed.ts']),
    gatedPaths: new Set(),
    pathContexts: new Map([[
      'src/mothballed.ts',
      { entrypointPaths: ['src/server.ts'], scopes: ['production'] }
    ]])
  })[0]!;
  assert.equal(mothballed.severity, 'low');
  assert.equal(mothballed.severityCalibration?.basis, 'static-mothballed-path');

  const unknown = evaluate('src/unknown.ts', 'export const unknown = true;\n', 'unknown');
  assert.equal(unknown.severity, 'medium');
  assert.equal(unknown.severityCalibration?.basis, 'static-reachability-incomplete');

  const intrinsicLow = { ...finding('8', 'appointments', 'status', 'src/services/low.ts'), severity: 'low' as const };
  const lowFile = file('src/services/low.ts', 'export const low = true;\n');
  const stillLow = postprocessFindings([intrinsicLow], [lowFile], {
    entrypoints: [{ path: 'src/server.ts', scope: 'production' }],
    reachablePaths: new Set(['src/services/low.ts']),
    gatedPaths: new Set(),
    pathContexts: new Map([[
      'src/services/low.ts',
      { entrypointPaths: ['src/server.ts'], scopes: ['production'] }
    ]])
  })[0]!;
  assert.equal(stillLow.severity, 'low');
  assert.equal(stillLow.severityCalibration?.ceiling, 'high');
  assert.equal(stillLow.severityCalibration?.detectorSeverity, 'low');
  await assertSchema('finding', gated, 'Statically calibrated finding');
});

test('passthrough findings promote evidence lines to top-level source locations', () => {
  const source = file('infrastructure/terraform-v2/modules/compute/variables.tf', 'variable "first" {}\n');
  const candidate: FindingRecord = {
    schemaVersion: 1,
    id: `finding:${'7'.repeat(24)}`,
    category: 'contract-mismatch',
    ruleId: 'deployment/terraform-variable-v1',
    status: 'candidate',
    severity: 'medium',
    confidence: 'high',
    title: 'Terraform variable mismatch',
    description: 'A declaration differs.',
    path: source.record.path,
    relatedPaths: [],
    signals: ['terraform-variable-mismatch'],
    evidence: [{
      level: 1,
      producer: 'test',
      producerVersion: '1',
      basis: 'terraform-variable',
      path: source.record.path,
      line: 159
    }],
    nextValidation: 'Inspect the declaration.'
  };

  const result = postprocessFindings([candidate], [source]);
  assert.deepEqual(result[0]?.location, { line: 159, column: 1, endLine: 159, endColumn: 1 });
});

test('aggregate severity calibration describes the instance that governs reported severity', () => {
  const productionPath = 'src/services/live.ts';
  const testPath = 'tests/routes/live.test.ts';
  const productionFinding = {
    ...finding('c', 'appointments', 'status', productionPath),
    severity: 'medium' as const
  };
  const testFinding = finding('d', 'bookings', 'state', testPath);
  const result = postprocessFindings(
    [testFinding, productionFinding],
    [file(testPath), file(productionPath)],
    {
      entrypoints: [
        { path: 'src/server.ts', scope: 'production' },
        { path: 'tests/runner.ts', scope: 'test' }
      ],
      reachablePaths: new Set([productionPath, testPath]),
      gatedPaths: new Set(),
      pathContexts: new Map([
        [productionPath, { entrypointPaths: ['src/server.ts'], scopes: ['production'] }],
        [testPath, { entrypointPaths: ['tests/runner.ts'], scopes: ['test'] }]
      ])
    }
  );

  assert.equal(result.length, 1);
  assert.equal(result[0]?.severity, 'medium');
  assert.deepEqual(result[0]?.instances?.map((instance) => instance.severity), ['medium', 'low']);
  assert.equal(result[0]?.severityCalibration?.detectorSeverity, 'medium');
  assert.equal(result[0]?.severityCalibration?.ceiling, 'high');
  assert.equal(result[0]?.severityCalibration?.basis, 'static-production-path-no-observed-feature-gate');
});
