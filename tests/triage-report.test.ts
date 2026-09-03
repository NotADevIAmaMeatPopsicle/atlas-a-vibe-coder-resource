import assert from 'node:assert/strict';
import test from 'node:test';
import { renderTriageReport } from '../src/triage-report.js';
import type { DiagnosticRecord, FindingRecord, RunRecord } from '../src/types.js';

const RUN = {
  runId: `run_sha256_${'a'.repeat(64)}`,
  snapshotId: `snapshot_sha256_${'b'.repeat(64)}`
} as RunRecord;

function finding(id: string, severity: FindingRecord['severity'], path: string, scope: 'production' | 'test'): FindingRecord {
  return {
    schemaVersion: 1,
    id: `finding:${id.repeat(24)}`,
    category: 'operational-defect',
    ruleId: `rule/${id}`,
    status: 'candidate',
    severity,
    confidence: 'high',
    title: `${id} finding`,
    description: 'Review this finding.',
    path,
    location: { line: 4, column: 2, endLine: 4, endColumn: 2 },
    relatedPaths: [],
    signals: ['signal'],
    evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'fixture', path, line: 4, column: 2 }],
    impactContext: {
      reachability: 'reachable',
      scope,
      entrypoints: [],
      mountedSurfaces: [],
      featureGate: 'unknown',
      summary: 'Fixture.',
      limitations: ['Fixture.']
    },
    nextValidation: 'Inspect it.'
  };
}

function diagnostic(index: number, code: string, severity: DiagnosticRecord['severity']): DiagnosticRecord {
  return {
    schemaVersion: 1,
    id: `diagnostic:${String(index).padStart(24, '0')}`,
    code,
    severity,
    message: `Per-instance diagnostic message ${index}.`,
    path: `generated/path-${index}.ts`,
    location: { line: index + 1, column: 1, endLine: index + 1, endColumn: 1 },
    evidence: {
      level: 1,
      producer: 'test',
      producerVersion: '1',
      basis: 'fixture',
      path: `generated/path-${index}.ts`
    }
  };
}

function reviewerVisibleEntries(markdown: string): string[] {
  const findings = markdown.split('## Findings\n\n')[1]?.split('\n## Diagnostics\n')[0] ?? '';
  return findings
    .split(/\n(?=### \d+\. )/u)
    .filter((entry) => entry.startsWith('### '))
    .map((entry) => entry
      .replace(/^### \d+\. /u, '### ')
      .replace(/^- Review ID: .*\n/mu, ''));
}

test('triage Markdown is deterministic and ordered by severity then production impact', () => {
  const highTest = finding('a', 'high', 'tests/a.test.ts', 'test');
  const highProduction = finding('b', 'high', 'src/b.ts', 'production');
  const lowProduction = finding('c', 'low', 'src/c.ts', 'production');
  const diagnostic: DiagnosticRecord = {
    schemaVersion: 1,
    id: `diagnostic:${'d'.repeat(24)}`,
    code: 'FIXTURE_WARNING',
    severity: 'warning',
    message: 'Fixture warning.',
    path: 'src/b.ts',
    evidence: { level: 1, producer: 'test', producerVersion: '1', basis: 'fixture', path: 'src/b.ts' }
  };
  const forward = renderTriageReport(RUN, [lowProduction, highTest, highProduction], [diagnostic]);
  const reversed = renderTriageReport(RUN, [highProduction, highTest, lowProduction], [diagnostic]);

  assert.equal(forward, reversed);
  assert(forward.indexOf('b finding') < forward.indexOf('a finding'));
  assert(forward.indexOf('a finding') < forward.indexOf('c finding'));
  assert.match(forward, /Anchor: `src\/b\.ts:4:2`/u);
  assert.match(forward, /Review ID: `finding_review_sha256_[a-f0-9]{64}`/u);
  assert.match(forward, /## Diagnostics/u);
  const reviewerEntries = reviewerVisibleEntries(forward);
  assert.equal(reviewerEntries.length, 3);
  assert.equal(new Set(reviewerEntries).size, reviewerEntries.length);
});

test('triage Markdown escapes target-controlled text and accounts for capped surfaces', () => {
  const hostile = finding('e', 'high', 'src/odd`name.ts', 'production');
  hostile.title = '# injected <script> [link](https://example.invalid)';
  hostile.description = '*unsafe* <img src=x>';
  const { scope: _scope, ...impactWithoutScope } = hostile.impactContext!;
  hostile.impactContext = {
    ...impactWithoutScope,
    reachability: 'mixed',
    mountedSurfaces: ['surface-a', 'surface-b'],
    entrypoints: ['entry-a', 'entry-b', 'entry-c'],
    entrypointRemainder: 2
  };
  const markdown = renderTriageReport(RUN, [hostile], []);

  assert(!markdown.includes('### 1. HIGH · # injected'));
  assert(!markdown.includes('<script>'));
  assert(!markdown.includes('<img'));
  assert.match(markdown, /mixed scope via .*plus 4 additional surfaces/u);
  assert(!markdown.includes('undefined scope'));
  assert.match(markdown, /Anchor: ``src\/odd`name\.ts:4:2``/u);
});

test('triage Markdown enumerates aggregated mapping contexts in canonical order', () => {
  const mapped = finding('m', 'medium', 'src/mapped.ts', 'production');
  mapped.mechanism = 'checked-landmark-divergence';
  mapped.severityCalibration = {
    version: 'static-reachability-v1',
    detectorSeverity: 'high',
    ceiling: 'medium',
    basis: 'static-production-path-feature-gated',
    runtimeReachability: 'not-evaluated',
    rationale: 'A local feature gate caps the static severity.'
  };
  mapped.mappingContexts = [{
    id: 'mapping-z',
    composePath: 'compose.z.yml',
    service: 'worker',
    sourceKind: 'docker-copy',
    hostRoot: '.',
    containerRoot: '/srv/app',
    buildContext: '.',
    dockerfile: 'Dockerfile.worker',
    workingDirectory: '/srv/app'
  }, {
    id: 'mapping-a',
    composePath: 'compose.a.yml',
    service: 'api',
    sourceKind: 'bind-mount',
    hostRoot: './src',
    containerRoot: '/app/src'
  }];

  const markdown = renderTriageReport(RUN, [mapped], []);

  assert.match(markdown, /Mechanism: `checked-landmark-divergence`/u);
  assert.match(
    markdown,
    /Severity calibration: detector `high` → reported `medium` \(ceiling `medium`; basis `static-production-path-feature-gated`; runtime reachability `not-evaluated`\)/u
  );
  assert.match(markdown, /Severity rationale: A local feature gate caps the static severity\./u);
  assert.match(markdown, /Mapping contexts: 2/u);
  assert(markdown.indexOf('`compose.a.yml`') < markdown.indexOf('`compose.z.yml`'));
  assert.match(markdown, /`compose.a.yml` · service `api` · `bind-mount` · `\.\/src` → `\/app\/src`/u);
  assert.match(markdown, /build `\.` · Dockerfile `Dockerfile.worker` · working directory `\/srv\/app`/u);
});

test('triage diagnostic summary stays proportional to findings rather than diagnostic volume', () => {
  const diagnostics = [
    ...Array.from({ length: 1_000 }, (_, index) => diagnostic(index, 'A_REPEATED_WARNING', 'warning')),
    ...Array.from({ length: 1_000 }, (_, index) => diagnostic(index + 1_000, 'Z_REPEATED_ERROR', 'error'))
  ];
  const full = renderTriageReport(RUN, [finding('f', 'medium', 'src/f.ts', 'production')], diagnostics);
  const reversed = renderTriageReport(
    RUN,
    [finding('f', 'medium', 'src/f.ts', 'production')],
    [...diagnostics].reverse()
  );
  const onePerCode = renderTriageReport(
    RUN,
    [finding('f', 'medium', 'src/f.ts', 'production')],
    [diagnostics[0]!, diagnostics[1_000]!]
  );

  assert.equal(full, reversed);
  assert.equal(full.trimEnd().split('\n').length, onePerCode.trimEnd().split('\n').length);
  assert(full.trimEnd().split('\n').length < 50);
  assert.match(full, /Diagnostics: 2000 across 2 codes/u);
  assert.match(full, /`A_REPEATED_WARNING`: 1000 total \(error 0, warning 1000, info 0\)/u);
  assert.match(full, /`Z_REPEATED_ERROR`: 1000 total \(error 1000, warning 0, info 0\)/u);
  assert.match(full, /Per-instance diagnostic records are retained only in `diagnostics\.jsonl`\./u);
  assert(!full.includes('Per-instance diagnostic message'));
  assert(!full.includes('generated/path-'));
});

test('triage rejects findings that differ only in Review ID or hidden evidence', () => {
  const original = finding('g', 'high', 'src/g.ts', 'production');
  const duplicate: FindingRecord = {
    ...original,
    id: `finding:${'h'.repeat(24)}`,
    relatedPaths: ['compose.hidden.yml']
  };

  assert.throws(
    () => renderTriageReport(RUN, [original, duplicate], []),
    /duplicate reviewer-visible finding entries/u
  );
});

test('triage surfaces actionability, falsifiers, blind spots, and applied dispositions before folded evidence', () => {
  const actionable = finding('p', 'medium', 'src/p.ts', 'production');
  actionable.reviewId = `finding_review_sha256_${'1'.repeat(64)}`;
  actionable.reviewPriority = {
    version: 'static-actionability-v1',
    band: 'production-gate-unknown',
    severityRank: 1,
    impactRank: 1,
    confidenceRank: 1,
    instanceCount: 1
  };
  actionable.refutationCondition = 'A mounted runtime route proves the client call is served.';
  const applied: DiagnosticRecord = {
    ...diagnostic(9000, 'FINDING_DISPOSITION_APPLIED', 'info'),
    disposition: {
      reviewId: `finding_review_sha256_${'2'.repeat(64)}`,
      findingId: `finding:${'2'.repeat(24)}`,
      title: 'Known compatibility shim',
      ruleId: 'contract/example-v1',
      disposition: 'intentional contract',
      reviewer: 'Admin',
      date: '2026-08-23',
      evidence: ['Validated against the deployment contract.'],
      anchors: [{ path: 'src/p.ts', sha256: '3'.repeat(64) }],
      state: 'applied'
    }
  };
  const boundary = diagnostic(9001, 'API_CONTRACT_DYNAMIC_SERVER_ROUTE', 'warning');

  const markdown = renderTriageReport(RUN, [actionable], [boundary, applied]);

  assert.match(markdown, /Review order: severity, static actionability band/u);
  assert.match(markdown, /Coverage status: incomplete; 1 API requests or routes outside the supported static boundary/u);
  assert.match(markdown, /## Dispositioned in this run/u);
  assert.match(markdown, /Known compatibility shim.*intentional contract.*Admin.*2026-08-23/u);
  assert.match(markdown, /Falsifier: A mounted runtime route proves the client call is served\./u);
  assert.match(markdown, /Actionability: Production, feature-gate status unknown/u);
  assert.match(markdown, /<summary>Evidence, impact, and calibration<\/summary>/u);
  assert(markdown.indexOf('Contradiction:') < markdown.indexOf('<details>'));
  assert(markdown.indexOf('Action:') < markdown.indexOf('<details>'));
});
