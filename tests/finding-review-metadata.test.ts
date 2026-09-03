import assert from 'node:assert/strict';
import test from 'node:test';
import { postprocessFindings } from '../src/analysis/finding-postprocess.js';
import { findingReviewIdentity } from '../src/finding-identity.js';
import {
  compareFindingReviewPriority,
  deriveFindingReviewMetadata,
  findingReviewMetadataMismatches,
  findingReviewMetadataMismatchesForCollection,
  reviewPriorityForFinding
} from '../src/finding-priority.js';
import { assertSchema } from '../src/schema-validator.js';
import type { AnalysisFile, FindingImpactContext, FindingRecord } from '../src/types.js';
import { sha256 } from '../src/util/canonical.js';

function file(filePath: string): AnalysisFile {
  const content = Buffer.from(`export const path = ${JSON.stringify(filePath)};\n`);
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
      evidence: {
        level: 0,
        producer: 'test',
        producerVersion: '1',
        basis: 'fixture',
        path: filePath
      }
    },
    content
  };
}

function finding(idDigit: string, filePath: string): FindingRecord {
  return {
    schemaVersion: 1,
    id: `finding:${idDigit.repeat(24)}`,
    category: 'contract-mismatch',
    ruleId: 'contract/api-client-route-missing-v1',
    status: 'candidate',
    severity: 'medium',
    confidence: 'high',
    title: 'Client route has no server route',
    description: 'A client request has no matching server contract.',
    path: filePath,
    relatedPaths: [],
    signals: ['client-route-has-no-server-match'],
    evidence: [{
      level: 2,
      producer: 'test',
      producerVersion: '1',
      basis: 'fixture',
      path: filePath,
      line: 1,
      column: 1
    }],
    nextValidation: 'Inspect the effective route mount table.'
  };
}

function impact(
  scope: FindingImpactContext['scope'],
  featureGate: FindingImpactContext['featureGate'] = 'not-observed'
): FindingImpactContext {
  return {
    reachability: 'reachable',
    ...(scope ? { scope } : {}),
    entrypoints: ['src/entry.ts'],
    mountedSurfaces: [],
    featureGate,
    summary: 'Fixture impact.',
    limitations: ['Static fixture only.']
  };
}

test('current postprocessing publishes deterministic, source-backed review metadata', async () => {
  const primary = file('src/z-client.ts');
  const related = file('src/a-router.ts');
  const candidate = finding('a', primary.record.path);
  candidate.relatedPaths = [related.record.path, 'src/absent-generated-route.ts'];
  candidate.evidence.push({
    level: 2,
    producer: 'test',
    producerVersion: '1',
    basis: 'related-fixture',
    path: related.record.path
  });

  const [current] = postprocessFindings([candidate], [primary, related]);
  assert(current);
  assert.equal(current.reviewId, findingReviewIdentity(current));
  assert.deepEqual(current.reviewAnchors, [
    { path: related.record.path, sha256: related.record.sha256 },
    { path: primary.record.path, sha256: primary.record.sha256 }
  ]);
  assert.deepEqual(current.reviewPriority, {
    version: 'static-actionability-v1',
    band: 'reachability-incomplete',
    severityRank: 1,
    impactRank: 5,
    confidenceRank: 1,
    instanceCount: 1
  });
  assert(current.refutationCondition.length > 0);
  assert.notEqual(current.refutationCondition, current.nextValidation);
  assert.deepEqual(
    findingReviewMetadataMismatches(current, [primary.record, related.record]),
    []
  );
  await assertSchema('finding', current, 'Current finding review metadata');
});

test('review metadata derivation detects tampering while identity excludes review wording and priority', () => {
  const source = file('src/client.ts');
  const [current] = postprocessFindings([finding('b', source.record.path)], [source]);
  assert(current);
  const forged: FindingRecord = {
    ...current,
    reviewId: `finding_review_sha256_${'f'.repeat(64)}`,
    reviewAnchors: [{ path: source.record.path, sha256: '0'.repeat(64) }],
    reviewPriority: {
      ...current.reviewPriority,
      band: 'inactive',
      impactRank: 7
    },
    refutationCondition: 'A forged falsifier.'
  };

  assert.equal(findingReviewIdentity(forged), current.reviewId);
  assert.deepEqual(findingReviewMetadataMismatches(forged, [source.record]), [
    'reviewId',
    'reviewAnchors',
    'reviewPriority',
    'refutationCondition'
  ]);
  assert.deepEqual(deriveFindingReviewMetadata(forged, [source.record]), {
    reviewId: current.reviewId,
    reviewAnchors: current.reviewAnchors,
    reviewPriority: current.reviewPriority,
    refutationCondition: current.refutationCondition
  });
});

test('duplicate review identities publish canonical occurrence-qualified ledger keys', async () => {
  const source = file('src/duplicate-client.ts');
  const first = finding('1', source.record.path);
  const second = finding('2', source.record.path);
  const forward = postprocessFindings([first, second], [source]);
  const reversed = postprocessFindings([second, first], [source]);
  const baseReviewId = findingReviewIdentity(forward[0]!);

  assert.deepEqual(forward.map((entry) => ({ id: entry.id, reviewId: entry.reviewId })), [
    { id: first.id, reviewId: `${baseReviewId}:occurrence:1` },
    { id: second.id, reviewId: `${baseReviewId}:occurrence:2` }
  ]);
  assert.deepEqual(
    reversed.map((entry) => ({ id: entry.id, reviewId: entry.reviewId })),
    forward.map((entry) => ({ id: entry.id, reviewId: entry.reviewId }))
  );
  assert.deepEqual(findingReviewMetadataMismatchesForCollection(forward, [source.record]), []);
  await Promise.all(forward.map((entry) => assertSchema('finding', entry, 'Duplicate review identity finding')));

  const forged = forward.map((entry) => ({ ...entry }));
  forged[0]!.reviewId = `${baseReviewId}:occurrence:2`;
  assert.deepEqual(findingReviewMetadataMismatchesForCollection(forged, [source.record]), [{
    findingId: first.id,
    fields: ['reviewId']
  }]);
});

test('collection verification preserves occurrence order across disposition-omitted findings', () => {
  const source = file('src/disposition-duplicate.ts');
  const [first, second] = postprocessFindings([
    finding('3', source.record.path),
    finding('4', source.record.path)
  ], [source]);
  assert(first && second);

  assert.deepEqual(findingReviewMetadataMismatchesForCollection(
    [second],
    [source.record],
    [{ findingId: first.id, reviewId: first.reviewId }]
  ), []);

  assert.deepEqual(findingReviewMetadataMismatchesForCollection(
    [second],
    [source.record],
    [{ findingId: first.id, reviewId: second.reviewId }]
  ), [
    { findingId: first.id, fields: ['reviewId'] },
    { findingId: second.id, fields: ['reviewId'] }
  ]);

  assert.deepEqual(findingReviewMetadataMismatchesForCollection(
    [second],
    [source.record],
    [{ findingId: second.id, reviewId: first.reviewId }]
  ), [{ findingId: second.id, fields: ['reviewId'] }]);

  const forgedOmittedId = `finding:${'f'.repeat(24)}`;
  assert.deepEqual(findingReviewMetadataMismatchesForCollection(
    [second],
    [source.record],
    [
      { findingId: first.id, reviewId: first.reviewId },
      { findingId: forgedOmittedId, reviewId: first.reviewId }
    ]
  ), [
    { findingId: first.id, fields: ['reviewId'] },
    { findingId: forgedOmittedId, fields: ['reviewId'] }
  ]);
});

test('priority uses the best existing instance impact and has a deterministic legacy fallback', () => {
  const production = {
    ...finding('c', 'src/production.ts'),
    impactContext: impact('production')
  };
  const gated = {
    ...finding('d', 'src/gated.ts'),
    impactContext: impact('production', 'observed')
  };
  const testOnly = {
    ...finding('e', 'tests/client.test.ts'),
    impactContext: impact('test')
  };
  const aggregate: FindingRecord = {
    ...finding('f', 'src/mixed.ts'),
    instanceCount: 2,
    impactContext: {
      ...impact(undefined),
      reachability: 'mixed'
    },
    instances: [
      {
        id: `finding:${'1'.repeat(24)}`,
        severity: 'medium',
        confidence: 'high',
        path: 'src/mixed.ts',
        relatedPaths: [],
        signals: ['fixture'],
        evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'fixture', path: 'src/mixed.ts' }],
        impactContext: impact('production')
      },
      {
        id: `finding:${'2'.repeat(24)}`,
        severity: 'low',
        confidence: 'high',
        path: 'tests/mixed.test.ts',
        relatedPaths: [],
        signals: ['fixture'],
        evidence: [{ level: 1, producer: 'test', producerVersion: '1', basis: 'fixture', path: 'tests/mixed.test.ts' }],
        impactContext: impact('test')
      }
    ]
  };

  assert.equal(reviewPriorityForFinding(aggregate).band, 'production-ungated');
  assert.deepEqual(
    [testOnly, gated, aggregate, production].sort(compareFindingReviewPriority).map((entry) => entry.id),
    [aggregate.id, production.id, gated.id, testOnly.id]
  );
});

test('legacy finding records remain valid without review metadata', async () => {
  await assertSchema('finding', finding('9', 'src/legacy.ts'), 'Legacy finding');
});
