import path from 'node:path';
import {
  ANALYSIS_HEALTH_ARTIFACT_NAME,
  ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS,
  ANALYSIS_HEALTH_MARKER_PREFIX,
  ANALYSIS_HEALTH_RUN_ARTIFACTS,
  ARTIFACT_MANIFEST_NAME,
  FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX,
  LEGACY_HASHED_RUN_ARTIFACTS,
  LEGACY_RUN_ARTIFACTS,
  OPERATIONAL_ANALYSIS_MARKER_PREFIX,
  PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX,
  SUPPORTED_TRIAGE_REPORT_ANALYSIS_MARKERS,
  TRIAGE_HASHED_RUN_ARTIFACTS,
  TRIAGE_REPORT_ANALYSIS_MARKER,
  TRIAGE_REPORT_ARTIFACT_NAME,
  TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER,
  TRIAGE_RUN_ARTIFACTS,
  analysisHealthMarker,
  profileObservationsAnalysisMarker
} from './artifact-contract.js';
import { AtlasError } from './errors.js';
import type { GitDiscoveryResult } from './discovery/types.js';
import { GIT_DISCOVERY_VERSION } from './discovery/index.js';
import { runIdentity, snapshotIdentity } from './identity.js';
import {
  ANALYSIS_HEALTH_VERSION,
  analysisHealthUsesProfileObservationContract,
  bundledOperationalControlEvaluation,
  operationalAnalysisMarkerForHealthVersion,
  operationalRuleInputStatusFromCodes,
  type OperationalControlEvaluation
} from './regression/incidents.js';
import { assertSchema } from './schema-validator.js';
import {
  MAX_VERIFIER_ARTIFACT_BYTES,
  MAX_VERIFIER_DIRECTORY_ENTRIES,
  MAX_VERIFIER_JSONL_RECORDS,
  MAX_VERIFIER_MANIFEST_BYTES,
  MAX_VERIFIER_NESTING_DEPTH,
  MAX_VERIFIER_TOTAL_BYTES,
  assertAggregateByteLimit,
  assertNestingDepth,
  parseBoundedJsonLines,
  readBoundedDirectoryEntries,
  readBoundedRegularFile
} from './security/bounded-artifacts.js';
import { renderTriageReportForMarker } from './triage-report.js';
import { FINDING_POSTPROCESS_VERSION } from './analysis/finding-postprocess.js';
import { findingReviewMetadataMismatchesForCollection } from './finding-priority.js';
import type {
  AnalysisHealthRecord,
  ArtifactManifest,
  DiagnosticRecord,
  FileRecord,
  FindingRecord,
  RelationshipRecord,
  RunRecord,
  SnapshotRecord
} from './types.js';
import { canonicalJson, canonicalJsonLines, compareCanonicalText, prettyCanonicalJson, sha256 } from './util/canonical.js';
import { normalizeIncludeRoot, normalizeTargetRelative } from './util/paths.js';

const MAX_ANALYSIS_HEALTH_PROFILE_PATTERNS = 10_000;
const MAX_ANALYSIS_HEALTH_RULES = 1_024;
const MAX_ANALYSIS_HEALTH_INCIDENTS = 10_000;
const MAX_ANALYSIS_HEALTH_SAMPLE_PATHS = 1_024;

export interface VerificationSummary {
  status: 'passed';
  healthState: 'recorded' | 'legacy-not-recorded';
  healthStatus: AnalysisHealthRecord['status'] | 'not-recorded';
  runId: string;
  snapshotId: string;
  files: number;
  relationships: number;
  diagnostics: number;
  findings: number;
  artifacts: number;
}

export interface VerifiedRunArtifacts {
  directory: string;
  run: RunRecord;
  snapshot: SnapshotRecord;
  discovery: GitDiscoveryResult;
  files: FileRecord[];
  relationships: RelationshipRecord[];
  diagnostics: DiagnosticRecord[];
  findings: FindingRecord[];
  analysisHealth?: AnalysisHealthRecord;
  triageReport?: string;
}

export interface VerifiedRunDirectoryResult {
  summary: VerificationSummary;
  manifest: ArtifactManifest;
  manifestSha256: string;
  artifacts: VerifiedRunArtifacts;
}

function unique<T>(values: T[], label: string): void {
  if (new Set(values).size !== values.length) throw new AtlasError('VERIFY_DUPLICATE', `${label} contains duplicate values.`);
}

function assertExactOrderedSet(observed: string[], expected: readonly string[], label: string): void {
  const normalizedObserved = [...observed].sort(compareCanonicalText);
  const normalizedExpected = [...expected].sort(compareCanonicalText);
  if (JSON.stringify(normalizedObserved) !== JSON.stringify(normalizedExpected)) {
    throw new AtlasError('VERIFY_ARTIFACT_SET', `${label} does not match the required Atlas artifact set.`);
  }
}

function matchesExactSet(observed: string[], expected: readonly string[]): boolean {
  const normalizedObserved = [...observed].sort(compareCanonicalText);
  const normalizedExpected = [...expected].sort(compareCanonicalText);
  return JSON.stringify(normalizedObserved) === JSON.stringify(normalizedExpected);
}

function assertExactOrder(observed: readonly string[], expected: readonly string[], label: string): void {
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    throw new AtlasError('VERIFY_ORDER', `${label} is not in canonical order.`);
  }
}

function assertSorted(values: string[], label: string): void {
  const sorted = [...values].sort(compareCanonicalText);
  assertExactOrder(values, sorted, label);
}

function assertCanonicalRelativePath(value: string): void {
  const normalized = normalizeTargetRelative(value);
  if (normalized !== value) throw new AtlasError('VERIFY_PATH', `Path is not in canonical target-relative form: ${value}`);
}

function parseJson<T>(content: string): T {
  const value = JSON.parse(content) as T;
  assertNestingDepth(value, {
    maxDepth: MAX_VERIFIER_NESTING_DEPTH,
    resourceCode: 'VERIFY_RESOURCE_LIMIT',
    label: 'Run JSON artifact'
  });
  return value;
}

function parseJsonLines<T>(content: string): T[] {
  return parseBoundedJsonLines<T>(content, {
    maxRecords: MAX_VERIFIER_JSONL_RECORDS,
    maxDepth: MAX_VERIFIER_NESTING_DEPTH,
    resourceCode: 'VERIFY_RESOURCE_LIMIT',
    label: 'Run JSON Lines artifact'
  });
}

function assertAnalysisHealthResourceLimits(value: unknown): void {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return;
  const record = value as Record<string, unknown>;
  const collections: Array<[unknown, number, string]> = [
    [record.profilePatterns, MAX_ANALYSIS_HEALTH_PROFILE_PATTERNS, 'profile-pattern observations'],
    [record.rules, MAX_ANALYSIS_HEALTH_RULES, 'rules'],
    [record.incidents, MAX_ANALYSIS_HEALTH_INCIDENTS, 'incidents']
  ];
  for (const [collection, limit, label] of collections) {
    if (Array.isArray(collection) && collection.length > limit) {
      throw new AtlasError('VERIFY_RESOURCE_LIMIT', `Analysis health exceeds ${limit} ${label}.`);
    }
  }
  if (Array.isArray(record.profilePatterns)) {
    for (const candidate of record.profilePatterns) {
      if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) continue;
      const samplePaths = (candidate as Record<string, unknown>).samplePaths;
      if (Array.isArray(samplePaths) && samplePaths.length > MAX_ANALYSIS_HEALTH_SAMPLE_PATHS) {
        throw new AtlasError('VERIFY_RESOURCE_LIMIT', `Analysis-health sample paths exceed ${MAX_ANALYSIS_HEALTH_SAMPLE_PATHS} entries.`);
      }
    }
  }
}

function assertAnalysisHealth(
  health: AnalysisHealthRecord,
  run: RunRecord,
  marker: string,
  findings: FindingRecord[],
  diagnostics: DiagnosticRecord[],
  usesProfileObservationContract: boolean,
  bundledEvaluation?: OperationalControlEvaluation
): void {
  const findingInstancesByRule = new Map<string, number>();
  for (const finding of findings) {
    findingInstancesByRule.set(
      finding.ruleId,
      (findingInstancesByRule.get(finding.ruleId) ?? 0) + (finding.instanceCount ?? 1)
    );
  }
  const diagnosticCodes = new Set(diagnostics.map((diagnostic) => diagnostic.code));
  if (health.runId !== run.runId || health.snapshotId !== run.snapshotId) {
    throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Analysis health run or snapshot binding differs from the verified run.');
  }
  const expectedMarker = analysisHealthMarker(health.producer.version, health.catalogDigest, health.corpusDigest);
  if (marker !== expectedMarker) {
    throw new AtlasError('VERIFY_IDENTITY', 'Analysis health marker does not bind the declared producer, catalog, and corpus digests.');
  }
  if (bundledEvaluation && (
    health.catalogDigest !== bundledEvaluation.catalogDigest || health.corpusDigest !== bundledEvaluation.corpusDigest
  )) {
    throw new AtlasError(
      'VERIFY_IDENTITY',
      'Analysis health catalog or corpus digest does not match the bundle for its producer version.'
    );
  }

  unique(health.profilePatterns.map((observation) => observation.id), 'Analysis health profile-pattern observations');
  unique(health.rules.map((rule) => rule.ruleId), 'Analysis health rules');
  unique(health.incidents.map((incident) => incident.id), 'Analysis health incidents');
  assertSorted(health.profilePatterns.map((observation) => observation.id), 'Analysis health profile-pattern observations');
  assertSorted(health.rules.map((rule) => rule.ruleId), 'Analysis health rules');
  assertSorted(health.incidents.map((incident) => incident.id), 'Analysis health incidents');

  for (const observation of health.profilePatterns) {
    if (observation.expected.maximum !== undefined && observation.expected.maximum < observation.expected.minimum) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health profile-pattern bounds are inconsistent: ${observation.id}`);
    }
    const passed = observation.observed >= observation.expected.minimum &&
      (observation.expected.maximum === undefined || observation.observed <= observation.expected.maximum);
    if (observation.status !== (passed ? 'passed' : 'failed')) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health profile-pattern status differs from its counts: ${observation.id}`);
    }
    const samplePaths = observation.samplePaths;
    if (usesProfileObservationContract && samplePaths === undefined) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health omits version-required profile-pattern sample paths: ${observation.id}`);
    }
    if (samplePaths !== undefined) {
      unique(samplePaths, `Analysis health profile-pattern sample paths: ${observation.id}`);
      assertSorted(samplePaths, `Analysis health profile-pattern sample paths: ${observation.id}`);
      for (const samplePath of samplePaths) assertCanonicalRelativePath(samplePath);
      if (samplePaths.length > observation.observed ||
        (usesProfileObservationContract && samplePaths.length !== Math.min(observation.observed, 32))) {
        throw new AtlasError('VERIFY_COUNT', `Analysis health profile-pattern samples differ from its observed count: ${observation.id}`);
      }
    }
  }

  const rulesById = new Map(health.rules.map((rule) => [rule.ruleId, rule]));
  for (const rule of health.rules) {
    const { controls } = rule;
    if (controls.total !== controls.passed + controls.failed) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health control counts do not add up: ${rule.ruleId}`);
    }
    if (usesProfileObservationContract && rule.target === undefined) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health omits version-required target accounting: ${rule.ruleId}`);
    }
    if (rule.target !== undefined) {
      if (usesProfileObservationContract && rule.target.inputStatus === undefined) {
        throw new AtlasError('VERIFY_COUNT', `Analysis health omits version-required target input status: ${rule.ruleId}`);
      }
      if (rule.target.inputStatus !== undefined &&
        rule.target.inputStatus !== operationalRuleInputStatusFromCodes(rule.ruleId, diagnosticCodes)) {
        throw new AtlasError('VERIFY_COUNT', `Analysis health target input status differs from diagnostics: ${rule.ruleId}`);
      }
      const possibleObservations = rule.target.detectedObservations + rule.target.uncertainObservations;
      const expectations = rule.target.expectations;
      if (expectations !== undefined && (
        (expectations.minimumDetectedObservations !== undefined &&
          expectations.minimumDetectedObservations > rule.target.detectedObservations) ||
        (expectations.maximumPossibleObservations !== undefined &&
          expectations.maximumPossibleObservations < possibleObservations) ||
        (expectations.minimumFindingInstances !== undefined &&
          expectations.minimumFindingInstances > rule.target.findingInstances) ||
        (expectations.maximumFindingInstances !== undefined &&
          expectations.maximumFindingInstances < rule.target.findingInstances) ||
        (expectations.minimumDetectedObservations !== undefined &&
          expectations.maximumPossibleObservations !== undefined &&
          expectations.maximumPossibleObservations < expectations.minimumDetectedObservations) ||
        (expectations.minimumFindingInstances !== undefined &&
          expectations.maximumFindingInstances !== undefined &&
          expectations.maximumFindingInstances < expectations.minimumFindingInstances)
      )) {
        throw new AtlasError('VERIFY_COUNT', `Analysis health target expectation differs from its counts: ${rule.ruleId}`);
      }
      const recordedFindingInstances = findingInstancesByRule.get(rule.ruleId) ?? 0;
      const suppressedFindingInstances = rule.target.suppressedFindingInstances ?? 0;
      if (
        suppressedFindingInstances > 0 &&
        !run.analyses.some((analysis) => analysis.startsWith(FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX))
      ) {
        throw new AtlasError(
          'VERIFY_IDENTITY',
          `Suppressed analysis-health findings lack a disposition-ledger identity marker: ${rule.ruleId}`
        );
      }
      if (
        suppressedFindingInstances > rule.target.findingInstances ||
        rule.target.findingInstances - suppressedFindingInstances !== recordedFindingInstances
      ) {
        throw new AtlasError(
          'VERIFY_COUNT',
          `Analysis health target finding and disposition counts differ from findings.jsonl: ${rule.ruleId}`
        );
      }
    }
  }

  const incidentAggregates = new Map<string, {
    total: number;
    passed: number;
    expectedObservations: number;
    observedObservations: number;
  }>();
  for (const incident of health.incidents) {
    const rule = rulesById.get(incident.ruleId);
    if (!rule) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Analysis health incident references a missing rule: ${incident.id}`);
    }
    const brokenOutcome = incident.broken.observed >= incident.broken.expectedMinimum ? 'detected' : 'missed';
    const fixedOutcome = incident.fixed.observed === 0 ? 'silent' : 'regressed';
    if (incident.fixed.expectedMaximum !== 0) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health fixed control does not require zero findings: ${incident.id}`);
    }
    if (
      (incident.broken.outcome === 'not-evaluated' && incident.broken.observed !== 0) ||
      (incident.fixed.outcome === 'not-evaluated' && incident.fixed.observed !== 0)
    ) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health unevaluated control has a nonzero observation count: ${incident.id}`);
    }
    if (
      (incident.broken.outcome !== 'not-evaluated' && incident.broken.outcome !== brokenOutcome) ||
      (incident.fixed.outcome !== 'not-evaluated' && incident.fixed.outcome !== fixedOutcome)
    ) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health incident outcome differs from its counts: ${incident.id}`);
    }
    const status = incident.broken.outcome === 'not-evaluated' || incident.fixed.outcome === 'not-evaluated'
      ? 'unsupported'
      : brokenOutcome === 'detected' && fixedOutcome === 'silent' ? 'passed' : 'failed';
    if (incident.status !== status) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health incident status differs from its outcomes: ${incident.id}`);
    }
    const aggregate = incidentAggregates.get(incident.ruleId) ?? {
      total: 0,
      passed: 0,
      expectedObservations: 0,
      observedObservations: 0
    };
    aggregate.total += 1;
    if (incident.status === 'passed') aggregate.passed += 1;
    aggregate.expectedObservations += incident.broken.expectedMinimum;
    aggregate.observedObservations += incident.broken.observed;
    incidentAggregates.set(incident.ruleId, aggregate);
  }
  for (const rule of health.rules) {
    const aggregate = incidentAggregates.get(rule.ruleId);
    if (!aggregate) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Analysis health rule has no incident regression case: ${rule.ruleId}`);
    }
    if (
      rule.controls.total !== aggregate.total || rule.controls.passed !== aggregate.passed ||
      rule.controls.failed !== aggregate.total - aggregate.passed ||
      rule.controls.expectedObservations !== aggregate.expectedObservations ||
      rule.controls.observedObservations !== aggregate.observedObservations
    ) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health rule controls differ from its incident records: ${rule.ruleId}`);
    }
    const enabled = aggregate.passed === aggregate.total;
    if (rule.state !== (enabled ? 'enabled' : 'disabled')) {
      throw new AtlasError('VERIFY_COUNT', `Analysis health rule state differs from its incident outcomes: ${rule.ruleId}`);
    }
  }

  if (bundledEvaluation) {
    const recordedControlRules = health.rules.map((rule) => ({
      ruleId: rule.ruleId,
      state: rule.state,
      controls: rule.controls
    }));
    if (
      canonicalJson(recordedControlRules) !== canonicalJson(bundledEvaluation.rules) ||
      canonicalJson(health.incidents) !== canonicalJson(bundledEvaluation.incidents)
    ) {
      throw new AtlasError(
        'VERIFY_IDENTITY',
        'Analysis health control results do not match a fresh evaluation of the bundled controls.'
      );
    }
  }

  if (health.producer.version === ANALYSIS_HEALTH_VERSION && (
    health.recall.tier !== 'synthetic' ||
    health.realTargetEvaluation?.tier !== 'real-target' ||
    health.realTargetEvaluation?.result !== 'not-recorded-in-run' ||
    health.realTargetEvaluation?.reportContract !== 'real-target-corpus-report.schema.json'
  )) {
    throw new AtlasError(
      'VERIFY_IDENTITY',
      'Current analysis health must label synthetic recall and point to the separately evaluated real-target report contract.'
    );
  }
  const detectedCases = health.incidents.filter((incident) => incident.broken.outcome === 'detected').length;
  if (health.recall.numerator !== detectedCases || health.recall.denominator !== health.incidents.length) {
    throw new AtlasError('VERIFY_COUNT', 'Analysis health recall counts do not match incident outcomes.');
  }
  const silentCases = health.incidents.filter((incident) => incident.fixed.outcome === 'silent').length;
  if (health.fixedCaseSilence.numerator !== silentCases || health.fixedCaseSilence.denominator !== health.incidents.length) {
    throw new AtlasError('VERIFY_COUNT', 'Analysis health fixed-case silence counts do not match incident outcomes.');
  }
  const complete = health.profilePatterns.every((observation) => observation.status === 'passed') &&
    health.rules.every((rule) => rule.state === 'enabled' && rule.target?.inputStatus !== 'incomplete') &&
    health.incidents.every((incident) => incident.status === 'passed');
  if (health.status !== (complete ? 'complete' : 'incomplete')) {
    throw new AtlasError('VERIFY_COUNT', 'Analysis health aggregate status differs from its component outcomes.');
  }
}

/** @internal Returns the parsed objects backed by the exact bytes verified in this call. */
export async function verifyAndLoadRunDirectory(runDirectoryValue: string): Promise<VerifiedRunDirectoryResult> {
  const runDirectory = path.resolve(runDirectoryValue);
  const directoryEntries = await readBoundedDirectoryEntries(runDirectory, {
    maxEntries: MAX_VERIFIER_DIRECTORY_ENTRIES,
    resourceCode: 'VERIFY_RESOURCE_LIMIT',
    label: 'Run directory'
  });
  if (directoryEntries.some((entry) => !entry.isFile() || entry.isSymbolicLink())) {
    throw new AtlasError('VERIFY_ARTIFACT_SET', 'Run directory contains a non-file entry.');
  }
  const directoryNames = directoryEntries.map((entry) => entry.name);
  const directoryHasTriage = matchesExactSet(directoryNames, TRIAGE_RUN_ARTIFACTS);
  const directoryHasAnalysisHealth = directoryHasTriage || matchesExactSet(directoryNames, ANALYSIS_HEALTH_RUN_ARTIFACTS);
  if (!directoryHasAnalysisHealth && !matchesExactSet(directoryNames, LEGACY_RUN_ARTIFACTS)) {
    throw new AtlasError('VERIFY_ARTIFACT_SET', 'Run directory does not match a supported Atlas artifact set.');
  }
  const runArtifacts = directoryHasTriage
    ? TRIAGE_RUN_ARTIFACTS
    : directoryHasAnalysisHealth ? ANALYSIS_HEALTH_RUN_ARTIFACTS : LEGACY_RUN_ARTIFACTS;
  const hashedArtifacts = directoryHasTriage
    ? TRIAGE_HASHED_RUN_ARTIFACTS
    : directoryHasAnalysisHealth ? ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS : LEGACY_HASHED_RUN_ARTIFACTS;
  const manifestBytes = await readBoundedRegularFile(path.join(runDirectory, ARTIFACT_MANIFEST_NAME), {
    maxBytes: MAX_VERIFIER_MANIFEST_BYTES,
    resourceCode: 'VERIFY_RESOURCE_LIMIT',
    invalidCode: 'VERIFY_ARTIFACT_SET',
    label: 'Run artifact manifest'
  });
  const rawManifest = manifestBytes.toString('utf8');
  const manifest = parseJson<ArtifactManifest>(rawManifest);
  await assertSchema('artifact-manifest', manifest, 'Artifact manifest');
  unique(manifest.artifacts.map((artifact) => artifact.path), 'Artifact manifest');
  assertExactOrderedSet(manifest.artifacts.map((artifact) => artifact.path), hashedArtifacts, 'Artifact manifest');
  assertSorted(manifest.artifacts.map((artifact) => artifact.path), 'Artifact manifest');
  if (manifest.artifacts.some((artifact) => artifact.bytes > MAX_VERIFIER_ARTIFACT_BYTES)) {
    throw new AtlasError('VERIFY_RESOURCE_LIMIT', `Run artifact exceeds the ${MAX_VERIFIER_ARTIFACT_BYTES}-byte verification limit.`);
  }
  assertAggregateByteLimit(
    [manifestBytes.length, ...manifest.artifacts.map((artifact) => artifact.bytes)],
    { maxBytes: MAX_VERIFIER_TOTAL_BYTES, resourceCode: 'VERIFY_RESOURCE_LIMIT', label: 'Run artifacts' }
  );

  const artifactBuffers = new Map<string, Buffer>([[ARTIFACT_MANIFEST_NAME, manifestBytes]]);
  let observedBytes = manifestBytes.length;
  for (const name of runArtifacts) {
    if (name === ARTIFACT_MANIFEST_NAME) continue;
    const content = await readBoundedRegularFile(path.join(runDirectory, name), {
      maxBytes: Math.min(MAX_VERIFIER_ARTIFACT_BYTES, MAX_VERIFIER_TOTAL_BYTES - observedBytes),
      resourceCode: 'VERIFY_RESOURCE_LIMIT',
      invalidCode: 'VERIFY_ARTIFACT_SET',
      label: `Run artifact ${name}`
    });
    observedBytes += content.length;
    artifactBuffers.set(name, content);
  }
  const contentFor = (name: string): Buffer => {
    const content = artifactBuffers.get(name);
    if (!content) throw new AtlasError('VERIFY_ARTIFACT_SET', `Required run artifact is missing: ${name}`);
    return content;
  };
  const textFor = (name: string): string => {
    return contentFor(name).toString('utf8');
  };
  for (const artifact of manifest.artifacts) {
    assertCanonicalRelativePath(artifact.path);
    const content = contentFor(artifact.path);
    if (content.length !== artifact.bytes || sha256(content) !== artifact.sha256) {
      throw new AtlasError('VERIFY_DIGEST', `Artifact digest mismatch: ${artifact.path}`);
    }
  }
  const rawSnapshot = textFor('snapshot.json');
  const rawRun = textFor('run.json');
  const rawDiscovery = textFor('discovery.json');
  const rawFiles = textFor('files.jsonl');
  const rawRelationships = textFor('relationships.jsonl');
  const rawDiagnostics = textFor('diagnostics.jsonl');
  const rawFindings = textFor('findings.jsonl');
  const rawTriageReport = directoryHasTriage ? textFor(TRIAGE_REPORT_ARTIFACT_NAME) : undefined;
  const rawAnalysisHealth = directoryHasAnalysisHealth ? textFor(ANALYSIS_HEALTH_ARTIFACT_NAME) : undefined;
  const manifestSha256 = sha256(manifestBytes);
  artifactBuffers.clear();
  const snapshot = parseJson<SnapshotRecord>(rawSnapshot);
  const run = parseJson<RunRecord>(rawRun);
  const discovery = parseJson<GitDiscoveryResult>(rawDiscovery);
  const files = parseJsonLines<FileRecord>(rawFiles);
  const relationships = parseJsonLines<RelationshipRecord>(rawRelationships);
  const diagnostics = parseJsonLines<DiagnosticRecord>(rawDiagnostics);
  const findings = parseJsonLines<FindingRecord>(rawFindings);
  const healthMarkers = Array.isArray(run.analyses)
    ? run.analyses.filter((analysis) => typeof analysis === 'string' && analysis.startsWith(ANALYSIS_HEALTH_MARKER_PREFIX))
    : [];
  const operationalMarkers = Array.isArray(run.analyses)
    ? run.analyses.filter((analysis) =>
        typeof analysis === 'string' && analysis.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX)
      )
    : [];
  const profileObservationMarkers = Array.isArray(run.analyses)
    ? run.analyses.filter((analysis) =>
        typeof analysis === 'string' && analysis.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX)
      )
    : [];
  const findingDispositionMarkers = Array.isArray(run.analyses)
    ? run.analyses.filter((analysis) =>
        typeof analysis === 'string' && analysis.startsWith(FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX)
      )
    : [];
  const findingPostprocessMarkers = Array.isArray(run.analyses)
    ? run.analyses.filter((analysis) =>
        typeof analysis === 'string' && analysis.startsWith('finding-postprocess-v')
      )
    : [];
  const triageMarkers = Array.isArray(run.analyses)
    ? run.analyses.filter((analysis) => typeof analysis === 'string' && analysis.startsWith('triage-report-v'))
    : [];
  if (healthMarkers.length > 1) {
    throw new AtlasError('VERIFY_DUPLICATE', 'Run declares more than one analysis health marker.');
  }
  if (profileObservationMarkers.length > 1) {
    throw new AtlasError('VERIFY_DUPLICATE', 'Run declares more than one profile-observations analysis marker.');
  }
  if (findingDispositionMarkers.length > 1) {
    throw new AtlasError('VERIFY_DUPLICATE', 'Run declares more than one finding-disposition analysis marker.');
  }
  if (findingPostprocessMarkers.length > 1) {
    throw new AtlasError('VERIFY_DUPLICATE', 'Run declares more than one finding-postprocess marker.');
  }
  if (triageMarkers.length > 1) {
    throw new AtlasError('VERIFY_DUPLICATE', 'Run declares more than one triage-report marker.');
  }
  const supportedTriageMarker = triageMarkers.length === 1 &&
    SUPPORTED_TRIAGE_REPORT_ANALYSIS_MARKERS.some((marker) => marker === triageMarkers[0]);
  if ((triageMarkers.length === 1) !== directoryHasTriage ||
    (directoryHasTriage && !supportedTriageMarker)) {
    throw new AtlasError('VERIFY_ARTIFACT_SET', 'The triage-report marker and run artifact set disagree.');
  }
  if (
    findingDispositionMarkers.length === 1 &&
    !/^finding-dispositions-v1\.(?:0|1)\.0\+sha256\.[a-f0-9]{64}$/u.test(findingDispositionMarkers[0]!)
  ) {
    throw new AtlasError('VERIFY_IDENTITY', 'Run finding-disposition marker is malformed or unsupported.');
  }
  if ((healthMarkers.length === 1) !== directoryHasAnalysisHealth) {
    throw new AtlasError('VERIFY_ARTIFACT_SET', 'The analysis health marker and run artifact set disagree.');
  }
  if (operationalMarkers.length > 0 && !directoryHasAnalysisHealth) {
    throw new AtlasError(
      'VERIFY_ARTIFACT_SET',
      'Operational-risk analysis requires the current analysis-health artifact and marker.'
    );
  }
  if (profileObservationMarkers.length > 0 && !directoryHasAnalysisHealth) {
    throw new AtlasError(
      'VERIFY_ARTIFACT_SET',
      'Profile-observations identity binding requires the analysis-health artifact and marker.'
    );
  }
  if (findingDispositionMarkers.length > 0 && !directoryHasAnalysisHealth) {
    throw new AtlasError(
      'VERIFY_ARTIFACT_SET',
      'Finding dispositions require the current analysis-health artifact and marker.'
    );
  }
  const analysisHealth = rawAnalysisHealth === undefined ? undefined : parseJson<AnalysisHealthRecord>(rawAnalysisHealth);
  if (analysisHealth !== undefined) assertAnalysisHealthResourceLimits(analysisHealth);
  if (
    rawManifest !== prettyCanonicalJson(manifest) || rawSnapshot !== prettyCanonicalJson(snapshot) ||
    rawRun !== prettyCanonicalJson(run) || rawDiscovery !== prettyCanonicalJson(discovery) || rawFiles !== canonicalJsonLines(files) ||
    rawRelationships !== canonicalJsonLines(relationships) || rawDiagnostics !== canonicalJsonLines(diagnostics) ||
    rawFindings !== canonicalJsonLines(findings) ||
    (analysisHealth !== undefined && rawAnalysisHealth !== prettyCanonicalJson(analysisHealth))
  ) throw new AtlasError('VERIFY_CANONICAL', 'One or more run artifacts are not canonically serialized.');
  await assertSchema('snapshot', snapshot, 'Snapshot');
  await assertSchema('run', run, 'Run');
  await assertSchema('git-discovery', discovery, 'Git discovery ledger');
  for (const [index, file] of files.entries()) await assertSchema('file', file, `File record ${index + 1}`);
  for (const [index, relationship] of relationships.entries()) {
    await assertSchema('relationship', relationship, `Relationship record ${index + 1}`);
  }
  for (const [index, diagnosticRecord] of diagnostics.entries()) {
    await assertSchema('diagnostic', diagnosticRecord, `Diagnostic record ${index + 1}`);
  }
  for (const [index, finding] of findings.entries()) await assertSchema('finding', finding, `Finding record ${index + 1}`);
  if (analysisHealth) await assertSchema('analysis-health', analysisHealth, 'Analysis health');
  assertExactOrder(run.artifacts, runArtifacts, 'Run artifact declaration');
  if (run.runId !== manifest.runId) throw new AtlasError('VERIFY_IDENTITY', 'Run ID differs from artifact manifest.');
  if (snapshot.targetId !== run.targetId) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Snapshot and run target IDs differ.');
  const { snapshotId: observedSnapshotId, ...snapshotMaterial } = snapshot;
  if (snapshotIdentity(snapshotMaterial) !== observedSnapshotId || run.snapshotId !== observedSnapshotId) {
    throw new AtlasError('VERIFY_IDENTITY', 'Snapshot identity does not match its canonical content.');
  }
  const expectedRunId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  if (expectedRunId !== run.runId) throw new AtlasError('VERIFY_IDENTITY', 'Run identity does not match its canonical inputs.');
  if (analysisHealth) {
    const currentAnalysisHealth = analysisHealth.producer.version === ANALYSIS_HEALTH_VERSION;
    if (currentAnalysisHealth && (
      !directoryHasTriage ||
      (triageMarkers[0] !== TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER &&
        triageMarkers[0] !== TRIAGE_REPORT_ANALYSIS_MARKER)
    )) {
      throw new AtlasError(
        'VERIFY_IDENTITY',
        'Current analysis health requires a compatible triage-report projection.'
      );
    }
    const usesProfileObservationContract = analysisHealthUsesProfileObservationContract(
      analysisHealth.producer.version
    );
    const expectedOperationalMarker = operationalAnalysisMarkerForHealthVersion(analysisHealth.producer.version);
    if (expectedOperationalMarker && operationalMarkers.length > 1) {
      throw new AtlasError('VERIFY_DUPLICATE', 'Supported analysis health declares more than one operational-risk marker.');
    }
    if (expectedOperationalMarker && (
      operationalMarkers.length !== 1 || operationalMarkers[0] !== expectedOperationalMarker
    )) {
      throw new AtlasError(
        'VERIFY_IDENTITY',
        'Analysis health requires the operational-risk marker paired with its producer version.'
      );
    }
    if (!expectedOperationalMarker && operationalMarkers.length > 0) {
      throw new AtlasError(
        'VERIFY_IDENTITY',
        'Operational-risk analysis uses an unsupported analysis-health producer pairing.'
      );
    }
    if (usesProfileObservationContract && profileObservationMarkers.length !== 1) {
      throw new AtlasError(
        'VERIFY_IDENTITY',
        'Analysis health requires its versioned profile-observations identity marker.'
      );
    }
    if (profileObservationMarkers.length === 1 &&
      profileObservationMarkers[0] !== profileObservationsAnalysisMarker(analysisHealth.profilePatterns)) {
      throw new AtlasError(
        'VERIFY_IDENTITY',
        'The profile-observations marker does not match analysis-health profile patterns.'
      );
    }
    const bundledEvaluation = currentAnalysisHealth
      ? await bundledOperationalControlEvaluation()
      : undefined;
    assertAnalysisHealth(
      analysisHealth,
      run,
      healthMarkers[0]!,
      findings,
      diagnostics,
      usesProfileObservationContract,
      bundledEvaluation
    );
  }
  if (rawTriageReport !== undefined && rawTriageReport !== renderTriageReportForMarker(
    triageMarkers[0]!,
    run,
    findings,
    diagnostics
  )) {
    throw new AtlasError('VERIFY_CONTENT', 'Triage report does not match the verified run findings and diagnostics.');
  }
  unique(files.map((file) => file.id), 'File records');
  unique(files.map((file) => file.path), 'File paths');
  unique(relationships.map((relationship) => relationship.id), 'Relationships');
  unique(diagnostics.map((entry) => entry.id), 'Diagnostics');
  unique(findings.map((finding) => finding.id), 'Findings');
  unique(snapshot.files.map((file) => file.id), 'Snapshot file records');
  unique(snapshot.files.map((file) => file.path), 'Snapshot file paths');
  unique(snapshot.boundary.includeRoots, 'Snapshot include roots');
  unique(snapshot.boundary.exclude, 'Snapshot exclusions');
  unique(snapshot.boundaryDiagnostics.map((diagnostic) => diagnostic.id), 'Snapshot boundary diagnostics');
  unique(run.analyses, 'Run analyses');
  unique(run.adapters.map((adapter) => adapter.id), 'Run adapters');
  unique(discovery.records.map((record) => record.path), 'Git discovery paths');
  assertSorted(files.map((file) => file.path), 'File records');
  assertSorted(snapshot.files.map((file) => file.path), 'Snapshot file records');
  assertSorted(snapshot.boundaryDiagnostics.map((diagnostic) => diagnostic.id), 'Snapshot boundary diagnostics');
  assertSorted(relationships.map((relationship) => relationship.id), 'Relationships');
  assertSorted(diagnostics.map((diagnostic) => diagnostic.id), 'Diagnostics');
  assertSorted(findings.map((finding) => finding.id), 'Findings');
  assertSorted(run.analyses, 'Run analyses');
  assertSorted(run.adapters.map((adapter) => adapter.id), 'Run adapters');
  assertSorted(discovery.records.map((record) => record.path), 'Git discovery records');
  const sortedDiscoveryDiagnostics = [...discovery.diagnostics].sort((left, right) =>
    compareCanonicalText(left.code, right.code) ||
    compareCanonicalText(left.path ?? '', right.path ?? '') ||
    compareCanonicalText(left.message, right.message)
  );
  if (canonicalJson(discovery.diagnostics) !== canonicalJson(sortedDiscoveryDiagnostics)) {
    throw new AtlasError('VERIFY_ORDER', 'Git discovery diagnostics are not in canonical order.');
  }
  if ((discovery.state === 'ready' || discovery.state === 'partial') && !discovery.repository) {
    throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Usable Git discovery is missing repository provenance.');
  }
  if (
    run.discovery.provider !== discovery.provider || run.discovery.state !== discovery.state ||
    run.discovery.digest !== sha256(canonicalJson(discovery)) || run.discovery.version !== GIT_DISCOVERY_VERSION
  ) {
    throw new AtlasError('VERIFY_IDENTITY', 'Run Git discovery binding does not match the discovery ledger.');
  }
  if (discovery.repository) {
    const expectedObjectIdLength = discovery.repository.objectFormat === 'sha1' ? 40 : 64;
    const { head } = discovery.repository;
    if (
      (head.state === 'attached' && (!head.objectId || !head.branch)) ||
      (head.state === 'detached' && (!head.objectId || head.branch !== undefined)) ||
      (head.state === 'unborn' && (!head.branch || head.objectId !== undefined))
    ) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Git HEAD fields do not match its declared state.');
    }
    if (discovery.repository.head.objectId && discovery.repository.head.objectId.length !== expectedObjectIdLength) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Git HEAD object ID does not match the repository object format.');
    }
  }
  for (const record of discovery.records) {
    assertCanonicalRelativePath(record.path);
    if (record.originalPath) assertCanonicalRelativePath(record.originalPath);
    const sortedIndexEntries = [...record.indexEntries].sort((left, right) =>
      left.stage - right.stage ||
      compareCanonicalText(left.mode, right.mode) ||
      compareCanonicalText(left.objectId, right.objectId)
    );
    if (canonicalJson(record.indexEntries) !== canonicalJson(sortedIndexEntries)) {
      throw new AtlasError('VERIFY_ORDER', `Git index entries are not in canonical order: ${record.path}`);
    }
  }
  for (const diagnostic of discovery.diagnostics) if (diagnostic.path) assertCanonicalRelativePath(diagnostic.path);
  for (const includeRoot of snapshot.boundary.includeRoots) {
    if (normalizeIncludeRoot(includeRoot) !== includeRoot) throw new AtlasError('VERIFY_PATH', `Non-canonical include root: ${includeRoot}`);
  }
  for (const exclusion of snapshot.boundary.exclude) assertCanonicalRelativePath(exclusion);
  for (const diagnostic of snapshot.boundaryDiagnostics) if (diagnostic.path) assertCanonicalRelativePath(diagnostic.path);
  const fileById = new Map(files.map((file) => [file.id, file]));
  const requiresLifecycle = run.analyses.includes('core-census-v1.2.0') || run.analyses.includes('core-census-v1.3.0');
  for (const file of files) {
    assertCanonicalRelativePath(file.path);
    if (!/^[a-f0-9]{64}$/.test(file.sha256)) throw new AtlasError('VERIFY_SCHEMA', `Invalid file digest: ${file.path}`);
    const expectedFileId = `file_sha256_${sha256(canonicalJson({ domain: 'atlas.file.v1', targetId: run.targetId, path: file.path }))}`;
    if (file.id !== expectedFileId) throw new AtlasError('VERIFY_IDENTITY', `File identity is not canonical: ${file.path}`);
    if (file.evidence.path !== file.path) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `File evidence path differs: ${file.path}`);
    if (!file.lifecycle) {
      if (requiresLifecycle) {
        throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Current core-census file lacks a lifecycle declaration: ${file.path}`);
      }
    } else if (
      file.lifecycle.uncertainty !== 'not-runtime-validated' ||
      (file.lifecycle.basis === 'profile-path-rule' && !file.lifecycle.ruleId?.trim()) ||
      (file.lifecycle.basis === 'no-profile-match' && (file.lifecycle.state !== 'unspecified' || file.lifecycle.ruleId !== undefined))
    ) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `File lifecycle declaration is inconsistent: ${file.path}`);
    }
  }
  const snapshotFiles = new Map(snapshot.files.map((file) => [file.id, file]));
  if (snapshotFiles.size !== files.length) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Snapshot and file-record counts differ.');
  for (const file of files) {
    const identity = snapshotFiles.get(file.id);
    if (!identity || identity.path !== file.path || identity.sha256 !== file.sha256 || identity.bytes !== file.bytes) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Snapshot file identity differs: ${file.path}`);
    }
  }
  for (const relationship of relationships) {
    assertCanonicalRelativePath(relationship.fromPath);
    if (relationship.toPath) assertCanonicalRelativePath(relationship.toPath);
    const source = fileById.get(relationship.from);
    if (!source) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Missing relationship source: ${relationship.id}`);
    if (source.path !== relationship.fromPath) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Relationship source path differs: ${relationship.id}`);
    const expectedRelationshipId = `relationship:${sha256(canonicalJson({
      from: relationship.fromPath,
      location: relationship.location,
      specifier: relationship.specifier,
      type: relationship.type
    })).slice(0, 24)}`;
    if (relationship.id !== expectedRelationshipId) throw new AtlasError('VERIFY_IDENTITY', `Relationship identity is not canonical: ${relationship.id}`);
    if (relationship.evidence.path !== relationship.fromPath) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Relationship evidence path differs: ${relationship.id}`);
    if (relationship.resolution === 'resolved') {
      const target = relationship.to ? fileById.get(relationship.to) : undefined;
      if (!target) {
        throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Missing resolved relationship target: ${relationship.id}`);
      }
      if (target.path !== relationship.toPath) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Relationship target path differs: ${relationship.id}`);
    } else if (relationship.to || relationship.toPath) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Unresolved relationship unexpectedly has a target: ${relationship.id}`);
    }
  }
  const recordIds = new Set<string>([
    ...files.map((file) => file.id),
    ...relationships.map((relationship) => relationship.id),
    ...diagnostics.map((diagnostic) => diagnostic.id),
    ...findings.map((finding) => finding.id)
  ]);
  const evidenceValues = [
    ...files.map((file) => file.evidence),
    ...relationships.map((relationship) => relationship.evidence),
    ...diagnostics.map((diagnostic) => diagnostic.evidence),
    ...findings.flatMap((finding) => [
      ...finding.evidence,
      ...(finding.instances ?? []).flatMap((instance) => instance.evidence)
    ])
  ];
  for (const evidence of evidenceValues) {
    if (evidence.path) assertCanonicalRelativePath(evidence.path);
    for (const recordId of evidence.recordIds ?? []) {
      if (!recordIds.has(recordId)) throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Evidence references a missing record: ${recordId}`);
    }
  }
  for (const diagnostic of diagnostics) {
    if (diagnostic.path) assertCanonicalRelativePath(diagnostic.path);
    if (diagnostic.path && diagnostic.evidence.path && diagnostic.path !== diagnostic.evidence.path) {
      throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', `Diagnostic evidence path differs: ${diagnostic.id}`);
    }
  }
  const observedBoundaryDiagnostics = diagnostics
    .filter((diagnostic) => diagnostic.evidence.producer === 'atlas/core-census')
    .map((diagnostic) => ({
      id: diagnostic.id,
      code: diagnostic.code,
      severity: diagnostic.severity,
      ...(diagnostic.path ? { path: diagnostic.path } : {})
    }));
  if (canonicalJson(snapshot.boundaryDiagnostics) !== canonicalJson(observedBoundaryDiagnostics)) {
    throw new AtlasError('VERIFY_REFERENTIAL_INTEGRITY', 'Snapshot boundary diagnostics differ from run diagnostics.');
  }
  for (const finding of findings) {
    if (finding.path) assertCanonicalRelativePath(finding.path);
    for (const relatedPath of finding.relatedPaths) assertCanonicalRelativePath(relatedPath);
    if (finding.instances) {
      unique(finding.instances.map((instance) => instance.id), `Finding instances for ${finding.id}`);
      if (finding.instanceCount !== finding.instances.length) {
        throw new AtlasError('VERIFY_COUNT', `Finding instance count differs from its records: ${finding.id}`);
      }
      for (const instance of finding.instances) {
        if (instance.path) assertCanonicalRelativePath(instance.path);
        for (const relatedPath of instance.relatedPaths) assertCanonicalRelativePath(relatedPath);
        for (const entrypoint of instance.impactContext?.entrypoints ?? []) assertCanonicalRelativePath(entrypoint);
      }
    } else if (finding.instanceCount !== undefined && finding.instanceCount !== 1) {
      throw new AtlasError('VERIFY_COUNT', `Singleton finding has a non-singleton instance count: ${finding.id}`);
    }
    for (const entrypoint of finding.impactContext?.entrypoints ?? []) assertCanonicalRelativePath(entrypoint);
  }
  if (findingPostprocessMarkers[0] === `finding-postprocess-v${FINDING_POSTPROCESS_VERSION}`) {
    const omittedReviews = diagnostics.flatMap((diagnostic) =>
      diagnostic.code === 'FINDING_DISPOSITION_APPLIED' && diagnostic.disposition?.state === 'applied'
        ? [{ findingId: diagnostic.disposition.findingId, reviewId: diagnostic.disposition.reviewId }]
        : []
    );
    const mismatches = findingReviewMetadataMismatchesForCollection(findings, files, omittedReviews);
    if (mismatches.length > 0) {
      const first = mismatches[0]!;
      throw new AtlasError(
        'VERIFY_IDENTITY',
        `Current finding review metadata differs for ${first.findingId}: ${first.fields.join(', ')}.`
      );
    }
  }
  const findingInstances = findings.reduce((total, finding) => total + (finding.instanceCount ?? 1), 0);
  if (
    run.counts.files !== files.length || run.counts.relationships !== relationships.length ||
    run.counts.diagnostics !== diagnostics.length || run.counts.findings !== findings.length ||
    (analysisHealth !== undefined && run.counts.findingInstances === undefined) ||
    (run.counts.findingInstances !== undefined && run.counts.findingInstances !== findingInstances)
  ) throw new AtlasError('VERIFY_COUNT', 'Run counts do not match artifact records.');
  const summary: VerificationSummary = {
    status: 'passed',
    healthState: analysisHealth === undefined ? 'legacy-not-recorded' : 'recorded',
    healthStatus: analysisHealth?.status ?? 'not-recorded',
    runId: run.runId,
    snapshotId: snapshot.snapshotId,
    files: files.length,
    relationships: relationships.length,
    diagnostics: diagnostics.length,
    findings: findings.length,
    artifacts: manifest.artifacts.length + 1
  };
  return {
    summary,
    manifest,
    manifestSha256,
    artifacts: {
      directory: runDirectory,
      run,
      snapshot,
      discovery,
      files,
      relationships,
      diagnostics,
      findings,
      ...(analysisHealth ? { analysisHealth } : {}),
      ...(rawTriageReport === undefined ? {} : { triageReport: rawTriageReport })
    }
  };
}

export async function verifyRunDirectory(runDirectoryValue: string): Promise<VerificationSummary> {
  return (await verifyAndLoadRunDirectory(runDirectoryValue)).summary;
}
