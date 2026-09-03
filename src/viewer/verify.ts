import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import {
  ANALYSIS_HEALTH_MARKER_PREFIX,
  FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX,
  OPERATIONAL_ANALYSIS_MARKER_PREFIX,
  PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX,
  TRIAGE_REPORT_ANALYSIS_MARKER,
  TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER,
  analysisHealthMarker,
  profileObservationsAnalysisMarker
} from '../artifact-contract.js';
import { AtlasError } from '../errors.js';
import { HARD_MAX_INCLUDED_FILES } from '../limits.js';
import {
  MAX_VERIFIER_ARTIFACT_BYTES,
  MAX_VERIFIER_DIRECTORY_ENTRIES,
  MAX_VERIFIER_MANIFEST_BYTES,
  MAX_VERIFIER_TOTAL_BYTES,
  assertAggregateByteLimit,
  readBoundedDirectoryEntries,
  readBoundedRegularFile
} from '../security/bounded-artifacts.js';
import { FINDING_POSTPROCESS_VERSION } from '../analysis/finding-postprocess.js';
import { findingReviewMetadataMismatchesForCollection } from '../finding-priority.js';
import {
  ANALYSIS_HEALTH_VERSION,
  analysisHealthUsesProfileObservationContract,
  bundledOperationalControlEvaluation,
  operationalAnalysisMarkerForHealthVersion,
  operationalRuleInputStatusFromCodes,
  type OperationalControlEvaluation
} from '../regression/incidents.js';
import type { AnalysisHealthPatternObservation } from '../types.js';
import { canonicalJson, compareCanonicalText, prettyCanonicalJson, sha256 } from '../util/canonical.js';
import { normalizeTargetRelative } from '../util/paths.js';
import { VIEWER_APP_JAVASCRIPT, VIEWER_CSS, VIEWER_HTML } from './assets.js';
import {
  ALL_VIEWER_ARTIFACTS,
  decodeViewerDataScript,
  viewerIdentity,
  VIEWER_CONTENT_ARTIFACTS,
  VIEWER_MANIFEST_NAME
} from './bundle.js';
import { renderDependencyMermaid } from './model.js';
import {
  VIEWER_VERSION,
  type VerifiedViewerArtifacts,
  type ViewerData,
  type ViewerManifest,
  type ViewerVerificationSummary
} from './types.js';

const MAX_VIEWER_COLLECTION_RECORDS = 250_000;
const MAX_VIEWER_ANALYSES = 10_000;
const MAX_VIEWER_RELATIONSHIP_PROJECTIONS = 500_000;
const MAX_VIEWER_HEALTH_PROFILE_PATTERNS = 10_000;
const MAX_VIEWER_HEALTH_RULES = 1_024;
const MAX_VIEWER_HEALTH_INCIDENTS = 10_000;
const MAX_VIEWER_HEALTH_SAMPLE_PATHS = 1_024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: string[], label: string): void {
  const observed = Object.keys(value).sort(compareCanonicalText);
  const sortedExpected = [...expected].sort(compareCanonicalText);
  if (canonicalJson(observed) !== canonicalJson(sortedExpected)) {
    throw new AtlasError('VIEWER_MANIFEST_INVALID', `${label} does not have the required fields.`);
  }
}

function exactDataKeys(value: Record<string, unknown>, expected: string[], label: string): void {
  const observed = Object.keys(value).sort(compareCanonicalText);
  const sortedExpected = [...expected].sort(compareCanonicalText);
  if (canonicalJson(observed) !== canonicalJson(sortedExpected)) {
    throw new AtlasError('VIEWER_DATA_INVALID', `${label} does not have the required fields.`);
  }
}

const PROFILE_LIFECYCLE_LIMITATION = 'Lifecycle is a static profile declaration and has not been validated against runtime deployment, traffic, or use.';
const UNSPECIFIED_LIFECYCLE_LIMITATION = 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.';
const LEGACY_LIFECYCLE_LIMITATION = 'This legacy v1 file record predates lifecycle declarations; runtime deployment, traffic, and use were not evaluated.';
const LEGACY_ANALYSIS_HEALTH_LIMITATION =
  'This legacy run predates analysis-health artifacts; rule controls, incident regressions, recall, and fixed-case silence were not recorded.';

function isNonnegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isCanonicalTargetRelativePath(value: unknown): value is string {
  if (typeof value !== 'string' || !value) return false;
  try {
    return normalizeTargetRelative(value) === value;
  } catch {
    return false;
  }
}

function assertUniqueStrings(value: unknown, label: string, allowEmpty = true): asserts value is string[] {
  if (
    !Array.isArray(value) || (!allowEmpty && value.length === 0) ||
    value.some((entry) => typeof entry !== 'string' || !entry) ||
    new Set(value).size !== value.length
  ) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
}

function assertHealthRatio(
  value: unknown,
  label: string,
  tier?: 'synthetic'
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is missing or invalid.`);
  exactDataKeys(value, [...(tier ? ['tier'] : []), 'numerator', 'denominator'], label);
  if (
    (tier !== undefined && value.tier !== tier) ||
    !isNonnegativeInteger(value.numerator) || !isNonnegativeInteger(value.denominator) ||
    value.numerator > value.denominator
  ) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
}

function assertViewerAnalysisHealth(
  value: unknown,
  runId: string,
  snapshotId: string,
  analyses: string[],
  bundledEvaluation: OperationalControlEvaluation,
  findings: ViewerData['findings'],
  diagnostics: ViewerData['diagnostics']
): void {
  if (!isRecord(value)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis health is missing or invalid.');
  const healthMarkers = analyses.filter((analysis) => analysis.startsWith(ANALYSIS_HEALTH_MARKER_PREFIX));
  const operationalMarkers = analyses.filter((analysis) => analysis.startsWith(OPERATIONAL_ANALYSIS_MARKER_PREFIX));
  const profileObservationMarkers = analyses.filter((analysis) =>
    analysis.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX)
  );
  const findingDispositionMarkers = analyses.filter((analysis) =>
    analysis.startsWith(FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX)
  );
  const triageMarkers = analyses.filter((analysis) => analysis.startsWith('triage-report-v'));
  if (value.state === 'legacy-not-recorded') {
    exactDataKeys(value, ['state', 'limitation'], 'Viewer legacy analysis health');
    if (
      value.limitation !== LEGACY_ANALYSIS_HEALTH_LIMITATION ||
      healthMarkers.length !== 0 || operationalMarkers.length !== 0 || profileObservationMarkers.length !== 0 ||
      findingDispositionMarkers.length !== 0
    ) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer legacy analysis health is invalid.');
    }
    return;
  }
  const hasRealTargetEvaluation = Object.hasOwn(value, 'realTargetEvaluation');
  exactDataKeys(value, [
    'state', 'schemaVersion', 'runId', 'snapshotId', 'producer', 'catalogDigest', 'corpusDigest', 'status',
    'profilePatterns', 'rules', 'incidents', 'recall',
    ...(hasRealTargetEvaluation ? ['realTargetEvaluation'] : []),
    'fixedCaseSilence'
  ], 'Viewer recorded analysis health');
  if (
    value.state !== 'recorded' || value.schemaVersion !== 1 || value.runId !== runId || value.snapshotId !== snapshotId ||
    !isRecord(value.producer) || value.producer.id !== 'atlas/analysis-health' ||
    typeof value.producer.version !== 'string' || !/^1(?:\.[0-9]+){2}(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.producer.version) ||
    typeof value.catalogDigest !== 'string' || !/^[a-f0-9]{64}$/u.test(value.catalogDigest) ||
    typeof value.corpusDigest !== 'string' || !/^[a-f0-9]{64}$/u.test(value.corpusDigest) ||
    !['complete', 'incomplete'].includes(value.status as string) ||
    !Array.isArray(value.profilePatterns) || value.profilePatterns.length === 0 ||
    !Array.isArray(value.rules) || value.rules.length === 0 ||
    !Array.isArray(value.incidents) || value.incidents.length === 0
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer recorded analysis health is invalid.');
  if (
    value.profilePatterns.length > MAX_VIEWER_HEALTH_PROFILE_PATTERNS ||
    value.rules.length > MAX_VIEWER_HEALTH_RULES ||
    value.incidents.length > MAX_VIEWER_HEALTH_INCIDENTS
  ) throw new AtlasError('VIEWER_RESOURCE_LIMIT', 'Viewer analysis health exceeds a bounded collection limit.');
  exactDataKeys(value.producer, ['id', 'version'], 'Viewer analysis-health producer');
  const usesCurrentContract = value.producer.version === ANALYSIS_HEALTH_VERSION;
  if (usesCurrentContract && (
    triageMarkers.length !== 1 ||
    (triageMarkers[0] !== TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER &&
      triageMarkers[0] !== TRIAGE_REPORT_ANALYSIS_MARKER)
  )) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Current viewer analysis health requires a compatible triage-report projection.');
  }
  const usesProfileObservationContract = analysisHealthUsesProfileObservationContract(
    value.producer.version as string
  );
  const expectedOperationalMarker = operationalAnalysisMarkerForHealthVersion(value.producer.version as string);
  const expectedMarker = analysisHealthMarker(
    value.producer.version as string,
    value.catalogDigest as string,
    value.corpusDigest as string
  );
  if (healthMarkers.length !== 1 || healthMarkers[0] !== expectedMarker) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health marker does not match its recorded producer and digests.');
  }
  if (
    findingDispositionMarkers.length > 1 ||
    (findingDispositionMarkers.length === 1 &&
      !/^finding-dispositions-v1\.(?:0|1)\.0\+sha256\.[a-f0-9]{64}$/u.test(findingDispositionMarkers[0]!))
  ) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding-disposition marker is malformed or duplicated.');
  }
  if (expectedOperationalMarker && (
    operationalMarkers.length !== 1 || operationalMarkers[0] !== expectedOperationalMarker
  )) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis health requires its paired operational-risk marker.');
  }
  if (!expectedOperationalMarker && operationalMarkers.length > 0) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer operational-risk analysis uses an unsupported health pairing.');
  }
  if (usesCurrentContract && (
    value.catalogDigest !== bundledEvaluation.catalogDigest || value.corpusDigest !== bundledEvaluation.corpusDigest
  )) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health digests do not match the current bundled controls.');
  }
  if (usesCurrentContract) {
    if (!hasRealTargetEvaluation || !isRecord(value.realTargetEvaluation)) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis health omits the separate real-target evaluation pointer.');
    }
    exactDataKeys(
      value.realTargetEvaluation,
      ['tier', 'result', 'reportContract'],
      'Viewer real-target evaluation pointer'
    );
    if (
      value.realTargetEvaluation.tier !== 'real-target' ||
      value.realTargetEvaluation.result !== 'not-recorded-in-run' ||
      value.realTargetEvaluation.reportContract !== 'real-target-corpus-report.schema.json'
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer real-target evaluation pointer is invalid.');
  } else if (hasRealTargetEvaluation) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'A historical viewer health record contains a current-only real-target pointer.');
  }

  const patternIds: string[] = [];
  for (const pattern of value.profilePatterns) {
    if (!isRecord(pattern)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health pattern is invalid.');
    const hasSamplePaths = Object.hasOwn(pattern, 'samplePaths');
    exactDataKeys(pattern, [
      'id', 'collection', 'pattern', 'expected', 'observed', 'status', ...(hasSamplePaths ? ['samplePaths'] : [])
    ], 'Viewer analysis-health pattern');
    if (!isRecord(pattern.expected)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health pattern expectation is invalid.');
    exactDataKeys(
      pattern.expected,
      ['minimum', ...(Object.hasOwn(pattern.expected, 'maximum') ? ['maximum'] : [])],
      'Viewer analysis-health pattern expectation'
    );
    const maximum = pattern.expected.maximum;
    const samplePaths = pattern.samplePaths;
    if (Array.isArray(samplePaths) && samplePaths.length > MAX_VIEWER_HEALTH_SAMPLE_PATHS) {
      throw new AtlasError('VIEWER_RESOURCE_LIMIT', `Viewer analysis-health sample paths exceed ${MAX_VIEWER_HEALTH_SAMPLE_PATHS} entries.`);
    }
    const passed = isNonnegativeInteger(pattern.observed) && isNonnegativeInteger(pattern.expected.minimum) &&
      (maximum === undefined || (isNonnegativeInteger(maximum) && maximum >= pattern.expected.minimum)) &&
      pattern.observed >= pattern.expected.minimum && (maximum === undefined || pattern.observed <= maximum);
    if (
      typeof pattern.id !== 'string' || !pattern.id || typeof pattern.pattern !== 'string' || !pattern.pattern ||
      ![
        'include-root', 'exclude', 'entrypoint', 'dead-code-exemption', 'fixture-boundary', 'guard-boundary',
        'seed-dictionary-source', 'loader-root'
      ].includes(pattern.collection as string) ||
      !isNonnegativeInteger(pattern.observed) || !isNonnegativeInteger(pattern.expected.minimum) ||
      (maximum !== undefined && (!isNonnegativeInteger(maximum) || maximum < pattern.expected.minimum)) ||
      !['passed', 'failed'].includes(pattern.status as string) || pattern.status !== (passed ? 'passed' : 'failed') ||
      (usesProfileObservationContract && !hasSamplePaths) ||
      (hasSamplePaths && (
        !Array.isArray(samplePaths) || samplePaths.some((samplePath) => !isCanonicalTargetRelativePath(samplePath)) ||
        new Set(samplePaths).size !== samplePaths.length ||
        canonicalJson(samplePaths) !== canonicalJson([...samplePaths].sort(compareCanonicalText)) ||
        samplePaths.length > (pattern.observed as number) ||
        (usesProfileObservationContract && samplePaths.length !== Math.min(pattern.observed as number, 32))
      ))
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health pattern is invalid.');
    patternIds.push(pattern.id);
  }
  if (profileObservationMarkers.length > 1 ||
    (usesProfileObservationContract && profileObservationMarkers.length !== 1)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis health requires its versioned profile-observations marker.');
  }
  if (
    profileObservationMarkers.length === 1 &&
    profileObservationMarkers[0] !== profileObservationsAnalysisMarker(
      value.profilePatterns as AnalysisHealthPatternObservation[]
    )
  ) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer profile-observations marker does not match projected health patterns.');
  }

  const findingInstancesByRule = new Map<string, number>();
  for (const finding of findings) {
    findingInstancesByRule.set(
      finding.ruleId,
      (findingInstancesByRule.get(finding.ruleId) ?? 0) + (finding.instanceCount ?? 1)
    );
  }
  const diagnosticCodes = new Set(diagnostics.map((diagnostic) => diagnostic.code));
  const ruleIds: string[] = [];
  for (const rule of value.rules) {
    if (!isRecord(rule) || !isRecord(rule.controls)) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule is invalid.');
    }
    const hasTarget = Object.hasOwn(rule, 'target');
    exactDataKeys(
      rule,
      ['ruleId', 'state', 'controls', ...(hasTarget ? ['target'] : [])],
      'Viewer analysis-health rule'
    );
    exactDataKeys(
      rule.controls,
      ['total', 'passed', 'failed', 'expectedObservations', 'observedObservations'],
      'Viewer analysis-health rule controls'
    );
    const counts = [
      rule.controls.total,
      rule.controls.passed,
      rule.controls.failed,
      rule.controls.expectedObservations,
      rule.controls.observedObservations
    ];
    if (
      typeof rule.ruleId !== 'string' || !rule.ruleId || !['enabled', 'disabled'].includes(rule.state as string) ||
      counts.some((count) => !isNonnegativeInteger(count)) ||
      (rule.controls.passed as number) + (rule.controls.failed as number) !== rule.controls.total
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule is invalid.');
    if (usesProfileObservationContract && !hasTarget) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule omits version-required target accounting.');
    }
    if (hasTarget) {
      if (!isRecord(rule.target)) {
        throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule target is invalid.');
      }
      const hasExpectations = Object.hasOwn(rule.target, 'expectations');
      const hasSuppressedFindings = Object.hasOwn(rule.target, 'suppressedFindingInstances');
      const hasInputStatus = Object.hasOwn(rule.target, 'inputStatus');
      exactDataKeys(
        rule.target,
        [
          'detectedObservations',
          'uncertainObservations',
          'findingInstances',
          ...(hasInputStatus ? ['inputStatus'] : []),
          ...(hasSuppressedFindings ? ['suppressedFindingInstances'] : []),
          ...(hasExpectations ? ['expectations'] : [])
        ],
        'Viewer analysis-health rule target'
      );
      if (
        !isNonnegativeInteger(rule.target.detectedObservations) ||
        !isNonnegativeInteger(rule.target.uncertainObservations) ||
        !isNonnegativeInteger(rule.target.findingInstances) ||
        (hasInputStatus && !['complete', 'incomplete'].includes(rule.target.inputStatus as string)) ||
        (usesProfileObservationContract && !hasInputStatus) ||
        (hasSuppressedFindings && !isNonnegativeInteger(rule.target.suppressedFindingInstances)) ||
        (hasSuppressedFindings && (rule.target.suppressedFindingInstances as number) > rule.target.findingInstances)
      ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule target counts are invalid.');
      const suppressedFindingInstances = hasSuppressedFindings
        ? rule.target.suppressedFindingInstances as number
        : 0;
      if (suppressedFindingInstances > 0 && findingDispositionMarkers.length !== 1) {
        throw new AtlasError('VIEWER_DATA_INVALID', 'Suppressed viewer findings lack a disposition-ledger marker.');
      }
      if (hasExpectations) {
        if (!isRecord(rule.target.expectations) || Object.keys(rule.target.expectations).length === 0) {
          throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health target expectations are invalid.');
        }
        const expectations = rule.target.expectations;
        const expectationKeys = [
          'minimumDetectedObservations',
          'maximumPossibleObservations',
          'minimumFindingInstances',
          'maximumFindingInstances'
        ].filter((key) => Object.hasOwn(expectations, key));
        exactDataKeys(expectations, expectationKeys, 'Viewer analysis-health target expectations');
        const minimumDetectedObservations = expectations.minimumDetectedObservations;
        const maximumPossibleObservations = expectations.maximumPossibleObservations;
        const minimumFindingInstances = expectations.minimumFindingInstances;
        const maximumFindingInstances = expectations.maximumFindingInstances;
        if (
          (minimumDetectedObservations !== undefined && !isNonnegativeInteger(minimumDetectedObservations)) ||
          (maximumPossibleObservations !== undefined && !isNonnegativeInteger(maximumPossibleObservations)) ||
          (minimumFindingInstances !== undefined && !isNonnegativeInteger(minimumFindingInstances)) ||
          (maximumFindingInstances !== undefined && !isNonnegativeInteger(maximumFindingInstances))
        ) {
          throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health target expectation bounds are invalid.');
        }
        const possibleObservations = rule.target.detectedObservations + rule.target.uncertainObservations;
        if (
          (minimumDetectedObservations !== undefined &&
            minimumDetectedObservations > rule.target.detectedObservations) ||
          (maximumPossibleObservations !== undefined &&
            maximumPossibleObservations < possibleObservations) ||
          (minimumFindingInstances !== undefined &&
            minimumFindingInstances > rule.target.findingInstances) ||
          (maximumFindingInstances !== undefined &&
            maximumFindingInstances < rule.target.findingInstances) ||
          (minimumDetectedObservations !== undefined && maximumPossibleObservations !== undefined &&
            maximumPossibleObservations < minimumDetectedObservations) ||
          (minimumFindingInstances !== undefined && maximumFindingInstances !== undefined &&
            maximumFindingInstances < minimumFindingInstances)
        ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health target expectation differs from its counts.');
      }
      const findingInstances = findingInstancesByRule.get(rule.ruleId as string) ?? 0;
      if (rule.target.findingInstances - suppressedFindingInstances !== findingInstances) {
        throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health target count differs from its findings.');
      }
      if (hasInputStatus && rule.target.inputStatus !== operationalRuleInputStatusFromCodes(
        rule.ruleId as string,
        diagnosticCodes
      )) {
        throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health target input status differs from diagnostics.');
      }
    }
    ruleIds.push(rule.ruleId);
  }

  const rulesById = new Map(
    value.rules.map((rule) => [(rule as Record<string, unknown>).ruleId as string, rule as Record<string, unknown>])
  );
  const incidentIds: string[] = [];
  const incidentAggregates = new Map<string, {
    total: number;
    passed: number;
    expectedObservations: number;
    observedObservations: number;
  }>();
  for (const incident of value.incidents) {
    if (!isRecord(incident) || !isRecord(incident.broken) || !isRecord(incident.fixed)) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health incident is invalid.');
    }
    exactDataKeys(incident, ['id', 'family', 'ruleId', 'mechanismId', 'broken', 'fixed', 'status'], 'Viewer analysis-health incident');
    exactDataKeys(incident.broken, ['expectedMinimum', 'observed', 'outcome'], 'Viewer analysis-health broken control');
    exactDataKeys(incident.fixed, ['expectedMaximum', 'observed', 'outcome'], 'Viewer analysis-health fixed control');
    if (
      typeof incident.id !== 'string' || !incident.id || typeof incident.family !== 'string' || !incident.family ||
      typeof incident.ruleId !== 'string' || !ruleIds.includes(incident.ruleId) ||
      typeof incident.mechanismId !== 'string' || !incident.mechanismId ||
      !Number.isSafeInteger(incident.broken.expectedMinimum) || (incident.broken.expectedMinimum as number) < 1 ||
      !isNonnegativeInteger(incident.broken.observed) ||
      !['detected', 'missed', 'not-evaluated'].includes(incident.broken.outcome as string) ||
      !isNonnegativeInteger(incident.fixed.expectedMaximum) || !isNonnegativeInteger(incident.fixed.observed) ||
      !['silent', 'regressed', 'not-evaluated'].includes(incident.fixed.outcome as string) ||
      !['passed', 'failed', 'unsupported'].includes(incident.status as string)
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health incident is invalid.');
    const rule = rulesById.get(incident.ruleId);
    if (!rule) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health incident references a missing rule.');
    if (incident.fixed.expectedMaximum !== 0) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health fixed control does not require zero findings.');
    }
    if (
      (incident.broken.outcome === 'not-evaluated' && incident.broken.observed !== 0) ||
      (incident.fixed.outcome === 'not-evaluated' && incident.fixed.observed !== 0)
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer unevaluated health control has a nonzero observation count.');
    const brokenOutcome = (incident.broken.observed as number) >= (incident.broken.expectedMinimum as number)
      ? 'detected'
      : 'missed';
    const fixedOutcome = incident.fixed.observed === 0 ? 'silent' : 'regressed';
    const status = incident.broken.outcome === 'not-evaluated' || incident.fixed.outcome === 'not-evaluated'
      ? 'unsupported'
      : brokenOutcome === 'detected' && fixedOutcome === 'silent' ? 'passed' : 'failed';
    if (
      (incident.broken.outcome !== 'not-evaluated' && incident.broken.outcome !== brokenOutcome) ||
      (incident.fixed.outcome !== 'not-evaluated' && incident.fixed.outcome !== fixedOutcome) ||
      incident.status !== status
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health incident outcome differs from its counts.');
    incidentIds.push(incident.id);
    const aggregate = incidentAggregates.get(incident.ruleId) ?? {
      total: 0,
      passed: 0,
      expectedObservations: 0,
      observedObservations: 0
    };
    aggregate.total += 1;
    if (incident.status === 'passed') aggregate.passed += 1;
    aggregate.expectedObservations += incident.broken.expectedMinimum as number;
    aggregate.observedObservations += incident.broken.observed as number;
    incidentAggregates.set(incident.ruleId, aggregate);
  }
  if (
    new Set(patternIds).size !== patternIds.length || new Set(ruleIds).size !== ruleIds.length ||
    new Set(incidentIds).size !== incidentIds.length ||
    canonicalJson(patternIds) !== canonicalJson([...patternIds].sort(compareCanonicalText)) ||
    canonicalJson(ruleIds) !== canonicalJson([...ruleIds].sort(compareCanonicalText)) ||
    canonicalJson(incidentIds) !== canonicalJson([...incidentIds].sort(compareCanonicalText))
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis health contains duplicate identifiers.');
  for (const ruleId of ruleIds) {
    const aggregate = incidentAggregates.get(ruleId);
    if (!aggregate) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule has no incident regression case.');
    }
    const rule = rulesById.get(ruleId)!;
    const controls = rule.controls as Record<string, unknown>;
    if (
      controls.total !== aggregate.total || controls.passed !== aggregate.passed ||
      controls.failed !== aggregate.total - aggregate.passed ||
      controls.expectedObservations !== aggregate.expectedObservations ||
      controls.observedObservations !== aggregate.observedObservations ||
      rule.state !== (aggregate.passed === aggregate.total ? 'enabled' : 'disabled')
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health rule controls differ from its incidents.');
  }
  if (usesCurrentContract) {
    const recordedControlRules = (value.rules as Array<Record<string, unknown>>).map((rule) => ({
      ruleId: rule.ruleId,
      state: rule.state,
      controls: rule.controls
    }));
    if (
      canonicalJson(recordedControlRules) !== canonicalJson(bundledEvaluation.rules) ||
      canonicalJson(value.incidents) !== canonicalJson(bundledEvaluation.incidents)
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health results do not match the current bundled controls.');
  }
  assertHealthRatio(value.recall, 'Viewer incident recall', usesCurrentContract ? 'synthetic' : undefined);
  assertHealthRatio(value.fixedCaseSilence, 'Viewer fixed-case silence');
  const detected = value.incidents.filter((incident) => (incident as Record<string, unknown>).broken &&
    ((incident as Record<string, unknown>).broken as Record<string, unknown>).outcome === 'detected').length;
  const silent = value.incidents.filter((incident) => (incident as Record<string, unknown>).fixed &&
    ((incident as Record<string, unknown>).fixed as Record<string, unknown>).outcome === 'silent').length;
  if (
    value.recall.numerator !== detected || value.recall.denominator !== value.incidents.length ||
    value.fixedCaseSilence.numerator !== silent || value.fixedCaseSilence.denominator !== value.incidents.length
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health ratios do not match incident records.');
  const complete = value.profilePatterns.every((pattern) => isRecord(pattern) && pattern.status === 'passed') &&
    value.rules.every((rule) => isRecord(rule) && rule.state === 'enabled' &&
      (!isRecord(rule.target) || rule.target.inputStatus !== 'incomplete')) &&
    value.incidents.every((incident) => isRecord(incident) && incident.status === 'passed');
  if (value.status !== (complete ? 'complete' : 'incomplete')) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer analysis-health status does not match component outcomes.');
  }
}

function assertDataContractSubject(value: unknown, label: string): void {
  if (!isRecord(value)) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
  if (
    value.kind !== 'data-contract' || typeof value.table !== 'string' || !value.table ||
    typeof value.column !== 'string' || !value.column ||
    !['column-presence', 'column-mapping', 'type-family', 'nullability', 'default', 'enum-members']
      .includes(value.dimension as string)
  ) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
  if (Object.hasOwn(value, 'model') || Object.hasOwn(value, 'storage')) {
    exactDataKeys(value, ['kind', 'table', 'column', 'dimension', 'model', 'storage'], label);
    if (
      !['prisma', 'sequelize'].includes(value.model as string) ||
      !['sql', 'sequelize-migration'].includes(value.storage as string)
    ) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
    return;
  }
  exactDataKeys(
    value,
    ['kind', 'table', 'column', 'dimension', 'comparison', 'migration', 'bootstrap'],
    label
  );
  if (
    value.dimension !== 'enum-members' || value.comparison !== 'provisioning-path' ||
    value.migration !== 'sequelize-migration' || value.bootstrap !== 'sql-bootstrap'
  ) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
}

function assertFindingExtensions(value: unknown): void {
  if (!isRecord(value)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding is invalid.');
  if (
    typeof value.id !== 'string' || !value.id ||
    !['dead-code-candidate', 'contract-mismatch', 'architecture-mismatch', 'operational-defect', 'review-inventory', 'latent-hazard']
      .includes(value.category as string) ||
    typeof value.ruleId !== 'string' || !value.ruleId || value.status !== 'candidate' ||
    !['info', 'low', 'medium', 'high'].includes(value.severity as string) ||
    !['confirmed', 'high', 'medium', 'low', 'unknown'].includes(value.confidence as string) ||
    typeof value.title !== 'string' || !value.title || typeof value.description !== 'string' || !value.description ||
    (value.path !== undefined && (typeof value.path !== 'string' || !value.path)) ||
    typeof value.nextValidation !== 'string' || !value.nextValidation
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding is invalid.');
  if (value.location !== undefined) assertSourceLocation(value.location, 'Viewer finding location');
  assertUniqueStrings(value.relatedPaths, 'Viewer finding related paths');
  assertUniqueStrings(value.signals, 'Viewer finding signals', false);
  if (!Array.isArray(value.evidence) || value.evidence.length === 0 || value.evidence.some((entry) => !isRecord(entry))) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding evidence is invalid.');
  }
  if (value.kind !== undefined && !['defect-candidate', 'review-inventory', 'latent-hazard'].includes(value.kind as string)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding kind is invalid.');
  }
  if (value.subject !== undefined) assertDataContractSubject(value.subject, 'Viewer finding subject');
  if (
    value.subject !== undefined &&
    (value.category !== 'contract-mismatch' || !(value.ruleId as string).startsWith('contract/data-'))
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding subject is attached to a non-data-contract finding.');
  if (value.mechanism !== undefined && (typeof value.mechanism !== 'string' || !value.mechanism)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding mechanism is invalid.');
  }
  if (value.reviewId !== undefined && (
    typeof value.reviewId !== 'string' ||
    !/^finding_review_sha256_[a-f0-9]{64}(?::occurrence:[1-9][0-9]*)?$/u.test(value.reviewId)
  )) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding review ID is invalid.');
  if (value.refutationCondition !== undefined && (
    typeof value.refutationCondition !== 'string' || !value.refutationCondition.trim()
  )) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding refutation condition is invalid.');
  if (value.reviewAnchors !== undefined) {
    if (!Array.isArray(value.reviewAnchors) || value.reviewAnchors.some((anchor) =>
      !isRecord(anchor) || !isCanonicalTargetRelativePath(anchor.path) ||
      typeof anchor.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(anchor.sha256)
    )) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding review anchors are invalid.');
    const serialized = value.reviewAnchors.map((anchor) => canonicalJson(anchor));
    if (new Set(serialized).size !== serialized.length ||
      canonicalJson(value.reviewAnchors) !== canonicalJson([...value.reviewAnchors].sort((left, right) =>
        compareCanonicalText((left as { path: string }).path, (right as { path: string }).path)
      ))) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding review anchors are not canonical.');
  }
  if (value.reviewPriority !== undefined) {
    const priority = value.reviewPriority;
    if (!isRecord(priority)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding review priority is invalid.');
    exactDataKeys(
      priority,
      ['version', 'band', 'severityRank', 'impactRank', 'confidenceRank', 'instanceCount'],
      'Viewer finding review priority'
    );
    if (
      priority.version !== 'static-actionability-v1' ||
      ![
        'production-ungated', 'production-gate-unknown', 'production-gated', 'cli',
        'build-migration-seeder', 'reachability-incomplete', 'test', 'inactive'
      ].includes(priority.band as string) ||
      !Number.isSafeInteger(priority.severityRank) || (priority.severityRank as number) < 0 || (priority.severityRank as number) > 3 ||
      !Number.isSafeInteger(priority.impactRank) || (priority.impactRank as number) < 0 || (priority.impactRank as number) > 7 ||
      !Number.isSafeInteger(priority.confidenceRank) || (priority.confidenceRank as number) < 0 || (priority.confidenceRank as number) > 4 ||
      !Number.isSafeInteger(priority.instanceCount) || (priority.instanceCount as number) < 1
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding review priority is invalid.');
  }
  if (value.mappingContexts !== undefined) {
    if (!Array.isArray(value.mappingContexts) || value.mappingContexts.length === 0 || value.mechanism === undefined) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding mapping contexts are invalid.');
    }
    const serializedContexts: string[] = [];
    for (const [index, context] of value.mappingContexts.entries()) {
      if (!isRecord(context)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding mapping context is invalid.');
      const optionalKeys = ['buildContext', 'dockerfile', 'workingDirectory']
        .filter((key) => Object.hasOwn(context, key));
      exactDataKeys(context, [
        'id', 'composePath', 'service', 'sourceKind', 'hostRoot', 'containerRoot', ...optionalKeys
      ], `Viewer finding mapping context ${index + 1}`);
      if (
        typeof context.id !== 'string' || !/^mapping-context:[a-f0-9]{24}$/u.test(context.id) ||
        !isCanonicalTargetRelativePath(context.composePath) ||
        typeof context.service !== 'string' || !context.service ||
        !['bind-mount', 'docker-copy'].includes(context.sourceKind as string) ||
        typeof context.hostRoot !== 'string' ||
        typeof context.containerRoot !== 'string' || !context.containerRoot ||
        (context.buildContext !== undefined && typeof context.buildContext !== 'string') ||
        (context.dockerfile !== undefined && !isCanonicalTargetRelativePath(context.dockerfile)) ||
        (context.workingDirectory !== undefined &&
          (typeof context.workingDirectory !== 'string' || !context.workingDirectory))
      ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding mapping context is invalid.');
      serializedContexts.push(canonicalJson(context));
    }
    if (new Set(serializedContexts).size !== serializedContexts.length) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding mapping contexts contain duplicates.');
    }
  }
  if (value.severityCalibration !== undefined) {
    const calibration = value.severityCalibration;
    if (!isRecord(calibration)) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding severity calibration is invalid.');
    }
    exactDataKeys(
      calibration,
      ['version', 'detectorSeverity', 'ceiling', 'basis', 'runtimeReachability', 'rationale'],
      'Viewer finding severity calibration'
    );
    const severityOrder = ['info', 'low', 'medium', 'high'];
    const detectorRank = severityOrder.indexOf(calibration.detectorSeverity as string);
    const reportedRank = severityOrder.indexOf(value.severity as string);
    const ceilingRank = severityOrder.indexOf(calibration.ceiling as string);
    if (
      calibration.version !== 'static-reachability-v1' || detectorRank < 0 ||
      !['low', 'medium', 'high'].includes(calibration.ceiling as string) ||
      ![
        'static-production-path-no-observed-feature-gate',
        'static-production-path-feature-gated',
        'static-non-production-path',
        'static-test-only-path',
        'static-mothballed-path',
        'static-unreachable-path',
        'static-reachability-incomplete'
      ].includes(calibration.basis as string) ||
      calibration.runtimeReachability !== 'not-evaluated' ||
      typeof calibration.rationale !== 'string' || !calibration.rationale ||
      reportedRank !== Math.min(detectorRank, ceilingRank)
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding severity calibration is invalid.');
  }
  if (value.instanceCount !== undefined && (!Number.isSafeInteger(value.instanceCount) || (value.instanceCount as number) < 1)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding instance count is invalid.');
  }
  if (value.instances !== undefined) {
    if (!Array.isArray(value.instances) || value.instances.length === 0 ||
      value.instanceCount === undefined || value.instanceCount !== value.instances.length) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding instances are invalid.');
    }
    const instanceIds = value.instances.map((instance) => isRecord(instance) ? instance.id : undefined);
    if (new Set(instanceIds).size !== instanceIds.length) {
      throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding instances contain duplicate IDs.');
    }
    for (const instance of value.instances) {
      if (
        !isRecord(instance) || typeof instance.id !== 'string' || !instance.id ||
        !['info', 'low', 'medium', 'high'].includes(instance.severity as string) ||
        !['confirmed', 'high', 'medium', 'low', 'unknown'].includes(instance.confidence as string)
      ) {
        throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding instance is invalid.');
      }
      if (instance.location !== undefined) assertSourceLocation(instance.location, 'Viewer finding instance location');
      assertUniqueStrings(instance.relatedPaths, 'Viewer finding instance related paths');
      assertUniqueStrings(instance.signals, 'Viewer finding instance signals', false);
      if (!Array.isArray(instance.evidence) || instance.evidence.length === 0 || instance.evidence.some((entry) => !isRecord(entry))) {
        throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding instance evidence is invalid.');
      }
      if (instance.subject !== undefined) {
        assertDataContractSubject(instance.subject, 'Viewer finding instance subject');
        if (value.category !== 'contract-mismatch' || !(value.ruleId as string).startsWith('contract/data-')) {
          throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer finding instance subject is attached to a non-data-contract finding.');
        }
      }
      if (instance.impactContext !== undefined) assertImpactContext(instance.impactContext, 'Viewer finding instance impact context');
    }
  } else if (value.instanceCount !== undefined && value.instanceCount !== 1) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer singleton finding has a non-singleton instance count.');
  }
  if (value.impactContext !== undefined) {
    assertImpactContext(value.impactContext, 'Viewer finding impact context');
  }
}

function assertImpactContext(value: unknown, label: string): void {
    const impact = value;
    if (!isRecord(impact)) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
    exactDataKeys(impact, [
      'reachability', ...(Object.hasOwn(impact, 'scope') ? ['scope'] : []), 'entrypoints',
      ...(Object.hasOwn(impact, 'entrypointRemainder') ? ['entrypointRemainder'] : []), 'mountedSurfaces',
      ...(Object.hasOwn(impact, 'lifecycle') ? ['lifecycle'] : []), 'featureGate', 'summary', 'limitations'
    ], label);
    assertUniqueStrings(impact.entrypoints, `${label} entrypoints`);
    assertUniqueStrings(impact.mountedSurfaces, `${label} mounted surfaces`);
    assertUniqueStrings(impact.limitations, `${label} limitations`, false);
    if (
      !['reachable', 'unreachable', 'coverage-incomplete', 'mixed', 'unknown'].includes(impact.reachability as string) ||
      (impact.scope !== undefined && !['production', 'test', 'build', 'cli', 'migration', 'seeder'].includes(impact.scope as string)) ||
      (impact.lifecycle !== undefined && !['active', 'mothballed', 'shared', 'unknown', 'unspecified'].includes(impact.lifecycle as string)) ||
      (impact.entrypointRemainder !== undefined && (!Number.isSafeInteger(impact.entrypointRemainder) || (impact.entrypointRemainder as number) < 1)) ||
      !['observed', 'not-observed', 'unknown'].includes(impact.featureGate as string) ||
      typeof impact.summary !== 'string' || !impact.summary
    ) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
}

function assertSourceLocation(value: unknown, label: string): void {
  if (!isRecord(value)) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
  exactDataKeys(value, ['line', 'column', 'endLine', 'endColumn'], label);
  if (['line', 'column', 'endLine', 'endColumn'].some((key) =>
    !Number.isSafeInteger(value[key]) || (value[key] as number) < 1
  )) throw new AtlasError('VIEWER_DATA_INVALID', `${label} is invalid.`);
}

function assertFileLifecycle(value: unknown, fileId: string): void {
  if (!isRecord(value)) {
    throw new AtlasError('VIEWER_DATA_INVALID', `Viewer file lifecycle is missing or invalid: ${fileId}`);
  }
  if (value.basis === 'profile-path-rule') {
    exactDataKeys(value, ['state', 'basis', 'ruleId', 'uncertainty', 'limitation'], 'Viewer profile lifecycle');
    if (
      !['active', 'mothballed', 'shared', 'unknown'].includes(value.state as string) ||
      typeof value.ruleId !== 'string' || !value.ruleId.trim() ||
      value.uncertainty !== 'not-runtime-validated' ||
      value.limitation !== PROFILE_LIFECYCLE_LIMITATION
    ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer profile lifecycle is invalid: ${fileId}`);
    return;
  }
  exactDataKeys(value, ['state', 'basis', 'uncertainty', 'limitation'], 'Viewer unspecified lifecycle');
  const isCurrentUnspecified = value.basis === 'no-profile-match' && value.limitation === UNSPECIFIED_LIFECYCLE_LIMITATION;
  const isLegacyProjection = value.basis === 'legacy-not-recorded' && value.limitation === LEGACY_LIFECYCLE_LIMITATION;
  if (
    value.state !== 'unspecified' || value.uncertainty !== 'not-runtime-validated' ||
    (!isCurrentUnspecified && !isLegacyProjection)
  ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer unspecified lifecycle is invalid: ${fileId}`);
}

function assertRelationshipLocation(value: unknown, relationshipId: string): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new AtlasError('VIEWER_DATA_INVALID', `Viewer relationship location is missing or invalid: ${relationshipId}`);
  }
  exactDataKeys(value, ['line', 'column', 'endLine', 'endColumn'], 'Viewer relationship location');
  const coordinates = [value.line, value.column, value.endLine, value.endColumn];
  if (
    coordinates.some((coordinate) => !Number.isSafeInteger(coordinate) || (coordinate as number) < 1) ||
    (value.endLine as number) < (value.line as number) ||
    (value.endLine === value.line && (value.endColumn as number) < (value.column as number))
  ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer relationship location is invalid: ${relationshipId}`);
}

function assertRelationshipEvidence(
  value: unknown,
  relationshipId: string,
  fromPath: string,
  location: Record<string, unknown>
): void {
  if (!isRecord(value)) {
    throw new AtlasError('VIEWER_DATA_INVALID', `Viewer relationship evidence is missing or invalid: ${relationshipId}`);
  }
  const optionalKeys = ['path', 'line', 'column', 'recordIds'].filter((key) => Object.hasOwn(value, key));
  exactDataKeys(
    value,
    ['level', 'producer', 'producerVersion', 'basis', ...optionalKeys],
    'Viewer relationship evidence'
  );
  if (
    !Number.isSafeInteger(value.level) || (value.level as number) < 0 || (value.level as number) > 4 ||
    typeof value.producer !== 'string' || !value.producer ||
    typeof value.producerVersion !== 'string' || !value.producerVersion ||
    typeof value.basis !== 'string' || !value.basis ||
    (value.path !== undefined && (typeof value.path !== 'string' || !value.path || value.path !== fromPath)) ||
    (value.line !== undefined && (!Number.isSafeInteger(value.line) || (value.line as number) < 1 || value.line !== location.line)) ||
    (value.column !== undefined && (!Number.isSafeInteger(value.column) || (value.column as number) < 1 || value.column !== location.column)) ||
    (value.recordIds !== undefined && (
      !Array.isArray(value.recordIds) || value.recordIds.some((id) => typeof id !== 'string' || !id) ||
      new Set(value.recordIds).size !== value.recordIds.length
    ))
  ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer relationship evidence is invalid: ${relationshipId}`);
}

function parseManifest(content: string): ViewerManifest {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer manifest is not valid JSON.');
  }
  if (!isRecord(value)) throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer manifest must be an object.');
  exactKeys(value, [
    'schemaVersion', 'viewerVersion', 'viewerId', 'runId', 'snapshotId',
    'sourceArtifactManifestSha256', 'artifacts'
  ], 'Viewer manifest');
  if (
    value.schemaVersion !== 1 || value.viewerVersion !== VIEWER_VERSION ||
    typeof value.viewerId !== 'string' || !/^viewer_sha256_[a-f0-9]{64}$/.test(value.viewerId) ||
    typeof value.runId !== 'string' || typeof value.snapshotId !== 'string' ||
    typeof value.sourceArtifactManifestSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.sourceArtifactManifestSha256) || !Array.isArray(value.artifacts)
  ) throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer manifest identity or version fields are invalid.');
  const seen = new Set<string>();
  for (const candidate of value.artifacts) {
    if (!isRecord(candidate)) throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer artifact digest must be an object.');
    exactKeys(candidate, ['path', 'bytes', 'sha256'], 'Viewer artifact digest');
    if (
      typeof candidate.path !== 'string' || !VIEWER_CONTENT_ARTIFACTS.includes(candidate.path as never) ||
      !Number.isSafeInteger(candidate.bytes) || (candidate.bytes as number) < 0 ||
      typeof candidate.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(candidate.sha256)
    ) throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer artifact digest fields are invalid.');
    if (seen.has(candidate.path)) throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer manifest contains duplicate artifact paths.');
    seen.add(candidate.path);
  }
  const artifactPaths = value.artifacts.map((artifact) => (artifact as Record<string, unknown>).path as string);
  if (
    canonicalJson(artifactPaths) !== canonicalJson([...artifactPaths].sort(compareCanonicalText)) ||
    canonicalJson(artifactPaths) !== canonicalJson(VIEWER_CONTENT_ARTIFACTS)
  ) throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer manifest does not declare the exact canonical artifact set.');
  const manifest = value as unknown as ViewerManifest;
  if (content !== prettyCanonicalJson(manifest)) {
    throw new AtlasError('VIEWER_MANIFEST_INVALID', 'Viewer manifest is not canonically serialized.');
  }
  return manifest;
}

function assertDispositionProjection(value: unknown, diagnosticCode: unknown): void {
  if (!isRecord(value)) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer disposition projection is invalid.');
  const optionalKeys = ['title', 'ruleId'].filter((key) => Object.hasOwn(value, key));
  exactDataKeys(value, [
    'reviewId', 'findingId', ...optionalKeys, 'disposition', 'reviewer', 'date', 'evidence', 'anchors', 'state'
  ], 'Viewer disposition projection');
  const expectedState = diagnosticCode === 'FINDING_DISPOSITION_APPLIED'
    ? 'applied'
    : diagnosticCode === 'FINDING_DISPOSITION_STALE'
      ? 'stale'
      : diagnosticCode === 'FINDING_DISPOSITION_ANCHOR_MISMATCH'
        ? 'anchor-mismatch'
        : undefined;
  if (
    expectedState === undefined || value.state !== expectedState ||
    typeof value.reviewId !== 'string' ||
    !/^finding_review_sha256_[a-f0-9]{64}(?::occurrence:[1-9][0-9]*)?$/u.test(value.reviewId) ||
    typeof value.findingId !== 'string' || !/^finding:[a-f0-9]{24}$/u.test(value.findingId) ||
    (value.title !== undefined && (typeof value.title !== 'string' || !value.title)) ||
    (value.ruleId !== undefined && (typeof value.ruleId !== 'string' || !value.ruleId)) ||
    ![
      'confirmed defect', 'intentional contract', 'false positive/profile gap', 'test fixture',
      'framework-managed/external entrypoint', 'obsolete but cleanup separately',
      'needs runtime/schema evidence', 'defer'
    ].includes(value.disposition as string) ||
    typeof value.reviewer !== 'string' || !value.reviewer ||
    typeof value.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/u.test(value.date)
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer disposition projection is invalid.');
  assertUniqueStrings(value.evidence, 'Viewer disposition evidence', false);
  if (!Array.isArray(value.anchors) || value.anchors.length === 0 || value.anchors.some((anchor) =>
    !isRecord(anchor) || !isCanonicalTargetRelativePath(anchor.path) ||
    typeof anchor.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(anchor.sha256)
  )) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer disposition anchors are invalid.');
}

function assertViewerData(data: ViewerData, bundledEvaluation: OperationalControlEvaluation): void {
  if (
    !isRecord(data) || data.schemaVersion !== 1 || data.viewerVersion !== VIEWER_VERSION ||
    typeof data.sourceArtifactManifestSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(data.sourceArtifactManifestSha256) ||
    !isRecord(data.run) || typeof data.run.runId !== 'string' || typeof data.run.snapshotId !== 'string' ||
    !isRecord(data.summary) || !isRecord(data.census) || !Array.isArray(data.census.files) ||
    !isRecord(data.dependencyGraph) || !Array.isArray(data.dependencyGraph.nodes) || !Array.isArray(data.dependencyGraph.edges) ||
    !isRecord(data.analysisHealth) ||
    !Array.isArray(data.findings) || !Array.isArray(data.diagnostics)
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer data does not have the required projection shape.');
  if (!Array.isArray(data.run.analyses)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer run analyses are invalid.');
  }
  if (data.run.analyses.length > MAX_VIEWER_ANALYSES) {
    throw new AtlasError('VIEWER_RESOURCE_LIMIT', `Viewer run analyses exceed ${MAX_VIEWER_ANALYSES} entries.`);
  }
  assertUniqueStrings(data.run.analyses, 'Viewer run analyses');
  if (
    data.census.files.length > HARD_MAX_INCLUDED_FILES ||
    data.dependencyGraph.nodes.length > MAX_VIEWER_COLLECTION_RECORDS ||
    data.dependencyGraph.edges.length > MAX_VIEWER_COLLECTION_RECORDS ||
    data.findings.length > MAX_VIEWER_COLLECTION_RECORDS ||
    data.diagnostics.length > MAX_VIEWER_COLLECTION_RECORDS
  ) throw new AtlasError('VIEWER_RESOURCE_LIMIT', 'Viewer data exceeds a bounded collection limit.');
  if (canonicalJson(data.run.analyses) !== canonicalJson([...data.run.analyses].sort(compareCanonicalText))) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer run analyses are not in canonical order.');
  }
  for (const finding of data.findings) assertFindingExtensions(finding);
  for (const diagnostic of data.diagnostics) {
    if (diagnostic.disposition !== undefined) assertDispositionProjection(diagnostic.disposition, diagnostic.code);
  }
  if (data.run.analyses.includes(`finding-postprocess-v${FINDING_POSTPROCESS_VERSION}`)) {
    const omittedReviews = data.diagnostics.flatMap((diagnostic) =>
      diagnostic.code === 'FINDING_DISPOSITION_APPLIED' && diagnostic.disposition?.state === 'applied'
        ? [{ findingId: diagnostic.disposition.findingId, reviewId: diagnostic.disposition.reviewId }]
        : []
    );
    const mismatches = findingReviewMetadataMismatchesForCollection(
      data.findings,
      data.census.files,
      omittedReviews
    );
    if (mismatches.length > 0) {
      throw new AtlasError(
        'VIEWER_DATA_INVALID',
        `Viewer finding review metadata differs for ${mismatches[0]!.findingId}.`
      );
    }
  }
  assertViewerAnalysisHealth(
    data.analysisHealth,
    data.run.runId,
    data.run.snapshotId,
    data.run.analyses,
    bundledEvaluation,
    data.findings,
    data.diagnostics
  );
  const summaryCounts = [
    data.summary.files,
    data.summary.relationships,
    data.summary.resolvedRelationships,
    data.summary.diagnostics,
    data.summary.findings,
    data.summary.totalBytes
  ];
  if (summaryCounts.some((count) => !Number.isSafeInteger(count) || count < 0)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer summary contains an invalid count.');
  }
  if (
    data.summary.files !== data.census.files.length ||
    data.summary.relationships !== data.dependencyGraph.edges.length ||
    data.summary.resolvedRelationships !== data.dependencyGraph.edges.filter((edge) => edge.resolution === 'resolved').length ||
    data.summary.findings !== data.findings.length ||
    data.summary.diagnostics !== data.diagnostics.length ||
    data.summary.totalBytes !== data.census.files.reduce((total, file) => total + file.bytes, 0)
  ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer summary counts do not match its projected records.');
  const fileIds = data.census.files.map((file) => file.id);
  if (new Set(fileIds).size !== fileIds.length) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer census contains duplicate file IDs.');
  for (const file of data.census.files) {
    if (
      !isRecord(file) || typeof file.id !== 'string' || !file.id || typeof file.path !== 'string' ||
      !Array.isArray(file.incoming) || !Array.isArray(file.outgoing)
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer census contains an invalid file projection.');
    assertFileLifecycle(file.lifecycle, file.id);
  }
  let relationshipProjections = 0;
  for (const file of data.census.files) {
    relationshipProjections += file.incoming.length + file.outgoing.length;
    if (relationshipProjections > MAX_VIEWER_RELATIONSHIP_PROJECTIONS) {
      throw new AtlasError('VIEWER_RESOURCE_LIMIT', 'Viewer file relationships exceed the bounded projection limit.');
    }
  }
  const nodeIds = data.dependencyGraph.nodes.map((node) => node.id);
  if (new Set(nodeIds).size !== nodeIds.length) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer graph contains duplicate node IDs.');
  const nodeIdSet = new Set(nodeIds);
  if (data.dependencyGraph.edges.some((edge) => !nodeIdSet.has(edge.source) || !nodeIdSet.has(edge.target))) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer graph contains an edge with a missing node.');
  }
  const fileById = new Map(data.census.files.map((file) => [file.id, file]));
  const graphNodeById = new Map(data.dependencyGraph.nodes.map((node) => [node.id, node]));
  for (const file of data.census.files) {
    const node = graphNodeById.get(file.id);
    if (!node || node.kind !== 'file' || node.fileId !== file.id) {
      throw new AtlasError('VIEWER_DATA_INVALID', `Viewer census file does not have its required graph node: ${file.id}`);
    }
  }
  const edgeIds = data.dependencyGraph.edges.map((edge) => edge.id);
  if (new Set(edgeIds).size !== edgeIds.length) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer graph contains duplicate edge IDs.');
  const edgeById = new Map(data.dependencyGraph.edges.map((edge) => [edge.id, edge]));
  const incomingEdgeIds = new Map<string, string[]>();
  const outgoingEdgeIds = new Map<string, string[]>();
  for (const edge of data.dependencyGraph.edges) {
    if (
      !isRecord(edge) || typeof edge.id !== 'string' || !edge.id ||
      typeof edge.source !== 'string' || typeof edge.target !== 'string' ||
      !fileById.has(edge.source)
    ) throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer graph contains an invalid dependency edge.');
    const outgoing = outgoingEdgeIds.get(edge.source) ?? [];
    outgoing.push(edge.id);
    outgoingEdgeIds.set(edge.source, outgoing);
    if (fileById.has(edge.target)) {
      const incoming = incomingEdgeIds.get(edge.target) ?? [];
      incoming.push(edge.id);
      incomingEdgeIds.set(edge.target, incoming);
    }
  }
  const assertRelationshipProjection = (
    value: unknown,
    expectedFileId: string,
    direction: 'incoming' | 'outgoing'
  ): void => {
    if (!isRecord(value) || typeof value.id !== 'string') {
      throw new AtlasError('VIEWER_DATA_INVALID', `Viewer file contains an invalid ${direction} relationship.`);
    }
    const expectedKeys = [
      'id', 'from', 'fromPath',
      ...(Object.hasOwn(value, 'to') ? ['to'] : []),
      ...(Object.hasOwn(value, 'toPath') ? ['toPath'] : []),
      'type',
      ...(Object.hasOwn(value, 'typeOnly') ? ['typeOnly'] : []),
      'specifier', 'resolution', 'location', 'evidence'
    ];
    exactDataKeys(value, expectedKeys, `Viewer ${direction} relationship`);
    if (
      typeof value.from !== 'string' || typeof value.fromPath !== 'string' || !value.fromPath ||
      (value.to !== undefined && typeof value.to !== 'string') ||
      (value.toPath !== undefined && typeof value.toPath !== 'string') ||
      !['static-import', 'dynamic-import', 'require', 'export-from'].includes(value.type as string) ||
      (value.typeOnly !== undefined && typeof value.typeOnly !== 'boolean') ||
      typeof value.specifier !== 'string' ||
      !['resolved', 'unresolved-internal', 'external-package', 'unsupported'].includes(value.resolution as string)
    ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer ${direction} relationship fields are invalid: ${value.id}`);
    assertRelationshipLocation(value.location, value.id);
    assertRelationshipEvidence(value.evidence, value.id, value.fromPath, value.location);
    const edge = edgeById.get(value.id);
    if (!edge) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer file relationship has no graph edge: ${value.id}`);
    const targetFile = fileById.get(edge.target);
    if (
      value.from !== edge.source || value.fromPath !== fileById.get(edge.source)?.path ||
      (targetFile ? value.to !== edge.target || value.toPath !== targetFile.path : value.to !== undefined || value.toPath !== undefined) ||
      value.type !== edge.type || value.typeOnly !== edge.typeOnly ||
      value.specifier !== edge.specifier || value.resolution !== edge.resolution ||
      (direction === 'outgoing' ? edge.source !== expectedFileId : edge.target !== expectedFileId)
    ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer ${direction} relationship does not match its graph edge: ${value.id}`);
  };
  for (const file of data.census.files) {
    const expectedIncomingIds = incomingEdgeIds.get(file.id) ?? [];
    const expectedOutgoingIds = outgoingEdgeIds.get(file.id) ?? [];
    const incomingIds = file.incoming.map((relationship) => relationship.id);
    const outgoingIds = file.outgoing.map((relationship) => relationship.id);
    if (
      canonicalJson(incomingIds) !== canonicalJson(expectedIncomingIds) ||
      canonicalJson(outgoingIds) !== canonicalJson(expectedOutgoingIds)
    ) throw new AtlasError('VIEWER_DATA_INVALID', `Viewer file relationship arrays do not match graph edges: ${file.id}`);
    for (const relationship of file.incoming) assertRelationshipProjection(relationship, file.id, 'incoming');
    for (const relationship of file.outgoing) assertRelationshipProjection(relationship, file.id, 'outgoing');
  }
}

function exactArtifactNames(observed: string[]): void {
  const sorted = [...observed].sort(compareCanonicalText);
  if (canonicalJson(sorted) !== canonicalJson(ALL_VIEWER_ARTIFACTS)) {
    throw new AtlasError('VIEWER_ARTIFACT_SET', 'Viewer directory does not match the required artifact set.');
  }
}

/** @internal Returns values backed by the exact viewer bytes verified in this call. */
export async function verifyAndLoadRunViewer(directoryValue: string): Promise<VerifiedViewerArtifacts> {
  const requestedDirectory = path.resolve(directoryValue);
  let metadata;
  try {
    metadata = await lstat(requestedDirectory);
  } catch {
    throw new AtlasError('VIEWER_ARTIFACT_SET', 'Viewer directory is missing or unreadable.');
  }
  const entries = await readBoundedDirectoryEntries(requestedDirectory, {
    maxEntries: MAX_VERIFIER_DIRECTORY_ENTRIES,
    resourceCode: 'VIEWER_RESOURCE_LIMIT',
    label: 'Viewer directory'
  });
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || entries.some((entry) => !entry.isFile() || entry.isSymbolicLink())) {
    throw new AtlasError('VIEWER_ARTIFACT_SET', 'Viewer directory must contain only regular artifact files.');
  }
  exactArtifactNames(entries.map((entry) => entry.name));
  const directory = await realpath(requestedDirectory);
  const manifestBytes = await readBoundedRegularFile(path.join(directory, VIEWER_MANIFEST_NAME), {
    maxBytes: MAX_VERIFIER_MANIFEST_BYTES,
    resourceCode: 'VIEWER_RESOURCE_LIMIT',
    invalidCode: 'VIEWER_ARTIFACT_SET',
    label: 'Viewer manifest'
  });
  const manifest = parseManifest(manifestBytes.toString('utf8'));
  for (const artifact of manifest.artifacts) {
    if (artifact.bytes > MAX_VERIFIER_ARTIFACT_BYTES) {
      throw new AtlasError('VIEWER_RESOURCE_LIMIT', `Viewer artifact exceeds ${MAX_VERIFIER_ARTIFACT_BYTES} declared bytes: ${artifact.path}`);
    }
  }
  assertAggregateByteLimit([manifestBytes.length, ...manifest.artifacts.map((artifact) => artifact.bytes)], {
    maxBytes: MAX_VERIFIER_TOTAL_BYTES,
    resourceCode: 'VIEWER_RESOURCE_LIMIT',
    label: 'Viewer artifacts'
  });
  const contents = new Map<string, Buffer>([[VIEWER_MANIFEST_NAME, manifestBytes]]);
  let observedBytes = manifestBytes.length;
  for (const artifact of manifest.artifacts) {
    const content = await readBoundedRegularFile(path.join(directory, artifact.path), {
      maxBytes: MAX_VERIFIER_ARTIFACT_BYTES,
      resourceCode: 'VIEWER_RESOURCE_LIMIT',
      invalidCode: 'VIEWER_ARTIFACT_SET',
      label: `Viewer artifact ${artifact.path}`
    });
    if (content.length > MAX_VERIFIER_TOTAL_BYTES - observedBytes) {
      throw new AtlasError('VIEWER_RESOURCE_LIMIT', `Viewer artifacts exceed ${MAX_VERIFIER_TOTAL_BYTES} observed bytes.`);
    }
    observedBytes += content.length;
    contents.set(artifact.path, content);
  }
  const contentFor = (name: string): Buffer => {
    const content = contents.get(name);
    if (!content) throw new AtlasError('VIEWER_ARTIFACT_SET', `Viewer artifact is missing: ${name}`);
    return content;
  };
  const indexHtmlBytes = contentFor('index.html');
  for (const artifact of manifest.artifacts) {
    const content = contentFor(artifact.path);
    if (content.length !== artifact.bytes || sha256(content) !== artifact.sha256) {
      throw new AtlasError('VIEWER_DIGEST_MISMATCH', `Viewer artifact digest mismatch: ${artifact.path}`);
    }
  }
  if (
    !indexHtmlBytes.equals(Buffer.from(VIEWER_HTML, 'utf8')) ||
    !contentFor('app.css').equals(Buffer.from(VIEWER_CSS, 'utf8')) ||
    !contentFor('app.js').equals(Buffer.from(VIEWER_APP_JAVASCRIPT, 'utf8'))
  ) throw new AtlasError('VIEWER_RENDERER_MISMATCH', 'Viewer renderer assets do not match this Atlas viewer version.');

  const data = decodeViewerDataScript(contentFor('atlas-data.js').toString('utf8'));
  assertViewerData(data, await bundledOperationalControlEvaluation());
  if (
    data.run.runId !== manifest.runId || data.run.snapshotId !== manifest.snapshotId ||
    data.sourceArtifactManifestSha256 !== manifest.sourceArtifactManifestSha256
  ) {
    throw new AtlasError('VIEWER_IDENTITY_MISMATCH', 'Viewer data and manifest identify different source run artifacts.');
  }
  if (contentFor('dependency-graph.mmd').toString('utf8') !== renderDependencyMermaid(data)) {
    throw new AtlasError('VIEWER_RENDERER_MISMATCH', 'Mermaid projection does not match the bundled viewer data.');
  }
  const expectedViewerId = viewerIdentity({
    runId: manifest.runId,
    snapshotId: manifest.snapshotId,
    sourceArtifactManifestSha256: manifest.sourceArtifactManifestSha256,
    artifacts: manifest.artifacts
  });
  if (manifest.viewerId !== expectedViewerId) {
    throw new AtlasError('VIEWER_IDENTITY_MISMATCH', 'Viewer identity does not match its canonical artifacts.');
  }
  const summary: ViewerVerificationSummary = {
    status: 'passed',
    healthState: data.analysisHealth.state,
    healthStatus: data.analysisHealth.state === 'recorded' ? data.analysisHealth.status : 'not-recorded',
    viewerId: manifest.viewerId,
    runId: manifest.runId,
    snapshotId: manifest.snapshotId,
    sourceArtifactManifestSha256: manifest.sourceArtifactManifestSha256,
    artifacts: manifest.artifacts.length + 1,
    files: data.summary.files,
    relationships: data.summary.relationships,
    diagnostics: data.summary.diagnostics,
    findings: data.summary.findings
  };
  return {
    summary,
    manifest,
    manifestSha256: sha256(manifestBytes),
    indexHtml: indexHtmlBytes.toString('utf8'),
    directory,
    contents
  };
}

export async function verifyRunViewer(directoryValue: string): Promise<ViewerVerificationSummary> {
  return (await verifyAndLoadRunViewer(directoryValue)).summary;
}
