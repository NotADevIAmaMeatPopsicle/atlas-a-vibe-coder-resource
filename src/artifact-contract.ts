import type { AnalysisHealthPatternObservation } from './types.js';
import { canonicalJson, sha256 } from './util/canonical.js';

export const LEGACY_HASHED_RUN_ARTIFACTS = [
  'snapshot.json',
  'run.json',
  'discovery.json',
  'files.jsonl',
  'relationships.jsonl',
  'diagnostics.jsonl',
  'findings.jsonl'
] as const;

export const ANALYSIS_HEALTH_ARTIFACT_NAME = 'analysis-health.json' as const;
export const ANALYSIS_HEALTH_MARKER_PREFIX = 'analysis-health-v1' as const;
export const OPERATIONAL_ANALYSIS_MARKER_PREFIX = 'operational-risks-v' as const;
export const PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX = 'profile-observations-v' as const;
export const PROFILE_OBSERVATIONS_ANALYSIS_VERSION = '1' as const;
export const FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX = 'finding-dispositions-v' as const;
export const TRIAGE_REPORT_ARTIFACT_NAME = 'triage.md' as const;
export const TRIAGE_REPORT_LEGACY_VERSION = '1.0.0' as const;
export const TRIAGE_REPORT_PREVIOUS_VERSION = '1.1.0' as const;
export const TRIAGE_REPORT_VERSION = '1.2.0' as const;
export const TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER = `triage-report-v${TRIAGE_REPORT_LEGACY_VERSION}` as const;
export const TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER = `triage-report-v${TRIAGE_REPORT_PREVIOUS_VERSION}` as const;
export const TRIAGE_REPORT_ANALYSIS_MARKER = `triage-report-v${TRIAGE_REPORT_VERSION}` as const;
export const SUPPORTED_TRIAGE_REPORT_ANALYSIS_MARKERS = [
  TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER,
  TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER,
  TRIAGE_REPORT_ANALYSIS_MARKER
] as const;

export const ARTIFACT_MANIFEST_NAME = 'artifact-digests.json' as const;

export const LEGACY_RUN_ARTIFACTS = [
  ...LEGACY_HASHED_RUN_ARTIFACTS,
  ARTIFACT_MANIFEST_NAME
] as const;

export const ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS = [
  ...LEGACY_HASHED_RUN_ARTIFACTS,
  ANALYSIS_HEALTH_ARTIFACT_NAME
] as const;

export const ANALYSIS_HEALTH_RUN_ARTIFACTS = [
  ...ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS,
  ARTIFACT_MANIFEST_NAME
] as const;

export const TRIAGE_HASHED_RUN_ARTIFACTS = [
  ...ANALYSIS_HEALTH_HASHED_RUN_ARTIFACTS,
  TRIAGE_REPORT_ARTIFACT_NAME
] as const;

export const TRIAGE_RUN_ARTIFACTS = [
  ...TRIAGE_HASHED_RUN_ARTIFACTS,
  ARTIFACT_MANIFEST_NAME
] as const;

/** Current producer artifact set. Explicit legacy constants remain available
 * so immutable pre-analysis-health runs continue to verify.
 */
export const HASHED_RUN_ARTIFACTS = TRIAGE_HASHED_RUN_ARTIFACTS;
export const ALL_RUN_ARTIFACTS = TRIAGE_RUN_ARTIFACTS;

export function analysisHealthMarker(
  producerVersion: string,
  catalogDigest: string,
  corpusDigest: string
): string {
  return `analysis-health-v${producerVersion}+catalog.${catalogDigest}+corpus.${corpusDigest}`;
}

export function profileObservationsAnalysisMarker(
  profilePatterns: readonly AnalysisHealthPatternObservation[]
): string {
  const digest = sha256(canonicalJson(profilePatterns));
  return `${PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX}${PROFILE_OBSERVATIONS_ANALYSIS_VERSION}+sha256.${digest}`;
}

export function hasAnalysisHealthMarker(analyses: readonly string[]): boolean {
  return analyses.some((analysis) => analysis.startsWith(ANALYSIS_HEALTH_MARKER_PREFIX));
}
