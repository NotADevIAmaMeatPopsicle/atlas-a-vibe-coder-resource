import type {
  AnalysisFile,
  DiagnosticRecord,
  FindingRecord,
  RelationshipRecord,
  ResolvedProfile
} from '../types.js';
import { compareCanonicalText } from '../util/canonical.js';
import { DEAD_CODE_ANALYSIS_VERSION, detectDeadCodeCandidates } from './dead-code.js';
import { detectDuplicateFileCandidates, DUPLICATE_FILE_ANALYSIS_VERSION } from './duplicate-files.js';
import { detectPlatformResidualCandidates, PLATFORM_RESIDUAL_ANALYSIS_VERSION } from './platform-residuals.js';
import {
  analyzeReachability,
  isUnsupportedNonLiteralModuleLoad as isUnsupportedNonLiteralModuleLoadRelationship,
  REACHABILITY_ANALYSIS_VERSION,
  type ReachabilityResult
} from './reachability.js';
import { detectUnusedExportCandidates, UNUSED_EXPORT_ANALYSIS_VERSION } from './unused-exports.js';

export const CLEANUP_ANALYSIS_VERSION = '1.7.0';

// Retained as a public compatibility constant for verification of historical
// runs. New cleanup output records scoped loader diagnostics instead of copying
// these relationships onto every no-inbound finding.
export const CLEANUP_DYNAMIC_COUNTER_EVIDENCE_BASIS =
  'active-unsupported-dynamic-module-load-counter-evidence';
export const CLEANUP_NO_ENTRYPOINT_DYNAMIC_COUNTER_EVIDENCE_BASIS =
  'unsupported-dynamic-module-load-without-entrypoint-closure-counter-evidence';
export const MAX_DYNAMIC_COUNTER_EVIDENCE_PER_FINDING = 32;

export const CLEANUP_COMPONENT_VERSIONS = {
  duplicateFiles: DUPLICATE_FILE_ANALYSIS_VERSION,
  platformResiduals: PLATFORM_RESIDUAL_ANALYSIS_VERSION,
  reachability: REACHABILITY_ANALYSIS_VERSION,
  staticReachability: DEAD_CODE_ANALYSIS_VERSION,
  unusedExports: UNUSED_EXPORT_ANALYSIS_VERSION
} as const;

/**
 * Historical/public predicate for the adapter's unsupported non-literal load
 * shape. Loader interpretation now lives in the centralized reachability
 * analysis.
 */
export function isUnsupportedNonLiteralModuleLoad(
  relationship: RelationshipRecord
): boolean {
  return isUnsupportedNonLiteralModuleLoadRelationship(relationship);
}

export function detectCleanupCandidates(
  files: AnalysisFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile,
  boundaryDiagnostics: DiagnosticRecord[] = [],
  precomputedReachability?: ReachabilityResult
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const reachabilityModel = precomputedReachability ?? analyzeReachability(files, relationships, profile);
  const reachability = detectDeadCodeCandidates(files, relationships, profile, reachabilityModel);
  const duplicates = detectDuplicateFileCandidates(files);
  const unusedExports = detectUnusedExportCandidates(files, relationships, profile);
  const platformResiduals = detectPlatformResidualCandidates(files, profile, boundaryDiagnostics);

  const safeReachabilityFindings = reachability.findings.filter((finding) =>
    // The literal platform analyzer below supersedes the original relationship-
    // only rule rather than claiming config files are unused because source code
    // does not import them.
    finding.ruleId !== 'dead-code/unused-platform-file-v1'
  );
  const findings = [...new Map([
    ...safeReachabilityFindings,
    ...duplicates.findings,
    ...unusedExports.findings,
    ...platformResiduals.findings
  ].map((finding) => [finding.id, finding])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  const diagnostics = [...new Map([
    ...reachability.diagnostics,
    ...duplicates.diagnostics,
    ...unusedExports.diagnostics,
    ...platformResiduals.diagnostics
  ].map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings, diagnostics };
}
