import { analyzeJavaScriptTypeScript } from '../adapters/js-ts.js';
import type { AnalysisFile, DiagnosticRecord, ResolvedProfile } from '../types.js';
import { detectApiContractMismatches } from './api-contracts.js';
import { detectCleanupCandidates } from './cleanup.js';
import { detectDataContractMismatches } from './data-contracts.js';
import { detectDeploymentContractMismatches } from './deployment-contracts.js';
import { detectMismatches } from './mismatches.js';
import { detectOperationalRisks } from './operational-risks.js';
import { analyzeReachability } from './reachability.js';

export const MAX_ISOLATED_ANALYSIS_OUTPUT_BYTES = 128 * 1024 * 1024;

export function analyzeUntrustedSnapshot(
  files: AnalysisFile[],
  profile: ResolvedProfile,
  boundaryDiagnostics: DiagnosticRecord[]
) {
  const adapterResult = analyzeJavaScriptTypeScript(files, profile);
  const astLimitedPaths = new Set(adapterResult.diagnostics
    .filter((entry) => entry.code === 'TYPESCRIPT_AST_RESOURCE_LIMIT')
    .map((entry) => entry.path));
  const boundedFiles = files.filter((file) => !astLimitedPaths.has(file.record.path));
  const reachability = analyzeReachability(boundedFiles, adapterResult.relationships, profile);
  return {
    fileRecords: files.map((file) => file.record),
    adapterResult,
    reachability,
    cleanup: detectCleanupCandidates(
      boundedFiles,
      adapterResult.relationships,
      profile,
      boundaryDiagnostics,
      reachability
    ),
    apiContracts: detectApiContractMismatches(boundedFiles, adapterResult.relationships),
    dataContracts: detectDataContractMismatches(boundedFiles),
    deploymentContracts: detectDeploymentContractMismatches(boundedFiles),
    mismatches: detectMismatches(boundedFiles, adapterResult.relationships, profile),
    operationalResult: detectOperationalRisks(boundedFiles, adapterResult.relationships, profile)
  };
}

export type UntrustedSnapshotAnalysis = ReturnType<typeof analyzeUntrustedSnapshot>;
