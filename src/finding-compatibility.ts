import {
  FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX,
  PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX
} from './artifact-contract.js';
import type { RunRecord } from './types.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';

/**
 * Finding comparison compatibility is deliberately deny-by-default. A future
 * producer change may be added here only after its finding identity semantics
 * have been shown to be equivalent. Semver proximity is never evidence of
 * compatibility.
 */
export const DECLARED_FINDING_COMPATIBILITY: ReadonlyMap<string, string> = new Map();

export interface FindingProducerSignature {
  producer: RunRecord['tool'];
  adapters: RunRecord['adapters'];
  analyzers: string[];
}

export type FindingCompatibilityAssessment =
  | {
      compatible: true;
      basis: 'exact' | 'declared-compatible';
      contractId: string;
      baseline: FindingProducerSignature;
      candidate: FindingProducerSignature;
    }
  | {
      compatible: false;
      baselineContractId: string;
      candidateContractId: string;
      baseline: FindingProducerSignature;
      candidate: FindingProducerSignature;
      differences: Array<'producer' | 'adapters' | 'analyzers'>;
    };

export function findingDispositionMarkers(run: RunRecord): string[] {
  return run.analyses.filter((entry) => entry.startsWith(FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX));
}

export function findingProducerSignature(run: RunRecord): FindingProducerSignature {
  return {
    producer: { ...run.tool },
    adapters: run.adapters.map((adapter) => ({ ...adapter })),
    analyzers: run.analyses.filter((entry) =>
      !entry.startsWith(FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX) &&
      !entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX)
    )
  };
}

export function findingProducerSignatureId(signature: FindingProducerSignature): string {
  return `finding_contract_sha256_${sha256(canonicalJson({
    domain: 'atlas.finding-comparison-contract.v1',
    ...signature
  }))}`;
}

export function assessFindingProducerCompatibility(
  baselineRun: RunRecord,
  candidateRun: RunRecord,
  declarations: ReadonlyMap<string, string> = DECLARED_FINDING_COMPATIBILITY
): FindingCompatibilityAssessment {
  const baseline = findingProducerSignature(baselineRun);
  const candidate = findingProducerSignature(candidateRun);
  const baselineSignatureId = findingProducerSignatureId(baseline);
  const candidateSignatureId = findingProducerSignatureId(candidate);
  if (baselineSignatureId === candidateSignatureId) {
    return {
      compatible: true,
      basis: 'exact',
      contractId: baselineSignatureId,
      baseline,
      candidate
    };
  }

  const baselineDeclaration = declarations.get(baselineSignatureId);
  const candidateDeclaration = declarations.get(candidateSignatureId);
  if (baselineDeclaration !== undefined && baselineDeclaration === candidateDeclaration) {
    return {
      compatible: true,
      basis: 'declared-compatible',
      contractId: baselineDeclaration,
      baseline,
      candidate
    };
  }

  const differences: Array<'producer' | 'adapters' | 'analyzers'> = [];
  if (canonicalJson(baseline.producer) !== canonicalJson(candidate.producer)) differences.push('producer');
  if (canonicalJson(baseline.adapters) !== canonicalJson(candidate.adapters)) differences.push('adapters');
  if (canonicalJson(baseline.analyzers) !== canonicalJson(candidate.analyzers)) differences.push('analyzers');
  differences.sort(compareCanonicalText);
  return {
    compatible: false,
    baselineContractId: baselineDeclaration ?? baselineSignatureId,
    candidateContractId: candidateDeclaration ?? candidateSignatureId,
    baseline,
    candidate,
    differences
  };
}
