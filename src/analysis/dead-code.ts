import type { AnalysisFile, DiagnosticRecord, FindingRecord, RelationshipRecord, ResolvedProfile } from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesAnyGlob } from '../util/paths.js';
import { analyzeReachability, type ReachabilityResult } from './reachability.js';

export const DEAD_CODE_ANALYSIS_VERSION = '1.8.1';

function findingId(path: string, signals: string[]): string {
  return `finding:${sha256(canonicalJson({ category: 'dead-code-candidate', path, signals })).slice(0, 24)}`;
}

export function detectDeadCodeCandidates(
  files: AnalysisFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile,
  precomputedReachability?: ReachabilityResult
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const findings: FindingRecord[] = [];
  const reachability = precomputedReachability ?? analyzeReachability(files, relationships, profile);
  const diagnostics: DiagnosticRecord[] = [...reachability.diagnostics];
  const sourceFiles = files.filter((file) =>
    file.record.kind === 'source' && !/\.d\.(?:ts|mts|cts)$/u.test(file.record.path)
  );
  const entrypointPaths = new Set(reachability.entrypoints.map((entrypoint) => entrypoint.path));
  const productionClosureEstablished = reachability.entrypointClosureScopes.has('production');
  if (!reachability.entrypointClosureEstablished) {
    diagnostics.push({
      schemaVersion: SCHEMA_VERSION,
      id: `diagnostic:${sha256(canonicalJson({ code: 'DEAD_CODE_NO_ENTRYPOINTS', profile: profile.id })).slice(0, 24)}`,
      code: 'DEAD_CODE_NO_ENTRYPOINTS',
      severity: 'warning',
      message: 'No configured, package, test, build, or CLI entrypoint matched. Atlas emitted only no-inbound static candidates and did not claim graph unreachability.',
      evidence: {
        level: 1,
        producer: 'atlas/dead-code-candidates',
        producerVersion: DEAD_CODE_ANALYSIS_VERSION,
        basis: 'configured-entrypoint-reachability'
      }
    });
  }
  for (const file of sourceFiles) {
    if (
      entrypointPaths.has(file.record.path) ||
      reachability.gatedPaths.has(file.record.path) ||
      matchesAnyGlob(file.record.path, profile.deadCodeExemptions)
    ) continue;
    const signals: string[] = [];
    if (!reachability.runtimeInboundPaths.has(file.record.path)) signals.push('no-inbound-resolved-runtime-static-import');
    if (productionClosureEstablished && !reachability.reachablePaths.has(file.record.path)) {
      signals.push('unreachable-from-configured-entrypoints');
    }
    if (!signals.length) continue;
    const confidence = signals.length === 2 ? 'medium' : 'low';
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: findingId(file.record.path, signals),
      category: 'dead-code-candidate',
      ruleId: 'dead-code/static-reachability-v1',
      status: 'candidate',
      severity: 'info',
      confidence,
      title: `Review possible unused source: ${file.record.path}`,
      description: 'Static graph and modeled loader evidence did not establish a supported runtime path to this file. This is a review candidate, never a deletion verdict.',
      path: file.record.path,
      relatedPaths: [],
      signals,
      evidence: [
        {
          level: 1,
          producer: 'atlas/dead-code-candidates',
          producerVersion: DEAD_CODE_ANALYSIS_VERSION,
          basis: 'static-entrypoint-reachability-and-inbound-import-count',
          path: file.record.path,
          recordIds: [file.record.id]
        }
      ],
      nextValidation: 'Check scoped loader-coverage diagnostics, framework registration, callbacks, deployment entrypoints, and external consumers before assigning lifecycle or cleanup status.'
    });
  }
  const relationshipParticipants = new Set(relationships.flatMap((relationship) => [relationship.from, ...(relationship.to ? [relationship.to] : [])]));
  const platformPatterns = profile.platformRoots.flatMap((root) => [root, `${root}/**`]);
  for (const file of files) {
    if (!platformPatterns.length || !matchesAnyGlob(file.record.path, platformPatterns) || relationshipParticipants.has(file.record.id)) continue;
    const signals = ['platform-file-without-supported-static-association'];
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: findingId(file.record.path, signals),
      category: 'dead-code-candidate',
      ruleId: 'dead-code/unused-platform-file-v1',
      status: 'candidate',
      severity: 'info',
      confidence: 'low',
      title: `Review unassociated platform artifact: ${file.record.path}`,
      description: 'No supported static source relationship references this configured platform artifact. External deployment, IaC, workflow, or operator use remains unknown.',
      path: file.record.path,
      relatedPaths: [],
      signals,
      evidence: [
        {
          level: 1,
          producer: 'atlas/dead-code-candidates',
          producerVersion: DEAD_CODE_ANALYSIS_VERSION,
          basis: 'configured-platform-root-and-static-association-absence',
          path: file.record.path,
          recordIds: [file.record.id]
        }
      ],
      nextValidation: 'Check deployment systems, IaC references, workflow inputs, operations runbooks, external consumers, and runtime inventory before cleanup.'
    });
  }
  findings.sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings, diagnostics };
}
