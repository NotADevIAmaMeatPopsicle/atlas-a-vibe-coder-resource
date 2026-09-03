import type {
  DiagnosticRecord,
  FindingRecord,
  RelationshipRecord,
  ResolvedProfile,
  AnalysisFile
} from '../types.js';
import { SCHEMA_VERSION, TOOL_VERSION } from '../types.js';
import { isExpectedFixtureUnresolvedImport } from '../profile-matching.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesAnyGlob } from '../util/paths.js';

function idFor(ruleId: string, material: unknown): string {
  return `finding:${sha256(canonicalJson({ ruleId, material })).slice(0, 24)}`;
}

function layerFor(filePath: string, profile: ResolvedProfile): string | undefined {
  return profile.architecture?.layers.find((layer) => matchesAnyGlob(filePath, layer.patterns))?.id;
}

export function detectMismatches(
  files: AnalysisFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const findings: FindingRecord[] = [];
  const diagnostics: DiagnosticRecord[] = [];
  for (const relationship of relationships) {
    if (relationship.resolution !== 'unresolved-internal') continue;
    if (isExpectedFixtureUnresolvedImport(profile, relationship.fromPath, relationship.specifier)) continue;
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: idFor('contract/unresolved-internal-import-v1', relationship.id),
      category: 'contract-mismatch',
      ruleId: 'contract/unresolved-internal-import-v1',
      status: 'candidate',
      severity: 'high',
      confidence: 'high',
      title: `Unresolved internal module reference in ${relationship.fromPath}`,
      description: `The JS/TS adapter could not resolve ${relationship.specifier} inside the declared snapshot boundary.`,
      path: relationship.fromPath,
      relatedPaths: [],
      signals: ['unresolved-internal-module-specifier'],
      evidence: [{ ...relationship.evidence, recordIds: [relationship.id] }],
      nextValidation: 'Check the import spelling, alias configuration, generated-file boundary, and intended module path.'
    });
  }

  const configuredExamples = new Set(profile.envExampleFiles);
  for (const configured of configuredExamples) {
    if (!files.some((file) => file.record.path === configured)) {
      diagnostics.push({
        schemaVersion: SCHEMA_VERSION,
        id: `diagnostic:${sha256(canonicalJson({ code: 'ENV_EXAMPLE_MISSING', configured })).slice(0, 24)}`,
        code: 'ENV_EXAMPLE_MISSING',
        severity: 'warning',
        message: `Configured environment example is outside the snapshot or missing: ${configured}`,
        path: configured,
        evidence: {
          level: 2,
          producer: 'atlas/mismatch-engine',
          producerVersion: TOOL_VERSION,
          basis: 'profile-to-snapshot-comparison',
          path: configured
        }
      });
    }
  }
  if (profile.architecture) {
    const allowed = new Set(profile.architecture.allowedDependencies.map((rule) => `${rule.from}\0${rule.to}`));
    for (const relationship of relationships) {
      if (relationship.resolution !== 'resolved' || !relationship.toPath) continue;
      const fromLayer = layerFor(relationship.fromPath, profile);
      const toLayer = layerFor(relationship.toPath, profile);
      if (!fromLayer || !toLayer || fromLayer === toLayer || allowed.has(`${fromLayer}\0${toLayer}`)) continue;
      findings.push({
        schemaVersion: SCHEMA_VERSION,
        id: idFor('architecture/allowed-dependency-v1', relationship.id),
        category: 'architecture-mismatch',
        ruleId: 'architecture/allowed-dependency-v1',
        status: 'candidate',
        severity: 'medium',
        confidence: 'high',
        title: `Architecture dependency is not allowed: ${fromLayer} -> ${toLayer}`,
        description: `${relationship.fromPath} statically references ${relationship.toPath}, but the resolved profile does not allow that layer direction.`,
        path: relationship.fromPath,
        relatedPaths: [relationship.toPath],
        signals: ['disallowed-declared-layer-direction'],
        evidence: [{ ...relationship.evidence, level: 2, producer: 'atlas/mismatch-engine', recordIds: [relationship.id] }],
        nextValidation: 'Inspect the imported symbol and workflow, then add an explicit architecture exception or correct the dependency.'
      });
    }
  }

  const deduplicated = [...new Map(findings.map((finding) => [finding.id, finding])).values()];
  deduplicated.sort((left, right) => compareCanonicalText(left.id, right.id));
  diagnostics.sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings: deduplicated, diagnostics };
}
