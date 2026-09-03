import type { LoadedRunWithManifest } from '../artifacts.js';
import { AtlasError } from '../errors.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import type { AnalysisHealthRecord, FindingRecord, RelationshipRecord } from '../types.js';
import {
  VIEWER_VERSION,
  type ViewerAnalysisHealth,
  type ViewerData,
  type ViewerGraphNode,
  type ViewerRelationship
} from './types.js';

const LEGACY_ANALYSIS_HEALTH_LIMITATION =
  'This legacy run predates analysis-health artifacts; rule controls, incident regressions, recall, and fixed-case silence were not recorded.';

function countsBy(values: string[]): Record<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return Object.fromEntries([...counts].sort(([left], [right]) => compareCanonicalText(left, right)));
}

function projectRelationship(relationship: RelationshipRecord): ViewerRelationship {
  return {
    id: relationship.id,
    from: relationship.from,
    fromPath: relationship.fromPath,
    ...(relationship.to ? { to: relationship.to } : {}),
    ...(relationship.toPath ? { toPath: relationship.toPath } : {}),
    type: relationship.type,
    ...(relationship.typeOnly === undefined ? {} : { typeOnly: relationship.typeOnly }),
    specifier: relationship.specifier,
    resolution: relationship.resolution,
    location: relationship.location,
    evidence: relationship.evidence
  };
}

function unresolvedNodeId(relationship: RelationshipRecord): string {
  return `dependency_sha256_${sha256(canonicalJson({
    domain: 'atlas.viewer.dependency-node.v1',
    resolution: relationship.resolution,
    specifier: relationship.specifier
  }))}`;
}

function projectAnalysisHealth(analysisHealth: AnalysisHealthRecord | undefined): ViewerAnalysisHealth {
  if (!analysisHealth) {
    return {
      state: 'legacy-not-recorded',
      limitation: LEGACY_ANALYSIS_HEALTH_LIMITATION
    };
  }
  return {
    state: 'recorded',
    schemaVersion: analysisHealth.schemaVersion,
    runId: analysisHealth.runId,
    snapshotId: analysisHealth.snapshotId,
    producer: { ...analysisHealth.producer },
    catalogDigest: analysisHealth.catalogDigest,
    corpusDigest: analysisHealth.corpusDigest,
    status: analysisHealth.status,
    profilePatterns: analysisHealth.profilePatterns.map((entry) => ({
      ...entry,
      expected: { ...entry.expected }
    })),
    rules: analysisHealth.rules.map((entry) => ({
      ...entry,
      controls: { ...entry.controls },
      ...(entry.target === undefined ? {} : {
        target: {
          ...entry.target,
          ...(entry.target.expectations === undefined
            ? {}
            : { expectations: { ...entry.target.expectations } })
        }
      })
    })),
    incidents: analysisHealth.incidents.map((entry) => ({
      ...entry,
      broken: { ...entry.broken },
      fixed: { ...entry.fixed }
    })),
    recall: { ...analysisHealth.recall },
    ...(analysisHealth.realTargetEvaluation === undefined ? {} : {
      realTargetEvaluation: { ...analysisHealth.realTargetEvaluation }
    }),
    fixedCaseSilence: { ...analysisHealth.fixedCaseSilence }
  };
}

function projectFinding(finding: FindingRecord): FindingRecord {
  return {
    ...finding,
    ...(finding.subject ? { subject: { ...finding.subject } } : {}),
    relatedPaths: [...finding.relatedPaths],
    signals: [...finding.signals],
    evidence: finding.evidence.map((evidence) => ({
      ...evidence,
      ...(evidence.recordIds ? { recordIds: [...evidence.recordIds] } : {})
    })),
    ...(finding.instances ? {
      instances: finding.instances.map((instance) => ({
        ...instance,
        ...(instance.subject ? { subject: { ...instance.subject } } : {}),
        relatedPaths: [...instance.relatedPaths],
        signals: [...instance.signals],
        evidence: instance.evidence.map((evidence) => ({
          ...evidence,
          ...(evidence.recordIds ? { recordIds: [...evidence.recordIds] } : {})
        }))
      }))
    } : {}),
    ...(finding.impactContext ? {
      impactContext: {
        ...finding.impactContext,
        entrypoints: [...finding.impactContext.entrypoints],
        mountedSurfaces: [...finding.impactContext.mountedSurfaces],
        limitations: [...finding.impactContext.limitations]
      }
    } : {}),
    ...(finding.reviewAnchors ? { reviewAnchors: finding.reviewAnchors.map((anchor) => ({ ...anchor })) } : {}),
    ...(finding.reviewPriority ? { reviewPriority: { ...finding.reviewPriority } } : {})
  };
}

export function buildViewerData(loaded: LoadedRunWithManifest): ViewerData {
  const relationships = loaded.relationships.map(projectRelationship);
  const relationshipById = new Map(relationships.map((relationship) => [relationship.id, relationship]));
  const incomingIds = new Map<string, string[]>();
  const outgoingIds = new Map<string, string[]>();
  for (const relationship of relationships) {
    const outgoing = outgoingIds.get(relationship.from) ?? [];
    outgoing.push(relationship.id);
    outgoingIds.set(relationship.from, outgoing);
    if (relationship.to) {
      const incoming = incomingIds.get(relationship.to) ?? [];
      incoming.push(relationship.id);
      incomingIds.set(relationship.to, incoming);
    }
  }
  const relationshipRecords = (ids: string[] | undefined): ViewerRelationship[] => (ids ?? [])
    .map((id) => relationshipById.get(id))
    .filter((relationship): relationship is ViewerRelationship => relationship !== undefined)
    .sort((left, right) => compareCanonicalText(left.id, right.id));

  const files = loaded.files.map((file) => ({
    id: file.id,
    path: file.path,
    sha256: file.sha256,
    bytes: file.bytes,
    kind: file.kind,
    language: file.language,
    symbols: [...file.symbols],
    environmentVariables: [...file.environmentVariables],
    lifecycle: file.lifecycle ? { ...file.lifecycle } : {
      state: 'unspecified' as const,
      basis: 'legacy-not-recorded' as const,
      uncertainty: 'not-runtime-validated' as const,
      limitation: 'This legacy v1 file record predates lifecycle declarations; runtime deployment, traffic, and use were not evaluated.'
    },
    evidence: file.evidence,
    incoming: relationshipRecords(incomingIds.get(file.id)),
    outgoing: relationshipRecords(outgoingIds.get(file.id))
  }));

  const graphNodes: ViewerGraphNode[] = files.map((file) => ({
    id: file.id,
    label: file.path,
    kind: 'file',
    fileId: file.id
  }));
  const syntheticNodes = new Map<string, ViewerGraphNode>();
  for (const relationship of loaded.relationships) {
    if (relationship.to) continue;
    if (relationship.resolution === 'resolved') {
      throw new AtlasError('VIEWER_GRAPH_INTEGRITY', `Resolved relationship has no target: ${relationship.id}`);
    }
    const id = unresolvedNodeId(relationship);
    syntheticNodes.set(id, {
      id,
      label: `${relationship.specifier} [${relationship.resolution}]`,
      kind: relationship.resolution
    });
  }
  for (const node of syntheticNodes.values()) graphNodes.push(node);
  graphNodes.sort((left, right) => compareCanonicalText(left.id, right.id));

  const graphEdges = loaded.relationships.map((relationship) => ({
    id: relationship.id,
    source: relationship.from,
    target: relationship.to ?? unresolvedNodeId(relationship),
    type: relationship.type,
    ...(relationship.typeOnly === undefined ? {} : { typeOnly: relationship.typeOnly }),
    specifier: relationship.specifier,
    resolution: relationship.resolution
  })).sort((left, right) => compareCanonicalText(left.id, right.id));

  return {
    schemaVersion: 1,
    viewerVersion: VIEWER_VERSION,
    sourceArtifactManifestSha256: loaded.sourceArtifactManifestSha256,
    run: {
      runId: loaded.run.runId,
      snapshotId: loaded.snapshot.snapshotId,
      targetId: loaded.run.targetId,
      profileId: loaded.run.profileId,
      profileDigest: loaded.run.profileDigest,
      tool: loaded.run.tool,
      adapters: loaded.run.adapters.map((adapter) => ({ ...adapter })),
      analyses: [...loaded.run.analyses]
    },
    summary: {
      files: files.length,
      relationships: relationships.length,
      resolvedRelationships: relationships.filter((relationship) => relationship.resolution === 'resolved').length,
      diagnostics: loaded.diagnostics.length,
      findings: loaded.findings.length,
      totalBytes: files.reduce((total, file) => total + file.bytes, 0)
    },
    census: {
      boundary: {
        includeRoots: [...loaded.snapshot.boundary.includeRoots],
        exclude: [...loaded.snapshot.boundary.exclude],
        maxFileBytes: loaded.snapshot.boundary.maxFileBytes,
        symlinkPolicy: loaded.snapshot.boundary.symlinkPolicy
      },
      boundaryDiagnostics: loaded.snapshot.boundaryDiagnostics.map((diagnostic) => ({ ...diagnostic })),
      byKind: countsBy(files.map((file) => file.kind)),
      byLanguage: countsBy(files.map((file) => file.language)),
      files,
    },
    dependencyGraph: { nodes: graphNodes, edges: graphEdges },
    analysisHealth: projectAnalysisHealth(loaded.analysisHealth),
    findings: loaded.findings.map(projectFinding),
    diagnostics: loaded.diagnostics.map((diagnostic) => ({
      ...diagnostic,
      ...(diagnostic.disposition ? {
        disposition: {
          ...diagnostic.disposition,
          evidence: [...diagnostic.disposition.evidence],
          anchors: diagnostic.disposition.anchors.map((anchor) => ({ ...anchor }))
        }
      } : {}),
      evidence: {
        ...diagnostic.evidence,
        ...(diagnostic.evidence.recordIds ? { recordIds: [...diagnostic.evidence.recordIds] } : {})
      }
    }))
  };
}

function mermaidLabel(value: string): string {
  let result = '';
  for (const character of value.normalize('NFC')) {
    if (/^[A-Za-z0-9._\/-]$/.test(character)) result += character;
    else result += `&#x${character.codePointAt(0)!.toString(16).toUpperCase()};`;
  }
  return result;
}

export function renderDependencyMermaid(data: ViewerData): string {
  const nodeAliases = new Map(data.dependencyGraph.nodes.map((node, index) => [node.id, `n${index}`]));
  const lines = ['flowchart LR'];
  for (const node of data.dependencyGraph.nodes) {
    const alias = nodeAliases.get(node.id)!;
    lines.push(`  ${alias}["${mermaidLabel(node.label)}"]`);
  }
  for (const edge of data.dependencyGraph.edges) {
    const source = nodeAliases.get(edge.source);
    const target = nodeAliases.get(edge.target);
    if (!source || !target) {
      throw new AtlasError('VIEWER_GRAPH_INTEGRITY', `Dependency graph edge has a missing node: ${edge.id}`);
    }
    lines.push(`  ${source} -->|${mermaidLabel(`${edge.type}${edge.typeOnly ? ' [type-only]' : ''}`)}| ${target}`);
  }
  return `${lines.join('\n')}\n`;
}
