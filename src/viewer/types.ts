import type {
  AnalysisHealthRecord,
  DiagnosticRecord,
  EvidenceReference,
  FileKind,
  FileLifecycleDeclaration,
  FindingRecord,
  RelationshipType,
  ResolutionState,
  SourceLocation
} from '../types.js';

export const VIEWER_VERSION = '0.9.0' as const;

export type ViewerAnalysisHealth =
  | (AnalysisHealthRecord & { state: 'recorded' })
  | {
      state: 'legacy-not-recorded';
      limitation: string;
    };

export interface ViewerRelationship {
  id: string;
  from: string;
  fromPath: string;
  to?: string;
  toPath?: string;
  type: RelationshipType;
  typeOnly?: boolean;
  specifier: string;
  resolution: ResolutionState;
  location: SourceLocation;
  evidence: EvidenceReference;
}

export interface ViewerFile {
  id: string;
  path: string;
  sha256: string;
  bytes: number;
  kind: FileKind;
  language: string;
  symbols: string[];
  environmentVariables: string[];
  lifecycle: FileLifecycleDeclaration | {
    state: 'unspecified';
    basis: 'legacy-not-recorded';
    uncertainty: 'not-runtime-validated';
    limitation: string;
  };
  evidence: EvidenceReference;
  incoming: ViewerRelationship[];
  outgoing: ViewerRelationship[];
}

export interface ViewerGraphNode {
  id: string;
  label: string;
  kind: 'file' | 'external-package' | 'unresolved-internal' | 'unsupported';
  fileId?: string;
}

export interface ViewerGraphEdge {
  id: string;
  source: string;
  target: string;
  type: RelationshipType;
  typeOnly?: boolean;
  specifier: string;
  resolution: ResolutionState;
}

export interface ViewerData {
  schemaVersion: 1;
  viewerVersion: typeof VIEWER_VERSION;
  sourceArtifactManifestSha256: string;
  run: {
    runId: string;
    snapshotId: string;
    targetId: string;
    profileId: string;
    profileDigest: string;
    tool: { name: 'atlas'; version: string };
    adapters: Array<{ id: string; version: string }>;
    analyses: string[];
  };
  summary: {
    files: number;
    relationships: number;
    resolvedRelationships: number;
    diagnostics: number;
    findings: number;
    totalBytes: number;
  };
  census: {
    boundary: {
      includeRoots: string[];
      exclude: string[];
      maxFileBytes: number;
      symlinkPolicy: 'deny';
    };
    boundaryDiagnostics: Array<{
      id: string;
      code: string;
      severity: 'info' | 'warning' | 'error';
      path?: string;
    }>;
    byKind: Record<string, number>;
    byLanguage: Record<string, number>;
    files: ViewerFile[];
  };
  dependencyGraph: {
    nodes: ViewerGraphNode[];
    edges: ViewerGraphEdge[];
  };
  analysisHealth: ViewerAnalysisHealth;
  findings: FindingRecord[];
  diagnostics: DiagnosticRecord[];
}

export interface ViewerArtifactDigest {
  path: string;
  bytes: number;
  sha256: string;
}

export interface ViewerManifest {
  schemaVersion: 1;
  viewerVersion: typeof VIEWER_VERSION;
  viewerId: string;
  runId: string;
  snapshotId: string;
  sourceArtifactManifestSha256: string;
  artifacts: ViewerArtifactDigest[];
}

export interface ViewerPublicationResult {
  directory: string;
  viewerId: string;
  manifest: ViewerManifest;
  sourceArtifactManifestSha256: string;
  reused: boolean;
  healthState: ViewerAnalysisHealth['state'];
  healthStatus: AnalysisHealthRecord['status'] | 'not-recorded';
}

export interface ViewerVerificationSummary {
  status: 'passed';
  healthState: ViewerAnalysisHealth['state'];
  healthStatus: AnalysisHealthRecord['status'] | 'not-recorded';
  viewerId: string;
  runId: string;
  snapshotId: string;
  sourceArtifactManifestSha256: string;
  artifacts: number;
  files: number;
  relationships: number;
  diagnostics: number;
  findings: number;
}

/** Exact, in-memory values backed by the artifact bytes verified in one call. */
export interface VerifiedViewerArtifacts {
  summary: ViewerVerificationSummary;
  manifest: ViewerManifest;
  manifestSha256: string;
  indexHtml: string;
  directory: string;
  contents: ReadonlyMap<string, Buffer>;
}
