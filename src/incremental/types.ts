import type { RelationshipRecord } from '../types.js';

export type IncrementalFullRebuildReason =
  | 'ADAPTER_SET_CHANGED'
  | 'ANALYZER_SET_CHANGED'
  | 'DISCOVERY_PROVIDER_CHANGED'
  | 'DISCOVERY_STATE_CHANGED'
  | 'DISCOVERY_VERSION_CHANGED'
  | 'PROFILE_DIGEST_CHANGED'
  | 'PROFILE_ID_CHANGED'
  | 'PROFILE_OBSERVATIONS_CHANGED'
  | 'RUN_ID_DIGEST_CONFLICT'
  | 'TOOL_CHANGED';

export interface IncrementalRunBinding {
  runId: string;
  artifactManifestDigest: string;
  snapshotId: string;
  targetId: string;
  profileId: string;
  profileDigest: string;
  discoveryDigest: string;
}

export interface IncrementalPathChanges {
  added: string[];
  changed: string[];
  removed: string[];
}

export interface IncrementalEvidenceEdge {
  relationshipId: string;
  recordDigest: string;
  fromPath: string;
  type: RelationshipRecord['type'];
  resolution: RelationshipRecord['resolution'];
  toPath?: string;
}

export interface IncrementalChangedEvidenceEdge {
  relationshipId: string;
  before: IncrementalEvidenceEdge;
  after: IncrementalEvidenceEdge;
}

export interface IncrementalAffectedRecords {
  baselineFindingIds: string[];
  nextFindingIds: string[];
  baselineDiagnosticIds: string[];
  nextDiagnosticIds: string[];
}

export interface IncrementalAnalysisPlan {
  schemaVersion: 1;
  planId: string;
  planner: { name: 'atlas/incremental-planner'; version: string };
  targetId: string;
  baseline: IncrementalRunBinding;
  next: IncrementalRunBinding;
  compatibility: {
    incrementalReuseEligible: boolean;
    discoveryChanged: boolean;
    fullRebuildReasons: IncrementalFullRebuildReason[];
  };
  paths: IncrementalPathChanges;
  evidenceEdges: {
    added: IncrementalEvidenceEdge[];
    changed: IncrementalChangedEvidenceEdge[];
    removed: IncrementalEvidenceEdge[];
  };
  impact: {
    seedPaths: string[];
    reverseDependencyClosurePaths: string[];
    affectedRecords: IncrementalAffectedRecords;
  };
  cache: {
    hitEligiblePaths: string[];
    missRequiredPaths: string[];
    evictedPaths: string[];
  };
}

export interface IncrementalPlanOptions {
  workspacePath: string;
  targetId: string;
  baselineRunDirectory: string;
  nextRunDirectory: string;
}

export interface IncrementalBatchPlan {
  schemaVersion: 1;
  batchPlanId: string;
  planner: { name: 'atlas/incremental-planner'; version: string };
  plans: IncrementalAnalysisPlan[];
}

export interface IncrementalBatchPlanOptions {
  workspacePath: string;
  targets: Array<{
    targetId: string;
    baselineRunDirectory: string;
    nextRunDirectory: string;
  }>;
}
