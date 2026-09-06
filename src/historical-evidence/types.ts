export const HISTORICAL_EVIDENCE_PRODUCER_VERSION = '1.2.0' as const;

export type HistoricalEvidenceKind = 'review' | 'trace';

export interface HistoricalEvidenceCitation {
  path: string;
  sha256: string;
  line: number;
  column: number;
  basis: 'artifact-path' | 'title' | 'scope-heading' | 'path-anchor' | 'trace-index-entry' | 'reviewer-metadata';
}

export interface HistoricalEvidenceScopeAnchor {
  heading: string;
  level: number;
  line: number;
  column: number;
}

export interface HistoricalEvidencePathMention {
  line: number;
  column: number;
}

export interface HistoricalEvidencePathAnchor {
  path: string;
  kind: 'file' | 'directory-or-pattern';
  targetStartLine?: number;
  targetEndLine?: number;
  mentions: HistoricalEvidencePathMention[];
}

export interface HistoricalReviewerIdentity {
  status: 'recorded' | 'unavailable';
  identity: string | null;
  reason: string;
  citation?: HistoricalEvidenceCitation;
}

export interface HistoricalAnchorFreshness {
  status: 'unavailable';
  checkedAgainstSourceHead: null;
  reason: string;
}

export interface HistoricalTraceMetadata {
  id: string;
  label: string;
  clusterId: string;
  lifecycle: string;
  historicalUnvalidatedSummary: string;
  citation: HistoricalEvidenceCitation;
}

export interface HistoricalEvidenceRecord {
  schemaVersion: 1;
  id: string;
  kind: HistoricalEvidenceKind;
  artifact: {
    path: string;
    bytes: number;
    sha256: string;
  };
  title: string;
  titleLine: number;
  scopeAnchors: HistoricalEvidenceScopeAnchor[];
  pathAnchors: HistoricalEvidencePathAnchor[];
  reviewerIdentity: HistoricalReviewerIdentity;
  anchorFreshness: HistoricalAnchorFreshness;
  interpretation: {
    usage: 'historical-navigation-context-only';
    claimBodiesImported: false;
    validatedFindingsCreated: false;
  };
  trace?: HistoricalTraceMetadata;
}

export interface HistoricalEvidenceSource {
  referencePath: string;
  manifestFileName: string;
  manifestSha256: string;
  referenceAggregateSha256: string;
  sourceAggregateSha256: string;
  referenceFileCount: number;
  referenceTotalBytes: number;
  sourceGitHead: string;
  sourceAtlasPath: string;
  sourceDirtyStatusSha256: string;
  sourceDirtyStatusLineCount: number;
}

export interface HistoricalEvidenceIndex {
  schemaVersion: 1;
  indexId: string;
  producer: {
    name: 'atlas/historical-evidence';
    version: typeof HISTORICAL_EVIDENCE_PRODUCER_VERSION;
  };
  source: HistoricalEvidenceSource;
  policy: {
    reviewSelection: 'reviews/*.md';
    traceSelection: 'named-entries-from-traces/trace-index.json';
    claimBodiesImported: false;
    validatedFindingsCreated: false;
    defaultTrust: 'historical-unvalidated-context';
  };
  artifacts: ['index.json', 'records.jsonl', 'artifact-digests.json'];
  counts: {
    reviews: number;
    traces: number;
    records: number;
    scopeAnchors: number;
    pathAnchors: number;
  };
}

export interface HistoricalEvidenceArtifactManifest {
  schemaVersion: 1;
  indexId: string;
  artifacts: Array<{
    path: 'index.json' | 'records.jsonl';
    bytes: number;
    sha256: string;
  }>;
}

export interface HistoricalEvidenceReferenceVerification {
  status: 'passed';
  referencePath: string;
  manifestPath: string;
  manifestSha256: string;
  fileCount: number;
  totalBytes: number;
  aggregateSha256: string;
  sourceGitHead: string;
}

export interface HistoricalEvidenceIndexVerification {
  status: 'passed';
  indexId: string;
  records: number;
  reviews: number;
  traces: number;
  artifacts: 3;
  referenceAggregateSha256: string;
  sourceGitHead: string;
}

export interface HistoricalEvidenceIndexResult {
  status: 'completed' | 'reused';
  directory: string;
  indexId: string;
  counts: HistoricalEvidenceIndex['counts'];
  referenceVerification: HistoricalEvidenceReferenceVerification;
}

export interface HistoricalEvidenceQueryHit {
  kind: HistoricalEvidenceKind;
  id: string;
  score: number;
  title: string;
  artifact: HistoricalEvidenceRecord['artifact'];
  matchedFields: Array<'artifact-path' | 'path-anchor' | 'scope-heading' | 'title' | 'trace-cluster' | 'trace-id' | 'trace-label' | 'trace-lifecycle' | 'trace-summary'>;
  citations: HistoricalEvidenceCitation[];
  reviewerIdentity: HistoricalReviewerIdentity;
  anchorFreshness: HistoricalAnchorFreshness;
  interpretation: HistoricalEvidenceRecord['interpretation'];
  trace?: HistoricalTraceMetadata;
}

export interface HistoricalEvidenceQueryResult {
  schemaVersion: 1;
  indexId: string;
  query: string;
  answer: {
    kind: 'matches' | 'abstention';
    text: string;
  };
  provenance: HistoricalEvidenceSource;
  interpretation: {
    usage: 'historical-navigation-context-only';
    claimBodiesImported: false;
    validatedFindingsCreated: false;
  };
  hits: HistoricalEvidenceQueryHit[];
  truncated: boolean;
}

export interface VerifiedHistoricalEvidenceIndex {
  directory: string;
  index: HistoricalEvidenceIndex;
  records: HistoricalEvidenceRecord[];
  manifest: HistoricalEvidenceArtifactManifest;
  manifestSha256: string;
  summary: HistoricalEvidenceIndexVerification;
}
