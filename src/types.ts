export const SCHEMA_VERSION = 1 as const;
export const TOOL_VERSION = '0.2.0';
export const JS_TS_ADAPTER_VERSION = '0.2.6';

export type EvidenceLevel = 0 | 1 | 2 | 3 | 4;
export type Confidence = 'confirmed' | 'high' | 'medium' | 'low' | 'unknown';

export interface EvidenceReference {
  level: EvidenceLevel;
  producer: string;
  producerVersion: string;
  basis: string;
  path?: string;
  line?: number;
  column?: number;
  recordIds?: string[];
}

export interface TargetConsent {
  agentReview: boolean;
  export: boolean;
  projectMemory: boolean;
}

export interface TargetConfig {
  schemaVersion: 1;
  id: string;
  path: string;
  consent: TargetConsent;
}

export interface TargetRegistration {
  schemaVersion: 1;
  targetId: string;
  targetRoot: string;
  targetConfigPath: string;
  consent: TargetConsent;
}

export interface ArchitectureLayer {
  id: string;
  patterns: string[];
}

export interface ArchitectureDependencyRule {
  from: string;
  to: string;
}

export type FileLifecycleState = 'active' | 'mothballed' | 'shared' | 'unknown' | 'unspecified';

export interface LifecyclePathRule {
  id: string;
  state: Exclude<FileLifecycleState, 'unspecified'>;
  paths: string[];
}

export type PatternCollection =
  | 'includeRoots'
  | 'exclude'
  | 'entrypoints'
  | 'deadCodeExemptions'
  | 'fixturePatterns'
  | 'guardPaths'
  | 'seedDictionarySources'
  | 'loaderPaths'
  | 'loadedPatterns';

export interface PatternExpectation {
  id: string;
  collection: PatternCollection;
  pattern: string;
  minMatches: number;
  maxMatches?: number;
}

export interface FixtureUnresolvedImport {
  id: string;
  sourcePattern: string;
  specifier: string;
}

export interface ProfilePatternObservation extends PatternExpectation {
  actualMatches: number;
  status: 'passed' | 'failed';
  samplePaths: string[];
}

export interface LoaderRule {
  id: string;
  kind: 'sequelize-models' | 'migrations' | 'seeders' | 'routes' | 'package-scripts' | 'tests' | 'build' | 'cli' | 'custom';
  loaderPaths: string[];
  loadedPatterns: string[];
  scope: 'production' | 'test' | 'build' | 'cli' | 'migration' | 'seeder';
  required: boolean;
}

export interface RuleExpectation {
  ruleId: string;
  minObservations?: number;
  maxObservations?: number;
  minFindings?: number;
  maxFindings?: number;
}

export interface OperationalRiskBoundary {
  id: string;
  module: string;
  protects: string[];
}

export interface OperationalRiskProtectedWriter {
  id: string;
  module: string;
  methods: string[];
}

export interface OperationalRiskProfile {
  guardPaths: string[];
  seedDictionarySources: string[];
  boundaries?: OperationalRiskBoundary[];
  protectedWriters?: OperationalRiskProtectedWriter[];
}

export interface FileLifecycleDeclaration {
  state: FileLifecycleState;
  basis: 'profile-path-rule' | 'no-profile-match';
  ruleId?: string;
  uncertainty: 'not-runtime-validated';
  limitation: string;
}

export interface ProfileConfig {
  schemaVersion: 1;
  id: string;
  includeRoots: string[];
  exclude?: string[];
  entrypoints?: string[];
  aliases?: Record<string, string[]>;
  envExampleFiles?: string[];
  platformRoots?: string[];
  deadCodeExemptions?: string[];
  fixturePatterns?: string[];
  fixtureUnresolvedImports?: FixtureUnresolvedImport[];
  loaderRules?: LoaderRule[];
  patternExpectations?: PatternExpectation[];
  ruleExpectations?: RuleExpectation[];
  operationalRisks?: {
    guardPaths?: string[];
    seedDictionarySources?: string[];
    boundaries?: OperationalRiskBoundary[];
    protectedWriters?: OperationalRiskProtectedWriter[];
  };
  lifecycleRules?: LifecyclePathRule[];
  maxFileBytes?: number;
  architecture?: {
    layers: ArchitectureLayer[];
    allowedDependencies: ArchitectureDependencyRule[];
  };
}

export interface ResolvedProfile extends ProfileConfig {
  exclude: string[];
  explicitExclude?: string[];
  entrypoints: string[];
  aliases: Record<string, string[]>;
  envExampleFiles: string[];
  platformRoots: string[];
  deadCodeExemptions: string[];
  fixturePatterns?: string[];
  fixtureUnresolvedImports?: FixtureUnresolvedImport[];
  loaderRules?: LoaderRule[];
  patternExpectations?: PatternExpectation[];
  ruleExpectations?: RuleExpectation[];
  operationalRisks?: OperationalRiskProfile;
  lifecycleRules: LifecyclePathRule[];
  maxFileBytes: number;
}

export type FileKind = 'source' | 'test' | 'configuration' | 'documentation' | 'other';

export interface FileRecord {
  schemaVersion: 1;
  id: string;
  path: string;
  sha256: string;
  bytes: number;
  kind: FileKind;
  language: string;
  symbols: string[];
  environmentVariables: string[];
  lifecycle?: FileLifecycleDeclaration;
  evidence: EvidenceReference;
}

export type RelationshipType = 'static-import' | 'dynamic-import' | 'require' | 'export-from';
export type ResolutionState = 'resolved' | 'unresolved-internal' | 'external-package' | 'unsupported';

export interface SourceLocation {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface RelationshipRecord {
  schemaVersion: 1;
  id: string;
  from: string;
  fromPath: string;
  to?: string;
  toPath?: string;
  type: RelationshipType;
  specifier: string;
  typeOnly?: boolean;
  resolution: ResolutionState;
  location: SourceLocation;
  evidence: EvidenceReference;
}

export type DiagnosticSeverity = 'info' | 'warning' | 'error';

export interface FindingDispositionDiagnosticProjection {
  reviewId: string;
  findingId: string;
  title?: string;
  ruleId?: string;
  disposition:
    | 'confirmed defect'
    | 'intentional contract'
    | 'false positive/profile gap'
    | 'test fixture'
    | 'framework-managed/external entrypoint'
    | 'obsolete but cleanup separately'
    | 'needs runtime/schema evidence'
    | 'defer';
  reviewer: string;
  date: string;
  evidence: string[];
  anchors: Array<{ path: string; sha256: string }>;
  state: 'applied' | 'stale' | 'anchor-mismatch';
}

export interface DiagnosticRecord {
  schemaVersion: 1;
  id: string;
  code: string;
  severity: DiagnosticSeverity;
  message: string;
  path?: string;
  location?: SourceLocation;
  disposition?: FindingDispositionDiagnosticProjection;
  evidence: EvidenceReference;
}

export type FindingCategory =
  | 'dead-code-candidate'
  | 'contract-mismatch'
  | 'architecture-mismatch'
  | 'operational-defect'
  | 'review-inventory'
  | 'latent-hazard';

export type FindingKind = 'defect-candidate' | 'review-inventory' | 'latent-hazard';

export interface FindingInstance {
  id: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  confidence: Confidence;
  path?: string;
  location?: SourceLocation;
  relatedPaths: string[];
  signals: string[];
  evidence: EvidenceReference[];
  subject?: DataContractFindingSubject;
  impactContext?: FindingImpactContext;
}

export interface FindingImpactContext {
  reachability: 'reachable' | 'unreachable' | 'coverage-incomplete' | 'mixed' | 'unknown';
  scope?: 'production' | 'test' | 'build' | 'cli' | 'migration' | 'seeder';
  entrypoints: string[];
  entrypointRemainder?: number;
  mountedSurfaces: string[];
  lifecycle?: FileLifecycleState;
  featureGate: 'observed' | 'not-observed' | 'unknown';
  summary: string;
  limitations: string[];
}

export interface FindingMappingContext {
  id: string;
  composePath: string;
  service: string;
  sourceKind: 'bind-mount' | 'docker-copy';
  hostRoot: string;
  containerRoot: string;
  buildContext?: string;
  dockerfile?: string;
  workingDirectory?: string;
}

export interface FindingSeverityCalibration {
  version: 'static-reachability-v1';
  detectorSeverity: 'info' | 'low' | 'medium' | 'high';
  ceiling: 'low' | 'medium' | 'high';
  basis:
    | 'static-production-path-no-observed-feature-gate'
    | 'static-production-path-feature-gated'
    | 'static-non-production-path'
    | 'static-test-only-path'
    | 'static-mothballed-path'
    | 'static-unreachable-path'
    | 'static-reachability-incomplete';
  runtimeReachability: 'not-evaluated';
  rationale: string;
}

export interface FindingReviewAnchor {
  path: string;
  sha256: string;
}

export type FindingReviewPriorityBand =
  | 'production-ungated'
  | 'production-gate-unknown'
  | 'production-gated'
  | 'cli'
  | 'build-migration-seeder'
  | 'reachability-incomplete'
  | 'test'
  | 'inactive';

/**
 * A lexicographic review-order tuple. Lower ranks are reviewed first, except
 * instanceCount, which is ordered descending after the three ranks.
 */
export interface FindingReviewPriority {
  version: 'static-actionability-v1';
  band: FindingReviewPriorityBand;
  severityRank: 0 | 1 | 2 | 3;
  impactRank: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;
  confidenceRank: 0 | 1 | 2 | 3 | 4;
  instanceCount: number;
}

export type DataContractDimension =
  | 'column-presence'
  | 'column-mapping'
  | 'type-family'
  | 'nullability'
  | 'default'
  | 'enum-members';

export interface ModelStorageDataContractFindingSubject {
  kind: 'data-contract';
  table: string;
  column: string;
  dimension: DataContractDimension;
  model: 'prisma' | 'sequelize';
  storage: 'sql' | 'sequelize-migration';
}

export interface ProvisioningPathDataContractFindingSubject {
  kind: 'data-contract';
  table: string;
  column: string;
  dimension: 'enum-members';
  comparison: 'provisioning-path';
  migration: 'sequelize-migration';
  bootstrap: 'sql-bootstrap';
}

export type DataContractFindingSubject =
  | ModelStorageDataContractFindingSubject
  | ProvisioningPathDataContractFindingSubject;

export interface FindingRecord {
  schemaVersion: 1;
  id: string;
  category: FindingCategory;
  ruleId: string;
  subject?: DataContractFindingSubject;
  kind?: FindingKind;
  patternKey?: string;
  instanceCount?: number;
  instances?: FindingInstance[];
  impactContext?: FindingImpactContext;
  mechanism?: string;
  mappingContexts?: FindingMappingContext[];
  severityCalibration?: FindingSeverityCalibration;
  reviewId?: string;
  reviewAnchors?: FindingReviewAnchor[];
  reviewPriority?: FindingReviewPriority;
  refutationCondition?: string;
  status: 'candidate';
  severity: 'info' | 'low' | 'medium' | 'high';
  confidence: Confidence;
  title: string;
  description: string;
  path?: string;
  location?: SourceLocation;
  relatedPaths: string[];
  signals: string[];
  evidence: EvidenceReference[];
  nextValidation: string;
}

export type CurrentFindingRecord = FindingRecord & {
  reviewId: string;
  reviewAnchors: FindingReviewAnchor[];
  reviewPriority: FindingReviewPriority;
  refutationCondition: string;
};

export interface SnapshotFileIdentity {
  id: string;
  path: string;
  sha256: string;
  bytes: number;
}

export interface SnapshotRecord {
  schemaVersion: 1;
  snapshotId: string;
  targetId: string;
  boundary: {
    includeRoots: string[];
    exclude: string[];
    maxFileBytes: number;
    symlinkPolicy: 'deny';
  };
  boundaryDiagnostics: Array<{
    id: string;
    code: string;
    severity: DiagnosticSeverity;
    path?: string;
  }>;
  files: SnapshotFileIdentity[];
}

export type AnalysisHealthPatternCollection =
  | 'include-root'
  | 'exclude'
  | 'entrypoint'
  | 'dead-code-exemption'
  | 'fixture-boundary'
  | 'guard-boundary'
  | 'seed-dictionary-source'
  | 'loader-root';

export interface AnalysisHealthPatternObservation {
  id: string;
  collection: AnalysisHealthPatternCollection;
  pattern: string;
  expected: {
    minimum: number;
    maximum?: number;
  };
  observed: number;
  status: 'passed' | 'failed';
  /** Present on current records; omitted by legacy analysis-health producers. */
  samplePaths?: string[];
}

export interface AnalysisRuleHealth {
  ruleId: string;
  state: 'enabled' | 'disabled';
  controls: {
    total: number;
    passed: number;
    failed: number;
    expectedObservations: number;
    observedObservations: number;
  };
  /** Present on current records; omitted by legacy analysis-health producers. */
  target?: {
    /** Whether all rule-specific target inputs required for a meaningful zero were available. */
    inputStatus?: 'complete' | 'incomplete';
    detectedObservations: number;
    uncertainObservations: number;
    findingInstances: number;
    /** Current detector instances omitted from findings.jsonl by a fresh disposition ledger. */
    suppressedFindingInstances?: number;
    expectations?: {
      minimumDetectedObservations?: number;
      maximumPossibleObservations?: number;
      minimumFindingInstances?: number;
      maximumFindingInstances?: number;
    };
  };
}

export interface IncidentRegressionCase {
  id: string;
  family: string;
  ruleId: string;
  mechanismId: string;
  broken: {
    expectedMinimum: number;
    observed: number;
    outcome: 'detected' | 'missed' | 'not-evaluated';
  };
  fixed: {
    expectedMaximum: number;
    observed: number;
    outcome: 'silent' | 'regressed' | 'not-evaluated';
  };
  status: 'passed' | 'failed' | 'unsupported';
}

export interface AnalysisHealthRecord {
  schemaVersion: 1;
  runId: string;
  snapshotId: string;
  producer: {
    id: 'atlas/analysis-health';
    version: string;
  };
  catalogDigest: string;
  corpusDigest: string;
  status: 'complete' | 'incomplete';
  profilePatterns: AnalysisHealthPatternObservation[];
  rules: AnalysisRuleHealth[];
  incidents: IncidentRegressionCase[];
  recall: {
    /** Present on current records; identifies the bundled fixture tier measured here. */
    tier?: 'synthetic';
    numerator: number;
    denominator: number;
  };
  /** Present on current records; real-target results are intentionally stored in a separate report. */
  realTargetEvaluation?: {
    tier: 'real-target';
    result: 'not-recorded-in-run';
    reportContract: 'real-target-corpus-report.schema.json';
  };
  fixedCaseSilence: {
    numerator: number;
    denominator: number;
  };
}

export interface RunRecord {
  schemaVersion: 1;
  runId: string;
  snapshotId: string;
  targetId: string;
  profileId: string;
  profileDigest: string;
  tool: { name: 'atlas'; version: string };
  adapters: Array<{ id: string; version: string }>;
  discovery: {
    provider: 'git';
    version: string;
    digest: string;
    state: 'ready' | 'partial' | 'not-git' | 'unsupported';
  };
  analyses: string[];
  artifacts: string[];
  counts: {
    files: number;
    relationships: number;
    diagnostics: number;
    findings: number;
    findingInstances?: number;
  };
}

export interface ArtifactDigest {
  path: string;
  bytes: number;
  sha256: string;
}

export interface ArtifactManifest {
  schemaVersion: 1;
  runId: string;
  artifacts: ArtifactDigest[];
}

export interface ExecutionRecord {
  schemaVersion: 1;
  attemptId: string;
  runId?: string;
  targetPath: string;
  targetConfigPath: string;
  profilePath: string;
  startedAt: string;
  finishedAt: string;
  status: 'completed' | 'reused' | 'failed';
  error?: { code: string; message: string };
}

export interface QueryHit {
  kind: 'file' | 'relationship' | 'finding' | 'diagnostic';
  id: string;
  score: number;
  label: string;
  path?: string;
  evidence: EvidenceReference[];
}

export interface QueryResult {
  schemaVersion: 1;
  runId: string;
  snapshotId: string;
  query: string;
  hits: QueryHit[];
}

export interface MemoryLookupResult {
  schemaVersion: 1;
  targetId: string;
  runId: string;
  snapshotId: string;
  query: string;
  answer: {
    kind: 'matches' | 'abstention';
    text: string;
  };
  freshness: {
    status: 'current' | 'stale';
    currentSnapshotId: string;
    currentDiscoveryDigest: string;
    reasons: Array<'snapshot-bytes' | 'git-provenance'>;
    addedPaths: string[];
    changedPaths: string[];
    removedPaths: string[];
  };
  coverage: {
    files: number;
    relationships: number;
    findings: number;
    diagnostics: number;
    boundaryDiagnosticCodes: string[];
    unsupportedDiagnosticCodes: string[];
    discoveryState: 'ready' | 'partial' | 'not-git' | 'unsupported';
    discoveryDiagnosticCodes: string[];
  };
  authorization: {
    scope: 'registered-local-target';
    projectMemoryConsent: true;
    sourceContentIncluded: false;
    secretValuesCollected: false;
  };
  hits: QueryHit[];
  truncated: boolean;
}

export interface ReviewPacketFile {
  id: string;
  path: string;
  sha256: string;
  bytes: number;
}

export interface ReviewPacket {
  schemaVersion: 1;
  packetId: string;
  packetHash: string;
  campaignId: string;
  runId: string;
  snapshotId: string;
  purpose: string;
  state: 'queued';
  files: ReviewPacketFile[];
  estimatedInputTokens: number;
  requiredResultFields: string[];
}

export type ReviewSelectionKind = 'all' | 'findings' | 'paths' | 'symbols' | 'diff' | 'neighborhood';

export interface ReviewSelectionSpec {
  selectors?: string[];
  depth?: number;
  direction?: 'incoming' | 'outgoing' | 'both';
  baselineRunId?: string;
  baselineSnapshotId?: string;
  incrementalPlanId?: string;
}

export interface ReviewCampaign {
  schemaVersion: 1;
  campaignId: string;
  runId: string;
  snapshotId: string;
  purpose: string;
  state: 'queued';
  selection: ReviewSelectionKind;
  selectionSpec?: ReviewSelectionSpec;
  batchSize: number;
  packetIds: string[];
  fileCount: number;
  estimatedInputTokens: number;
}

export interface AnalysisFile {
  record: FileRecord;
  content: Buffer;
}

export interface ScannedFile extends AnalysisFile {
  absolutePath: string;
  observedMtimeMs: number;
}

export interface ScanResult {
  runDirectory: string;
  attemptPath: string;
  run: RunRecord;
  reused: boolean;
}
