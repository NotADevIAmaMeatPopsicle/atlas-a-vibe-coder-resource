export const REVIEW_EXECUTION_VERSION = '1.0.0' as const;
export const MAX_REVIEW_RESULT_INPUT_BYTES = 4 * 1024 * 1024;

export type ReviewExecutionState = 'pending' | 'running' | 'completed' | 'failed' | 'paused';
export type ReviewPacketExecutionState = 'pending' | 'running' | 'completed' | 'failed';

export interface ReviewBudgetLimits {
  maxPackets: number;
  maxCalls: number;
  maxTokens: number;
  maxTimeMs: number;
}

export interface ReviewBudgetUse {
  packets: number;
  calls: number;
  tokens: number;
  timeMs: number;
}

export interface ReviewReviewer {
  kind: 'human' | 'agent';
  identity: string;
  version: string;
  promptVersion: string;
}

export interface ReviewReservation {
  tokenLimit: number;
  timeLimitMs: number;
}

export interface ReviewUsage {
  inputTokens: number;
  outputTokens: number;
  durationMs: number;
}

export interface ReviewEvidenceFile {
  id: string;
  path: string;
  sha256: string;
  bytes: number;
}

interface ReviewEvidenceAnchorBase {
  fileId: string;
  path: string;
  sha256: string;
}

export type ReviewEvidenceAnchor = ReviewEvidenceAnchorBase & (
  { line: number; column: number } |
  { line?: never; column?: never }
);

export interface ReviewStatement {
  summary: string;
  confidence: 'confirmed' | 'high' | 'medium' | 'low' | 'unknown';
  evidence: ReviewEvidenceAnchor[];
}

export interface ReviewResult {
  schemaVersion: 1;
  resultId: string;
  executionId: string;
  runId: string;
  snapshotId: string;
  campaignId: string;
  packetId: string;
  packetHash: string;
  attemptId: string;
  reviewer: ReviewReviewer;
  evidenceFiles: ReviewEvidenceFile[];
  reviewedFiles: ReviewEvidenceFile[];
  responsibilities: ReviewStatement[];
  associations: ReviewStatement[];
  observed: ReviewStatement[];
  suspected: ReviewStatement[];
  needsRuntimeValidation: ReviewStatement[];
  unknowns: ReviewStatement[];
  usage: ReviewUsage;
}

export type ReviewResultInput = Omit<ReviewResult, 'schemaVersion' | 'resultId'>;

export interface ReviewExecutionAttempt {
  schemaVersion: 1;
  attemptId: string;
  executionId: string;
  campaignId: string;
  runId: string;
  snapshotId: string;
  packetId: string;
  packetHash: string;
  attemptNumber: number;
  previousAttemptId?: string;
  reviewer: ReviewReviewer;
  reservation: ReviewReservation;
  state: 'running' | 'completed' | 'failed';
  usage?: ReviewUsage;
  resultId?: string;
  failure?: { code: string; message: string };
  outcomeHash?: string;
}

export interface ReviewExecutionPacket {
  packetId: string;
  packetHash: string;
  estimatedInputTokens: number;
  state: ReviewPacketExecutionState;
  attemptIds: string[];
  resultId?: string;
}

export interface ReviewExecution {
  schemaVersion: 1;
  executionId: string;
  campaignId: string;
  runId: string;
  snapshotId: string;
  state: ReviewExecutionState;
  budgets: {
    limits: ReviewBudgetLimits;
    used: ReviewBudgetUse;
    reserved: { tokens: number; timeMs: number };
  };
  packets: ReviewExecutionPacket[];
  revision: number;
  pauseCount: number;
  resumeCount: number;
}

export interface ReviewExecutionRecords {
  directory: string;
  execution: ReviewExecution;
  attempts: ReviewExecutionAttempt[];
  results: ReviewResult[];
}

export interface ReviewExecutionVerification {
  status: 'passed';
  executionId: string;
  campaignId: string;
  runId: string;
  snapshotId: string;
  state: ReviewExecutionState;
  revision: number;
  packets: number;
  attempts: number;
  results: number;
  budgets: ReviewExecution['budgets'];
}
