import { randomUUID } from 'node:crypto';
import { link, lstat, mkdir, open, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { AtlasError } from '../errors.js';
import { reviewCampaignStatus } from '../reviews.js';
import { assertSchema } from '../schema-validator.js';
import { assertPortableDataSafe } from '../security/portable-data.js';
import { verifyTargetRegistrationBinding } from '../targets.js';
import type { ExecutionRecord, ReviewCampaign, ReviewPacket, TargetConfig } from '../types.js';
import { canonicalJson, compareCanonicalText, prettyCanonicalJson, sha256 } from '../util/canonical.js';
import { isInside, resolveForContainment } from '../util/paths.js';
import type {
  ReviewBudgetLimits,
  ReviewEvidenceFile,
  ReviewExecution,
  ReviewExecutionAttempt,
  ReviewExecutionRecords,
  ReviewExecutionVerification,
  ReviewResult,
  ReviewResultInput,
  ReviewReviewer,
  ReviewUsage
} from './types.js';

export * from './types.js';

interface CampaignContext {
  campaignDirectory: string;
  workspacePath: string;
  targetRoot: string;
  targetConfigPath: string;
  campaign: ReviewCampaign;
  packets: ReviewPacket[];
}

interface LoadedExecution extends ReviewExecutionRecords {
  context: CampaignContext;
  attemptById: Map<string, ReviewExecutionAttempt>;
  resultByPacketId: Map<string, ReviewResult>;
  storageParent: string;
}

interface ExecutionLocation {
  directory: string;
  storageParent: string;
  campaignId: string;
  context: CampaignContext;
}

type TransactionOperationKind = 'attempt' | 'result' | 'execution';

interface ReviewExecutionTransactionOperation {
  kind: TransactionOperationKind;
  recordId: string;
  expectedHash: string | null;
  pre: string | null;
  postHash: string;
  post: string;
}

interface ReviewExecutionTransaction {
  schemaVersion: 1;
  transactionId: string;
  transactionNonce: string;
  executionId: string;
  campaignId: string;
  fromRevision: number;
  toRevision: number;
  operations: ReviewExecutionTransactionOperation[];
}

interface TransitionWrite {
  kind: Exclude<TransactionOperationKind, 'execution'>;
  recordId: string;
  before: ReviewExecutionAttempt | ReviewResult | null;
  after: ReviewExecutionAttempt | ReviewResult;
}

const RESULT_FILE_LIMIT = 500;
const RESULT_STATEMENT_LIMIT = 1000;
const RESULT_ANCHOR_LIMIT = 10000;
const RESULT_SUMMARY_BYTES_LIMIT = 1024 * 1024;
const RESULT_CANONICAL_BYTES_LIMIT = 2 * 1024 * 1024;
const EXECUTION_CANONICAL_BYTES_LIMIT = 8 * 1024 * 1024;
const CAMPAIGN_PACKET_LIMIT = 512;
const ATTEMPT_RECEIPT_LIMIT = 4096;
const EXECUTION_ATTEMPT_LIMIT = 10000;
const AGGREGATE_INPUT_BYTES_LIMIT = 64 * 1024 * 1024;

interface ReadBudget {
  remainingBytes: number;
}

const RESULT_KEYS = [
  'executionId', 'runId', 'snapshotId', 'campaignId', 'packetId', 'packetHash', 'attemptId',
  'reviewer', 'evidenceFiles', 'reviewedFiles', 'responsibilities', 'associations', 'observed',
  'suspected', 'needsRuntimeValidation', 'unknowns', 'usage'
] as const;

function invalidResult(message: string): never {
  throw new AtlasError('REVIEW_RESULT_INVALID', message);
}

function objectRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResult(`${label} must be an object.`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidResult(`${label} must be a plain data object.`);
  return value as Record<string, unknown>;
}

function exactObjectKeys(record: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(record).sort(compareCanonicalText);
  const required = [...expected].sort(compareCanonicalText);
  if (!exactArray(actual, required)) invalidResult(`${label} has missing or unsupported fields.`);
}

function boundedObjectKeys(
  record: Record<string, unknown>,
  required: readonly string[],
  allowed: readonly string[],
  label: string
): void {
  const keys = Object.keys(record);
  if (required.some((key) => !Object.hasOwn(record, key)) || keys.some((key) => !allowed.includes(key))) {
    invalidResult(`${label} has missing or unsupported fields.`);
  }
}

function resultString(value: unknown, label: string, maximum = 10000): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum) {
    invalidResult(`${label} must be a non-empty string no longer than ${maximum} characters.`);
  }
  return value.normalize('NFC');
}

function resultInteger(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    invalidResult(`${label} must be a safe integer greater than or equal to ${minimum}.`);
  }
  return value;
}

function resultArray(value: unknown, label: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) invalidResult(`${label} must be an array with at most ${maximum} entries.`);
  return value;
}

async function exists(value: string): Promise<boolean> {
  try {
    await lstat(value);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function samePath(left: string, right: string): boolean {
  return path.relative(path.resolve(left), path.resolve(right)) === '';
}

function canonicalClone<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

function exactArray(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function safeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new AtlasError('REVIEW_BUDGET_INVALID', `${label} must be a non-negative safe integer.`);
}

function checkedSum(values: number[], label: string): number {
  let total = 0;
  for (const value of values) {
    safeInteger(value, label);
    total += value;
    if (!Number.isSafeInteger(total)) throw new AtlasError('REVIEW_BUDGET_INVALID', `${label} exceeds the safe integer range.`);
  }
  return total;
}

function normalizeReviewer(value: ReviewReviewer): ReviewReviewer {
  const record = objectRecord(value, 'reviewer');
  exactObjectKeys(record, ['kind', 'identity', 'version', 'promptVersion'], 'reviewer');
  if (record.kind !== 'human' && record.kind !== 'agent') invalidResult('reviewer.kind must be human or agent.');
  return {
    kind: record.kind,
    identity: resultString(record.identity, 'reviewer.identity', 256),
    version: resultString(record.version, 'reviewer.version', 256),
    promptVersion: resultString(record.promptVersion, 'reviewer.promptVersion', 256)
  };
}

function normalizeUsage(value: ReviewUsage): ReviewUsage {
  const record = objectRecord(value, 'usage');
  exactObjectKeys(record, ['inputTokens', 'outputTokens', 'durationMs'], 'usage');
  return {
    inputTokens: resultInteger(record.inputTokens, 'usage.inputTokens'),
    outputTokens: resultInteger(record.outputTokens, 'usage.outputTokens'),
    durationMs: resultInteger(record.durationMs, 'usage.durationMs')
  };
}

function sanitizeEvidenceFile(value: unknown, label: string): ReviewEvidenceFile {
  const record = objectRecord(value, label);
  exactObjectKeys(record, ['id', 'path', 'sha256', 'bytes'], label);
  return {
    id: resultString(record.id, `${label}.id`, 512),
    path: resultString(record.path, `${label}.path`, 4096),
    sha256: resultString(record.sha256, `${label}.sha256`, 64),
    bytes: resultInteger(record.bytes, `${label}.bytes`)
  };
}

function sanitizeResultInput(value: unknown): ReviewResultInput {
  const record = objectRecord(value, 'Review result input');
  exactObjectKeys(record, RESULT_KEYS, 'Review result input');
  const counters = { statements: 0, anchors: 0, summaryBytes: 0 };
  const statementArray = (raw: unknown, label: string): ReviewResult['responsibilities'] => resultArray(
    raw,
    label,
    RESULT_STATEMENT_LIMIT
  ).map((entry, index) => {
    counters.statements += 1;
    if (counters.statements > RESULT_STATEMENT_LIMIT) invalidResult(`Review result has more than ${RESULT_STATEMENT_LIMIT} statements in aggregate.`);
    const statementLabel = `${label}[${index}]`;
    const statement = objectRecord(entry, statementLabel);
    exactObjectKeys(statement, ['summary', 'confidence', 'evidence'], statementLabel);
    const summary = resultString(statement.summary, `${statementLabel}.summary`, 4000);
    counters.summaryBytes += Buffer.byteLength(summary, 'utf8');
    if (counters.summaryBytes > RESULT_SUMMARY_BYTES_LIMIT) invalidResult('Review result summaries exceed the aggregate byte limit.');
    if (typeof statement.confidence !== 'string' || !['confirmed', 'high', 'medium', 'low', 'unknown'].includes(statement.confidence)) {
      invalidResult(`${statementLabel}.confidence is unsupported.`);
    }
    const evidence = resultArray(statement.evidence, `${statementLabel}.evidence`, 1000).map((anchorEntry, anchorIndex) => {
      counters.anchors += 1;
      if (counters.anchors > RESULT_ANCHOR_LIMIT) invalidResult(`Review result has more than ${RESULT_ANCHOR_LIMIT} evidence anchors in aggregate.`);
      const anchorLabel = `${statementLabel}.evidence[${anchorIndex}]`;
      const anchor = objectRecord(anchorEntry, anchorLabel);
      boundedObjectKeys(anchor, ['fileId', 'path', 'sha256'], ['fileId', 'path', 'sha256', 'line', 'column'], anchorLabel);
      if (Object.hasOwn(anchor, 'line') !== Object.hasOwn(anchor, 'column')) invalidResult(`${anchorLabel} must include line and column together.`);
      return {
        fileId: resultString(anchor.fileId, `${anchorLabel}.fileId`, 512),
        path: resultString(anchor.path, `${anchorLabel}.path`, 4096),
        sha256: resultString(anchor.sha256, `${anchorLabel}.sha256`, 64),
        ...(Object.hasOwn(anchor, 'line') ? {
          line: resultInteger(anchor.line, `${anchorLabel}.line`, 1),
          column: resultInteger(anchor.column, `${anchorLabel}.column`, 1)
        } : {})
      };
    });
    return {
      summary,
      confidence: statement.confidence as ReviewResult['responsibilities'][number]['confidence'],
      evidence
    };
  });
  const fileArray = (raw: unknown, label: string): ReviewEvidenceFile[] => resultArray(raw, label, RESULT_FILE_LIMIT)
    .map((entry, index) => sanitizeEvidenceFile(entry, `${label}[${index}]`));
  const result: ReviewResultInput = {
    executionId: resultString(record.executionId, 'executionId', 256),
    runId: resultString(record.runId, 'runId', 256),
    snapshotId: resultString(record.snapshotId, 'snapshotId', 256),
    campaignId: resultString(record.campaignId, 'campaignId', 256),
    packetId: resultString(record.packetId, 'packetId', 256),
    packetHash: resultString(record.packetHash, 'packetHash', 64),
    attemptId: resultString(record.attemptId, 'attemptId', 256),
    reviewer: normalizeReviewer(record.reviewer as ReviewReviewer),
    evidenceFiles: fileArray(record.evidenceFiles, 'evidenceFiles'),
    reviewedFiles: fileArray(record.reviewedFiles, 'reviewedFiles'),
    responsibilities: statementArray(record.responsibilities, 'responsibilities'),
    associations: statementArray(record.associations, 'associations'),
    observed: statementArray(record.observed, 'observed'),
    suspected: statementArray(record.suspected, 'suspected'),
    needsRuntimeValidation: statementArray(record.needsRuntimeValidation, 'needsRuntimeValidation'),
    unknowns: statementArray(record.unknowns, 'unknowns'),
    usage: normalizeUsage(record.usage as ReviewUsage)
  };
  if (Buffer.byteLength(canonicalJson(result), 'utf8') > RESULT_CANONICAL_BYTES_LIMIT) {
    invalidResult('Review result exceeds the canonical serialized byte limit.');
  }
  return result;
}

function normalizeFailure(value: unknown): { code: string; message: string } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new AtlasError('REVIEW_FAILURE_INVALID', 'Review failure must be a plain object.');
  }
  const record = value as Record<string, unknown>;
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new AtlasError('REVIEW_FAILURE_INVALID', 'Review failure must be a plain data object.');
  }
  const keys = Object.keys(record).sort(compareCanonicalText);
  if (!exactArray(keys, ['code', 'message'])) {
    throw new AtlasError('REVIEW_FAILURE_INVALID', 'Review failure requires only code and message.');
  }
  if (typeof record.code !== 'string' || typeof record.message !== 'string') {
    throw new AtlasError('REVIEW_FAILURE_INVALID', 'Review failure code and message must be strings.');
  }
  return { code: record.code.normalize('NFC'), message: record.message.normalize('NFC') };
}

function executionIdentity(campaign: ReviewCampaign, limits: ReviewBudgetLimits): string {
  return `review_execution_${sha256(canonicalJson({
    domain: 'atlas.review-execution.v1',
    campaignId: campaign.campaignId,
    runId: campaign.runId,
    snapshotId: campaign.snapshotId,
    limits
  }))}`;
}

function attemptIdentity(attempt: Omit<ReviewExecutionAttempt, 'attemptId' | 'schemaVersion' | 'state'>): string {
  return `review_attempt_${sha256(canonicalJson({ domain: 'atlas.review-attempt.v1', ...attempt }))}`;
}

function resultIdentity(result: Omit<ReviewResult, 'resultId'>): string {
  return `review_result_${sha256(canonicalJson({ domain: 'atlas.review-result.v1', ...result }))}`;
}

function terminalOutcomeHash(attempt: ReviewExecutionAttempt): string {
  if (attempt.state === 'running' || !attempt.usage) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Only a terminal attempt has an outcome hash.');
  }
  return sha256(canonicalJson({
    domain: 'atlas.review-attempt-outcome.v1',
    attemptId: attempt.attemptId,
    state: attempt.state,
    usage: attempt.usage,
    resultId: attempt.resultId ?? null,
    failure: attempt.failure ?? null
  }));
}

async function readCanonicalSchema<T>(
  filePath: string,
  schema: string,
  label: string,
  maximumBytes = 16 * 1024 * 1024,
  budget?: ReadBudget
): Promise<T> {
  const metadata = await lstat(filePath);
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes ||
    (budget && metadata.size > budget.remainingBytes)
  ) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} is not a bounded regular file.`);
  }
  const content = await readFile(filePath, 'utf8');
  const contentBytes = Buffer.byteLength(content, 'utf8');
  if (contentBytes > maximumBytes || (budget && contentBytes > budget.remainingBytes)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} exceeded its read budget.`);
  }
  if (budget) budget.remainingBytes -= contentBytes;
  let value: T;
  try {
    value = JSON.parse(content) as T;
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} is not valid JSON.`);
  }
  await assertSchema(schema, value, label);
  if (content !== prettyCanonicalJson(value)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} is not canonically serialized.`);
  return value;
}

async function readBoundedSchema<T>(filePath: string, schema: string, label: string, maximumBytes: number): Promise<T> {
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} is not a bounded regular file.`);
  }
  const content = await readFile(filePath, 'utf8');
  if (Buffer.byteLength(content, 'utf8') > maximumBytes) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} exceeded its read budget.`);
  }
  let value: T;
  try {
    value = JSON.parse(content) as T;
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `${label} is not valid JSON.`);
  }
  await assertSchema(schema, value, label);
  return value;
}

async function safeRemoveTemporary(parent: string, candidate: string, prefix: string): Promise<void> {
  if (path.dirname(candidate) !== parent || !path.basename(candidate).startsWith(prefix) || samePath(parent, candidate)) {
    throw new AtlasError('UNSAFE_TEMP_PATH', 'Refusing to remove an unsafe review-execution temporary path.');
  }
  await rm(candidate, { recursive: true, force: true });
}

async function assertWriteScope(storageParent: string, executionDirectory: string, destination: string): Promise<void> {
  const [canonicalStorageParent, canonicalExecutionDirectory, canonicalDestinationParent] = await Promise.all([
    realpath(storageParent),
    realpath(executionDirectory),
    realpath(path.dirname(destination))
  ]);
  if (
    !samePath(canonicalStorageParent, storageParent) ||
    !samePath(canonicalExecutionDirectory, executionDirectory) ||
    !samePath(path.dirname(canonicalExecutionDirectory), canonicalStorageParent) ||
    !samePath(path.dirname(path.resolve(destination)), canonicalDestinationParent) ||
    !isInside(canonicalExecutionDirectory, destination)
  ) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Review execution write destination is outside its canonical external store.');
  }
  const allowedParents = [
    canonicalExecutionDirectory,
    path.join(canonicalExecutionDirectory, 'attempts'),
    path.join(canonicalExecutionDirectory, 'results')
  ];
  if (!allowedParents.some((candidate) => samePath(candidate, canonicalDestinationParent))) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Review execution write destination is not an allowed artifact path.');
  }
  const [storageMetadata, executionMetadata, parentMetadata] = await Promise.all([
    lstat(canonicalStorageParent),
    lstat(canonicalExecutionDirectory),
    lstat(canonicalDestinationParent)
  ]);
  if (
    !storageMetadata.isDirectory() || storageMetadata.isSymbolicLink() ||
    !executionMetadata.isDirectory() || executionMetadata.isSymbolicLink() ||
    !parentMetadata.isDirectory() || parentMetadata.isSymbolicLink()
  ) throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Review execution write path traverses an invalid directory.');
  if (await exists(destination)) {
    const destinationMetadata = await lstat(destination);
    if (!destinationMetadata.isFile() || destinationMetadata.isSymbolicLink()) {
      throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution destination must be a regular file.');
    }
  }
}

async function syncDirectory(directory: string): Promise<void> {
  let handle;
  try {
    handle = await open(directory, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EINVAL', 'EPERM', 'EISDIR', 'ENOTSUP'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
  } finally {
    await handle?.close();
  }
}

async function atomicWriteText(
  storageParent: string,
  executionDirectory: string,
  destination: string,
  content: string
): Promise<void> {
  await assertWriteScope(storageParent, executionDirectory, destination);
  const temporaryPath = path.join(storageParent, `.review-write-${randomUUID().replaceAll('-', '')}`);
  try {
    await writeFile(temporaryPath, content, { encoding: 'utf8', flag: 'wx', flush: true });
    await assertWriteScope(storageParent, executionDirectory, destination);
    await rename(temporaryPath, destination);
    await syncDirectory(path.dirname(destination));
  } finally {
    await assertCanonicalStorageParent(storageParent);
    if (await exists(temporaryPath)) await rm(temporaryPath, { force: true });
  }
}

async function assertCanonicalStorageParent(storageParent: string): Promise<void> {
  const metadata = await lstat(storageParent);
  const canonical = await realpath(storageParent);
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() ||
    !samePath(storageParent, canonical) || path.basename(storageParent) !== 'review-executions'
  ) throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Review execution storage parent is no longer a canonical directory.');
}

async function withCampaignLock<T>(storageParent: string, campaignId: string, action: () => Promise<T>): Promise<T> {
  const lockPath = path.join(storageParent, `.review-lock-${campaignId}`);
  const recoveryPath = path.join(storageParent, `.review-lock-recovery-${campaignId}`);
  const ownerToken = randomUUID().replaceAll('-', '');
  const ownerRecord = `${process.pid}:${ownerToken}\n`;
  const releaseOwnedFile = async (filePath: string, expected: string): Promise<void> => {
    await assertCanonicalStorageParent(storageParent);
    let observed: string;
    try {
      observed = await readFile(filePath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw error;
    }
    if (observed !== expected) {
      throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Review execution lock ownership changed unexpectedly.');
    }
    await rm(filePath, { force: false });
  };
  const tryDirectAcquire = async (): Promise<boolean> => {
    await assertCanonicalStorageParent(storageParent);
    try {
      await writeFile(lockPath, ownerRecord, { encoding: 'utf8', flag: 'wx' });
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw error;
    }
  };
  const acquire = async (): Promise<void> => {
    if (await tryDirectAcquire()) return;
    const recoveryToken = `${process.pid}:${randomUUID().replaceAll('-', '')}\n`;
    try {
      await assertCanonicalStorageParent(storageParent);
      await writeFile(recoveryPath, recoveryToken, { encoding: 'utf8', flag: 'wx' });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Another local operation is inspecting this review execution lock.');
      }
      throw error;
    }
    try {
      let observed: string;
      try {
        observed = await readFile(lockPath, 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT' && await tryDirectAcquire()) return;
        throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Review execution lock cannot be safely inspected.');
      }
      const match = /^([1-9][0-9]*):([a-f0-9]{32})\n$/.exec(observed);
      if (!match) throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Review execution lock is malformed and requires operator inspection.');
      const ownerPid = Number(match[1]);
      if (!Number.isSafeInteger(ownerPid)) throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Review execution lock owner is invalid.');
      let ownerAlive = true;
      try {
        process.kill(ownerPid, 0);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ESRCH') ownerAlive = false;
      }
      if (ownerAlive) throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Another local operation is updating this review execution.');
      const confirmed = await readFile(lockPath, 'utf8');
      if (confirmed !== observed) throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Review execution lock changed during stale-owner inspection.');
      await assertCanonicalStorageParent(storageParent);
      await rm(lockPath, { force: false });
      if (!await tryDirectAcquire()) {
        throw new AtlasError('REVIEW_EXECUTION_BUSY', 'Another local operation acquired the recovered review execution lock.');
      }
    } finally {
      await releaseOwnedFile(recoveryPath, recoveryToken);
    }
  };
  await acquire();
  try {
    return await action();
  } finally {
    await releaseOwnedFile(lockPath, ownerRecord);
  }
}

async function attemptTargetBinding(workspacePath: string, runId: string): Promise<{
  targetRoot: string;
  targetConfigPath: string;
}> {
  const attemptsDirectory = path.join(workspacePath, 'attempts');
  let entries;
  let metadata;
  try {
    metadata = await lstat(attemptsDirectory);
    entries = await readdir(attemptsDirectory, { withFileTypes: true });
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Review workspace has no readable scan-attempt ledger.');
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || entries.some((entry) => !entry.isFile() || entry.isSymbolicLink())) {
    throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Scan-attempt ledger must contain only regular files.');
  }
  if (entries.length > ATTEMPT_RECEIPT_LIMIT) {
    throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Scan-attempt ledger exceeds the bounded receipt limit.');
  }
  const bindings: Array<{ targetRoot: string; targetConfigPath: string }> = [];
  const receiptBudget: ReadBudget = { remainingBytes: AGGREGATE_INPUT_BYTES_LIMIT };
  for (const entry of entries.sort((left, right) => compareCanonicalText(left.name, right.name))) {
    if (!entry.name.endsWith('.json')) throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', `Unexpected scan-attempt entry: ${entry.name}`);
    const receipt = await readCanonicalSchema<ExecutionRecord>(
      path.join(attemptsDirectory, entry.name),
      'attempt',
      `Scan attempt ${entry.name}`,
      256 * 1024,
      receiptBudget
    );
    if (entry.name !== `${receipt.attemptId}.json`) throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Scan-attempt filename and identity differ.');
    if ((receipt.status !== 'completed' && receipt.status !== 'reused') || receipt.runId !== runId) continue;
    if (!path.isAbsolute(receipt.targetPath) || !path.isAbsolute(receipt.targetConfigPath)) {
      throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Successful scan attempt has a non-absolute target binding.');
    }
    const targetRoot = await realpath(receipt.targetPath);
    if (!samePath(targetRoot, receipt.targetPath) || !(await lstat(targetRoot)).isDirectory()) {
      throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Successful scan attempt target binding is no longer canonical.');
    }
    let targetConfigPath = path.resolve(receipt.targetConfigPath);
    try {
      targetConfigPath = await realpath(targetConfigPath);
    } catch {
      // Read/verify remain available after descriptor removal; start/retry recheck it below.
    }
    bindings.push({ targetRoot, targetConfigPath });
  }
  if (!bindings.length) throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'No successful scan attempt binds this campaign run to a target.');
  const binding = bindings[0]!;
  if (bindings.some((candidate) => (
    !samePath(candidate.targetRoot, binding.targetRoot) ||
    !samePath(candidate.targetConfigPath, binding.targetConfigPath)
  ))) {
    throw new AtlasError('REVIEW_EXECUTION_TARGET_MISMATCH', 'Successful scan attempts conflict on the campaign target binding.');
  }
  return binding;
}

function staleError(error: unknown): AtlasError {
  const message = error instanceof Error ? error.message : String(error);
  return new AtlasError('REVIEW_RESULT_STALE', `The exact canonical run or campaign bound to this result is no longer verifiable: ${message}`);
}

async function campaignContext(campaignDirectoryValue: string, staleOnFailure: boolean): Promise<CampaignContext> {
  const requested = path.resolve(campaignDirectoryValue);
  let metadata;
  try {
    metadata = await lstat(requested);
  } catch (error) {
    if (staleOnFailure) throw staleError(error);
    throw error;
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign path must be a real directory.');
  const campaignDirectory = await realpath(requested);
  try {
    const readSnapshot = async (): Promise<{ campaign: ReviewCampaign; packets: ReviewPacket[] }> => {
      const campaignBudget: ReadBudget = { remainingBytes: AGGREGATE_INPUT_BYTES_LIMIT };
      const campaign = await readCanonicalSchema<ReviewCampaign>(
        path.join(campaignDirectory, 'campaign.json'),
        'review-campaign',
        'Review campaign',
        4 * 1024 * 1024,
        campaignBudget
      );
      if (campaign.packetIds.length > CAMPAIGN_PACKET_LIMIT) {
        throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Review campaign exceeds the bounded packet limit.');
      }
      const packets: ReviewPacket[] = [];
      for (const packetId of campaign.packetIds) {
        packets.push(await readCanonicalSchema<ReviewPacket>(
          path.join(campaignDirectory, 'packets', `${packetId}.json`),
          'review-packet',
          `Review packet ${packetId}`,
          4 * 1024 * 1024,
          campaignBudget
        ));
      }
      return { campaign, packets };
    };
    const before = await readSnapshot();
    const workspacePath = path.resolve(campaignDirectory, '..', '..');
    if (!samePath(campaignDirectory, path.join(workspacePath, 'reviews', before.campaign.campaignId))) {
      throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign is not in its canonical workspace location.');
    }
    const verified = await reviewCampaignStatus(campaignDirectory) as { campaign?: unknown };
    const after = await readSnapshot();
    if (
      !verified || typeof verified !== 'object' ||
      !exactArray(before.campaign, verified.campaign) ||
      !exactArray(before, after)
    ) {
      throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign artifacts changed while their canonical run binding was verified.');
    }
    const binding = await attemptTargetBinding(workspacePath, after.campaign.runId);
    if (isInside(binding.targetRoot, workspacePath)) {
      throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Review execution workspace must be outside the scanned target repository.');
    }
    return {
      campaignDirectory,
      workspacePath,
      targetRoot: binding.targetRoot,
      targetConfigPath: binding.targetConfigPath,
      campaign: after.campaign,
      packets: after.packets
    };
  } catch (error) {
    if (staleOnFailure && !(error instanceof AtlasError && error.code === 'WORKSPACE_INSIDE_TARGET')) throw staleError(error);
    throw error;
  }
}

async function assertCurrentReviewConsent(context: CampaignContext): Promise<void> {
  let targetConfigPath: string;
  try {
    targetConfigPath = await realpath(context.targetConfigPath);
  } catch {
    throw new AtlasError('AGENT_REVIEW_NOT_AUTHORIZED', 'The target descriptor bound to this campaign is missing or unreadable.');
  }
  if (!samePath(targetConfigPath, context.targetConfigPath)) {
    throw new AtlasError('TARGET_MISMATCH', 'The target descriptor no longer matches the successful scan binding.');
  }
  const metadata = await lstat(targetConfigPath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new AtlasError('TARGET_MISMATCH', 'The target descriptor must remain a regular file.');
  }
  const target = await readBoundedSchema<TargetConfig>(
    targetConfigPath,
    'target',
    'Target configuration',
    1024 * 1024
  );
  const configuredPath = path.isAbsolute(target.path)
    ? target.path
    : path.resolve(path.dirname(targetConfigPath), target.path);
  const targetRoot = await realpath(configuredPath);
  if (!samePath(targetRoot, context.targetRoot)) {
    throw new AtlasError('TARGET_MISMATCH', 'The target descriptor root no longer matches the campaign target.');
  }
  await verifyTargetRegistrationBinding({
    workspacePath: context.workspacePath,
    targetId: target.id,
    targetRoot,
    targetConfigPath,
    consent: target.consent
  });
  if (!target.consent.agentReview) {
    throw new AtlasError('AGENT_REVIEW_NOT_AUTHORIZED', 'Target consent.agentReview must remain true before starting or retrying review work.');
  }
}

function transactionIdentity(transaction: Omit<ReviewExecutionTransaction, 'transactionId'>): string {
  return `review_transaction_${sha256(canonicalJson({ domain: 'atlas.review-execution-transaction.v1', ...transaction }))}`;
}

function transactionPath(location: ExecutionLocation): string {
  return path.join(location.storageParent, `.review-transaction-${location.campaignId}.json`);
}

function operationDestination(location: ExecutionLocation, operation: ReviewExecutionTransactionOperation): string {
  if (operation.kind === 'execution' && operation.recordId === 'execution') {
    return path.join(location.directory, 'execution.json');
  }
  if (operation.kind === 'attempt' && /^review_attempt_[a-f0-9]{64}$/.test(operation.recordId)) {
    return path.join(location.directory, 'attempts', `${operation.recordId}.json`);
  }
  if (operation.kind === 'result' && /^packet_[a-f0-9]{64}$/.test(operation.recordId)) {
    return path.join(location.directory, 'results', `${operation.recordId}.json`);
  }
  throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction contains an invalid typed destination.');
}

async function resolveExecutionLocation(directoryValue: string): Promise<ExecutionLocation> {
  const requested = path.resolve(directoryValue);
  let metadata;
  try {
    metadata = await lstat(requested);
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_MISSING', 'Review execution directory is missing or unreadable.');
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution path must be a real directory.');
  }
  const directory = await realpath(requested);
  if (!samePath(directory, requested)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution path is not canonical.');
  const storageParent = path.dirname(directory);
  const workspacePath = path.dirname(storageParent);
  const campaignId = path.basename(directory);
  if (path.basename(storageParent) !== 'review-executions' || !/^campaign_[a-f0-9]{64}$/.test(campaignId)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution is not in a canonical campaign-scoped store.');
  }
  const [storageMetadata, canonicalStorageParent] = await Promise.all([lstat(storageParent), realpath(storageParent)]);
  if (!storageMetadata.isDirectory() || storageMetadata.isSymbolicLink() || !samePath(storageParent, canonicalStorageParent)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution store is not a canonical directory.');
  }
  const context = await campaignContext(path.join(workspacePath, 'reviews', campaignId), true);
  if (
    !samePath(context.workspacePath, workspacePath) ||
    !isInside(workspacePath, storageParent) ||
    isInside(context.targetRoot, storageParent)
  ) throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Review execution store is not in its canonical external workspace.');
  return { directory, storageParent, campaignId, context };
}

function operationPostValue(operation: ReviewExecutionTransactionOperation): unknown {
  let value: unknown;
  try {
    value = JSON.parse(operation.post) as unknown;
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction post-image is not valid JSON.');
  }
  if (operation.post !== prettyCanonicalJson(value) || sha256(operation.post) !== operation.postHash) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction post-image is not canonical or does not match its hash.');
  }
  return value;
}

function operationPreValue(operation: ReviewExecutionTransactionOperation): unknown | null {
  if (operation.pre === null) {
    if (operation.expectedHash !== null) {
      throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction absent pre-image has a non-null expected hash.');
    }
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(operation.pre) as unknown;
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction pre-image is not valid JSON.');
  }
  if (
    operation.expectedHash === null ||
    operation.pre !== prettyCanonicalJson(value) ||
    sha256(operation.pre) !== operation.expectedHash
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction pre-image is not canonical or does not match its hash.');
  return value;
}

async function validateTransaction(
  location: ExecutionLocation,
  transaction: ReviewExecutionTransaction
): Promise<ReviewExecution> {
  await assertSchema('review-execution-transaction', transaction, 'Review execution transaction');
  const { transactionId: _transactionId, ...material } = transaction;
  if (transaction.transactionId !== transactionIdentity(material)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction identity does not match its canonical content.');
  }
  if (
    transaction.campaignId !== location.campaignId ||
    transaction.toRevision !== transaction.fromRevision + 1
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction revision or campaign binding is invalid.');
  const operationKeys = transaction.operations.map((operation) => `${operation.kind}:${operation.recordId}`);
  if (new Set(operationKeys).size !== operationKeys.length) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction contains duplicate destinations.');
  }
  const executionOperations = transaction.operations.filter((operation) => operation.kind === 'execution');
  if (
    executionOperations.length !== 1 ||
    transaction.operations.filter((operation) => operation.kind === 'attempt').length > 1 ||
    transaction.operations.filter((operation) => operation.kind === 'result').length > 1 ||
    transaction.operations.at(-1)?.kind !== 'execution'
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction must contain one final execution operation.');
  let postExecution: ReviewExecution | undefined;
  let preExecution: ReviewExecution | undefined;
  for (const operation of transaction.operations) {
    operationDestination(location, operation);
    const preValue = operationPreValue(operation);
    const value = operationPostValue(operation);
    if (preValue !== null) assertPortableDataSafe(preValue, 'Review transaction pre-image');
    assertPortableDataSafe(value, 'Review transaction post-image');
    if (operation.kind === 'execution') {
      if (preValue === null) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution transaction requires a pre-image.');
      await assertSchema('review-execution', preValue, 'Review transaction execution pre-image');
      await assertSchema('review-execution', value, 'Review transaction execution post-image');
      preExecution = preValue as ReviewExecution;
      postExecution = value as ReviewExecution;
      if (operation.recordId !== 'execution') throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution operation identity is invalid.');
    } else if (operation.kind === 'attempt') {
      if (preValue !== null) {
        await assertSchema('review-execution-attempt', preValue, 'Review transaction attempt pre-image');
        if ((preValue as ReviewExecutionAttempt).attemptId !== operation.recordId) {
          throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Attempt transaction pre-image and destination differ.');
        }
      }
      await assertSchema('review-execution-attempt', value, 'Review transaction attempt post-image');
      if ((value as ReviewExecutionAttempt).attemptId !== operation.recordId) {
        throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Attempt transaction destination and identity differ.');
      }
    } else {
      if (preValue !== null) {
        await assertSchema('review-result', preValue, 'Review transaction result pre-image');
        validateResultResourceBounds(preValue as ReviewResult);
        if ((preValue as ReviewResult).packetId !== operation.recordId) {
          throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result transaction pre-image and destination differ.');
        }
      }
      await assertSchema('review-result', value, 'Review transaction result post-image');
      validateResultResourceBounds(value as ReviewResult);
      if ((value as ReviewResult).packetId !== operation.recordId) {
        throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result transaction destination and packet identity differ.');
      }
    }
  }
  if (
    !preExecution || !postExecution ||
    preExecution.executionId !== transaction.executionId ||
    preExecution.campaignId !== transaction.campaignId ||
    preExecution.runId !== location.context.campaign.runId ||
    preExecution.snapshotId !== location.context.campaign.snapshotId ||
    preExecution.revision !== transaction.fromRevision ||
    preExecution.executionId !== executionIdentity(location.context.campaign, preExecution.budgets.limits) ||
    !exactArray(preExecution.budgets.limits, postExecution.budgets.limits) ||
    postExecution.executionId !== transaction.executionId ||
    postExecution.campaignId !== transaction.campaignId ||
    postExecution.runId !== location.context.campaign.runId ||
    postExecution.snapshotId !== location.context.campaign.snapshotId ||
    postExecution.revision !== transaction.toRevision ||
    postExecution.executionId !== executionIdentity(location.context.campaign, postExecution.budgets.limits)
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction post-state is not bound to the exact canonical campaign.');
  return postExecution;
}

async function readLooseLedger(location: ExecutionLocation): Promise<{
  attempts: Array<{ name: string; value: ReviewExecutionAttempt }>;
  results: Array<{ name: string; value: ReviewResult }>;
}> {
  const rootEntries = await readdir(location.directory, { withFileTypes: true });
  if (!exactArray(rootEntries.map((entry) => entry.name).sort(compareCanonicalText), ['attempts', 'execution.json', 'results'])) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution directory does not match the required artifact set.');
  }
  const executionEntry = rootEntries.find((entry) => entry.name === 'execution.json');
  const attemptsEntry = rootEntries.find((entry) => entry.name === 'attempts');
  const resultsEntry = rootEntries.find((entry) => entry.name === 'results');
  if (
    !executionEntry?.isFile() || executionEntry.isSymbolicLink() ||
    !attemptsEntry?.isDirectory() || attemptsEntry.isSymbolicLink() ||
    !resultsEntry?.isDirectory() || resultsEntry.isSymbolicLink()
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution artifacts have invalid filesystem types.');
  const attemptsDirectory = path.join(location.directory, 'attempts');
  const resultsDirectory = path.join(location.directory, 'results');
  const [attemptEntries, resultEntries] = await Promise.all([
    readdir(attemptsDirectory, { withFileTypes: true }),
    readdir(resultsDirectory, { withFileTypes: true })
  ]);
  if (attemptEntries.some((entry) => !entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith('.json'))) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Attempt ledger contains a non-canonical entry.');
  }
  if (resultEntries.some((entry) => !entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith('.json'))) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result store contains a non-canonical entry.');
  }
  if (attemptEntries.length > EXECUTION_ATTEMPT_LIMIT || resultEntries.length > CAMPAIGN_PACKET_LIMIT) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution artifact count exceeds its bounded limit.');
  }
  const ledgerBudget: ReadBudget = { remainingBytes: AGGREGATE_INPUT_BYTES_LIMIT };
  const attempts: Array<{ name: string; value: ReviewExecutionAttempt }> = [];
  for (const entry of attemptEntries.sort((left, right) => compareCanonicalText(left.name, right.name))) {
    attempts.push({
      name: entry.name,
      value: await readCanonicalSchema<ReviewExecutionAttempt>(
      path.join(attemptsDirectory, entry.name),
      'review-execution-attempt',
        `Review attempt ${entry.name}`,
        1024 * 1024,
        ledgerBudget
      )
    });
  }
  const results: Array<{ name: string; value: ReviewResult }> = [];
  for (const entry of resultEntries.sort((left, right) => compareCanonicalText(left.name, right.name))) {
    results.push({
      name: entry.name,
      value: await readCanonicalSchema<ReviewResult>(
      path.join(resultsDirectory, entry.name),
      'review-result',
      `Review result ${entry.name}`,
        4 * 1024 * 1024,
        ledgerBudget
      )
    });
  }
  return { attempts, results };
}

function validateTransitionDelta(transaction: ReviewExecutionTransaction): void {
  const executionOperation = transaction.operations.find((operation) => operation.kind === 'execution')!;
  const preExecution = operationPreValue(executionOperation) as ReviewExecution;
  const postExecution = operationPostValue(executionOperation) as ReviewExecution;
  const attemptOperation = transaction.operations.find((operation) => operation.kind === 'attempt');
  const resultOperation = transaction.operations.find((operation) => operation.kind === 'result');
  const reject = (): never => {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction does not encode one permitted deterministic state transition.');
  };
  if (!attemptOperation && !resultOperation) {
    const expected = canonicalClone(preExecution);
    if (
      preExecution.state !== 'paused' && postExecution.state === 'paused'
    ) {
      if (preExecution.state === 'running' || preExecution.state === 'completed') reject();
      expected.state = 'paused';
      expected.pauseCount += 1;
      expected.revision += 1;
    } else if (preExecution.state === 'paused' && postExecution.state !== 'paused') {
      expected.resumeCount += 1;
      expected.revision += 1;
      expected.state = expected.packets.some((packet) => packet.state === 'failed') ? 'failed' : 'pending';
    } else reject();
    if (!exactArray(expected, postExecution)) reject();
    return;
  }
  if (!attemptOperation) return reject();
  const preAttempt = operationPreValue(attemptOperation) as ReviewExecutionAttempt | null;
  const postAttempt = operationPostValue(attemptOperation) as ReviewExecutionAttempt;
  if (preAttempt === null) {
    if (resultOperation || postAttempt.state !== 'running') reject();
    const expected = canonicalClone(preExecution);
    const packet = expected.packets.find((candidate) => candidate.packetId === postAttempt.packetId);
    if (
      !packet ||
      !(
        (packet.state === 'pending' && preExecution.state === 'pending') ||
        (packet.state === 'failed' && preExecution.state === 'failed')
      )
    ) return reject();
    const firstPacketAttempt = packet.attemptIds.length === 0;
    packet.attemptIds.push(postAttempt.attemptId);
    packet.state = 'running';
    expected.state = 'running';
    expected.budgets.used.packets += firstPacketAttempt ? 1 : 0;
    expected.budgets.used.calls += 1;
    expected.budgets.reserved.tokens += postAttempt.reservation.tokenLimit;
    expected.budgets.reserved.timeMs += postAttempt.reservation.timeLimitMs;
    expected.revision += 1;
    if (!exactArray(expected, postExecution)) reject();
    return;
  }
  if (preAttempt.state !== 'running' || preAttempt.attemptId !== postAttempt.attemptId) reject();
  const expectedAttempt: ReviewExecutionAttempt = {
    ...canonicalClone(preAttempt),
    state: postAttempt.state,
    ...(postAttempt.usage ? { usage: postAttempt.usage } : {}),
    ...(postAttempt.resultId ? { resultId: postAttempt.resultId } : {}),
    ...(postAttempt.failure ? { failure: postAttempt.failure } : {}),
    ...(postAttempt.outcomeHash ? { outcomeHash: postAttempt.outcomeHash } : {})
  };
  if (!exactArray(expectedAttempt, postAttempt) || !postAttempt.usage) return reject();
  const usage = postAttempt.usage;
  const expected = canonicalClone(preExecution);
  applyTerminalUsage(expected, expectedAttempt, usage);
  const packet = expected.packets.find((candidate) => candidate.packetId === postAttempt.packetId);
  if (!packet) return reject();
  if (postAttempt.state === 'failed') {
    if (resultOperation || !postAttempt.failure || postAttempt.resultId) reject();
    packet.state = 'failed';
    expected.state = 'failed';
  } else if (postAttempt.state === 'completed') {
    if (!resultOperation || !postAttempt.resultId) return reject();
    if (operationPreValue(resultOperation) !== null) return reject();
    const result = operationPostValue(resultOperation) as ReviewResult;
    if (result.resultId !== postAttempt.resultId || result.packetId !== postAttempt.packetId) reject();
    packet.state = 'completed';
    packet.resultId = result.resultId;
    expected.state = expected.packets.every((candidate) => candidate.state === 'completed') ? 'completed' : 'pending';
  } else reject();
  expected.revision += 1;
  if (!exactArray(expected, postExecution)) reject();
}

async function validateTransactionCandidates(
  location: ExecutionLocation,
  transaction: ReviewExecutionTransaction
): Promise<void> {
  const current = await readLooseLedger(location);
  const preAttempts = new Map(current.attempts.map((record) => [record.name, record.value]));
  const postAttempts = new Map(current.attempts.map((record) => [record.name, record.value]));
  const preResults = new Map(current.results.map((record) => [record.name, record.value]));
  const postResults = new Map(current.results.map((record) => [record.name, record.value]));
  let preExecution: ReviewExecution | undefined;
  let postExecution: ReviewExecution | undefined;
  for (const operation of transaction.operations) {
    const pre = operationPreValue(operation);
    const post = operationPostValue(operation);
    if (operation.kind === 'execution') {
      preExecution = pre as ReviewExecution;
      postExecution = post as ReviewExecution;
      continue;
    }
    const name = `${operation.recordId}.json`;
    const preMap = operation.kind === 'attempt' ? preAttempts : preResults;
    const postMap = operation.kind === 'attempt' ? postAttempts : postResults;
    if (pre === null) preMap.delete(name);
    else preMap.set(name, pre as ReviewExecutionAttempt & ReviewResult);
    postMap.set(name, post as ReviewExecutionAttempt & ReviewResult);
  }
  if (!preExecution || !postExecution) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction is missing execution images.');
  const validateCandidate = (
    execution: ReviewExecution,
    attemptMap: Map<string, ReviewExecutionAttempt>,
    resultMap: Map<string, ReviewResult>
  ): void => {
    const attemptRecords = [...attemptMap.entries()].sort((left, right) => compareCanonicalText(left[0], right[0]));
    const resultRecords = [...resultMap.entries()].sort((left, right) => compareCanonicalText(left[0], right[0]));
    validateLedgerSemantics({
      execution,
      attempts: attemptRecords.map((record) => record[1]),
      results: resultRecords.map((record) => record[1]),
      attemptNames: attemptRecords.map((record) => record[0]),
      resultNames: resultRecords.map((record) => record[0]),
      context: location.context
    });
  };
  validateCandidate(preExecution, preAttempts, preResults);
  validateCandidate(postExecution, postAttempts, postResults);
  validateTransitionDelta(transaction);
}

async function destinationHash(destination: string): Promise<string | null> {
  let metadata;
  try {
    metadata = await lstat(destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction destination is not a regular file.');
  }
  return sha256(await readFile(destination, 'utf8'));
}

async function removeExactFile(filePath: string, expectedContent: string): Promise<void> {
  const observed = await readFile(filePath, 'utf8');
  if (observed !== expectedContent) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction ownership changed unexpectedly.');
  }
  await rm(filePath, { force: false });
  await syncDirectory(path.dirname(filePath));
}

async function recoverTransaction(location: ExecutionLocation): Promise<LoadedExecution | undefined> {
  const journal = transactionPath(location);
  if (!await exists(journal)) return undefined;
  const transaction = await readCanonicalSchema<ReviewExecutionTransaction>(
    journal,
    'review-execution-transaction',
    'Review execution transaction',
    64 * 1024 * 1024
  );
  const postExecution = await validateTransaction(location, transaction);
  const observed = new Map<string, string | null>();
  for (const operation of transaction.operations) {
    const destination = operationDestination(location, operation);
    await assertWriteScope(location.storageParent, location.directory, destination);
    const hash = await destinationHash(destination);
    if (hash !== operation.expectedHash && hash !== operation.postHash) {
      throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review transaction destination differs from both its pre-image and post-image.');
    }
    observed.set(`${operation.kind}:${operation.recordId}`, hash);
  }
  const startOperation = transaction.operations.find((operation) => operation.kind === 'attempt' && operation.pre === null);
  const transactionIncomplete = transaction.operations.some((operation) => (
    observed.get(`${operation.kind}:${operation.recordId}`) !== operation.postHash
  ));
  if (startOperation && transactionIncomplete) await assertCurrentReviewConsent(location.context);
  await validateTransactionCandidates(location, transaction);
  for (const operation of transaction.operations) {
    if (observed.get(`${operation.kind}:${operation.recordId}`) === operation.postHash) continue;
    await atomicWriteText(
      location.storageParent,
      location.directory,
      operationDestination(location, operation),
      operation.post
    );
  }
  const verified = await loadExecutionState(location.directory);
  if (
    verified.execution.executionId !== transaction.executionId ||
    verified.execution.revision !== transaction.toRevision ||
    !exactArray(verified.execution, postExecution)
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Recovered review transaction did not produce its exact verified post-state.');
  await removeExactFile(journal, prettyCanonicalJson(transaction));
  return verified;
}

function transitionOperation(
  kind: TransitionWrite['kind'],
  recordId: string,
  before: TransitionWrite['before'],
  after: TransitionWrite['after']
): ReviewExecutionTransactionOperation {
  const pre = before === null ? null : prettyCanonicalJson(before);
  const post = prettyCanonicalJson(after);
  return {
    kind,
    recordId,
    expectedHash: pre === null ? null : sha256(pre),
    pre,
    postHash: sha256(post),
    post
  };
}

async function publishJournal(location: ExecutionLocation, transaction: ReviewExecutionTransaction): Promise<void> {
  const journal = transactionPath(location);
  const content = prettyCanonicalJson(transaction);
  if (Buffer.byteLength(content, 'utf8') > 64 * 1024 * 1024) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution transaction exceeds its serialized byte limit.');
  }
  const temporaryPath = path.join(location.storageParent, `.review-transaction-tmp-${randomUUID().replaceAll('-', '')}`);
  try {
    await assertCanonicalStorageParent(location.storageParent);
    await writeFile(temporaryPath, content, { encoding: 'utf8', flag: 'wx', flush: true });
    try {
      await assertCanonicalStorageParent(location.storageParent);
      await link(temporaryPath, journal);
      await syncDirectory(location.storageParent);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new AtlasError('REVIEW_EXECUTION_BUSY', 'A review execution transaction is already pending recovery.');
      }
      throw error;
    }
  } finally {
    await assertCanonicalStorageParent(location.storageParent);
    if (await exists(temporaryPath)) await rm(temporaryPath, { force: true });
  }
}

async function commitTransition(
  loaded: LoadedExecution,
  writes: TransitionWrite[],
  execution: ReviewExecution
): Promise<LoadedExecution> {
  if (execution.revision !== loaded.execution.revision + 1) {
    throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Review execution transition must advance exactly one revision.');
  }
  assertPortableDataSafe({
    execution,
    records: writes.map((write) => write.after)
  }, 'Review execution transition');
  const operations = writes
    .map((write) => transitionOperation(write.kind, write.recordId, write.before, write.after))
    .sort((left, right) => {
      const rank = { result: 0, attempt: 1, execution: 2 } as const;
      return rank[left.kind] - rank[right.kind] || compareCanonicalText(left.recordId, right.recordId);
    });
  const executionPost = prettyCanonicalJson(execution);
  operations.push({
    kind: 'execution',
    recordId: 'execution',
    expectedHash: sha256(prettyCanonicalJson(loaded.execution)),
    pre: prettyCanonicalJson(loaded.execution),
    postHash: sha256(executionPost),
    post: executionPost
  });
  const material: Omit<ReviewExecutionTransaction, 'transactionId'> = {
    schemaVersion: 1,
    transactionNonce: randomUUID().replaceAll('-', ''),
    executionId: execution.executionId,
    campaignId: execution.campaignId,
    fromRevision: loaded.execution.revision,
    toRevision: execution.revision,
    operations
  };
  const transaction: ReviewExecutionTransaction = {
    ...material,
    transactionId: transactionIdentity(material)
  };
  const location = {
    directory: loaded.directory,
    storageParent: loaded.storageParent,
    campaignId: loaded.execution.campaignId,
    context: loaded.context
  } satisfies ExecutionLocation;
  await validateTransaction(location, transaction);
  await validateTransactionCandidates(location, transaction);
  await publishJournal(location, transaction);
  return (await recoverTransaction(location))!;
}

async function withLoadedExecution<T>(
  directoryValue: string,
  action: (loaded: LoadedExecution) => Promise<T>
): Promise<T> {
  const initialLocation = await resolveExecutionLocation(directoryValue);
  return withCampaignLock(initialLocation.storageParent, initialLocation.campaignId, async () => {
    const location = await resolveExecutionLocation(initialLocation.directory);
    if (
      !samePath(location.directory, initialLocation.directory) ||
      !samePath(location.storageParent, initialLocation.storageParent) ||
      location.campaignId !== initialLocation.campaignId
    ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution location changed while acquiring its lock.');
    await recoverTransaction(location);
    return action(await loadExecutionState(location.directory));
  });
}

async function loadExecution(directoryValue: string): Promise<LoadedExecution> {
  return withLoadedExecution(directoryValue, async (loaded) => loaded);
}

function budgetLimits(value: ReviewBudgetLimits): ReviewBudgetLimits {
  const limits = canonicalClone(value);
  safeInteger(limits.maxPackets, 'maxPackets');
  safeInteger(limits.maxCalls, 'maxCalls');
  safeInteger(limits.maxTokens, 'maxTokens');
  safeInteger(limits.maxTimeMs, 'maxTimeMs');
  if (limits.maxCalls > EXECUTION_ATTEMPT_LIMIT || limits.maxPackets > CAMPAIGN_PACKET_LIMIT) {
    throw new AtlasError('REVIEW_BUDGET_INVALID', 'Review packet/call budget exceeds the bounded execution-ledger capacity.');
  }
  return limits;
}

function evidenceFiles(packet: ReviewPacket): ReviewEvidenceFile[] {
  return packet.files.map((file) => ({ id: file.id, path: file.path, sha256: file.sha256, bytes: file.bytes }));
}

function allStatements(result: ReviewResult) {
  return [
    ...result.responsibilities,
    ...result.associations,
    ...result.observed,
    ...result.suspected,
    ...result.needsRuntimeValidation,
    ...result.unknowns
  ];
}

function validateResultResourceBounds(result: ReviewResult): void {
  const statements = allStatements(result);
  const anchors = statements.reduce((total, statement) => total + statement.evidence.length, 0);
  const summaryBytes = statements.reduce((total, statement) => total + Buffer.byteLength(statement.summary, 'utf8'), 0);
  if (
    statements.length > RESULT_STATEMENT_LIMIT ||
    anchors > RESULT_ANCHOR_LIMIT ||
    summaryBytes > RESULT_SUMMARY_BYTES_LIMIT ||
    Buffer.byteLength(canonicalJson(result), 'utf8') > RESULT_CANONICAL_BYTES_LIMIT
  ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Persisted review result exceeds canonical aggregate resource limits.');
}

function validateResultBinding(
  result: ReviewResult,
  execution: ReviewExecution,
  attempt: ReviewExecutionAttempt,
  packet: ReviewPacket
): void {
  if (
    result.executionId !== execution.executionId || result.runId !== execution.runId ||
    result.snapshotId !== execution.snapshotId || result.campaignId !== execution.campaignId ||
    result.packetId !== packet.packetId || result.packetHash !== packet.packetHash ||
    result.attemptId !== attempt.attemptId
  ) throw new AtlasError('REVIEW_RESULT_FORGED_TUPLE', 'Review result does not match its execution/run/campaign/packet/attempt tuple.');
  if (!exactArray(result.reviewer, attempt.reviewer)) {
    throw new AtlasError('REVIEW_RESULT_FORGED_TUPLE', 'Review result reviewer identity/version differs from the reserved attempt.');
  }
  const expectedFiles = evidenceFiles(packet);
  if (!exactArray(result.evidenceFiles, expectedFiles) || !exactArray(result.reviewedFiles, expectedFiles)) {
    throw new AtlasError('REVIEW_RESULT_FORGED_TUPLE', 'Review result evidence and reviewed-file tuples must exactly match the immutable packet.');
  }
  const fileById = new Map(expectedFiles.map((file) => [file.id, file]));
  for (const statement of allStatements(result)) {
    for (const anchor of statement.evidence) {
      const file = fileById.get(anchor.fileId);
      if (!file || file.path !== anchor.path || file.sha256 !== anchor.sha256) {
        throw new AtlasError('REVIEW_RESULT_FORGED_TUPLE', 'Review statement evidence is not anchored to an exact packet file tuple.');
      }
    }
  }
  const usedTokens = checkedSum([result.usage.inputTokens, result.usage.outputTokens], 'result token usage');
  if (usedTokens > attempt.reservation.tokenLimit || result.usage.durationMs > attempt.reservation.timeLimitMs) {
    throw new AtlasError('REVIEW_BUDGET_EXCEEDED', 'Review result usage exceeds its pre-authorized attempt reservation.');
  }
}

function derivedAttemptId(attempt: ReviewExecutionAttempt): string {
  const {
    attemptId: _attemptId,
    schemaVersion: _schemaVersion,
    state: _state,
    usage: _usage,
    resultId: _resultId,
    failure: _failure,
    outcomeHash: _outcomeHash,
    ...identityMaterial
  } = attempt;
  return attemptIdentity(identityMaterial);
}

function derivedResultId(result: ReviewResult): string {
  const { resultId: _resultId, ...material } = result;
  return resultIdentity(material);
}

function validateLedgerSemantics(options: {
  execution: ReviewExecution;
  attempts: ReviewExecutionAttempt[];
  results: ReviewResult[];
  attemptNames: string[];
  resultNames: string[];
  context: CampaignContext;
}): {
  attemptById: Map<string, ReviewExecutionAttempt>;
  resultByPacketId: Map<string, ReviewResult>;
} {
  const { execution, attempts, results, context } = options;
  if (attempts.length > EXECUTION_ATTEMPT_LIMIT || results.length > CAMPAIGN_PACKET_LIMIT) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution artifact count exceeds its bounded limit.');
  }
  let aggregateArtifactBytes = 0;
  for (const artifact of [...attempts, ...results]) {
    aggregateArtifactBytes += Buffer.byteLength(prettyCanonicalJson(artifact), 'utf8');
    if (!Number.isSafeInteger(aggregateArtifactBytes) || aggregateArtifactBytes > AGGREGATE_INPUT_BYTES_LIMIT) {
      throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution artifacts exceed the aggregate serialized byte limit.');
    }
  }
  if (Buffer.byteLength(canonicalJson(execution), 'utf8') > EXECUTION_CANONICAL_BYTES_LIMIT) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution exceeds its canonical serialized byte limit.');
  }
  assertPortableDataSafe(execution, 'Review execution plan');
  if (
    execution.runId !== context.campaign.runId || execution.snapshotId !== context.campaign.snapshotId ||
    execution.campaignId !== context.campaign.campaignId
  ) throw new AtlasError('REVIEW_RESULT_STALE', 'Review execution identity differs from its exact canonical campaign.');
  if (execution.executionId !== executionIdentity(context.campaign, execution.budgets.limits)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution identity does not match its campaign and budgets.');
  }
  for (const result of results) validateResultResourceBounds(result);
  if (options.attemptNames.some((name, index) => name !== `${attempts[index]?.attemptId}.json`)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Attempt filename and record identity differ.');
  }
  if (options.resultNames.some((name, index) => name !== `${results[index]?.packetId}.json`)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result filename and packet identity differ.');
  }
  const expectedAttemptNames = execution.packets
    .flatMap((packet) => packet.attemptIds.map((attemptId) => `${attemptId}.json`))
    .sort(compareCanonicalText);
  if (!exactArray([...options.attemptNames].sort(compareCanonicalText), expectedAttemptNames)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Attempt ledger does not match the execution declaration.');
  }
  const expectedResultNames = execution.packets
    .filter((packet) => packet.resultId)
    .map((packet) => `${packet.packetId}.json`)
    .sort(compareCanonicalText);
  if (!exactArray([...options.resultNames].sort(compareCanonicalText), expectedResultNames)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result store does not match the execution declaration.');
  }
  const attemptById = new Map(attempts.map((attempt) => [attempt.attemptId, attempt]));
  if (attemptById.size !== attempts.length) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Attempt ledger contains duplicate identities.');
  const resultByPacketId = new Map(results.map((result) => [result.packetId, result]));
  if (resultByPacketId.size !== results.length) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result store contains duplicate packet results.');
  if (execution.packets.length !== context.packets.length) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution packet count differs from the campaign.');
  let runningAttempts = 0;
  for (let packetIndex = 0; packetIndex < execution.packets.length; packetIndex += 1) {
    const statePacket = execution.packets[packetIndex]!;
    const campaignPacket = context.packets[packetIndex]!;
    if (
      statePacket.packetId !== campaignPacket.packetId || statePacket.packetHash !== campaignPacket.packetHash ||
      statePacket.estimatedInputTokens !== campaignPacket.estimatedInputTokens
    ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution packet tuple differs from the immutable campaign packet.');
    let previousAttemptId: string | undefined;
    for (let attemptIndex = 0; attemptIndex < statePacket.attemptIds.length; attemptIndex += 1) {
      const attemptId = statePacket.attemptIds[attemptIndex]!;
      const attempt = attemptById.get(attemptId);
      if (!attempt || attempt.attemptId !== derivedAttemptId(attempt)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `Attempt identity mismatch: ${attemptId}`);
      if (
        attempt.executionId !== execution.executionId || attempt.campaignId !== execution.campaignId ||
        attempt.runId !== execution.runId || attempt.snapshotId !== execution.snapshotId ||
        attempt.packetId !== statePacket.packetId || attempt.packetHash !== statePacket.packetHash ||
        attempt.attemptNumber !== attemptIndex + 1 || attempt.previousAttemptId !== previousAttemptId
      ) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `Attempt chain or binding mismatch: ${attemptId}`);
      if (attempt.state === 'running') {
        runningAttempts += 1;
        if (attempt.outcomeHash !== undefined) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Running attempt unexpectedly declares a terminal outcome hash.');
      } else if (attempt.outcomeHash !== terminalOutcomeHash(attempt)) {
        throw new AtlasError('REVIEW_EXECUTION_TAMPERED', `Attempt terminal outcome hash mismatch: ${attemptId}`);
      }
      if (attemptIndex < statePacket.attemptIds.length - 1 && attempt.state !== 'failed') {
        throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Only a failed attempt may be followed by a retry.');
      }
      if (attempt.usage) {
        const tokens = checkedSum([attempt.usage.inputTokens, attempt.usage.outputTokens], 'attempt token usage');
        if (tokens > attempt.reservation.tokenLimit || attempt.usage.durationMs > attempt.reservation.timeLimitMs) {
          throw new AtlasError('REVIEW_BUDGET_EXCEEDED', 'Attempt ledger records usage beyond its reservation.');
        }
      }
      previousAttemptId = attemptId;
    }
    const lastAttempt = statePacket.attemptIds.length ? attemptById.get(statePacket.attemptIds.at(-1)!) : undefined;
    const expectedPacketState = lastAttempt?.state ?? 'pending';
    if (statePacket.state !== expectedPacketState) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Packet state differs from its attempt ledger.');
    const result = resultByPacketId.get(statePacket.packetId);
    if (lastAttempt?.state === 'completed') {
      if (!result || result.resultId !== statePacket.resultId || lastAttempt.resultId !== result.resultId) {
        throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Completed packet is missing its exact result binding.');
      }
      if (result.resultId !== derivedResultId(result)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review result identity does not match its canonical content.');
      validateResultBinding(result, execution, lastAttempt, campaignPacket);
      if (!exactArray(result.usage, lastAttempt.usage)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Result and attempt usage differ.');
    } else if (result || statePacket.resultId) {
      throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Non-completed packet unexpectedly declares a result.');
    }
  }
  if (runningAttempts > 1) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'This execution contract permits at most one running attempt.');
  const terminalAttempts = attempts.filter((attempt) => attempt.state !== 'running');
  const expectedBudgets = {
    limits: execution.budgets.limits,
    used: {
      packets: execution.packets.filter((packet) => packet.attemptIds.length > 0).length,
      calls: attempts.length,
      tokens: checkedSum(terminalAttempts.map((attempt) => checkedSum([
        attempt.usage!.inputTokens,
        attempt.usage!.outputTokens
      ], 'terminal token usage')), 'campaign token usage'),
      timeMs: checkedSum(terminalAttempts.map((attempt) => attempt.usage!.durationMs), 'campaign time usage')
    },
    reserved: {
      tokens: checkedSum(attempts.filter((attempt) => attempt.state === 'running').map((attempt) => attempt.reservation.tokenLimit), 'reserved tokens'),
      timeMs: checkedSum(attempts.filter((attempt) => attempt.state === 'running').map((attempt) => attempt.reservation.timeLimitMs), 'reserved time')
    }
  };
  if (!exactArray(execution.budgets, expectedBudgets)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution budget counters differ from the attempt ledger.');
  if (
    expectedBudgets.used.packets > execution.budgets.limits.maxPackets ||
    expectedBudgets.used.calls > execution.budgets.limits.maxCalls ||
    expectedBudgets.used.tokens + expectedBudgets.reserved.tokens > execution.budgets.limits.maxTokens ||
    expectedBudgets.used.timeMs + expectedBudgets.reserved.timeMs > execution.budgets.limits.maxTimeMs
  ) throw new AtlasError('REVIEW_BUDGET_EXCEEDED', 'Execution ledger exceeds its campaign budget.');
  if (execution.resumeCount > execution.pauseCount || execution.pauseCount - execution.resumeCount > 1) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Pause/resume counters do not form a valid transition sequence.');
  }
  const allCompleted = execution.packets.every((packet) => packet.state === 'completed');
  const isPaused = execution.pauseCount === execution.resumeCount + 1;
  let expectedState: ReviewExecution['state'];
  if (allCompleted) expectedState = 'completed';
  else if (isPaused) expectedState = 'paused';
  else if (runningAttempts) expectedState = 'running';
  else if (execution.packets.some((packet) => packet.state === 'failed')) expectedState = 'failed';
  else expectedState = 'pending';
  if (execution.state !== expectedState || (allCompleted && isPaused)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution state differs from its deterministic packet transitions.');
  const expectedRevision = attempts.length + terminalAttempts.length + execution.pauseCount + execution.resumeCount;
  if (execution.revision !== expectedRevision) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Execution revision differs from its transition ledger.');
  return { attemptById, resultByPacketId };
}

async function loadExecutionState(directoryValue: string): Promise<LoadedExecution> {
  const requestedDirectory = path.resolve(directoryValue);
  let rootMetadata;
  let rootEntries;
  try {
    rootMetadata = await lstat(requestedDirectory);
    rootEntries = await readdir(requestedDirectory, { withFileTypes: true });
  } catch {
    throw new AtlasError('REVIEW_EXECUTION_MISSING', 'Review execution directory is missing or unreadable.');
  }
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution path must be a real directory.');
  const observedRootNames = rootEntries.map((entry) => entry.name).sort(compareCanonicalText);
  if (!exactArray(observedRootNames, ['attempts', 'execution.json', 'results'])) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution directory does not match the required artifact set.');
  }
  const executionFile = rootEntries.find((entry) => entry.name === 'execution.json');
  const attemptsEntry = rootEntries.find((entry) => entry.name === 'attempts');
  const resultsEntry = rootEntries.find((entry) => entry.name === 'results');
  if (!executionFile?.isFile() || executionFile.isSymbolicLink() || !attemptsEntry?.isDirectory() || attemptsEntry.isSymbolicLink() || !resultsEntry?.isDirectory() || resultsEntry.isSymbolicLink()) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution artifacts have invalid filesystem types.');
  }
  const directory = await realpath(requestedDirectory);
  const execution = await readCanonicalSchema<ReviewExecution>(path.join(directory, 'execution.json'), 'review-execution', 'Review execution');
  const workspacePath = path.resolve(directory, '..', '..');
  const expectedDirectory = path.join(workspacePath, 'review-executions', execution.campaignId);
  if (!samePath(directory, expectedDirectory)) throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution is not in its canonical campaign-scoped location.');
  const context = await campaignContext(path.join(workspacePath, 'reviews', execution.campaignId), true);
  if (
    execution.runId !== context.campaign.runId || execution.snapshotId !== context.campaign.snapshotId ||
    execution.campaignId !== context.campaign.campaignId
  ) throw new AtlasError('REVIEW_RESULT_STALE', 'Review execution identity differs from its exact canonical campaign.');
  if (execution.executionId !== executionIdentity(context.campaign, execution.budgets.limits)) {
    throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'Review execution identity does not match its campaign and budgets.');
  }
  if (isInside(context.targetRoot, directory)) throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Review execution output resolves inside the scanned target repository.');

  const ledger = await readLooseLedger({
    directory,
    storageParent: path.dirname(directory),
    campaignId: execution.campaignId,
    context
  });
  const attemptRecords = ledger.attempts;
  const resultRecords = ledger.results;
  const attempts = attemptRecords.map((record) => record.value);
  const results = resultRecords.map((record) => record.value);
  const { attemptById, resultByPacketId } = validateLedgerSemantics({
    execution,
    attempts,
    results,
    attemptNames: attemptRecords.map((record) => record.name),
    resultNames: resultRecords.map((record) => record.name),
    context
  });
  return {
    directory,
    execution,
    attempts,
    results,
    context,
    attemptById,
    resultByPacketId,
    storageParent: path.dirname(directory)
  };
}

function copyRecords(loaded: LoadedExecution): ReviewExecutionRecords {
  return {
    directory: loaded.directory,
    execution: canonicalClone(loaded.execution),
    attempts: canonicalClone(loaded.attempts),
    results: canonicalClone(loaded.results)
  };
}

export async function readReviewExecution(directory: string): Promise<ReviewExecutionRecords> {
  return copyRecords(await loadExecution(directory));
}

export async function verifyReviewExecution(directory: string): Promise<ReviewExecutionVerification> {
  const loaded = await loadExecution(directory);
  return {
    status: 'passed',
    executionId: loaded.execution.executionId,
    campaignId: loaded.execution.campaignId,
    runId: loaded.execution.runId,
    snapshotId: loaded.execution.snapshotId,
    state: loaded.execution.state,
    revision: loaded.execution.revision,
    packets: loaded.execution.packets.length,
    attempts: loaded.attempts.length,
    results: loaded.results.length,
    budgets: canonicalClone(loaded.execution.budgets)
  };
}

export async function createReviewExecution(options: {
  campaignDirectory: string;
  budgets: ReviewBudgetLimits;
}): Promise<{ directory: string; execution: ReviewExecution; reused: boolean }> {
  const context = await campaignContext(options.campaignDirectory, false);
  const limits = budgetLimits(options.budgets);
  const execution: ReviewExecution = {
    schemaVersion: 1,
    executionId: executionIdentity(context.campaign, limits),
    campaignId: context.campaign.campaignId,
    runId: context.campaign.runId,
    snapshotId: context.campaign.snapshotId,
    state: context.packets.length ? 'pending' : 'completed',
    budgets: {
      limits,
      used: { packets: 0, calls: 0, tokens: 0, timeMs: 0 },
      reserved: { tokens: 0, timeMs: 0 }
    },
    packets: context.packets.map((packet) => ({
      packetId: packet.packetId,
      packetHash: packet.packetHash,
      estimatedInputTokens: packet.estimatedInputTokens,
      state: 'pending',
      attemptIds: []
    })),
    revision: 0,
    pauseCount: 0,
    resumeCount: 0
  };
  if (Buffer.byteLength(canonicalJson(execution), 'utf8') > EXECUTION_CANONICAL_BYTES_LIMIT) {
    throw new AtlasError('REVIEW_EXECUTION_TOO_LARGE', 'Review execution plan exceeds its canonical serialized byte limit.');
  }
  await assertSchema('review-execution', execution, 'Review execution');
  const storageParentValue = await resolveForContainment(path.join(context.workspacePath, 'review-executions'));
  if (!isInside(context.workspacePath, storageParentValue) || isInside(context.targetRoot, storageParentValue)) {
    throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Review execution store must be inside the selected workspace and outside the target.');
  }
  await mkdir(storageParentValue, { recursive: true });
  const storageParent = await realpath(storageParentValue);
  const storageMetadata = await lstat(storageParent);
  if (
    !samePath(storageParent, storageParentValue) ||
    !storageMetadata.isDirectory() || storageMetadata.isSymbolicLink() ||
    !isInside(context.workspacePath, storageParent) ||
    isInside(context.targetRoot, storageParent)
  ) throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Review execution store changed containment while it was created.');
  const directory = path.join(storageParent, context.campaign.campaignId);
  return withCampaignLock(storageParent, context.campaign.campaignId, async () => {
    const directoryExists = await exists(directory);
    const pendingJournal = path.join(storageParent, `.review-transaction-${context.campaign.campaignId}.json`);
    if (!directoryExists && await exists(pendingJournal)) {
      throw new AtlasError('REVIEW_EXECUTION_TAMPERED', 'A review transaction exists without its campaign execution directory.');
    }
    if (directoryExists) {
      const location = await resolveExecutionLocation(directory);
      await recoverTransaction(location);
      const existing = await loadExecutionState(directory);
      if (existing.execution.executionId !== execution.executionId || !exactArray(existing.execution.budgets.limits, limits)) {
        throw new AtlasError('REVIEW_EXECUTION_CONFLICT', 'Campaign already has a review execution with different budgets.');
      }
      return { directory: existing.directory, execution: canonicalClone(existing.execution), reused: true };
    }
    const temporaryDirectory = path.join(storageParent, `.review-execution-tmp-${randomUUID().replaceAll('-', '')}`);
    let temporaryExists = false;
    try {
      await mkdir(path.join(temporaryDirectory, 'attempts'), { recursive: true });
      temporaryExists = true;
      await mkdir(path.join(temporaryDirectory, 'results'));
      await writeFile(path.join(temporaryDirectory, 'execution.json'), prettyCanonicalJson(execution), {
        encoding: 'utf8',
        flag: 'wx',
        flush: true
      });
      await Promise.all([
        syncDirectory(path.join(temporaryDirectory, 'attempts')),
        syncDirectory(path.join(temporaryDirectory, 'results'))
      ]);
      await syncDirectory(temporaryDirectory);
      await rename(temporaryDirectory, directory);
      await syncDirectory(storageParent);
      temporaryExists = false;
    } finally {
      if (temporaryExists && await exists(temporaryDirectory)) {
        await safeRemoveTemporary(storageParent, temporaryDirectory, '.review-execution-tmp-');
      }
    }
    const verified = await loadExecutionState(directory);
    return { directory: verified.directory, execution: canonicalClone(verified.execution), reused: false };
  });
}

async function startAttemptInternal(options: {
  executionDirectory: string;
  packetId: string;
  reviewer: ReviewReviewer;
  tokenLimit: number;
  timeLimitMs: number;
}, retry: boolean): Promise<{ execution: ReviewExecution; attempt: ReviewExecutionAttempt }> {
  return withLoadedExecution(options.executionDirectory, async (loaded) => {
    await assertCurrentReviewConsent(loaded.context);
    const execution = canonicalClone(loaded.execution);
    const packet = execution.packets.find((candidate) => candidate.packetId === options.packetId);
    const campaignPacket = loaded.context.packets.find((candidate) => candidate.packetId === options.packetId);
    if (!packet || !campaignPacket) throw new AtlasError('REVIEW_PACKET_MISMATCH', 'Packet is not part of this execution campaign.');
    if (retry) {
      if (execution.state !== 'failed' || packet.state !== 'failed') throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Retry requires a failed execution packet.');
    } else if (execution.state !== 'pending' || packet.state !== 'pending') {
      throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Starting an attempt requires a pending execution packet.');
    }
    safeInteger(options.tokenLimit, 'attempt tokenLimit');
    safeInteger(options.timeLimitMs, 'attempt timeLimitMs');
    if (options.tokenLimit < packet.estimatedInputTokens) {
      throw new AtlasError('REVIEW_BUDGET_EXCEEDED', 'Attempt token reservation is smaller than the immutable packet input estimate.');
    }
    const firstPacketAttempt = packet.attemptIds.length === 0;
    const prospectivePackets = execution.budgets.used.packets + (firstPacketAttempt ? 1 : 0);
    const prospectiveCalls = execution.budgets.used.calls + 1;
    const prospectiveTokens = checkedSum([
      execution.budgets.used.tokens,
      execution.budgets.reserved.tokens,
      options.tokenLimit
    ], 'prospective token budget');
    const prospectiveTime = checkedSum([
      execution.budgets.used.timeMs,
      execution.budgets.reserved.timeMs,
      options.timeLimitMs
    ], 'prospective time budget');
    if (
      prospectivePackets > execution.budgets.limits.maxPackets || prospectiveCalls > execution.budgets.limits.maxCalls ||
      prospectiveTokens > execution.budgets.limits.maxTokens || prospectiveTime > execution.budgets.limits.maxTimeMs
    ) throw new AtlasError('REVIEW_BUDGET_EXCEEDED', 'Starting this attempt would exceed the immutable campaign budget.');
    const reviewer = normalizeReviewer(options.reviewer);
    const identityMaterial = {
      executionId: execution.executionId,
      campaignId: execution.campaignId,
      runId: execution.runId,
      snapshotId: execution.snapshotId,
      packetId: packet.packetId,
      packetHash: packet.packetHash,
      attemptNumber: packet.attemptIds.length + 1,
      ...(packet.attemptIds.length ? { previousAttemptId: packet.attemptIds.at(-1)! } : {}),
      reviewer,
      reservation: { tokenLimit: options.tokenLimit, timeLimitMs: options.timeLimitMs }
    };
    const attempt: ReviewExecutionAttempt = {
      schemaVersion: 1,
      attemptId: attemptIdentity(identityMaterial),
      ...identityMaterial,
      state: 'running'
    };
    packet.attemptIds.push(attempt.attemptId);
    packet.state = 'running';
    execution.state = 'running';
    execution.budgets.used.packets = prospectivePackets;
    execution.budgets.used.calls = prospectiveCalls;
    execution.budgets.reserved.tokens += options.tokenLimit;
    execution.budgets.reserved.timeMs += options.timeLimitMs;
    execution.revision += 1;
    await Promise.all([
      assertSchema('review-execution-attempt', attempt, 'Review execution attempt'),
      assertSchema('review-execution', execution, 'Review execution')
    ]);
    const verified = await commitTransition(loaded, [{
      kind: 'attempt',
      recordId: attempt.attemptId,
      before: null,
      after: attempt
    }], execution);
    return { execution: canonicalClone(verified.execution), attempt: canonicalClone(verified.attemptById.get(attempt.attemptId)!) };
  });
}

export async function startReviewAttempt(options: {
  executionDirectory: string;
  packetId: string;
  reviewer: ReviewReviewer;
  tokenLimit: number;
  timeLimitMs: number;
}): Promise<{ execution: ReviewExecution; attempt: ReviewExecutionAttempt }> {
  return startAttemptInternal(options, false);
}

export async function retryReviewAttempt(options: {
  executionDirectory: string;
  packetId: string;
  reviewer: ReviewReviewer;
  tokenLimit: number;
  timeLimitMs: number;
}): Promise<{ execution: ReviewExecution; attempt: ReviewExecutionAttempt }> {
  return startAttemptInternal(options, true);
}

function applyTerminalUsage(execution: ReviewExecution, attempt: ReviewExecutionAttempt, usage: ReviewUsage): void {
  const usedTokens = checkedSum([usage.inputTokens, usage.outputTokens], 'attempt token usage');
  if (usedTokens > attempt.reservation.tokenLimit || usage.durationMs > attempt.reservation.timeLimitMs) {
    throw new AtlasError('REVIEW_BUDGET_EXCEEDED', 'Attempt usage exceeds its pre-authorized token/time reservation.');
  }
  execution.budgets.reserved.tokens -= attempt.reservation.tokenLimit;
  execution.budgets.reserved.timeMs -= attempt.reservation.timeLimitMs;
  execution.budgets.used.tokens = checkedSum([execution.budgets.used.tokens, usedTokens], 'campaign token usage');
  execution.budgets.used.timeMs = checkedSum([execution.budgets.used.timeMs, usage.durationMs], 'campaign time usage');
}

export async function failReviewAttempt(options: {
  executionDirectory: string;
  attemptId: string;
  usage: ReviewUsage;
  failure: { code: string; message: string };
}): Promise<{ execution: ReviewExecution; attempt: ReviewExecutionAttempt }> {
  return withLoadedExecution(options.executionDirectory, async (loaded) => {
    const currentAttempt = loaded.attemptById.get(options.attemptId);
    if (!currentAttempt || currentAttempt.state !== 'running' || loaded.execution.state !== 'running') {
      throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Only the active running attempt can fail.');
    }
    const execution = canonicalClone(loaded.execution);
    const attempt = canonicalClone(currentAttempt);
    const usage = normalizeUsage(options.usage);
    applyTerminalUsage(execution, attempt, usage);
    attempt.state = 'failed';
    attempt.usage = usage;
    attempt.failure = normalizeFailure(options.failure);
    attempt.outcomeHash = terminalOutcomeHash(attempt);
    const packet = execution.packets.find((candidate) => candidate.packetId === attempt.packetId)!;
    packet.state = 'failed';
    execution.state = 'failed';
    execution.revision += 1;
    await Promise.all([
      assertSchema('review-execution-attempt', attempt, 'Failed review attempt'),
      assertSchema('review-execution', execution, 'Review execution')
    ]);
    const verified = await commitTransition(loaded, [{
      kind: 'attempt',
      recordId: attempt.attemptId,
      before: currentAttempt,
      after: attempt
    }], execution);
    return { execution: canonicalClone(verified.execution), attempt: canonicalClone(verified.attemptById.get(attempt.attemptId)!) };
  });
}

export async function completeReviewAttempt(options: {
  executionDirectory: string;
  result: ReviewResultInput;
}): Promise<{ execution: ReviewExecution; attempt: ReviewExecutionAttempt; result: ReviewResult }> {
  return withLoadedExecution(options.executionDirectory, async (loaded) => {
    const input = sanitizeResultInput(options.result);
    const currentAttempt = loaded.attemptById.get(input.attemptId);
    if (!currentAttempt || currentAttempt.state !== 'running' || loaded.execution.state !== 'running') {
      throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Only the active running attempt can accept a result.');
    }
    const campaignPacket = loaded.context.packets.find((packet) => packet.packetId === currentAttempt.packetId)!;
    const material: Omit<ReviewResult, 'resultId'> = { schemaVersion: 1, ...input };
    const result: ReviewResult = { ...material, resultId: resultIdentity(material) };
    if (Buffer.byteLength(canonicalJson(result), 'utf8') > RESULT_CANONICAL_BYTES_LIMIT) {
      throw new AtlasError('REVIEW_RESULT_INVALID', 'Review result exceeds the canonical serialized byte limit.');
    }
    await assertSchema('review-result', result, 'Review result');
    validateResultBinding(result, loaded.execution, currentAttempt, campaignPacket);
    const execution = canonicalClone(loaded.execution);
    const attempt = canonicalClone(currentAttempt);
    applyTerminalUsage(execution, attempt, result.usage);
    attempt.state = 'completed';
    attempt.usage = result.usage;
    attempt.resultId = result.resultId;
    attempt.outcomeHash = terminalOutcomeHash(attempt);
    const packet = execution.packets.find((candidate) => candidate.packetId === attempt.packetId)!;
    packet.state = 'completed';
    packet.resultId = result.resultId;
    execution.state = execution.packets.every((candidate) => candidate.state === 'completed') ? 'completed' : 'pending';
    execution.revision += 1;
    await Promise.all([
      assertSchema('review-execution-attempt', attempt, 'Completed review attempt'),
      assertSchema('review-execution', execution, 'Review execution')
    ]);
    if (loaded.resultByPacketId.has(packet.packetId)) throw new AtlasError('REVIEW_RESULT_CONFLICT', 'Packet already has a persisted result.');
    const verified = await commitTransition(loaded, [
      { kind: 'result', recordId: packet.packetId, before: null, after: result },
      { kind: 'attempt', recordId: attempt.attemptId, before: currentAttempt, after: attempt }
    ], execution);
    return {
      execution: canonicalClone(verified.execution),
      attempt: canonicalClone(verified.attemptById.get(attempt.attemptId)!),
      result: canonicalClone(verified.resultByPacketId.get(packet.packetId)!)
    };
  });
}

export async function pauseReviewExecution(directoryValue: string): Promise<ReviewExecution> {
  return withLoadedExecution(directoryValue, async (loaded) => {
    if (loaded.execution.state === 'paused') return canonicalClone(loaded.execution);
    if (loaded.execution.state === 'running' || loaded.execution.state === 'completed') {
      throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Only an idle pending or failed execution can be paused.');
    }
    const execution = canonicalClone(loaded.execution);
    execution.state = 'paused';
    execution.pauseCount += 1;
    execution.revision += 1;
    await assertSchema('review-execution', execution, 'Paused review execution');
    return canonicalClone((await commitTransition(loaded, [], execution)).execution);
  });
}

export async function resumeReviewExecution(directoryValue: string): Promise<ReviewExecution> {
  return withLoadedExecution(directoryValue, async (loaded) => {
    if (loaded.execution.state !== 'paused') throw new AtlasError('REVIEW_TRANSITION_INVALID', 'Only a paused execution can resume.');
    const execution = canonicalClone(loaded.execution);
    execution.resumeCount += 1;
    execution.revision += 1;
    execution.state = execution.packets.some((packet) => packet.state === 'failed') ? 'failed' : 'pending';
    await assertSchema('review-execution', execution, 'Resumed review execution');
    return canonicalClone((await commitTransition(loaded, [], execution)).execution);
  });
}
