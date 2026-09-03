import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { appendFile, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AtlasError } from '../src/errors.js';
import {
  completeReviewAttempt,
  createReviewExecution,
  failReviewAttempt,
  pauseReviewExecution,
  readReviewExecution,
  resumeReviewExecution,
  retryReviewAttempt,
  startReviewAttempt,
  verifyReviewExecution,
  type ReviewExecution,
  type ReviewExecutionAttempt,
  type ReviewResultInput
} from '../src/review-execution/index.js';
import { createReviewCampaign } from '../src/reviews.js';
import { scanProject } from '../src/run.js';
import type { ReviewPacket } from '../src/types.js';
import { canonicalJson, prettyCanonicalJson, readJson, sha256, writeCanonicalJson } from '../src/util/canonical.js';

async function fixture(batchSize = 10): Promise<{
  root: string;
  target: string;
  workspace: string;
  targetConfigPath: string;
  runDirectory: string;
  campaignDirectory: string;
  packets: ReviewPacket[];
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-review-execution-'));
  const target = path.join(root, 'target');
  const workspace = path.join(root, 'workspace');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), "import { value } from './value.js';\nconsole.log(value);\n");
  await writeFile(path.join(target, 'src', 'value.ts'), 'export const value = 42;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'review-execution-target',
    path: './target',
    consent: { agentReview: true, export: false, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'review-execution-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    maxFileBytes: 100000
  });
  const scan = await scanProject({ targetConfigPath, profilePath, workspacePath: workspace });
  const campaign = await createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'Deterministic execution fixture',
    selection: 'all',
    batchSize
  });
  const packets = await Promise.all(campaign.campaign.packetIds.map((packetId) => readJson<ReviewPacket>(
    path.join(campaign.directory, 'packets', `${packetId}.json`)
  )));
  return { root, target, workspace, targetConfigPath, runDirectory: scan.runDirectory, campaignDirectory: campaign.directory, packets };
}

function resultInput(
  execution: ReviewExecution,
  attempt: ReviewExecutionAttempt,
  packet: ReviewPacket,
  usage = { inputTokens: packet.estimatedInputTokens, outputTokens: 2, durationMs: 10 }
): ReviewResultInput {
  const files = packet.files.map((file) => ({ ...file }));
  const first = files[0];
  return {
    executionId: execution.executionId,
    runId: execution.runId,
    snapshotId: execution.snapshotId,
    campaignId: execution.campaignId,
    packetId: packet.packetId,
    packetHash: packet.packetHash,
    attemptId: attempt.attemptId,
    reviewer: { ...attempt.reviewer },
    evidenceFiles: files,
    reviewedFiles: files.map((file) => ({ ...file })),
    responsibilities: first ? [{
      summary: 'Reviewed the exact packet responsibility boundary.',
      confidence: 'high',
      evidence: [{ fileId: first.id, path: first.path, sha256: first.sha256, line: 1, column: 1 }]
    }] : [],
    associations: [],
    observed: [],
    suspected: [],
    needsRuntimeValidation: [],
    unknowns: [],
    usage
  };
}

interface TestTransactionOperation {
  kind: 'attempt' | 'result' | 'execution';
  recordId: string;
  expectedHash: string | null;
  pre: string | null;
  postHash: string;
  post: string;
}

function transactionOperation(
  kind: TestTransactionOperation['kind'],
  recordId: string,
  before: unknown | null,
  after: unknown
): TestTransactionOperation {
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

function testTransaction(
  before: ReviewExecution,
  after: ReviewExecution,
  operations: TestTransactionOperation[]
): Record<string, unknown> {
  const material = {
    schemaVersion: 1,
    transactionNonce: '0'.repeat(32),
    executionId: after.executionId,
    campaignId: after.campaignId,
    fromRevision: before.revision,
    toRevision: after.revision,
    operations: [
      ...operations,
      transactionOperation('execution', 'execution', before, after)
    ]
  };
  return {
    ...material,
    transactionId: `review_transaction_${sha256(canonicalJson({
      domain: 'atlas.review-execution-transaction.v1',
      ...material
    }))}`
  };
}

test('review execution supports deterministic pause, resume, failure, retry, and completion ledgers', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const packet = value.packets[0]!;
  const tokenLimit = packet.estimatedInputTokens + 20;
  const created = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 2, maxTokens: tokenLimit * 2, maxTimeMs: 200 }
  });
  assert.equal(created.reused, false);
  const reused = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 2, maxTokens: tokenLimit * 2, maxTimeMs: 200 }
  });
  assert.equal(reused.reused, true);
  assert.equal(reused.execution.executionId, created.execution.executionId);

  assert.equal((await pauseReviewExecution(created.directory)).state, 'paused');
  assert.equal((await resumeReviewExecution(created.directory)).state, 'pending');
  const first = await startReviewAttempt({
    executionDirectory: created.directory,
    packetId: packet.packetId,
    reviewer: { kind: 'agent', identity: 'local-reviewer', version: '1.2.3', promptVersion: 'prompt-1' },
    tokenLimit,
    timeLimitMs: 100
  });
  assert.equal(first.execution.state, 'running');
  const failed = await failReviewAttempt({
    executionDirectory: created.directory,
    attemptId: first.attempt.attemptId,
    usage: { inputTokens: 1, outputTokens: 0, durationMs: 5 },
    failure: { code: 'TRANSIENT_FAILURE', message: 'Local reviewer returned no result.' }
  });
  assert.equal(failed.execution.state, 'failed');
  const retry = await retryReviewAttempt({
    executionDirectory: created.directory,
    packetId: packet.packetId,
    reviewer: { kind: 'agent', identity: 'local-reviewer', version: '1.2.3', promptVersion: 'prompt-1' },
    tokenLimit,
    timeLimitMs: 100
  });
  assert.equal(retry.attempt.attemptNumber, 2);
  assert.equal(retry.attempt.previousAttemptId, first.attempt.attemptId);
  const completed = await completeReviewAttempt({
    executionDirectory: created.directory,
    result: resultInput(retry.execution, retry.attempt, packet)
  });
  assert.equal(completed.execution.state, 'completed');
  const verification = await verifyReviewExecution(created.directory);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.state, 'completed');
  assert.equal(verification.attempts, 2);
  assert.equal(verification.results, 1);
  assert.equal(verification.budgets.used.calls, 2);
  assert.equal(verification.budgets.reserved.tokens, 0);
  const records = await readReviewExecution(created.directory);
  assert.deepEqual(
    [...records.attempts].sort((left, right) => left.attemptNumber - right.attemptNumber).map((attempt) => attempt.state),
    ['failed', 'completed']
  );
  assert.equal(records.results[0]?.reviewer.version, '1.2.3');
  assert.equal(records.results[0]?.reviewer.promptVersion, 'prompt-1');
  const storageEntries = await readdir(path.join(value.workspace, 'review-executions'));
  assert.deepEqual(storageEntries, [created.execution.campaignId]);
});

test('forged result tuples are rejected without partial writes and persisted result tampering is detected', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const packet = value.packets[0]!;
  const tokenLimit = packet.estimatedInputTokens + 20;
  const created = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: tokenLimit, maxTimeMs: 100 }
  });
  const started = await startReviewAttempt({
    executionDirectory: created.directory,
    packetId: packet.packetId,
    reviewer: { kind: 'human', identity: 'reviewer@example.test', version: 'policy-1', promptVersion: 'checklist-1' },
    tokenLimit,
    timeLimitMs: 100
  });
  const forged = resultInput(started.execution, started.attempt, packet);
  forged.packetHash = '0'.repeat(64);
  await assert.rejects(
    completeReviewAttempt({ executionDirectory: created.directory, result: forged }),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_RESULT_FORGED_TUPLE'
  );
  const forgedEvidence = resultInput(started.execution, started.attempt, packet);
  forgedEvidence.evidenceFiles[0]!.sha256 = 'f'.repeat(64);
  await assert.rejects(
    completeReviewAttempt({ executionDirectory: created.directory, result: forgedEvidence }),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_RESULT_FORGED_TUPLE'
  );
  const poisoned = {
    ...resultInput(started.execution, started.attempt, packet),
    resultId: `review_result_${'a'.repeat(64)}`
  } as unknown as ReviewResultInput;
  await assert.rejects(
    completeReviewAttempt({ executionDirectory: created.directory, result: poisoned }),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_RESULT_INVALID'
  );
  const oversized = resultInput(started.execution, started.attempt, packet);
  oversized.observed = Array.from({ length: 1001 }, (_, index) => ({
    summary: `bounded statement ${index}`,
    confidence: 'low' as const,
    evidence: []
  }));
  await assert.rejects(
    completeReviewAttempt({ executionDirectory: created.directory, result: oversized }),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_RESULT_INVALID'
  );
  assert.deepEqual(await readdir(path.join(created.directory, 'results')), []);
  assert.equal((await verifyReviewExecution(created.directory)).state, 'running');

  const completed = await completeReviewAttempt({
    executionDirectory: created.directory,
    result: resultInput(started.execution, started.attempt, packet)
  });
  const resultPath = path.join(created.directory, 'results', `${packet.packetId}.json`);
  const tampered = await readJson<Record<string, unknown>>(resultPath);
  const observed = tampered.observed as unknown[];
  observed.push({ summary: 'forged post-publication claim', confidence: 'confirmed', evidence: [] });
  await writeCanonicalJson(resultPath, tampered);
  await assert.rejects(
    verifyReviewExecution(created.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_EXECUTION_TAMPERED'
  );
  assert.equal(completed.result.packetId, packet.packetId);
});

test('packet, call, token, and time budgets cannot be exceeded', async (context) => {
  const value = await fixture(1);
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  assert.equal(value.packets.length, 2);
  const firstPacket = value.packets[0]!;
  const firstLimit = firstPacket.estimatedInputTokens + 2;
  const created = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: firstLimit, maxTimeMs: 10 }
  });
  await assert.rejects(startReviewAttempt({
    executionDirectory: created.directory,
    packetId: firstPacket.packetId,
    reviewer: { kind: 'agent', identity: 'budget-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: firstLimit + 1,
    timeLimitMs: 10
  }), (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_BUDGET_EXCEEDED');
  await assert.rejects(startReviewAttempt({
    executionDirectory: created.directory,
    packetId: firstPacket.packetId,
    reviewer: { kind: 'agent', identity: 'budget-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: firstLimit,
    timeLimitMs: 11
  }), (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_BUDGET_EXCEEDED');
  const started = await startReviewAttempt({
    executionDirectory: created.directory,
    packetId: firstPacket.packetId,
    reviewer: { kind: 'agent', identity: 'budget-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: firstLimit,
    timeLimitMs: 10
  });
  await failReviewAttempt({
    executionDirectory: created.directory,
    attemptId: started.attempt.attemptId,
    usage: { inputTokens: 0, outputTokens: 0, durationMs: 0 },
    failure: { code: 'NO_RESULT', message: 'No call output was accepted.' }
  });
  await assert.rejects(retryReviewAttempt({
    executionDirectory: created.directory,
    packetId: firstPacket.packetId,
    reviewer: { kind: 'agent', identity: 'budget-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: firstLimit,
    timeLimitMs: 10
  }), (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_BUDGET_EXCEEDED');
  const verification = await verifyReviewExecution(created.directory);
  assert.equal(verification.budgets.used.calls, 1);
  assert.equal(verification.budgets.used.packets, 1);
  assert(verification.budgets.used.calls <= verification.budgets.limits.maxCalls);
  assert(verification.budgets.used.packets <= verification.budgets.limits.maxPackets);

  const packetBounded = await fixture(1);
  context.after(async () => rm(packetBounded.root, { recursive: true, force: true }));
  const packetA = packetBounded.packets[0]!;
  const packetB = packetBounded.packets[1]!;
  const packetALimit = packetA.estimatedInputTokens + 2;
  const packetBLimit = packetB.estimatedInputTokens + 2;
  const packetExecution = await createReviewExecution({
    campaignDirectory: packetBounded.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 2, maxTokens: packetALimit + packetBLimit, maxTimeMs: 20 }
  });
  const packetAttempt = await startReviewAttempt({
    executionDirectory: packetExecution.directory,
    packetId: packetA.packetId,
    reviewer: { kind: 'agent', identity: 'packet-budget-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: packetALimit,
    timeLimitMs: 10
  });
  await completeReviewAttempt({
    executionDirectory: packetExecution.directory,
    result: resultInput(packetAttempt.execution, packetAttempt.attempt, packetA)
  });
  await assert.rejects(startReviewAttempt({
    executionDirectory: packetExecution.directory,
    packetId: packetB.packetId,
    reviewer: { kind: 'agent', identity: 'packet-budget-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: packetBLimit,
    timeLimitMs: 10
  }), (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_BUDGET_EXCEEDED');
  const packetVerification = await verifyReviewExecution(packetExecution.directory);
  assert.equal(packetVerification.budgets.used.packets, 1);
  assert.equal(packetVerification.budgets.used.calls, 1);
});

test('result verification detects a stale exact run', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const packet = value.packets[0]!;
  const tokenLimit = packet.estimatedInputTokens + 10;
  const created = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: tokenLimit, maxTimeMs: 100 }
  });
  const started = await startReviewAttempt({
    executionDirectory: created.directory,
    packetId: packet.packetId,
    reviewer: { kind: 'agent', identity: 'stale-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit,
    timeLimitMs: 100
  });
  await completeReviewAttempt({
    executionDirectory: created.directory,
    result: resultInput(started.execution, started.attempt, packet)
  });
  await appendFile(path.join(value.runDirectory, 'diagnostics.jsonl'), '{"tampered":true}\n');
  await assert.rejects(
    verifyReviewExecution(created.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_RESULT_STALE'
  );
});

test('execution creation refuses a campaign workspace copied inside the target', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const embeddedWorkspace = path.join(value.target, 'embedded-workspace');
  await cp(value.workspace, embeddedWorkspace, { recursive: true });
  const embeddedCampaign = path.join(embeddedWorkspace, 'reviews', path.basename(value.campaignDirectory));
  await assert.rejects(
    createReviewExecution({
      campaignDirectory: embeddedCampaign,
      budgets: { maxPackets: 1, maxCalls: 1, maxTokens: 100000, maxTimeMs: 1000 }
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'WORKSPACE_INSIDE_TARGET'
  );
  await assert.rejects(stat(path.join(embeddedWorkspace, 'review-executions')), /ENOENT/);
  await assert.rejects(startReviewAttempt({
    executionDirectory: path.join(value.target, 'forged-review-execution'),
    packetId: value.packets[0]!.packetId,
    reviewer: { kind: 'agent', identity: 'unsafe', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: 1,
    timeLimitMs: 1
  }), /missing or unreadable/i);
  assert(!(await readdir(value.target)).some((entry) => entry.startsWith('.review-lock-')));
  assert(!await readFile(path.join(value.target, 'src', 'index.ts'), 'utf8').then((content) => content.includes('review_execution_')));
});

test('journal recovery is idempotent at pre-image, partial-leaf, and all-post crash points', async (context) => {
  const setup = async () => {
    const value = await fixture();
    context.after(async () => rm(value.root, { recursive: true, force: true }));
    const packet = value.packets[0]!;
    const tokenLimit = packet.estimatedInputTokens + 10;
    const created = await createReviewExecution({
      campaignDirectory: value.campaignDirectory,
      budgets: { maxPackets: 1, maxCalls: 1, maxTokens: tokenLimit, maxTimeMs: 100 }
    });
    const journalPath = path.join(path.dirname(created.directory), `.review-transaction-${created.execution.campaignId}.json`);
    return { value, packet, tokenLimit, created, journalPath };
  };

  const preImage = await setup();
  const paused = structuredClone(preImage.created.execution);
  paused.state = 'paused';
  paused.pauseCount += 1;
  paused.revision += 1;
  await writeCanonicalJson(preImage.journalPath, testTransaction(preImage.created.execution, paused, []));
  assert.equal((await verifyReviewExecution(preImage.created.directory)).state, 'paused');
  await assert.rejects(stat(preImage.journalPath), /ENOENT/);

  const allPost = await setup();
  const allPostPaused = structuredClone(allPost.created.execution);
  allPostPaused.state = 'paused';
  allPostPaused.pauseCount += 1;
  allPostPaused.revision += 1;
  await writeCanonicalJson(allPost.journalPath, testTransaction(allPost.created.execution, allPostPaused, []));
  await writeCanonicalJson(path.join(allPost.created.directory, 'execution.json'), allPostPaused);
  assert.equal((await verifyReviewExecution(allPost.created.directory)).state, 'paused');
  await assert.rejects(stat(allPost.journalPath), /ENOENT/);

  const partial = await setup();
  const reviewer = { kind: 'agent' as const, identity: 'crash-recovery-reviewer', version: '1', promptVersion: 'prompt-1' };
  const identityMaterial = {
    executionId: partial.created.execution.executionId,
    campaignId: partial.created.execution.campaignId,
    runId: partial.created.execution.runId,
    snapshotId: partial.created.execution.snapshotId,
    packetId: partial.packet.packetId,
    packetHash: partial.packet.packetHash,
    attemptNumber: 1,
    reviewer,
    reservation: { tokenLimit: partial.tokenLimit, timeLimitMs: 100 }
  };
  const attempt: ReviewExecutionAttempt = {
    schemaVersion: 1,
    attemptId: `review_attempt_${sha256(canonicalJson({ domain: 'atlas.review-attempt.v1', ...identityMaterial }))}`,
    ...identityMaterial,
    state: 'running'
  };
  const running = structuredClone(partial.created.execution);
  running.state = 'running';
  running.packets[0]!.state = 'running';
  running.packets[0]!.attemptIds.push(attempt.attemptId);
  running.budgets.used.packets = 1;
  running.budgets.used.calls = 1;
  running.budgets.reserved.tokens = partial.tokenLimit;
  running.budgets.reserved.timeMs = 100;
  running.revision = 1;
  await writeCanonicalJson(partial.journalPath, testTransaction(partial.created.execution, running, [
    transactionOperation('attempt', attempt.attemptId, null, attempt)
  ]));
  await writeCanonicalJson(path.join(partial.created.directory, 'attempts', `${attempt.attemptId}.json`), attempt);
  const recovered = await readReviewExecution(partial.created.directory);
  assert.equal(recovered.execution.state, 'running');
  assert.equal(recovered.attempts[0]?.attemptId, attempt.attemptId);
  await assert.rejects(stat(partial.journalPath), /ENOENT/);
});

test('forged journals never overwrite unexpected or semantically invalid pre-state', async (context) => {
  const semantic = await fixture();
  context.after(async () => rm(semantic.root, { recursive: true, force: true }));
  const semanticCreated = await createReviewExecution({
    campaignDirectory: semantic.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: 100000, maxTimeMs: 100 }
  });
  const semanticPost = structuredClone(semanticCreated.execution);
  semanticPost.state = 'paused';
  semanticPost.pauseCount = 1;
  semanticPost.revision = 1;
  semanticPost.budgets.used.calls = 1;
  const semanticJournal = path.join(path.dirname(semanticCreated.directory), `.review-transaction-${semanticCreated.execution.campaignId}.json`);
  await writeCanonicalJson(semanticJournal, testTransaction(semanticCreated.execution, semanticPost, []));
  const originalExecutionText = await readFile(path.join(semanticCreated.directory, 'execution.json'), 'utf8');
  await assert.rejects(
    verifyReviewExecution(semanticCreated.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_EXECUTION_TAMPERED'
  );
  assert.equal(await readFile(path.join(semanticCreated.directory, 'execution.json'), 'utf8'), originalExecutionText);

  const thirdHash = await fixture();
  context.after(async () => rm(thirdHash.root, { recursive: true, force: true }));
  const thirdCreated = await createReviewExecution({
    campaignDirectory: thirdHash.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: 100000, maxTimeMs: 100 }
  });
  const intended = structuredClone(thirdCreated.execution);
  intended.state = 'paused';
  intended.pauseCount = 1;
  intended.revision = 1;
  const thirdJournal = path.join(path.dirname(thirdCreated.directory), `.review-transaction-${thirdCreated.execution.campaignId}.json`);
  await writeCanonicalJson(thirdJournal, testTransaction(thirdCreated.execution, intended, []));
  const unexpected = structuredClone(thirdCreated.execution);
  unexpected.budgets.limits.maxTimeMs += 1;
  await writeCanonicalJson(path.join(thirdCreated.directory, 'execution.json'), unexpected);
  await assert.rejects(
    verifyReviewExecution(thirdCreated.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_EXECUTION_TAMPERED'
  );
  assert.deepEqual(await readJson(path.join(thirdCreated.directory, 'execution.json')), unexpected);
});

test('review consent is rechecked before start while read and verify remain available after revocation', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const packet = value.packets[0]!;
  const created = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: 100000, maxTimeMs: 100 }
  });
  const descriptor = await readJson<Record<string, unknown>>(value.targetConfigPath);
  (descriptor.consent as Record<string, unknown>).agentReview = false;
  await writeCanonicalJson(value.targetConfigPath, descriptor);
  assert.equal((await verifyReviewExecution(created.directory)).state, 'pending');
  await assert.rejects(startReviewAttempt({
    executionDirectory: created.directory,
    packetId: packet.packetId,
    reviewer: { kind: 'agent', identity: 'revoked-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: packet.estimatedInputTokens + 10,
    timeLimitMs: 100
  }), (error: unknown) => error instanceof AtlasError && error.code === 'AGENT_REVIEW_NOT_AUTHORIZED');
  const records = await readReviewExecution(created.directory);
  assert.equal(records.attempts.length, 0);
  assert.equal(records.execution.budgets.used.calls, 0);
});

test('terminal outcome edits and filename swaps are detected', async (context) => {
  const outcome = await fixture();
  context.after(async () => rm(outcome.root, { recursive: true, force: true }));
  const outcomePacket = outcome.packets[0]!;
  const outcomeLimit = outcomePacket.estimatedInputTokens + 10;
  const outcomeCreated = await createReviewExecution({
    campaignDirectory: outcome.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: outcomeLimit, maxTimeMs: 100 }
  });
  const outcomeStarted = await startReviewAttempt({
    executionDirectory: outcomeCreated.directory,
    packetId: outcomePacket.packetId,
    reviewer: { kind: 'agent', identity: 'outcome-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: outcomeLimit,
    timeLimitMs: 100
  });
  await failReviewAttempt({
    executionDirectory: outcomeCreated.directory,
    attemptId: outcomeStarted.attempt.attemptId,
    usage: { inputTokens: 1, outputTokens: 0, durationMs: 1 },
    failure: { code: 'FAILED', message: 'Original failure.' }
  });
  const outcomePath = path.join(outcomeCreated.directory, 'attempts', `${outcomeStarted.attempt.attemptId}.json`);
  const changedOutcome = await readJson<Record<string, unknown>>(outcomePath);
  (changedOutcome.failure as Record<string, unknown>).message = 'Altered failure.';
  await writeCanonicalJson(outcomePath, changedOutcome);
  await assert.rejects(
    verifyReviewExecution(outcomeCreated.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_EXECUTION_TAMPERED'
  );

  const swapped = await fixture();
  context.after(async () => rm(swapped.root, { recursive: true, force: true }));
  const swappedPacket = swapped.packets[0]!;
  const swappedLimit = swappedPacket.estimatedInputTokens + 10;
  const swappedCreated = await createReviewExecution({
    campaignDirectory: swapped.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 2, maxTokens: swappedLimit * 2, maxTimeMs: 200 }
  });
  const first = await startReviewAttempt({
    executionDirectory: swappedCreated.directory,
    packetId: swappedPacket.packetId,
    reviewer: { kind: 'agent', identity: 'swap-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: swappedLimit,
    timeLimitMs: 100
  });
  await failReviewAttempt({
    executionDirectory: swappedCreated.directory,
    attemptId: first.attempt.attemptId,
    usage: { inputTokens: 0, outputTokens: 0, durationMs: 0 },
    failure: { code: 'RETRY', message: 'Create a second attempt.' }
  });
  const second = await retryReviewAttempt({
    executionDirectory: swappedCreated.directory,
    packetId: swappedPacket.packetId,
    reviewer: { kind: 'agent', identity: 'swap-reviewer', version: '1', promptVersion: 'prompt-1' },
    tokenLimit: swappedLimit,
    timeLimitMs: 100
  });
  const firstPath = path.join(swappedCreated.directory, 'attempts', `${first.attempt.attemptId}.json`);
  const secondPath = path.join(swappedCreated.directory, 'attempts', `${second.attempt.attemptId}.json`);
  const [firstText, secondText] = await Promise.all([readFile(firstPath, 'utf8'), readFile(secondPath, 'utf8')]);
  await Promise.all([writeFile(firstPath, secondText), writeFile(secondPath, firstText)]);
  await assert.rejects(
    verifyReviewExecution(swappedCreated.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_EXECUTION_TAMPERED'
  );
});

test('a dead primary lock is recovered and a recovery guard fails closed', async (context) => {
  const value = await fixture();
  context.after(async () => rm(value.root, { recursive: true, force: true }));
  const created = await createReviewExecution({
    campaignDirectory: value.campaignDirectory,
    budgets: { maxPackets: 1, maxCalls: 1, maxTokens: 100000, maxTimeMs: 100 }
  });
  const child = spawn(process.execPath, ['-e', 'process.exit(0)']);
  const childPid = child.pid!;
  await once(child, 'exit');
  const lockPath = path.join(path.dirname(created.directory), `.review-lock-${created.execution.campaignId}`);
  await writeFile(lockPath, `${childPid}:${'a'.repeat(32)}\n`, { flag: 'wx' });
  assert.equal((await verifyReviewExecution(created.directory)).status, 'passed');
  await assert.rejects(stat(lockPath), /ENOENT/);

  const guardOwner = spawn(process.execPath, ['-e', 'process.exit(0)']);
  const guardPid = guardOwner.pid!;
  await once(guardOwner, 'exit');
  const recoveryPath = path.join(path.dirname(created.directory), `.review-lock-recovery-${created.execution.campaignId}`);
  const primaryContent = `${guardPid}:${'b'.repeat(32)}\n`;
  const recoveryContent = `${guardPid}:${'c'.repeat(32)}\n`;
  await Promise.all([
    writeFile(lockPath, primaryContent, { flag: 'wx' }),
    writeFile(recoveryPath, recoveryContent, { flag: 'wx' })
  ]);
  await assert.rejects(
    verifyReviewExecution(created.directory),
    (error: unknown) => error instanceof AtlasError && error.code === 'REVIEW_EXECUTION_BUSY'
  );
  assert.equal(await readFile(lockPath, 'utf8'), primaryContent);
  assert.equal(await readFile(recoveryPath, 'utf8'), recoveryContent);
});
