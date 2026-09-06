import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { TOOL_VERSION } from '../src/types.js';
import { MAX_REVIEW_RESULT_INPUT_BYTES } from '../src/review-execution/types.js';

const CLI_PATH = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const PROJECT_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const CLI_TIMEOUT_MS = 30_000;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

interface CliResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

interface CliFixture {
  root: string;
  targetRoot: string;
  targetConfigPath: string;
  profilePath: string;
  workspacePath: string;
}

function runCli(argumentsList: string[], input = '', cliPath = CLI_PATH): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...argumentsList], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let forcedError: Error | undefined;
    let settled = false;
    const timer = setTimeout(() => {
      forcedError = new Error(`Atlas CLI exceeded its ${CLI_TIMEOUT_MS} ms test timeout.`);
      child.kill();
    }, CLI_TIMEOUT_MS);

    const capture = (destination: Buffer[], chunk: Buffer): void => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT_BYTES) {
        forcedError = new Error(`Atlas CLI exceeded its ${MAX_OUTPUT_BYTES} byte test output limit.`);
        child.kill();
        return;
      }
      destination.push(chunk);
    };
    child.stdout.on('data', (chunk: Buffer) => capture(stdout, chunk));
    child.stderr.on('data', (chunk: Buffer) => capture(stderr, chunk));
    child.stdin.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EPIPE' || settled) return;
      forcedError = error;
      child.kill();
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      reject(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (forcedError) {
        reject(forcedError);
        return;
      }
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8')
      });
    });
    child.stdin.end(input);
  });
}

async function isolatedRegressionCli(root: string): Promise<{ cliPath: string; corpusPath: string }> {
  const runtime = path.join(root, 'runtime');
  await mkdir(runtime, { recursive: true });
  await Promise.all([
    cp(path.join(PROJECT_ROOT, 'dist', 'src'), path.join(runtime, 'dist', 'src'), { recursive: true }),
    cp(path.join(PROJECT_ROOT, 'schemas'), path.join(runtime, 'schemas'), { recursive: true }),
    cp(path.join(PROJECT_ROOT, 'corpus'), path.join(runtime, 'corpus'), { recursive: true })
  ]);
  return {
    cliPath: path.join(runtime, 'dist', 'src', 'cli.js'),
    corpusPath: path.join(runtime, 'corpus', 'incidents', 'synthetic-operational-risks', 'manifest.json')
  };
}

function successful(result: CliResult): void {
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, '');
}

function jsonOutput<T>(result: CliResult): T {
  successful(result);
  assert.notEqual(result.stdout, '');
  return JSON.parse(result.stdout) as T;
}

async function createCliFixture(exportConsent = false): Promise<CliFixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-cli-e2e-'));
  const targetRoot = path.join(root, 'target');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  const workspacePath = path.join(root, 'workspace');
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await writeFile(path.join(targetRoot, 'src', 'index.ts'), [
    "import { format } from './format.js';",
    'export const ready = format("ready");',
    ''
  ].join('\n'));
  await writeFile(path.join(targetRoot, 'src', 'format.ts'), 'export const format = (value: string) => value;\n');
  await writeFile(path.join(targetRoot, 'src', 'orphan.ts'), 'export const orphan = true;\n');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'cli-e2e-target',
    path: './target',
    consent: {
      agentReview: true,
      export: exportConsent,
      projectMemory: true
    }
  }, null, 2)}\n`);
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'cli-e2e-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  }, null, 2)}\n`);
  return { root, targetRoot, targetConfigPath, profilePath, workspacePath };
}

test('CLI help and usage failures preserve stdout, stderr, and exit-code contracts', { timeout: 60_000 }, async () => {
  const help = await runCli(['help']);
  successful(help);
  assert.match(help.stdout, new RegExp(`^Atlas ${TOOL_VERSION.replaceAll('.', '\\.')}\\n\\nUsage:`, 'u'));
  assert.match(help.stdout, /atlas memory serve/u);
  assert.match(help.stdout, /atlas review execution/u);
  assert.match(help.stdout, /atlas regression verify \[--output <report\.json>\]/u);
  assert.match(help.stdout, /atlas regression real-target \[--checkout <detached-checkout> \| --target <target\.json-or-checkout>\]/u);

  const duplicateOption = await runCli(['scan', '--workspace', 'first', '--workspace', 'second']);
  assert.equal(duplicateOption.code, 1);
  assert.equal(duplicateOption.signal, null);
  assert.equal(duplicateOption.stdout, '');
  const failure = JSON.parse(duplicateOption.stderr) as {
    status: string;
    error: { code: string; message: string };
  };
  assert.deepEqual(failure, {
    status: 'failed',
    error: { code: 'CLI_USAGE', message: 'Duplicate option --workspace.' }
  });

  const missingDispositionPath = await runCli(['scan', '--dispositions']);
  assert.equal(missingDispositionPath.code, 1);
  assert.deepEqual(JSON.parse(missingDispositionPath.stderr), {
    status: 'failed',
    error: { code: 'CLI_USAGE', message: '--dispositions requires a ledger path.' }
  });

  const hostileCommand = 'unsafe\u009B31m\u202Etxt';
  const terminalSafeFailure = await runCli([hostileCommand]);
  assert.equal(terminalSafeFailure.code, 1);
  assert.doesNotMatch(terminalSafeFailure.stderr, /[\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u);
  assert.match(terminalSafeFailure.stderr, /unsafe\\u009B31m\\u202Etxt/u);
  assert.equal(
    (JSON.parse(terminalSafeFailure.stderr) as { error: { message: string } }).error.message,
    `Unknown command: ${hostileCommand}`
  );
});

test('review-result CLI input is size-bounded before JSON parsing', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-cli-review-size-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const resultPath = path.join(root, 'oversized-result.json');
  await writeFile(resultPath, Buffer.alloc(MAX_REVIEW_RESULT_INPUT_BYTES + 1, 0x20));

  const result = await runCli([
    'review', 'execution', 'complete', path.join(root, 'missing-execution'), '--result', resultPath
  ]);
  assert.equal(result.code, 1);
  assert.equal((JSON.parse(result.stderr) as { error: { code: string } }).error.code, 'REVIEW_RESULT_RESOURCE_LIMIT');
});

test('real-target CLI accepts a clear checkout flag and resolves legacy target descriptors', async (context) => {
  const fixture = await createCliFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));

  const byCheckout = await runCli([
    'regression', 'real-target', '--checkout', fixture.targetRoot
  ]);
  const byDescriptor = await runCli([
    'regression', 'real-target', '--target', fixture.targetConfigPath
  ]);
  assert.equal(byCheckout.code, 0, byCheckout.stderr);
  assert.equal(byDescriptor.code, 0, byDescriptor.stderr);
  assert.deepEqual(JSON.parse(byDescriptor.stdout), JSON.parse(byCheckout.stdout));
  const diagnosticCodes = (JSON.parse(byDescriptor.stdout) as {
    diagnostics: Array<{ code: string }>;
  }).diagnostics.map((entry) => entry.code);
  assert(diagnosticCodes.includes('REAL_TARGET_GIT_UNAVAILABLE'));
  assert.equal(diagnosticCodes.includes('REAL_TARGET_UNAVAILABLE'), false);

  const conflicting = await runCli([
    'regression', 'real-target', '--checkout', fixture.targetRoot, '--target', fixture.targetConfigPath
  ]);
  assert.equal(conflicting.code, 1);
  assert.equal((JSON.parse(conflicting.stderr) as { error: { code: string } }).error.code, 'CLI_USAGE');
});

test('CLI regression verification emits a portable immutable report and distinct complete, incomplete, and error exits', { timeout: 120_000 }, async (context) => {
  const root = await mkdtemp(path.join(PROJECT_ROOT, '.atlas-cli-regression-test-'));
  context.after(async () => rm(root, { recursive: true, force: true }));

  const reportPath = path.join(root, 'reports', 'regression.json');
  const complete = await runCli(['regression', 'verify', '--output', reportPath]);
  assert.equal(complete.code, 0, complete.stderr);
  assert.equal(complete.stderr, '');
  const report = JSON.parse(complete.stdout) as {
    kind: string;
    status: string;
    ruleHealth: { total: number; enabled: number; disabled: number };
    incidentRecall: { tier: string; numerator: number; denominator: number };
    realTargetEvaluation: { tier: string; result: string; reportContract: string };
    fixedCaseSilence: { numerator: number; denominator: number };
    incidents: unknown[];
  };
  assert.equal(report.kind, 'atlas-incident-regression-report');
  assert.equal(report.status, 'passed');
  assert.deepEqual(report.ruleHealth, {
    total: 9,
    enabled: 9,
    disabled: 0,
    disabledRuleIds: [],
    incompleteInputRuleIds: [],
    controls: {
      total: 21,
      passed: 21,
      failed: 0,
      expectedObservations: 21,
      observedObservations: 21
    }
  });
  assert.deepEqual(report.incidentRecall, { tier: 'synthetic', numerator: 21, denominator: 21 });
  assert.deepEqual(report.realTargetEvaluation, {
    tier: 'real-target',
    result: 'not-recorded-in-run',
    reportContract: 'real-target-corpus-report.schema.json'
  });
  assert.deepEqual(report.fixedCaseSilence, { numerator: 21, denominator: 21 });
  assert.equal(report.incidents.length, 21);
  assert.equal(await readFile(reportPath, 'utf8'), complete.stdout);

  const reused = await runCli(['regression', 'verify', '--output', reportPath]);
  assert.equal(reused.code, 0, reused.stderr);
  assert.equal(reused.stdout, complete.stdout);

  const realTargetReportPath = path.join(root, 'reports', 'real-target.json');
  const realTargetAbsent = await runCli(['regression', 'real-target', '--output', realTargetReportPath]);
  assert.equal(realTargetAbsent.code, 0, realTargetAbsent.stderr);
  assert.equal(realTargetAbsent.stderr, '');
  const realTargetReport = JSON.parse(realTargetAbsent.stdout) as {
    tier: string;
    status: string;
    realTargetRecall: { numerator: number; denominator: number };
    diagnostics: Array<{ code: string }>;
  };
  assert.equal(realTargetReport.tier, 'real-target');
  assert.equal(realTargetReport.status, 'not-evaluated');
  assert.deepEqual(realTargetReport.realTargetRecall, { numerator: 0, denominator: 0 });
  assert.deepEqual(realTargetReport.diagnostics.map((entry) => entry.code), ['REAL_TARGET_ABSENT']);
  assert.equal(await readFile(realTargetReportPath, 'utf8'), realTargetAbsent.stdout);

  const isolated = await isolatedRegressionCli(root);
  const corpus = JSON.parse(await readFile(isolated.corpusPath, 'utf8')) as {
    cases: Array<{ expected: { brokenMinimum: number } }>;
  };
  corpus.cases[0]!.expected.brokenMinimum += 1;
  await writeFile(isolated.corpusPath, `${JSON.stringify(corpus, null, 2)}\n`, 'utf8');
  const incomplete = await runCli(['regression', 'verify'], '', isolated.cliPath);
  assert.equal(incomplete.code, 2, incomplete.stderr);
  assert.equal(incomplete.stderr, '');
  const incompleteReport = JSON.parse(incomplete.stdout) as {
    status: string;
    ruleHealth: { disabled: number; disabledRuleIds: string[] };
    incidentHealth: { failed: number; failedIncidentIds: string[]; unsupported: number };
  };
  assert.equal(incompleteReport.status, 'incomplete');
  assert.equal(incompleteReport.ruleHealth.disabled, 1);
  assert.deepEqual(incompleteReport.ruleHealth.disabledRuleIds, ['operational/silent-empty-instrument-v1']);
  assert.equal(incompleteReport.incidentHealth.failed, 1);
  assert.deepEqual(incompleteReport.incidentHealth.failedIncidentIds, ['silent-empty-pass-with-no-tests']);
  assert.equal(incompleteReport.incidentHealth.unsupported, 0);

  const scanFixture = await createCliFixture(true);
  context.after(async () => rm(scanFixture.root, { recursive: true, force: true }));
  const incompleteScan = await runCli([
    'scan',
    '--target', scanFixture.targetConfigPath,
    '--profile', scanFixture.profilePath,
    '--workspace', scanFixture.workspacePath
  ], '', isolated.cliPath);
  assert.equal(incompleteScan.code, 2, incompleteScan.stderr);
  assert.equal(incompleteScan.stderr, '');
  const incompleteScanReport = JSON.parse(incompleteScan.stdout) as {
    status: string;
    runDirectory: string;
    analysisHealth: { state: string; status: string; ruleHealth: { disabled: number } };
  };
  assert.equal(incompleteScanReport.status, 'completed');
  assert.equal(incompleteScanReport.analysisHealth.state, 'recorded');
  assert.equal(incompleteScanReport.analysisHealth.status, 'incomplete');
  assert.equal(incompleteScanReport.analysisHealth.ruleHealth.disabled, 1);
  const incompleteVerification = await runCli(['verify', incompleteScanReport.runDirectory], '', isolated.cliPath);
  assert.equal(incompleteVerification.code, 2, incompleteVerification.stderr);
  assert.equal(
    (JSON.parse(incompleteVerification.stdout) as { analysisHealth: { status: string } }).analysisHealth.status,
    'incomplete'
  );

  const incompleteViewerDirectory = path.join(scanFixture.root, 'incomplete-viewer');
  const incompleteViewer = await runCli([
    'viewer', 'create', incompleteScanReport.runDirectory,
    '--workspace', scanFixture.workspacePath,
    '--target', scanFixture.targetConfigPath,
    '--output', incompleteViewerDirectory
  ], '', isolated.cliPath);
  assert.equal(incompleteViewer.code, 2, incompleteViewer.stderr);
  assert.equal(incompleteViewer.stderr, '');
  const incompletePublication = JSON.parse(incompleteViewer.stdout) as {
    healthState: string;
    healthStatus: string;
  };
  assert.equal(incompletePublication.healthState, 'recorded');
  assert.equal(incompletePublication.healthStatus, 'incomplete');
  const incompleteViewerVerification = await runCli(
    ['viewer', 'verify', incompleteViewerDirectory],
    '',
    isolated.cliPath
  );
  assert.equal(incompleteViewerVerification.code, 2, incompleteViewerVerification.stderr);
  assert.equal(incompleteViewerVerification.stderr, '');
  const incompleteViewerSummary = JSON.parse(incompleteViewerVerification.stdout) as {
    status: string;
    healthState: string;
    healthStatus: string;
  };
  assert.equal(incompleteViewerSummary.status, 'passed');
  assert.equal(incompleteViewerSummary.healthState, 'recorded');
  assert.equal(incompleteViewerSummary.healthStatus, 'incomplete');

  await writeFile(isolated.corpusPath, '{', 'utf8');
  const malformed = await runCli(['regression', 'verify'], '', isolated.cliPath);
  assert.equal(malformed.code, 1);
  assert.equal(malformed.stdout, '');
  assert.equal((JSON.parse(malformed.stderr) as { status: string }).status, 'failed');

  const outputConflict = path.join(root, 'conflict.json');
  await writeFile(outputConflict, '{}\n', 'utf8');
  const conflict = await runCli(['regression', 'verify', '--output', outputConflict]);
  assert.equal(conflict.code, 1);
  assert.equal(conflict.stdout, '');
  assert.equal((JSON.parse(conflict.stderr) as { error: { code: string } }).error.code, 'REPORT_OUTPUT_EXISTS');
});

test('CLI subprocesses scan, inspect, query, serve memory, plan incrementally, and create review packets', { timeout: 180_000 }, async (context) => {
  const fixture = await createCliFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));

  const scanResult = await runCli([
    'scan',
    '--target', fixture.targetConfigPath,
    '--profile', fixture.profilePath,
    '--workspace', fixture.workspacePath
  ]);
  assert.equal(scanResult.code, 2, scanResult.stderr);
  assert.equal(scanResult.stderr, '');
  const scan = JSON.parse(scanResult.stdout) as {
    status: string;
    runDirectory: string;
    run: { runId: string; snapshotId: string; targetId: string; counts: { files: number } };
    analysisHealth: {
      state: string;
      status: string;
      ruleHealth: { enabled: number; disabled: number };
      incidentRecall: { tier: string; numerator: number; denominator: number };
      realTargetEvaluation: { tier: string; result: string; reportContract: string };
    };
  };
  assert.equal(scan.status, 'completed');
  assert.equal(scan.run.targetId, 'cli-e2e-target');
  assert.equal(scan.run.counts.files, 3);
  assert.equal(scan.analysisHealth.state, 'recorded');
  assert.equal(scan.analysisHealth.status, 'incomplete');
  assert.deepEqual(scan.analysisHealth.ruleHealth, {
    total: 9,
    enabled: 9,
    disabled: 0,
    disabledRuleIds: [],
    incompleteInputRuleIds: ['latent/accidental-protection-v1'],
    controls: {
      total: 21,
      passed: 21,
      failed: 0,
      expectedObservations: 21,
      observedObservations: 21
    }
  });
  assert.deepEqual(scan.analysisHealth.incidentRecall, { tier: 'synthetic', numerator: 21, denominator: 21 });
  assert.deepEqual(scan.analysisHealth.realTargetEvaluation, {
    tier: 'real-target',
    result: 'not-recorded-in-run',
    reportContract: 'real-target-corpus-report.schema.json'
  });
  assert.equal(path.relative(fixture.workspacePath, scan.runDirectory).split(path.sep)[0], 'runs');

  const verificationResult = await runCli(['verify', scan.runDirectory]);
  assert.equal(verificationResult.code, 2, verificationResult.stderr);
  assert.equal(verificationResult.stderr, '');
  const verification = JSON.parse(verificationResult.stdout) as {
    status: string;
    runId: string;
    files: number;
    analysisHealth: {
      state: string;
      status: string;
      incidentRecall: { tier: string; numerator: number; denominator: number };
    };
  };
  assert.equal(verification.status, 'passed');
  assert.equal(verification.runId, scan.run.runId);
  assert.equal(verification.files, 3);
  assert.equal(verification.analysisHealth.state, 'recorded');
  assert.equal(verification.analysisHealth.status, 'incomplete');
  assert.deepEqual(verification.analysisHealth.incidentRecall, {
    tier: 'synthetic', numerator: 21, denominator: 21
  });

  const inspection = jsonOutput<{
    kind: string;
    runId: string;
    file: { path: string; symbols: string[] };
    outgoing: unknown[];
  }>(await runCli(['inspect', scan.runDirectory, '--file', 'src/index.ts']));
  assert.equal(inspection.kind, 'file');
  assert.equal(inspection.runId, scan.run.runId);
  assert.equal(inspection.file.path, 'src/index.ts');
  assert(inspection.file.symbols.includes('ready'));
  assert.equal(inspection.outgoing.length, 1);

  const neighborhood = await runCli([
    'inspect', scan.runDirectory,
    '--neighborhood', 'src/index.ts',
    '--depth', '1',
    '--direction', 'outgoing',
    '--format', 'text'
  ]);
  successful(neighborhood);
  assert.match(neighborhood.stdout, /^Atlas inspection: neighborhood\n/u);
  assert.match(neighborhood.stdout, /Seed: src\/index\.ts/u);
  assert.match(neighborhood.stdout, /Direction\/depth: outgoing\/1/u);

  const query = jsonOutput<{
    runId: string;
    query: string;
    hits: Array<{ path?: string; evidence: unknown[] }>;
  }>(await runCli(['query', scan.runDirectory, '--text', 'format', '--limit', '5']));
  assert.equal(query.runId, scan.run.runId);
  assert.equal(query.query, 'format');
  assert(query.hits.length > 0);
  assert(query.hits.every((hit) => hit.evidence.length > 0));

  const memoryArguments = [
    scan.runDirectory,
    '--workspace', fixture.workspacePath,
    '--target', fixture.targetConfigPath,
    '--profile', fixture.profilePath
  ];
  const memory = jsonOutput<{
    targetId: string;
    runId: string;
    answer: { kind: string };
    freshness: { status: string };
    hits: unknown[];
  }>(await runCli(['memory', 'lookup', ...memoryArguments, '--text', 'format', '--limit', '3']));
  assert.equal(memory.targetId, 'cli-e2e-target');
  assert.equal(memory.runId, scan.run.runId);
  assert.equal(memory.answer.kind, 'matches');
  assert.equal(memory.freshness.status, 'current');
  assert(memory.hits.length > 0);

  const serviceInput = [
    JSON.stringify({ id: 'valid', method: 'memory.lookup', params: { query: 'format', limit: 2 } }),
    JSON.stringify({ id: 'invalid', method: 'memory.lookup', params: { query: 'format', target: 'other' } }),
    ''
  ].join('\n');
  const service = await runCli(['memory', 'serve', ...memoryArguments], serviceInput);
  successful(service);
  const serviceLines = service.stdout.trimEnd().split('\n').map((line) => JSON.parse(line) as {
    id: string;
    result?: { runId: string; hits: unknown[] };
    error?: { code: string };
  });
  assert.equal(serviceLines.length, 2);
  assert.equal(serviceLines[0]?.id, 'valid');
  assert.equal(serviceLines[0]?.result?.runId, scan.run.runId);
  assert((serviceLines[0]?.result?.hits.length ?? 0) > 0);
  assert.equal(serviceLines[1]?.id, 'invalid');
  assert.equal(serviceLines[1]?.error?.code, 'INVALID_MEMORY_REQUEST');

  const incremental = jsonOutput<{
    targetId: string;
    baseline: { runId: string };
    next: { runId: string };
    compatibility: { incrementalReuseEligible: boolean; fullRebuildReasons: string[] };
    paths: { added: string[]; changed: string[]; removed: string[] };
    cache: { hitEligiblePaths: string[]; missRequiredPaths: string[]; evictedPaths: string[] };
  }>(await runCli([
    'incremental', 'plan',
    '--workspace', fixture.workspacePath,
    '--target-id', 'cli-e2e-target',
    '--baseline', scan.runDirectory,
    '--next', scan.runDirectory
  ]));
  assert.equal(incremental.targetId, 'cli-e2e-target');
  assert.equal(incremental.baseline.runId, scan.run.runId);
  assert.equal(incremental.next.runId, scan.run.runId);
  assert.equal(incremental.compatibility.incrementalReuseEligible, true);
  assert.deepEqual(incremental.compatibility.fullRebuildReasons, []);
  assert.deepEqual(incremental.paths, { added: [], changed: [], removed: [] });
  assert.deepEqual(incremental.cache.hitEligiblePaths, ['src/format.ts', 'src/index.ts', 'src/orphan.ts']);
  assert.deepEqual(incremental.cache.missRequiredPaths, []);
  assert.deepEqual(incremental.cache.evictedPaths, []);

  const review = jsonOutput<{
    directory: string;
    campaign: { campaignId: string; runId: string; selection: string; fileCount: number; packetIds: string[] };
  }>(await runCli([
    'review', 'create', scan.runDirectory,
    '--workspace', fixture.workspacePath,
    '--target', fixture.targetConfigPath,
    '--selection', 'paths',
    '--selector', 'src/index.ts',
    '--batch-size', '1',
    '--purpose', 'CLI end-to-end review'
  ]));
  assert.equal(review.campaign.runId, scan.run.runId);
  assert.equal(review.campaign.selection, 'paths');
  assert.equal(review.campaign.fileCount, 1);
  assert.equal(review.campaign.packetIds.length, 1);

  const reviewStatus = jsonOutput<{
    campaign: { campaignId: string; fileCount: number };
    packets: unknown[];
  }>(await runCli(['review', 'status', review.directory]));
  assert.equal(reviewStatus.campaign.campaignId, review.campaign.campaignId);
  assert.equal(reviewStatus.campaign.fileCount, 1);
  assert.equal(reviewStatus.packets.length, 1);
});
