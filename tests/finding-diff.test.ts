import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { TRIAGE_HASHED_RUN_ARTIFACTS, TRIAGE_REPORT_ARTIFACT_NAME } from '../src/artifact-contract.js';
import {
  compareFindingRecords,
  compareFindingRuns,
  findingReviewIdentity,
  severityAtOrAbove,
  writeFindingDeltaReport
} from '../src/finding-diff.js';
import {
  assessFindingProducerCompatibility,
  findingProducerSignature,
  findingProducerSignatureId
} from '../src/finding-compatibility.js';
import { runIdentity } from '../src/identity.js';
import { scanProject } from '../src/run.js';
import { assertSchema } from '../src/schema-validator.js';
import { renderTriageReport } from '../src/triage-report.js';
import type { AnalysisHealthRecord, ArtifactManifest, DiagnosticRecord, FindingRecord, RunRecord } from '../src/types.js';
import {
  canonicalJson,
  compareCanonicalText,
  readJson,
  readJsonLines,
  sha256,
  writeCanonicalJson
} from '../src/util/canonical.js';

const CLI_PATH = fileURLToPath(new URL('../src/cli.js', import.meta.url));

function finding(options: {
  id: string;
  path?: string;
  line?: number;
  severity?: FindingRecord['severity'];
  title?: string;
  description?: string;
  patternKey?: string;
}): FindingRecord {
  const findingPath = options.path ?? 'src/service.ts';
  return {
    schemaVersion: 1,
    id: options.id,
    category: options.patternKey ? 'operational-defect' : 'contract-mismatch',
    ruleId: options.patternKey ? 'operational/result-collapse-v1' : 'contract/unresolved-internal-import-v1',
    ...(options.patternKey ? { kind: 'defect-candidate', patternKey: options.patternKey } : {}),
    status: 'candidate',
    severity: options.severity ?? 'high',
    confidence: 'high',
    title: options.title ?? `Unresolved internal module reference in ${findingPath}`,
    description: options.description ?? 'The JS/TS adapter could not resolve ./missing.js inside the declared snapshot boundary.',
    path: findingPath,
    relatedPaths: [],
    signals: ['unresolved-internal-module-specifier'],
    evidence: [{
      level: 2,
      producer: 'atlas/test',
      producerVersion: '1.0.0',
      basis: 'source-anchor',
      path: findingPath,
      line: options.line ?? 1,
      column: 1,
      recordIds: [`relationship:${options.id.slice('finding:'.length)}`]
    }],
    nextValidation: 'Inspect the source.'
  };
}

function runCli(argumentsList: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...argumentsList], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolve({
      code,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8')
    }));
  });
}

function runGit(repositoryPath: string, argumentsList: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', argumentsList, {
      cwd: repositoryPath,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => {
      if (code === 0) resolve(Buffer.concat(stdout).toString('utf8').trim());
      else reject(new Error(`git ${argumentsList[0] ?? ''} failed: ${Buffer.concat(stderr).toString('utf8')}`));
    });
  });
}

async function cloneWithRunContractMutation(
  source: string,
  destination: string,
  mutate: (run: RunRecord) => void
): Promise<void> {
  await cp(source, destination, { recursive: true });
  const [run, health, findings, diagnostics] = await Promise.all([
    readJson<RunRecord>(path.join(destination, 'run.json')),
    readJson<AnalysisHealthRecord>(path.join(destination, 'analysis-health.json')),
    readJsonLines<FindingRecord>(path.join(destination, 'findings.jsonl')),
    readJsonLines<DiagnosticRecord>(path.join(destination, 'diagnostics.jsonl'))
  ]);
  mutate(run);
  run.adapters.sort((left, right) => compareCanonicalText(left.id, right.id));
  run.analyses.sort(compareCanonicalText);
  run.runId = runIdentity({
    snapshotId: run.snapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses: run.analyses
  });
  health.runId = run.runId;
  await writeCanonicalJson(path.join(destination, 'run.json'), run);
  await writeCanonicalJson(path.join(destination, 'analysis-health.json'), health);
  await writeFile(
    path.join(destination, TRIAGE_REPORT_ARTIFACT_NAME),
    renderTriageReport(run, findings, diagnostics),
    'utf8'
  );
  const artifacts = await Promise.all(TRIAGE_HASHED_RUN_ARTIFACTS.map(async (artifactPath) => {
    const content = await readFile(path.join(destination, artifactPath));
    return { path: artifactPath, bytes: content.length, sha256: sha256(content) };
  }));
  artifacts.sort((left, right) => compareCanonicalText(left.path, right.path));
  const manifest: ArtifactManifest = { schemaVersion: 1, runId: run.runId, artifacts };
  await writeCanonicalJson(path.join(destination, 'artifact-digests.json'), manifest);
}

test('review identity and pairing survive source-line and finding-ID shifts', () => {
  const before = finding({ id: `finding:${'1'.repeat(24)}`, line: 4 });
  const after = finding({ id: `finding:${'2'.repeat(24)}`, line: 91, severity: 'medium' });

  assert.equal(findingReviewIdentity(after), findingReviewIdentity(before));
  const delta = compareFindingRecords([before], [after]);
  assert.equal(delta.new.length, 0);
  assert.equal(delta.resolved.length, 0);
  assert.equal(delta.unchanged.length, 1);
  assert.equal(delta.unchanged[0]?.baseline?.findingId, before.id);
  assert.equal(delta.unchanged[0]?.candidate?.findingId, after.id);
  assert.equal(delta.unchanged[0]?.candidate?.severity, 'medium');
});

test('review identity expires across producer and activation-context changes', () => {
  const current = finding({ id: `finding:${'1'.repeat(24)}` });
  const changedProducer: FindingRecord = {
    ...current,
    evidence: current.evidence.map((entry) => ({ ...entry, producerVersion: '2.0.0' }))
  };
  const production: FindingRecord = {
    ...current,
    impactContext: {
      reachability: 'reachable',
      scope: 'production',
      entrypoints: ['src/index.ts'],
      mountedSurfaces: [],
      lifecycle: 'active',
      featureGate: 'not-observed',
      summary: 'Production reachable.',
      limitations: []
    }
  };
  const testOnly: FindingRecord = {
    ...production,
    impactContext: { ...production.impactContext!, scope: 'test' }
  };

  assert.notEqual(findingReviewIdentity(changedProducer), findingReviewIdentity(current));
  assert.notEqual(findingReviewIdentity(production), findingReviewIdentity(testOnly));
});

test('review identity uses stable pattern keys plus source paths and preserves duplicate multiplicity', () => {
  const first = finding({
    id: `finding:${'3'.repeat(24)}`,
    path: 'src/first.ts',
    line: 10,
    patternKey: 'operational/result-collapse-v1:stable-pattern'
  });
  const second = finding({
    id: `finding:${'4'.repeat(24)}`,
    path: 'src/first.ts',
    line: 20,
    patternKey: 'operational/result-collapse-v1:stable-pattern'
  });
  const moved = finding({
    id: `finding:${'5'.repeat(24)}`,
    path: 'src/first.ts',
    line: 200,
    patternKey: 'operational/result-collapse-v1:stable-pattern'
  });
  const differentPath = finding({
    id: `finding:${'6'.repeat(24)}`,
    path: 'src/other.ts',
    line: 200,
    patternKey: 'operational/result-collapse-v1:stable-pattern'
  });

  assert.equal(findingReviewIdentity(first), findingReviewIdentity(moved));
  assert.notEqual(findingReviewIdentity(first), findingReviewIdentity(differentPath));
  const delta = compareFindingRecords([first, second], [moved]);
  assert.equal(delta.unchanged.length, 1);
  assert.equal(delta.resolved.length, 1);
  assert.equal(delta.new.length, 0);
  assert.deepEqual(
    [...delta.unchanged, ...delta.resolved].map((entry) => entry.occurrence),
    [1, 2]
  );
});

test('severity thresholds include only new findings at or above the selected level', () => {
  assert.equal(severityAtOrAbove('high', 'high'), true);
  assert.equal(severityAtOrAbove('medium', 'high'), false);
  assert.equal(severityAtOrAbove('low', 'info'), true);
  assert.equal(severityAtOrAbove('info', 'low'), false);
});

test('verified run diff emits deterministic deltas, gates new severity, and writes immutably', { timeout: 120_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-finding-diff-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  const sourcePath = path.join(targetRoot, 'src', 'index.ts');
  await mkdir(path.dirname(sourcePath), { recursive: true });
  await writeFile(sourcePath, 'export const ready = true;\n', 'utf8');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  }, null, 2)}\n`, 'utf8');

  const baseline = await scanProject({ targetConfigPath, profilePath, workspacePath });
  await writeFile(sourcePath, "import './missing.js';\nexport const ready = true;\n", 'utf8');
  await writeFile(path.join(targetRoot, 'src', 'additional.ts'), 'export const additional = true;\n', 'utf8');
  const candidate = await scanProject({ targetConfigPath, profilePath, workspacePath });

  const first = await compareFindingRuns({
    baselineRunDirectory: baseline.runDirectory,
    candidateRunDirectory: candidate.runDirectory,
    failOnNew: 'high'
  });
  const second = await compareFindingRuns({
    baselineRunDirectory: baseline.runDirectory,
    candidateRunDirectory: candidate.runDirectory,
    failOnNew: 'high'
  });
  assert.deepEqual(second, first);
  assert(first.findings.new.some((entry) =>
    entry.candidate?.ruleId === 'contract/unresolved-internal-import-v1' && entry.candidate.severity === 'high'
  ));
  assert.equal(first.gate.triggered, true);
  assert(first.gate.matchingNewFindings >= 1);
  assert.equal(first.compatibility.basis, 'exact');
  assert.match(first.compatibility.contractId, /^finding_contract_sha256_[a-f0-9]{64}$/u);
  assert.equal(first.compatibility.producer.name, 'atlas');
  assert(first.compatibility.adapters.length > 0);
  assert(first.compatibility.analyzers.length > 0);
  assert.deepEqual(first.compatibility.dispositions, []);

  const legacyReport = structuredClone(first) as unknown as {
    producer: { version: string };
    compatibility: Partial<typeof first.compatibility>;
  };
  legacyReport.producer.version = '1.0.0';
  delete legacyReport.compatibility.basis;
  delete legacyReport.compatibility.contractId;
  delete legacyReport.compatibility.candidate;
  await assertSchema('finding-delta', legacyReport, 'Legacy finding delta report');

  const incompleteCurrentReport = structuredClone(first) as unknown as {
    compatibility: Partial<typeof first.compatibility>;
  };
  delete incompleteCurrentReport.compatibility.basis;
  delete incompleteCurrentReport.compatibility.contractId;
  await assert.rejects(
    assertSchema('finding-delta', incompleteCurrentReport, 'Incomplete current finding delta report'),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );

  await writeFile(sourcePath, "\n\nimport './missing.js';\nexport const ready = true;\n", 'utf8');
  const lineShifted = await scanProject({ targetConfigPath, profilePath, workspacePath });
  const shiftedDelta = await compareFindingRuns({
    baselineRunDirectory: candidate.runDirectory,
    candidateRunDirectory: lineShifted.runDirectory
  });
  const unresolvedShift = shiftedDelta.findings.unchanged.find((entry) =>
    entry.candidate?.ruleId === 'contract/unresolved-internal-import-v1'
  );
  assert(unresolvedShift);
  assert.notEqual(unresolvedShift.baseline?.findingId, unresolvedShift.candidate?.findingId);

  const outputPath = path.join(root, 'reports', 'delta.json');
  const written = await writeFindingDeltaReport({
    baselineRunDirectory: baseline.runDirectory,
    candidateRunDirectory: candidate.runDirectory,
    failOnNew: 'high',
    targetConfigPath,
    outputPath
  }, first);
  assert.equal(written.reused, false);
  const reused = await writeFindingDeltaReport({
    baselineRunDirectory: baseline.runDirectory,
    candidateRunDirectory: candidate.runDirectory,
    failOnNew: 'high',
    targetConfigPath,
    outputPath
  }, first);
  assert.equal(reused.reused, true);

  const archiveRoot = path.join(root, 'archived-runs');
  const archivedBaselineDirectory = path.join(archiveRoot, baseline.run.runId);
  const archivedCandidateDirectory = path.join(archiveRoot, candidate.run.runId);
  await mkdir(archiveRoot, { recursive: true });
  await Promise.all([
    cp(baseline.runDirectory, archivedBaselineDirectory, { recursive: true }),
    cp(candidate.runDirectory, archivedCandidateDirectory, { recursive: true })
  ]);
  const archivedReport = await compareFindingRuns({
    baselineRunDirectory: archivedBaselineDirectory,
    candidateRunDirectory: archivedCandidateDirectory,
    failOnNew: 'high'
  });
  assert.deepEqual(archivedReport, first);
  await writeFindingDeltaReport({
    baselineRunDirectory: archivedBaselineDirectory,
    candidateRunDirectory: archivedCandidateDirectory,
    failOnNew: 'high',
    targetConfigPath,
    outputPath: path.join(root, 'reports', 'archived-delta.json')
  }, archivedReport);
  const pairedArchivedReport = await compareFindingRuns({
    baselineRunDirectory: archivedBaselineDirectory,
    candidateRunDirectory: archivedCandidateDirectory,
    baselineTargetConfigPath: targetConfigPath,
    candidateTargetConfigPath: targetConfigPath,
    failOnNew: 'high'
  });
  assert.deepEqual(pairedArchivedReport, first);
  await assert.rejects(
    writeFindingDeltaReport({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: candidate.runDirectory,
      targetConfigPath,
      outputPath: path.join(candidate.runDirectory, 'delta.json')
    }, first),
    (error: unknown) => (error as { code?: string }).code === 'REPORT_OUTPUT_UNSAFE'
  );
  await assert.rejects(
    writeFindingDeltaReport({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: candidate.runDirectory,
      targetConfigPath,
      outputPath: path.join(targetRoot, 'delta.json')
    }, first),
    (error: unknown) => (error as { code?: string }).code === 'REPORT_OUTPUT_UNSAFE'
  );

  const cliOutput = path.join(root, 'reports', 'cli-delta.json');
  const cli = await runCli([
    'diff',
    '--baseline', baseline.runDirectory,
    '--candidate', candidate.runDirectory,
    '--fail-on-new', 'high',
    '--target', targetConfigPath,
    '--output', cliOutput
  ]);
  assert.equal(cli.code, 3, cli.stderr);
  assert.equal(cli.stderr, '');
  const cliReport = JSON.parse(cli.stdout) as typeof first;
  assert.equal(cliReport.gate.triggered, true);
  assert.equal(await readFile(cliOutput, 'utf8'), cli.stdout);

  const unboundCliOutput = path.join(root, 'reports', 'unbound-cli-delta.json');
  const unboundOutput = await runCli([
    'diff',
    '--baseline', baseline.runDirectory,
    '--candidate', candidate.runDirectory,
    '--output', unboundCliOutput
  ]);
  assert.equal(unboundOutput.code, 1);
  assert.equal(unboundOutput.stdout, '');
  assert.equal((JSON.parse(unboundOutput.stderr) as { error: { code: string } }).error.code, 'CLI_USAGE');
  await assert.rejects(readFile(unboundCliOutput, 'utf8'), { code: 'ENOENT' });

  const invalid = await runCli([
    'diff',
    '--baseline', baseline.runDirectory,
    '--candidate', candidate.runDirectory,
    '--fail-on-new', 'critical'
  ]);
  assert.equal(invalid.code, 1);
  assert.equal(invalid.stdout, '');
  assert.equal((JSON.parse(invalid.stderr) as { error: { code: string } }).error.code, 'CLI_USAGE');
});

test('verified run diff proves distinct target IDs are pinned worktrees of one repository', { timeout: 180_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-finding-diff-worktrees-'));
  const repositoryRoot = path.join(root, 'repository');
  const baselineRoot = path.join(root, 'baseline-checkout');
  const candidateRoot = path.join(root, 'candidate-checkout');
  const alienRepositoryRoot = path.join(root, 'alien-repository');
  const alienRoot = path.join(root, 'alien-checkout');
  context.after(async () => {
    await runGit(repositoryRoot, ['worktree', 'remove', '--force', baselineRoot]).catch(() => undefined);
    await runGit(repositoryRoot, ['worktree', 'remove', '--force', candidateRoot]).catch(() => undefined);
    await runGit(alienRepositoryRoot, ['worktree', 'remove', '--force', alienRoot]).catch(() => undefined);
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });
  const workspacePath = path.join(root, 'workspace');
  const baselineTargetConfigPath = path.join(root, 'baseline-target.json');
  const candidateTargetConfigPath = path.join(root, 'candidate-target.json');
  const profilePath = path.join(root, 'profile.json');

  await runGit(root, ['init', '--initial-branch=main', repositoryRoot]);
  await runGit(repositoryRoot, ['config', 'user.name', 'Atlas Tests']);
  await runGit(repositoryRoot, ['config', 'user.email', 'atlas-tests@example.invalid']);
  await runGit(repositoryRoot, ['config', 'core.autocrlf', 'false']);
  await mkdir(path.join(repositoryRoot, 'src'), { recursive: true });
  await writeFile(path.join(repositoryRoot, 'src', 'index.ts'), 'export const ready = true;\n', 'utf8');
  await runGit(repositoryRoot, ['add', '--', 'src/index.ts']);
  await runGit(repositoryRoot, ['commit', '-m', 'baseline']);
  const baselineRevision = await runGit(repositoryRoot, ['rev-parse', 'HEAD']);
  await writeFile(
    path.join(repositoryRoot, 'src', 'index.ts'),
    "import './missing.js';\nexport const ready = true;\n",
    'utf8'
  );
  await runGit(repositoryRoot, ['add', '--', 'src/index.ts']);
  await runGit(repositoryRoot, ['commit', '-m', 'candidate']);
  const candidateRevision = await runGit(repositoryRoot, ['rev-parse', 'HEAD']);
  await runGit(repositoryRoot, ['worktree', 'add', '--detach', baselineRoot, baselineRevision]);
  await runGit(repositoryRoot, ['worktree', 'add', '--detach', candidateRoot, candidateRevision]);

  await writeFile(baselineTargetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-baseline-checkout',
    path: './baseline-checkout',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(candidateTargetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-candidate-checkout',
    path: './candidate-checkout',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-worktree-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  }, null, 2)}\n`, 'utf8');

  const baseline = await scanProject({
    targetConfigPath: baselineTargetConfigPath,
    profilePath,
    workspacePath
  });
  const candidate = await scanProject({
    targetConfigPath: candidateTargetConfigPath,
    profilePath,
    workspacePath
  });
  const comparisonOptions = {
    baselineRunDirectory: baseline.runDirectory,
    candidateRunDirectory: candidate.runDirectory,
    baselineTargetConfigPath,
    candidateTargetConfigPath,
    failOnNew: 'high' as const
  };
  const report = await compareFindingRuns(comparisonOptions);
  assert.deepEqual(report.target, {
    id: 'finding-diff-baseline-checkout',
    candidateId: 'finding-diff-candidate-checkout',
    equivalence: 'shared-git-common-directory-v1'
  });
  assert.equal(report.compatibility.basis, 'exact');
  assert.equal(report.gate.triggered, true);
  assert(report.gate.matchingNewFindings >= 1);
  assert.equal(canonicalJson(report).includes(baselineRoot), false);
  assert.equal(canonicalJson(report).includes(candidateRoot), false);

  const outputPath = path.join(root, 'reports', 'worktree-delta.json');
  await writeFindingDeltaReport({ ...comparisonOptions, outputPath }, report);
  for (const protectedOutput of [
    baselineTargetConfigPath,
    candidateTargetConfigPath,
    path.join(baselineRoot, 'delta.json'),
    path.join(candidateRoot, 'delta.json'),
    path.join(baseline.runDirectory, 'delta.json'),
    path.join(candidate.runDirectory, 'delta.json')
  ]) {
    await assert.rejects(
      writeFindingDeltaReport({ ...comparisonOptions, outputPath: protectedOutput }, report),
      (error: unknown) => (error as { code?: string }).code === 'REPORT_OUTPUT_UNSAFE'
    );
  }

  const cliOutputPath = path.join(root, 'reports', 'worktree-cli-delta.json');
  const cli = await runCli([
    'diff',
    '--baseline', baseline.runDirectory,
    '--candidate', candidate.runDirectory,
    '--baseline-target', baselineTargetConfigPath,
    '--candidate-target', candidateTargetConfigPath,
    '--fail-on-new', 'high',
    '--output', cliOutputPath
  ]);
  assert.equal(cli.code, 3, cli.stderr);
  assert.equal((JSON.parse(cli.stdout) as typeof report).gate.triggered, true);

  const dirtyPaths = Array.from({ length: 12 }, (_, index) =>
    path.join(baselineRoot, 'src', `dirty-fixture-${String(index).padStart(2, '0')}.ts`)
  );
  await Promise.all(dirtyPaths.map((dirtyPath, index) =>
    writeFile(
      dirtyPath,
      `export const dirty${index} = true;\n`,
      'utf8'
    )
  ));
  const dirtyBaseline = await scanProject({
    targetConfigPath: baselineTargetConfigPath,
    profilePath,
    workspacePath
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: dirtyBaseline.runDirectory,
      candidateRunDirectory: candidate.runDirectory,
      baselineTargetConfigPath,
      candidateTargetConfigPath
    }),
    (error: unknown) => {
      const candidateError = error as { code?: string; message?: string };
      return candidateError.code === 'FINDING_DIFF_CHECKOUT_UNPROVEN' &&
        candidateError.message?.includes('12 unclean records') === true &&
        candidateError.message.includes('2 more omitted') &&
        candidateError.message.includes('src/dirty-fixture-00.ts') &&
        !candidateError.message.includes('src/dirty-fixture-10.ts') &&
        !candidateError.message.includes(baselineRoot);
    }
  );
  await Promise.all(dirtyPaths.map((dirtyPath) => rm(dirtyPath, { force: true })));

  const incompletePair = await runCli([
    'diff',
    '--baseline', baseline.runDirectory,
    '--candidate', candidate.runDirectory,
    '--baseline-target', baselineTargetConfigPath
  ]);
  assert.equal(incompletePair.code, 1);
  assert.equal((JSON.parse(incompletePair.stderr) as { error: { code: string } }).error.code, 'CLI_USAGE');

  const alienTargetConfigPath = path.join(root, 'alien-target.json');
  await runGit(root, ['init', '--initial-branch=main', alienRepositoryRoot]);
  await runGit(alienRepositoryRoot, ['config', 'user.name', 'Atlas Tests']);
  await runGit(alienRepositoryRoot, ['config', 'user.email', 'atlas-tests@example.invalid']);
  await runGit(alienRepositoryRoot, ['config', 'core.autocrlf', 'false']);
  await mkdir(path.join(alienRepositoryRoot, 'src'), { recursive: true });
  await writeFile(path.join(alienRepositoryRoot, 'src', 'index.ts'), 'export const alien = true;\n', 'utf8');
  await runGit(alienRepositoryRoot, ['add', '--', 'src/index.ts']);
  await runGit(alienRepositoryRoot, ['commit', '-m', 'alien']);
  const alienRevision = await runGit(alienRepositoryRoot, ['rev-parse', 'HEAD']);
  await runGit(alienRepositoryRoot, ['worktree', 'add', '--detach', alienRoot, alienRevision]);
  await writeFile(alienTargetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-alien-checkout',
    path: './alien-checkout',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  const alien = await scanProject({
    targetConfigPath: alienTargetConfigPath,
    profilePath,
    workspacePath
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: alien.runDirectory,
      baselineTargetConfigPath,
      candidateTargetConfigPath: alienTargetConfigPath
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_REPOSITORY_MISMATCH'
  );

  await writeFile(path.join(candidateRoot, 'src', 'index.ts'), 'export const stale = true;\n', 'utf8');
  await assert.rejects(
    compareFindingRuns(comparisonOptions),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_CHECKOUT_STALE'
  );
});

test('verified run diff rejects profile incompatibility and tampered inputs', { timeout: 120_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-finding-diff-compatibility-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  const targetConfigPath = path.join(root, 'target.json');
  const otherTargetConfigPath = path.join(root, 'other-target.json');
  const profilePath = path.join(root, 'profile.json');
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await writeFile(path.join(targetRoot, 'src', 'index.ts'), 'export const ready = true;\n', 'utf8');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'finding-diff-compatibility-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(otherTargetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'other-finding-diff-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  const profile = {
    schemaVersion: 1,
    id: 'finding-diff-compatibility-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  };
  await writeFile(profilePath, `${JSON.stringify(profile, null, 2)}\n`, 'utf8');
  const baseline = await scanProject({ targetConfigPath, profilePath, workspacePath });
  const otherTarget = await scanProject({ targetConfigPath: otherTargetConfigPath, profilePath, workspacePath });
  const baselineRunRecord = await readJson<RunRecord>(path.join(baseline.runDirectory, 'run.json'));
  const candidateProducerRun: RunRecord = {
    ...baselineRunRecord,
    tool: { ...baselineRunRecord.tool, version: `${baselineRunRecord.tool.version}-different` }
  };
  const exactAssessment = assessFindingProducerCompatibility(baselineRunRecord, baselineRunRecord);
  assert.equal(exactAssessment.compatible, true);
  if (exactAssessment.compatible) assert.equal(exactAssessment.basis, 'exact');
  const incompatibleAssessment = assessFindingProducerCompatibility(baselineRunRecord, candidateProducerRun);
  assert.equal(incompatibleAssessment.compatible, false);
  const baselineSignatureId = findingProducerSignatureId(findingProducerSignature(baselineRunRecord));
  const candidateSignatureId = findingProducerSignatureId(findingProducerSignature(candidateProducerRun));
  const declaredAssessment = assessFindingProducerCompatibility(
    baselineRunRecord,
    candidateProducerRun,
    new Map([
      [baselineSignatureId, 'finding_compatibility_test-v1'],
      [candidateSignatureId, 'finding_compatibility_test-v1']
    ])
  );
  assert.equal(declaredAssessment.compatible, true);
  if (declaredAssessment.compatible) assert.equal(declaredAssessment.basis, 'declared-compatible');
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: otherTarget.runDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_TARGET_MISMATCH'
  );

  const producerMismatchDirectory = path.join(root, 'producer-mismatch');
  await cloneWithRunContractMutation(baseline.runDirectory, producerMismatchDirectory, (run) => {
    run.tool = { ...run.tool, version: `${run.tool.version}-different` };
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: producerMismatchDirectory
    }),
    (error: unknown) => {
      const candidateError = error as { code?: string; message?: string };
      return candidateError.code === 'FINDING_DIFF_REBASE_REQUIRED' &&
        candidateError.message?.includes('does not infer compatibility from version numbers') === true &&
        candidateError.message.includes(`exact profile ${baselineRunRecord.profileId}`);
    }
  );

  const producerAndDispositionMismatchDirectory = path.join(root, 'producer-and-disposition-mismatch');
  await cloneWithRunContractMutation(baseline.runDirectory, producerAndDispositionMismatchDirectory, (run) => {
    run.tool = { ...run.tool, version: `${run.tool.version}-different` };
    run.analyses.push(`finding-dispositions-v1.1.0+sha256.${'a'.repeat(64)}`);
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: producerAndDispositionMismatchDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_REBASE_REQUIRED'
  );

  const adapterMismatchDirectory = path.join(root, 'adapter-mismatch');
  await cloneWithRunContractMutation(baseline.runDirectory, adapterMismatchDirectory, (run) => {
    run.adapters = run.adapters.map((adapter, index) => index === 0
      ? { ...adapter, version: `${adapter.version}-different` }
      : adapter);
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: adapterMismatchDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_REBASE_REQUIRED'
  );

  const analyzerMismatchDirectory = path.join(root, 'analyzer-mismatch');
  await cloneWithRunContractMutation(baseline.runDirectory, analyzerMismatchDirectory, (run) => {
    const markerIndex = run.analyses.findIndex((entry) => entry.startsWith('api-contracts-v'));
    assert.notEqual(markerIndex, -1);
    run.analyses[markerIndex] = 'api-contracts-v999.0.0';
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: analyzerMismatchDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_REBASE_REQUIRED'
  );

  const dispositionLedgerPath = path.join(root, 'empty-dispositions.json');
  await writeCanonicalJson(dispositionLedgerPath, {
    schemaVersion: 1,
    kind: 'atlas-finding-disposition-ledger',
    targetId: 'finding-diff-compatibility-target',
    profileId: baselineRunRecord.profileId,
    profileDigest: baselineRunRecord.profileDigest,
    entries: {}
  });
  const dispositionRun = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath,
    dispositionLedgerPath
  });
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: dispositionRun.runDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_DISPOSITION_MISMATCH'
  );

  const baselineSelfReport = await compareFindingRuns({
    baselineRunDirectory: baseline.runDirectory,
    candidateRunDirectory: baseline.runDirectory
  });
  const mismatchedOutput = path.join(root, 'reports', 'mismatched-target.json');
  await assert.rejects(
    writeFindingDeltaReport({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: baseline.runDirectory,
      targetConfigPath: otherTargetConfigPath,
      outputPath: mismatchedOutput
    }, baselineSelfReport),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_TARGET_MISMATCH'
  );
  await assert.rejects(readFile(mismatchedOutput, 'utf8'), { code: 'ENOENT' });

  await writeFile(profilePath, `${JSON.stringify({ ...profile, deadCodeExemptions: ['src/index.ts'] }, null, 2)}\n`, 'utf8');
  const incompatible = await scanProject({ targetConfigPath, profilePath, workspacePath });

  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: incompatible.runDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'FINDING_DIFF_PROFILE_MISMATCH'
  );

  await writeFile(path.join(incompatible.runDirectory, 'findings.jsonl'), '{"forged":true}\n', 'utf8');
  await assert.rejects(
    compareFindingRuns({
      baselineRunDirectory: baseline.runDirectory,
      candidateRunDirectory: incompatible.runDirectory
    }),
    (error: unknown) => (error as { code?: string }).code === 'VERIFY_DIGEST'
  );
});
