import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createChangedFindingsReport, writeChangedFindingsReport } from '../src/changed-findings.js';
import { HARD_MAX_FILE_BYTES } from '../src/limits.js';
import { scanProject } from '../src/run.js';
import { assertSchema } from '../src/schema-validator.js';

const CLI_PATH = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

function runGit(repositoryPath: string, command: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('git', [
      '-c', 'user.name=Atlas Tests',
      '-c', 'user.email=atlas-tests@example.invalid',
      '-c', 'commit.gpgSign=false',
      '-c', `core.hooksPath=${NULL_DEVICE}`,
      '-C', repositoryPath,
      ...command
    ], {
      encoding: 'utf8',
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' },
      windowsHide: true
    }, (error, stdout) => error ? reject(error) : resolve(stdout));
  });
}

function runCli(argumentsList: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(process.execPath, [CLI_PATH, ...argumentsList], {
      encoding: 'utf8',
      windowsHide: true
    }, (error, stdout, stderr) => {
      const exitCode = error && typeof (error as unknown as { code?: number }).code === 'number'
        ? (error as unknown as { code: number }).code
        : error ? -1 : 0;
      resolve({ code: exitCode, stdout, stderr });
    });
    child.once('error', reject);
  });
}

async function gitAvailable(): Promise<boolean> {
  return new Promise((resolve) => execFile('git', ['--version'], { windowsHide: true }, (error) => resolve(!error)));
}

const hasGit = await gitAvailable();

test('changed scope rejects an oversized untracked file before hashing it', {
  skip: !hasGit,
  timeout: 120_000
}, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-changed-limit-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await runGit(targetRoot, ['init', '-b', 'main']);
  await writeFile(path.join(targetRoot, 'src', 'index.ts'), 'export const ready = true;\n');
  await runGit(targetRoot, ['add', '--', 'src/index.ts']);
  await runGit(targetRoot, ['commit', '-m', 'base']);
  const baseCommit = (await runGit(targetRoot, ['rev-parse', 'HEAD'])).trim();
  const oversizedPath = path.join(targetRoot, 'oversized.bin');
  const oversized = await open(oversizedPath, 'w');
  await oversized.truncate(HARD_MAX_FILE_BYTES + 1);
  await oversized.close();

  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  const workspacePath = path.join(root, 'workspace');
  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'changed-limit-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  })}\n`);
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'changed-limit-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  })}\n`);
  const scan = await scanProject({ targetConfigPath, profilePath, workspacePath });

  await assert.rejects(
    createChangedFindingsReport({ runDirectory: scan.runDirectory, targetConfigPath, since: baseCommit }),
    (error: unknown) => (error as { code?: string }).code === 'CHANGED_SCOPE_RESOURCE_LIMIT'
  );
});

test('changed report covers committed, staged, unstaged, renamed, and untracked current paths', {
  skip: !hasGit,
  timeout: 120_000
}, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-changed-findings-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const workspacePath = path.join(root, 'workspace');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await mkdir(path.join(targetRoot, 'src'), { recursive: true });
  await runGit(targetRoot, ['init', '-b', 'main']);
  await runGit(targetRoot, ['config', 'core.autocrlf', 'false']);
  await writeFile(path.join(targetRoot, 'src', 'index.ts'), [
    "import './committed.js';",
    "import './staged.js';",
    "import './unstaged.js';",
    "import './old-name.js';",
    'export const ready = true;',
    ''
  ].join('\n'), 'utf8');
  for (const name of ['committed', 'staged', 'unstaged', 'old-name']) {
    await writeFile(path.join(targetRoot, 'src', `${name}.ts`), `export const ${name.replace('-', '_')} = true;\n`, 'utf8');
  }
  await runGit(targetRoot, ['add', '--', 'src']);
  await runGit(targetRoot, ['commit', '-m', 'base']);
  const baseCommit = (await runGit(targetRoot, ['rev-parse', 'HEAD'])).trim();

  await writeFile(path.join(targetRoot, 'src', 'committed.ts'), "import './missing-committed.js';\nexport const committed = true;\n", 'utf8');
  await runGit(targetRoot, ['add', '--', 'src/committed.ts']);
  await runGit(targetRoot, ['commit', '-m', 'committed change']);
  const headCommit = (await runGit(targetRoot, ['rev-parse', 'HEAD'])).trim();

  await writeFile(path.join(targetRoot, 'src', 'staged.ts'), "import './missing-staged.js';\nexport const staged = true;\n", 'utf8');
  await runGit(targetRoot, ['add', '--', 'src/staged.ts']);
  await writeFile(path.join(targetRoot, 'src', 'unstaged.ts'), "import './missing-unstaged.js';\nexport const unstaged = true;\n", 'utf8');
  await runGit(targetRoot, ['mv', '--', 'src/old-name.ts', 'src/renamed.ts']);
  await writeFile(path.join(targetRoot, 'src', 'renamed.ts'), "import './missing-renamed.js';\nexport const old_name = true;\n", 'utf8');
  await writeFile(path.join(targetRoot, 'src', 'untracked.ts'), "import './missing-untracked.js';\nexport const untracked = true;\n", 'utf8');

  await writeFile(targetConfigPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'changed-findings-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await writeFile(profilePath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'changed-findings-profile',
    includeRoots: ['src'],
    entrypoints: ['src/index.ts']
  }, null, 2)}\n`, 'utf8');
  const scan = await scanProject({ targetConfigPath, profilePath, workspacePath });

  const first = await createChangedFindingsReport({
    runDirectory: scan.runDirectory,
    targetConfigPath,
    since: baseCommit
  });
  const second = await createChangedFindingsReport({
    runDirectory: scan.runDirectory,
    targetConfigPath,
    since: baseCommit
  });
  assert.deepEqual(second, first);
  assert.equal(first.comparison.requestedRef, baseCommit);
  assert.equal(first.comparison.resolvedCommit, baseCommit);
  assert.equal(first.comparison.headCommit, headCommit);
  assert.deepEqual(first.changedPaths, [
    'src/committed.ts',
    'src/renamed.ts',
    'src/staged.ts',
    'src/unstaged.ts',
    'src/untracked.ts'
  ]);
  assert(!first.changedPaths.includes('src/old-name.ts'));
  assert.equal(first.counts.changedPaths, 5);
  assert.equal(first.counts.runFindings, scan.run.counts.findings);
  assert.equal(first.counts.matchingFindings, first.matchingFindings.length);
  const legacyReport = structuredClone(first) as unknown as {
    producer: { version: string };
    counts: { matchingDispositions?: number };
    matchingDispositions?: unknown[];
  };
  legacyReport.producer.version = '1.0.0';
  delete legacyReport.counts.matchingDispositions;
  delete legacyReport.matchingDispositions;
  await assertSchema('changed-findings', legacyReport, 'Legacy changed-findings report');

  const incompleteCurrentReport = structuredClone(first) as unknown as {
    counts: { matchingDispositions?: number };
    matchingDispositions?: unknown[];
  };
  delete incompleteCurrentReport.counts.matchingDispositions;
  delete incompleteCurrentReport.matchingDispositions;
  await assert.rejects(
    assertSchema('changed-findings', incompleteCurrentReport, 'Incomplete current changed-findings report'),
    (error: unknown) => (error as { code?: string }).code === 'SCHEMA_VALIDATION'
  );
  assert.equal(first.counts.matchingDispositions, first.matchingDispositions.length);
  assert.deepEqual(first.matchingDispositions, []);
  const matchedPaths = new Set(first.matchingFindings.flatMap((entry) => entry.matchedPaths));
  assert.deepEqual([...matchedPaths].sort(), first.changedPaths);
  assert(first.matchingFindings.every((entry) => entry.reviewIdentity.startsWith('finding_review_sha256_')));

  const outputPath = path.join(root, 'reports', 'changed.json');
  const written = await writeChangedFindingsReport({
    runDirectory: scan.runDirectory,
    targetConfigPath,
    since: baseCommit,
    outputPath
  }, first);
  assert.equal(written.reused, false);
  const reused = await writeChangedFindingsReport({
    runDirectory: scan.runDirectory,
    targetConfigPath,
    since: baseCommit,
    outputPath
  }, first);
  assert.equal(reused.reused, true);
  await assert.rejects(
    writeChangedFindingsReport({
      runDirectory: scan.runDirectory,
      targetConfigPath,
      since: baseCommit,
      outputPath: path.join(targetRoot, 'changed.json')
    }, first),
    (error: unknown) => (error as { code?: string }).code === 'REPORT_OUTPUT_UNSAFE'
  );

  const cliOutputPath = path.join(root, 'reports', 'changed-cli.json');
  const cli = await runCli([
    'changed', scan.runDirectory,
    '--target', targetConfigPath,
    '--since', baseCommit,
    '--output', cliOutputPath
  ]);
  assert.equal(cli.code, 0, cli.stderr);
  assert.equal(cli.stderr, '');
  assert.deepEqual(JSON.parse(cli.stdout), first);
  assert.equal(await readFile(cliOutputPath, 'utf8'), cli.stdout);

  const dispositionCandidate = first.matchingFindings[0]?.finding;
  assert(dispositionCandidate?.reviewId, 'Expected changed finding to publish a disposition key.');
  assert(dispositionCandidate.reviewAnchors?.length, 'Expected changed finding to publish review anchors.');
  const dispositionLedgerPath = path.join(root, 'changed-dispositions.json');
  await writeFile(dispositionLedgerPath, `${JSON.stringify({
    schemaVersion: 1,
    kind: 'atlas-finding-disposition-ledger',
    targetId: 'changed-findings-target',
    profileId: scan.run.profileId,
    profileDigest: scan.run.profileDigest,
    entries: {
      [dispositionCandidate.reviewId]: {
        findingId: dispositionCandidate.id,
        disposition: 'intentional contract',
        reviewer: 'Admin',
        date: '2026-08-23',
        evidence: ['Confirmed for changed-report projection coverage.'],
        anchors: dispositionCandidate.reviewAnchors
      }
    }
  }, null, 2)}\n`, 'utf8');
  const dispositionScan = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath,
    dispositionLedgerPath
  });
  const dispositionReport = await createChangedFindingsReport({
    runDirectory: dispositionScan.runDirectory,
    targetConfigPath,
    since: baseCommit
  });
  assert.equal(dispositionReport.counts.matchingDispositions, 1);
  assert.equal(dispositionReport.matchingDispositions[0]?.reviewId, dispositionCandidate.reviewId);
  assert.equal(dispositionReport.matchingDispositions[0]?.reviewer, 'Admin');
  assert.equal(dispositionReport.matchingDispositions[0]?.state, 'applied');

  await assert.rejects(
    createChangedFindingsReport({ runDirectory: scan.runDirectory, targetConfigPath, since: 'missing-ref' }),
    (error: unknown) => (error as { code?: string }).code === 'CHANGED_SCOPE_REF_UNRESOLVED'
  );

  const mismatchedTargetPath = path.join(root, 'mismatched-target.json');
  await writeFile(mismatchedTargetPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'different-target-id',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await assert.rejects(
    createChangedFindingsReport({ runDirectory: scan.runDirectory, targetConfigPath: mismatchedTargetPath, since: baseCommit }),
    (error: unknown) => (error as { code?: string }).code === 'CHANGED_SCOPE_TARGET_MISMATCH'
  );

  const plainRoot = path.join(root, 'plain');
  const plainTargetPath = path.join(root, 'plain-target.json');
  await mkdir(plainRoot);
  await writeFile(plainTargetPath, `${JSON.stringify({
    schemaVersion: 1,
    id: 'changed-findings-target',
    path: './plain',
    consent: { agentReview: false, export: false, projectMemory: false }
  }, null, 2)}\n`, 'utf8');
  await assert.rejects(
    createChangedFindingsReport({ runDirectory: scan.runDirectory, targetConfigPath: plainTargetPath, since: baseCommit }),
    (error: unknown) => (error as { code?: string }).code === 'CHANGED_SCOPE_GIT_UNAVAILABLE'
  );

  const help = await runCli(['help']);
  assert.equal(help.code, 0, help.stderr);
  assert.match(help.stdout, /atlas changed <run-directory> --target <target\.json> --since <git-ref>/u);

  // The Git status shape is still "modified", but the bytes no longer match
  // the run that supplied the findings, so the post-filter must fail closed.
  await writeFile(
    path.join(targetRoot, 'src', 'unstaged.ts'),
    "import './missing-unstaged.js';\nexport const unstaged = false;\n",
    'utf8'
  );
  await assert.rejects(
    createChangedFindingsReport({ runDirectory: scan.runDirectory, targetConfigPath, since: baseCommit }),
    (error: unknown) => (error as { code?: string }).code === 'CHANGED_SCOPE_RUN_STALE'
  );
});
