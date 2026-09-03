import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, open, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { resolveTrustedGitExecutable } from '../src/security/git-executable.js';

function run(executable: string, args: readonly string[], options: {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
} = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(executable, args, {
      cwd: options.cwd,
      env: options.env,
      encoding: 'utf8',
      windowsHide: true
    }, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

async function assertMissing(filePath: string): Promise<void> {
  await assert.rejects(stat(filePath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
}

function runFailure(executable: string, args: readonly string[], options: { cwd?: string } = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(executable, args, {
      cwd: options.cwd,
      encoding: 'utf8',
      windowsHide: true
    }, (error, _stdout, stderr) => {
      if (!error) reject(new Error('Expected command to fail.'));
      else resolve(stderr);
    });
  });
}

test('reference verifier bounds manifest and evidence file bytes before buffering', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-reference-limits-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const referenceRoot = path.join(root, 'reference');
  const manifestPath = path.join(root, 'manifest.json');
  await mkdir(referenceRoot);
  const verifier = path.resolve('scripts/verify-reference-manifest.mjs');

  const oversizedManifest = await open(manifestPath, 'w');
  await oversizedManifest.truncate(4 * 1024 * 1024 + 1);
  await oversizedManifest.close();
  assert.match(
    await runFailure(process.execPath, [verifier, '--reference', referenceRoot, '--manifest', manifestPath]),
    /Reference manifest exceeds the 4194304-byte limit/u
  );

  let nestedManifest = 'true';
  for (let depth = 0; depth < 130; depth += 1) nestedManifest = `{"nested":${nestedManifest}}`;
  await writeFile(manifestPath, nestedManifest);
  assert.match(
    await runFailure(process.execPath, [verifier, '--reference', referenceRoot, '--manifest', manifestPath]),
    /Reference manifest exceeds the 128-level nesting limit/u
  );

  await writeFile(manifestPath, '{"schemaVersion":1,"files":[],"fileCount":0,"totalBytes":0,"aggregateSha256":""}\n');
  const oversizedFile = await open(path.join(referenceRoot, 'oversized.bin'), 'w');
  await oversizedFile.truncate(8 * 1024 * 1024 + 1);
  await oversizedFile.close();
  assert.match(
    await runFailure(process.execPath, [verifier, '--reference', referenceRoot, '--manifest', manifestPath]),
    /Reference file exceeds the 8388608-byte limit/u
  );

  const supportUrl = pathToFileURL(path.resolve('scripts/reference-manifest-support.mjs')).href;
  assert.match(
    await runFailure(process.execPath, [
      '--input-type=module',
      '--eval',
      `import { assertReferenceManifestSize } from ${JSON.stringify(supportUrl)}; assertReferenceManifestSize('x'.repeat(4 * 1024 * 1024 + 1));`
    ]),
    /Reference manifest exceeds the 4194304-byte limit/u
  );

  assert.match(
    await runFailure(process.execPath, [
      '--input-type=module',
      '--eval',
      `import { normalizeReferenceRelativePath } from ${JSON.stringify(supportUrl)}; normalizeReferenceRelativePath('../outside');`
    ]),
    /Reference path must be a portable relative path/u
  );
});

test('reference manifest creation rejects an output inside the reference tree', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-reference-output-boundary-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const repositoryRoot = path.join(root, 'repository');
  const sourceRoot = path.join(repositoryRoot, 'source');
  const referenceRoot = path.join(root, 'reference');
  await Promise.all([mkdir(sourceRoot, { recursive: true }), mkdir(referenceRoot, { recursive: true })]);

  assert.match(
    await runFailure(process.execPath, [
      path.resolve('scripts/create-reference-manifest.mjs'),
      '--reference', referenceRoot,
      '--source', sourceRoot,
      '--source-repository', repositoryRoot,
      '--out', path.join(referenceRoot, 'manifest.json')
    ], { cwd: root }),
    /Reference manifest output must be outside both the source repository and reference tree/u
  );
});

for (const executableName of ['git.com', 'git.exe']) {
  test(`reference manifest creation never executes a source-root ${executableName} on Windows`, {
    skip: process.platform !== 'win32'
  }, async (context) => {
    const trustedGit = await resolveTrustedGitExecutable([]);
    assert(trustedGit, 'Git must be available for this test.');

    const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-reference-git-boundary-'));
    context.after(async () => rm(root, { recursive: true, force: true }));
    const repositoryRoot = path.join(root, 'repository');
    const sourceRoot = path.join(repositoryRoot, 'source');
    const referenceRoot = path.join(root, 'reference');
    const outputPath = path.join(root, 'reference-manifest.json');
    const marker = path.join(root, 'target-git-executed.txt');
    const loader = path.join(root, 'target-git-loader.cjs');
    await Promise.all([mkdir(sourceRoot, { recursive: true }), mkdir(referenceRoot, { recursive: true })]);
    await Promise.all([
      writeFile(path.join(sourceRoot, 'fixture.txt'), 'reference fixture\n', 'utf8'),
      writeFile(path.join(referenceRoot, 'fixture.txt'), 'reference fixture\n', 'utf8'),
      writeFile(
        loader,
        "const fs=require('node:fs');const path=require('node:path');if(/^git\\.(?:com|exe)$/i.test(path.basename(process.execPath)))fs.writeFileSync(process.env.ATLAS_GIT_EXEC_MARKER,'executed');\n",
        'utf8'
      )
    ]);

    await run(trustedGit, ['init', repositoryRoot]);
    await run(trustedGit, [
      '-c', 'user.name=Atlas Tests',
      '-c', 'user.email=atlas-tests@example.invalid',
      '-c', 'commit.gpgSign=false',
      '-C', repositoryRoot,
      'add', '--', 'source/fixture.txt'
    ]);
    await run(trustedGit, [
      '-c', 'user.name=Atlas Tests',
      '-c', 'user.email=atlas-tests@example.invalid',
      '-c', 'commit.gpgSign=false',
      '-C', repositoryRoot,
      'commit', '-m', 'initial'
    ]);
    await copyFile(process.execPath, path.join(repositoryRoot, executableName));

    const scriptPath = path.resolve('scripts/create-reference-manifest.mjs');
    const environment = {
      ...process.env,
      PATH: [repositoryRoot, path.dirname(trustedGit)].join(path.delimiter),
      NODE_OPTIONS: `--require=${loader}`,
      ATLAS_GIT_EXEC_MARKER: marker
    };
    await run(process.execPath, [
      scriptPath,
      '--reference', referenceRoot,
      '--source', sourceRoot,
      '--source-repository', repositoryRoot,
      '--out', outputPath
    ], { cwd: root, env: environment });

    await assertMissing(marker);
    const manifest = JSON.parse(await readFile(outputPath, 'utf8')) as {
      fileCount?: number;
      referencePath?: string;
      sourceObservation?: { atlasPath?: string; gitHead?: string; note?: string };
    };
    assert.equal(manifest.fileCount, 1);
    assert.equal(manifest.referencePath, 'reference');
    assert.equal(manifest.sourceObservation?.atlasPath, 'source');
    assert.match(manifest.sourceObservation?.gitHead ?? '', /^[0-9a-f]{40,64}$/);
    assert.equal(
      manifest.sourceObservation?.note,
      'The status digest records the complete source-repository worktree observation without embedding status paths.'
    );
  });
}
