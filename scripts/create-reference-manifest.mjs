#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { constants, accessSync, lstatSync, realpathSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  aggregateReferenceEntries,
  assertReferenceManifestSize,
  inventoryReferenceTree,
  normalizeReferenceRelativePath,
  sha256
} from './reference-manifest-support.mjs';

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) {
      throw new Error('Expected --reference, --source, --source-repository, and --out arguments.');
    }
    result[key.slice(2)] = value;
  }
  for (const required of ['reference', 'source', 'source-repository', 'out']) {
    if (!result[required]) throw new Error(`Missing --${required}.`);
  }
  return result;
}

function isInside(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function relativeChildPath(parent, candidate, label) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${label} must be a proper child of ${path.resolve(parent)}.`);
  }
  return normalizeReferenceRelativePath(relative.split(path.sep).join('/'), label);
}

function environmentPath() {
  return Object.entries(process.env).find(([key, value]) => key.toUpperCase() === 'PATH' && value)?.[1];
}

function resolveTrustedGitExecutable(repository) {
  const pathValue = environmentPath();
  if (!pathValue) throw new Error('Git was not found on PATH.');
  const repositoryRoot = realpathSync(path.resolve(repository));
  const names = process.platform === 'win32' ? ['git.com', 'git.exe'] : ['git'];
  for (const rawEntry of pathValue.split(path.delimiter)) {
    const trimmed = rawEntry.trim();
    const unquoted = trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')
      ? trimmed.slice(1, -1)
      : trimmed;
    if (!unquoted || !path.isAbsolute(unquoted)) continue;
    for (const name of names) {
      const candidate = path.resolve(unquoted, name);
      try {
        const metadata = lstatSync(candidate);
        if (!metadata.isFile() && !metadata.isSymbolicLink()) continue;
        const resolved = realpathSync(candidate);
        if (!lstatSync(resolved).isFile()) continue;
        if (process.platform !== 'win32') accessSync(resolved, constants.X_OK);
        if (isInside(repositoryRoot, candidate) || isInside(repositoryRoot, resolved)) continue;
        return resolved;
      } catch {
        continue;
      }
    }
  }
  throw new Error('Git was not found on trusted absolute PATH entries outside the source repository.');
}

function git(repository, args) {
  const disabledHooksPath = process.platform === 'win32' ? 'NUL' : '/dev/null';
  const safeArguments = [
    '-c', 'core.fsmonitor=false',
    '-c', `core.hooksPath=${disabledHooksPath}`,
    '-c', 'diff.external=',
    '-c', 'credential.helper=',
    '-c', 'protocol.ext.allow=never',
    '-c', 'protocol.file.allow=never',
    '-c', 'submodule.recurse=false',
    ...args
  ];
  const environment = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_EXTERNAL_DIFF: '',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    GIT_PAGER: 'cat'
  };
  for (const key of Object.keys(environment)) {
    if (key === 'GIT_CONFIG_COUNT' || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(key)) delete environment[key];
  }
  return execFileSync(resolveTrustedGitExecutable(repository), safeArguments, {
    cwd: repository,
    encoding: 'utf8',
    env: environment
  }).trim();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const referenceRoot = path.resolve(args.reference);
  const sourceRoot = path.resolve(args.source);
  const repositoryRoot = path.resolve(args['source-repository']);
  const outputPath = path.resolve(args.out);
  const referencePath = relativeChildPath(process.cwd(), referenceRoot, 'Reference directory');
  const atlasPath = relativeChildPath(repositoryRoot, sourceRoot, 'Source directory');
  if (isInside(repositoryRoot, referenceRoot) || isInside(referenceRoot, repositoryRoot)) {
    throw new Error('Reference and source repository directories must not overlap.');
  }
  if (isInside(repositoryRoot, outputPath) || isInside(referenceRoot, outputPath)) {
    throw new Error('Reference manifest output must be outside both the source repository and reference tree.');
  }
  const referenceFiles = await inventoryReferenceTree(referenceRoot);
  const sourceFiles = await inventoryReferenceTree(sourceRoot);
  const referenceDigest = aggregateReferenceEntries(referenceFiles);
  const sourceDigest = aggregateReferenceEntries(sourceFiles);
  if (JSON.stringify(referenceFiles) !== JSON.stringify(sourceFiles)) {
    throw new Error('Copied reference does not exactly match the source inventory and content hashes.');
  }
  const status = git(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']);
  const manifest = {
    schemaVersion: 1,
    capturedAt: new Date().toISOString(),
    referencePath,
    sourceObservation: {
      repositoryPath: repositoryRoot,
      atlasPath,
      gitHead: git(repositoryRoot, ['rev-parse', 'HEAD']),
      branch: git(repositoryRoot, ['branch', '--show-current']) || null,
      detached: !git(repositoryRoot, ['branch', '--show-current']),
      dirtyStatusSha256: sha256(status),
      dirtyStatusLineCount: status ? status.split(/\r?\n/).length : 0,
      note: 'The status digest records the complete source-repository worktree observation without embedding status paths.'
    },
    fileCount: referenceFiles.length,
    totalBytes: referenceFiles.reduce((total, entry) => total + entry.bytes, 0),
    aggregateAlgorithm: 'sha256(path\\0bytes\\0sha256 joined by LF, paths sorted lexically)',
    aggregateSha256: referenceDigest,
    sourceAggregateSha256: sourceDigest,
    files: referenceFiles
  };
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  assertReferenceManifestSize(manifestText);
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, manifestText, 'utf8');
  process.stdout.write(`${JSON.stringify({ outputPath, fileCount: manifest.fileCount, totalBytes: manifest.totalBytes, aggregateSha256: referenceDigest })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
