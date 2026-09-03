import assert from 'node:assert/strict';
import { chmod, copyFile, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { resolveTrustedGitExecutable } from '../src/security/git-executable.js';

test('trusted Git resolution skips target-owned and relative PATH entries', async (context) => {
  const systemGit = await resolveTrustedGitExecutable([]);
  assert(systemGit, 'Git must be available for this test.');

  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-trusted-git-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const trustedRoot = path.join(root, 'trusted');
  await Promise.all([mkdir(targetRoot), mkdir(trustedRoot)]);
  const executableName = process.platform === 'win32' ? 'git.exe' : 'git';
  const targetExecutable = path.join(targetRoot, executableName);
  const trustedExecutable = path.join(trustedRoot, executableName);
  await Promise.all([
    copyFile(process.execPath, targetExecutable),
    copyFile(systemGit, trustedExecutable)
  ]);
  if (process.platform !== 'win32') {
    await Promise.all([chmod(targetExecutable, 0o755), chmod(trustedExecutable, 0o755)]);
  }

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = ['.', targetRoot, trustedRoot].join(path.delimiter);
    const resolved = await resolveTrustedGitExecutable([targetRoot]);
    assert(resolved);
    assert.equal(await realpath(resolved), await realpath(trustedExecutable));
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test('trusted Git resolution does not fall back to a target-owned executable', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-untrusted-git-only-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const executableName = process.platform === 'win32' ? 'git.exe' : 'git';
  const targetExecutable = path.join(root, executableName);
  await copyFile(process.execPath, targetExecutable);
  if (process.platform !== 'win32') await chmod(targetExecutable, 0o755);

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = root;
    assert.equal(await resolveTrustedGitExecutable([root]), undefined);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test('trusted Git resolution rejects a PATH alias that resolves inside the target', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-untrusted-git-alias-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const targetRoot = path.join(root, 'target');
  const aliasRoot = path.join(root, 'alias');
  await mkdir(targetRoot);
  const executableName = process.platform === 'win32' ? 'git.exe' : 'git';
  const targetExecutable = path.join(targetRoot, executableName);
  await copyFile(process.execPath, targetExecutable);
  if (process.platform !== 'win32') await chmod(targetExecutable, 0o755);
  await symlink(targetRoot, aliasRoot, process.platform === 'win32' ? 'junction' : 'dir');

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = aliasRoot;
    assert.equal(await resolveTrustedGitExecutable([targetRoot]), undefined);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test('trusted Git resolution never treats command scripts as Git on Windows', {
  skip: process.platform !== 'win32'
}, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-untrusted-git-scripts-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, 'git.cmd'), '@echo off\r\nexit /b 0\r\n', 'utf8'),
    writeFile(path.join(root, 'git.bat'), '@echo off\r\nexit /b 0\r\n', 'utf8')
  ]);

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = root;
    assert.equal(await resolveTrustedGitExecutable([]), undefined);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});
