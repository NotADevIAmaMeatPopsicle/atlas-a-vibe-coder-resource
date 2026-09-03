import { constants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isInside } from '../util/paths.js';

function environmentPath(): string | undefined {
  const entry = Object.entries(process.env)
    .find(([key, value]) => key.toUpperCase() === 'PATH' && value !== undefined);
  return entry?.[1];
}

function normalizedPathEntry(value: string): string | undefined {
  const trimmed = value.trim();
  const unquoted = trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')
    ? trimmed.slice(1, -1)
    : trimmed;
  return unquoted && path.isAbsolute(unquoted) ? path.resolve(unquoted) : undefined;
}

function candidateNames(): readonly string[] {
  return process.platform === 'win32' ? ['git.com', 'git.exe'] : ['git'];
}

function blockedByTarget(candidate: string, resolvedCandidate: string, targetRoots: readonly string[]): boolean {
  return targetRoots.some((root) => isInside(root, candidate) || isInside(root, resolvedCandidate));
}

/**
 * Resolve Git without allowing the child working directory or a target-owned
 * PATH entry to participate in executable selection.
 */
export async function resolveTrustedGitExecutable(targetRoots: readonly string[]): Promise<string | undefined> {
  const pathValue = environmentPath();
  if (!pathValue) return undefined;

  const canonicalTargetRoots = await Promise.all(targetRoots.map(async (root) => {
    try {
      return await realpath(path.resolve(root));
    } catch {
      return path.resolve(root);
    }
  }));

  for (const rawEntry of pathValue.split(path.delimiter)) {
    const directory = normalizedPathEntry(rawEntry);
    if (!directory) continue;
    for (const name of candidateNames()) {
      const candidate = path.join(directory, name);
      let resolvedCandidate: string;
      try {
        const metadata = await lstat(candidate);
        if (!metadata.isFile() && !metadata.isSymbolicLink()) continue;
        resolvedCandidate = await realpath(candidate);
        if (!(await lstat(resolvedCandidate)).isFile()) continue;
        if (process.platform !== 'win32') await access(resolvedCandidate, constants.X_OK);
      } catch {
        continue;
      }
      if (blockedByTarget(candidate, resolvedCandidate, canonicalTargetRoots)) continue;
      return resolvedCandidate;
    }
  }
  return undefined;
}
