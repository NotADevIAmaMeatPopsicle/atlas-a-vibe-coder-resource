import path from 'node:path';
import { realpath } from 'node:fs/promises';
import { AtlasError } from '../errors.js';
import { compareCanonicalText } from './canonical.js';

export const DEFAULT_EXCLUDED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.turbo',
  '.cache'
]);

export function toPosixPath(value: string): string {
  return value.split(path.sep).join('/');
}

const WINDOWS_DEVICE_COMPONENT = /^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)(?:\..*)?$/i;

function normalizePortableRelative(value: string, allowRootDot: boolean): string {
  if (!value || value.includes('\0') || value.includes(':')) {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Expected a portable target-relative path: ${value}`);
  }
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Expected a target-relative path: ${value}`);
  }
  if (allowRootDot && value === '.') return value;

  const rawSegments = value.split(/[\\/]/);
  if (rawSegments.some((segment) => segment === '.' || segment === '..')) {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Path contains a non-canonical dot segment: ${value}`);
  }
  const portableValue = value.replaceAll('\\', '/').normalize('NFC');
  const segments = portableValue.split('/');
  if (segments.some((segment) =>
    segment === '.' || segment === '..' ||
    segment.endsWith('.') || segment.endsWith(' ') || WINDOWS_DEVICE_COMPONENT.test(segment)
  )) {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Path is not in canonical portable form: ${value}`);
  }
  const normalized = path.posix.normalize(portableValue).replace(/\/+$/, '');
  if (!normalized || normalized === '.') {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Expected a target-relative path: ${value}`);
  }
  return normalized;
}

export function normalizeTargetRelative(value: string): string {
  return normalizePortableRelative(value, false);
}

export function normalizeIncludeRoot(value: string): string {
  return normalizePortableRelative(value, true);
}

export function normalizeFilesystemRelative(value: string): string {
  if (path.sep === '/' && value.includes('\\')) {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Filesystem path contains a non-portable backslash: ${value}`);
  }
  const portableValue = toPosixPath(value);
  const normalized = normalizeTargetRelative(portableValue);
  if (normalized !== portableValue) {
    throw new AtlasError('INVALID_RELATIVE_PATH', `Filesystem path is not in canonical portable form: ${value}`);
  }
  return normalized;
}

export function isInside(parent: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export async function resolveForContainment(value: string): Promise<string> {
  let cursor = path.resolve(value);
  const missingSegments: string[] = [];
  while (true) {
    try {
      const resolvedParent = await realpath(cursor);
      return path.resolve(resolvedParent, ...missingSegments);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      const parent = path.dirname(cursor);
      if (parent === cursor) throw error;
      missingSegments.unshift(path.basename(cursor));
      cursor = parent;
    }
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

export function globToRegExp(glob: string): RegExp {
  const normalized = normalizeTargetRelative(glob);
  const segments = normalized.split('/').filter((segment, index, values) => segment !== '**' || values[index - 1] !== '**');
  let expression = '^';
  segments.forEach((segment, index) => {
    if (segment === '**') {
      if (segments.length === 1) expression += '.*';
      else if (index === 0) expression += '(?:[^/]+/)*';
      else if (index === segments.length - 1) expression += '(?:/.*)?';
      else expression += '(?:/[^/]+)*';
      return;
    }
    if (index > 0) {
      const previousWasGlobstar = segments[index - 1] === '**';
      if (!previousWasGlobstar || index - 1 > 0) expression += '/';
    }
    let segmentExpression = '';
    for (const character of segment) {
      if (character === '*') segmentExpression += '[^/]*';
      else if (character === '?') segmentExpression += '[^/]';
      else segmentExpression += escapeRegex(character);
    }
    expression += segmentExpression;
  });
  expression += '$';
  return new RegExp(expression);
}

export function matchesGlob(value: string, glob: string): boolean {
  const normalizedValue = normalizeTargetRelative(value);
  const normalizedGlob = normalizeTargetRelative(glob);
  if (normalizedGlob.startsWith('**/')) {
    const withoutPrefix = normalizedGlob.slice(3);
    if (globToRegExp(withoutPrefix).test(normalizedValue)) return true;
  }
  if (normalizedGlob.endsWith('/**')) {
    const directory = normalizedGlob.slice(0, -3);
    if (normalizedValue === directory) return true;
  }
  return globToRegExp(normalizedGlob).test(normalizedValue);
}

export function matchesAnyGlob(value: string, globs: string[]): boolean {
  return globs.some((glob) => matchesGlob(value, glob));
}

export function comparePath(left: { path: string }, right: { path: string }): number {
  return compareCanonicalText(left.path, right.path);
}
