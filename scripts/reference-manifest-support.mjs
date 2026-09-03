import { createHash } from 'node:crypto';
import { lstat, open, opendir } from 'node:fs/promises';
import path from 'node:path';

export const MAX_REFERENCE_DEPTH = 128;
export const MAX_REFERENCE_BOUNDARY_ENTRIES = 100_000;
export const MAX_REFERENCE_FILES = 25_000;
export const MAX_REFERENCE_FILE_BYTES = 8 * 1024 * 1024;
export const MAX_REFERENCE_TOTAL_BYTES = 128 * 1024 * 1024;
export const MAX_REFERENCE_MANIFEST_BYTES = 4 * 1024 * 1024;
export const MAX_REFERENCE_JSON_DEPTH = 128;
const WINDOWS_DEVICE_COMPONENT = /^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)(?:\..*)?$/iu;

export function normalizeReferenceRelativePath(value, label = 'Reference path') {
  if (!value || value.includes('\0') || value.includes(':') || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    throw new Error(`${label} must be a portable relative path.`);
  }
  const portable = value.replaceAll('\\', '/').normalize('NFC');
  const segments = portable.split('/');
  if (segments.some((segment) =>
    !segment || segment === '.' || segment === '..' || segment.endsWith('.') ||
    segment.endsWith(' ') || WINDOWS_DEVICE_COMPONENT.test(segment)
  )) {
    throw new Error(`${label} must be a portable relative path.`);
  }
  const normalized = path.posix.normalize(portable).replace(/\/+$/u, '');
  if (normalized !== portable) throw new Error(`${label} must be in canonical portable form.`);
  return normalized;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function assertJsonNestingDepth(value, maxDepth = MAX_REFERENCE_JSON_DEPTH) {
  const pending = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current.value === null || typeof current.value !== 'object') continue;
    if (current.depth > maxDepth) {
      throw new Error(`Reference manifest exceeds the ${maxDepth}-level nesting limit.`);
    }
    const children = Array.isArray(current.value) ? current.value : Object.values(current.value);
    for (const child of children) pending.push({ value: child, depth: current.depth + 1 });
  }
}

export function assertReferenceManifestSize(content) {
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes > MAX_REFERENCE_MANIFEST_BYTES) {
    throw new Error(`Reference manifest exceeds the ${MAX_REFERENCE_MANIFEST_BYTES}-byte limit.`);
  }
  return bytes;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

export async function readBoundedRegularFile(filePath, maxBytes, label) {
  const before = await lstat(filePath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`${label} must be a regular file.`);
  if (before.size > BigInt(maxBytes)) throw new Error(`${label} exceeds the ${maxBytes}-byte limit.`);
  const handle = await open(filePath, 'r');
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened) || opened.size !== before.size) {
      throw new Error(`${label} changed before it could be read.`);
    }
    const content = Buffer.allocUnsafe(Number(opened.size));
    let offset = 0;
    while (offset < content.length) {
      const { bytesRead } = await handle.read(content, offset, content.length - offset, null);
      if (bytesRead === 0) throw new Error(`${label} changed while it was being read.`);
      offset += bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    if ((await handle.read(probe, 0, 1, null)).bytesRead !== 0) {
      throw new Error(`${label} grew beyond its bounded observed size.`);
    }
    const after = await handle.stat({ bigint: true });
    if (!sameIdentity(opened, after) || opened.size !== after.size || opened.mtimeNs !== after.mtimeNs) {
      throw new Error(`${label} changed while it was being read.`);
    }
    return content;
  } finally {
    await handle.close();
  }
}

async function hashRegularFile(filePath, remainingBytes) {
  const before = await lstat(filePath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`Unsupported reference entry: ${filePath}`);
  if (before.size > BigInt(MAX_REFERENCE_FILE_BYTES)) {
    throw new Error(`Reference file exceeds the ${MAX_REFERENCE_FILE_BYTES}-byte limit: ${filePath}`);
  }
  if (before.size > BigInt(remainingBytes)) {
    throw new Error(`Reference tree exceeds the ${MAX_REFERENCE_TOTAL_BYTES}-byte aggregate limit.`);
  }

  const handle = await open(filePath, 'r');
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened) || opened.size !== before.size) {
      throw new Error(`Reference file changed before it could be hashed: ${filePath}`);
    }
    const expectedBytes = Number(opened.size);
    let observedBytes = 0;
    const digest = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      observedBytes += chunk.length;
      if (observedBytes > expectedBytes || observedBytes > MAX_REFERENCE_FILE_BYTES) {
        throw new Error(`Reference file grew beyond its bounded observed size: ${filePath}`);
      }
      digest.update(chunk);
    }
    const [after, pathAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(filePath, { bigint: true })
    ]);
    if (
      observedBytes !== expectedBytes || !after.isFile() || !pathAfter.isFile() ||
      !sameIdentity(opened, after) || !sameIdentity(opened, pathAfter) ||
      opened.size !== after.size || opened.size !== pathAfter.size ||
      opened.mtimeNs !== after.mtimeNs || opened.mtimeNs !== pathAfter.mtimeNs
    ) {
      throw new Error(`Reference file changed while it was being hashed: ${filePath}`);
    }
    return { bytes: expectedBytes, sha256: digest.digest('hex') };
  } finally {
    await handle.close();
  }
}

export async function inventoryReferenceTree(root) {
  const rootMetadata = await lstat(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error(`Reference root must be a directory, not a link: ${root}`);
  }
  const entries = [];
  const pending = [{ directory: root, depth: 0 }];
  let boundaryEntries = 0;
  let totalBytes = 0;
  while (pending.length > 0) {
    const { directory, depth } = pending.pop();
    const handle = await opendir(directory);
    for await (const child of handle) {
      boundaryEntries += 1;
      if (boundaryEntries > MAX_REFERENCE_BOUNDARY_ENTRIES) {
        throw new Error(`Reference tree exceeds the ${MAX_REFERENCE_BOUNDARY_ENTRIES}-entry boundary limit.`);
      }
      const absolutePath = path.join(directory, child.name);
      if (child.isSymbolicLink()) throw new Error(`Unsupported reference entry: ${absolutePath}`);
      if (child.isDirectory()) {
        if (depth >= MAX_REFERENCE_DEPTH) {
          throw new Error(`Reference tree exceeds ${MAX_REFERENCE_DEPTH} directory levels.`);
        }
        pending.push({ directory: absolutePath, depth: depth + 1 });
        continue;
      }
      if (!child.isFile()) throw new Error(`Unsupported reference entry: ${absolutePath}`);
      if (entries.length >= MAX_REFERENCE_FILES) {
        throw new Error(`Reference tree exceeds the ${MAX_REFERENCE_FILES}-file limit.`);
      }
      const hashed = await hashRegularFile(absolutePath, MAX_REFERENCE_TOTAL_BYTES - totalBytes);
      totalBytes += hashed.bytes;
      entries.push({
        path: normalizeReferenceRelativePath(
          path.relative(root, absolutePath).split(path.sep).join('/'),
          'Reference entry path'
        ),
        ...hashed
      });
    }
  }
  entries.sort((left, right) => left.path.localeCompare(right.path, 'en'));
  return entries;
}

export function aggregateReferenceEntries(entries) {
  return sha256(entries.map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}`).join('\n'));
}
