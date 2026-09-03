import type { Dirent } from 'node:fs';
import { lstat, open, opendir } from 'node:fs/promises';
import { AtlasError } from '../errors.js';

export const MAX_VERIFIER_DIRECTORY_ENTRIES = 64;
export const MAX_VERIFIER_MANIFEST_BYTES = 4 * 1024 * 1024;
export const MAX_VERIFIER_ARTIFACT_BYTES = 128 * 1024 * 1024;
export const MAX_VERIFIER_TOTAL_BYTES = 256 * 1024 * 1024;
export const MAX_VERIFIER_JSONL_RECORDS = 250_000;
export const MAX_HISTORICAL_REFERENCE_DEPTH = 128;
export const MAX_HISTORICAL_TEXT_LINES = 250_000;
export const MAX_VERIFIER_NESTING_DEPTH = 128;

interface BoundedReadOptions {
  maxBytes: number;
  resourceCode: string;
  invalidCode: string;
  label: string;
}

interface BoundedJsonReadOptions extends BoundedReadOptions {
  maxDepth?: number;
}

function sameIdentity(
  left: { dev: bigint; ino: bigint },
  right: { dev: bigint; ino: bigint }
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

export async function readBoundedRegularFile(
  filePath: string,
  options: BoundedReadOptions
): Promise<Buffer> {
  const before = await lstat(filePath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new AtlasError(options.invalidCode, `${options.label} must be a regular file.`);
  }
  if (before.size > BigInt(options.maxBytes)) {
    throw new AtlasError(options.resourceCode, `${options.label} exceeds the ${options.maxBytes}-byte verification limit.`);
  }

  const handle = await open(filePath, 'r');
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened) || opened.size !== before.size) {
      throw new AtlasError(options.invalidCode, `${options.label} changed before it could be read.`);
    }
    const size = Number(opened.size);
    const content = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const result = await handle.read(content, offset, size - offset, null);
      if (result.bytesRead === 0) {
        throw new AtlasError(options.invalidCode, `${options.label} changed while it was being read.`);
      }
      offset += result.bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    if ((await handle.read(probe, 0, 1, null)).bytesRead !== 0) {
      throw new AtlasError(options.resourceCode, `${options.label} grew beyond its bounded observed size.`);
    }
    const after = await handle.stat({ bigint: true });
    if (
      !sameIdentity(opened, after) || after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs
    ) {
      throw new AtlasError(options.invalidCode, `${options.label} changed while it was being read.`);
    }
    return content;
  } finally {
    await handle.close();
  }
}

export async function readBoundedJsonFile<T>(
  filePath: string,
  options: BoundedJsonReadOptions
): Promise<T> {
  const content = await readBoundedRegularFile(filePath, options);
  let value: unknown;
  try {
    value = JSON.parse(content.toString('utf8')) as unknown;
  } catch (error) {
    throw new AtlasError(
      options.invalidCode,
      `${options.label} is not valid JSON: ${error instanceof Error ? error.message : 'unknown parse failure'}`
    );
  }
  if (options.maxDepth !== undefined) {
    assertNestingDepth(value, {
      maxDepth: options.maxDepth,
      resourceCode: options.resourceCode,
      label: options.label
    });
  }
  return value as T;
}

export async function readBoundedDirectoryEntries(
  directory: string,
  options: { maxEntries: number; resourceCode: string; label: string }
): Promise<Dirent[]> {
  const entries: Dirent[] = [];
  const handle = await opendir(directory);
  for await (const entry of handle) {
    entries.push(entry);
    if (entries.length > options.maxEntries) {
      throw new AtlasError(
        options.resourceCode,
        `${options.label} exceeds the ${options.maxEntries}-entry verification limit.`
      );
    }
  }
  return entries;
}

export function assertAggregateByteLimit(
  values: readonly number[],
  options: { maxBytes: number; resourceCode: string; label: string }
): void {
  let total = 0;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0 || value > options.maxBytes - total) {
      throw new AtlasError(
        options.resourceCode,
        `${options.label} exceeds the ${options.maxBytes}-byte aggregate verification limit.`
      );
    }
    total += value;
  }
}

export function addToBoundedCount(
  current: number,
  additional: number,
  options: { maxCount: number; resourceCode: string; label: string }
): number {
  if (
    !Number.isSafeInteger(current) || current < 0 ||
    !Number.isSafeInteger(additional) || additional < 0 ||
    additional > options.maxCount - current
  ) {
    throw new AtlasError(
      options.resourceCode,
      `${options.label} exceeds the ${options.maxCount}-item aggregate limit.`
    );
  }
  return current + additional;
}

export function parseBoundedJsonLines<T>(
  content: string,
  options: { maxRecords: number; maxDepth?: number; resourceCode: string; label: string }
): T[] {
  const records: T[] = [];
  let start = 0;
  while (start < content.length) {
    const newline = content.indexOf('\n', start);
    const end = newline === -1 ? content.length : newline;
    const lineEnd = end > start && content[end - 1] === '\r' ? end - 1 : end;
    if (lineEnd > start) {
      if (records.length >= options.maxRecords) {
        throw new AtlasError(
          options.resourceCode,
          `${options.label} exceeds the ${options.maxRecords}-record verification limit.`
        );
      }
      const value = JSON.parse(content.slice(start, lineEnd)) as T;
      if (options.maxDepth !== undefined) {
        assertNestingDepth(value, {
          maxDepth: options.maxDepth,
          resourceCode: options.resourceCode,
          label: options.label
        });
      }
      records.push(value);
    }
    if (newline === -1) break;
    start = newline + 1;
  }
  return records;
}

export function assertTextLineLimit(
  content: string,
  options: { maxLines: number; resourceCode: string; label: string }
): void {
  let lines = content.length === 0 ? 0 : 1;
  for (let index = 0; index < content.length; index += 1) {
    if (content.charCodeAt(index) === 10) {
      lines += 1;
      if (lines > options.maxLines) {
        throw new AtlasError(
          options.resourceCode,
          `${options.label} exceeds the ${options.maxLines}-line verification limit.`
        );
      }
    }
  }
}

export function assertNestingDepth(
  value: unknown,
  options: { maxDepth: number; resourceCode: string; label: string }
): void {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (current.value === null || typeof current.value !== 'object') continue;
    if (current.depth > options.maxDepth) {
      throw new AtlasError(
        options.resourceCode,
        `${options.label} exceeds the ${options.maxDepth}-level nesting limit.`
      );
    }
    if (Array.isArray(current.value)) {
      for (const child of current.value) pending.push({ value: child, depth: current.depth + 1 });
    } else {
      for (const child of Object.values(current.value as Record<string, unknown>)) {
        pending.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
}
