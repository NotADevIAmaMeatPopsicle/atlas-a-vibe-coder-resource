import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function compareCanonicalText(leftValue: string, rightValue: string): number {
  const left = [...leftValue.normalize('NFC')];
  const right = [...rightValue.normalize('NFC')];
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left[index]!.codePointAt(0)! - right[index]!.codePointAt(0)!;
    if (difference) return difference;
  }
  return left.length - right.length;
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key.normalize('NFC'), normalize(entry)] as const)
      .sort(([left], [right]) => compareCanonicalText(left, right));
    if (new Set(entries.map(([key]) => key)).size !== entries.length) throw new TypeError('Object keys collide after Unicode NFC normalization.');
    return Object.fromEntries(entries);
  }
  if (typeof value === 'string') return value.normalize('NFC');
  if (typeof value === 'number' && (!Number.isFinite(value) || !Number.isInteger(value))) {
    throw new TypeError('Canonical Atlas JSON supports only finite integers.');
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function prettyCanonicalJson(value: unknown): string {
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}

export function terminalSafeJson(value: unknown): string {
  return prettyCanonicalJson(value).replace(
    /[\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu,
    (character) => `\\u${character.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`
  );
}

export function canonicalJsonLines(values: unknown[]): string {
  return values.map((value) => canonicalJson(value)).join('\n') + (values.length ? '\n' : '');
}

export async function writeCanonicalJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, prettyCanonicalJson(value), 'utf8');
}

export async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

export async function readJsonLines<T>(path: string): Promise<T[]> {
  const content = await readFile(path, 'utf8');
  return content.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as T);
}
