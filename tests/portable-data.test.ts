import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AtlasError } from '../src/errors.js';
import { scanProject } from '../src/run.js';
import { assertPortableDataSafe } from '../src/security/portable-data.js';
import { writeCanonicalJson } from '../src/util/canonical.js';

test('portable data preflight accepts normalized evidence metadata without mutation', () => {
  const value = {
    path: 'src/config.ts',
    symbols: ['API_KEY_NAME', 'sketchProject'],
    evidence: {
      producer: 'atlas/test',
      basis: 'literal-key-name-only',
      message: 'A token declaration is missing, but no value was retained.'
    },
    ids: [`run_sha256_${'a'.repeat(64)}`]
  };
  const before = structuredClone(value);
  const summary = assertPortableDataSafe(value);
  assert(summary.checkedStrings > 0);
  assert(summary.checkedObjects > 0);
  assert.equal(summary.secretLikeMatches, 0);
  assert.deepEqual(value, before);
});

test('portable data preflight rejects credential shapes without disclosing them', () => {
  const credential = `sk-proj-${'A'.repeat(32)}`;
  assert.throws(
    () => assertPortableDataSafe({ nested: [{ label: credential }] }, 'memory response'),
    (error: unknown) => {
      assert(error instanceof AtlasError);
      assert.equal(error.code, 'PORTABLE_DATA_SECRET_DETECTED');
      assert.match(error.message, /openai-api-key/);
      assert(!error.message.includes(credential));
      return true;
    }
  );
});

test('portable data preflight rejects source and binary bodies while allowing graph source identifiers', () => {
  assert.throws(
    () => assertPortableDataSafe({ sourceText: 'export const secret = 1;' }),
    (error: unknown) => error instanceof AtlasError && error.code === 'PORTABLE_DATA_SOURCE_BODY'
  );
  assert.throws(
    () => assertPortableDataSafe({ bytes: Buffer.from('not portable') }),
    (error: unknown) => error instanceof AtlasError && error.code === 'PORTABLE_DATA_BINARY_BODY'
  );
  assert.doesNotThrow(() => assertPortableDataSafe({ source: 'file-id', target: 'other-file-id' }));
});

test('portable data preflight rejects cycles deterministically', () => {
  const cyclic: { self?: unknown } = {};
  cyclic.self = cyclic;
  assert.throws(
    () => assertPortableDataSafe(cyclic),
    (error: unknown) => error instanceof AtlasError && error.code === 'PORTABLE_DATA_CYCLE'
  );
});

test('scan publication fails closed without retaining a secret-shaped artifact string', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-portable-preflight-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const target = path.join(root, 'target');
  const workspace = path.join(root, 'workspace');
  const credential = `sk-proj-${'Q'.repeat(32)}`;
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', `${credential}.ts`), 'export const safeValue = 1;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'portable-preflight-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'portable-preflight-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: [],
    maxFileBytes: 100000
  });

  await assert.rejects(
    scanProject({ targetConfigPath, profilePath, workspacePath: workspace }),
    (error: unknown) => {
      assert(error instanceof AtlasError);
      assert.equal(error.code, 'PORTABLE_DATA_SECRET_DETECTED');
      assert(!error.message.includes(credential));
      return true;
    }
  );
  await assert.rejects(readdir(path.join(workspace, 'runs')), /ENOENT/u);
  const attempts = await readdir(path.join(workspace, 'attempts'));
  assert.equal(attempts.length, 1);
  const receipt = await readFile(path.join(workspace, 'attempts', attempts[0]!), 'utf8');
  assert(!receipt.includes(credential));
  assert.match(receipt, /PORTABLE_DATA_SECRET_DETECTED/u);
});
