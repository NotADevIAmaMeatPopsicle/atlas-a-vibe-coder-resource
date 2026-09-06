import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  inspectLoadedRun,
  inspectRun,
  renderInspectionText,
  scanProject,
  type FindingInspection,
  type NeighborhoodInspection,
  type SymbolInspection
} from '../src/index.js';
import { terminalSafeJson, writeCanonicalJson } from '../src/util/canonical.js';
import { writeFile } from 'node:fs/promises';
import { verifyAndLoadRunDirectory } from '../src/verify.js';

async function createInspectionRun(): Promise<{ root: string; target: string; runDirectory: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-inspect-'));
  const target = path.join(root, 'target');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), [
    "import { middle } from './middle.js';",
    "export const start = middle;",
    "const marker = 'INSPECTION_SOURCE_SENTINEL';",
    'void marker;',
    ''
  ].join('\n'));
  await writeFile(path.join(target, 'src', 'middle.ts'), [
    "import { leaf } from './leaf.js';",
    'export const middle = leaf;',
    ''
  ].join('\n'));
  await writeFile(path.join(target, 'src', 'leaf.ts'), 'export const leaf = 7;\n');
  await writeFile(path.join(target, 'src', 'orphan.ts'), 'export const orphan = true;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'inspect-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'inspect-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    maxFileBytes: 100_000
  });
  const scan = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath: path.join(root, 'workspace')
  });
  return { root, target, runDirectory: scan.runDirectory };
}

test('symbol and finding inspection return exact cited run records', async (context) => {
  const fixture = await createInspectionRun();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const symbol = await inspectRun(fixture.runDirectory, { symbol: 'middle' }) as SymbolInspection;
  assert.equal(symbol.kind, 'symbol');
  assert.deepEqual(symbol.matches.map((match) => match.file.path), ['src/middle.ts']);
  assert.deepEqual(symbol.matches[0]?.matchedSymbols, ['middle']);
  assert(symbol.matches[0]?.incoming.some((relationship) => relationship.fromPath === 'src/index.ts'));
  assert(symbol.matches[0]?.outgoing.some((relationship) => relationship.toPath === 'src/leaf.ts'));

  const summary = await inspectRun(fixture.runDirectory);
  assert.equal(summary.kind, 'summary');
  const orphanFile = await inspectRun(fixture.runDirectory, { file: 'src/orphan.ts' });
  assert.equal(orphanFile.kind, 'file');
  if (orphanFile.kind !== 'file') throw new Error('Expected file inspection.');
  const candidate = orphanFile.findings.find((finding) => finding.category === 'dead-code-candidate');
  assert(candidate);
  const finding = await inspectRun(fixture.runDirectory, { finding: candidate.id }) as FindingInspection;
  assert.equal(finding.kind, 'finding');
  assert.equal(finding.finding.id, candidate.id);
  assert(finding.files.some((file) => file.path === 'src/orphan.ts'));
});

test('loaded inspection remains bound to verified in-memory artifacts after disk replacement', async (context) => {
  const fixture = await createInspectionRun();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const verified = await verifyAndLoadRunDirectory(fixture.runDirectory);
  const candidate = verified.artifacts.findings.find((finding) => finding.path === 'src/orphan.ts');
  assert(candidate);
  await writeFile(path.join(fixture.runDirectory, 'findings.jsonl'), '{}\n');

  const inspection = await inspectLoadedRun(verified.artifacts, { finding: candidate.id });
  assert.equal(inspection.kind, 'finding');
  if (inspection.kind !== 'finding') throw new Error('Expected finding inspection.');
  assert.deepEqual(inspection.finding, candidate);
  assert(inspection.files.some((file) => file.path === 'src/orphan.ts'));
  await assert.rejects(inspectRun(fixture.runDirectory, { finding: candidate.id }), /digest mismatch/i);
});

test('bounded graph neighborhoods expose direction, boundary, and truncation', async (context) => {
  const fixture = await createInspectionRun();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const oneHop = await inspectRun(fixture.runDirectory, {
    neighborhood: 'src/index.ts',
    direction: 'outgoing',
    depth: 1
  }) as NeighborhoodInspection;
  assert.equal(oneHop.kind, 'neighborhood');
  assert.deepEqual(oneHop.nodes.map((node) => [node.distance, node.file.path]), [
    [0, 'src/index.ts'],
    [1, 'src/middle.ts']
  ]);
  const boundary = oneHop.relationships.find((relationship) => relationship.toPath === 'src/leaf.ts');
  assert(boundary);
  assert(oneHop.boundaryRelationshipIds.includes(boundary.id));
  assert.equal(oneHop.coverage.truncated, true);

  const full = await inspectRun(fixture.runDirectory, {
    neighborhood: 'src/index.ts',
    direction: 'outgoing',
    depth: 2
  }) as NeighborhoodInspection;
  assert.deepEqual(full.nodes.map((node) => node.file.path), ['src/index.ts', 'src/middle.ts', 'src/leaf.ts']);
  assert.equal(full.coverage.truncated, false);
  const reverse = await inspectRun(fixture.runDirectory, {
    neighborhood: 'src/leaf.ts',
    direction: 'incoming',
    depth: 2
  }) as NeighborhoodInspection;
  assert.deepEqual(reverse.nodes.map((node) => node.file.path), ['src/leaf.ts', 'src/middle.ts', 'src/index.ts']);
});

test('neighborhood traversal indexes relationships once instead of rescanning for each frontier node', async (context) => {
  const fixture = await createInspectionRun();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const loaded = (await verifyAndLoadRunDirectory(fixture.runDirectory)).artifacts;
  let relationshipReads = 0;
  const relationships = new Proxy(loaded.relationships, {
    get(target, property, receiver) {
      if (typeof property === 'string' && /^\d+$/u.test(property)) relationshipReads += 1;
      return Reflect.get(target, property, receiver);
    }
  });

  const result = await inspectLoadedRun({ ...loaded, relationships }, {
    neighborhood: 'src/index.ts',
    direction: 'outgoing',
    depth: 2
  });
  assert.equal(result.kind, 'neighborhood');
  assert.equal(relationshipReads, relationships.length * 2);
});

test('inspection rejects ambiguous selectors and human output contains no source bodies or absolute paths', async (context) => {
  const fixture = await createInspectionRun();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await assert.rejects(
    inspectRun(fixture.runDirectory, { file: 'src/index.ts', symbol: 'start' }),
    /exactly one/i
  );
  await assert.rejects(inspectRun(fixture.runDirectory, { depth: 1 }), /only valid with a neighborhood/i);
  await assert.rejects(inspectRun(fixture.runDirectory, { neighborhood: 'src/index.ts', depth: 9 }), /between 0 and 8/i);
  await assert.rejects(inspectRun(fixture.runDirectory, { symbol: 'missing' }), /no exported symbol/i);

  const result = await inspectRun(fixture.runDirectory, { neighborhood: 'src/index.ts', depth: 2 });
  const rendered = renderInspectionText(result);
  assert.match(rendered, /Atlas inspection: neighborhood/);
  assert.match(rendered, /src\/leaf\.ts/);
  assert(!rendered.includes('INSPECTION_SOURCE_SENTINEL'));
  assert(!rendered.includes(path.resolve(fixture.target)));
});

test('human inspection output visibly encodes terminal and bidi controls', async (context) => {
  const fixture = await createInspectionRun();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const fileResult = await inspectRun(fixture.runDirectory, { file: 'src/orphan.ts' });
  if (fileResult.kind !== 'file') throw new Error('Expected file inspection.');
  const result = await inspectRun(fixture.runDirectory, { finding: fileResult.findings[0]!.id }) as FindingInspection;
  result.finding.title = 'safe\u001b]8;;https://example.invalid\u0007link\nspoof';
  result.finding.nextValidation = 'left\u202Eright';

  const rendered = renderInspectionText(result);
  assert.match(rendered, /Title: safe\\u\{1B\}\]8;;https:\/\/example\.invalid\\u\{7\}link\\u\{A\}spoof/u);
  assert.match(rendered, /Next validation: left\\u\{202E\}right/u);
  assert.doesNotMatch(rendered, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u);

  const json = terminalSafeJson({ path: 'safe\u009B31mbad\u202Etxt', escape: '\u001b]52;c;secret\u0007' });
  assert.doesNotMatch(json, /[\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u);
  assert.match(json, /safe\\u009B31mbad\\u202Etxt/u);
  assert.deepEqual(JSON.parse(json), { path: 'safe\u009B31mbad\u202Etxt', escape: '\u001b]52;c;secret\u0007' });
});
