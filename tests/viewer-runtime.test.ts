import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';

import { createRunViewer } from '../src/viewer/index.js';
import { scanProject } from '../src/run.js';
import { VIEWER_APP_JAVASCRIPT } from '../src/viewer/assets.js';

/**
 * Executes the generated viewer bundle instead of matching its source text.
 *
 * A text assertion proves a function was written; it cannot prove the bundle
 * runs. The bundle wraps its bootstrap in a try/catch that turns any throw into
 * a status message, so a scope or reference error renders an empty viewer while
 * every source-matching test still passes. That is what shipped in `ec0123d`,
 * where `findingQueueGroups` (module scope) called `recordAnchor` (declared
 * inside `render`), and the queue rendered zero rows.
 *
 * The DOM stub below is deliberately permissive: unknown element members are
 * absorbed so the renderer can run to completion. It does NOT absorb a missing
 * binding in the bundle's own scope, which is exactly the class this guards.
 */

interface StatusRecord {
  texts: string[];
  listeners?: Map<string, () => void>;
  blobs?: string[];
}

/** Values the renderer's own filter controls must yield for findings to survive. */
function controlValue(id: string): string {
  if (id.includes('severity')) return 'all';
  if (id.includes('sort')) return 'severity';
  return '';
}

function createDomStub(status: StatusRecord): Record<string, unknown> {
  const nodes = new Map<string, unknown>();
  const makeNode = (value = '', id?: string): unknown => new Proxy(function stub() {} as unknown as Record<string | symbol, unknown>, {
    get(_target, property) {
      if (property === 'value') return value;
      if (property === 'length') return 0;
      if (property === Symbol.iterator) return function* () { /* empty collection */ };
      if (property === Symbol.toPrimitive || property === 'toString') return () => '';
      if (property === 'classList') return { add() {}, remove() {}, toggle() {}, contains() { return false; } };
      if (property === 'dataset' || property === 'style') return {};
      if (property === 'parentNode' || property === 'firstChild') return null;
      if (property === 'addEventListener') return (event: string, listener: () => void) => {
        if (id && status.listeners) status.listeners.set(`${id}:${event}`, listener);
      };
      return makeNode();
    },
    set() { return true; },
    has() { return true; },
    apply() { return makeNode(); }
  });

  const document = {
    createElement: () => makeNode(),
    createElementNS: () => makeNode(),
    createDocumentFragment: () => makeNode(),
    createTextNode: (value: unknown) => {
      status.texts.push(String(value));
      return makeNode();
    },
    // Form controls must return real primitive values. A permissive proxy here
    // makes every severity comparison fail, empties the finding list, and the
    // grouping path then runs over nothing, so the test would pass while
    // observing nothing at all.
    getElementById: (id: string) => {
      const existing = nodes.get(id);
      if (existing) return existing;
      const node = makeNode(controlValue(id), id);
      nodes.set(id, node);
      return node;
    },
    querySelector: () => makeNode(),
    querySelectorAll: () => [],
    addEventListener: () => {},
    documentElement: makeNode(),
    body: makeNode()
  };

  return {
    document,
    window: new Proxy({}, {
      get(_target, property) {
        if (property === 'location') return { href: '', hash: '' };
        if (property === 'matchMedia') return () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
        if (property === 'devicePixelRatio' || property === 'innerWidth' || property === 'innerHeight') return 1;
        return () => undefined;
      },
      set() { return true; },
      has() { return true; }
    }),
    navigator: { clipboard: { writeText: async () => {} } },
    requestAnimationFrame: (callback: () => void) => { callback(); return 0; },
    setTimeout: (callback: () => void) => { callback(); return 0; },
    clearTimeout: () => {},
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    URL: {
      createObjectURL: () => 'blob:atlas-test',
      revokeObjectURL: () => {}
    },
    Blob: class {
      constructor(parts: unknown[]) {
        status.blobs?.push(parts.map(String).join(''));
      }
    },
    atob: (value: string) => Buffer.from(value, 'base64').toString('binary'),
    btoa: (value: string) => Buffer.from(value, 'binary').toString('base64'),
    TextDecoder,
    TextEncoder,
    Uint8Array,
    JSON,
    Math,
    Number,
    String,
    Array,
    Object,
    Boolean,
    Date,
    RegExp,
    Error,
    Map,
    Set,
    isNaN,
    parseInt,
    parseFloat,
    console
  };
}

async function buildViewerBundle(): Promise<{ root: string; encoded: string; findingCount: number }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-viewer-runtime-'));
  const target = path.join(root, 'target');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(
    path.join(target, 'src', 'index.ts'),
    // The unresolved import is deliberate: it guarantees the run produces
    // findings so the queue-grouping path actually executes. A fixture with zero
    // findings would make this whole test a silent pass.
    [
      "import { missing } from './not-here.js';",
      "export function entry(value: string): string {",
      "  return missing(value.trim());",
      "}",
      ''
    ].join('\n'),
    'utf8'
  );
  await writeFile(path.join(target, 'package.json'), JSON.stringify({ name: 'runtime-fixture', version: '1.0.0' }), 'utf8');

  const targetConfigPath = path.join(root, 'target.json');
  await writeFile(targetConfigPath, JSON.stringify({
    schemaVersion: 1,
    id: 'viewer-runtime-fixture',
    path: target,
    consent: { agentReview: false, export: true, projectMemory: false }
  }), 'utf8');

  const profilePath = path.join(root, 'profile.json');
  await writeFile(profilePath, JSON.stringify({
    schemaVersion: 1,
    id: 'viewer-runtime-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    operationalRisks: { guardPaths: ['src/index.ts'], seedDictionarySources: [] },
    lifecycleRules: [{ id: 'runtime-entrypoint', state: 'active', paths: ['src/index.ts'] }],
    maxFileBytes: 100000
  }), 'utf8');

  const workspacePath = path.join(root, 'workspace');
  const scan = await scanProject({ targetConfigPath, profilePath, workspacePath });

  const outputDirectory = path.join(root, 'viewer');
  await createRunViewer({
    runDirectory: scan.runDirectory,
    workspacePath,
    targetConfigPath,
    outputDirectory
  });

  const data = await readFile(path.join(outputDirectory, 'atlas-data.js'), 'utf8');
  const match = /__ATLAS_VIEWER_DATA_B64__\s*=\s*"([A-Za-z0-9+/=]*)"/.exec(data);
  assert.ok(match, 'atlas-data.js must expose a base64 payload');
  const decoded = JSON.parse(Buffer.from(match[1]!, 'base64').toString('utf8')) as { findings?: unknown[] };
  return { root, encoded: match[1]!, findingCount: (decoded.findings ?? []).length };
}

test('the generated viewer bundle executes and reports a ready status', async (context) => {
  const { root, encoded, findingCount } = await buildViewerBundle();
  context.after(async () => rm(root, { recursive: true, force: true }));

  // Positive control. Without findings the grouping path never runs, and a green
  // below would mean nothing at all.
  assert.ok(findingCount > 0, 'the fixture run must produce findings for this control to observe anything');

  const status: StatusRecord = { texts: [] };
  const sandbox = createDomStub(status);
  (sandbox as Record<string, unknown>).__ATLAS_VIEWER_DATA_B64__ = encoded;
  vm.createContext(sandbox);

  // A throw here is a genuine bundle fault. The bundle's own try/catch converts
  // most faults into a status message, which is what the assertions below read.
  vm.runInContext(VIEWER_APP_JAVASCRIPT, sandbox, { filename: 'app.js', timeout: 30_000 });

  const failures = status.texts.filter((text) => text.startsWith('Unable to load this viewer'));
  assert.deepEqual(
    failures,
    [],
    `the viewer bundle failed at runtime: ${failures.join(' | ')}`
  );
  assert.ok(
    status.texts.some((text) => text === 'Bundled run data loaded'),
    `the viewer bundle never reached its ready status; observed: ${status.texts.join(' | ')}`
  );
});

test('viewer handoff renders every target-controlled field as inert Markdown code', async (context) => {
  const { root, encoded } = await buildViewerBundle();
  context.after(async () => rm(root, { recursive: true, force: true }));
  const data = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8')) as {
    findings: Array<Record<string, unknown>>;
  };
  const finding = data.findings[0]!;
  finding.title = '![remote](https://example.invalid/pixel)\n# injected';
  finding.description = '<img src="https://example.invalid/pixel">\u001b]8;;https://example.invalid\u0007link';
  finding.nextValidation = '[click](https://example.invalid)\u202Etxt `break`';
  const hostileEncoded = Buffer.from(JSON.stringify(data), 'utf8').toString('base64');

  const status: StatusRecord = { texts: [], listeners: new Map(), blobs: [] };
  const sandbox = createDomStub(status);
  (sandbox as Record<string, unknown>).__ATLAS_VIEWER_DATA_B64__ = hostileEncoded;
  vm.createContext(sandbox);
  vm.runInContext(VIEWER_APP_JAVASCRIPT, sandbox, { filename: 'app.js', timeout: 30_000 });
  const exportHandoff = status.listeners?.get('export-handoff:click');
  assert(exportHandoff, 'viewer must register the handoff action');
  exportHandoff();

  const markdown = status.blobs?.[0] ?? '';
  assert.match(markdown, /^# Atlas implementation handoff: `!\[remote\]/u);
  assert.match(markdown, /\\u\{A\}# injected/u);
  assert.match(markdown, /`<img src="https:\/\/example\.invalid\/pixel">\\u\{1B\}\]8/u);
  assert.match(markdown, /`` \[click\]\(https:\/\/example\.invalid\)\\u\{202E\}txt `break` ``/u);
  assert.doesNotMatch(markdown, /\n# injected/u);
  assert.doesNotMatch(markdown, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u);
});
