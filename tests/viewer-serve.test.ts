import assert from 'node:assert/strict';
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AtlasError } from '../src/errors.js';
import { scanProject } from '../src/run.js';
import { writeCanonicalJson } from '../src/util/canonical.js';
import { createRunViewer, startViewerServer } from '../src/viewer/index.js';

async function createViewerFixture(): Promise<{ root: string; viewerDirectory: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-viewer-serve-test-'));
  const target = path.join(root, 'target');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), 'export const ready = true;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'viewer-serve-test-target',
    path: './target',
    consent: { agentReview: false, export: true, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'viewer-serve-test-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    operationalRisks: { guardPaths: ['src/index.ts'], seedDictionarySources: [] },
    lifecycleRules: [{ id: 'fixture-entrypoint', state: 'active', paths: ['src/index.ts'] }],
    maxFileBytes: 100_000
  });
  const workspacePath = path.join(root, 'workspace');
  const scan = await scanProject({ targetConfigPath, profilePath, workspacePath });
  const viewerDirectory = path.join(root, 'viewer');
  await createRunViewer({
    runDirectory: scan.runDirectory,
    workspacePath,
    targetConfigPath,
    outputDirectory: viewerDirectory
  });
  return { root, viewerDirectory };
}

async function request(
  url: URL,
  requestPath: string,
  method = 'GET',
  options: { hostHeader?: string; omitHost?: boolean } = {}
): Promise<{
  status: number | undefined;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}> {
  return new Promise((resolve, reject) => {
    const outgoing = http.request({
      host: url.hostname,
      port: url.port,
      path: requestPath,
      method,
      setHost: options.omitHost !== true,
      headers: {
        Connection: 'close',
        ...(options.hostHeader === undefined ? {} : { Host: options.hostHeader })
      }
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks)
      }));
    });
    outgoing.on('error', reject);
    outgoing.end();
  });
}

test('viewer server verifies once, serves only canonical artifacts, and applies hardened headers', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const running = await startViewerServer({ viewerDirectory: fixture.viewerDirectory, port: 0 });
  context.after(async () => running.close());

  assert.equal(running.host, '127.0.0.1');
  assert(running.port > 0);
  assert.match(running.viewerId, /^viewer_sha256_[a-f0-9]{64}$/u);
  const url = new URL(running.url);
  const index = await request(url, '/');
  assert.equal(index.status, 200);
  assert.deepEqual(index.body, await readFile(path.join(fixture.viewerDirectory, 'index.html')));
  assert.equal(index.headers['content-type'], 'text/html; charset=utf-8');
  assert.equal(index.headers['cache-control'], 'no-store, max-age=0');
  assert.equal(index.headers['x-content-type-options'], 'nosniff');
  assert.equal(index.headers['x-frame-options'], 'DENY');
  assert.equal(index.headers['cross-origin-resource-policy'], 'same-origin');
  assert.match(String(index.headers['content-security-policy'] ?? ''), /default-src 'none'/u);

  for (const artifact of [
    'app.css',
    'app.js',
    'atlas-data.js',
    'dependency-graph.mmd',
    'index.html',
    'viewer-manifest.json'
  ]) {
    const response = await request(url, `/${artifact}`);
    assert.equal(response.status, 200, artifact);
    assert.deepEqual(response.body, await readFile(path.join(fixture.viewerDirectory, artifact)), artifact);
  }

  const manifestHead = await request(url, '/viewer-manifest.json?download=false', 'HEAD');
  assert.equal(manifestHead.status, 200);
  assert.equal(manifestHead.headers['content-type'], 'application/json; charset=utf-8');
  assert.equal(manifestHead.body.length, 0);
  assert(Number(manifestHead.headers['content-length']) > 0);

  const missing = await request(url, '/package.json');
  assert.equal(missing.status, 404);
  const traversal = await request(url, '/../package.json');
  assert.equal(traversal.status, 404);
  const encodedTraversal = await request(url, '/..%2fpackage.json');
  assert.equal(encodedTraversal.status, 404);
  const post = await request(url, '/index.html', 'POST');
  assert.equal(post.status, 405);
  assert.equal(post.headers.allow, 'GET, HEAD');
});

test('viewer server refuses a bundle changed after publication before listening', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await appendFile(path.join(fixture.viewerDirectory, 'app.css'), '\n/* changed */\n');
  await assert.rejects(
    startViewerServer({ viewerDirectory: fixture.viewerDirectory, port: 0 }),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DIGEST_MISMATCH'
  );
});

test('viewer server rejects non-loopback hosts', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await assert.rejects(
    async () => {
      const running = await startViewerServer({
        viewerDirectory: fixture.viewerDirectory,
        host: '0.0.0.0',
        port: 0
      });
      await running.close();
    },
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_SERVER_HOST_UNSAFE'
  );
});

test('viewer server rejects untrusted Host headers and permits an explicit proxy hostname', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const running = await startViewerServer({
    viewerDirectory: fixture.viewerDirectory,
    port: 0,
    allowedHosts: ['atlas-node.example.test']
  });
  context.after(async () => running.close());
  const url = new URL(running.url);

  assert.equal((await request(url, '/', 'GET', { hostHeader: 'attacker.example' })).status, 421);
  assert.notEqual((await request(url, '/', 'GET', { omitHost: true })).status, 200);
  assert.equal((await request(url, '/', 'GET', { hostHeader: `LOCALHOST:${running.port}` })).status, 200);
  assert.equal((await request(url, '/', 'GET', { hostHeader: `[0:0:0:0:0:0:0:1]:${running.port}` })).status, 200);
  assert.equal((await request(url, '/', 'GET', { hostHeader: 'localhost:1' })).status, 421);
  assert.equal((await request(url, '/', 'GET', { hostHeader: 'atlas-node.example.test:443' })).status, 200);
  assert.equal((await request(url, '/', 'GET', { hostHeader: 'atlas-node.example.test.evil' })).status, 421);
});

test('viewer server keeps serving verified in-memory bytes after an artifact changes on disk', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const cssPath = path.join(fixture.viewerDirectory, 'app.css');
  const verifiedCss = await readFile(cssPath);
  const running = await startViewerServer({ viewerDirectory: fixture.viewerDirectory, port: 0 });
  context.after(async () => running.close());

  await appendFile(cssPath, '\n/* changed after server start */\n');
  const response = await request(new URL(running.url), '/app.css');

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, verifiedCss);
  assert.equal(response.headers['content-length'], String(verifiedCss.length));
  assert.notDeepEqual(response.body, await readFile(cssPath));
});
