import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateRealTargetCorpus } from '../src/regression/real-target.js';
import { sha256 } from '../src/util/canonical.js';

const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

function runGit(repositoryPath: string, command: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('git', [
      '-c', 'user.name=Atlas Tests',
      '-c', 'user.email=atlas-tests@example.invalid',
      '-c', 'commit.gpgSign=false',
      '-c', `core.hooksPath=${NULL_DEVICE}`,
      '--no-optional-locks',
      '-C', repositoryPath,
      ...command
    ], {
      encoding: 'utf8',
      env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' },
      windowsHide: true
    }, (error, stdout) => error ? reject(error) : resolve(stdout));
  });
}

async function gitAvailable(): Promise<boolean> {
  return new Promise((resolve) => execFile('git', ['--version'], { windowsHide: true }, (error) => resolve(!error)));
}

const hasGit = await gitAvailable();

function lineContaining(source: string, needle: string): number {
  const index = source.split(/\r?\n/u).findIndex((line) => line.includes(needle));
  assert.notEqual(index, -1, `Missing fixture line: ${needle}`);
  return index + 1;
}

interface FixtureRepository {
  root: string;
  revision: string;
  manifestPath: string;
  markerPath: string;
  paths: string[];
}

async function createFixtureRepository(temporaryRoot: string, detach = true): Promise<FixtureRepository> {
  const root = path.join(temporaryRoot, 'target');
  const markerPath = path.join(temporaryRoot, 'target-code-executed.txt');
  const checkout = [
    "const fs = require('node:fs');",
    `fs.writeFileSync(${JSON.stringify(markerPath.replace(/\\/gu, '/'))}, 'target code executed');`,
    "const appointmentRepository = require('../repositories/appointment.repository.js');",
    'async function rebook(data) {',
    '  return appointmentRepository.create(data);',
    '}',
    'module.exports = { rebook };',
    ''
  ].join('\n');
  const boundary = [
    "const appointmentRepository = require('../repositories/appointment.repository.js');",
    'async function createAppointment(data) {',
    '  return appointmentRepository.create(data);',
    '}',
    'module.exports = { createAppointment };',
    ''
  ].join('\n');
  const repository = [
    'async function create(data) { return data; }',
    'module.exports = { create };',
    ''
  ].join('\n');
  const notification = [
    'class NotificationService {',
    '  async sendEmail(enabled) {',
    "    if (!enabled) return { success: true, messageId: 'suppressed', suppressed: true };",
    "    return { success: true, messageId: 'delivered' };",
    '  }',
    '  async logNotification(id, action) {',
    "    await sequelize.query('INSERT INTO notification_history(action) VALUES ($1)', { bind: [action] });",
    '  }',
    '  async confirm(id) {',
    '    await this.sendEmail(false);',
    "    await this.logNotification(id, 'confirmation_sent');",
    '  }',
    '}',
    'module.exports = NotificationService;',
    ''
  ].join('\n');
  const compose = [
    'services:',
    '  test-runner-isolated:',
    '    build:',
    '      context: ./src',
    '      dockerfile: Dockerfile.test',
    '    volumes:',
    '      - ./src:/app',
    '      - /app/node_modules',
    '    command: npm test',
    ''
  ].join('\n');
  const dockerfile = [
    'FROM node:22-alpine',
    'WORKDIR /app',
    'COPY . .',
    'CMD ["npm", "test"]',
    ''
  ].join('\n');
  const representativeTest = [
    "const path = require('node:path');",
    "const appRoot = path.resolve(__dirname, '../../..');",
    'void appRoot;',
    ''
  ].join('\n');
  const apiApp = [
    "const express = require('express');",
    "const routes = require('./routes');",
    'const app = express();',
    "app.use('/api', routes);",
    'module.exports = app;',
    ''
  ].join('\n');
  const apiRoutes = [
    "const express = require('express');",
    "const usersRoutes = require('./users.routes');",
    "const importRoutes = require('./import.routes');",
    'const router = express.Router();',
    "router.use('/users', usersRoutes);",
    'module.exports = router;',
    ''
  ].join('\n');
  const userRoutes = [
    "const express = require('express');",
    'const router = express.Router();',
    "router.get('/:id', handler);",
    'module.exports = router;',
    ''
  ].join('\n');
  const importRoutes = [
    "const express = require('express');",
    'const router = express.Router();',
    "router.post('/upload', handler);",
    'module.exports = router;',
    ''
  ].join('\n');
  const apiClient = [
    "import axios from 'axios';",
    'class ApiClient {',
    '  private instance;',
    "  constructor() { this.instance = axios.create({ baseURL: '/api' }); }",
    '  post(url: string, data?: unknown) { return this.instance.post(url, data); }',
    '}',
    'export const apiClient = new ApiClient();',
    'export default apiClient;',
    ''
  ].join('\n');
  const importService = [
    "import apiClient from './api/client';",
    'export function upload(data: unknown) {',
    "  return apiClient.post('/import/upload', data);",
    '}',
    ''
  ].join('\n');
  const sources = new Map<string, string>([
    ['src/src/services/checkout-orchestration.service.js', checkout],
    ['src/src/services/appointment.service.js', boundary],
    ['src/src/repositories/appointment.repository.js', repository],
    ['src/src/services/notification.service.js', notification],
    ['docker-compose.test.yml', compose],
    ['src/Dockerfile.test', dockerfile],
    ['src/tests/unit/reference/appointment-status-artifacts.test.js', representativeTest],
    ['src/package.json', '{"name":"real-target-fixture","scripts":{"test":"node --test"}}\n'],
    ['src/src/app.js', apiApp],
    ['src/src/routes/index.js', apiRoutes],
    ['src/src/routes/users.routes.js', userRoutes],
    ['src/src/routes/import.routes.js', importRoutes],
    ['frontends/admin-dashboard/src/services/api/client.ts', apiClient],
    ['frontends/admin-dashboard/src/services/import.service.ts', importService]
  ]);
  for (const [relativePath, content] of sources) {
    const absolutePath = path.join(root, ...relativePath.split('/'));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, content, 'utf8');
  }
  await runGit(root, ['init', '-b', 'main']);
  await runGit(root, ['config', 'core.autocrlf', 'false']);
  await runGit(root, ['add', '--', '.']);
  await runGit(root, ['commit', '-m', 'fixture']);
  const revision = (await runGit(root, ['rev-parse', 'HEAD'])).trim();
  if (detach) await runGit(root, ['checkout', '--detach', revision]);

  const manifest = {
    schemaVersion: 1,
    id: 'fixture-real-target',
    tier: 'real-target',
    provenance: {
      source: 'Atlas test fixture',
      recordedAt: '2026-08-22',
      note: 'Minimal real-target regression fixture.'
    },
    target: {
      repository: 'fixture/real-target',
      revision,
      objectFormat: 'sha1',
      requireDetached: true,
      requireClean: true
    },
    analysis: {
      entrypoints: ['src/src/services/appointment.service.js', 'src/tests/**/*.test.js'],
      maxFileBytes: 1_000_000,
      operationalRisks: {
        guardPaths: ['src/src/services/**'],
        seedDictionarySources: [],
        boundaries: [{
          id: 'appointment-create-service',
          module: 'src/src/services/appointment.service.js',
          protects: ['appointment-repository-create']
        }],
        protectedWriters: [{
          id: 'appointment-repository-create',
          module: 'src/src/repositories/appointment.repository.js',
          methods: ['create']
        }]
      }
    },
    cases: [
      {
        id: 'fixture-a1',
        family: 'guard-bypass-inventory',
        ruleId: 'operational/guard-bypass-v1',
        mechanismId: 'guard-bypass',
        kind: 'finding',
        anchor: {
          path: 'src/src/services/checkout-orchestration.service.js',
          line: lineContaining(checkout, 'appointmentRepository.create'),
          contains: 'appointmentRepository.create'
        },
        supportingAnchors: [{
          path: 'src/src/services/appointment.service.js',
          line: lineContaining(boundary, 'appointmentRepository.create'),
          contains: 'appointmentRepository.create'
        }],
        expected: {
          minimum: 1,
          requiredSignals: [
            'declared-protected-writer',
            'direct-low-level-writer-call',
            'resolved-boundary-graph-bypass'
          ]
        }
      },
      {
        id: 'fixture-a2',
        family: 'result-collapse',
        ruleId: 'operational/result-collapse-v1',
        mechanismId: 'durable-success-side-effect',
        kind: 'finding',
        anchor: {
          path: 'src/src/services/notification.service.js',
          line: lineContaining(notification, 'confirmation_sent'),
          contains: 'confirmation_sent'
        },
        supportingAnchors: [{
          path: 'src/src/services/notification.service.js',
          line: lineContaining(notification, 'suppressed: true'),
          contains: 'suppressed: true'
        }],
        expected: {
          minimum: 1,
          requiredSignals: [
            'durable-success-write-without-discriminator-branch',
            'rich-result-contract',
            'success-outcome-literal'
          ]
        }
      },
      {
        id: 'fixture-a3',
        family: 'host-container-path-divergence',
        ruleId: 'operational/host-container-path-divergence-v1',
        mechanismId: 'resolved-container-test-coverage',
        kind: 'container-mapping',
        anchor: {
          path: 'docker-compose.test.yml',
          line: lineContaining(compose, 'test-runner-isolated:'),
          contains: 'test-runner-isolated:'
        },
        mapping: {
          composePath: 'docker-compose.test.yml',
          service: 'test-runner-isolated',
          buildContext: 'src',
          dockerfile: 'src/Dockerfile.test',
          workingDirectory: '/app',
          hostRoot: 'src',
          containerRoot: '/app',
          representativePath: 'src/tests/unit/reference/appointment-status-artifacts.test.js',
          expectedContainerPath: '/app/tests/unit/reference/appointment-status-artifacts.test.js',
          sourceKind: 'bind-mount',
          selection: 'broad-test-command'
        },
        expected: {
          forbiddenDiagnosticCodes: [
            'OPERATIONAL_CONTAINER_MAPPING_AMBIGUOUS',
            'OPERATIONAL_CONTAINER_MAPPING_UNDEFINED',
            'OPERATIONAL_CONTAINER_MAPPING_UNSUPPORTED',
            'OPERATIONAL_DOCKERFILE_UNRESOLVED'
          ]
        }
      },
      {
        id: 'fixture-a4',
        family: 'api-client-route-missing',
        ruleId: 'contract/api-client-route-missing-v1',
        mechanismId: 'literal-client-to-unmounted-express-router',
        kind: 'finding',
        anchor: {
          path: 'frontends/admin-dashboard/src/services/import.service.ts',
          line: lineContaining(importService, "apiClient.post('/import/upload'"),
          contains: "apiClient.post('/import/upload'"
        },
        supportingAnchors: [
          {
            path: 'src/src/app.js',
            line: lineContaining(apiApp, "app.use('/api', routes)"),
            contains: "app.use('/api', routes)"
          },
          {
            path: 'src/src/routes/index.js',
            line: lineContaining(apiRoutes, 'module.exports = router'),
            contains: 'module.exports = router'
          },
          {
            path: 'src/src/routes/import.routes.js',
            line: lineContaining(importRoutes, "router.post('/upload'"),
            contains: "router.post('/upload'"
          },
          {
            path: 'frontends/admin-dashboard/src/services/api/client.ts',
            line: lineContaining(apiClient, 'export default apiClient'),
            contains: 'export default apiClient'
          }
        ],
        expected: {
          minimum: 1,
          requiredSignals: [
            'literal-client-http-call',
            'resolved-local-http-client-facade',
            'complete-literal-express-mount-composition',
            'no-compatible-composed-server-route'
          ]
        }
      }
    ]
  };
  const manifestPath = path.join(temporaryRoot, 'manifest.json');
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return { root, revision, manifestPath, markerPath, paths: [...sources.keys()].sort() };
}

async function fileState(root: string, paths: string[]): Promise<Array<{ path: string; hash: string; mtimeMs: number }>> {
  const values = await Promise.all(paths.map(async (relativePath) => {
    const absolutePath = path.join(root, ...relativePath.split('/'));
    return {
      path: relativePath,
      hash: sha256(await readFile(absolutePath)),
      mtimeMs: (await stat(absolutePath)).mtimeMs
    };
  }));
  return values.sort((left, right) => left.path.localeCompare(right.path));
}

test('real-target tier abstains explicitly when no checkout is supplied', async () => {
  const report = await evaluateRealTargetCorpus();
  assert.equal(report.tier, 'real-target');
  assert.equal(report.status, 'not-evaluated');
  assert.equal(report.target.expectedRevision, '0123456789abcdef0123456789abcdef01234567');
  assert.equal(report.cases.length, 4);
  assert.deepEqual(report.realTargetRecall, { numerator: 0, denominator: 0 });
  assert(report.cases.every((entry) => entry.outcome === 'not-evaluated'));
  assert.deepEqual(report.diagnostics.map((entry) => entry.code), ['REAL_TARGET_ABSENT']);
});

test('real-target tier evaluates all four incident shapes without executing or changing target code', {
  skip: !hasGit,
  timeout: 120_000
}, async (context) => {
  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), 'atlas-real-target-'));
  context.after(async () => rm(temporaryRoot, { recursive: true, force: true }));
  const fixture = await createFixtureRepository(temporaryRoot);
  const before = await fileState(fixture.root, fixture.paths);

  const first = await evaluateRealTargetCorpus({ targetRoot: fixture.root, corpusPath: fixture.manifestPath });
  const second = await evaluateRealTargetCorpus({ targetRoot: fixture.root, corpusPath: fixture.manifestPath });

  assert.deepEqual(second, first, 'the real-target report must be deterministic');
  assert.equal(first.target.observedRevision, fixture.revision);
  assert.equal(first.target.verification, 'verified');
  assert.equal(first.status, 'passed');
  assert.deepEqual(first.summary, { total: 4, evaluated: 4, passed: 4, failed: 0 });
  assert.deepEqual(first.realTargetRecall, { numerator: 4, denominator: 4 });
  assert(first.cases.every((entry) => entry.outcome === 'passed'));
  assert.equal(first.cases.find((entry) => entry.id === 'fixture-a1')?.observed.matches, 1);
  assert.equal(first.cases.find((entry) => entry.id === 'fixture-a2')?.observed.matches, 1);
  assert.equal(first.cases.find((entry) => entry.id === 'fixture-a3')?.observed.matches, 1);
  assert.equal(first.cases.find((entry) => entry.id === 'fixture-a4')?.observed.matches, 1);

  const mismatchedManifest = JSON.parse(await readFile(fixture.manifestPath, 'utf8')) as {
    cases: Array<{ id: string; mapping?: { workingDirectory: string } }>;
  };
  const containerCase = mismatchedManifest.cases.find((entry) => entry.id === 'fixture-a3');
  assert(containerCase?.mapping);
  containerCase.mapping.workingDirectory = '/wrong-workdir';
  await writeFile(fixture.manifestPath, `${JSON.stringify(mismatchedManifest, null, 2)}\n`, 'utf8');
  const mismatchedMapping = await evaluateRealTargetCorpus({
    targetRoot: fixture.root,
    corpusPath: fixture.manifestPath
  });
  assert.equal(mismatchedMapping.status, 'failed');
  assert.equal(mismatchedMapping.cases.find((entry) => entry.id === 'fixture-a3')?.outcome, 'failed');

  await assert.rejects(readFile(fixture.markerPath), (error: unknown) => (error as NodeJS.ErrnoException).code === 'ENOENT');
  assert.deepEqual(await fileState(fixture.root, fixture.paths), before, 'target files must remain byte- and mtime-identical');
  assert.equal((await runGit(fixture.root, ['status', '--porcelain=v1'])).trim(), '');
  assert.equal((await runGit(fixture.root, ['rev-parse', 'HEAD'])).trim(), fixture.revision);
});

test('real-target tier refuses revision mismatch, attached HEAD, and a dirty worktree', {
  skip: !hasGit,
  timeout: 120_000
}, async (context) => {
  const mismatchRoot = await mkdtemp(path.join(os.tmpdir(), 'atlas-real-target-mismatch-'));
  const attachedRoot = await mkdtemp(path.join(os.tmpdir(), 'atlas-real-target-attached-'));
  const dirtyRoot = await mkdtemp(path.join(os.tmpdir(), 'atlas-real-target-dirty-'));
  context.after(async () => Promise.all([
    rm(mismatchRoot, { recursive: true, force: true }),
    rm(attachedRoot, { recursive: true, force: true }),
    rm(dirtyRoot, { recursive: true, force: true })
  ]));

  const mismatch = await createFixtureRepository(mismatchRoot);
  const mismatchManifest = JSON.parse(await readFile(mismatch.manifestPath, 'utf8')) as Record<string, unknown>;
  (mismatchManifest.target as Record<string, unknown>).revision = '0000000000000000000000000000000000000000';
  await writeFile(mismatch.manifestPath, `${JSON.stringify(mismatchManifest, null, 2)}\n`, 'utf8');
  const mismatchReport = await evaluateRealTargetCorpus({ targetRoot: mismatch.root, corpusPath: mismatch.manifestPath });
  assert.equal(mismatchReport.status, 'not-evaluated');
  assert(mismatchReport.diagnostics.some((entry) => entry.code === 'REAL_TARGET_REVISION_MISMATCH'));

  const attached = await createFixtureRepository(attachedRoot, false);
  const attachedReport = await evaluateRealTargetCorpus({ targetRoot: attached.root, corpusPath: attached.manifestPath });
  assert.equal(attachedReport.status, 'not-evaluated');
  assert(attachedReport.diagnostics.some((entry) => entry.code === 'REAL_TARGET_NOT_DETACHED'));

  const dirty = await createFixtureRepository(dirtyRoot);
  await writeFile(path.join(dirty.root, 'untracked.txt'), 'dirty\n', 'utf8');
  const dirtyReport = await evaluateRealTargetCorpus({ targetRoot: dirty.root, corpusPath: dirty.manifestPath });
  assert.equal(dirtyReport.status, 'not-evaluated');
  assert(dirtyReport.diagnostics.some((entry) => entry.code === 'REAL_TARGET_NOT_CLEAN'));
  assert(dirtyReport.cases.every((entry) => entry.outcome === 'not-evaluated'));
});
