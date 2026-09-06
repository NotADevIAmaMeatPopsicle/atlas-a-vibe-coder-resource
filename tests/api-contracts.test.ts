import assert from 'node:assert/strict';
import test from 'node:test';
import {
  detectApiContractMismatches,
  MAX_API_CONTRACT_COMPARISON_STATES
} from '../src/analysis/api-contracts.js';
import type { AnalysisFile, EvidenceReference, FileRecord, RelationshipRecord } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { canonicalJson, sha256 } from '../src/util/canonical.js';

function analysisFile(filePath: string, source: string): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  const evidence: EvidenceReference = {
    level: 0,
    producer: 'atlas/test-fixture',
    producerVersion: '1',
    basis: 'fixture-source',
    path: filePath
  };
  const record: FileRecord = {
    schemaVersion: SCHEMA_VERSION,
    id: `file:${sha256(filePath).slice(0, 24)}`,
    path: filePath,
    sha256: sha256(content),
    bytes: content.length,
    kind: 'source',
    language: filePath.endsWith('.js') ? 'javascript' : 'typescript',
    symbols: [],
    environmentVariables: [],
    lifecycle: {
      state: 'unspecified',
      basis: 'no-profile-match',
      uncertainty: 'not-runtime-validated',
      limitation: 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.'
    },
    evidence
  };
  return { record, content };
}

function relationship(
  from: AnalysisFile,
  to: AnalysisFile,
  specifier: string,
  type: RelationshipRecord['type'] = 'static-import'
): RelationshipRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `relationship:${sha256(`${from.record.path}:${specifier}:${to.record.path}`).slice(0, 24)}`,
    from: from.record.id,
    fromPath: from.record.path,
    to: to.record.id,
    toPath: to.record.path,
    type,
    specifier,
    typeOnly: false,
    resolution: 'resolved',
    location: { line: 1, column: 1, endLine: 1, endColumn: 20 },
    evidence: {
      level: 1,
      producer: 'atlas/test-fixture',
      producerVersion: '1',
      basis: 'fixture-relationship',
      path: from.record.path,
      line: 1,
      column: 1
    }
  };
}

test('literal Express routes match fetch and axios calls across parameters, queries, route chains, and axios bases', () => {
  const files = [
    analysisFile('src/server.ts', [
      "import express, { Router } from 'express';",
      'const app = express();',
      'const router = Router();',
      "app.get('/', handler);",
      "app.get('/api/users/:id', handler);",
      'app.use(router);',
      "router.route('/api/users').post(handler);",
      ''
    ].join('\n')),
    analysisFile('src/client.ts', [
      "import axios from 'axios';",
      "const api = axios.create({ baseURL: '/api' });",
      "fetch('/?health=ready');",
      "fetch('/api/users/42?view=compact');",
      "api.post('/users');",
      "axios({ url: '/api/users', method: 'POST' });",
      ''
    ].join('\n'))
  ];

  const result = detectApiContractMismatches(files);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.diagnostics, []);
});

test('literal method and missing-route candidates are deterministic and do not retain query values', () => {
  const server = analysisFile('src/server.ts', [
    "const app = express();",
    "app.post('/api/items/:itemId', handler);",
    ''
  ].join('\n'));
  const client = analysisFile('src/client.ts', [
    "fetch('/api/items/123?secret=do-not-retain', { method: 'GET' });",
    "axios.delete('/api/missing?token=do-not-retain');",
    ''
  ].join('\n'));

  const first = detectApiContractMismatches([server, client]);
  const reversed = detectApiContractMismatches([client, server]);
  assert.deepEqual(reversed, first);
  assert.equal(first.findings.length, 2);
  assert(first.findings.some((finding) => finding.ruleId === 'contract/api-client-method-mismatch-v1'));
  assert(first.findings.some((finding) => finding.ruleId === 'contract/api-client-route-missing-v1'));
  assert(!canonicalJson(first).includes('do-not-retain'));
  for (const finding of first.findings) {
    assert.equal(finding.category, 'contract-mismatch');
    assert.equal(finding.status, 'candidate');
    assert(finding.evidence.every((entry) => entry.path && entry.line && entry.column));
  }
});

test('dynamic server and client constructs produce uncertainty diagnostics instead of mismatch claims', () => {
  const files = [analysisFile('src/routes.ts', [
    "const app = express();",
    "const route = '/api/maybe';",
    'app.get(route, handler);',
    "fetch('/api/maybe');",
    'fetch(`/api/users/${userId}`);',
    "const verb = 'post';",
    "app[verb]('/api/computed', handler);",
    "fetch('/api/computed', { method: 'POST' });",
    ''
  ].join('\n'))];

  const result = detectApiContractMismatches(files);
  assert.deepEqual(result.findings, []);
  assert(result.diagnostics.some((entry) => entry.code === 'API_CONTRACT_DYNAMIC_SERVER_ROUTE'));
  assert(result.diagnostics.some((entry) => entry.code === 'API_CONTRACT_DYNAMIC_CLIENT_ROUTE'));
  assert(result.diagnostics.some((entry) => entry.code === 'API_CONTRACT_COMPARISON_UNCERTAIN'));
});

function mountedRouterFixture(mountImportRoutes: boolean): {
  files: AnalysisFile[];
  relationships: RelationshipRecord[];
} {
  const app = analysisFile('src/app.js', [
    "const express = require('express');",
    "const routes = require('./routes');",
    'const app = express();',
    "app.use('/api', routes);",
    ''
  ].join('\n'));
  const routes = analysisFile('src/routes.js', [
    "const express = require('express');",
    "const usersRoutes = require('./users.routes');",
    "const importRoutes = require('./import.routes');",
    'const router = express.Router();',
    "router.use('/users', usersRoutes);",
    ...(mountImportRoutes ? ["router.use('/import', importRoutes);"] : []),
    'module.exports = router;',
    ''
  ].join('\n'));
  const users = analysisFile('src/users.routes.js', [
    "const express = require('express');",
    'const router = express.Router();',
    "router.get('/:id', handler);",
    'module.exports = router;',
    ''
  ].join('\n'));
  const imports = analysisFile('src/import.routes.js', [
    "const express = require('express');",
    'const router = express.Router();',
    "router.post('/upload', handler);",
    'module.exports = router;',
    ''
  ].join('\n'));
  const client = analysisFile('src/api-client.ts', [
    "import axios from 'axios';",
    'class ApiClient {',
    '  private instance;',
    "  constructor() { this.instance = axios.create({ baseURL: '/api' }); }",
    '  get(url: string) { return this.instance.get(url); }',
    '  post(url: string, data?: unknown) { return this.instance.post(url, data); }',
    '}',
    'export const apiClient = new ApiClient();',
    'export default apiClient;',
    ''
  ].join('\n'));
  const service = analysisFile('src/import.service.ts', [
    "import apiClient from './api-client';",
    'export function loadUser(id: string) {',
    '  return apiClient.get(`/users/${id}`);',
    '}',
    'export function upload(data: unknown) {',
    "  return apiClient.post('/import/upload', data);",
    '}',
    ''
  ].join('\n'));
  const files = [app, routes, users, imports, client, service];
  return {
    files,
    relationships: [
      relationship(app, routes, './routes', 'require'),
      relationship(routes, users, './users.routes', 'require'),
      relationship(routes, imports, './import.routes', 'require'),
      relationship(service, client, './api-client')
    ]
  };
}

test('resolved CommonJS mount tables compose reachable routes and exclude an imported but unmounted router', () => {
  const broken = mountedRouterFixture(false);
  const first = detectApiContractMismatches(broken.files, broken.relationships);
  const reversed = detectApiContractMismatches([...broken.files].reverse(), [...broken.relationships].reverse());

  assert.deepEqual(reversed, first);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0]?.ruleId, 'contract/api-client-route-missing-v1');
  assert.equal(first.findings[0]?.path, 'src/import.service.ts');
  assert(first.findings[0]?.title.includes('POST /api/import/upload'));
  assert(first.findings[0]?.signals.includes('resolved-local-http-client-facade'));
  assert(first.findings[0]?.signals.includes('complete-literal-express-mount-composition'));
  assert(!first.findings.some((finding) => finding.title.includes('/users/')));
  assert.deepEqual(first.diagnostics, []);

  const fixed = mountedRouterFixture(true);
  assert.deepEqual(detectApiContractMismatches(fixed.files, fixed.relationships), { findings: [], diagnostics: [] });
});

test('resolved ESM default and named router exports compose from an Express application root', () => {
  const app = analysisFile('src/app.ts', [
    "import express from 'express';",
    "import routes from './routes';",
    'const app = express();',
    "app.use('/api', routes);",
    ''
  ].join('\n'));
  const routes = analysisFile('src/routes.ts', [
    "import { Router } from 'express';",
    "import { usersRouter } from './users';",
    'const router = Router();',
    "router.use('/users', usersRouter);",
    'export default router;',
    ''
  ].join('\n'));
  const users = analysisFile('src/users.ts', [
    "import { Router } from 'express';",
    'export const usersRouter = Router();',
    "usersRouter.get('/:id', handler);",
    ''
  ].join('\n'));
  const client = analysisFile('src/client.ts', "fetch('/api/users/42');\n");
  const files = [app, routes, users, client];
  const relationships = [
    relationship(app, routes, './routes'),
    relationship(routes, users, './users')
  ];

  assert.deepEqual(detectApiContractMismatches(files, relationships), { findings: [], diagnostics: [] });
});

test('dynamic and unsupported mounts abstain only for client routes within their reachable scope', () => {
  const files = [analysisFile('src/app.ts', [
    'const app = express();',
    "app.use('/api/private', buildRouter());",
    "fetch('/api/private/unknown');",
    "fetch('/public/missing');",
    ''
  ].join('\n'))];

  const result = detectApiContractMismatches(files);
  assert.equal(result.findings.length, 1);
  assert(result.findings[0]?.title.includes('GET /public/missing'));
  assert(result.diagnostics.some((entry) => entry.code === 'API_CONTRACT_DYNAMIC_SERVER_ROUTE'));
  assert(result.diagnostics.some((entry) => entry.code === 'API_CONTRACT_COMPARISON_UNCERTAIN'));
});

test('an imported client wrapper is ignored unless its same-method URL delegation is structurally certified', () => {
  const facade = analysisFile('src/unsafe-client.ts', [
    "import axios from 'axios';",
    'class UnsafeClient {',
    '  private instance;',
    '  constructor() { this.instance = axios.create(); }',
    '  get(url: string) { return this.instance.post(url); }',
    '}',
    'const unsafeClient = new UnsafeClient();',
    'export default unsafeClient;',
    ''
  ].join('\n'));
  const consumer = analysisFile('src/consumer.ts', [
    "import unsafeClient from './unsafe-client';",
    "unsafeClient.get('/not-a-certified-call');",
    ''
  ].join('\n'));

  assert.deepEqual(
    detectApiContractMismatches([facade, consumer], [relationship(consumer, facade, './unsafe-client')]),
    { findings: [], diagnostics: [] }
  );
});

test('resolved imported response middleware and router barrels preserve scoped uncertainty', () => {
  const app = analysisFile('src/app.ts', [
    "import express from 'express';",
    "import handler from './handler';",
    "import routes from './routes';",
    'const app = express();',
    "app.use('/api/middleware', handler);",
    "app.use('/api/barrel', routes);",
    ''
  ].join('\n'));
  const handler = analysisFile('src/handler.ts', 'export default (_request, response) => response.json({ ok: true });\n');
  const barrel = analysisFile('src/routes.ts', "export { default } from './nested-router';\n");
  const nestedRouter = analysisFile('src/nested-router.ts', [
    "import { Router } from 'express';",
    'const router = Router();',
    "router.get('/reachable', handler);",
    'export default router;',
    ''
  ].join('\n'));
  const client = analysisFile('src/client.ts', [
    "fetch('/api/middleware');",
    "fetch('/api/barrel/reachable');",
    "fetch('/public/missing');",
    ''
  ].join('\n'));
  const relationships = [
    relationship(app, handler, './handler'),
    relationship(app, barrel, './routes'),
    relationship(barrel, nestedRouter, './nested-router')
  ];

  const result = detectApiContractMismatches([app, handler, barrel, nestedRouter, client], relationships);
  assert.equal(result.findings.length, 1);
  assert(result.findings[0]?.title.includes('GET /public/missing'));
  assert.equal(result.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_DYNAMIC_SERVER_ROUTE').length, 2);
  assert.equal(result.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_COMPARISON_UNCERTAIN').length, 2);
});

test('a definitely pass-through imported middleware does not hide mounted router findings', () => {
  const app = analysisFile('src/app.js', [
    "const express = require('express');",
    "const { apiHeaders } = require('./headers');",
    "const routes = require('./routes');",
    'const app = express();',
    "app.use('/api', apiHeaders);",
    "app.use('/api', routes);",
    ''
  ].join('\n'));
  const headers = analysisFile('src/headers.js', [
    'const apiHeaders = (_request, response, next) => {',
    "  response.set('Cache-Control', 'no-store');",
    '  next();',
    '};',
    'module.exports = { apiHeaders };',
    ''
  ].join('\n'));
  const routes = analysisFile('src/routes.js', [
    "const express = require('express');",
    'const router = express.Router();',
    "router.get('/present', handler);",
    'module.exports = router;',
    ''
  ].join('\n'));
  const client = analysisFile('src/client.ts', "fetch('/api/missing');\n");
  const relationships = [
    relationship(app, headers, './headers', 'require'),
    relationship(app, routes, './routes', 'require')
  ];

  const result = detectApiContractMismatches([app, headers, routes, client], relationships);
  assert.equal(result.findings.length, 1);
  assert(result.findings[0]?.title.includes('GET /api/missing'));
  assert.deepEqual(result.diagnostics, []);
});

test('imported axios facades propagate literal bases and abstain for literal external bases', () => {
  const localFacade = analysisFile('src/local-client.ts', [
    "import axios from 'axios';",
    'class Client {',
    "  constructor() { this.instance = axios.create({ baseURL: '/v2' }); }",
    '  get(url: string) { return this.instance.get(url); }',
    '}',
    'const client = new Client();',
    'export default client;',
    ''
  ].join('\n'));
  const externalFacade = analysisFile('src/external-client.ts', [
    "import axios from 'axios';",
    'class Client {',
    "  constructor() { this.instance = axios.create({ baseURL: 'https://external.example' }); }",
    '  get(url: string) { return this.instance.get(url); }',
    '}',
    'const client = new Client();',
    'export default client;',
    ''
  ].join('\n'));
  const consumer = analysisFile('src/consumer.ts', [
    "import localClient from './local-client';",
    "import externalClient from './external-client';",
    "localClient.get('/missing');",
    "externalClient.get('/remote-only');",
    ''
  ].join('\n'));
  const result = detectApiContractMismatches(
    [localFacade, externalFacade, consumer],
    [
      relationship(consumer, localFacade, './local-client'),
      relationship(consumer, externalFacade, './external-client')
    ]
  );

  assert.equal(result.findings.length, 1);
  assert(result.findings[0]?.title.includes('GET /v2/missing'));
  assert.equal(result.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_DYNAMIC_CLIENT_BASE').length, 1);
});

test('dynamic facade bases use conservative suffix matching and identify that uncertainty', () => {
  const app = analysisFile('src/app.ts', [
    "import express from 'express';",
    'const app = express();',
    "app.get('/v2/users/:id', handler);",
    ''
  ].join('\n'));
  const facade = analysisFile('src/api-client.ts', [
    "import axios from 'axios';",
    'class Client {',
    '  constructor() { this.instance = axios.create({ baseURL: API_CONFIG.BASE_URL }); }',
    '  async get(url: string) {',
    '    const response = await this.instance.get(url);',
    '    return response.data;',
    '  }',
    '}',
    'const client = new Client();',
    'export default client;',
    ''
  ].join('\n'));
  const consumer = analysisFile('src/consumer.ts', [
    "import client from './api-client';",
    'client.get(`/users/${userId}`);',
    "client.get('/import/upload');",
    ''
  ].join('\n'));
  const files = [app, facade, consumer];
  const relationships = [relationship(consumer, facade, './api-client')];

  const first = detectApiContractMismatches(files, relationships);
  const reversed = detectApiContractMismatches([...files].reverse(), [...relationships].reverse());
  assert.deepEqual(reversed, first);
  assert.equal(first.findings.length, 1);
  assert(first.findings[0]?.title.includes('GET /import/upload'));
  assert.equal(first.findings[0]?.confidence, 'low');
  assert(first.findings[0]?.signals.includes('dynamic-client-base-suffix-comparison'));
  assert(first.findings[0]?.description.includes('not a runtime reachability claim'));
  assert.equal(first.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_DYNAMIC_CLIENT_BASE').length, 2);
});

test('facade certification rejects reassigned transports and unreachable decoy delegation', () => {
  const reassigned = analysisFile('src/reassigned-client.ts', [
    "import axios from 'axios';",
    'class Client {',
    "  constructor() { this.instance = axios.create({ baseURL: '/api' }); this.instance = otherClient; }",
    '  get(url: string) { return this.instance.get(url); }',
    '}',
    'const client = new Client();',
    'export default client;',
    ''
  ].join('\n'));
  const decoy = analysisFile('src/decoy-client.ts', [
    "import axios from 'axios';",
    'class Client {',
    "  constructor() { this.instance = axios.create({ baseURL: '/api' }); }",
    '  get(url: string) {',
    '    return localCache.get(url);',
    '    this.instance.get(url);',
    '  }',
    '}',
    'const client = new Client();',
    'export default client;',
    ''
  ].join('\n'));
  const shadowed = analysisFile('src/shadowed-client.ts', [
    "import axios from 'axios';",
    'class Client {',
    "  constructor(axios: { create: Function }) { this.instance = axios.create({ baseURL: '/api' }); }",
    '  get(url: string) { return this.instance.get(url); }',
    '}',
    'const client = new Client(otherClient);',
    'export default client;',
    ''
  ].join('\n'));
  const consumer = analysisFile('src/consumer.ts', [
    "import reassigned from './reassigned-client';",
    "import decoy from './decoy-client';",
    "import shadowed from './shadowed-client';",
    "reassigned.get('/unsafe');",
    "decoy.get('/also-unsafe');",
    "shadowed.get('/shadowed');",
    ''
  ].join('\n'));

  assert.deepEqual(detectApiContractMismatches(
    [reassigned, decoy, shadowed, consumer],
    [
      relationship(consumer, reassigned, './reassigned-client'),
      relationship(consumer, decoy, './decoy-client'),
      relationship(consumer, shadowed, './shadowed-client')
    ]
  ), { findings: [], diagnostics: [] });
});

test('route composition deduplicates equivalent states and abstains deterministically at its context limit', () => {
  const app = analysisFile('src/app.ts', [
    "import express from 'express';",
    "import router from './router-0';",
    'const app = express();',
    "app.use('/root', router);",
    ''
  ].join('\n'));
  const files = [app];
  const relationships: RelationshipRecord[] = [];
  let importer = app;
  for (let index = 0; index < 13; index += 1) {
    const final = index === 12;
    const router = analysisFile(`src/router-${index}.ts`, final
      ? [
          "import { Router } from 'express';",
          'const router = Router();',
          "router.get('/present', handler);",
          'export default router;',
          ''
        ].join('\n')
      : [
          "import { Router } from 'express';",
          `import next from './router-${index + 1}';`,
          'const router = Router();',
          "router.use('/left', next);",
          "router.use('/right', next);",
          'export default router;',
          ''
        ].join('\n'));
    files.push(router);
    relationships.push(relationship(importer, router, `./router-${index}`));
    importer = router;
  }
  files.push(analysisFile('src/client.ts', "fetch('/unrelated/missing');\n"));

  const first = detectApiContractMismatches(files, relationships);
  const reversed = detectApiContractMismatches([...files].reverse(), [...relationships].reverse());
  assert.deepEqual(reversed, first);
  assert.equal(first.findings.length, 0);
  assert.equal(first.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_ROUTE_COMPOSITION_LIMIT').length, 1);
  assert.equal(first.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_COMPARISON_UNCERTAIN').length, 1);
});

test('API route correlation stops at its shared work budget and discards partial mismatch claims', () => {
  const routeCount = Math.floor(Math.sqrt(MAX_API_CONTRACT_COMPARISON_STATES));
  const server = analysisFile('src/server.ts', [
    "import express from 'express';",
    'const app = express();',
    ...Array.from({ length: routeCount }, (_, index) => `app.get('/server-${index}', handler);`),
    ''
  ].join('\n'));
  const client = (count: number) => analysisFile('src/client.ts', [
    ...Array.from({ length: count }, (_, index) => `fetch('/client-${index}');`),
    ''
  ].join('\n'));

  const exact = detectApiContractMismatches([server, client(routeCount)]);
  assert.equal(exact.diagnostics.some((entry) => entry.code === 'API_CONTRACT_COMPARISON_LIMIT'), false);
  assert.equal(exact.findings.length, routeCount);

  const over = detectApiContractMismatches([server, client(routeCount + 1)]);
  assert.equal(over.findings.length, 0);
  assert.equal(over.diagnostics.filter((entry) => entry.code === 'API_CONTRACT_COMPARISON_LIMIT').length, 1);
});
