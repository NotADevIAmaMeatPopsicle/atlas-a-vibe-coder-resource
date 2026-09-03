import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeJavaScriptTypeScript,
  MAX_WORKSPACE_PATTERN_EVALUATIONS
} from '../src/adapters/js-ts.js';
import { assertSchema } from '../src/schema-validator.js';
import type { AnalysisFile, FileKind, ResolvedProfile } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { canonicalJson, sha256 } from '../src/util/canonical.js';

const PROFILE: ResolvedProfile = {
  schemaVersion: SCHEMA_VERSION,
  id: 'js-ts-adapter-test',
  includeRoots: ['.'],
  exclude: [],
  entrypoints: [],
  aliases: {},
  envExampleFiles: [],
  platformRoots: [],
  deadCodeExemptions: [],
  lifecycleRules: [],
  maxFileBytes: 1_000_000
};

function language(filePath: string): string {
  if (filePath.endsWith('.tsx')) return 'typescript-tsx';
  if (/\.(?:ts|mts|cts)$/u.test(filePath)) return 'typescript';
  if (filePath.endsWith('.jsx')) return 'javascript-jsx';
  if (/\.(?:js|mjs|cjs)$/u.test(filePath)) return 'javascript';
  return 'json';
}

function kind(filePath: string): FileKind {
  return language(filePath) === 'json' ? 'configuration' : 'source';
}

function analysisFile(filePath: string, source: string): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  return {
    content,
    record: {
      schemaVersion: SCHEMA_VERSION,
      id: `file_sha256_${sha256(canonicalJson({ filePath }))}`,
      path: filePath,
      sha256: sha256(content),
      bytes: content.length,
      kind: kind(filePath),
      language: language(filePath),
      symbols: [],
      environmentVariables: [],
      lifecycle: {
        state: 'unspecified',
        basis: 'no-profile-match',
        uncertainty: 'not-runtime-validated',
        limitation: 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.'
      },
      evidence: {
        level: 0,
        producer: 'atlas/test-fixture',
        producerVersion: '1',
        basis: 'fixture-source',
        path: filePath
      }
    }
  };
}

test('adapter emits declaration and import-type semantics without changing the relationship shape for older records', async () => {
  const files = [
    analysisFile('src/types.ts', 'export interface Shape { value: string }\n'),
    analysisFile('src/value.ts', 'export const value = 1;\n'),
    analysisFile('src/consumer.ts', [
      "import type { Shape } from './types.js';",
      "import { type Shape as OtherShape } from './types.js';",
      "import { type Shape as MixedShape, value } from './value.js';",
      "export type { Shape as PublicShape } from './types.js';",
      "type LoadedShape = import('./types.js').Shape;",
      "void import('./value.js');",
      "require('./value.js');",
      'void import.meta.env.VITE_PUBLIC_API;',
      "void import.meta.env['VITE_OTHER'];",
      'void (value as unknown as Shape as OtherShape as MixedShape as LoadedShape);',
      ''
    ].join('\n'))
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  const consumer = result.relationships.filter((entry) => entry.fromPath === 'src/consumer.ts');
  assert.deepEqual(consumer.map((entry) => entry.typeOnly).sort(), [false, false, false, true, true, true, true]);
  assert.equal(consumer.find((entry) => entry.location.line === 1)?.typeOnly, true);
  assert.equal(consumer.find((entry) => entry.location.line === 2)?.typeOnly, true);
  assert.equal(consumer.find((entry) => entry.location.line === 3)?.typeOnly, false);
  assert.equal(consumer.find((entry) => entry.location.line === 4)?.typeOnly, true);
  assert.equal(consumer.find((entry) => entry.location.line === 5)?.typeOnly, true);
  assert.equal(consumer.find((entry) => entry.location.line === 6)?.typeOnly, false);
  assert.equal(consumer.find((entry) => entry.location.line === 7)?.typeOnly, false);
  const first = consumer.find((entry) => entry.location.line === 1)!;
  assert.equal(
    first.id,
    `relationship:${sha256(canonicalJson({
      from: first.fromPath,
      location: first.location,
      specifier: first.specifier,
      type: first.type
    })).slice(0, 24)}`
  );
  for (const relationship of consumer) await assertSchema('relationship', relationship, 'Adapter relationship');
  assert.deepEqual(files.find((entry) => entry.record.path === 'src/consumer.ts')?.record.environmentVariables, [
    'VITE_OTHER',
    'VITE_PUBLIC_API'
  ]);
});

test('JSDoc import types are parser-backed type-only relationships while prose and strings stay ignored', () => {
  const files = [
    analysisFile('src/types.js', 'export class Widget {}\n'),
    analysisFile('src/client.js', 'export class Client {}\n'),
    analysisFile('src/consumer.js', [
      "/** @type {import('./types').Widget} */",
      'const widget = null;',
      "/** @param {import('./client').Client} client */",
      'function use(client) { return client; }',
      "/** @returns {Promise<import('./types').Widget>} */",
      'function load() { return Promise.resolve(widget); }',
      "/** @type {import('sequelize-cli').Migration} */",
      'const migration = {};',
      "/** Example prose mentioning import('./ignored') is not a type tag. */",
      "const example = \"import('./string-only')\";",
      "// Removed: const old = require('./comment-only');",
      'void use; void load; void migration; void example;',
      ''
    ].join('\n'))
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  const consumer = result.relationships.filter((entry) => entry.fromPath === 'src/consumer.js');
  assert.deepEqual(consumer.map((entry) => entry.specifier).sort(), [
    './client',
    './types',
    './types',
    'sequelize-cli'
  ]);
  assert(consumer.every((entry) => entry.type === 'static-import' && entry.typeOnly));
  assert.equal(consumer.find((entry) => entry.location.line === 1)?.toPath, 'src/types.js');
  assert.equal(consumer.find((entry) => entry.location.line === 3)?.toPath, 'src/client.js');
  assert.equal(consumer.find((entry) => entry.location.line === 5)?.toPath, 'src/types.js');
  assert.equal(consumer.find((entry) => entry.specifier === 'sequelize-cli')?.resolution, 'external-package');
  assert(!consumer.some((entry) => entry.specifier.includes('ignored') || entry.specifier.includes('string-only') || entry.specifier.includes('comment-only')));
  assert.deepEqual(result.diagnostics, []);
});

test('runtime imports resolve implementation twins while type-only imports resolve declarations', () => {
  const files = [
    analysisFile('src/staging-users.js', 'export const stagingUsers = [];\n'),
    analysisFile('src/staging-users.d.ts', 'export interface StagingUser { id: string }\nexport const stagingUsers: StagingUser[];\n'),
    analysisFile('src/consumer.ts', [
      "import type { StagingUser } from './staging-users';",
      "import { stagingUsers } from './staging-users';",
      "const requiredUsers = require('./staging-users');",
      "void import('./staging-users');",
      'void (stagingUsers as StagingUser[]); void requiredUsers;',
      ''
    ].join('\n'))
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  const consumer = result.relationships.filter((entry) => entry.fromPath === 'src/consumer.ts');
  assert.equal(consumer.find((entry) => entry.location.line === 1)?.typeOnly, true);
  assert.equal(consumer.find((entry) => entry.location.line === 1)?.toPath, 'src/staging-users.d.ts');
  for (const line of [2, 3, 4]) {
    assert.equal(consumer.find((entry) => entry.location.line === line)?.typeOnly, false);
    assert.equal(consumer.find((entry) => entry.location.line === line)?.toPath, 'src/staging-users.js');
  }
  assert.deepEqual(result.diagnostics, []);
});

test('nearest package resolver config scopes identical aliases to each importer', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"workspaces":["apps/*"]}\n'),
    analysisFile('tsconfig.json', '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["root/*"]}}}\n'),
    analysisFile('root/thing.ts', 'export const root = true;\n'),
    analysisFile('apps/alpha/package.json', '{"name":"alpha","private":true}\n'),
    analysisFile('apps/alpha/tsconfig.json', '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}\n'),
    analysisFile('apps/alpha/src/thing.ts', 'export const thing = "alpha";\n'),
    analysisFile('apps/alpha/src/use.ts', 'import { thing } from "@/thing"; void thing;\n'),
    analysisFile('apps/beta/package.json', '{"name":"beta","private":true}\n'),
    analysisFile('apps/beta/jsconfig.json', '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["lib/*"]}}}\n'),
    analysisFile('apps/beta/lib/thing.js', 'export const thing = "beta";\n'),
    analysisFile('apps/beta/src/use.js', 'import { thing } from "@/thing"; void thing;\n')
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  assert.equal(
    result.relationships.find((entry) => entry.fromPath === 'apps/alpha/src/use.ts')?.toPath,
    'apps/alpha/src/thing.ts'
  );
  assert.equal(
    result.relationships.find((entry) => entry.fromPath === 'apps/beta/src/use.js')?.toPath,
    'apps/beta/lib/thing.js'
  );
  assert(!result.relationships.some((entry) => entry.toPath === 'root/thing.ts'));
  assert.deepEqual(result.diagnostics, []);
});

test('extensionless imports with domain suffixes and exact asset extensions both resolve', () => {
  const files = [
    analysisFile('src/user.service.ts', 'export const user = true;\n'),
    analysisFile('src/styles.css', '.root {}\n'),
    analysisFile('src/use.ts', [
      'import { user } from "./user.service";',
      'import "./styles.css";',
      'void user;',
      ''
    ].join('\n'))
  ];
  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  assert.equal(result.relationships.find((entry) => entry.specifier === './user.service')?.toPath, 'src/user.service.ts');
  assert.equal(result.relationships.find((entry) => entry.specifier === './styles.css')?.toPath, 'src/styles.css');
  assert.deepEqual(result.diagnostics, []);
});

test('workspace package exports resolve only within a declared workspace and ambiguous exports stay unsupported', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"workspaces":["apps/*","packages/*"]}\n'),
    analysisFile('apps/web/package.json', '{"name":"web","private":true}\n'),
    analysisFile('apps/web/src/use.ts', [
      'import type { PublicType } from "@scope/shared";',
      'import { feature } from "@scope/shared/feature";',
      'import { escaped } from "unsafe-local";',
      'import { external } from "not-in-workspace";',
      'void feature; void escaped; void external;',
      ''
    ].join('\n')),
    analysisFile('packages/shared/package.json', JSON.stringify({
      name: '@scope/shared',
      exports: {
        '.': './src/index.ts',
        './feature': './src/feature.ts'
      }
    })),
    analysisFile('packages/shared/src/index.ts', 'export interface PublicType { ok: true }\n'),
    analysisFile('packages/shared/src/feature.ts', 'export const feature = true;\n'),
    analysisFile('packages/unsafe/package.json', '{"name":"unsafe-local","exports":"./../escaped.ts"}\n'),
    analysisFile('packages/escaped.ts', 'export const escaped = true;\n')
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  const rootImport = result.relationships.find((entry) => entry.specifier === '@scope/shared');
  assert.equal(rootImport?.toPath, 'packages/shared/src/index.ts');
  assert.equal(rootImport?.typeOnly, true);
  assert.equal(result.relationships.find((entry) => entry.specifier === '@scope/shared/feature')?.toPath, 'packages/shared/src/feature.ts');
  assert.equal(result.relationships.find((entry) => entry.specifier === 'unsafe-local')?.resolution, 'unresolved-internal');
  assert.equal(result.relationships.find((entry) => entry.specifier === 'not-in-workspace')?.resolution, 'external-package');

  const conditionalFiles = [
    analysisFile('package.json', '{"private":true,"workspaces":["apps/*","packages/*"]}\n'),
    analysisFile('apps/web/package.json', '{"name":"web","private":true}\n'),
    analysisFile('apps/web/src/use.ts', 'import { shared } from "shared"; void shared;\n'),
    analysisFile('packages/shared/package.json', JSON.stringify({
      name: 'shared',
      exports: { '.': { import: './src/runtime.ts', types: './src/types.ts' } }
    })),
    analysisFile('packages/shared/src/runtime.ts', 'export const shared = true;\n'),
    analysisFile('packages/shared/src/types.ts', 'export interface shared { ok: true }\n')
  ];
  const conditional = analyzeJavaScriptTypeScript(conditionalFiles, PROFILE);
  assert.equal(conditional.relationships[0]?.resolution, 'unsupported');
  assert(conditional.diagnostics.some((entry) => entry.code === 'AMBIGUOUS_WORKSPACE_PACKAGE_EXPORT'));
});

test('duplicate workspace package names are preclassified once for repeated imports', () => {
  const duplicateCount = 128;
  const importCount = 256;
  const files = [
    analysisFile('package.json', '{"private":true,"workspaces":["apps/*","packages/*"]}\n'),
    analysisFile('apps/web/package.json', '{"name":"web","private":true}\n'),
    analysisFile(
      'apps/web/src/use.ts',
      `${Array.from({ length: importCount }, () => 'import "duplicate";').join('\n')}\n`
    ),
    ...Array.from({ length: duplicateCount }, (_, index) =>
      analysisFile(
        `packages/duplicate-${String(index).padStart(3, '0')}/package.json`,
        '{"name":"duplicate","main":"index.js"}\n'
      )
    )
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  const duplicateImports = result.relationships.filter((entry) => entry.specifier === 'duplicate');
  assert.equal(duplicateImports.length, importCount);
  assert(duplicateImports.every((entry) => entry.resolution === 'unsupported'));
  assert.equal(
    result.diagnostics.filter((entry) => entry.code === 'AMBIGUOUS_WORKSPACE_PACKAGE_IMPORT').length,
    importCount
  );
});

test('source and resolver parser errors remain explicit and do not enable a parent-package alias guess', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"workspaces":["apps/*"]}\n'),
    analysisFile('tsconfig.json', '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["root/*"]}}}\n'),
    analysisFile('root/thing.ts', 'export const thing = true;\n'),
    analysisFile('apps/broken/package.json', '{"name":"broken","private":true}\n'),
    analysisFile('apps/broken/tsconfig.json', '{"compilerOptions":{"baseUrl":".","paths": {'),
    analysisFile('apps/broken/src/broken.ts', 'export const value = ;\nimport "@/thing";\n')
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  assert(result.diagnostics.some((entry) => entry.code === 'RESOLVER_CONFIG_PARSE_ERROR'));
  assert(result.diagnostics.some((entry) => entry.code === 'PARSE_ERROR' && entry.path === 'apps/broken/src/broken.ts'));
  const relationship = result.relationships.find((entry) => entry.fromPath === 'apps/broken/src/broken.ts');
  assert.equal(relationship?.resolution, 'external-package');
  assert.equal(relationship?.toPath, undefined);
});

test('pathological AST depth is rejected without partial output and safe siblings remain analyzable', () => {
  const deepSource = `import './early.js';\nconst value = root${'.child'.repeat(2_000)};\n`;
  const files = [
    analysisFile('src/deep.ts', deepSource),
    analysisFile('src/safe.ts', "import './dependency.js';\nexport const safe = process.env.SAFE_VALUE;\n"),
    analysisFile('src/dependency.ts', 'export const dependency = true;\n')
  ];

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  assert(!result.relationships.some((entry) => entry.fromPath === 'src/deep.ts'));
  assert.equal(result.relationships.find((entry) => entry.fromPath === 'src/safe.ts')?.toPath, 'src/dependency.ts');
  assert.deepEqual(files.find((entry) => entry.record.path === 'src/deep.ts')?.record.symbols, []);
  assert.deepEqual(files.find((entry) => entry.record.path === 'src/deep.ts')?.record.environmentVariables, []);
  assert.deepEqual(files.find((entry) => entry.record.path === 'src/safe.ts')?.record.environmentVariables, ['SAFE_VALUE']);
  const diagnostic = result.diagnostics.find((entry) => entry.path === 'src/deep.ts');
  assert.equal(diagnostic?.code, 'TYPESCRIPT_AST_RESOURCE_LIMIT');
  assert.match(diagnostic?.message ?? '', /supported depth/u);
});

test('TypeScript parser stack failures become deterministic per-file diagnostics', () => {
  const nested = `${'('.repeat(10_000)}0${')'.repeat(10_000)};\n`;
  const first = analyzeJavaScriptTypeScript([
    analysisFile('src/deep.ts', nested),
    analysisFile('src/safe.ts', 'export const safe = true;\n')
  ], PROFILE);
  const second = analyzeJavaScriptTypeScript([
    analysisFile('src/safe.ts', 'export const safe = true;\n'),
    analysisFile('src/deep.ts', nested)
  ], PROFILE);

  assert.deepEqual(second, first);
  assert.deepEqual(first.relationships, []);
  assert.deepEqual(first.diagnostics.map((entry) => ({ code: entry.code, path: entry.path })), [
    { code: 'TYPESCRIPT_AST_RESOURCE_LIMIT', path: 'src/deep.ts' }
  ]);
  assert.match(first.diagnostics[0]?.message ?? '', /process stack limit/u);
  assert.deepEqual(first.diagnostics[0]?.location, undefined);
  assert.deepEqual(first.diagnostics[0]?.evidence.path, 'src/deep.ts');
});

test('resolver configuration inheritance has a deterministic depth limit', () => {
  const configCount = 160;
  const files: AnalysisFile[] = [];
  for (let index = 0; index < configCount; index += 1) {
    const directory = `configs/c${String(index).padStart(3, '0')}`;
    const next = index + 1 < configCount
      ? `../c${String(index + 1).padStart(3, '0')}/tsconfig.json`
      : undefined;
    files.push(analysisFile(
      `${directory}/tsconfig.json`,
      `${JSON.stringify({
        ...(next ? { extends: next } : {}),
        compilerOptions: { baseUrl: '.', paths: { '@/*': ['src/*'] } }
      })}\n`
    ));
  }
  files.push(analysisFile('configs/c000/src/value.ts', 'export const value = true;\n'));
  files.push(analysisFile('configs/c000/src/use.ts', 'import { value } from "@/value"; void value;\n'));

  const result = analyzeJavaScriptTypeScript(files, PROFILE);
  assert(result.diagnostics.some((entry) => entry.code === 'RESOLVER_CONFIG_EXTENDS_DEPTH_LIMIT'));
  assert.equal(
    result.relationships.find((entry) => entry.fromPath === 'configs/c000/src/use.ts')?.toPath,
    'configs/c000/src/value.ts'
  );
});

test('adapter relationship and diagnostic output is deterministic under file-order reversal', () => {
  const makeFiles = () => [
    analysisFile('package.json', '{"private":true,"workspaces":["packages/*"]}\n'),
    analysisFile('packages/a/package.json', '{"name":"a","main":"index.js"}\n'),
    analysisFile('packages/a/index.ts', 'export const a = true;\n'),
    analysisFile('src/index.ts', 'import { a } from "a"; import type { A } from "./types.js"; void a;\n'),
    analysisFile('src/types.ts', 'export interface A { ok: true }\n')
  ];
  const first = analyzeJavaScriptTypeScript(makeFiles(), PROFILE);
  const reversed = analyzeJavaScriptTypeScript(makeFiles().reverse(), PROFILE);
  assert.deepEqual(reversed, first);
});

test('workspace matching has a deterministic aggregate budget and never publishes partial memberships', () => {
  const patterns = [
    'packages/*',
    ...Array.from({ length: 999 }, (_, index) => `unused-${index}/*`)
  ];
  const exactPackageCount = Math.floor(MAX_WORKSPACE_PATTERN_EVALUATIONS / patterns.length);
  const makeFiles = (packageCount: number): AnalysisFile[] => [
    analysisFile('package.json', `${JSON.stringify({ private: true, workspaces: patterns })}\n`),
    ...Array.from({ length: packageCount }, (_, index) => analysisFile(
      `packages/p${String(index).padStart(3, '0')}/package.json`,
      `${JSON.stringify({ name: `pkg-${String(index).padStart(3, '0')}`, main: 'index.js' })}\n`
    )),
    analysisFile('packages/p000/index.ts', 'import { value } from "pkg-001"; void value;\n'),
    analysisFile('packages/p001/index.ts', 'export const value = true;\n')
  ];

  const exact = analyzeJavaScriptTypeScript(makeFiles(exactPackageCount), PROFILE);
  assert.equal(exact.diagnostics.some((entry) => entry.code === 'PACKAGE_WORKSPACE_RESOURCE_LIMIT'), false);
  assert.equal(exact.relationships.find((entry) => entry.fromPath === 'packages/p000/index.ts')?.resolution, 'resolved');

  const result = analyzeJavaScriptTypeScript(makeFiles(exactPackageCount + 1), PROFILE);
  assert.equal(result.diagnostics.filter((entry) => entry.code === 'PACKAGE_WORKSPACE_RESOURCE_LIMIT').length, 1);
  assert.equal(
    result.relationships.find((entry) => entry.fromPath === 'packages/p000/index.ts')?.resolution,
    'unsupported'
  );
});
