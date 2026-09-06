import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeJavaScriptTypeScript } from '../src/adapters/js-ts.js';
import { detectDeadCodeCandidates } from '../src/analysis/dead-code.js';
import { analyzeReachability } from '../src/analysis/reachability.js';
import type {
  AnalysisFile,
  EvidenceReference,
  FileKind,
  FileRecord,
  LoaderRule,
  ResolvedProfile
} from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { sha256 } from '../src/util/canonical.js';

const PROFILE: ResolvedProfile = {
  schemaVersion: SCHEMA_VERSION,
  id: 'reachability-fixture',
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
  if (/\.tsx$/u.test(filePath)) return 'typescript-tsx';
  if (/\.(?:ts|mts|cts)$/u.test(filePath)) return 'typescript';
  if (/\.jsx$/u.test(filePath)) return 'javascript-jsx';
  if (/\.(?:js|mjs|cjs)$/u.test(filePath)) return 'javascript';
  if (filePath.endsWith('.json')) return 'json';
  if (filePath.endsWith('.html')) return 'html';
  return 'text';
}

function kind(filePath: string): FileKind {
  if (/(?:^|\/)(?:tests?|__tests__)\//u.test(filePath) || /\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(filePath)) return 'test';
  if (/\.(?:[cm]?[jt]sx?)$/u.test(filePath)) return 'source';
  return 'configuration';
}

function analysisFile(filePath: string, source: string, kindOverride?: FileKind): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  const evidence: EvidenceReference = {
    level: 0,
    producer: 'atlas/reachability-test',
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
    kind: kindOverride ?? kind(filePath),
    language: language(filePath),
    symbols: [],
    environmentVariables: [],
    evidence
  };
  return { record, content };
}

function withLifecycle(file: AnalysisFile, state: NonNullable<FileRecord['lifecycle']>['state']): AnalysisFile {
  file.record.lifecycle = {
    state,
    basis: 'profile-path-rule',
    uncertainty: 'not-runtime-validated',
    limitation: 'Fixture lifecycle declaration.'
  };
  return file;
}

function profile(overrides: Partial<ResolvedProfile> = {}): ResolvedProfile {
  return { ...PROFILE, ...overrides };
}

function withLoaderRules(rules: LoaderRule[], overrides: Partial<ResolvedProfile> = {}): ResolvedProfile {
  return profile({ ...overrides, loaderRules: rules });
}

test('configured entrypoints seed test files and traverse their runtime imports', () => {
  const files = [
    analysisFile('tests/entry.test.ts', "import { helper } from '../src/helper.js';\nvoid helper;\n"),
    analysisFile('src/helper.ts', 'export const helper = true;\n')
  ];
  const selectedProfile = profile({ entrypoints: ['tests/**/*.test.ts'] });
  const graph = analyzeJavaScriptTypeScript(files, selectedProfile);
  const result = analyzeReachability(files, graph.relationships, selectedProfile);

  assert(result.entrypoints.some((entrypoint) =>
    entrypoint.path === 'tests/entry.test.ts' && entrypoint.origin === 'profile' && entrypoint.scope === 'test'
  ));
  assert(result.reachablePaths.has('tests/entry.test.ts'));
  assert(result.reachablePaths.has('src/helper.ts'));
  assert(result.runtimeInboundPaths.has('src/helper.ts'));
  assert.deepEqual(result.pathContexts.get('src/helper.ts'), {
    entrypointPaths: ['tests/entry.test.ts'],
    scopes: ['test']
  });
  assert(!detectDeadCodeCandidates(files, graph.relationships, selectedProfile, result).findings.some(
    (finding) => finding.path === 'src/helper.ts'
  ));
});

test('test-only closure does not raise production dead-code confidence', () => {
  const files = [
    analysisFile('package.json', JSON.stringify({ scripts: { test: 'vitest' } })),
    analysisFile('tests/a.test.ts', 'export const coveredTest = true;\n'),
    analysisFile('src/server.ts', 'export const server = true;\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const reachability = analyzeReachability(files, graph.relationships, PROFILE);
  const result = detectDeadCodeCandidates(files, graph.relationships, PROFILE, reachability);
  const server = result.findings.find((finding) => finding.path === 'src/server.ts');

  assert.deepEqual([...reachability.entrypointClosureScopes], ['test']);
  assert(server);
  assert.equal(server.confidence, 'low');
  assert.deepEqual(server.signals, ['no-inbound-resolved-runtime-static-import']);
});

test('package metadata, scripts, test config, build config, and HTML produce scoped roots', () => {
  const files = [
    analysisFile('package.json', JSON.stringify({
      private: true,
      main: './src/server.js',
      module: './src/module.ts',
      bin: { app: './bin/tool.js' },
      scripts: {
        test: 'vitest run',
        build: 'vite build',
        audit: 'node scripts/audit.mjs'
      }
    })),
    analysisFile('src/server.js', 'export const server = true;\n'),
    analysisFile('src/module.ts', 'export const moduleEntry = true;\n'),
    analysisFile('src/library.ts', 'export const library = true;\n'),
    analysisFile('src/browser.ts', 'export const browser = true;\n'),
    analysisFile('bin/tool.js', '#!/usr/bin/env node\nexport const cli = true;\n'),
    analysisFile('scripts/audit.mjs', 'throw new Error("must never execute during analysis");\n'),
    analysisFile('tests/unit/example.test.ts', 'export const testCase = true;\n'),
    analysisFile('vite.config.ts', [
      'export default {',
      "  build: { lib: { entry: './src/library.ts' } },",
      "  test: { include: ['tests/**/*.test.ts'] }",
      '};',
      ''
    ].join('\n')),
    analysisFile('index.html', '<script type="module" src="/src/browser.ts"></script>\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const result = analyzeReachability(files, graph.relationships, PROFILE);
  const roots = new Map(result.entrypoints.map((entrypoint) => [entrypoint.path, entrypoint]));

  assert.equal(roots.get('src/server.js')?.origin, 'package-main');
  assert.equal(roots.get('src/module.ts')?.origin, 'package-module');
  assert.equal(roots.get('bin/tool.js')?.scope, 'cli');
  assert.equal(roots.get('scripts/audit.mjs')?.scope, 'cli');
  assert.equal(roots.get('tests/unit/example.test.ts')?.scope, 'test');
  assert.equal(roots.get('src/library.ts')?.scope, 'build');
  assert.equal(roots.get('src/browser.ts')?.origin, 'html-entry');
  assert.equal(roots.get('vite.config.ts')?.origin, 'build-config');
  assert([...roots.keys()].every((filePath) => result.reachablePaths.has(filePath)));
});

test('a reachable bounded Sequelize sibling registry loads its exact model cohort', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"main":"src/index.js"}\n'),
    analysisFile('src/index.js', "require('./models/index.js');\n"),
    analysisFile('src/models/index.js', [
      "const fs = require('fs');",
      "const path = require('path');",
      'const basename = path.basename(__filename);',
      'fs.readdirSync(__dirname)',
      "  .filter(file => file !== basename && file.endsWith('.js') && !file.includes('.test.'))",
      '  .forEach(file => require(path.join(__dirname, file)));',
      ''
    ].join('\n')),
    analysisFile('src/models/Client.js', 'module.exports = () => ({ name: "Client" });\n'),
    analysisFile('src/models/Staff.js', 'module.exports = () => ({ name: "Staff" });\n'),
    analysisFile('src/models/Client.test.js', 'throw new Error("not a model");\n', 'test')
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const result = analyzeReachability(files, graph.relationships, PROFILE);
  const loader = result.loaderScopes.find((scope) => scope.kind === 'sequelize-models');

  assert.equal(loader?.state, 'complete');
  assert.deepEqual(loader?.targetPaths, ['src/models/Client.js', 'src/models/Staff.js']);
  assert(result.reachablePaths.has('src/models/Client.js'));
  assert(result.runtimeInboundPaths.has('src/models/Staff.js'));
  assert(!result.diagnostics.some((diagnostic) => diagnostic.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'));
  const deadCode = detectDeadCodeCandidates(files, graph.relationships, PROFILE, result);
  assert(!deadCode.findings.some((finding) => finding.path?.startsWith('src/models/')));
});

test('a reachable bounded route registry loads its exact sibling route cohort', () => {
  const files = [
    analysisFile('src/server.js', "require('./routes/index.js');\n"),
    analysisFile('src/routes/index.js', [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'const current = path.basename(__filename);',
      "fs.readdirSync(__dirname).filter(file => file !== current && path.extname(file) === '.js').forEach(file => app.use(require(path.join(__dirname, file))));",
      ''
    ].join('\n')),
    analysisFile('src/routes/appointments.js', 'module.exports = router;\n'),
    analysisFile('src/routes/admin.js', 'module.exports = router;\n')
  ];
  const selectedProfile = profile({ entrypoints: ['src/server.js'] });
  const graph = analyzeJavaScriptTypeScript(files, selectedProfile);
  const result = analyzeReachability(files, graph.relationships, selectedProfile);
  const scope = result.loaderScopes.find((entry) => entry.id === 'convention:routes:src/routes/index.js');
  assert(scope);
  assert.equal(scope.state, 'complete');
  assert.deepEqual(scope.targetPaths, ['src/routes/admin.js', 'src/routes/appointments.js']);
  assert(result.reachablePaths.has('src/routes/admin.js'));
  assert(result.reachablePaths.has('src/routes/appointments.js'));
});

test('unrelated extension and self tokens cannot complete a Sequelize model registry', () => {
  const baseFiles = [
    analysisFile('package.json', '{"private":true,"main":"src/index.js"}\n'),
    analysisFile('src/index.js', "require('./models/index.js');\n"),
    analysisFile('src/models/Client.js', 'module.exports = {};\n')
  ];
  const sources = [
    [
      "const fs = require('fs');",
      "const path = require('path');",
      "const suffix = '.js';",
      'const basename = path.basename(__filename);',
      'fs.readdirSync(__dirname)',
      '  .filter(file => file !== basename)',
      '  .forEach(file => require(path.join(__dirname, file)));',
      ''
    ].join('\n'),
    [
      "const fs = require('fs');",
      "const path = require('path');",
      'const basename = path.basename(__filename);',
      'fs.readdirSync(__dirname)',
      "  .filter(file => file.endsWith('.js'))",
      '  .forEach(file => require(path.join(__dirname, file)));',
      ''
    ].join('\n')
  ];

  for (const source of sources) {
    const files = [...baseFiles, analysisFile('src/models/index.js', source)];
    const graph = analyzeJavaScriptTypeScript(files, PROFILE);
    const result = analyzeReachability(files, graph.relationships, PROFILE);
    const loader = result.loaderScopes.find((scope) => scope.kind === 'sequelize-models');

    assert.equal(loader?.state, 'incomplete');
    assert.deepEqual(loader?.targetPaths, ['src/models/Client.js']);
    assert(!result.reachablePaths.has('src/models/Client.js'));
    assert(result.gatedPaths.has('src/models/Client.js'));
    assert(result.diagnostics.some((diagnostic) => diagnostic.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'));
  }
});

test('an incomplete active convention gates only its model directory', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"main":"packages/a/index.js"}\n'),
    analysisFile('packages/a/index.js', "require('./models/index.js');\n"),
    analysisFile('packages/a/models/index.js', [
      "const fs = require('fs');",
      "const path = require('path');",
      'fs.readdirSync(__dirname).forEach(file => require(path.join(__dirname, file)));',
      ''
    ].join('\n')),
    analysisFile('packages/a/models/Maybe.js', 'module.exports = {};\n'),
    analysisFile('packages/b/orphan.js', 'module.exports = {};\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const result = analyzeReachability(files, graph.relationships, PROFILE);
  const diagnostic = result.diagnostics.find((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE');

  assert(diagnostic);
  assert(result.gatedPaths.has('packages/a/models/Maybe.js'));
  assert(!result.gatedPaths.has('packages/b/orphan.js'));
  const deadCode = detectDeadCodeCandidates(files, graph.relationships, PROFILE, result);
  assert(!deadCode.findings.some((finding) => finding.path === 'packages/a/models/Maybe.js'));
  assert(deadCode.findings.some((finding) => finding.path === 'packages/b/orphan.js'));
});

test('external test, build, and CLI loader rules seed exact targets without a static loader edge', () => {
  const rules: LoaderRule[] = [
    {
      id: 'build-roots',
      kind: 'build',
      loaderPaths: ['package.json'],
      loadedPatterns: ['build/entry.ts'],
      scope: 'build',
      required: true
    },
    {
      id: 'cli-roots',
      kind: 'cli',
      loaderPaths: ['package.json'],
      loadedPatterns: ['cli/tool.ts'],
      scope: 'cli',
      required: true
    },
    {
      id: 'test-roots',
      kind: 'tests',
      loaderPaths: ['package.json'],
      loadedPatterns: ['tests/external.test.ts'],
      scope: 'test',
      required: true
    }
  ];
  const selectedProfile = withLoaderRules(rules);
  const files = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('build/entry.ts', 'export const build = true;\n'),
    analysisFile('cli/tool.ts', 'export const cli = true;\n'),
    analysisFile('tests/external.test.ts', 'export const test = true;\n')
  ];
  const result = analyzeReachability(files, [], selectedProfile);

  assert.equal(result.entrypointClosureEstablished, true);
  assert.deepEqual(result.loaderScopes.filter((scope) => scope.source === 'profile').map((scope) => scope.state), [
    'complete',
    'complete',
    'complete'
  ]);
  assert(result.reachablePaths.has('build/entry.ts'));
  assert(result.reachablePaths.has('cli/tool.ts'));
  assert(result.reachablePaths.has('tests/external.test.ts'));
});

test('a required external loader with a missing loader path gates only matched loaded targets', () => {
  const selectedProfile = withLoaderRules([{
    id: 'missing-test-runner',
    kind: 'tests',
    loaderPaths: ['config/missing.test.config.ts'],
    loadedPatterns: ['tests/**/*.test.ts'],
    scope: 'test',
    required: true
  }], { entrypoints: ['src/index.ts'] });
  const files = [
    analysisFile('src/index.ts', 'export const entry = true;\n'),
    analysisFile('tests/unit/gated.test.ts', 'export const gated = true;\n'),
    analysisFile('src/orphan.ts', 'export const orphan = true;\n')
  ];
  const result = analyzeReachability(files, [], selectedProfile);

  assert(result.gatedPaths.has('tests/unit/gated.test.ts'));
  assert(!result.gatedPaths.has('src/orphan.ts'));
  assert.equal(result.diagnostics.filter((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE').length, 1);
  assert.equal(result.loaderScopes.find((scope) => scope.id === 'missing-test-runner')?.state, 'incomplete');
});

test('Sequelize CLI scripts and exact .sequelizerc paths seed model, migration, and seeder cohorts', () => {
  const files = [
    analysisFile('service/package.json', JSON.stringify({
      private: true,
      scripts: {
        migrate: 'sequelize-cli db:migrate',
        seed: 'sequelize-cli db:seed:all'
      }
    })),
    analysisFile('service/.sequelizerc', [
      "const path = require('path');",
      'module.exports = {',
      "  'models-path': path.join(__dirname, 'src', 'models'),",
      "  'migrations-path': path.resolve(__dirname, 'database', 'migrations'),",
      "  'seeders-path': path.resolve('database', 'seeders')",
      '};',
      ''
    ].join('\n')),
    analysisFile('service/config/.sequelizerc', "module.exports = { 'models-path': 'wrong-models' };\n"),
    analysisFile('service/src/models/account.js', 'module.exports = () => ({ name: "Account" });\n'),
    analysisFile('service/database/migrations/001-create.js', 'module.exports = { up() {}, down() {} };\n'),
    analysisFile('service/database/seeders/001-seed.js', 'module.exports = { up() {}, down() {} };\n')
  ];
  const result = analyzeReachability(files, [], PROFILE);
  const cliScopes = result.loaderScopes.filter((scope) => scope.id.startsWith('convention:sequelize-cli:'));

  assert(cliScopes.every((scope) => scope.state === 'complete'));
  const configScope = cliScopes.find((scope) => scope.kind === 'cli');
  const modelScope = cliScopes.find((scope) => scope.kind === 'sequelize-models');
  assert.deepEqual(configScope?.targetPaths, ['service/.sequelizerc']);
  assert.deepEqual(modelScope?.targetPaths, ['service/src/models/account.js']);
  assert(result.reachablePaths.has('service/.sequelizerc'));
  assert(!result.reachablePaths.has('service/config/.sequelizerc'));
  assert(result.reachablePaths.has('service/src/models/account.js'));
  assert(result.reachablePaths.has('service/database/migrations/001-create.js'));
  assert(result.reachablePaths.has('service/database/seeders/001-seed.js'));
});

test('.sequelizerc paths with dynamic path arguments stay incomplete', () => {
  const files = [
    analysisFile('service/package.json', JSON.stringify({
      private: true,
      scripts: { migrate: 'sequelize-cli db:migrate' }
    })),
    analysisFile('service/.sequelizerc', [
      "const path = require('path');",
      'module.exports = {',
      "  'migrations-path': path.resolve(__dirname, process.env.DB_ROOT, 'migrations')",
      '};',
      ''
    ].join('\n')),
    analysisFile('service/migrations/001-create.js', 'module.exports = { up() {}, down() {} };\n'),
    analysisFile('src/unrelated.js', 'module.exports = {};\n')
  ];
  const result = analyzeReachability(files, [], PROFILE);
  const migrationScope = result.loaderScopes.find((scope) => scope.kind === 'migrations');

  assert.equal(migrationScope?.state, 'incomplete');
  assert.deepEqual(migrationScope?.loadedPatterns, []);
  assert.deepEqual(migrationScope?.targetPaths, []);
  assert.match(migrationScope?.reason ?? '', /unsupported expression/u);
  assert(!result.reachablePaths.has('service/migrations/001-create.js'));
  assert(!result.gatedPaths.has('service/migrations/001-create.js'));
  assert(!result.gatedPaths.has('src/unrelated.js'));
});

test('unresolved package main, module, bin, and literal script entries diagnose without broad gating', () => {
  const files = [
    analysisFile('package.json', JSON.stringify({
      private: true,
      main: './missing-main.js',
      module: './missing-module.js',
      bin: { atlas: './missing-bin.js' },
      scripts: { audit: 'node scripts/missing-audit.ts' }
    })),
    analysisFile('src/unrelated.ts', 'export const unrelated = true;\n')
  ];
  const result = analyzeReachability(files, [], PROFILE);
  const incomplete = result.loaderScopes.filter((scope) =>
    scope.state === 'incomplete' &&
    (scope.id.includes('package-main') || scope.id.includes('package-module') ||
      scope.id.includes('package-bin') || scope.id.includes('package-script'))
  );

  assert.equal(incomplete.length, 4);
  assert(incomplete.every((scope) => scope.targetPaths.length === 0));
  assert.equal(result.gatedPaths.size, 0);
  assert(!result.gatedPaths.has('src/unrelated.ts'));
  assert.equal(result.diagnostics.filter((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE').length, 4);
});

test('package-script extension lists are not misclassified as source entry paths', () => {
  const fixture = [
    analysisFile('package.json', JSON.stringify({ scripts: { lint: 'eslint . --ext .ts,.tsx' } })),
    analysisFile('src/index.ts', 'export {};\n')
  ];
  const selectedProfile = profile();
  const graph = analyzeJavaScriptTypeScript(fixture, selectedProfile);
  const result = analyzeReachability(fixture, graph.relationships, selectedProfile);
  assert.equal(result.loaderScopes.some((entry) => entry.reason?.includes('.ts,.tsx')), false);
});

test('documentation and mothballed dynamic loads do not create active loader coverage claims', () => {
  const fixture = [
    analysisFile('docs/positive-control.js', "require(dynamicName);\n"),
    withLifecycle(analysisFile('src/legacy-loader.js', "require(dynamicName);\n"), 'mothballed'),
    analysisFile('src/server.ts', "import '../docs/positive-control.js';\nimport './legacy-loader.js';\n")
  ];
  const selectedProfile = profile({ entrypoints: ['src/server.ts'] });
  const graph = analyzeJavaScriptTypeScript(fixture, selectedProfile);
  const result = analyzeReachability(fixture, graph.relationships, selectedProfile);
  assert.equal(result.loaderScopes.some((entry) => entry.id.startsWith('convention:dynamic-module')), false);
});

test('unsupported and zero-match test configuration stays incomplete and gates only a bounded test cohort', () => {
  const unsupportedFiles = [
    analysisFile('package.json', JSON.stringify({ private: true, scripts: { test: 'vitest run' } })),
    analysisFile('vitest.config.ts', "export default { test: { include: ['tests/**/?(*.)+(spec|test).ts'] } };\n"),
    analysisFile('tests/unit/example.test.ts', 'export const example = true;\n'),
    analysisFile('src/unrelated.ts', 'export const unrelated = true;\n')
  ];
  const unsupported = analyzeReachability(unsupportedFiles, [], PROFILE);
  const unsupportedScope = unsupported.loaderScopes.find((scope) => scope.kind === 'tests');

  assert.equal(unsupportedScope?.state, 'incomplete');
  assert.deepEqual(unsupportedScope?.targetPaths, ['tests/unit/example.test.ts']);
  assert(unsupported.gatedPaths.has('tests/unit/example.test.ts'));
  assert(!unsupported.gatedPaths.has('src/unrelated.ts'));
  assert(!unsupported.entrypoints.some((entrypoint) => entrypoint.path === 'tests/unit/example.test.ts'));

  const zeroMatchFiles = [
    analysisFile('package.json', JSON.stringify({ private: true, scripts: { test: 'vitest run' } })),
    analysisFile('vitest.config.ts', "export default { test: { include: ['tests/**/*.test.ts'] } };\n"),
    analysisFile('src/unrelated.ts', 'export const unrelated = true;\n')
  ];
  const zeroMatch = analyzeReachability(zeroMatchFiles, [], PROFILE);
  const zeroMatchScope = zeroMatch.loaderScopes.find((scope) => scope.kind === 'tests');
  assert.equal(zeroMatchScope?.state, 'incomplete');
  assert.deepEqual(zeroMatchScope?.targetPaths, []);
  assert.match(zeroMatchScope?.reason ?? '', /resolved no included test entry/u);
  assert(!zeroMatch.gatedPaths.has('src/unrelated.ts'));
});

test('an active build with no statically resolved entry is diagnosed without package-wide suppression', () => {
  const files = [
    analysisFile('package.json', JSON.stringify({ private: true, scripts: { build: 'vite build' } })),
    analysisFile('vite.config.ts', 'export default { build: { rollupOptions: { input: process.env.ENTRY } } };\n'),
    analysisFile('src/unrelated.ts', 'export const unrelated = true;\n')
  ];
  const result = analyzeReachability(files, [], PROFILE);
  const buildScope = result.loaderScopes.find((scope) => scope.kind === 'build');

  assert.equal(buildScope?.state, 'incomplete');
  assert.deepEqual(buildScope?.targetPaths, []);
  assert.match(buildScope?.reason ?? '', /non-literal or unsupported input entry/u);
  assert(!result.gatedPaths.has('src/unrelated.ts'));
  assert(result.diagnostics.some((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'));
});

test('generic dynamic fallback gates only an explicit literal descendant cohort', () => {
  const selectedProfile = profile({ entrypoints: ['src/index.ts'] });
  const files = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', [
      "const path = require('node:path');",
      "const name = process.env.PLUGIN;",
      "if (name) require(path.join(__dirname, 'plugins', name));",
      ''
    ].join('\n')),
    analysisFile('src/plugins/optional.ts', 'export const optional = true;\n'),
    analysisFile('src/unrelated.ts', 'export const unrelated = true;\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, selectedProfile);
  const result = analyzeReachability(files, graph.relationships, selectedProfile);
  const scope = result.loaderScopes.find((entry) => entry.id.includes('dynamic-module:production:bounded'));

  assert.equal(scope?.state, 'incomplete');
  assert.deepEqual(scope?.targetPaths, ['src/plugins/optional.ts']);
  assert(result.gatedPaths.has('src/plugins/optional.ts'));
  assert(!result.gatedPaths.has('src/unrelated.ts'));
  const deadCode = detectDeadCodeCandidates(files, graph.relationships, selectedProfile, result);
  assert(!deadCode.findings.some((finding) => finding.path === 'src/plugins/optional.ts'));
  assert(deadCode.findings.some((finding) => finding.path === 'src/unrelated.ts'));
});

test('uncovered dynamic scopes are isolated per loader path', () => {
  const selectedProfile = profile({ entrypoints: ['src/index.ts'] });
  const files = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', "import './active-loader.js';\n"),
    analysisFile('src/active-loader.ts', 'void import(activeName);\n'),
    analysisFile('src/inactive-loader.ts', 'void import(inactiveName);\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, selectedProfile);
  const result = analyzeReachability(files, graph.relationships, selectedProfile);
  const scopes = result.loaderScopes.filter((scope) => scope.id.startsWith('convention:dynamic-module:'));

  assert.equal(scopes.length, 2);
  const active = scopes.find((scope) => scope.loaderPaths[0] === 'src/active-loader.ts');
  const inactive = scopes.find((scope) => scope.loaderPaths[0] === 'src/inactive-loader.ts');
  assert.equal(active?.state, 'incomplete');
  assert.equal(active?.relationshipIds.length, 1);
  assert.equal(inactive?.state, 'inactive');
  assert.equal(inactive?.relationshipIds.length, 1);
  const diagnostics = result.diagnostics.filter((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE');
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0]?.path, 'src/active-loader.ts');
  assert.deepEqual(diagnostics[0]?.evidence.recordIds, active?.relationshipIds);
});

test('ambient TypeScript declarations are excluded from static dead-code candidates', () => {
  const selectedProfile = profile({ entrypoints: ['src/index.ts'] });
  const files = [
    analysisFile('src/index.ts', 'export const entry = true;\n'),
    analysisFile('src/globals.d.ts', 'declare const injected: string;\n'),
    analysisFile('src/worker.d.mts', 'declare const workerName: string;\n'),
    analysisFile('src/legacy.d.cts', 'declare const legacyName: string;\n'),
    analysisFile('src/orphan.ts', 'export const orphan = true;\n')
  ];
  const result = detectDeadCodeCandidates(files, [], selectedProfile);
  const paths = result.findings
    .filter((finding) => finding.ruleId === 'dead-code/static-reachability-v1')
    .map((finding) => finding.path);

  assert.deepEqual(paths, ['src/orphan.ts']);
});

test('Vite public directories and literal service-worker URLs establish bounded asset roots', () => {
  const defaultFiles = [
    analysisFile('package.json', JSON.stringify({ scripts: { build: 'vite build' } })),
    analysisFile('index.html', '<script type="module" src="/src/main.ts"></script>\n'),
    analysisFile('src/main.ts', "navigator.serviceWorker.register('/service-worker.js');\n"),
    analysisFile('public/service-worker.js', 'self.addEventListener("fetch", () => {});\n'),
    analysisFile('public/manifest-helper.js', 'export const manifest = true;\n')
  ];
  const defaultResult = analyzeReachability(defaultFiles, [], PROFILE);
  assert(defaultResult.reachablePaths.has('public/service-worker.js'));
  assert(defaultResult.reachablePaths.has('public/manifest-helper.js'));
  assert(defaultResult.loaderScopes.some((scope) =>
    scope.kind === 'build' && scope.loadedPatterns.includes('public/**') && scope.state === 'complete'
  ));
  assert(defaultResult.loaderScopes.some((scope) =>
    scope.kind === 'custom' && scope.loadedPatterns.includes('/service-worker.js') && scope.state === 'complete'
  ));
  assert(!detectDeadCodeCandidates(defaultFiles, [], PROFILE, defaultResult).findings.some(
    (finding) => finding.path?.startsWith('public/')
  ));

  const customFiles = [
    analysisFile('package.json', JSON.stringify({ scripts: { build: 'vite build' } })),
    analysisFile('vite.config.ts', "export default defineConfig({ publicDir: 'static-assets' });\n"),
    analysisFile('index.html', '<script type="module" src="/src/main.ts"></script>\n'),
    analysisFile('src/main.ts', "navigator.serviceWorker.register('/sw.js');\n"),
    analysisFile('static-assets/sw.js', 'self.addEventListener("fetch", () => {});\n'),
    analysisFile('public/not-served.js', 'export const orphan = true;\n')
  ];
  const customResult = analyzeReachability(customFiles, [], PROFILE);
  assert(customResult.reachablePaths.has('static-assets/sw.js'));
  assert(!customResult.reachablePaths.has('public/not-served.js'));
  assert(detectDeadCodeCandidates(customFiles, [], PROFILE, customResult).findings.some(
    (finding) => finding.path === 'public/not-served.js'
  ));
});

test('ambiguous public directories and service-worker URLs diagnose and gate only bounded public cohorts', () => {
  const viteFiles = [
    analysisFile('package.json', JSON.stringify({ scripts: { build: 'vite build' } })),
    analysisFile('vite.config.ts', 'export default { publicDir: process.env.PUBLIC_DIR };\n'),
    analysisFile('index.html', '<script type="module" src="/src/main.ts"></script>\n'),
    analysisFile('src/main.ts', "navigator.serviceWorker.register('/sw.js');\n"),
    analysisFile('public/sw.js', 'self.addEventListener("fetch", () => {});\n'),
    analysisFile('src/unrelated.ts', 'export const unrelated = true;\n')
  ];
  const viteResult = analyzeReachability(viteFiles, [], PROFILE);
  assert(!viteResult.reachablePaths.has('public/sw.js'));
  assert(viteResult.gatedPaths.has('public/sw.js'));
  assert(!viteResult.gatedPaths.has('src/unrelated.ts'));
  assert(viteResult.diagnostics.some((entry) =>
    entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE' && entry.message.includes('publicDir')
  ));

  const dynamicFiles = [
    analysisFile('package.json', '{"private":true,"main":"src/main.js"}\n'),
    analysisFile('src/main.js', 'navigator.serviceWorker.register(workerUrl);\n'),
    analysisFile('public/sw.js', 'self.addEventListener("fetch", () => {});\n'),
    analysisFile('src/unrelated.js', 'module.exports = {};\n')
  ];
  const dynamicResult = analyzeReachability(dynamicFiles, [], PROFILE);
  const serviceWorkerScope = dynamicResult.loaderScopes.find((scope) =>
    scope.kind === 'custom' && scope.reason?.includes('non-literal asset URL')
  );
  assert.equal(serviceWorkerScope?.state, 'incomplete');
  assert.deepEqual(serviceWorkerScope?.targetPaths, ['public/sw.js']);
  assert(dynamicResult.gatedPaths.has('public/sw.js'));
  assert(!dynamicResult.gatedPaths.has('src/unrelated.js'));
});

test('test configs bind per package script and resolve literal path.join test roots', () => {
  const files = [
    analysisFile('package.json', JSON.stringify({
      scripts: { e2e: 'playwright test --config configs/playwright.admin.config.ts' }
    })),
    analysisFile('configs/playwright.admin.config.ts', [
      "import path from 'node:path';",
      "export default { testDir: path.join(__dirname, '..', 'tests', 'admin'), testMatch: '**/*.spec.ts' };",
      ''
    ].join('\n')),
    analysisFile('configs/playwright.staff.config.ts', [
      "import path from 'node:path';",
      "export default { testDir: path.join(__dirname, '..', 'tests', 'staff'), testMatch: '**/*.spec.ts' };",
      ''
    ].join('\n')),
    analysisFile('tests/admin/access.spec.ts', 'export const admin = true;\n'),
    analysisFile('tests/staff/access.spec.ts', 'export const staff = true;\n'),
    analysisFile('tests/other/access.spec.ts', 'export const other = true;\n')
  ];
  const result = analyzeReachability(files, [], PROFILE);
  const configScopes = result.loaderScopes.filter((scope) => scope.id.startsWith('convention:tests-config:'));

  assert.equal(configScopes.length, 1);
  assert.deepEqual(configScopes[0]?.loaderPaths, ['configs/playwright.admin.config.ts']);
  assert.deepEqual(configScopes[0]?.targetPaths, ['tests/admin/access.spec.ts']);
  assert(result.reachablePaths.has('tests/admin/access.spec.ts'));
  assert(!result.reachablePaths.has('tests/staff/access.spec.ts'));
  assert(!result.reachablePaths.has('tests/other/access.spec.ts'));
});

test('unsupported and ambiguous test configs never gate sibling or package-global test cohorts', () => {
  const selectedFiles = [
    analysisFile('package.json', JSON.stringify({
      scripts: { e2e: 'playwright test --config configs/playwright.admin.config.ts' }
    })),
    analysisFile('configs/playwright.admin.config.ts', [
      "import path from 'node:path';",
      "export default { testDir: path.join(__dirname, '..', 'tests', 'admin'), testMatch: makePattern() };",
      ''
    ].join('\n')),
    analysisFile('configs/playwright.staff.config.ts', "export default { testDir: '../tests/staff' };\n"),
    analysisFile('tests/admin/access.spec.ts', 'export const admin = true;\n'),
    analysisFile('tests/staff/access.spec.ts', 'export const staff = true;\n'),
    analysisFile('tests/other/access.spec.ts', 'export const other = true;\n')
  ];
  const selected = analyzeReachability(selectedFiles, [], PROFILE);
  const incomplete = selected.loaderScopes.find((scope) => scope.id.startsWith('convention:tests-config:'));
  assert.equal(incomplete?.state, 'incomplete');
  assert.deepEqual(incomplete?.targetPaths, ['tests/admin/access.spec.ts']);
  assert(selected.gatedPaths.has('tests/admin/access.spec.ts'));
  assert(!selected.gatedPaths.has('tests/staff/access.spec.ts'));
  assert(!selected.gatedPaths.has('tests/other/access.spec.ts'));

  const ambiguousFiles = [
    analysisFile('package.json', JSON.stringify({ scripts: { e2e: 'playwright test' } })),
    analysisFile('playwright.config.ts', "export default { testDir: './tests/admin' };\n"),
    analysisFile('playwright.config.js', "module.exports = { testDir: './tests/staff' };\n"),
    analysisFile('tests/admin/access.spec.ts', 'export const admin = true;\n'),
    analysisFile('tests/staff/access.spec.ts', 'export const staff = true;\n')
  ];
  const ambiguous = analyzeReachability(ambiguousFiles, [], PROFILE);
  assert.equal(ambiguous.loaderScopes.filter((scope) => scope.id.startsWith('convention:tests-config:')).length, 0);
  const selection = ambiguous.loaderScopes.find((scope) => scope.id.startsWith('convention:tests-selection:'));
  assert.equal(selection?.state, 'incomplete');
  assert.deepEqual(selection?.targetPaths, []);
  assert(!ambiguous.gatedPaths.has('tests/admin/access.spec.ts'));
  assert(!ambiguous.gatedPaths.has('tests/staff/access.spec.ts'));
  assert(!ambiguous.reachablePaths.has('tests/admin/access.spec.ts'));
  assert(!ambiguous.reachablePaths.has('tests/staff/access.spec.ts'));
});

test('reachability output is deterministic under reversed file and relationship order', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"main":"src/index.js"}\n'),
    analysisFile('src/index.js', "require('./feature.js');\n"),
    analysisFile('src/feature.js', 'module.exports = true;\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const first = analyzeReachability(files, graph.relationships, PROFILE);
  const second = analyzeReachability([...files].reverse(), [...graph.relationships].reverse(), PROFILE);

  assert.deepEqual(second, first);
});
