import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeJavaScriptTypeScript } from '../src/adapters/js-ts.js';
import {
  detectCleanupCandidates,
  MAX_DYNAMIC_COUNTER_EVIDENCE_PER_FINDING
} from '../src/analysis/cleanup.js';
import { detectDuplicateFileCandidates } from '../src/analysis/duplicate-files.js';
import { detectPlatformResidualCandidates } from '../src/analysis/platform-residuals.js';
import { detectUnusedExportCandidates } from '../src/analysis/unused-exports.js';
import type {
  AnalysisFile,
  DiagnosticRecord,
  EvidenceReference,
  FileKind,
  FileRecord,
  ResolvedProfile
} from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { canonicalJson, sha256 } from '../src/util/canonical.js';

const PROFILE: ResolvedProfile = {
  schemaVersion: SCHEMA_VERSION,
  id: 'cleanup-fixture',
  includeRoots: ['.'],
  exclude: [],
  entrypoints: ['src/index.ts'],
  aliases: {},
  envExampleFiles: [],
  platformRoots: ['.github', 'infra'],
  deadCodeExemptions: [],
  lifecycleRules: [],
  maxFileBytes: 1_000_000
};

function language(filePath: string): string {
  if (/\.(?:ts|mts|cts)$/u.test(filePath)) return 'typescript';
  if (/\.(?:js|mjs|cjs)$/u.test(filePath)) return 'javascript';
  if (filePath.endsWith('.json')) return 'json';
  if (filePath.endsWith('.tf')) return 'terraform';
  if (/\.ya?ml$/u.test(filePath)) return 'yaml';
  if (filePath.endsWith('.md')) return 'markdown';
  return 'text';
}

function kind(filePath: string): FileKind {
  if (/\.(?:ts|mts|cts|js|mjs|cjs)$/u.test(filePath)) return 'source';
  if (filePath.endsWith('.md')) return 'documentation';
  return 'configuration';
}

function analysisFile(filePath: string, source: string, kindOverride?: FileKind): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  const sourceEvidence: EvidenceReference = {
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
    kind: kindOverride ?? kind(filePath),
    language: language(filePath),
    symbols: [],
    environmentVariables: [],
    lifecycle: {
      state: 'unspecified',
      basis: 'no-profile-match',
      uncertainty: 'not-runtime-validated',
      limitation: 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.'
    },
    evidence: sourceEvidence
  };
  return { record, content };
}

test('unused exports are claimed only across a private, fully parsed static consumer boundary', () => {
  const files = [
    analysisFile('package.json', '{"private":true,"name":"cleanup-test"}\n'),
    analysisFile('src/index.ts', "import { used } from './library.js';\nconsole.log(used());\n"),
    analysisFile('src/library.ts', [
      'export function used(): string { return "used"; }',
      'export function unused(): string { return "unused"; }',
      ''
    ].join('\n'))
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const first = detectUnusedExportCandidates(files, graph.relationships, PROFILE);
  const reversed = detectUnusedExportCandidates([...files].reverse(), [...graph.relationships].reverse(), PROFILE);

  assert.deepEqual(reversed, first);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0]?.ruleId, 'dead-code/unused-private-export-surface-v1');
  assert(first.findings[0]?.title.includes('unused'));
  assert(first.findings[0]?.evidence.every((entry) => entry.path && entry.line && entry.column));
  assert.deepEqual(first.diagnostics, []);
});

test('an exact fixture unresolved-import allowlist does not suppress an unrelated unused export', () => {
  const selectedProfile: ResolvedProfile = {
    ...PROFILE,
    fixtureUnresolvedImports: [{
      id: 'intentional-missing-fixture-model',
      sourcePattern: 'tests/fixture.ts',
      specifier: '../missing/live.js'
    }]
  };
  const files = [
    analysisFile('package.json', '{"private":true,"name":"fixture-unused-export-test"}\n'),
    analysisFile('src/live.ts', 'export const foo = 1;\nexport const bar = 2;\n'),
    analysisFile('src/use.ts', "import { bar } from './live.js';\nvoid bar;\n"),
    analysisFile('tests/fixture.ts', "import { foo } from '../missing/live.js';\nvoid foo;\n", 'test')
  ];
  const graph = analyzeJavaScriptTypeScript(files, selectedProfile);
  const result = detectUnusedExportCandidates(files, graph.relationships, selectedProfile);

  assert(graph.diagnostics.some((entry) => entry.code === 'EXPECTED_FIXTURE_UNRESOLVED_IMPORT'));
  assert.deepEqual(result.findings.map((finding) => finding.title), ['Review unused private export: foo']);
  assert(!result.diagnostics.some((entry) => entry.code === 'CLEANUP_UNUSED_EXPORT_GRAPH_UNCERTAIN'));
});

test('dynamic and namespace consumers suppress unsupported claims with scoped uncertainty', () => {
  const dynamicFiles = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', [
      "const moduleName = './library.js';",
      "const secondModuleName = './other-library.js';",
      'void import(moduleName);',
      'void import(secondModuleName);',
      ''
    ].join('\n')),
    analysisFile('src/library.ts', 'export const possiblyLoaded = 1;\n')
  ];
  const dynamicGraph = analyzeJavaScriptTypeScript(dynamicFiles, PROFILE);
  const dynamic = detectCleanupCandidates(dynamicFiles, dynamicGraph.relationships, PROFILE);
  assert(!dynamic.findings.some((finding) => finding.ruleId.includes('unused-private-export')));
  const dynamicReachability = dynamic.findings.filter((finding) => finding.ruleId === 'dead-code/static-reachability-v1');
  assert.deepEqual(dynamicReachability.map((finding) => finding.path), ['src/library.ts']);
  assert.deepEqual(dynamicReachability[0]?.signals, [
    'no-inbound-resolved-runtime-static-import',
    'unreachable-from-configured-entrypoints'
  ]);
  assert(dynamic.diagnostics.some((entry) => entry.code === 'CLEANUP_UNUSED_EXPORT_GRAPH_UNCERTAIN'));
  const scoped = dynamic.diagnostics.find((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE');
  assert(scoped);
  assert.equal(scoped.path, 'src/index.ts');
  assert.equal(scoped.evidence.basis, 'scoped-loader-coverage');
  assert.equal(scoped.evidence.recordIds?.length, 2);

  const namespaceFiles = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', "import * as library from './library.js';\nconsole.log(library.used);\n"),
    analysisFile('src/library.ts', 'export const used = 1;\nexport const maybeUsed = 2;\n')
  ];
  const namespaceGraph = analyzeJavaScriptTypeScript(namespaceFiles, PROFILE);
  const namespace = detectUnusedExportCandidates(namespaceFiles, namespaceGraph.relationships, PROFILE);
  assert.deepEqual(namespace.findings, []);
  assert(namespace.diagnostics.some((entry) => entry.code === 'CLEANUP_UNUSED_EXPORT_NAMESPACE_IMPORT'));
});

test('an inactive dynamic loader does not fabricate an entrypoint closure or broaden candidates', () => {
  const noEntrypointProfile: ResolvedProfile = {
    ...PROFILE,
    id: 'cleanup-no-entrypoint-fixture',
    entrypoints: ['src/does-not-exist.ts']
  };
  const files = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/loader.ts', "const name = './candidate.js';\nvoid import(name);\n"),
    analysisFile('src/candidate.ts', 'export const candidate = 1;\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, noEntrypointProfile);
  const result = detectCleanupCandidates(files, graph.relationships, noEntrypointProfile);
  assert(result.diagnostics.some((entry) => entry.code === 'DEAD_CODE_NO_ENTRYPOINTS'));
  assert(!result.diagnostics.some((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'));

  const candidate = result.findings.find(
    (finding) => finding.ruleId === 'dead-code/static-reachability-v1' && finding.path === 'src/candidate.ts'
  );
  assert(candidate);
  assert.deepEqual(candidate.signals, ['no-inbound-resolved-runtime-static-import']);
  assert(!candidate.signals.includes('active-unsupported-dynamic-loading-counter-evidence'));
  assert(candidate.evidence.every((entry) => entry.basis !== 'unsupported-dynamic-module-load-without-entrypoint-closure-counter-evidence'));
});

test('an unbounded root dynamic load is diagnosed once without suppressing unrelated candidates', () => {
  const dynamicLoadCount = MAX_DYNAMIC_COUNTER_EVIDENCE_PER_FINDING + 17;
  const orphanCount = 80;
  const loaderSource = Array.from({ length: dynamicLoadCount }, (_, index) => [
    `const moduleName${index} = './optional-${index}.js';`,
    `void import(moduleName${index});`
  ].join('\n')).join('\n');
  const files = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', `${loaderSource}\n`),
    ...Array.from({ length: orphanCount }, (_, index) =>
      analysisFile(`src/orphan-${index.toString().padStart(3, '0')}.ts`, `export const orphan${index} = ${index};\n`)
    )
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  const dynamicRelationships = graph.relationships.filter((relationship) => relationship.specifier === '<dynamic>');
  assert.equal(dynamicRelationships.length, dynamicLoadCount);

  const first = detectCleanupCandidates(files, graph.relationships, PROFILE);
  const second = detectCleanupCandidates([...files].reverse(), [...graph.relationships].reverse(), PROFILE);
  assert.deepEqual(second, first);
  const orphanFindings = first.findings.filter(
    (finding) => finding.ruleId === 'dead-code/static-reachability-v1' && (finding.path ?? '').startsWith('src/orphan-')
  );
  assert.equal(orphanFindings.length, orphanCount);
  const scopedDiagnostics = first.diagnostics.filter(
    (entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'
  );
  assert.equal(scopedDiagnostics.length, 1);
  const aggregate = scopedDiagnostics[0];
  assert(aggregate);
  assert.match(aggregate.message, /suppressed only for its 0 observed target/u);
  assert.match(aggregate.message, /does not suppress cleanup findings/u);
  assert.equal(aggregate.evidence.recordIds?.length, dynamicLoadCount);
});

test('literal unsupported workspace ambiguity does not act as a dynamic reachability suppressor', () => {
  const ambiguityProfile: ResolvedProfile = {
    ...PROFILE,
    entrypoints: ['apps/web/src/index.ts']
  };
  const files = [
    analysisFile('package.json', '{"private":true,"workspaces":["apps/*","packages/*"]}\n'),
    analysisFile('apps/web/package.json', '{"name":"web","private":true}\n'),
    analysisFile('apps/web/src/index.ts', 'import { shared } from "shared"; void shared;\n'),
    analysisFile('apps/web/src/orphan.ts', 'export const orphan = true;\n'),
    analysisFile('packages/shared/package.json', JSON.stringify({
      name: 'shared',
      exports: { '.': { import: './src/runtime.ts', types: './src/types.ts' } }
    })),
    analysisFile('packages/shared/src/runtime.ts', 'export const shared = true;\n'),
    analysisFile('packages/shared/src/types.ts', 'export interface Shared { ok: true }\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, ambiguityProfile);
  const ambiguous = graph.relationships.find((relationship) => relationship.specifier === 'shared');
  assert.equal(ambiguous?.type, 'static-import');
  assert.equal(ambiguous?.resolution, 'unsupported');
  assert.notEqual(ambiguous?.specifier, '<dynamic>');

  const result = detectCleanupCandidates(files, graph.relationships, ambiguityProfile);
  assert(!result.diagnostics.some((entry) =>
    entry.code === 'CLEANUP_REACHABILITY_DYNAMIC_LOADING' ||
    entry.code === 'CLEANUP_REACHABILITY_INACTIVE_DYNAMIC_LOADING'
  ));
  const orphan = result.findings.find((finding) =>
    finding.ruleId === 'dead-code/static-reachability-v1' && finding.path === 'apps/web/src/orphan.ts'
  );
  assert(orphan);
  assert.equal(orphan.confidence, 'medium');
  assert.deepEqual(orphan.signals, [
    'no-inbound-resolved-runtime-static-import',
    'unreachable-from-configured-entrypoints'
  ]);
  assert(!orphan.signals.includes('active-unsupported-dynamic-loading-counter-evidence'));
});

test('type-only relationships do not activate runtime reachability or dynamic-load suppression', () => {
  const files = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', "import type { Shape } from './types.js';\nconst value: Shape = { ok: true };\nvoid value;\n"),
    analysisFile('src/types.ts', [
      "const selected = './plugin.js';",
      'void import(selected);',
      'export interface Shape { ok: boolean }',
      ''
    ].join('\n')),
    analysisFile('src/orphan.ts', 'export const orphan = true;\n')
  ];
  const graph = analyzeJavaScriptTypeScript(files, PROFILE);
  assert(graph.relationships.some((relationship) =>
    relationship.fromPath === 'src/index.ts' && relationship.toPath === 'src/types.ts' && relationship.typeOnly === true
  ));
  const result = detectCleanupCandidates(files, graph.relationships, PROFILE);
  assert(!result.diagnostics.some((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'));
  const candidates = result.findings.filter((finding) => finding.ruleId === 'dead-code/static-reachability-v1');
  assert(candidates.some((finding) =>
    finding.path === 'src/types.ts' && finding.signals.includes('no-inbound-resolved-runtime-static-import')
  ));
  assert(candidates.some((finding) => finding.path === 'src/orphan.ts'));
  assert(candidates.every((finding) => !finding.signals.includes('active-unsupported-dynamic-loading-counter-evidence')));
});

test('unresolved named imports are symbol-scoped and unreachable dynamic loads do not broaden entrypoint closure', () => {
  const aliasProfile: ResolvedProfile = {
    ...PROFILE,
    aliases: { '@missing/*': ['src/not-present/*'] }
  };
  const symbolFiles = [
    analysisFile('package.json', '{"private":true}\n'),
    analysisFile('src/index.ts', [
      "import { used } from './library.js';",
      "import { maybeUsed } from '@missing/module';",
      'console.log(used(), maybeUsed);',
      ''
    ].join('\n')),
    analysisFile('src/library.ts', [
      'export const used = (): number => 1;',
      'export const maybeUsed = (): number => 2;',
      'export const unused = (): number => 3;',
      ''
    ].join('\n'))
  ];
  const symbolGraph = analyzeJavaScriptTypeScript(symbolFiles, aliasProfile);
  const symbols = detectUnusedExportCandidates(symbolFiles, symbolGraph.relationships, aliasProfile);
  assert.deepEqual(symbols.findings.map((finding) => finding.title), ['Review unused private export: unused']);
  assert(symbols.diagnostics.some((entry) => entry.code === 'CLEANUP_UNUSED_EXPORT_GRAPH_UNCERTAIN'));

  const scopedProfile: ResolvedProfile = {
    ...PROFILE,
    entrypoints: ['packages/a/index.ts', 'packages/b/index.ts']
  };
  const scopedFiles = [
    analysisFile('packages/a/package.json', '{"private":true}\n'),
    analysisFile('packages/a/index.ts', 'console.log("package-a");\n'),
    analysisFile('packages/a/tool.ts', "const selected = './orphan.js';\nvoid import(selected);\n"),
    analysisFile('packages/a/orphan.ts', 'export const orphanA = true;\n'),
    analysisFile('packages/b/package.json', '{"private":true}\n'),
    analysisFile('packages/b/index.ts', 'console.log("package-b");\n'),
    analysisFile('packages/b/orphan.ts', 'export const orphanB = true;\n')
  ];
  const scopedGraph = analyzeJavaScriptTypeScript(scopedFiles, scopedProfile);
  const scoped = detectCleanupCandidates(scopedFiles, scopedGraph.relationships, scopedProfile);
  const reachabilityPaths = scoped.findings
    .filter((finding) => finding.ruleId === 'dead-code/static-reachability-v1')
    .map((finding) => finding.path);
  assert(reachabilityPaths.includes('packages/a/orphan.ts'));
  assert(reachabilityPaths.includes('packages/b/orphan.ts'));
  assert(!scoped.diagnostics.some((entry) => entry.code === 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE'));
});

test('byte-identical authored files are grouped while boilerplate, generated, test, and mixed-semantic groups abstain', () => {
  const authored = [
    'export function normalizeCustomerRecord(value: string): string {',
    '  return value.trim().toLocaleLowerCase("en-US");',
    '}',
    '// This intentionally exceeds the conservative tiny-file floor for the fixture.',
    ''
  ].join('\n');
  const generated = `// @generated - do not edit\n${'export const generatedValue = 1;\n'.repeat(6)}`;
  const inconsistent = analysisFile('src/inconsistent.ts', authored);
  inconsistent.record.sha256 = '0'.repeat(64);
  const files = [
    analysisFile('src/customer-a.ts', authored),
    analysisFile('src/customer-b.ts', authored),
    analysisFile('generated/model-a.ts', generated),
    analysisFile('generated/model-b.ts', generated),
    analysisFile('test/fixture-a.ts', `${authored}// test-only copy\n`, 'test'),
    analysisFile('test/fixture-b.ts', `${authored}// test-only copy\n`, 'test'),
    inconsistent
  ];
  const result = detectDuplicateFileCandidates(files);

  assert.equal(result.findings.length, 1);
  assert.deepEqual([result.findings[0]?.path, ...(result.findings[0]?.relatedPaths ?? [])], ['src/customer-a.ts', 'src/customer-b.ts']);
  assert(result.diagnostics.filter((entry) => entry.code === 'CLEANUP_DUPLICATE_GROUP_SUPPRESSED').length >= 2);
  assert(result.diagnostics.some((entry) => entry.code === 'CLEANUP_DUPLICATE_RECORD_CONTENT_MISMATCH'));
  assert(!canonicalJson(result).includes('normalizeCustomerRecord'));
});

test('literal platform/config references produce candidates only inside complete boundaries', () => {
  const workflow = analysisFile('.github/workflows/check.yml', [
    'jobs:',
    '  check:',
    '    steps:',
    '      - uses: ./.github/actions/live',
    '      - uses: ./.github/actions/gone',
    '      - uses: ${{ matrix.dynamic_action }}',
    '    defaults:',
    '      run:',
    '        working-directory: packages/missing',
    ''
  ].join('\n'));
  const terraform = analysisFile('infra/main.tf', [
    'module "live" {',
    '  source = "./modules/live"',
    '}',
    'module "gone" {',
    '  source = "./modules/gone"',
    '}',
    'locals {',
    '  rendered = templatefile(var.template_path, {})',
    '}',
    ''
  ].join('\n'));
  const blockWorkflow = analysisFile('.github/workflows/block.yml', [
    'jobs:',
    '  check:',
    '    steps:',
    '      - run: |',
    '          uses: ./.github/actions/embedded-only',
    '          echo "not workflow structure"',
    ''
  ].join('\n'));
  const files = [
    workflow,
    blockWorkflow,
    terraform,
    analysisFile('.github/actions/live/action.yml', 'name: live\nruns:\n  using: node20\n  main: index.js\n'),
    analysisFile('infra/modules/live/main.tf', 'output "ready" { value = true }\n')
  ];
  const skipped: DiagnosticRecord = {
    schemaVersion: SCHEMA_VERSION,
    id: 'diagnostic:fixture-skip',
    code: 'SYMLINK_SKIPPED',
    severity: 'warning',
    message: 'fixture',
    path: 'packages/missing',
    evidence: {
      level: 0,
      producer: 'atlas/test-fixture',
      producerVersion: '1',
      basis: 'fixture-boundary',
      path: 'packages/missing'
    }
  };
  const result = detectPlatformResidualCandidates(files, PROFILE, [skipped]);

  assert(result.findings.some((finding) => finding.ruleId === 'dead-code/stale-literal-platform-reference-v1' && finding.path === workflow.record.path));
  assert(result.findings.some((finding) => finding.ruleId === 'dead-code/stale-literal-platform-reference-v1' && finding.path === terraform.record.path));
  assert(!result.findings.some((finding) => finding.title.includes('working-directory')));
  assert(result.diagnostics.some((entry) => entry.code === 'CLEANUP_PLATFORM_DYNAMIC_REFERENCE'));
  assert(result.diagnostics.some((entry) => entry.code === 'CLEANUP_PLATFORM_REFERENCE_BOUNDARY_UNCERTAIN'));
  assert(result.diagnostics.some((entry) => entry.code === 'CLEANUP_PLATFORM_REFERENCE_UNCERTAIN'));
  assert(!result.findings.some((finding) => finding.title.includes('embedded-only')));
  assert(result.findings.every((finding) => finding.evidence.every((entry) => entry.path && entry.line && entry.column)));
  assert(!canonicalJson(result).includes('dynamic_action'));
});
