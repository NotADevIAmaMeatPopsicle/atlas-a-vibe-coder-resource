import path from 'node:path';
import ts from 'typescript';
import type {
  AnalysisFile,
  DiagnosticRecord,
  RelationshipRecord,
  ResolvedProfile
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesAnyGlob, matchesGlob } from '../util/paths.js';

export const REACHABILITY_ANALYSIS_VERSION = '1.2.1';

export type ReachabilityScope = 'production' | 'test' | 'build' | 'cli' | 'migration' | 'seeder';
export type ReachabilityLoaderKind =
  | 'sequelize-models'
  | 'migrations'
  | 'seeders'
  | 'routes'
  | 'package-scripts'
  | 'tests'
  | 'build'
  | 'cli'
  | 'custom';

export interface ReachabilityEntrypoint {
  path: string;
  origin:
    | 'profile'
    | 'package-main'
    | 'package-module'
    | 'package-bin'
    | 'package-script'
    | 'test-config'
    | 'build-config'
    | 'html-entry';
  scope: ReachabilityScope;
  sourcePath?: string;
}

export interface LoaderScopeCoverage {
  id: string;
  source: 'profile' | 'convention';
  kind: ReachabilityLoaderKind;
  scope: ReachabilityScope;
  loaderPaths: string[];
  loadedPatterns: string[];
  targetPaths: string[];
  relationshipIds: string[];
  state: 'complete' | 'incomplete' | 'inactive';
  reason?: string;
}

export interface ReachabilityPathContext {
  entrypointPaths: string[];
  scopes: ReachabilityScope[];
}

export interface ReachabilityResult {
  entrypoints: ReachabilityEntrypoint[];
  entrypointClosureEstablished: boolean;
  entrypointClosureScopes: ReadonlySet<ReachabilityScope>;
  reachablePaths: ReadonlySet<string>;
  runtimeInboundPaths: ReadonlySet<string>;
  gatedPaths: ReadonlySet<string>;
  pathContexts: ReadonlyMap<string, ReachabilityPathContext>;
  loaderScopes: LoaderScopeCoverage[];
  diagnostics: DiagnosticRecord[];
}

interface ProfileLoaderRule {
  id: string;
  kind: ReachabilityLoaderKind;
  loaderPaths: string[];
  loadedPatterns: string[];
  scope: ReachabilityScope;
  required: boolean;
}

interface PackageBoundary {
  path: string;
  root: string;
  manifest: Record<string, unknown>;
  scripts: Record<string, string>;
}

interface PendingLoaderScope {
  id: string;
  source: 'profile' | 'convention';
  kind: ReachabilityLoaderKind;
  scope: ReachabilityScope;
  loaderPaths: string[];
  loadedPatterns: string[];
  targetPaths: string[];
  relationshipIds: string[];
  externallyActivated: boolean;
  required: boolean;
  complete: boolean;
  reason?: string;
}

const EXTERNAL_LOADER_KINDS = new Set<ReachabilityLoaderKind>([
  'migrations',
  'seeders',
  'package-scripts',
  'tests',
  'build',
  'cli'
]);

const SCRIPT_FILE = /\.(?:[cm]?[jt]sx?|sh)$/u;
const JAVASCRIPT_TYPESCRIPT_FILE = /\.(?:[cm]?[jt]sx?)$/u;
const TEST_FILE = /(?:^|\/)(?:__tests__\/.*|[^/]+\.(?:test|spec)\.[cm]?[jt]sx?)$/u;

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort(compareCanonicalText);
}

function uniqueInOrder(values: Iterable<string>): string[] {
  return [...new Set(values)];
}

function directoryOf(filePath: string): string {
  const directory = path.posix.dirname(filePath);
  return directory === '.' ? '.' : directory;
}

function atOrBelow(filePath: string, root: string): boolean {
  return root === '.' || filePath === root || filePath.startsWith(`${root}/`);
}

function joinTargetPath(root: string, value: string): string | undefined {
  const portable = value.replaceAll('\\', '/').trim();
  if (!portable || portable.includes('\0') || /^[a-z][a-z0-9+.-]*:/iu.test(portable)) return undefined;
  const withoutRootSlash = portable.replace(/^\/+/, '').replace(/^\.\//u, '');
  const joined = path.posix.normalize(root === '.' ? withoutRootSlash : path.posix.join(root, withoutRootSlash));
  if (!joined || joined === '.' || joined === '..' || joined.startsWith('../') || path.posix.isAbsolute(joined)) return undefined;
  return joined.normalize('NFC');
}

function resolutionCandidates(root: string, value: string): string[] {
  const base = joinTargetPath(root, value);
  if (!base) return [];
  const extension = path.posix.extname(base);
  const values = [base];
  if (extension) {
    const stem = base.slice(0, -extension.length);
    if (/^\.[cm]?js$/u.test(extension)) {
      values.push(`${stem}.ts`, `${stem}.tsx`, `${stem}.mts`, `${stem}.cts`, `${stem}.jsx`);
    }
  } else {
    for (const candidateExtension of ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']) {
      values.push(`${base}${candidateExtension}`, `${base}/index${candidateExtension}`);
    }
  }
  return uniqueInOrder(values);
}

function resolveExistingPath(
  root: string,
  value: string,
  fileByPath: ReadonlyMap<string, AnalysisFile>
): string | undefined {
  return resolutionCandidates(root, value).find((candidate) => fileByPath.has(candidate));
}

function parseObject(content: Buffer): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(content.toString('utf8')) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function packageBoundaries(files: readonly AnalysisFile[]): PackageBoundary[] {
  return files
    .filter((file) => path.posix.basename(file.record.path) === 'package.json')
    .flatMap((file): PackageBoundary[] => {
      const manifest = parseObject(file.content);
      if (!manifest) return [];
      const rawScripts = manifest.scripts;
      const scripts: Record<string, string> = {};
      if (rawScripts && typeof rawScripts === 'object' && !Array.isArray(rawScripts)) {
        for (const [name, command] of Object.entries(rawScripts)) {
          if (typeof command === 'string') scripts[name.normalize('NFC')] = command.normalize('NFC');
        }
      }
      return [{ path: file.record.path, root: directoryOf(file.record.path), manifest, scripts }];
    })
    .sort((left, right) => compareCanonicalText(left.path, right.path));
}

function nearestPackageRoot(filePath: string, packages: readonly PackageBoundary[]): string {
  return packages
    .filter((candidate) => atOrBelow(filePath, candidate.root))
    .sort((left, right) => right.root.length - left.root.length || compareCanonicalText(left.root, right.root))[0]?.root ?? '.';
}

function ownedByPackage(filePath: string, owner: PackageBoundary, packages: readonly PackageBoundary[]): boolean {
  return nearestPackageRoot(filePath, packages) === owner.root;
}

function classifyScript(name: string, command: string): ReachabilityScope {
  const material = `${name} ${command}`.toLowerCase();
  if (/\b(?:test|spec|jest|vitest|playwright|mocha|ava)\b/u.test(material)) return 'test';
  if (/\b(?:build|bundle|compile|vite|rollup|webpack|esbuild)\b/u.test(material)) return 'build';
  if (/\b(?:migrat|sequelize[^\n]*db:migrate)\b/u.test(material)) return 'migration';
  if (/\b(?:seed|sequelize[^\n]*db:seed)\b/u.test(material)) return 'seeder';
  return 'cli';
}

function scriptPathTokens(command: string): string[] {
  const values: string[] = [];
  const tokenPattern = /"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s"'`;|&<>]+)/gu;
  for (const match of command.matchAll(tokenPattern)) {
    const token = (match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (!token || token.startsWith('-') || token.includes('$') || token.includes('*') || token.includes('?')) continue;
    const withoutPunctuation = token.replace(/[),]+$/u, '');
    if (/[,{[\]() }]/u.test(withoutPunctuation)) continue;
    if (SCRIPT_FILE.test(withoutPunctuation)) values.push(withoutPunctuation);
  }
  return sortedUnique(values);
}

function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string');
}

function expandBraces(pattern: string): string[] {
  const match = /\{([^{}]+)\}/u.exec(pattern);
  if (!match || match.index === undefined) return [pattern];
  const prefix = pattern.slice(0, match.index);
  const suffix = pattern.slice(match.index + match[0].length);
  return match[1]!.split(',').flatMap((choice) => expandBraces(`${prefix}${choice}${suffix}`));
}

function relativePatternMatches(filePath: string, root: string, pattern: string): boolean {
  const withoutRoot = pattern.replaceAll('\\', '/').replaceAll('<rootDir>/', '').replace(/^\.\//u, '').replace(/^\/+/, '');
  const rootedPatterns = expandBraces(withoutRoot).flatMap((entry) => {
    const candidate = root === '.' ? entry : `${root}/${entry}`;
    return candidate.includes('(') || candidate.includes(')') || candidate.includes('+')
      ? []
      : [candidate];
  });
  return rootedPatterns.some((candidate) => {
    try {
      return matchesGlob(filePath, candidate);
    } catch {
      return false;
    }
  });
}

function literalProperty(source: string, property: string): string | undefined {
  const expression = new RegExp(`(?:["']${property}["']|\\b${property})\\s*:\\s*(["'])([^"']+)\\1`, 'u');
  return expression.exec(source)?.[2];
}

function literalArrayProperty(source: string, property: string): string[] {
  const expression = new RegExp(`(?:["']${property}["']|\\b${property})\\s*:\\s*\\[([\\s\\S]*?)\\]`, 'gu');
  const values: string[] = [];
  for (const propertyMatch of source.matchAll(expression)) {
    for (const literal of propertyMatch[1]!.matchAll(/(["'])([^"']+)\1/gu)) values.push(literal[2]!);
  }
  return sortedUnique(values);
}

function propertyDeclared(source: string, property: string): boolean {
  return new RegExp(`(?:["']${property}["']|\\b${property})\\s*:`, 'u').test(source);
}

type TestRunner = 'jest' | 'vitest' | 'playwright' | 'unknown';

interface TestConfiguration {
  id: string;
  runner: TestRunner;
  source: string;
  rootPaths: string[];
  explicitRoot: boolean;
  boundaryKnown: boolean;
  patterns: string[];
  patternsDeclared: boolean;
  unsupportedReasons: string[];
}

function literalStringCollection(expression: ts.Expression): string[] | undefined {
  const value = unwrapConfigurationExpression(expression);
  if (ts.isStringLiteralLike(value)) return [value.text.normalize('NFC')];
  if (!ts.isArrayLiteralExpression(value)) return undefined;
  const strings = value.elements.map((element) => {
    const item = unwrapConfigurationExpression(element as ts.Expression);
    return ts.isStringLiteralLike(item) ? item.text.normalize('NFC') : undefined;
  });
  return strings.every((item): item is string => item !== undefined) ? sortedUnique(strings) : undefined;
}

function literalTestRoot(
  expression: ts.Expression,
  config: AnalysisFile,
  owner: PackageBoundary,
  pathBindings: ModuleBindings
): string | undefined {
  const value = unwrapConfigurationExpression(expression);
  if (ts.isStringLiteralLike(value)) {
    const configured = value.text.replaceAll('<rootDir>', '.');
    const base = value.text.includes('<rootDir>') ? owner.root : directoryOf(config.record.path);
    return joinTargetPath(base, configured);
  }
  if (
    !ts.isCallExpression(value) ||
    (!isBoundFunction(value.expression, pathBindings, 'join') && !isBoundFunction(value.expression, pathBindings, 'resolve')) ||
    value.arguments.length === 0
  ) return undefined;
  const segments: string[] = [];
  let base = owner.root;
  for (const [index, argument] of value.arguments.entries()) {
    if (identifierName(argument) === '__dirname') {
      if (index !== 0) return undefined;
      base = directoryOf(config.record.path);
      continue;
    }
    const item = unwrapConfigurationExpression(argument);
    if (!ts.isStringLiteralLike(item)) return undefined;
    segments.push(item.text);
  }
  return segments.length ? joinTargetPath(base, path.posix.join(...segments)) : undefined;
}

function testRunnerForConfig(filePath: string): TestRunner {
  const name = path.posix.basename(filePath);
  if (name.startsWith('jest')) return 'jest';
  if (name.startsWith('vitest') || name.startsWith('vite')) return 'vitest';
  if (name.startsWith('playwright')) return 'playwright';
  return 'unknown';
}

function fileTestConfiguration(
  owner: PackageBoundary,
  config: AnalysisFile,
  runnerOverride?: TestRunner
): TestConfiguration {
  const runner = runnerOverride ?? testRunnerForConfig(config.record.path);
  const unsupportedReasons: string[] = [];
  const parsedSource = parseBoundedTypeScript(
    config.record.path,
    config.content.toString('utf8'),
    scriptKind(config.record.path)
  );
  if (parsedSource.state === 'rejected') {
    return {
      id: conventionScopeId('tests-config', { packagePath: owner.path, configPath: config.record.path }),
      runner,
      source: config.record.path,
      rootPaths: [],
      explicitRoot: false,
      boundaryKnown: false,
      patterns: [],
      patternsDeclared: false,
      unsupportedReasons: [`${config.record.path} exceeded the JavaScript/TypeScript AST resource limit`]
    };
  }
  const sourceFile = parsedSource.sourceFile;
  const pathBindings = moduleBindings(sourceFile, new Set(['path', 'node:path']));
  const exported = exportedConfigurationObject(config);
  let object = exported;
  if (exported && runner === 'vitest') {
    const testProperties = namedConfigurationProperties(exported, 'test');
    if (testProperties.length === 1) {
      const nested = unwrapConfigurationExpression(testProperties[0]!.initializer);
      object = ts.isObjectLiteralExpression(nested) ? nested : undefined;
    } else if (path.posix.basename(config.record.path).startsWith('vite')) {
      object = undefined;
    }
  }
  if (!object) unsupportedReasons.push(`${config.record.path} does not expose one supported literal test configuration object`);
  if (object?.properties.some((property) => ts.isSpreadAssignment(property))) {
    unsupportedReasons.push(`${config.record.path} test configuration uses a spread property`);
  }

  const rootPaths: string[] = [];
  let explicitRoot = false;
  let boundaryKnown = Boolean(object);
  if (object) {
    for (const propertyName of ['testDir', 'roots']) {
      const properties = namedConfigurationProperties(object, propertyName);
      if (!properties.length) continue;
      explicitRoot = true;
      if (properties.length !== 1) {
        boundaryKnown = false;
        unsupportedReasons.push(`${config.record.path} declares ${propertyName} more than once`);
        continue;
      }
      const initializer = unwrapConfigurationExpression(properties[0]!.initializer);
      if (propertyName === 'roots' && ts.isArrayLiteralExpression(initializer)) {
        const resolved = initializer.elements.map((element) =>
          literalTestRoot(element as ts.Expression, config, owner, pathBindings)
        );
        if (resolved.some((entry) => entry === undefined) || !resolved.length) {
          boundaryKnown = false;
          unsupportedReasons.push(`${config.record.path} has non-literal or empty roots`);
        } else {
          rootPaths.push(...resolved as string[]);
        }
      } else {
        const resolved = literalTestRoot(initializer, config, owner, pathBindings);
        if (resolved) rootPaths.push(resolved);
        else {
          boundaryKnown = false;
          unsupportedReasons.push(`${config.record.path} has a non-literal ${propertyName}`);
        }
      }
    }
  }

  const patterns: string[] = [];
  let patternsDeclared = false;
  if (object) {
    for (const propertyName of ['testMatch', 'include']) {
      const properties = namedConfigurationProperties(object, propertyName);
      if (!properties.length) continue;
      patternsDeclared = true;
      if (properties.length !== 1) {
        unsupportedReasons.push(`${config.record.path} declares ${propertyName} more than once`);
        continue;
      }
      const values = literalStringCollection(properties[0]!.initializer);
      if (values?.length) patterns.push(...values);
      else unsupportedReasons.push(`${config.record.path} has a non-literal or empty ${propertyName}`);
    }
    for (const propertyName of ['testRegex', 'testPathIgnorePatterns', 'exclude', 'projects']) {
      if (namedConfigurationProperties(object, propertyName).length) {
        unsupportedReasons.push(`${config.record.path} uses unsupported ${propertyName}`);
      }
    }
  }
  return {
    id: conventionScopeId('tests-config', { packagePath: owner.path, configPath: config.record.path }),
    runner,
    source: config.record.path,
    rootPaths: sortedUnique(rootPaths),
    explicitRoot,
    boundaryKnown,
    patterns: sortedUnique(patterns),
    patternsDeclared,
    unsupportedReasons: sortedUnique(unsupportedReasons)
  };
}

function packageJestConfiguration(owner: PackageBoundary): TestConfiguration | undefined {
  const jest = owner.manifest.jest;
  if (!jest || typeof jest !== 'object' || Array.isArray(jest)) return undefined;
  const record = jest as Record<string, unknown>;
  const rootPaths: string[] = [];
  const unsupportedReasons: string[] = [];
  let explicitRoot = false;
  let boundaryKnown = true;
  if (Object.hasOwn(record, 'roots')) {
    explicitRoot = true;
    const values = strings(record.roots);
    const resolved = values.map((value) => joinTargetPath(owner.root, value.replaceAll('<rootDir>', '.')));
    if (!values.length || resolved.some((value) => value === undefined)) {
      boundaryKnown = false;
      unsupportedReasons.push(`${owner.path} has a non-literal Jest roots value`);
    } else {
      rootPaths.push(...resolved as string[]);
    }
  }
  const patternsDeclared = Object.hasOwn(record, 'testMatch');
  const patterns = patternsDeclared ? strings(record.testMatch) : [];
  if (patternsDeclared && !patterns.length) unsupportedReasons.push(`${owner.path} has a non-literal or empty Jest testMatch value`);
  if (Object.hasOwn(record, 'testRegex')) unsupportedReasons.push(`${owner.path} uses unsupported Jest testRegex`);
  if (Object.hasOwn(record, 'testPathIgnorePatterns')) unsupportedReasons.push(`${owner.path} uses unsupported Jest testPathIgnorePatterns`);
  return {
    id: conventionScopeId('tests-config', { packagePath: owner.path, configPath: owner.path, kind: 'inline-jest' }),
    runner: 'jest',
    source: owner.path,
    rootPaths: sortedUnique(rootPaths),
    explicitRoot,
    boundaryKnown,
    patterns: sortedUnique(patterns),
    patternsDeclared,
    unsupportedReasons: sortedUnique(unsupportedReasons)
  };
}

function testConfigurations(
  owner: PackageBoundary,
  ownedFiles: readonly AnalysisFile[]
): TestConfiguration[] {
  const configs = ownedFiles.filter((file) => {
    const name = path.posix.basename(file.record.path);
    return /^(?:jest|vitest|playwright)(?:\.[^.]+)?\.config\.[cm]?[jt]sx?$/u.test(name) ||
      (/^vite(?:\.[^.]+)?\.config\.[cm]?[jt]sx?$/u.test(name) && /\btest\s*:/u.test(file.content.toString('utf8')));
  });
  const values = configs.map((config) => fileTestConfiguration(owner, config));
  const packageJest = packageJestConfiguration(owner);
  if (packageJest) values.push(packageJest);
  return values.sort((left, right) => compareCanonicalText(left.source, right.source));
}

function scriptConfigPaths(command: string, owner: PackageBoundary): string[] {
  const values: string[] = [];
  const expression = /(?:^|\s)--config(?:=|\s+)(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"']+))/gu;
  for (const match of command.matchAll(expression)) {
    const configured = match[1] ?? match[2] ?? match[3];
    if (!configured) continue;
    const resolved = joinTargetPath(owner.root, configured);
    if (resolved) values.push(resolved);
  }
  return sortedUnique(values);
}

function testRunnerForCommand(command: string): TestRunner {
  if (/\bplaywright\b/u.test(command)) return 'playwright';
  if (/\bvitest\b/u.test(command)) return 'vitest';
  if (/\bjest\b/u.test(command)) return 'jest';
  return 'unknown';
}

function testConfigurationScope(
  configuration: TestConfiguration,
  owner: PackageBoundary,
  ownedFiles: readonly AnalysisFile[]
): { scope: PendingLoaderScope; matchedPaths: string[] } {
  const reasons = [...configuration.unsupportedReasons];
  const defaultRoot = configuration.source === owner.path || configuration.runner !== 'playwright'
    ? owner.root
    : directoryOf(configuration.source);
  const patternRoots = configuration.patterns.flatMap((pattern) => {
    const normalized = pattern.replaceAll('\\', '/').replaceAll('<rootDir>/', '').replace(/^\.\//u, '');
    const wildcard = normalized.search(/[?*()[\]{+!]/u);
    if (wildcard < 0) return [];
    const prefix = normalized.slice(0, wildcard).replace(/\/$/u, '');
    const directory = prefix.includes('/') ? prefix.slice(0, prefix.lastIndexOf('/')) : prefix;
    const resolved = directory ? joinTargetPath(owner.root, directory) : undefined;
    return resolved ? [resolved] : [];
  });
  const roots = configuration.boundaryKnown
    ? configuration.rootPaths.length
      ? configuration.rootPaths
      : patternRoots.length
        ? sortedUnique(patternRoots)
        : [defaultRoot]
    : [];
  const supportedPatterns = configuration.patterns.filter((pattern) =>
    !['(', ')', '[', ']', '+'].some((token) => pattern.includes(token)) && !pattern.startsWith('!')
  );
  const unsupportedPatterns = configuration.patterns.filter((pattern) => !supportedPatterns.includes(pattern));
  for (const pattern of unsupportedPatterns) reasons.push(`test pattern uses unsupported glob syntax: ${pattern}`);
  const candidateTestPaths = sortedUnique(ownedFiles
    .filter((file) => file.record.kind === 'test' || TEST_FILE.test(file.record.path))
    .filter((file) => roots.some((root) => atOrBelow(file.record.path, root)))
    .map((file) => file.record.path));
  const matchedPaths = candidateTestPaths.filter((filePath) => {
    if (!configuration.patternsDeclared) return true;
    if (!supportedPatterns.length) return false;
    return supportedPatterns.some((pattern) =>
      roots.some((root) => relativePatternMatches(filePath, root, pattern)) ||
      relativePatternMatches(filePath, owner.root, pattern)
    );
  });
  if (!matchedPaths.length) reasons.push(`the active test configuration ${configuration.source} resolved no included test entry`);
  const complete = reasons.length === 0;
  const boundedIncompleteTargets = configuration.boundaryKnown && (configuration.explicitRoot || patternRoots.length > 0)
    ? candidateTestPaths
    : configuration.boundaryKnown && configuration.patternsDeclared && supportedPatterns.length
      ? matchedPaths
      : [];
  return {
    scope: {
      id: configuration.id,
      source: 'convention',
      kind: 'tests',
      scope: 'test',
      loaderPaths: [configuration.source],
      loadedPatterns: configuration.patternsDeclared
        ? [...configuration.patterns]
        : ['**/__tests__/**', '**/*.test.*', '**/*.spec.*'],
      targetPaths: complete ? matchedPaths : boundedIncompleteTargets,
      relationshipIds: [],
      externallyActivated: true,
      required: true,
      complete,
      ...(reasons.length ? { reason: sortedUnique(reasons).join('; ') } : {})
    },
    matchedPaths
  };
}

function addEntrypoint(
  entries: ReachabilityEntrypoint[],
  fileByPath: ReadonlyMap<string, AnalysisFile>,
  entry: ReachabilityEntrypoint
): void {
  if (fileByPath.has(entry.path)) entries.push(entry);
}

function conventionScopeId(kind: string, material: unknown): string {
  return `convention:${kind}:${sha256(canonicalJson(material)).slice(0, 20)}`;
}

function discoverEntrypoints(
  files: readonly AnalysisFile[],
  profile: ResolvedProfile,
  packages: readonly PackageBoundary[],
  fileByPath: ReadonlyMap<string, AnalysisFile>,
  conventionScopes: PendingLoaderScope[]
): ReachabilityEntrypoint[] {
  const entries: ReachabilityEntrypoint[] = [];
  for (const file of files) {
    if (matchesAnyGlob(file.record.path, profile.entrypoints)) {
      addEntrypoint(entries, fileByPath, { path: file.record.path, origin: 'profile', scope: file.record.kind === 'test' ? 'test' : 'production' });
    }
  }

  for (const owner of packages) {
    for (const field of ['main', 'module'] as const) {
      const value = owner.manifest[field];
      if (value === undefined) continue;
      const resolved = typeof value === 'string' ? resolveExistingPath(owner.root, value, fileByPath) : undefined;
      if (resolved) {
        addEntrypoint(entries, fileByPath, {
          path: resolved,
          origin: field === 'main' ? 'package-main' : 'package-module',
          scope: 'production',
          sourcePath: owner.path
        });
      } else {
        conventionScopes.push({
          id: conventionScopeId(`package-${field}`, { packagePath: owner.path, value }),
          source: 'convention',
          kind: 'package-scripts',
          scope: 'production',
          loaderPaths: [owner.path],
          loadedPatterns: typeof value === 'string' ? [value.normalize('NFC')] : [],
          targetPaths: [],
          relationshipIds: [],
          externallyActivated: true,
          required: true,
          complete: false,
          reason: typeof value === 'string'
            ? `package ${field} did not resolve to an included file: ${value}`
            : `package ${field} is not a literal string`
        });
      }
    }

    const bin = owner.manifest.bin;
    const binEntries: Array<[string, unknown]> = typeof bin === 'string'
      ? [['default', bin]]
      : bin && typeof bin === 'object' && !Array.isArray(bin)
        ? Object.entries(bin).sort(([left], [right]) => compareCanonicalText(left, right))
        : bin === undefined
          ? []
          : [['default', bin]];
    for (const [name, value] of binEntries) {
      const resolved = typeof value === 'string' ? resolveExistingPath(owner.root, value, fileByPath) : undefined;
      if (resolved) {
        addEntrypoint(entries, fileByPath, {
          path: resolved,
          origin: 'package-bin',
          scope: 'cli',
          sourcePath: owner.path
        });
      } else {
        conventionScopes.push({
          id: conventionScopeId('package-bin', { packagePath: owner.path, name, value }),
          source: 'convention',
          kind: 'cli',
          scope: 'cli',
          loaderPaths: [owner.path],
          loadedPatterns: typeof value === 'string' ? [value.normalize('NFC')] : [],
          targetPaths: [],
          relationshipIds: [],
          externallyActivated: true,
          required: true,
          complete: false,
          reason: typeof value === 'string'
            ? `package bin ${name} did not resolve to an included file: ${value}`
            : `package bin ${name} is not a literal string`
        });
      }
    }

    for (const [name, command] of Object.entries(owner.scripts).sort(([left], [right]) => compareCanonicalText(left, right))) {
      for (const token of scriptPathTokens(command)) {
        const resolved = resolveExistingPath(owner.root, token, fileByPath);
        const scope = classifyScript(name, command);
        if (resolved) {
          addEntrypoint(entries, fileByPath, {
            path: resolved,
            origin: 'package-script',
            scope,
            sourcePath: owner.path
          });
        } else {
          conventionScopes.push({
            id: conventionScopeId('package-script', { packagePath: owner.path, name, token }),
            source: 'convention',
            kind: 'package-scripts',
            scope,
            loaderPaths: [owner.path],
            loadedPatterns: [token.normalize('NFC')],
            targetPaths: [],
            relationshipIds: [],
            externallyActivated: true,
            required: true,
            complete: false,
            reason: `package script ${name} references an included-file entry that did not resolve: ${token}`
          });
        }
      }
    }

    const ownedFiles = files.filter((file) => ownedByPackage(file.record.path, owner, packages));
    const availableTestConfigurations = testConfigurations(owner, ownedFiles);
    const activeTestConfigurations = new Map<string, TestConfiguration>();
    const testSelectionReasons: string[] = [];
    const testScripts = Object.entries(owner.scripts)
      .filter(([name, command]) => classifyScript(name, command) === 'test')
      .sort(([left], [right]) => compareCanonicalText(left, right));
    for (const [scriptName, command] of testScripts) {
      const runner = testRunnerForCommand(command);
      const configuredPaths = scriptConfigPaths(command, owner);
      const declaresConfig = /(?:^|\s)--config(?:=|\s+)/u.test(command);
      if (declaresConfig) {
        if (!configuredPaths.length) {
          testSelectionReasons.push(`package script ${scriptName} has a non-literal or unsupported --config path`);
          continue;
        }
        for (const configuredPath of configuredPaths) {
          let configuration = availableTestConfigurations.find((candidate) => candidate.source === configuredPath);
          if (!configuration) {
            const configuredFile = fileByPath.get(configuredPath);
            if (configuredFile) configuration = fileTestConfiguration(owner, configuredFile, runner);
          }
          if (configuration) activeTestConfigurations.set(configuration.id, configuration);
          else testSelectionReasons.push(`package script ${scriptName} --config path did not resolve to an included file: ${configuredPath}`);
        }
        continue;
      }

      let candidates = availableTestConfigurations.filter((configuration) => {
        if (configuration.runner !== runner) return false;
        if (configuration.source === owner.path) return runner === 'jest';
        const name = path.posix.basename(configuration.source);
        return name.startsWith(`${runner}.config.`);
      });
      if (runner === 'vitest' && !candidates.length) {
        candidates = availableTestConfigurations.filter((configuration) =>
          configuration.runner === 'vitest' && path.posix.basename(configuration.source).startsWith('vite.config.')
        );
      }
      if (runner === 'unknown') {
        candidates = availableTestConfigurations.filter((configuration) => {
          if (configuration.source === owner.path) return true;
          return /^(?:jest|vitest|playwright|vite)\.config\.[cm]?[jt]sx?$/u.test(path.posix.basename(configuration.source));
        });
      }
      if (candidates.length === 1) {
        activeTestConfigurations.set(candidates[0]!.id, candidates[0]!);
      } else if (candidates.length > 1) {
        testSelectionReasons.push(`package script ${scriptName} has multiple possible default test configurations; use a literal --config path`);
      } else {
        const synthetic: TestConfiguration = {
          id: conventionScopeId('tests-default', { packagePath: owner.path, scriptName, runner }),
          runner,
          source: owner.path,
          rootPaths: [],
          explicitRoot: false,
          boundaryKnown: true,
          patterns: [],
          patternsDeclared: false,
          unsupportedReasons: []
        };
        activeTestConfigurations.set(synthetic.id, synthetic);
      }
    }

    for (const configuration of [...activeTestConfigurations.values()].sort((left, right) =>
      compareCanonicalText(left.source, right.source) || compareCanonicalText(left.id, right.id)
    )) {
      if (configuration.source !== owner.path && !path.posix.basename(configuration.source).startsWith('vite.config.')) {
        addEntrypoint(entries, fileByPath, {
          path: configuration.source,
          origin: 'test-config',
          scope: 'test',
          sourcePath: owner.path
        });
      }
      const evaluated = testConfigurationScope(configuration, owner, ownedFiles);
      if (evaluated.scope.complete) {
        for (const filePath of evaluated.matchedPaths) {
          addEntrypoint(entries, fileByPath, {
            path: filePath,
            origin: 'test-config',
            scope: 'test',
            sourcePath: configuration.source
          });
        }
      }
      conventionScopes.push(evaluated.scope);
    }
    if (testSelectionReasons.length) {
      conventionScopes.push({
        id: conventionScopeId('tests-selection', { packagePath: owner.path, reasons: sortedUnique(testSelectionReasons) }),
        source: 'convention',
        kind: 'tests',
        scope: 'test',
        loaderPaths: [owner.path],
        loadedPatterns: [],
        targetPaths: [],
        relationshipIds: [],
        externallyActivated: true,
        required: true,
        complete: false,
        reason: sortedUnique(testSelectionReasons).join('; ')
      });
    }

    const buildScripts = Object.entries(owner.scripts).filter(([name, command]) => classifyScript(name, command) === 'build');
    const buildConfigs = ownedFiles.filter((file) => /^(?:vite|rollup|webpack)(?:\.[^.]+)?\.config\.[cm]?[jt]sx?$/u.test(path.posix.basename(file.record.path)));
    if (buildScripts.length || buildConfigs.length) {
      const buildReasons: string[] = [];
      const buildPatterns: string[] = [];
      const buildTargets: string[] = [];
      for (const [, command] of buildScripts) {
        for (const token of scriptPathTokens(command)) {
          buildPatterns.push(token);
          const resolved = resolveExistingPath(owner.root, token, fileByPath);
          if (resolved) buildTargets.push(resolved);
        }
      }
      for (const config of buildConfigs) {
        addEntrypoint(entries, fileByPath, {
          path: config.record.path,
          origin: 'build-config',
          scope: 'build',
          sourcePath: owner.path
        });
        const source = config.content.toString('utf8');
        const literalEntries = [
          ...literalArrayProperty(source, 'entry'),
          ...literalArrayProperty(source, 'input')
        ];
        for (const property of ['entry', 'input']) {
          const literal = literalProperty(source, property);
          if (literal) literalEntries.push(literal);
          if (propertyDeclared(source, property) && !literal && !literalArrayProperty(source, property).length) {
            buildReasons.push(`${config.record.path} has a non-literal or unsupported ${property} entry`);
          }
        }
        for (const value of sortedUnique(literalEntries)) {
          buildPatterns.push(value);
          const resolved = resolveExistingPath(owner.root, value, fileByPath);
          if (resolved) {
            buildTargets.push(resolved);
            addEntrypoint(entries, fileByPath, {
              path: resolved,
              origin: 'build-config',
              scope: 'build',
              sourcePath: config.record.path
            });
          } else {
            buildReasons.push(`${config.record.path} build entry did not resolve to an included file: ${value}`);
          }
        }
      }
      for (const html of ownedFiles.filter((file) => path.posix.basename(file.record.path) === 'index.html')) {
        buildPatterns.push(html.record.path);
        buildTargets.push(html.record.path);
        addEntrypoint(entries, fileByPath, {
          path: html.record.path,
          origin: 'html-entry',
          scope: 'build',
          sourcePath: owner.path
        });
        const source = html.content.toString('utf8');
        for (const match of source.matchAll(/<script\b[^>]*\bsrc\s*=\s*(["'])([^"']+)\1/giu)) {
          const value = match[2]!;
          buildPatterns.push(value);
          const resolved = resolveExistingPath(owner.root, value, fileByPath);
          if (resolved) {
            buildTargets.push(resolved);
            addEntrypoint(entries, fileByPath, {
              path: resolved,
              origin: 'html-entry',
              scope: 'build',
              sourcePath: html.record.path
            });
          } else if (!/^[a-z][a-z0-9+.-]*:/iu.test(value) && !value.startsWith('//')) {
            buildReasons.push(`${html.record.path} script entry did not resolve to an included file: ${value}`);
          }
        }
      }
      const targetPaths = sortedUnique(buildTargets);
      if (!targetPaths.length) buildReasons.push('the active build configuration or script resolved no included build entry');
      const complete = buildReasons.length === 0;
      conventionScopes.push({
        id: conventionScopeId('build', {
          packagePath: owner.path,
          scripts: buildScripts.map(([name]) => name),
          configs: buildConfigs.map((config) => config.record.path)
        }),
        source: 'convention',
        kind: 'build',
        scope: 'build',
        loaderPaths: sortedUnique([owner.path, ...buildConfigs.map((config) => config.record.path)]),
        loadedPatterns: sortedUnique(buildPatterns),
        targetPaths,
        relationshipIds: [],
        externallyActivated: true,
        required: true,
        complete,
        ...(buildReasons.length ? { reason: sortedUnique(buildReasons).join('; ') } : {})
      });
    }
  }

  return [...new Map(entries
    .sort((left, right) =>
      compareCanonicalText(left.path, right.path) ||
      compareCanonicalText(left.origin, right.origin) ||
      compareCanonicalText(left.scope, right.scope) ||
      compareCanonicalText(left.sourcePath ?? '', right.sourcePath ?? '')
    )
    .map((entry) => [`${entry.path}\0${entry.origin}\0${entry.scope}\0${entry.sourcePath ?? ''}`, entry])).values()];
}

function profileLoaderRules(profile: ResolvedProfile): ProfileLoaderRule[] {
  const value = (profile as ResolvedProfile & { loaderRules?: ProfileLoaderRule[] }).loaderRules;
  return Array.isArray(value) ? [...value].sort((left, right) => compareCanonicalText(left.id, right.id)) : [];
}

function configuredLoaderScopes(
  files: readonly AnalysisFile[],
  relationships: readonly RelationshipRecord[],
  profile: ResolvedProfile
): PendingLoaderScope[] {
  return profileLoaderRules(profile).map((rule) => {
    const unmatchedLoaderPatterns = rule.loaderPaths.filter((pattern) =>
      !files.some((file) => matchesAnyGlob(file.record.path, [pattern]))
    );
    const unmatchedLoadedPatterns = rule.loadedPatterns.filter((pattern) =>
      !files.some((file) => matchesAnyGlob(file.record.path, [pattern]))
    );
    const loaderPaths = sortedUnique(files
      .filter((file) => matchesAnyGlob(file.record.path, rule.loaderPaths))
      .map((file) => file.record.path));
    const targetPaths = sortedUnique(files
      .filter((file) => matchesAnyGlob(file.record.path, rule.loadedPatterns))
      .map((file) => file.record.path));
    const relationshipIds = sortedUnique(relationships
      .filter((relationship) => loaderPaths.includes(relationship.fromPath) && isUnsupportedNonLiteralModuleLoad(relationship))
      .map((relationship) => relationship.id));
    const missing: string[] = [];
    for (const pattern of unmatchedLoaderPatterns) missing.push(`loader path pattern matched no files: ${pattern}`);
    for (const pattern of unmatchedLoadedPatterns) missing.push(`loaded target pattern matched no files: ${pattern}`);
    return {
      id: rule.id,
      source: 'profile',
      kind: rule.kind,
      scope: rule.scope,
      loaderPaths,
      loadedPatterns: [...rule.loadedPatterns].sort(compareCanonicalText),
      targetPaths,
      relationshipIds,
      externallyActivated: EXTERNAL_LOADER_KINDS.has(rule.kind),
      required: rule.required,
      complete: missing.length === 0,
      ...(missing.length ? { reason: missing.join('; ') } : {})
    };
  });
}

interface ModuleBindings {
  namespaces: ReadonlySet<string>;
  functions: ReadonlyMap<string, ReadonlySet<string>>;
}

type ModelPredicateValue = boolean | number | string;

interface ModelFilter {
  expression: ts.Expression;
  parameterName: string;
}

interface ModelRegistryChain {
  filters: ModelFilter[];
  loadCalls: ts.CallExpression[];
  bindingsVerified: boolean;
}

function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (filePath.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (/\.(?:ts|mts|cts)$/u.test(filePath)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function moduleSpecifier(node: ts.Expression | undefined): string | undefined {
  return node && ts.isStringLiteralLike(node) ? node.text : undefined;
}

function requiredModule(node: ts.Expression | undefined): string | undefined {
  if (!node || !ts.isCallExpression(node) || node.arguments.length !== 1) return undefined;
  if (!ts.isIdentifier(node.expression) || node.expression.text !== 'require') return undefined;
  return moduleSpecifier(node.arguments[0]);
}

function moduleBindings(sourceFile: ts.SourceFile, moduleNames: ReadonlySet<string>): ModuleBindings {
  const namespaces = new Set<string>();
  const mutableFunctions = new Map<string, Set<string>>();
  const addFunction = (exportedName: string, localName: string): void => {
    const values = mutableFunctions.get(exportedName) ?? new Set<string>();
    values.add(localName);
    mutableFunctions.set(exportedName, values);
  };

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && moduleNames.has(moduleSpecifier(statement.moduleSpecifier) ?? '')) {
      const clause = statement.importClause;
      if (clause?.name) namespaces.add(clause.name.text);
      if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
        namespaces.add(clause.namedBindings.name.text);
      } else if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          addFunction(element.propertyName?.text ?? element.name.text, element.name.text);
        }
      }
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      const required = requiredModule(declaration.initializer);
      if (!required || !moduleNames.has(required)) continue;
      if (ts.isIdentifier(declaration.name)) {
        namespaces.add(declaration.name.text);
        continue;
      }
      if (!ts.isObjectBindingPattern(declaration.name)) continue;
      for (const element of declaration.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const exportedName = element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : element.name.text;
        addFunction(exportedName, element.name.text);
      }
    }
  }

  return {
    namespaces,
    functions: new Map([...mutableFunctions].map(([name, values]) => [name, values as ReadonlySet<string>]))
  };
}

function isBoundFunction(expression: ts.Expression, bindings: ModuleBindings, name: string): boolean {
  if (ts.isIdentifier(expression)) return bindings.functions.get(name)?.has(expression.text) === true;
  return ts.isPropertyAccessExpression(expression) &&
    ts.isIdentifier(expression.expression) &&
    bindings.namespaces.has(expression.expression.text) &&
    expression.name.text === name;
}

function isNamedFunction(expression: ts.Expression, name: string): boolean {
  return (ts.isIdentifier(expression) && expression.text === name) ||
    (ts.isPropertyAccessExpression(expression) && expression.name.text === name);
}

function identifierName(expression: ts.Expression): string | undefined {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current)) {
    current = current.expression;
  }
  return ts.isIdentifier(current) ? current.text : undefined;
}

function callbackFilter(node: ts.Expression | undefined): ModelFilter | undefined {
  if (!node || (!ts.isArrowFunction(node) && !ts.isFunctionExpression(node))) return undefined;
  if (node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)) return undefined;
  if (node.asteriskToken || node.parameters.length !== 1) return undefined;
  const parameter = node.parameters[0];
  if (!parameter || !ts.isIdentifier(parameter.name) || parameter.initializer || parameter.dotDotDotToken) return undefined;
  if (!ts.isBlock(node.body)) return { expression: node.body, parameterName: parameter.name.text };
  if (node.body.statements.length !== 1) return undefined;
  const statement = node.body.statements[0];
  if (!statement || !ts.isReturnStatement(statement) || !statement.expression) return undefined;
  return { expression: statement.expression, parameterName: parameter.name.text };
}

function staticModelBindings(
  sourceFile: ts.SourceFile,
  loaderBasename: string,
  pathBindings: ModuleBindings
): ReadonlyMap<string, ModelPredicateValue> {
  const values = new Map<string, ModelPredicateValue>();
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const initializer = declaration.initializer;
      if (ts.isStringLiteralLike(initializer)) {
        values.set(declaration.name.text, initializer.text);
      } else if (ts.isNumericLiteral(initializer)) {
        values.set(declaration.name.text, Number(initializer.text));
      } else if (
        ts.isCallExpression(initializer) &&
        isBoundFunction(initializer.expression, pathBindings, 'basename') &&
        initializer.arguments.length === 1 &&
        identifierName(initializer.arguments[0]!) === '__filename'
      ) {
        values.set(declaration.name.text, loaderBasename);
      }
    }
  }
  return values;
}

function staticString(
  expression: ts.Expression,
  bindings: ReadonlyMap<string, ModelPredicateValue>
): string | undefined {
  if (ts.isStringLiteralLike(expression)) return expression.text;
  const name = identifierName(expression);
  const value = name ? bindings.get(name) : undefined;
  return typeof value === 'string' ? value : undefined;
}

function evaluateModelPredicate(
  expression: ts.Expression,
  parameterName: string,
  fileName: string,
  loaderBasename: string,
  bindings: ReadonlyMap<string, ModelPredicateValue>,
  pathBindings: ModuleBindings
): { supported: boolean; value?: ModelPredicateValue } {
  if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)) {
    return evaluateModelPredicate(expression.expression, parameterName, fileName, loaderBasename, bindings, pathBindings);
  }
  if (ts.isStringLiteralLike(expression)) return { supported: true, value: expression.text };
  if (ts.isNumericLiteral(expression)) return { supported: true, value: Number(expression.text) };
  if (expression.kind === ts.SyntaxKind.TrueKeyword) return { supported: true, value: true };
  if (expression.kind === ts.SyntaxKind.FalseKeyword) return { supported: true, value: false };
  if (ts.isIdentifier(expression)) {
    if (expression.text === parameterName) return { supported: true, value: fileName };
    const value = bindings.get(expression.text);
    return value === undefined ? { supported: false } : { supported: true, value };
  }
  if (ts.isPrefixUnaryExpression(expression)) {
    const operand = evaluateModelPredicate(expression.operand, parameterName, fileName, loaderBasename, bindings, pathBindings);
    if (!operand.supported) return { supported: false };
    if (expression.operator === ts.SyntaxKind.ExclamationToken && typeof operand.value === 'boolean') {
      return { supported: true, value: !operand.value };
    }
    if (expression.operator === ts.SyntaxKind.MinusToken && typeof operand.value === 'number') {
      return { supported: true, value: -operand.value };
    }
    return { supported: false };
  }
  if (ts.isPropertyAccessExpression(expression) && expression.name.text === 'length') {
    const owner = evaluateModelPredicate(expression.expression, parameterName, fileName, loaderBasename, bindings, pathBindings);
    return owner.supported && typeof owner.value === 'string'
      ? { supported: true, value: owner.value.length }
      : { supported: false };
  }
  if (ts.isCallExpression(expression)) {
    if (isBoundFunction(expression.expression, pathBindings, 'basename') && expression.arguments.length === 1) {
      const argument = identifierName(expression.arguments[0]!);
      return argument === '__filename'
        ? { supported: true, value: loaderBasename }
        : { supported: false };
    }
    if (isBoundFunction(expression.expression, pathBindings, 'extname') && expression.arguments.length === 1) {
      const argument = evaluateModelPredicate(expression.arguments[0]!, parameterName, fileName, loaderBasename, bindings, pathBindings);
      return argument.supported && typeof argument.value === 'string'
        ? { supported: true, value: path.posix.extname(argument.value) }
        : { supported: false };
    }
    if (!ts.isPropertyAccessExpression(expression.expression)) return { supported: false };
    const receiver = evaluateModelPredicate(expression.expression.expression, parameterName, fileName, loaderBasename, bindings, pathBindings);
    const argumentsList = expression.arguments.map((argument) =>
      evaluateModelPredicate(argument, parameterName, fileName, loaderBasename, bindings, pathBindings)
    );
    if (!receiver.supported || argumentsList.some((argument) => !argument.supported)) return { supported: false };
    const values = argumentsList.map((argument) => argument.value);
    if (typeof receiver.value !== 'string') return { supported: false };
    switch (expression.expression.name.text) {
      case 'endsWith':
        return typeof values[0] === 'string' && values.length === 1
          ? { supported: true, value: receiver.value.endsWith(values[0]) }
          : { supported: false };
      case 'startsWith':
        return typeof values[0] === 'string' && values.length === 1
          ? { supported: true, value: receiver.value.startsWith(values[0]) }
          : { supported: false };
      case 'includes':
        return typeof values[0] === 'string' && values.length === 1
          ? { supported: true, value: receiver.value.includes(values[0]) }
          : { supported: false };
      case 'indexOf':
        return typeof values[0] === 'string' && values.length === 1
          ? { supported: true, value: receiver.value.indexOf(values[0]) }
          : { supported: false };
      case 'slice':
        return typeof values[0] === 'number' && values.length <= 2 && (values[1] === undefined || typeof values[1] === 'number')
          ? { supported: true, value: receiver.value.slice(values[0], values[1] as number | undefined) }
          : { supported: false };
      default:
        return { supported: false };
    }
  }
  if (ts.isBinaryExpression(expression)) {
    const left = evaluateModelPredicate(expression.left, parameterName, fileName, loaderBasename, bindings, pathBindings);
    const right = evaluateModelPredicate(expression.right, parameterName, fileName, loaderBasename, bindings, pathBindings);
    if (!left.supported || !right.supported) return { supported: false };
    switch (expression.operatorToken.kind) {
      case ts.SyntaxKind.AmpersandAmpersandToken:
        return typeof left.value === 'boolean' && typeof right.value === 'boolean'
          ? { supported: true, value: left.value && right.value }
          : { supported: false };
      case ts.SyntaxKind.BarBarToken:
        return typeof left.value === 'boolean' && typeof right.value === 'boolean'
          ? { supported: true, value: left.value || right.value }
          : { supported: false };
      case ts.SyntaxKind.EqualsEqualsEqualsToken:
      case ts.SyntaxKind.EqualsEqualsToken:
        return { supported: true, value: left.value === right.value };
      case ts.SyntaxKind.ExclamationEqualsEqualsToken:
      case ts.SyntaxKind.ExclamationEqualsToken:
        return { supported: true, value: left.value !== right.value };
      case ts.SyntaxKind.LessThanToken:
        if (typeof left.value === 'string' && typeof right.value === 'string') return { supported: true, value: left.value < right.value };
        if (typeof left.value === 'number' && typeof right.value === 'number') return { supported: true, value: left.value < right.value };
        return { supported: false };
      case ts.SyntaxKind.LessThanEqualsToken:
        if (typeof left.value === 'string' && typeof right.value === 'string') return { supported: true, value: left.value <= right.value };
        if (typeof left.value === 'number' && typeof right.value === 'number') return { supported: true, value: left.value <= right.value };
        return { supported: false };
      case ts.SyntaxKind.GreaterThanToken:
        if (typeof left.value === 'string' && typeof right.value === 'string') return { supported: true, value: left.value > right.value };
        if (typeof left.value === 'number' && typeof right.value === 'number') return { supported: true, value: left.value > right.value };
        return { supported: false };
      case ts.SyntaxKind.GreaterThanEqualsToken:
        if (typeof left.value === 'string' && typeof right.value === 'string') return { supported: true, value: left.value >= right.value };
        if (typeof left.value === 'number' && typeof right.value === 'number') return { supported: true, value: left.value >= right.value };
        return { supported: false };
      default:
        return { supported: false };
    }
  }
  return { supported: false };
}

function isSupportedExtension(value: string | undefined): value is string {
  return value !== undefined && /^\.[cm]?[jt]sx?$/u.test(value);
}

function modelPredicateConstrainsExtension(
  expression: ts.Expression,
  parameterName: string,
  bindings: ReadonlyMap<string, ModelPredicateValue>,
  pathBindings: ModuleBindings
): boolean {
  if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)) {
    return modelPredicateConstrainsExtension(expression.expression, parameterName, bindings, pathBindings);
  }
  if (ts.isBinaryExpression(expression)) {
    if (expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
      return modelPredicateConstrainsExtension(expression.left, parameterName, bindings, pathBindings) ||
        modelPredicateConstrainsExtension(expression.right, parameterName, bindings, pathBindings);
    }
    if (expression.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
      return modelPredicateConstrainsExtension(expression.left, parameterName, bindings, pathBindings) &&
        modelPredicateConstrainsExtension(expression.right, parameterName, bindings, pathBindings);
    }
    if (
      expression.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
      expression.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsToken
    ) return false;
    const pairs: Array<[ts.Expression, ts.Expression]> = [[expression.left, expression.right], [expression.right, expression.left]];
    return pairs.some(([candidate, literal]) => {
      if (!isSupportedExtension(staticString(literal, bindings)) || !ts.isCallExpression(candidate)) return false;
      if (isBoundFunction(candidate.expression, pathBindings, 'extname')) {
        return candidate.arguments.length === 1 && identifierName(candidate.arguments[0]!) === parameterName;
      }
      return ts.isPropertyAccessExpression(candidate.expression) &&
        candidate.expression.name.text === 'slice' &&
        identifierName(candidate.expression.expression) === parameterName;
    });
  }
  if (!ts.isCallExpression(expression) || !ts.isPropertyAccessExpression(expression.expression)) return false;
  return expression.expression.name.text === 'endsWith' &&
    identifierName(expression.expression.expression) === parameterName &&
    expression.arguments.length === 1 &&
    isSupportedExtension(staticString(expression.arguments[0]!, bindings));
}

function siblingLoadCalls(
  callback: ts.Expression | undefined,
  pathBindings: ModuleBindings,
  requireVerifiedBindings: boolean
): ts.CallExpression[] {
  if (!callback || (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))) return [];
  if (callback.parameters.length !== 1 || !ts.isIdentifier(callback.parameters[0]!.name)) return [];
  const parameterName = callback.parameters[0]!.name.text;
  const matches: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (node !== callback && (ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node))) return;
    if (ts.isCallExpression(node)) {
      const isLoad = (ts.isIdentifier(node.expression) && node.expression.text === 'require') ||
        node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const argument = node.arguments[0];
      if (isLoad && node.arguments.length === 1 && argument && ts.isCallExpression(argument)) {
        const pathCall = requireVerifiedBindings
          ? (isBoundFunction(argument.expression, pathBindings, 'join') || isBoundFunction(argument.expression, pathBindings, 'resolve'))
          : (isNamedFunction(argument.expression, 'join') || isNamedFunction(argument.expression, 'resolve'));
        if (
          pathCall && argument.arguments.length === 2 &&
          identifierName(argument.arguments[0]!) === '__dirname' &&
          identifierName(argument.arguments[1]!) === parameterName
        ) matches.push(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(callback.body);
  return matches;
}

function registryChains(
  sourceFile: ts.SourceFile,
  fsBindings: ModuleBindings,
  pathBindings: ModuleBindings
): ModelRegistryChain[] {
  const chains: ModelRegistryChain[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const looselyEnumerates = isNamedFunction(node.expression, 'readdirSync') &&
        node.arguments.length >= 1 && identifierName(node.arguments[0]!) === '__dirname';
      if (looselyEnumerates) {
        const strictlyEnumerates = isBoundFunction(node.expression, fsBindings, 'readdirSync') && node.arguments.length === 1;
        const filters: ModelFilter[] = [];
        const loadCalls: ts.CallExpression[] = [];
        let bindingsVerified = strictlyEnumerates;
        let current: ts.Expression = node;
        while (
          ts.isPropertyAccessExpression(current.parent) && current.parent.expression === current &&
          ts.isCallExpression(current.parent.parent) && current.parent.parent.expression === current.parent
        ) {
          const chainedCall = current.parent.parent;
          const method = current.parent.name.text;
          if (method === 'filter') {
            const filter = callbackFilter(chainedCall.arguments[0]);
            if (filter) filters.push(filter);
            else bindingsVerified = false;
          } else if (method === 'forEach' || method === 'map') {
            const strictLoads = siblingLoadCalls(chainedCall.arguments[0], pathBindings, true);
            const looseLoads = siblingLoadCalls(chainedCall.arguments[0], pathBindings, false);
            if (looseLoads.length) {
              loadCalls.push(...looseLoads);
              if (!strictLoads.length || strictLoads.length !== looseLoads.length) bindingsVerified = false;
            }
          }
          current = chainedCall;
        }
        if (loadCalls.length) chains.push({ filters, loadCalls, bindingsVerified });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return chains;
}

function relationshipIdsAtCalls(
  loaderPath: string,
  sourceFile: ts.SourceFile,
  calls: readonly ts.CallExpression[],
  relationships: readonly RelationshipRecord[]
): string[] {
  const locations = new Set(calls.map((call) => {
    const start = sourceFile.getLineAndCharacterOfPosition(call.getStart(sourceFile));
    return `${start.line + 1}:${start.character + 1}`;
  }));
  return sortedUnique(relationships
    .filter((relationship) =>
      relationship.fromPath === loaderPath &&
      isUnsupportedNonLiteralModuleLoad(relationship) &&
      locations.has(`${relationship.location.line}:${relationship.location.column}`)
    )
    .map((relationship) => relationship.id));
}

function siblingRegistryScopes(
  files: readonly AnalysisFile[],
  relationships: readonly RelationshipRecord[],
  descriptor: {
    loaderPattern: RegExp;
    id: 'sequelize-models' | 'routes';
    kind: 'sequelize-models' | 'routes';
    scope: 'production';
    targetLabel: string;
  }
): PendingLoaderScope[] {
  const scopes: PendingLoaderScope[] = [];
  for (const loader of files) {
    if (
      !descriptor.loaderPattern.test(loader.record.path) ||
      loader.record.kind === 'test' ||
      /(?:^|\/)(?:tests?|__tests__|fixtures|e2e)(?:\/|$)/u.test(loader.record.path) ||
      /^(?:corpus|docs|examples|reference)(?:\/|$)/u.test(loader.record.path) ||
      loader.record.lifecycle?.state === 'mothballed'
    ) continue;
    const source = loader.content.toString('utf8');
    const parsedSource = parseBoundedTypeScript(loader.record.path, source, scriptKind(loader.record.path));
    if (parsedSource.state === 'rejected') continue;
    const sourceFile = parsedSource.sourceFile;
    const fsBindings = moduleBindings(sourceFile, new Set(['fs', 'node:fs']));
    const pathBindings = moduleBindings(sourceFile, new Set(['path', 'node:path']));
    const chains = registryChains(sourceFile, fsBindings, pathBindings);
    if (!chains.length) continue;
    const directory = directoryOf(loader.record.path);
    const siblingFiles = files.filter((file) =>
      directoryOf(file.record.path) === directory &&
      file.record.path !== loader.record.path &&
      JAVASCRIPT_TYPESCRIPT_FILE.test(file.record.path) &&
      !/\.d\.[cm]?ts$/u.test(file.record.path)
    );
    const loaderBasename = path.posix.basename(loader.record.path);
    const bindings = staticModelBindings(sourceFile, loaderBasename, pathBindings);
    let selectedChain: ModelRegistryChain | undefined;
    let targetPaths: string[] = [];
    let reason = 'the registry predicate could not be bound to the enumerated sibling filename';
    for (const chain of chains) {
      if (!chain.bindingsVerified) {
        reason = 'the fs/path bindings for the sibling registry were not statically established';
        continue;
      }
      if (!chain.filters.length) {
        reason = 'the sibling extension predicate and loader self-exclusion were not statically established';
        continue;
      }
      const extensionBound = chain.filters.some((filter) =>
        modelPredicateConstrainsExtension(filter.expression, filter.parameterName, bindings, pathBindings)
      );
      if (!extensionBound) {
        reason = 'the sibling extension predicate was not statically understood';
        continue;
      }
      const evaluated = siblingFiles.map((file) => {
        const basename = path.posix.basename(file.record.path);
        const values = chain.filters.map((filter) =>
          evaluateModelPredicate(filter.expression, filter.parameterName, basename, loaderBasename, bindings, pathBindings)
        );
        return {
          path: file.record.path,
          supported: values.every((value) => value.supported && typeof value.value === 'boolean'),
          selected: values.every((value) => value.value === true)
        };
      });
      const selfValues = chain.filters.map((filter) =>
        evaluateModelPredicate(filter.expression, filter.parameterName, loaderBasename, loaderBasename, bindings, pathBindings)
      );
      if (
        evaluated.some((entry) => !entry.supported) ||
        selfValues.some((value) => !value.supported || typeof value.value !== 'boolean')
      ) {
        reason = 'the sibling filter uses an unsupported or ambiguous expression';
        continue;
      }
      if (selfValues.every((value) => value.value === true)) {
        reason = 'the loader self-exclusion was not statically established';
        continue;
      }
      const selectedPaths = sortedUnique(evaluated.filter((entry) => entry.selected).map((entry) => entry.path));
      if (!selectedPaths.length) {
        reason = `no sibling ${descriptor.targetLabel} target matched the understood predicate`;
        continue;
      }
      selectedChain = chain;
      targetPaths = selectedPaths;
      break;
    }
    const complete = selectedChain !== undefined;
    const relationshipCalls = selectedChain?.loadCalls ?? chains.flatMap((chain) => chain.loadCalls);
    scopes.push({
      id: `convention:${descriptor.id}:${loader.record.path}`,
      source: 'convention',
      kind: descriptor.kind,
      scope: descriptor.scope,
      loaderPaths: [loader.record.path],
      loadedPatterns: [`${directory}/*`],
      targetPaths: complete ? targetPaths : sortedUnique(siblingFiles.map((file) => file.record.path)),
      relationshipIds: relationshipIdsAtCalls(loader.record.path, sourceFile, relationshipCalls, relationships),
      externallyActivated: false,
      required: true,
      complete,
      ...(!complete ? { reason } : {})
    });
  }
  return scopes;
}

function sequelizeModelScopes(
  files: readonly AnalysisFile[],
  relationships: readonly RelationshipRecord[]
): PendingLoaderScope[] {
  return siblingRegistryScopes(files, relationships, {
    loaderPattern: /(?:^|\/)models\/index\.[cm]?[jt]sx?$/u,
    id: 'sequelize-models',
    kind: 'sequelize-models',
    scope: 'production',
    targetLabel: 'model'
  });
}

function routeRegistryScopes(
  files: readonly AnalysisFile[],
  relationships: readonly RelationshipRecord[]
): PendingLoaderScope[] {
  return siblingRegistryScopes(files, relationships, {
    loaderPattern: /(?:^|\/)routes\/index\.[cm]?[jt]sx?$/u,
    id: 'routes',
    kind: 'routes',
    scope: 'production',
    targetLabel: 'route'
  });
}

function sequelizeDirectory(
  config: AnalysisFile | undefined,
  owner: PackageBoundary,
  key: 'models-path' | 'migrations-path' | 'seeders-path'
): { root?: string; unsupported: boolean; declared: boolean } {
  const fallbackDirectory = key === 'models-path' ? undefined : key === 'migrations-path' ? 'migrations' : 'seeders';
  const fallback = fallbackDirectory ? joinTargetPath(owner.root, fallbackDirectory) : undefined;
  if (!config) return { ...(fallback ? { root: fallback } : {}), unsupported: false, declared: false };
  const source = config.content.toString('utf8');
  const parsedSource = parseBoundedTypeScript(config.record.path, source, ts.ScriptKind.JS);
  if (parsedSource.state === 'rejected') return { unsupported: true, declared: true };
  const sourceFile = parsedSource.sourceFile;
  const pathBindings = moduleBindings(sourceFile, new Set(['path', 'node:path']));
  let exportedObject: ts.ObjectLiteralExpression | undefined;
  let unsupportedExport = false;
  for (const statement of sourceFile.statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
    const assignment = statement.expression;
    const left = assignment.left;
    if (
      assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
      !ts.isPropertyAccessExpression(left) ||
      !ts.isIdentifier(left.expression) || left.expression.text !== 'module' || left.name.text !== 'exports'
    ) continue;
    let right = assignment.right;
    while (ts.isParenthesizedExpression(right) || ts.isAsExpression(right) || ts.isNonNullExpression(right)) {
      right = right.expression;
    }
    if (!ts.isObjectLiteralExpression(right) || exportedObject) {
      unsupportedExport = true;
    } else {
      exportedObject = right;
    }
  }
  if (!exportedObject || unsupportedExport) return { unsupported: true, declared: false };

  const namedProperties = exportedObject.properties.filter((property): property is ts.PropertyAssignment => {
    if (!ts.isPropertyAssignment(property)) return false;
    const name = property.name;
    return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === key;
  });
  if (exportedObject.properties.some((property) => ts.isSpreadAssignment(property)) || namedProperties.length > 1) {
    return { unsupported: true, declared: true };
  }
  const property = namedProperties[0];
  if (!property) return { ...(fallback ? { root: fallback } : {}), unsupported: false, declared: false };
  let initializer = property.initializer;
  while (ts.isParenthesizedExpression(initializer) || ts.isAsExpression(initializer) || ts.isNonNullExpression(initializer)) {
    initializer = initializer.expression;
  }
  if (ts.isStringLiteralLike(initializer)) {
    const root = joinTargetPath(owner.root, initializer.text);
    return { ...(root ? { root } : {}), unsupported: !root, declared: true };
  }
  if (
    !ts.isCallExpression(initializer) ||
    (!isBoundFunction(initializer.expression, pathBindings, 'resolve') && !isBoundFunction(initializer.expression, pathBindings, 'join')) ||
    initializer.arguments.length === 0
  ) return { unsupported: true, declared: true };

  const segments: string[] = [];
  let usesDirname = false;
  for (const [index, argument] of initializer.arguments.entries()) {
    if (identifierName(argument) === '__dirname') {
      if (index !== 0 || usesDirname) return { unsupported: true, declared: true };
      usesDirname = true;
      continue;
    }
    if (!ts.isStringLiteralLike(argument)) return { unsupported: true, declared: true };
    segments.push(argument.text);
  }
  if (!segments.length) return { unsupported: true, declared: true };
  const base = usesDirname ? directoryOf(config.record.path) : owner.root;
  const root = joinTargetPath(base, path.posix.join(...segments));
  return { ...(root ? { root } : {}), unsupported: !root, declared: true };
}

function scriptFlagDirectory(
  scripts: readonly string[],
  owner: PackageBoundary,
  flag: '--models-path' | '--migrations-path' | '--seeders-path'
): string | undefined {
  for (const command of scripts) {
    const expression = new RegExp(`${flag}(?:=|\\s+)(["']?)([^\\s"']+)\\1`, 'u');
    const value = expression.exec(command)?.[2];
    if (value) return joinTargetPath(owner.root, value);
  }
  return undefined;
}

function sequelizeCliScopes(
  files: readonly AnalysisFile[],
  packages: readonly PackageBoundary[]
): PendingLoaderScope[] {
  const scopes: PendingLoaderScope[] = [];
  const fileByPath = new Map(files.map((file) => [file.record.path, file]));
  for (const owner of packages) {
    const sequelizeScripts = Object.values(owner.scripts).filter((command) => /\bsequelize(?:-cli)?\b/u.test(command));
    if (!sequelizeScripts.length) continue;
    const configPath = owner.root === '.' ? '.sequelizerc' : `${owner.root}/.sequelizerc`;
    const config = fileByPath.get(configPath);
    if (config) {
      scopes.push({
        id: `convention:sequelize-cli:config:${owner.path}`,
        source: 'convention',
        kind: 'cli',
        scope: 'cli',
        loaderPaths: [owner.path],
        loadedPatterns: [configPath],
        targetPaths: [configPath],
        relationshipIds: [],
        externallyActivated: true,
        required: true,
        complete: true
      });
    }
    for (const descriptor of [
      { kind: 'sequelize-models' as const, scope: 'cli' as const, key: 'models-path' as const, flag: '--models-path' as const },
      { kind: 'migrations' as const, scope: 'migration' as const, key: 'migrations-path' as const, command: /\bdb:migrate(?::\w+)?\b/u, flag: '--migrations-path' as const },
      { kind: 'seeders' as const, scope: 'seeder' as const, key: 'seeders-path' as const, command: /\bdb:seed(?::\w+)?\b/u, flag: '--seeders-path' as const }
    ]) {
      const activeScripts = descriptor.command
        ? sequelizeScripts.filter((command) => descriptor.command!.test(command))
        : sequelizeScripts;
      if (!activeScripts.length) continue;
      const configured = sequelizeDirectory(config, owner, descriptor.key);
      const flagRoot = scriptFlagDirectory(activeScripts, owner, descriptor.flag);
      if (descriptor.key === 'models-path' && !flagRoot && !configured.declared) continue;
      const root = flagRoot ?? configured.root;
      const targetPaths = root
        ? sortedUnique(files.filter((file) => atOrBelow(file.record.path, root) && file.record.path !== root).map((file) => file.record.path))
        : [];
      const complete = Boolean(root) && !configured.unsupported && targetPaths.length > 0;
      const reasons: string[] = [];
      if (!root) reasons.push(`${descriptor.key} could not be resolved statically`);
      if (configured.unsupported) reasons.push(`${descriptor.key} uses an unsupported expression`);
      if (root && !targetPaths.length) reasons.push(`no files were observed below ${root}`);
      scopes.push({
        id: `convention:sequelize-cli:${descriptor.kind}:${owner.path}`,
        source: 'convention',
        kind: descriptor.kind,
        scope: descriptor.scope,
        loaderPaths: sortedUnique([owner.path, ...(config ? [config.record.path] : [])]),
        loadedPatterns: root ? [`${root}/**`] : [],
        targetPaths,
        relationshipIds: [],
        externallyActivated: true,
        required: true,
        complete,
        ...(reasons.length ? { reason: reasons.join('; ') } : {})
      });
    }
  }
  return scopes;
}

interface VitePublicDirectoryState {
  ownerRoot: string;
  loaderPaths: string[];
  roots: string[];
  complete: boolean;
  reason?: string;
}

function unwrapConfigurationExpression(expression: ts.Expression): ts.Expression {
  let value = expression;
  while (
    ts.isParenthesizedExpression(value) || ts.isAsExpression(value) ||
    ts.isNonNullExpression(value) || ts.isSatisfiesExpression(value)
  ) value = value.expression;
  if (
    ts.isCallExpression(value) && value.arguments.length === 1 &&
    ts.isIdentifier(value.expression) && value.expression.text === 'defineConfig'
  ) return unwrapConfigurationExpression(value.arguments[0]!);
  return value;
}

function exportedConfigurationObject(file: AnalysisFile): ts.ObjectLiteralExpression | undefined {
  const parsedSource = parseBoundedTypeScript(
    file.record.path,
    file.content.toString('utf8'),
    scriptKind(file.record.path)
  );
  if (parsedSource.state === 'rejected') return undefined;
  const sourceFile = parsedSource.sourceFile;
  const candidates: ts.Expression[] = [];
  for (const statement of sourceFile.statements) {
    if (ts.isExportAssignment(statement)) candidates.push(statement.expression);
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
    const assignment = statement.expression;
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const left = assignment.left;
    if (
      ts.isPropertyAccessExpression(left) && ts.isIdentifier(left.expression) &&
      left.expression.text === 'module' && left.name.text === 'exports'
    ) candidates.push(assignment.right);
  }
  if (candidates.length !== 1) return undefined;
  const candidate = unwrapConfigurationExpression(candidates[0]!);
  return ts.isObjectLiteralExpression(candidate) ? candidate : undefined;
}

function namedConfigurationProperties(
  object: ts.ObjectLiteralExpression,
  propertyName: string
): ts.PropertyAssignment[] {
  return object.properties.filter((property): property is ts.PropertyAssignment => {
    if (!ts.isPropertyAssignment(property)) return false;
    return (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) &&
      property.name.text === propertyName;
  });
}

function relativeConfiguredDirectory(root: string, value: string): string | undefined {
  const portable = value.replaceAll('\\', '/').trim();
  if (
    !portable || portable.startsWith('/') || portable.includes('\0') ||
    /^[a-z]:\//iu.test(portable) || /^[a-z][a-z0-9+.-]*:/iu.test(portable)
  ) return undefined;
  return joinTargetPath(root, portable);
}

function vitePublicDirectoryStates(
  files: readonly AnalysisFile[],
  packages: readonly PackageBoundary[]
): VitePublicDirectoryState[] {
  const states: VitePublicDirectoryState[] = [];
  for (const owner of packages) {
    const ownedFiles = files.filter((file) => ownedByPackage(file.record.path, owner, packages));
    const configs = ownedFiles.filter((file) =>
      /^vite(?:\.[^.]+)?\.config\.[cm]?[jt]sx?$/u.test(path.posix.basename(file.record.path))
    );
    const hasViteScript = Object.values(owner.scripts).some((command) => /(?:^|\s)(?:npx\s+)?vite(?:\s|$)/u.test(command));
    if (!configs.length && !hasViteScript) continue;

    const roots: string[] = [];
    const reasons: string[] = [];
    if (!configs.length) {
      const defaultRoot = joinTargetPath(owner.root, 'public');
      if (defaultRoot) roots.push(defaultRoot);
    }
    for (const config of configs) {
      const object = exportedConfigurationObject(config);
      const defaultProjectRoot = owner.root;
      let projectRoot = defaultProjectRoot;
      if (!object || object.properties.some((property) => ts.isSpreadAssignment(property))) {
        reasons.push(`${config.record.path} does not expose one closed literal Vite configuration object`);
      } else {
        const rootProperties = namedConfigurationProperties(object, 'root');
        if (rootProperties.length > 1) {
          reasons.push(`${config.record.path} declares root more than once`);
        } else if (rootProperties.length === 1) {
          const initializer = unwrapConfigurationExpression(rootProperties[0]!.initializer);
          const resolved = ts.isStringLiteralLike(initializer)
            ? relativeConfiguredDirectory(owner.root, initializer.text)
            : undefined;
          if (resolved) projectRoot = resolved;
          else reasons.push(`${config.record.path} has a non-literal or unsupported Vite root`);
        }
      }

      if (!object) {
        const fallback = joinTargetPath(defaultProjectRoot, 'public');
        if (fallback) roots.push(fallback);
        continue;
      }
      const publicProperties = namedConfigurationProperties(object, 'publicDir');
      if (publicProperties.length > 1) {
        reasons.push(`${config.record.path} declares publicDir more than once`);
        const fallback = joinTargetPath(projectRoot, 'public');
        if (fallback) roots.push(fallback);
        continue;
      }
      if (!publicProperties.length) {
        const fallback = joinTargetPath(projectRoot, 'public');
        if (fallback) roots.push(fallback);
        continue;
      }
      const initializer = unwrapConfigurationExpression(publicProperties[0]!.initializer);
      if (initializer.kind === ts.SyntaxKind.FalseKeyword) continue;
      const resolved = ts.isStringLiteralLike(initializer)
        ? relativeConfiguredDirectory(projectRoot, initializer.text)
        : undefined;
      if (resolved) roots.push(resolved);
      else {
        reasons.push(`${config.record.path} has a non-literal or unsupported publicDir`);
        const fallback = joinTargetPath(projectRoot, 'public');
        if (fallback) roots.push(fallback);
      }
    }
    if (configs.length > 1) reasons.push('multiple Vite configuration files are present and command-to-config selection was not established');
    states.push({
      ownerRoot: owner.root,
      loaderPaths: sortedUnique([owner.path, ...configs.map((config) => config.record.path)]),
      roots: sortedUnique(roots),
      complete: reasons.length === 0,
      ...(reasons.length ? { reason: sortedUnique(reasons).join('; ') } : {})
    });
  }
  return states.sort((left, right) => compareCanonicalText(left.ownerRoot, right.ownerRoot));
}

function vitePublicScopes(
  files: readonly AnalysisFile[],
  states: readonly VitePublicDirectoryState[]
): PendingLoaderScope[] {
  return states.map((state) => ({
    id: conventionScopeId('vite-public', { ownerRoot: state.ownerRoot, loaderPaths: state.loaderPaths }),
    source: 'convention',
    kind: 'build',
    scope: 'build',
    loaderPaths: state.loaderPaths,
    loadedPatterns: state.roots.map((root) => `${root}/**`),
    targetPaths: sortedUnique(files
      .filter((file) => state.roots.some((root) => file.record.path !== root && atOrBelow(file.record.path, root)))
      .map((file) => file.record.path)),
    relationshipIds: [],
    externallyActivated: true,
    required: true,
    complete: state.complete,
    ...(state.reason ? { reason: state.reason } : {})
  }));
}

function isServiceWorkerRegisterCall(call: ts.CallExpression): boolean {
  const callee = unwrapConfigurationExpression(call.expression);
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'register') return false;
  const receiver = unwrapConfigurationExpression(callee.expression);
  if (ts.isIdentifier(receiver)) return receiver.text === 'serviceWorker';
  if (!ts.isPropertyAccessExpression(receiver) || receiver.name.text !== 'serviceWorker') return false;
  const owner = unwrapConfigurationExpression(receiver.expression);
  if (ts.isIdentifier(owner)) return owner.text === 'navigator';
  return ts.isPropertyAccessExpression(owner) && owner.name.text === 'navigator' &&
    ts.isIdentifier(owner.expression) && ['window', 'globalThis'].includes(owner.expression.text);
}

function rootRelativeAssetPath(value: string): string | undefined {
  const withoutQuery = value.split(/[?#]/u, 1)[0] ?? '';
  if (!withoutQuery.startsWith('/') || withoutQuery.startsWith('//') || withoutQuery.includes('\\')) return undefined;
  const segments = withoutQuery.slice(1).split('/');
  if (!segments.length || segments.some((segment) => !segment || segment === '.' || segment === '..')) return undefined;
  return segments.join('/').normalize('NFC');
}

function serviceWorkerScopes(
  files: readonly AnalysisFile[],
  packages: readonly PackageBoundary[],
  viteStates: readonly VitePublicDirectoryState[]
): PendingLoaderScope[] {
  const scopes: PendingLoaderScope[] = [];
  const filePaths = new Set(files.map((file) => file.record.path));
  const viteByRoot = new Map(viteStates.map((state) => [state.ownerRoot, state]));
  for (const loader of files) {
    if (
      !JAVASCRIPT_TYPESCRIPT_FILE.test(loader.record.path) || /\.d\.[cm]?ts$/u.test(loader.record.path) ||
      /^(?:corpus|docs|examples|reference)(?:\/|$)/u.test(loader.record.path) ||
      loader.record.lifecycle?.state === 'mothballed'
    ) continue;
    const parsedSource = parseBoundedTypeScript(
      loader.record.path,
      loader.content.toString('utf8'),
      scriptKind(loader.record.path)
    );
    if (parsedSource.state === 'rejected') continue;
    const sourceFile = parsedSource.sourceFile;
    const packageRoot = nearestPackageRoot(loader.record.path, packages);
    const viteState = viteByRoot.get(packageRoot);
    const fallbackRoot = joinTargetPath(packageRoot, 'public');
    const publicRoots = viteState ? viteState.roots : fallbackRoot ? [fallbackRoot] : [];
    function visit(node: ts.Node): void {
      if (ts.isCallExpression(node) && isServiceWorkerRegisterCall(node)) {
        const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
        const argument = node.arguments[0] ? unwrapConfigurationExpression(node.arguments[0]!) : undefined;
        const literal = argument && ts.isStringLiteralLike(argument) ? argument.text : undefined;
        const assetPath = literal === undefined ? undefined : rootRelativeAssetPath(literal);
        const exactTargets = assetPath === undefined
          ? []
          : sortedUnique(publicRoots
            .flatMap((root) => {
              const candidate = joinTargetPath(root, assetPath);
              return candidate && filePaths.has(candidate) ? [candidate] : [];
            }));
        const targetPaths = literal === undefined
          ? sortedUnique(files
            .filter((file) => publicRoots.some((root) => file.record.path !== root && atOrBelow(file.record.path, root)))
            .map((file) => file.record.path))
          : exactTargets;
        const mappingComplete = viteState?.complete ?? true;
        const complete = literal !== undefined && assetPath !== undefined && mappingComplete && exactTargets.length === 1;
        const reasons: string[] = [];
        if (literal === undefined) reasons.push('serviceWorker.register uses a non-literal asset URL');
        else if (assetPath === undefined) reasons.push(`serviceWorker.register does not use one supported root-relative asset URL: ${literal}`);
        if (!mappingComplete) reasons.push('the Vite public directory mapping is incomplete');
        if (assetPath !== undefined && exactTargets.length === 0) reasons.push(`the registered service-worker asset did not resolve below a modeled public directory: ${literal}`);
        if (exactTargets.length > 1) reasons.push(`the registered service-worker asset matched multiple modeled public directories: ${literal}`);
        scopes.push({
          id: conventionScopeId('service-worker', {
            loaderPath: loader.record.path,
            line: start.line + 1,
            column: start.character + 1
          }),
          source: 'convention',
          kind: 'custom',
          scope: loader.record.kind === 'test' ? 'test' : 'production',
          loaderPaths: [loader.record.path],
          loadedPatterns: literal !== undefined ? [literal] : publicRoots.map((root) => `${root}/**`),
          targetPaths,
          relationshipIds: [],
          externallyActivated: false,
          required: true,
          complete,
          ...(!complete ? { reason: sortedUnique(reasons).join('; ') } : {})
        });
      }
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }
  return scopes;
}

function graphEdges(relationships: readonly RelationshipRecord[]): Map<string, string[]> {
  const outgoing = new Map<string, string[]>();
  for (const relationship of [...relationships].sort((left, right) => compareCanonicalText(left.id, right.id))) {
    if (relationship.resolution !== 'resolved' || relationship.typeOnly === true || !relationship.toPath) continue;
    const targets = outgoing.get(relationship.fromPath) ?? [];
    targets.push(relationship.toPath);
    outgoing.set(relationship.fromPath, targets);
  }
  for (const [owner, targets] of outgoing) outgoing.set(owner, sortedUnique(targets));
  return outgoing;
}

function expandReachable(seedPaths: Iterable<string>, outgoing: ReadonlyMap<string, string[]>): Set<string> {
  const reachable = new Set<string>();
  const queue = sortedUnique(seedPaths);
  while (queue.length) {
    const current = queue.shift()!;
    if (reachable.has(current)) continue;
    reachable.add(current);
    for (const target of outgoing.get(current) ?? []) {
      if (!reachable.has(target)) queue.push(target);
    }
    queue.sort(compareCanonicalText);
  }
  return reachable;
}

function pathReachabilityContexts(
  entrypoints: readonly ReachabilityEntrypoint[],
  loaderScopes: readonly LoaderScopeCoverage[],
  reachable: ReadonlySet<string>,
  outgoing: ReadonlyMap<string, string[]>
): ReadonlyMap<string, ReachabilityPathContext> {
  const propagatedEdges = new Map<string, string[]>(
    [...outgoing].map(([owner, targets]) => [owner, [...targets]])
  );
  const mutable = new Map<string, { entrypointPaths: Set<string>; scopes: Set<ReachabilityScope> }>();
  const queue: string[] = [];

  function addContext(filePath: string, entrypointPaths: Iterable<string>, scopes: Iterable<ReachabilityScope>): void {
    if (!reachable.has(filePath)) return;
    const value = mutable.get(filePath) ?? { entrypointPaths: new Set<string>(), scopes: new Set<ReachabilityScope>() };
    const before = value.entrypointPaths.size + value.scopes.size;
    for (const entrypointPath of entrypointPaths) value.entrypointPaths.add(entrypointPath);
    for (const scope of scopes) value.scopes.add(scope);
    mutable.set(filePath, value);
    if (value.entrypointPaths.size + value.scopes.size !== before && !queue.includes(filePath)) queue.push(filePath);
  }

  for (const entrypoint of entrypoints) addContext(entrypoint.path, [entrypoint.path], [entrypoint.scope]);
  for (const scope of loaderScopes) {
    if (scope.state !== 'complete') continue;
    for (const target of scope.targetPaths) addContext(target, [], [scope.scope]);
    for (const loaderPath of scope.loaderPaths.filter((candidate) => reachable.has(candidate))) {
      propagatedEdges.set(loaderPath, sortedUnique([
        ...(propagatedEdges.get(loaderPath) ?? []),
        ...scope.targetPaths
      ]));
    }
  }

  queue.sort(compareCanonicalText);
  while (queue.length) {
    const current = queue.shift()!;
    const context = mutable.get(current);
    if (!context) continue;
    for (const target of propagatedEdges.get(current) ?? []) {
      addContext(target, context.entrypointPaths, context.scopes);
    }
    queue.sort(compareCanonicalText);
  }

  return new Map([...mutable.entries()]
    .sort(([left], [right]) => compareCanonicalText(left, right))
    .map(([filePath, context]) => [filePath, {
      entrypointPaths: sortedUnique(context.entrypointPaths),
      scopes: sortedUnique(context.scopes) as ReachabilityScope[]
    }]));
}

function scopeState(scope: PendingLoaderScope, reachable: ReadonlySet<string>): LoaderScopeCoverage['state'] {
  const externallyActive = scope.externallyActivated &&
    (scope.required || scope.loaderPaths.length > 0 || scope.targetPaths.length > 0);
  const active = externallyActive || scope.loaderPaths.some((loaderPath) => reachable.has(loaderPath)) ||
    (scope.required && scope.loaderPaths.length === 0);
  if (!active) return 'inactive';
  return scope.complete ? 'complete' : 'incomplete';
}

function loaderCoverageDiagnostic(scope: LoaderScopeCoverage): DiagnosticRecord {
  const code = 'REACHABILITY_LOADER_COVERAGE_INCOMPLETE';
  const pathValue = scope.loaderPaths[0] ?? scope.targetPaths[0];
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({
      code,
      id: scope.id,
      loaderPaths: scope.loaderPaths,
      targetPaths: scope.targetPaths,
      reason: scope.reason
    })).slice(0, 24)}`,
    code,
    severity: 'warning',
    message: `Reachability loader coverage is incomplete for ${scope.id} (${scope.kind}, ${scope.scope}); static cleanup findings are suppressed only for its ${scope.targetPaths.length} observed target(s). ${scope.reason ?? 'The loader target set could not be established completely.'}`,
    ...(pathValue ? { path: pathValue } : {}),
    evidence: {
      level: 1,
      producer: 'atlas/reachability',
      producerVersion: REACHABILITY_ANALYSIS_VERSION,
      basis: 'scoped-loader-coverage',
      ...(pathValue ? { path: pathValue } : {}),
      recordIds: scope.relationshipIds
    }
  };
}

export function isUnsupportedNonLiteralModuleLoad(relationship: RelationshipRecord): boolean {
  return relationship.resolution === 'unsupported' &&
    relationship.specifier === '<dynamic>' &&
    relationship.typeOnly === false &&
    (relationship.type === 'require' || relationship.type === 'dynamic-import') &&
    relationship.to === undefined && relationship.toPath === undefined;
}

function dynamicScopeRoot(
  relationship: RelationshipRecord,
  owner: AnalysisFile,
  packages: readonly PackageBoundary[]
): { root: string; bounded: boolean } {
  const source = owner.content.toString('utf8');
  const lines = source.split(/\r?\n/u);
  const line = lines[relationship.location.line - 1] ?? '';
  const around = `${line}\n${lines[relationship.location.line] ?? ''}`;
  const dirnameCall = /(?:path\.)?(?:join|resolve)\s*\(\s*__dirname(?:\s*,\s*(["'])([^"']+)\1)?/u.exec(around);
  if (dirnameCall?.[2]) {
    const ownerDirectory = directoryOf(owner.record.path);
    const literalDirectory = dirnameCall[2].replaceAll('\\', '/');
    const literalSegments = literalDirectory.split('/');
    const root = !literalDirectory.startsWith('/') && !literalDirectory.includes(':') &&
      literalSegments.every((segment) => segment !== '' && segment !== '.' && segment !== '..')
      ? joinTargetPath(ownerDirectory, literalDirectory)
      : undefined;
    if (root && root !== ownerDirectory && atOrBelow(root, ownerDirectory)) return { root, bounded: true };
  }
  // A bare variable load, a bare __dirname load, or an expression whose
  // directory cannot be reduced to a literal descendant does not establish a
  // target cohort. Retain the nearest package only as diagnostic context; it
  // must never become a package-wide cleanup suppression.
  return { root: nearestPackageRoot(owner.record.path, packages), bounded: false };
}

function uncoveredDynamicScopes(
  files: readonly AnalysisFile[],
  relationships: readonly RelationshipRecord[],
  packages: readonly PackageBoundary[],
  reachable: ReadonlySet<string>,
  coveredRelationshipIds: ReadonlySet<string>
): LoaderScopeCoverage[] {
  const fileByPath = new Map(files.map((file) => [file.record.path, file]));
  const grouped = new Map<string, RelationshipRecord[]>();
  for (const relationship of relationships) {
    if (!isUnsupportedNonLiteralModuleLoad(relationship) || coveredRelationshipIds.has(relationship.id)) continue;
    const owner = fileByPath.get(relationship.fromPath);
    if (!owner) continue;
    if (/^(?:corpus|docs|examples|reference)(?:\/|$)/u.test(owner.record.path) || owner.record.lifecycle?.state === 'mothballed') continue;
    const descriptor = dynamicScopeRoot(relationship, owner, packages);
    const key = `${relationship.fromPath}\0${descriptor.root}\0${owner.record.kind === 'test' ? 'test' : 'production'}\0${descriptor.bounded ? 'bounded' : 'unbounded'}`;
    const values = grouped.get(key) ?? [];
    values.push(relationship);
    grouped.set(key, values);
  }
  const scopes: LoaderScopeCoverage[] = [];
  for (const [key, values] of [...grouped.entries()].sort(([left], [right]) => compareCanonicalText(left, right))) {
    const [loaderPath, root, scopeValue, boundedValue] = key.split('\0') as [string, string, ReachabilityScope, 'bounded' | 'unbounded'];
    const bounded = boundedValue === 'bounded';
    const active = values.some((relationship) => reachable.has(relationship.fromPath));
    const targets = bounded
      ? sortedUnique(files.filter((file) => atOrBelow(file.record.path, root)).map((file) => file.record.path))
      : [];
    scopes.push({
      id: `convention:dynamic-module:${scopeValue}:${boundedValue}:${loaderPath}:${root}`,
      source: 'convention',
      kind: 'custom',
      scope: scopeValue,
      loaderPaths: [loaderPath],
      loadedPatterns: bounded ? [`${root}/**`] : [],
      targetPaths: targets,
      relationshipIds: sortedUnique(values.map((relationship) => relationship.id)),
      state: active ? 'incomplete' : 'inactive',
      ...(active ? {
        reason: bounded
          ? 'an active non-literal module load has only a literal descendant cohort, but its complete filter semantics are unknown'
          : 'an active non-literal module load has no statically bounded target cohort; package context is diagnostic only and does not suppress cleanup findings'
      } : {})
    });
  }
  return scopes;
}

function sortScopes(scopes: Iterable<LoaderScopeCoverage>): LoaderScopeCoverage[] {
  return [...scopes].sort((left, right) =>
    compareCanonicalText(left.id, right.id) ||
    compareCanonicalText(left.state, right.state)
  );
}

export function analyzeReachability(
  files: AnalysisFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile
): ReachabilityResult {
  const orderedFiles = [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  const orderedRelationships = [...relationships].sort((left, right) => compareCanonicalText(left.id, right.id));
  const fileByPath = new Map(orderedFiles.map((file) => [file.record.path, file]));
  const packages = packageBoundaries(orderedFiles);
  const conventionScopes: PendingLoaderScope[] = [];
  const entrypoints = discoverEntrypoints(orderedFiles, profile, packages, fileByPath, conventionScopes);
  const outgoing = graphEdges(orderedRelationships);
  const reachable = expandReachable(entrypoints.map((entrypoint) => entrypoint.path), outgoing);
  const vitePublicStates = vitePublicDirectoryStates(orderedFiles, packages);
  const runtimeInboundPaths = new Set<string>();
  for (const relationship of orderedRelationships) {
    if (relationship.resolution !== 'resolved' || relationship.typeOnly === true || !relationship.toPath) continue;
    runtimeInboundPaths.add(relationship.toPath);
  }

  const pendingScopes = [
    ...conventionScopes,
    ...configuredLoaderScopes(orderedFiles, orderedRelationships, profile),
    ...sequelizeModelScopes(orderedFiles, orderedRelationships),
    ...routeRegistryScopes(orderedFiles, orderedRelationships),
    ...sequelizeCliScopes(orderedFiles, packages),
    ...vitePublicScopes(orderedFiles, vitePublicStates),
    ...serviceWorkerScopes(orderedFiles, packages, vitePublicStates)
  ].sort((left, right) => compareCanonicalText(left.id, right.id));
  let changed = true;
  while (changed) {
    changed = false;
    for (const scope of pendingScopes) {
      if (scopeState(scope, reachable) !== 'complete') continue;
      const newlyLoaded = scope.targetPaths.filter((target) => !reachable.has(target));
      if (!newlyLoaded.length) continue;
      for (const target of scope.targetPaths) {
        runtimeInboundPaths.add(target);
      }
      const expanded = expandReachable([...reachable, ...scope.targetPaths], outgoing);
      if (expanded.size > reachable.size) changed = true;
      reachable.clear();
      for (const target of [...expanded].sort(compareCanonicalText)) reachable.add(target);
    }
  }
  // A complete loader can target a file that was already statically reachable;
  // it still supplies supported inbound evidence.
  for (const scope of pendingScopes) {
    if (scopeState(scope, reachable) !== 'complete') continue;
    for (const target of scope.targetPaths) {
      runtimeInboundPaths.add(target);
    }
  }

  const loaderScopes: LoaderScopeCoverage[] = pendingScopes.map((scope) => ({
    id: scope.id,
    source: scope.source,
    kind: scope.kind,
    scope: scope.scope,
    loaderPaths: scope.loaderPaths,
    loadedPatterns: scope.loadedPatterns,
    targetPaths: scope.targetPaths,
    relationshipIds: scope.relationshipIds,
    state: scopeState(scope, reachable),
    ...(scope.reason ? { reason: scope.reason } : {})
  }));
  // A recognized-but-incomplete loader already owns its uncertainty scope.
  // Do not also widen it through the generic non-literal fallback.
  const coveredRelationshipIds = new Set(loaderScopes.flatMap((scope) => scope.relationshipIds));
  loaderScopes.push(...uncoveredDynamicScopes(
    orderedFiles,
    orderedRelationships,
    packages,
    reachable,
    coveredRelationshipIds
  ));

  const gatedPaths = new Set<string>();
  const diagnostics: DiagnosticRecord[] = [];
  for (const scope of loaderScopes) {
    if (scope.state !== 'incomplete') continue;
    for (const target of scope.targetPaths) gatedPaths.add(target);
    diagnostics.push(loaderCoverageDiagnostic(scope));
  }
  const entrypointClosureScopes = new Set<ReachabilityScope>([
    ...entrypoints.map((entrypoint) => entrypoint.scope),
    ...pendingScopes
      .filter((scope) =>
        scope.externallyActivated && scopeState(scope, reachable) === 'complete' && scope.targetPaths.length > 0
      )
      .map((scope) => scope.scope)
  ].sort(compareCanonicalText));
  const entrypointClosureEstablished = entrypointClosureScopes.size > 0;
  const pathContexts = pathReachabilityContexts(entrypoints, loaderScopes, reachable, outgoing);

  return {
    entrypoints,
    entrypointClosureEstablished,
    entrypointClosureScopes,
    reachablePaths: new Set([...reachable].sort(compareCanonicalText)),
    runtimeInboundPaths: new Set([...runtimeInboundPaths].sort(compareCanonicalText)),
    gatedPaths: new Set([...gatedPaths].sort(compareCanonicalText)),
    pathContexts,
    loaderScopes: sortScopes(loaderScopes),
    diagnostics: [...new Map(diagnostics.map((entry) => [entry.id, entry])).values()]
      .sort((left, right) => compareCanonicalText(left.id, right.id))
  };
}
