import path from 'node:path';
import ts from 'typescript';
import { AtlasError } from '../errors.js';
import { isExpectedFixtureUnresolvedImport } from '../profile-matching.js';
import { adapterEvidence } from '../snapshot.js';
import { boundedTypeScriptDiagnosticMessage, parseBoundedTypeScript } from '../security/typescript-ast.js';
import type {
  DiagnosticRecord,
  RelationshipRecord,
  ResolvedProfile,
  AnalysisFile,
  SourceLocation
} from '../types.js';
import { JS_TS_ADAPTER_VERSION, SCHEMA_VERSION } from '../types.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesGlob } from '../util/paths.js';

const PARSED_LANGUAGES = new Set(['javascript', 'javascript-jsx', 'typescript', 'typescript-tsx']);
const IMPLEMENTATION_RESOLUTION_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.json'];
const DECLARATION_RESOLUTION_EXTENSIONS = ['.d.ts', '.d.mts', '.d.cts'];
const RESOLUTION_EXTENSIONS = [...IMPLEMENTATION_RESOLUTION_EXTENSIONS, ...DECLARATION_RESOLUTION_EXTENSIONS];
const TYPE_ONLY_RESOLUTION_EXTENSIONS = [...DECLARATION_RESOLUTION_EXTENSIONS, ...IMPLEMENTATION_RESOLUTION_EXTENSIONS];
const MAX_RESOLVER_CONFIG_EXTENDS_DEPTH = 64;
export const MAX_WORKSPACE_PATTERN_EVALUATIONS = 250_000;
const EXPLICIT_EXTENSION_SUBSTITUTIONS = new Map<string, string[]>([
  ['.js', ['.ts', '.tsx', '.js', '.jsx', '.d.ts']],
  ['.jsx', ['.tsx', '.jsx', '.d.ts']],
  ['.mjs', ['.mts', '.mjs', '.d.mts']],
  ['.cjs', ['.cts', '.cjs', '.d.cts']]
]);

function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (filePath.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (filePath.endsWith('.ts') || filePath.endsWith('.mts') || filePath.endsWith('.cts')) return ts.ScriptKind.TS;
  if (filePath.endsWith('.json')) return ts.ScriptKind.JSON;
  return ts.ScriptKind.JS;
}

function locationFor(sourceFile: ts.SourceFile, node: ts.Node): SourceLocation {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return { line: start.line + 1, column: start.character + 1, endLine: end.line + 1, endColumn: end.character + 1 };
}

function diagnostic(
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  filePath: string,
  location?: SourceLocation
): DiagnosticRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({ code, filePath, location: location ?? null, message })).slice(0, 24)}`,
    code,
    severity,
    message,
    path: filePath,
    ...(location ? { location } : {}),
    evidence: adapterEvidence(filePath, 'typescript-compiler-api', location?.line, location?.column)
  };
}

function candidatePaths(base: string, typeOnly: boolean): string[] {
  const extension = path.posix.extname(base);
  const hasModuleExtension = RESOLUTION_EXTENSIONS.includes(extension);
  let result: string[];
  const substitutions = EXPLICIT_EXTENSION_SUBSTITUTIONS.get(extension);
  if (substitutions) {
    const stem = base.slice(0, -extension.length);
    const orderedSubstitutions = typeOnly
      ? [
          ...substitutions.filter((candidateExtension) => DECLARATION_RESOLUTION_EXTENSIONS.includes(candidateExtension)),
          ...substitutions.filter((candidateExtension) => !DECLARATION_RESOLUTION_EXTENSIONS.includes(candidateExtension))
        ]
      : substitutions;
    result = orderedSubstitutions.map((candidateExtension) => `${stem}${candidateExtension}`);
  } else {
    result = [base];
  }
  // A domain suffix such as `user.service` is not a module extension. Keep the
  // exact candidate for assets, then apply normal extension/index resolution.
  if (!hasModuleExtension) {
    const resolutionExtensions = typeOnly ? TYPE_ONLY_RESOLUTION_EXTENSIONS : RESOLUTION_EXTENSIONS;
    for (const extension of resolutionExtensions) result.push(`${base}${extension}`);
    for (const extension of resolutionExtensions) result.push(`${base}/index${extension}`);
  }
  return [...new Set(result.map((entry) => path.posix.normalize(entry).replace(/^\.\//, '')))];
}

interface AliasMatch {
  matched: boolean;
  targets: string[];
}

interface ResolverConfig {
  path: string;
  directory: string;
  aliases: Record<string, string[]>;
  baseUrl?: string;
}

interface PackageBoundary {
  root: string;
  manifestPath: string;
  name?: string;
  manifest: Record<string, unknown>;
  workspaceMembers: Set<string>;
}

type WorkspacePackageMatch =
  | { state: 'none' }
  | { state: 'one'; boundary: PackageBoundary }
  | { state: 'ambiguous' };

interface ResolverIndex {
  configs: ResolverConfig[];
  packages: PackageBoundary[];
  packageByRoot: Map<string, PackageBoundary>;
  workspaceContainersByPackageRoot: Map<string, Set<string>>;
  workspacePackagesByContainer: Map<string, Map<string, PackageBoundary | null>>;
  workspacePackageMatchCache: Map<string, Map<string, WorkspacePackageMatch>>;
  workspaceResolutionAvailable: boolean;
}

interface ResolutionResult {
  state: RelationshipRecord['resolution'];
  to?: AnalysisFile;
  caseMismatch?: string;
  silentUnsupported?: boolean;
  diagnostic?: {
    code: string;
    severity: DiagnosticRecord['severity'];
    message: string;
  };
}

function aliasTargets(specifier: string, aliases: Record<string, string[]>): AliasMatch {
  const matches: Array<{
    pattern: string;
    targets: string[];
    captured: string;
    exact: boolean;
    prefixLength: number;
    suffixLength: number;
  }> = [];
  for (const [pattern, targets] of Object.entries(aliases)) {
    const star = pattern.indexOf('*');
    if (star === -1) {
      if (specifier === pattern) matches.push({ pattern, targets, captured: '', exact: true, prefixLength: pattern.length, suffixLength: 0 });
      continue;
    }
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    if (specifier.length < prefix.length + suffix.length || !specifier.startsWith(prefix) || !specifier.endsWith(suffix)) continue;
    const captured = specifier.slice(prefix.length, specifier.length - suffix.length);
    matches.push({ pattern, targets, captured, exact: false, prefixLength: prefix.length, suffixLength: suffix.length });
  }
  matches.sort((left, right) =>
    Number(right.exact) - Number(left.exact) ||
    right.prefixLength - left.prefixLength ||
    right.suffixLength - left.suffixLength ||
    compareCanonicalText(left.pattern, right.pattern)
  );
  const selected = matches[0];
  return selected
    ? { matched: true, targets: selected.targets.map((target) => target.replace('*', selected.captured)) }
    : { matched: false, targets: [] };
}

function targetPath(base: string, value: string): string | undefined {
  if (!value || path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || value.includes('\0')) return undefined;
  const portable = value.replaceAll('\\', '/');
  const resolved = path.posix.normalize(path.posix.join(base === '.' ? '' : base, portable)).replace(/^\.\//u, '');
  if (!resolved || resolved === '..' || resolved.startsWith('../')) return undefined;
  return resolved;
}

function packageTargetPath(packageRoot: string, value: string): string | undefined {
  const resolved = targetPath(packageRoot, value);
  if (!resolved) return undefined;
  return packageRoot === '.' || resolved === packageRoot || resolved.startsWith(`${packageRoot}/`)
    ? resolved
    : undefined;
}

function resolveBases(
  bases: string[],
  typeOnly: boolean,
  fileByPath: Map<string, AnalysisFile>,
  caseFolded: Map<string, string>
): ResolutionResult | undefined {
  for (const base of bases) {
    for (const candidate of candidatePaths(base, typeOnly)) {
      const exact = fileByPath.get(candidate);
      if (exact) return { state: 'resolved', to: exact };
      const differentlyCased = caseFolded.get(candidate.toLowerCase());
      if (differentlyCased) return { state: 'unresolved-internal', caseMismatch: differentlyCased };
    }
  }
  return undefined;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function configDirectory(configPath: string): string {
  const directory = path.posix.dirname(configPath);
  return directory === '.' ? '.' : directory;
}

function isAncestor(directory: string, filePath: string): boolean {
  return directory === '.' || filePath === directory || filePath.startsWith(`${directory}/`);
}

function depth(value: string): number {
  return value === '.' ? 0 : value.split('/').length;
}

function parentDirectory(directory: string): string | undefined {
  if (directory === '.') return undefined;
  const parent = path.posix.dirname(directory);
  return parent === directory ? undefined : parent;
}

function parsePackageBoundaries(
  files: AnalysisFile[],
  diagnostics: DiagnosticRecord[]
): { boundaries: PackageBoundary[]; workspaceResolutionAvailable: boolean } {
  const boundaries: PackageBoundary[] = [];
  for (const file of [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path))) {
    if (path.posix.basename(file.record.path).toLowerCase() !== 'package.json') continue;
    let manifest: unknown;
    try {
      manifest = JSON.parse(file.content.toString('utf8'));
    } catch {
      diagnostics.push(diagnostic(
        'PACKAGE_MANIFEST_PARSE_ERROR',
        'warning',
        'Package manifest is not valid JSON; its directory remains a boundary but package-name resolution is unavailable.',
        file.record.path
      ));
      manifest = {};
    }
    let value = objectValue(manifest);
    if (!value) {
      diagnostics.push(diagnostic(
        'PACKAGE_MANIFEST_INVALID',
        'warning',
        'Package manifest is not a JSON object; its directory remains a boundary but package-name resolution is unavailable.',
        file.record.path
      ));
      value = {};
    }
    const rawName = value.name;
    const name = typeof rawName === 'string' && rawName.trim() ? rawName.normalize('NFC') : undefined;
    boundaries.push({
      root: configDirectory(file.record.path),
      manifestPath: file.record.path,
      ...(name ? { name } : {}),
      manifest: value,
      workspaceMembers: new Set<string>()
    });
  }
  boundaries.sort((left, right) => depth(right.root) - depth(left.root) || compareCanonicalText(left.root, right.root));

  const boundaryByRoot = new Map(boundaries.map((entry) => [entry.root, entry]));
  const patternsByRoot = new Map<string, string[]>();
  for (const workspace of boundaries) {
    const workspaces = Array.isArray(workspace.manifest.workspaces)
      ? workspace.manifest.workspaces
      : objectValue(workspace.manifest.workspaces)?.packages;
    if (!Array.isArray(workspaces)) continue;
    patternsByRoot.set(
      workspace.root,
      workspaces.filter((entry): entry is string => typeof entry === 'string' && Boolean(entry))
    );
  }

  let evaluations = 0;
  let exhaustedAt: PackageBoundary | undefined;
  outer: for (const candidate of boundaries) {
    let ancestor = parentDirectory(candidate.root);
    while (ancestor !== undefined) {
      const workspace = boundaryByRoot.get(ancestor);
      const patterns = workspace ? patternsByRoot.get(workspace.root) : undefined;
      if (workspace && patterns) {
        const relative = workspace.root === '.' ? candidate.root : candidate.root.slice(workspace.root.length + 1);
        let matched = false;
        for (const pattern of patterns) {
          if (pattern.startsWith('!')) continue;
          if (evaluations >= MAX_WORKSPACE_PATTERN_EVALUATIONS) {
            exhaustedAt = workspace;
            break outer;
          }
          evaluations += 1;
          try {
            if (matchesGlob(relative, pattern)) matched = true;
          } catch {
            diagnostics.push(diagnostic(
              'WORKSPACE_PATTERN_UNSUPPORTED',
              'warning',
              'A package workspace pattern is not a supported portable glob; that pattern was ignored.',
              workspace.manifestPath
            ));
          }
        }
        if (matched) workspace.workspaceMembers.add(candidate.root);
      }
      ancestor = parentDirectory(ancestor);
    }
  }
  if (exhaustedAt) {
    for (const boundary of boundaries) boundary.workspaceMembers.clear();
    diagnostics.push(diagnostic(
      'PACKAGE_WORKSPACE_RESOURCE_LIMIT',
      'warning',
      `Workspace package matching exceeded the ${MAX_WORKSPACE_PATTERN_EVALUATIONS}-evaluation limit; workspace package-name resolution was disabled for this analysis.`,
      exhaustedAt.manifestPath
    ));
  }
  return { boundaries, workspaceResolutionAvailable: exhaustedAt === undefined };
}

function localConfigExtendsPath(
  configPath: string,
  extendsValue: string,
  fileByPath: Map<string, AnalysisFile>
): string | undefined {
  if (!extendsValue.startsWith('.')) return undefined;
  const base = targetPath(configDirectory(configPath), extendsValue);
  if (!base) return undefined;
  for (const candidate of [base, `${base}.json`, `${base}/tsconfig.json`]) {
    if (fileByPath.has(candidate)) return candidate;
  }
  return undefined;
}

function parseResolverConfigs(
  files: AnalysisFile[],
  fileByPath: Map<string, AnalysisFile>,
  diagnostics: DiagnosticRecord[]
): ResolverConfig[] {
  const canonicalPaths = files
    .map((file) => file.record.path)
    .filter((filePath) => ['tsconfig.json', 'jsconfig.json'].includes(path.posix.basename(filePath).toLowerCase()))
    .sort(compareCanonicalText);
  const cache = new Map<string, ResolverConfig | undefined>();
  const active = new Set<string>();

  function parseConfig(configPath: string, inheritanceDepth = 0): ResolverConfig | undefined {
    if (cache.has(configPath)) return cache.get(configPath);
    const file = fileByPath.get(configPath);
    if (!file) return undefined;
    if (inheritanceDepth > MAX_RESOLVER_CONFIG_EXTENDS_DEPTH) {
      diagnostics.push(diagnostic(
        'RESOLVER_CONFIG_EXTENDS_DEPTH_LIMIT',
        'warning',
        `Resolver configuration inheritance exceeded the supported depth of ${MAX_RESOLVER_CONFIG_EXTENDS_DEPTH}; deeper inherited aliases were ignored.`,
        configPath
      ));
      return undefined;
    }
    if (active.has(configPath)) {
      diagnostics.push(diagnostic(
        'RESOLVER_CONFIG_EXTENDS_CYCLE',
        'warning',
        'A local resolver configuration extends cycle was detected; inherited aliases were ignored.',
        configPath
      ));
      return undefined;
    }
    active.add(configPath);
    let parsed: ReturnType<typeof ts.parseConfigFileTextToJson>;
    try {
      parsed = ts.parseConfigFileTextToJson(configPath, file.content.toString('utf8'));
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      diagnostics.push(diagnostic(
        'RESOLVER_CONFIG_PARSE_ERROR',
        'warning',
        'TypeScript/JavaScript resolver configuration exceeded the parser resource limit; its aliases were ignored.',
        configPath
      ));
      active.delete(configPath);
      const blocked: ResolverConfig = {
        path: configPath,
        directory: configDirectory(configPath),
        aliases: {}
      };
      cache.set(configPath, blocked);
      return blocked;
    }
    if (parsed.error || !objectValue(parsed.config)) {
      const location = parsed.error?.start === undefined
        ? undefined
        : (() => {
            const parsedLocationSource = parseBoundedTypeScript(
              configPath,
              file.content.toString('utf8'),
              ts.ScriptKind.JSON
            );
            if (parsedLocationSource.state === 'rejected') return undefined;
            const point = parsedLocationSource.sourceFile.getLineAndCharacterOfPosition(parsed.error!.start!);
            return { line: point.line + 1, column: point.character + 1, endLine: point.line + 1, endColumn: point.character + 1 };
          })();
      diagnostics.push(diagnostic(
        'RESOLVER_CONFIG_PARSE_ERROR',
        'warning',
        'TypeScript/JavaScript resolver configuration could not be parsed; its aliases were ignored.',
        configPath,
        location
      ));
      active.delete(configPath);
      const blocked: ResolverConfig = {
        path: configPath,
        directory: configDirectory(configPath),
        aliases: {}
      };
      cache.set(configPath, blocked);
      return blocked;
    }
    const raw = parsed.config as Record<string, unknown>;
    let inherited: ResolverConfig | undefined;
    if (typeof raw.extends === 'string') {
      const inheritedPath = localConfigExtendsPath(configPath, raw.extends, fileByPath);
      if (inheritedPath) inherited = parseConfig(inheritedPath, inheritanceDepth + 1);
      else diagnostics.push(diagnostic(
        raw.extends.startsWith('.') ? 'RESOLVER_CONFIG_EXTENDS_UNRESOLVED' : 'RESOLVER_CONFIG_EXTENDS_UNSUPPORTED',
        'info',
        raw.extends.startsWith('.')
          ? 'A local resolver configuration extension was not present in the analysis boundary; inherited aliases are unknown.'
          : 'Package-based resolver configuration extensions are not evaluated; inherited aliases are unknown.',
        configPath
      ));
    }
    const directory = configDirectory(configPath);
    const compilerOptions = objectValue(raw.compilerOptions) ?? {};
    let baseUrl = inherited?.baseUrl;
    if (Object.hasOwn(compilerOptions, 'baseUrl')) {
      if (typeof compilerOptions.baseUrl === 'string') {
        baseUrl = targetPath(directory, compilerOptions.baseUrl);
        if (!baseUrl) diagnostics.push(diagnostic(
          'RESOLVER_CONFIG_BASE_URL_INVALID',
          'warning',
          'Resolver baseUrl escapes the analysis target or is not portable; it was ignored.',
          configPath
        ));
      } else {
        baseUrl = undefined;
        diagnostics.push(diagnostic(
          'RESOLVER_CONFIG_BASE_URL_INVALID',
          'warning',
          'Resolver baseUrl must be a string; it was ignored.',
          configPath
        ));
      }
    }
    let aliases = inherited ? { ...inherited.aliases } : {};
    if (Object.hasOwn(compilerOptions, 'paths')) {
      aliases = {};
      const paths = objectValue(compilerOptions.paths);
      if (!paths) {
        diagnostics.push(diagnostic(
          'RESOLVER_CONFIG_PATHS_INVALID',
          'warning',
          'Resolver paths must be an object; aliases from this configuration were ignored.',
          configPath
        ));
      } else {
        const aliasBase = baseUrl ?? directory;
        for (const [pattern, rawTargets] of Object.entries(paths).sort(([left], [right]) => compareCanonicalText(left, right))) {
          if (!pattern || (pattern.match(/\*/gu) ?? []).length > 1 || !Array.isArray(rawTargets)) {
            diagnostics.push(diagnostic(
              'RESOLVER_CONFIG_ALIAS_INVALID',
              'warning',
              'A resolver alias has an unsupported pattern or target list and was ignored.',
              configPath
            ));
            continue;
          }
          const targets: string[] = [];
          for (const rawTarget of rawTargets) {
            if (typeof rawTarget !== 'string' || (rawTarget.match(/\*/gu) ?? []).length > 1) continue;
            const rooted = targetPath(aliasBase, rawTarget);
            if (rooted) targets.push(rooted);
          }
          if (targets.length) aliases[pattern.normalize('NFC')] = [...new Set(targets)];
          else diagnostics.push(diagnostic(
            'RESOLVER_CONFIG_ALIAS_INVALID',
            'warning',
            'A resolver alias has no portable in-target target patterns and was ignored.',
            configPath
          ));
        }
      }
    }
    const value: ResolverConfig = { path: configPath, directory, aliases, ...(baseUrl ? { baseUrl } : {}) };
    cache.set(configPath, value);
    active.delete(configPath);
    return value;
  }

  return canonicalPaths.map(parseConfig).filter((value): value is ResolverConfig => Boolean(value));
}

function nearestPackage(fromPath: string, index: ResolverIndex): PackageBoundary | undefined {
  let directory = configDirectory(fromPath);
  while (true) {
    const candidate = index.packageByRoot.get(directory);
    if (candidate) return candidate;
    const parent = parentDirectory(directory);
    if (parent === undefined) return undefined;
    directory = parent;
  }
}

function nearestResolverConfig(
  fromPath: string,
  language: string,
  index: ResolverIndex
): ResolverConfig | undefined {
  const boundary = nearestPackage(fromPath, index);
  const candidates = index.configs.filter((config) =>
    isAncestor(config.directory, fromPath) && (!boundary || isAncestor(boundary.root, config.directory))
  );
  if (!candidates.length) return undefined;
  const nearestDepth = Math.max(...candidates.map((entry) => depth(entry.directory)));
  const nearest = candidates.filter((entry) => depth(entry.directory) === nearestDepth);
  const prefersJs = language === 'javascript' || language === 'javascript-jsx';
  const preferredName = prefersJs ? 'jsconfig.json' : 'tsconfig.json';
  return nearest.find((entry) => path.posix.basename(entry.path).toLowerCase() === preferredName)
    ?? nearest.find((entry) => path.posix.basename(entry.path).toLowerCase() === 'tsconfig.json')
    ?? nearest[0];
}

function packageNameForSpecifier(specifier: string): { name: string; subpath: string } | undefined {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('#')) return undefined;
  const segments = specifier.split('/');
  if (specifier.startsWith('@')) {
    if (segments.length < 2) return undefined;
    return { name: `${segments[0]}/${segments[1]}`, subpath: segments.slice(2).join('/') };
  }
  return { name: segments[0]!, subpath: segments.slice(1).join('/') };
}

function visibleWorkspacePackage(
  owner: PackageBoundary | undefined,
  packageName: string,
  index: ResolverIndex
): WorkspacePackageMatch {
  if (!owner || !index.workspaceResolutionAvailable) return { state: 'none' };
  const ownerCache = index.workspacePackageMatchCache.get(owner.root) ?? new Map<string, WorkspacePackageMatch>();
  index.workspacePackageMatchCache.set(owner.root, ownerCache);
  const cached = ownerCache.get(packageName);
  if (cached) return cached;

  let selected: PackageBoundary | undefined;
  for (const container of index.workspaceContainersByPackageRoot.get(owner.root) ?? []) {
    const candidate = index.workspacePackagesByContainer.get(container)?.get(packageName);
    if (candidate === null || (candidate && selected && candidate.root !== selected.root)) {
      const result: WorkspacePackageMatch = { state: 'ambiguous' };
      ownerCache.set(packageName, result);
      return result;
    }
    if (candidate) selected = candidate;
  }
  const result: WorkspacePackageMatch = selected
    ? { state: 'one', boundary: selected }
    : { state: 'none' };
  ownerCache.set(packageName, result);
  return result;
}

function exportTargetStrings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(exportTargetStrings);
  const object = objectValue(value);
  if (!object) return [];
  return Object.entries(object)
    .sort(([left], [right]) => compareCanonicalText(left, right))
    .flatMap(([, child]) => exportTargetStrings(child));
}

function packageExportValue(exportsValue: unknown, subpath: string): unknown {
  if (typeof exportsValue === 'string' || Array.isArray(exportsValue)) return subpath ? undefined : exportsValue;
  const object = objectValue(exportsValue);
  if (!object) return undefined;
  const keys = Object.keys(object);
  if (!keys.some((key) => key.startsWith('.'))) return subpath ? undefined : object;
  const requested = subpath ? `./${subpath}` : '.';
  if (Object.hasOwn(object, requested)) return object[requested];
  const wildcardMatches = keys
    .filter((key) => (key.match(/\*/gu) ?? []).length === 1)
    .map((key) => {
      const star = key.indexOf('*');
      const prefix = key.slice(0, star);
      const suffix = key.slice(star + 1);
      return requested.startsWith(prefix) && requested.endsWith(suffix)
        ? { key, captured: requested.slice(prefix.length, requested.length - suffix.length), prefix: prefix.length, suffix: suffix.length }
        : undefined;
    })
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry))
    .sort((left, right) => right.prefix - left.prefix || right.suffix - left.suffix || compareCanonicalText(left.key, right.key));
  const selected = wildcardMatches[0];
  if (!selected) return undefined;
  const replace = (value: unknown): unknown => {
    if (typeof value === 'string') return value.replace('*', selected.captured);
    if (Array.isArray(value)) return value.map(replace);
    const nested = objectValue(value);
    if (!nested) return value;
    return Object.fromEntries(Object.entries(nested).map(([key, child]) => [key, replace(child)]));
  };
  return replace(object[selected.key]);
}

function packageBases(boundary: PackageBoundary, subpath: string, typeOnly: boolean): { bases: string[]; conditional: boolean } {
  const root = boundary.root;
  if (boundary.manifest.exports !== undefined) {
    const targets = exportTargetStrings(packageExportValue(boundary.manifest.exports, subpath))
      .map((entry) => entry.startsWith('./') ? packageTargetPath(root, entry) : undefined)
      .filter((entry): entry is string => Boolean(entry));
    return { bases: [...new Set(targets)], conditional: targets.length > 1 };
  }
  if (subpath) {
    const base = packageTargetPath(root, subpath);
    return { bases: base ? [base] : [], conditional: false };
  }
  const fieldOrder = typeOnly
    ? ['types', 'typings', 'module', 'main', 'source']
    : ['module', 'main', 'source'];
  const values = fieldOrder
    .map((field) => boundary.manifest[field])
    .filter((entry): entry is string => typeof entry === 'string')
    .map((entry) => packageTargetPath(root, entry))
    .filter((entry): entry is string => Boolean(entry));
  for (const fallback of ['src/index', 'index']) {
    const base = packageTargetPath(root, fallback);
    if (base) values.push(base);
  }
  return { bases: [...new Set(values)], conditional: false };
}

function resolveWorkspacePackage(
  fromPath: string,
  specifier: string,
  typeOnly: boolean,
  index: ResolverIndex,
  fileByPath: Map<string, AnalysisFile>,
  caseFolded: Map<string, string>
): ResolutionResult | undefined {
  const parsed = packageNameForSpecifier(specifier);
  if (!parsed) return undefined;
  if (!index.workspaceResolutionAvailable) return { state: 'unsupported', silentUnsupported: true };
  const owner = nearestPackage(fromPath, index);
  const match = visibleWorkspacePackage(owner, parsed.name, index);
  if (match.state === 'none') return undefined;
  if (match.state === 'ambiguous') {
    return {
      state: 'unsupported',
      diagnostic: {
        code: 'AMBIGUOUS_WORKSPACE_PACKAGE_IMPORT',
        severity: 'warning',
        message: `Workspace package specifier ${specifier} matches more than one visible package boundary.`
      }
    };
  }
  const candidates = packageBases(match.boundary, parsed.subpath, typeOnly);
  if (candidates.conditional) {
    const resolvedTargets = candidates.bases.map((base) => resolveBases([base], typeOnly, fileByPath, caseFolded));
    const uniqueTargets = new Set(resolvedTargets.map((entry) => entry?.to?.record.path));
    if (resolvedTargets.some((entry) => entry?.state !== 'resolved') || uniqueTargets.size !== 1) {
      return {
        state: 'unsupported',
        diagnostic: {
          code: 'AMBIGUOUS_WORKSPACE_PACKAGE_EXPORT',
          severity: 'warning',
          message: `Workspace package specifier ${specifier} has condition-dependent in-target export targets.`
        }
      };
    }
  }
  return resolveBases(candidates.bases, typeOnly, fileByPath, caseFolded) ?? { state: 'unresolved-internal' };
}

function resolveSpecifier(
  owner: AnalysisFile,
  specifier: string,
  typeOnly: boolean,
  fileByPath: Map<string, AnalysisFile>,
  caseFolded: Map<string, string>,
  profileAliases: Record<string, string[]>,
  resolverIndex: ResolverIndex
): ResolutionResult {
  const fromPath = owner.record.path;
  if (specifier.startsWith('.')) {
    const base = targetPath(path.posix.dirname(fromPath), specifier);
    if (!base) return { state: 'unresolved-internal' };
    return resolveBases([base], typeOnly, fileByPath, caseFolded) ?? { state: 'unresolved-internal' };
  }

  const config = nearestResolverConfig(fromPath, owner.record.language, resolverIndex);
  if (config) {
    const scopedAlias = aliasTargets(specifier, config.aliases);
    if (scopedAlias.matched) {
      return resolveBases(scopedAlias.targets, typeOnly, fileByPath, caseFolded) ?? { state: 'unresolved-internal' };
    }
    if (config.baseUrl) {
      const baseUrlCandidate = targetPath(config.baseUrl, specifier);
      const baseUrlResolution = baseUrlCandidate
        ? resolveBases([baseUrlCandidate], typeOnly, fileByPath, caseFolded)
        : undefined;
      if (baseUrlResolution) return baseUrlResolution;
    }
  }

  const configuredAlias = aliasTargets(specifier, profileAliases);
  if (configuredAlias.matched) {
    return resolveBases(configuredAlias.targets, typeOnly, fileByPath, caseFolded) ?? { state: 'unresolved-internal' };
  }
  return resolveWorkspacePackage(fromPath, specifier, typeOnly, resolverIndex, fileByPath, caseFolded)
    ?? { state: 'external-package' };
}

function moduleLiteral(node: ts.Expression | undefined): string | undefined {
  return node && ts.isStringLiteralLike(node) ? node.text : undefined;
}

function exported(node: ts.Node): boolean {
  return Boolean(ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));
}

function declarationName(node: ts.Node): string | undefined {
  if (
    ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) ||
    ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node)
  ) return node.name?.getText();
  return undefined;
}

function isEnvironmentObject(candidate: ts.Node): boolean {
  return ts.isPropertyAccessExpression(candidate) &&
    candidate.name.text === 'env' && (
      (ts.isIdentifier(candidate.expression) && candidate.expression.text === 'process') ||
      (
        ts.isMetaProperty(candidate.expression) &&
        candidate.expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
        candidate.expression.name.text === 'meta'
      )
    );
}

function environmentVariable(node: ts.Node): string | undefined {
  if (ts.isPropertyAccessExpression(node)) {
    const environment = node.expression;
    if (isEnvironmentObject(environment)) return node.name.text;
  }
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
    const environment = node.expression;
    if (isEnvironmentObject(environment)) return node.argumentExpression.text;
  }
  return undefined;
}

export function analyzeJavaScriptTypeScript(
  files: AnalysisFile[],
  profile: ResolvedProfile
): { relationships: RelationshipRecord[]; diagnostics: DiagnosticRecord[] } {
  const relationships: RelationshipRecord[] = [];
  const diagnostics: DiagnosticRecord[] = [];
  const fileByPath = new Map(files.map((file) => [file.record.path, file]));
  const caseFolded = new Map(files.map((file) => [file.record.path.toLowerCase(), file.record.path]));
  const packageResult = parsePackageBoundaries(files, diagnostics);
  const packages = packageResult.boundaries;
  const packageByRoot = new Map(packages.map((entry) => [entry.root, entry]));
  const workspaceContainersByPackageRoot = new Map<string, Set<string>>();
  for (const boundary of packages) {
    const ownContainers = workspaceContainersByPackageRoot.get(boundary.root) ?? new Set<string>();
    ownContainers.add(boundary.root);
    workspaceContainersByPackageRoot.set(boundary.root, ownContainers);
    for (const member of boundary.workspaceMembers) {
      const containers = workspaceContainersByPackageRoot.get(member) ?? new Set<string>();
      containers.add(boundary.root);
      workspaceContainersByPackageRoot.set(member, containers);
    }
  }
  const workspacePackagesByContainer = new Map<string, Map<string, PackageBoundary | null>>();
  for (const boundary of packages) {
    if (!boundary.name) continue;
    for (const container of workspaceContainersByPackageRoot.get(boundary.root) ?? []) {
      const packagesByName = workspacePackagesByContainer.get(container) ?? new Map<string, PackageBoundary | null>();
      const existing = packagesByName.get(boundary.name);
      if (!packagesByName.has(boundary.name)) packagesByName.set(boundary.name, boundary);
      else if (existing?.root !== boundary.root) packagesByName.set(boundary.name, null);
      workspacePackagesByContainer.set(container, packagesByName);
    }
  }
  const resolverIndex: ResolverIndex = {
    packages,
    packageByRoot,
    workspaceContainersByPackageRoot,
    workspacePackagesByContainer,
    workspacePackageMatchCache: new Map(),
    workspaceResolutionAvailable: packageResult.workspaceResolutionAvailable,
    configs: parseResolverConfigs(files, fileByPath, diagnostics)
  };

  function addRelationship(
    owner: AnalysisFile,
    sourceFile: ts.SourceFile,
    node: ts.Node,
    type: RelationshipRecord['type'],
    specifier: string,
    typeOnly: boolean,
    forcedState?: RelationshipRecord['resolution']
  ): void {
    const location = locationFor(sourceFile, node);
    const resolved: ResolutionResult = forcedState
      ? { state: forcedState }
      : resolveSpecifier(owner, specifier, typeOnly, fileByPath, caseFolded, profile.aliases, resolverIndex);
    const relationship: RelationshipRecord = {
      schemaVersion: SCHEMA_VERSION,
      id: `relationship:${sha256(canonicalJson({ from: owner.record.path, location, specifier, type })).slice(0, 24)}`,
      from: owner.record.id,
      fromPath: owner.record.path,
      ...(resolved.to ? { to: resolved.to.record.id, toPath: resolved.to.record.path } : {}),
      type,
      specifier,
      typeOnly,
      resolution: resolved.state,
      location,
      evidence: adapterEvidence(owner.record.path, 'typescript-compiler-api', location.line, location.column)
    };
    relationships.push(relationship);
    if (resolved.diagnostic) {
      diagnostics.push(diagnostic(
        resolved.diagnostic.code,
        resolved.diagnostic.severity,
        resolved.diagnostic.message,
        owner.record.path,
        location
      ));
    } else if (resolved.caseMismatch) {
      diagnostics.push(diagnostic(
        'PATH_CASE_MISMATCH',
        'error',
        `Import casing does not match the target path ${resolved.caseMismatch}.`,
        owner.record.path,
        location
      ));
    } else if (resolved.state === 'unresolved-internal') {
      const expectedFixture = isExpectedFixtureUnresolvedImport(profile, owner.record.path, specifier);
      diagnostics.push(diagnostic(
        expectedFixture ? 'EXPECTED_FIXTURE_UNRESOLVED_IMPORT' : 'UNRESOLVED_INTERNAL_IMPORT',
        expectedFixture ? 'info' : 'error',
        expectedFixture
          ? `An intentional scanner fixture contains an unresolved internal specifier: ${specifier}.`
          : `Unable to resolve internal specifier ${specifier}.`,
        owner.record.path,
        location
      ));
    } else if (resolved.state === 'unsupported' && resolved.silentUnsupported !== true) {
      diagnostics.push(diagnostic('UNSUPPORTED_DYNAMIC_IMPORT', 'warning', 'Dynamic module loading uses a non-literal specifier.', owner.record.path, location));
    }
  }

  for (const file of files) {
    if (!PARSED_LANGUAGES.has(file.record.language)) continue;
    const sourceText = file.content.toString('utf8');
    const parsedSource = parseBoundedTypeScript(file.record.path, sourceText, scriptKind(file.record.path));
    if (parsedSource.state === 'rejected') {
      diagnostics.push(diagnostic(
        'TYPESCRIPT_AST_RESOURCE_LIMIT',
        'error',
        boundedTypeScriptDiagnosticMessage(parsedSource.reason),
        file.record.path
      ));
      continue;
    }
    const sourceFile = parsedSource.sourceFile;
    const symbols = new Set<string>();
    const environmentVariables = new Set<string>();
    const emittedTypeImportRanges = new Set<string>();
    const visitedJsDocNodes = new Set<ts.Node>();
    const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    for (const parseDiagnostic of parseDiagnostics) {
      const start = parseDiagnostic.start ?? 0;
      const point = sourceFile.getLineAndCharacterOfPosition(start);
      const location = { line: point.line + 1, column: point.character + 1, endLine: point.line + 1, endColumn: point.character + 1 };
      diagnostics.push(diagnostic(
        'PARSE_ERROR',
        'error',
        ts.flattenDiagnosticMessageText(parseDiagnostic.messageText, '\n'),
        file.record.path,
        location
      ));
    }

    function addTypeOnlyImport(node: ts.Node, specifier: string): void {
      const key = `${node.getStart(sourceFile)}:${node.getEnd()}:${specifier}`;
      if (emittedTypeImportRanges.has(key)) return;
      emittedTypeImportRanges.add(key);
      addRelationship(file, sourceFile, node, 'static-import', specifier, true);
    }

    function visitJsDoc(root: ts.Node): void {
      const stack = [root];
      while (stack.length > 0) {
        const node = stack.pop()!;
        if (visitedJsDocNodes.has(node)) continue;
        visitedJsDocNodes.add(node);
        if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteralLike(node.argument.literal)) {
          addTypeOnlyImport(node.argument.literal, node.argument.literal.text);
        } else if (ts.isJSDocImportTag(node)) {
          const specifier = moduleLiteral(node.moduleSpecifier);
          if (specifier) addTypeOnlyImport(node.moduleSpecifier, specifier);
        }
        const children: ts.Node[] = [];
        ts.forEachChild(node, (child) => {
          children.push(child);
        });
        for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]!);
      }
    }

    function visit(root: ts.Node): void {
      const stack = [root];
      while (stack.length > 0) {
        const node = stack.pop()!;
        for (const jsDoc of ts.getJSDocCommentsAndTags(node)) visitJsDoc(jsDoc);
        const env = environmentVariable(node);
        if (env) environmentVariables.add(env);
        const name = declarationName(node);
        if (name && exported(node)) symbols.add(name);
        if (ts.isVariableStatement(node) && exported(node)) {
          for (const declaration of node.declarationList.declarations) symbols.add(declaration.name.getText(sourceFile));
        }
        if (ts.isImportDeclaration(node)) {
          const specifier = moduleLiteral(node.moduleSpecifier);
          if (specifier) {
            const namedBindings = node.importClause?.namedBindings;
            const onlyTypeSpecifiers = namedBindings && ts.isNamedImports(namedBindings) && namedBindings.elements.length > 0 &&
              namedBindings.elements.every((element) => element.isTypeOnly) && !node.importClause?.name;
            addRelationship(
              file,
              sourceFile,
              node.moduleSpecifier,
              'static-import',
              specifier,
              Boolean(node.importClause?.isTypeOnly || onlyTypeSpecifiers)
            );
          }
        } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
          const specifier = moduleLiteral(node.moduleSpecifier);
          if (specifier) {
            const onlyTypeSpecifiers = node.exportClause && ts.isNamedExports(node.exportClause) && node.exportClause.elements.length > 0 &&
              node.exportClause.elements.every((element) => element.isTypeOnly);
            addRelationship(
              file,
              sourceFile,
              node.moduleSpecifier,
              'export-from',
              specifier,
              Boolean(node.isTypeOnly || onlyTypeSpecifiers)
            );
          }
          if (node.exportClause && ts.isNamedExports(node.exportClause)) {
            for (const element of node.exportClause.elements) symbols.add(element.name.text);
          }
        } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
          const specifier = moduleLiteral(node.moduleReference.expression);
          if (specifier) addRelationship(file, sourceFile, node.moduleReference, 'static-import', specifier, node.isTypeOnly);
        } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteralLike(node.argument.literal)) {
          addTypeOnlyImport(node.argument.literal, node.argument.literal.text);
        } else if (ts.isCallExpression(node)) {
          const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
          const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
          if (isDynamicImport || isRequire) {
            const specifier = moduleLiteral(node.arguments[0]);
            addRelationship(
              file,
              sourceFile,
              node,
              isDynamicImport ? 'dynamic-import' : 'require',
              specifier ?? '<dynamic>',
              false,
              specifier ? undefined : 'unsupported'
            );
          }
        } else if (ts.isExportAssignment(node)) {
          symbols.add(node.isExportEquals ? 'export=' : 'default');
        }
        const children: ts.Node[] = [];
        ts.forEachChild(node, (child) => {
          children.push(child);
        });
        for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]!);
      }
    }
    visit(sourceFile);
    file.record.symbols = [...symbols].sort(compareCanonicalText);
    file.record.environmentVariables = [...environmentVariables].sort(compareCanonicalText);
  }

  relationships.sort((left, right) => compareCanonicalText(left.id, right.id));
  const uniqueDiagnostics = [...new Map(diagnostics.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  const ids = new Set<string>();
  for (const relationship of relationships) {
    if (ids.has(relationship.id)) throw new AtlasError('DUPLICATE_RELATIONSHIP', `Duplicate relationship ID: ${relationship.id}`);
    ids.add(relationship.id);
  }
  return { relationships, diagnostics: uniqueDiagnostics };
}

export const adapterDescriptor = { id: 'atlas/js-ts', version: `${JS_TS_ADAPTER_VERSION}+typescript-${ts.version}` } as const;
