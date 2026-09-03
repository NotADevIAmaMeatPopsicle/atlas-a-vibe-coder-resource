import path from 'node:path';
import { AtlasError } from './errors.js';
import { OPERATIONAL_RULE_CATALOG } from './analysis/operational-risks.js';
import { HARD_MAX_FILE_BYTES } from './limits.js';
import { assertSchema } from './schema-validator.js';
import { resolveTargetDescriptor } from './targets.js';
import type {
  FixtureUnresolvedImport,
  LifecyclePathRule,
  LoaderRule,
  OperationalRiskBoundary,
  OperationalRiskProfile,
  OperationalRiskProtectedWriter,
  PatternExpectation,
  ProfileConfig,
  ResolvedProfile,
  RuleExpectation,
  TargetConfig
} from './types.js';
import { compareCanonicalText, readJson } from './util/canonical.js';
import { normalizeIncludeRoot, normalizeTargetRelative } from './util/paths.js';

const DEFAULT_EXCLUDES = [
  '**/.git/**',
  '**/.hg/**',
  '**/.svn/**',
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/.next/**',
  '**/.turbo/**',
  '**/.cache/**'
];

function assertObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AtlasError('INVALID_CONFIG', `${label} must be an object.`);
}

function stringArray(value: unknown, label: string, fallback: string[] = []): string[] {
  if (value === undefined) return fallback;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new AtlasError('INVALID_CONFIG', `${label} must be an array of strings.`);
  }
  return [...value] as string[];
}

function normalizedPathSet(values: string[]): string[] {
  return [...new Set(values.map(normalizeTargetRelative))].sort(compareCanonicalText);
}

function normalizedId(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new AtlasError('INVALID_CONFIG', `${label} must contain a non-whitespace string.`);
  }
  return value.normalize('NFC');
}

function optionalNonNegativeInteger(value: unknown, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new AtlasError('INVALID_CONFIG', `${label} must be a non-negative safe integer.`);
  }
  return value as number;
}

function loaderRules(value: unknown): LoaderRule[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new AtlasError('INVALID_CONFIG', 'loaderRules must be an array.');
  const ids = new Set<string>();
  return value.map((rawRule, index) => {
    assertObject(rawRule, `loaderRules[${index}]`);
    const id = normalizedId(rawRule.id, `loaderRules[${index}].id`);
    if (ids.has(id)) throw new AtlasError('INVALID_CONFIG', `Loader rule IDs collide after normalization: ${id}`);
    ids.add(id);
    const loaderPaths = normalizedPathSet(stringArray(rawRule.loaderPaths, `loaderRules[${index}].loaderPaths`));
    const loadedPatterns = normalizedPathSet(stringArray(rawRule.loadedPatterns, `loaderRules[${index}].loadedPatterns`));
    if (!loaderPaths.length || !loadedPatterns.length) {
      throw new AtlasError('INVALID_CONFIG', `loaderRules[${index}] requires non-empty loaderPaths and loadedPatterns.`);
    }
    return {
      id,
      kind: rawRule.kind as LoaderRule['kind'],
      loaderPaths,
      loadedPatterns,
      scope: rawRule.scope as LoaderRule['scope'],
      required: rawRule.required === undefined ? true : rawRule.required as boolean
    };
  }).sort((left, right) => compareCanonicalText(left.id, right.id));
}

function fixtureUnresolvedImports(
  value: unknown,
  fixturePatterns: ReadonlySet<string>
): FixtureUnresolvedImport[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new AtlasError('INVALID_CONFIG', 'fixtureUnresolvedImports must be an array.');
  const ids = new Set<string>();
  const pairs = new Set<string>();
  return value.map((rawExpectation, index) => {
    assertObject(rawExpectation, `fixtureUnresolvedImports[${index}]`);
    const id = normalizedId(rawExpectation.id, `fixtureUnresolvedImports[${index}].id`);
    if (ids.has(id)) throw new AtlasError('INVALID_CONFIG', `Fixture unresolved-import IDs collide after normalization: ${id}`);
    ids.add(id);
    if (typeof rawExpectation.sourcePattern !== 'string') {
      throw new AtlasError('INVALID_CONFIG', `fixtureUnresolvedImports[${index}].sourcePattern must be a string.`);
    }
    const sourcePattern = normalizeTargetRelative(rawExpectation.sourcePattern);
    if (!fixturePatterns.has(sourcePattern)) {
      throw new AtlasError(
        'INVALID_CONFIG',
        `Fixture unresolved-import ${id} must reference a configured fixturePatterns entry: ${sourcePattern}`
      );
    }
    const specifier = normalizedId(rawExpectation.specifier, `fixtureUnresolvedImports[${index}].specifier`);
    const pair = `${sourcePattern}\0${specifier}`;
    if (pairs.has(pair)) {
      throw new AtlasError('INVALID_CONFIG', `Duplicate fixture unresolved-import expectation: ${sourcePattern} -> ${specifier}`);
    }
    pairs.add(pair);
    return { id, sourcePattern, specifier };
  }).sort((left, right) => compareCanonicalText(left.id, right.id));
}

function patternExpectations(
  value: unknown,
  configuredPatterns: ReadonlyMap<PatternExpectation['collection'], ReadonlySet<string>>
): PatternExpectation[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new AtlasError('INVALID_CONFIG', 'patternExpectations must be an array.');
  const ids = new Set<string>();
  const ownedPatterns = new Set<string>();
  const expectations = value.map((rawExpectation, index) => {
    assertObject(rawExpectation, `patternExpectations[${index}]`);
    const id = normalizedId(rawExpectation.id, `patternExpectations[${index}].id`);
    if (ids.has(id)) throw new AtlasError('INVALID_CONFIG', `Pattern expectation IDs collide after normalization: ${id}`);
    ids.add(id);
    const collection = rawExpectation.collection as PatternExpectation['collection'];
    const pattern = normalizeTargetRelative(String(rawExpectation.pattern));
    const minMatches = optionalNonNegativeInteger(rawExpectation.minMatches, `patternExpectations[${index}].minMatches`);
    const maxMatches = optionalNonNegativeInteger(rawExpectation.maxMatches, `patternExpectations[${index}].maxMatches`);
    if (minMatches === undefined) {
      throw new AtlasError('INVALID_CONFIG', `patternExpectations[${index}].minMatches is required.`);
    }
    if (maxMatches !== undefined && maxMatches < minMatches) {
      throw new AtlasError('INVALID_CONFIG', `patternExpectations[${index}] maxMatches cannot be less than minMatches.`);
    }
    const available = configuredPatterns.get(collection);
    if (!available?.has(pattern)) {
      throw new AtlasError(
        'INVALID_CONFIG',
        `Pattern expectation ${id} references an unconfigured ${collection} pattern: ${pattern}`
      );
    }
    const owner = `${collection}\0${pattern}`;
    if (ownedPatterns.has(owner)) {
      throw new AtlasError('INVALID_CONFIG', `Only one expectation may own ${collection}:${pattern}.`);
    }
    ownedPatterns.add(owner);
    return {
      id,
      collection,
      pattern,
      minMatches,
      ...(maxMatches === undefined ? {} : { maxMatches })
    };
  });
  return expectations.sort((left, right) => compareCanonicalText(left.id, right.id));
}

function ruleExpectations(value: unknown): RuleExpectation[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new AtlasError('INVALID_CONFIG', 'ruleExpectations must be an array.');
  const ruleIds = new Set<string>();
  const expectations = value.map((rawExpectation, index) => {
    assertObject(rawExpectation, `ruleExpectations[${index}]`);
    const ruleId = normalizedId(rawExpectation.ruleId, `ruleExpectations[${index}].ruleId`);
    if (!OPERATIONAL_RULE_CATALOG.some((descriptor) => descriptor.ruleId === ruleId)) {
      throw new AtlasError(
        'INVALID_CONFIG',
        `ruleExpectations[${index}].ruleId must name a catalogued operational rule: ${ruleId}`
      );
    }
    if (ruleIds.has(ruleId)) throw new AtlasError('INVALID_CONFIG', `Duplicate rule expectation: ${ruleId}`);
    ruleIds.add(ruleId);
    const minObservations = optionalNonNegativeInteger(rawExpectation.minObservations, `ruleExpectations[${index}].minObservations`);
    const maxObservations = optionalNonNegativeInteger(rawExpectation.maxObservations, `ruleExpectations[${index}].maxObservations`);
    const minFindings = optionalNonNegativeInteger(rawExpectation.minFindings, `ruleExpectations[${index}].minFindings`);
    const maxFindings = optionalNonNegativeInteger(rawExpectation.maxFindings, `ruleExpectations[${index}].maxFindings`);
    if ([minObservations, maxObservations, minFindings, maxFindings].every((entry) => entry === undefined)) {
      throw new AtlasError('INVALID_CONFIG', `ruleExpectations[${index}] must declare at least one bound.`);
    }
    if (minObservations !== undefined && maxObservations !== undefined && maxObservations < minObservations) {
      throw new AtlasError('INVALID_CONFIG', `ruleExpectations[${index}] observation maximum is below its minimum.`);
    }
    if (minFindings !== undefined && maxFindings !== undefined && maxFindings < minFindings) {
      throw new AtlasError('INVALID_CONFIG', `ruleExpectations[${index}] finding maximum is below its minimum.`);
    }
    return {
      ruleId,
      ...(minObservations === undefined ? {} : { minObservations }),
      ...(maxObservations === undefined ? {} : { maxObservations }),
      ...(minFindings === undefined ? {} : { minFindings }),
      ...(maxFindings === undefined ? {} : { maxFindings })
    };
  });
  return expectations.sort((left, right) => compareCanonicalText(left.ruleId, right.ruleId));
}

function exactOperationalModule(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new AtlasError('INVALID_CONFIG', `${label} must be a string.`);
  const normalized = normalizeTargetRelative(value);
  if (/[?*{}\[\]]/u.test(normalized)) {
    throw new AtlasError('INVALID_CONFIG', `${label} must be an exact target-relative module path, not a glob.`);
  }
  return normalized;
}

function normalizedUniqueNames(value: unknown, label: string): string[] {
  const raw = stringArray(value, label);
  if (!raw.length) throw new AtlasError('INVALID_CONFIG', `${label} cannot be empty.`);
  const normalized = raw.map((entry, index) => normalizedId(entry, `${label}[${index}]`));
  if (new Set(normalized).size !== normalized.length) {
    throw new AtlasError('INVALID_CONFIG', `${label} contains values that collide after normalization.`);
  }
  return normalized.sort(compareCanonicalText);
}

function operationalRiskProfile(value: unknown): OperationalRiskProfile | undefined {
  if (value === undefined) return undefined;
  assertObject(value, 'operationalRisks');
  const guardPaths = normalizedPathSet(stringArray(value.guardPaths, 'operationalRisks.guardPaths'));
  const seedDictionarySources = normalizedPathSet(
    stringArray(value.seedDictionarySources, 'operationalRisks.seedDictionarySources')
  );
  const hasBoundaries = value.boundaries !== undefined;
  const hasProtectedWriters = value.protectedWriters !== undefined;
  if (hasBoundaries !== hasProtectedWriters) {
    throw new AtlasError(
      'INVALID_CONFIG',
      'operationalRisks.boundaries and operationalRisks.protectedWriters must be declared together.'
    );
  }
  if (!hasBoundaries) return { guardPaths, seedDictionarySources };
  if (!Array.isArray(value.boundaries) || !value.boundaries.length) {
    throw new AtlasError('INVALID_CONFIG', 'operationalRisks.boundaries must be a non-empty array.');
  }
  if (!Array.isArray(value.protectedWriters) || !value.protectedWriters.length) {
    throw new AtlasError('INVALID_CONFIG', 'operationalRisks.protectedWriters must be a non-empty array.');
  }

  const writerIds = new Set<string>();
  const ownedMethods = new Map<string, string>();
  const protectedWriters = value.protectedWriters.map((rawWriter, index): OperationalRiskProtectedWriter => {
    assertObject(rawWriter, `operationalRisks.protectedWriters[${index}]`);
    const id = normalizedId(rawWriter.id, `operationalRisks.protectedWriters[${index}].id`);
    if (writerIds.has(id)) {
      throw new AtlasError('INVALID_CONFIG', `Protected-writer IDs collide after normalization: ${id}`);
    }
    writerIds.add(id);
    const module = exactOperationalModule(rawWriter.module, `operationalRisks.protectedWriters[${index}].module`);
    const methods = normalizedUniqueNames(rawWriter.methods, `operationalRisks.protectedWriters[${index}].methods`);
    for (const method of methods) {
      const sink = `${module}\0${method}`;
      const owner = ownedMethods.get(sink);
      if (owner) {
        throw new AtlasError(
          'INVALID_CONFIG',
          `Protected writers ${owner} and ${id} both own ${module}#${method}.`
        );
      }
      ownedMethods.set(sink, id);
    }
    return { id, module, methods };
  }).sort((left, right) => compareCanonicalText(left.id, right.id));

  const boundaryIds = new Set<string>();
  const protectedBy = new Set<string>();
  const boundaries = value.boundaries.map((rawBoundary, index): OperationalRiskBoundary => {
    assertObject(rawBoundary, `operationalRisks.boundaries[${index}]`);
    const id = normalizedId(rawBoundary.id, `operationalRisks.boundaries[${index}].id`);
    if (boundaryIds.has(id)) {
      throw new AtlasError('INVALID_CONFIG', `Operational boundary IDs collide after normalization: ${id}`);
    }
    boundaryIds.add(id);
    const module = exactOperationalModule(rawBoundary.module, `operationalRisks.boundaries[${index}].module`);
    const protects = normalizedUniqueNames(rawBoundary.protects, `operationalRisks.boundaries[${index}].protects`);
    for (const writerId of protects) {
      if (!writerIds.has(writerId)) {
        throw new AtlasError('INVALID_CONFIG', `Operational boundary ${id} protects unknown writer ${writerId}.`);
      }
      protectedBy.add(writerId);
    }
    return { id, module, protects };
  }).sort((left, right) => compareCanonicalText(left.id, right.id));

  const unprotected = protectedWriters.map((writer) => writer.id).filter((id) => !protectedBy.has(id));
  if (unprotected.length) {
    throw new AtlasError(
      'INVALID_CONFIG',
      `Every protected writer must be owned by at least one boundary; unowned: ${unprotected.join(', ')}.`
    );
  }
  return { guardPaths, seedDictionarySources, boundaries, protectedWriters };
}

function lifecyclePathsOverlap(left: string, right: string): boolean {
  const leftFolded = left.toLowerCase();
  const rightFolded = right.toLowerCase();
  return (
    leftFolded === rightFolded ||
    leftFolded.startsWith(`${rightFolded}/`) ||
    rightFolded.startsWith(`${leftFolded}/`)
  );
}

function lifecycleRules(value: unknown): LifecyclePathRule[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new AtlasError('INVALID_CONFIG', 'lifecycleRules must be an array.');
  const rules: LifecyclePathRule[] = [];
  const ruleIds = new Set<string>();
  const ownedPaths: Array<{ path: string; ruleId: string }> = [];
  for (let index = 0; index < value.length; index += 1) {
    const rawRule = value[index];
    assertObject(rawRule, `lifecycleRules[${index}]`);
    if (typeof rawRule.id !== 'string' || typeof rawRule.state !== 'string') {
      throw new AtlasError('INVALID_CONFIG', `lifecycleRules[${index}] requires id and state.`);
    }
    const id = rawRule.id.normalize('NFC');
    if (!id.trim()) throw new AtlasError('INVALID_CONFIG', `lifecycleRules[${index}].id must contain a non-whitespace character.`);
    if (ruleIds.has(id)) throw new AtlasError('INVALID_CONFIG', `Lifecycle rule IDs collide after normalization: ${rawRule.id}`);
    ruleIds.add(id);
    const paths = normalizedPathSet(stringArray(rawRule.paths, `lifecycleRules[${index}].paths`));
    if (!paths.length) throw new AtlasError('INVALID_CONFIG', `lifecycleRules[${index}].paths cannot be empty.`);
    for (const lifecyclePath of paths) {
      if (/[?*{}\[\]]/u.test(lifecyclePath)) {
        throw new AtlasError('INVALID_CONFIG', `Lifecycle rule paths are exact file or directory roots, not globs: ${lifecyclePath}`);
      }
      const overlap = ownedPaths.find((owned) => lifecyclePathsOverlap(lifecyclePath, owned.path));
      if (overlap) {
        throw new AtlasError(
          'INVALID_CONFIG',
          `Lifecycle paths must not overlap: ${overlap.ruleId}:${overlap.path} and ${id}:${lifecyclePath}`
        );
      }
      ownedPaths.push({ path: lifecyclePath, ruleId: id });
    }
    rules.push({
      id,
      state: rawRule.state as LifecyclePathRule['state'],
      paths
    });
  }
  return rules;
}

export async function loadConfiguration(targetConfigPath: string, profilePath: string): Promise<{
  target: TargetConfig;
  profile: ResolvedProfile;
  targetRoot: string;
  targetConfigPath: string;
  profilePath: string;
}> {
  const absoluteProfilePath = path.resolve(profilePath);
  const [descriptor, rawProfile] = await Promise.all([
    resolveTargetDescriptor(targetConfigPath),
    readJson<unknown>(absoluteProfilePath)
  ]);
  const absoluteTargetConfigPath = descriptor.targetConfigPath;
  const rawTarget: unknown = descriptor.target;
  await assertSchema('profile', rawProfile, 'Profile configuration');
  assertObject(rawTarget, 'Target configuration');
  assertObject(rawProfile, 'Profile configuration');
  if (rawTarget.schemaVersion !== 1 || typeof rawTarget.id !== 'string' || typeof rawTarget.path !== 'string') {
    throw new AtlasError('INVALID_CONFIG', 'Target configuration requires schemaVersion 1, id, and path.');
  }
  assertObject(rawTarget.consent, 'Target consent');
  for (const permission of ['agentReview', 'export', 'projectMemory']) {
    if (typeof rawTarget.consent[permission] !== 'boolean') {
      throw new AtlasError('INVALID_CONFIG', `Target consent.${permission} must be boolean.`);
    }
  }
  if (rawProfile.schemaVersion !== 1 || typeof rawProfile.id !== 'string') {
    throw new AtlasError('INVALID_CONFIG', 'Profile configuration requires schemaVersion 1 and id.');
  }
  const includeRoots = stringArray(rawProfile.includeRoots, 'includeRoots');
  if (!includeRoots.length) throw new AtlasError('INVALID_CONFIG', 'Profile includeRoots cannot be empty.');
  const normalizedIncludeRoots = [...new Set(includeRoots.map(normalizeIncludeRoot))].sort(compareCanonicalText);
  const explicitExclude = normalizedPathSet(stringArray(rawProfile.exclude, 'exclude'));
  const exclude = normalizedPathSet([...DEFAULT_EXCLUDES, ...explicitExclude]);
  const entrypoints = normalizedPathSet(stringArray(rawProfile.entrypoints, 'entrypoints'));
  const envExampleFiles = normalizedPathSet(stringArray(rawProfile.envExampleFiles, 'envExampleFiles'));
  const platformRoots = normalizedPathSet(stringArray(rawProfile.platformRoots, 'platformRoots'));
  const deadCodeExemptions = normalizedPathSet(stringArray(rawProfile.deadCodeExemptions, 'deadCodeExemptions'));
  const fixturePatterns = normalizedPathSet(stringArray(rawProfile.fixturePatterns, 'fixturePatterns'));
  const normalizedFixtureUnresolvedImports = fixtureUnresolvedImports(
    rawProfile.fixtureUnresolvedImports,
    new Set(fixturePatterns)
  );
  const normalizedLoaderRules = loaderRules(rawProfile.loaderRules);
  const operationalRisks = operationalRiskProfile(rawProfile.operationalRisks);
  const configuredPatterns = new Map<PatternExpectation['collection'], ReadonlySet<string>>([
    ['includeRoots', new Set(normalizedIncludeRoots.filter((entry) => entry !== '.'))],
    ['exclude', new Set(explicitExclude)],
    ['entrypoints', new Set(entrypoints)],
    ['deadCodeExemptions', new Set(deadCodeExemptions)],
    ['fixturePatterns', new Set(fixturePatterns)],
    ['guardPaths', new Set(operationalRisks?.guardPaths ?? [])],
    ['seedDictionarySources', new Set(operationalRisks?.seedDictionarySources ?? [])],
    ['loaderPaths', new Set(normalizedLoaderRules.flatMap((rule) => rule.loaderPaths))],
    ['loadedPatterns', new Set(normalizedLoaderRules.flatMap((rule) => rule.loadedPatterns))]
  ]);
  const normalizedPatternExpectations = patternExpectations(rawProfile.patternExpectations, configuredPatterns);
  const normalizedRuleExpectations = ruleExpectations(rawProfile.ruleExpectations);
  const normalizedLifecycleRules = lifecycleRules(rawProfile.lifecycleRules);
  const aliases: Record<string, string[]> = {};
  if (rawProfile.aliases !== undefined) {
    assertObject(rawProfile.aliases, 'aliases');
    for (const [key, value] of Object.entries(rawProfile.aliases).sort(([left], [right]) => compareCanonicalText(left, right))) {
      const normalizedKey = key.normalize('NFC');
      if (Object.hasOwn(aliases, normalizedKey)) throw new AtlasError('INVALID_CONFIG', `Alias keys collide after normalization: ${key}`);
      if ((normalizedKey.match(/\*/g) ?? []).length > 1) throw new AtlasError('INVALID_CONFIG', `Alias pattern may contain at most one wildcard: ${key}`);
      const targets = [...new Set(stringArray(value, `aliases.${key}`).map(normalizeTargetRelative))];
      if (targets.some((entry) => (entry.match(/\*/g) ?? []).length > 1)) {
        throw new AtlasError('INVALID_CONFIG', `Alias targets may contain at most one wildcard: ${key}`);
      }
      aliases[normalizedKey] = targets;
    }
  }
  const maxFileBytes = rawProfile.maxFileBytes === undefined ? 2_000_000 : rawProfile.maxFileBytes;
  if (!Number.isSafeInteger(maxFileBytes) || (maxFileBytes as number) <= 0 || (maxFileBytes as number) > HARD_MAX_FILE_BYTES) {
    throw new AtlasError('INVALID_CONFIG', `maxFileBytes must be a positive safe integer no greater than ${HARD_MAX_FILE_BYTES}.`);
  }
  let architecture: ProfileConfig['architecture'];
  if (rawProfile.architecture !== undefined) {
    assertObject(rawProfile.architecture, 'architecture');
    if (!Array.isArray(rawProfile.architecture.layers) || !Array.isArray(rawProfile.architecture.allowedDependencies)) {
      throw new AtlasError('INVALID_CONFIG', 'architecture requires layers and allowedDependencies arrays.');
    }
    const rawArchitecture = rawProfile.architecture as unknown as NonNullable<ProfileConfig['architecture']>;
    const seenLayerIds = new Set<string>();
    const layers = rawArchitecture.layers.map((layer) => {
      const id = layer.id.normalize('NFC');
      if (seenLayerIds.has(id)) {
        throw new AtlasError('INVALID_CONFIG', `Architecture layer IDs collide after normalization: ${layer.id}`);
      }
      seenLayerIds.add(id);
      return { id, patterns: normalizedPathSet(layer.patterns) };
    });
    const allowedDependencies = [...new Map(rawArchitecture.allowedDependencies.map((rule) => {
      const normalizedRule = { from: rule.from.normalize('NFC'), to: rule.to.normalize('NFC') };
      return [`${normalizedRule.from}\0${normalizedRule.to}`, normalizedRule] as const;
    })).values()].sort((left, right) => (
      compareCanonicalText(left.from, right.from) || compareCanonicalText(left.to, right.to)
    ));
    for (const rule of allowedDependencies) {
      if (!seenLayerIds.has(rule.from) || !seenLayerIds.has(rule.to)) {
        throw new AtlasError('INVALID_CONFIG', `Architecture dependency references an unknown layer: ${rule.from} -> ${rule.to}`);
      }
    }
    architecture = { layers, allowedDependencies };
  }
  const target = rawTarget as unknown as TargetConfig;
  const targetRoot = descriptor.targetRoot;
  const profile: ResolvedProfile = {
    schemaVersion: 1,
    id: rawProfile.id.normalize('NFC'),
    includeRoots: normalizedIncludeRoots,
    exclude,
    explicitExclude,
    entrypoints,
    aliases,
    envExampleFiles,
    platformRoots,
    deadCodeExemptions,
    fixturePatterns,
    fixtureUnresolvedImports: normalizedFixtureUnresolvedImports,
    loaderRules: normalizedLoaderRules,
    patternExpectations: normalizedPatternExpectations,
    ruleExpectations: normalizedRuleExpectations,
    ...(operationalRisks ? { operationalRisks } : {}),
    lifecycleRules: normalizedLifecycleRules,
    maxFileBytes: maxFileBytes as number,
    ...(architecture ? { architecture } : {})
  };
  return { target, profile, targetRoot, targetConfigPath: absoluteTargetConfigPath, profilePath: absoluteProfilePath };
}
