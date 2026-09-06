import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { analyzeJavaScriptTypeScript } from '../adapters/js-ts.js';
import { AtlasError } from '../errors.js';
import { assertSchema } from '../schema-validator.js';
import type {
  AnalysisFile,
  AnalysisHealthPatternObservation,
  AnalysisHealthRecord,
  AnalysisRuleHealth,
  DiagnosticRecord,
  IncidentRegressionCase,
  ProfilePatternObservation,
  ResolvedProfile,
  RuleExpectation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { canonicalJson, compareCanonicalText, readJson, sha256 } from '../util/canonical.js';
import {
  detectOperationalRisks,
  OPERATIONAL_RISK_ANALYSIS_VERSION,
  OPERATIONAL_RULE_CATALOG,
  OPERATIONAL_RULE_IDS,
  type OperationalRiskResult,
  type OperationalRuleId
} from '../analysis/operational-risks.js';

export const ANALYSIS_HEALTH_VERSION = '1.3.2';

const INCOMPLETE_INPUT_CODES_BY_RULE = new Map<string, ReadonlySet<string>>([
  [OPERATIONAL_RULE_IDS.seededDictionary, new Set([
    'OPERATIONAL_SEED_DICTIONARY_SOURCE_REQUIRED',
    'OPERATIONAL_SEED_DICTIONARY_SOURCE_UNRESOLVED',
    'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE',
    'OPERATIONAL_SEED_DICTIONARY_UNAVAILABLE'
  ])],
  [OPERATIONAL_RULE_IDS.accidentalProtection, new Set([
    'OPERATIONAL_ACCIDENTAL_PROTECTION_INPUT_INCOMPLETE',
    'OPERATIONAL_SOURCE_PARSE_INCOMPLETE'
  ])]
]);

export function operationalRuleInputStatus(
  ruleId: string,
  diagnostics: readonly DiagnosticRecord[]
): 'complete' | 'incomplete' {
  const incompleteCodes = INCOMPLETE_INPUT_CODES_BY_RULE.get(ruleId);
  return incompleteCodes && diagnostics.some((entry) => incompleteCodes.has(entry.code))
    ? 'incomplete'
    : 'complete';
}

export function operationalRuleInputStatusFromCodes(
  ruleId: string,
  diagnosticCodes: ReadonlySet<string>
): 'complete' | 'incomplete' {
  const incompleteCodes = INCOMPLETE_INPUT_CODES_BY_RULE.get(ruleId);
  return incompleteCodes && [...incompleteCodes].some((code) => diagnosticCodes.has(code))
    ? 'incomplete'
    : 'complete';
}

interface CorpusFixtureFile {
  path: string;
  content: string;
}

interface CorpusFixture {
  files: CorpusFixtureFile[];
}

interface CorpusCase {
  id: string;
  family: string;
  ruleId: OperationalRuleId;
  mechanismId: string;
  expected: { brokenMinimum: number; fixedMaximum: number };
  broken: CorpusFixture;
  fixed: CorpusFixture;
}

interface IncidentCorpus {
  $schema?: string;
  schemaVersion: 1;
  id: string;
  provenance: {
    source: string;
    recordedAt: string;
    target: string;
    revision: string;
    note: string;
  };
  cases: CorpusCase[];
}

export interface OperationalControlEvaluation {
  catalogDigest: string;
  corpusDigest: string;
  rules: AnalysisRuleHealth[];
  incidents: IncidentRegressionCase[];
  enabledRuleIds: Set<OperationalRuleId>;
}

const DEFAULT_CORPUS_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../corpus/incidents/synthetic-operational-risks/manifest.json'
);

const CORPUS_PROFILE: ResolvedProfile = {
  schemaVersion: 1,
  id: 'incident-regression-corpus',
  includeRoots: ['.'],
  exclude: [],
  entrypoints: [],
  aliases: {},
  envExampleFiles: [],
  platformRoots: [],
  deadCodeExemptions: [],
  operationalRisks: {
    guardPaths: ['src/services/**'],
    seedDictionarySources: ['**/*.sql', '**/seeders/**'],
    boundaries: [{
      id: 'appointment-create-boundary',
      module: 'src/services/appointment.service.ts',
      protects: ['appointment-create-writer']
    }],
    protectedWriters: [{
      id: 'appointment-create-writer',
      module: 'src/repositories/appointment.ts',
      methods: ['create']
    }]
  },
  lifecycleRules: [],
  maxFileBytes: 1_000_000
};

/**
 * Every independently implemented detector branch needs its own positive and
 * negative control. Matching on a branch-specific signal prevents a different
 * mechanism under the same umbrella rule from accidentally satisfying it.
 */
export const OPERATIONAL_MECHANISM_CATALOG = [
  { ruleId: 'operational/silent-empty-instrument-v1', mechanismId: 'zero-observation-success', requiredSignals: ['zero-observation-success-enabled'] },
  { ruleId: 'operational/silent-empty-instrument-v1', mechanismId: 'pipeline-status-mask', requiredSignals: ['conditional-uses-terminal-pipeline-status'] },
  { ruleId: 'operational/silent-empty-instrument-v1', mechanismId: 'non-enforced-count', requiredSignals: ['observation-count-only-logged'] },
  { ruleId: 'operational/host-container-path-divergence-v1', mechanismId: 'dirname-divergence', requiredSignals: ['literal-host-container-resolution-diverges'] },
  { ruleId: 'operational/host-container-path-divergence-v1', mechanismId: 'host-rooted-literal', requiredSignals: ['host-rooted-literal-used-under-container-root'] },
  { ruleId: 'operational/host-container-path-divergence-v1', mechanismId: 'copy-only-runtime-source', requiredSignals: ['container-read-depends-on-build-copy'] },
  { ruleId: 'operational/guard-bypass-v1', mechanismId: 'guard-bypass', requiredSignals: ['direct-low-level-writer-call'] },
  { ruleId: 'contract/vocabulary-drift-v1', mechanismId: 'vocabulary-drift', requiredSignals: ['complete-literal-vocabularies-disagree'] },
  { ruleId: 'operational/clock-date-basis-v1', mechanismId: 'absolute-test-date', requiredSignals: ['absolute-test-date'] },
  { ruleId: 'operational/clock-date-basis-v1', mechanismId: 'open-ended-date-range', requiredSignals: ['date-lower-bound-observed'] },
  { ruleId: 'operational/clock-date-basis-v1', mechanismId: 'tenant-process-clock', requiredSignals: ['process-clock-read'] },
  { ruleId: 'operational/clock-date-basis-v1', mechanismId: 'date-without-time', requiredSignals: ['date-only-bound-observed'] },
  { ruleId: 'operational/result-collapse-v1', mechanismId: 'result-collapse', requiredSignals: ['caller-reads-success-only'] },
  { ruleId: 'operational/result-collapse-v1', mechanismId: 'durable-success-side-effect', requiredSignals: ['durable-success-write-without-discriminator-branch'] },
  { ruleId: 'operational/result-collapse-v1', mechanismId: 'swallowed-catch', requiredSignals: ['caught-error-not-propagated'] },
  { ruleId: 'operational/result-collapse-v1', mechanismId: 'cli-success-on-error', requiredSignals: ['successful-exit-status-on-error-path'] },
  { ruleId: 'operational/duplicate-guard-fragment-v1', mechanismId: 'duplicate-guard', requiredSignals: ['normalized-guard-fragment-duplicate'] },
  { ruleId: 'contract/seeded-dictionary-id-coupling-v1', mechanismId: 'seed-id-name-mismatch', requiredSignals: ['seeded-id-name-mismatch'] },
  { ruleId: 'contract/seeded-dictionary-id-coupling-v1', mechanismId: 'seed-name-missing', requiredSignals: ['name-absent-from-complete-seed'] },
  { ruleId: 'contract/seeded-dictionary-id-coupling-v1', mechanismId: 'seed-test-integer-coupling', requiredSignals: ['test-asserts-seeded-integer-id'] },
  { ruleId: 'latent/accidental-protection-v1', mechanismId: 'unconsumed-protection', requiredSignals: ['protection-shaped-value-computed', 'lexically-unconsumed-local'] }
] as const satisfies ReadonlyArray<{
  ruleId: OperationalRuleId;
  mechanismId: string;
  requiredSignals: readonly string[];
}>;

export interface BundledOperationalControlContract {
  catalogDigest: string;
  corpusDigest: string;
  ruleIds: string[];
  incidents: Array<{
    id: string;
    family: string;
    ruleId: string;
    mechanismId: string;
    brokenMinimum: number;
    fixedMaximum: 0;
  }>;
}

function catalogDigest(): string {
  return sha256(canonicalJson({
    rules: OPERATIONAL_RULE_CATALOG,
    mechanisms: OPERATIONAL_MECHANISM_CATALOG
  }));
}

function analyzeCorpusFixture(fixture: CorpusFixture): OperationalRiskResult {
  const files = analysisFiles(fixture);
  const graph = analyzeJavaScriptTypeScript(files, CORPUS_PROFILE);
  return detectOperationalRisks(files, graph.relationships, CORPUS_PROFILE);
}

function language(filePath: string): string {
  const lower = filePath.toLowerCase();
  if (/\.(?:ts|mts|cts)$/u.test(lower)) return 'typescript';
  if (/\.(?:js|mjs|cjs)$/u.test(lower)) return 'javascript';
  if (/\.ya?ml$/u.test(lower)) return 'yaml';
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.sql')) return 'sql';
  if (lower.endsWith('.sh')) return 'shell';
  return 'text';
}

function kind(filePath: string): AnalysisFile['record']['kind'] {
  const lower = filePath.toLowerCase();
  if (/(?:^|\/)(?:tests?|__tests__|e2e|fixtures)(?:\/|$)|\.(?:test|spec)\./u.test(lower)) return 'test';
  if (/\.(?:[cm]?[jt]sx?)$/u.test(lower)) return 'source';
  return 'configuration';
}

function analysisFiles(fixture: CorpusFixture): AnalysisFile[] {
  return fixture.files.map((entry): AnalysisFile => {
    const content = Buffer.from(entry.content, 'utf8');
    return {
      record: {
        schemaVersion: SCHEMA_VERSION,
        id: `file:${sha256(canonicalJson({ corpus: true, path: entry.path })).slice(0, 24)}`,
        path: entry.path,
        sha256: sha256(content),
        bytes: content.length,
        kind: kind(entry.path),
        language: language(entry.path),
        symbols: [],
        environmentVariables: [],
        lifecycle: {
          state: 'unspecified' as const,
          basis: 'no-profile-match' as const,
          uncertainty: 'not-runtime-validated' as const,
          limitation: 'Synthetic incident-regression fixture; runtime state is intentionally unavailable.'
        },
        evidence: {
          level: 0,
          producer: 'atlas/incident-corpus',
          producerVersion: ANALYSIS_HEALTH_VERSION,
          basis: 'minimized-synthetic-regression-fixture',
          path: entry.path
        }
      },
      content
    };
  }).sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
}

async function loadCorpus(corpusPath = DEFAULT_CORPUS_PATH): Promise<IncidentCorpus> {
  const corpus = await readJson<IncidentCorpus>(corpusPath);
  await assertSchema('incident-corpus', corpus, 'Incident regression corpus');
  const caseIds = corpus.cases.map((entry) => entry.id);
  if (new Set(caseIds).size !== caseIds.length) throw new AtlasError('INVALID_CORPUS', 'Incident corpus contains duplicate case IDs.');
  const catalog = new Set(OPERATIONAL_RULE_CATALOG.map((entry) => entry.ruleId));
  const mechanisms = new Map(OPERATIONAL_MECHANISM_CATALOG.map((entry) => [
    `${entry.ruleId}\0${entry.mechanismId}`,
    entry
  ]));
  if (mechanisms.size !== OPERATIONAL_MECHANISM_CATALOG.length) {
    throw new AtlasError('INVALID_CORPUS', 'Operational mechanism catalog contains duplicate rule/mechanism pairs.');
  }
  if (OPERATIONAL_MECHANISM_CATALOG.some((entry) =>
    (entry.requiredSignals as readonly string[]).length === 0 ||
    new Set(entry.requiredSignals).size !== entry.requiredSignals.length
  )) {
    throw new AtlasError('INVALID_CORPUS', 'Operational mechanism catalog contains invalid signal matchers.');
  }
  for (const rule of catalog) {
    if (!OPERATIONAL_MECHANISM_CATALOG.some((entry) => entry.ruleId === rule)) {
      throw new AtlasError('INVALID_CORPUS', `Operational rule has no catalogued detector mechanism: ${rule}`);
    }
  }
  for (const incident of corpus.cases) {
    const descriptor = OPERATIONAL_RULE_CATALOG.find((entry) => entry.ruleId === incident.ruleId);
    if (!descriptor || !catalog.has(incident.ruleId)) {
      throw new AtlasError('INVALID_CORPUS', `Incident ${incident.id} references an undeclared operational rule.`);
    }
    if (incident.family !== descriptor.family) {
      throw new AtlasError('INVALID_CORPUS', `Incident ${incident.id} family differs from its operational rule.`);
    }
    if (!mechanisms.has(`${incident.ruleId}\0${incident.mechanismId}`)) {
      throw new AtlasError('INVALID_CORPUS', `Incident ${incident.id} references an undeclared mechanism for ${incident.ruleId}.`);
    }
    if (incident.expected.fixedMaximum !== 0) {
      throw new AtlasError('INVALID_CORPUS', `Incident ${incident.id} must require zero fixed-case findings.`);
    }
  }
  for (const mechanism of OPERATIONAL_MECHANISM_CATALOG) {
    if (!corpus.cases.some((incident) =>
      incident.ruleId === mechanism.ruleId && incident.mechanismId === mechanism.mechanismId
    )) {
      throw new AtlasError(
        'INVALID_CORPUS',
        `Operational mechanism has no broken/fixed incident pair: ${mechanism.ruleId}/${mechanism.mechanismId}`
      );
    }
  }
  return corpus;
}

function mechanismFor(incident: CorpusCase): typeof OPERATIONAL_MECHANISM_CATALOG[number] {
  const mechanism = OPERATIONAL_MECHANISM_CATALOG.find((entry) =>
    entry.ruleId === incident.ruleId && entry.mechanismId === incident.mechanismId
  );
  if (!mechanism) throw new AtlasError('INVALID_CORPUS', `Incident ${incident.id} references an undeclared mechanism.`);
  return mechanism;
}

function countFor(result: OperationalRiskResult, incident: CorpusCase): number {
  const mechanism = mechanismFor(incident);
  return result.findings.filter((finding) =>
    finding.ruleId === incident.ruleId &&
    mechanism.requiredSignals.every((signal) => finding.signals.includes(signal))
  ).length;
}

function contractFor(corpus: IncidentCorpus): BundledOperationalControlContract {
  return {
    catalogDigest: catalogDigest(),
    corpusDigest: sha256(canonicalJson(corpus)),
    ruleIds: OPERATIONAL_RULE_CATALOG.map((entry) => entry.ruleId).sort(compareCanonicalText),
    incidents: corpus.cases.map((incident) => ({
      id: incident.id,
      family: incident.family,
      ruleId: incident.ruleId,
      mechanismId: incident.mechanismId,
      brokenMinimum: incident.expected.brokenMinimum,
      fixedMaximum: 0 as const
    })).sort((left, right) => compareCanonicalText(left.id, right.id))
  };
}

export async function bundledOperationalControlContract(): Promise<BundledOperationalControlContract> {
  return contractFor(await loadCorpus());
}

let bundledOperationalControlEvaluationPromise: Promise<OperationalControlEvaluation> | undefined;

/** Re-evaluates the bundled controls once per process for artifact verification. */
export function bundledOperationalControlEvaluation(): Promise<OperationalControlEvaluation> {
  bundledOperationalControlEvaluationPromise ??= evaluateOperationalControls();
  return bundledOperationalControlEvaluationPromise;
}

export async function evaluateOperationalControls(corpusPath = DEFAULT_CORPUS_PATH): Promise<OperationalControlEvaluation> {
  const corpus = await loadCorpus(corpusPath);
  const contract = contractFor(corpus);
  const raw = new Map<OperationalRuleId, Array<{
    incident: CorpusCase;
    broken: number | undefined;
    fixed: number | undefined;
    passed: boolean;
  }>>();
  for (const incident of [...corpus.cases].sort((left, right) => compareCanonicalText(left.id, right.id))) {
    let broken: number | undefined;
    let fixed: number | undefined;
    try {
      broken = countFor(analyzeCorpusFixture(incident.broken), incident);
    } catch {}
    try {
      fixed = countFor(analyzeCorpusFixture(incident.fixed), incident);
    } catch {}
    const passed = broken !== undefined && fixed !== undefined &&
      broken >= incident.expected.brokenMinimum && fixed === 0;
    const values = raw.get(incident.ruleId) ?? [];
    values.push({ incident, broken, fixed, passed });
    raw.set(incident.ruleId, values);
  }

  const enabledRuleIds = new Set<OperationalRuleId>();
  const rules: AnalysisRuleHealth[] = OPERATIONAL_RULE_CATALOG.map((descriptor): AnalysisRuleHealth => {
    const controls = raw.get(descriptor.ruleId) ?? [];
    const passed = controls.filter((entry) => entry.passed).length;
    const expectedObservations = controls.reduce((total, entry) => total + entry.incident.expected.brokenMinimum, 0);
    const observedObservations = controls.reduce((total, entry) => total + (entry.broken ?? 0), 0);
    const enabled = controls.length > 0 && passed === controls.length && observedObservations >= expectedObservations;
    if (enabled) enabledRuleIds.add(descriptor.ruleId);
    return {
      ruleId: descriptor.ruleId,
      state: enabled ? 'enabled' as const : 'disabled' as const,
      controls: {
        total: controls.length,
        passed,
        failed: controls.length - passed,
        expectedObservations,
        observedObservations
      }
    };
  }).sort((left, right) => compareCanonicalText(left.ruleId, right.ruleId));

  const incidents: IncidentRegressionCase[] = [...corpus.cases]
    .sort((left, right) => compareCanonicalText(left.id, right.id))
    .map((incident) => {
      const evaluation = raw.get(incident.ruleId)?.find((entry) => entry.incident.id === incident.id)!;
      const brokenOutcome = evaluation.broken === undefined
        ? 'not-evaluated' as const
        : evaluation.broken >= incident.expected.brokenMinimum ? 'detected' as const : 'missed' as const;
      const fixedOutcome = evaluation.fixed === undefined
        ? 'not-evaluated' as const
        : evaluation.fixed === 0 ? 'silent' as const : 'regressed' as const;
      return {
        id: incident.id,
        family: incident.family,
        ruleId: incident.ruleId,
        mechanismId: incident.mechanismId,
        broken: { expectedMinimum: incident.expected.brokenMinimum, observed: evaluation.broken ?? 0, outcome: brokenOutcome },
        fixed: { expectedMaximum: 0, observed: evaluation.fixed ?? 0, outcome: fixedOutcome },
        status: brokenOutcome === 'not-evaluated' || fixedOutcome === 'not-evaluated'
          ? 'unsupported' as const
          : brokenOutcome === 'detected' && fixedOutcome === 'silent' ? 'passed' as const : 'failed' as const
      };
    });
  return {
    catalogDigest: contract.catalogDigest,
    corpusDigest: contract.corpusDigest,
    rules,
    incidents,
    enabledRuleIds
  };
}

function healthCollection(collection: ProfilePatternObservation['collection']): AnalysisHealthPatternObservation['collection'] {
  if (collection === 'includeRoots') return 'include-root';
  if (collection === 'entrypoints') return 'entrypoint';
  if (collection === 'deadCodeExemptions') return 'dead-code-exemption';
  if (collection === 'fixturePatterns') return 'fixture-boundary';
  if (collection === 'guardPaths') return 'guard-boundary';
  if (collection === 'seedDictionarySources') return 'seed-dictionary-source';
  if (collection === 'loaderPaths' || collection === 'loadedPatterns') return 'loader-root';
  return 'exclude';
}

export function buildAnalysisHealthRecord(options: {
  runId: string;
  snapshotId: string;
  profileObservations: ProfilePatternObservation[];
  controls: OperationalControlEvaluation;
  operational: OperationalRiskResult;
  ruleExpectations: RuleExpectation[];
  suppressedFindingInstancesByRule?: Readonly<Record<string, number>>;
}): AnalysisHealthRecord {
  const profilePatterns = options.profileObservations.map((entry) => ({
    id: entry.id,
    collection: healthCollection(entry.collection),
    pattern: entry.pattern,
    expected: {
      minimum: entry.minMatches,
      ...(entry.maxMatches === undefined ? {} : { maximum: entry.maxMatches })
    },
    observed: entry.actualMatches,
    status: entry.status,
    samplePaths: entry.samplePaths
  })).sort((left, right) => compareCanonicalText(left.id, right.id));
  const detected = options.controls.incidents.filter((entry) => entry.broken.outcome === 'detected').length;
  const silent = options.controls.incidents.filter((entry) => entry.fixed.outcome === 'silent').length;
  const expectationsByRuleId = new Map(options.ruleExpectations.map((entry) => [entry.ruleId, entry]));
  const rules: AnalysisRuleHealth[] = options.controls.rules.map((rule) => {
    const expectation = expectationsByRuleId.get(rule.ruleId);
    const findingInstances = options.operational.findings
      .filter((entry) => entry.ruleId === rule.ruleId)
      .reduce((total, entry) => total + (entry.instanceCount ?? 1), 0);
    const suppressedFindingInstances = options.suppressedFindingInstancesByRule?.[rule.ruleId] ?? 0;
    if (suppressedFindingInstances > findingInstances) {
      throw new AtlasError(
        'DISPOSITION_COUNT_INVALID',
        `Suppressed finding instances exceed detected instances for ${rule.ruleId}.`
      );
    }
    const normalizedExpectations = expectation === undefined ? undefined : {
      ...(expectation.minObservations === undefined
        ? {}
        : { minimumDetectedObservations: expectation.minObservations }),
      ...(expectation.maxObservations === undefined
        ? {}
        : { maximumPossibleObservations: expectation.maxObservations }),
      ...(expectation.minFindings === undefined
        ? {}
        : { minimumFindingInstances: expectation.minFindings }),
      ...(expectation.maxFindings === undefined
        ? {}
        : { maximumFindingInstances: expectation.maxFindings })
    };
    return {
      ...rule,
      target: {
        inputStatus: operationalRuleInputStatus(rule.ruleId, options.operational.diagnostics),
        detectedObservations: options.operational.observations.filter(
          (entry) => entry.ruleId === rule.ruleId && entry.state === 'detected'
        ).length,
        uncertainObservations: options.operational.observations.filter(
          (entry) => entry.ruleId === rule.ruleId && entry.state === 'uncertain'
        ).length,
        findingInstances,
        ...(suppressedFindingInstances > 0 ? { suppressedFindingInstances } : {}),
        ...(normalizedExpectations === undefined ? {} : { expectations: normalizedExpectations })
      }
    };
  });
  const status = profilePatterns.every((entry) => entry.status === 'passed') &&
    rules.every((entry) => entry.state === 'enabled' && entry.target?.inputStatus !== 'incomplete') &&
    options.controls.incidents.every((entry) => entry.status === 'passed')
    ? 'complete' as const
    : 'incomplete' as const;
  return {
    schemaVersion: SCHEMA_VERSION,
    runId: options.runId,
    snapshotId: options.snapshotId,
    producer: { id: 'atlas/analysis-health', version: ANALYSIS_HEALTH_VERSION },
    catalogDigest: options.controls.catalogDigest,
    corpusDigest: options.controls.corpusDigest,
    status,
    profilePatterns,
    rules,
    incidents: options.controls.incidents,
    recall: { tier: 'synthetic', numerator: detected, denominator: options.controls.incidents.length },
    realTargetEvaluation: {
      tier: 'real-target',
      result: 'not-recorded-in-run',
      reportContract: 'real-target-corpus-report.schema.json'
    },
    fixedCaseSilence: { numerator: silent, denominator: options.controls.incidents.length }
  };
}

export function applyOperationalControls(
  result: OperationalRiskResult,
  controls: OperationalControlEvaluation
): OperationalRiskResult {
  const findings = result.findings.filter((finding) => controls.enabledRuleIds.has(finding.ruleId as OperationalRuleId));
  const observations = result.observations.filter((observation) => controls.enabledRuleIds.has(observation.ruleId));
  const disabledDiagnostics: DiagnosticRecord[] = controls.rules
    .filter((rule) => rule.state === 'disabled')
    .map((rule) => ({
      schemaVersion: SCHEMA_VERSION,
      id: `diagnostic:${sha256(canonicalJson({ code: 'ANALYSIS_RULE_DISABLED', ruleId: rule.ruleId })).slice(0, 24)}`,
      code: 'ANALYSIS_RULE_DISABLED',
      severity: 'error',
      message: `Operational rule ${rule.ruleId} was disabled because its mechanism-level broken/fixed controls did not satisfy the required outcomes. Target findings from this rule were suppressed.`,
      evidence: {
        level: 1,
        producer: 'atlas/analysis-health',
        producerVersion: ANALYSIS_HEALTH_VERSION,
        basis: 'rule-positive-and-negative-control'
      }
    }));
  return {
    findings,
    observations,
    containerCoverage: controls.enabledRuleIds.has(OPERATIONAL_RULE_IDS.hostContainerPath)
      ? result.containerCoverage
      : [],
    diagnostics: [...result.diagnostics, ...disabledDiagnostics].sort((left, right) => compareCanonicalText(left.id, right.id))
  };
}

export function enforceRuleExpectations(
  profile: ResolvedProfile,
  result: OperationalRiskResult
): void {
  const failures: string[] = [];
  const cataloguedRules = new Set(OPERATIONAL_RULE_CATALOG.map((entry) => entry.ruleId as string));
  for (const expectation of profile.ruleExpectations ?? []) {
    if (!cataloguedRules.has(expectation.ruleId)) {
      throw new AtlasError('INVALID_CONFIG', `Rule expectation names an uncatalogued operational rule: ${expectation.ruleId}`);
    }
    const detectedObservations = result.observations.filter(
      (entry) => entry.ruleId === expectation.ruleId && entry.state === 'detected'
    ).length;
    const uncertainObservations = result.observations.filter(
      (entry) => entry.ruleId === expectation.ruleId && entry.state === 'uncertain'
    ).length;
    const possibleObservations = detectedObservations + uncertainObservations;
    const findingInstances = result.findings
      .filter((entry) => entry.ruleId === expectation.ruleId)
      .reduce((total, entry) => total + (entry.instanceCount ?? 1), 0);
    if (expectation.minObservations !== undefined && detectedObservations < expectation.minObservations) {
      failures.push(`${expectation.ruleId}: detected observations ${detectedObservations} < ${expectation.minObservations} (${uncertainObservations} uncertain)`);
    }
    if (expectation.maxObservations !== undefined && possibleObservations > expectation.maxObservations) {
      failures.push(`${expectation.ruleId}: possible observations ${possibleObservations} > ${expectation.maxObservations} (${uncertainObservations} uncertain)`);
    }
    if (expectation.minFindings !== undefined && findingInstances < expectation.minFindings) {
      failures.push(`${expectation.ruleId}: finding instances ${findingInstances} < ${expectation.minFindings}`);
    }
    if (expectation.maxFindings !== undefined && findingInstances > expectation.maxFindings) {
      failures.push(`${expectation.ruleId}: finding instances ${findingInstances} > ${expectation.maxFindings}`);
    }
  }
  if (failures.length) {
    throw new AtlasError('RULE_OBSERVATION_COUNT_MISMATCH', `Rule observation expectations failed: ${failures.sort(compareCanonicalText).join('; ')}`);
  }
}

export const OPERATIONAL_ANALYSIS_MARKER = `operational-risks-v${OPERATIONAL_RISK_ANALYSIS_VERSION}`;

const OPERATIONAL_MARKER_BY_HEALTH_VERSION = new Map<string, string>([
  ['1.2.0', 'operational-risks-v1.2.2'],
  ['1.3.0', 'operational-risks-v1.3.0'],
  ['1.3.1', 'operational-risks-v1.3.1'],
  [ANALYSIS_HEALTH_VERSION, OPERATIONAL_ANALYSIS_MARKER]
]);

export function operationalAnalysisMarkerForHealthVersion(healthVersion: string): string | undefined {
  return OPERATIONAL_MARKER_BY_HEALTH_VERSION.get(healthVersion);
}

export function analysisHealthUsesProfileObservationContract(healthVersion: string): boolean {
  return healthVersion === '1.3.0' || healthVersion === '1.3.1' || healthVersion === ANALYSIS_HEALTH_VERSION;
}
