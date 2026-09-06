import { lstat, readFile, realpath, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { runIsolatedAnalysis } from '../analysis/isolated.js';
import {
  OPERATIONAL_RULE_CATALOG,
  type ContainerCoverageRecord
} from '../analysis/operational-risks.js';
import { discoverGitRepository } from '../discovery/git.js';
import type { GitDiscoveryResult } from '../discovery/types.js';
import { AtlasError } from '../errors.js';
import { assertSchema } from '../schema-validator.js';
import type {
  AnalysisFile,
  DiagnosticRecord,
  FileKind,
  FindingRecord,
  OperationalRiskProfile,
  ResolvedProfile
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { canonicalJson, compareCanonicalText, readJson, sha256 } from '../util/canonical.js';

export const REAL_TARGET_REGRESSION_VERSION = '1.1.0';

const DEFAULT_REAL_TARGET_CORPUS_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../corpus/real-target/example-target/manifest.json'
);

const REAL_TARGET_RULE_CATALOG = [
  ...OPERATIONAL_RULE_CATALOG,
  {
    family: 'api-client-route-missing',
    ruleId: 'contract/api-client-route-missing-v1'
  }
] as const;

interface RealTargetAnchor {
  path: string;
  line: number;
  contains: string;
}

interface RealTargetCaseBase {
  id: string;
  family: string;
  ruleId: string;
  mechanismId: string;
  anchor: RealTargetAnchor;
}

interface RealTargetFindingCase extends RealTargetCaseBase {
  kind: 'finding';
  supportingAnchors: RealTargetAnchor[];
  expected: {
    minimum: number;
    requiredSignals: string[];
  };
}

interface RealTargetContainerCase extends RealTargetCaseBase {
  kind: 'container-mapping';
  mapping: {
    composePath: string;
    service: string;
    buildContext: string;
    dockerfile: string;
    workingDirectory: string;
    hostRoot: string;
    containerRoot: string;
    representativePath: string;
    expectedContainerPath: string;
    sourceKind: 'bind-mount' | 'docker-copy';
    selection: 'broad-test-command' | 'explicit-test-path';
  };
  expected: {
    forbiddenDiagnosticCodes: string[];
  };
}

type RealTargetCase = RealTargetFindingCase | RealTargetContainerCase;

interface RealTargetCorpus {
  $schema?: string;
  schemaVersion: 1;
  id: string;
  tier: 'real-target';
  provenance: {
    source: string;
    recordedAt: string;
    note: string;
  };
  target: {
    repository: string;
    revision: string;
    objectFormat: 'sha1' | 'sha256';
    requireDetached: true;
    requireClean: true;
  };
  analysis: {
    entrypoints: string[];
    maxFileBytes: number;
    operationalRisks: OperationalRiskProfile;
  };
  cases: RealTargetCase[];
}

export interface RealTargetRegressionDiagnostic {
  code: string;
  message: string;
  path?: string;
}

export interface RealTargetRegressionCaseResult {
  id: string;
  family: string;
  ruleId: string;
  mechanismId: string;
  kind: RealTargetCase['kind'];
  anchor: RealTargetAnchor;
  outcome: 'passed' | 'failed' | 'not-evaluated';
  observed: {
    matches: number;
    anchors: string[];
    diagnosticCodes: string[];
  };
}

export interface RealTargetRegressionReport {
  schemaVersion: 1;
  producer: {
    name: 'atlas/real-target-regression';
    version: string;
    executionPolicy: 'static-read-only';
  };
  tier: 'real-target';
  corpusId: string;
  corpusDigest: string;
  target: {
    repository: string;
    expectedRevision: string;
    observedRevision?: string;
    verification: 'verified' | 'not-evaluated';
    detached: boolean;
    clean: boolean;
  };
  status: 'passed' | 'failed' | 'not-evaluated';
  cases: RealTargetRegressionCaseResult[];
  summary: {
    total: number;
    evaluated: number;
    passed: number;
    failed: number;
  };
  realTargetRecall: {
    numerator: number;
    denominator: number;
  };
  diagnostics: RealTargetRegressionDiagnostic[];
}

export interface EvaluateRealTargetCorpusOptions {
  /** A clean detached checkout at the manifest's exact full revision. */
  targetRoot?: string;
  corpusPath?: string;
}

function reportDiagnostic(code: string, message: string, pathValue?: string): RealTargetRegressionDiagnostic {
  return pathValue === undefined ? { code, message } : { code, message, path: pathValue };
}

function sortDiagnostics(values: RealTargetRegressionDiagnostic[]): RealTargetRegressionDiagnostic[] {
  return [...values].sort((left, right) =>
    compareCanonicalText(left.code, right.code) ||
    compareCanonicalText(left.path ?? '', right.path ?? '') ||
    compareCanonicalText(left.message, right.message)
  );
}

async function loadRealTargetCorpus(corpusPath: string): Promise<RealTargetCorpus> {
  const corpus = await readJson<RealTargetCorpus>(corpusPath);
  await assertSchema('real-target-corpus', corpus, 'Real-target regression corpus');
  const ids = corpus.cases.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) {
    throw new AtlasError('INVALID_REAL_TARGET_CORPUS', 'Real-target corpus contains duplicate case IDs.');
  }
  const expectedRevisionLength = corpus.target.objectFormat === 'sha1' ? 40 : 64;
  if (corpus.target.revision.length !== expectedRevisionLength) {
    throw new AtlasError(
      'INVALID_REAL_TARGET_CORPUS',
      `Real-target corpus revision length does not match ${corpus.target.objectFormat}.`
    );
  }
  for (const entry of corpus.cases) {
    const descriptor = REAL_TARGET_RULE_CATALOG.find((candidate) => candidate.ruleId === entry.ruleId);
    if (!descriptor || descriptor.family !== entry.family) {
      throw new AtlasError(
        'INVALID_REAL_TARGET_CORPUS',
        `Real-target case ${entry.id} does not match a catalogued regression rule and family.`
      );
    }
  }
  return corpus;
}

function emptyCaseResult(entry: RealTargetCase): RealTargetRegressionCaseResult {
  return {
    id: entry.id,
    family: entry.family,
    ruleId: entry.ruleId,
    mechanismId: entry.mechanismId,
    kind: entry.kind,
    anchor: entry.anchor,
    outcome: 'not-evaluated',
    observed: { matches: 0, anchors: [], diagnosticCodes: [] }
  };
}

function baseReport(
  corpus: RealTargetCorpus,
  target: RealTargetRegressionReport['target'],
  diagnostics: RealTargetRegressionDiagnostic[]
): RealTargetRegressionReport {
  return {
    schemaVersion: SCHEMA_VERSION,
    producer: {
      name: 'atlas/real-target-regression',
      version: REAL_TARGET_REGRESSION_VERSION,
      executionPolicy: 'static-read-only'
    },
    tier: 'real-target',
    corpusId: corpus.id,
    corpusDigest: sha256(canonicalJson(corpus)),
    target,
    status: 'not-evaluated',
    cases: [...corpus.cases]
      .sort((left, right) => compareCanonicalText(left.id, right.id))
      .map(emptyCaseResult),
    summary: { total: corpus.cases.length, evaluated: 0, passed: 0, failed: 0 },
    realTargetRecall: { numerator: 0, denominator: 0 },
    diagnostics: sortDiagnostics(diagnostics)
  };
}

function cleanDiscovery(discovery: GitDiscoveryResult): boolean {
  return discovery.state === 'ready' && discovery.records.every((record) => {
    if (record.tracking === 'ignored') return true;
    if (record.tracking === 'untracked') return false;
    return !record.conflicted && record.indexStatus === 'clean' && record.worktreeStatus === 'clean';
  });
}

function discoveryGate(
  corpus: RealTargetCorpus,
  discovery: GitDiscoveryResult
): { target: RealTargetRegressionReport['target']; diagnostics: RealTargetRegressionDiagnostic[] } {
  const head = discovery.repository?.head;
  const observedRevision = head?.objectId;
  const detached = head?.state === 'detached';
  const clean = cleanDiscovery(discovery);
  const target: RealTargetRegressionReport['target'] = {
    repository: corpus.target.repository,
    expectedRevision: corpus.target.revision,
    ...(observedRevision === undefined ? {} : { observedRevision }),
    verification: 'not-evaluated',
    detached,
    clean
  };
  const diagnostics: RealTargetRegressionDiagnostic[] = [];
  if (discovery.state !== 'ready' || !discovery.repository) {
    diagnostics.push(reportDiagnostic(
      'REAL_TARGET_GIT_UNAVAILABLE',
      'Real-target evaluation requires complete, supported Git worktree discovery.'
    ));
  }
  if (discovery.repository && discovery.repository.objectFormat !== corpus.target.objectFormat) {
    diagnostics.push(reportDiagnostic(
      'REAL_TARGET_OBJECT_FORMAT_MISMATCH',
      'The target Git object format differs from the pinned corpus contract.'
    ));
  }
  if (!detached) {
    diagnostics.push(reportDiagnostic(
      'REAL_TARGET_NOT_DETACHED',
      'Real-target evaluation requires a detached checkout so the target cannot advance with a branch.'
    ));
  }
  if (observedRevision !== corpus.target.revision) {
    diagnostics.push(reportDiagnostic(
      'REAL_TARGET_REVISION_MISMATCH',
      'The target HEAD is not the exact full revision pinned by the real-target corpus.'
    ));
  }
  if (!clean) {
    diagnostics.push(reportDiagnostic(
      'REAL_TARGET_NOT_CLEAN',
      'Real-target evaluation requires a clean worktree with no staged, unstaged, conflicted, or untracked paths.'
    ));
  }
  if (diagnostics.length === 0) target.verification = 'verified';
  return { target, diagnostics };
}

function languageFor(filePath: string): string {
  const basename = path.posix.basename(filePath).toLowerCase();
  if (basename === 'dockerfile' || basename.startsWith('dockerfile.')) return 'dockerfile';
  const extension = path.posix.extname(filePath).toLowerCase();
  if (['.js', '.jsx', '.mjs', '.cjs'].includes(extension)) return 'javascript';
  if (['.ts', '.tsx', '.mts', '.cts'].includes(extension)) return 'typescript';
  if (extension === '.json') return 'json';
  if (extension === '.yaml' || extension === '.yml') return 'yaml';
  if (extension === '.sql') return 'sql';
  if (extension === '.sh' || extension === '.ps1') return 'shell';
  if (extension === '.md' || extension === '.mdx') return 'markdown';
  return extension ? extension.slice(1) : 'unknown';
}

function kindFor(filePath: string, language: string): FileKind {
  const lower = filePath.toLowerCase();
  if (/(?:^|\/)(?:test|tests|__tests__|e2e)(?:\/|$)|\.(?:test|spec)\.[^.]+$/u.test(lower)) return 'test';
  if (/\.(?:[cm]?[jt]sx?)$/u.test(lower)) return 'source';
  if (language === 'markdown') return 'documentation';
  if (language === 'json' || language === 'yaml' || language === 'dockerfile') return 'configuration';
  return 'other';
}

function relevantStaticInput(filePath: string): boolean {
  const basename = path.posix.basename(filePath).toLowerCase();
  return /\.(?:[cm]?[jt]sx?|json|ya?ml|sql|sh|ps1)$/u.test(filePath.toLowerCase()) ||
    basename === 'dockerfile' || basename.startsWith('dockerfile.');
}

function containedPath(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function readStaticInputs(
  corpus: RealTargetCorpus,
  targetRoot: string,
  discovery: GitDiscoveryResult
): Promise<{ files: AnalysisFile[]; diagnostics: RealTargetRegressionDiagnostic[] }> {
  const files: AnalysisFile[] = [];
  const diagnostics: RealTargetRegressionDiagnostic[] = [];
  const requiredPaths = new Set(corpus.cases.flatMap((entry) => [
    entry.anchor.path,
    ...(entry.kind === 'finding' ? entry.supportingAnchors.map((anchor) => anchor.path) : [
      entry.mapping.composePath,
      entry.mapping.dockerfile,
      entry.mapping.representativePath
    ])
  ]));
  const records = discovery.records
    .filter((record) => record.tracking === 'tracked' && record.kind === 'file')
    .filter((record) => relevantStaticInput(record.path) || requiredPaths.has(record.path))
    .sort((left, right) => compareCanonicalText(left.path, right.path));

  for (const record of records) {
    const absolutePath = path.resolve(targetRoot, ...record.path.split('/'));
    if (!containedPath(targetRoot, absolutePath)) {
      diagnostics.push(reportDiagnostic(
        'REAL_TARGET_PATH_OUTSIDE_ROOT',
        'A tracked path resolved outside the target root and was not read.',
        record.path
      ));
      continue;
    }
    let metadata;
    try {
      metadata = await lstat(absolutePath);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        diagnostics.push(reportDiagnostic(
          'REAL_TARGET_FILE_UNSUPPORTED',
          'A tracked static input is not a regular non-symbolic file and was not read.',
          record.path
        ));
        continue;
      }
      if (metadata.size > corpus.analysis.maxFileBytes) {
        diagnostics.push(reportDiagnostic(
          'REAL_TARGET_FILE_TOO_LARGE',
          'A tracked static input exceeds the corpus file-size limit and was not read.',
          record.path
        ));
        continue;
      }
      const canonicalPath = await realpath(absolutePath);
      if (!containedPath(targetRoot, canonicalPath)) {
        diagnostics.push(reportDiagnostic(
          'REAL_TARGET_PATH_OUTSIDE_ROOT',
          'A tracked path resolves outside the target root and was not read.',
          record.path
        ));
        continue;
      }
      const content = await readFile(canonicalPath);
      const after = await stat(canonicalPath);
      if (after.size !== metadata.size || after.mtimeMs !== metadata.mtimeMs) {
        throw new AtlasError('REAL_TARGET_CHANGED', `Target input changed while being read: ${record.path}`);
      }
      if (content.subarray(0, Math.min(content.length, 8192)).includes(0)) continue;
      const language = languageFor(record.path);
      files.push({
        record: {
          schemaVersion: SCHEMA_VERSION,
          id: `file:${sha256(canonicalJson({ corpus: corpus.id, path: record.path })).slice(0, 24)}`,
          path: record.path,
          sha256: sha256(content),
          bytes: content.length,
          kind: kindFor(record.path, language),
          language,
          symbols: [],
          environmentVariables: [],
          evidence: {
            level: 0,
            producer: 'atlas/real-target-regression',
            producerVersion: REAL_TARGET_REGRESSION_VERSION,
            basis: 'sha-pinned-static-read',
            path: record.path
          }
        },
        content
      });
    } catch (error) {
      if (error instanceof AtlasError) throw error;
      diagnostics.push(reportDiagnostic(
        'REAL_TARGET_FILE_UNREADABLE',
        'A tracked static input could not be read safely.',
        record.path
      ));
    }
  }
  for (const requiredPath of [...requiredPaths].sort(compareCanonicalText)) {
    if (!files.some((file) => file.record.path === requiredPath)) {
      diagnostics.push(reportDiagnostic(
        'REAL_TARGET_REQUIRED_INPUT_UNAVAILABLE',
        'A real-target case input was not available to the static evaluator.',
        requiredPath
      ));
    }
  }
  return { files, diagnostics: sortDiagnostics(diagnostics) };
}

function analysisProfile(corpus: RealTargetCorpus): ResolvedProfile {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `${corpus.id}-profile`,
    includeRoots: ['.'],
    exclude: [],
    explicitExclude: [],
    entrypoints: [...corpus.analysis.entrypoints],
    aliases: {},
    envExampleFiles: [],
    platformRoots: [],
    deadCodeExemptions: [],
    fixturePatterns: [],
    fixtureUnresolvedImports: [],
    loaderRules: [],
    patternExpectations: [],
    ruleExpectations: [],
    operationalRisks: corpus.analysis.operationalRisks,
    lifecycleRules: [],
    maxFileBytes: corpus.analysis.maxFileBytes
  };
}

function sourceAnchorPresent(anchor: RealTargetAnchor, filesByPath: ReadonlyMap<string, AnalysisFile>): boolean {
  const file = filesByPath.get(anchor.path);
  if (!file) return false;
  const line = file.content.toString('utf8').split(/\r?\n/u)[anchor.line - 1];
  return line?.includes(anchor.contains) ?? false;
}

function findingPrimaryAnchor(finding: FindingRecord): { path: string; line: number } | undefined {
  const primary = finding.evidence[0];
  if (!primary?.path || primary.line === undefined) return undefined;
  return { path: primary.path, line: primary.line };
}

function findingCaseResult(
  entry: RealTargetFindingCase,
  findings: FindingRecord[],
  filesByPath: ReadonlyMap<string, AnalysisFile>
): RealTargetRegressionCaseResult {
  const matches = findings.filter((finding) => {
    const primary = findingPrimaryAnchor(finding);
    return finding.ruleId === entry.ruleId && primary?.path === entry.anchor.path && primary.line === entry.anchor.line &&
      entry.expected.requiredSignals.every((signal) => finding.signals.includes(signal));
  });
  const anchors = matches
    .map(findingPrimaryAnchor)
    .filter((anchor): anchor is { path: string; line: number } => anchor !== undefined)
    .map((anchor) => `${anchor.path}:${anchor.line}`)
    .sort(compareCanonicalText);
  const sourceAnchorsPresent = [entry.anchor, ...entry.supportingAnchors]
    .every((anchor) => sourceAnchorPresent(anchor, filesByPath));
  return {
    id: entry.id,
    family: entry.family,
    ruleId: entry.ruleId,
    mechanismId: entry.mechanismId,
    kind: entry.kind,
    anchor: entry.anchor,
    outcome: sourceAnchorsPresent && matches.length >= entry.expected.minimum ? 'passed' : 'failed',
    observed: {
      matches: matches.length,
      anchors: [...new Set(anchors)],
      diagnosticCodes: []
    }
  };
}

function relevantContainerDiagnostic(entry: RealTargetContainerCase, diagnostic: DiagnosticRecord): boolean {
  if (diagnostic.path === entry.mapping.composePath) {
    return diagnostic.location === undefined || diagnostic.location.line >= entry.anchor.line;
  }
  // Source-anchored diagnostics can belong to a different broad test service
  // whose context does not mount this path. A positive coverage record binds
  // the named service unambiguously; only its Compose/Dockerfile configuration
  // diagnostics are relevant to this case.
  return diagnostic.path === entry.mapping.dockerfile;
}

function containerCaseResult(
  entry: RealTargetContainerCase,
  coverage: ContainerCoverageRecord[],
  diagnostics: DiagnosticRecord[],
  filesByPath: ReadonlyMap<string, AnalysisFile>
): RealTargetRegressionCaseResult {
  const matches = coverage.filter((record) =>
    record.ruleId === entry.ruleId &&
    record.composePath === entry.mapping.composePath &&
    record.service === entry.mapping.service &&
    record.buildContext === entry.mapping.buildContext &&
    record.dockerfile === entry.mapping.dockerfile &&
    record.workingDirectory === entry.mapping.workingDirectory &&
    record.hostRoot === entry.mapping.hostRoot &&
    record.containerRoot === entry.mapping.containerRoot &&
    record.sourcePath === entry.mapping.representativePath &&
    record.containerPath === entry.mapping.expectedContainerPath &&
    record.sourceKind === entry.mapping.sourceKind &&
    record.selection === entry.mapping.selection
  );
  const relevantDiagnostics = diagnostics.filter((diagnostic) => relevantContainerDiagnostic(entry, diagnostic));
  const diagnosticCodes = [...new Set(relevantDiagnostics.map((diagnostic) => diagnostic.code))].sort(compareCanonicalText);
  const forbidden = diagnosticCodes.filter((code) => entry.expected.forbiddenDiagnosticCodes.includes(code));
  return {
    id: entry.id,
    family: entry.family,
    ruleId: entry.ruleId,
    mechanismId: entry.mechanismId,
    kind: entry.kind,
    anchor: entry.anchor,
    outcome: sourceAnchorPresent(entry.anchor, filesByPath) && matches.length > 0 && forbidden.length === 0
      ? 'passed'
      : 'failed',
    observed: {
      matches: matches.length,
      anchors: [...new Set(matches.map((record) => `${record.composePath}#${record.service}:${record.sourcePath}->${record.containerPath}`))]
        .sort(compareCanonicalText),
      diagnosticCodes
    }
  };
}

function completedReport(
  corpus: RealTargetCorpus,
  target: RealTargetRegressionReport['target'],
  cases: RealTargetRegressionCaseResult[],
  diagnostics: RealTargetRegressionDiagnostic[]
): RealTargetRegressionReport {
  const orderedCases = [...cases].sort((left, right) => compareCanonicalText(left.id, right.id));
  const passed = orderedCases.filter((entry) => entry.outcome === 'passed').length;
  const failed = orderedCases.filter((entry) => entry.outcome === 'failed').length;
  return {
    schemaVersion: SCHEMA_VERSION,
    producer: {
      name: 'atlas/real-target-regression',
      version: REAL_TARGET_REGRESSION_VERSION,
      executionPolicy: 'static-read-only'
    },
    tier: 'real-target',
    corpusId: corpus.id,
    corpusDigest: sha256(canonicalJson(corpus)),
    target,
    status: failed === 0 ? 'passed' : 'failed',
    cases: orderedCases,
    summary: {
      total: orderedCases.length,
      evaluated: orderedCases.length,
      passed,
      failed
    },
    realTargetRecall: { numerator: passed, denominator: orderedCases.length },
    diagnostics: sortDiagnostics(diagnostics)
  };
}

async function validateReport(report: RealTargetRegressionReport): Promise<RealTargetRegressionReport> {
  await assertSchema('real-target-corpus-report', report, 'Real-target regression report');
  return report;
}

/**
 * Evaluates real incident shapes against an exact immutable checkout. The
 * evaluator only performs bounded Git discovery and static file reads; target
 * modules, scripts, hooks, package managers, and tests are never executed.
 */
export async function evaluateRealTargetCorpus(
  options: EvaluateRealTargetCorpusOptions = {}
): Promise<RealTargetRegressionReport> {
  const corpusPath = path.resolve(options.corpusPath ?? DEFAULT_REAL_TARGET_CORPUS_PATH);
  const corpus = await loadRealTargetCorpus(corpusPath);
  if (!options.targetRoot) {
    return validateReport(baseReport(corpus, {
      repository: corpus.target.repository,
      expectedRevision: corpus.target.revision,
      verification: 'not-evaluated',
      detached: false,
      clean: false
    }, [reportDiagnostic(
      'REAL_TARGET_ABSENT',
      'No real-target checkout was supplied; the SHA-pinned tier was not evaluated.'
    )]));
  }

  const requestedRoot = path.resolve(options.targetRoot);
  let targetRoot: string;
  try {
    targetRoot = await realpath(requestedRoot);
    if (!(await lstat(targetRoot)).isDirectory()) throw new Error('not-directory');
  } catch {
    return validateReport(baseReport(corpus, {
      repository: corpus.target.repository,
      expectedRevision: corpus.target.revision,
      verification: 'not-evaluated',
      detached: false,
      clean: false
    }, [reportDiagnostic(
      'REAL_TARGET_UNAVAILABLE',
      'The supplied real-target checkout is unavailable or is not a directory.'
    )]));
  }

  const before = await discoverGitRepository(targetRoot);
  const gate = discoveryGate(corpus, before);
  if (gate.diagnostics.length > 0) return validateReport(baseReport(corpus, gate.target, gate.diagnostics));

  let inputs: Awaited<ReturnType<typeof readStaticInputs>>;
  try {
    inputs = await readStaticInputs(corpus, targetRoot, before);
  } catch (error) {
    return validateReport(baseReport(corpus, gate.target, [reportDiagnostic(
      'REAL_TARGET_CHANGED',
      error instanceof AtlasError ? error.message : 'The target changed while static inputs were read.'
    )]));
  }
  if (inputs.diagnostics.some((entry) => entry.code === 'REAL_TARGET_REQUIRED_INPUT_UNAVAILABLE')) {
    return validateReport(baseReport(corpus, gate.target, inputs.diagnostics));
  }

  const profile = analysisProfile(corpus);
  const isolated = await runIsolatedAnalysis(inputs.files, profile, []);
  const operational = isolated.operationalResult;
  const apiContracts = isolated.apiContracts;

  const after = await discoverGitRepository(targetRoot);
  const afterGate = discoveryGate(corpus, after);
  if (afterGate.diagnostics.length > 0 || canonicalJson(after) !== canonicalJson(before)) {
    return validateReport(baseReport(corpus, afterGate.target, [
      ...afterGate.diagnostics,
      reportDiagnostic(
        'REAL_TARGET_CHANGED',
        'The target Git boundary changed during real-target evaluation, so all case results were discarded.'
      )
    ]));
  }

  const filesByPath = new Map(inputs.files.map((file) => [file.record.path, file]));
  const findings = [...operational.findings, ...apiContracts.findings];
  const cases = corpus.cases.map((entry) => entry.kind === 'finding'
    ? findingCaseResult(entry, findings, filesByPath)
    : containerCaseResult(entry, operational.containerCoverage, operational.diagnostics, filesByPath));
  return validateReport(completedReport(corpus, {
    ...gate.target,
    verification: 'verified'
  }, cases, inputs.diagnostics));
}
