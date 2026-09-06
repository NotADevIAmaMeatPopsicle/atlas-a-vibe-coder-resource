#!/usr/bin/env node
import { AtlasError, errorDetails } from './errors.js';
import { writeImmutableCanonicalReport } from './acceptance/report-output.js';
import { createChangedFindingsReport, writeChangedFindingsReport } from './changed-findings.js';
import {
  compareFindingRuns,
  writeFindingDeltaReport,
  type FindingSeverity
} from './finding-diff.js';
import {
  createHistoricalEvidenceIndex,
  queryHistoricalEvidence,
  verifyHistoricalEvidenceIndex
} from './historical-evidence/index.js';
import {
  planIncrementalAnalysis,
  planIncrementalAnalysisBatch,
  type IncrementalBatchPlanOptions
} from './incremental/index.js';
import { inspectRun, renderInspectionText, type InspectionDirection } from './inspect.js';
import { lookupMemory, runMemoryStdioService } from './memory.js';
import { queryRun } from './query.js';
import {
  ANALYSIS_HEALTH_VERSION,
  evaluateOperationalControls,
  type OperationalControlEvaluation
} from './regression/incidents.js';
import { evaluateRealTargetCorpus } from './regression/real-target.js';
import {
  completeReviewAttempt,
  createReviewExecution,
  failReviewAttempt,
  pauseReviewExecution,
  readReviewExecution,
  resumeReviewExecution,
  retryReviewAttempt,
  startReviewAttempt,
  verifyReviewExecution,
  MAX_REVIEW_RESULT_INPUT_BYTES,
  type ReviewResultInput,
  type ReviewReviewer
} from './review-execution/index.js';
import { readBoundedJsonFile } from './security/bounded-artifacts.js';
import { createReviewCampaign, reviewCampaignStatus } from './reviews.js';
import { scanProject } from './run.js';
import { assertPortableDataSafe } from './security/portable-data.js';
import { listTargetRegistrations, registerTarget, resolveTargetRootInput } from './targets.js';
import { TOOL_VERSION, type AnalysisHealthRecord, type AnalysisRuleHealth, type IncidentRegressionCase } from './types.js';
import { compareCanonicalText, readJson, terminalSafeJson } from './util/canonical.js';
import { verifyAndLoadRunDirectory } from './verify.js';
import { createRunViewer, runViewerServer, verifyRunViewer } from './viewer/index.js';

const EXIT_INCOMPLETE_HEALTH = 2;
const EXIT_FINDING_GATE_TRIGGERED = 3;

interface ParsedArguments {
  positionals: string[];
  options: Map<string, string | true>;
}

function parseArguments(values: string[]): ParsedArguments {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]!;
    if (!value.startsWith('--')) {
      positionals.push(value);
      continue;
    }
    const name = value.slice(2);
    if (!name) throw new AtlasError('CLI_USAGE', 'Invalid empty option name.');
    if (options.has(name)) throw new AtlasError('CLI_USAGE', `Duplicate option --${name}.`);
    const next = values[index + 1];
    if (next !== undefined && !next.startsWith('--')) {
      options.set(name, next);
      index += 1;
    } else {
      options.set(name, true);
    }
  }
  return { positionals, options };
}

function assertOptions(argumentsValue: ParsedArguments, allowed: string[]): void {
  for (const name of argumentsValue.options.keys()) {
    if (!allowed.includes(name)) throw new AtlasError('CLI_USAGE', `Unknown option --${name}.`);
  }
}

function assertPositionals(argumentsValue: ParsedArguments, count: number, command: string): void {
  if (argumentsValue.positionals.length > count) throw new AtlasError('CLI_USAGE', `${command} received unexpected positional arguments.`);
}

function option(argumentsValue: ParsedArguments, name: string, required = false): string | undefined {
  const value = argumentsValue.options.get(name);
  if (value === true) {
    if (required) throw new AtlasError('CLI_USAGE', `--${name} requires a value.`);
    return undefined;
  }
  if (value === undefined && required) throw new AtlasError('CLI_USAGE', `Missing required --${name}.`);
  return value;
}

function print(value: unknown): void {
  process.stdout.write(terminalSafeJson(value));
}

function ruleHealthSummary(rules: AnalysisRuleHealth[]): {
  total: number;
  enabled: number;
  disabled: number;
  disabledRuleIds: string[];
  incompleteInputRuleIds: string[];
  controls: {
    total: number;
    passed: number;
    failed: number;
    expectedObservations: number;
    observedObservations: number;
  };
} {
  const disabledRuleIds = rules
    .filter((rule) => rule.state === 'disabled')
    .map((rule) => rule.ruleId)
    .sort(compareCanonicalText);
  const incompleteInputRuleIds = rules
    .filter((rule) => rule.target?.inputStatus === 'incomplete')
    .map((rule) => rule.ruleId)
    .sort(compareCanonicalText);
  return {
    total: rules.length,
    enabled: rules.length - disabledRuleIds.length,
    disabled: disabledRuleIds.length,
    disabledRuleIds,
    incompleteInputRuleIds,
    controls: rules.reduce((summary, rule) => ({
      total: summary.total + rule.controls.total,
      passed: summary.passed + rule.controls.passed,
      failed: summary.failed + rule.controls.failed,
      expectedObservations: summary.expectedObservations + rule.controls.expectedObservations,
      observedObservations: summary.observedObservations + rule.controls.observedObservations
    }), { total: 0, passed: 0, failed: 0, expectedObservations: 0, observedObservations: 0 })
  };
}

function incidentSummary(incidents: IncidentRegressionCase[]): {
  total: number;
  passed: number;
  failed: number;
  unsupported: number;
  failedIncidentIds: string[];
  unsupportedIncidentIds: string[];
} {
  const failedIncidentIds = incidents
    .filter((incident) => incident.status === 'failed')
    .map((incident) => incident.id)
    .sort(compareCanonicalText);
  const unsupportedIncidentIds = incidents
    .filter((incident) => incident.status === 'unsupported')
    .map((incident) => incident.id)
    .sort(compareCanonicalText);
  return {
    total: incidents.length,
    passed: incidents.length - failedIncidentIds.length - unsupportedIncidentIds.length,
    failed: failedIncidentIds.length,
    unsupported: unsupportedIncidentIds.length,
    failedIncidentIds,
    unsupportedIncidentIds
  };
}

function analysisHealthSummary(health: AnalysisHealthRecord | undefined): unknown {
  if (!health) {
    return {
      state: 'legacy-not-recorded',
      limitation: 'This legacy eight-file run predates the analysis-health contract and makes no rule-control or incident-recall claim.'
    };
  }
  return {
    state: 'recorded',
    status: health.status,
    producer: health.producer,
    catalogDigest: health.catalogDigest,
    corpusDigest: health.corpusDigest,
    profilePatterns: {
      total: health.profilePatterns.length,
      passed: health.profilePatterns.filter((entry) => entry.status === 'passed').length,
      failed: health.profilePatterns.filter((entry) => entry.status === 'failed').length
    },
    ruleHealth: ruleHealthSummary(health.rules),
    incidentRecall: health.recall,
    ...(health.realTargetEvaluation === undefined ? {} : {
      realTargetEvaluation: health.realTargetEvaluation
    }),
    fixedCaseSilence: health.fixedCaseSilence,
    incidents: incidentSummary(health.incidents)
  };
}

function regressionVerificationSummary(controls: OperationalControlEvaluation): unknown {
  const detected = controls.incidents.filter((incident) => incident.broken.outcome === 'detected').length;
  const silent = controls.incidents.filter((incident) => incident.fixed.outcome === 'silent').length;
  const complete = controls.rules.every((rule) => rule.state === 'enabled') &&
    controls.incidents.every((incident) => incident.status === 'passed');
  return {
    schemaVersion: 1,
    kind: 'atlas-incident-regression-report',
    producer: {
      id: 'atlas/analysis-health',
      version: ANALYSIS_HEALTH_VERSION
    },
    tool: { name: 'atlas', version: TOOL_VERSION },
    status: complete ? 'passed' : 'incomplete',
    catalogDigest: controls.catalogDigest,
    corpusDigest: controls.corpusDigest,
    ruleHealth: ruleHealthSummary(controls.rules),
    incidentRecall: {
      tier: 'synthetic',
      numerator: detected,
      denominator: controls.incidents.length
    },
    realTargetEvaluation: {
      tier: 'real-target',
      result: 'not-recorded-in-run',
      reportContract: 'real-target-corpus-report.schema.json'
    },
    fixedCaseSilence: {
      numerator: silent,
      denominator: controls.incidents.length
    },
    incidentHealth: incidentSummary(controls.incidents),
    rules: controls.rules,
    incidents: controls.incidents
  };
}

function integerOption(argumentsValue: ParsedArguments, name: string, minimum = 0): number {
  const value = option(argumentsValue, name, true)!;
  if (!/^\d+$/u.test(value)) throw new AtlasError('CLI_USAGE', `--${name} must be an integer of at least ${minimum}.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new AtlasError('CLI_USAGE', `--${name} must be an integer of at least ${minimum}.`);
  }
  return parsed;
}

function reviewReviewer(argumentsValue: ParsedArguments): ReviewReviewer {
  const kind = option(argumentsValue, 'reviewer-kind', true)!;
  if (kind !== 'human' && kind !== 'agent') throw new AtlasError('CLI_USAGE', '--reviewer-kind must be human or agent.');
  const identity = option(argumentsValue, 'reviewer', true)!;
  const version = option(argumentsValue, 'reviewer-version', true)!;
  const promptVersion = option(argumentsValue, 'prompt-version', true)!;
  if (!identity.trim() || !version.trim() || !promptVersion.trim()) {
    throw new AtlasError('CLI_USAGE', 'Reviewer identity, version, and prompt version must not be empty.');
  }
  return { kind, identity, version, promptVersion };
}

async function reviewSelectors(argumentsValue: ParsedArguments): Promise<string[] | undefined> {
  const selector = option(argumentsValue, 'selector');
  const selectorFile = option(argumentsValue, 'selectors');
  if (selector && selectorFile) throw new AtlasError('CLI_USAGE', 'Use either --selector or --selectors, not both.');
  if (selector) return [selector];
  if (!selectorFile) return undefined;
  const value = await readJson<unknown>(selectorFile);
  if (!Array.isArray(value) || !value.length || value.some((entry) => typeof entry !== 'string')) {
    throw new AtlasError('CLI_USAGE', '--selectors must name a JSON file containing a non-empty string array.');
  }
  return value as string[];
}

function incrementalBatchTargets(value: unknown): IncrementalBatchPlanOptions['targets'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new AtlasError('CLI_USAGE', 'Incremental batch spec must be an object containing targets.');
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort(compareCanonicalText).join(',') !== 'targets' || !Array.isArray(record.targets)) {
    throw new AtlasError('CLI_USAGE', 'Incremental batch spec must contain only a targets array.');
  }
  if (!record.targets.length || record.targets.length > 100) {
    throw new AtlasError('CLI_USAGE', 'Incremental batch spec must contain between 1 and 100 targets.');
  }
  return record.targets.map((candidate, index) => {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      throw new AtlasError('CLI_USAGE', `Incremental batch target ${index + 1} must be an object.`);
    }
    const target = candidate as Record<string, unknown>;
    const expectedKeys = ['baselineRunDirectory', 'nextRunDirectory', 'targetId'].sort(compareCanonicalText);
    if (Object.keys(target).sort(compareCanonicalText).join(',') !== expectedKeys.join(',')) {
      throw new AtlasError('CLI_USAGE', `Incremental batch target ${index + 1} has unexpected or missing fields.`);
    }
    if (
      typeof target.targetId !== 'string' || !target.targetId ||
      typeof target.baselineRunDirectory !== 'string' || !target.baselineRunDirectory ||
      typeof target.nextRunDirectory !== 'string' || !target.nextRunDirectory
    ) throw new AtlasError('CLI_USAGE', `Incremental batch target ${index + 1} fields must be non-empty strings.`);
    return {
      targetId: target.targetId,
      baselineRunDirectory: target.baselineRunDirectory,
      nextRunDirectory: target.nextRunDirectory
    };
  });
}

function help(): string {
  return `Atlas ${TOOL_VERSION}

Usage:
  atlas scan --target <target.json> --profile <profile.json> --workspace <directory> [--dispositions <ledger.json>]
  atlas target register --target <target.json> --workspace <directory>
  atlas target list --workspace <directory>
  atlas verify <run-directory>
  atlas changed <run-directory> --target <target.json> --since <git-ref> [--output <report.json>]
  atlas diff --baseline <run-directory> --candidate <run-directory> [--fail-on-new info|low|medium|high] [--baseline-target <target.json> --candidate-target <target.json>] [--target <target.json> --output <report.json>]
  atlas regression verify [--output <report.json>]
  atlas regression real-target [--checkout <detached-checkout> | --target <target.json-or-checkout>] [--corpus <manifest.json>] [--output <report.json>]
  atlas inspect <run-directory> [--file <path-or-id> | --symbol <exact-name> | --finding <id> | --neighborhood <path-or-id> [--depth <0-8>] [--direction incoming|outgoing|both]] [--format json|text]
  atlas query <run-directory> --text <query> [--limit <count>]
  atlas incremental plan --workspace <directory> --target-id <id> --baseline <run-directory> --next <run-directory>
  atlas incremental batch --workspace <directory> --spec <batch.json>
  atlas historical-evidence index --reference <directory> --manifest <manifest.json> --workspace <directory>
  atlas historical-evidence verify <index-directory>
  atlas historical-evidence query <index-directory> --text <query> [--limit <count>] [--kind review|trace]
  atlas memory lookup <run-directory> --workspace <directory> --target <target.json> --profile <profile.json> --text <query> [--limit <count>]
  atlas memory serve <run-directory> --workspace <directory> --target <target.json> --profile <profile.json>
  atlas viewer create <run-directory> --workspace <directory> --target <target.json> --output <directory>
  atlas viewer verify <viewer-directory>
  atlas viewer serve <viewer-directory> [--host <127.0.0.1|::1|localhost>] [--port <port>] [--allowed-host <hostname>]
  atlas review create <run-directory> --workspace <directory> --target <target.json> [--selection all|findings|paths|symbols|diff|neighborhood] [--selector <value> | --selectors <array.json>] [--baseline <run-directory>] [--depth <0-8>] [--direction incoming|outgoing|both] [--batch-size <count>] --purpose <text>
  atlas review status <campaign-directory>
  atlas review execution create <campaign-directory> --max-packets <count> --max-calls <count> --max-tokens <count> --max-time-ms <count>
  atlas review execution start|retry <execution-directory> --packet <id> --reviewer-kind human|agent --reviewer <identity> --reviewer-version <version> --prompt-version <version> --token-limit <count> --time-limit-ms <count>
  atlas review execution fail <execution-directory> --attempt <id> --input-tokens <count> --output-tokens <count> --duration-ms <count> --failure-code <code> --failure-message <text>
  atlas review execution complete <execution-directory> --result <result.json>
  atlas review execution pause|resume|status|verify <execution-directory>
  atlas version

Safety defaults: target code is never executed, network access is not used, target writes are forbidden,
symlinks/junctions are skipped, and dead-code output is always a review candidate rather than a deletion verdict.
`;
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || rest.includes('--help')) {
    process.stdout.write(help());
    return;
  }
  if (command === 'version' || command === '--version') {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return;
  }
  if (command === 'scan') {
    const parsed = parseArguments(rest);
    assertOptions(parsed, ['target', 'profile', 'workspace', 'dispositions']);
    assertPositionals(parsed, 0, 'scan');
    const dispositionLedgerPath = option(parsed, 'dispositions');
    if (parsed.options.has('dispositions') && dispositionLedgerPath === undefined) {
      throw new AtlasError('CLI_USAGE', '--dispositions requires a ledger path.');
    }
    const result = await scanProject({
      targetConfigPath: option(parsed, 'target', true)!,
      profilePath: option(parsed, 'profile', true)!,
      workspacePath: option(parsed, 'workspace', true)!,
      ...(dispositionLedgerPath ? { dispositionLedgerPath } : {})
    });
    const verified = await verifyAndLoadRunDirectory(result.runDirectory);
    print({
      status: result.reused ? 'reused' : 'completed',
      runDirectory: result.runDirectory,
      attemptPath: result.attemptPath,
      run: result.run,
      analysisHealth: analysisHealthSummary(verified.artifacts.analysisHealth)
    });
    if (verified.summary.healthStatus === 'incomplete') process.exitCode = EXIT_INCOMPLETE_HEALTH;
    return;
  }
  if (command === 'target') {
    const [targetCommand, ...targetRest] = rest;
    const parsed = parseArguments(targetRest);
    if (targetCommand === 'register') {
      assertOptions(parsed, ['target', 'workspace']);
      assertPositionals(parsed, 0, 'target register');
      print(await registerTarget({
        targetConfigPath: option(parsed, 'target', true)!,
        workspacePath: option(parsed, 'workspace', true)!
      }));
      return;
    }
    if (targetCommand === 'list') {
      assertOptions(parsed, ['workspace']);
      assertPositionals(parsed, 0, 'target list');
      print({ targets: await listTargetRegistrations(option(parsed, 'workspace', true)!) });
      return;
    }
    throw new AtlasError('CLI_USAGE', 'target requires register or list.');
  }
  if (command === 'verify') {
    const parsed = parseArguments(rest);
    assertOptions(parsed, []);
    assertPositionals(parsed, 1, 'verify');
    if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'verify requires a run directory.');
    const verified = await verifyAndLoadRunDirectory(parsed.positionals[0]);
    print({ ...verified.summary, analysisHealth: analysisHealthSummary(verified.artifacts.analysisHealth) });
    if (verified.summary.healthStatus === 'incomplete') process.exitCode = EXIT_INCOMPLETE_HEALTH;
    return;
  }
  if (command === 'diff') {
    const parsed = parseArguments(rest);
    assertOptions(parsed, [
      'baseline',
      'candidate',
      'fail-on-new',
      'baseline-target',
      'candidate-target',
      'target',
      'output'
    ]);
    assertPositionals(parsed, 0, 'diff');
    const baselineRunDirectory = option(parsed, 'baseline', true)!;
    const candidateRunDirectory = option(parsed, 'candidate', true)!;
    const threshold = option(parsed, 'fail-on-new');
    if (parsed.options.has('fail-on-new') && threshold === undefined) {
      throw new AtlasError('CLI_USAGE', '--fail-on-new requires info, low, medium, or high.');
    }
    if (threshold !== undefined && !['info', 'low', 'medium', 'high'].includes(threshold)) {
      throw new AtlasError('CLI_USAGE', '--fail-on-new must be info, low, medium, or high.');
    }
    const outputPath = option(parsed, 'output');
    if (parsed.options.has('output') && outputPath === undefined) {
      throw new AtlasError('CLI_USAGE', '--output requires a value.');
    }
    const targetConfigPath = option(parsed, 'target');
    if (parsed.options.has('target') && targetConfigPath === undefined) {
      throw new AtlasError('CLI_USAGE', '--target requires a target descriptor path.');
    }
    const baselineTargetConfigPath = option(parsed, 'baseline-target');
    const candidateTargetConfigPath = option(parsed, 'candidate-target');
    if (parsed.options.has('baseline-target') && baselineTargetConfigPath === undefined) {
      throw new AtlasError('CLI_USAGE', '--baseline-target requires a target descriptor path.');
    }
    if (parsed.options.has('candidate-target') && candidateTargetConfigPath === undefined) {
      throw new AtlasError('CLI_USAGE', '--candidate-target requires a target descriptor path.');
    }
    if ((baselineTargetConfigPath === undefined) !== (candidateTargetConfigPath === undefined)) {
      throw new AtlasError('CLI_USAGE', '--baseline-target and --candidate-target must be provided together.');
    }
    if (targetConfigPath && baselineTargetConfigPath) {
      throw new AtlasError('CLI_USAGE', '--target cannot be combined with --baseline-target and --candidate-target.');
    }
    if (outputPath && !targetConfigPath && !baselineTargetConfigPath) {
      throw new AtlasError(
        'CLI_USAGE',
        '--output requires --target <target.json> or paired --baseline-target and --candidate-target descriptors.'
      );
    }
    const report = await compareFindingRuns({
      baselineRunDirectory,
      candidateRunDirectory,
      ...(baselineTargetConfigPath === undefined
        ? {}
        : { baselineTargetConfigPath, candidateTargetConfigPath: candidateTargetConfigPath! }),
      ...(threshold === undefined ? {} : { failOnNew: threshold as FindingSeverity })
    });
    if (outputPath) {
      await writeFindingDeltaReport({
        baselineRunDirectory,
        candidateRunDirectory,
        outputPath,
        ...(targetConfigPath === undefined ? {} : { targetConfigPath }),
        ...(baselineTargetConfigPath === undefined
          ? {}
          : { baselineTargetConfigPath, candidateTargetConfigPath: candidateTargetConfigPath! }),
        ...(threshold === undefined ? {} : { failOnNew: threshold as FindingSeverity })
      }, report);
    }
    print(report);
    if (report.gate.triggered) process.exitCode = EXIT_FINDING_GATE_TRIGGERED;
    return;
  }
  if (command === 'changed') {
    const parsed = parseArguments(rest);
    assertOptions(parsed, ['target', 'since', 'output']);
    assertPositionals(parsed, 1, 'changed');
    if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'changed requires a run directory.');
    const runDirectory = parsed.positionals[0];
    const targetConfigPath = option(parsed, 'target', true)!;
    const since = option(parsed, 'since', true)!;
    const outputPath = option(parsed, 'output');
    if (parsed.options.has('output') && outputPath === undefined) {
      throw new AtlasError('CLI_USAGE', '--output requires a value.');
    }
    const report = await createChangedFindingsReport({ runDirectory, targetConfigPath, since });
    if (outputPath) {
      await writeChangedFindingsReport({ runDirectory, targetConfigPath, since, outputPath }, report);
    }
    print(report);
    return;
  }
  if (command === 'regression') {
    const [regressionCommand, ...regressionRest] = rest;
    const parsed = parseArguments(regressionRest);
    if (regressionCommand === 'real-target') {
      assertOptions(parsed, ['checkout', 'target', 'corpus', 'output']);
      assertPositionals(parsed, 0, 'regression real-target');
      const checkout = option(parsed, 'checkout');
      const target = option(parsed, 'target');
      const corpusPath = option(parsed, 'corpus');
      const outputPath = option(parsed, 'output');
      for (const name of ['checkout', 'target', 'corpus', 'output']) {
        if (parsed.options.has(name) && option(parsed, name) === undefined) {
          throw new AtlasError('CLI_USAGE', `--${name} requires a value.`);
        }
      }
      if (checkout && target) {
        throw new AtlasError('CLI_USAGE', 'Use either --checkout or --target for real-target regression, not both.');
      }
      const targetRoot = checkout ?? (target ? await resolveTargetRootInput(target) : undefined);
      const report = await evaluateRealTargetCorpus({
        ...(targetRoot ? { targetRoot } : {}),
        ...(corpusPath ? { corpusPath } : {})
      });
      assertPortableDataSafe(report, 'Atlas real-target regression report');
      if (outputPath) await writeImmutableCanonicalReport(outputPath, report, targetRoot ? [targetRoot] : []);
      print(report);
      if (report.status === 'failed') process.exitCode = EXIT_INCOMPLETE_HEALTH;
      return;
    }
    if (regressionCommand !== 'verify') throw new AtlasError('CLI_USAGE', 'regression requires verify or real-target.');
    assertOptions(parsed, ['output']);
    assertPositionals(parsed, 0, 'regression verify');
    const outputPath = option(parsed, 'output');
    if (parsed.options.has('output') && (!outputPath || !outputPath.trim())) {
      throw new AtlasError('CLI_USAGE', '--output requires a value.');
    }
    const summary = regressionVerificationSummary(await evaluateOperationalControls());
    assertPortableDataSafe(summary, 'Atlas incident regression report');
    if (outputPath) await writeImmutableCanonicalReport(outputPath, summary, []);
    print(summary);
    if ((summary as { status: string }).status !== 'passed') process.exitCode = EXIT_INCOMPLETE_HEALTH;
    return;
  }
  if (command === 'inspect') {
    const parsed = parseArguments(rest);
    assertOptions(parsed, ['file', 'symbol', 'finding', 'neighborhood', 'depth', 'direction', 'format']);
    assertPositionals(parsed, 1, 'inspect');
    if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'inspect requires a run directory.');
    const selectors = ['file', 'symbol', 'finding', 'neighborhood'].filter((name) => option(parsed, name) !== undefined);
    if (selectors.length > 1) throw new AtlasError('CLI_USAGE', 'inspect accepts only one of --file, --symbol, --finding, or --neighborhood.');
    const depthValue = option(parsed, 'depth');
    if (depthValue !== undefined && !/^\d+$/u.test(depthValue)) throw new AtlasError('CLI_USAGE', '--depth must be an integer between 0 and 8.');
    const depth = depthValue === undefined ? undefined : Number(depthValue);
    if (depth !== undefined && (!Number.isSafeInteger(depth) || depth < 0 || depth > 8)) {
      throw new AtlasError('CLI_USAGE', '--depth must be an integer between 0 and 8.');
    }
    const directionValue = option(parsed, 'direction');
    if (directionValue !== undefined && !['incoming', 'outgoing', 'both'].includes(directionValue)) {
      throw new AtlasError('CLI_USAGE', '--direction must be incoming, outgoing, or both.');
    }
    const format = option(parsed, 'format') ?? 'json';
    if (format !== 'json' && format !== 'text') throw new AtlasError('CLI_USAGE', '--format must be json or text.');
    const result = await inspectRun(parsed.positionals[0], {
      ...(option(parsed, 'file') !== undefined ? { file: option(parsed, 'file')! } : {}),
      ...(option(parsed, 'symbol') !== undefined ? { symbol: option(parsed, 'symbol')! } : {}),
      ...(option(parsed, 'finding') !== undefined ? { finding: option(parsed, 'finding')! } : {}),
      ...(option(parsed, 'neighborhood') !== undefined ? { neighborhood: option(parsed, 'neighborhood')! } : {}),
      ...(depth !== undefined ? { depth } : {}),
      ...(directionValue !== undefined ? { direction: directionValue as InspectionDirection } : {})
    });
    if (format === 'text') process.stdout.write(renderInspectionText(result));
    else print(result);
    return;
  }
  if (command === 'query') {
    const parsed = parseArguments(rest);
    assertOptions(parsed, ['text', 'limit']);
    assertPositionals(parsed, 1, 'query');
    if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'query requires a run directory.');
    const limitValue = option(parsed, 'limit');
    if (limitValue !== undefined && !/^\d+$/.test(limitValue)) throw new AtlasError('CLI_USAGE', '--limit must be a positive integer.');
    const limit = limitValue === undefined ? 20 : Number(limitValue);
    if (!Number.isSafeInteger(limit) || limit < 1) throw new AtlasError('CLI_USAGE', '--limit must be a positive integer.');
    print(await queryRun(parsed.positionals[0], option(parsed, 'text', true)!, limit));
    return;
  }
  if (command === 'incremental') {
    const [incrementalCommand, ...incrementalRest] = rest;
    const parsed = parseArguments(incrementalRest);
    if (incrementalCommand === 'plan') {
      assertOptions(parsed, ['workspace', 'target-id', 'baseline', 'next']);
      assertPositionals(parsed, 0, 'incremental plan');
      print(await planIncrementalAnalysis({
        workspacePath: option(parsed, 'workspace', true)!,
        targetId: option(parsed, 'target-id', true)!,
        baselineRunDirectory: option(parsed, 'baseline', true)!,
        nextRunDirectory: option(parsed, 'next', true)!
      }));
      return;
    }
    if (incrementalCommand === 'batch') {
      assertOptions(parsed, ['workspace', 'spec']);
      assertPositionals(parsed, 0, 'incremental batch');
      const spec = await readJson<unknown>(option(parsed, 'spec', true)!);
      print(await planIncrementalAnalysisBatch({
        workspacePath: option(parsed, 'workspace', true)!,
        targets: incrementalBatchTargets(spec)
      }));
      return;
    }
    throw new AtlasError('CLI_USAGE', 'incremental requires plan or batch.');
  }
  if (command === 'historical-evidence') {
    const [historicalCommand, ...historicalRest] = rest;
    const parsed = parseArguments(historicalRest);
    if (historicalCommand === 'index') {
      assertOptions(parsed, ['reference', 'manifest', 'workspace']);
      assertPositionals(parsed, 0, 'historical-evidence index');
      print(await createHistoricalEvidenceIndex({
        referencePath: option(parsed, 'reference', true)!,
        manifestPath: option(parsed, 'manifest', true)!,
        workspacePath: option(parsed, 'workspace', true)!
      }));
      return;
    }
    if (historicalCommand === 'verify') {
      assertOptions(parsed, []);
      assertPositionals(parsed, 1, 'historical-evidence verify');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'historical-evidence verify requires an index directory.');
      print(await verifyHistoricalEvidenceIndex(parsed.positionals[0]));
      return;
    }
    if (historicalCommand === 'query') {
      assertOptions(parsed, ['text', 'limit', 'kind']);
      assertPositionals(parsed, 1, 'historical-evidence query');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'historical-evidence query requires an index directory.');
      const limitValue = option(parsed, 'limit');
      if (parsed.options.has('limit') && limitValue === undefined) throw new AtlasError('CLI_USAGE', '--limit requires a value.');
      if (limitValue !== undefined && !/^\d+$/u.test(limitValue)) throw new AtlasError('CLI_USAGE', '--limit must be an integer between 1 and 100.');
      const limit = limitValue === undefined ? undefined : Number(limitValue);
      if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)) {
        throw new AtlasError('CLI_USAGE', '--limit must be an integer between 1 and 100.');
      }
      const kind = option(parsed, 'kind');
      if (parsed.options.has('kind') && kind === undefined) throw new AtlasError('CLI_USAGE', '--kind requires review or trace.');
      if (kind !== undefined && kind !== 'review' && kind !== 'trace') {
        throw new AtlasError('CLI_USAGE', '--kind must be review or trace.');
      }
      print(await queryHistoricalEvidence(parsed.positionals[0], option(parsed, 'text', true)!, {
        ...(limit === undefined ? {} : { limit }),
        ...(kind === undefined ? {} : { kinds: [kind] })
      }));
      return;
    }
    throw new AtlasError('CLI_USAGE', 'historical-evidence requires index, verify, or query.');
  }
  if (command === 'memory') {
    const [memoryCommand, ...memoryRest] = rest;
    const parsed = parseArguments(memoryRest);
    if (memoryCommand === 'lookup') {
      assertOptions(parsed, ['workspace', 'target', 'profile', 'text', 'limit']);
      assertPositionals(parsed, 1, 'memory lookup');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'memory lookup requires a run directory.');
      const limitValue = option(parsed, 'limit');
      if (limitValue !== undefined && !/^\d+$/u.test(limitValue)) throw new AtlasError('CLI_USAGE', '--limit must be a positive integer.');
      print(await lookupMemory({
        runDirectory: parsed.positionals[0],
        workspacePath: option(parsed, 'workspace', true)!,
        targetConfigPath: option(parsed, 'target', true)!,
        profilePath: option(parsed, 'profile', true)!,
        query: option(parsed, 'text', true)!,
        ...(limitValue === undefined ? {} : { limit: Number(limitValue) })
      }));
      return;
    }
    if (memoryCommand === 'serve') {
      assertOptions(parsed, ['workspace', 'target', 'profile']);
      assertPositionals(parsed, 1, 'memory serve');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'memory serve requires a run directory.');
      await runMemoryStdioService({
        runDirectory: parsed.positionals[0],
        workspacePath: option(parsed, 'workspace', true)!,
        targetConfigPath: option(parsed, 'target', true)!,
        profilePath: option(parsed, 'profile', true)!
      });
      return;
    }
    throw new AtlasError('CLI_USAGE', 'memory requires lookup or serve.');
  }
  if (command === 'viewer') {
    const [viewerCommand, ...viewerRest] = rest;
    const parsed = parseArguments(viewerRest);
    if (viewerCommand === 'create') {
      assertOptions(parsed, ['workspace', 'target', 'output']);
      assertPositionals(parsed, 1, 'viewer create');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'viewer create requires a run directory.');
      const publication = await createRunViewer({
        runDirectory: parsed.positionals[0],
        workspacePath: option(parsed, 'workspace', true)!,
        targetConfigPath: option(parsed, 'target', true)!,
        outputDirectory: option(parsed, 'output', true)!
      });
      print(publication);
      if (publication.healthStatus === 'incomplete') process.exitCode = EXIT_INCOMPLETE_HEALTH;
      return;
    }
    if (viewerCommand === 'verify') {
      assertOptions(parsed, []);
      assertPositionals(parsed, 1, 'viewer verify');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'viewer verify requires a viewer directory.');
      const verification = await verifyRunViewer(parsed.positionals[0]);
      print(verification);
      if (verification.healthStatus === 'incomplete') process.exitCode = EXIT_INCOMPLETE_HEALTH;
      return;
    }
    if (viewerCommand === 'serve') {
      assertOptions(parsed, ['host', 'port', 'allowed-host']);
      assertPositionals(parsed, 1, 'viewer serve');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'viewer serve requires a viewer directory.');
      const hostValue = parsed.options.has('host') ? option(parsed, 'host', true) : undefined;
      const portValue = parsed.options.has('port') ? option(parsed, 'port', true) : undefined;
      const allowedHostValue = parsed.options.has('allowed-host') ? option(parsed, 'allowed-host', true) : undefined;
      if (portValue !== undefined && !/^\d+$/u.test(portValue)) {
        throw new AtlasError('CLI_USAGE', '--port must be an integer from 0 through 65535.');
      }
      const port = portValue === undefined ? undefined : Number(portValue);
      if (port !== undefined && port > 65_535) {
        throw new AtlasError('CLI_USAGE', '--port must be an integer from 0 through 65535.');
      }
      await runViewerServer({
        viewerDirectory: parsed.positionals[0],
        ...(hostValue === undefined ? {} : { host: hostValue }),
        ...(port === undefined ? {} : { port }),
        ...(allowedHostValue === undefined ? {} : { allowedHosts: [allowedHostValue] })
      });
      return;
    }
    throw new AtlasError('CLI_USAGE', 'viewer requires create, verify, or serve.');
  }
  if (command === 'review') {
    const [reviewCommand, ...reviewRest] = rest;
    if (reviewCommand === 'execution') {
      const [executionCommand, ...executionRest] = reviewRest;
      const parsed = parseArguments(executionRest);
      if (executionCommand === 'create') {
        assertOptions(parsed, ['max-packets', 'max-calls', 'max-tokens', 'max-time-ms']);
        assertPositionals(parsed, 1, 'review execution create');
        if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'review execution create requires a campaign directory.');
        print(await createReviewExecution({
          campaignDirectory: parsed.positionals[0],
          budgets: {
            maxPackets: integerOption(parsed, 'max-packets'),
            maxCalls: integerOption(parsed, 'max-calls'),
            maxTokens: integerOption(parsed, 'max-tokens'),
            maxTimeMs: integerOption(parsed, 'max-time-ms')
          }
        }));
        return;
      }
      if (executionCommand === 'start' || executionCommand === 'retry') {
        assertOptions(parsed, ['packet', 'reviewer-kind', 'reviewer', 'reviewer-version', 'prompt-version', 'token-limit', 'time-limit-ms']);
        assertPositionals(parsed, 1, `review execution ${executionCommand}`);
        if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', `review execution ${executionCommand} requires an execution directory.`);
        const attemptOptions = {
          executionDirectory: parsed.positionals[0],
          packetId: option(parsed, 'packet', true)!,
          reviewer: reviewReviewer(parsed),
          tokenLimit: integerOption(parsed, 'token-limit'),
          timeLimitMs: integerOption(parsed, 'time-limit-ms')
        };
        print(executionCommand === 'start'
          ? await startReviewAttempt(attemptOptions)
          : await retryReviewAttempt(attemptOptions));
        return;
      }
      if (executionCommand === 'fail') {
        assertOptions(parsed, ['attempt', 'input-tokens', 'output-tokens', 'duration-ms', 'failure-code', 'failure-message']);
        assertPositionals(parsed, 1, 'review execution fail');
        if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'review execution fail requires an execution directory.');
        print(await failReviewAttempt({
          executionDirectory: parsed.positionals[0],
          attemptId: option(parsed, 'attempt', true)!,
          usage: {
            inputTokens: integerOption(parsed, 'input-tokens'),
            outputTokens: integerOption(parsed, 'output-tokens'),
            durationMs: integerOption(parsed, 'duration-ms')
          },
          failure: {
            code: option(parsed, 'failure-code', true)!,
            message: option(parsed, 'failure-message', true)!
          }
        }));
        return;
      }
      if (executionCommand === 'complete') {
        assertOptions(parsed, ['result']);
        assertPositionals(parsed, 1, 'review execution complete');
        if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'review execution complete requires an execution directory.');
        print(await completeReviewAttempt({
          executionDirectory: parsed.positionals[0],
          result: await readBoundedJsonFile<ReviewResultInput>(option(parsed, 'result', true)!, {
            maxBytes: MAX_REVIEW_RESULT_INPUT_BYTES,
            maxDepth: 128,
            resourceCode: 'REVIEW_RESULT_RESOURCE_LIMIT',
            invalidCode: 'REVIEW_RESULT_INVALID',
            label: 'Review result input'
          })
        }));
        return;
      }
      if (['pause', 'resume', 'status', 'verify'].includes(executionCommand ?? '')) {
        assertOptions(parsed, []);
        assertPositionals(parsed, 1, `review execution ${executionCommand}`);
        if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', `review execution ${executionCommand} requires an execution directory.`);
        if (executionCommand === 'pause') print(await pauseReviewExecution(parsed.positionals[0]));
        else if (executionCommand === 'resume') print(await resumeReviewExecution(parsed.positionals[0]));
        else if (executionCommand === 'status') print(await readReviewExecution(parsed.positionals[0]));
        else print(await verifyReviewExecution(parsed.positionals[0]));
        return;
      }
      throw new AtlasError('CLI_USAGE', 'review execution requires create, start, retry, fail, complete, pause, resume, status, or verify.');
    }
    const parsed = parseArguments(reviewRest);
    if (reviewCommand === 'create') {
      assertOptions(parsed, ['workspace', 'target', 'selection', 'selector', 'selectors', 'baseline', 'depth', 'direction', 'batch-size', 'purpose']);
      assertPositionals(parsed, 1, 'review create');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'review create requires a run directory.');
      const selectionValue = option(parsed, 'selection') ?? 'all';
      if (!['all', 'findings', 'paths', 'symbols', 'diff', 'neighborhood'].includes(selectionValue)) {
        throw new AtlasError('CLI_USAGE', '--selection must be all, findings, paths, symbols, diff, or neighborhood.');
      }
      const selectorValues = await reviewSelectors(parsed);
      const depthValue = option(parsed, 'depth');
      const depth = depthValue === undefined ? undefined : integerOption(parsed, 'depth');
      if (depth !== undefined && depth > 8) throw new AtlasError('CLI_USAGE', '--depth must be between 0 and 8.');
      const direction = option(parsed, 'direction');
      if (direction !== undefined && !['incoming', 'outgoing', 'both'].includes(direction)) {
        throw new AtlasError('CLI_USAGE', '--direction must be incoming, outgoing, or both.');
      }
      const batchValue = option(parsed, 'batch-size') ?? '50';
      if (!/^\d+$/.test(batchValue)) throw new AtlasError('CLI_USAGE', '--batch-size must be a positive integer.');
      const batchSize = Number(batchValue);
      print(await createReviewCampaign({
        runDirectory: parsed.positionals[0],
        workspacePath: option(parsed, 'workspace', true)!,
        targetConfigPath: option(parsed, 'target', true)!,
        purpose: option(parsed, 'purpose', true)!,
        selection: selectionValue as 'all' | 'findings' | 'paths' | 'symbols' | 'diff' | 'neighborhood',
        ...(selectorValues ? { selectors: selectorValues } : {}),
        ...(option(parsed, 'baseline') ? { baselineRunDirectory: option(parsed, 'baseline')! } : {}),
        ...(depth === undefined ? {} : { depth }),
        ...(direction ? { direction: direction as 'incoming' | 'outgoing' | 'both' } : {}),
        batchSize
      }));
      return;
    }
    if (reviewCommand === 'status') {
      assertOptions(parsed, []);
      assertPositionals(parsed, 1, 'review status');
      if (!parsed.positionals[0]) throw new AtlasError('CLI_USAGE', 'review status requires a campaign directory.');
      print(await reviewCampaignStatus(parsed.positionals[0]));
      return;
    }
    throw new AtlasError('CLI_USAGE', 'review requires create or status.');
  }
  throw new AtlasError('CLI_USAGE', `Unknown command: ${command}`);
}

main().catch((error) => {
  process.stderr.write(terminalSafeJson({ status: 'failed', error: errorDetails(error) }));
  process.exitCode = 1;
});
