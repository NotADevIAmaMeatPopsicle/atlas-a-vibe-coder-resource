import { execFile } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { writeImmutableCanonicalReport, type ImmutableReportWriteResult } from './acceptance/report-output.js';
import { discoverGitRepository } from './discovery/git.js';
import { AtlasError } from './errors.js';
import {
  assessFindingProducerCompatibility,
  findingDispositionMarkers,
  type FindingProducerSignature
} from './finding-compatibility.js';
import { assertSchema } from './schema-validator.js';
import { resolveTrustedGitExecutable } from './security/git-executable.js';
import { assertPortableDataSafe } from './security/portable-data.js';
import { resolveTargetDescriptor, verifyTargetRegistrationBinding } from './targets.js';
import type { FindingRecord, RunRecord } from './types.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';
import { verifyAndLoadRunDirectory, type VerifiedRunDirectoryResult } from './verify.js';
import { findingReviewIdentity } from './finding-identity.js';

export { findingReviewIdentity, findingSourcePaths } from './finding-identity.js';

export const FINDING_DIFF_VERSION = '1.1.0';

export type FindingSeverity = FindingRecord['severity'];
export type FindingDeltaStatus = 'new' | 'resolved' | 'unchanged';

export interface FindingDeltaFinding {
  findingId: string;
  ruleId: string;
  category: FindingRecord['category'];
  severity: FindingSeverity;
  confidence: FindingRecord['confidence'];
  title: string;
  path?: string;
  relatedPaths: string[];
  signals: string[];
  instanceCount: number;
}

export interface FindingDeltaEntry {
  reviewIdentity: string;
  occurrence: number;
  status: FindingDeltaStatus;
  baseline?: FindingDeltaFinding;
  candidate?: FindingDeltaFinding;
}

export interface FindingDeltaReport {
  schemaVersion: 1;
  reportId: string;
  kind: 'atlas-finding-delta-report';
  producer: {
    id: 'atlas/finding-diff';
    version: string;
  };
  target: {
    id: string;
    candidateId?: string;
    equivalence?: 'shared-git-common-directory-v1';
  };
  profile: { id: string; digest: string };
  compatibility: FindingDeltaCompatibility;
  baseline: FindingDeltaRunBinding;
  candidate: FindingDeltaRunBinding;
  summary: Record<FindingDeltaStatus, number>;
  gate: {
    threshold?: FindingSeverity;
    matchingNewFindings: number;
    triggered: boolean;
  };
  findings: Record<Extract<FindingDeltaStatus, 'new' | 'resolved' | 'unchanged'>, FindingDeltaEntry[]>;
}

export interface FindingDeltaCompatibility {
  basis: 'exact' | 'declared-compatible';
  contractId: string;
  producer: RunRecord['tool'];
  adapters: RunRecord['adapters'];
  analyzers: string[];
  dispositions: string[];
  candidate?: FindingProducerSignature;
}

export interface FindingDeltaRunBinding {
  runId: string;
  snapshotId: string;
  artifactManifestDigest: string;
  findingCount: number;
}

export interface CompareFindingRunsOptions {
  baselineRunDirectory: string;
  candidateRunDirectory: string;
  baselineTargetConfigPath?: string;
  candidateTargetConfigPath?: string;
  failOnNew?: FindingSeverity;
}

export interface WriteFindingDeltaOptions extends CompareFindingRunsOptions {
  outputPath: string;
  targetConfigPath?: string;
}

interface IndexedFinding {
  finding: FindingRecord;
  reviewIdentity: string;
}

interface ReportWithoutIdentity extends Omit<FindingDeltaReport, 'reportId'> {}

interface BoundTarget {
  configPath: string;
  targetRoot: string;
}

interface TargetComparison {
  reportTarget: FindingDeltaReport['target'];
  outputBoundaries: string[];
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3
};

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareCanonicalText);
}

function summarizeFinding(finding: FindingRecord): FindingDeltaFinding {
  return {
    findingId: finding.id,
    ruleId: finding.ruleId,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    title: finding.title,
    ...(finding.path ? { path: finding.path } : {}),
    relatedPaths: uniqueSorted(finding.relatedPaths),
    signals: uniqueSorted(finding.signals),
    instanceCount: finding.instanceCount ?? 1
  };
}

function compareIndexedFindings(left: IndexedFinding, right: IndexedFinding): number {
  return compareCanonicalText(left.reviewIdentity, right.reviewIdentity) ||
    compareCanonicalText(left.finding.id, right.finding.id);
}

function findingsByReviewIdentity(findings: readonly FindingRecord[]): Map<string, IndexedFinding[]> {
  const result = new Map<string, IndexedFinding[]>();
  for (const finding of findings) {
    const reviewIdentity = findingReviewIdentity(finding);
    const group = result.get(reviewIdentity) ?? [];
    group.push({ finding, reviewIdentity });
    result.set(reviewIdentity, group);
  }
  for (const group of result.values()) group.sort(compareIndexedFindings);
  return result;
}

function pairIdentityGroup(
  reviewIdentity: string,
  baseline: readonly IndexedFinding[],
  candidate: readonly IndexedFinding[]
): FindingDeltaEntry[] {
  const baselineById = new Map(baseline.map((entry) => [entry.finding.id, entry]));
  const candidateById = new Map(candidate.map((entry) => [entry.finding.id, entry]));
  const paired: Array<{ baseline: IndexedFinding; candidate: IndexedFinding }> = [];

  for (const findingId of [...baselineById.keys()].filter((id) => candidateById.has(id)).sort(compareCanonicalText)) {
    paired.push({ baseline: baselineById.get(findingId)!, candidate: candidateById.get(findingId)! });
    baselineById.delete(findingId);
    candidateById.delete(findingId);
  }

  const remainingBaseline = [...baselineById.values()].sort(compareIndexedFindings);
  const remainingCandidate = [...candidateById.values()].sort(compareIndexedFindings);
  const sharedCount = Math.min(remainingBaseline.length, remainingCandidate.length);
  for (let index = 0; index < sharedCount; index += 1) {
    paired.push({ baseline: remainingBaseline[index]!, candidate: remainingCandidate[index]! });
  }

  const entries: FindingDeltaEntry[] = [];
  let occurrence = 0;
  for (const pair of paired.sort((left, right) =>
    compareCanonicalText(left.baseline.finding.id, right.baseline.finding.id) ||
    compareCanonicalText(left.candidate.finding.id, right.candidate.finding.id)
  )) {
    occurrence += 1;
    entries.push({
      reviewIdentity,
      occurrence,
      status: 'unchanged',
      baseline: summarizeFinding(pair.baseline.finding),
      candidate: summarizeFinding(pair.candidate.finding)
    });
  }
  for (const entry of remainingBaseline.slice(sharedCount)) {
    occurrence += 1;
    entries.push({
      reviewIdentity,
      occurrence,
      status: 'resolved',
      baseline: summarizeFinding(entry.finding)
    });
  }
  for (const entry of remainingCandidate.slice(sharedCount)) {
    occurrence += 1;
    entries.push({
      reviewIdentity,
      occurrence,
      status: 'new',
      candidate: summarizeFinding(entry.finding)
    });
  }
  return entries;
}

export function compareFindingRecords(
  baselineFindings: readonly FindingRecord[],
  candidateFindings: readonly FindingRecord[]
): FindingDeltaReport['findings'] {
  const baseline = findingsByReviewIdentity(baselineFindings);
  const candidate = findingsByReviewIdentity(candidateFindings);
  const identities = uniqueSorted([...baseline.keys(), ...candidate.keys()]);
  const result: FindingDeltaReport['findings'] = { new: [], resolved: [], unchanged: [] };
  for (const identity of identities) {
    for (const entry of pairIdentityGroup(identity, baseline.get(identity) ?? [], candidate.get(identity) ?? [])) {
      result[entry.status].push(entry);
    }
  }
  return result;
}

function assertFindingCompatibility(
  baseline: VerifiedRunDirectoryResult,
  candidate: VerifiedRunDirectoryResult
): FindingDeltaCompatibility {
  const baselineRun = baseline.artifacts.run;
  const candidateRun = candidate.artifacts.run;
  if (
    baselineRun.profileId !== candidateRun.profileId ||
    baselineRun.profileDigest !== candidateRun.profileDigest
  ) {
    throw new AtlasError(
      'FINDING_DIFF_PROFILE_MISMATCH',
      'Finding delta requires the same profile ID and exact profile digest for baseline and candidate.'
    );
  }
  const assessment = assessFindingProducerCompatibility(baselineRun, candidateRun);
  if (!assessment.compatible) {
    const baselineRevision = baseline.artifacts.discovery.repository?.head.objectId;
    const baselineSource = baselineRevision === undefined
      ? `recreate the source revision sealed by baseline run ${baselineRun.runId}`
      : `check out baseline revision ${baselineRevision}`;
    throw new AtlasError(
      'FINDING_DIFF_REBASE_REQUIRED',
      `No declared finding-comparison compatibility exists for the baseline and candidate contracts ` +
      `(${assessment.differences.join(', ')} differ); Atlas does not infer compatibility from version numbers. ` +
      `To re-baseline without changing the original run, ${baselineSource}, scan it with candidate contract ` +
      `${assessment.candidateContractId} and exact profile ${candidateRun.profileId} ` +
      `(${candidateRun.profileDigest}), then rerun atlas diff.`
    );
  }
  const baselineDispositions = findingDispositionMarkers(baselineRun);
  const candidateDispositions = findingDispositionMarkers(candidateRun);
  if (canonicalJson(baselineDispositions) !== canonicalJson(candidateDispositions)) {
    throw new AtlasError(
      'FINDING_DIFF_DISPOSITION_MISMATCH',
      'Finding delta requires the same exact disposition-ledger marker set.'
    );
  }
  return {
    basis: assessment.basis,
    contractId: assessment.contractId,
    producer: { ...assessment.baseline.producer },
    adapters: assessment.baseline.adapters.map((adapter) => ({ ...adapter })),
    analyzers: [...assessment.baseline.analyzers],
    dispositions: [...baselineDispositions],
    ...(assessment.basis === 'declared-compatible'
      ? {
          candidate: {
            producer: { ...assessment.candidate.producer },
            adapters: assessment.candidate.adapters.map((adapter) => ({ ...adapter })),
            analyzers: [...assessment.candidate.analyzers]
          }
        }
      : {})
  };
}

function workspaceForRun(verified: VerifiedRunDirectoryResult): string {
  const runDirectory = path.resolve(verified.artifacts.directory);
  const runsDirectory = path.dirname(runDirectory);
  if (path.basename(runsDirectory) !== 'runs' || path.basename(runDirectory) !== verified.artifacts.run.runId) {
    throw new AtlasError(
      'FINDING_DIFF_RUN_LOCATION_INVALID',
      'Cross-target comparison requires each verified run to remain in its registered workspace runs directory.'
    );
  }
  return path.dirname(runsDirectory);
}

async function resolveBoundTarget(
  verified: VerifiedRunDirectoryResult,
  targetConfigPath: string,
  label: 'baseline' | 'candidate'
): Promise<BoundTarget> {
  const descriptor = await resolveTargetDescriptor(targetConfigPath);
  if (descriptor.target.id !== verified.artifacts.run.targetId) {
    throw new AtlasError(
      'FINDING_DIFF_TARGET_MISMATCH',
      `The ${label} target descriptor ID does not match the ${label} run target ID.`
    );
  }
  await verifyTargetRegistrationBinding({
    workspacePath: workspaceForRun(verified),
    targetId: verified.artifacts.run.targetId,
    targetRoot: descriptor.targetRoot,
    targetConfigPath: descriptor.targetConfigPath,
    consent: descriptor.target.consent
  });
  return { configPath: descriptor.targetConfigPath, targetRoot: descriptor.targetRoot };
}

async function resolveOutputTarget(
  targetConfigPath: string,
  expectedTargetId: string,
  label: 'baseline' | 'candidate'
): Promise<BoundTarget> {
  const descriptor = await resolveTargetDescriptor(targetConfigPath);
  if (descriptor.target.id !== expectedTargetId) {
    throw new AtlasError(
      'FINDING_DIFF_TARGET_MISMATCH',
      `The ${label} target descriptor ID does not match the ${label} run target ID.`
    );
  }
  return { configPath: descriptor.targetConfigPath, targetRoot: descriptor.targetRoot };
}

function discoveryIsPinnedAndClean(verified: VerifiedRunDirectoryResult): boolean {
  const discovery = verified.artifacts.discovery;
  return discovery.state === 'ready' &&
    discovery.repository?.head.state === 'detached' &&
    discovery.repository.head.objectId !== undefined &&
    !discovery.diagnostics.some((diagnostic) => diagnostic.severity === 'error') &&
    discovery.records.every((record) =>
      record.tracking === 'ignored' || (
        record.tracking === 'tracked' &&
        record.indexStatus === 'clean' &&
        record.worktreeStatus === 'clean' &&
        !record.conflicted
      )
    );
}

async function proveLiveCheckout(
  verified: VerifiedRunDirectoryResult,
  target: BoundTarget,
  label: 'baseline' | 'candidate'
): Promise<void> {
  if (!discoveryIsPinnedAndClean(verified)) {
    const discovery = verified.artifacts.discovery;
    const unclean = discovery.records.filter((record) =>
      record.tracking !== 'ignored' && (
        record.tracking !== 'tracked' ||
        record.indexStatus !== 'clean' ||
        record.worktreeStatus !== 'clean' ||
        record.conflicted
      )
    );
    const uncleanStates = uniqueSorted(unclean.map((record) =>
      `${record.path}=${record.tracking}:${record.indexStatus}:${record.worktreeStatus}:` +
      `${record.conflicted ? 'conflicted' : 'unconflicted'}`
    ));
    const uncleanSample = uncleanStates.slice(0, 10);
    const omittedUncleanStates = uncleanStates.length - uncleanSample.length;
    const uncleanDetail = uncleanSample.length === 0
      ? ''
      : `: ${uncleanSample.join(', ')}${omittedUncleanStates > 0 ? `; ${omittedUncleanStates} more omitted` : ''}`;
    throw new AtlasError(
      'FINDING_DIFF_CHECKOUT_UNPROVEN',
      `The sealed ${label} discovery is not a clean detached Git checkout and cannot prove cross-target identity ` +
      `(state ${discovery.state}, HEAD ${discovery.repository?.head.state ?? 'unavailable'}, ` +
      `${unclean.length} unclean records${uncleanDetail}).`
    );
  }
  const liveDiscovery = await discoverGitRepository(target.targetRoot);
  if (
    liveDiscovery.state !== 'ready' ||
    liveDiscovery.repository?.head.state !== 'detached' ||
    canonicalJson(liveDiscovery) !== canonicalJson(verified.artifacts.discovery)
  ) {
    throw new AtlasError(
      'FINDING_DIFF_CHECKOUT_STALE',
      `The live ${label} checkout no longer exactly matches the Git discovery sealed into its run.`
    );
  }
}

function gitEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith('GIT_') && value !== undefined) environment[key] = value;
  }
  const nullDevice = process.platform === 'win32' ? 'NUL' : '/dev/null';
  return {
    ...environment,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_SYSTEM: nullDevice,
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_OPTIONAL_LOCKS: '0',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: '',
    LC_ALL: 'C',
    LANG: 'C'
  };
}

async function gitCommonDirectory(targetRoot: string): Promise<string> {
  const nullDevice = process.platform === 'win32' ? 'NUL' : '/dev/null';
  let output: string;
  try {
    const gitExecutable = await resolveTrustedGitExecutable([targetRoot]);
    if (!gitExecutable) throw new Error('Git executable is unavailable.');
    output = await new Promise<string>((resolve, reject) => {
      execFile(gitExecutable, [
        '--no-optional-locks',
        '--no-replace-objects',
        '-c', `core.hooksPath=${nullDevice}`,
        '-c', 'protocol.allow=never',
        '-c', 'protocol.file.allow=never',
        '-C', targetRoot,
        'rev-parse', '--path-format=absolute', '--git-common-dir'
      ], {
        cwd: targetRoot,
        env: gitEnvironment(),
        encoding: 'utf8',
        maxBuffer: 64 * 1024,
        timeout: 30_000,
        windowsHide: true,
        shell: false
      }, (error, stdout) => {
        if (error) reject(error);
        else resolve(stdout.trim());
      });
    });
  } catch {
    throw new AtlasError(
      'FINDING_DIFF_REPOSITORY_UNPROVEN',
      'Git common-directory identity could not be established for a target checkout.'
    );
  }
  if (!output) {
    throw new AtlasError(
      'FINDING_DIFF_REPOSITORY_UNPROVEN',
      'Git returned an empty common-directory identity for a target checkout.'
    );
  }
  try {
    return await realpath(path.isAbsolute(output) ? output : path.resolve(targetRoot, output));
  } catch {
    throw new AtlasError(
      'FINDING_DIFF_REPOSITORY_UNPROVEN',
      'The canonical Git common directory could not be resolved for a target checkout.'
    );
  }
}

function sameFilesystemLocation(left: string, right: string): boolean {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

async function resolveTargetComparison(
  baseline: VerifiedRunDirectoryResult,
  candidate: VerifiedRunDirectoryResult,
  options: CompareFindingRunsOptions
): Promise<TargetComparison> {
  const baselineTargetPath = options.baselineTargetConfigPath;
  const candidateTargetPath = options.candidateTargetConfigPath;
  if ((baselineTargetPath === undefined) !== (candidateTargetPath === undefined)) {
    throw new AtlasError(
      'FINDING_DIFF_TARGET_MISMATCH',
      'Cross-target identity proof requires both --baseline-target and --candidate-target descriptors.'
    );
  }
  const baselineTargetId = baseline.artifacts.run.targetId;
  const candidateTargetId = candidate.artifacts.run.targetId;
  if (baselineTargetId === candidateTargetId) {
    if (baselineTargetPath === undefined || candidateTargetPath === undefined) {
      return { reportTarget: { id: baselineTargetId }, outputBoundaries: [] };
    }
    const [baselineTarget, candidateTarget] = await Promise.all([
      resolveOutputTarget(baselineTargetPath, baselineTargetId, 'baseline'),
      resolveOutputTarget(candidateTargetPath, candidateTargetId, 'candidate')
    ]);
    return {
      reportTarget: { id: baselineTargetId },
      outputBoundaries: [
        baselineTarget.configPath,
        baselineTarget.targetRoot,
        candidateTarget.configPath,
        candidateTarget.targetRoot
      ]
    };
  }
  if (baselineTargetPath === undefined || candidateTargetPath === undefined) {
    throw new AtlasError(
      'FINDING_DIFF_TARGET_MISMATCH',
      `Finding delta target IDs differ (${baselineTargetId} and ${candidateTargetId}); ` +
      'provide both --baseline-target and --candidate-target to prove pinned checkouts of one repository.'
    );
  }

  const [baselineTarget, candidateTarget] = await Promise.all([
    resolveBoundTarget(baseline, baselineTargetPath, 'baseline'),
    resolveBoundTarget(candidate, candidateTargetPath, 'candidate')
  ]);
  await Promise.all([
    proveLiveCheckout(baseline, baselineTarget, 'baseline'),
    proveLiveCheckout(candidate, candidateTarget, 'candidate')
  ]);
  const [baselineCommonDirectory, candidateCommonDirectory] = await Promise.all([
    gitCommonDirectory(baselineTarget.targetRoot),
    gitCommonDirectory(candidateTarget.targetRoot)
  ]);
  if (!sameFilesystemLocation(baselineCommonDirectory, candidateCommonDirectory)) {
    throw new AtlasError(
      'FINDING_DIFF_REPOSITORY_MISMATCH',
      'The baseline and candidate targets are not worktrees of the same canonical Git common directory.'
    );
  }
  return {
    reportTarget: {
      id: baselineTargetId,
      candidateId: candidateTargetId,
      equivalence: 'shared-git-common-directory-v1'
    },
    outputBoundaries: [
      baselineTarget.configPath,
      baselineTarget.targetRoot,
      candidateTarget.configPath,
      candidateTarget.targetRoot
    ]
  };
}

function runBinding(verified: VerifiedRunDirectoryResult): FindingDeltaRunBinding {
  return {
    runId: verified.artifacts.run.runId,
    snapshotId: verified.artifacts.run.snapshotId,
    artifactManifestDigest: verified.manifestSha256,
    findingCount: verified.artifacts.findings.length
  };
}

export function severityAtOrAbove(severity: FindingSeverity, threshold: FindingSeverity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

export async function compareFindingRuns(options: CompareFindingRunsOptions): Promise<FindingDeltaReport> {
  const [baseline, candidate] = await Promise.all([
    verifyAndLoadRunDirectory(options.baselineRunDirectory),
    verifyAndLoadRunDirectory(options.candidateRunDirectory)
  ]);
  const targetComparison = await resolveTargetComparison(baseline, candidate, options);
  const compatibility = assertFindingCompatibility(baseline, candidate);

  const findings = compareFindingRecords(baseline.artifacts.findings, candidate.artifacts.findings);
  const matchingNewFindings = options.failOnNew === undefined
    ? 0
    : findings.new.filter((entry) => severityAtOrAbove(entry.candidate!.severity, options.failOnNew!)).length;
  const withoutIdentity: ReportWithoutIdentity = {
    schemaVersion: 1,
    kind: 'atlas-finding-delta-report',
    producer: { id: 'atlas/finding-diff', version: FINDING_DIFF_VERSION },
    target: targetComparison.reportTarget,
    profile: {
      id: baseline.artifacts.run.profileId,
      digest: baseline.artifacts.run.profileDigest
    },
    compatibility,
    baseline: runBinding(baseline),
    candidate: runBinding(candidate),
    summary: {
      new: findings.new.length,
      resolved: findings.resolved.length,
      unchanged: findings.unchanged.length
    },
    gate: {
      ...(options.failOnNew === undefined ? {} : { threshold: options.failOnNew }),
      matchingNewFindings,
      triggered: matchingNewFindings > 0
    },
    findings
  };
  const report: FindingDeltaReport = {
    ...withoutIdentity,
    reportId: `finding_delta_sha256_${sha256(canonicalJson({ domain: 'atlas.finding-delta.v1', ...withoutIdentity }))}`
  };
  await assertSchema('finding-delta', report, 'Finding delta report');
  assertPortableDataSafe(report, 'Atlas finding delta report');
  return report;
}

export async function writeFindingDeltaReport(
  options: WriteFindingDeltaOptions,
  report?: FindingDeltaReport
): Promise<ImmutableReportWriteResult> {
  const resolvedReport = report ?? await compareFindingRuns(options);
  await assertSchema('finding-delta', resolvedReport, 'Finding delta report');
  assertPortableDataSafe(resolvedReport, 'Atlas finding delta report');
  const [baseline, candidate] = await Promise.all([
    verifyAndLoadRunDirectory(options.baselineRunDirectory),
    verifyAndLoadRunDirectory(options.candidateRunDirectory)
  ]);
  const targetComparison = await resolveTargetComparison(baseline, candidate, options);
  const compatibility = assertFindingCompatibility(baseline, candidate);
  if (
    canonicalJson(resolvedReport.target) !== canonicalJson(targetComparison.reportTarget) ||
    resolvedReport.profile.id !== baseline.artifacts.run.profileId ||
    resolvedReport.profile.digest !== baseline.artifacts.run.profileDigest ||
    canonicalJson(resolvedReport.compatibility) !== canonicalJson(compatibility) ||
    canonicalJson(resolvedReport.baseline) !== canonicalJson(runBinding(baseline)) ||
    canonicalJson(resolvedReport.candidate) !== canonicalJson(runBinding(candidate))
  ) {
    throw new AtlasError(
      'FINDING_DIFF_REPORT_MISMATCH',
      'Finding delta report bindings do not match the verified baseline and candidate runs.'
    );
  }
  let outputBoundaries = targetComparison.outputBoundaries;
  if (outputBoundaries.length === 0) {
    if (options.targetConfigPath === undefined) {
      throw new AtlasError(
        'FINDING_DIFF_OUTPUT_TARGET_REQUIRED',
        'Writing a same-target finding delta requires --target <target.json> for output-boundary enforcement.'
      );
    }
    const target = await resolveOutputTarget(
      options.targetConfigPath,
      baseline.artifacts.run.targetId,
      'baseline'
    );
    outputBoundaries = [target.configPath, target.targetRoot];
  } else if (options.targetConfigPath !== undefined) {
    throw new AtlasError(
      'FINDING_DIFF_TARGET_MISMATCH',
      'Do not combine --target with paired --baseline-target and --candidate-target descriptors.'
    );
  }
  return writeImmutableCanonicalReport(
    options.outputPath,
    resolvedReport,
    [options.baselineRunDirectory, options.candidateRunDirectory, ...outputBoundaries]
  );
}
