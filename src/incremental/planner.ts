import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX } from '../artifact-contract.js';
import { AtlasError } from '../errors.js';
import { assertSchema } from '../schema-validator.js';
import { loadTargetRegistration, resolveTargetDescriptor, verifyTargetRegistrationBinding } from '../targets.js';
import type {
  DiagnosticRecord,
  EvidenceReference,
  ExecutionRecord,
  FindingRecord,
  RelationshipRecord
} from '../types.js';
import { canonicalJson, compareCanonicalText, prettyCanonicalJson, sha256 } from '../util/canonical.js';
import { isInside, resolveForContainment } from '../util/paths.js';
import { verifyAndLoadRunDirectory, type VerifiedRunDirectoryResult } from '../verify.js';
import type {
  IncrementalAffectedRecords,
  IncrementalAnalysisPlan,
  IncrementalBatchPlan,
  IncrementalBatchPlanOptions,
  IncrementalChangedEvidenceEdge,
  IncrementalEvidenceEdge,
  IncrementalFullRebuildReason,
  IncrementalPathChanges,
  IncrementalPlanOptions,
  IncrementalRunBinding
} from './types.js';

export const INCREMENTAL_PLANNER_VERSION = '1.0.0';

const PLANNER = { name: 'atlas/incremental-planner' as const, version: INCREMENTAL_PLANNER_VERSION };

interface AttemptBinding {
  targetRoot: string;
  targetConfigPath: string;
}

interface BoundRun {
  verified: VerifiedRunDirectoryResult;
  binding: IncrementalRunBinding;
}

function samePath(left: string, right: string): boolean {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort(compareCanonicalText);
}

async function successfulAttemptBinding(workspacePath: string, runId: string): Promise<AttemptBinding> {
  const attemptsDirectory = path.join(workspacePath, 'attempts');
  let directoryMetadata;
  let entries;
  try {
    directoryMetadata = await lstat(attemptsDirectory);
    entries = await readdir(attemptsDirectory, { withFileTypes: true });
  } catch {
    throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'The workspace has no readable execution attempt ledger.');
  }
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'The workspace attempt ledger must be a real directory.');
  }
  const canonicalAttemptsDirectory = await realpath(attemptsDirectory);
  if (!samePath(canonicalAttemptsDirectory, attemptsDirectory)) {
    throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'The workspace attempt ledger path is not canonical.');
  }
  entries.sort((left, right) => compareCanonicalText(left.name, right.name));
  const bindings: AttemptBinding[] = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith('.json')) {
      throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'The workspace attempt ledger contains an invalid entry.');
    }
    const receiptPath = path.join(attemptsDirectory, entry.name);
    const rawReceipt = await readFile(receiptPath, 'utf8');
    const receipt = JSON.parse(rawReceipt) as ExecutionRecord;
    await assertSchema('attempt', receipt, 'Execution attempt receipt');
    if (rawReceipt !== prettyCanonicalJson(receipt) || entry.name !== `${receipt.attemptId}.json`) {
      throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'An execution attempt receipt is not canonical.');
    }
    if ((receipt.status !== 'completed' && receipt.status !== 'reused') || receipt.runId !== runId) continue;
    if (!path.isAbsolute(receipt.targetPath) || !path.isAbsolute(receipt.targetConfigPath)) {
      throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'A matching execution attempt has a non-absolute target binding.');
    }
    let targetRoot: string;
    let targetConfigPath: string;
    try {
      [targetRoot, targetConfigPath] = await Promise.all([
        realpath(receipt.targetPath),
        realpath(receipt.targetConfigPath)
      ]);
    } catch {
      throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'A matching execution attempt target binding is unavailable.');
    }
    if (!samePath(targetRoot, receipt.targetPath) || !samePath(targetConfigPath, receipt.targetConfigPath)) {
      throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'A matching execution attempt target binding is not canonical.');
    }
    const [targetMetadata, configMetadata] = await Promise.all([lstat(targetRoot), lstat(targetConfigPath)]);
    if (
      !targetMetadata.isDirectory() || targetMetadata.isSymbolicLink() ||
      !configMetadata.isFile() || configMetadata.isSymbolicLink()
    ) {
      throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'A matching execution attempt target binding has an invalid filesystem type.');
    }
    bindings.push({ targetRoot, targetConfigPath });
  }
  if (bindings.length === 0) {
    throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'No successful execution attempt binds the selected run to this workspace.');
  }
  const first = bindings[0]!;
  if (bindings.some((binding) =>
    !samePath(binding.targetRoot, first.targetRoot) || !samePath(binding.targetConfigPath, first.targetConfigPath)
  )) {
    throw new AtlasError('INCREMENTAL_ATTEMPT_MISMATCH', 'Successful execution attempts conflict on the selected run target binding.');
  }
  return first;
}

async function loadBoundRun(
  workspacePath: string,
  runsRoot: string,
  expectedTargetId: string,
  runDirectoryValue: string
): Promise<BoundRun> {
  const requestedDirectory = path.resolve(runDirectoryValue);
  let runDirectory: string;
  try {
    const metadata = await lstat(requestedDirectory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new AtlasError('INCREMENTAL_RUN_MISMATCH', 'An incremental input run must be a real directory.');
    }
    runDirectory = await realpath(requestedDirectory);
  } catch (error) {
    if (error instanceof AtlasError) throw error;
    throw new AtlasError('INCREMENTAL_RUN_MISMATCH', 'An incremental input run is unavailable.');
  }
  if (!isInside(runsRoot, runDirectory)) {
    throw new AtlasError('INCREMENTAL_RUN_MISMATCH', 'An incremental input run is outside the selected workspace.');
  }
  const verified = await verifyAndLoadRunDirectory(runDirectory);
  const expectedDirectory = path.join(runsRoot, verified.artifacts.run.runId);
  if (!samePath(runDirectory, expectedDirectory)) {
    throw new AtlasError('INCREMENTAL_RUN_MISMATCH', 'An incremental input is not the canonical published workspace run.');
  }
  if (verified.artifacts.run.targetId !== expectedTargetId) {
    throw new AtlasError('INCREMENTAL_TARGET_MISMATCH', 'An incremental input run belongs to a different registered target.');
  }
  const attemptBinding = await successfulAttemptBinding(workspacePath, verified.artifacts.run.runId);
  const descriptor = await resolveTargetDescriptor(attemptBinding.targetConfigPath);
  if (
    descriptor.target.id !== expectedTargetId ||
    !samePath(descriptor.targetRoot, attemptBinding.targetRoot)
  ) {
    throw new AtlasError('TARGET_REGISTRATION_CONFLICT', 'Current target descriptor does not match the successful scan binding.');
  }
  await verifyTargetRegistrationBinding({
    workspacePath,
    targetId: expectedTargetId,
    targetRoot: attemptBinding.targetRoot,
    targetConfigPath: attemptBinding.targetConfigPath,
    consent: descriptor.target.consent
  });
  const run = verified.artifacts.run;
  return {
    verified,
    binding: {
      runId: run.runId,
      artifactManifestDigest: sha256(canonicalJson(verified.manifest)),
      snapshotId: run.snapshotId,
      targetId: run.targetId,
      profileId: run.profileId,
      profileDigest: run.profileDigest,
      discoveryDigest: run.discovery.digest
    }
  };
}

function pathChanges(baseline: BoundRun, next: BoundRun): IncrementalPathChanges {
  const before = new Map(baseline.verified.artifacts.files.map((file) => [file.path, file]));
  const after = new Map(next.verified.artifacts.files.map((file) => [file.path, file]));
  const added: string[] = [];
  const changed: string[] = [];
  const removed: string[] = [];
  for (const [pathValue, file] of after) {
    const previous = before.get(pathValue);
    if (!previous) added.push(pathValue);
    else if (file.sha256 !== previous.sha256 || file.bytes !== previous.bytes) changed.push(pathValue);
  }
  for (const pathValue of before.keys()) if (!after.has(pathValue)) removed.push(pathValue);
  return {
    added: added.sort(compareCanonicalText),
    changed: changed.sort(compareCanonicalText),
    removed: removed.sort(compareCanonicalText)
  };
}

function evidenceEdge(relationship: RelationshipRecord): IncrementalEvidenceEdge {
  return {
    relationshipId: relationship.id,
    recordDigest: sha256(canonicalJson(relationship)),
    fromPath: relationship.fromPath,
    type: relationship.type,
    resolution: relationship.resolution,
    ...(relationship.toPath ? { toPath: relationship.toPath } : {})
  };
}

function evidenceEdgeChanges(baseline: BoundRun, next: BoundRun): {
  added: IncrementalEvidenceEdge[];
  changed: IncrementalChangedEvidenceEdge[];
  removed: IncrementalEvidenceEdge[];
} {
  const before = new Map(baseline.verified.artifacts.relationships.map((entry) => [entry.id, entry]));
  const after = new Map(next.verified.artifacts.relationships.map((entry) => [entry.id, entry]));
  const added: IncrementalEvidenceEdge[] = [];
  const changed: IncrementalChangedEvidenceEdge[] = [];
  const removed: IncrementalEvidenceEdge[] = [];
  for (const [id, relationship] of after) {
    const previous = before.get(id);
    if (!previous) added.push(evidenceEdge(relationship));
    else if (canonicalJson(previous) !== canonicalJson(relationship)) {
      changed.push({ relationshipId: id, before: evidenceEdge(previous), after: evidenceEdge(relationship) });
    }
  }
  for (const [id, relationship] of before) if (!after.has(id)) removed.push(evidenceEdge(relationship));
  added.sort((left, right) => compareCanonicalText(left.relationshipId, right.relationshipId));
  changed.sort((left, right) => compareCanonicalText(left.relationshipId, right.relationshipId));
  removed.sort((left, right) => compareCanonicalText(left.relationshipId, right.relationshipId));
  return { added, changed, removed };
}

function recordDeltaIds<T extends { id: string }>(beforeValues: T[], afterValues: T[]): Set<string> {
  const before = new Map(beforeValues.map((entry) => [entry.id, entry]));
  const after = new Map(afterValues.map((entry) => [entry.id, entry]));
  const changed = new Set<string>();
  for (const [id, value] of before) {
    const nextValue = after.get(id);
    if (!nextValue || canonicalJson(value) !== canonicalJson(nextValue)) changed.add(id);
  }
  for (const id of after.keys()) if (!before.has(id)) changed.add(id);
  return changed;
}

function findingPaths(value: FindingRecord): string[] {
  return sortedUnique([
    ...(value.path ? [value.path] : []),
    ...value.relatedPaths,
    ...value.evidence.flatMap((entry) => entry.path ? [entry.path] : []),
    ...(value.instances ?? []).flatMap((instance) => [
      ...(instance.path ? [instance.path] : []),
      ...instance.relatedPaths,
      ...instance.evidence.flatMap((entry) => entry.path ? [entry.path] : [])
    ])
  ]);
}

function findingInstancePaths(value: NonNullable<FindingRecord['instances']>[number]): string[] {
  return sortedUnique([
    ...(value.path ? [value.path] : []),
    ...value.relatedPaths,
    ...value.evidence.flatMap((entry) => entry.path ? [entry.path] : [])
  ]);
}

function aggregatePatternKey(value: FindingRecord): string | undefined {
  return value.patternKey ? `${value.ruleId}\0${value.patternKey}` : undefined;
}

function changedAggregateFindingPaths(
  before: FindingRecord[],
  after: FindingRecord[]
): { handledIds: Set<string>; paths: string[] } {
  const beforeByPattern = new Map(before.flatMap((finding) => {
    const key = aggregatePatternKey(finding);
    return key ? [[key, finding] as const] : [];
  }));
  const afterByPattern = new Map(after.flatMap((finding) => {
    const key = aggregatePatternKey(finding);
    return key ? [[key, finding] as const] : [];
  }));
  const handledIds = new Set<string>();
  const paths = new Set<string>();
  for (const [key, beforeFinding] of beforeByPattern) {
    const afterFinding = afterByPattern.get(key);
    if (!afterFinding || !beforeFinding.instances?.length || !afterFinding.instances?.length) continue;
    if (canonicalJson(beforeFinding) === canonicalJson(afterFinding)) continue;
    handledIds.add(beforeFinding.id);
    handledIds.add(afterFinding.id);
    const beforeInstances = new Map(beforeFinding.instances.map((instance) => [instance.id, instance]));
    const afterInstances = new Map(afterFinding.instances.map((instance) => [instance.id, instance]));
    let changedInstanceCount = 0;
    for (const [id, instance] of beforeInstances) {
      const nextInstance = afterInstances.get(id);
      if (nextInstance && canonicalJson(instance) === canonicalJson(nextInstance)) continue;
      changedInstanceCount += 1;
      for (const pathValue of findingInstancePaths(instance)) paths.add(pathValue);
      if (nextInstance) for (const pathValue of findingInstancePaths(nextInstance)) paths.add(pathValue);
    }
    for (const [id, instance] of afterInstances) {
      if (beforeInstances.has(id)) continue;
      changedInstanceCount += 1;
      for (const pathValue of findingInstancePaths(instance)) paths.add(pathValue);
    }
    // A pattern-level change without an instance delta cannot be localized safely.
    if (changedInstanceCount === 0) {
      for (const pathValue of findingPaths(beforeFinding)) paths.add(pathValue);
      for (const pathValue of findingPaths(afterFinding)) paths.add(pathValue);
    }
  }
  return { handledIds, paths: sortedUnique(paths) };
}

function diagnosticPaths(value: DiagnosticRecord): string[] {
  return sortedUnique([
    ...(value.path ? [value.path] : []),
    ...(value.evidence.path ? [value.evidence.path] : [])
  ]);
}

function directRecordImpactSeeds(baseline: BoundRun, next: BoundRun): {
  paths: string[];
  findingIds: Set<string>;
  diagnosticIds: Set<string>;
} {
  const beforeArtifacts = baseline.verified.artifacts;
  const nextArtifacts = next.verified.artifacts;
  const findingIds = recordDeltaIds(beforeArtifacts.findings, nextArtifacts.findings);
  const diagnosticIds = recordDeltaIds(beforeArtifacts.diagnostics, nextArtifacts.diagnostics);
  const aggregateDelta = changedAggregateFindingPaths(beforeArtifacts.findings, nextArtifacts.findings);
  const paths = new Set<string>(aggregateDelta.paths);
  for (const finding of [...beforeArtifacts.findings, ...nextArtifacts.findings]) {
    if (findingIds.has(finding.id) && !aggregateDelta.handledIds.has(finding.id)) {
      for (const pathValue of findingPaths(finding)) paths.add(pathValue);
    }
  }
  for (const diagnostic of [...beforeArtifacts.diagnostics, ...nextArtifacts.diagnostics]) {
    if (diagnosticIds.has(diagnostic.id)) for (const pathValue of diagnosticPaths(diagnostic)) paths.add(pathValue);
  }
  return { paths: sortedUnique(paths), findingIds, diagnosticIds };
}

function dependencyImpact(
  baseline: BoundRun,
  next: BoundRun,
  changes: IncrementalPathChanges,
  edgeChanges: ReturnType<typeof evidenceEdgeChanges>,
  recordSeeds: string[]
): { seedPaths: string[]; reverseDependencyClosurePaths: string[] } {
  const seeds = new Set<string>([...changes.added, ...changes.changed, ...changes.removed, ...recordSeeds]);
  for (const edge of [...edgeChanges.added, ...edgeChanges.removed]) {
    seeds.add(edge.fromPath);
    if (edge.toPath) seeds.add(edge.toPath);
  }
  for (const edge of edgeChanges.changed) {
    seeds.add(edge.before.fromPath);
    seeds.add(edge.after.fromPath);
    if (edge.before.toPath) seeds.add(edge.before.toPath);
    if (edge.after.toPath) seeds.add(edge.after.toPath);
  }
  const reverse = new Map<string, Set<string>>();
  for (const relationship of [
    ...baseline.verified.artifacts.relationships,
    ...next.verified.artifacts.relationships
  ]) {
    if (relationship.resolution !== 'resolved' || !relationship.toPath) continue;
    const dependents = reverse.get(relationship.toPath) ?? new Set<string>();
    dependents.add(relationship.fromPath);
    reverse.set(relationship.toPath, dependents);
  }
  const closure = new Set<string>(seeds);
  const queue = sortedUnique(seeds);
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index]!;
    for (const dependent of sortedUnique(reverse.get(current) ?? [])) {
      if (closure.has(dependent)) continue;
      closure.add(dependent);
      queue.push(dependent);
    }
  }
  return {
    seedPaths: sortedUnique(seeds),
    reverseDependencyClosurePaths: sortedUnique(closure)
  };
}

function recordReferencesImpact(
  record: FindingRecord | DiagnosticRecord,
  impactPaths: Set<string>,
  changedEvidenceIds: Set<string>
): boolean {
  const paths = 'relatedPaths' in record ? findingPaths(record) : diagnosticPaths(record);
  if (paths.some((pathValue) => impactPaths.has(pathValue))) return true;
  const evidenceValues: EvidenceReference[] = Array.isArray(record.evidence) ? record.evidence : [record.evidence];
  return evidenceValues.some((entry) =>
    (entry.recordIds ?? []).some((id: string) => changedEvidenceIds.has(id))
  );
}

function affectedRecords(
  baseline: BoundRun,
  next: BoundRun,
  closurePaths: string[],
  edgeChanges: ReturnType<typeof evidenceEdgeChanges>,
  directFindingIds: Set<string>,
  directDiagnosticIds: Set<string>
): IncrementalAffectedRecords {
  const impactPaths = new Set(closurePaths);
  const changedEvidenceIds = new Set<string>([
    ...edgeChanges.added.map((edge) => edge.relationshipId),
    ...edgeChanges.changed.map((edge) => edge.relationshipId),
    ...edgeChanges.removed.map((edge) => edge.relationshipId)
  ]);
  const baselineArtifacts = baseline.verified.artifacts;
  const nextArtifacts = next.verified.artifacts;
  return {
    baselineFindingIds: sortedUnique(baselineArtifacts.findings
      .filter((entry) => directFindingIds.has(entry.id) || recordReferencesImpact(entry, impactPaths, changedEvidenceIds))
      .map((entry) => entry.id)),
    nextFindingIds: sortedUnique(nextArtifacts.findings
      .filter((entry) => directFindingIds.has(entry.id) || recordReferencesImpact(entry, impactPaths, changedEvidenceIds))
      .map((entry) => entry.id)),
    baselineDiagnosticIds: sortedUnique(baselineArtifacts.diagnostics
      .filter((entry) => directDiagnosticIds.has(entry.id) || recordReferencesImpact(entry, impactPaths, changedEvidenceIds))
      .map((entry) => entry.id)),
    nextDiagnosticIds: sortedUnique(nextArtifacts.diagnostics
      .filter((entry) => directDiagnosticIds.has(entry.id) || recordReferencesImpact(entry, impactPaths, changedEvidenceIds))
      .map((entry) => entry.id))
  };
}

function compatibilityReasons(baseline: BoundRun, next: BoundRun): IncrementalFullRebuildReason[] {
  const before = baseline.verified.artifacts.run;
  const after = next.verified.artifacts.run;
  const reasons: IncrementalFullRebuildReason[] = [];
  if (before.profileId !== after.profileId) reasons.push('PROFILE_ID_CHANGED');
  if (before.profileDigest !== after.profileDigest) reasons.push('PROFILE_DIGEST_CHANGED');
  if (canonicalJson(before.tool) !== canonicalJson(after.tool)) reasons.push('TOOL_CHANGED');
  if (canonicalJson(before.adapters) !== canonicalJson(after.adapters)) reasons.push('ADAPTER_SET_CHANGED');
  const beforeAnalyzers = before.analyses.filter((entry) => !entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX));
  const afterAnalyzers = after.analyses.filter((entry) => !entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX));
  if (canonicalJson(beforeAnalyzers) !== canonicalJson(afterAnalyzers)) reasons.push('ANALYZER_SET_CHANGED');
  const beforeProfileObservations = before.analyses.filter((entry) => entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX));
  const afterProfileObservations = after.analyses.filter((entry) => entry.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX));
  if (canonicalJson(beforeProfileObservations) !== canonicalJson(afterProfileObservations)) {
    reasons.push('PROFILE_OBSERVATIONS_CHANGED');
  }
  if (before.discovery.provider !== after.discovery.provider) reasons.push('DISCOVERY_PROVIDER_CHANGED');
  if (before.discovery.version !== after.discovery.version) reasons.push('DISCOVERY_VERSION_CHANGED');
  if (before.discovery.state !== after.discovery.state) reasons.push('DISCOVERY_STATE_CHANGED');
  if (
    before.runId === after.runId &&
    baseline.binding.artifactManifestDigest !== next.binding.artifactManifestDigest
  ) reasons.push('RUN_ID_DIGEST_CONFLICT');
  return [...new Set(reasons)].sort(compareCanonicalText);
}

export function incrementalPlanIdentity(plan: Omit<IncrementalAnalysisPlan, 'planId'>): string {
  return `incremental_plan_sha256_${sha256(canonicalJson({ domain: 'atlas.incremental-plan.v1', ...plan }))}`;
}

export function incrementalBatchPlanIdentity(plan: Omit<IncrementalBatchPlan, 'batchPlanId'>): string {
  return `incremental_batch_sha256_${sha256(canonicalJson({ domain: 'atlas.incremental-batch.v1', ...plan }))}`;
}

export async function planIncrementalAnalysis(options: IncrementalPlanOptions): Promise<IncrementalAnalysisPlan> {
  const workspacePath = await resolveForContainment(options.workspacePath);
  const registration = await loadTargetRegistration(workspacePath, options.targetId);
  if (registration.targetId !== options.targetId) {
    throw new AtlasError('INCREMENTAL_TARGET_MISMATCH', 'The selected target registration does not match the requested target.');
  }
  const runsRoot = await resolveForContainment(path.join(workspacePath, 'runs'));
  if (!isInside(workspacePath, runsRoot)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'The workspace run directory resolves outside the selected workspace.');
  }
  const [baseline, next] = await Promise.all([
    loadBoundRun(workspacePath, runsRoot, options.targetId, options.baselineRunDirectory),
    loadBoundRun(workspacePath, runsRoot, options.targetId, options.nextRunDirectory)
  ]);
  if (baseline.verified.artifacts.run.targetId !== next.verified.artifacts.run.targetId) {
    throw new AtlasError('INCREMENTAL_TARGET_MISMATCH', 'Incremental runs must belong to the same registered target.');
  }

  const paths = pathChanges(baseline, next);
  const evidenceEdges = evidenceEdgeChanges(baseline, next);
  const directImpact = directRecordImpactSeeds(baseline, next);
  const impactPaths = dependencyImpact(baseline, next, paths, evidenceEdges, directImpact.paths);
  const affected = affectedRecords(
    baseline,
    next,
    impactPaths.reverseDependencyClosurePaths,
    evidenceEdges,
    directImpact.findingIds,
    directImpact.diagnosticIds
  );
  const fullRebuildReasons = compatibilityReasons(baseline, next);
  const incrementalReuseEligible = fullRebuildReasons.length === 0;
  const nextPaths = next.verified.artifacts.files.map((file) => file.path);
  const affectedPathSet = new Set(impactPaths.reverseDependencyClosurePaths);
  const hitEligiblePaths = incrementalReuseEligible
    ? nextPaths.filter((pathValue) => !affectedPathSet.has(pathValue)).sort(compareCanonicalText)
    : [];
  const missRequiredPaths = incrementalReuseEligible
    ? nextPaths.filter((pathValue) => affectedPathSet.has(pathValue)).sort(compareCanonicalText)
    : [...nextPaths].sort(compareCanonicalText);
  const draft: Omit<IncrementalAnalysisPlan, 'planId'> = {
    schemaVersion: 1,
    planner: PLANNER,
    targetId: options.targetId,
    baseline: baseline.binding,
    next: next.binding,
    compatibility: {
      incrementalReuseEligible,
      discoveryChanged: baseline.binding.discoveryDigest !== next.binding.discoveryDigest,
      fullRebuildReasons
    },
    paths,
    evidenceEdges,
    impact: {
      ...impactPaths,
      affectedRecords: affected
    },
    cache: {
      hitEligiblePaths,
      missRequiredPaths,
      evictedPaths: [...paths.removed]
    }
  };
  const plan: IncrementalAnalysisPlan = { ...draft, planId: incrementalPlanIdentity(draft) };
  await assertSchema('incremental-plan', plan, 'Incremental analysis plan');
  return plan;
}

export async function planIncrementalAnalysisBatch(
  options: IncrementalBatchPlanOptions
): Promise<IncrementalBatchPlan> {
  const targetIds = options.targets.map((entry) => entry.targetId);
  if (new Set(targetIds).size !== targetIds.length) {
    throw new AtlasError('INCREMENTAL_BATCH_TARGET_DUPLICATE', 'A batch may contain at most one plan per registered target.');
  }
  const ordered = [...options.targets].sort((left, right) => compareCanonicalText(left.targetId, right.targetId));
  const plans = await Promise.all(ordered.map((entry) => planIncrementalAnalysis({
    workspacePath: options.workspacePath,
    targetId: entry.targetId,
    baselineRunDirectory: entry.baselineRunDirectory,
    nextRunDirectory: entry.nextRunDirectory
  })));
  const draft: Omit<IncrementalBatchPlan, 'batchPlanId'> = {
    schemaVersion: 1,
    planner: PLANNER,
    plans
  };
  const plan: IncrementalBatchPlan = { ...draft, batchPlanId: incrementalBatchPlanIdentity(draft) };
  await assertSchema('incremental-batch-plan', plan, 'Incremental batch plan');
  return plan;
}
