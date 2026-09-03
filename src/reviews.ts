import { randomUUID } from 'node:crypto';
import { access, lstat, mkdir, readdir, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { loadRunArtifacts, type LoadedRun } from './artifacts.js';
import { AtlasError } from './errors.js';
import { planIncrementalAnalysis } from './incremental/index.js';
import { assertSchema } from './schema-validator.js';
import { assertPortableDataSafe } from './security/portable-data.js';
import { verifyTargetRegistrationBinding } from './targets.js';
import type {
  ExecutionRecord,
  FileRecord,
  ReviewCampaign,
  ReviewPacket,
  ReviewPacketFile,
  ReviewSelectionKind,
  ReviewSelectionSpec,
  TargetConfig
} from './types.js';
import { SCHEMA_VERSION } from './types.js';
import { canonicalJson, compareCanonicalText, readJson, sha256, writeCanonicalJson } from './util/canonical.js';
import { isInside, matchesGlob, normalizeTargetRelative, resolveForContainment } from './util/paths.js';

const REQUIRED_RESULT_FIELDS = [
  'packetId', 'packetHash', 'reviewer', 'reviewedFiles', 'responsibilities',
  'associations', 'observed', 'suspected', 'needsRuntimeValidation', 'unknowns'
] as const;

async function exists(value: string): Promise<boolean> {
  try { await access(value); return true; } catch { return false; }
}

async function removeCampaignTemporary(parent: string, candidate: string): Promise<void> {
  if (path.dirname(candidate) !== parent || !path.basename(candidate).startsWith('.review-campaign-tmp-')) {
    throw new AtlasError('UNSAFE_TEMP_PATH', 'Refusing to remove an unsafe review-campaign temporary path.');
  }
  await rm(candidate, { recursive: true, force: true });
}

function packetHashMaterial(packet: Omit<ReviewPacket, 'packetHash'>): string {
  return sha256(canonicalJson(packet));
}

function samePath(left: string, right: string): boolean {
  return path.relative(path.resolve(left), path.resolve(right)) === '';
}

interface ReviewAttemptBinding {
  targetRoot: string;
  targetConfigPath: string;
}

async function reviewAttemptBinding(workspacePath: string, runId: string): Promise<ReviewAttemptBinding> {
  const attemptsDirectory = path.join(workspacePath, 'attempts');
  let directoryMetadata;
  let entries;
  try {
    directoryMetadata = await lstat(attemptsDirectory);
    entries = await readdir(attemptsDirectory, { withFileTypes: true });
  } catch {
    throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', 'Review workspace has no readable attempt receipts.');
  }
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', 'Review workspace attempts path must be a real directory.');
  }
  const canonicalAttemptsDirectory = await realpath(attemptsDirectory);
  if (!samePath(canonicalAttemptsDirectory, attemptsDirectory)) {
    throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', 'Review workspace attempts path is not canonical.');
  }
  entries.sort((left, right) => compareCanonicalText(left.name, right.name));
  const matchingBindings: ReviewAttemptBinding[] = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith('.json')) {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Invalid attempt receipt entry: ${entry.name}`);
    }
    const receiptPath = path.join(attemptsDirectory, entry.name);
    const receiptMetadata = await lstat(receiptPath);
    if (!receiptMetadata.isFile() || receiptMetadata.isSymbolicLink()) {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Attempt receipt is not a regular file: ${entry.name}`);
    }
    const receipt = await readJson<ExecutionRecord>(receiptPath);
    await assertSchema('attempt', receipt, `Attempt receipt ${entry.name}`);
    if (entry.name !== `${receipt.attemptId}.json`) {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Attempt receipt filename and ID differ: ${entry.name}`);
    }
    if ((receipt.status !== 'completed' && receipt.status !== 'reused') || receipt.runId !== runId) continue;
    if (!path.isAbsolute(receipt.targetPath) || !path.isAbsolute(receipt.targetConfigPath)) {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Attempt target binding is not absolute: ${entry.name}`);
    }
    let canonicalTargetRoot: string;
    let canonicalTargetConfigPath: string;
    try {
      [canonicalTargetRoot, canonicalTargetConfigPath] = await Promise.all([
        realpath(receipt.targetPath),
        realpath(receipt.targetConfigPath)
      ]);
    } catch {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Attempt target binding is missing or unreadable: ${entry.name}`);
    }
    if (!samePath(canonicalTargetRoot, receipt.targetPath)) {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Attempt target path is not canonical: ${entry.name}`);
    }
    if (!(await lstat(canonicalTargetRoot)).isDirectory() || !(await lstat(canonicalTargetConfigPath)).isFile()) {
      throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', `Attempt target binding has an invalid filesystem type: ${entry.name}`);
    }
    matchingBindings.push({ targetRoot: canonicalTargetRoot, targetConfigPath: canonicalTargetConfigPath });
  }
  if (!matchingBindings.length) {
    throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', 'No successful attempt receipt authorizes the selected run.');
  }
  const binding = matchingBindings[0]!;
  if (matchingBindings.some((candidate) => (
    !samePath(candidate.targetRoot, binding.targetRoot) ||
    !samePath(candidate.targetConfigPath, binding.targetConfigPath)
  ))) {
    throw new AtlasError('REVIEW_ATTEMPT_MISMATCH', 'Successful attempt receipts conflict on the selected run target binding.');
  }
  return binding;
}

function reviewPacketFiles(files: FileRecord[]): ReviewPacketFile[] {
  return files.map((file) => ({
    id: file.id,
    path: file.path,
    sha256: file.sha256,
    bytes: file.bytes
  }));
}

function normalizedSelectors(values: string[] | undefined, label: string): string[] {
  if (!values?.length) throw new AtlasError('REVIEW_SELECTION_INVALID', `${label} selection requires at least one selector.`);
  if (values.length > 25_000) throw new AtlasError('REVIEW_SELECTION_INVALID', `${label} selection exceeds 25000 selectors.`);
  const normalized = values.map((value) => value.normalize('NFC').trim());
  if (normalized.some((value) => !value || value.length > 4096 || /[\u0000-\u001f\u007f-\u009f]/u.test(value))) {
    throw new AtlasError('REVIEW_SELECTION_INVALID', `${label} selectors must contain 1-4096 printable characters.`);
  }
  return [...new Set(normalized)].sort(compareCanonicalText);
}

function normalizedReviewPurpose(value: string): string {
  const purpose = value.normalize('NFC').trim();
  if (!purpose || purpose.length > 4096 || /[\u0000-\u001f\u007f-\u009f]/u.test(purpose)) {
    throw new AtlasError('REVIEW_PURPOSE_INVALID', 'Review purpose must contain 1-4096 printable characters.');
  }
  return purpose;
}

function filesForPaths(loaded: LoadedRun, selectors: string[]): FileRecord[] {
  const normalized = selectors.map((selector) => selector.startsWith('file_sha256_')
    ? selector
    : normalizeTargetRelative(selector));
  const matched = new Set<string>();
  const selected = loaded.files.filter((file) => normalized.some((selector) => {
    const matches = selector.startsWith('file_sha256_')
      ? file.id === selector
      : matchesGlob(file.path, selector);
    if (matches) matched.add(selector);
    return matches;
  }));
  const missing = normalized.filter((selector) => !matched.has(selector));
  if (missing.length) throw new AtlasError('REVIEW_SELECTION_EMPTY', 'One or more path selectors matched no file in the selected run.');
  return selected;
}

function filesForSymbols(loaded: LoadedRun, selectors: string[]): FileRecord[] {
  const matched = new Set<string>();
  const selected = loaded.files.filter((file) => selectors.some((selector) => {
    const matches = file.symbols.includes(selector);
    if (matches) matched.add(selector);
    return matches;
  }));
  if (selectors.some((selector) => !matched.has(selector))) {
    throw new AtlasError('REVIEW_SELECTION_EMPTY', 'One or more exact symbol selectors matched no exported symbol in the selected run.');
  }
  return selected;
}

function filesForFindings(loaded: LoadedRun, selectors?: string[]): FileRecord[] {
  const selectedFindings = selectors?.length
    ? loaded.findings.filter((finding) => selectors.includes(finding.id))
    : loaded.findings;
  if (selectors?.some((selector) => !selectedFindings.some((finding) => finding.id === selector))) {
    throw new AtlasError('REVIEW_SELECTION_EMPTY', 'One or more finding selectors matched no finding in the selected run.');
  }
  const selectedPaths = new Set<string>();
  for (const finding of selectedFindings) {
    if (finding.path) selectedPaths.add(finding.path);
    for (const relatedPath of finding.relatedPaths) selectedPaths.add(relatedPath);
    if (selectors?.length) for (const evidence of finding.evidence) if (evidence.path) selectedPaths.add(evidence.path);
  }
  return loaded.files.filter((file) => selectedPaths.has(file.path));
}

function filesForNeighborhood(
  loaded: LoadedRun,
  selectors: string[],
  depth: number,
  direction: 'incoming' | 'outgoing' | 'both'
): FileRecord[] {
  if (!Number.isSafeInteger(depth) || depth < 0 || depth > 8) {
    throw new AtlasError('REVIEW_SELECTION_INVALID', 'Neighborhood depth must be between 0 and 8.');
  }
  const byPath = new Map(loaded.files.map((file) => [file.path, file]));
  const byId = new Map(loaded.files.map((file) => [file.id, file]));
  const seedFiles = selectors.map((selector) => byId.get(selector) ?? byPath.get(normalizeTargetRelative(selector)));
  if (seedFiles.some((file) => !file)) {
    throw new AtlasError('REVIEW_SELECTION_EMPTY', 'One or more neighborhood seeds matched no exact file path or ID.');
  }
  const outgoing = new Map<string, Set<string>>();
  const incoming = new Map<string, Set<string>>();
  for (const relationship of loaded.relationships) {
    if (relationship.resolution !== 'resolved' || !relationship.toPath) continue;
    const outgoingTargets = outgoing.get(relationship.fromPath) ?? new Set<string>();
    outgoingTargets.add(relationship.toPath);
    outgoing.set(relationship.fromPath, outgoingTargets);
    const incomingSources = incoming.get(relationship.toPath) ?? new Set<string>();
    incomingSources.add(relationship.fromPath);
    incoming.set(relationship.toPath, incomingSources);
  }
  const visited = new Set(seedFiles.map((file) => file!.path));
  let frontier = [...visited].sort(compareCanonicalText);
  for (let level = 0; level < depth; level += 1) {
    const next = new Set<string>();
    for (const current of frontier) {
      if (direction !== 'incoming') for (const candidate of outgoing.get(current) ?? []) if (!visited.has(candidate)) next.add(candidate);
      if (direction !== 'outgoing') for (const candidate of incoming.get(current) ?? []) if (!visited.has(candidate)) next.add(candidate);
    }
    frontier = [...next].sort(compareCanonicalText);
    for (const candidate of frontier) visited.add(candidate);
    if (!frontier.length) break;
  }
  return loaded.files.filter((file) => visited.has(file.path));
}

async function resolveReviewSelection(options: {
  loaded: LoadedRun;
  workspacePath: string;
  selection: ReviewSelectionKind;
  selectors?: string[];
  depth?: number;
  direction?: 'incoming' | 'outgoing' | 'both';
  baselineRunDirectory?: string;
  expectedSpec?: ReviewSelectionSpec;
}): Promise<{ files: FileRecord[]; selectionSpec?: ReviewSelectionSpec }> {
  const { loaded, selection } = options;
  let files: FileRecord[];
  let selectionSpec: ReviewSelectionSpec | undefined;
  if (selection === 'all') {
    if (options.selectors?.length || options.expectedSpec) throw new AtlasError('REVIEW_SELECTION_INVALID', 'All-files selection does not accept selectors.');
    files = loaded.files;
  } else if (selection === 'findings') {
    const selectors = options.expectedSpec?.selectors ?? options.selectors;
    const normalized = selectors?.length ? normalizedSelectors(selectors, 'Finding') : undefined;
    files = filesForFindings(loaded, normalized);
    if (normalized) selectionSpec = { selectors: normalized };
  } else if (selection === 'paths') {
    const selectors = normalizedSelectors(options.expectedSpec?.selectors ?? options.selectors, 'Path');
    files = filesForPaths(loaded, selectors);
    selectionSpec = { selectors };
  } else if (selection === 'symbols') {
    const selectors = normalizedSelectors(options.expectedSpec?.selectors ?? options.selectors, 'Symbol');
    files = filesForSymbols(loaded, selectors);
    selectionSpec = { selectors };
  } else if (selection === 'neighborhood') {
    const selectors = normalizedSelectors(options.expectedSpec?.selectors ?? options.selectors, 'Neighborhood');
    const depth = options.expectedSpec?.depth ?? options.depth ?? 1;
    const direction = options.expectedSpec?.direction ?? options.direction ?? 'both';
    files = filesForNeighborhood(loaded, selectors, depth, direction);
    selectionSpec = { selectors, depth, direction };
  } else {
    const baselineRunId = options.expectedSpec?.baselineRunId;
    const baselineDirectory = options.baselineRunDirectory ?? (baselineRunId
      ? path.join(options.workspacePath, 'runs', baselineRunId)
      : undefined);
    if (!baselineDirectory) throw new AtlasError('REVIEW_SELECTION_INVALID', 'Diff selection requires a baseline run directory.');
    const plan = await planIncrementalAnalysis({
      workspacePath: options.workspacePath,
      targetId: loaded.run.targetId,
      baselineRunDirectory: baselineDirectory,
      nextRunDirectory: loaded.directory
    });
    if (
      options.expectedSpec && (
        options.expectedSpec.baselineRunId !== plan.baseline.runId ||
        options.expectedSpec.baselineSnapshotId !== plan.baseline.snapshotId ||
        options.expectedSpec.incrementalPlanId !== plan.planId
      )
    ) throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Diff selection no longer matches its exact incremental plan.');
    const selectedPaths = new Set(plan.cache.missRequiredPaths);
    files = loaded.files.filter((file) => selectedPaths.has(file.path));
    selectionSpec = {
      baselineRunId: plan.baseline.runId,
      baselineSnapshotId: plan.baseline.snapshotId,
      incrementalPlanId: plan.planId
    };
  }
  const ordered = [...files].sort((left, right) => compareCanonicalText(left.path, right.path));
  if (options.expectedSpec && canonicalJson(options.expectedSpec) !== canonicalJson(selectionSpec)) {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign selection parameters are not canonical.');
  }
  return { files: ordered, ...(selectionSpec ? { selectionSpec } : {}) };
}

function campaignIdentity(input: {
  runId: string;
  snapshotId: string;
  purpose: string;
  selection: ReviewCampaign['selection'];
  selectionSpec?: ReviewSelectionSpec;
  batchSize: number;
  files: ReviewPacketFile[];
}): string {
  return `campaign_${sha256(canonicalJson({
    domain: 'atlas.review-campaign.v1',
    schemaVersion: SCHEMA_VERSION,
    state: 'queued',
    ...input
  }))}`;
}

function packetIdentity(offset: number, body: Omit<ReviewPacket, 'packetId' | 'packetHash'>): string {
  return `packet_${sha256(canonicalJson({ domain: 'atlas.review-packet.v1', offset, ...body }))}`;
}

function planReviewCampaign(
  loaded: LoadedRun,
  purpose: string,
  selection: ReviewCampaign['selection'],
  selectionSpec: ReviewSelectionSpec | undefined,
  selected: FileRecord[],
  batchSize: number
): { campaign: ReviewCampaign; packets: ReviewPacket[] } {
  const selectedFiles = reviewPacketFiles(selected);
  const campaignId = campaignIdentity({
    runId: loaded.run.runId,
    snapshotId: loaded.snapshot.snapshotId,
    purpose,
    selection,
    ...(selectionSpec ? { selectionSpec } : {}),
    batchSize,
    files: selectedFiles
  });
  const packets: ReviewPacket[] = [];
  for (let offset = 0; offset < selectedFiles.length; offset += batchSize) {
    const files = selectedFiles.slice(offset, offset + batchSize);
    const body: Omit<ReviewPacket, 'packetId' | 'packetHash'> = {
      schemaVersion: SCHEMA_VERSION,
      campaignId,
      runId: loaded.run.runId,
      snapshotId: loaded.snapshot.snapshotId,
      purpose,
      state: 'queued',
      files,
      estimatedInputTokens: Math.ceil(files.reduce((total, file) => total + file.bytes, 0) / 4),
      requiredResultFields: [...REQUIRED_RESULT_FIELDS]
    };
    const packetId = packetIdentity(offset, body);
    const material: Omit<ReviewPacket, 'packetHash'> = { ...body, packetId };
    packets.push({ ...material, packetHash: packetHashMaterial(material) });
  }
  const campaign: ReviewCampaign = {
    schemaVersion: SCHEMA_VERSION,
    campaignId,
    runId: loaded.run.runId,
    snapshotId: loaded.snapshot.snapshotId,
    purpose,
    state: 'queued',
    selection,
    ...(selectionSpec ? { selectionSpec } : {}),
    batchSize,
    packetIds: packets.map((packet) => packet.packetId),
    fileCount: selectedFiles.length,
    estimatedInputTokens: packets.reduce((total, packet) => total + packet.estimatedInputTokens, 0)
  };
  return { campaign, packets };
}

export async function createReviewCampaign(options: {
  runDirectory: string;
  workspacePath: string;
  targetConfigPath: string;
  purpose: string;
  selection: ReviewSelectionKind;
  selectors?: string[];
  depth?: number;
  direction?: 'incoming' | 'outgoing' | 'both';
  baselineRunDirectory?: string;
  batchSize: number;
}): Promise<{ directory: string; campaign: ReviewCampaign; reused: boolean }> {
  const suppliedTargetConfigPath = await realpath(path.resolve(options.targetConfigPath));
  const workspacePath = await resolveForContainment(options.workspacePath);
  const loaded = await loadRunArtifacts(options.runDirectory);
  const expectedRunDirectory = path.join(workspacePath, 'runs', loaded.run.runId);
  let canonicalRunDirectory: string;
  try {
    canonicalRunDirectory = await realpath(expectedRunDirectory);
  } catch {
    throw new AtlasError('REVIEW_RUN_MISMATCH', 'The selected run is not published in the review workspace.');
  }
  if (!samePath(canonicalRunDirectory, expectedRunDirectory) || !samePath(canonicalRunDirectory, loaded.directory)) {
    throw new AtlasError('REVIEW_RUN_MISMATCH', 'Review creation requires the canonical run from the selected workspace.');
  }
  const binding = await reviewAttemptBinding(workspacePath, loaded.run.runId);
  if (!samePath(suppliedTargetConfigPath, binding.targetConfigPath)) {
    throw new AtlasError('TARGET_MISMATCH', 'Supplied target descriptor is not the descriptor bound to the successful scan attempt.');
  }
  const rawTarget = await readJson<unknown>(binding.targetConfigPath);
  await assertSchema('target', rawTarget, 'Target configuration');
  const target = rawTarget as TargetConfig;
  if (loaded.run.targetId !== target.id) throw new AtlasError('TARGET_MISMATCH', 'Target configuration does not match the selected run.');
  await verifyTargetRegistrationBinding({
    workspacePath,
    targetId: target.id,
    targetRoot: binding.targetRoot,
    targetConfigPath: binding.targetConfigPath,
    consent: target.consent
  });
  if (!target.consent?.agentReview) {
    throw new AtlasError('AGENT_REVIEW_NOT_AUTHORIZED', 'Target consent.agentReview must be true before creating agent review packets.');
  }
  const configuredTargetPath = path.isAbsolute(target.path)
    ? target.path
    : path.resolve(path.dirname(binding.targetConfigPath), target.path);
  const descriptorTargetRoot = await realpath(configuredTargetPath);
  const targetRoot = binding.targetRoot;
  if (!samePath(descriptorTargetRoot, targetRoot)) {
    throw new AtlasError('TARGET_MISMATCH', 'Target descriptor root does not match the successful scan attempt for this run.');
  }
  if (isInside(targetRoot, workspacePath)) {
    throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Atlas review workspace must be outside the scanned target repository.');
  }
  if (!Number.isSafeInteger(options.batchSize) || options.batchSize < 1 || options.batchSize > 500) {
    throw new AtlasError('INVALID_BATCH_SIZE', 'Review batch size must be between 1 and 500.');
  }
  const resolvedSelection = await resolveReviewSelection({
    loaded,
    workspacePath,
    selection: options.selection,
    ...(options.selectors ? { selectors: options.selectors } : {}),
    ...(options.depth === undefined ? {} : { depth: options.depth }),
    ...(options.direction ? { direction: options.direction } : {}),
    ...(options.baselineRunDirectory ? { baselineRunDirectory: options.baselineRunDirectory } : {})
  });
  const purpose = normalizedReviewPurpose(options.purpose);
  const { campaign, packets } = planReviewCampaign(
    loaded,
    purpose,
    options.selection,
    resolvedSelection.selectionSpec,
    resolvedSelection.files,
    options.batchSize
  );
  const { campaignId } = campaign;
  const directory = await resolveForContainment(path.join(workspacePath, 'reviews', campaignId));
  if (!isInside(workspacePath, directory)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Review output resolves outside the selected workspace.');
  }
  if (isInside(targetRoot, directory)) {
    throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Atlas review output resolves inside the target repository.');
  }
  await Promise.all([
    assertSchema('review-campaign', campaign, 'Review campaign'),
    ...packets.map((packet, index) => assertSchema('review-packet', packet, `Review packet ${index + 1}`))
  ]);
  assertPortableDataSafe({ campaign, packets }, 'Review campaign');
  if (await exists(directory)) {
    const existing = await readJson<ReviewCampaign>(path.join(directory, 'campaign.json'));
    await assertSchema('review-campaign', existing, 'Existing review campaign');
    if (canonicalJson(existing) !== canonicalJson(campaign)) throw new AtlasError('REVIEW_CAMPAIGN_COLLISION', 'Existing campaign differs from deterministic campaign content.');
    await reviewCampaignStatus(directory);
    return { directory, campaign: existing, reused: true };
  }
  const reviewsRoot = path.dirname(directory);
  await mkdir(reviewsRoot, { recursive: true });
  const temporaryDirectory = path.join(reviewsRoot, `.review-campaign-tmp-${randomUUID().replaceAll('-', '')}`);
  let temporaryExists = false;
  try {
    await mkdir(path.join(temporaryDirectory, 'packets'), { recursive: true });
    temporaryExists = true;
    await writeCanonicalJson(path.join(temporaryDirectory, 'campaign.json'), campaign);
    for (const packet of packets) {
      await writeCanonicalJson(path.join(temporaryDirectory, 'packets', `${packet.packetId}.json`), packet);
    }
    await rename(temporaryDirectory, directory);
    temporaryExists = false;
  } catch (error) {
    if (temporaryExists && await exists(temporaryDirectory)) {
      await removeCampaignTemporary(reviewsRoot, temporaryDirectory);
      temporaryExists = false;
    }
    if (await exists(directory)) {
      const existing = await readJson<ReviewCampaign>(path.join(directory, 'campaign.json'));
      await assertSchema('review-campaign', existing, 'Existing review campaign');
      if (canonicalJson(existing) === canonicalJson(campaign)) {
        await reviewCampaignStatus(directory);
        return { directory, campaign: existing, reused: true };
      }
    }
    throw error;
  } finally {
    if (temporaryExists && await exists(temporaryDirectory)) {
      await removeCampaignTemporary(reviewsRoot, temporaryDirectory);
    }
  }
  await reviewCampaignStatus(directory);
  return { directory, campaign, reused: false };
}

export async function reviewCampaignStatus(campaignDirectoryValue: string): Promise<unknown> {
  const requestedCampaignDirectory = path.resolve(campaignDirectoryValue);
  let campaignDirectoryMetadata;
  let campaignEntries;
  try {
    campaignDirectoryMetadata = await lstat(requestedCampaignDirectory);
    campaignEntries = await readdir(requestedCampaignDirectory, { withFileTypes: true });
  } catch {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign directory is missing or unreadable.');
  }
  if (!campaignDirectoryMetadata.isDirectory() || campaignDirectoryMetadata.isSymbolicLink()) {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign path must be a real directory.');
  }
  const campaignEntryNames = campaignEntries.map((entry) => entry.name).sort(compareCanonicalText);
  if (canonicalJson(campaignEntryNames) !== canonicalJson(['campaign.json', 'packets'])) {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign directory does not match the required Atlas campaign artifact set.');
  }
  const campaignFileEntry = campaignEntries.find((entry) => entry.name === 'campaign.json');
  const packetsDirectoryEntry = campaignEntries.find((entry) => entry.name === 'packets');
  if (!campaignFileEntry?.isFile() || !packetsDirectoryEntry?.isDirectory()) {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign artifacts have invalid filesystem types.');
  }
  const campaignDirectory = await realpath(requestedCampaignDirectory);
  const campaign = await readJson<ReviewCampaign>(path.join(campaignDirectory, 'campaign.json'));
  await assertSchema('review-campaign', campaign, 'Review campaign');
  const workspacePath = path.resolve(campaignDirectory, '..', '..');
  const expectedCampaignDirectory = path.join(workspacePath, 'reviews', campaign.campaignId);
  if (!samePath(campaignDirectory, expectedCampaignDirectory)) {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign directory does not match its content-addressed campaign ID.');
  }
  const packetsDirectory = path.join(campaignDirectory, 'packets');
  let packetDirectoryMetadata;
  let packetEntries;
  try {
    packetDirectoryMetadata = await lstat(packetsDirectory);
    packetEntries = await readdir(packetsDirectory, { withFileTypes: true });
  } catch {
    throw new AtlasError('REVIEW_PACKET_MISMATCH', 'Campaign packets directory is missing or unreadable.');
  }
  if (!packetDirectoryMetadata.isDirectory() || packetDirectoryMetadata.isSymbolicLink()) {
    throw new AtlasError('REVIEW_PACKET_MISMATCH', 'Campaign packets path must be a real directory.');
  }
  if (packetEntries.some((entry) => !entry.isFile())) {
    throw new AtlasError('REVIEW_PACKET_MISMATCH', 'Campaign packets directory contains a non-file entry.');
  }
  const observedPacketNames = packetEntries.map((entry) => entry.name).sort(compareCanonicalText);
  const expectedPacketNames = campaign.packetIds.map((packetId) => `${packetId}.json`).sort(compareCanonicalText);
  if (canonicalJson(observedPacketNames) !== canonicalJson(expectedPacketNames)) {
    throw new AtlasError('REVIEW_PACKET_MISMATCH', 'Campaign packets directory does not match the declared packet set.');
  }
  const expectedRunDirectory = path.join(workspacePath, 'runs', campaign.runId);
  let canonicalRunDirectory: string;
  try {
    canonicalRunDirectory = await realpath(expectedRunDirectory);
  } catch {
    throw new AtlasError('REVIEW_RUN_MISMATCH', 'Campaign canonical run is missing from its workspace.');
  }
  if (!samePath(canonicalRunDirectory, expectedRunDirectory)) {
    throw new AtlasError('REVIEW_RUN_MISMATCH', 'Campaign run path is not the canonical workspace run.');
  }
  const loaded = await loadRunArtifacts(canonicalRunDirectory);
  if (loaded.run.runId !== campaign.runId || loaded.snapshot.snapshotId !== campaign.snapshotId) {
    throw new AtlasError('REVIEW_RUN_MISMATCH', 'Campaign run and snapshot do not match the verified workspace run.');
  }
  const resolvedSelection = await resolveReviewSelection({
    loaded,
    workspacePath,
    selection: campaign.selection,
    ...(campaign.selectionSpec ? { expectedSpec: campaign.selectionSpec } : {})
  });
  const expected = planReviewCampaign(
    loaded,
    campaign.purpose,
    campaign.selection,
    resolvedSelection.selectionSpec,
    resolvedSelection.files,
    campaign.batchSize
  );
  if (canonicalJson(campaign) !== canonicalJson(expected.campaign)) {
    throw new AtlasError('REVIEW_CAMPAIGN_MISMATCH', 'Campaign content does not match the verified run and canonical selection.');
  }
  const packetRecords = await Promise.all(campaign.packetIds.map(async (packetId, index) => {
    const packetPath = path.join(packetsDirectory, `${packetId}.json`);
    const metadata = await lstat(packetPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new AtlasError('REVIEW_PACKET_MISMATCH', `Packet path is not a regular file: ${packetId}`);
    }
    const packet = await readJson<ReviewPacket>(packetPath);
    await assertSchema('review-packet', packet, `Review packet ${packetId}`);
    if (packet.packetId !== packetId) throw new AtlasError('REVIEW_PACKET_MISMATCH', `Packet filename and ID differ: ${packetId}`);
    const { packetHash, ...material } = packet;
    if (packetHashMaterial(material) !== packetHash) throw new AtlasError('REVIEW_PACKET_TAMPERED', `Packet hash mismatch: ${packetId}`);
    if (canonicalJson(packet) !== canonicalJson(expected.packets[index])) {
      throw new AtlasError('REVIEW_PACKET_MISMATCH', `Packet content does not match the verified run and canonical campaign: ${packetId}`);
    }
    return packet;
  }));
  const packets = packetRecords.map((packet) => ({
    packetId: packet.packetId,
    state: packet.state,
    fileCount: packet.files.length,
    estimatedInputTokens: packet.estimatedInputTokens
  }));
  return { campaign, packets };
}
