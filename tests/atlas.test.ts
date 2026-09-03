import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  CLEANUP_ANALYSIS_VERSION,
  CLEANUP_COMPONENT_VERSIONS,
  createReviewCampaign,
  inspectRun,
  queryRun,
  reviewCampaignStatus,
  scanProject,
  verifyRunDirectory
} from '../src/index.js';
import { runIdentity } from '../src/identity.js';
import { LEGACY_RUN_ARTIFACTS, PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX } from '../src/artifact-contract.js';
import { renderTriageReport } from '../src/triage-report.js';
import { attachFindingReviewMetadata } from '../src/finding-priority.js';
import type { ArtifactManifest, DiagnosticRecord, FileRecord, FindingRecord, RelationshipRecord, ReviewPacket, RunRecord, SnapshotRecord } from '../src/types.js';
import { canonicalJson, canonicalJsonLines, compareCanonicalText, prettyCanonicalJson, readJson, readJsonLines, sha256, writeCanonicalJson } from '../src/util/canonical.js';
import { matchesGlob, normalizeFilesystemRelative, normalizeTargetRelative } from '../src/util/paths.js';

async function createFixture(agentReview = true): Promise<{
  root: string;
  target: string;
  targetConfig: string;
  profile: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-test-'));
  const target = path.join(root, 'target');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), [
    "import { useful } from './useful.js';",
    "import { missing } from './missing.js';",
    'console.log(useful, missing, process.env.DECLARED_KEY, process.env.MISSING_KEY);',
    ''
  ].join('\n'));
  await writeFile(path.join(target, 'src', 'useful.ts'), 'export const useful = 42;\n');
  await writeFile(path.join(target, 'src', 'orphan.ts'), 'export const orphan = true;\n');
  await writeFile(path.join(target, '.env.example'), 'DECLARED_KEY=\n');
  await writeFile(path.join(target, 'package.json'), '{"scripts":{"postinstall":"node should-never-run.js"}}\n');
  const targetConfig = path.join(root, 'target.json');
  const profile = path.join(root, 'profile.json');
  await writeFile(targetConfig, `${JSON.stringify({
    schemaVersion: 1,
    id: 'test-target',
    path: './target',
    consent: { agentReview, export: false, projectMemory: false }
  }, null, 2)}\n`);
  await writeFile(profile, `${JSON.stringify({
    schemaVersion: 1,
    id: 'test-profile',
    includeRoots: ['src', '.env.example', 'package.json'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    envExampleFiles: ['.env.example'],
    maxFileBytes: 100000
  }, null, 2)}\n`);
  return { root, target, targetConfig, profile };
}

async function targetObservation(target: string): Promise<Array<{ path: string; content: string; mtimeMs: number }>> {
  const paths = ['src/index.ts', 'src/useful.ts', 'src/orphan.ts', '.env.example', 'package.json'];
  return Promise.all(paths.map(async (relativePath) => ({
    path: relativePath,
    content: await readFile(path.join(target, ...relativePath.split('/')), 'utf8'),
    mtimeMs: (await stat(path.join(target, ...relativePath.split('/')))).mtimeMs
  })));
}

test('scan is deterministic, read-only, verifiable, and evidence-backed', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const before = await targetObservation(fixture.target);
  const first = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace-a')
  });
  assert.equal(first.reused, false);
  const verification = await verifyRunDirectory(first.runDirectory);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.files, 5);
  const after = await targetObservation(fixture.target);
  assert.deepEqual(after, before);
  await assert.rejects(stat(path.join(fixture.target, '.atlas')), /ENOENT/);
  await assert.rejects(stat(path.join(fixture.target, 'should-never-run.js')), /ENOENT/);

  const second = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace-b')
  });
  assert.equal(second.run.runId, first.run.runId);
  assert.equal(second.run.snapshotId, first.run.snapshotId);
  assert.equal(
    await readFile(path.join(second.runDirectory, 'artifact-digests.json'), 'utf8'),
    await readFile(path.join(first.runDirectory, 'artifact-digests.json'), 'utf8')
  );
  assert(first.run.analyses.includes(`cleanup-candidates-v${CLEANUP_ANALYSIS_VERSION}`));
  assert(first.run.analyses.includes(`cleanup-static-reachability-v${CLEANUP_COMPONENT_VERSIONS.staticReachability}`));
  const preBoundedCleanupAnalyses = first.run.analyses.map((analysis) =>
    analysis === `cleanup-candidates-v${CLEANUP_ANALYSIS_VERSION}`
      ? 'cleanup-candidates-v1.3.0'
      : analysis === `cleanup-static-reachability-v${CLEANUP_COMPONENT_VERSIONS.staticReachability}`
        ? 'cleanup-static-reachability-v1.3.0'
        : analysis
  ).sort(compareCanonicalText);
  assert.notEqual(runIdentity({
    snapshotId: first.run.snapshotId,
    targetId: first.run.targetId,
    profileId: first.run.profileId,
    profileDigest: first.run.profileDigest,
    tool: first.run.tool,
    adapters: first.run.adapters,
    discovery: first.run.discovery,
    analyses: preBoundedCleanupAnalyses
  }), first.run.runId);

  const findings = await readJsonLines<FindingRecord>(path.join(first.runDirectory, 'findings.jsonl'));
  assert(findings.some((finding) => finding.category === 'dead-code-candidate' && finding.path === 'src/orphan.ts'));
  assert(findings.some((finding) => finding.ruleId === 'contract/unresolved-internal-import-v1'));
  assert(findings.some((finding) => finding.ruleId === 'contract/deployment-env-missing-declaration-v1' && finding.title.includes('MISSING_KEY')));
  const relationships = await readJsonLines<RelationshipRecord>(path.join(first.runDirectory, 'relationships.jsonl'));
  const emittedJsImport = relationships.find((relationship) => relationship.specifier === './useful.js');
  assert.equal(emittedJsImport?.resolution, 'resolved');
  assert.equal(emittedJsImport?.toPath, 'src/useful.ts');

  const inspection = await inspectRun(first.runDirectory, 'src/orphan.ts') as { findings: FindingRecord[] };
  assert(inspection.findings.some((finding) => finding.category === 'dead-code-candidate'));
  const query = await queryRun(first.runDirectory, 'orphan', 10);
  assert(query.hits.some((hit) => hit.path === 'src/orphan.ts'));
  const noMatch = await queryRun(first.runDirectory, 'definitely-no-such-atlas-term', 10);
  assert.equal(noMatch.hits.length, 0);

  const review = await createReviewCampaign({
    runDirectory: first.runDirectory,
    workspacePath: path.join(fixture.root, 'workspace-a'),
    targetConfigPath: fixture.targetConfig,
    purpose: 'Exhaustive fixture review',
    selection: 'all',
    batchSize: 2
  });
  assert.equal(review.campaign.fileCount, 5);
  assert.equal(review.campaign.packetIds.length, 3);
  const status = await reviewCampaignStatus(review.directory) as { packets: unknown[] };
  assert.equal(status.packets.length, 3);
  const campaignPath = path.join(review.directory, 'campaign.json');
  const tamperedCampaign = await readJson<Record<string, unknown>>(campaignPath);
  tamperedCampaign.fileCount = 6;
  await writeCanonicalJson(campaignPath, tamperedCampaign);
  await assert.rejects(reviewCampaignStatus(review.directory), /campaign content|campaign totals|packet size/i);
});

test('verification remains compatible with legacy v1 file records that predate lifecycle declarations', async (context) => {
  const fixture = await createFixture(false);
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const [run, snapshot, files] = await Promise.all([
    readJson<RunRecord>(path.join(scan.runDirectory, 'run.json')),
    readJson<SnapshotRecord>(path.join(scan.runDirectory, 'snapshot.json')),
    readJsonLines<FileRecord>(path.join(scan.runDirectory, 'files.jsonl'))
  ]);
  const legacyFiles = files.map((file) => {
    const legacy = structuredClone(file);
    delete legacy.lifecycle;
    legacy.evidence.producerVersion = '1.1.0';
    return legacy;
  });
  const legacySnapshotId = snapshot.snapshotId;
  const legacySnapshot: SnapshotRecord = structuredClone(snapshot);
  const analyses = run.analyses
    .filter((analysis) =>
      !analysis.startsWith('analysis-health-v1') && !analysis.startsWith('operational-risks-v') &&
      !analysis.startsWith('triage-report-v') &&
      !analysis.startsWith(PROFILE_OBSERVATIONS_ANALYSIS_MARKER_PREFIX)
    )
    .map((analysis) => /^core-census-v1\.(?:2|3)\.0$/.test(analysis) ? 'core-census-v1.1.0' : analysis)
    .sort(compareCanonicalText);
  const identityInput = {
    snapshotId: legacySnapshotId,
    targetId: run.targetId,
    profileId: run.profileId,
    profileDigest: run.profileDigest,
    tool: run.tool,
    adapters: run.adapters,
    discovery: run.discovery,
    analyses
  };
  const legacyRunId = runIdentity(identityInput);
  const legacyRun: RunRecord = {
    ...run,
    ...identityInput,
    runId: legacyRunId,
    artifacts: [...LEGACY_RUN_ARTIFACTS]
  };
  delete legacyRun.counts.findingInstances;
  const artifactContent = new Map<string, string>([
    ['snapshot.json', prettyCanonicalJson(legacySnapshot)],
    ['run.json', prettyCanonicalJson(legacyRun)],
    ['discovery.json', await readFile(path.join(scan.runDirectory, 'discovery.json'), 'utf8')],
    ['files.jsonl', canonicalJsonLines(legacyFiles)],
    ['relationships.jsonl', await readFile(path.join(scan.runDirectory, 'relationships.jsonl'), 'utf8')],
    ['diagnostics.jsonl', await readFile(path.join(scan.runDirectory, 'diagnostics.jsonl'), 'utf8')],
    ['findings.jsonl', await readFile(path.join(scan.runDirectory, 'findings.jsonl'), 'utf8')]
  ]);
  const legacyDirectory = path.join(fixture.root, 'legacy-v1-run');
  await mkdir(legacyDirectory);
  await Promise.all([...artifactContent].map(([name, content]) => writeFile(path.join(legacyDirectory, name), content)));
  const manifest: ArtifactManifest = {
    schemaVersion: 1,
    runId: legacyRunId,
    artifacts: [...artifactContent].map(([artifactPath, content]) => ({
      path: artifactPath as ArtifactManifest['artifacts'][number]['path'],
      bytes: Buffer.byteLength(content),
      sha256: sha256(content)
    })).sort((left, right) => compareCanonicalText(left.path, right.path))
  };
  await writeCanonicalJson(path.join(legacyDirectory, 'artifact-digests.json'), manifest);

  const verification = await verifyRunDirectory(legacyDirectory);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.files, legacyFiles.length);
});

test('verification rejects a resealed current run with a whitespace-only lifecycle rule ID', async (context) => {
  const fixture = await createFixture(false);
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const profile = await readJson<Record<string, unknown>>(fixture.profile);
  profile.lifecycleRules = [
    { id: 'entrypoint-lifecycle', state: 'active', paths: ['src/index.ts'] }
  ];
  await writeCanonicalJson(fixture.profile, profile);
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const filesPath = path.join(scan.runDirectory, 'files.jsonl');
  const files = await readJsonLines<FileRecord>(filesPath);
  const activeFile = files.find((file) => file.lifecycle?.basis === 'profile-path-rule');
  assert(activeFile?.lifecycle);
  activeFile.lifecycle.ruleId = '   ';
  const filesContent = canonicalJsonLines(files);
  await writeFile(filesPath, filesContent);

  const manifestPath = path.join(scan.runDirectory, 'artifact-digests.json');
  const manifest = await readJson<ArtifactManifest>(manifestPath);
  const filesDigest = manifest.artifacts.find((artifact) => artifact.path === 'files.jsonl');
  assert(filesDigest);
  filesDigest.bytes = Buffer.byteLength(filesContent);
  filesDigest.sha256 = sha256(filesContent);
  await writeCanonicalJson(manifestPath, manifest);

  await assert.rejects(
    verifyRunDirectory(scan.runDirectory),
    /schema validation.*ruleId|lifecycle declaration is inconsistent/iu
  );
});

test('review status verifies its canonical run, immutable packet tuples, and exact packet set', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const workspace = path.join(fixture.root, 'workspace');
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: workspace
  });
  const createReview = (purpose: string, selection: 'all' | 'findings' = 'all') => createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: workspace,
    targetConfigPath: fixture.targetConfig,
    purpose,
    selection,
    batchSize: 2
  });

  const deterministic = await createReview('Deterministic review');
  const reused = await createReview('Deterministic review');
  assert.equal(reused.reused, true);
  assert.equal(reused.campaign.campaignId, deterministic.campaign.campaignId);
  await reviewCampaignStatus(deterministic.directory);

  const snapshotReview = await createReview('Snapshot cross-link review');
  const snapshotCampaignPath = path.join(snapshotReview.directory, 'campaign.json');
  const snapshotCampaign = await readJson<Record<string, unknown>>(snapshotCampaignPath);
  snapshotCampaign.snapshotId = `snapshot_sha256_${'0'.repeat(64)}`;
  await writeCanonicalJson(snapshotCampaignPath, snapshotCampaign);
  await assert.rejects(reviewCampaignStatus(snapshotReview.directory), /run and snapshot do not match/i);

  const tupleReview = await createReview('Full tuple review', 'findings');
  const tuplePacketPath = path.join(tupleReview.directory, 'packets', `${tupleReview.campaign.packetIds[0]}.json`);
  const tuplePacket = await readJson<ReviewPacket>(tuplePacketPath);
  assert(tuplePacket.files[0]);
  tuplePacket.files[0].bytes += 4;
  tuplePacket.estimatedInputTokens = Math.ceil(tuplePacket.files.reduce((total, file) => total + file.bytes, 0) / 4);
  const { packetHash: _packetHash, ...tupleMaterial } = tuplePacket;
  tuplePacket.packetHash = sha256(canonicalJson(tupleMaterial));
  await writeCanonicalJson(tuplePacketPath, tuplePacket);
  await assert.rejects(reviewCampaignStatus(tupleReview.directory), /packet content does not match/i);

  const rootExtraReview = await createReview('Extra campaign artifact review');
  await writeFile(path.join(rootExtraReview.directory, 'extra.json'), '{}\n');
  await assert.rejects(reviewCampaignStatus(rootExtraReview.directory), /campaign artifact set/i);

  const extraReview = await createReview('Extra packet review');
  await writeFile(path.join(extraReview.directory, 'packets', 'extra.json'), '{}\n');
  await assert.rejects(reviewCampaignStatus(extraReview.directory), /declared packet set/i);

  const directoryReview = await createReview('Packet subdirectory review');
  await mkdir(path.join(directoryReview.directory, 'packets', 'unexpected-directory'));
  await assert.rejects(reviewCampaignStatus(directoryReview.directory), /non-file entry/i);

  const symlinkReview = await createReview('Packet symlink review');
  const externalDirectory = path.join(fixture.root, 'packet-link-target');
  await mkdir(externalDirectory);
  try {
    await symlink(
      externalDirectory,
      path.join(symlinkReview.directory, 'packets', 'unexpected-link'),
      process.platform === 'win32' ? 'junction' : 'dir'
    );
    await assert.rejects(reviewCampaignStatus(symlinkReview.directory), /non-file entry/i);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'EPERM' && code !== 'EACCES' && code !== 'ENOTSUP') throw error;
  }

  const conflictingAttempt = await readJson<Record<string, unknown>>(scan.attemptPath);
  const conflictingAttemptId = `att_20260821T000000Z_${'f'.repeat(32)}`;
  conflictingAttempt.attemptId = conflictingAttemptId;
  conflictingAttempt.status = 'reused';
  conflictingAttempt.targetPath = externalDirectory;
  const conflictingAttemptPath = path.join(workspace, 'attempts', `${conflictingAttemptId}.json`);
  await writeCanonicalJson(conflictingAttemptPath, conflictingAttempt);
  await assert.rejects(createReview('Conflicting attempt review'), /attempt receipts conflict/i);
  await rm(conflictingAttemptPath);

  const runReview = await createReview('Verified run review');
  await writeFile(path.join(scan.runDirectory, 'diagnostics.jsonl'), '{"tampered":true}\n');
  await assert.rejects(reviewCampaignStatus(runReview.directory), /digest mismatch/i);
});

test('verification detects artifact tampering', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const tampered = path.join(fixture.root, 'tampered-run');
  await cp(scan.runDirectory, tampered, { recursive: true });
  await writeFile(path.join(tampered, 'diagnostics.jsonl'), '{"tampered":true}\n', 'utf8');
  await assert.rejects(verifyRunDirectory(tampered), /digest mismatch/i);
});

test('verification rejects omitted digests and unmanifested run files', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const omitted = path.join(fixture.root, 'omitted-digest-run');
  await cp(scan.runDirectory, omitted, { recursive: true });
  const manifestPath = path.join(omitted, 'artifact-digests.json');
  const manifest = await readJson<ArtifactManifest>(manifestPath);
  manifest.artifacts = manifest.artifacts.filter((artifact) => artifact.path !== 'findings.jsonl');
  await writeCanonicalJson(manifestPath, manifest);
  await writeFile(path.join(omitted, 'findings.jsonl'), '{"forged":true}\n', 'utf8');
  await assert.rejects(verifyRunDirectory(omitted), /artifact set/i);

  const extra = path.join(fixture.root, 'extra-file-run');
  await cp(scan.runDirectory, extra, { recursive: true });
  await writeFile(path.join(extra, 'unmanifested.txt'), 'not allowed\n', 'utf8');
  await assert.rejects(verifyRunDirectory(extra), /artifact set/i);
});

test('same-run reuse fails if generated artifact digests conflict', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const workspace = path.join(fixture.root, 'workspace');
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: workspace
  });
  const findingsPath = path.join(scan.runDirectory, 'findings.jsonl');
  const findings = await readJsonLines<FindingRecord>(findingsPath);
  findings[0]!.title = `${findings[0]!.title} (alternate producer output)`;
  const files = await readJsonLines<FileRecord>(path.join(scan.runDirectory, 'files.jsonl'));
  const updatedFindings = attachFindingReviewMetadata(findings, files);
  const changedContent = canonicalJsonLines(updatedFindings);
  await writeFile(findingsPath, changedContent, 'utf8');
  const triagePath = path.join(scan.runDirectory, 'triage.md');
  const [run, diagnostics] = await Promise.all([
    readJson<RunRecord>(path.join(scan.runDirectory, 'run.json')),
    readJsonLines<DiagnosticRecord>(path.join(scan.runDirectory, 'diagnostics.jsonl'))
  ]);
  const triageContent = renderTriageReport(run, updatedFindings, diagnostics);
  await writeFile(triagePath, triageContent, 'utf8');
  const manifestPath = path.join(scan.runDirectory, 'artifact-digests.json');
  const manifest = await readJson<ArtifactManifest>(manifestPath);
  const findingDigest = manifest.artifacts.find((artifact) => artifact.path === 'findings.jsonl')!;
  findingDigest.bytes = Buffer.byteLength(changedContent);
  findingDigest.sha256 = sha256(changedContent);
  const triageDigest = manifest.artifacts.find((artifact) => artifact.path === 'triage.md')!;
  triageDigest.bytes = Buffer.byteLength(triageContent);
  triageDigest.sha256 = sha256(triageContent);
  await writeCanonicalJson(manifestPath, manifest);
  await verifyRunDirectory(scan.runDirectory);
  await assert.rejects(scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: workspace
  }), /newly generated artifact digests differ/i);
});

test('review campaigns require explicit target consent', async (context) => {
  const fixture = await createFixture(false);
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  await assert.rejects(createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: path.join(fixture.root, 'workspace'),
    targetConfigPath: fixture.targetConfig,
    purpose: 'Unauthorized review',
    selection: 'all',
    batchSize: 10
  }), /consent\.agentReview/);
});

test('a forged same-ID target descriptor cannot authorize review writes', async (context) => {
  const fixture = await createFixture(false);
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const originalWorkspace = path.join(fixture.root, 'workspace');
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: originalWorkspace
  });
  const embeddedWorkspace = path.join(fixture.target, 'forged-workspace');
  await cp(originalWorkspace, embeddedWorkspace, { recursive: true });
  const forgedTarget = path.join(fixture.root, 'forged-target');
  await mkdir(forgedTarget);
  const forgedTargetConfig = path.join(fixture.root, 'forged-target.json');
  await writeCanonicalJson(forgedTargetConfig, {
    schemaVersion: 1,
    id: 'test-target',
    path: './forged-target',
    consent: { agentReview: true, export: false, projectMemory: false }
  });
  await assert.rejects(createReviewCampaign({
    runDirectory: path.join(embeddedWorkspace, 'runs', scan.run.runId),
    workspacePath: embeddedWorkspace,
    targetConfigPath: forgedTargetConfig,
    purpose: 'Forged authorization',
    selection: 'all',
    batchSize: 2
  }), /not the descriptor bound/i);
  await assert.rejects(stat(path.join(embeddedWorkspace, 'reviews')), /ENOENT/);
});

test('target consent is explicit and review writes inside targets are rejected', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  await assert.rejects(createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: path.join(fixture.target, 'atlas-review'),
    targetConfigPath: fixture.targetConfig,
    purpose: 'Unsafe review location',
    selection: 'all',
    batchSize: 10
  }), /outside the target|inside the target|not published in the review workspace/i);
  await assert.rejects(stat(path.join(fixture.target, 'atlas-review')), /ENOENT/);

  const target = await readJson<Record<string, unknown>>(fixture.targetConfig);
  target.consent = { agentReview: 'false', export: false, projectMemory: false };
  await writeCanonicalJson(fixture.targetConfig, target);
  await assert.rejects(createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: path.join(fixture.root, 'workspace'),
    targetConfigPath: fixture.targetConfig,
    purpose: 'Invalid consent type',
    selection: 'all',
    batchSize: 10
  }), /schema validation/i);

  target.consent = { agentReview: false, export: false };
  await writeCanonicalJson(fixture.targetConfig, target);
  await assert.rejects(createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: path.join(fixture.root, 'workspace'),
    targetConfigPath: fixture.targetConfig,
    purpose: 'Missing project-memory consent',
    selection: 'all',
    batchSize: 10
  }), /schema validation/i);

  target.consent = { agentReview: false, export: false, projectMemory: false, runtimeEvidence: false };
  await writeCanonicalJson(fixture.targetConfig, target);
  await assert.rejects(createReviewCampaign({
    runDirectory: scan.runDirectory,
    workspacePath: path.join(fixture.root, 'workspace'),
    targetConfigPath: fixture.targetConfig,
    purpose: 'Unsupported runtime consent',
    selection: 'all',
    batchSize: 10
  }), /schema validation/i);
});

test('a pathological TypeScript AST is isolated without aborting the scan', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await writeFile(
    path.join(fixture.target, 'src', 'deep.ts'),
    `import './missing-deep.js';\nconst value = root${'.child'.repeat(2_000)};\n`,
    'utf8'
  );

  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const verification = await verifyRunDirectory(scan.runDirectory);
  assert.equal(verification.status, 'passed');
  const diagnostics = await readJsonLines<DiagnosticRecord>(path.join(scan.runDirectory, 'diagnostics.jsonl'));
  assert(diagnostics.some((entry) =>
    entry.code === 'TYPESCRIPT_AST_RESOURCE_LIMIT' && entry.path === 'src/deep.ts'
  ));
  const relationships = await readJsonLines<RelationshipRecord>(path.join(scan.runDirectory, 'relationships.jsonl'));
  assert(!relationships.some((entry) => entry.fromPath === 'src/deep.ts'));
  assert(relationships.some((entry) => entry.fromPath === 'src/index.ts'));
});

test('portable path normalization and globstar exclusions are canonical', async (context) => {
  assert.throws(() => normalizeTargetRelative('src/file.ts:stream'), /portable target-relative path/i);
  assert.throws(() => normalizeTargetRelative('src/COM¹.txt'), /canonical portable form/i);
  assert.throws(() => normalizeTargetRelative('src/./file.ts'), /dot segment/i);
  assert.throws(() => normalizeTargetRelative('src/../file.ts'), /dot segment/i);
  assert.equal(normalizeTargetRelative('src//x.ts'), 'src/x.ts');
  assert.equal(normalizeTargetRelative('src\\x.ts'), 'src/x.ts');
  assert.throws(() => normalizeFilesystemRelative('src/cafe\u0301.ts'), /canonical portable form/i);
  if (process.platform !== 'win32') {
    assert.throws(() => normalizeFilesystemRelative('src\\aliased.ts'), /non-portable backslash/i);
  }
  assert.equal(matchesGlob('src/secrets.ts', 'src/**/secrets.ts'), true);
  assert.equal(matchesGlob('src/nested/secrets.ts', 'src/**/secrets.ts'), true);

  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const profile = await readJson<Record<string, unknown>>(fixture.profile);
  profile.exclude = ['src/**/orphan.ts'];
  await writeCanonicalJson(fixture.profile, profile);
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const files = await readJsonLines<{ path: string }>(path.join(scan.runDirectory, 'files.jsonl'));
  assert(!files.some((file) => file.path === 'src/orphan.ts'));
  const windowsInspection = await inspectRun(scan.runDirectory, 'src\\useful.ts') as { file: { path: string } };
  assert.equal(windowsInspection.file.path, 'src/useful.ts');
});

test('profiles cannot disable the hard per-file resource ceiling', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const profile = await readJson<Record<string, unknown>>(fixture.profile);
  profile.maxFileBytes = 8 * 1024 * 1024 + 1;
  await writeCanonicalJson(fixture.profile, profile);
  const workspace = path.join(fixture.root, 'workspace');
  await assert.rejects(scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: workspace
  }), /schema validation|maxFileBytes.*no greater|must be <= 8388608/i);
  await assert.rejects(stat(workspace), /ENOENT/);
});

test('a dot include root scans the complete target boundary', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const profile = await readJson<Record<string, unknown>>(fixture.profile);
  profile.includeRoots = ['.'];
  await writeCanonicalJson(fixture.profile, profile);
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const verification = await verifyRunDirectory(scan.runDirectory);
  assert.equal(verification.files, 5);
});

test('skipped boundary paths participate in snapshot identity', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const firstLargePath = path.join(fixture.target, 'src', 'large-a.ts');
  const secondLargePath = path.join(fixture.target, 'src', 'large-b.ts');
  await writeFile(firstLargePath, Buffer.alloc(100_001, 65));
  const first = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace-a')
  });
  await rename(firstLargePath, secondLargePath);
  const second = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace-b')
  });
  assert.notEqual(first.run.snapshotId, second.run.snapshotId);
  assert.notEqual(first.run.runId, second.run.runId);
});

test('alias target fallback order is preserved', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await mkdir(path.join(fixture.target, 'src', 'a'), { recursive: true });
  await mkdir(path.join(fixture.target, 'src', 'z'), { recursive: true });
  await mkdir(path.join(fixture.target, 'src', 'general', 'special'), { recursive: true });
  await mkdir(path.join(fixture.target, 'src', 'specific'), { recursive: true });
  await writeFile(path.join(fixture.target, 'src', 'a', 'value.ts'), 'export const selected = "a";\n');
  await writeFile(path.join(fixture.target, 'src', 'z', 'value.ts'), 'export const selected = "z";\n');
  await writeFile(path.join(fixture.target, 'src', 'alias-user.ts'), 'import { selected } from "@/value";\nvoid selected;\n');
  await writeFile(path.join(fixture.target, 'src', 'general', 'special', 'value.ts'), 'export const general = true;\n');
  await writeFile(path.join(fixture.target, 'src', 'specific', 'value.ts'), 'export const specific = true;\n');
  await writeFile(path.join(fixture.target, 'src', 'specific-user.ts'), 'import { specific } from "@/special/value";\nvoid specific;\n');
  const profile = await readJson<Record<string, unknown>>(fixture.profile);
  profile.aliases = {
    '@/*': ['src/z/*', 'src/a/*', 'src/general/*'],
    '@/special/*': ['src/specific/*']
  };
  await writeCanonicalJson(fixture.profile, profile);
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const relationships = await readJsonLines<RelationshipRecord>(path.join(scan.runDirectory, 'relationships.jsonl'));
  const aliasRelationship = relationships.find((relationship) => relationship.fromPath === 'src/alias-user.ts');
  assert.equal(aliasRelationship?.toPath, 'src/z/value.ts');
  const specificRelationship = relationships.find((relationship) => relationship.fromPath === 'src/specific-user.ts');
  assert.equal(specificRelationship?.toPath, 'src/specific/value.ts');
});

test('equivalent path spellings produce one canonical profile and honor dead-code exemptions', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const baseProfile = await readJson<Record<string, unknown>>(fixture.profile);
  const canonicalProfilePath = path.join(fixture.root, 'profile-canonical.json');
  const redundantProfilePath = path.join(fixture.root, 'profile-redundant.json');
  await writeCanonicalJson(canonicalProfilePath, {
    ...baseProfile,
    entrypoints: ['src/index.ts'],
    deadCodeExemptions: ['src/orphan.ts']
  });
  await writeCanonicalJson(redundantProfilePath, {
    ...baseProfile,
    entrypoints: ['src//index.ts'],
    deadCodeExemptions: ['src//orphan.ts']
  });
  const canonical = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: canonicalProfilePath,
    workspacePath: path.join(fixture.root, 'workspace-canonical')
  });
  const redundant = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: redundantProfilePath,
    workspacePath: path.join(fixture.root, 'workspace-redundant')
  });
  assert.equal(redundant.run.profileDigest, canonical.run.profileDigest);
  assert.equal(redundant.run.runId, canonical.run.runId);
  const redundantFindings = await readJsonLines<FindingRecord>(path.join(redundant.runDirectory, 'findings.jsonl'));
  assert(!redundantFindings.some((finding) => finding.path === 'src/orphan.ts'));
});

test('workspace writes inside the target are rejected', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await assert.rejects(scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.target, '.atlas-workspace')
  }), /outside the target repository/);
  await assert.rejects(stat(path.join(fixture.target, '.atlas-workspace')), /ENOENT/);
});

test('external directory links are skipped without ingesting external bytes', async (context) => {
  const fixture = await createFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const external = path.join(fixture.root, 'external');
  await mkdir(external);
  await writeFile(path.join(external, 'secret.ts'), 'export const shouldNotAppear = true;\n');
  try {
    await symlink(external, path.join(fixture.target, 'src', 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    context.skip(`Filesystem did not permit link creation: ${String(error)}`);
    return;
  }
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfig,
    profilePath: fixture.profile,
    workspacePath: path.join(fixture.root, 'workspace')
  });
  const fileArtifact = await readFile(path.join(scan.runDirectory, 'files.jsonl'), 'utf8');
  const diagnosticArtifact = await readFile(path.join(scan.runDirectory, 'diagnostics.jsonl'), 'utf8');
  assert(!fileArtifact.includes('secret.ts'));
  assert(diagnosticArtifact.includes('SYMLINK_SKIPPED'));
});
