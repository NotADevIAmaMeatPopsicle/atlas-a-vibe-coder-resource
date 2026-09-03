import { randomUUID } from 'node:crypto';
import { access, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  ANALYSIS_HEALTH_ARTIFACT_NAME,
  ARTIFACT_MANIFEST_NAME,
  TRIAGE_REPORT_ANALYSIS_MARKER,
  TRIAGE_REPORT_ARTIFACT_NAME,
  TRIAGE_RUN_ARTIFACTS,
  analysisHealthMarker,
  profileObservationsAnalysisMarker
} from './artifact-contract.js';
import { adapterDescriptor } from './adapters/js-ts.js';
import {
  CLEANUP_ANALYSIS_VERSION,
  CLEANUP_COMPONENT_VERSIONS
} from './analysis/cleanup.js';
import { API_CONTRACT_ANALYSIS_VERSION } from './analysis/api-contracts.js';
import { DATA_CONTRACT_ANALYSIS_VERSION } from './analysis/data-contracts.js';
import { DEPLOYMENT_CONTRACT_ANALYSIS_VERSION } from './analysis/deployment-contracts.js';
import {
  FINDING_POSTPROCESS_VERSION,
  postprocessFindings,
  findingInstanceCount
} from './analysis/finding-postprocess.js';
import { REACHABILITY_ANALYSIS_VERSION } from './analysis/reachability.js';
import { runIsolatedAnalysis } from './analysis/isolated.js';
import { loadConfiguration } from './config.js';
import { AtlasError, errorDetails } from './errors.js';
import { discoverGitRepository, GIT_DISCOVERY_VERSION } from './discovery/index.js';
import {
  applyFindingDispositions,
  findingDispositionAnalysisMarker,
  loadFindingDispositionLedger
} from './finding-dispositions.js';
import { profileDigest, runIdentity } from './identity.js';
import { assertSchema } from './schema-validator.js';
import { assertPortableDataSafe, PORTABLE_DATA_PREFLIGHT_VERSION } from './security/portable-data.js';
import { buildSnapshot, CORE_CENSUS_VERSION, verifyTargetUnchanged } from './snapshot.js';
import { registerTarget } from './targets.js';
import {
  ANALYSIS_HEALTH_VERSION,
  applyOperationalControls,
  buildAnalysisHealthRecord,
  enforceRuleExpectations,
  evaluateOperationalControls,
  OPERATIONAL_ANALYSIS_MARKER
} from './regression/incidents.js';
import type {
  ArtifactManifest,
  DiagnosticRecord,
  ExecutionRecord,
  FindingRecord,
  RunRecord,
  ScanResult
} from './types.js';
import { SCHEMA_VERSION, TOOL_VERSION } from './types.js';
import { canonicalJson, canonicalJsonLines, compareCanonicalText, prettyCanonicalJson, sha256, writeCanonicalJson } from './util/canonical.js';
import { isInside, resolveForContainment } from './util/paths.js';
import { verifyAndLoadRunDirectory } from './verify.js';
import { renderTriageReport } from './triage-report.js';

async function exists(pathValue: string): Promise<boolean> {
  try {
    await access(pathValue);
    return true;
  } catch {
    return false;
  }
}

async function safeRemoveTemporary(temporaryRoot: string, candidate: string): Promise<void> {
  if (!isInside(temporaryRoot, candidate) || path.resolve(temporaryRoot) === path.resolve(candidate)) {
    throw new AtlasError('UNSAFE_TEMP_PATH', `Refusing to remove unsafe temporary path: ${candidate}`);
  }
  await rm(candidate, { recursive: true, force: true });
}

async function safeWorkspaceChild(workspacePath: string, targetRoot: string, candidate: string): Promise<string> {
  const resolved = await resolveForContainment(candidate);
  if (!isInside(workspacePath, resolved)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', `Workspace output resolves outside the selected workspace: ${candidate}`);
  }
  if (isInside(targetRoot, resolved)) {
    throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Atlas workspace output resolves inside the target repository.');
  }
  return resolved;
}

function deduplicateDiagnostics(values: DiagnosticRecord[]): DiagnosticRecord[] {
  return [...new Map(values.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
}

function deduplicateFindings(values: FindingRecord[]): FindingRecord[] {
  return [...new Map(values.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
}

export async function scanProject(options: {
  targetConfigPath: string;
  profilePath: string;
  workspacePath: string;
  dispositionLedgerPath?: string;
}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const attemptTimestamp = startedAt.replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const attemptId = `att_${attemptTimestamp}_${randomUUID().replaceAll('-', '')}`;
  const workspacePath = await resolveForContainment(options.workspacePath);
  let attemptsDirectory = path.join(workspacePath, 'attempts');
  let temporaryRoot = path.join(workspacePath, '.tmp');
  let temporaryDirectory = path.join(temporaryRoot, attemptId);
  let targetPath = '<unresolved>';
  let observedRunId: string | undefined;
  let workspaceAuthorized = false;
  try {
    const configuration = await loadConfiguration(options.targetConfigPath, options.profilePath);
    const resolvedProfileDigest = profileDigest(configuration.profile);
    const dispositionLedger = options.dispositionLedgerPath
      ? await loadFindingDispositionLedger(options.dispositionLedgerPath, {
          targetId: configuration.target.id,
          profileId: configuration.profile.id,
          profileDigest: resolvedProfileDigest
        })
      : undefined;
    targetPath = configuration.targetRoot;
    if (isInside(configuration.targetRoot, workspacePath)) {
      throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Atlas workspace must be outside the target repository.');
    }
    attemptsDirectory = await safeWorkspaceChild(workspacePath, configuration.targetRoot, attemptsDirectory);
    temporaryRoot = await safeWorkspaceChild(workspacePath, configuration.targetRoot, temporaryRoot);
    temporaryDirectory = path.join(temporaryRoot, attemptId);
    workspaceAuthorized = true;
    await mkdir(attemptsDirectory, { recursive: true });
    await mkdir(temporaryRoot, { recursive: true });
    await registerTarget({
      targetConfigPath: configuration.targetConfigPath,
      workspacePath
    });
    const gitDiscovery = await discoverGitRepository(configuration.targetRoot);
    await assertSchema('git-discovery', gitDiscovery, 'Git discovery ledger');
    const gitDiscoveryDigest = sha256(canonicalJson(gitDiscovery));
    const snapshotResult = await buildSnapshot(configuration.targetRoot, configuration.target.id, configuration.profile, gitDiscovery);
    const analysisFiles = snapshotResult.files.map(({ record, content }) => ({ record, content }));
    const {
      fileRecords,
      adapterResult,
      reachability,
      cleanup,
      apiContracts,
      dataContracts,
      deploymentContracts,
      mismatches,
      operationalResult
    } = await runIsolatedAnalysis(analysisFiles, configuration.profile, snapshotResult.diagnostics);
    const analyzedRecords = new Map(fileRecords.map((record) => [record.path, record]));
    for (const file of snapshotResult.files) {
      const analyzed = analyzedRecords.get(file.record.path);
      if (analyzed) Object.assign(file.record, analyzed);
    }
    const operationalControls = await evaluateOperationalControls();
    const operational = applyOperationalControls(operationalResult, operationalControls);
    enforceRuleExpectations(configuration.profile, operational);
    const revalidatedSnapshot = await buildSnapshot(configuration.targetRoot, configuration.target.id, configuration.profile, gitDiscovery);
    if (revalidatedSnapshot.snapshot.snapshotId !== snapshotResult.snapshot.snapshotId) {
      throw new AtlasError('TARGET_CHANGED', 'The target boundary changed between discovery and final revalidation.');
    }
    if (canonicalJson(revalidatedSnapshot.profileObservations) !== canonicalJson(snapshotResult.profileObservations)) {
      throw new AtlasError('TARGET_CHANGED', 'Profile pattern observations changed between discovery and final revalidation.');
    }
    await verifyTargetUnchanged(snapshotResult.files);
    const revalidatedGitDiscovery = await discoverGitRepository(configuration.targetRoot);
    if (canonicalJson(revalidatedGitDiscovery) !== canonicalJson(gitDiscovery)) {
      throw new AtlasError('DISCOVERY_CHANGED', 'Git discovery state changed between acquisition and final revalidation.');
    }
    const analysisDiagnostics = deduplicateDiagnostics([
      ...snapshotResult.diagnostics,
      ...adapterResult.diagnostics,
      ...apiContracts.diagnostics,
      ...dataContracts.diagnostics,
      ...deploymentContracts.diagnostics,
      ...cleanup.diagnostics,
      ...mismatches.diagnostics,
      ...operational.diagnostics
    ]);
    const rawFindings = deduplicateFindings([
      ...apiContracts.findings,
      ...dataContracts.findings,
      ...deploymentContracts.findings,
      ...cleanup.findings,
      ...mismatches.findings,
      ...operational.findings
    ]);
    const postprocessedFindings = postprocessFindings(rawFindings, analysisFiles, reachability);
    const dispositionApplication = dispositionLedger
      ? applyFindingDispositions(
          dispositionLedger.ledger,
          postprocessedFindings,
          snapshotResult.files.map((file) => file.record)
        )
      : {
          findings: postprocessedFindings,
          diagnostics: [],
          suppressedFindingInstancesByRule: {}
        };
    const findings = dispositionApplication.findings;
    const diagnostics = deduplicateDiagnostics([
      ...analysisDiagnostics,
      ...dispositionApplication.diagnostics
    ]);
    const analysisHealthWithoutRunBinding = buildAnalysisHealthRecord({
      runId: `run_sha256_${'0'.repeat(64)}`,
      snapshotId: snapshotResult.snapshot.snapshotId,
      profileObservations: snapshotResult.profileObservations,
      controls: operationalControls,
      operational,
      ruleExpectations: configuration.profile.ruleExpectations ?? [],
      suppressedFindingInstancesByRule: dispositionApplication.suppressedFindingInstancesByRule
    });
    const identityInput = {
      snapshotId: snapshotResult.snapshot.snapshotId,
      targetId: configuration.target.id,
      profileId: configuration.profile.id,
      profileDigest: resolvedProfileDigest,
      tool: { name: 'atlas' as const, version: TOOL_VERSION },
      adapters: [adapterDescriptor],
      discovery: {
        provider: 'git' as const,
        version: GIT_DISCOVERY_VERSION,
        digest: gitDiscoveryDigest,
        state: gitDiscovery.state
      },
      analyses: [
        `api-contracts-v${API_CONTRACT_ANALYSIS_VERSION}`,
        'architecture-mismatch-v1',
        `core-census-v${CORE_CENSUS_VERSION}`,
        `data-contracts-v${DATA_CONTRACT_ANALYSIS_VERSION}`,
        `cleanup-candidates-v${CLEANUP_ANALYSIS_VERSION}`,
        `cleanup-duplicates-v${CLEANUP_COMPONENT_VERSIONS.duplicateFiles}`,
        `cleanup-platform-residuals-v${CLEANUP_COMPONENT_VERSIONS.platformResiduals}`,
        `cleanup-static-reachability-v${CLEANUP_COMPONENT_VERSIONS.staticReachability}`,
        `cleanup-unused-exports-v${CLEANUP_COMPONENT_VERSIONS.unusedExports}`,
        `deployment-contracts-v${DEPLOYMENT_CONTRACT_ANALYSIS_VERSION}`,
        `finding-postprocess-v${FINDING_POSTPROCESS_VERSION}`,
        OPERATIONAL_ANALYSIS_MARKER,
        `reachability-v${REACHABILITY_ANALYSIS_VERSION}`,
        analysisHealthMarker(
          ANALYSIS_HEALTH_VERSION,
          operationalControls.catalogDigest,
          operationalControls.corpusDigest
        ),
        profileObservationsAnalysisMarker(analysisHealthWithoutRunBinding.profilePatterns),
        ...(dispositionLedger ? [findingDispositionAnalysisMarker(dispositionLedger.digest)] : []),
        TRIAGE_REPORT_ANALYSIS_MARKER,
        'js-ts-static-relationships-v1',
        `portable-data-preflight-v${PORTABLE_DATA_PREFLIGHT_VERSION}`,
        'profile-contract-v1'
      ].sort(compareCanonicalText)
    };
    const runId = runIdentity(identityInput);
    observedRunId = runId;
    const run: RunRecord = {
      schemaVersion: SCHEMA_VERSION,
      runId,
      ...identityInput,
      artifacts: [...TRIAGE_RUN_ARTIFACTS],
      counts: {
        files: snapshotResult.files.length,
        relationships: adapterResult.relationships.length,
        diagnostics: diagnostics.length,
        findings: findings.length,
        findingInstances: findingInstanceCount(findings)
      }
    };
    const analysisHealth: typeof analysisHealthWithoutRunBinding = {
      ...analysisHealthWithoutRunBinding,
      runId
    };
    const triageReport = renderTriageReport(run, findings, diagnostics);
    assertPortableDataSafe({
      snapshot: snapshotResult.snapshot,
      run,
      discovery: gitDiscovery,
      files: snapshotResult.files.map((file) => file.record),
      relationships: adapterResult.relationships,
      diagnostics,
      findings,
      analysisHealth,
      triageReport
    }, 'Atlas run artifact set');
    await mkdir(temporaryDirectory, { recursive: false });
    const artifactContent = new Map<string, string>([
      ['snapshot.json', prettyCanonicalJson(snapshotResult.snapshot)],
      ['run.json', prettyCanonicalJson(run)],
      ['discovery.json', prettyCanonicalJson(gitDiscovery)],
      ['files.jsonl', canonicalJsonLines(snapshotResult.files.map((file) => file.record))],
      ['relationships.jsonl', canonicalJsonLines(adapterResult.relationships)],
      ['diagnostics.jsonl', canonicalJsonLines(diagnostics)],
      ['findings.jsonl', canonicalJsonLines(findings)],
      [ANALYSIS_HEALTH_ARTIFACT_NAME, prettyCanonicalJson(analysisHealth)],
      [TRIAGE_REPORT_ARTIFACT_NAME, triageReport]
    ]);
    for (const [name, content] of artifactContent) await writeFile(path.join(temporaryDirectory, name), content, 'utf8');
    const manifest: ArtifactManifest = {
      schemaVersion: SCHEMA_VERSION,
      runId,
      artifacts: [...artifactContent.entries()].map(([artifactPath, content]) => ({
        path: artifactPath,
        bytes: Buffer.byteLength(content),
        sha256: sha256(content)
      })).sort((left, right) => compareCanonicalText(left.path, right.path))
    };
    await writeCanonicalJson(path.join(temporaryDirectory, ARTIFACT_MANIFEST_NAME), manifest);
    const candidateManifest = (await verifyAndLoadRunDirectory(temporaryDirectory)).manifest;
    const runsDirectory = await safeWorkspaceChild(workspacePath, configuration.targetRoot, path.join(workspacePath, 'runs'));
    const finalRunDirectory = path.join(runsDirectory, runId);
    await mkdir(runsDirectory, { recursive: true });
    let reused = false;
    if (await exists(finalRunDirectory)) {
      const publishedManifest = (await verifyAndLoadRunDirectory(finalRunDirectory)).manifest;
      if (canonicalJson(publishedManifest) !== canonicalJson(candidateManifest)) {
        throw new AtlasError(
          'DETERMINISM_CONFLICT',
          `Run ${runId} already exists, but the newly generated artifact digests differ.`
        );
      }
      await safeRemoveTemporary(temporaryRoot, temporaryDirectory);
      reused = true;
    } else {
      await rename(temporaryDirectory, finalRunDirectory);
    }
    const execution: ExecutionRecord = {
      schemaVersion: SCHEMA_VERSION,
      attemptId,
      runId,
      targetPath: configuration.targetRoot,
      targetConfigPath: configuration.targetConfigPath,
      profilePath: configuration.profilePath,
      startedAt,
      finishedAt: new Date().toISOString(),
      status: reused ? 'reused' : 'completed'
    };
    await assertSchema('attempt', execution, 'Execution attempt');
    const attemptPath = path.join(attemptsDirectory, `${attemptId}.json`);
    await writeCanonicalJson(attemptPath, execution);
    return { runDirectory: finalRunDirectory, attemptPath, run, reused };
  } catch (error) {
    if (workspaceAuthorized && await exists(temporaryDirectory)) await safeRemoveTemporary(temporaryRoot, temporaryDirectory);
    const execution: ExecutionRecord = {
      schemaVersion: SCHEMA_VERSION,
      attemptId,
      ...(observedRunId ? { runId: observedRunId } : {}),
      targetPath,
      targetConfigPath: path.resolve(options.targetConfigPath),
      profilePath: path.resolve(options.profilePath),
      startedAt,
      finishedAt: new Date().toISOString(),
      status: 'failed',
      error: errorDetails(error)
    };
    if (workspaceAuthorized) {
      await assertSchema('attempt', execution, 'Failed execution attempt');
      await mkdir(attemptsDirectory, { recursive: true });
      await writeCanonicalJson(path.join(attemptsDirectory, `${attemptId}.json`), execution);
    }
    throw error;
  }
}
