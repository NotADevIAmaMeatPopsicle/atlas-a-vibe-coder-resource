import assert from 'node:assert/strict';
import { appendFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadRunArtifacts } from '../src/artifacts.js';
import {
  TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER,
  analysisHealthMarker
} from '../src/artifact-contract.js';
import { scanProject } from '../src/run.js';
import { AtlasError } from '../src/errors.js';
import { prettyCanonicalJson, sha256, writeCanonicalJson } from '../src/util/canonical.js';
import {
  createRunViewer,
  buildViewerData,
  decodeViewerDataScript,
  renderDependencyMermaid,
  VIEWER_VERSION,
  verifyRunViewer,
  type ViewerData
} from '../src/viewer/index.js';
import { verifyAndLoadRunViewer } from '../src/viewer/verify.js';
import { VIEWER_APP_JAVASCRIPT, VIEWER_CSS, VIEWER_HTML } from '../src/viewer/assets.js';
import {
  buildViewerBundle,
  encodeViewerData,
  viewerIdentity,
  VIEWER_MANIFEST_NAME
} from '../src/viewer/bundle.js';

async function createViewerFixture(exportConsent = true): Promise<{
  root: string;
  target: string;
  targetConfigPath: string;
  profilePath: string;
  workspacePath: string;
  runDirectory: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-viewer-test-'));
  const target = path.join(root, 'target');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), [
    "import { useful } from './useful.js';",
    "import { absent } from './missing.js';",
    "console.log(useful, absent, 'SOURCE_BODY_SENTINEL');",
    ''
  ].join('\n'));
  await writeFile(path.join(target, 'src', 'useful.ts'), 'export const useful = 42;\n');
  await writeFile(path.join(target, 'src', 'orphan.ts'), 'export const orphan = true;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'viewer-test-target',
    path: './target',
    consent: { agentReview: false, export: exportConsent, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'viewer-test-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    operationalRisks: { guardPaths: ['src/index.ts'], seedDictionarySources: [] },
    lifecycleRules: [
      { id: 'fixture-entrypoint', state: 'active', paths: ['src/index.ts'] }
    ],
    maxFileBytes: 100000
  });
  const workspacePath = path.join(root, 'workspace');
  const scan = await scanProject({
    targetConfigPath,
    profilePath,
    workspacePath
  });
  return { root, target, targetConfigPath, profilePath, workspacePath, runDirectory: scan.runDirectory };
}

async function writeResealedViewerBundle(
  directory: string,
  data: ViewerData,
  sourceArtifactManifestSha256?: string
): Promise<void> {
  const bundle = buildViewerBundle(data);
  if (sourceArtifactManifestSha256 !== undefined) {
    const manifest = {
      ...bundle.manifest,
      sourceArtifactManifestSha256,
      viewerId: viewerIdentity({
        runId: bundle.manifest.runId,
        snapshotId: bundle.manifest.snapshotId,
        sourceArtifactManifestSha256,
        artifacts: bundle.manifest.artifacts
      })
    };
    bundle.artifacts.set(VIEWER_MANIFEST_NAME, Buffer.from(prettyCanonicalJson(manifest), 'utf8'));
  }
  await mkdir(directory, { recursive: true });
  await Promise.all([...bundle.artifacts].map(([name, content]) => writeFile(path.join(directory, name), content)));
}

test('standalone viewer is deterministic, self-contained, injection-safe, and relationship-aware', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const outputDirectory = path.join(fixture.root, 'viewer');
  const first = await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory
  });
  assert.equal(first.reused, false);
  assert.equal(first.manifest.viewerVersion, '0.9.0');
  assert.equal(first.healthState, 'recorded');
  assert.equal(first.healthStatus, 'incomplete');
  const sourceArtifactManifestSha256 = sha256(
    await readFile(path.join(fixture.runDirectory, 'artifact-digests.json'))
  );
  assert.equal(first.sourceArtifactManifestSha256, sourceArtifactManifestSha256);
  assert.equal(first.manifest.sourceArtifactManifestSha256, sourceArtifactManifestSha256);
  const verification = await verifyRunViewer(outputDirectory);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.healthState, 'recorded');
  assert.equal(verification.healthStatus, 'incomplete');
  assert.equal(verification.sourceArtifactManifestSha256, sourceArtifactManifestSha256);
  assert.equal(verification.files, 3);
  assert.equal(verification.relationships, 2);
  assert(verification.findings > 0);

  const names = (await readdir(outputDirectory)).sort();
  assert.deepEqual(names, [
    'app.css',
    'app.js',
    'atlas-data.js',
    'dependency-graph.mmd',
    'index.html',
    'viewer-manifest.json'
  ]);
  const html = await readFile(path.join(outputDirectory, 'index.html'), 'utf8');
  const app = await readFile(path.join(outputDirectory, 'app.js'), 'utf8');
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'self'/);
  assert.match(html, /connect-src 'none'/);
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.doesNotMatch(app, /innerHTML/);
  assert.doesNotMatch(app, /\bfetch\s*\(/);
  assert.match(app, /textContent/);

  const data = decodeViewerDataScript(await readFile(path.join(outputDirectory, 'atlas-data.js'), 'utf8'));
  assert.equal(data.sourceArtifactManifestSha256, sourceArtifactManifestSha256);
  const indexFile = data.census.files.find((file) => file.path === 'src/index.ts');
  const usefulFile = data.census.files.find((file) => file.path === 'src/useful.ts');
  assert(indexFile);
  assert(usefulFile);
  assert.deepEqual(indexFile.lifecycle, {
    state: 'active',
    basis: 'profile-path-rule',
    ruleId: 'fixture-entrypoint',
    uncertainty: 'not-runtime-validated',
    limitation: 'Lifecycle is a static profile declaration and has not been validated against runtime deployment, traffic, or use.'
  });
  assert.equal(usefulFile.lifecycle.state, 'unspecified');
  assert(indexFile.outgoing.some((relationship) => relationship.toPath === 'src/useful.ts'));
  assert(indexFile.outgoing.some((relationship) => relationship.resolution === 'unresolved-internal'));
  assert(usefulFile.incoming.some((relationship) => relationship.fromPath === 'src/index.ts'));
  assert(data.findings.length > 0);
  assert(data.diagnostics.length > 0);
  assert.equal(data.dependencyGraph.edges.length, 2);
  assert.equal(data.analysisHealth.state, 'recorded');
  if (data.analysisHealth.state === 'recorded') {
    assert.equal(data.analysisHealth.status, 'incomplete');
    assert(data.analysisHealth.profilePatterns.some((pattern) => pattern.collection === 'guard-boundary'));
    assert(data.analysisHealth.rules.length > 0);
    assert(data.analysisHealth.incidents.length > 0);
    assert.equal(data.analysisHealth.recall.tier, 'synthetic');
    assert.equal(data.analysisHealth.recall.denominator, data.analysisHealth.incidents.length);
    assert.deepEqual(data.analysisHealth.realTargetEvaluation, {
      tier: 'real-target',
      result: 'not-recorded-in-run',
      reportContract: 'real-target-corpus-report.schema.json'
    });
    assert.equal(data.analysisHealth.fixedCaseSilence.denominator, data.analysisHealth.incidents.length);
  }
  assert(data.findings.every((finding) => finding.kind !== undefined));
  assert(data.findings.every((finding) => finding.impactContext !== undefined));

  const combined = Buffer.concat(await Promise.all(names.map((name) => readFile(path.join(outputDirectory, name))))).toString('utf8');
  assert(!combined.includes('SOURCE_BODY_SENTINEL'));
  assert(!combined.includes(path.resolve(fixture.target)));

  const hostile = structuredClone(data) as ViewerData;
  hostile.dependencyGraph.nodes[0]!.label = 'unsafe"]\n%%{init: {"theme":"evil"}}%%\nclick target';
  const escapedMermaid = renderDependencyMermaid(hostile);
  assert(!escapedMermaid.includes('%%{'));
  assert(!escapedMermaid.includes('\nclick target'));
  assert.match(escapedMermaid, /&#x25;&#x25;&#x7B;/);

  const second = await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory
  });
  assert.equal(second.reused, true);
  assert.equal(second.healthState, 'recorded');
  assert.equal(second.healthStatus, 'incomplete');
  assert.equal(second.sourceArtifactManifestSha256, sourceArtifactManifestSha256);
  assert.equal(second.viewerId, first.viewerId);
  assert.deepEqual(second.manifest, first.manifest);
  assert(!(await readdir(fixture.root)).some((name) => name.startsWith('.atlas-viewer-tmp-')));
});

test('viewer projects an explicit legacy state when analysis health was not recorded', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const loaded = await loadRunArtifacts(fixture.runDirectory);
  const legacyLoaded = {
    ...loaded,
    run: {
      ...loaded.run,
      analyses: loaded.run.analyses.filter((analysis) =>
        !analysis.startsWith('analysis-health-v1') && !analysis.startsWith('operational-risks-v') &&
        !analysis.startsWith('profile-observations-v')
      )
    }
  };
  delete legacyLoaded.analysisHealth;
  const data = buildViewerData(legacyLoaded);
  assert.deepEqual(data.analysisHealth, {
    state: 'legacy-not-recorded',
    limitation: 'This legacy run predates analysis-health artifacts; rule controls, incident regressions, recall, and fixed-case silence were not recorded.'
  });

  const outputDirectory = path.join(fixture.root, 'resealed-legacy-health-viewer');
  await writeResealedViewerBundle(outputDirectory, data);
  const verification = await verifyRunViewer(outputDirectory);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.healthState, 'legacy-not-recorded');
  assert.equal(verification.healthStatus, 'not-recorded');

  const downgradedLoaded = { ...loaded };
  delete downgradedLoaded.analysisHealth;
  const downgradedDirectory = path.join(fixture.root, 'resealed-downgraded-current-viewer');
  await writeResealedViewerBundle(downgradedDirectory, buildViewerData(downgradedLoaded));
  await assert.rejects(
    verifyRunViewer(downgradedDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );
});

test('data-contract view retains and traverses subjects from aggregated finding instances', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await mkdir(path.join(fixture.target, 'src', 'models'), { recursive: true });
  await mkdir(path.join(fixture.target, 'src', 'migrations'), { recursive: true });
  await writeFile(path.join(fixture.target, 'src', 'models', 'jobs.js'), [
    "sequelize.define('Job', { status: { type: DataTypes.STRING } }, { tableName: 'jobs' });",
    "sequelize.define('Task', { status: { type: DataTypes.STRING } }, { tableName: 'tasks' });",
    ''
  ].join('\n'));
  await writeFile(path.join(fixture.target, 'src', 'migrations', '001-work.js'), [
    'module.exports = { async up(queryInterface, Sequelize) {',
    "  await queryInterface.createTable('jobs', { status: { type: Sequelize.ENUM('queued', 'done') } });",
    "  await queryInterface.createTable('tasks', { status: { type: Sequelize.ENUM('queued', 'done') } });",
    '} };',
    ''
  ].join('\n'));
  await writeFile(path.join(fixture.target, 'src', 'bootstrap.sql'), [
    'CREATE TABLE jobs (status VARCHAR(32));',
    'CREATE TABLE tasks (status VARCHAR(32));',
    ''
  ].join('\n'));
  const scan = await scanProject({
    targetConfigPath: fixture.targetConfigPath,
    profilePath: fixture.profilePath,
    workspacePath: fixture.workspacePath
  });
  const data = buildViewerData(await loadRunArtifacts(scan.runDirectory));
  const aggregate = data.findings.find((finding) =>
    finding.ruleId === 'contract/data-enum-v1' && (finding.instanceCount ?? 0) === 2
  );
  assert(aggregate);
  assert.equal(aggregate.subject, undefined);
  assert.deepEqual(
    aggregate.instances?.map((instance) => instance.subject?.table).sort(),
    ['jobs', 'tasks']
  );
  const provisioning = data.findings.find((finding) =>
    finding.ruleId === 'contract/data-provisioning-path-enum-v1'
  );
  assert(provisioning);
  assert.equal(provisioning.instanceCount, 2);
  assert.equal(provisioning.subject, undefined);
  const provisioningSubjects = provisioning.instances?.map((instance) => instance.subject);
  assert(provisioningSubjects?.every((subject) => subject && 'comparison' in subject));
  assert(provisioningSubjects?.every((subject) => subject && 'comparison' in subject && subject.comparison === 'provisioning-path'));

  const outputDirectory = path.join(fixture.root, 'aggregate-data-contract-viewer');
  await writeResealedViewerBundle(outputDirectory, data);
  assert.equal((await verifyRunViewer(outputDirectory)).status, 'passed');
  assert.match(VIEWER_APP_JAVASCRIPT, /function dataContractSubjectEntries\(finding\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /finding\.instances\.flatMap/);
  assert.match(VIEWER_APP_JAVASCRIPT, /dataContractSubjectEntries\(finding\)\.forEach/);
  assert.match(VIEWER_APP_JAVASCRIPT, /subject\.comparison === 'provisioning-path'/);
});

test('verified viewer values remain bound to the exact bytes verified before a later disk replacement', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const outputDirectory = path.join(fixture.root, 'viewer-byte-binding');
  await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory
  });

  const verified = await verifyAndLoadRunViewer(outputDirectory);
  const originalManifest = structuredClone(verified.manifest);
  const originalManifestSha256 = verified.manifestSha256;
  const originalIndexHtml = verified.indexHtml;
  await Promise.all([
    writeFile(path.join(outputDirectory, 'viewer-manifest.json'), '{}\n'),
    writeFile(path.join(outputDirectory, 'index.html'), '<main>replaced after verification</main>')
  ]);

  assert.deepEqual(verified.manifest, originalManifest);
  assert.equal(verified.manifestSha256, originalManifestSha256);
  assert.equal(verified.indexHtml, originalIndexHtml);
  assert.notEqual(await readFile(path.join(outputDirectory, 'index.html'), 'utf8'), verified.indexHtml);
});

test('viewer rejects publication inside the target before writing', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const unsafeOutput = path.join(fixture.target, 'generated-viewer');
  await assert.rejects(
    createRunViewer({
      runDirectory: fixture.runDirectory,
      workspacePath: fixture.workspacePath,
      targetConfigPath: fixture.targetConfigPath,
      outputDirectory: unsafeOutput
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_OUTPUT_INSIDE_TARGET'
  );
  await assert.rejects(stat(unsafeOutput), /ENOENT/);
});

test('viewer publication requires the registered target export consent', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await writeCanonicalJson(fixture.targetConfigPath, {
    schemaVersion: 1,
    id: 'viewer-test-target',
    path: './target',
    consent: { agentReview: false, export: false, projectMemory: false }
  });
  const outputDirectory = path.join(fixture.root, 'viewer-without-consent');
  await assert.rejects(
    createRunViewer({
      runDirectory: fixture.runDirectory,
      workspacePath: fixture.workspacePath,
      targetConfigPath: fixture.targetConfigPath,
      outputDirectory
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_EXPORT_NOT_AUTHORIZED'
  );
  await assert.rejects(stat(outputDirectory), /ENOENT/);
});

test('target-controlled edits cannot escalate registered viewer export consent', async (context) => {
  const fixture = await createViewerFixture(false);
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await writeCanonicalJson(fixture.targetConfigPath, {
    schemaVersion: 1,
    id: 'viewer-test-target',
    path: './target',
    consent: { agentReview: false, export: true, projectMemory: false }
  });
  const outputDirectory = path.join(fixture.root, 'viewer-after-consent-escalation');
  await assert.rejects(
    createRunViewer({
      runDirectory: fixture.runDirectory,
      workspacePath: fixture.workspacePath,
      targetConfigPath: fixture.targetConfigPath,
      outputDirectory
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'TARGET_CONSENT_ESCALATION'
  );
  await assert.rejects(stat(outputDirectory), /ENOENT/);
});

test('viewer never overwrites a conflicting publication', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const outputDirectory = path.join(fixture.root, 'viewer-conflict');
  await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory
  });
  const stylesheet = path.join(outputDirectory, 'app.css');
  await appendFile(stylesheet, 'conflicting-content\n');
  const conflictingContent = await readFile(stylesheet, 'utf8');
  await assert.rejects(
    createRunViewer({
      runDirectory: fixture.runDirectory,
      workspacePath: fixture.workspacePath,
      targetConfigPath: fixture.targetConfigPath,
      outputDirectory
    }),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_OUTPUT_CONFLICT'
  );
  assert.equal(await readFile(stylesheet, 'utf8'), conflictingContent);
});

test('viewer refuses a tampered run and leaves no output', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  await appendFile(path.join(fixture.runDirectory, 'diagnostics.jsonl'), '{"tampered":true}\n');
  const outputDirectory = path.join(fixture.root, 'viewer-from-tampered-run');
  await assert.rejects(
    createRunViewer({
      runDirectory: fixture.runDirectory,
      workspacePath: fixture.workspacePath,
      targetConfigPath: fixture.targetConfigPath,
      outputDirectory
    }),
    /digest mismatch/i
  );
  await assert.rejects(stat(outputDirectory), /ENOENT/);
});

test('viewer verification rejects resealed bundles with missing or invalid lifecycle projections', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const validDirectory = path.join(fixture.root, 'valid-lifecycle-viewer');
  await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory: validDirectory
  });
  const valid = decodeViewerDataScript(await readFile(path.join(validDirectory, 'atlas-data.js'), 'utf8'));

  const missing = structuredClone(valid);
  delete (missing.census.files[0] as Partial<(typeof missing.census.files)[number]>).lifecycle;
  const missingDirectory = path.join(fixture.root, 'resealed-missing-lifecycle');
  await writeResealedViewerBundle(missingDirectory, missing);
  await assert.rejects(
    verifyRunViewer(missingDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalid = structuredClone(valid);
  Object.assign(invalid.census.files[0]!, {
    lifecycle: {
      state: 'active',
      basis: 'no-profile-match',
      uncertainty: 'not-runtime-validated',
      limitation: 'invalid lifecycle combination'
    }
  });
  const invalidDirectory = path.join(fixture.root, 'resealed-invalid-lifecycle');
  await writeResealedViewerBundle(invalidDirectory, invalid);
  await assert.rejects(
    verifyRunViewer(invalidDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );
});

test('viewer verification rejects resealed bundles with changed or absent source-manifest binding', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const valid = buildViewerData(await loadRunArtifacts(fixture.runDirectory));
  const originalBinding = valid.sourceArtifactManifestSha256;

  const changed = structuredClone(valid);
  changed.sourceArtifactManifestSha256 = `${originalBinding[0] === '0' ? '1' : '0'}${originalBinding.slice(1)}`;
  const changedDirectory = path.join(fixture.root, 'resealed-changed-source-binding');
  await writeResealedViewerBundle(changedDirectory, changed, originalBinding);
  await assert.rejects(
    verifyRunViewer(changedDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_IDENTITY_MISMATCH'
  );

  const missing = structuredClone(valid) as Partial<ViewerData>;
  delete missing.sourceArtifactManifestSha256;
  const missingDirectory = path.join(fixture.root, 'resealed-missing-source-binding');
  await writeResealedViewerBundle(missingDirectory, missing as ViewerData, originalBinding);
  await assert.rejects(
    verifyRunViewer(missingDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );
});

test('viewer verification rejects resealed bundles with empty, malformed, or endpoint-mismatched relationship arrays', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const validDirectory = path.join(fixture.root, 'valid-relationship-viewer');
  await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory: validDirectory
  });
  const valid = decodeViewerDataScript(await readFile(path.join(validDirectory, 'atlas-data.js'), 'utf8'));

  const empty = structuredClone(valid);
  for (const file of empty.census.files) {
    file.incoming = [];
    file.outgoing = [];
  }
  const emptyDirectory = path.join(fixture.root, 'resealed-empty-relationships');
  await writeResealedViewerBundle(emptyDirectory, empty);
  await assert.rejects(
    verifyRunViewer(emptyDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const mismatched = structuredClone(valid);
  const source = mismatched.census.files.find((file) => file.outgoing.length > 0);
  const other = mismatched.census.files.find((file) => file.id !== source?.id);
  assert(source?.outgoing[0]);
  assert(other);
  source.outgoing[0] = {
    ...source.outgoing[0],
    from: other.id,
    fromPath: other.path
  };
  const mismatchedDirectory = path.join(fixture.root, 'resealed-mismatched-relationships');
  await writeResealedViewerBundle(mismatchedDirectory, mismatched);
  await assert.rejects(
    verifyRunViewer(mismatchedDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const missingLocation = structuredClone(valid);
  const locatedSource = missingLocation.census.files.find((file) => file.outgoing.length > 0);
  assert(locatedSource?.outgoing[0]);
  delete (locatedSource.outgoing[0] as Partial<(typeof locatedSource.outgoing)[number]>).location;
  const missingLocationDirectory = path.join(fixture.root, 'resealed-missing-relationship-location');
  await writeResealedViewerBundle(missingLocationDirectory, missingLocation);
  await assert.rejects(
    verifyRunViewer(missingLocationDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );
});

test('viewer verification rejects inconsistent health and malformed finding context', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const validDirectory = path.join(fixture.root, 'valid-health-viewer');
  await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory: validDirectory
  });
  const valid = decodeViewerDataScript(await readFile(path.join(validDirectory, 'atlas-data.js'), 'utf8'));
  assert.equal(valid.analysisHealth.state, 'recorded');

  const invalidHealth = structuredClone(valid);
  if (invalidHealth.analysisHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  invalidHealth.analysisHealth.recall.numerator = invalidHealth.analysisHealth.recall.denominator + 1;
  const invalidHealthDirectory = path.join(fixture.root, 'resealed-invalid-health');
  await writeResealedViewerBundle(invalidHealthDirectory, invalidHealth);
  await assert.rejects(
    verifyRunViewer(invalidHealthDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidTarget = structuredClone(valid);
  if (invalidTarget.analysisHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  const target = invalidTarget.analysisHealth.rules[0]?.target;
  assert(target);
  target.findingInstances += 1;
  const invalidTargetDirectory = path.join(fixture.root, 'resealed-invalid-target-count');
  await writeResealedViewerBundle(invalidTargetDirectory, invalidTarget);
  await assert.rejects(
    verifyRunViewer(invalidTargetDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidMarker = structuredClone(valid);
  const markerIndex = invalidMarker.run.analyses.findIndex((analysis) => analysis.startsWith('analysis-health-v1'));
  assert.notEqual(markerIndex, -1);
  invalidMarker.run.analyses[markerIndex] = `${invalidMarker.run.analyses[markerIndex]}-tampered`;
  invalidMarker.run.analyses.sort();
  const invalidMarkerDirectory = path.join(fixture.root, 'resealed-invalid-health-marker');
  await writeResealedViewerBundle(invalidMarkerDirectory, invalidMarker);
  await assert.rejects(
    verifyRunViewer(invalidMarkerDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const missingOperationalMarker = structuredClone(valid);
  missingOperationalMarker.run.analyses = missingOperationalMarker.run.analyses.filter((analysis) =>
    !analysis.startsWith('operational-risks-v')
  );
  const missingOperationalMarkerDirectory = path.join(fixture.root, 'resealed-missing-operational-marker');
  await writeResealedViewerBundle(missingOperationalMarkerDirectory, missingOperationalMarker);
  await assert.rejects(
    verifyRunViewer(missingOperationalMarkerDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const downgradedTriageMarker = structuredClone(valid);
  const triageMarkerIndex = downgradedTriageMarker.run.analyses.findIndex((analysis) =>
    analysis.startsWith('triage-report-v')
  );
  assert.notEqual(triageMarkerIndex, -1);
  downgradedTriageMarker.run.analyses[triageMarkerIndex] = TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER;
  downgradedTriageMarker.run.analyses.sort();
  const downgradedTriageMarkerDirectory = path.join(fixture.root, 'resealed-downgraded-triage-marker');
  await writeResealedViewerBundle(downgradedTriageMarkerDirectory, downgradedTriageMarker);
  await assert.rejects(
    verifyRunViewer(downgradedTriageMarkerDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidOperationalMarker = structuredClone(valid);
  const operationalMarkerIndex = invalidOperationalMarker.run.analyses.findIndex((analysis) =>
    analysis.startsWith('operational-risks-v')
  );
  assert.notEqual(operationalMarkerIndex, -1);
  invalidOperationalMarker.run.analyses[operationalMarkerIndex] = 'operational-risks-v999.0.0';
  invalidOperationalMarker.run.analyses.sort();
  const invalidOperationalMarkerDirectory = path.join(fixture.root, 'resealed-invalid-operational-marker');
  await writeResealedViewerBundle(invalidOperationalMarkerDirectory, invalidOperationalMarker);
  await assert.rejects(
    verifyRunViewer(invalidOperationalMarkerDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const previousSupportedPair = structuredClone(valid);
  const previousHealth = previousSupportedPair.analysisHealth;
  if (previousHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  previousHealth.producer.version = '1.3.1';
  delete previousHealth.recall.tier;
  delete previousHealth.realTargetEvaluation;
  previousSupportedPair.run.analyses = previousSupportedPair.run.analyses.map((analysis) => {
    if (analysis.startsWith('analysis-health-v1')) {
      return analysisHealthMarker(
        '1.3.1',
        previousHealth.catalogDigest,
        previousHealth.corpusDigest
      );
    }
    return analysis.startsWith('operational-risks-v') ? 'operational-risks-v1.3.1' : analysis;
  }).sort();
  const previousSupportedPairDirectory = path.join(fixture.root, 'resealed-previous-supported-pair');
  await writeResealedViewerBundle(previousSupportedPairDirectory, previousSupportedPair);
  assert.equal((await verifyRunViewer(previousSupportedPairDirectory)).status, 'passed');

  const olderSupportedPair = structuredClone(valid);
  const olderHealth = olderSupportedPair.analysisHealth;
  if (olderHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  olderHealth.producer.version = '1.3.0';
  delete olderHealth.recall.tier;
  delete olderHealth.realTargetEvaluation;
  olderSupportedPair.run.analyses = olderSupportedPair.run.analyses.map((analysis) => {
    if (analysis.startsWith('analysis-health-v1')) {
      return analysisHealthMarker(
        '1.3.0',
        olderHealth.catalogDigest,
        olderHealth.corpusDigest
      );
    }
    return analysis.startsWith('operational-risks-v') ? 'operational-risks-v1.3.0' : analysis;
  }).sort();
  const olderSupportedPairDirectory = path.join(fixture.root, 'resealed-older-supported-pair');
  await writeResealedViewerBundle(olderSupportedPairDirectory, olderSupportedPair);
  assert.equal((await verifyRunViewer(olderSupportedPairDirectory)).status, 'passed');

  const earliestSupportedPair = structuredClone(valid);
  const earliestHealth = earliestSupportedPair.analysisHealth;
  if (earliestHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  earliestHealth.producer.version = '1.2.0';
  delete earliestHealth.recall.tier;
  delete earliestHealth.realTargetEvaluation;
  earliestSupportedPair.run.analyses = earliestSupportedPair.run.analyses.map((analysis) => {
    if (analysis.startsWith('analysis-health-v1')) {
      return analysisHealthMarker(
        '1.2.0',
        earliestHealth.catalogDigest,
        earliestHealth.corpusDigest
      );
    }
    return analysis.startsWith('operational-risks-v') ? 'operational-risks-v1.2.2' : analysis;
  }).sort();
  const earliestSupportedPairDirectory = path.join(fixture.root, 'resealed-earliest-supported-pair');
  await writeResealedViewerBundle(earliestSupportedPairDirectory, earliestSupportedPair);
  assert.equal((await verifyRunViewer(earliestSupportedPairDirectory)).status, 'passed');

  const invalidProfileObservationsMarker = structuredClone(valid);
  const profileObservationsMarkerIndex = invalidProfileObservationsMarker.run.analyses.findIndex((analysis) =>
    analysis.startsWith('profile-observations-v')
  );
  assert.notEqual(profileObservationsMarkerIndex, -1);
  invalidProfileObservationsMarker.run.analyses[profileObservationsMarkerIndex] =
    `profile-observations-v1+sha256.${'0'.repeat(64)}`;
  invalidProfileObservationsMarker.run.analyses.sort();
  const invalidProfileObservationsMarkerDirectory = path.join(fixture.root, 'resealed-invalid-profile-observations-marker');
  await writeResealedViewerBundle(invalidProfileObservationsMarkerDirectory, invalidProfileObservationsMarker);
  await assert.rejects(
    verifyRunViewer(invalidProfileObservationsMarkerDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidSamplePath = structuredClone(valid);
  if (invalidSamplePath.analysisHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  const sampledPattern = invalidSamplePath.analysisHealth.profilePatterns.find((entry) => entry.samplePaths?.length);
  assert(sampledPattern?.samplePaths);
  sampledPattern.samplePaths[0] = '../outside.ts';
  const invalidSamplePathDirectory = path.join(fixture.root, 'resealed-invalid-profile-sample-path');
  await writeResealedViewerBundle(invalidSamplePathDirectory, invalidSamplePath);
  await assert.rejects(
    verifyRunViewer(invalidSamplePathDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidFinding = structuredClone(valid);
  assert(invalidFinding.findings[0]?.impactContext);
  invalidFinding.findings[0].impactContext.summary = '';
  const invalidFindingDirectory = path.join(fixture.root, 'resealed-invalid-finding-context');
  await writeResealedViewerBundle(invalidFindingDirectory, invalidFinding);
  await assert.rejects(
    verifyRunViewer(invalidFindingDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidSeverityCalibration = structuredClone(valid);
  assert(invalidSeverityCalibration.findings[0]?.severityCalibration);
  invalidSeverityCalibration.findings[0].severityCalibration.rationale = '';
  const invalidSeverityCalibrationDirectory = path.join(fixture.root, 'resealed-invalid-severity-calibration');
  await writeResealedViewerBundle(invalidSeverityCalibrationDirectory, invalidSeverityCalibration);
  await assert.rejects(
    verifyRunViewer(invalidSeverityCalibrationDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );

  const invalidMappingContext = structuredClone(valid);
  assert(invalidMappingContext.findings[0]);
  invalidMappingContext.findings[0].mechanism = 'dirname-divergence';
  invalidMappingContext.findings[0].mappingContexts = [{
    id: 'not-a-mapping-context-id',
    composePath: 'compose.yml',
    service: 'app',
    sourceKind: 'bind-mount',
    hostRoot: '.',
    containerRoot: '/app'
  }];
  const invalidMappingContextDirectory = path.join(fixture.root, 'resealed-invalid-mapping-context');
  await writeResealedViewerBundle(invalidMappingContextDirectory, invalidMappingContext);
  await assert.rejects(
    verifyRunViewer(invalidMappingContextDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );
});

test('viewer verification rejects internally coherent substituted current-control outcomes', async (context) => {
  const fixture = await createViewerFixture();
  context.after(async () => rm(fixture.root, { recursive: true, force: true }));
  const completeDirectory = path.join(fixture.root, 'complete-health-viewer');
  await createRunViewer({
    runDirectory: fixture.runDirectory,
    workspacePath: fixture.workspacePath,
    targetConfigPath: fixture.targetConfigPath,
    outputDirectory: completeDirectory
  });
  const incomplete = structuredClone(
    decodeViewerDataScript(await readFile(path.join(completeDirectory, 'atlas-data.js'), 'utf8'))
  );
  if (incomplete.analysisHealth.state !== 'recorded') assert.fail('Expected recorded analysis health.');
  const incident = incomplete.analysisHealth.incidents[0]!;
  const rule = incomplete.analysisHealth.rules.find((entry) => entry.ruleId === incident.ruleId)!;
  incident.broken.observed += 1;
  rule.controls.observedObservations += 1;
  const substitutedDirectory = path.join(fixture.root, 'substituted-current-health-viewer');
  await writeResealedViewerBundle(substitutedDirectory, incomplete);

  await assert.rejects(
    verifyRunViewer(substitutedDirectory),
    (error: unknown) => error instanceof AtlasError && error.code === 'VIEWER_DATA_INVALID'
  );
});

test('viewer data decoding is linear and stack-safe for large verified runs', () => {
  const largeAnalysis = 'analysis-'.repeat(400_000);
  const data: ViewerData = {
    schemaVersion: 1,
    viewerVersion: VIEWER_VERSION,
    sourceArtifactManifestSha256: '4'.repeat(64),
    run: {
      runId: `run_sha256_${'1'.repeat(64)}`,
      snapshotId: `snapshot_sha256_${'2'.repeat(64)}`,
      targetId: 'large-viewer-target',
      profileId: 'large-viewer-profile',
      profileDigest: '3'.repeat(64),
      tool: { name: 'atlas', version: 'test' },
      adapters: [],
      analyses: [largeAnalysis]
    },
    summary: {
      files: 0,
      relationships: 0,
      resolvedRelationships: 0,
      diagnostics: 0,
      findings: 0,
      totalBytes: 0
    },
    census: {
      boundary: { includeRoots: ['.'], exclude: [], maxFileBytes: 1, symlinkPolicy: 'deny' },
      boundaryDiagnostics: [],
      byKind: {},
      byLanguage: {},
      files: []
    },
    dependencyGraph: { nodes: [], edges: [] },
    analysisHealth: {
      state: 'legacy-not-recorded',
      limitation: 'This legacy run predates analysis-health artifacts; rule controls, incident regressions, recall, and fixed-case silence were not recorded.'
    },
    findings: [],
    diagnostics: []
  };
  const encoded = encodeViewerData(data);
  assert(encoded.length > 4_000_000);
  assert.equal(decodeViewerDataScript(encoded).run.analyses[0], largeAnalysis);
});

test('viewer renderer is an accessible, bounded, offline investigation workspace', () => {
  const ids = [...VIEWER_HTML.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]!);
  const rendererIds = [...VIEWER_APP_JAVASCRIPT.matchAll(/(?:required|setText)\('([^']+)'/g)]
    .map((match) => match[1]!);
  assert.equal(new Set(ids).size, ids.length, 'static viewer element IDs must be unique');
  assert.deepEqual(rendererIds.filter((id) => !ids.includes(id)), [], 'renderer element references must exist');
  assert.match(VIEWER_HTML, /id="graph-canvas"[^>]*role="group"[^>]*tabindex="0"/);
  assert.match(VIEWER_HTML, /aria-label="Graph view"/);
  assert.match(VIEWER_HTML, /data-graph-mode="architecture"/);
  assert.match(VIEWER_HTML, /data-graph-mode="neighborhood"/);
  assert.match(VIEWER_HTML, /data-graph-mode="data-contracts"/);
  assert.match(VIEWER_HTML, /data-graph-mode="findings"/);
  assert.match(VIEWER_HTML, /id="toggle-graph-focus"[^>]*aria-pressed="false"/);
  assert.match(VIEWER_HTML, /id="incoming-relationship-summary-count"/);
  assert.match(VIEWER_HTML, /id="outgoing-relationship-summary-count"/);
  assert.match(VIEWER_HTML, /id="selected-file-id"/);
  assert.match(VIEWER_HTML, /id="selected-file-evidence"/);
  assert.match(VIEWER_HTML, /id="selected-file-lifecycle"/);
  assert.match(VIEWER_HTML, /id="selected-file-limitation"/);
  assert.match(VIEWER_HTML, /id="analysis-health-state"/);
  assert.match(VIEWER_HTML, /id="analysis-health-recall"/);
  assert.match(VIEWER_HTML, /id="analysis-health-fixed-silence"/);
  assert.match(VIEWER_HTML, /id="analysis-health-rules"/);
  assert.match(VIEWER_HTML, /id="disabled-rules"/);
  assert.match(VIEWER_HTML, /id="health-incidents"/);
  assert.match(VIEWER_HTML, /href="viewer-manifest\.json"/);
  assert.match(VIEWER_HTML, /atlas viewer verify &lt;viewer-directory&gt;/);
  assert.match(VIEWER_HTML, /browser does not verify bundle hashes/i);
  assert.match(VIEWER_HTML, /aria-live="polite"/);
  assert.match(VIEWER_HTML, /data-workspace-panel="investigation"/);
  assert.match(VIEWER_HTML, /id="finding-queue"[^>]*role="listbox"/);
  assert.match(VIEWER_HTML, /id="brief-title"/);
  assert.match(VIEWER_HTML, /id="brief-evidence"/);
  assert.match(VIEWER_HTML, /id="brief-refutation"/);
  assert.match(VIEWER_HTML, /id="disposition-panel"/);
  assert.match(VIEWER_HTML, /<details class="story-card evidence-card">/);
  assert.match(VIEWER_HTML, /id="brief-calibration-rationale"/);
  assert.match(VIEWER_HTML, /id="brief-contexts"/);
  assert.match(VIEWER_HTML, /id="brief-next-validation"/);
  assert.match(VIEWER_HTML, /id="verification-dialog"/);
  assert.doesNotMatch(VIEWER_HTML, /\son[a-z]+\s*=/i);
  assert.match(VIEWER_CSS, /color-scheme:\s*light/);
  assert.doesNotMatch(VIEWER_CSS, /prefers-color-scheme:\s*dark/);
  assert.match(VIEWER_APP_JAVASCRIPT, /GRAPH_NODE_LIMIT = 72/);
  assert.match(VIEWER_APP_JAVASCRIPT, /GRAPH_EDGE_LIMIT = 240/);
  assert.match(VIEWER_APP_JAVASCRIPT, /ARCHITECTURE_NODE_LIMIT = 34/);
  assert.match(VIEWER_APP_JAVASCRIPT, /DATA_CONTRACT_SUBJECT_LIMIT = 22/);
  assert.match(VIEWER_APP_JAVASCRIPT, /FILE_LIST_LIMIT = 180/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function dataContractsGraph\(\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /Data contract projection/);
  assert.match(VIEWER_CSS, /\.graph-node\.kind-data-contract/);
  assert.match(VIEWER_CSS, /\.edge-contract-storage/);
  assert.match(VIEWER_CSS, /\.workspace-grid\.graph-focus/);
  assert.match(VIEWER_CSS, /\.badge\.active/);
  assert.match(VIEWER_CSS, /\.badge\.mothballed/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function setGraphFocus\(active\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function renderRelationshipSection\(direction, relationships\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /required\(direction \+ '-relationship-section'\)\.open = relationships\.length > 0/);
  assert.match(VIEWER_APP_JAVASCRIPT, /selectFile\(clusterFileId, true\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /formatNumber\(paths\.length\) \+ ' related files'/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function renderAnalysisHealth\(\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function findingImpactSummary\(finding\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function renderInvestigationBrief\(finding, ordinal\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function compareActionability\(left, right\)/);
  // The sort value is a parameter because this helper is module scope and cannot
  // read render's local controls. See tests/viewer-runtime.test.ts, which executes
  // the bundle; a source match alone cannot prove the grouping path runs.
  assert.match(VIEWER_APP_JAVASCRIPT, /function findingQueueGroups\(findings, sort\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /queueGroupLabel\(group\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /groups · ' \+ formatNumber\(allVisible\.length\) \+ ' findings'/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function renderDispositionSummary\(\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function renderDiagnosticSummary\(\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /function exportSelectedFinding\(\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /findingFilter\.addEventListener\('input', scheduleFindingViews\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /diagnosticFilter\.addEventListener\('input', scheduleDiagnosticViews\)/);
  assert.match(VIEWER_APP_JAVASCRIPT, /FINDING_QUEUE_LIMIT = 180/);
  assert.doesNotMatch(VIEWER_APP_JAVASCRIPT, /dblclick/);
  assert.match(VIEWER_APP_JAVASCRIPT, /Legacy finding: static impact context was not recorded\./);
  assert.match(VIEWER_APP_JAVASCRIPT, /file\.evidence\.producer \+ ' v' \+ file\.evidence\.producerVersion/);
  assert.match(VIEWER_APP_JAVASCRIPT, /file\.lifecycle\.uncertainty \+ ' · ' \+ file\.lifecycle\.limitation/);
  assert.match(VIEWER_APP_JAVASCRIPT, /'active', 'mothballed', 'shared', 'unknown', 'unspecified'/);
  assert.match(VIEWER_APP_JAVASCRIPT, /Bundled run data loaded/);
  assert.doesNotMatch(VIEWER_APP_JAVASCRIPT, /Verified data loaded/);
  assert.doesNotMatch(VIEWER_APP_JAVASCRIPT, /innerHTML|outerHTML|insertAdjacentHTML/);
  assert.doesNotMatch(VIEWER_APP_JAVASCRIPT, /\bfetch\s*\(/);
});
