import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createReviewCampaign, reviewCampaignStatus } from '../src/reviews.js';
import { scanProject } from '../src/run.js';
import type { ReviewPacket } from '../src/types.js';
import { readJson, writeCanonicalJson } from '../src/util/canonical.js';

async function selectedPaths(directory: string, packetIds: string[]): Promise<string[]> {
  const packets = await Promise.all(packetIds.map((packetId) => readJson<ReviewPacket>(
    path.join(directory, 'packets', `${packetId}.json`)
  )));
  return packets.flatMap((packet) => packet.files.map((file) => file.path)).sort();
}

test('review campaigns select exact paths, symbols, findings, neighborhoods, and incremental diffs', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'atlas-review-selection-'));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const target = path.join(root, 'target');
  const workspace = path.join(root, 'workspace');
  await mkdir(path.join(target, 'src'), { recursive: true });
  await writeFile(path.join(target, 'src', 'index.ts'), "import { chosen } from './alpha.js';\nconsole.log(chosen);\n");
  await writeFile(path.join(target, 'src', 'alpha.ts'), 'export const chosen = 1;\n');
  await writeFile(path.join(target, 'src', 'orphan.ts'), 'export const orphan = true;\n');
  const targetConfigPath = path.join(root, 'target.json');
  const profilePath = path.join(root, 'profile.json');
  await writeCanonicalJson(targetConfigPath, {
    schemaVersion: 1,
    id: 'review-selection-target',
    path: './target',
    consent: { agentReview: true, export: false, projectMemory: false }
  });
  await writeCanonicalJson(profilePath, {
    schemaVersion: 1,
    id: 'review-selection-profile',
    includeRoots: ['src'],
    exclude: [],
    entrypoints: ['src/index.ts'],
    maxFileBytes: 100000
  });
  const baseline = await scanProject({ targetConfigPath, profilePath, workspacePath: workspace });

  const paths = await createReviewCampaign({
    runDirectory: baseline.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'Path slice',
    selection: 'paths',
    selectors: ['src/a*.ts'],
    batchSize: 10
  });
  assert.deepEqual(await selectedPaths(paths.directory, paths.campaign.packetIds), ['src/alpha.ts']);
  assert.deepEqual(paths.campaign.selectionSpec, { selectors: ['src/a*.ts'] });

  const symbols = await createReviewCampaign({
    runDirectory: baseline.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'Symbol slice',
    selection: 'symbols',
    selectors: ['chosen'],
    batchSize: 10
  });
  assert.deepEqual(await selectedPaths(symbols.directory, symbols.campaign.packetIds), ['src/alpha.ts']);

  const neighborhood = await createReviewCampaign({
    runDirectory: baseline.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'Dependency neighborhood',
    selection: 'neighborhood',
    selectors: ['src/index.ts'],
    depth: 1,
    direction: 'outgoing',
    batchSize: 10
  });
  assert.deepEqual(await selectedPaths(neighborhood.directory, neighborhood.campaign.packetIds), [
    'src/alpha.ts',
    'src/index.ts'
  ]);

  const baselineFindings = (await readFile(path.join(baseline.runDirectory, 'findings.jsonl'), 'utf8'))
    .trim().split('\n').map((line) => JSON.parse(line) as { id: string; path?: string });
  const orphanFinding = baselineFindings.find((finding) => finding.path === 'src/orphan.ts');
  assert(orphanFinding);
  const findings = await createReviewCampaign({
    runDirectory: baseline.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'One finding',
    selection: 'findings',
    selectors: [orphanFinding.id],
    batchSize: 10
  });
  assert.deepEqual(await selectedPaths(findings.directory, findings.campaign.packetIds), ['src/orphan.ts']);

  await writeFile(path.join(target, 'src', 'alpha.ts'), 'export const chosen = 2;\n');
  await writeFile(path.join(target, 'src', 'beta.ts'), 'export const beta = true;\n');
  const next = await scanProject({ targetConfigPath, profilePath, workspacePath: workspace });
  const diff = await createReviewCampaign({
    runDirectory: next.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'Affected change slice',
    selection: 'diff',
    baselineRunDirectory: baseline.runDirectory,
    batchSize: 10
  });
  assert.deepEqual(await selectedPaths(diff.directory, diff.campaign.packetIds), [
    'src/alpha.ts',
    'src/beta.ts',
    'src/index.ts',
    'src/orphan.ts'
  ]);
  assert.equal(diff.campaign.selectionSpec?.baselineRunId, baseline.run.runId);
  assert(diff.campaign.selectionSpec?.incrementalPlanId?.startsWith('incremental_plan_sha256_'));
  const status = await reviewCampaignStatus(diff.directory) as { campaign: { campaignId: string } };
  assert.equal(status.campaign.campaignId, diff.campaign.campaignId);

  await assert.rejects(createReviewCampaign({
    runDirectory: next.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: 'Missing path',
    selection: 'paths',
    selectors: ['does/not/exist.ts'],
    batchSize: 10
  }), /matched no file/u);

  const reviewsBefore = (await readdir(path.join(workspace, 'reviews'))).sort();
  const credentialShape = `sk-proj-${'A'.repeat(24)}`;
  await assert.rejects(createReviewCampaign({
    runDirectory: next.runDirectory,
    workspacePath: workspace,
    targetConfigPath,
    purpose: `Inspect ${credentialShape}`,
    selection: 'all',
    batchSize: 10
  }), (error: unknown) => {
    assert(error instanceof Error);
    assert.match(error.message, /credential preflight/u);
    assert(!error.message.includes(credentialShape));
    return true;
  });
  assert.deepEqual((await readdir(path.join(workspace, 'reviews'))).sort(), reviewsBefore);
});
