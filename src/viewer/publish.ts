import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { loadRunArtifacts } from '../artifacts.js';
import { AtlasError } from '../errors.js';
import { assertSchema } from '../schema-validator.js';
import { assertPortableDataSafe } from '../security/portable-data.js';
import { verifyTargetRegistrationBinding } from '../targets.js';
import type { TargetConfig } from '../types.js';
import { readJson } from '../util/canonical.js';
import { isInside, resolveForContainment } from '../util/paths.js';
import { buildViewerBundle } from './bundle.js';
import { buildViewerData } from './model.js';
import type { ViewerPublicationResult } from './types.js';
import { verifyRunViewer } from './verify.js';

async function exists(value: string): Promise<boolean> {
  try {
    await lstat(value);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function samePath(left: string, right: string): boolean {
  return path.relative(path.resolve(left), path.resolve(right)) === '';
}

async function safeRemoveTemporary(parent: string, temporaryDirectory: string): Promise<void> {
  if (
    path.dirname(temporaryDirectory) !== parent ||
    !path.basename(temporaryDirectory).startsWith('.atlas-viewer-tmp-') ||
    samePath(parent, temporaryDirectory)
  ) throw new AtlasError('UNSAFE_TEMP_PATH', 'Refusing to remove an unsafe viewer temporary path.');
  await rm(temporaryDirectory, { recursive: true, force: true });
}

async function assertExpectedViewer(
  outputDirectory: string,
  expectedArtifacts: Map<string, Buffer>,
  expectedManifest: ViewerPublicationResult['manifest']
): Promise<void> {
  let summary;
  try {
    summary = await verifyRunViewer(outputDirectory);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new AtlasError('VIEWER_OUTPUT_CONFLICT', `Viewer output already exists but is not the expected bundle: ${message}`);
  }
  if (
    summary.viewerId !== expectedManifest.viewerId ||
    summary.sourceArtifactManifestSha256 !== expectedManifest.sourceArtifactManifestSha256
  ) {
    throw new AtlasError('VIEWER_OUTPUT_CONFLICT', 'Viewer output already contains a different deterministic viewer.');
  }
  for (const [name, expectedContent] of expectedArtifacts) {
    const observed = await readFile(path.join(outputDirectory, name));
    if (!observed.equals(expectedContent)) {
      throw new AtlasError('VIEWER_OUTPUT_CONFLICT', `Viewer output artifact differs from the deterministic bundle: ${name}`);
    }
  }
}

export async function createRunViewer(options: {
  runDirectory: string;
  workspacePath: string;
  targetConfigPath: string;
  outputDirectory: string;
}): Promise<ViewerPublicationResult> {
  const workspacePath = await resolveForContainment(options.workspacePath);
  const targetConfigPath = await realpath(path.resolve(options.targetConfigPath));
  const rawTarget = await readJson<unknown>(targetConfigPath);
  await assertSchema('target', rawTarget, 'Target configuration');
  const target = rawTarget as TargetConfig;
  if (!target.consent.export) {
    throw new AtlasError('VIEWER_EXPORT_NOT_AUTHORIZED', 'Target consent.export must be true before creating a portable viewer.');
  }
  const configuredTargetPath = path.isAbsolute(target.path)
    ? target.path
    : path.resolve(path.dirname(targetConfigPath), target.path);
  const targetRoot = await realpath(configuredTargetPath);
  const targetMetadata = await lstat(targetRoot);
  if (!targetMetadata.isDirectory()) throw new AtlasError('VIEWER_TARGET_INVALID', 'Viewer target root must be a directory.');
  if (isInside(targetRoot, workspacePath)) {
    throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Atlas viewer workspace must be outside the scanned target repository.');
  }

  const loaded = await loadRunArtifacts(options.runDirectory);
  const expectedRunDirectory = path.join(workspacePath, 'runs', loaded.run.runId);
  let canonicalRunDirectory: string;
  try {
    canonicalRunDirectory = await realpath(expectedRunDirectory);
  } catch {
    throw new AtlasError('VIEWER_RUN_MISMATCH', 'The selected run is not published in the selected workspace.');
  }
  if (!samePath(canonicalRunDirectory, expectedRunDirectory) || !samePath(canonicalRunDirectory, loaded.directory)) {
    throw new AtlasError('VIEWER_RUN_MISMATCH', 'Viewer creation requires the canonical run from the selected workspace.');
  }
  if (loaded.run.targetId !== target.id) {
    throw new AtlasError('VIEWER_TARGET_MISMATCH', 'Target descriptor does not match the selected run.');
  }
  await verifyTargetRegistrationBinding({
    workspacePath,
    targetId: target.id,
    targetRoot,
    targetConfigPath,
    consent: target.consent
  });
  const outputDirectory = await resolveForContainment(options.outputDirectory);
  if (isInside(targetRoot, outputDirectory)) {
    throw new AtlasError('VIEWER_OUTPUT_INSIDE_TARGET', 'Atlas viewer output must be outside the scanned target repository.');
  }

  const viewerData = buildViewerData(loaded);
  assertPortableDataSafe(viewerData, 'Viewer projection');
  const bundle = buildViewerBundle(viewerData);
  const publicationHealth = {
    sourceArtifactManifestSha256: viewerData.sourceArtifactManifestSha256,
    healthState: viewerData.analysisHealth.state,
    healthStatus: viewerData.analysisHealth.state === 'recorded'
      ? viewerData.analysisHealth.status
      : 'not-recorded' as const
  };
  if (await exists(outputDirectory)) {
    await assertExpectedViewer(outputDirectory, bundle.artifacts, bundle.manifest);
    return {
      directory: await realpath(outputDirectory),
      viewerId: bundle.manifest.viewerId,
      manifest: bundle.manifest,
      reused: true,
      ...publicationHealth
    };
  }

  const parent = path.dirname(outputDirectory);
  await mkdir(parent, { recursive: true });
  const canonicalParent = await realpath(parent);
  const canonicalOutputDirectory = path.join(canonicalParent, path.basename(outputDirectory));
  if (!samePath(canonicalOutputDirectory, outputDirectory) || isInside(targetRoot, canonicalOutputDirectory)) {
    throw new AtlasError('VIEWER_OUTPUT_PATH_ESCAPE', 'Viewer output parent changed during containment validation.');
  }
  const temporaryDirectory = path.join(canonicalParent, `.atlas-viewer-tmp-${randomUUID().replaceAll('-', '')}`);
  if (isInside(targetRoot, temporaryDirectory)) {
    throw new AtlasError('VIEWER_OUTPUT_INSIDE_TARGET', 'Atlas viewer temporary output must be outside the scanned target repository.');
  }
  let temporaryExists = false;
  try {
    await mkdir(temporaryDirectory, { recursive: false });
    temporaryExists = true;
    const names = [...bundle.artifacts.keys()].sort();
    for (const name of names) {
      await writeFile(path.join(temporaryDirectory, name), bundle.artifacts.get(name)!, { flag: 'wx' });
    }
    await verifyRunViewer(temporaryDirectory);
    if (await exists(canonicalOutputDirectory)) {
      await assertExpectedViewer(canonicalOutputDirectory, bundle.artifacts, bundle.manifest);
      await safeRemoveTemporary(canonicalParent, temporaryDirectory);
      temporaryExists = false;
      return {
        directory: await realpath(canonicalOutputDirectory),
        viewerId: bundle.manifest.viewerId,
        manifest: bundle.manifest,
        reused: true,
        ...publicationHealth
      };
    }
    try {
      await rename(temporaryDirectory, canonicalOutputDirectory);
      temporaryExists = false;
    } catch (error) {
      if (!(await exists(canonicalOutputDirectory))) throw error;
      await assertExpectedViewer(canonicalOutputDirectory, bundle.artifacts, bundle.manifest);
      await safeRemoveTemporary(canonicalParent, temporaryDirectory);
      temporaryExists = false;
      return {
        directory: await realpath(canonicalOutputDirectory),
        viewerId: bundle.manifest.viewerId,
        manifest: bundle.manifest,
        reused: true,
        ...publicationHealth
      };
    }
    const summary = await verifyRunViewer(canonicalOutputDirectory);
    if (summary.viewerId !== bundle.manifest.viewerId) {
      throw new AtlasError('VIEWER_IDENTITY_MISMATCH', 'Published viewer identity differs from the generated bundle.');
    }
    return {
      directory: await realpath(canonicalOutputDirectory),
      viewerId: bundle.manifest.viewerId,
      manifest: bundle.manifest,
      reused: false,
      ...publicationHealth
    };
  } finally {
    if (temporaryExists && await exists(temporaryDirectory)) {
      await safeRemoveTemporary(canonicalParent, temporaryDirectory);
    }
  }
}
