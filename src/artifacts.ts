import { verifyAndLoadRunDirectory, type VerifiedRunArtifacts } from './verify.js';

export type LoadedRun = VerifiedRunArtifacts;

export type LoadedRunWithManifest = LoadedRun & {
  sourceArtifactManifestSha256: string;
};

export async function loadRunArtifacts(runDirectoryValue: string): Promise<LoadedRunWithManifest> {
  const verified = await verifyAndLoadRunDirectory(runDirectoryValue);
  return {
    ...verified.artifacts,
    sourceArtifactManifestSha256: verified.manifestSha256
  };
}
