import type { ProfileConfig, RunRecord, SnapshotRecord } from './types.js';
import { canonicalJson, sha256 } from './util/canonical.js';

export function profileDigest(profile: ProfileConfig): string {
  return sha256(canonicalJson(profile));
}

export function snapshotIdentity(snapshot: Omit<SnapshotRecord, 'snapshotId'>): string {
  return `snapshot_sha256_${sha256(canonicalJson({ domain: 'atlas.snapshot.v1', ...snapshot }))}`;
}

export interface RunIdentityInput {
  snapshotId: string;
  targetId: string;
  profileId: string;
  profileDigest: string;
  tool: RunRecord['tool'];
  adapters: RunRecord['adapters'];
  discovery: RunRecord['discovery'];
  analyses: string[];
}

export function runIdentity(input: RunIdentityInput): string {
  return `run_sha256_${sha256(canonicalJson({ domain: 'atlas.run.v1', ...input }))}`;
}
