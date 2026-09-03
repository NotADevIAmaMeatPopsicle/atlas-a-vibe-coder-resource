export type GitDiscoveryState = 'ready' | 'partial' | 'not-git' | 'unsupported';

export type GitDiscoverySeverity = 'info' | 'warning' | 'error';

export interface GitDiscoveryDiagnostic {
  code: string;
  severity: GitDiscoverySeverity;
  message: string;
  path?: string;
}

export type GitHeadState = 'attached' | 'detached' | 'unborn';

export interface GitHeadRecord {
  state: GitHeadState;
  objectId?: string;
  branch?: string;
}

export interface GitRepositoryRecord {
  root: '.';
  objectFormat: 'sha1' | 'sha256';
  head: GitHeadRecord;
}

export type GitTrackingState = 'tracked' | 'untracked' | 'ignored';
export type GitPathKind = 'file' | 'directory' | 'gitlink';
export type GitDeltaState =
  | 'clean'
  | 'added'
  | 'modified'
  | 'deleted'
  | 'renamed'
  | 'copied'
  | 'type-changed'
  | 'unmerged'
  | 'untracked'
  | 'ignored'
  | 'unknown';

export interface GitIndexEntry {
  mode: string;
  objectId: string;
  stage: 0 | 1 | 2 | 3;
}

export interface GitPathRecord {
  path: string;
  kind: GitPathKind;
  tracking: GitTrackingState;
  indexStatus: GitDeltaState;
  worktreeStatus: GitDeltaState;
  conflicted: boolean;
  indexEntries: GitIndexEntry[];
  originalPath?: string;
  similarity?: number;
}

export interface GitDiscoveryResult {
  schemaVersion: 1;
  provider: 'git';
  state: GitDiscoveryState;
  repository?: GitRepositoryRecord;
  records: GitPathRecord[];
  diagnostics: GitDiscoveryDiagnostic[];
}

export interface GitDiscoveryOptions {
  /** Maximum stdout bytes accepted from any single fixed Git query. */
  maxOutputBytes?: number;
  /** Maximum number of portable path records returned. */
  maxRecords?: number;
  /** Per-command execution limit. */
  timeoutMs?: number;
}
