import { once } from 'node:events';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { loadConfiguration } from './config.js';
import { AtlasError, errorDetails } from './errors.js';
import { discoverGitRepository } from './discovery/index.js';
import { profileDigest } from './identity.js';
import { queryLoadedRun } from './query.js';
import { assertSchema } from './schema-validator.js';
import { assertPortableDataSafe } from './security/portable-data.js';
import { buildSnapshot, verifyTargetUnchanged } from './snapshot.js';
import { verifyTargetRegistrationBinding } from './targets.js';
import type { MemoryLookupResult, SnapshotFileIdentity } from './types.js';
import { SCHEMA_VERSION } from './types.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';
import { resolveForContainment } from './util/paths.js';
import { verifyAndLoadRunDirectory, type VerifiedRunDirectoryResult } from './verify.js';

const MAX_QUERY_CHARACTERS = 4096;
const MAX_SERVICE_REQUEST_BYTES = 65_536;
const MAX_MEMORY_HITS = 100;

export interface MemoryScope {
  runDirectory: string;
  workspacePath: string;
  targetConfigPath: string;
  profilePath: string;
}

export interface MemoryServiceRequest {
  id: string;
  method: 'memory.lookup';
  params: {
    query: string;
    limit?: number;
  };
}

function samePath(left: string, right: string): boolean {
  return path.relative(path.resolve(left), path.resolve(right)) === '';
}

function normalizeQuery(value: string): string {
  const query = value.normalize('NFC').trim();
  if (!query || query.length > MAX_QUERY_CHARACTERS || /[\u0000-\u001f\u007f-\u009f]/u.test(query)) {
    throw new AtlasError('INVALID_MEMORY_QUERY', `Memory query must contain 1-${MAX_QUERY_CHARACTERS} printable characters.`);
  }
  return query;
}

function normalizeLimit(value: number | undefined): number {
  const limit = value ?? 20;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_MEMORY_HITS) {
    throw new AtlasError('INVALID_MEMORY_LIMIT', `Memory result limit must be between 1 and ${MAX_MEMORY_HITS}.`);
  }
  return limit;
}

function freshnessDiff(
  previousFiles: SnapshotFileIdentity[],
  currentFiles: SnapshotFileIdentity[]
): Pick<MemoryLookupResult['freshness'], 'addedPaths' | 'changedPaths' | 'removedPaths'> {
  const previous = new Map(previousFiles.map((file) => [file.path, file]));
  const current = new Map(currentFiles.map((file) => [file.path, file]));
  const addedPaths = [...current.keys()].filter((filePath) => !previous.has(filePath)).sort(compareCanonicalText);
  const removedPaths = [...previous.keys()].filter((filePath) => !current.has(filePath)).sort(compareCanonicalText);
  const changedPaths = [...current.entries()]
    .filter(([filePath, file]) => previous.has(filePath) && previous.get(filePath)!.sha256 !== file.sha256)
    .map(([filePath]) => filePath)
    .sort(compareCanonicalText);
  return { addedPaths, changedPaths, removedPaths };
}

type MemoryLookupOptions = MemoryScope & {
  query: string;
  limit?: number;
};

/** @internal Derives memory hits only from the exact run object verified by the caller. */
export async function lookupMemoryFromVerifiedRun(
  options: MemoryLookupOptions,
  verified: VerifiedRunDirectoryResult
): Promise<MemoryLookupResult> {
  const query = normalizeQuery(options.query);
  assertPortableDataSafe({ query }, 'Memory lookup request');
  const limit = normalizeLimit(options.limit);
  const workspacePath = await resolveForContainment(options.workspacePath);
  const loaded = verified.artifacts;
  const expectedRunDirectory = path.join(workspacePath, 'runs', loaded.run.runId);
  let canonicalRunDirectory: string;
  try {
    canonicalRunDirectory = await realpath(expectedRunDirectory);
  } catch {
    throw new AtlasError('MEMORY_RUN_MISMATCH', 'The selected run is not published in the selected workspace.');
  }
  if (!samePath(canonicalRunDirectory, expectedRunDirectory) || !samePath(canonicalRunDirectory, loaded.directory)) {
    throw new AtlasError('MEMORY_RUN_MISMATCH', 'Memory lookup requires the canonical run from the selected workspace.');
  }

  const configuration = await loadConfiguration(options.targetConfigPath, options.profilePath);
  if (
    configuration.target.id !== loaded.run.targetId ||
    configuration.profile.id !== loaded.run.profileId ||
    profileDigest(configuration.profile) !== loaded.run.profileDigest
  ) {
    throw new AtlasError('MEMORY_SCOPE_MISMATCH', 'Target or profile does not match the selected run.');
  }
  await verifyTargetRegistrationBinding({
    workspacePath,
    targetId: configuration.target.id,
    targetRoot: configuration.targetRoot,
    targetConfigPath: configuration.targetConfigPath,
    consent: configuration.target.consent
  });
  if (!configuration.target.consent.projectMemory) {
    throw new AtlasError('MEMORY_NOT_AUTHORIZED', 'Target consent.projectMemory must be true before serving project memory.');
  }

  const currentDiscovery = await discoverGitRepository(configuration.targetRoot);
  await assertSchema('git-discovery', currentDiscovery, 'Current Git discovery ledger');
  const current = await buildSnapshot(configuration.targetRoot, configuration.target.id, configuration.profile, currentDiscovery);
  await verifyTargetUnchanged(current.files);
  const currentDiscoveryDigest = sha256(canonicalJson(currentDiscovery));
  const differences = freshnessDiff(loaded.snapshot.files, current.snapshot.files);
  const freshnessReasons: MemoryLookupResult['freshness']['reasons'] = [];
  if (loaded.snapshot.snapshotId !== current.snapshot.snapshotId) freshnessReasons.push('snapshot-bytes');
  if (loaded.run.discovery.digest !== currentDiscoveryDigest) freshnessReasons.push('git-provenance');
  const status = freshnessReasons.length ? 'stale' : 'current';
  const queryResult = await queryLoadedRun(loaded, query, limit + 1);
  const hits = queryResult.hits.slice(0, limit);
  const truncated = queryResult.hits.length > limit;
  const unsupportedDiagnosticCodes = [...new Set(loaded.diagnostics
    .map((diagnostic) => diagnostic.code)
    .filter((code) => /(UNSUPPORTED|DYNAMIC|PARSE|LIMIT|SKIPPED|UNRESOLVED)/u.test(code)))]
    .sort(compareCanonicalText);
  const boundaryDiagnosticCodes = [...new Set(loaded.snapshot.boundaryDiagnostics.map((entry) => entry.code))]
    .sort(compareCanonicalText);
  const answerText = hits.length === 0
    ? 'No cited Atlas records matched this query in the selected run. This is an abstention, not evidence that the concept is absent.'
    : `Found ${hits.length} cited Atlas record${hits.length === 1 ? '' : 's'} in the selected run.${status === 'stale' ? ' The run is stale relative to current target bytes; re-scan before treating these records as current.' : ''}`;
  const result: MemoryLookupResult = {
    schemaVersion: SCHEMA_VERSION,
    targetId: loaded.run.targetId,
    runId: loaded.run.runId,
    snapshotId: loaded.snapshot.snapshotId,
    query,
    answer: { kind: hits.length ? 'matches' : 'abstention', text: answerText },
    freshness: {
      status,
      currentSnapshotId: current.snapshot.snapshotId,
      currentDiscoveryDigest,
      reasons: freshnessReasons,
      ...differences
    },
    coverage: {
      files: loaded.files.length,
      relationships: loaded.relationships.length,
      findings: loaded.findings.length,
      diagnostics: loaded.diagnostics.length,
      boundaryDiagnosticCodes,
      unsupportedDiagnosticCodes,
      discoveryState: loaded.discovery.state,
      discoveryDiagnosticCodes: [...new Set(loaded.discovery.diagnostics.map((entry) => entry.code))]
        .sort(compareCanonicalText)
    },
    authorization: {
      scope: 'registered-local-target',
      projectMemoryConsent: true,
      sourceContentIncluded: false,
      secretValuesCollected: false
    },
    hits,
    truncated
  };
  await assertSchema('memory-lookup', result, 'Memory lookup response');
  assertPortableDataSafe(result, 'Memory lookup response');
  return result;
}

export async function lookupMemory(options: MemoryLookupOptions): Promise<MemoryLookupResult> {
  const verified = await verifyAndLoadRunDirectory(options.runDirectory);
  return lookupMemoryFromVerifiedRun(options, verified);
}

function assertRequest(value: unknown): asserts value is MemoryServiceRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory request must be a JSON object.');
  }
  const request = value as Record<string, unknown>;
  const keys = Object.keys(request).sort(compareCanonicalText);
  if (canonicalJson(keys) !== canonicalJson(['id', 'method', 'params'].sort(compareCanonicalText))) {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory request must contain exactly id, method, and params.');
  }
  if (typeof request.id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/u.test(request.id)) {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory request id is invalid.');
  }
  if (request.method !== 'memory.lookup') {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Only memory.lookup is supported.');
  }
  if (!request.params || typeof request.params !== 'object' || Array.isArray(request.params)) {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory request params must be an object.');
  }
  const params = request.params as Record<string, unknown>;
  const paramKeys = Object.keys(params).sort(compareCanonicalText);
  if (paramKeys.some((key) => key !== 'limit' && key !== 'query') || !paramKeys.includes('query')) {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory params require query and may contain only limit.');
  }
  if (typeof params.query !== 'string') throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory query must be a string.');
  if (params.limit !== undefined && typeof params.limit !== 'number') {
    throw new AtlasError('INVALID_MEMORY_REQUEST', 'Memory limit must be a number.');
  }
}

export async function handleMemoryServiceRequest(
  scope: MemoryScope,
  value: unknown
): Promise<{ id: string; result: MemoryLookupResult }> {
  assertRequest(value);
  return {
    id: value.id,
    result: await lookupMemory({
      ...scope,
      query: value.params.query,
      ...(value.params.limit === undefined ? {} : { limit: value.params.limit })
    })
  };
}

async function writeServiceLine(output: Writable, value: unknown): Promise<void> {
  if (!output.write(`${canonicalJson(value)}\n`, 'utf8')) await once(output, 'drain');
}

async function processServiceLine(scope: MemoryScope, output: Writable, line: Buffer): Promise<void> {
  const normalizedLine = line.length && line[line.length - 1] === 0x0d ? line.subarray(0, -1) : line;
  if (!normalizedLine.length) return;
  let request: unknown;
  try {
    request = JSON.parse(normalizedLine.toString('utf8')) as unknown;
    await writeServiceLine(output, await handleMemoryServiceRequest(scope, request));
  } catch (error) {
    const candidateId = request && typeof request === 'object' && !Array.isArray(request) &&
      typeof (request as Record<string, unknown>).id === 'string'
      ? (request as Record<string, unknown>).id
      : null;
    await writeServiceLine(output, { id: candidateId, error: errorDetails(error) });
  }
}

export async function runMemoryStdioService(
  scope: MemoryScope,
  input: Readable = process.stdin,
  output: Writable = process.stdout
): Promise<void> {
  let pending = Buffer.alloc(0);
  let discardingOversizedLine = false;
  for await (const rawChunk of input) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(String(rawChunk));
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(0x0a, offset);
      const end = newline === -1 ? chunk.length : newline;
      const segment = chunk.subarray(offset, end);
      if (!discardingOversizedLine) {
        if (pending.length + segment.length > MAX_SERVICE_REQUEST_BYTES) {
          pending = Buffer.alloc(0);
          await writeServiceLine(output, {
            id: null,
            error: { code: 'MEMORY_REQUEST_TOO_LARGE', message: `Memory request exceeds ${MAX_SERVICE_REQUEST_BYTES} bytes.` }
          });
          discardingOversizedLine = newline === -1;
        } else {
          pending = Buffer.concat([pending, segment]);
        }
      }
      if (newline !== -1) {
        if (!discardingOversizedLine) await processServiceLine(scope, output, pending);
        pending = Buffer.alloc(0);
        discardingOversizedLine = false;
        offset = newline + 1;
      } else {
        offset = chunk.length;
      }
    }
  }
  if (!discardingOversizedLine && pending.length) await processServiceLine(scope, output, pending);
}
