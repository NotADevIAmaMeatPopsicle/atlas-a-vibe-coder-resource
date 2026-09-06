import assert from 'node:assert/strict';
import test from 'node:test';
import ts from 'typescript';
import { analyzeJavaScriptTypeScript } from '../src/adapters/js-ts.js';
import { detectApiContractMismatches } from '../src/analysis/api-contracts.js';
import { detectCleanupCandidates } from '../src/analysis/cleanup.js';
import { detectDataContractMismatches } from '../src/analysis/data-contracts.js';
import { detectDeploymentContractMismatches } from '../src/analysis/deployment-contracts.js';
import { detectOperationalRisks } from '../src/analysis/operational-risks.js';
import { analyzeReachability } from '../src/analysis/reachability.js';
import { runIsolatedAnalysis } from '../src/analysis/isolated.js';
import type { AnalysisFile, ResolvedProfile } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { canonicalJson, sha256 } from '../src/util/canonical.js';
import { MAX_TYPESCRIPT_AST_NODES, parseBoundedTypeScript } from '../src/security/typescript-ast.js';

const PROFILE: ResolvedProfile = {
  schemaVersion: SCHEMA_VERSION,
  id: 'typescript-ast-limit-test',
  includeRoots: ['.'],
  exclude: [],
  entrypoints: [],
  aliases: {},
  envExampleFiles: [],
  platformRoots: [],
  deadCodeExemptions: [],
  lifecycleRules: [],
  maxFileBytes: 1_000_000
};

function analysisFile(filePath: string, source: string): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  return {
    content,
    record: {
      schemaVersion: SCHEMA_VERSION,
      id: `file_sha256_${sha256(canonicalJson({ filePath }))}`,
      path: filePath,
      sha256: sha256(content),
      bytes: content.length,
      kind: 'source',
      language: 'typescript',
      symbols: [],
      environmentVariables: [],
      lifecycle: {
        state: 'unspecified',
        basis: 'no-profile-match',
        uncertainty: 'not-runtime-validated',
        limitation: 'Test fixture.'
      },
      evidence: {
        level: 0,
        producer: 'atlas/test-fixture',
        producerVersion: '1',
        basis: 'fixture-source',
        path: filePath
      }
    }
  };
}

test('all internal JavaScript/TypeScript analyses abstain safely for a depth-limited AST', () => {
  const files = [analysisFile('src/deep.ts', `const value = root${'.child'.repeat(2_000)};\n`)];
  const adapter = analyzeJavaScriptTypeScript(files, PROFILE);
  assert.equal(adapter.diagnostics[0]?.code, 'TYPESCRIPT_AST_RESOURCE_LIMIT');

  assert.doesNotThrow(() => analyzeReachability(files, [], PROFILE));
  assert.doesNotThrow(() => detectApiContractMismatches(files, []));
  assert.doesNotThrow(() => detectCleanupCandidates(files, [], PROFILE));
  assert.doesNotThrow(() => detectDataContractMismatches(files));
  assert.doesNotThrow(() => detectDeploymentContractMismatches(files));
  assert.doesNotThrow(() => detectOperationalRisks(files, [], PROFILE));
});

test('all internal JavaScript/TypeScript analyses contain parser stack exhaustion', () => {
  const files = [analysisFile('src/deep.ts', `${'('.repeat(10_000)}0${')'.repeat(10_000)};\n`)];
  const adapter = analyzeJavaScriptTypeScript(files, PROFILE);
  assert.equal(adapter.diagnostics[0]?.code, 'TYPESCRIPT_AST_RESOURCE_LIMIT');

  assert.doesNotThrow(() => analyzeReachability(files, [], PROFILE));
  assert.doesNotThrow(() => detectApiContractMismatches(files, []));
  assert.doesNotThrow(() => detectCleanupCandidates(files, [], PROFILE));
  assert.doesNotThrow(() => detectDataContractMismatches(files));
  assert.doesNotThrow(() => detectDeploymentContractMismatches(files));
  assert.doesNotThrow(() => detectOperationalRisks(files, [], PROFILE));
});

test('the shared parser rejects a broad AST that exceeds its node budget', () => {
  const result = parseBoundedTypeScript(
    'src/broad.ts',
    ';'.repeat(MAX_TYPESCRIPT_AST_NODES + 1),
    ts.ScriptKind.TS
  );
  assert.deepEqual(result, { state: 'rejected', reason: 'ast-nodes' });
});

test('the supported scan analysis boundary parses untrusted source in a worker', async () => {
  const files = [analysisFile('src/deep.ts', `${'('.repeat(10_000)}0${')'.repeat(10_000)};\n`)];
  const result = await runIsolatedAnalysis(files, PROFILE, []);
  assert.equal(result.adapterResult.diagnostics[0]?.code, 'TYPESCRIPT_AST_RESOURCE_LIMIT');
  assert.equal(result.adapterResult.relationships.length, 0);
});
