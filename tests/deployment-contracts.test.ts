import assert from 'node:assert/strict';
import test from 'node:test';
import {
  detectDeploymentContractMismatches,
  MAX_DEPLOYMENT_CONTRACT_OBSERVATIONS
} from '../src/analysis/deployment-contracts.js';
import type { AnalysisFile, EvidenceReference, FileKind, FileRecord } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { canonicalJson, sha256 } from '../src/util/canonical.js';

function languageFor(filePath: string): string {
  const lower = filePath.toLowerCase();
  const basename = lower.split('/').at(-1)!;
  if (/^\.env(?:\..+)?\.(?:example|template)$/u.test(basename)) return 'dotenv-template';
  if (lower.endsWith('.ts')) return 'typescript';
  if (lower.endsWith('.js')) return 'javascript';
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml';
  if (lower.endsWith('.tf')) return 'tf';
  return 'unknown';
}

function analysisFile(filePath: string, source: string): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  const evidence: EvidenceReference = {
    level: 0,
    producer: 'atlas/test-fixture',
    producerVersion: '1',
    basis: 'fixture-source',
    path: filePath
  };
  const kind: FileKind = /\.[cm]?[jt]sx?$/iu.test(filePath) ? 'source' : 'configuration';
  const record: FileRecord = {
    schemaVersion: SCHEMA_VERSION,
    id: `file:${sha256(filePath).slice(0, 24)}`,
    path: filePath,
    sha256: sha256(content),
    bytes: content.length,
    kind,
    language: languageFor(filePath),
    symbols: [],
    environmentVariables: [],
    lifecycle: {
      state: 'unspecified',
      basis: 'no-profile-match',
      uncertainty: 'not-runtime-validated',
      limitation: 'No profile lifecycle path rule matched this file; runtime deployment, traffic, and use were not evaluated.'
    },
    evidence
  };
  return { record, content };
}

test('literal application, deployment, workflow, and Terraform names produce useful missing and unused candidates', () => {
  const files = [
    analysisFile('src/config.ts', [
      'export const port = process.env.APP_PORT;',
      "export const compose = process.env['COMPOSE_ONLY'];",
      'export const missing = process.env.MISSING_JS;',
      ''
    ].join('\n')),
    analysisFile('.env.example', [
      'APP_PORT=env-value-never-returned',
      'HOST_APP_PORT=host-value-never-returned',
      'UNUSED_ENV=unused-value-never-returned',
      ''
    ].join('\n')),
    analysisFile('Dockerfile', [
      'ARG BUILD_VERSION=build-default-never-returned',
      'ENV COMPOSE_ONLY=container-value-never-returned',
      'RUN echo "$BUILD_VERSION" "$MISSING_DOCKER"',
      ''
    ].join('\n')),
    analysisFile('compose.yaml', [
      'services:',
      '  app:',
      '    environment:',
      '      APP_PORT: ${HOST_APP_PORT}',
      ''
    ].join('\n')),
    analysisFile('.github/workflows/ci.yml', [
      'name: CI',
      'env:',
      '  CI_MODE: workflow-value-never-returned',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ env.CI_MODE }} ${{ env.MISSING_CI }}"',
      ''
    ].join('\n')),
    analysisFile('infra/main.tf', [
      'variable "region" {}',
      'variable "unused_tf" { default = "terraform-value-never-returned" }',
      'output "region" { value = var.region }',
      'output "missing" { value = var.missing_tf }',
      ''
    ].join('\n'))
  ];

  const result = detectDeploymentContractMismatches(files);
  assert.deepEqual(detectDeploymentContractMismatches([...files].reverse()), result);
  assert.deepEqual(result.diagnostics, []);
  assert.deepEqual(
    result.findings.map((finding) => [finding.ruleId, finding.title]).sort((left, right) => left[1]!.localeCompare(right[1]!)),
    [
      ['contract/deployment-env-missing-declaration-v1', 'Deployment environment name has no literal declaration: MISSING_CI'],
      ['contract/deployment-env-missing-declaration-v1', 'Deployment environment name has no literal declaration: MISSING_DOCKER'],
      ['contract/deployment-env-missing-declaration-v1', 'Deployment environment name has no literal declaration: MISSING_JS'],
      ['contract/deployment-env-unused-declaration-v1', 'Deployment environment declaration has no literal consumer: UNUSED_ENV'],
      ['contract/terraform-variable-missing-declaration-v1', 'Terraform variable has no literal declaration: missing_tf'],
      ['contract/terraform-variable-unused-declaration-v1', 'Terraform declaration has no supported literal var. consumer: unused_tf']
    ].sort((left, right) => left[1]!.localeCompare(right[1]!))
  );
  for (const finding of result.findings) {
    assert.equal(finding.category, 'contract-mismatch');
    assert.equal(finding.status, 'candidate');
    assert(finding.evidence.length > 0);
    assert(finding.evidence.every((entry) => entry.path && entry.line && entry.column));
  }
});

test('unused Terraform declarations remain interface drift when naming variants exist', () => {
  const result = detectDeploymentContractMismatches([
    analysisFile('infra/variables.tf', 'variable "db_pool_max" {}\n'),
    analysisFile('.env.example', 'DB_POOL_MAX_SIZE=value-never-returned\n')
  ]);
  const finding = result.findings.find(
    (entry) => entry.ruleId === 'contract/terraform-variable-unused-declaration-v1'
  );
  assert(finding);
  assert(finding.signals.includes('capability-status-not-inferred'));
  assert(finding.signals.includes('naming-variant-counter-evidence'));
  assert.match(finding.description, /does not establish that the underlying capability is inert/u);
  assert.match(finding.nextValidation, /SSM or secret parameter paths/u);
});

test('exact literal declarations and references match across every supported source family', () => {
  const files = [
    analysisFile('src/config.js', [
      'console.log(process.env.APP_NAME);',
      'console.log(process.env.CONTAINER_MODE);',
      ''
    ].join('\n')),
    analysisFile('.env.template', 'APP_NAME=application\n'),
    analysisFile('Dockerfile.production', [
      'ARG RELEASE_TAG=latest',
      'ENV CONTAINER_MODE=production',
      'RUN echo "$RELEASE_TAG"',
      ''
    ].join('\n')),
    analysisFile('docker-compose.prod.yml', [
      'services:',
      '  app:',
      '    environment:',
      '      COMPOSE_TOKEN: ${COMPOSE_TOKEN}',
      ''
    ].join('\n')),
    analysisFile('.github/workflows/deploy.yaml', [
      'env:',
      '  DEPLOY_ENV: production',
      'jobs:',
      '  deploy:',
      '    steps:',
      '      - run: echo "${{ env.DEPLOY_ENV }}"',
      ''
    ].join('\n')),
    analysisFile('infra/variables.tf', [
      'variable "image_tag" {}',
      'output "image_tag" { value = "${var.image_tag}" }',
      ''
    ].join('\n'))
  ];

  assert.deepEqual(detectDeploymentContractMismatches(files), { findings: [], diagnostics: [] });
});

test('Vite-style import.meta.env consumers are literal-only and source anchored', () => {
  const literal = detectDeploymentContractMismatches([
    analysisFile('src/client.ts', [
      'console.log(import.meta.env.VITE_PRESENT);',
      "console.log(import.meta.env['VITE_MISSING']);",
      ''
    ].join('\n')),
    analysisFile('.env.example', 'VITE_PRESENT=value-never-returned\n')
  ]);
  assert.deepEqual(literal.diagnostics, []);
  assert.deepEqual(literal.findings.map((entry) => entry.title), [
    'Deployment environment name has no literal declaration: VITE_MISSING'
  ]);
  assert(literal.findings[0]?.signals.includes('javascript-import-meta-env'));
  assert.equal(literal.findings[0]?.evidence[0]?.path, 'src/client.ts');

  const computed = detectDeploymentContractMismatches([
    analysisFile('src/client.ts', [
      'const key = getKey();',
      'console.log(import.meta.env[key]);',
      'console.log(import.meta.env.VITE_OTHER);',
      ''
    ].join('\n'))
  ]);
  assert.deepEqual(computed.findings, []);
  assert(computed.diagnostics.some((entry) => entry.code === 'DEPLOYMENT_CONTRACT_DYNAMIC_IMPORT_META_ENV_ACCESS'));
});

test('computed names and uncertain mappings emit diagnostics and suppress mismatch claims', () => {
  const files = [
    analysisFile('src/dynamic.ts', [
      'const key = getKey();',
      'console.log(process.env[key]);',
      'console.log(process.env.LITERAL_WITHOUT_DECLARATION);',
      ''
    ].join('\n')),
    analysisFile('.env.example', 'ORPHAN_DECLARATION=value\n'),
    analysisFile('Dockerfile', 'RUN echo "${!PREFIX}"\n'),
    analysisFile('compose.yaml', [
      'services:',
      '  app:',
      '    environment: { STATIC_NAME: value }',
      ''
    ].join('\n')),
    analysisFile('.github/workflows/ci.yml', [
      'env:',
      '  STATIC_CI: value',
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: echo "${{ env[matrix.name] }}"',
      ''
    ].join('\n')),
    analysisFile('infra/main.tf', [
      'variable "unused" {}',
      'output "dynamic" { value = var[local.variable_name] }',
      ''
    ].join('\n'))
  ];

  const result = detectDeploymentContractMismatches(files);
  assert.deepEqual(result.findings, []);
  const codes = new Set(result.diagnostics.map((entry) => entry.code));
  assert(codes.has('DEPLOYMENT_CONTRACT_DYNAMIC_ENV_ACCESS'));
  assert(codes.has('DEPLOYMENT_CONTRACT_DYNAMIC_DOCKER_REFERENCE'));
  assert(codes.has('DEPLOYMENT_CONTRACT_UNSUPPORTED_COMPOSE_ENVIRONMENT'));
  assert(codes.has('DEPLOYMENT_CONTRACT_DYNAMIC_WORKFLOW_ENV_REFERENCE'));
  assert(codes.has('DEPLOYMENT_CONTRACT_DYNAMIC_TERRAFORM_VARIABLE'));
});

test('results retain contract names and source anchors but never deployment values', () => {
  const secrets = [
    'dotenv-secret-7f2f',
    'docker-secret-91ac',
    'compose-secret-33bd',
    'workflow-secret-b712',
    'terraform-secret-c049'
  ];
  const files = [
    analysisFile('.env.example', `UNUSED_DOTENV=${secrets[0]}\n`),
    analysisFile('Dockerfile', `ARG UNUSED_ARG=${secrets[1]}\n`),
    analysisFile('compose.yml', [
      'services:',
      '  app:',
      '    environment:',
      `      UNUSED_COMPOSE: ${secrets[2]}`,
      ''
    ].join('\n')),
    analysisFile('.github/workflows/ci.yml', [
      'env:',
      `  UNUSED_WORKFLOW: ${secrets[3]}`,
      ''
    ].join('\n')),
    analysisFile('infra/main.tf', `variable "unused_tf" { default = "${secrets[4]}" }\n`)
  ];

  const result = detectDeploymentContractMismatches(files);
  const serialized = canonicalJson(result);
  for (const secret of secrets) assert(!serialized.includes(secret));
  for (const name of ['UNUSED_DOTENV', 'UNUSED_ARG', 'UNUSED_COMPOSE', 'UNUSED_WORKFLOW', 'unused_tf']) {
    assert(serialized.includes(name));
  }
});

test('deployment observation limits suppress all partial mismatch claims', () => {
  const exactSource = `${'SAME_NAME=value\n'.repeat(MAX_DEPLOYMENT_CONTRACT_OBSERVATIONS)}`;
  const exact = detectDeploymentContractMismatches([analysisFile('.env.example', exactSource)]);
  assert.equal(exact.diagnostics.some((entry) => entry.code === 'DEPLOYMENT_CONTRACT_RESOURCE_LIMIT'), false);
  assert.equal(exact.findings.length, 1);

  const over = detectDeploymentContractMismatches([
    analysisFile('.env.example', `${exactSource}ONE_TOO_MANY=value\n`)
  ]);
  assert.equal(over.findings.length, 0);
  assert.equal(over.diagnostics.filter((entry) => entry.code === 'DEPLOYMENT_CONTRACT_RESOURCE_LIMIT').length, 1);
});

test('cached deployment anchors preserve CRLF line and column coordinates', () => {
  const result = detectDeploymentContractMismatches([
    analysisFile('.env.example', 'FIRST=one\r\nSECOND=two\r\n')
  ]);
  const second = result.findings.find((entry) => entry.title.includes('SECOND'));
  assert.equal(second?.evidence[0]?.line, 2);
  assert.equal(second?.evidence[0]?.column, 1);
});
