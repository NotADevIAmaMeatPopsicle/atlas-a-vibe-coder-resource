import assert from 'node:assert/strict';
import test from 'node:test';
import { detectDataContractMismatches } from '../src/analysis/data-contracts.js';
import type { AnalysisFile, EvidenceReference, FileRecord } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { assertSchema } from '../src/schema-validator.js';
import { canonicalJson, sha256 } from '../src/util/canonical.js';

function analysisFile(filePath: string, source: string): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  const evidence: EvidenceReference = {
    level: 0,
    producer: 'atlas/test-fixture',
    producerVersion: '1',
    basis: 'fixture-source',
    path: filePath
  };
  const record: FileRecord = {
    schemaVersion: SCHEMA_VERSION,
    id: `file:${sha256(filePath).slice(0, 24)}`,
    path: filePath,
    sha256: sha256(content),
    bytes: content.length,
    kind: 'configuration',
    language: filePath.endsWith('.prisma')
      ? 'prisma'
      : /\.(?:ts|mts|cts)$/u.test(filePath)
        ? 'typescript'
        : /\.(?:js|mjs|cjs)$/u.test(filePath)
          ? 'javascript'
          : 'sql',
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

test('literal Prisma and SQL declarations expose missing-column, type-family, and nullability drift', async () => {
  const prisma = analysisFile('prisma/schema.prisma', [
    'model User {',
    '  id       Int',
    '  email    String',
    '  bio      String?',
    '  nickname String @map("display_name")',
    '',
    '  @@map("users")',
    '}',
    ''
  ].join('\n'));
  const sql = analysisFile('migrations/001_users.sql', [
    'CREATE TABLE "users" (',
    '  "id" INTEGER NOT NULL,',
    '  "email" BOOLEAN NOT NULL,',
    '  "bio" TEXT NOT NULL,',
    '  "legacy" TEXT NULL',
    ');',
    ''
  ].join('\n'));

  const result = detectDataContractMismatches([prisma, sql]);
  assert.deepEqual(detectDataContractMismatches([sql, prisma]), result);
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'contract/data-column-missing-v1',
    'contract/data-nullability-v1',
    'contract/data-type-family-v1'
  ]);
  const byRule = new Map(result.findings.map((finding) => [finding.ruleId, finding]));
  assert.deepEqual(byRule.get('contract/data-column-missing-v1')?.subject, {
    kind: 'data-contract',
    table: 'users',
    column: 'display_name',
    dimension: 'column-presence',
    model: 'prisma',
    storage: 'sql'
  });
  assert.deepEqual(byRule.get('contract/data-type-family-v1')?.subject, {
    kind: 'data-contract',
    table: 'users',
    column: 'email',
    dimension: 'type-family',
    model: 'prisma',
    storage: 'sql'
  });
  assert.deepEqual(byRule.get('contract/data-nullability-v1')?.subject, {
    kind: 'data-contract',
    table: 'users',
    column: 'bio',
    dimension: 'nullability',
    model: 'prisma',
    storage: 'sql'
  });
  assert.equal(result.diagnostics.length, 0);
  for (const finding of result.findings) {
    assert.equal(finding.category, 'contract-mismatch');
    assert.equal(finding.status, 'candidate');
    assert(finding.evidence.length >= 2);
    assert(finding.evidence.every((entry) => entry.path && entry.line && entry.column));
    await assertSchema('finding', finding, 'Prisma data-contract finding');
  }
  await assert.rejects(
    assertSchema(
      'finding',
      { ...result.findings[0]!, ruleId: 'architecture/not-a-data-contract-v1' },
      'Invalid subject-bearing finding'
    ),
    /ruleId.*pattern/u
  );
  assert(!canonicalJson(result).includes('legacy'));
});

test('equivalent broad scalar families and optionality do not produce drift findings', () => {
  const files = [
    analysisFile('prisma/schema.prisma', [
      'model Account {',
      '  id        Int',
      '  email     String?',
      '  active    Boolean',
      '  createdAt DateTime @map("created_at")',
      '  publicId  String @db.Uuid @map("public_id")',
      '',
      '  @@map("accounts")',
      '}',
      ''
    ].join('\n')),
    analysisFile('migrations/001_accounts.sql', [
      'CREATE TABLE accounts (',
      '  id BIGINT NOT NULL,',
      '  email VARCHAR(320) NULL,',
      '  active BOOL NOT NULL,',
      '  created_at TIMESTAMPTZ NOT NULL,',
      '  public_id UUID NOT NULL',
      ');',
      ''
    ].join('\n'))
  ];

  assert.deepEqual(detectDataContractMismatches(files), { findings: [], diagnostics: [] });
});

test('dynamic mappings and unsupported DDL produce diagnostics while suppressing mismatch claims', () => {
  const files = [
    analysisFile('prisma/schema.prisma', [
      'model DynamicAccount {',
      '  id Int',
      '  @@map(env("ACCOUNT_TABLE"))',
      '}',
      '',
      'model GeneratedAccount {',
      '  id Int',
      '  @@map("generated_accounts")',
      '}',
      ''
    ].join('\n')),
    analysisFile('migrations/001_dynamic.sql', [
      'CREATE TABLE DynamicAccount (id TEXT NULL);',
      'CREATE TABLE generated_accounts AS SELECT id FROM source_accounts;',
      'CREATE TABLE ${runtime_table} (id INTEGER NOT NULL);',
      ''
    ].join('\n'))
  ];

  const result = detectDataContractMismatches(files);
  assert.deepEqual(result.findings, []);
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_DYNAMIC_PRISMA_MAPPING'));
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_UNSUPPORTED_SQL_DDL'));
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_DYNAMIC_SQL_MAPPING'));
});

test('literal Sequelize define and createTable contracts expose mapping, type, nullability, default, enum, and missing-column drift without retaining values', async () => {
  const model = analysisFile('src/models/user.model.js', [
    "module.exports = (sequelize, DataTypes) => sequelize.define('User', {",
    "  id: { type: DataTypes.INTEGER, allowNull: false },",
    "  displayName: { type: DataTypes.STRING, allowNull: false, field: 'display_name' },",
    "  status: { type: DataTypes.ENUM('model-secret-a', 'model-secret-b'), allowNull: false, defaultValue: 'model-secret-a' },",
    "  handle: { type: DataTypes.STRING, allowNull: true, field: 'handle_text' },",
    "  orphan: { type: DataTypes.TEXT, allowNull: true }",
    "}, { tableName: 'users', schema: 'fct', underscored: false });",
    ''
  ].join('\n'));
  const migration = analysisFile('src/migrations/20260821000100-create-users.js', [
    'module.exports = {',
    '  async up(queryInterface, Sequelize) {',
    "    await queryInterface.createTable({ tableName: 'users', schema: 'fct' }, {",
    '      id: { type: Sequelize.BIGINT, allowNull: false },',
    '      display_name: { type: Sequelize.BOOLEAN, allowNull: true },',
    "      status: { type: Sequelize.ENUM('model-secret-a', 'db-secret-c'), allowNull: false, defaultValue: 'db-secret-c' },",
    '      handle: { type: Sequelize.STRING, allowNull: true }',
    '    });',
    '  },',
    '  async down(queryInterface) {',
    "    await queryInterface.removeColumn({ tableName: 'users', schema: 'fct' }, 'id');",
    '  }',
    '};',
    ''
  ].join('\n'));

  const result = detectDataContractMismatches([migration, model]);
  assert.deepEqual(detectDataContractMismatches([model, migration]), result);
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'contract/data-column-mapping-v1',
    'contract/data-column-missing-v1',
    'contract/data-default-v1',
    'contract/data-enum-v1',
    'contract/data-nullability-v1',
    'contract/data-type-family-v1'
  ]);
  const byRule = new Map(result.findings.map((finding) => [finding.ruleId, finding]));
  assert.deepEqual(byRule.get('contract/data-column-mapping-v1')?.subject, {
    kind: 'data-contract',
    table: 'fct.users',
    column: 'handle_text',
    dimension: 'column-mapping',
    model: 'sequelize',
    storage: 'sequelize-migration'
  });
  assert.deepEqual(byRule.get('contract/data-enum-v1')?.subject, {
    kind: 'data-contract',
    table: 'fct.users',
    column: 'status',
    dimension: 'enum-members',
    model: 'sequelize',
    storage: 'sequelize-migration'
  });
  assert.deepEqual(byRule.get('contract/data-type-family-v1')?.subject, {
    kind: 'data-contract',
    table: 'fct.users',
    column: 'display_name',
    dimension: 'type-family',
    model: 'sequelize',
    storage: 'sequelize-migration'
  });
  assert.deepEqual(result.diagnostics, []);
  const serialized = canonicalJson(result);
  for (const sensitiveValue of ['model-secret-a', 'model-secret-b', 'db-secret-c']) assert(!serialized.includes(sensitiveValue));
  for (const finding of result.findings) {
    assert(finding.evidence.every((entry) => entry.path && entry.line && entry.column));
    await assertSchema('finding', finding, 'Sequelize data-contract finding');
  }
});

test('Sequelize Model.init and createTable exact contracts normalize primary keys, field mappings, defaults, and enum sets', () => {
  const files = [
    analysisFile('src/models/account.model.ts', [
      'class Account extends Model {}',
      'Account.init({',
      '  id: { type: DataTypes.INTEGER, primaryKey: true },',
      "  displayName: { type: DataTypes.STRING(100), allowNull: true, field: 'display_name' },",
      "  status: { type: DataTypes.ENUM('ready', 'paused'), allowNull: false, defaultValue: 'ready' }",
      "}, { sequelize, tableName: 'accounts', schema: 'dim', underscored: true });",
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821000200-create-accounts.ts', [
      'export async function up(queryInterface, Sequelize) {',
      "  await queryInterface.createTable('accounts', {",
      '    id: { type: Sequelize.BIGINT, primaryKey: true },',
      '    display_name: { type: Sequelize.TEXT, allowNull: true },',
      "    status: { type: Sequelize.ENUM('paused', 'ready'), allowNull: false, defaultValue: 'ready' }",
      "  }, { schema: 'dim' });",
      '}',
      ''
    ].join('\n'))
  ];

  assert.deepEqual(detectDataContractMismatches(files), { findings: [], diagnostics: [] });
});

test('model-storage enum drift and provisioning-path drift remain independent', async () => {
  const model = analysisFile('src/models/job.js', [
    "module.exports = (sequelize, DataTypes) => sequelize.define('Job', {",
    "  status: { type: DataTypes.STRING, allowNull: false }",
    "}, { tableName: 'jobs' });",
    ''
  ].join('\n'));
  const migration = analysisFile('src/migrations/001-jobs.js', [
    'module.exports = { async up(queryInterface, Sequelize) {',
    "  await queryInterface.createTable('jobs', {",
    "    status: { type: Sequelize.ENUM('queued', 'done'), allowNull: false }",
    '  });',
    '} };',
    ''
  ].join('\n'));
  const unconstrainedBootstrap = analysisFile('docker/init.sql', [
    'CREATE TABLE jobs (',
    '  status VARCHAR(32) NOT NULL',
    ');',
    ''
  ].join('\n'));

  const result = detectDataContractMismatches([unconstrainedBootstrap, migration, model]);
  assert(result.findings.some((finding) => finding.ruleId === 'contract/data-enum-v1'));
  const provisioning = result.findings.find(
    (finding) => finding.ruleId === 'contract/data-provisioning-path-enum-v1'
  );
  assert(provisioning);
  assert.equal(provisioning.severity, 'low');
  assert.match(provisioning.description, /independent from the application-model-to-storage contract/u);
  assert.deepEqual(provisioning.subject, {
    kind: 'data-contract',
    table: 'jobs',
    column: 'status',
    dimension: 'enum-members',
    comparison: 'provisioning-path',
    migration: 'sequelize-migration',
    bootstrap: 'sql-bootstrap'
  });
  await assertSchema('finding', provisioning, 'Provisioning-path finding');

  const constrainedBootstrap = analysisFile('docker/init.sql', [
    'CREATE TABLE jobs (',
    "  status VARCHAR(32) NOT NULL CHECK (status IN ('queued', 'done'))",
    ');',
    ''
  ].join('\n'));
  const aligned = detectDataContractMismatches([constrainedBootstrap, migration, model]);
  assert(!aligned.findings.some((finding) => finding.ruleId === 'contract/data-provisioning-path-enum-v1'));
});

test('provisioning-path enum drift does not require an application model', () => {
  const migration = analysisFile('src/migrations/001-jobs.js', [
    'module.exports = { async up(queryInterface, Sequelize) {',
    "  await queryInterface.createTable('jobs', {",
    "    status: { type: Sequelize.ENUM('queued', 'done'), allowNull: false }",
    '  });',
    '} };',
    ''
  ].join('\n'));
  const bootstrap = analysisFile('docker/init.sql', [
    'CREATE TABLE jobs (',
    '  status VARCHAR(32) NOT NULL',
    ');',
    ''
  ].join('\n'));

  const result = detectDataContractMismatches([bootstrap, migration]);
  assert.equal(
    result.findings.filter((finding) => finding.ruleId === 'contract/data-provisioning-path-enum-v1').length,
    1
  );
});

test('provisioning-path enum drift survives duplicate application-model mappings', () => {
  const modelSource = (name: string) => analysisFile(`src/models/${name}.js`, [
    `sequelize.define('${name}', { status: { type: DataTypes.STRING } }, { tableName: 'jobs' });`,
    ''
  ].join('\n'));
  const migration = analysisFile('src/migrations/001-jobs.js', [
    'module.exports = { async up(queryInterface, Sequelize) {',
    "  await queryInterface.createTable('jobs', { status: { type: Sequelize.ENUM('queued', 'done') } });",
    '} };',
    ''
  ].join('\n'));
  const bootstrap = analysisFile('docker/init.sql', 'CREATE TABLE jobs (status VARCHAR(32));\n');

  const result = detectDataContractMismatches([
    bootstrap,
    migration,
    modelSource('FirstJob'),
    modelSource('SecondJob')
  ]);
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_TABLE'));
  assert.equal(
    result.findings.filter((finding) => finding.ruleId === 'contract/data-provisioning-path-enum-v1').length,
    1
  );
});

test('SQL enum checks isolate their literal list from defaults and additional string constraints', () => {
  const migration = (members: string) => analysisFile('src/migrations/001-jobs.js', [
    'module.exports = { async up(queryInterface, Sequelize) {',
    `  await queryInterface.createTable('jobs', { status: { type: Sequelize.ENUM(${members}) } });`,
    '} };',
    ''
  ].join('\n'));
  const bootstrap = analysisFile('docker/init.sql', [
    'CREATE TABLE jobs (',
    "  status VARCHAR(32) CHECK (status IN ('queued', 'done')) DEFAULT 'queued' CHECK (status <> 'retired')",
    ');',
    ''
  ].join('\n'));

  const aligned = detectDataContractMismatches([bootstrap, migration("'done', 'queued'")]);
  assert(!aligned.findings.some((finding) => finding.ruleId === 'contract/data-provisioning-path-enum-v1'));

  const drifted = detectDataContractMismatches([bootstrap, migration("'archived', 'done', 'queued'")]);
  assert.equal(
    drifted.findings.filter((finding) => finding.ruleId === 'contract/data-provisioning-path-enum-v1').length,
    1
  );
});

test('ordered literal add, change, remove, and renameColumn operations form a bounded current migration contract', () => {
  const files = [
    analysisFile('src/models/widget.model.js', [
      "module.exports = (sequelize, DataTypes) => sequelize.define('Widget', {",
      '  id: { type: DataTypes.INTEGER, primaryKey: true },',
      "  displayName: { type: DataTypes.STRING, allowNull: false, field: 'display_name_v2' },",
      '  added: { type: DataTypes.BOOLEAN, allowNull: false },',
      '  legacy: { type: DataTypes.TEXT, allowNull: true }',
      "}, { tableName: 'widgets', schema: 'fct', underscored: false });",
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821000300-create-widgets.js', [
      'module.exports = { async up(queryInterface, Sequelize) {',
      "  await queryInterface.createTable({ tableName: 'widgets', schema: 'fct' }, {",
      '    id: { type: Sequelize.INTEGER, primaryKey: true },',
      '    display_name: { type: Sequelize.TEXT, allowNull: true },',
      '    legacy: { type: Sequelize.TEXT, allowNull: true }',
      '  });',
      '} };',
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821000400-update-widgets.js', [
      'module.exports = { async up(queryInterface, Sequelize) {',
      "  await queryInterface.changeColumn({ tableName: 'widgets', schema: 'fct' }, 'display_name', { type: Sequelize.STRING, allowNull: false });",
      "  await queryInterface.renameColumn({ tableName: 'widgets', schema: 'fct' }, 'display_name', 'display_name_v2');",
      "  await queryInterface.addColumn({ tableName: 'widgets', schema: 'fct' }, 'added', { type: Sequelize.BOOLEAN, allowNull: false });",
      "  await queryInterface.removeColumn({ tableName: 'widgets', schema: 'fct' }, 'legacy');",
      '} };',
      ''
    ].join('\n'))
  ];

  const result = detectDataContractMismatches(files);
  assert.deepEqual(result.findings.map((finding) => finding.ruleId), ['contract/data-column-removed-v1']);
  assert.deepEqual(result.diagnostics, []);
});

test('dynamic and conditional Sequelize constructs suppress claims at the narrowest defensible scope', () => {
  const files = [
    analysisFile('src/models/risky.model.js', [
      "sequelize.define('Risky', {",
      '  ...sharedAttributes,',
      '  id: { type: DataTypes.BOOLEAN, allowNull: false }',
      "}, { tableName: 'risky', schema: 'fct' });",
      "sequelize.define('Stable', { id: { type: DataTypes.BOOLEAN, allowNull: false } }, { tableName: 'stable', schema: 'fct' });",
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821000500-risky.js', [
      'module.exports = { async up(queryInterface, Sequelize) {',
      '  if (featureFlag) {',
      "    await queryInterface.changeColumn({ tableName: 'stable', schema: 'fct' }, 'id', { type: Sequelize.INTEGER, allowNull: false });",
      '  }',
      '  await queryInterface.createTable(runtimeTable, { id: { type: Sequelize.INTEGER, allowNull: false } });',
      '} };',
      ''
    ].join('\n'))
  ];

  const result = detectDataContractMismatches(files);
  assert.deepEqual(result.findings, []);
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MODEL'));
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_CONDITIONAL_SEQUELIZE_MIGRATION'));
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION'));
});

test('dynamic defaults and enums plus validator hooks emit limitations without retaining or guessing values', () => {
  const files = [
    analysisFile('src/models/policy.model.js', [
      "sequelize.define('Policy', {",
      '  state: {',
      "    type: DataTypes.ENUM(...runtimeStates),",
      '    allowNull: false,',
      '    defaultValue: chooseDefault(),',
      "    validate: { isIn: [['secret-model-state']] }",
      '  }',
      "}, { tableName: 'policies', schema: 'fct' });",
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821000600-create-policies.js', [
      'module.exports = { async up(queryInterface, Sequelize) {',
      "  await queryInterface.createTable({ tableName: 'policies', schema: 'fct' }, {",
      "    state: { type: Sequelize.ENUM('secret-db-state'), allowNull: false, defaultValue: 'secret-db-state' }",
      '  });',
      '} };',
      ''
    ].join('\n'))
  ];

  const result = detectDataContractMismatches(files);
  assert.deepEqual(result.findings, []);
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_DYNAMIC_SEQUELIZE_DEFAULT'));
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_DYNAMIC_SEQUELIZE_ENUM'));
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_VALIDATOR_SERIALIZER_SCOPE_LIMITED'));
  const serialized = canonicalJson(result);
  assert(!serialized.includes('secret-model-state'));
  assert(!serialized.includes('secret-db-state'));
});

test('cross-file migration sequencing is suppressed when leading timestamp keys are not unique', () => {
  const files = [
    analysisFile('src/models/order.model.js', [
      "sequelize.define('Order', { id: { type: DataTypes.BOOLEAN, allowNull: false } }, { tableName: 'orders', schema: 'fct' });",
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821-create-orders.js', [
      'module.exports = { async up(queryInterface, Sequelize) {',
      "  await queryInterface.createTable({ tableName: 'orders', schema: 'fct' }, { id: { type: Sequelize.INTEGER, allowNull: false } });",
      '} };',
      ''
    ].join('\n')),
    analysisFile('src/migrations/20260821-change-orders.js', [
      'module.exports = { async up(queryInterface, Sequelize) {',
      "  await queryInterface.changeColumn({ tableName: 'orders', schema: 'fct' }, 'id', { type: Sequelize.STRING, allowNull: false });",
      '} };',
      ''
    ].join('\n'))
  ];

  const result = detectDataContractMismatches(files);
  assert.deepEqual(result.findings, []);
  assert(result.diagnostics.some((entry) => entry.code === 'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_MIGRATION_ORDER'));
});
