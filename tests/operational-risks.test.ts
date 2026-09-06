import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeJavaScriptTypeScript } from '../src/adapters/js-ts.js';
import {
  detectOperationalRisks,
  OPERATIONAL_RISK_ANALYSIS_VERSION,
  OPERATIONAL_RULE_CATALOG,
  OPERATIONAL_RULE_IDS,
  type OperationalRuleId
} from '../src/analysis/operational-risks.js';
import { postprocessFindings } from '../src/analysis/finding-postprocess.js';
import { operationalRuleInputStatus } from '../src/regression/incidents.js';
import type { AnalysisFile, EvidenceReference, FileKind, FileRecord, ResolvedProfile } from '../src/types.js';
import { SCHEMA_VERSION } from '../src/types.js';
import { assertSchema } from '../src/schema-validator.js';
import { sha256 } from '../src/util/canonical.js';

function language(filePath: string): string {
  if (/\.(?:ts|mts|cts)$/u.test(filePath)) return 'typescript';
  if (/\.(?:js|mjs|cjs)$/u.test(filePath)) return 'javascript';
  if (/\.sql$/u.test(filePath)) return 'sql';
  if (/\.ya?ml$/u.test(filePath)) return 'yaml';
  if (/\.json$/u.test(filePath)) return 'json';
  if (/\.sh$/u.test(filePath)) return 'shell';
  return 'text';
}

function kind(filePath: string): FileKind {
  if (/(?:^|\/)(?:tests?|__tests__|fixtures)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(filePath)) return 'test';
  if (/\.(?:[cm]?[jt]sx?)$/u.test(filePath)) return 'source';
  return 'configuration';
}

function analysisFile(filePath: string, source: string): AnalysisFile {
  const content = Buffer.from(source, 'utf8');
  const sourceEvidence: EvidenceReference = {
    level: 0,
    producer: 'atlas/operational-risk-test-fixture',
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
    kind: kind(filePath),
    language: language(filePath),
    symbols: [],
    environmentVariables: [],
    lifecycle: {
      state: 'unspecified',
      basis: 'no-profile-match',
      uncertainty: 'not-runtime-validated',
      limitation: 'Fixture lifecycle is intentionally not runtime validated.'
    },
    evidence: sourceEvidence
  };
  return { record, content };
}

function withLifecycle(file: AnalysisFile, state: NonNullable<FileRecord['lifecycle']>['state']): AnalysisFile {
  return {
    ...file,
    record: {
      ...file.record,
      lifecycle: {
        state,
        basis: state === 'unspecified' ? 'no-profile-match' : 'profile-path-rule',
        ...(state === 'unspecified' ? {} : { ruleId: `test-${state}` }),
        uncertainty: 'not-runtime-validated',
        limitation: 'Test lifecycle declaration.'
      }
    }
  };
}

const PROFILE: ResolvedProfile = {
  schemaVersion: 1,
  id: 'operational-risk-tests',
  includeRoots: ['.'],
  exclude: [],
  entrypoints: [],
  aliases: {},
  envExampleFiles: [],
  platformRoots: [],
  deadCodeExemptions: [],
  operationalRisks: {
    guardPaths: [],
    seedDictionarySources: ['**/*.sql', '**/seeders/**']
  },
  lifecycleRules: [],
  maxFileBytes: 1_000_000
};

function detect(files: AnalysisFile[], selectedProfile: ResolvedProfile = PROFILE) {
  const graph = analyzeJavaScriptTypeScript(files, selectedProfile);
  return detectOperationalRisks(files, graph.relationships, selectedProfile);
}

interface IncidentPair {
  ruleId: OperationalRuleId;
  broken: AnalysisFile[];
  fixed: AnalysisFile[];
  requiredSignals?: string[];
}

const INCIDENTS: IncidentPair[] = [
  {
    ruleId: OPERATIONAL_RULE_IDS.silentEmpty,
    broken: [
      analysisFile('package.json', '{"scripts":{"test":"vitest --passWithNoTests"}}\n'),
      analysisFile('scripts/gate.sh', 'checker | tail -10 && commit-result\n'),
      analysisFile('scripts/count.ts', [
        'const violationCount = scanRepository().length;',
        "console.log('observed', violationCount);",
        ''
      ].join('\n'))
    ],
    fixed: [
      analysisFile('package.json', '{"scripts":{"test":"vitest"}}\n'),
      analysisFile('scripts/gate.sh', 'set -o pipefail\nchecker | tail -10 && commit-result\n'),
      analysisFile('scripts/count.ts', [
        'const violationCount = scanRepository().length;',
        "console.log('observed', violationCount);",
        "if (violationCount > 0) throw new Error('gate failed');",
        ''
      ].join('\n'))
    ],
    requiredSignals: [
      'zero-observation-success-enabled',
      'conditional-uses-terminal-pipeline-status',
      'observation-count-only-logged'
    ]
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.hostContainerPath,
    broken: [
      analysisFile('compose.yaml', [
        'services:',
        '  app:',
        '    volumes:',
        '      - ./src:/app',
        ''
      ].join('\n')),
      analysisFile('Dockerfile', 'WORKDIR /app\nCOPY src /app\n'),
      analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
    ],
    fixed: [
      analysisFile('compose.yaml', [
        'services:',
        '  app:',
        '    volumes:',
        '      - ./src:/app',
        ''
      ].join('\n')),
      analysisFile('Dockerfile', 'WORKDIR /app\nCOPY src /app\n'),
      analysisFile('src/tools/check.ts', "const root = findUpRequired('package.json');\n")
    ],
    requiredSignals: ['literal-host-container-resolution-diverges']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.guardBypass,
    broken: [
      analysisFile('src/repositories/appointment.ts', 'export const appointmentRepository = { create(input) { return input; } };\n'),
      analysisFile('src/services/appointment.service.ts', "import { appointmentRepository } from '../repositories/appointment.js';\nexport function guarded(input) { return appointmentRepository.create(input); }\n"),
      analysisFile('src/routes/checkout.ts', "import { appointmentRepository } from '../repositories/appointment.js';\nexport function checkout(input) { return appointmentRepository.create(input); }\n")
    ],
    fixed: [
      analysisFile('src/repositories/appointment.ts', 'export const appointmentRepository = { create(input) { return input; } };\n'),
      analysisFile('src/services/appointment.service.ts', "import { appointmentRepository } from '../repositories/appointment.js';\nexport function guarded(input) { return appointmentRepository.create(input); }\n"),
      analysisFile('src/routes/checkout.ts', "import { guarded } from '../services/appointment.service.js';\nexport function checkout(input) { return guarded(input); }\n")
    ],
    requiredSignals: ['caller-inventory-not-policy-verdict']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.vocabularyDrift,
    broken: [
      analysisFile('src/domain/status.ts', "export const APPOINTMENT_STATUS_VALUES = ['QUEUED_PRIVATE', 'CANCELLED_PRIVATE'];\n"),
      analysisFile('src/routes/status.ts', "export type AppointmentStatus = 'QUEUED_PRIVATE' | 'COMPLETED_PRIVATE';\n")
    ],
    fixed: [
      analysisFile('src/domain/status.ts', "export const APPOINTMENT_STATUS_VALUES = ['QUEUED_PRIVATE', 'CANCELLED_PRIVATE'];\n"),
      analysisFile('src/routes/status.ts', "export type AppointmentStatus = 'QUEUED_PRIVATE' | 'CANCELLED_PRIVATE';\n")
    ],
    requiredSignals: ['complete-literal-vocabularies-disagree']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.clockDateBasis,
    broken: [
      analysisFile('tests/window.test.ts', "const boundary = new Date('2099-07-01T00:00:00Z');\nexpect(isUpcoming(boundary)).toBe(true);\n"),
      analysisFile('src/services/daily-report.ts', 'export function report(tenantId) { const today = new Date(); return load(tenantId, today); }\n'),
      analysisFile('schema.sql', 'CREATE TABLE appointments (appointment_date DATE, start_time TIME);\n'),
      analysisFile('src/repositories/appointment.ts', 'export const query = `SELECT * FROM appointments WHERE appointment_date >= $1`;\n')
    ],
    fixed: [
      analysisFile('tests/window.test.ts', "jest.useFakeTimers();\njest.setSystemTime(new Date('2099-07-01T00:00:00Z'));\nexpect(isUpcoming(new Date())).toBe(true);\n"),
      analysisFile('src/services/daily-report.ts', 'export function report(tenantId, clock) { const today = localDateFor(tenantId, clock); return load(tenantId, today); }\n'),
      analysisFile('schema.sql', 'CREATE TABLE appointments (appointment_date DATE, start_time TIME);\n'),
      analysisFile('src/repositories/appointment.ts', 'export const query = `SELECT * FROM appointments WHERE appointment_date >= $1 AND appointment_date < $2 AND start_time >= $3`;\n')
    ],
    requiredSignals: ['absolute-test-date', 'process-clock-read', 'date-lower-bound-observed', 'date-only-bound-observed']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.resultCollapse,
    broken: [
      analysisFile('src/notifications/send.ts', [
        'function sendMessage() { return { success: true, suppressed: true, reason: "PRIVATE_REASON" }; }',
        'const { success } = sendMessage();',
        "if (success) console.log('sent');",
        'export async function deliverRequired() { try { return await deliver(); } catch (error) { console.log(error); } }',
        ''
      ].join('\n')),
      analysisFile('src/cli/run.ts', "console.log('PRIVATE_CLI_FAILURE'); process.exit(0);\n")
    ],
    fixed: [
      analysisFile('src/notifications/send.ts', [
        'function sendMessage() { return { success: true, suppressed: true, reason: "PRIVATE_REASON" }; }',
        'const { success, suppressed } = sendMessage();',
        "if (success && !suppressed) console.log('sent');",
        'try { deliver(); } catch (error) { throw error; }',
        ''
      ].join('\n')),
      analysisFile('src/cli/run.ts', "console.error('PRIVATE_CLI_FAILURE'); process.exit(1);\n")
    ],
    requiredSignals: ['caller-reads-success-only', 'caught-error-not-propagated', 'successful-exit-status-on-error-path']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.duplicateGuard,
    broken: [
      analysisFile('src/readers/a.ts', 'if (tenant === owner && status === activeStatus) { readRows(); }\n'),
      analysisFile('src/readers/b.ts', 'if (tenant === owner && status === activeStatus) { readOtherRows(); }\n')
    ],
    fixed: [
      analysisFile('src/readers/a.ts', 'if (tenant === owner && status === activeStatus) { readRows(); }\n'),
      analysisFile('src/readers/b.ts', 'if (canReadTenant(request)) { readOtherRows(); }\n')
    ],
    requiredSignals: ['normalized-guard-fragment-duplicate']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.seededDictionary,
    broken: [
      analysisFile('seed.sql', "INSERT INTO statuses (id, name) VALUES (6, 'CANCELED_PRIVATE'), (7, 'RESCHEDULED_PRIVATE');\n"),
      analysisFile('src/status-map.ts', [
        'const STATUS_ID_MAP = { CANCELED_PRIVATE: 7 };',
        "const missing = findStatusByName('ARCHIVED_PRIVATE');",
        ''
      ].join('\n')),
      analysisFile('tests/status.test.ts', 'expect(result.status_id).toBe(7);\n')
    ],
    fixed: [
      analysisFile('seed.sql', "INSERT INTO statuses (id, name) VALUES (6, 'CANCELED_PRIVATE'), (7, 'RESCHEDULED_PRIVATE');\n"),
      analysisFile('src/status-map.ts', [
        'const STATUS_ID_MAP = { CANCELED_PRIVATE: 6 };',
        "const existing = findStatusByName('CANCELED_PRIVATE');",
        ''
      ].join('\n')),
      analysisFile('tests/status.test.ts', "expect(result.status_id).toBe(resolveStatusId('CANCELED_PRIVATE'));\n")
    ],
    requiredSignals: ['seeded-id-name-mismatch', 'name-absent-from-complete-seed', 'test-asserts-seeded-integer-id']
  },
  {
    ruleId: OPERATIONAL_RULE_IDS.accidentalProtection,
    broken: [
      analysisFile('src/services/import.ts', [
        'export function persist(input) {',
        '  const statusId = resolveStatus(input.status);',
        '  return auditStore.create({ name: input.name });',
        '}',
        ''
      ].join('\n'))
    ],
    fixed: [
      analysisFile('src/services/import.ts', [
        'export function persist(input) {',
        '  const statusId = resolveStatus(input.status);',
        '  return auditStore.create({ name: input.name, statusId });',
        '}',
        ''
      ].join('\n'))
    ],
    requiredSignals: ['protection-shaped-value-computed', 'lexically-unconsumed-local']
  }
];

test('every operational rule detects its broken control and stays silent for its fixed control', async () => {
  assert.equal(OPERATIONAL_RISK_ANALYSIS_VERSION, '1.3.2');
  assert.deepEqual(
    OPERATIONAL_RULE_CATALOG.map((entry) => entry.ruleId).sort(),
    Object.values(OPERATIONAL_RULE_IDS).sort()
  );

  for (const incident of INCIDENTS) {
    const broken = detect(incident.broken);
    const fixed = detect(incident.fixed);
    const brokenFindings = broken.findings.filter((finding) => finding.ruleId === incident.ruleId);
    const fixedFindings = fixed.findings.filter((finding) => finding.ruleId === incident.ruleId);
    assert(brokenFindings.length > 0, `${incident.ruleId} missed its broken positive control`);
    assert.equal(fixedFindings.length, 0, `${incident.ruleId} fired on its fixed negative control`);
    assert(broken.observations.some((entry) => entry.ruleId === incident.ruleId && entry.state === 'detected'));
    for (const signal of incident.requiredSignals ?? []) {
      assert(brokenFindings.some((finding) => finding.signals.includes(signal)), `${incident.ruleId} did not exercise ${signal}`);
    }
    for (const finding of brokenFindings) {
      await assertSchema('finding', finding, `${incident.ruleId} positive control finding`);
      assert.equal(finding.instanceCount, 1);
      assert.match(finding.patternKey, new RegExp(`^${incident.ruleId.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}:`));
      assert(finding.kind === 'defect-candidate' || finding.kind === 'review-inventory' || finding.kind === 'latent-hazard');
      assert(finding.evidence.length > 0);
      assert(finding.evidence.every((entry) => entry.path && entry.line && entry.column));
      assert(finding.impactContext.limitations.length > 0);
      assert.equal(finding.category, finding.kind === 'review-inventory'
        ? 'review-inventory'
        : finding.kind === 'latent-hazard'
          ? 'latent-hazard'
          : 'operational-defect');
    }
  }
});

test('the combined operational analysis is deterministic under file-order reversal', () => {
  const files = INCIDENTS.flatMap((incident, index) =>
    incident.broken.map((file) => analysisFile(`case-${index}/${file.record.path}`, file.content.toString('utf8')))
  );
  const forward = detect(files);
  const reversed = detect([...files].reverse());
  assert.deepEqual(reversed, forward);
  for (const ruleId of Object.values(OPERATIONAL_RULE_IDS)) {
    assert(forward.findings.some((finding) => finding.ruleId === ruleId), `combined fixture missed ${ruleId}`);
  }
});

test('source locations remain instances while repeated operational mechanisms aggregate as one headline', () => {
  const files = [
    analysisFile('tests/first.test.ts', "expect(runAvailability(new Date('2099-01-01T00:00:00Z'))).toBe(true);\n"),
    analysisFile('tests/second.test.ts', "expect(runAvailability(new Date('2099-02-01T00:00:00Z'))).toBe(true);\n")
  ];
  const raw = detect(files).findings.filter(
    (finding) => finding.ruleId === OPERATIONAL_RULE_IDS.clockDateBasis
  );
  assert.equal(raw.length, 2);
  assert.equal(new Set(raw.map((finding) => finding.patternKey)).size, 1);

  const processed = postprocessFindings(raw, files);
  assert.equal(processed.length, 1);
  assert.equal(processed[0]?.instanceCount, 2);
  assert.equal(processed[0]?.instances?.length, 2);
});

test('operational records retain anchors and irreversible signatures without source or literal values', () => {
  const result = detect(INCIDENTS.flatMap((incident) => incident.broken));
  const serialized = JSON.stringify(result);
  for (const forbidden of [
    'QUEUED_PRIVATE',
    'CANCELLED_PRIVATE',
    'COMPLETED_PRIVATE',
    'CANCELED_PRIVATE',
    'RESCHEDULED_PRIVATE',
    'ARCHIVED_PRIVATE',
    'PRIVATE_REASON',
    'PRIVATE_CLI_FAILURE',
    'checker | tail -10 && commit-result'
  ]) {
    assert.equal(serialized.includes(forbidden), false, `operational output leaked ${forbidden}`);
  }
  assert(result.findings.every((finding) => finding.evidence.every((entry) => entry.path && entry.line && entry.column)));
  assert(result.observations.every((entry) => entry.evidence.path && entry.evidence.line && entry.evidence.column));
});

test('seeded dictionary analysis reports incomplete when required profile inputs are absent or unresolved', () => {
  const candidate = analysisFile('src/status-map.ts', 'const STATUS_ID_MAP = { CANCELED: 7 };\n');
  const { operationalRisks: _ignoredOperationalRisks, ...withoutOperationalRisks } = PROFILE;
  const absent = detect([candidate], withoutOperationalRisks);
  assert.equal(absent.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.seededDictionary), false);
  assert(absent.observations.some((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.seededDictionary && entry.state === 'uncertain'
  ));
  assert(absent.diagnostics.some((entry) => entry.code === 'OPERATIONAL_SEED_DICTIONARY_SOURCE_REQUIRED'));

  const unresolved = detect([candidate], {
    ...PROFILE,
    operationalRisks: { guardPaths: [], seedDictionarySources: ['db/missing-seeds/**'] }
  });
  assert.equal(unresolved.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.seededDictionary), false);
  assert(unresolved.diagnostics.some((entry) => entry.code === 'OPERATIONAL_SEED_DICTIONARY_SOURCE_UNRESOLVED'));
});

test('configured JavaScript seed sources provide SQL dictionaries without treating row objects as mappings', () => {
  const files = [
    analysisFile('src/seeders/statuses.js', [
      'await queryInterface.sequelize.query(`',
      '  INSERT INTO dim.appointment_status (status_id, name) VALUES',
      "  (6, 'Canceled'), (7, 'Rescheduled');",
      '`);',
      'const harmlessRows = [{ id: 7, name: "Rescheduled" }];',
      'void harmlessRows;',
      ''
    ].join('\n')),
    analysisFile('src/status-map.ts', 'const APPOINTMENT_STATUS_ID_MAP = { CANCELED: 7 };\n'),
    analysisFile('src/academy.ts', 'const STATUS_ORDER = { completed: 3, in_progress: 2 };\n'),
    analysisFile('src/facts.ts', 'const STATUS_FACTS_BY_NAME = { completed: { statusId: 3, name: "Completed" } };\n')
  ];
  const result = detect(files, {
    ...PROFILE,
    operationalRisks: { guardPaths: [], seedDictionarySources: ['src/seeders/**'] }
  });
  const findings = result.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.seededDictionary);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.path, 'src/status-map.ts');
  assert(findings[0]?.signals.includes('seeded-id-name-mismatch'));
});

test('seeded test coupling requires an ID-shaped subject and an integer present in the selected dictionary', () => {
  const result = detect([
    analysisFile(
      'src/seeders/statuses.js',
      "queryInterface.bulkInsert('appointment_status', [{ id: 6, name: 'Canceled' }, { id: 7, name: 'Rescheduled' }]);\n"
    ),
    analysisFile('tests/status.test.ts', [
      'expect(response.status).toBe(200);',
      'expect(result.status_id).toBe(999);',
      'expect(result.status_id_count).toBe(7);',
      'expect(result.statusIdCount).toBe(6);',
      'expect(result.status_id).toBe(7);',
      'expect(result.status.id).toBe(6);',
      ''
    ].join('\n'))
  ], {
    ...PROFILE,
    operationalRisks: { guardPaths: [], seedDictionarySources: ['src/seeders/**'] }
  });
  const findings = result.findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.seededDictionary && entry.signals.includes('test-asserts-seeded-integer-id')
  );
  assert.deepEqual(findings.map((finding) => finding.evidence[0]?.line ?? -1).sort((left, right) => left - right), [5, 6]);
});

test('configured seed dictionaries participate in vocabulary-drift comparisons', () => {
  const seed = analysisFile('src/seeders/appointment-statuses.js', [
    'await queryInterface.sequelize.query(`',
    '  INSERT INTO dim.appointment_status (status_id, name) VALUES',
    "  (6, 'Canceled'), (7, 'Rescheduled');",
    '`);',
    ''
  ].join('\n'));
  const selectedProfile: ResolvedProfile = {
    ...PROFILE,
    operationalRisks: { guardPaths: [], seedDictionarySources: ['src/seeders/**'] }
  };

  const drift = detect([
    seed,
    analysisFile(
      'src/domain/appointment-status.ts',
      "export const APPOINTMENT_STATUS_VALUES = ['Canceled', 'Rescheduled', 'Completed'] as const;\n"
    )
  ], selectedProfile).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift);
  assert.equal(drift.length, 1);
  assert(drift[0]?.signals.includes('seed-dictionary'));

  const matching = detect([
    seed,
    analysisFile(
      'src/domain/appointment-status.ts',
      "export const APPOINTMENT_STATUS_VALUES = ['Canceled', 'Rescheduled'] as const;\n"
    )
  ], selectedProfile);
  assert.equal(matching.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift), false);
});

test('one unusable configured seed source keeps seeded-dictionary input health incomplete', () => {
  const result = detect([
    analysisFile(
      'src/seeders/complete.js',
      "queryInterface.bulkInsert('appointment_status', [{ id: 6, name: 'Canceled' }, { id: 7, name: 'Rescheduled' }]);\n"
    ),
    analysisFile(
      'src/seeders/dynamic.js',
      "queryInterface.bulkInsert('booking_status', generatedRows);\n"
    ),
    analysisFile('src/status-map.ts', 'const APPOINTMENT_STATUS_ID_MAP = { CANCELED: 7 };\n')
  ], {
    ...PROFILE,
    operationalRisks: { guardPaths: [], seedDictionarySources: ['src/seeders/**'] }
  });

  assert(result.diagnostics.some((entry) => entry.code === 'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE'));
  assert.equal(
    operationalRuleInputStatus(OPERATIONAL_RULE_IDS.seededDictionary, result.diagnostics),
    'incomplete'
  );
});

test('documentation, corpus, examples, and explicitly mothballed files cannot leak into target operational findings', () => {
  const noisy = [
    analysisFile('docs/gate.md', 'vitest --passWithNoTests\n'),
    analysisFile('corpus/incidents/sample.json', '{"content":"vitest --passWithNoTests"}\n'),
    analysisFile('examples/unsafe.ts', "expect(book(new Date('2099-01-01'))).toBe(true);\n"),
    withLifecycle(analysisFile('src/legacy/gate.ts', "const errors = scan().length; console.log(errors);\n"), 'mothballed'),
    analysisFile('tests/duplicate-a.test.ts', 'if (tenantId === ownerId && status === activeStatus) allow();\n'),
    analysisFile('tests/duplicate-b.test.ts', 'if (tenantId === ownerId && status === activeStatus) allow();\n'),
    analysisFile('tests/protection.test.ts', 'function setup(input) { const statusId = resolveStatus(input.status); return input; }\n')
  ];
  assert.deepEqual(detect(noisy).findings, []);
});

test('guard bypass inventory binds resolved sink identity and excludes test-only callers', () => {
  const unrelated = [
    analysisFile('src/repositories/a.ts', 'export const appointmentRepository = { create(input) { return input; } };\n'),
    analysisFile('src/repositories/b.ts', 'export const appointmentRepository = { create(input) { return input; } };\n'),
    analysisFile('src/services/a.ts', "import { appointmentRepository } from '../repositories/a.js';\nexport const save = input => appointmentRepository.create(input);\n"),
    analysisFile('src/routes/b.ts', "import { appointmentRepository } from '../repositories/b.js';\nexport const save = input => appointmentRepository.create(input);\n")
  ];
  assert.equal(detect(unrelated).findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass), false);

  const sameSink = [
    unrelated[0]!,
    unrelated[2]!,
    analysisFile('src/routes/a.ts', "import { appointmentRepository } from '../repositories/a.js';\nexport function save(input) { const result = appointmentRepository.create(input); validate(input); return result; }\n"),
    analysisFile('tests/a.test.ts', "import { appointmentRepository } from '../src/repositories/a.js';\nit('writes', () => appointmentRepository.create({}));\n")
  ];
  const findings = detect(sameSink).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.path, 'src/routes/a.ts');
});

test('guardPaths remain a fallback hint without explicit boundary declarations', () => {
  const files = [
    analysisFile('src/repositories/appointment.ts', 'export const appointmentRepository = { create(input) { return input; } };\n'),
    analysisFile('src/policies/appointment.ts', "import { appointmentRepository } from '../repositories/appointment.js';\nexport const save = input => appointmentRepository.create(input);\n"),
    analysisFile('src/routes/checkout.ts', "import { appointmentRepository } from '../repositories/appointment.js';\nexport const checkout = input => appointmentRepository.create(input);\n")
  ];
  const result = detect(files, {
    ...PROFILE,
    operationalRisks: { guardPaths: ['src/policies/**'], seedDictionarySources: [] }
  });
  const findings = result.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.path, 'src/routes/checkout.ts');
});

test('declared protected writers partition service callers by resolved boundary traversal', () => {
  const files = [
    analysisFile('src/repositories/appointment.ts', [
      'export const appointmentRepository = {',
      '  create(input) { return input; },',
      '  update(input) { return input; }',
      '};',
      ''
    ].join('\n')),
    analysisFile('src/services/appointment.service.ts', [
      "const { guardedCreate } = require('./appointment-write.service.js');",
      'export const create = input => guardedCreate(input);',
      ''
    ].join('\n')),
    analysisFile('src/services/appointment-write.service.ts', [
      "const appointmentRepository = require('../repositories/appointment.js');",
      'export const guardedCreate = input => appointmentRepository.create(input);',
      ''
    ].join('\n')),
    analysisFile('src/services/checkout-orchestration.service.ts', [
      "const appointmentRepository = require('../repositories/appointment.js');",
      'export const checkout = input => appointmentRepository.create(input);',
      ''
    ].join('\n')),
    analysisFile('src/services/unrelated-update.service.ts', [
      "const appointmentRepository = require('../repositories/appointment.js');",
      'export const update = input => appointmentRepository.update(input);',
      ''
    ].join('\n'))
  ];
  const result = detect(files, {
    ...PROFILE,
    operationalRisks: {
      guardPaths: ['src/services/**'],
      seedDictionarySources: [],
      boundaries: [{
        id: 'appointment-create-boundary',
        module: 'src/services/appointment.service.ts',
        protects: ['appointment-create-writer']
      }],
      protectedWriters: [{
        id: 'appointment-create-writer',
        module: 'src/repositories/appointment.ts',
        methods: ['create']
      }]
    }
  });
  const findings = result.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.path, 'src/services/checkout-orchestration.service.ts');
  assert.deepEqual(findings[0]?.relatedPaths, ['src/services/appointment-write.service.ts']);
  assert(findings[0]?.signals.includes('resolved-boundary-graph-bypass'));
  assert.match(findings[0]?.description ?? '', /appointment-create-writer/u);
});

test('guard bypass SQL inventory requires complete SQL literals at recognized database calls', () => {
  const proseOnly = [
    analysisFile('src/services/help.ts', [
      '/** Example: db.query("UPDATE appointments SET status = ?") */',
      "export const help = 'Run UPDATE appointments SET status = active from the admin UI';",
      ''
    ].join('\n')),
    analysisFile('src/routes/help.ts', [
      '// db.query(`UPDATE appointments SET status = ${status}`);',
      "export function render() { return view('UPDATE appointments SET status = active'); }",
      ''
    ].join('\n'))
  ];
  assert.equal(
    detect(proseOnly).findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass),
    false
  );

  const executed = [
    analysisFile('src/services/appointments.ts', [
      "const updateAppointment = 'UPDATE appointments SET status = $1 WHERE id = $2';",
      'export function guarded(db, values) { return db.query(updateAppointment, values); }',
      ''
    ].join('\n')),
    analysisFile('src/routes/appointments.ts', [
      'export function direct(db, status, id) {',
      '  return db.query(`UPDATE appointments SET status = ${status} WHERE id = ${id}`);',
      '}',
      ''
    ].join('\n'))
  ];
  const findings = detect(executed).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.path, 'src/routes/appointments.ts');

  const schemaQualified = [
    analysisFile('src/services/accounts.ts', "export const guarded = ctx => ctx.db.execute('UPDATE public.accounts SET active = true');\n"),
    analysisFile('src/routes/accounts.ts', "export const direct = function() { return this.db.execute('UPDATE accounts SET active = false'); };\n")
  ];
  assert.equal(
    detect(schemaQualified).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass).length,
    1
  );

  const nonDominatingGuard = [
    analysisFile('src/services/products.ts', "export function guarded(db) { return db.query('UPDATE products SET active = true'); }\n"),
    analysisFile('src/routes/products.ts', "export function direct(db, admin) { if (admin) authorize(); return db.query('UPDATE products SET active = false'); }\n")
  ];
  assert.equal(
    detect(nonDominatingGuard).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass).length,
    1
  );

  const shadowed = [
    analysisFile('src/services/users.ts', "export const guarded = db => db.query('UPDATE users SET active = true');\n"),
    analysisFile('src/routes/users.ts', [
      "const statement = 'UPDATE users SET active = false';",
      'export function direct(db, statement) { return db.query(statement); }',
      ''
    ].join('\n'))
  ];
  assert.equal(
    detect(shadowed).findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass),
    false
  );

  const tagged = [
    analysisFile('src/services/tagged.ts', 'export const guarded = (prisma, active) => prisma.$executeRaw`UPDATE users SET active = ${active}`;\n'),
    analysisFile('src/routes/tagged.ts', 'export const direct = (prisma, active) => prisma.$executeRaw`UPDATE users SET active = ${active}`;\n')
  ];
  assert.equal(
    detect(tagged).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass).length,
    1
  );

  const dynamicRelations = [
    analysisFile('src/services/dynamic.ts', 'export const guarded = (db, suffix) => db.query(`UPDATE appointments_${suffix} SET status = 1`);\n'),
    analysisFile('src/routes/dynamic.ts', 'export const direct = (db, suffix) => db.query(`UPDATE appointments_${suffix} SET status = 2`);\n')
  ];
  assert.equal(
    detect(dynamicRelations).findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.guardBypass),
    false
  );
});

test('vocabulary drift does not compare generic field names across unrelated domains or historical tests', () => {
  const files = [
    analysisFile('src/academy.ts', "export const STATUS_VALUES = ['OPEN', 'CLOSED'];\n"),
    analysisFile('src/billing.ts', "export const STATUS_VALUES = ['PAID', 'VOID'];\n"),
    analysisFile('tests/academy.test.ts', "export const ACADEMY_STATUS_VALUES = ['OPEN', 'BROKEN'];\n"),
    analysisFile('migrations/001.sql', "CREATE TABLE billing (status TEXT CHECK (status IN ('PAID', 'LEGACY')));\n")
  ];
  assert.equal(detect(files).findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift), false);
});

test('vocabulary drift binds generic fields to owners and does not treat route filters as canonical sets', () => {
  const files = [
    analysisFile('src/academy.ts', "export function reduce(state, event) { switch (event.type) { case 'OPEN': return state; case 'CLOSE': return state; } }\n"),
    analysisFile('src/stripe.ts', "export function dispatch(event) { switch (event.type) { case 'paid': return 1; case 'failed': return 0; } }\n"),
    analysisFile('src/routes/academy.ts', [
      "router.post('/module-progress', body('status').isIn(['not_started', 'completed']), saveProgress);",
      "router.post('/attempt', body('status').isIn(['submitted', 'review_required']), saveAttempt);",
      ''
    ].join('\n')),
    analysisFile('src/waitlist.ts', [
      "const VALID_WAITLIST_STATUSES = ['waiting', 'seated', 'cancelled'];",
      "router.get('/waitlist', query('status').isIn(['waiting', 'seated']), listWaitlist);",
      "const blockedStatuses = ['cancelled', 'completed'];",
      ''
    ].join('\n')),
    analysisFile('schema.sql', "CREATE TABLE payment_audit (action_type TEXT CHECK (action_type IN ('create', 'refund')));\n"),
    analysisFile('src/insights.ts', "export function act(actionType) { switch (actionType) { case 'authorize': return 1; case 'reorder': return 2; } }\n"),
    analysisFile('src/domain/status.ts', "export const APPOINTMENT_STATUS_VALUES = ['QUEUED', 'CANCELLED'];\n"),
    analysisFile('src/routes/status.ts', "export type AppointmentStatus = 'QUEUED' | 'COMPLETED';\n")
  ];
  const findings = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.path, 'src/domain/status.ts');
});

test('switch cases remain subset evidence unless an unconditional rejecting default proves completeness', () => {
  const subset = detect([
    analysisFile('src/services/appointment-a.ts', [
      'export function handle(appointment) {',
      "  switch (appointment.status) { case 'QUEUED': return 1; case 'CANCELLED': return 2; }",
      '}',
      ''
    ].join('\n')),
    analysisFile('src/services/appointment-b.ts', [
      'export function handle(appointment) {',
      "  switch (appointment.status) { case 'QUEUED': return 1; case 'COMPLETED': return 2; }",
      '}',
      ''
    ].join('\n'))
  ]);
  assert.equal(subset.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift), false);
  assert.deepEqual(
    subset.diagnostics
      .filter((entry) => entry.code === 'OPERATIONAL_VOCABULARY_SWITCH_COMPLETENESS_UNKNOWN')
      .map((entry) => entry.path)
      .sort(),
    ['src/services/appointment-a.ts', 'src/services/appointment-b.ts']
  );

  const exhaustive = detect([
    analysisFile('src/domain/appointment-a.ts', [
      'export function handle(appointment) {',
      "  switch (appointment.status) { case 'QUEUED': return 1; case 'CANCELLED': return 2; default: throw new Error('unknown'); }",
      '}',
      ''
    ].join('\n')),
    analysisFile('src/domain/appointment-b.ts', [
      'export function handle(appointment) {',
      "  switch (appointment.status) { case 'QUEUED': return 1; case 'COMPLETED': return 2; default: throw new Error('unknown'); }",
      '}',
      ''
    ].join('\n'))
  ]);
  const findings = exhaustive.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift);
  assert.equal(findings.length, 1);
  assert(findings[0]?.signals.includes('switch-cases'));
});

test('literal vocabulary arrays unwrap as-const and satisfies expressions', () => {
  const findings = detect([
    analysisFile('src/domain/appointment-status.ts', "export const APPOINTMENT_STATUS_VALUES = ['QUEUED', 'CANCELLED'] as const;\n"),
    analysisFile('src/routes/appointment-status.ts', "export type AppointmentStatus = 'QUEUED' | 'COMPLETED';\n"),
    analysisFile('src/domain/booking-state.ts', "export const BOOKING_STATE_VALUES = ['OPEN', 'CLOSED'] satisfies readonly string[];\n"),
    analysisFile('src/routes/booking-state.ts', "export type BookingState = 'OPEN' | 'ARCHIVED';\n")
  ]).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.vocabularyDrift);
  assert.deepEqual(findings.map((entry) => entry.path).sort(), [
    'src/domain/appointment-status.ts',
    'src/domain/booking-state.ts'
  ]);
  assert(findings.every((entry) => entry.signals.includes('literal-array')));
});

test('clock checks are scoped to time-sensitive tests, individual SQL statements, and direct tenant-clock flow', () => {
  const files = [
    analysisFile('tests/history.test.ts', "const fixture = { createdAt: '2020-01-01T00:00:00Z' }; expect(fixture.createdAt).toBeTruthy();\n"),
    analysisFile('tests/mixed.test.ts', [
      "it('frozen booking', () => { jest.useFakeTimers(); jest.setSystemTime(new Date('2099-01-01')); expect(book(new Date('2099-02-01'))).toBe(true); });",
      "it('unfrozen booking', () => { expect(book(new Date('2099-03-01'))).toBe(true); });",
      ''
    ].join('\n')),
    analysisFile('src/logging.ts', 'export function audit(tenantId) { console.log(tenantId, new Date()); }\n'),
    analysisFile('tests/clock-flow.test.ts', 'it(\'uses a process clock\', () => { const today = new Date(); return load(tenantId, today); });\n'),
    analysisFile('src/queries.ts', [
      'export const open = `SELECT * FROM visits WHERE visit_date >= $1`;',
      'export const closed = `SELECT * FROM visits WHERE visit_date >= $1 AND visit_date < $2`;',
      'export const oriented = `SELECT * FROM visits a WHERE a.visit_date > a.computed_at::date AND a.visit_date <= CURRENT_DATE`;',
      ''
    ].join('\n')),
    analysisFile('schema.sql', 'CREATE TABLE appointments (appointment_date DATE, start_time TIME);\n'),
    analysisFile('src/unrelated-query.ts', 'export const query = `SELECT * FROM visits WHERE appointment_date >= $1 AND appointment_date < $2`;\n')
  ];
  const clock = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.clockDateBasis);
  assert.equal(clock.filter((entry) => entry.signals.includes('absolute-test-date')).length, 1);
  assert.equal(clock.filter((entry) => entry.signals.includes('date-lower-bound-observed')).length, 1);
  assert.equal(clock.some((entry) => entry.signals.includes('process-clock-read')), false);
  assert.equal(clock.some((entry) => entry.path === 'src/unrelated-query.ts' && entry.signals.includes('date-only-bound-observed')), false);
});

test('clock findings require relative calendar behavior and exclude injected or UTC-instant flows', () => {
  const files = [
    analysisFile('tests/pure-date.test.ts', "const input = new Date('2099-01-01T00:00:00Z'); expect(formatUtc(input)).toBe('fixed');\n"),
    analysisFile('tests/pure-boundary.test.ts', "const boundary = new Date('2099-02-01T00:00:00Z'); expect(select(boundary)).toBe(true);\n"),
    analysisFile('tests/live-calendar.test.ts', "expect(book(new Date('2099-03-01T00:00:00Z'))).toBe(true);\n"),
    analysisFile('tests/late-clock.test.ts', "expect(book(new Date('2099-04-01T00:00:00Z'))).toBe(true); jest.useFakeTimers();\n"),
    analysisFile('tests/comment-clock.test.ts', "/* jest.useFakeTimers() */ expect(book(new Date('2099-05-01T00:00:00Z'))).toBe(true);\n"),
    analysisFile('tests/wrapped-date.test.ts', "const boundary = startOfDay(new Date('2099-06-01T00:00:00Z')); expect(book(boundary)).toBe(true);\n"),
    analysisFile('tests/unused-clock-helper.test.ts', "function helper() { jest.useFakeTimers(); } expect(book(new Date('2099-07-01T00:00:00Z'))).toBe(true);\n"),
    analysisFile('tests/frozen-calendar.test.ts', [
      'jest.useFakeTimers();',
      "jest.setSystemTime(new Date('2099-02-01T00:00:00Z'));",
      "expect(book(new Date('2099-03-01T00:00:00Z'))).toBe(true);",
      ''
    ].join('\n')),
    analysisFile('tests/injected-calendar.test.ts', [
      "it('injects a named clock value', async () => { expect(await getTenantLocalToday(1, { now: new Date('2099-08-01T00:00:00Z') })).toBe('2099-07-31'); });",
      "it('injects a shorthand clock value', async () => { const now = new Date('2099-08-02T00:00:00Z'); expect(await getTenantLocalToday(1, { now })).toBe('2099-08-01'); });",
      ''
    ].join('\n')),
    analysisFile('src/services/calendar.ts', 'export function loadCalendar(tenantId) { const today = new Date(); return load(tenantId, today); }\n'),
    analysisFile('src/services/unrelated-clock.ts', 'export function calendar(tenantId, clock) { const today = new Date(); return load(tenantId, today); }\n'),
    analysisFile('src/services/unrelated-resolver.ts', 'export function calendar(tenantId, otherTenantId, clock) { localDateFor(otherTenantId, clock); const today = new Date(); return load(tenantId, today); }\n'),
    analysisFile('src/services/wrapped.ts', 'export function calendar(tenantId) { const today = startOfDay(new Date()); return load(tenantId, today); }\n'),
    analysisFile('src/services/string-tenant.ts', "export function calendar() { const today = new Date(); return loadCalendar('tenantId', today); }\n"),
    analysisFile('src/services/audit.ts', 'export function audit(tenantId) { const timestamp = Date.now(); return recordAudit(tenantId, timestamp); }\n'),
    analysisFile('src/services/create.ts', 'export function create(tenantId) { const createdAt = new Date(); return persist(tenantId, { createdAt }); }\n'),
    analysisFile('src/services/complete.ts', 'export function complete(tenantId) { const completedAt = new Date(); return persist(tenantId, { completedAt }); }\n'),
    analysisFile('src/services/expiry.ts', 'export function expiry(tenantId) { const expiresAt = new Date(); return persist(tenantId, { expiresAt }); }\n'),
    analysisFile('src/services/injected.ts', 'export function availability(tenantId, now = new Date()) { return loadAvailability(tenantId, now); }\n'),
    analysisFile('src/services/as-of.ts', 'export function schedule(tenantId, options) { const today = options.asOf ?? new Date(); return load(tenantId, today); }\n'),
    analysisFile('src/services/later-shadow.ts', 'const today = suppliedDate; export function calendar(tenantId) { loadCalendar(tenantId, today); { const today = new Date(); void today; } }\n'),
    analysisFile('src/services/consumer-shadow.ts', 'export function calendar(tenantId, suppliedDate) { const today = new Date(); { const today = suppliedDate; return loadCalendar(tenantId, today); } }\n')
  ];
  const findings = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.clockDateBasis);
  assert.deepEqual(
    findings.filter((entry) => entry.signals.includes('absolute-test-date')).map((entry) => entry.path).sort(),
    [
      'tests/comment-clock.test.ts',
      'tests/late-clock.test.ts',
      'tests/live-calendar.test.ts',
      'tests/unused-clock-helper.test.ts',
      'tests/wrapped-date.test.ts'
    ]
  );
  assert.deepEqual(
    findings.filter((entry) => entry.signals.includes('process-clock-read')).map((entry) => entry.path).sort(),
    [
      'src/services/calendar.ts',
      'src/services/unrelated-clock.ts',
      'src/services/unrelated-resolver.ts',
      'src/services/wrapped.ts'
    ]
  );
  assert.equal(findings.some((entry) => entry.path === 'src/services/consumer-shadow.ts'), false);
});

test('a sibling TIME column must participate in a predicate rather than only projection or ordering', () => {
  const result = detect([
    analysisFile('schema.sql', 'CREATE TABLE appointments (appointment_date DATE, start_time TIME);\n'),
    analysisFile('src/repositories/mentioned-time.ts', [
      'export const appointmentWindowQuery = `',
      '  SELECT start_time FROM appointments',
      '  WHERE appointment_date >= $1 AND appointment_date < $2',
      '  ORDER BY start_time',
      '`;',
      ''
    ].join('\n')),
    analysisFile('src/repositories/bounded-time.ts', [
      'export const appointmentWindowQuery = `',
      '  SELECT start_time FROM appointments',
      '  WHERE appointment_date >= $1 AND appointment_date < $2 AND start_time >= $3',
      '  ORDER BY start_time',
      '`;',
      ''
    ].join('\n')),
    analysisFile('src/repositories/cross-relation-time.ts', [
      'export const appointmentWindowQuery = `',
      '  SELECT a.appointment_date FROM appointments a',
      '  JOIN sessions s ON s.appointment_id = a.id',
      '  WHERE a.appointment_date >= $1 AND a.appointment_date < $2 AND s.start_time >= $3',
      '`;',
      ''
    ].join('\n')),
    analysisFile('src/repositories/same-alias-time.ts', [
      'export const appointmentWindowQuery = `',
      '  SELECT a.appointment_date FROM appointments a',
      '  JOIN sessions s ON s.appointment_id = a.id',
      '  WHERE a.appointment_date >= $1 AND a.appointment_date < $2 AND a.start_time >= $3',
      '`;',
      ''
    ].join('\n')),
    analysisFile('src/repositories/ambiguous-date-relation.ts', [
      'export const appointmentWindowQuery = `',
      '  SELECT * FROM appointments a JOIN sessions s ON s.appointment_id = a.id',
      '  WHERE appointment_date >= $1 AND appointment_date < $2',
      '`;',
      ''
    ].join('\n')),
    analysisFile('src/repositories/ambiguous-time-relation.ts', [
      'export const appointmentWindowQuery = `',
      '  SELECT * FROM appointments a JOIN sessions s ON s.appointment_id = a.id',
      '  WHERE a.appointment_date >= $1 AND a.appointment_date < $2 AND start_time >= $3',
      '`;',
      ''
    ].join('\n'))
  ]);
  const findings = result.findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.clockDateBasis && entry.signals.includes('date-only-bound-observed')
  );
  assert.deepEqual(findings.map((entry) => entry.path).sort(), [
    'src/repositories/cross-relation-time.ts',
    'src/repositories/mentioned-time.ts'
  ]);
  assert.equal(findings.some((entry) => entry.path === 'src/repositories/bounded-time.ts'), false);
  assert.equal(findings.some((entry) => entry.path?.includes('ambiguous-') || entry.path === 'src/repositories/same-alias-time.ts'), false);
});

test('host/container aggregation keeps one headline per source anchor rather than per shared mapping', () => {
  const files = [
    analysisFile('compose.yml', 'services:\n  app:\n    volumes:\n      - ./src:/app\n'),
    analysisFile('src/a.ts', "const root = path.resolve(__dirname, '..', '..');\n"),
    analysisFile('src/b.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ];
  const raw = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath);
  const processed = postprocessFindings(raw, files);
  assert.equal(processed.length, 2);
  assert.deepEqual(processed.map((entry) => entry.path), ['src/a.ts', 'src/b.ts']);
  assert(processed.every((entry) => entry.instanceCount === 1));
  assert(processed.every((entry) => entry.relatedPaths.includes('compose.yml')));
});

test('result contracts bind to resolved callees and catch findings require a returned operation', () => {
  const files = [
    analysisFile('src/a.ts', 'export function send() { return { success: true, suppressed: true }; }\n'),
    analysisFile('src/b.ts', 'export function send() { return { success: true }; }\n'),
    analysisFile('src/use-a.ts', "import { send } from './a.js'; const { success } = send(); void success;\n"),
    analysisFile('src/use-b.ts', "import { send } from './b.js'; const { success } = send(); void success;\n"),
    analysisFile('src/import-shadow.ts', "import { send } from './a.js'; export function run() { const send = () => ({ success: true }); const { success } = send(); return success; }\n"),
    analysisFile('src/local-shadow.ts', 'function send() { return { success: true, suppressed: true }; } export function run(send) { const { success } = send(); return success; }\n'),
    analysisFile('tests/use-a.test.ts', "import { send } from '../src/a.js'; const { success } = send(); void success;\n"),
    analysisFile('src/branches.ts', 'export function maybe(ok) { if (ok) return { success: true, suppressed: true }; return { success: false }; } const { success } = maybe(true); void success;\n'),
    analysisFile('src/best-effort.ts', 'export async function metric() { try { await emitMetric(); } catch (error) { console.warn(error); } }\n'),
    analysisFile('src/required.ts', 'export async function required() { try { return await deliver(); } catch (error) { auditStore.create({ error }); } }\n')
  ];
  const result = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.resultCollapse);
  assert.equal(result.filter((entry) => entry.signals.includes('caller-reads-success-only')).length, 1);
  assert.equal(result.some((entry) => entry.path === 'src/use-a.ts'), true);
  assert.equal(result.some((entry) => [
    'src/use-b.ts',
    'src/import-shadow.ts',
    'src/local-shadow.ts',
    'tests/use-a.test.ts',
    'src/branches.ts',
    'src/best-effort.ts'
  ].includes(entry.path ?? '')), false);
  assert.equal(result.some((entry) => entry.path === 'src/required.ts' && entry.signals.includes('caught-error-not-propagated')), true);
});

test('result collapse detects an unchecked discriminated class-method result before a proven durable success write', () => {
  const positive = [
    'class NotificationService {',
    '  async sendEmail(enabled) {',
    "    if (!enabled) return { success: true, messageId: 'suppressed', suppressed: true };",
    "    return { success: true, messageId: 'delivered' };",
    '  }',
    '  async logNotification(id, action) {',
    "    await sequelize.query('INSERT INTO notification_history(action) VALUES ($1)', { bind: [action] });",
    '  }',
    '  async confirm(id) {',
    '    await this.sendEmail(false);',
    "    await this.logNotification(id, 'confirmation_sent');",
    '  }',
    '}',
    ''
  ].join('\n');
  const result = detect([
    analysisFile('src/notifications/positive.ts', positive),
    analysisFile('src/notifications/direct-write.ts', [
      "function sendDelivery() { return { success: true, suppressed: true }; }",
      "export function run() { sendDelivery(); auditStore.create('confirmation_sent'); }",
      ''
    ].join('\n')),
    analysisFile('src/notifications/handled.ts', [
      'class NotificationService {',
      '  async sendEmail(enabled) {',
      "    if (!enabled) return { success: true, messageId: 'suppressed', suppressed: true };",
      "    return { success: true, messageId: 'delivered' };",
      '  }',
      '  async logNotification(id, action) {',
      "    await sequelize.query('INSERT INTO notification_history(action) VALUES ($1)', { bind: [action] });",
      '  }',
      '  async confirm(id) {',
      '    const outcome = await this.sendEmail(false);',
      '    if (outcome.suppressed) return;',
      "    await this.logNotification(id, 'confirmation_sent');",
      '  }',
      '}',
      ''
    ].join('\n')),
    analysisFile('src/notifications/logging-only.ts', [
      'class NotificationService {',
      "  sendEmail() { return { success: true, suppressed: true }; }",
      "  logNotification(action) { return auditStore.create({ action }); }",
      '  confirm() {',
      '    const outcome = this.sendEmail();',
      '    console.log(outcome.suppressed);',
      "    return this.logNotification('confirmation_sent');",
      '  }',
      '}',
      ''
    ].join('\n')),
    analysisFile('src/notifications/destructured-only.ts', [
      'class NotificationService {',
      "  sendEmail() { return { success: true, suppressed: true }; }",
      "  logNotification(action) { return auditStore.create({ action }); }",
      '  confirm() {',
      '    const { suppressed } = this.sendEmail();',
      '    console.log(suppressed);',
      "    return this.logNotification('confirmation_sent');",
      '  }',
      '}',
      ''
    ].join('\n')),
    analysisFile('src/notifications/not-durable.ts', [
      "class Service { send() { return { success: true, suppressed: true }; }",
      "  logNotification(id, action) { console.log(id, action); }",
      "  run(id) { this.send(); this.logNotification(id, 'confirmation_sent'); } }",
      ''
    ].join('\n')),
    analysisFile('src/notifications/failure-literal.ts', [
      "class Service { send() { return { success: true, suppressed: true }; }",
      "  save(id, action) { return auditStore.create({ id, action }); }",
      "  run(id) { this.send(); this.save(id, 'confirmation_failed'); } }",
      ''
    ].join('\n')),
    analysisFile('src/notifications/unpersisted-literal.ts', [
      "class Service { send() { return { success: true, suppressed: true }; }",
      "  save(id, action) { return auditStore.create({ id }); }",
      "  run(id) { this.send(); this.save(id, 'confirmation_sent'); } }",
      ''
    ].join('\n')),
    analysisFile('src/notifications/sibling-branches.ts', [
      "class Service { send() { return { success: true, suppressed: true }; }",
      "  save(id, action) { return auditStore.create({ id, action }); }",
      "  run(id, enabled) { if (enabled) { this.send(); } else { this.save(id, 'confirmation_sent'); } } }",
      ''
    ].join('\n'))
  ]).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.resultCollapse &&
    entry.signals.includes('durable-success-write-without-discriminator-branch')
  );
  assert.deepEqual(result.map((entry) => entry.path).sort(), [
    'src/notifications/destructured-only.ts',
    'src/notifications/direct-write.ts',
    'src/notifications/logging-only.ts',
    'src/notifications/positive.ts'
  ]);
  const targetFinding = result.find((entry) => entry.path === 'src/notifications/positive.ts');
  const primaryLine = targetFinding?.evidence[0]?.line;
  assert(primaryLine);
  assert.match(positive.split('\n')[primaryLine - 1] ?? '', /confirmation_sent/u);
});

test('result property evidence follows the result variable binding through nested shadows', () => {
  const result = detect([analysisFile('src/result-shadow.ts', [
    'function send() { return { success: true, suppressed: true }; }',
    'const result = send();',
    'function inspect(result) { return result.suppressed; }',
    'if (result.success) recordDelivery();',
    ''
  ].join('\n'))]).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.resultCollapse && entry.signals.includes('caller-reads-success-only')
  );
  assert.deepEqual(result.map((entry) => entry.path), ['src/result-shadow.ts']);
});

test('parse-probe catches are exempt only when their try block is parse-only', () => {
  const findings = detect([
    analysisFile('src/handlers/parse-only.ts', [
      'export function find(lines) {',
      '  for (const line of lines) {',
      '    try { const parsed = JSON.parse(line); if (parsed.ok) return parsed; } catch (_) {}',
      '  }',
      '  return null;',
      '}',
      ''
    ].join('\n')),
    analysisFile('src/handlers/parse-and-deliver.ts', [
      'export async function run(lines) {',
      '  for (const line of lines) {',
      '    try { const parsed = JSON.parse(line); return await deliver(parsed); } catch (_) {}',
      '  }',
      '  return null;',
      '}',
      ''
    ].join('\n'))
  ]).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.resultCollapse && entry.signals.includes('caught-error-not-propagated')
  );
  assert.deepEqual(findings.map((entry) => entry.path), ['src/handlers/parse-and-deliver.ts']);
});

test('required-operation catches distinguish forwarded, HTTP, typed, and continuation outcomes', () => {
  const files = [
    analysisFile('src/handlers/next.ts', 'export async function run(next) { try { return await deliver(); } catch (error) { return next(error); } }\n'),
    analysisFile('src/handlers/next-wrapped.ts', "export async function run(next) { try { return await deliver(); } catch (error) { next(new ForbiddenError('denied')); } }\n"),
    analysisFile('src/handlers/callback.ts', 'export async function run(callback) { try { return await deliver(); } catch (error) { callback(error); } }\n'),
    analysisFile('src/handlers/http.ts', 'export async function run(res) { try { return await deliver(); } catch (error) { return res.status(503).json({ error }); } }\n'),
    analysisFile('src/handlers/awaited-http.ts', 'export async function run(res) { try { return await deliver(); } catch (error) { return await res.status(503).json({ error }); } }\n'),
    analysisFile('src/handlers/fluent-http.ts', "export async function run(res) { try { return await deliver(); } catch (error) { res.status(503).type('application/json').send({ status: 'error', error }); } }\n"),
    analysisFile('src/handlers/body-error-http.ts', "export async function run(res) { try { return await deliver(); } catch (error) { res.status(200).json({ status: 'error' }); } }\n"),
    analysisFile('src/handlers/builder-http.ts', "export async function run(res) { try { return await deliver(); } catch (error) { const message = new Message(); message.add('Sorry, an error occurred'); res.type('text/plain').send(message.toString()); } }\n"),
    analysisFile('src/handlers/http-ok.ts', "export async function run(res) { try { return await deliver(); } catch (error) { res.status(200).send('OK'); } }\n"),
    analysisFile('src/handlers/throwing-helper.ts', [
      'class ErrorHandler { handle(error) { log(error); throw new Error(error.message); } }',
      'const handler = new ErrorHandler();',
      'export async function run() { try { return await deliver(); } catch (error) { handler.handle(error); } }',
      ''
    ].join('\n')),
    analysisFile('src/handlers/throwing-function.ts', [
      'function fail(error) { log(error); throw error; }',
      'export async function run() { try { return await deliver(); } catch (error) { fail(error); } }',
      ''
    ].join('\n')),
    analysisFile('src/handlers/shadowed-function.ts', [
      'function fail(error) { log(error); throw error; }',
      'export async function run(fail) { try { return await deliver(); } catch (error) { fail(error); } }',
      ''
    ].join('\n')),
    analysisFile('src/handlers/shadowed-method.ts', [
      'class ErrorHandler { handle(error) { log(error); throw error; } }',
      'const other = { handle(error) { log(error); } };',
      'export async function run() { try { return await deliver(); } catch (error) { other.handle(error); } }',
      ''
    ].join('\n')),
    analysisFile('src/handlers/imported-function.ts', [
      "import { handle } from './logger.js';",
      'class ErrorHandler { handle(error) { log(error); throw error; } }',
      'export async function run() { try { return await deliver(); } catch (error) { handle(error); } }',
      ''
    ].join('\n')),
    analysisFile('src/handlers/logger.ts', 'export function handle(error) { log(error); }\n'),
    analysisFile('src/handlers/parse-probe.ts', [
      'export async function run(lines) {',
      '  try { return await deliver(); } catch (error) {',
      '    for (const line of lines) { try { const parsed = JSON.parse(line); if (parsed.ok) return parsed; } catch (_) { /* keep scanning */ } }',
      '    return null;',
      '  }',
      '}',
      ''
    ].join('\n')),
    analysisFile('src/handlers/typed.ts', 'export async function run(): Promise<DeliveryResult> { try { return await deliver(); } catch (error) { return ({ ok: false, error } satisfies DeliveryResult); } }\n'),
    analysisFile('src/handlers/fallback.ts', 'export async function run() { try { return await deliver(); } catch { return cachedFallback; } }\n'),
    analysisFile('src/handlers/awaited-fallback.ts', 'export async function run() { try { return await deliver(); } catch { return await recoverFromCache(); } }\n'),
    analysisFile('src/handlers/empty-array.ts', 'export async function run() { try { return await deliver(); } catch { return []; } }\n'),
    analysisFile('src/handlers/continue.ts', 'export async function run(items) { for (const item of items) { try { return await deliver(item); } catch { continue; } } return []; }\n'),
    analysisFile('src/handlers/switch.ts', "export async function run() { try { return await deliver(); } catch (error) { switch (error.code) { case 'offline': return recoverFromCache(); default: throw error; } } }\n"),
    analysisFile('src/handlers/partial.ts', 'export async function run(retryable) { try { return await deliver(); } catch (error) { if (retryable) throw error; console.warn(error); } }\n'),
    analysisFile('e2e/setup.ts', 'export async function setup() { try { return await deliver(); } catch (error) { console.warn(error); } }\n'),
    analysisFile('scripts/setup.ts', 'export async function setup() { try { return await deliver(); } catch (error) { console.warn(error); } }\n'),
    analysisFile('src/handlers/swallowed.ts', 'export async function run() { try { return await deliver(); } catch (error) { console.warn(error); } }\n')
  ];
  const swallowed = detect(files).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.resultCollapse && entry.signals.includes('caught-error-not-propagated')
  );
  assert.deepEqual(swallowed.map((entry) => entry.path).sort(), [
    'src/handlers/empty-array.ts',
    'src/handlers/http-ok.ts',
    'src/handlers/imported-function.ts',
    'src/handlers/partial.ts',
    'src/handlers/shadowed-function.ts',
    'src/handlers/shadowed-method.ts',
    'src/handlers/swallowed.ts'
  ]);
});

test('CLI success-on-error requires ordered stdout and exit-zero evidence in the same AST branch', () => {
  const files = [
    analysisFile('src/cli/positive.ts', 'if (error) { console.log(error); process.exit(0); }\n'),
    analysisFile('src/cli/promise.ts', 'main().catch(e => { console.log(e); process.exit(0); });\n'),
    analysisFile('src/cli/sibling.ts', 'if (error) { console.log(error); } else { process.exit(0); }\n'),
    analysisFile('src/cli/reversed.ts', 'process.exit(0); console.log(error);\n'),
    analysisFile('src/cli/success.ts', "console.log('completed with 0 errors'); process.exit(0);\n"),
    analysisFile('src/cli/no-failure-prose.ts', "console.log('completed with no failures'); process.exit(0);\n"),
    analysisFile('src/cli/prose.ts', "const example = 'console.log(error); process.exit(0)';\n"),
    analysisFile('src/cli/no-error.ts', 'if (!error) { console.log(result); process.exit(0); }\n'),
    analysisFile('src/cli/no-failures.ts', "if (failures === 0) { console.log('clean'); process.exit(0); }\n"),
    analysisFile('src/cli/logical.ts', 'error && console.log(error); success && process.exit(0);\n'),
    analysisFile('src/cli/unreachable.ts', 'export function main() { console.log(error); return; process.exit(0); }\n'),
    analysisFile('src/cli/already-failed.ts', 'export function main() { console.log(error); process.exit(1); process.exit(0); }\n')
  ];
  const findings = detect(files).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.resultCollapse && entry.signals.includes('successful-exit-status-on-error-path')
  );
  assert.deepEqual(findings.map((entry) => entry.path).sort(), ['src/cli/positive.ts', 'src/cli/promise.ts']);
});

test('pipefail protection is scoped to the shell step that enables it', () => {
  const files = [analysisFile('.github/workflows/check.yml', [
    'run: set -o pipefail; checker | tail -1 && accept',
    'run: checker | tail -1 && accept',
    ''
  ].join('\n'))];
  const findings = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.silentEmpty);
  assert.equal(findings.filter((entry) => entry.signals.includes('conditional-uses-terminal-pipeline-status')).length, 1);
});

test('disabled workflow artifacts do not produce production silent-empty findings', () => {
  const files = [
    analysisFile('.github/workflows/active.yml', 'run: npm test -- --passWithNoTests\n'),
    analysisFile('.github/workflows/legacy.yml.disabled', 'run: npm test -- --passWithNoTests\n')
  ];
  const findings = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.silentEmpty);
  assert.deepEqual(findings.map((entry) => entry.path), ['.github/workflows/active.yml']);
});

test('Vitest basic reporter output is not treated as zero-test success', () => {
  const basic = detect([
    analysisFile('package.json', JSON.stringify({ scripts: { test: 'vitest --reporter basic' } }))
  ]).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.silentEmpty && entry.signals.includes('zero-observation-success-enabled')
  );
  assert.equal(basic.length, 0);
  const permissive = detect([
    analysisFile('package.json', JSON.stringify({ scripts: { test: 'vitest --reporter basic --passWithNoTests' } }))
  ]).findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.silentEmpty && entry.signals.includes('zero-observation-success-enabled')
  );
  assert.equal(permissive.length, 1);
});

test('host/container analysis coalesces mapping contexts at one source defect', async () => {
  const files = [
    analysisFile('compose.app.yml', 'services:\n  app:\n    volumes:\n      - ./src:/app\n'),
    analysisFile('compose.worker.yml', 'services:\n  worker:\n    volumes:\n      - ./src:/worker\n'),
    analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ];
  const result = detect(files);
  const findings = result.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.mechanism, 'dirname-divergence');
  assert.equal(findings[0]?.instanceCount, 1);
  assert.deepEqual(
    findings[0]?.mappingContexts?.map((entry) => ({
      composePath: entry.composePath,
      service: entry.service,
      sourceKind: entry.sourceKind,
      hostRoot: entry.hostRoot,
      containerRoot: entry.containerRoot
    })).sort((left, right) => left.service.localeCompare(right.service)),
    [
      { composePath: 'compose.app.yml', service: 'app', sourceKind: 'bind-mount', hostRoot: 'src', containerRoot: '/app' },
      { composePath: 'compose.worker.yml', service: 'worker', sourceKind: 'bind-mount', hostRoot: 'src', containerRoot: '/worker' }
    ]
  );
  assert.match(findings[0]?.description ?? '', /2 distinct static mapping context/u);
  await assertSchema('finding', findings[0], 'Mapping-context aggregate');
  assert.equal(result.diagnostics.some((entry) => entry.code === 'OPERATIONAL_CONTAINER_MAPPING_AMBIGUOUS'), false);

  const reversed = detect([...files].reverse()).findings.filter(
    (entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath
  );
  assert.deepEqual(reversed, findings);
});

test('bind mounts and Docker COPY are one path-divergence mechanism when the source fix is shared', () => {
  const files = [
    analysisFile('compose.bind.yml', 'services:\n  app:\n    volumes:\n      - ./src:/app\n'),
    analysisFile('compose.copy.yml', 'services:\n  app:\n    build:\n      context: .\n      dockerfile: Dockerfile.app\n'),
    analysisFile('Dockerfile.app', 'FROM node:20-alpine\nWORKDIR /srv\nCOPY src /srv\n'),
    analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ];
  const findings = detect(files).findings.filter(
    (entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.mechanism, 'dirname-divergence');
  assert.equal(findings[0]?.instanceCount, 1);
  assert.deepEqual(
    findings[0]?.mappingContexts?.map((entry) => entry.sourceKind).sort(),
    ['bind-mount', 'docker-copy']
  );
  assert.deepEqual(findings[0]?.signals, [
    'bind-mount',
    'docker-copy',
    'literal-host-container-resolution-diverges'
  ]);
});

test('host/container paths bind to one service/build context and only include selected tests', () => {
  const sameTargetServices = detect([
    analysisFile('compose.yml', [
      'services:',
      '  app:',
      '    volumes:',
      '      - ./src:/app',
      '  worker:',
      '    volumes:',
      '      - ./src:/app',
      ''
    ].join('\n')),
    analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]);
  const sameTargetFindings = sameTargetServices.findings.filter(
    (entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath
  );
  assert.equal(sameTargetFindings.length, 1);
  assert.equal(sameTargetFindings[0]?.mappingContexts?.length, 2);
  assert.equal(sameTargetServices.diagnostics.some((entry) => entry.code === 'OPERATIONAL_CONTAINER_MAPPING_AMBIGUOUS'), false);

  const namedVolume = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    volumes:\n      - src:/app\n'),
    analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]);
  assert.equal(namedVolume.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath), false);
  assert.equal(namedVolume.diagnostics.some((entry) => entry.code === 'OPERATIONAL_CONTAINER_MAPPING_UNSUPPORTED'), false);

  const undefinedBinding = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    volumes:\n      - ./app:/app\n'),
    analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]);
  assert.equal(undefinedBinding.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath), false);
  assert.equal(undefinedBinding.diagnostics.some((entry) => entry.code === 'OPERATIONAL_CONTAINER_MAPPING_UNDEFINED'), false);

  const customResolver = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    volumes:\n      - ./src:/app\n'),
    analysisFile('src/tools/check.ts', "const root = router.resolve(__dirname, '..', '..');\n")
  ]);
  assert.equal(customResolver.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath), false);

  const ordinaryTest = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    volumes:\n      - ./tests:/app/tests\n'),
    analysisFile('tests/check.test.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]);
  assert.equal(ordinaryTest.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath), false);

  const selectedTest = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    command: node --test tests/check.test.ts\n    volumes:\n      - ./tests:/app/tests\n'),
    analysisFile('tests/check.test.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]);
  assert.equal(selectedTest.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath).length, 1);
  assert.deepEqual(selectedTest.containerCoverage.map((entry) => ({
    service: entry.service,
    sourcePath: entry.sourcePath,
    containerPath: entry.containerPath,
    sourceKind: entry.sourceKind,
    selection: entry.selection
  })), [{
    service: 'app',
    sourcePath: 'tests/check.test.ts',
    containerPath: '/app/tests/check.test.ts',
    sourceKind: 'bind-mount',
    selection: 'explicit-test-path'
  }]);

  const buildBound = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    build:\n      context: .\n      dockerfile: Dockerfile.app\n'),
    analysisFile('Dockerfile.app', 'FROM node:20-alpine\nWORKDIR /app\nCOPY src /app\n'),
    analysisFile('src/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]);
  assert.equal(buildBound.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath).length, 1);

  const separatedServices = detect([
    analysisFile('compose.yml', 'services:\n  app:\n    volumes:\n      - ./app:/srv\n  worker:\n    volumes:\n      - ./worker:/srv\n'),
    analysisFile('app/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n"),
    analysisFile('worker/tools/check.ts', "const root = path.resolve(__dirname, '..', '..');\n")
  ]).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath);
  assert.equal(separatedServices.length, 2);
  assert.equal(new Set(separatedServices.map((entry) => entry.patternKey)).size, 2);
});

test('container coverage resolves the pinned test-runner shape under a broad npm test command', () => {
  const result = detect([
    analysisFile('docker-compose.test.yml', [
      'services:',
      '  test-runner-isolated:',
      '    build:',
      '      context: ./src',
      '      dockerfile: Dockerfile.test',
      '    volumes:',
      '      - ./src:/app',
      '      - /app/node_modules',
      '    command: npm test',
      'networks:',
      '  default:',
      '    name: test-network',
      ''
    ].join('\n')),
    analysisFile('src/Dockerfile.test', 'FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nCMD ["npm", "test"]\n'),
    analysisFile(
      'src/tests/unit/reference/appointment-status-artifacts.test.js',
      "const root = path.resolve(__dirname, '../../..');\n"
    )
  ]);

  assert.deepEqual(result.containerCoverage.map((entry) => ({
    composePath: entry.composePath,
    service: entry.service,
    sourcePath: entry.sourcePath,
    containerPath: entry.containerPath,
    sourceKind: entry.sourceKind,
    selection: entry.selection
  })), [{
    composePath: 'docker-compose.test.yml',
    service: 'test-runner-isolated',
    sourcePath: 'src/tests/unit/reference/appointment-status-artifacts.test.js',
    containerPath: '/app/tests/unit/reference/appointment-status-artifacts.test.js',
    sourceKind: 'bind-mount',
    selection: 'broad-test-command'
  }]);
  assert.equal(result.diagnostics.some((entry) =>
    entry.code === 'OPERATIONAL_CONTAINER_MAPPING_UNSUPPORTED' ||
    entry.code === 'OPERATIONAL_CONTAINER_MAPPING_AMBIGUOUS' ||
    entry.code === 'OPERATIONAL_DOCKERFILE_UNRESOLVED'
  ), false);
});

test('container checks detect COPY-only live inputs and accept a specific bind overlay', () => {
  const compose = (seedMount: boolean) => analysisFile('compose.yml', [
    'services:',
    '  test-runner:',
    '    build:',
    '      context: .',
    '      dockerfile: Dockerfile',
    '      target: test',
    '    volumes:',
    '      - ./tests:/app/tests',
    ...(seedMount ? ['      - ./src/seeders:/app/seeders'] : []),
    '      - dependencies:/app/node_modules',
    '      - /app/cache',
    '    command: ["npm", "run", "test:docker"]',
    'volumes:',
    '  dependencies:',
    ''
  ].join('\n'));
  const dockerfile = analysisFile('Dockerfile', [
    'FROM node:20-alpine AS base',
    'WORKDIR /app',
    'COPY src/ .',
    'FROM base AS test',
    'COPY tests/ ./tests/',
    'FROM node:20-alpine AS unrelated',
    'WORKDIR /wrong',
    'COPY other/ .',
    ''
  ].join('\n'));
  const testFile = analysisFile(
    'tests/reference/artifacts.test.ts',
    "const file = readRepoFile('src/seeders/status.js');\nvoid file;\n"
  );
  const seedFile = analysisFile('src/seeders/status.js', 'module.exports = {};\n');
  const otherFile = analysisFile('other/ignored.js', 'module.exports = {};\n');

  const broken = detect([compose(false), dockerfile, testFile, seedFile, otherFile]);
  const copyOnly = broken.findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.hostContainerPath &&
    entry.signals.includes('container-read-depends-on-build-copy')
  );
  assert.equal(copyOnly.length, 1);
  assert.equal(copyOnly[0]?.path, 'tests/reference/artifacts.test.ts');
  assert.equal(broken.diagnostics.some((entry) => entry.code === 'OPERATIONAL_CONTAINER_MAPPING_UNSUPPORTED'), false);

  const fixed = detect([compose(true), dockerfile, testFile, seedFile, otherFile]);
  assert.equal(fixed.findings.some((entry) => entry.signals.includes('container-read-depends-on-build-copy')), false);
  assert.equal(fixed.containerCoverage[0]?.sourceKind, 'bind-mount');
});

test('duplicate guard signatures retain literals and exclude mocks, comments, and status-only predicates', () => {
  const distinct = detect([
    analysisFile('src/policies/alpha.ts', "if (tenantId === 'alpha' && role === 'admin') allow();\n"),
    analysisFile('src/policies/beta.ts', "if (tenantId === 'beta' && role === 'viewer') allow();\n")
  ]);
  assert.equal(distinct.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.duplicateGuard), false);

  const duplicate = detect([
    analysisFile('src/policies/a.ts', "if(tenantId==='alpha'&&role==='admin') allow();\n"),
    analysisFile('src/policies/b.ts', "if ( tenantId === 'alpha' && role === 'admin' ) allow();\n")
  ]);
  assert.equal(duplicate.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.duplicateGuard).length, 1);

  const decimalLiterals = detect([
    analysisFile('src/policies/confidence-a.ts', "if (tenantId === ownerId && role === 'admin' && confidence >= 0.75) allow();\n"),
    analysisFile('src/policies/confidence-b.ts', "if(tenantId===ownerId&&role==='admin'&&confidence>=0.75) allow();\n"),
    analysisFile('src/policies/confidence-c.ts', "if (tenantId === ownerId && role === 'admin' && confidence >= 0.5) allow();\n")
  ]);
  const decimalFindings = decimalLiterals.findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.duplicateGuard);
  assert.equal(decimalFindings.length, 1);
  assert.equal(decimalFindings[0]?.path, 'src/policies/confidence-a.ts');
  assert.deepEqual(decimalFindings[0]?.relatedPaths, ['src/policies/confidence-b.ts']);

  const excluded = detect([
    analysisFile('src/policies/live.ts', 'if (tenantId === ownerId && role === requiredRole) allow();\n'),
    analysisFile('src/__mocks__/policy.ts', 'if (tenantId === ownerId && role === requiredRole) allow();\n'),
    analysisFile('src/fixtures/policy.ts', 'if (tenantId === ownerId && role === requiredRole) allow();\n'),
    analysisFile('sql/a.sql', '-- WHERE tenant_id = owner_id AND role = required_role;\nSELECT 1;\n'),
    analysisFile('sql/b.sql', '-- WHERE tenant_id = owner_id AND role = required_role;\nSELECT 1;\n'),
    analysisFile('src/a.ts', 'if (status === activeStatus && state === readyState) run();\n'),
    analysisFile('src/b.ts', 'if (status === activeStatus && state === readyState) run();\n')
  ]);
  assert.equal(excluded.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.duplicateGuard), false);
});

test('open-ended date findings require executable production SQL with window intent', () => {
  const files = [
    analysisFile('src/repositories/availability.ts', 'export const availabilityWindowQuery = `SELECT * FROM visits WHERE visit_date >= $1`;\n'),
    analysisFile('src/repositories/reversed.ts', 'export const appointmentWindowQuery = `SELECT * FROM appointments WHERE $1 <= appointment_date`;\n'),
    analysisFile('src/repositories/disjunctive.ts', 'export const appointmentWindowQuery = `SELECT * FROM appointments WHERE appointment_date >= $1 OR appointment_date < $2`;\n'),
    analysisFile('src/repositories/global-upper-disjunction.ts', 'export const appointmentWindowQuery = `SELECT * FROM appointments WHERE (appointment_date >= $1 OR $1 IS NULL) AND appointment_date < $2`;\n'),
    analysisFile('src/repositories/closed.ts', 'export const appointmentWindowQuery = `SELECT * FROM appointments WHERE appointment_date >= $1 AND appointment_date < $2`;\n'),
    analysisFile('src/repositories/audit.ts', 'export const query = `SELECT * FROM audit_log WHERE created_at >= $1`;\n'),
    analysisFile('src/services/prose.ts', "console.log('SELECT * FROM appointments WHERE appointment_date >= $1');\n"),
    analysisFile('tests/query.test.ts', 'export const query = `SELECT * FROM appointments WHERE appointment_date >= $1`;\n'),
    analysisFile('scripts/query.ts', 'export const query = `SELECT * FROM appointments WHERE appointment_date >= $1`;\n'),
    analysisFile('migrations/001.sql', 'SELECT * FROM appointments WHERE appointment_date >= $1;\n')
  ];
  const result = detect(files);
  const findings = result.findings.filter((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.clockDateBasis && entry.signals.includes('date-lower-bound-observed')
  );
  assert.deepEqual(findings.map((entry) => entry.path).sort(), [
    'src/repositories/availability.ts',
    'src/repositories/reversed.ts'
  ]);
  assert.equal(findings.some((entry) => entry.path === 'src/repositories/disjunctive.ts'), false);
  assert.equal(findings.some((entry) => entry.path === 'src/repositories/global-upper-disjunction.ts'), false);
  assert.deepEqual(
    result.diagnostics
      .filter((entry) => entry.code === 'OPERATIONAL_DATE_WINDOW_BOOLEAN_UNMODELED')
      .map((entry) => entry.path)
      .sort(),
    ['src/repositories/disjunctive.ts', 'src/repositories/global-upper-disjunction.ts']
  );
  assert(result.diagnostics.some((entry) => entry.code === 'OPERATIONAL_DATE_WINDOW_SEMANTICS_UNCLEAR'));
});

test('accidental protection requires a protection resolver flowing toward a mutation boundary', () => {
  const files = [
    analysisFile('src/services/positive.ts', 'export function save(input) { const statusId = resolveStatus(input.status); return auditStore.create({ name: input.name }); }\n'),
    analysisFile('src/services/shadow.ts', 'export function save(input) { const statusId = resolveStatus(input.status); function helper(statusId) { return statusId; } helper(1); return auditStore.create({ name: input.name }); }\n'),
    analysisFile('src/services/format.ts', 'export function save(input) { const tenantNameUpper = input.tenantName.toUpperCase(); return auditStore.create({ name: input.name }); }\n'),
    analysisFile('src/services/response.ts', 'export function save(response, input) { const status = readResponseCode(response); return auditStore.create({ name: input.name }); }\n'),
    analysisFile('src/services/no-boundary.ts', 'export function read(input) { const statusId = resolveStatus(input.status); return input.name; }\n'),
    analysisFile('src/services/unrelated.ts', 'export function save(input, other) { const statusId = resolveStatus(input.status); return auditStore.create({ name: other.name }); }\n'),
    analysisFile('src/services/enforcing.ts', 'export function save(user, input) { const authResult = authorizeOrThrow(user); return auditStore.create({ name: input.name }); }\n'),
    analysisFile('src/services/consumed.ts', 'export function save(input) { const statusId = resolveStatus(input.status); return auditStore.create({ name: input.name, statusId }); }\n')
  ];
  const findings = detect(files).findings.filter((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.accidentalProtection);
  assert.deepEqual(findings.map((entry) => entry.path).sort(), ['src/services/positive.ts', 'src/services/shadow.ts']);
  assert(findings.every((entry) => entry.signals.includes('downstream-mutation-boundary')));
});

test('an accidental-protection zero is explicitly incomplete rather than an all-clear', () => {
  const result = detect([
    analysisFile('src/services/negative.ts', 'export function save(input) { return auditStore.create({ name: input.name }); }\n')
  ]);
  assert.equal(
    result.findings.some((entry) => entry.ruleId === OPERATIONAL_RULE_IDS.accidentalProtection),
    false
  );
  assert(result.diagnostics.some((entry) =>
    entry.code === 'OPERATIONAL_ACCIDENTAL_PROTECTION_INPUT_INCOMPLETE'
  ));
  assert(result.observations.some((entry) =>
    entry.ruleId === OPERATIONAL_RULE_IDS.accidentalProtection && entry.state === 'uncertain'
  ));
  assert.equal(
    operationalRuleInputStatus(OPERATIONAL_RULE_IDS.accidentalProtection, result.diagnostics),
    'incomplete'
  );
});
