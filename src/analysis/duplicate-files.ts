import path from 'node:path';
import type { AnalysisFile, DiagnosticRecord, EvidenceReference, FindingRecord } from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';

export const DUPLICATE_FILE_ANALYSIS_VERSION = '1.0.0';

const PRODUCER = 'atlas/duplicate-files';
const MINIMUM_AUTHORED_BYTES = 128;
const GENERATED_DIRECTORIES = new Set([
  '.cache', '.next', '.turbo', 'build', 'coverage', 'dist', 'generated', 'gen',
  'node_modules', 'vendor'
]);
const EXCLUDED_BASENAMES = new Set([
  '.gitkeep', 'cargo.lock', 'composer.lock', 'license', 'license.md', 'license.txt',
  'package-lock.json', 'package.json', 'pnpm-lock.yaml', 'poetry.lock', 'tsconfig.json',
  'yarn.lock'
]);

type ExclusionReason =
  | 'binary-or-unknown'
  | 'documentation-or-test'
  | 'generated-marker'
  | 'generated-or-vendor-path'
  | 'lockfile-or-package-metadata'
  | 'minified-or-source-map'
  | 'tiny-or-whitespace-only';

interface EligibleFile {
  file: AnalysisFile;
  reason?: ExclusionReason;
}

function evidence(file: AnalysisFile): EvidenceReference {
  return {
    level: 0,
    producer: PRODUCER,
    producerVersion: DUPLICATE_FILE_ANALYSIS_VERSION,
    basis: 'snapshot-byte-identity-verified-against-buffer',
    path: file.record.path,
    line: 1,
    column: 1,
    recordIds: [file.record.id]
  };
}

function id(prefix: 'finding' | 'diagnostic', material: unknown): string {
  return `${prefix}:${sha256(canonicalJson(material)).slice(0, 24)}`;
}

function diagnostic(code: string, message: string, file: AnalysisFile, material: unknown): DiagnosticRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: id('diagnostic', { code, material }),
    code,
    severity: 'info',
    message,
    path: file.record.path,
    location: { line: 1, column: 1, endLine: 1, endColumn: 1 },
    evidence: evidence(file)
  };
}

function generatedMarker(content: Buffer): boolean {
  const prefix = content.subarray(0, Math.min(content.length, 4096)).toString('utf8').toLowerCase();
  return /(?:@generated|auto[- ]generated|automatically generated|code generated|do not edit)/u.test(prefix);
}

function exclusionFor(file: AnalysisFile): ExclusionReason | undefined {
  const lowerPath = file.record.path.toLowerCase();
  const basename = path.posix.basename(lowerPath);
  const segments = lowerPath.split('/');
  if (file.record.bytes < MINIMUM_AUTHORED_BYTES || !file.content.toString('utf8').trim()) return 'tiny-or-whitespace-only';
  if (file.record.language === 'binary' || file.record.language === 'unknown') return 'binary-or-unknown';
  if (file.record.kind === 'test' || file.record.kind === 'documentation') return 'documentation-or-test';
  if (segments.some((segment) => GENERATED_DIRECTORIES.has(segment))) return 'generated-or-vendor-path';
  if (EXCLUDED_BASENAMES.has(basename) || /(?:^|[-.])lock(?:\.[^.]+)?$/u.test(basename)) return 'lockfile-or-package-metadata';
  if (/\.(?:map|min\.js|min\.css)$/u.test(lowerPath)) return 'minified-or-source-map';
  if (generatedMarker(file.content)) return 'generated-marker';
  return undefined;
}

function bufferIdentity(files: AnalysisFile[]): boolean {
  const first = files[0]?.content;
  return Boolean(first && files.every((file) => file.content.equals(first)));
}

export function detectDuplicateFileCandidates(
  files: AnalysisFile[]
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const uniqueByPath = new Map<string, AnalysisFile>();
  const conflictedPaths = new Set<string>();
  const diagnostics: DiagnosticRecord[] = [];
  for (const file of [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path))) {
    if (conflictedPaths.has(file.record.path)) continue;
    const existing = uniqueByPath.get(file.record.path);
    if (!existing) {
      uniqueByPath.set(file.record.path, file);
      continue;
    }
    if (existing.record.id !== file.record.id || !existing.content.equals(file.content)) {
      diagnostics.push(diagnostic(
        'CLEANUP_DUPLICATE_INPUT_PATH_CONFLICT',
        'The cleanup input contains conflicting records for one path; duplicate analysis suppressed that path.',
        existing,
        { path: existing.record.path }
      ));
      uniqueByPath.delete(file.record.path);
      conflictedPaths.add(file.record.path);
    }
  }

  const pathsByRecordId = new Map<string, string[]>();
  for (const file of uniqueByPath.values()) {
    const values = pathsByRecordId.get(file.record.id) ?? [];
    values.push(file.record.path);
    pathsByRecordId.set(file.record.id, values);
  }
  for (const [recordId, paths] of pathsByRecordId) {
    if (paths.length < 2) continue;
    paths.sort(compareCanonicalText);
    const first = uniqueByPath.get(paths[0]!)!;
    diagnostics.push({
      ...diagnostic(
        'CLEANUP_DUPLICATE_RECORD_ID_CONFLICT',
        'One file record ID is bound to multiple paths; Atlas suppressed those inputs rather than treating them as duplicates.',
        first,
        { recordId, paths }
      ),
      severity: 'error'
    });
    for (const filePath of paths) uniqueByPath.delete(filePath);
  }

  const byDeclaredDigest = new Map<string, AnalysisFile[]>();
  for (const file of uniqueByPath.values()) {
    const actualDigest = sha256(file.content);
    if (file.record.bytes !== file.content.length || file.record.sha256 !== actualDigest) {
      diagnostics.push({
        ...diagnostic(
          'CLEANUP_DUPLICATE_RECORD_CONTENT_MISMATCH',
          'A file record does not match its supplied bytes; Atlas suppressed it from duplicate analysis.',
          file,
          { path: file.record.path }
        ),
        severity: 'error'
      });
      continue;
    }
    const key = `${file.record.bytes}\0${file.record.sha256}`;
    const values = byDeclaredDigest.get(key) ?? [];
    values.push(file);
    byDeclaredDigest.set(key, values);
  }

  const findings: FindingRecord[] = [];
  for (const members of byDeclaredDigest.values()) {
    if (members.length < 2) continue;
    members.sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
    const first = members[0]!;
    if (!bufferIdentity(members)) {
      diagnostics.push({
        ...diagnostic(
          'CLEANUP_DUPLICATE_DIGEST_CONFLICT',
          'Files share declared byte metadata but their supplied buffers differ; Atlas suppressed the duplicate claim.',
          first,
          { digest: first.record.sha256, paths: members.map((file) => file.record.path) }
        ),
        severity: 'error'
      });
      continue;
    }
    const eligibility: EligibleFile[] = members.map((file) => {
      const reason = exclusionFor(file);
      return { file, ...(reason ? { reason } : {}) };
    });
    const reasons = [...new Set(eligibility.flatMap((entry) => entry.reason ? [entry.reason] : []))]
      .sort(compareCanonicalText);
    const languages = [...new Set(members.map((file) => file.record.language))];
    const kinds = [...new Set(members.map((file) => file.record.kind))];
    if (reasons.length || languages.length !== 1 || kinds.length !== 1) {
      diagnostics.push(diagnostic(
        'CLEANUP_DUPLICATE_GROUP_SUPPRESSED',
        'A byte-identical group was suppressed because generated, boilerplate, non-authored, or cross-semantic duplicates are not safe cleanup candidates.',
        first,
        {
          paths: members.map((file) => file.record.path),
          reasons,
          mixedKinds: kinds.length !== 1,
          mixedLanguages: languages.length !== 1
        }
      ));
      continue;
    }
    const paths = members.map((file) => file.record.path);
    const ruleId = 'dead-code/byte-identical-authored-files-v1';
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: id('finding', { ruleId, digest: first.record.sha256, paths }),
      category: 'dead-code-candidate',
      ruleId,
      status: 'candidate',
      severity: 'info',
      confidence: 'high',
      title: `Review byte-identical authored files (${members.length})`,
      description: 'Atlas verified that these authored files have identical bytes. Their canonical path ordering is only a comparison anchor, not a recommendation to retain or delete any member.',
      path: first.record.path,
      relatedPaths: paths.slice(1),
      signals: [
        'same-declared-byte-length',
        'same-declared-sha256',
        'supplied-buffers-byte-identical',
        'generated-test-documentation-and-boilerplate-exclusions-passed'
      ],
      evidence: members.map(evidence),
      nextValidation: 'Check intentional platform variants, vendoring, generated provenance, licensing, independent release boundaries, and runtime references before consolidating anything.'
    });
  }

  findings.sort((left, right) => compareCanonicalText(left.id, right.id));
  const uniqueDiagnostics = [...new Map(diagnostics.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings, diagnostics: uniqueDiagnostics };
}
