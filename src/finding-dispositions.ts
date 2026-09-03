import type { DiagnosticRecord, FileRecord, FindingRecord } from './types.js';
import { SCHEMA_VERSION } from './types.js';
import { FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX } from './artifact-contract.js';
import { AtlasError } from './errors.js';
import { findingReviewIdentity, findingSourcePaths } from './finding-identity.js';
import { assertSchema } from './schema-validator.js';
import { readBoundedJsonFile } from './security/bounded-artifacts.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';

export const FINDING_DISPOSITION_VERSION = '1.1.0';
export const MAX_FINDING_DISPOSITION_LEDGER_BYTES = 64 * 1024 * 1024;

export type FindingDisposition =
  | 'confirmed defect'
  | 'intentional contract'
  | 'false positive/profile gap'
  | 'test fixture'
  | 'framework-managed/external entrypoint'
  | 'obsolete but cleanup separately'
  | 'needs runtime/schema evidence'
  | 'defer';

export interface FindingDispositionAnchor {
  path: string;
  sha256: string;
}

export interface FindingDispositionEntry {
  findingId: string;
  disposition: FindingDisposition;
  reviewer: string;
  date: string;
  evidence: string[];
  anchors: FindingDispositionAnchor[];
}

export interface FindingDispositionLedger {
  $schema?: string;
  schemaVersion: 1;
  kind: 'atlas-finding-disposition-ledger';
  targetId: string;
  profileId: string;
  profileDigest: string;
  entries: Record<string, FindingDispositionEntry>;
}

export interface LoadedFindingDispositionLedger {
  ledger: FindingDispositionLedger;
  digest: string;
}

export interface FindingDispositionApplication {
  findings: FindingRecord[];
  diagnostics: DiagnosticRecord[];
  appliedReviewIds: string[];
  staleReviewIds: string[];
  suppressedFindingInstancesByRule: Record<string, number>;
}

interface AnchorState extends FindingDispositionAnchor {
  state: 'current' | 'changed' | 'missing';
  file?: FileRecord;
}

const REVIEW_KEY = /^(finding_review_sha256_[a-f0-9]{64})(?::occurrence:([1-9][0-9]*))?$/u;

function parseReviewKey(reviewId: string): {
  reviewIdentity: string;
  occurrence: number;
  occurrenceQualified: boolean;
} {
  const match = REVIEW_KEY.exec(reviewId);
  if (!match) throw new AtlasError('DISPOSITION_LEDGER_INVALID', `Disposition review key ${reviewId} is invalid.`);
  return {
    reviewIdentity: match[1]!,
    occurrence: Number(match[2] ?? '1'),
    occurrenceQualified: match[2] !== undefined
  };
}

function normalizedLedger(ledger: FindingDispositionLedger): FindingDispositionLedger {
  const entries = Object.fromEntries(Object.entries(ledger.entries)
    .sort(([left], [right]) => compareCanonicalText(left, right))
    .map(([reviewId, entry]) => [reviewId, {
      ...entry,
      evidence: [...entry.evidence].sort(compareCanonicalText),
      anchors: [...entry.anchors].sort((left, right) =>
        compareCanonicalText(left.path, right.path) || compareCanonicalText(left.sha256, right.sha256)
      )
    }]));
  return { ...ledger, entries };
}

function assertLedgerSemantics(ledger: FindingDispositionLedger): void {
  const findingIds = new Map<string, string>();
  const reviewOccurrences = new Map<string, string>();
  for (const [reviewId, entry] of Object.entries(ledger.entries).sort(([left], [right]) => compareCanonicalText(left, right))) {
    const parsedReview = parseReviewKey(reviewId);
    const occurrenceKey = `${parsedReview.reviewIdentity}\0${parsedReview.occurrence}`;
    const existingOccurrence = reviewOccurrences.get(occurrenceKey);
    if (existingOccurrence !== undefined) {
      throw new AtlasError(
        'DISPOSITION_LEDGER_INVALID',
        `Disposition reviews ${existingOccurrence} and ${reviewId} address the same finding occurrence.`
      );
    }
    reviewOccurrences.set(occurrenceKey, reviewId);
    const existingReview = findingIds.get(entry.findingId);
    if (existingReview !== undefined) {
      throw new AtlasError(
        'DISPOSITION_LEDGER_INVALID',
        `Disposition reviews ${existingReview} and ${reviewId} reference the same finding identity ${entry.findingId}.`
      );
    }
    findingIds.set(entry.findingId, reviewId);
    const anchorPaths = new Set<string>();
    for (const anchor of entry.anchors) {
      if (anchorPaths.has(anchor.path)) {
        throw new AtlasError(
          'DISPOSITION_LEDGER_INVALID',
          `Disposition review ${reviewId} declares source path ${anchor.path} more than once.`
        );
      }
      anchorPaths.add(anchor.path);
    }
  }
}

export async function loadFindingDispositionLedger(
  ledgerPath: string,
  expected: { targetId: string; profileId: string; profileDigest: string }
): Promise<LoadedFindingDispositionLedger> {
  const raw = await readBoundedJsonFile<unknown>(ledgerPath, {
    maxBytes: MAX_FINDING_DISPOSITION_LEDGER_BYTES,
    maxDepth: 128,
    resourceCode: 'DISPOSITION_LEDGER_RESOURCE_LIMIT',
    invalidCode: 'DISPOSITION_LEDGER_INVALID',
    label: 'Finding disposition ledger'
  });
  await assertSchema('finding-disposition-ledger', raw, 'Finding disposition ledger');
  const ledger = normalizedLedger(raw as FindingDispositionLedger);
  assertLedgerSemantics(ledger);
  if (ledger.targetId !== expected.targetId) {
    throw new AtlasError(
      'DISPOSITION_TARGET_MISMATCH',
      `Disposition ledger target ${ledger.targetId} does not match scan target ${expected.targetId}.`
    );
  }
  if (ledger.profileId !== expected.profileId || ledger.profileDigest !== expected.profileDigest) {
    throw new AtlasError(
      'DISPOSITION_PROFILE_MISMATCH',
      'Disposition ledger profile identity does not match the exact scan profile; review dispositions again under the current profile.'
    );
  }
  return { ledger, digest: sha256(canonicalJson(ledger)) };
}

export function findingDispositionAnalysisMarker(digest: string): string {
  if (!/^[a-f0-9]{64}$/u.test(digest)) {
    throw new AtlasError('DISPOSITION_LEDGER_INVALID', 'Disposition ledger digest must be a lowercase SHA-256 value.');
  }
  return `${FINDING_DISPOSITION_ANALYSIS_MARKER_PREFIX}${FINDING_DISPOSITION_VERSION}+sha256.${digest}`;
}

function findingInstanceCount(finding: FindingRecord): number {
  return finding.instanceCount ?? 1;
}

function dispositionEvidence(
  pathValue: string | undefined,
  file: FileRecord | undefined,
  basis: string
): DiagnosticRecord['evidence'] {
  return {
    level: 1,
    producer: 'atlas/finding-dispositions',
    producerVersion: FINDING_DISPOSITION_VERSION,
    basis,
    ...(pathValue ? { path: pathValue } : {}),
    ...(file ? { recordIds: [file.id] } : {})
  };
}

function dispositionDiagnostic(options: {
  code: 'FINDING_DISPOSITION_APPLIED' | 'FINDING_DISPOSITION_STALE' | 'FINDING_DISPOSITION_ANCHOR_MISMATCH';
  severity: DiagnosticRecord['severity'];
  message: string;
  reviewId: string;
  entry: FindingDispositionEntry;
  state: 'applied' | 'stale' | 'anchor-mismatch';
  finding?: FindingRecord;
  path?: string;
  file?: FileRecord;
  basis: string;
  material: unknown;
}): DiagnosticRecord {
  const projectedFindingId = options.state === 'applied' && options.finding
    ? options.finding.id
    : options.entry.findingId;
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({
      producer: 'atlas/finding-dispositions',
      version: FINDING_DISPOSITION_VERSION,
      code: options.code,
      reviewId: options.reviewId,
      findingId: projectedFindingId,
      material: options.material
    })).slice(0, 24)}`,
    code: options.code,
    severity: options.severity,
    message: options.message,
    ...(options.path ? { path: options.path } : {}),
    disposition: {
      reviewId: options.reviewId,
      findingId: projectedFindingId,
      ...(options.finding ? { title: options.finding.title, ruleId: options.finding.ruleId } : {}),
      disposition: options.entry.disposition,
      reviewer: options.entry.reviewer,
      date: options.entry.date,
      evidence: [...options.entry.evidence],
      anchors: options.entry.anchors.map((anchor) => ({ ...anchor })),
      state: options.state
    },
    evidence: dispositionEvidence(
      options.path,
      options.file,
      options.basis
    )
  };
}

function cappedPaths(paths: string[]): string {
  const shown = paths.slice(0, 8);
  const remainder = paths.length - shown.length;
  return `${shown.join(', ')}${remainder > 0 ? ` (+${remainder} more)` : ''}`;
}

export function applyFindingDispositions(
  ledger: FindingDispositionLedger,
  findings: FindingRecord[],
  files: FileRecord[]
): FindingDispositionApplication {
  const fileByPath = new Map(files.map((file) => [file.path, file]));
  const findingsByReviewIdentity = new Map<string, FindingRecord[]>();
  for (const finding of findings) {
    const reviewIdentity = findingReviewIdentity(finding);
    const values = findingsByReviewIdentity.get(reviewIdentity) ?? [];
    values.push(finding);
    findingsByReviewIdentity.set(reviewIdentity, values);
  }
  for (const values of findingsByReviewIdentity.values()) {
    values.sort((left, right) => compareCanonicalText(left.id, right.id));
  }
  const suppressedFindingIds = new Set<string>();
  const diagnostics: DiagnosticRecord[] = [];
  const appliedReviewIds: string[] = [];
  const staleReviewIds: string[] = [];
  const suppressedFindingInstancesByRule: Record<string, number> = {};

  for (const [reviewId, entry] of Object.entries(ledger.entries).sort(([left], [right]) => compareCanonicalText(left, right))) {
    const review = parseReviewKey(reviewId);
    const candidates = findingsByReviewIdentity.get(review.reviewIdentity) ?? [];
    const anchorStates: AnchorState[] = entry.anchors.map((anchor) => {
      const file = fileByPath.get(anchor.path);
      return {
        ...anchor,
        state: file === undefined ? 'missing' : file.sha256 === anchor.sha256 ? 'current' : 'changed',
        ...(file ? { file } : {})
      };
    });
    const staleAnchors = anchorStates.filter((anchor) => anchor.state !== 'current');
    if (staleAnchors.length > 0) {
      staleReviewIds.push(reviewId);
      const changedPaths = staleAnchors.filter((anchor) => anchor.state === 'changed').map((anchor) => anchor.path);
      const missingPaths = staleAnchors.filter((anchor) => anchor.state === 'missing').map((anchor) => anchor.path);
      const details = [
        ...(changedPaths.length ? [`changed: ${cappedPaths(changedPaths)}`] : []),
        ...(missingPaths.length ? [`missing from this scan: ${cappedPaths(missingPaths)}`] : [])
      ].join('; ');
      const primary = staleAnchors[0]!;
      diagnostics.push(dispositionDiagnostic({
        code: 'FINDING_DISPOSITION_STALE',
        severity: 'warning',
        message: `Disposition review ${reviewId} for ${entry.findingId} is stale (${details}); it suppresses no current finding.`,
        reviewId,
        entry,
        state: 'stale',
        path: primary.path,
        ...(primary.file ? { file: primary.file } : {}),
        basis: 'stale-finding-disposition-source-anchor',
        material: staleAnchors.map(({ path: anchorPath, sha256: expected, state, file }) => ({
          path: anchorPath,
          expected,
          state,
          ...(file ? { observed: file.sha256 } : {})
        }))
      }));
      continue;
    }
    if (!candidates.length) continue;

    const occurrenceFormMatches = candidates.length === 1
      ? !review.occurrenceQualified
      : review.occurrenceQualified;
    if (!occurrenceFormMatches) {
      const primary = anchorStates[0]!;
      diagnostics.push(dispositionDiagnostic({
        code: 'FINDING_DISPOSITION_ANCHOR_MISMATCH',
        severity: 'warning',
        message: candidates.length === 1
          ? `Disposition review ${reviewId} uses an occurrence-qualified key for a singleton current identity; the finding was retained.`
          : `Disposition review ${reviewId} omits the required occurrence suffix for ${candidates.length} current findings; all candidates were retained.`,
        reviewId,
        entry,
        state: 'anchor-mismatch',
        path: primary.path,
        ...(primary.file ? { file: primary.file } : {}),
        basis: 'finding-disposition-occurrence-mismatch',
        material: {
          candidateFindingIds: candidates.map((finding) => finding.id),
          occurrenceQualified: review.occurrenceQualified,
          requestedOccurrence: review.occurrence
        }
      }));
      continue;
    }

    const ledgerAnchorPaths = new Set(anchorStates.map((anchor) => anchor.path));
    const candidateAnchors = candidates.map((finding) => {
      const sourcePaths = findingSourcePaths(finding).filter((sourcePath) => fileByPath.has(sourcePath));
      return {
        finding,
        sourcePaths,
        missingSourcePaths: sourcePaths.filter((sourcePath) => !ledgerAnchorPaths.has(sourcePath)),
        matchingAnchor: anchorStates.find((anchor) => sourcePaths.includes(anchor.path))
      };
    }).filter((candidate): candidate is {
      finding: FindingRecord;
      sourcePaths: string[];
      missingSourcePaths: string[];
      matchingAnchor: AnchorState;
    } => candidate.matchingAnchor !== undefined && candidate.missingSourcePaths.length === 0);
    const requestedFinding = candidates[review.occurrence - 1];
    const selected = requestedFinding === undefined
      ? undefined
      : candidateAnchors.find((candidate) => candidate.finding.id === requestedFinding.id);
    if (!selected) {
      const primary = anchorStates[0]!;
      diagnostics.push(dispositionDiagnostic({
        code: 'FINDING_DISPOSITION_ANCHOR_MISMATCH',
        severity: 'warning',
        message: candidateAnchors.length > 1
          ? `Disposition review ${reviewId} matches multiple current findings through its source anchors; all candidates were retained.`
          : `Disposition review ${reviewId} has no source anchor belonging to its current finding candidate; the finding was retained.`,
        reviewId,
        entry,
        state: 'anchor-mismatch',
        path: primary.path,
        ...(primary.file ? { file: primary.file } : {}),
        basis: 'finding-disposition-anchor-mismatch',
        material: {
          ledgerPaths: anchorStates.map((anchor) => anchor.path),
          candidateFindingIds: candidates.map((finding) => finding.id),
          coveredFindingIds: candidateAnchors.map((candidate) => candidate.finding.id),
          missingSourcePaths: candidates.map((finding) => ({
            findingId: finding.id,
            paths: findingSourcePaths(finding)
              .filter((sourcePath) => !ledgerAnchorPaths.has(sourcePath))
              .sort(compareCanonicalText)
          }))
        }
      }));
      continue;
    }

    const { finding, matchingAnchor } = selected;
    suppressedFindingIds.add(finding.id);
    appliedReviewIds.push(reviewId);
    suppressedFindingInstancesByRule[finding.ruleId] =
      (suppressedFindingInstancesByRule[finding.ruleId] ?? 0) + findingInstanceCount(finding);
    const diagnosticPath = finding.path ?? matchingAnchor.path;
    const diagnosticFile = fileByPath.get(diagnosticPath);
    diagnostics.push(dispositionDiagnostic({
      code: 'FINDING_DISPOSITION_APPLIED',
      severity: 'info',
      message: `Disposition review ${reviewId} (${entry.disposition}) suppressed current finding ${finding.id}; all ${entry.anchors.length} source anchor(s) match.`,
      reviewId,
      entry,
      state: 'applied',
      finding,
      path: diagnosticPath,
      ...(diagnosticFile ? { file: diagnosticFile } : {}),
      basis: 'current-finding-disposition-source-anchors',
      material: { disposition: entry.disposition, anchors: entry.anchors }
    }));
  }

  return {
    findings: findings.filter((finding) => !suppressedFindingIds.has(finding.id)),
    diagnostics: diagnostics.sort((left, right) => compareCanonicalText(left.id, right.id)),
    appliedReviewIds,
    staleReviewIds,
    suppressedFindingInstancesByRule: Object.fromEntries(Object.entries(suppressedFindingInstancesByRule)
      .sort(([left], [right]) => compareCanonicalText(left, right)))
  };
}
