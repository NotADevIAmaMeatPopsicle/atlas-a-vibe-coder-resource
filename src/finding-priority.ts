import { findingReviewAnchors, findingReviewIdentity } from './finding-identity.js';
import type {
  FileRecord,
  FindingImpactContext,
  FindingRecord,
  FindingReviewAnchor,
  FindingReviewPriority,
  FindingReviewPriorityBand
} from './types.js';
import { canonicalJson, compareCanonicalText } from './util/canonical.js';

const SEVERITY_RANK: Record<FindingRecord['severity'], FindingReviewPriority['severityRank']> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3
};

const CONFIDENCE_RANK: Record<FindingRecord['confidence'], FindingReviewPriority['confidenceRank']> = {
  confirmed: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4
};

const IMPACT_RANK: Record<FindingReviewPriorityBand, FindingReviewPriority['impactRank']> = {
  'production-ungated': 0,
  'production-gate-unknown': 1,
  'production-gated': 2,
  cli: 3,
  'build-migration-seeder': 4,
  'reachability-incomplete': 5,
  test: 6,
  inactive: 7
};

const BAND_LABEL: Record<FindingReviewPriorityBand, string> = {
  'production-ungated': 'Production, no observed feature gate',
  'production-gate-unknown': 'Production, feature-gate status unknown',
  'production-gated': 'Production, feature gate observed',
  cli: 'Reachable CLI surface',
  'build-migration-seeder': 'Reachable build, migration, or seeder surface',
  'reachability-incomplete': 'Reachability or scope incomplete',
  test: 'Test-only surface',
  inactive: 'Unreachable or mothballed surface'
};

export interface FindingReviewMetadata {
  reviewId: string;
  reviewAnchors: FindingReviewAnchor[];
  reviewPriority: FindingReviewPriority;
  refutationCondition: string;
}

export type FindingReviewMetadataField = keyof FindingReviewMetadata;

export interface FindingReviewMetadataMismatch {
  findingId: string;
  fields: FindingReviewMetadataField[];
}

export interface OmittedFindingReviewReference {
  findingId: string;
  reviewId: string;
}

type FileDigestIndex = ReadonlyMap<string, string>;

const REVIEW_ID_PATTERN = /^(finding_review_sha256_[a-f0-9]{64})(?::occurrence:[1-9][0-9]*)?$/u;

function impactBand(context: FindingImpactContext): FindingReviewPriorityBand {
  if (context.lifecycle === 'mothballed' || context.reachability === 'unreachable') return 'inactive';
  if (context.reachability !== 'reachable') return 'reachability-incomplete';
  if (context.scope === 'production') {
    if (context.featureGate === 'not-observed') return 'production-ungated';
    if (context.featureGate === 'unknown') return 'production-gate-unknown';
    return 'production-gated';
  }
  if (context.scope === 'cli') return 'cli';
  if (context.scope === 'build' || context.scope === 'migration' || context.scope === 'seeder') {
    return 'build-migration-seeder';
  }
  if (context.scope === 'test') return 'test';
  return 'reachability-incomplete';
}

function findingImpactBand(finding: FindingRecord): FindingReviewPriorityBand {
  const contexts = [
    ...(finding.impactContext ? [finding.impactContext] : []),
    ...(finding.instances ?? []).flatMap((instance) => instance.impactContext ? [instance.impactContext] : [])
  ];
  return contexts
    .map(impactBand)
    .sort((left, right) => IMPACT_RANK[left] - IMPACT_RANK[right])[0] ?? 'reachability-incomplete';
}

function findingReportedInstanceCount(finding: FindingRecord): number {
  return finding.instanceCount ?? finding.instances?.length ?? 1;
}

/** Derive priority exclusively from existing severity, impact, confidence, and instance fields. */
export function reviewPriorityForFinding(finding: FindingRecord): FindingReviewPriority {
  const band = findingImpactBand(finding);
  return {
    version: 'static-actionability-v1',
    band,
    severityRank: SEVERITY_RANK[finding.severity],
    impactRank: IMPACT_RANK[band],
    confidenceRank: CONFIDENCE_RANK[finding.confidence],
    instanceCount: findingReportedInstanceCount(finding)
  };
}

export function findingReviewPriorityBandLabel(band: FindingReviewPriorityBand): string {
  return BAND_LABEL[band];
}

/**
 * Review order is severity, actionable impact, confidence, then repeated
 * instances. Stable review identity and record ID provide deterministic ties.
 * Stored priority metadata is deliberately recomputed so legacy and forged
 * records cannot alter ordering.
 */
export function compareFindingReviewPriority(left: FindingRecord, right: FindingRecord): number {
  const leftPriority = reviewPriorityForFinding(left);
  const rightPriority = reviewPriorityForFinding(right);
  return leftPriority.severityRank - rightPriority.severityRank ||
    leftPriority.impactRank - rightPriority.impactRank ||
    leftPriority.confidenceRank - rightPriority.confidenceRank ||
    rightPriority.instanceCount - leftPriority.instanceCount ||
    compareCanonicalText(findingReviewIdentity(left), findingReviewIdentity(right)) ||
    compareCanonicalText(left.id, right.id);
}

/**
 * State the evidence that would falsify the conclusion, rather than repeating
 * the next investigative action. The wording is deterministic for verifier
 * recomputation and intentionally excluded from review identity.
 */
export function refutationConditionForFinding(finding: FindingRecord): string {
  let condition: string;
  if (finding.ruleId === 'contract/api-client-route-missing-v1' ||
      finding.ruleId === 'contract/api-client-method-mismatch-v1') {
    condition = 'This finding is refuted if the effective runtime route table, after mounts, prefixes, aliases, and generated registration are applied, exposes every reported client method and path.';
  } else if (finding.ruleId === 'contract/unresolved-internal-import-v1') {
    condition = 'This finding is refuted if configured resolver, loader, package, or generated-module semantics resolve every reported specifier to shipped runtime code.';
  } else if (finding.ruleId.startsWith('contract/data-')) {
    condition = 'This finding is refuted if field mappings or the effective deployed schema make every reported model, migration, and storage contract equivalent on the reported dimension.';
  } else if (finding.ruleId.startsWith('contract/deployment-') ||
      finding.ruleId.startsWith('contract/terraform-')) {
    condition = 'This finding is refuted if interpolation and the effective deployment configuration prove that every reported declaration and consumer resolve to the same runtime value or intentionally absent value.';
  } else if (finding.ruleId === 'contract/vocabulary-drift-v1') {
    condition = 'This finding is refuted if the reported vocabularies belong to distinct domains, or an enforced normalization step makes their accepted values equivalent before comparison or persistence.';
  } else if (finding.ruleId === 'contract/seeded-dictionary-id-coupling-v1') {
    condition = 'This finding is refuted if every reported boundary resolves a stable semantic key or name instead of relying on an environment-local seeded identifier.';
  } else if (finding.ruleId === 'dead-code/static-reachability-v1' ||
      finding.category === 'dead-code-candidate') {
    condition = 'This finding is refuted if a supported framework, loader, package, CLI, deployment, generated-code, or external-consumer path activates any reported source instance.';
  } else if (finding.category === 'architecture-mismatch') {
    condition = 'This finding is refuted if the declared architecture policy permits the reported dependency, or the referenced edge cannot cross the reported runtime layer boundary.';
  } else if (finding.ruleId === 'operational/silent-empty-instrument-v1') {
    condition = 'This finding is refuted if the reported empty or missing state is explicitly surfaced as non-healthy and cannot be recorded or returned as successful execution.';
  } else if (finding.ruleId === 'operational/result-collapse-v1') {
    condition = 'This finding is refuted if every materially distinct reported outcome is preserved through the caller-visible return, exit, status, or durable result channel.';
  } else if (finding.ruleId === 'operational/host-container-path-divergence-v1') {
    condition = 'This finding is refuted if the effective image, mount, working-directory, and runtime path mappings resolve every reported host and container reference to the same shipped artifact.';
  } else if (finding.ruleId === 'operational/clock-date-basis-v1') {
    condition = 'This finding is refuted if every reported value is created, compared, and persisted in one explicit clock and timezone basis, or is normalized before the boundary.';
  } else if (finding.ruleId === 'operational/guard-bypass-v1') {
    condition = 'This finding is refuted if every reported bypass path is unreachable or enforces the same authorization and state preconditions as the guarded path.';
  } else if (finding.ruleId === 'operational/duplicate-guard-fragment-v1') {
    condition = 'This finding is refuted if the reported guard fragments are generated from one authoritative policy or are proven to enforce intentionally different contracts.';
  } else if (finding.ruleId === 'latent/accidental-protection-v1') {
    condition = 'This finding is refuted if the protection-shaped value participates in an enforcing branch or durable state transition and removing it changes the protected behavior.';
  } else if (finding.category === 'contract-mismatch') {
    condition = 'This finding is refuted if resolution, normalization, or runtime composition proves that every reported producer and consumer enforce the same effective contract.';
  } else if (finding.category === 'operational-defect') {
    condition = 'This finding is refuted if execution-path evidence proves that the reported failure state cannot occur or is propagated before success is recorded.';
  } else if (finding.category === 'review-inventory') {
    condition = 'This finding is refuted if the reported sites do not implement the same policy boundary or are generated from one authoritative, enforced definition.';
  } else {
    condition = 'This finding is refuted if source or runtime evidence proves that the reported signals cannot produce the stated behavior in any supported configuration.';
  }
  const normalizedValidation = finding.nextValidation.trim();
  return condition === normalizedValidation
    ? `${condition} The falsifier must be established independently of the proposed validation step.`
    : condition;
}

export function deriveFindingReviewMetadata(
  finding: FindingRecord,
  files: readonly Pick<FileRecord, 'path' | 'sha256'>[]
): FindingReviewMetadata {
  return deriveFindingReviewMetadataWithIndex(
    finding,
    new Map(files.map((file) => [file.path, file.sha256]))
  );
}

function deriveFindingReviewMetadataWithIndex(
  finding: FindingRecord,
  digestByPath: FileDigestIndex
): FindingReviewMetadata {
  return {
    reviewId: findingReviewIdentity(finding),
    reviewAnchors: findingReviewAnchors(finding, digestByPath),
    reviewPriority: reviewPriorityForFinding(finding),
    refutationCondition: refutationConditionForFinding(finding)
  };
}

/**
 * Attach metadata to a complete finding collection. Duplicate stable review
 * identities receive occurrence suffixes in canonical finding-ID order, which
 * makes every ledger key recoverable from findings.jsonl alone.
 */
export function attachFindingReviewMetadata(
  findings: readonly FindingRecord[],
  files: readonly Pick<FileRecord, 'path' | 'sha256'>[]
): Array<FindingRecord & FindingReviewMetadata> {
  const digestByPath = new Map(files.map((file) => [file.path, file.sha256]));
  const metadata = findings.map((finding) => deriveFindingReviewMetadataWithIndex(finding, digestByPath));
  const groups = new Map<string, number[]>();
  for (let index = 0; index < metadata.length; index += 1) {
    const baseReviewId = metadata[index]!.reviewId;
    const members = groups.get(baseReviewId) ?? [];
    members.push(index);
    groups.set(baseReviewId, members);
  }
  const assignedReviewIds = new Map<number, string>();
  for (const [baseReviewId, members] of groups) {
    const ordered = [...members].sort((leftIndex, rightIndex) =>
      compareCanonicalText(findings[leftIndex]!.id, findings[rightIndex]!.id)
    );
    for (let occurrence = 0; occurrence < ordered.length; occurrence += 1) {
      assignedReviewIds.set(
        ordered[occurrence]!,
        ordered.length === 1 ? baseReviewId : `${baseReviewId}:occurrence:${occurrence + 1}`
      );
    }
  }
  return findings.map((finding, index) => ({
    ...finding,
    ...metadata[index]!,
    reviewId: assignedReviewIds.get(index)!
  }));
}

/** Return the exact persisted review fields that fail current deterministic derivation. */
export function findingReviewMetadataMismatches(
  finding: FindingRecord,
  files: readonly Pick<FileRecord, 'path' | 'sha256'>[]
): FindingReviewMetadataField[] {
  const expected = deriveFindingReviewMetadata(finding, files);
  const actual: Record<FindingReviewMetadataField, unknown> = {
    reviewId: finding.reviewId,
    reviewAnchors: finding.reviewAnchors,
    reviewPriority: finding.reviewPriority,
    refutationCondition: finding.refutationCondition
  };
  return (Object.keys(expected) as FindingReviewMetadataField[])
    .filter((field) => canonicalJson(actual[field]) !== canonicalJson(expected[field]));
}


/** Recompute and compare occurrence-aware review metadata for a complete artifact. */
export function findingReviewMetadataMismatchesForCollection(
  findings: readonly FindingRecord[],
  files: readonly Pick<FileRecord, 'path' | 'sha256'>[],
  omittedReviews: readonly OmittedFindingReviewReference[] = []
): FindingReviewMetadataMismatch[] {
  const referenceConflicts = findingReviewReferenceConflicts(findings, omittedReviews);
  if (referenceConflicts.length > 0) return referenceConflicts;
  const digestByPath = new Map(files.map((file) => [file.path, file.sha256]));
  const metadata = findings.map((finding) => deriveFindingReviewMetadataWithIndex(finding, digestByPath));
  const groups = new Map<string, Array<{
    findingId: string;
    currentIndex?: number;
    omittedIndex?: number;
  }>>();
  for (let index = 0; index < findings.length; index += 1) {
    const baseReviewId = metadata[index]!.reviewId;
    const members = groups.get(baseReviewId) ?? [];
    members.push({ findingId: findings[index]!.id, currentIndex: index });
    groups.set(baseReviewId, members);
  }
  const mismatches: FindingReviewMetadataMismatch[] = [];
  for (let index = 0; index < omittedReviews.length; index += 1) {
    const omitted = omittedReviews[index]!;
    const match = REVIEW_ID_PATTERN.exec(omitted.reviewId);
    if (!match) {
      mismatches.push({ findingId: omitted.findingId, fields: ['reviewId'] });
      continue;
    }
    const baseReviewId = match[1]!;
    const members = groups.get(baseReviewId) ?? [];
    members.push({ findingId: omitted.findingId, omittedIndex: index });
    groups.set(baseReviewId, members);
  }
  const expectedCurrentReviewIds = new Map<number, string>();
  const expectedOmittedReviewIds = new Map<number, string>();
  for (const [baseReviewId, members] of groups) {
    const ordered = [...members].sort((left, right) => compareCanonicalText(left.findingId, right.findingId));
    for (let occurrence = 0; occurrence < ordered.length; occurrence += 1) {
      const member = ordered[occurrence]!;
      const expectedReviewId = ordered.length === 1
        ? baseReviewId
        : `${baseReviewId}:occurrence:${occurrence + 1}`;
      if (member.currentIndex !== undefined) expectedCurrentReviewIds.set(member.currentIndex, expectedReviewId);
      if (member.omittedIndex !== undefined) expectedOmittedReviewIds.set(member.omittedIndex, expectedReviewId);
    }
  }
  for (let index = 0; index < findings.length; index += 1) {
    const finding = findings[index]!;
    const expected = {
      ...metadata[index]!,
      reviewId: expectedCurrentReviewIds.get(index)!
    };
    const fields = (['reviewId', 'reviewAnchors', 'reviewPriority', 'refutationCondition'] as const)
      .filter((field) => canonicalJson(finding[field]) !== canonicalJson(expected[field]));
    if (fields.length) mismatches.push({ findingId: finding.id, fields: [...fields] });
  }
  for (let index = 0; index < omittedReviews.length; index += 1) {
    const omitted = omittedReviews[index]!;
    const expectedReviewId = expectedOmittedReviewIds.get(index);
    if (expectedReviewId !== undefined && omitted.reviewId !== expectedReviewId) {
      mismatches.push({ findingId: omitted.findingId, fields: ['reviewId'] });
    }
  }
  return mismatches.sort((left, right) => compareCanonicalText(left.findingId, right.findingId));
}

/**
 * Reject ambiguous visible/omitted membership before occurrence suffixes are
 * reconstructed. Otherwise a forged duplicate can shift the expected suffix
 * of an unrelated visible finding.
 */
function findingReviewReferenceConflicts(
  findings: readonly FindingRecord[],
  omittedReviews: readonly OmittedFindingReviewReference[]
): FindingReviewMetadataMismatch[] {
  const findingIdOwner = new Map(findings.map((finding) => [finding.id, finding.id]));
  const reviewIdOwner = new Map(findings.flatMap((finding) =>
    typeof finding.reviewId === 'string' ? [[finding.reviewId, finding.id] as const] : []
  ));
  const conflicts = new Set<string>();
  for (const { findingId, reviewId } of omittedReviews) {
    const existingFindingOwner = findingIdOwner.get(findingId);
    if (existingFindingOwner !== undefined) {
      conflicts.add(findingId);
      conflicts.add(existingFindingOwner);
    } else {
      findingIdOwner.set(findingId, findingId);
    }
    const existingReviewOwner = reviewIdOwner.get(reviewId);
    if (existingReviewOwner !== undefined) {
      conflicts.add(findingId);
      conflicts.add(existingReviewOwner);
    } else {
      reviewIdOwner.set(reviewId, findingId);
    }
  }
  return [...conflicts]
    .sort(compareCanonicalText)
    .map((findingId) => ({ findingId, fields: ['reviewId'] }));
}
