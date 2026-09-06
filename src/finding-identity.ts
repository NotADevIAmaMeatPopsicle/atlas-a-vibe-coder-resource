import type { FileRecord, FindingRecord, FindingReviewAnchor } from './types.js';
import { canonicalJson, compareCanonicalText, sha256 } from './util/canonical.js';

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareCanonicalText);
}

function findingProducerContracts(finding: FindingRecord): unknown[] {
  const evidence = [
    ...finding.evidence,
    ...(finding.instances ?? []).flatMap((instance) => instance.evidence)
  ];
  return [...new Map(evidence.map((entry) => {
    const contract = {
      producer: entry.producer,
      producerVersion: entry.producerVersion,
      basis: entry.basis
    };
    return [canonicalJson(contract), contract];
  })).values()].sort((left, right) => compareCanonicalText(canonicalJson(left), canonicalJson(right)));
}

function findingImpactContract(finding: FindingRecord): unknown {
  const impact = finding.impactContext;
  if (!impact) return undefined;
  return {
    reachability: impact.reachability,
    ...(impact.scope ? { scope: impact.scope } : {}),
    ...(impact.lifecycle ? { lifecycle: impact.lifecycle } : {}),
    featureGate: impact.featureGate
  };
}

export function findingSourcePaths(finding: FindingRecord): string[] {
  return uniqueSorted([
    ...(finding.path ? [finding.path] : []),
    ...finding.relatedPaths,
    ...finding.evidence.flatMap((entry) => entry.path ? [entry.path] : []),
    ...(finding.instances ?? []).flatMap((instance) => [
      ...(instance.path ? [instance.path] : []),
      ...instance.relatedPaths,
      ...instance.evidence.flatMap((entry) => entry.path ? [entry.path] : [])
    ])
  ]);
}

/**
 * Return every source path named by the finding that has content in the
 * current snapshot. Paths that deliberately describe an absent target (for
 * example, an unresolved import destination) remain part of review identity
 * but cannot be content-hash anchors.
 */
export function findingReviewAnchors(
  finding: FindingRecord,
  filesOrDigestIndex: readonly Pick<FileRecord, 'path' | 'sha256'>[] | ReadonlyMap<string, string>
): FindingReviewAnchor[] {
  const digestByPath: ReadonlyMap<string, string> = Array.isArray(filesOrDigestIndex)
    ? new Map(filesOrDigestIndex.map((file) => [file.path, file.sha256]))
    : filesOrDigestIndex as ReadonlyMap<string, string>;
  return findingSourcePaths(finding).flatMap((sourcePath) => {
    const digest = digestByPath.get(sourcePath);
    return digest ? [{ path: sourcePath, sha256: digest }] : [];
  });
}

/**
 * Produce a review identity that deliberately omits source locations, record
 * IDs, severity, confidence, review priority, review anchors, refutation
 * wording, and presentation-only impact text. Producer and reachability/
 * lifecycle contracts are retained so a disposition cannot flow across a
 * materially different analysis or activation context.
 */
export function findingReviewIdentity(finding: FindingRecord): string {
  const common = {
    ruleId: finding.ruleId,
    category: finding.category,
    ...(finding.kind ? { kind: finding.kind } : {}),
    paths: findingSourcePaths(finding),
    producers: findingProducerContracts(finding),
    impact: findingImpactContract(finding)
  };
  const material = finding.patternKey
    ? {
        ...common,
        patternKey: finding.patternKey,
      }
    : finding.subject
      ? {
          ...common,
          subject: finding.subject,
        }
      : {
          ...common,
          signals: uniqueSorted(finding.signals),
          title: finding.title,
          description: finding.description,
          evidence: [...new Map(finding.evidence.map((entry) => [
            canonicalJson({ basis: entry.basis, ...(entry.path ? { path: entry.path } : {}) }),
            { basis: entry.basis, ...(entry.path ? { path: entry.path } : {}) }
          ])).values()].sort((left, right) => compareCanonicalText(canonicalJson(left), canonicalJson(right)))
        };
  return `finding_review_sha256_${sha256(canonicalJson({ domain: 'atlas.finding-review.v1', ...material }))}`;
}
