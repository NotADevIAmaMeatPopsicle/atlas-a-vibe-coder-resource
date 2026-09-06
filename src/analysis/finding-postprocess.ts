import type {
  AnalysisFile,
  CurrentFindingRecord,
  EvidenceReference,
  FindingImpactContext,
  FindingInstance,
  FindingRecord,
  FindingSeverityCalibration
} from '../types.js';
import { attachFindingReviewMetadata } from '../finding-priority.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';

export const FINDING_POSTPROCESS_VERSION = '1.3.0';

const MAX_IMPACT_ENTRYPOINTS = 8;

interface ReachabilityView {
  entrypoints: Array<{ path: string; scope?: FindingImpactContext['scope'] }>;
  reachablePaths: ReadonlySet<string>;
  gatedPaths: ReadonlySet<string>;
  pathContexts?: ReadonlyMap<string, {
    entrypointPaths: string[];
    scopes: FindingImpactContext['scope'][];
  }>;
}

function uniqueSorted<T extends string>(values: T[]): T[] {
  return [...new Set(values)].sort(compareCanonicalText);
}

function evidenceKey(value: EvidenceReference): string {
  return canonicalJson(value);
}

function uniqueEvidence(values: EvidenceReference[]): EvidenceReference[] {
  return [...new Map(values.map((value) => [evidenceKey(value), value])).values()]
    .sort((left, right) =>
      compareCanonicalText(left.path ?? '', right.path ?? '') ||
      (left.line ?? 0) - (right.line ?? 0) ||
      (left.column ?? 0) - (right.column ?? 0) ||
      compareCanonicalText(left.basis, right.basis)
    );
}

function sourceLocationFor(finding: FindingRecord): FindingRecord['location'] {
  const anchored = finding.evidence.find((entry) =>
    entry.path === finding.path && entry.line !== undefined
  ) ?? finding.evidence.find((entry) => entry.path && entry.line !== undefined);
  if (!anchored?.line) return undefined;
  const column = anchored.column ?? 1;
  return {
    line: anchored.line,
    column,
    endLine: anchored.line,
    endColumn: column
  };
}

function promoteSourceLocations(findings: FindingRecord[]): FindingRecord[] {
  return findings.map((finding) => {
    if (finding.location) return finding;
    const location = sourceLocationFor(finding);
    return location ? { ...finding, location } : finding;
  });
}

function testLikePath(pathValue: string): boolean {
  return /(?:^|\/)(?:tests?|__tests__|e2e|fixtures)(?:\/|$)|\.(?:test|spec)\.[^/]+$/iu.test(pathValue);
}

function entrypointRank(pathValue: string, scope?: FindingImpactContext['scope']): number {
  if (scope === 'production') return 0;
  if (scope === 'cli') return 1;
  if (scope === 'build' || scope === 'migration' || scope === 'seeder') return 2;
  if (scope === 'test' || testLikePath(pathValue)) return 4;
  return 3;
}

function cappedEntrypoints(
  paths: string[],
  scopeByPath?: ReadonlyMap<string, FindingImpactContext['scope'] | undefined>
): { entrypoints: string[]; remainder: number } {
  const ordered = uniqueSorted(paths).sort((left, right) =>
    entrypointRank(left, scopeByPath?.get(left)) - entrypointRank(right, scopeByPath?.get(right)) ||
    compareCanonicalText(left, right)
  );
  return {
    entrypoints: ordered.slice(0, MAX_IMPACT_ENTRYPOINTS),
    remainder: Math.max(0, ordered.length - MAX_IMPACT_ENTRYPOINTS)
  };
}

function reclassifyUnreachableBrokenReferences(findings: FindingRecord[]): FindingRecord[] {
  const cleanupByPath = new Map(
    findings
      .filter((finding) =>
        finding.ruleId === 'dead-code/static-reachability-v1' &&
        finding.path && finding.signals.includes('unreachable-from-configured-entrypoints')
      )
      .map((finding) => [finding.path!, finding])
  );
  const absorbed = new Set<string>();
  const replacements = new Map<string, FindingRecord>();
  const brokenReferencesByCleanupId = new Map<string, FindingRecord[]>();
  for (const brokenReference of findings) {
    if (brokenReference.ruleId !== 'contract/unresolved-internal-import-v1' || !brokenReference.path) continue;
    const cleanup = cleanupByPath.get(brokenReference.path);
    if (!cleanup) continue;
    const values = brokenReferencesByCleanupId.get(cleanup.id) ?? [];
    values.push(brokenReference);
    brokenReferencesByCleanupId.set(cleanup.id, values);
  }
  for (const [cleanupId, brokenReferences] of brokenReferencesByCleanupId) {
    const cleanup = findings.find((finding) => finding.id === cleanupId)!;
    const orderedBrokenReferences = [...brokenReferences]
      .sort((left, right) => compareCanonicalText(left.id, right.id));
    for (const brokenReference of orderedBrokenReferences) absorbed.add(brokenReference.id);
    const signals = uniqueSorted([...cleanup.signals, 'contains-unresolved-internal-reference']);
    const evidence = uniqueEvidence([
      ...cleanup.evidence,
      ...orderedBrokenReferences.flatMap((brokenReference) => brokenReference.evidence)
    ]);
    const relatedPaths = uniqueSorted([
      ...cleanup.relatedPaths,
      ...orderedBrokenReferences.flatMap((brokenReference) => brokenReference.relatedPaths)
    ]).filter((relatedPath) => relatedPath !== cleanup.path);
    const absorbedIds = orderedBrokenReferences.map((brokenReference) => brokenReference.id);
    replacements.set(cleanup.id, {
      ...cleanup,
      id: `finding:${sha256(canonicalJson({
        ruleId: cleanup.ruleId,
        path: cleanup.path,
        signals,
        absorbed: absorbedIds
      })).slice(0, 24)}`,
      title: `Review unreachable source with a broken internal reference: ${cleanup.path}`,
      description: `${cleanup.description} The same statically unreachable file also contains ${orderedBrokenReferences.length} unresolved internal reference(s), so Atlas treats every reference as file-level cleanup evidence rather than an instruction to repair a live import.`,
      relatedPaths,
      signals,
      evidence,
      nextValidation: 'Confirm the file has no framework, loader, package, CLI, deployment, or external activation path; then retire the file or restore both its activation path and internal reference intentionally.'
    });
  }
  return findings.flatMap((finding) => {
    if (absorbed.has(finding.id)) return [];
    return [replacements.get(finding.id) ?? finding];
  });
}

function mountedSurfaces(filePath: string): string[] {
  const lower = filePath.toLowerCase();
  const result: string[] = [];
  if (/(?:^|\/)(?:routes?|controllers?)(?:\/|\.)/u.test(lower)) result.push('static-http-route-or-controller');
  if (/(?:^|\/)(?:bin|cli|scripts?)(?:\/|\.)/u.test(lower)) result.push('static-cli-or-script');
  if (/(?:test|spec)\.[^.]+$/u.test(lower) || /(?:^|\/)(?:tests?|__tests__|e2e)\//u.test(lower)) result.push('static-test-surface');
  if (/(?:vite|webpack|rollup|esbuild|playwright|jest)\.config/u.test(lower)) result.push('static-build-or-test-config');
  return result;
}

function annotateImpact(
  findings: FindingRecord[],
  files: AnalysisFile[],
  reachability?: ReachabilityView
): FindingRecord[] {
  const fileByPath = new Map(files.map((file) => [file.record.path, file]));
  const entrypointPaths = uniqueSorted(reachability?.entrypoints.map((entry) => entry.path) ?? []);
  const entrypointScopes = new Map(reachability?.entrypoints.map((entry) => [entry.path, entry.scope]) ?? []);
  return findings.map((finding) => {
    const file = finding.path ? fileByPath.get(finding.path) : undefined;
    const reachabilityState: FindingImpactContext['reachability'] = !finding.path || !reachability
      ? 'unknown'
      : reachability.gatedPaths.has(finding.path)
        ? 'coverage-incomplete'
        : reachability.reachablePaths.has(finding.path)
          ? 'reachable'
          : 'unreachable';
    const source = file?.content.toString('utf8') ?? '';
    const surfaces = finding.path ? mountedSurfaces(finding.path) : [];
    const pathContext = finding.path ? reachability?.pathContexts?.get(finding.path) : undefined;
    const scopes = uniqueSorted((pathContext?.scopes ?? []).filter(
      (value): value is NonNullable<FindingImpactContext['scope']> => value !== undefined
    ));
    const scope = scopes.includes('production')
      ? 'production'
      : scopes.length === 1
        ? scopes[0]
      : reachability?.entrypoints.find((entry) => entry.path === finding.path)?.scope;
    const relevantEntrypoints = pathContext
      ? uniqueSorted(pathContext.entrypointPaths)
      : reachabilityState === 'reachable'
        ? entrypointPaths
        : [];
    const rankedEntrypoints = cappedEntrypoints(relevantEntrypoints, entrypointScopes);
    const scopeSummary = scopes.length ? ` Modeled scope(s): ${scopes.join(', ')}.` : '';
    const remainderSummary = rankedEntrypoints.remainder > 0
      ? ` ${rankedEntrypoints.remainder} additional entrypoint(s) omitted.`
      : '';
    const summary = (reachabilityState === 'reachable'
      ? `The file is statically reachable from at least one modeled entrypoint or loader root.${scopeSummary}`
      : reachabilityState === 'unreachable'
        ? 'No modeled static entrypoint or complete loader scope reaches the file.'
        : reachabilityState === 'coverage-incomplete'
          ? 'The file is inside a loader scope whose static coverage is incomplete.'
          : 'Static reachability context was not available for this finding.') + remainderSummary;
    return {
      ...finding,
      kind: finding.kind ?? (finding.category === 'latent-hazard'
        ? 'latent-hazard'
        : finding.category === 'review-inventory'
          ? 'review-inventory'
          : 'defect-candidate'),
      impactContext: {
        reachability: reachabilityState,
        ...(scope ? { scope } : {}),
        entrypoints: rankedEntrypoints.entrypoints,
        ...(rankedEntrypoints.remainder > 0 ? { entrypointRemainder: rankedEntrypoints.remainder } : {}),
        mountedSurfaces: surfaces,
        ...(file?.record.lifecycle ? { lifecycle: file.record.lifecycle.state } : {}),
        featureGate: file
          ? /(?:feature.?flag|process\.env|import\.meta\.env)/iu.test(source) ? 'observed' : 'not-observed'
          : 'unknown',
        summary,
        limitations: [
          'Impact context is static evidence only; deployment, traffic, runtime row counts, and user exposure were not inferred.'
        ]
      }
    };
  });
}

function aggregateImpactContext(
  group: FindingRecord[],
  reachabilityView?: ReachabilityView
): FindingImpactContext | undefined {
  const contexts = group.flatMap((finding) => finding.impactContext ? [finding.impactContext] : []);
  if (!contexts.length) return undefined;
  const reachabilityStates = uniqueSorted(contexts.map((entry) => entry.reachability));
  const reachability: FindingImpactContext['reachability'] = reachabilityStates.length === 1
    ? reachabilityStates[0]!
    : 'mixed';
  const scopes = uniqueSorted(contexts.flatMap((entry) => entry.scope ? [entry.scope] : []));
  const lifecycles = uniqueSorted(contexts.flatMap((entry) => entry.lifecycle ? [entry.lifecycle] : []));
  const featureGateStates = uniqueSorted(contexts.map((entry) => entry.featureGate));
  const featureGate: FindingImpactContext['featureGate'] = featureGateStates.length === 1
    ? featureGateStates[0]!
    : 'unknown';
  const reachabilityCounts = reachabilityStates.map((state) => (
    `${contexts.filter((entry) => entry.reachability === state).length} ${state}`
  ));
  const entrypointScopes = new Map(reachabilityView?.entrypoints.map((entry) => [entry.path, entry.scope]) ?? []);
  const sourceEntrypoints = uniqueSorted(group.flatMap((finding) => {
    const fullContext = finding.path ? reachabilityView?.pathContexts?.get(finding.path) : undefined;
    return fullContext?.entrypointPaths ?? finding.impactContext?.entrypoints ?? [];
  }));
  const rankedEntrypoints = cappedEntrypoints(sourceEntrypoints, entrypointScopes);
  // Without the original reachability view, a persisted per-instance context
  // may already be capped. Preserve its largest known omitted count without
  // summing overlapping unknown sets.
  const entrypointRemainder = Math.max(
    rankedEntrypoints.remainder,
    ...(reachabilityView ? [0] : contexts.map((entry) => entry.entrypointRemainder ?? 0))
  );
  return {
    reachability,
    ...(scopes.length === 1 && contexts.every((entry) => entry.scope === scopes[0]) ? { scope: scopes[0] } : {}),
    entrypoints: rankedEntrypoints.entrypoints,
    ...(entrypointRemainder > 0 ? { entrypointRemainder } : {}),
    mountedSurfaces: uniqueSorted(contexts.flatMap((entry) => entry.mountedSurfaces)),
    ...(lifecycles.length === 1 ? { lifecycle: lifecycles[0] } : {}),
    featureGate,
    summary: `${group.length} source-located instance(s) share this pattern; reachability evidence is ${reachabilityCounts.join(', ')}${scopes.length ? ` across modeled scope(s): ${scopes.join(', ')}` : ''}.${entrypointRemainder > 0 ? ` ${entrypointRemainder} additional entrypoint(s) omitted.` : ''}`,
    limitations: uniqueSorted(contexts.flatMap((entry) => entry.limitations))
  };
}

function derivedPatternKey(finding: FindingRecord): string | undefined {
  if (finding.patternKey) return finding.patternKey;
  if (finding.ruleId === 'contract/data-enum-v1' && finding.subject && 'model' in finding.subject) {
    return `data-enum:${finding.subject.model}:${finding.subject.storage}:${uniqueSorted(finding.signals).join(',')}`;
  }
  if (finding.ruleId === 'contract/data-provisioning-path-enum-v1' && finding.subject && 'comparison' in finding.subject) {
    return `data-provisioning-enum:${finding.subject.migration}:${finding.subject.bootstrap}:${uniqueSorted(finding.signals).join(',')}`;
  }
  if (finding.ruleId === 'dead-code/static-reachability-v1') {
    return `static-reachability:${uniqueSorted(finding.signals).join(',')}`;
  }
  return undefined;
}

function instanceFor(finding: FindingRecord): FindingInstance {
  const location = finding.location ?? sourceLocationFor(finding);
  return {
    id: finding.id,
    severity: finding.severity,
    confidence: finding.confidence,
    ...(finding.path ? { path: finding.path } : {}),
    ...(location ? { location } : {}),
    relatedPaths: [...finding.relatedPaths],
    signals: [...finding.signals],
    evidence: [...finding.evidence],
    ...(finding.subject ? { subject: finding.subject } : {}),
    ...(finding.impactContext ? { impactContext: finding.impactContext } : {})
  };
}

function findingOrder(left: FindingRecord, right: FindingRecord): number {
  const leftPath = left.path ?? left.evidence.find((entry) => entry.path)?.path ?? '';
  const rightPath = right.path ?? right.evidence.find((entry) => entry.path)?.path ?? '';
  return entrypointRank(leftPath, left.impactContext?.scope) - entrypointRank(rightPath, right.impactContext?.scope) ||
    compareCanonicalText(leftPath, rightPath) ||
    (sourceLocationFor(left)?.line ?? 0) - (sourceLocationFor(right)?.line ?? 0) ||
    compareCanonicalText(left.id, right.id);
}

const SEVERITY_ORDER: FindingRecord['severity'][] = ['info', 'low', 'medium', 'high'];
const CONFIDENCE_ORDER: FindingRecord['confidence'][] = ['unknown', 'low', 'medium', 'high', 'confirmed'];

function highestSeverity(values: FindingRecord['severity'][]): FindingRecord['severity'] {
  return values.reduce<FindingRecord['severity']>((highest, severity) => (
    SEVERITY_ORDER.indexOf(severity) > SEVERITY_ORDER.indexOf(highest) ? severity : highest
  ), 'info');
}

function aggregateSeverity(findings: FindingRecord[]): FindingRecord['severity'] {
  return highestSeverity(findings.map((finding) => finding.severity));
}

function aggregateConfidence(findings: FindingRecord[]): FindingRecord['confidence'] {
  return findings.reduce<FindingRecord['confidence']>((lowest, finding) => (
    CONFIDENCE_ORDER.indexOf(finding.confidence) < CONFIDENCE_ORDER.indexOf(lowest) ? finding.confidence : lowest
  ), 'confirmed');
}

interface StaticSeverityDecision {
  ceiling: FindingSeverityCalibration['ceiling'];
  basis: FindingSeverityCalibration['basis'];
  rationale: string;
}

/**
 * Static severity policy (v1): HIGH is available only when the source is
 * statically reachable from a production entrypoint or mounted route and no
 * local feature-gate expression was observed. A known local gate, or a
 * reachable CLI/build/migration/seeder surface, caps severity at MEDIUM.
 * Test-only, mothballed, and statically unreachable sources cap at LOW.
 * Unknown, mixed, or incomplete reachability caps at MEDIUM. This is a ceiling only and never
 * upgrades detector severity; it deliberately makes no runtime-reachability
 * claim.
 */
function staticSeverityDecision(context: FindingImpactContext | undefined): StaticSeverityDecision {
  if (context?.lifecycle === 'mothballed') {
    return {
      ceiling: 'low',
      basis: 'static-mothballed-path',
      rationale: 'The anchor is classified as mothballed source, so severity is capped at LOW even if a static graph path remains; runtime activation was not evaluated.'
    };
  }
  if (!context || context.reachability === 'unknown' || context.reachability === 'coverage-incomplete' ||
    context.reachability === 'mixed') {
    return {
      ceiling: 'medium',
      basis: 'static-reachability-incomplete',
      rationale: 'Static reachability is unknown, mixed, or incomplete, so severity is capped at MEDIUM; runtime reachability was not evaluated.'
    };
  }
  if (context.reachability === 'unreachable') {
    return {
      ceiling: 'low',
      basis: 'static-unreachable-path',
      rationale: 'No modeled static entrypoint reaches the anchor, so severity is capped at LOW; dynamic or runtime activation was not evaluated.'
    };
  }
  const testSurface = context.scope === 'test' || context.mountedSurfaces.some((surface) =>
    surface === 'static-test-surface' || surface === 'test'
  );
  const nonProductionSurface = context.scope === 'cli' || context.scope === 'build' ||
    context.scope === 'migration' || context.scope === 'seeder' || context.mountedSurfaces.some((surface) =>
      surface === 'static-cli-or-script' || surface === 'static-build-or-test-config' ||
      surface === 'cli' || surface === 'build' || surface === 'migration' || surface === 'seeder'
    );
  if (testSurface) {
    return {
      ceiling: 'low',
      basis: 'static-test-only-path',
      rationale: 'The anchor is statically reachable only through a test surface, so severity is capped at LOW; runtime production reachability was not evaluated.'
    };
  }
  if (nonProductionSurface) {
    return {
      ceiling: 'medium',
      basis: 'static-non-production-path',
      rationale: 'The anchor is statically reachable only through a CLI, build, migration, or seeder surface, so severity is capped at MEDIUM; runtime invocation was not evaluated.'
    };
  }
  const productionSurface = context.scope === 'production' || context.mountedSurfaces.some((surface) =>
    surface === 'static-http-route-or-controller' || surface === 'http-route'
  );
  if (productionSurface) {
    if (context.featureGate === 'observed') {
      return {
        ceiling: 'medium',
        basis: 'static-production-path-feature-gated',
        rationale: 'The anchor is statically production-reachable but a local feature-gate expression is observed, so severity is capped at MEDIUM; gate state and runtime reachability were not evaluated.'
      };
    }
    if (context.featureGate === 'not-observed') {
      return {
        ceiling: 'high',
        basis: 'static-production-path-no-observed-feature-gate',
        rationale: 'The anchor is statically reachable from a production entrypoint or mounted route and no local feature-gate expression was observed; runtime reachability was not evaluated.'
      };
    }
    return {
      ceiling: 'medium',
      basis: 'static-reachability-incomplete',
      rationale: 'The anchor is statically production-reachable, but local feature-gate evidence is unavailable, so severity is capped at MEDIUM; runtime reachability was not evaluated.'
    };
  }
  return {
    ceiling: 'medium',
    basis: 'static-reachability-incomplete',
    rationale: 'The anchor is statically reachable but no production, route, CLI, build, migration, seeder, or test scope is established, so severity is capped at MEDIUM; runtime reachability was not evaluated.'
  };
}

function severityAtMost(
  severity: FindingRecord['severity'],
  ceiling: FindingSeverityCalibration['ceiling']
): FindingRecord['severity'] {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(ceiling) ? severity : ceiling;
}

function calibrateSeverity(finding: FindingRecord): FindingRecord {
  const candidates = finding.instances?.length
    ? finding.instances.map((instance) => ({
        detectorSeverity: instance.severity,
        decision: staticSeverityDecision(instance.impactContext)
      }))
    : [{
        detectorSeverity: finding.severity,
        decision: staticSeverityDecision(finding.impactContext)
      }];
  const effective = candidates.map((candidate) => ({
    ...candidate,
    severity: severityAtMost(candidate.detectorSeverity, candidate.decision.ceiling)
  }));
  const severity = highestSeverity(effective.map((entry) => entry.severity));
  const governing = effective
    .filter((entry) => entry.severity === severity)
    .sort((left, right) =>
      SEVERITY_ORDER.indexOf(right.decision.ceiling) - SEVERITY_ORDER.indexOf(left.decision.ceiling) ||
      compareCanonicalText(left.decision.basis, right.decision.basis)
    )[0]!;
  return {
    ...finding,
    severity,
    ...(finding.instances ? {
      instances: finding.instances.map((instance, index) => ({
        ...instance,
        severity: effective[index]!.severity
      }))
    } : {}),
    severityCalibration: {
      version: 'static-reachability-v1',
      detectorSeverity: governing.detectorSeverity,
      ceiling: governing.decision.ceiling,
      basis: governing.decision.basis,
      runtimeReachability: 'not-evaluated',
      rationale: governing.decision.rationale
    }
  };
}

function aggregatePatternFindings(findings: FindingRecord[], reachability?: ReachabilityView): FindingRecord[] {
  const grouped = new Map<string, FindingRecord[]>();
  const passthrough: FindingRecord[] = [];
  for (const finding of findings) {
    const patternKey = derivedPatternKey(finding);
    if (!patternKey) {
      passthrough.push(finding);
      continue;
    }
    const key = `${finding.ruleId}\0${patternKey}`;
    const values = grouped.get(key) ?? [];
    values.push(finding);
    grouped.set(key, values);
  }
  const aggregated: FindingRecord[] = [];
  for (const [groupKey, group] of grouped) {
    const ordered = [...group].sort(findingOrder);
    if (ordered.length === 1) {
      const only = ordered[0]!;
      const location = only.location ?? sourceLocationFor(only);
      aggregated.push({
        ...only,
        ...(location ? { location } : {}),
        patternKey: derivedPatternKey(only)!,
        instanceCount: 1,
        instances: [instanceFor(only)]
      });
      continue;
    }
    const primary = ordered[0]!;
    const { subject: _subject, ...base } = primary;
    const instances = ordered.map(instanceFor);
    const allPaths = uniqueSorted(ordered.flatMap((finding) => [
      ...(finding.path ? [finding.path] : []),
      ...finding.relatedPaths
    ]));
    const primaryPath = primary.path ?? primary.evidence.find((entry) => entry.path)?.path;
    const patternKey = derivedPatternKey(primary)!;
    const impactContext = aggregateImpactContext(ordered, reachability);
    const primaryLocation = primary.location ?? sourceLocationFor(primary);
    aggregated.push({
      ...base,
      id: `finding:${sha256(canonicalJson({ groupKey, instances: instances.map((entry) => entry.id) })).slice(0, 24)}`,
      patternKey,
      instanceCount: instances.length,
      instances,
      severity: aggregateSeverity(ordered),
      confidence: aggregateConfidence(ordered),
      title: `${instances.length} instances share one ${primary.ruleId} pattern`,
      description: `${instances.length} source-located instances share the same underlying pattern. They are reported as one headline finding so repeated manifestations do not inflate the top-level count. ${primary.description}`,
      ...(primaryPath ? { path: primaryPath } : {}),
      ...(primaryLocation ? { location: primaryLocation } : {}),
      relatedPaths: primaryPath ? allPaths.filter((value) => value !== primaryPath) : allPaths,
      signals: uniqueSorted([...ordered.flatMap((finding) => finding.signals), 'aggregated-pattern-instances']),
      evidence: uniqueEvidence(ordered.flatMap((finding) => finding.evidence)),
      ...(impactContext ? { impactContext } : {})
    });
  }
  return [...passthrough, ...aggregated].sort((left, right) => compareCanonicalText(left.id, right.id));
}

export function postprocessFindings(
  findings: FindingRecord[],
  files: AnalysisFile[],
  reachability?: ReachabilityView
): CurrentFindingRecord[] {
  const fileRecords = files.map((file) => file.record);
  const processed = aggregatePatternFindings(
    annotateImpact(promoteSourceLocations(reclassifyUnreachableBrokenReferences(findings)), files, reachability),
    reachability
  ).map(calibrateSeverity);
  return attachFindingReviewMetadata(processed, fileRecords);
}

export function findingInstanceCount(findings: FindingRecord[]): number {
  return findings.reduce((total, finding) => total + (finding.instanceCount ?? 1), 0);
}
