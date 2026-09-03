import type {
  DiagnosticRecord,
  FindingImpactContext,
  FindingMappingContext,
  FindingRecord,
  RunRecord
} from './types.js';
import { findingReviewIdentity } from './finding-identity.js';
import {
  compareFindingReviewPriority,
  findingReviewPriorityBandLabel
} from './finding-priority.js';
import {
  TRIAGE_REPORT_ANALYSIS_MARKER,
  TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER,
  TRIAGE_REPORT_LEGACY_VERSION,
  TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER,
  TRIAGE_REPORT_PREVIOUS_VERSION,
  TRIAGE_REPORT_VERSION
} from './artifact-contract.js';
import { compareCanonicalText } from './util/canonical.js';

export {
  TRIAGE_REPORT_ARTIFACT_NAME,
  TRIAGE_REPORT_LEGACY_VERSION,
  TRIAGE_REPORT_PREVIOUS_VERSION,
  TRIAGE_REPORT_VERSION
} from './artifact-contract.js';

const FINDING_SEVERITY: Record<FindingRecord['severity'], number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3
};

const LEGACY_DIAGNOSTIC_SEVERITY: Record<DiagnosticRecord['severity'], number> = {
  error: 0,
  warning: 1,
  info: 2
};

function testLikePath(pathValue: string): boolean {
  return /(?:^|\/)(?:tests?|__tests__|e2e|fixtures)(?:\/|$)|\.(?:test|spec)\.[^/]+$/iu.test(pathValue);
}

function scopeRank(scope: FindingImpactContext['scope'] | undefined, pathValue: string): number {
  if (scope === 'production') return 0;
  if (scope === 'cli') return 1;
  if (scope === 'build' || scope === 'migration' || scope === 'seeder') return 2;
  if (scope === 'test' || testLikePath(pathValue)) return 4;
  return 3;
}

function primaryAnchor(finding: FindingRecord): { path?: string; line?: number; column?: number } {
  const source = finding.evidence.find((entry) =>
    entry.path === finding.path && entry.line !== undefined && entry.column !== undefined
  ) ?? finding.evidence.find((entry) => entry.path);
  const pathValue = finding.path ?? source?.path;
  const line = finding.location?.line ?? source?.line;
  const column = finding.location?.column ?? source?.column;
  return {
    ...(pathValue ? { path: pathValue } : {}),
    ...(line ? { line } : {}),
    ...(column ? { column } : {})
  };
}

function compareFindingsV1_1_0(left: FindingRecord, right: FindingRecord): number {
  const leftAnchor = primaryAnchor(left);
  const rightAnchor = primaryAnchor(right);
  return FINDING_SEVERITY[left.severity] - FINDING_SEVERITY[right.severity] ||
    scopeRank(left.impactContext?.scope, leftAnchor.path ?? '') - scopeRank(right.impactContext?.scope, rightAnchor.path ?? '') ||
    compareCanonicalText(left.ruleId, right.ruleId) ||
    compareCanonicalText(leftAnchor.path ?? '', rightAnchor.path ?? '') ||
    (leftAnchor.line ?? 0) - (rightAnchor.line ?? 0) ||
    compareCanonicalText(findingReviewIdentity(left), findingReviewIdentity(right));
}

function inlineCode(value: string): string {
  const normalized = value.replace(/\s+/gu, ' ').trim();
  const longest = Math.max(0, ...(normalized.match(/`+/gu) ?? []).map((entry) => entry.length));
  const fence = '`'.repeat(longest + 1);
  const padding = normalized.startsWith('`') || normalized.endsWith('`') ? ' ' : '';
  return `${fence}${padding}${normalized}${padding}${fence}`;
}

function prose(value: string): string {
  return value.replace(/\s+/gu, ' ').trim()
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/[\\`*_[\]{}#+!|]/gu, '\\$&');
}

function anchorText(finding: FindingRecord): string {
  const anchor = primaryAnchor(finding);
  if (!anchor.path) return 'not source-located';
  return inlineCode(`${anchor.path}${anchor.line ? `:${anchor.line}${anchor.column ? `:${anchor.column}` : ''}` : ''}`);
}

function severityCounts(findings: readonly FindingRecord[]): string {
  return (['high', 'medium', 'low', 'info'] as const)
    .map((severity) => `${severity} ${findings.filter((finding) => finding.severity === severity).length}`)
    .join(', ');
}

function affectedSurface(finding: FindingRecord): string {
  const context = finding.impactContext;
  if (!context) return 'Impact surface was not resolved.';
  const candidates = [...new Set([...context.mountedSurfaces, ...context.entrypoints])];
  const shown = candidates.slice(0, 3);
  const remainder = Math.max(0, candidates.length - shown.length) + (context.entrypointRemainder ?? 0);
  const suffix = remainder > 0 ? `, plus ${remainder} additional surface${remainder === 1 ? '' : 's'}` : '';
  const scope = context.scope ?? (context.reachability === 'mixed' ? 'mixed' : 'unknown');
  return shown.length
    ? `${scope} scope via ${shown.map(inlineCode).join(', ')}${suffix}`
    : `${scope} scope; ${prose(context.summary)}`;
}

function activationCondition(finding: FindingRecord): string {
  const context = finding.impactContext;
  if (!context) return 'Runtime activation was not established.';
  const gate = context.featureGate === 'unknown' ? 'feature-gate state unknown' : `feature gate ${context.featureGate}`;
  return `${context.reachability}; ${gate}`;
}

/** Preserve the exact v1.0.0 projection for immutable historical runs. */
export function renderTriageReportV1_0_0(
  run: RunRecord,
  findings: readonly FindingRecord[],
  diagnostics: readonly DiagnosticRecord[]
): string {
  const orderedFindings = [...findings].sort(compareFindingsV1_1_0);
  const orderedDiagnostics = [...diagnostics].sort((left, right) =>
    LEGACY_DIAGNOSTIC_SEVERITY[left.severity] - LEGACY_DIAGNOSTIC_SEVERITY[right.severity] ||
    compareCanonicalText(left.code, right.code) ||
    compareCanonicalText(left.path ?? '', right.path ?? '') ||
    (left.location?.line ?? 0) - (right.location?.line ?? 0) ||
    compareCanonicalText(left.id, right.id)
  );
  const instanceCount = findings.reduce((total, finding) => total + (finding.instanceCount ?? 1), 0);
  const lines = [
    '# Atlas triage report',
    '',
    `Run: ${inlineCode(run.runId)}`,
    `Snapshot: ${inlineCode(run.snapshotId)}`,
    `Producer: ${inlineCode(`atlas/triage-report@${TRIAGE_REPORT_LEGACY_VERSION}`)}`,
    '',
    '## Summary',
    '',
    `- Headline findings: ${findings.length}`,
    `- Finding instances: ${instanceCount}`,
    `- Severity: ${severityCounts(findings)}`,
    `- Diagnostics: ${diagnostics.length}`,
    '',
    '## Findings',
    ''
  ];
  if (!orderedFindings.length) lines.push('No surfaced findings.', '');
  for (const [index, finding] of orderedFindings.entries()) {
    const context = finding.impactContext;
    lines.push(
      `### ${index + 1}. ${finding.severity.toUpperCase()} · ${prose(finding.title)}`,
      '',
      `- Rule: ${inlineCode(finding.ruleId)}`,
      `- Review ID: ${inlineCode(findingReviewIdentity(finding))}`,
      `- Anchor: ${anchorText(finding)}`,
      `- Instances: ${finding.instanceCount ?? 1}`,
      `- What breaks: ${prose(finding.description)}`,
      `- Who/where: ${affectedSurface(finding)}`,
      `- When: ${activationCondition(finding)}`,
      `- Mechanism: ${finding.signals.map(inlineCode).join(', ')}`,
      `- Uncertainty: confidence ${finding.confidence}; ${context?.limitations.map(prose).join(' ') || 'no additional limitation recorded'}`,
      '',
      `Next validation: ${prose(finding.nextValidation)}`,
      ''
    );
  }
  lines.push('## Diagnostics', '');
  if (!orderedDiagnostics.length) lines.push('No diagnostics.', '');
  for (const diagnostic of orderedDiagnostics) {
    const anchor = diagnostic.path
      ? `${diagnostic.path}${diagnostic.location?.line ? `:${diagnostic.location.line}` : ''}`
      : 'not source-located';
    lines.push(
      `- **${diagnostic.severity.toUpperCase()}** ${inlineCode(diagnostic.code)} at ${inlineCode(anchor)}: ${prose(diagnostic.message)}`
    );
  }
  if (orderedDiagnostics.length) lines.push('');
  return `${lines.join('\n')}\n`;
}

interface FindingPresentation {
  heading: string;
  details: string[];
  nextValidation: string;
}

function mappingContextKey(context: FindingMappingContext): string {
  return [
    context.composePath,
    context.service,
    context.sourceKind,
    context.hostRoot,
    context.containerRoot,
    context.buildContext ?? '',
    context.dockerfile ?? '',
    context.workingDirectory ?? ''
  ].join('\0');
}

function mappingContextLines(finding: FindingRecord): string[] {
  if (!finding.mappingContexts?.length) return [];
  const contexts = [...finding.mappingContexts].sort((left, right) =>
    compareCanonicalText(mappingContextKey(left), mappingContextKey(right))
  );
  return [
    `- Mapping contexts: ${contexts.length}`,
    ...contexts.map((context, index) => {
      const dockerDetails = [
        ...(context.buildContext ? [`build ${inlineCode(context.buildContext)}`] : []),
        ...(context.dockerfile ? [`Dockerfile ${inlineCode(context.dockerfile)}`] : []),
        ...(context.workingDirectory ? [`working directory ${inlineCode(context.workingDirectory)}`] : [])
      ];
      return `  - ${index + 1}. ${inlineCode(context.composePath)} · service ${inlineCode(context.service)} · ` +
        `${inlineCode(context.sourceKind)} · ${inlineCode(context.hostRoot)} → ${inlineCode(context.containerRoot)}` +
        `${dockerDetails.length ? ` · ${dockerDetails.join(' · ')}` : ''}`;
    })
  ];
}

function severityCalibrationLines(finding: FindingRecord): string[] {
  const calibration = finding.severityCalibration;
  if (!calibration) return [];
  return [
    `- Severity calibration: detector ${inlineCode(calibration.detectorSeverity)} → reported ${inlineCode(finding.severity)} ` +
      `(ceiling ${inlineCode(calibration.ceiling)}; basis ${inlineCode(calibration.basis)}; ` +
      `runtime reachability ${inlineCode(calibration.runtimeReachability)})`,
    `- Severity rationale: ${prose(calibration.rationale)}`
  ];
}

function findingPresentation(finding: FindingRecord): FindingPresentation {
  const context = finding.impactContext;
  const mechanism = finding.mechanism
    ? [
        `- Mechanism: ${inlineCode(finding.mechanism)}`,
        `- Signals: ${finding.signals.map(inlineCode).join(', ')}`
      ]
    : [`- Mechanism: ${finding.signals.map(inlineCode).join(', ')}`];
  return {
    heading: `${finding.severity.toUpperCase()} · ${prose(finding.title)}`,
    details: [
      `- Rule: ${inlineCode(finding.ruleId)}`,
      `- Anchor: ${anchorText(finding)}`,
      `- Instances: ${finding.instanceCount ?? 1}`,
      ...severityCalibrationLines(finding),
      `- What breaks: ${prose(finding.description)}`,
      `- Who/where: ${affectedSurface(finding)}`,
      `- When: ${activationCondition(finding)}`,
      ...mechanism,
      ...mappingContextLines(finding),
      `- Uncertainty: confidence ${finding.confidence}; ${context?.limitations.map(prose).join(' ') || 'no additional limitation recorded'}`
    ],
    nextValidation: `Next validation: ${prose(finding.nextValidation)}`
  };
}

function assertDistinctFindingPresentations(
  entries: readonly { finding: FindingRecord; presentation: FindingPresentation }[]
): void {
  const seen = new Map<string, FindingRecord>();
  for (const { finding, presentation } of entries) {
    const key = JSON.stringify(presentation);
    const duplicate = seen.get(key);
    if (duplicate) {
      throw new Error(
        'Cannot render triage report with duplicate reviewer-visible finding entries; ' +
        `aggregate ${findingReviewIdentity(duplicate)} and ${findingReviewIdentity(finding)} before rendering.`
      );
    }
    seen.set(key, finding);
  }
}

interface DiagnosticCodeSummary {
  code: string;
  total: number;
  error: number;
  warning: number;
  info: number;
}

function summarizeDiagnostics(diagnostics: readonly DiagnosticRecord[]): DiagnosticCodeSummary[] {
  const byCode = new Map<string, DiagnosticCodeSummary>();
  for (const diagnostic of diagnostics) {
    const summary = byCode.get(diagnostic.code) ?? {
      code: diagnostic.code,
      total: 0,
      error: 0,
      warning: 0,
      info: 0
    };
    summary.total += 1;
    summary[diagnostic.severity] += 1;
    byCode.set(diagnostic.code, summary);
  }
  return [...byCode.values()].sort((left, right) => compareCanonicalText(left.code, right.code));
}

/** Preserve the exact v1.1.0 projection for immutable historical runs. */
export function renderTriageReportV1_1_0(
  run: RunRecord,
  findings: readonly FindingRecord[],
  diagnostics: readonly DiagnosticRecord[]
): string {
  const orderedFindings = [...findings].sort(compareFindingsV1_1_0);
  const presentedFindings = orderedFindings.map((finding) => ({
    finding,
    presentation: findingPresentation(finding)
  }));
  assertDistinctFindingPresentations(presentedFindings);
  const diagnosticSummaries = summarizeDiagnostics(diagnostics);
  const instanceCount = findings.reduce((total, finding) => total + (finding.instanceCount ?? 1), 0);
  const lines = [
    '# Atlas triage report',
    '',
    `Run: ${inlineCode(run.runId)}`,
    `Snapshot: ${inlineCode(run.snapshotId)}`,
    `Producer: ${inlineCode(`atlas/triage-report@${TRIAGE_REPORT_PREVIOUS_VERSION}`)}`,
    '',
    '## Summary',
    '',
    `- Headline findings: ${findings.length}`,
    `- Finding instances: ${instanceCount}`,
    `- Severity: ${severityCounts(findings)}`,
    `- Diagnostics: ${diagnostics.length} across ${diagnosticSummaries.length} code${diagnosticSummaries.length === 1 ? '' : 's'}`,
    '',
    '## Findings',
    ''
  ];
  if (!orderedFindings.length) lines.push('No surfaced findings.', '');
  for (const [index, { finding, presentation }] of presentedFindings.entries()) {
    lines.push(
      `### ${index + 1}. ${presentation.heading}`,
      '',
      presentation.details[0]!,
      `- Review ID: ${inlineCode(findingReviewIdentity(finding))}`,
      ...presentation.details.slice(1),
      '',
      presentation.nextValidation,
      ''
    );
  }
  lines.push(
    '## Diagnostics',
    '',
    `Per-instance diagnostic records are retained only in ${inlineCode('diagnostics.jsonl')}.`,
    ''
  );
  if (!diagnosticSummaries.length) lines.push('No diagnostics.', '');
  for (const summary of diagnosticSummaries) {
    lines.push(
      `- ${inlineCode(summary.code)}: ${summary.total} total (error ${summary.error}, warning ${summary.warning}, info ${summary.info})`
    );
  }
  if (diagnosticSummaries.length) lines.push('');
  return `${lines.join('\n')}\n`;
}

interface CoverageLimitationSummary {
  label: string;
  total: number;
}

const COVERAGE_LIMITATION_GROUPS: ReadonlyArray<{
  label: string;
  codes: ReadonlySet<string>;
}> = [
  {
    label: 'API requests or routes outside the supported static boundary',
    codes: new Set([
      'API_CONTRACT_COMPARISON_UNCERTAIN',
      'API_CONTRACT_DYNAMIC_CLIENT_BASE',
      'API_CONTRACT_DYNAMIC_CLIENT_METHOD',
      'API_CONTRACT_DYNAMIC_CLIENT_ROUTE',
      'API_CONTRACT_DYNAMIC_SERVER_ROUTE'
    ])
  },
  {
    label: 'operational rule inputs incomplete',
    codes: new Set([
      'OPERATIONAL_ACCIDENTAL_PROTECTION_INPUT_INCOMPLETE',
      'OPERATIONAL_SEED_DICTIONARY_INCOMPLETE',
      'OPERATIONAL_SEED_DICTIONARY_SOURCE_REQUIRED',
      'OPERATIONAL_SEED_DICTIONARY_SOURCE_UNRESOLVED',
      'OPERATIONAL_SEED_DICTIONARY_UNAVAILABLE',
      'OPERATIONAL_SOURCE_PARSE_INCOMPLETE'
    ])
  }
];

function summarizeCoverageLimitations(diagnostics: readonly DiagnosticRecord[]): CoverageLimitationSummary[] {
  return COVERAGE_LIMITATION_GROUPS.map((group) => ({
    label: group.label,
    total: diagnostics.filter((diagnostic) => group.codes.has(diagnostic.code)).length
  })).filter((summary) => summary.total > 0);
}

interface DispositionProjection {
  reviewId?: string;
  disposition?: string;
  reviewer?: string;
  date?: string;
  evidence?: string[];
  findingId?: string;
  title?: string;
}

function diagnosticDisposition(diagnostic: DiagnosticRecord): DispositionProjection | undefined {
  const value = (diagnostic as DiagnosticRecord & { disposition?: DispositionProjection }).disposition;
  return value && typeof value === 'object' ? value : undefined;
}

function dispositionLines(diagnostics: readonly DiagnosticRecord[]): string[] {
  const applied = diagnostics
    .filter((diagnostic) => diagnostic.code === 'FINDING_DISPOSITION_APPLIED')
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  if (!applied.length) return [];
  return [
    '## Dispositioned in this run',
    '',
    ...applied.map((diagnostic) => {
      const disposition = diagnosticDisposition(diagnostic);
      if (!disposition) return `- ${prose(diagnostic.message)}`;
      const review = disposition.reviewId ? inlineCode(disposition.reviewId) : 'unknown review';
      const subject = disposition.title
        ? prose(disposition.title)
        : disposition.findingId ? inlineCode(disposition.findingId) : 'suppressed finding';
      const decision = disposition.disposition ? inlineCode(disposition.disposition) : 'disposition applied';
      const attribution = [disposition.reviewer, disposition.date]
        .filter((value): value is string => Boolean(value))
        .map(prose)
        .join(' · ');
      const rationale = disposition.evidence?.length
        ? ` Evidence: ${disposition.evidence.map(prose).join('; ')}`
        : '';
      return `- ${review}: ${subject} — ${decision}${attribution ? ` (${attribution})` : ''}.${rationale}`;
    }),
    ''
  ];
}

/** Render the current deterministic, actionability-first review projection. */
export function renderTriageReport(
  run: RunRecord,
  findings: readonly FindingRecord[],
  diagnostics: readonly DiagnosticRecord[]
): string {
  const orderedFindings = [...findings].sort(compareFindingReviewPriority);
  const presentedFindings = orderedFindings.map((finding) => ({
    finding,
    presentation: findingPresentation(finding)
  }));
  assertDistinctFindingPresentations(presentedFindings);
  const diagnosticSummaries = summarizeDiagnostics(diagnostics);
  const coverageLimitations = summarizeCoverageLimitations(diagnostics);
  const instanceCount = findings.reduce((total, finding) => total + (finding.instanceCount ?? 1), 0);
  const lines = [
    '# Atlas triage report',
    '',
    `Run: ${inlineCode(run.runId)}`,
    `Snapshot: ${inlineCode(run.snapshotId)}`,
    `Producer: ${inlineCode(`atlas/triage-report@${TRIAGE_REPORT_VERSION}`)}`,
    '',
    '## Summary',
    '',
    `- Headline findings: ${findings.length}`,
    `- Finding instances: ${instanceCount}`,
    `- Severity: ${severityCounts(findings)}`,
    '- Review order: severity, static actionability band, confidence, repeated-instance count, then canonical identity. Severity labels are unchanged.',
    `- Diagnostics: ${diagnostics.length} across ${diagnosticSummaries.length} code${diagnosticSummaries.length === 1 ? '' : 's'}`,
    ...(coverageLimitations.length
      ? [
          `- Coverage status: incomplete; ${coverageLimitations.map((summary) => `${summary.total} ${summary.label}`).join('; ')}.`
        ]
      : ['- Coverage status: no known static-boundary limitation diagnostics were emitted; runtime behavior is still not established.']),
    '',
    ...dispositionLines(diagnostics),
    '## Findings',
    ''
  ];
  if (!orderedFindings.length) lines.push('No surfaced findings.', '');
  for (const [index, { finding, presentation }] of presentedFindings.entries()) {
    const reviewId = finding.reviewId ?? findingReviewIdentity(finding);
    const priorityBand = finding.reviewPriority?.band;
    lines.push(
      `### ${index + 1}. ${presentation.heading}`,
      '',
      `Contradiction: ${prose(finding.description)}`,
      '',
      `Action: ${prose(finding.nextValidation)}`,
      '',
      `Falsifier: ${prose(finding.refutationCondition ?? 'A reviewer demonstrates that the cited static relationship is not part of the effective target behavior.')}`,
      '',
      `- Review ID: ${inlineCode(reviewId)}`,
      `- Actionability: ${priorityBand ? prose(findingReviewPriorityBandLabel(priorityBand)) : 'legacy priority not recorded'}`,
      '',
      '<details>',
      '<summary>Evidence, impact, and calibration</summary>',
      '',
      ...presentation.details,
      '',
      '</details>',
      ''
    );
  }
  lines.push(
    '## Diagnostics',
    '',
    `Per-instance diagnostic records are retained only in ${inlineCode('diagnostics.jsonl')}.`,
    ''
  );
  if (!diagnosticSummaries.length) lines.push('No diagnostics.', '');
  for (const summary of diagnosticSummaries) {
    lines.push(
      `- ${inlineCode(summary.code)}: ${summary.total} total (error ${summary.error}, warning ${summary.warning}, info ${summary.info})`
    );
  }
  if (diagnosticSummaries.length) lines.push('');
  return `${lines.join('\n')}\n`;
}

/** Select the canonical projection declared by an immutable run marker. */
export function renderTriageReportForMarker(
  marker: string,
  run: RunRecord,
  findings: readonly FindingRecord[],
  diagnostics: readonly DiagnosticRecord[]
): string {
  if (marker === TRIAGE_REPORT_LEGACY_ANALYSIS_MARKER) {
    return renderTriageReportV1_0_0(run, findings, diagnostics);
  }
  if (marker === TRIAGE_REPORT_PREVIOUS_ANALYSIS_MARKER) {
    return renderTriageReportV1_1_0(run, findings, diagnostics);
  }
  if (marker === TRIAGE_REPORT_ANALYSIS_MARKER) {
    return renderTriageReport(run, findings, diagnostics);
  }
  throw new Error(`Unsupported triage-report marker: ${marker}`);
}
