import { loadRunArtifacts, type LoadedRun } from './artifacts.js';
import type { EvidenceReference, QueryHit, QueryResult } from './types.js';
import { assertSchema } from './schema-validator.js';
import { compareCanonicalText } from './util/canonical.js';

function terms(value: string): string[] {
  return [...new Set(value.toLowerCase().split(/[^a-z0-9_./:@-]+/).filter(Boolean))];
}

function scoreText(queryTerms: string[], text: string): number {
  const normalized = text.toLowerCase();
  let score = 0;
  for (const term of queryTerms) {
    if (normalized === term) score += 100;
    else if (normalized.includes(term)) score += 20;
  }
  return score;
}

function evidenceArray(value: EvidenceReference | EvidenceReference[]): EvidenceReference[] {
  return Array.isArray(value) ? value : [value];
}

/** @internal Queries only the caller's already verified run artifacts. */
export async function queryLoadedRun(loaded: LoadedRun, query: string, limit = 20): Promise<QueryResult> {
  const queryTerms = terms(query);
  const hits: QueryHit[] = [];
  for (const file of loaded.files) {
    const label = `${file.path} ${file.kind} ${file.language} ${file.symbols.join(' ')} ${file.environmentVariables.join(' ')}`;
    const score = scoreText(queryTerms, label) + (file.path.toLowerCase() === query.toLowerCase() ? 200 : 0);
    if (score) hits.push({ kind: 'file', id: file.id, score, label, path: file.path, evidence: [file.evidence] });
  }
  for (const relationship of loaded.relationships) {
    const label = `${relationship.fromPath} ${relationship.type} ${relationship.specifier} ${relationship.toPath ?? ''} ${relationship.resolution}`;
    const score = scoreText(queryTerms, label);
    if (score) hits.push({ kind: 'relationship', id: relationship.id, score, label, path: relationship.fromPath, evidence: [relationship.evidence] });
  }
  for (const finding of loaded.findings) {
    const instanceSubjects = (finding.instances ?? []).flatMap((instance) => instance.subject
      ? [instance.subject.table, instance.subject.column, instance.subject.dimension]
      : []
    );
    const label = `${finding.category} ${finding.kind ?? ''} ${finding.ruleId} ${finding.title} ${finding.description} ${finding.path ?? ''} ${finding.signals.join(' ')} ${instanceSubjects.join(' ')}`;
    const lexicalScore = scoreText(queryTerms, label);
    const score = lexicalScore ? lexicalScore + 10 : 0;
    if (score) hits.push({
      kind: 'finding',
      id: finding.id,
      score,
      label,
      ...(finding.path ? { path: finding.path } : {}),
      evidence: evidenceArray([
        ...finding.evidence,
        ...(finding.instances ?? []).flatMap((instance) => instance.evidence)
      ])
    });
  }
  for (const diagnostic of loaded.diagnostics) {
    const label = `${diagnostic.code} ${diagnostic.severity} ${diagnostic.message} ${diagnostic.path ?? ''}`;
    const score = scoreText(queryTerms, label);
    if (score) hits.push({ kind: 'diagnostic', id: diagnostic.id, score, label, ...(diagnostic.path ? { path: diagnostic.path } : {}), evidence: [diagnostic.evidence] });
  }
  hits.sort((left, right) => right.score - left.score || compareCanonicalText(left.id, right.id));
  const result: QueryResult = {
    schemaVersion: 1,
    runId: loaded.run.runId,
    snapshotId: loaded.snapshot.snapshotId,
    query,
    hits: hits.slice(0, Math.max(1, Math.min(limit, 500)))
  };
  await assertSchema('query-result', result, 'Query response');
  return result;
}

export async function queryRun(runDirectory: string, query: string, limit = 20): Promise<QueryResult> {
  return queryLoadedRun(await loadRunArtifacts(runDirectory), query, limit);
}
