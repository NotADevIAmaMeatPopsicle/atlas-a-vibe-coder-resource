import { AtlasError } from '../errors.js';

export const PORTABLE_DATA_PREFLIGHT_VERSION = '1.0.0';

interface SecretPattern {
  id: string;
  pattern: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { id: 'private-key', pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u },
  { id: 'aws-access-key', pattern: /(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:$|[^A-Z0-9])/u },
  { id: 'github-token', pattern: /(?:^|[^A-Za-z0-9])(?:gh[opusr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})(?:$|[^A-Za-z0-9_])/u },
  { id: 'slack-token', pattern: /(?:^|[^A-Za-z0-9])xox[aboprs]-[A-Za-z0-9-]{20,}(?:$|[^A-Za-z0-9-])/u },
  { id: 'google-api-key', pattern: /(?:^|[^A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?:$|[^A-Za-z0-9_-])/u },
  { id: 'stripe-live-secret', pattern: /(?:^|[^A-Za-z0-9])(?:sk|rk)_live_[0-9A-Za-z]{20,}(?:$|[^A-Za-z0-9])/u },
  { id: 'openai-api-key', pattern: /(?:^|[^A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}(?:$|[^A-Za-z0-9_-])/u },
  { id: 'credentialed-url', pattern: /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@/u },
  { id: 'sensitive-query-value', pattern: /[?&](?:access_token|api_key|apikey|auth|password|secret|token)=[^&#\s]{8,}/iu }
];

const SOURCE_BODY_FIELD_NAMES = new Set([
  'contentBase64',
  'contentBytes',
  'fileContent',
  'rawSource',
  'sourceBody',
  'sourceText'
]);

export interface PortableDataPreflightSummary {
  checkedStrings: number;
  checkedObjects: number;
  secretLikeMatches: 0;
  sourceBodyFields: 0;
}

/**
 * Reject high-confidence credential shapes and source-body fields without ever
 * echoing the matched value or user-controlled object key into the error.
 */
export function assertPortableDataSafe(value: unknown, label = 'portable Atlas data'): PortableDataPreflightSummary {
  let checkedStrings = 0;
  let checkedObjects = 0;
  const active = new Set<object>();

  function visit(candidate: unknown): void {
    if (typeof candidate === 'string') {
      checkedStrings += 1;
      const match = SECRET_PATTERNS.find(({ pattern }) => pattern.test(candidate));
      if (match) {
        throw new AtlasError(
          'PORTABLE_DATA_SECRET_DETECTED',
          `${label} failed credential preflight (${match.id}); the matched value was not retained or logged.`
        );
      }
      return;
    }
    if (candidate === null || typeof candidate !== 'object') return;
    if (Buffer.isBuffer(candidate) || ArrayBuffer.isView(candidate) || candidate instanceof ArrayBuffer) {
      throw new AtlasError('PORTABLE_DATA_BINARY_BODY', `${label} contains a binary body and cannot be published.`);
    }
    const object = candidate as object;
    if (active.has(object)) throw new AtlasError('PORTABLE_DATA_CYCLE', `${label} contains a cyclic object graph.`);
    active.add(object);
    checkedObjects += 1;
    if (Array.isArray(candidate)) {
      for (const entry of candidate) visit(entry);
    } else {
      for (const [key, entry] of Object.entries(candidate as Record<string, unknown>)) {
        if (SOURCE_BODY_FIELD_NAMES.has(key)) {
          throw new AtlasError('PORTABLE_DATA_SOURCE_BODY', `${label} contains a forbidden source-body field.`);
        }
        visit(key);
        visit(entry);
      }
    }
    active.delete(object);
  }

  visit(value);
  return { checkedStrings, checkedObjects, secretLikeMatches: 0, sourceBodyFields: 0 };
}
