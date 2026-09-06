import { AtlasError } from '../errors.js';
import { MAX_VERIFIER_NESTING_DEPTH, assertNestingDepth } from '../security/bounded-artifacts.js';
import { canonicalJson, compareCanonicalText, prettyCanonicalJson, sha256 } from '../util/canonical.js';
import { VIEWER_APP_JAVASCRIPT, VIEWER_CSS, VIEWER_HTML } from './assets.js';
import { renderDependencyMermaid } from './model.js';
import {
  VIEWER_VERSION,
  type ViewerArtifactDigest,
  type ViewerData,
  type ViewerManifest
} from './types.js';

export const VIEWER_MANIFEST_NAME = 'viewer-manifest.json' as const;
export const VIEWER_CONTENT_ARTIFACTS = [
  'app.css',
  'app.js',
  'atlas-data.js',
  'dependency-graph.mmd',
  'index.html'
] as const;
export const ALL_VIEWER_ARTIFACTS = [...VIEWER_CONTENT_ARTIFACTS, VIEWER_MANIFEST_NAME] as const;

const DATA_PREFIX = 'globalThis.__ATLAS_VIEWER_DATA_B64__="';
const DATA_SUFFIX = '";\n';

function isBase64AlphabetCode(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    (code >= 0x30 && code <= 0x39) ||
    code === 0x2b || code === 0x2f
  );
}

function hasCanonicalBase64Shape(value: string): boolean {
  if (!value.length || value.length % 4 !== 0) return false;
  let contentLength = value.length;
  if (value.endsWith('==')) contentLength -= 2;
  else if (value.endsWith('=')) contentLength -= 1;
  for (let index = 0; index < contentLength; index += 1) {
    if (!isBase64AlphabetCode(value.charCodeAt(index))) return false;
  }
  for (let index = contentLength; index < value.length; index += 1) {
    if (value.charCodeAt(index) !== 0x3d) return false;
  }
  return true;
}

export interface ViewerBundle {
  data: ViewerData;
  manifest: ViewerManifest;
  artifacts: Map<string, Buffer>;
}

export function encodeViewerData(data: ViewerData): string {
  const encoded = Buffer.from(canonicalJson(data), 'utf8').toString('base64');
  return `${DATA_PREFIX}${encoded}${DATA_SUFFIX}`;
}

export function decodeViewerDataScript(content: string): ViewerData {
  if (!content.startsWith(DATA_PREFIX) || !content.endsWith(DATA_SUFFIX)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer data script does not use the inert Atlas data envelope.');
  }
  const encoded = content.slice(DATA_PREFIX.length, -DATA_SUFFIX.length);
  if (!hasCanonicalBase64Shape(encoded)) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer data envelope is not canonical base64.');
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(encoded, 'base64'));
  } catch {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer data envelope is not valid UTF-8.');
  }
  let data: ViewerData;
  try {
    data = JSON.parse(text) as ViewerData;
  } catch {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer data envelope does not contain JSON.');
  }
  assertNestingDepth(data, {
    maxDepth: MAX_VERIFIER_NESTING_DEPTH,
    resourceCode: 'VIEWER_RESOURCE_LIMIT',
    label: 'Viewer data'
  });
  if (canonicalJson(data) !== text || Buffer.from(text, 'utf8').toString('base64') !== encoded) {
    throw new AtlasError('VIEWER_DATA_INVALID', 'Viewer data is not canonically encoded.');
  }
  return data;
}

function artifactDigest(artifactPath: string, content: Buffer): ViewerArtifactDigest {
  return { path: artifactPath, bytes: content.length, sha256: sha256(content) };
}

export function viewerIdentity(input: {
  runId: string;
  snapshotId: string;
  sourceArtifactManifestSha256: string;
  artifacts: ViewerArtifactDigest[];
}): string {
  return `viewer_sha256_${sha256(canonicalJson({
    domain: 'atlas.run-viewer.v1',
    schemaVersion: 1,
    viewerVersion: VIEWER_VERSION,
    ...input
  }))}`;
}

export function buildViewerBundle(data: ViewerData): ViewerBundle {
  const contentArtifacts = new Map<string, Buffer>([
    ['app.css', Buffer.from(VIEWER_CSS, 'utf8')],
    ['app.js', Buffer.from(VIEWER_APP_JAVASCRIPT, 'utf8')],
    ['atlas-data.js', Buffer.from(encodeViewerData(data), 'utf8')],
    ['dependency-graph.mmd', Buffer.from(renderDependencyMermaid(data), 'utf8')],
    ['index.html', Buffer.from(VIEWER_HTML, 'utf8')]
  ]);
  const digests = [...contentArtifacts]
    .map(([artifactPath, content]) => artifactDigest(artifactPath, content))
    .sort((left, right) => compareCanonicalText(left.path, right.path));
  const manifest: ViewerManifest = {
    schemaVersion: 1,
    viewerVersion: VIEWER_VERSION,
    viewerId: viewerIdentity({
      runId: data.run.runId,
      snapshotId: data.run.snapshotId,
      sourceArtifactManifestSha256: data.sourceArtifactManifestSha256,
      artifacts: digests
    }),
    runId: data.run.runId,
    snapshotId: data.run.snapshotId,
    sourceArtifactManifestSha256: data.sourceArtifactManifestSha256,
    artifacts: digests
  };
  return {
    data,
    manifest,
    artifacts: new Map([
      ...contentArtifacts,
      [VIEWER_MANIFEST_NAME, Buffer.from(prettyCanonicalJson(manifest), 'utf8')]
    ])
  };
}
