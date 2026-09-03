import { createServer, type ServerResponse } from 'node:http';
import { isIP, type AddressInfo } from 'node:net';
import { domainToASCII } from 'node:url';
import { AtlasError } from '../errors.js';
import { ALL_VIEWER_ARTIFACTS } from './bundle.js';
import { verifyAndLoadRunViewer } from './verify.js';

export const DEFAULT_VIEWER_HOST = '127.0.0.1' as const;
export const DEFAULT_VIEWER_PORT = 4173 as const;
const LOOPBACK_VIEWER_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

type ViewerArtifactName = (typeof ALL_VIEWER_ARTIFACTS)[number];

const CONTENT_TYPES: Record<ViewerArtifactName, string> = {
  'app.css': 'text/css; charset=utf-8',
  'app.js': 'text/javascript; charset=utf-8',
  'atlas-data.js': 'text/javascript; charset=utf-8',
  'dependency-graph.mmd': 'text/plain; charset=utf-8',
  'index.html': 'text/html; charset=utf-8',
  'viewer-manifest.json': 'application/json; charset=utf-8'
};

const REQUEST_ARTIFACTS = new Map<string, ViewerArtifactName>([
  ['/', 'index.html'],
  ...ALL_VIEWER_ARTIFACTS.map((name) => [`/${name}`, name] as const)
]);

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'none'",
  "connect-src 'none'",
  "font-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "worker-src 'none'",
  "manifest-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'"
].join('; ');

const BASE_HEADERS = {
  'Cache-Control': 'no-store, max-age=0',
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=()',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
} as const;

export interface ViewerServerOptions {
  viewerDirectory: string;
  host?: string;
  port?: number;
  allowedHosts?: readonly string[];
}

export interface RunningViewerServer {
  directory: string;
  host: string;
  port: number;
  url: string;
  viewerId: string;
  close(): Promise<void>;
}

function requestArtifact(requestUrl: string | undefined): ViewerArtifactName | undefined {
  if (requestUrl === undefined) return undefined;
  const queryIndex = requestUrl.indexOf('?');
  const pathname = queryIndex < 0 ? requestUrl : requestUrl.slice(0, queryIndex);
  return REQUEST_ARTIFACTS.get(pathname);
}

function send(
  response: ServerResponse,
  status: number,
  body: Buffer,
  contentType: string,
  headOnly = false,
  additionalHeaders: Record<string, string> = {}
): void {
  response.writeHead(status, {
    ...BASE_HEADERS,
    ...additionalHeaders,
    'Content-Length': String(body.length),
    'Content-Type': contentType
  });
  response.end(headOnly ? undefined : body);
}

async function loadVerifiedArtifacts(viewerDirectory: string): Promise<{
  directory: string;
  viewerId: string;
  contents: Map<ViewerArtifactName, Buffer>;
}> {
  const verified = await verifyAndLoadRunViewer(viewerDirectory);
  const contents = new Map<ViewerArtifactName, Buffer>();
  for (const name of ALL_VIEWER_ARTIFACTS) {
    const content = verified.contents.get(name);
    if (!content) throw new AtlasError('VIEWER_ARTIFACT_SET', `Verified viewer artifact is missing: ${name}`);
    contents.set(name, content);
  }
  return { directory: verified.directory, viewerId: verified.summary.viewerId, contents };
}

function displayHost(host: string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function normalizedHostname(value: string): string | undefined {
  if (!value || value.length > 253 || /[\u0000-\u0020\u007f/@\\,#?]/u.test(value)) return undefined;
  const withoutDot = value.endsWith('.') ? value.slice(0, -1) : value;
  if (!withoutDot) return undefined;
  const ipVersion = isIP(withoutDot);
  if (ipVersion === 4) return withoutDot;
  if (ipVersion === 6) return new URL(`http://[${withoutDot}]/`).hostname.slice(1, -1).toLowerCase();
  const ascii = domainToASCII(withoutDot);
  if (!ascii || ascii.length > 253 || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/iu.test(ascii)) return undefined;
  return ascii.toLowerCase();
}

function requestAuthority(hostHeader: string | undefined): { hostname: string; port?: number } | undefined {
  if (!hostHeader || hostHeader.length > 261 || /[\u0000-\u0020\u007f/@\\,#?]/u.test(hostHeader)) return undefined;
  if (hostHeader.startsWith('[')) {
    const match = /^\[([^\]]+)\](?::([0-9]{1,5}))?$/u.exec(hostHeader);
    if (!match || isIP(match[1]!) !== 6 || (match[2] !== undefined && Number(match[2]) > 65_535)) return undefined;
    const hostname = normalizedHostname(match[1]!);
    return hostname ? { hostname, ...(match[2] === undefined ? {} : { port: Number(match[2]) }) } : undefined;
  }
  const match = /^([^:]+)(?::([0-9]{1,5}))?$/u.exec(hostHeader);
  if (!match || (match[2] !== undefined && Number(match[2]) > 65_535)) return undefined;
  const hostname = normalizedHostname(match[1]!);
  return hostname ? { hostname, ...(match[2] === undefined ? {} : { port: Number(match[2]) }) } : undefined;
}

export async function startViewerServer(options: ViewerServerOptions): Promise<RunningViewerServer> {
  const host = options.host ?? DEFAULT_VIEWER_HOST;
  const port = options.port ?? DEFAULT_VIEWER_PORT;
  if (!host.trim()) throw new AtlasError('VIEWER_SERVER_HOST_INVALID', 'Viewer server host must not be empty.');
  if (!LOOPBACK_VIEWER_HOSTS.has(host.toLowerCase())) {
    throw new AtlasError(
      'VIEWER_SERVER_HOST_UNSAFE',
      'Viewer server host must be loopback-only (127.0.0.1, ::1, or localhost).'
    );
  }
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new AtlasError('VIEWER_SERVER_PORT_INVALID', 'Viewer server port must be an integer from 0 through 65535.');
  }
  const allowedHosts = new Set(LOOPBACK_VIEWER_HOSTS);
  for (const candidate of options.allowedHosts ?? []) {
    const normalized = normalizedHostname(candidate);
    if (!normalized) {
      throw new AtlasError('VIEWER_SERVER_ALLOWED_HOST_INVALID', `Viewer allowed host is invalid: ${candidate}`);
    }
    allowedHosts.add(normalized);
  }

  const verified = await loadVerifiedArtifacts(options.viewerDirectory);
  let listeningPort = port;
  const server = createServer((request, response) => {
    const headOnly = request.method === 'HEAD';
    const authority = requestAuthority(request.headers.host);
    const loopbackPortMismatch = authority !== undefined && LOOPBACK_VIEWER_HOSTS.has(authority.hostname) &&
      authority.port !== listeningPort && !(authority.port === undefined && listeningPort === 80);
    if (authority === undefined || !allowedHosts.has(authority.hostname) || loopbackPortMismatch) {
      send(response, 421, Buffer.from('Misdirected request.\n', 'utf8'), 'text/plain; charset=utf-8', headOnly, { Connection: 'close' });
      return;
    }
    if (request.method !== 'GET' && !headOnly) {
      send(
        response,
        405,
        Buffer.from('Method not allowed.\n', 'utf8'),
        'text/plain; charset=utf-8',
        false,
        { Allow: 'GET, HEAD' }
      );
      return;
    }
    const artifact = requestArtifact(request.url);
    const content = artifact === undefined ? undefined : verified.contents.get(artifact);
    if (artifact === undefined || content === undefined) {
      send(response, 404, Buffer.from('Not found.\n', 'utf8'), 'text/plain; charset=utf-8', headOnly);
      return;
    }
    send(response, 200, content, CONTENT_TYPES[artifact], headOnly);
  });
  server.maxHeadersCount = 32;
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });

  await new Promise<void>((resolve, reject) => {
    const failed = (error: Error): void => {
      reject(new AtlasError('VIEWER_SERVER_LISTEN_FAILED', `Unable to start viewer server on ${host}:${port}: ${error.message}`));
    };
    server.once('error', failed);
    server.listen(port, host, () => {
      server.off('error', failed);
      resolve();
    });
  });

  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new AtlasError('VIEWER_SERVER_LISTEN_FAILED', 'Viewer server did not receive a TCP address.');
  }
  const listening = address as AddressInfo;
  listeningPort = listening.port;
  let closed = false;
  return {
    directory: verified.directory,
    host: listening.address,
    port: listening.port,
    url: `http://${displayHost(listening.address)}:${listening.port}/`,
    viewerId: verified.viewerId,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  };
}

export async function runViewerServer(options: ViewerServerOptions): Promise<void> {
  const running = await startViewerServer(options);
  process.stdout.write([
    'Atlas viewer verified and serving.',
    `URL: ${running.url}`,
    `Viewer: ${running.viewerId}`,
    `Directory: ${running.directory}`,
    'Press Ctrl+C to stop.',
    ''
  ].join('\n'));

  let stop = (): void => {};
  await new Promise<void>((resolve) => {
    stop = resolve;
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  process.off('SIGINT', stop);
  process.off('SIGTERM', stop);
  await running.close();
  process.stdout.write('Atlas viewer stopped.\n');
}
