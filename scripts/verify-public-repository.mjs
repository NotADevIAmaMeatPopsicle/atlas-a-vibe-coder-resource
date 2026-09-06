#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const MAX_SCANNED_FILE_BYTES = 16 * 1024 * 1024;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: options.encoding ?? 'utf8',
    input: options.input,
    windowsHide: true,
    maxBuffer: options.maxBuffer ?? MAX_SCANNED_FILE_BYTES + 1024 * 1024
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(command + ' ' + args.join(' ') + ' failed: ' + String(result.stderr).trim());
  }
  return result.stdout;
}

function git(args, options) {
  return run('git', ['-c', 'core.hooksPath=', ...args], options);
}

function npm(args) {
  const npmCli = process.env.npm_execpath;
  if (!npmCli) throw new Error('Run this verifier through npm run check or npm run verify:public.');
  return run(process.execPath, [npmCli, ...args]);
}

const detectors = [
  {
    label: 'private-key header',
    pattern: new RegExp(['-----BEGIN ', '(?:RSA |EC |OPENSSH |DSA )?', 'PRIVATE KEY-----'].join(''), 'u')
  },
  { label: 'AWS access key', pattern: new RegExp(['(?:AK', 'IA|AS', 'IA)[0-9A-Z]{16}'].join(''), 'u') },
  { label: 'GitHub token', pattern: new RegExp(['(?:gh[pousr]_', '[A-Za-z0-9]{20,}|github_pat_', '[A-Za-z0-9_]{20,})'].join(''), 'u') },
  { label: 'Google API key', pattern: new RegExp(['AIza', '[0-9A-Za-z_-]{35}'].join(''), 'u') },
  { label: 'Slack token', pattern: new RegExp(['xox[baprs]-', '[A-Za-z0-9-]{10,}'].join(''), 'u') },
  { label: 'Stripe live secret', pattern: new RegExp(['sk_', 'live_', '[0-9A-Za-z]{16,}'].join(''), 'u') },
  {
    label: 'credential-bearing connection URL',
    pattern: new RegExp(['(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis)', ':\\/\\/', '[^/\\s:@]+:[^@\\s/]+@'].join(''), 'iu')
  },
  {
    label: 'literal credential assignment',
    pattern: new RegExp(["(?:pass", "word|passwd|api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)", "\\s*[:=]\\s*['\"]", "[^'\"\\r\\n]{8,}", "['\"]"].join(''), 'iu')
  },
  {
    label: 'Windows user-profile path',
    pattern: new RegExp(['[A-Za-z]:\\\\', 'Users\\\\', '[^\\\\\\r\\n]+'].join(''), 'u')
  },
  {
    label: 'Unix user-home path',
    pattern: new RegExp(['/(?:Users|home)/', '[^/\\s]+/'].join(''), 'u')
  },
  { label: 'internal task identifier', pattern: new RegExp(['TA', 'SK-[0-9]+'].join(''), 'u') }
];

const sensitivePath = /(?:^|\/)(?:\.env(?:\.|$)|credentials\.json$|service-account[^/]*\.json$|id_(?:rsa|dsa|ecdsa|ed25519)$|[^/]+\.(?:db|dump|jks|key|keystore|p12|pem|pfx|sqlite|sqlite3))$/iu;
const allowedSensitivePaths = new Set(['examples/minimal-js-ts-repository/.env.example']);
const allowedEmailDomains = new Set(['example.invalid', 'example.test', 'users.noreply.github.com']);
const emailPattern = /[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/giu;

function textFromBytes(bytes) {
  if (bytes.includes(0)) return undefined;
  return bytes.toString('utf8');
}

function scanText(text, location, findings) {
  for (const detector of detectors) {
    if (detector.pattern.test(text)) findings.add(detector.label + ': ' + location);
  }
  for (const match of text.matchAll(emailPattern)) {
    if (!allowedEmailDomains.has(match[1].toLowerCase())) {
      findings.add('non-placeholder email address: ' + location);
    }
  }
}

function scanPath(relativePath, location, findings) {
  const portable = relativePath.replaceAll('\\', '/');
  if (sensitivePath.test(portable) && !allowedSensitivePaths.has(portable)) {
    findings.add('sensitive path class: ' + location);
  }
}

function scanFile(filePath, location, findings) {
  const metadata = lstatSync(filePath);
  if (!metadata.isFile()) {
    findings.add('non-regular file: ' + location);
    return;
  }
  if (metadata.size > MAX_SCANNED_FILE_BYTES) {
    findings.add('file exceeds ' + MAX_SCANNED_FILE_BYTES + '-byte audit limit: ' + location);
    return;
  }
  const text = textFromBytes(readFileSync(filePath));
  if (text !== undefined) scanText(text, location, findings);
}

const findings = new Set();
const currentFiles = String(git(['ls-files', '--cached', '--others', '--exclude-standard', '-z']))
  .split('\0')
  .filter(Boolean)
  .sort();
for (const relativePath of currentFiles) {
  scanPath(relativePath, 'working tree ' + relativePath, findings);
  scanFile(path.join(root, relativePath), 'working tree ' + relativePath, findings);
}

const historyObjects = String(git(['rev-list', '--objects', '--all']))
  .split(/\r?\n/u)
  .filter(Boolean);
const historyObjectPaths = new Map();
for (const record of historyObjects) {
  const separator = record.indexOf(' ');
  if (separator < 0) continue;
  const objectId = record.slice(0, separator);
  const relativePath = record.slice(separator + 1);
  historyObjectPaths.set(objectId, relativePath);
  scanPath(relativePath, 'Git history path ' + relativePath, findings);
}
const historyObjectChecks = String(git(
  ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
  { input: [...historyObjectPaths.keys()].join('\n') + '\n' }
)).split(/\r?\n/u).filter(Boolean);
let historyBlobCount = 0;
for (const record of historyObjectChecks) {
  const [objectId = '', type = '', rawSize = ''] = record.split(' ');
  if (type !== 'blob') continue;
  historyBlobCount += 1;
  const size = Number(rawSize);
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_SCANNED_FILE_BYTES) {
    const relativePath = historyObjectPaths.get(objectId) ?? '(unknown path)';
    findings.add('historical blob exceeds ' + MAX_SCANNED_FILE_BYTES + '-byte audit limit: Git history ' + relativePath);
  }
}

const historyPatch = String(git(
  ['log', '--all', '--format=commit %H%nAuthor: %an <%ae>%nSubject: %s', '--patch', '--binary', '--root'],
  { maxBuffer: 128 * 1024 * 1024 }
));
scanText(historyPatch, 'reachable Git history', findings);
if (/^Binary files .* differ$/mu.test(historyPatch) || /^GIT binary patch$/mu.test(historyPatch)) {
  findings.add('binary content requires manual inspection: reachable Git history');
}

const historyMetadata = String(git(['log', '--all', '--format=%H%x00%an%x00%ae%x00%s%x00']))
  .split('\0')
  .map((value) => value.trim())
  .filter(Boolean);
if (historyMetadata.length % 4 !== 0) throw new Error('Git returned malformed commit metadata.');
for (let index = 0; index < historyMetadata.length; index += 4) {
  const [commit = '', author = '', email = '', subject = ''] = historyMetadata.slice(index, index + 4);
  scanText(author + '\n' + email + '\n' + subject, 'commit metadata ' + commit.slice(0, 12), findings);
}

const packageReports = JSON.parse(npm(['pack', '--dry-run', '--json', '--ignore-scripts']));
if (!Array.isArray(packageReports) || packageReports.length !== 1 || !Array.isArray(packageReports[0]?.files)) {
  throw new Error('npm pack --dry-run returned an unexpected report shape.');
}
for (const entry of packageReports[0].files) {
  scanPath(entry.path, 'npm archive ' + entry.path, findings);
  scanFile(path.join(root, entry.path), 'npm archive ' + entry.path, findings);
}

if (findings.size) {
  throw new Error(['Public repository audit failed.', ...[...findings].sort()].join('\n'));
}

process.stdout.write(JSON.stringify({
  status: 'passed',
  workingTreeFiles: currentFiles.length,
  reachableHistoryBlobs: historyBlobCount,
  commits: historyMetadata.length / 4,
  packageFiles: packageReports[0].files.length
}) + '\n');
