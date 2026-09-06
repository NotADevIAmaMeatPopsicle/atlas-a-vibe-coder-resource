#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  throw new Error('Run this verifier through npm run check or npm run verify:package.');
}

const result = spawnSync(
  process.execPath,
  [npmCli, 'pack', '--dry-run', '--json', '--ignore-scripts'],
  { encoding: 'utf8', windowsHide: true }
);
if (result.error) throw result.error;
if (result.status !== 0) {
  throw new Error(`npm pack --dry-run failed:\n${result.stderr.trim()}`);
}

let reports;
try {
  reports = JSON.parse(result.stdout);
} catch {
  throw new Error('npm pack --dry-run did not return valid JSON.');
}
if (!Array.isArray(reports) || reports.length !== 1 || !Array.isArray(reports[0]?.files)) {
  throw new Error('npm pack --dry-run returned an unexpected report shape.');
}

const exactFiles = new Set([
  'CODE_OF_CONDUCT.md',
  'CONTRIBUTING.md',
  'README.md',
  'SECURITY.md',
  'package.json',
  'reference/README.md',
  'corpus/incidents/synthetic-operational-risks/manifest.json',
  'corpus/real-target/example-target/manifest.json',
  'scripts/create-reference-manifest.mjs',
  'scripts/reference-manifest-support.mjs',
  'scripts/verify-package-contents.mjs',
  'scripts/verify-reference-manifest.mjs'
]);
const allowedPatterns = [
  /^dist\/src\/.+\.(?:d\.ts|js|js\.map)$/u,
  /^docs\/[^/]+\.md$/u,
  /^examples\/minimal-js-ts-repository(?:\.(?:profile|target)\.json|\/.+)$/u,
  /^schemas\/v1\/(?:README\.md|[^/]+\.schema\.json)$/u
];
const requiredFiles = [
  'dist/src/cli.js',
  'docs/PUBLIC-SOURCE-MANIFEST.md',
  'examples/minimal-js-ts-repository.target.json',
  'schemas/v1/target.schema.json',
  'scripts/create-reference-manifest.mjs'
];
const sensitivePath = /(?:^|\/)(?:\.env(?:\.|$)|credentials\.json$|service-account[^/]*\.json$|id_(?:rsa|dsa|ecdsa|ed25519)$|[^/]+\.(?:db|dump|jks|key|keystore|p12|pem|pfx|sqlite|sqlite3))$/iu;

const files = reports[0].files.map((entry) => entry.path).sort();
const unexpected = files.filter((file) =>
  !exactFiles.has(file) &&
  !allowedPatterns.some((pattern) => pattern.test(file)) &&
  !/^(?:LICEN[CS]E|NOTICE)(?:\..+)?$/iu.test(file)
);
const sensitive = files.filter((file) => sensitivePath.test(file) && file !== 'examples/minimal-js-ts-repository/.env.example');
const missing = requiredFiles.filter((file) => !files.includes(file));
const packageManifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const licenseFiles = files.filter((file) => /^(?:LICEN[CS]E|NOTICE)(?:\..+)?$/iu.test(file));

const publicExport = packageManifest.exports?.['.'];
if (
  packageManifest.type !== 'module' ||
  !publicExport ||
  Object.keys(publicExport).join(',') !== 'types,import' ||
  publicExport.types !== './dist/src/index.d.ts' ||
  publicExport.import !== './dist/src/index.js'
) {
  throw new Error('The package must expose one explicit ESM-only JavaScript and type entry point.');
}

if (packageManifest.private !== true) {
  throw new Error('Package publication lock is missing: package.json private must remain true until owner approval.');
}
if (packageManifest.license === 'UNLICENSED' && licenseFiles.length) {
  throw new Error('A license file exists but package.json still declares UNLICENSED.');
}
if (packageManifest.license !== 'UNLICENSED' && !licenseFiles.some((file) => /^LICEN[CS]E(?:\..+)?$/iu.test(file))) {
  throw new Error('Licensed package metadata requires a packaged license file.');
}

const packedFiles = new Set(files);
const brokenLinks = [];
for (const file of files.filter((candidate) => candidate.endsWith('.md'))) {
  const markdown = readFileSync(file, 'utf8');
  for (const match of markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/gu)) {
    const rawTarget = match[1].trim().replace(/^<|>$/gu, '');
    if (/^(?:[a-z][a-z0-9+.-]*:|#)/iu.test(rawTarget)) continue;
    const withoutFragment = rawTarget.split('#', 1)[0];
    if (!withoutFragment) continue;
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), decodeURIComponent(withoutFragment)));
    if (!packedFiles.has(target)) brokenLinks.push(`${file} -> ${rawTarget}`);
  }
}

if (unexpected.length || sensitive.length || missing.length || brokenLinks.length) {
  const lines = ['Package contents violate the public archive manifest.'];
  if (unexpected.length) lines.push(`Unexpected: ${unexpected.join(', ')}`);
  if (sensitive.length) lines.push(`Sensitive path class: ${sensitive.join(', ')}`);
  if (missing.length) lines.push(`Missing: ${missing.join(', ')}`);
  if (brokenLinks.length) lines.push(`Broken local Markdown links: ${brokenLinks.join(', ')}`);
  throw new Error(lines.join('\n'));
}

process.stdout.write(`${JSON.stringify({
  status: 'passed',
  fileCount: files.length,
  unpackedSize: reports[0].unpackedSize
})}\n`);
