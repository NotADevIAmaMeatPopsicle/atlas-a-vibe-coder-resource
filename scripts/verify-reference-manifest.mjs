#!/usr/bin/env node
import path from 'node:path';
import {
  MAX_REFERENCE_MANIFEST_BYTES,
  aggregateReferenceEntries,
  assertJsonNestingDepth,
  inventoryReferenceTree,
  readBoundedRegularFile
} from './reference-manifest-support.mjs';

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error('Expected --reference and --manifest arguments.');
    result[key.slice(2)] = value;
  }
  if (!result.reference || !result.manifest) throw new Error('Both --reference and --manifest are required.');
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const referenceRoot = path.resolve(args.reference);
  const manifestPath = path.resolve(args.manifest);
  const manifest = JSON.parse((await readBoundedRegularFile(
    manifestPath,
    MAX_REFERENCE_MANIFEST_BYTES,
    'Reference manifest'
  )).toString('utf8'));
  assertJsonNestingDepth(manifest);
  const files = await inventoryReferenceTree(referenceRoot);
  const totalBytes = files.reduce((total, entry) => total + entry.bytes, 0);
  const aggregateSha256 = aggregateReferenceEntries(files);
  if (manifest.schemaVersion !== 1) throw new Error('Unsupported reference manifest schemaVersion.');
  if (JSON.stringify(files) !== JSON.stringify(manifest.files)) throw new Error('Reference files differ from the immutable manifest.');
  if (files.length !== manifest.fileCount || totalBytes !== manifest.totalBytes || aggregateSha256 !== manifest.aggregateSha256) {
    throw new Error('Reference summary differs from the immutable manifest.');
  }
  process.stdout.write(`${JSON.stringify({
    status: 'passed',
    referenceRoot,
    manifestPath,
    fileCount: files.length,
    totalBytes,
    aggregateSha256
  })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
