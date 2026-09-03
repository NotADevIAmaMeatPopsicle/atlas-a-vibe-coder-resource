import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { FINDING_POSTPROCESS_VERSION } from '../src/analysis/finding-postprocess.js';
import { OPERATIONAL_RISK_ANALYSIS_VERSION } from '../src/analysis/operational-risks.js';
import { TRIAGE_REPORT_VERSION } from '../src/artifact-contract.js';
import { evaluateOperationalControls, ANALYSIS_HEALTH_VERSION } from '../src/regression/incidents.js';
import { scanProject } from '../src/run.js';
import { TOOL_VERSION } from '../src/types.js';
import { verifyRunDirectory } from '../src/verify.js';
import { VIEWER_VERSION } from '../src/viewer/types.js';

const execFileAsync = promisify(execFile);
const projectRoot = path.resolve(import.meta.dirname, '..', '..');

async function projectText(relativePath: string): Promise<string> {
  return readFile(path.join(projectRoot, ...relativePath.split('/')), 'utf8');
}

test('the public CLI reference contains every current help signature and exit status', async () => {
  const [{ stdout }, documentation] = await Promise.all([
    execFileAsync(process.execPath, [path.join(projectRoot, 'dist', 'src', 'cli.js'), '--help'], { cwd: projectRoot }),
    projectText('docs/CLI-REFERENCE.md')
  ]);
  const signatures = stdout.split(/\r?\n/u)
    .filter((line) => line.startsWith('  atlas '))
    .map((line) => line.trim());
  assert(signatures.length > 20);
  for (const signature of signatures) {
    assert(documentation.includes(signature), `CLI reference is missing: ${signature}`);
  }
  for (const status of [0, 1, 2, 3]) assert(documentation.includes(`\`${status}\``));
  assert(documentation.includes(`Atlas \`${TOOL_VERSION}\``));
});

test('schema documentation matches current producer versions and control digests', async () => {
  const [documentation, controls] = await Promise.all([
    projectText('schemas/v1/README.md'),
    evaluateOperationalControls()
  ]);
  const expectedVersions = [
    ['Analysis health', ANALYSIS_HEALTH_VERSION],
    ['Operational-risk analyzer', OPERATIONAL_RISK_ANALYSIS_VERSION],
    ['Finding postprocessor', FINDING_POSTPROCESS_VERSION],
    ['Triage report', TRIAGE_REPORT_VERSION],
    ['Viewer', VIEWER_VERSION]
  ];
  for (const [producer, version] of expectedVersions) {
    assert(documentation.includes(`| ${producer} | \`${version}\` |`));
  }
  assert(documentation.includes(controls.catalogDigest));
  assert(documentation.includes(controls.corpusDigest));
  const normalized = documentation.replace(/\s+/gu, ' ');
  assert(normalized.includes(
    `The current corpus has ${controls.incidents.length} mechanism-specific broken/fixed pairs across ${controls.rules.length} operational rules`
  ));
});

test('dependency documentation matches every locked package version, scope, and license', async () => {
  const [documentation, rawLock] = await Promise.all([
    projectText('docs/DEPENDENCIES.md'),
    projectText('package-lock.json')
  ]);
  const lock = JSON.parse(rawLock) as {
    packages: Record<string, {
      version?: string;
      license?: string;
      dev?: boolean;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    }>;
  };
  const root = lock.packages['']!;
  for (const [location, metadata] of Object.entries(lock.packages).filter(([location]) => location !== '')) {
    const name = location.slice('node_modules/'.length);
    const scope = root.dependencies?.[name] !== undefined
      ? 'production'
      : root.devDependencies?.[name] !== undefined
        ? 'development'
        : metadata.dev === true
          ? 'transitive development'
          : 'transitive production';
    assert(metadata.version && metadata.license);
    assert(
      documentation.includes(`| \`${name}\` | ${metadata.version} | ${scope} | ${metadata.license} |`),
      `Dependency documentation is stale for ${name}.`
    );
  }
});

test('the documented public example retains its exact baseline and incomplete-health contract', {
  timeout: 120_000
}, async (context) => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atlas-public-example-'));
  context.after(async () => rm(workspace, { recursive: true, force: true }));
  const result = await scanProject({
    targetConfigPath: path.join(projectRoot, 'examples', 'minimal-js-ts-repository.target.json'),
    profilePath: path.join(projectRoot, 'examples', 'minimal-js-ts-repository.profile.json'),
    workspacePath: workspace
  });
  const verification = await verifyRunDirectory(result.runDirectory);
  assert.equal(result.run.counts.files, 10);
  assert.equal(result.run.counts.relationships, 7);
  assert.equal(verification.status, 'passed');
  assert.equal(verification.healthStatus, 'incomplete');

  const [rootReadme, exampleReadme] = await Promise.all([
    projectText('README.md'),
    projectText('examples/minimal-js-ts-repository/README.md')
  ]);
  assert(exampleReadme.includes('census contains these ten files'));
  assert(exampleReadme.includes('observe seven import-like declarations'));
  assert(rootReadme.includes('exits with status `2`'));
});
