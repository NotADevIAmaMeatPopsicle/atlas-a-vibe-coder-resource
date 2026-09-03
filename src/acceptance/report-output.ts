import { open, lstat, mkdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { AtlasError } from '../errors.js';
import { prettyCanonicalJson } from '../util/canonical.js';
import { isInside, resolveForContainment } from '../util/paths.js';

export interface ImmutableReportWriteResult {
  path: string;
  reused: boolean;
}

async function existingRegularFile(filePath: string): Promise<boolean> {
  try {
    const metadata = await lstat(filePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new AtlasError('REPORT_OUTPUT_UNSAFE', 'Report output must be a regular file, never a symlink or directory.');
    }
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

async function resolvedForbiddenRoots(values: string[]): Promise<string[]> {
  return Promise.all(values.map((value) => resolveForContainment(value)));
}

function assertOutsideForbiddenRoots(outputPath: string, forbiddenRoots: string[]): void {
  if (forbiddenRoots.some((root) => isInside(root, outputPath))) {
    throw new AtlasError(
      'REPORT_OUTPUT_UNSAFE',
      'Refusing to write a report inside a protected input, target, run, viewer, or reference location.'
    );
  }
}

/**
 * Write canonical report bytes exactly once. Existing identical bytes are
 * reused; an existing different file is never overwritten. Containment is
 * checked before and after parent creation so a junction/symlink cannot make a
 * lexical path appear to be outside a protected root.
 */
export async function writeImmutableCanonicalReport(
  outputValue: string,
  report: unknown,
  forbiddenRootValues: string[]
): Promise<ImmutableReportWriteResult> {
  const requestedOutput = path.resolve(outputValue);
  const forbiddenRoots = await resolvedForbiddenRoots(forbiddenRootValues);
  const beforeCreation = await resolveForContainment(requestedOutput);
  assertOutsideForbiddenRoots(beforeCreation, forbiddenRoots);

  await mkdir(path.dirname(requestedOutput), { recursive: true });
  const realParent = await realpath(path.dirname(requestedOutput));
  const outputPath = path.join(realParent, path.basename(requestedOutput));
  const afterCreation = await resolveForContainment(outputPath);
  assertOutsideForbiddenRoots(afterCreation, forbiddenRoots);

  const content = prettyCanonicalJson(report);
  if (await existingRegularFile(outputPath)) {
    const existing = await readFile(outputPath, 'utf8');
    if (existing !== content) {
      throw new AtlasError('REPORT_OUTPUT_EXISTS', 'Refusing to overwrite an existing report with different bytes.');
    }
    return { path: await realpath(outputPath), reused: true };
  }

  let handle;
  try {
    handle = await open(outputPath, 'wx');
    await handle.writeFile(content, 'utf8');
    await handle.sync();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    if (!(await existingRegularFile(outputPath)) || await readFile(outputPath, 'utf8') !== content) {
      throw new AtlasError('REPORT_OUTPUT_EXISTS', 'Refusing to overwrite an existing report with different bytes.');
    }
    return { path: await realpath(outputPath), reused: true };
  } finally {
    await handle?.close();
  }
  return { path: await realpath(outputPath), reused: false };
}
