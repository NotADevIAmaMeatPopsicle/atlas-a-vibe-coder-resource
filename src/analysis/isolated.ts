import { Worker } from 'node:worker_threads';
import { deserialize } from 'node:v8';
import { AtlasError } from '../errors.js';
import type { AnalysisFile, DiagnosticRecord, ResolvedProfile } from '../types.js';
import type { UntrustedSnapshotAnalysis } from './isolated-core.js';

export const MAX_ISOLATED_ANALYSIS_MILLISECONDS = 120_000;
export const MAX_ISOLATED_ANALYSIS_OLD_GENERATION_MB = 512;

export async function runIsolatedAnalysis(
  files: AnalysisFile[],
  profile: ResolvedProfile,
  boundaryDiagnostics: DiagnosticRecord[]
): Promise<UntrustedSnapshotAnalysis> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./isolated-worker.js', import.meta.url), {
      workerData: { files, profile, boundaryDiagnostics },
      resourceLimits: {
        maxOldGenerationSizeMb: MAX_ISOLATED_ANALYSIS_OLD_GENERATION_MB,
        maxYoungGenerationSizeMb: 128,
        stackSizeMb: 8
      }
    });
    let settled = false;
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      action();
    };
    const timeout = setTimeout(() => {
      finish(() => {
        void worker.terminate();
        reject(new AtlasError(
          'ANALYSIS_RESOURCE_LIMIT',
          `Untrusted source analysis exceeded the ${MAX_ISOLATED_ANALYSIS_MILLISECONDS}-millisecond isolation limit.`
        ));
      });
    }, MAX_ISOLATED_ANALYSIS_MILLISECONDS);
    worker.once('message', (message: unknown) => {
      const result = message as
        | { ok: true; payload: Uint8Array }
        | { ok: false; error: { name: string; message: string } };
      finish(() => {
        if (!result.ok) {
          reject(new AtlasError('ANALYSIS_WORKER_FAILED', `Isolated source analysis failed: ${result.error.message}`));
          return;
        }
        try {
          resolve(deserialize(Buffer.from(result.payload)) as UntrustedSnapshotAnalysis);
        } catch (error) {
          reject(new AtlasError(
            'ANALYSIS_WORKER_FAILED',
            `Isolated source analysis returned an invalid bounded result: ${error instanceof Error ? error.message : 'unknown decode failure'}`
          ));
        }
      });
    });
    worker.once('error', (error) => {
      finish(() => reject(new AtlasError('ANALYSIS_RESOURCE_LIMIT', `Isolated source analysis failed safely: ${error.message}`)));
    });
    worker.once('exit', (code) => {
      if (code !== 0) {
        finish(() => reject(new AtlasError(
          'ANALYSIS_RESOURCE_LIMIT',
          `Isolated source analysis stopped with worker exit code ${code}.`
        )));
      }
    });
  });
}
