import { parentPort, workerData } from 'node:worker_threads';
import { serialize } from 'node:v8';
import type { AnalysisFile, DiagnosticRecord, ResolvedProfile } from '../types.js';
import {
  analyzeUntrustedSnapshot,
  MAX_ISOLATED_ANALYSIS_OUTPUT_BYTES
} from './isolated-core.js';

interface WorkerInput {
  files: Array<Omit<AnalysisFile, 'content'> & { content: Uint8Array }>;
  profile: ResolvedProfile;
  boundaryDiagnostics: DiagnosticRecord[];
}

if (!parentPort) throw new Error('Atlas analysis worker requires a parent port.');

try {
  const input = workerData as WorkerInput;
  const files: AnalysisFile[] = input.files.map((file) => ({
    ...file,
    content: Buffer.from(file.content)
  }));
  const payload = serialize(analyzeUntrustedSnapshot(files, input.profile, input.boundaryDiagnostics));
  if (payload.length > MAX_ISOLATED_ANALYSIS_OUTPUT_BYTES) {
    throw new Error(`Analysis output exceeds the ${MAX_ISOLATED_ANALYSIS_OUTPUT_BYTES}-byte isolation limit.`);
  }
  parentPort.postMessage({ ok: true, payload });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    error: {
      name: error instanceof Error ? error.name : 'Error',
      message: error instanceof Error ? error.message : String(error)
    }
  });
}
