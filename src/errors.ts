export class AtlasError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'AtlasError';
    this.code = code;
  }
}
export function errorDetails(error: unknown): { code: string; message: string } {
  if (error instanceof AtlasError) return { code: error.code, message: error.message };
  if (error instanceof Error) return { code: 'UNEXPECTED', message: error.message };
  return { code: 'UNEXPECTED', message: String(error) };
}
