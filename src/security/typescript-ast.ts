import ts from 'typescript';

export const MAX_TYPESCRIPT_AST_DEPTH = 256;
export const MAX_TYPESCRIPT_AST_NODES = 250_000;

export type TypeScriptAstRejectionReason = 'parser-stack' | 'ast-depth' | 'ast-nodes';

export type BoundedTypeScriptParseResult =
  | { state: 'ready'; sourceFile: ts.SourceFile }
  | { state: 'rejected'; reason: TypeScriptAstRejectionReason };

function validateAstShape(sourceFile: ts.SourceFile): TypeScriptAstRejectionReason | undefined {
  const stack: Array<{ node: ts.Node; depth: number }> = [{ node: sourceFile, depth: 0 }];
  let visited = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    visited += 1;
    if (visited > MAX_TYPESCRIPT_AST_NODES) return 'ast-nodes';
    if (current.depth > MAX_TYPESCRIPT_AST_DEPTH) return 'ast-depth';
    const children: ts.Node[] = [];
    ts.forEachChild(current.node, (child) => {
      children.push(child);
    });
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: children[index]!, depth: current.depth + 1 });
    }
  }
  return undefined;
}

export function parseBoundedTypeScript(
  filePath: string,
  sourceText: string,
  scriptKind: ts.ScriptKind
): BoundedTypeScriptParseResult {
  let sourceFile: ts.SourceFile;
  try {
    sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true, scriptKind);
  } catch (error) {
    if (error instanceof RangeError) return { state: 'rejected', reason: 'parser-stack' };
    throw error;
  }
  const reason = validateAstShape(sourceFile);
  return reason ? { state: 'rejected', reason } : { state: 'ready', sourceFile };
}

export function boundedTypeScriptDiagnosticMessage(reason: TypeScriptAstRejectionReason): string {
  if (reason === 'parser-stack') {
    return 'TypeScript parsing exceeded the process stack limit; JavaScript/TypeScript analysis was skipped for this file.';
  }
  if (reason === 'ast-depth') {
    return `The parsed TypeScript AST exceeded the supported depth of ${MAX_TYPESCRIPT_AST_DEPTH}; JavaScript/TypeScript analysis was skipped for this file.`;
  }
  return `The parsed TypeScript AST exceeded the supported ${MAX_TYPESCRIPT_AST_NODES}-node budget; JavaScript/TypeScript analysis was skipped for this file.`;
}
