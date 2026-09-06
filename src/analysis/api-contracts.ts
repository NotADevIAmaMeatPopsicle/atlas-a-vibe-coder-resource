import ts from 'typescript';
import type {
  AnalysisFile,
  DiagnosticRecord,
  FindingRecord,
  RelationshipRecord,
  SourceLocation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';

export const API_CONTRACT_ANALYSIS_VERSION = '1.2.0';

const PRODUCER = 'atlas/api-contracts';
const PARSED_LANGUAGES = new Set(['javascript', 'javascript-jsx', 'typescript', 'typescript-tsx']);
const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';
type ServerMethod = HttpMethod | 'ANY';

interface PathContract {
  display: string;
  segments: PathSegment[];
}

interface PathSegment {
  kind: 'literal' | 'parameter';
  value: string;
  comparisonValue: string;
  optional: boolean;
}

interface SourceAnchor {
  file: AnalysisFile;
  sourceFile: ts.SourceFile;
  node: ts.Node;
}

interface ServerRoute extends SourceAnchor {
  method: ServerMethod;
  route: PathContract;
  mountAnchors: SourceAnchor[];
}

interface ClientCall extends SourceAnchor {
  method: HttpMethod;
  route: PathContract;
  clientKind: 'fetch' | 'axios' | 'axios-facade';
  dynamicBaseSuffix: boolean;
}

interface ServerUncertainty {
  method?: ServerMethod;
  prefix: string;
  scope: 'exact' | 'prefix';
}

interface LocalServerRoute extends SourceAnchor {
  receiver: string;
  method: ServerMethod;
  route?: PathContract;
  uncertainty?: {
    message: string;
    basis: string;
  };
}

interface ImportedBinding {
  exportName: string;
  localName: string;
  resolution: RelationshipRecord['resolution'] | 'missing';
  specifier: string;
  targetPath?: string;
}

interface LocalMount extends SourceAnchor {
  receiver: string;
  prefix:
    | { state: 'root' }
    | { state: 'literal'; route: PathContract }
    | { state: 'dynamic' };
  target:
    | { kind: 'local-router'; receiver: string }
    | { kind: 'imported-router'; binding: ImportedBinding }
    | { kind: 'unsupported'; expression: ts.Expression; routeLike: boolean };
}

interface ServerModule {
  file: AnalysisFile;
  sourceFile: ts.SourceFile;
  applicationReceivers: Set<string>;
  routerReceivers: Set<string>;
  exportedRouters: Map<string, Set<string>>;
  exportedPassThroughMiddleware: Set<string>;
  importedBindings: Map<string, ImportedBinding>;
  routes: LocalServerRoute[];
  mounts: LocalMount[];
}

interface FacadeModule {
  exports: Map<string, Map<HttpMethod, AxiosReceiver>>;
}

interface AxiosReceiver {
  basePath?: string;
  dynamicBase: boolean;
  compareRelativeSuffix?: boolean;
}

const MAX_ROUTE_COMPOSITION_CONTEXTS = 4_096;
const MAX_COMPOSED_SERVER_ROUTES = 16_384;
export const MAX_API_CONTRACT_COMPARISON_STATES = 1_000_000;
export const MAX_API_CONTRACT_COMPARISON_CHARACTERS = 64 * 1024 * 1024;

interface ComparisonBudget {
  remaining: number;
  remainingCharacters: number;
}

interface LiteralProperty {
  state: 'absent' | 'literal' | 'dynamic';
  value?: string;
}

function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (filePath.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (filePath.endsWith('.ts') || filePath.endsWith('.mts') || filePath.endsWith('.cts')) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function locationFor(sourceFile: ts.SourceFile, node: ts.Node): SourceLocation {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return {
    line: start.line + 1,
    column: start.character + 1,
    endLine: end.line + 1,
    endColumn: end.character + 1
  };
}

function literalText(node: ts.Expression | undefined): string | undefined {
  return node && ts.isStringLiteralLike(node) ? node.text.normalize('NFC') : undefined;
}

function clientRouteText(node: ts.Expression | undefined): string | undefined {
  if (!node) return undefined;
  const literal = literalText(node);
  if (literal !== undefined) return literal;
  if (!ts.isTemplateExpression(node)) return undefined;

  let value = node.head.text.normalize('NFC');
  const initialBoundary = value.search(/[?#]/u);
  if (initialBoundary !== -1) return value.slice(0, initialBoundary);
  for (const span of node.templateSpans) {
    if (!value.endsWith('/')) return undefined;
    const suffix = span.literal.text.normalize('NFC');
    const boundary = suffix.search(/[?#]/u);
    const pathSuffix = boundary === -1 ? suffix : suffix.slice(0, boundary);
    if (pathSuffix && !pathSuffix.startsWith('/')) return undefined;
    value += `:param${pathSuffix}`;
    if (boundary !== -1) return value;
  }
  return value;
}

function relationshipFor(
  relationships: readonly RelationshipRecord[],
  fromPath: string,
  specifier: string
): Pick<ImportedBinding, 'resolution' | 'targetPath'> {
  const matches = relationships.filter((relationship) =>
    relationship.fromPath === fromPath &&
    relationship.specifier === specifier &&
    relationship.typeOnly !== true
  );
  const resolvedTargets = [...new Set(matches
    .filter((relationship) => relationship.resolution === 'resolved' && relationship.toPath)
    .map((relationship) => relationship.toPath!))];
  const targetPath = resolvedTargets[0];
  if (resolvedTargets.length === 1 && targetPath) return { resolution: 'resolved', targetPath };
  const states = [...new Set(matches.map((relationship) => relationship.resolution))].sort(compareCanonicalText);
  return { resolution: states[0] ?? 'missing' };
}

function importedBindings(
  sourceFile: ts.SourceFile,
  filePath: string,
  relationships: readonly RelationshipRecord[]
): Map<string, ImportedBinding> {
  const bindings = new Map<string, ImportedBinding>();
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      const specifier = statement.moduleSpecifier.text;
      const resolved = relationshipFor(relationships, filePath, specifier);
      const clause = statement.importClause;
      if (clause?.name) {
        bindings.set(clause.name.text, {
          localName: clause.name.text,
          exportName: 'default',
          specifier,
          ...resolved
        });
      }
      if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          bindings.set(element.name.text, {
            localName: element.name.text,
            exportName: element.propertyName?.text ?? element.name.text,
            specifier,
            ...resolved
          });
        }
      }
      if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
        bindings.set(clause.namedBindings.name.text, {
          localName: clause.namedBindings.name.text,
          exportName: '*',
          specifier,
          ...resolved
        });
      }
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!declaration.initializer || !ts.isCallExpression(declaration.initializer)) continue;
      const call = declaration.initializer;
      if (!ts.isIdentifier(call.expression) || call.expression.text !== 'require') continue;
      const specifier = literalText(call.arguments[0]);
      if (!specifier) continue;
      const resolved = relationshipFor(relationships, filePath, specifier);
      if (ts.isIdentifier(declaration.name)) {
        bindings.set(declaration.name.text, {
          localName: declaration.name.text,
          exportName: 'default',
          specifier,
          ...resolved
        });
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        for (const element of declaration.name.elements) {
          if (!ts.isIdentifier(element.name)) continue;
          const exported = element.propertyName && (ts.isIdentifier(element.propertyName) || ts.isStringLiteralLike(element.propertyName))
            ? element.propertyName.text
            : element.name.text;
          bindings.set(element.name.text, {
            localName: element.name.text,
            exportName: exported,
            specifier,
            ...resolved
          });
        }
      }
    }
  }
  return bindings;
}

function propertyName(node: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) return node.text;
  return undefined;
}

function literalObjectProperty(node: ts.Expression | undefined, requestedName: string): LiteralProperty {
  if (!node || !ts.isObjectLiteralExpression(node)) return { state: 'dynamic' };
  let result: LiteralProperty = { state: 'absent' };
  for (const property of node.properties) {
    if (ts.isSpreadAssignment(property)) {
      result = { state: 'dynamic' };
      continue;
    }
    if (ts.isPropertyAssignment(property)) {
      const name = propertyName(property.name);
      if (name === undefined) {
        result = { state: 'dynamic' };
      } else if (name === requestedName) {
        const value = literalText(property.initializer);
        result = value === undefined ? { state: 'dynamic' } : { state: 'literal', value };
      }
      continue;
    }
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === requestedName) {
      result = { state: 'dynamic' };
    } else if (ts.isMethodDeclaration(property) || ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property)) {
      const name = propertyName(property.name);
      if (name === undefined || name === requestedName) result = { state: 'dynamic' };
    }
  }
  return result;
}

function normalizeMethod(value: string | undefined): HttpMethod | undefined {
  const normalized = value?.normalize('NFC').toUpperCase();
  return normalized && HTTP_METHODS.has(normalized) ? normalized as HttpMethod : undefined;
}

function parsePathContract(value: string, client: boolean): PathContract | undefined {
  let normalized = value.normalize('NFC');
  if (client) {
    const boundary = normalized.search(/[?#]/u);
    if (boundary !== -1) normalized = normalized.slice(0, boundary);
  } else if (normalized.includes('#')) {
    return undefined;
  }
  if (!normalized.startsWith('/') || normalized.startsWith('//') || normalized.includes('\\')) return undefined;
  if (normalized.length > 1 && normalized.endsWith('/')) normalized = normalized.slice(0, -1);
  if (!normalized) normalized = '/';
  if (normalized === '/') return { display: '/', segments: [] };

  const segments: PathSegment[] = [];
  for (const segment of normalized.split('/').slice(1)) {
    if (!segment || segment === '.' || segment === '..') return undefined;
    const parameter = segment.match(/^:([A-Za-z_$][A-Za-z0-9_$]*)(\?)?$/u);
    if (parameter) {
      segments.push({ kind: 'parameter', value: ':param', comparisonValue: ':param', optional: parameter[2] === '?' });
      continue;
    }
    if (segment.includes('*') || segment.includes('(') || segment.includes(')') || (!client && segment.includes('?'))) return undefined;
    segments.push({ kind: 'literal', value: segment, comparisonValue: segment.toLowerCase(), optional: false });
  }
  const display = segments.length
    ? `/${segments.map((segment) => segment.kind === 'parameter' ? `:param${segment.optional ? '?' : ''}` : segment.value).join('/')}`
    : '/';
  return { display, segments };
}

function consumeComparisonState(budget: ComparisonBudget): boolean {
  if (budget.remaining <= 0) return false;
  budget.remaining -= 1;
  return true;
}

function consumeComparisonCharacters(budget: ComparisonBudget, count: number): boolean {
  if (count > budget.remainingCharacters) return false;
  budget.remainingCharacters -= count;
  return true;
}

function compatiblePath(
  server: PathContract,
  client: PathContract,
  budget: ComparisonBudget,
  serverStart = 0
): boolean | undefined {
  const pending: Array<[number, number]> = [[serverStart, 0]];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const [serverIndex, clientIndex] = pending.pop()!;
    const key = `${serverIndex}:${clientIndex}`;
    if (visited.has(key)) continue;
    if (!consumeComparisonState(budget)) return undefined;
    visited.add(key);
    if (serverIndex === server.segments.length) {
      if (clientIndex === client.segments.length) return true;
      continue;
    }
    const serverSegment = server.segments[serverIndex]!;
    if (serverSegment.optional) pending.push([serverIndex + 1, clientIndex]);
    if (clientIndex === client.segments.length) continue;
    const clientSegment = client.segments[clientIndex]!;
    if (!consumeComparisonCharacters(budget, serverSegment.value.length + clientSegment.value.length)) return undefined;
    if (
      serverSegment.kind === 'parameter' || clientSegment.kind === 'parameter' ||
      serverSegment.comparisonValue === clientSegment.comparisonValue
    ) {
      pending.push([serverIndex + 1, clientIndex + 1]);
    }
  }
  return false;
}

function compatibleMethod(server: ServerMethod, client: HttpMethod): boolean {
  return server === 'ANY' || server === client || (client === 'HEAD' && server === 'GET') || client === 'OPTIONS';
}

function joinedPath(basePath: string | undefined, routePath: string): string {
  if (!basePath || basePath === '/') return routePath;
  if (routePath === '/') return basePath;
  return `${basePath.replace(/\/$/u, '')}/${routePath.replace(/^\//u, '')}`;
}

function memberName(expression: ts.LeftHandSideExpression): { owner?: ts.Expression; name?: string; dynamic: boolean } {
  if (ts.isPropertyAccessExpression(expression)) {
    return { owner: expression.expression, name: expression.name.text, dynamic: false };
  }
  if (ts.isElementAccessExpression(expression)) {
    const name = literalText(expression.argumentExpression);
    return { owner: expression.expression, ...(name === undefined ? {} : { name }), dynamic: name === undefined };
  }
  return { dynamic: false };
}

function identifierName(expression: ts.Expression | undefined): string | undefined {
  return expression && ts.isIdentifier(expression) ? expression.text : undefined;
}

function terminalMemberName(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return undefined;
}

function evidence(anchor: SourceAnchor, basis: string) {
  const location = locationFor(anchor.sourceFile, anchor.node);
  return {
    level: 1 as const,
    producer: PRODUCER,
    producerVersion: API_CONTRACT_ANALYSIS_VERSION,
    basis,
    path: anchor.file.record.path,
    line: location.line,
    column: location.column,
    recordIds: [anchor.file.record.id]
  };
}

function diagnostic(
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  anchor: SourceAnchor,
  basis: string,
  material: unknown = null
): DiagnosticRecord {
  const location = locationFor(anchor.sourceFile, anchor.node);
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({ producer: PRODUCER, version: API_CONTRACT_ANALYSIS_VERSION, code, path: anchor.file.record.path, location, material })).slice(0, 24)}`,
    code,
    severity,
    message,
    path: anchor.file.record.path,
    location,
    evidence: evidence(anchor, basis)
  };
}

function findingId(ruleId: string, client: ClientCall): string {
  return `finding:${sha256(canonicalJson({
    producer: PRODUCER,
    version: API_CONTRACT_ANALYSIS_VERSION,
    ruleId,
    path: client.file.record.path,
    location: locationFor(client.sourceFile, client.node),
    method: client.method,
    route: client.route.display
  })).slice(0, 24)}`;
}

function uncertaintyCouldCover(
  uncertainty: ServerUncertainty,
  client: ClientCall,
  budget: ComparisonBudget
): boolean | undefined {
  if (!consumeComparisonState(budget)) return undefined;
  if (uncertainty.method && uncertainty.method !== 'ANY' && uncertainty.method !== client.method) return false;
  for (const route of clientRouteCandidates(client)) {
    if (!consumeComparisonCharacters(budget, route.display.length + uncertainty.prefix.length)) return undefined;
    if (uncertainty.scope === 'exact' && route.display === uncertainty.prefix) return true;
    if (uncertainty.scope === 'prefix' && (
      uncertainty.prefix === '/' ||
      route.display === uncertainty.prefix ||
      route.display.startsWith(`${uncertainty.prefix}/`)
    )) return true;
  }
  return false;
}

function expressFactoryKind(
  expression: ts.Expression | undefined,
  factories: Set<string>,
  routerFactories: Set<string>
): 'application' | 'router' | undefined {
  if (!expression || !ts.isCallExpression(expression)) return undefined;
  const called = terminalMemberName(expression.expression);
  if (!called) return undefined;
  if (routerFactories.has(called) || called === 'Router') return 'router';
  return factories.has(called) ? 'application' : undefined;
}

function hasExportModifier(node: ts.Node): boolean {
  return Boolean(ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));
}

function exportedRouters(sourceFile: ts.SourceFile, routerReceivers: ReadonlySet<string>): Map<string, Set<string>> {
  const exported = new Map<string, Set<string>>();
  function add(exportName: string, receiver: string): void {
    if (!routerReceivers.has(receiver)) return;
    const receivers = exported.get(exportName) ?? new Set<string>();
    receivers.add(receiver);
    exported.set(exportName, receivers);
  }
  for (const statement of sourceFile.statements) {
    if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression) && routerReceivers.has(statement.expression.text)) {
      add('default', statement.expression.text);
      continue;
    }
    if (ts.isExportDeclaration(statement) && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) {
        const local = element.propertyName?.text ?? element.name.text;
        add(element.name.text, local);
      }
      continue;
    }
    if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) add(declaration.name.text, declaration.name.text);
      }
      continue;
    }
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
    const assignment = statement.expression;
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken || !ts.isIdentifier(assignment.right)) continue;
    const left = assignment.left;
    if (
      ts.isPropertyAccessExpression(left) &&
      ts.isIdentifier(left.expression) && left.expression.text === 'module' &&
      left.name.text === 'exports' &&
      routerReceivers.has(assignment.right.text)
    ) {
      add('default', assignment.right.text);
    } else if (
      ts.isPropertyAccessExpression(left) &&
      ts.isIdentifier(left.expression) && left.expression.text === 'exports'
    ) {
      add(left.name.text, assignment.right.text);
    } else if (
      ts.isPropertyAccessExpression(left) &&
      ts.isPropertyAccessExpression(left.expression) &&
      ts.isIdentifier(left.expression.expression) && left.expression.expression.text === 'module' &&
      left.expression.name.text === 'exports'
    ) {
      add(left.name.text, assignment.right.text);
    }
  }
  return exported;
}

function isDefinitelyPassThroughMiddleware(
  expression: ts.ArrowFunction | ts.FunctionExpression | ts.FunctionDeclaration
): boolean {
  if (!expression.body || !ts.isBlock(expression.body) || expression.parameters.length < 3) return false;
  const nextParameter = expression.parameters[2]?.name;
  if (!nextParameter || !ts.isIdentifier(nextParameter)) return false;
  const statements = expression.body.statements;
  const last = statements.at(-1);
  if (
    !last || !ts.isExpressionStatement(last) || !ts.isCallExpression(last.expression) ||
    !ts.isIdentifier(last.expression.expression) || last.expression.expression.text !== nextParameter.text ||
    last.expression.arguments.length !== 0
  ) return false;

  const responseParameter = expression.parameters[1]?.name;
  if (!responseParameter || !ts.isIdentifier(responseParameter)) return false;
  const responseParameterName = responseParameter.text;
  const safeResponseMethods = new Set(['append', 'header', 'set', 'setHeader', 'type', 'vary']);
  return statements.slice(0, -1).every((statement) => {
    if (!ts.isExpressionStatement(statement) || !ts.isCallExpression(statement.expression)) return false;
    const called = memberName(statement.expression.expression);
    return called.name !== undefined && safeResponseMethods.has(called.name) &&
      called.owner !== undefined && ts.isIdentifier(called.owner) && called.owner.text === responseParameterName &&
      statement.expression.arguments.every((argument) =>
        ts.isIdentifier(argument) || ts.isStringLiteralLike(argument) || ts.isNumericLiteral(argument) ||
        argument.kind === ts.SyntaxKind.TrueKeyword || argument.kind === ts.SyntaxKind.FalseKeyword ||
        argument.kind === ts.SyntaxKind.NullKeyword
      );
  });
}

function exportedPassThroughMiddleware(sourceFile: ts.SourceFile): Set<string> {
  const local = new Set<string>();
  const exported = new Set<string>();
  for (const statement of sourceFile.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && isDefinitelyPassThroughMiddleware(statement)) {
      local.add(statement.name.text);
      if (hasExportModifier(statement)) exported.add(statement.name.text);
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(declaration.name) && declaration.initializer &&
        (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer)) &&
        isDefinitelyPassThroughMiddleware(declaration.initializer)
      ) {
        local.add(declaration.name.text);
        if (hasExportModifier(statement)) exported.add(declaration.name.text);
      }
    }
  }
  for (const statement of sourceFile.statements) {
    if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression) && local.has(statement.expression.text)) {
      exported.add('default');
      continue;
    }
    if (ts.isExportDeclaration(statement) && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) {
        const localName = element.propertyName?.text ?? element.name.text;
        if (local.has(localName)) exported.add(element.name.text);
      }
      continue;
    }
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
    const assignment = statement.expression;
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const left = assignment.left;
    if (
      ts.isIdentifier(assignment.right) && local.has(assignment.right.text) &&
      ts.isPropertyAccessExpression(left) && ts.isIdentifier(left.expression) &&
      left.expression.text === 'module' && left.name.text === 'exports'
    ) {
      exported.add('default');
    } else if (
      ts.isIdentifier(assignment.right) && local.has(assignment.right.text) &&
      ts.isPropertyAccessExpression(left) && ts.isIdentifier(left.expression) && left.expression.text === 'exports'
    ) {
      exported.add(left.name.text);
    } else if (
      ts.isIdentifier(assignment.right) && local.has(assignment.right.text) &&
      ts.isPropertyAccessExpression(left) && ts.isPropertyAccessExpression(left.expression) &&
      ts.isIdentifier(left.expression.expression) && left.expression.expression.text === 'module' &&
      left.expression.name.text === 'exports'
    ) {
      exported.add(left.name.text);
    } else if (
      ts.isObjectLiteralExpression(assignment.right) && ts.isPropertyAccessExpression(left) &&
      ts.isIdentifier(left.expression) && left.expression.text === 'module' && left.name.text === 'exports'
    ) {
      for (const property of assignment.right.properties) {
        if (ts.isShorthandPropertyAssignment(property) && local.has(property.name.text)) {
          exported.add(property.name.text);
        } else if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.initializer) && local.has(property.initializer.text)) {
          const name = propertyName(property.name);
          if (name) exported.add(name);
        }
      }
    }
  }
  return exported;
}

function collectServerBindings(sourceFile: ts.SourceFile): {
  applicationReceivers: Set<string>;
  routerReceivers: Set<string>;
} {
  const expressFactories = new Set(['express']);
  const routerFactories = new Set(['Router']);
  const applicationReceivers = new Set<string>();
  const routerReceivers = new Set<string>();

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      const moduleName = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      if (moduleName === 'express' && clause) {
        if (clause.name) expressFactories.add(clause.name.text);
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const binding of clause.namedBindings.elements) {
            if ((binding.propertyName?.text ?? binding.name.text) === 'Router') routerFactories.add(binding.name.text);
          }
        }
      }
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!declaration.initializer || !ts.isCallExpression(declaration.initializer)) continue;
      const call = declaration.initializer;
      if (!ts.isIdentifier(call.expression) || call.expression.text !== 'require' || literalText(call.arguments[0]) !== 'express') continue;
      if (ts.isIdentifier(declaration.name)) {
        expressFactories.add(declaration.name.text);
        routerFactories.add('Router');
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        for (const element of declaration.name.elements) {
          if (!ts.isIdentifier(element.name)) continue;
          const importedName = element.propertyName && (ts.isIdentifier(element.propertyName) || ts.isStringLiteralLike(element.propertyName))
            ? element.propertyName.text
            : element.name.text;
          if (importedName === 'Router') routerFactories.add(element.name.text);
        }
      }
    }
  }

  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const kind = expressFactoryKind(node.initializer, expressFactories, routerFactories);
      if (kind === 'application') applicationReceivers.add(node.name.text);
      if (kind === 'router') routerReceivers.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return { applicationReceivers, routerReceivers };
}

function collectClientBindings(
  sourceFile: ts.SourceFile,
  filePath: string,
  relationships: readonly RelationshipRecord[],
  facadeModules: ReadonlyMap<string, FacadeModule>
): {
  axiosReceivers: Map<string, AxiosReceiver & {
    clientKind: ClientCall['clientKind'];
    methods?: ReadonlyMap<HttpMethod, AxiosReceiver>;
  }>;
  fetchReceivers: Set<string>;
} {
  const axiosReceivers = new Map<string, AxiosReceiver & {
    clientKind: ClientCall['clientKind'];
    methods?: ReadonlyMap<HttpMethod, AxiosReceiver>;
  }>([
    ['axios', { dynamicBase: false, clientKind: 'axios' }]
  ]);
  const fetchReceivers = new Set(['fetch']);
  const imports = importedBindings(sourceFile, filePath, relationships);

  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    const moduleName = statement.moduleSpecifier.text;
    const clause = statement.importClause;
    if (!clause) continue;
    if (moduleName === 'axios' && clause.name) {
      axiosReceivers.set(clause.name.text, { dynamicBase: false, clientKind: 'axios' });
    } else if (moduleName === 'node-fetch' && clause.name) {
      fetchReceivers.add(clause.name.text);
    } else if (moduleName === 'undici' && clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const binding of clause.namedBindings.elements) {
        if ((binding.propertyName?.text ?? binding.name.text) === 'fetch') fetchReceivers.add(binding.name.text);
      }
    }
  }

  for (const binding of imports.values()) {
    if (!binding.targetPath) continue;
    const methods = facadeModules.get(binding.targetPath)?.exports.get(binding.exportName);
    if (methods?.size) {
      axiosReceivers.set(binding.localName, { dynamicBase: false, clientKind: 'axios-facade', methods });
    }
  }

  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const localName = node.name.text;
      if (ts.isCallExpression(node.initializer)) {
        const member = memberName(node.initializer.expression);
        const ownerName = identifierName(member.owner);
        if (member.name === 'create' && ownerName && axiosReceivers.has(ownerName)) {
          axiosReceivers.set(localName, {
            ...axiosCreateBase(node.initializer, false),
            clientKind: 'axios'
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return { axiosReceivers, fetchReceivers };
}

function axiosCreateBase(call: ts.CallExpression, compareDynamicSuffix: boolean): AxiosReceiver {
  const base = call.arguments[0] === undefined
    ? { state: 'absent' } as LiteralProperty
    : literalObjectProperty(call.arguments[0], 'baseURL');
  if (base.state === 'absent') return { dynamicBase: false };
  if (base.state === 'dynamic') {
    return {
      dynamicBase: true,
      ...(compareDynamicSuffix ? { compareRelativeSuffix: true } : {})
    };
  }
  const parsed = base.value === undefined ? undefined : parsePathContract(base.value, true);
  return parsed
    ? { basePath: parsed.display, dynamicBase: false }
    : { dynamicBase: true };
}

function unwrappedExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) || ts.isTypeAssertionExpression(current) || ts.isNonNullExpression(current)
  ) current = current.expression;
  return current;
}

function rootIdentifier(expression: ts.Expression): string | undefined {
  let current = unwrappedExpression(expression);
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    current = unwrappedExpression(current.expression);
  }
  return ts.isIdentifier(current) ? current.text : undefined;
}

function certifiedFacadeMethod(
  member: ts.MethodDeclaration,
  method: HttpMethod,
  firstParameterName: string,
  axiosProperties: ReadonlyMap<string, AxiosReceiver>
): AxiosReceiver | undefined {
  if (!member.body) return undefined;
  function delegation(expression: ts.Expression | undefined): AxiosReceiver | undefined {
    if (!expression) return undefined;
    const unwrapped = unwrappedExpression(expression);
    if (!ts.isCallExpression(unwrapped)) return undefined;
    const called = memberName(unwrapped.expression);
    const delegatedMethod = normalizeMethod(called.name);
    const firstArgument = unwrapped.arguments[0];
    if (
      delegatedMethod !== method || !firstArgument || !ts.isIdentifier(firstArgument) ||
      firstArgument.text !== firstParameterName
    ) return undefined;
    if (called.owner && ts.isPropertyAccessExpression(called.owner) && called.owner.expression.kind === ts.SyntaxKind.ThisKeyword) {
      return axiosProperties.get(called.owner.name.text);
    }
    return undefined;
  }

  const statements = member.body.statements;
  if (statements.length === 1 && ts.isReturnStatement(statements[0]!)) {
    return delegation(statements[0]!.expression);
  }
  if (
    statements.length === 2 && ts.isVariableStatement(statements[0]!) &&
    statements[0]!.declarationList.declarations.length === 1 && ts.isReturnStatement(statements[1]!)
  ) {
    const declaration = statements[0]!.declarationList.declarations[0]!;
    const returned = statements[1]!.expression;
    if (!ts.isIdentifier(declaration.name) || !returned || rootIdentifier(returned) !== declaration.name.text) {
      return undefined;
    }
    return delegation(declaration.initializer);
  }
  return undefined;
}

function bindingContainsIdentifier(name: ts.BindingName, requested: string): boolean {
  if (ts.isIdentifier(name)) return name.text === requested;
  return name.elements.some((element) =>
    ts.isOmittedExpression(element) ? false : bindingContainsIdentifier(element.name, requested)
  );
}

function functionBindsIdentifier(
  declaration: ts.ConstructorDeclaration,
  requested: string
): boolean {
  if (declaration.parameters.some((parameter) => bindingContainsIdentifier(parameter.name, requested))) return true;
  let found = false;
  function inspect(node: ts.Node): void {
    if (found) return;
    if (node !== declaration.body && ts.isFunctionLike(node)) return;
    if (ts.isVariableDeclaration(node) && bindingContainsIdentifier(node.name, requested)) {
      found = true;
      return;
    }
    if (ts.isCatchClause(node) && node.variableDeclaration && bindingContainsIdentifier(node.variableDeclaration.name, requested)) {
      found = true;
      return;
    }
    ts.forEachChild(node, inspect);
  }
  if (declaration.body) inspect(declaration.body);
  return found;
}

function certifiedFacadeModule(sourceFile: ts.SourceFile): FacadeModule {
  const axiosNames = new Set<string>();
  for (const statement of sourceFile.statements) {
    if (
      ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier) &&
      statement.moduleSpecifier.text === 'axios' && statement.importClause?.name
    ) {
      axiosNames.add(statement.importClause.name.text);
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(declaration.name) && declaration.initializer && ts.isCallExpression(declaration.initializer) &&
        ts.isIdentifier(declaration.initializer.expression) && declaration.initializer.expression.text === 'require' &&
        literalText(declaration.initializer.arguments[0]) === 'axios'
      ) axiosNames.add(declaration.name.text);
    }
  }

  const classMethods = new Map<string, Map<HttpMethod, AxiosReceiver>>();
  for (const statement of sourceFile.statements) {
    if (!ts.isClassDeclaration(statement) || !statement.name) continue;
    const propertyAssignments = new Map<string, ts.BinaryExpression[]>();
    function collectAssignments(node: ts.Node): void {
      if (
        ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left) && node.left.expression.kind === ts.SyntaxKind.ThisKeyword
      ) {
        const assignments = propertyAssignments.get(node.left.name.text) ?? [];
        assignments.push(node);
        propertyAssignments.set(node.left.name.text, assignments);
      }
      ts.forEachChild(node, collectAssignments);
    }
    for (const member of statement.members) collectAssignments(member);

    const axiosProperties = new Map<string, AxiosReceiver>();
    for (const member of statement.members) {
      if (!ts.isConstructorDeclaration(member) || !member.body) continue;
      for (const constructorStatement of member.body.statements) {
        if (!ts.isExpressionStatement(constructorStatement)) continue;
        const assignment = constructorStatement.expression;
        if (
          !ts.isBinaryExpression(assignment) || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
          !ts.isPropertyAccessExpression(assignment.left) ||
          assignment.left.expression.kind !== ts.SyntaxKind.ThisKeyword || !ts.isCallExpression(assignment.right)
        ) continue;
        const property = assignment.left.name.text;
        const called = memberName(assignment.right.expression);
        const axiosName = identifierName(called.owner);
        if (
          propertyAssignments.get(property)?.length === 1 && called.name === 'create' && axiosName &&
          axiosNames.has(axiosName) && !functionBindsIdentifier(member, axiosName)
        ) {
          axiosProperties.set(property, axiosCreateBase(assignment.right, true));
        }
      }
    }
    const methods = new Map<HttpMethod, AxiosReceiver>();
    for (const member of statement.members) {
      if (!ts.isMethodDeclaration(member) || !member.body || !member.name) continue;
      const declaredName = propertyName(member.name);
      const method = normalizeMethod(declaredName);
      const firstParameter = member.parameters[0]?.name;
      if (!method || !firstParameter || !ts.isIdentifier(firstParameter)) continue;
      const contract = certifiedFacadeMethod(member, method, firstParameter.text, axiosProperties);
      if (contract) methods.set(method, contract);
    }
    if (methods.size) classMethods.set(statement.name.text, methods);
  }

  const instances = new Map<string, Map<HttpMethod, AxiosReceiver>>();
  const namedExports = new Map<string, Map<HttpMethod, AxiosReceiver>>();
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer || !ts.isNewExpression(declaration.initializer)) continue;
      const className = identifierName(declaration.initializer.expression);
      const methods = className ? classMethods.get(className) : undefined;
      if (!methods) continue;
      instances.set(declaration.name.text, methods);
      if (hasExportModifier(statement)) namedExports.set(declaration.name.text, methods);
    }
  }

  for (const statement of sourceFile.statements) {
    if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression)) {
      const methods = instances.get(statement.expression.text);
      if (methods) namedExports.set('default', methods);
      continue;
    }
    if (ts.isExportDeclaration(statement) && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) {
        const local = element.propertyName?.text ?? element.name.text;
        const methods = instances.get(local);
        if (methods) namedExports.set(element.name.text, methods);
      }
      continue;
    }
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
    const assignment = statement.expression;
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken || !ts.isIdentifier(assignment.right)) continue;
    const methods = instances.get(assignment.right.text);
    if (!methods || !ts.isPropertyAccessExpression(assignment.left)) continue;
    const left = assignment.left;
    if (ts.isIdentifier(left.expression) && left.expression.text === 'module' && left.name.text === 'exports') {
      namedExports.set('default', methods);
    } else if (ts.isIdentifier(left.expression) && left.expression.text === 'exports') {
      namedExports.set(left.name.text, methods);
    }
  }
  return { exports: namedExports };
}

function parseServerModule(
  file: AnalysisFile,
  sourceFile: ts.SourceFile,
  relationships: readonly RelationshipRecord[]
): ServerModule {
  const { applicationReceivers, routerReceivers } = collectServerBindings(sourceFile);
  const allReceivers = new Set([...applicationReceivers, ...routerReceivers]);
  const bindings = importedBindings(sourceFile, file.record.path, relationships);
  const routes: LocalServerRoute[] = [];
  const mounts: LocalMount[] = [];
  const makeAnchor = (node: ts.Node): SourceAnchor => ({ file, sourceFile, node });

  function inspect(node: ts.Node): void {
    if (ts.isCallExpression(node)) {
      const member = memberName(node.expression);
      let receiver = identifierName(member.owner);
      let routeArgument = node.arguments[0];
      if (member.owner && ts.isCallExpression(member.owner)) {
        const chained = memberName(member.owner.expression);
        const candidate = identifierName(chained.owner);
        if (chained.name === 'route' && candidate && allReceivers.has(candidate)) {
          receiver = candidate;
          routeArgument = member.owner.arguments[0];
        }
      }
      if (receiver && allReceivers.has(receiver)) {
        if (!member.dynamic && member.name === 'use') {
          const prefixText = literalText(node.arguments[0]);
          let prefix: LocalMount['prefix'];
          let targetArguments: ts.Expression[];
          if (prefixText !== undefined) {
            const route = parsePathContract(prefixText, false);
            prefix = route ? { state: 'literal', route } : { state: 'dynamic' };
            targetArguments = [...node.arguments.slice(1)];
          } else {
            const firstName = identifierName(node.arguments[0]);
            const firstIsKnownTarget = Boolean(
              firstName && (
                routerReceivers.has(firstName) ||
                (bindings.has(firstName) && /(?:route|router)/iu.test(firstName))
              )
            );
            if (node.arguments.length <= 1 || firstIsKnownTarget) {
              prefix = { state: 'root' };
              targetArguments = [...node.arguments];
            } else {
              prefix = { state: 'dynamic' };
              targetArguments = [...node.arguments.slice(1)];
            }
          }

          let supportedTarget = false;
          let unsupportedRouteTarget: ts.Expression | undefined;
          for (const targetExpression of targetArguments) {
            const targetName = identifierName(targetExpression);
            const localRouter = targetName && routerReceivers.has(targetName) ? targetName : undefined;
            const binding = targetName ? bindings.get(targetName) : undefined;
            if (localRouter) {
              supportedTarget = true;
              mounts.push({ ...makeAnchor(node), receiver, prefix, target: { kind: 'local-router', receiver: localRouter } });
            } else if (binding) {
              supportedTarget = true;
              mounts.push({ ...makeAnchor(node), receiver, prefix, target: { kind: 'imported-router', binding } });
            } else if (
              (targetName && /(?:route|router)/iu.test(targetName)) ||
              (ts.isCallExpression(targetExpression) && /(?:route|router)/iu.test(terminalMemberName(targetExpression.expression) ?? ''))
            ) {
              unsupportedRouteTarget ??= targetExpression;
            }
          }
          if (unsupportedRouteTarget || !supportedTarget) {
            const targetExpression = unsupportedRouteTarget ?? targetArguments.at(-1);
            if (targetExpression) {
              const targetName = identifierName(targetExpression);
              const routeLike = Boolean(
                prefix.state !== 'root' ||
                (targetName && /(?:route|router)/iu.test(targetName)) ||
                (ts.isCallExpression(targetExpression) && /(?:route|router)/iu.test(terminalMemberName(targetExpression.expression) ?? ''))
              );
              if (routeLike) {
                mounts.push({ ...makeAnchor(node), receiver, prefix, target: { kind: 'unsupported', expression: targetExpression, routeLike } });
              }
            }
          }
        } else {
          const method = member.dynamic ? 'ANY' : member.name === 'all' ? 'ANY' : normalizeMethod(member.name);
          if (method) {
            const routeText = literalText(routeArgument);
            const route = routeText === undefined ? undefined : parsePathContract(routeText, false);
            routes.push({
              ...makeAnchor(routeArgument ?? node),
              receiver,
              method,
              ...(route ? { route } : {}),
              ...((member.dynamic || !route) ? {
                uncertainty: {
                  message: member.dynamic
                    ? 'An Express receiver uses a dynamic registration method, so matching client requests remain unknown.'
                    : routeText === undefined
                    ? 'An Express route uses a dynamic path, so compatible client requests remain unknown.'
                    : 'An Express route uses unsupported literal path syntax, so compatible client requests remain unknown.',
                  basis: 'unsupported-or-dynamic-express-route-syntax'
                }
              } : {})
            });
          }
        }
      }
    }
    ts.forEachChild(node, inspect);
  }
  inspect(sourceFile);
  return {
    file,
    sourceFile,
    applicationReceivers,
    routerReceivers,
    exportedRouters: exportedRouters(sourceFile, routerReceivers),
    exportedPassThroughMiddleware: exportedPassThroughMiddleware(sourceFile),
    importedBindings: bindings,
    routes,
    mounts
  };
}

function clientRouteCandidates(client: ClientCall): PathContract[] {
  return [client.route];
}

function compatibleClientRoute(
  server: PathContract,
  client: ClientCall,
  budget: ComparisonBudget
): boolean | undefined {
  if (!client.dynamicBaseSuffix) return compatiblePath(server, client.route, budget);
  for (let index = 0; index <= server.segments.length; index += 1) {
    const result = compatiblePath(server, client.route, budget, index);
    if (result === undefined || result) return result;
  }
  return false;
}

/**
 * Compares source-anchored literal Express routes with source-anchored literal
 * fetch and axios calls. Resolved literal router mounts are composed from
 * direct Express application roots. Unsupported routing remains uncertainty.
 */
export function detectApiContractMismatches(
  files: AnalysisFile[],
  relationships: readonly RelationshipRecord[] = []
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const routes: ServerRoute[] = [];
  const clients: ClientCall[] = [];
  const uncertainties: ServerUncertainty[] = [];
  const diagnostics: DiagnosticRecord[] = [];
  const parsed = [...files]
    .filter((file) => PARSED_LANGUAGES.has(file.record.language))
    .sort((left, right) => compareCanonicalText(left.record.path, right.record.path))
    .flatMap((file) => {
      const parsedSource = parseBoundedTypeScript(file.record.path, file.content.toString('utf8'), scriptKind(file.record.path));
      return parsedSource.state === 'ready' ? [{ file, sourceFile: parsedSource.sourceFile }] : [];
    });
  const facadeModules = new Map(parsed.map(({ file, sourceFile }) => [file.record.path, certifiedFacadeModule(sourceFile)]));
  const serverModules = new Map(parsed.map(({ file, sourceFile }) => [
    file.record.path,
    parseServerModule(file, sourceFile, relationships)
  ]));

  function addServerUncertainty(
    anchor: SourceAnchor,
    method: ServerMethod | undefined,
    message: string,
    prefixes: readonly string[],
    scope: ServerUncertainty['scope'] = 'prefix',
    code = 'API_CONTRACT_DYNAMIC_SERVER_ROUTE',
    basis = 'unsupported-or-dynamic-express-route-syntax'
  ): void {
    const values = prefixes.length ? prefixes : ['/'];
    for (const prefix of values) uncertainties.push({ ...(method ? { method } : {}), prefix, scope });
    diagnostics.push(diagnostic(
      code,
      'warning',
      message,
      anchor,
      basis,
      { method: method ?? null, prefixes: values, scope }
    ));
  }

  interface TraversalContext {
    module: ServerModule;
    receiver: string;
    bases: string[];
    mounts: SourceAnchor[];
    ancestry: Set<string>;
  }

  const queue: TraversalContext[] = [];
  const visitedContexts = new Set<string>();
  let compositionLimitReached = false;
  function contextKey(module: ServerModule, receiver: string, bases: readonly string[]): string {
    return canonicalJson({ path: module.file.record.path, receiver, bases });
  }
  function noteCompositionLimit(anchor: SourceAnchor, detail: string): void {
    if (compositionLimitReached) return;
    compositionLimitReached = true;
    addServerUncertainty(
      anchor,
      'ANY',
      `Express route composition exceeded its deterministic ${detail}; API contract comparison is incomplete.`,
      ['/'],
      'prefix',
      'API_CONTRACT_ROUTE_COMPOSITION_LIMIT',
      'express-route-composition-context-limit'
    );
  }
  for (const module of serverModules.values()) {
    if (module.file.record.kind === 'test') continue;
    for (const receiver of module.applicationReceivers) {
      const key = contextKey(module, receiver, ['/']);
      if (visitedContexts.has(key)) continue;
      if (visitedContexts.size >= MAX_ROUTE_COMPOSITION_CONTEXTS) {
        noteCompositionLimit(
          { file: module.file, sourceFile: module.sourceFile, node: module.sourceFile },
          `${MAX_ROUTE_COMPOSITION_CONTEXTS}-context limit`
        );
        break;
      }
      visitedContexts.add(key);
      queue.push({ module, receiver, bases: ['/'], mounts: [], ancestry: new Set([`${module.file.record.path}:${receiver}`]) });
    }
    if (compositionLimitReached) break;
  }
  let queueIndex = 0;
  while (queueIndex < queue.length && !compositionLimitReached) {
    const context = queue[queueIndex++]!;
    for (const local of context.module.routes.filter((route) => route.receiver === context.receiver)) {
      if (local.uncertainty) {
        const uncertaintyBases = local.route
          ? context.bases.map((base) => joinedPath(base, local.route!.display))
          : context.bases;
        addServerUncertainty(
          local,
          local.method,
          local.uncertainty.message,
          uncertaintyBases,
          local.route ? 'exact' : 'prefix'
        );
        continue;
      }
      if (!local.route) continue;
      for (const base of context.bases) {
        const composed = parsePathContract(joinedPath(base, local.route.display), false);
        if (!composed) continue;
        if (routes.length >= MAX_COMPOSED_SERVER_ROUTES) {
          noteCompositionLimit(local, `${MAX_COMPOSED_SERVER_ROUTES}-route limit`);
          break;
        }
        routes.push({ ...local, route: composed, mountAnchors: context.mounts });
      }
      if (compositionLimitReached) break;
    }
    if (compositionLimitReached) break;
    for (const mount of context.module.mounts.filter((candidate) => candidate.receiver === context.receiver)) {
      let targets: Array<{ module: ServerModule; receiver: string }> = [];
      let unresolvedTarget = false;
      if (mount.target.kind === 'local-router') {
        targets = [{ module: context.module, receiver: mount.target.receiver }];
      } else if (mount.target.kind === 'imported-router') {
        const binding = mount.target.binding;
        const targetModule = binding.targetPath ? serverModules.get(binding.targetPath) : undefined;
        const exported = targetModule?.exportedRouters.get(binding.exportName);
        if (binding.resolution === 'resolved' && targetModule && exported?.size) {
          targets = [...exported].map((receiver) => ({ module: targetModule, receiver }));
        } else if (binding.resolution === 'resolved' && targetModule) {
          const passThrough = targetModule.exportedPassThroughMiddleware.has(binding.exportName);
          unresolvedTarget = !passThrough && (
            mount.prefix.state !== 'root' || targetModule.routerReceivers.size > 0 ||
            binding.exportName === '*' || /(?:route|router)/iu.test(binding.localName)
          );
        } else {
          unresolvedTarget = mount.prefix.state !== 'root' || /(?:route|router)/iu.test(binding.localName);
        }
      } else if (mount.target.routeLike) {
        unresolvedTarget = true;
      }

      const mountedBases = mount.prefix.state === 'literal'
        ? [...new Set(context.bases.map((base) => joinedPath(base, mount.prefix.state === 'literal' ? mount.prefix.route.display : '/')))].sort(compareCanonicalText)
        : [...context.bases];
      if (unresolvedTarget) {
        addServerUncertainty(
          mount,
          'ANY',
          mount.target.kind === 'unsupported'
            ? 'An Express router mount target uses an unsupported expression, so matching client requests remain unknown.'
            : 'An Express router mount target could not be resolved to a supported exported router, so matching client requests remain unknown.',
          mountedBases
        );
        continue;
      }
      if (!targets.length) continue;
      if (mount.prefix.state === 'dynamic') {
        addServerUncertainty(
          mount,
          'ANY',
          'An Express router mount uses a dynamic or unsupported path, so matching client requests remain unknown.',
          context.bases
        );
        continue;
      }
      for (const target of targets) {
        const key = `${target.module.file.record.path}:${target.receiver}`;
        if (context.ancestry.has(key)) {
          addServerUncertainty(
            mount,
            'ANY',
            'An Express router mount cycle prevents complete static route composition.',
            mountedBases
          );
          continue;
        }
        const traversalKey = contextKey(target.module, target.receiver, mountedBases);
        if (visitedContexts.has(traversalKey)) continue;
        if (visitedContexts.size >= MAX_ROUTE_COMPOSITION_CONTEXTS) {
          noteCompositionLimit(mount, `${MAX_ROUTE_COMPOSITION_CONTEXTS}-context limit`);
          break;
        }
        visitedContexts.add(traversalKey);
        queue.push({
          module: target.module,
          receiver: target.receiver,
          bases: mountedBases,
          mounts: [...context.mounts, mount],
          ancestry: new Set([...context.ancestry, key])
        });
      }
    }
  }

  for (const { file, sourceFile } of parsed) {
    const { axiosReceivers, fetchReceivers } = collectClientBindings(sourceFile, file.record.path, relationships, facadeModules);
    const makeAnchor = (node: ts.Node): SourceAnchor => ({ file, sourceFile, node });
    function addClient(
      node: ts.Node,
      clientKind: ClientCall['clientKind'],
      methodValue: string | undefined,
      routeValue: string | undefined,
      dynamicMethod: boolean,
      dynamicBase = false,
      basePath?: string,
      compareRelativeSuffix = false
    ): void {
      if (dynamicMethod || !methodValue) {
        diagnostics.push(diagnostic('API_CONTRACT_DYNAMIC_CLIENT_METHOD', 'info', 'A client request uses a dynamic or unsupported HTTP method, so Atlas did not compare it with literal server routes.', makeAnchor(node), 'dynamic-client-method'));
        return;
      }
      if (dynamicBase) {
        diagnostics.push(diagnostic(
          'API_CONTRACT_DYNAMIC_CLIENT_BASE',
          'info',
          compareRelativeSuffix && clientKind === 'axios-facade'
            ? 'An imported axios facade uses a dynamic base URL; Atlas compared its literal relative path only as a suffix of composed local routes.'
            : 'An axios client uses a dynamic or non-local base URL, so Atlas did not infer a server-route mismatch.',
          makeAnchor(node),
          'dynamic-axios-base-url'
        ));
        if (!compareRelativeSuffix || clientKind !== 'axios-facade') return;
      }
      if (routeValue === undefined) {
        diagnostics.push(diagnostic('API_CONTRACT_DYNAMIC_CLIENT_ROUTE', 'info', 'A client request uses a dynamic URL, so Atlas did not infer a server-route mismatch.', makeAnchor(node), 'dynamic-client-route'));
        return;
      }
      const method = normalizeMethod(methodValue);
      const rawRoute = parsePathContract(routeValue, true);
      const combined = rawRoute ? parsePathContract(joinedPath(basePath, rawRoute.display), true) : undefined;
      if (!method || !combined) {
        diagnostics.push(diagnostic(
          !method ? 'API_CONTRACT_DYNAMIC_CLIENT_METHOD' : 'API_CONTRACT_NON_LOCAL_CLIENT_ROUTE',
          'info',
          !method ? 'A client request uses a dynamic or unsupported HTTP method, so Atlas did not compare it with literal server routes.' : 'A client request uses a non-local or unsupported literal URL, so Atlas did not compare it with local server routes.',
          makeAnchor(node),
          !method ? 'unsupported-client-method' : 'non-local-or-unsupported-client-url'
        ));
        return;
      }
      clients.push({
        ...makeAnchor(node),
        clientKind,
        method,
        route: combined,
        dynamicBaseSuffix: dynamicBase && compareRelativeSuffix
      });
    }

    function inspectClientCall(node: ts.CallExpression): void {
      if (ts.isIdentifier(node.expression) && fetchReceivers.has(node.expression.text)) {
        const options = node.arguments[1];
        const method = options === undefined ? { state: 'literal', value: 'GET' } as LiteralProperty : literalObjectProperty(options, 'method');
        addClient(node, 'fetch', method.state === 'absent' ? 'GET' : method.value, literalText(node.arguments[0]), method.state === 'dynamic');
        return;
      }
      if (
        ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'fetch' &&
        ts.isIdentifier(node.expression.expression) && ['window', 'globalThis'].includes(node.expression.expression.text)
      ) {
        const options = node.arguments[1];
        const method = options === undefined ? { state: 'literal', value: 'GET' } as LiteralProperty : literalObjectProperty(options, 'method');
        addClient(node, 'fetch', method.state === 'absent' ? 'GET' : method.value, literalText(node.arguments[0]), method.state === 'dynamic');
        return;
      }
      if (ts.isIdentifier(node.expression) && axiosReceivers.has(node.expression.text)) {
        const receiver = axiosReceivers.get(node.expression.text)!;
        if (receiver.clientKind === 'axios-facade') return;
        const firstArgument = node.arguments[0];
        if (firstArgument && ts.isObjectLiteralExpression(firstArgument)) {
          const method = literalObjectProperty(firstArgument, 'method');
          const url = literalObjectProperty(firstArgument, 'url');
          addClient(node, receiver.clientKind, method.state === 'absent' ? 'GET' : method.value, url.value, method.state === 'dynamic', receiver.dynamicBase, receiver.basePath);
          return;
        }
        const config = node.arguments[1];
        const method = config === undefined ? { state: 'literal', value: 'GET' } as LiteralProperty : literalObjectProperty(config, 'method');
        const route = literalText(node.arguments[0]);
        addClient(node, receiver.clientKind, method.state === 'absent' ? 'GET' : method.value, route, method.state === 'dynamic', receiver.dynamicBase, receiver.basePath);
        return;
      }
      const member = memberName(node.expression);
      const ownerName = identifierName(member.owner);
      if (!ownerName || !axiosReceivers.has(ownerName) || member.dynamic || !member.name) return;
      const receiver = axiosReceivers.get(ownerName)!;
      const helperMethod = normalizeMethod(member.name);
      if (helperMethod) {
        const methodContract = receiver.methods?.get(helperMethod);
        if (receiver.methods && !methodContract) return;
        const effectiveReceiver = methodContract ?? receiver;
        const route = receiver.clientKind === 'axios-facade' ? clientRouteText(node.arguments[0]) : literalText(node.arguments[0]);
        addClient(
          node,
          receiver.clientKind,
          helperMethod,
          route,
          false,
          effectiveReceiver.dynamicBase,
          effectiveReceiver.basePath,
          effectiveReceiver.compareRelativeSuffix
        );
        return;
      }
      if (member.name !== 'request' || receiver.clientKind === 'axios-facade') return;
      const config = node.arguments[0];
      const method = literalObjectProperty(config, 'method');
      const url = literalObjectProperty(config, 'url');
      addClient(node, receiver.clientKind, method.state === 'absent' ? 'GET' : method.value, url.value, method.state === 'dynamic', receiver.dynamicBase, receiver.basePath);
    }
    function visit(node: ts.Node): void {
      if (ts.isCallExpression(node)) inspectClientCall(node);
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }

  const findings: FindingRecord[] = [];
  routes.sort((left, right) => compareCanonicalText(
    canonicalJson({ path: left.file.record.path, location: locationFor(left.sourceFile, left.node), method: left.method, route: left.route.display }),
    canonicalJson({ path: right.file.record.path, location: locationFor(right.sourceFile, right.node), method: right.method, route: right.route.display })
  ));
  clients.sort((left, right) => compareCanonicalText(
    canonicalJson({ path: left.file.record.path, location: locationFor(left.sourceFile, left.node), method: left.method, route: left.route.display }),
    canonicalJson({ path: right.file.record.path, location: locationFor(right.sourceFile, right.node), method: right.method, route: right.route.display })
  ));
  const comparisonBudget: ComparisonBudget = {
    remaining: MAX_API_CONTRACT_COMPARISON_STATES,
    remainingCharacters: MAX_API_CONTRACT_COMPARISON_CHARACTERS
  };
  let comparisonLimitClient: ClientCall | undefined;
  for (const client of clients) {
    const matchingPaths: ServerRoute[] = [];
    for (const route of routes) {
      const compatible = compatibleClientRoute(route.route, client, comparisonBudget);
      if (compatible === undefined) {
        comparisonLimitClient = client;
        break;
      }
      if (compatible) matchingPaths.push(route);
    }
    if (comparisonLimitClient) break;
    if (matchingPaths.some((route) => compatibleMethod(route.method, client.method))) continue;
    let coveredByUncertainty = false;
    for (const candidate of uncertainties) {
      const covered = uncertaintyCouldCover(candidate, client, comparisonBudget);
      if (covered === undefined) {
        comparisonLimitClient = client;
        break;
      }
      if (covered) {
        coveredByUncertainty = true;
        break;
      }
    }
    if (comparisonLimitClient) break;
    if (coveredByUncertainty) {
      diagnostics.push(diagnostic(
        'API_CONTRACT_COMPARISON_UNCERTAIN',
        'info',
        `Dynamic server routing may cover ${client.method} ${client.route.display}; Atlas did not emit a mismatch candidate.`,
        client,
        'literal-client-route-with-dynamic-server-coverage',
        { method: client.method, route: client.route.display }
      ));
      continue;
    }
    const methodMismatch = matchingPaths.length > 0;
    const ruleId = methodMismatch ? 'contract/api-client-method-mismatch-v1' : 'contract/api-client-route-missing-v1';
    const relatedPaths = [...new Set(matchingPaths.flatMap((route) => [
      route.file.record.path,
      ...route.mountAnchors.map((mount) => mount.file.record.path)
    ]))].sort(compareCanonicalText);
    const methods = [...new Set(matchingPaths.map((route) => route.method))].sort(compareCanonicalText);
    const composedSignal = 'complete-literal-express-mount-composition';
    const dynamicBaseSignals = client.dynamicBaseSuffix ? ['dynamic-client-base-suffix-comparison'] : [];
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: findingId(ruleId, client),
      category: 'contract-mismatch',
      ruleId,
      status: 'candidate',
      severity: 'medium',
      confidence: client.dynamicBaseSuffix ? 'low' : 'medium',
      title: methodMismatch
        ? `${client.dynamicBaseSuffix ? 'Relative API' : 'Literal API'} method mismatch for ${client.method} ${client.route.display}`
        : `No compatible composed server route${client.dynamicBaseSuffix ? ' suffix' : ''} for ${client.method} ${client.route.display}`,
      description: methodMismatch
        ? `A ${client.clientKind} call uses ${client.method} ${client.route.display}, while compatible composed Express routes were observed only for ${methods.join(', ')}.${client.dynamicBaseSuffix ? ' Its dynamic base was compared only as a relative suffix; runtime routing remains unverified.' : ''}`
        : `A ${client.clientKind} call uses ${client.method} ${client.route.display}, but no compatible route was observed through the supported literal Express mount graph.${client.dynamicBaseSuffix ? ' Its dynamic base was compared only as a relative suffix; this is a conservative local-contract candidate, not a runtime reachability claim.' : ''}`,
      path: client.file.record.path,
      relatedPaths,
      signals: methodMismatch
        ? ['literal-client-http-call', composedSignal, 'compatible-server-path-with-different-method', ...dynamicBaseSignals, ...(client.clientKind === 'axios-facade' ? ['resolved-local-http-client-facade'] : [])]
        : ['literal-client-http-call', composedSignal, 'no-compatible-composed-server-route', ...dynamicBaseSignals, ...(client.clientKind === 'axios-facade' ? ['resolved-local-http-client-facade'] : [])],
      evidence: [
        evidence(client, 'typescript-ast-literal-client-route'),
        ...matchingPaths.flatMap((route) => [
          evidence(route, 'typescript-ast-literal-server-route'),
          ...route.mountAnchors.map((mount) => evidence(mount, 'typescript-ast-resolved-express-router-mount'))
        ])
      ],
      nextValidation: client.dynamicBaseSuffix
        ? 'Resolve the facade base URL for the deployed environment, then confirm framework registration, router mounts, generated routes, proxies, and runtime routing before treating this candidate as a defect.'
        : 'Confirm framework registration, router mounts, base paths, generated routes, proxies, and runtime routing before treating this candidate as a defect.'
    });
  }
  if (comparisonLimitClient) {
    findings.length = 0;
    diagnostics.push(diagnostic(
      'API_CONTRACT_COMPARISON_LIMIT',
      'warning',
      `API client/server comparison exceeded the ${MAX_API_CONTRACT_COMPARISON_STATES}-state limit; mismatch findings were suppressed because comparison was incomplete.`,
      comparisonLimitClient,
      'api-contract-comparison-resource-limit',
      { limit: MAX_API_CONTRACT_COMPARISON_STATES }
    ));
  }

  const deduplicatedFindings = [...new Map(findings.map((finding) => [finding.id, finding])).values()];
  const deduplicatedDiagnostics = [...new Map(diagnostics.map((entry) => [entry.id, entry])).values()];
  deduplicatedFindings.sort((left, right) => compareCanonicalText(left.id, right.id));
  deduplicatedDiagnostics.sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings: deduplicatedFindings, diagnostics: deduplicatedDiagnostics };
}
