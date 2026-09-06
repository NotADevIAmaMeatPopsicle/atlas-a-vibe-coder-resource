import path from 'node:path';
import ts from 'typescript';
import type {
  AnalysisFile,
  DiagnosticRecord,
  EvidenceReference,
  FindingRecord,
  RelationshipRecord,
  ResolvedProfile,
  SourceLocation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { isExpectedFixtureUnresolvedImport } from '../profile-matching.js';
import { boundedTypeScriptDiagnosticMessage, parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';
import { matchesAnyGlob } from '../util/paths.js';

export const UNUSED_EXPORT_ANALYSIS_VERSION = '1.0.1';

const PRODUCER = 'atlas/unused-exports';
const PARSED_LANGUAGES = new Set(['javascript', 'javascript-jsx', 'typescript', 'typescript-tsx']);

interface Anchor {
  file: AnalysisFile;
  location: SourceLocation;
}

interface ExportFact {
  symbol: string;
  anchors: Anchor[];
}

interface ModuleFacts {
  file: AnalysisFile;
  sourceFile: ts.SourceFile;
  exports: Map<string, ExportFact>;
  uncertainOwnExports: boolean;
}

interface PackageBoundary extends Anchor {
  root: string;
  privatePackage: boolean;
  valid: boolean;
}

function scriptKind(filePath: string): ts.ScriptKind {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (lower.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (lower.endsWith('.ts') || lower.endsWith('.mts') || lower.endsWith('.cts')) return ts.ScriptKind.TS;
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

function anchor(file: AnalysisFile, sourceFile: ts.SourceFile, node: ts.Node): Anchor {
  return { file, location: locationFor(sourceFile, node) };
}

function anchorAtOffset(file: AnalysisFile, sourceFile: ts.SourceFile, offset: number): Anchor {
  const safeOffset = Math.max(0, Math.min(offset, sourceFile.text.length));
  const point = sourceFile.getLineAndCharacterOfPosition(safeOffset);
  return {
    file,
    location: {
      line: point.line + 1,
      column: point.character + 1,
      endLine: point.line + 1,
      endColumn: point.character + 1
    }
  };
}

function id(prefix: 'finding' | 'diagnostic', material: unknown): string {
  return `${prefix}:${sha256(canonicalJson(material)).slice(0, 24)}`;
}

function evidence(value: Anchor, basis: string): EvidenceReference {
  return {
    level: 1,
    producer: PRODUCER,
    producerVersion: UNUSED_EXPORT_ANALYSIS_VERSION,
    basis,
    path: value.file.record.path,
    line: value.location.line,
    column: value.location.column,
    recordIds: [value.file.record.id]
  };
}

function diagnostic(
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  value: Anchor,
  basis: string,
  material: unknown
): DiagnosticRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: id('diagnostic', {
      code,
      path: value.file.record.path,
      line: value.location.line,
      column: value.location.column,
      material
    }),
    code,
    severity,
    message,
    path: value.file.record.path,
    location: value.location,
    evidence: evidence(value, basis)
  };
}

function modifiersInclude(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return Boolean(ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === kind));
}

function namedDeclaration(node: ts.Statement): { name: ts.Identifier; exported: boolean; defaulted: boolean } | undefined {
  if (
    ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) ||
    ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node)
  ) {
    if (!node.name || !ts.isIdentifier(node.name)) return undefined;
    return {
      name: node.name,
      exported: modifiersInclude(node, ts.SyntaxKind.ExportKeyword),
      defaulted: modifiersInclude(node, ts.SyntaxKind.DefaultKeyword)
    };
  }
  return undefined;
}

function relationKey(fromPath: string, type: RelationshipRecord['type'], specifier: string): string {
  return `${fromPath}\0${type}\0${specifier.normalize('NFC')}`;
}

function rootContains(root: string, filePath: string): boolean {
  return root === '.' || filePath === root || filePath.startsWith(`${root}/`);
}

function packageBoundaries(files: AnalysisFile[], diagnostics: DiagnosticRecord[]): PackageBoundary[] {
  const result: PackageBoundary[] = [];
  for (const file of files) {
    if (path.posix.basename(file.record.path).toLowerCase() !== 'package.json') continue;
    const source = file.content.toString('utf8');
    const root = path.posix.dirname(file.record.path);
    const normalizedRoot = root === '' ? '.' : root;
    const parsedSource = parseBoundedTypeScript(file.record.path, source, ts.ScriptKind.JSON);
    if (parsedSource.state === 'rejected') {
      const boundaryAnchor: Anchor = {
        file,
        location: { line: 1, column: 1, endLine: 1, endColumn: 1 }
      };
      diagnostics.push(diagnostic(
        'CLEANUP_PACKAGE_BOUNDARY_UNCERTAIN',
        'warning',
        boundedTypeScriptDiagnosticMessage(parsedSource.reason),
        boundaryAnchor,
        'typescript-ast-resource-limit',
        { packagePath: file.record.path, reason: parsedSource.reason }
      ));
      result.push({ ...boundaryAnchor, root: normalizedRoot, privatePackage: false, valid: false });
      continue;
    }
    const sourceFile = parsedSource.sourceFile as ts.JsonSourceFile;
    const parseDiagnostics = (sourceFile as ts.JsonSourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    const statement = sourceFile.statements[0];
    const object = statement && ts.isExpressionStatement(statement) && ts.isObjectLiteralExpression(statement.expression)
      ? statement.expression
      : undefined;
    let strictJson = true;
    try {
      JSON.parse(source);
    } catch {
      strictJson = false;
    }
    const privateProperties = object?.properties.filter((property): property is ts.PropertyAssignment => {
      if (!ts.isPropertyAssignment(property)) return false;
      const name = property.name;
      return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === 'private';
    }) ?? [];
    const valid = strictJson && parseDiagnostics.length === 0 && Boolean(object) && privateProperties.length <= 1;
    let privatePackage = false;
    const privateProperty = privateProperties[0];
    if (valid && privateProperty) privatePackage = privateProperty.initializer.kind === ts.SyntaxKind.TrueKeyword;
    const boundaryAnchor = privateProperty
      ? anchor(file, sourceFile, privateProperty.name)
      : anchorAtOffset(file, sourceFile, parseDiagnostics[0]?.start ?? 0);
    if (!valid) {
      diagnostics.push(diagnostic(
        'CLEANUP_PACKAGE_BOUNDARY_UNCERTAIN',
        'warning',
        'A package manifest could not be parsed; unused-export claims inside that package boundary are suppressed.',
        boundaryAnchor,
        'invalid-package-manifest',
        { packagePath: file.record.path }
      ));
    }
    result.push({ ...boundaryAnchor, root: normalizedRoot, privatePackage, valid });
  }
  return result.sort((left, right) => right.root.length - left.root.length || compareCanonicalText(left.root, right.root));
}

function closestPackage(filePath: string, boundaries: PackageBoundary[]): PackageBoundary | undefined {
  return boundaries.find((boundary) => rootContains(boundary.root, filePath));
}

function generatedOrDeclarationPath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return /(?:^|\/)(?:dist|build|generated|gen|vendor)(?:\/|$)/u.test(lower) ||
    /\.d\.(?:ts|mts|cts)$/u.test(lower) || /(?:^|[._-])generated(?:[._-]|$)/u.test(path.posix.basename(lower));
}

export function detectUnusedExportCandidates(
  files: AnalysisFile[],
  relationships: RelationshipRecord[],
  profile: ResolvedProfile
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const diagnostics: DiagnosticRecord[] = [];
  const orderedFiles = [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  const jsFiles = orderedFiles.filter((file) => PARSED_LANGUAGES.has(file.record.language));
  const boundaries = packageBoundaries(orderedFiles, diagnostics);
  const factsByPath = new Map<string, ModuleFacts>();
  const consumedByTarget = new Map<string, Set<string>>();
  const uncertainTargets = new Set<string>();
  const uncertainScopes = new Set<string>();
  const unresolvedSymbolsByScope = new Map<string, Set<string>>();
  const matchedRelationshipKeys = new Set<string>();

  function expectedFixtureRelationship(relationship: RelationshipRecord): boolean {
    return relationship.resolution === 'unresolved-internal' &&
      isExpectedFixtureUnresolvedImport(profile, relationship.fromPath, relationship.specifier);
  }

  function scopeFor(filePath: string): string {
    void filePath;
    // package.json is an API-publication signal, not a runtime sandbox. A
    // computed import may legally traverse package directories, so target-wide
    // scope is the smallest sound scope for unknown-target consumers.
    return '.';
  }

  function markScopeUncertain(filePath: string): void {
    uncertainScopes.add(scopeFor(filePath));
  }

  function recordUnresolvedSymbol(filePath: string, symbolValue: string): void {
    const scope = scopeFor(filePath);
    const symbols = unresolvedSymbolsByScope.get(scope) ?? new Set<string>();
    symbols.add(symbolValue.normalize('NFC'));
    unresolvedSymbolsByScope.set(scope, symbols);
  }

  const relationshipsByKey = new Map<string, RelationshipRecord[]>();
  for (const relationship of relationships) {
    const key = relationKey(relationship.fromPath, relationship.type, relationship.specifier);
    const values = relationshipsByKey.get(key) ?? [];
    values.push(relationship);
    relationshipsByKey.set(key, values);
    if (
      (relationship.resolution === 'unsupported' || relationship.resolution === 'unresolved-internal') &&
      !expectedFixtureRelationship(relationship)
    ) {
      if (relationship.resolution === 'unsupported') markScopeUncertain(relationship.fromPath);
      const owner = orderedFiles.find((file) => file.record.path === relationship.fromPath);
      if (owner) {
        const value: Anchor = { file: owner, location: relationship.location };
        diagnostics.push(diagnostic(
          'CLEANUP_UNUSED_EXPORT_GRAPH_UNCERTAIN',
          'warning',
          relationship.resolution === 'unsupported'
            ? 'A non-literal module reference has unknown target and symbol scope; Atlas suppresses unused-export claims across the target.'
            : 'An unresolved literal module reference is retained as target-wide symbol-scoped counter-evidence.',
          value,
          'unsupported-or-unresolved-module-relationship',
          { relationshipId: relationship.id }
        ));
      }
    }
  }

  function targetFor(fromPath: string, type: RelationshipRecord['type'], specifier: string): string | undefined {
    const key = relationKey(fromPath, type, specifier);
    matchedRelationshipKeys.add(key);
    const related = (relationshipsByKey.get(key) ?? []).filter((relationship) =>
      !expectedFixtureRelationship(relationship)
    );
    const targets = [...new Set(related
      .filter((relationship) => relationship.resolution === 'resolved' && relationship.toPath)
      .map((relationship) => relationship.toPath!))];
    const states = new Set(related.map((relationship) => relationship.resolution));
    if (targets.length === 1 && states.size === 1) return targets[0];
    if (targets.length > 1 || states.size > 1) markScopeUncertain(fromPath);
    return undefined;
  }

  function unresolvedRelationship(fromPath: string, type: RelationshipRecord['type'], specifier: string): boolean {
    return (relationshipsByKey.get(relationKey(fromPath, type, specifier)) ?? [])
      .some((relationship) =>
        relationship.resolution === 'unresolved-internal' && !expectedFixtureRelationship(relationship)
      );
  }

  function consume(targetPath: string, symbol: string): void {
    const values = consumedByTarget.get(targetPath) ?? new Set<string>();
    values.add(symbol.normalize('NFC'));
    consumedByTarget.set(targetPath, values);
  }

  function suppressTarget(targetPath: string, value: Anchor, code: string, message: string, material: unknown): void {
    uncertainTargets.add(targetPath);
    diagnostics.push(diagnostic(code, 'warning', message, value, 'ambiguous-export-consumer-semantics', material));
  }

  for (const file of jsFiles) {
    const sourceText = file.content.toString('utf8');
    const parsedSource = parseBoundedTypeScript(file.record.path, sourceText, scriptKind(file.record.path));
    if (parsedSource.state === 'rejected') {
      markScopeUncertain(file.record.path);
      diagnostics.push(diagnostic(
        'CLEANUP_UNUSED_EXPORT_PARSE_UNCERTAIN',
        'warning',
        boundedTypeScriptDiagnosticMessage(parsedSource.reason),
        { file, location: { line: 1, column: 1, endLine: 1, endColumn: 1 } },
        'typescript-ast-resource-limit',
        { path: file.record.path, reason: parsedSource.reason }
      ));
      continue;
    }
    const sourceFile = parsedSource.sourceFile;
    const moduleFacts: ModuleFacts = { file, sourceFile, exports: new Map(), uncertainOwnExports: false };
    factsByPath.set(file.record.path, moduleFacts);
    const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (parseDiagnostics.length) {
      markScopeUncertain(file.record.path);
      const first = parseDiagnostics[0]!;
      const start = first.start ?? 0;
      diagnostics.push(diagnostic(
        'CLEANUP_UNUSED_EXPORT_PARSE_UNCERTAIN',
        'warning',
        'A JS/TS parse error prevents closed-world unused-export claims for this snapshot.',
        anchorAtOffset(file, sourceFile, start),
        'typescript-parse-diagnostic',
        { path: file.record.path, start }
      ));
      continue;
    }

    function addExport(symbolValue: string, node: ts.Node): void {
      const symbol = symbolValue.normalize('NFC');
      if (symbol === 'default') return;
      const existing = moduleFacts.exports.get(symbol) ?? { symbol, anchors: [] };
      existing.anchors.push(anchor(file, sourceFile, node));
      moduleFacts.exports.set(symbol, existing);
    }

    function markOwnExportsUncertain(node: ts.Node, reason: string): void {
      if (moduleFacts.uncertainOwnExports) return;
      moduleFacts.uncertainOwnExports = true;
      diagnostics.push(diagnostic(
        'CLEANUP_UNUSED_EXPORT_MODULE_SURFACE_UNCERTAIN',
        'warning',
        'A default, CommonJS, or reflective export construct makes this module surface incomplete; symbol cleanup claims for it are suppressed.',
        anchor(file, sourceFile, node),
        'unsupported-module-export-surface',
        { path: file.record.path, reason }
      ));
    }

    for (const statement of sourceFile.statements) {
      const declaration = namedDeclaration(statement);
      if (declaration?.exported && !declaration.defaulted) addExport(declaration.name.text, declaration.name);
      if (ts.isVariableStatement(statement) && modifiersInclude(statement, ts.SyntaxKind.ExportKeyword) && !modifiersInclude(statement, ts.SyntaxKind.DefaultKeyword)) {
        for (const variable of statement.declarationList.declarations) {
          if (ts.isIdentifier(variable.name)) addExport(variable.name.text, variable.name);
          else {
            markOwnExportsUncertain(variable.name, 'exported-binding-pattern');
            diagnostics.push(diagnostic(
              'CLEANUP_UNUSED_EXPORT_DECLARATION_UNCERTAIN',
              'info',
              'An exported destructuring declaration was not assigned symbol-level cleanup claims.',
              anchor(file, sourceFile, variable.name),
              'unsupported-exported-binding-pattern',
              { path: file.record.path }
            ));
          }
        }
      }
      if (ts.isExportDeclaration(statement)) {
        const specifier = statement.moduleSpecifier && ts.isStringLiteralLike(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : undefined;
        if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
          for (const element of statement.exportClause.elements) {
            addExport(element.name.text, element.name);
            if (specifier) {
              const target = targetFor(file.record.path, 'export-from', specifier);
              if (target) consume(target, element.propertyName?.text ?? element.name.text);
              else if (unresolvedRelationship(file.record.path, 'export-from', specifier)) {
                recordUnresolvedSymbol(file.record.path, element.propertyName?.text ?? element.name.text);
              }
            }
          }
        } else if (specifier) {
          const target = targetFor(file.record.path, 'export-from', specifier);
          if (target) suppressTarget(
            target,
            anchor(file, sourceFile, statement),
            'CLEANUP_UNUSED_EXPORT_STAR_REEXPORT',
            'A star or namespace re-export can expose any target symbol; unused-export claims for that target are suppressed.',
            { fromPath: file.record.path, target }
          );
          else if (unresolvedRelationship(file.record.path, 'export-from', specifier)) markScopeUncertain(file.record.path);
        }
      }
      if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
        const specifier = statement.moduleSpecifier.text;
        const target = targetFor(file.record.path, 'static-import', specifier);
        if (!statement.importClause) continue;
        const bindings = statement.importClause.namedBindings;
        if (target && bindings && ts.isNamespaceImport(bindings)) {
          suppressTarget(
            target,
            anchor(file, sourceFile, bindings),
            'CLEANUP_UNUSED_EXPORT_NAMESPACE_IMPORT',
            'A namespace import can access target symbols through computed properties; unused-export claims for that target are suppressed.',
            { fromPath: file.record.path, target }
          );
        } else if (target && bindings && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) consume(target, element.propertyName?.text ?? element.name.text);
        } else if (!target && unresolvedRelationship(file.record.path, 'static-import', specifier)) {
          if (bindings && ts.isNamespaceImport(bindings)) markScopeUncertain(file.record.path);
          else if (bindings && ts.isNamedImports(bindings)) {
            for (const element of bindings.elements) recordUnresolvedSymbol(file.record.path, element.propertyName?.text ?? element.name.text);
          }
        }
      }
      if (ts.isImportEqualsDeclaration(statement) && ts.isExternalModuleReference(statement.moduleReference)) {
        const expression = statement.moduleReference.expression;
        if (expression && ts.isStringLiteralLike(expression)) {
          const target = targetFor(file.record.path, 'static-import', expression.text);
          if (target) suppressTarget(
            target,
            anchor(file, sourceFile, statement),
            'CLEANUP_UNUSED_EXPORT_IMPORT_EQUALS',
            'An import-equals binding exposes the complete target module; unused-export claims for that target are suppressed.',
            { fromPath: file.record.path, target }
          );
          else if (unresolvedRelationship(file.record.path, 'static-import', expression.text)) markScopeUncertain(file.record.path);
        }
      }
    }

    function visit(node: ts.Node): void {
      if (ts.isExportAssignment(node)) markOwnExportsUncertain(node, 'export-assignment');
      if (
        ts.isIdentifier(node) && node.text === 'exports' ||
        ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'module' && node.name.text === 'exports'
      ) markOwnExportsUncertain(node, 'commonjs-export-surface');
      if (ts.isImportTypeNode(node)) {
        markScopeUncertain(file.record.path);
        diagnostics.push(diagnostic(
          'CLEANUP_UNUSED_EXPORT_IMPORT_TYPE_UNCERTAIN',
          'warning',
          'A TypeScript import-type expression is outside the current relationship model; unused-export claims are suppressed.',
          anchor(file, sourceFile, node),
          'unsupported-import-type-consumer',
          { path: file.record.path, line: locationFor(sourceFile, node).line }
        ));
      }
      if (ts.isCallExpression(node)) {
        const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
        if (isDynamicImport || isRequire) {
          const argument = node.arguments[0];
          if (argument && ts.isStringLiteralLike(argument)) {
            const relationType = isDynamicImport ? 'dynamic-import' : 'require';
            const target = targetFor(file.record.path, relationType, argument.text);
            if (target) suppressTarget(
              target,
              anchor(file, sourceFile, node),
              isDynamicImport ? 'CLEANUP_UNUSED_EXPORT_DYNAMIC_IMPORT' : 'CLEANUP_UNUSED_EXPORT_COMMONJS_CONSUMER',
              'A whole-module dynamic/CommonJS consumer can access any exported symbol; unused-export claims for that target are suppressed.',
              { fromPath: file.record.path, target, relationType }
            );
          } else {
            markScopeUncertain(file.record.path);
          }
        }
        const calleeText = node.expression.getText(sourceFile);
        if (
          calleeText === 'eval' || calleeText === 'Function' || calleeText === 'require.context' ||
          calleeText === 'jest.mock' || calleeText === 'vi.mock' || calleeText.endsWith('.glob')
        ) {
          markScopeUncertain(file.record.path);
          diagnostics.push(diagnostic(
            'CLEANUP_UNUSED_EXPORT_REFLECTION_UNCERTAIN',
            'warning',
            'Reflection, module mocking, or glob loading prevents closed-world unused-export claims for this snapshot.',
            anchor(file, sourceFile, node.expression),
            'reflective-or-framework-module-loading',
            { path: file.record.path, line: locationFor(sourceFile, node).line }
          ));
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }

  for (const relationship of relationships) {
    if (relationship.type !== 'static-import' && relationship.type !== 'export-from') continue;
    if (expectedFixtureRelationship(relationship)) continue;
    const key = relationKey(relationship.fromPath, relationship.type, relationship.specifier);
    if (matchedRelationshipKeys.has(key)) continue;
    if (relationship.resolution === 'unresolved-internal') {
      markScopeUncertain(relationship.fromPath);
      continue;
    }
    if (relationship.resolution !== 'resolved' || !relationship.toPath) continue;
    uncertainTargets.add(relationship.toPath);
    const owner = orderedFiles.find((file) => file.record.path === relationship.fromPath);
    if (!owner) continue;
    diagnostics.push(diagnostic(
      'CLEANUP_UNUSED_EXPORT_RELATIONSHIP_UNMATCHED',
      'warning',
      'A resolved relationship had no supported symbol-level syntax match; unused-export claims for its target are suppressed.',
      { file: owner, location: relationship.location },
      'relationship-to-symbol-consumer-mismatch',
      { relationshipId: relationship.id, target: relationship.toPath }
    ));
  }

  const inboundByTarget = new Map<string, RelationshipRecord[]>();
  for (const relationship of relationships) {
    if (relationship.resolution !== 'resolved' || !relationship.toPath || relationship.fromPath === relationship.toPath) continue;
    if (relationship.type !== 'static-import' && relationship.type !== 'export-from') continue;
    const values = inboundByTarget.get(relationship.toPath) ?? [];
    values.push(relationship);
    inboundByTarget.set(relationship.toPath, values);
  }

  const findings: FindingRecord[] = [];
  for (const moduleFacts of factsByPath.values()) {
      const file = moduleFacts.file;
      if (!moduleFacts.exports.size || moduleFacts.uncertainOwnExports || uncertainTargets.has(file.record.path)) continue;
      if (file.record.kind !== 'source' || generatedOrDeclarationPath(file.record.path)) continue;
      if (matchesAnyGlob(file.record.path, profile.entrypoints) || matchesAnyGlob(file.record.path, profile.deadCodeExemptions)) continue;
      const inbound = (inboundByTarget.get(file.record.path) ?? [])
        .sort((left, right) => compareCanonicalText(left.id, right.id));
      if (!inbound.length) continue;
      const boundary = closestPackage(file.record.path, boundaries);
      if (!boundary?.valid || !boundary.privatePackage) {
        const firstExport = [...moduleFacts.exports.values()][0]!.anchors[0]!;
        diagnostics.push(diagnostic(
          'CLEANUP_UNUSED_EXPORT_BOUNDARY_UNCERTAIN',
          'info',
          'Unused-export claims require a nearest literal package.json with private: true; this module was suppressed.',
          firstExport,
          'external-package-consumer-boundary-unknown',
          { path: file.record.path, packagePath: boundary?.file.record.path ?? null }
        ));
        continue;
      }
      if ([...uncertainScopes].some((scope) => rootContains(scope, file.record.path))) continue;
      const consumed = consumedByTarget.get(file.record.path) ?? new Set<string>();
      for (const exported of moduleFacts.exports.values()) {
        if (consumed.has(exported.symbol)) continue;
        if ([...unresolvedSymbolsByScope].some(([scope, symbols]) =>
          rootContains(scope, file.record.path) && symbols.has(exported.symbol)
        )) continue;
        const exportAnchors = [...exported.anchors].sort((left, right) =>
          left.location.line - right.location.line || left.location.column - right.location.column
        );
        const ruleId = 'dead-code/unused-private-export-surface-v1';
        findings.push({
          schemaVersion: SCHEMA_VERSION,
          id: id('finding', { ruleId, path: file.record.path, symbol: exported.symbol }),
          category: 'dead-code-candidate',
          ruleId,
          status: 'candidate',
          severity: 'info',
          confidence: 'medium',
          title: `Review unused private export: ${exported.symbol}`,
          description: `${file.record.path} exports ${exported.symbol}, but none of its fully parsed, resolved static consumers imports or re-exports that name. The declaration itself may still be used locally; this candidate concerns the export surface only.`,
          path: file.record.path,
          relatedPaths: [...new Set(inbound.map((relationship) => relationship.fromPath))].sort(compareCanonicalText),
          signals: [
            'nearest-package-declares-private-true',
            'module-has-resolved-static-inbound-consumer',
            'no-supported-static-consumer-imports-export-name',
            'dynamic-namespace-commonjs-and-reflective-consumers-absent'
          ],
          evidence: [
            ...exportAnchors.map((value) => evidence(value, 'typescript-export-declaration')),
            evidence(boundary, 'literal-private-package-boundary'),
            ...inbound.map((relationship) => ({
              ...relationship.evidence,
              level: 1 as const,
              producer: PRODUCER,
              producerVersion: UNUSED_EXPORT_ANALYSIS_VERSION,
              basis: 'resolved-static-inbound-consumer',
              recordIds: [relationship.id]
            }))
          ],
          nextValidation: 'Check external workspace consumers, framework reflection, generated code, package scripts, runtime import paths, and whether only the export modifier or the whole declaration is actually redundant.'
        });
      }
  }

  findings.sort((left, right) => compareCanonicalText(left.id, right.id));
  const uniqueDiagnostics = [...new Map(diagnostics.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings, diagnostics: uniqueDiagnostics };
}
