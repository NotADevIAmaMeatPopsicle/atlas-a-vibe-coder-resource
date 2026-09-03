import ts from 'typescript';
import type {
  AnalysisFile,
  DataContractDimension,
  DiagnosticRecord,
  EvidenceReference,
  FindingRecord,
  ModelStorageDataContractFindingSubject,
  SourceLocation
} from '../types.js';
import { SCHEMA_VERSION } from '../types.js';
import { boundedTypeScriptDiagnosticMessage, parseBoundedTypeScript } from '../security/typescript-ast.js';
import { canonicalJson, compareCanonicalText, sha256 } from '../util/canonical.js';

export const DATA_CONTRACT_ANALYSIS_VERSION = '2.2.0';

const PRODUCER = 'atlas/data-contracts';

type TypeFamily = 'text' | 'numeric' | 'boolean' | 'temporal' | 'binary' | 'json' | 'uuid';
type DataContractRuleId =
  | 'contract/data-column-missing-v1'
  | 'contract/data-column-removed-v1'
  | 'contract/data-column-mapping-v1'
  | 'contract/data-type-family-v1'
  | 'contract/data-nullability-v1'
  | 'contract/data-default-v1'
  | 'contract/data-enum-v1';
type SequelizeStorageBasis =
  | 'literal-sequelize-migration-remove-or-rename-column'
  | 'literal-sequelize-migration-column'
  | 'literal-sequelize-migration-create-table'
  | 'literal-sql-table-or-column-declaration';

const DATA_CONTRACT_DIMENSION_BY_RULE = {
  'contract/data-column-missing-v1': 'column-presence',
  'contract/data-column-removed-v1': 'column-presence',
  'contract/data-column-mapping-v1': 'column-mapping',
  'contract/data-type-family-v1': 'type-family',
  'contract/data-nullability-v1': 'nullability',
  'contract/data-default-v1': 'default',
  'contract/data-enum-v1': 'enum-members'
} as const satisfies Record<DataContractRuleId, DataContractDimension>;

function dataContractSubject(
  ruleId: DataContractRuleId,
  table: string,
  column: string,
  model: ModelStorageDataContractFindingSubject['model'],
  storage: ModelStorageDataContractFindingSubject['storage']
): ModelStorageDataContractFindingSubject {
  return {
    kind: 'data-contract',
    table,
    column,
    dimension: DATA_CONTRACT_DIMENSION_BY_RULE[ruleId],
    model,
    storage
  };
}

function sequelizeStorage(storageBasis: SequelizeStorageBasis): ModelStorageDataContractFindingSubject['storage'] {
  return storageBasis === 'literal-sql-table-or-column-declaration' ? 'sql' : 'sequelize-migration';
}

interface Anchor {
  file: AnalysisFile;
  location: SourceLocation;
}

interface PrismaField extends Anchor {
  fieldName: string;
  columnName: string;
  family: TypeFamily;
  nullable: boolean;
}

interface PrismaModel extends Anchor {
  modelName: string;
  tableName: string;
  fields: PrismaField[];
}

interface SqlColumn extends Anchor {
  columnName: string;
  family?: TypeFamily;
  nullable: boolean;
  enumSignature?: string;
}

interface SqlTable {
  tableName: string;
  anchors: Anchor[];
  createAnchors: Anchor[];
  columns: Map<string, SqlColumn[]>;
  uncertainColumns: Set<string>;
  incompleteColumnSet: boolean;
  uncertainTable: boolean;
}

interface SequelizeColumn extends Anchor {
  attributeName: string;
  columnName: string;
  family?: TypeFamily;
  nullable?: boolean;
  defaultSignature?: string;
  enumSignature?: string;
}

interface SequelizeModel extends Anchor {
  modelName: string;
  tableName: string;
  fields: SequelizeColumn[];
}

type MigrationOperationKind = 'create' | 'add' | 'change' | 'remove' | 'rename';

interface MigrationOperation extends Anchor {
  kind: MigrationOperationKind;
  tableName: string;
  columnName?: string;
  replacementName?: string;
  column?: SequelizeColumn;
  columns?: SequelizeColumn[];
  completeColumnSet?: boolean;
  uncertainColumns?: string[];
  sequence: number;
  orderKey?: string;
  conditional?: boolean;
}

interface SequelizeMigrationTable {
  tableName: string;
  anchors: Anchor[];
  createAnchors: Anchor[];
  columns: Map<string, SequelizeColumn>;
  removedColumns: Map<string, Anchor>;
  uncertainColumns: Set<string>;
  completeColumnSet: boolean;
  uncertainTable: boolean;
}

interface SequelizeMigrationResult {
  tables: Map<string, SequelizeMigrationTable>;
  globalUncertainty: boolean;
}

interface ObjectPropertyResult {
  properties: Map<string, ts.ObjectLiteralElementLike[]>;
  dynamic: boolean;
}

interface ParsedColumnDefinition {
  column?: SequelizeColumn;
  uncertain: boolean;
}

interface Token {
  kind: 'word' | 'identifier' | 'string' | 'symbol';
  text: string;
  value: string;
  start: number;
  end: number;
}

interface ParseState {
  diagnostics: DiagnosticRecord[];
  sequelizeLimitationPaths: Set<string>;
}

function lineAndColumn(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  for (let index = 0; index < Math.min(offset, source.length); index += 1) {
    if (source[index] === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

function locationFor(file: AnalysisFile, start: number, end: number): SourceLocation {
  const source = file.content.toString('utf8');
  const beginning = lineAndColumn(source, start);
  const finish = lineAndColumn(source, Math.max(start + 1, end));
  return {
    line: beginning.line,
    column: beginning.column,
    endLine: finish.line,
    endColumn: finish.column
  };
}

function anchorFor(file: AnalysisFile, start: number, end: number): Anchor {
  return { file, location: locationFor(file, start, end) };
}

function evidence(anchor: Anchor, basis: string): EvidenceReference {
  return {
    level: 2,
    producer: PRODUCER,
    producerVersion: DATA_CONTRACT_ANALYSIS_VERSION,
    basis,
    path: anchor.file.record.path,
    line: anchor.location.line,
    column: anchor.location.column,
    recordIds: [anchor.file.record.id]
  };
}

function diagnostic(
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  anchor: Anchor,
  basis: string,
  material: unknown = null
): DiagnosticRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: `diagnostic:${sha256(canonicalJson({
      code,
      path: anchor.file.record.path,
      line: anchor.location.line,
      column: anchor.location.column,
      material
    })).slice(0, 24)}`,
    code,
    severity,
    message,
    path: anchor.file.record.path,
    location: anchor.location,
    evidence: evidence(anchor, basis)
  };
}

const JAVASCRIPT_LANGUAGES = new Set(['javascript', 'javascript-jsx', 'typescript', 'typescript-tsx']);
const DEFAULT_ABSENT_SIGNATURE = sha256('sequelize-default:absent');
const ENUM_ABSENT_SIGNATURE = sha256('sequelize-enum:absent');

function scriptKind(filePath: string): ts.ScriptKind {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (lower.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (lower.endsWith('.ts') || lower.endsWith('.mts') || lower.endsWith('.cts')) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function nodeAnchor(file: AnalysisFile, sourceFile: ts.SourceFile, node: ts.Node): Anchor {
  return anchorFor(file, node.getStart(sourceFile), node.getEnd());
}

function literalPropertyName(name: ts.PropertyName | ts.BindingName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
    return name.text.normalize('NFC');
  }
  return undefined;
}

function inspectObject(node: ts.ObjectLiteralExpression): ObjectPropertyResult {
  const properties = new Map<string, ts.ObjectLiteralElementLike[]>();
  let dynamic = false;
  for (const property of node.properties) {
    if (ts.isSpreadAssignment(property) || !property.name) {
      dynamic = true;
      continue;
    }
    const name = literalPropertyName(property.name);
    if (name === undefined || ts.isComputedPropertyName(property.name)) {
      dynamic = true;
      continue;
    }
    const values = properties.get(name) ?? [];
    values.push(property);
    properties.set(name, values);
  }
  return { properties, dynamic };
}

function uniquePropertyInitializer(
  object: ObjectPropertyResult,
  propertyName: string
): { present: boolean; ambiguous: boolean; initializer?: ts.Expression; node?: ts.ObjectLiteralElementLike } {
  const entries = object.properties.get(propertyName) ?? [];
  if (entries.length === 0) return { present: false, ambiguous: false };
  const node = entries[0]!;
  if (entries.length !== 1 || !ts.isPropertyAssignment(node)) return { present: true, ambiguous: true, node };
  return { present: true, ambiguous: false, initializer: node.initializer, node };
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) || ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) || ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function literalString(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  const value = unwrapExpression(expression);
  return ts.isStringLiteralLike(value) ? value.text.normalize('NFC') : undefined;
}

function literalBoolean(expression: ts.Expression | undefined): boolean | undefined {
  if (!expression) return undefined;
  const value = unwrapExpression(expression);
  if (value.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (value.kind === ts.SyntaxKind.FalseKeyword) return false;
  return undefined;
}

type LiteralValueResult = { ok: true; value: unknown } | { ok: false };

function literalValue(expression: ts.Expression, depth = 0): LiteralValueResult {
  if (depth > 16) return { ok: false };
  const value = unwrapExpression(expression);
  if (ts.isStringLiteralLike(value)) return { ok: true, value: { kind: 'string', value: value.text.normalize('NFC') } };
  if (ts.isNumericLiteral(value)) return { ok: true, value: { kind: 'number', value: value.text } };
  if (value.kind === ts.SyntaxKind.TrueKeyword) return { ok: true, value: { kind: 'boolean', value: true } };
  if (value.kind === ts.SyntaxKind.FalseKeyword) return { ok: true, value: { kind: 'boolean', value: false } };
  if (value.kind === ts.SyntaxKind.NullKeyword) return { ok: true, value: { kind: 'null' } };
  if (
    ts.isPrefixUnaryExpression(value) &&
    (value.operator === ts.SyntaxKind.MinusToken || value.operator === ts.SyntaxKind.PlusToken) &&
    ts.isNumericLiteral(value.operand)
  ) {
    return { ok: true, value: { kind: 'number', value: `${value.operator === ts.SyntaxKind.MinusToken ? '-' : '+'}${value.operand.text}` } };
  }
  if (ts.isArrayLiteralExpression(value)) {
    const items: unknown[] = [];
    for (const element of value.elements) {
      if (ts.isSpreadElement(element) || ts.isOmittedExpression(element)) return { ok: false };
      const item = literalValue(element, depth + 1);
      if (!item.ok) return item;
      items.push(item.value);
    }
    return { ok: true, value: { kind: 'array', items } };
  }
  if (ts.isObjectLiteralExpression(value)) {
    const inspected = inspectObject(value);
    if (inspected.dynamic) return { ok: false };
    const entries: Array<{ name: string; value: unknown }> = [];
    for (const [name, properties] of inspected.properties) {
      if (properties.length !== 1 || !ts.isPropertyAssignment(properties[0]!)) return { ok: false };
      const item = literalValue(properties[0]!.initializer, depth + 1);
      if (!item.ok) return item;
      entries.push({ name, value: item.value });
    }
    entries.sort((left, right) => compareCanonicalText(left.name, right.name));
    return { ok: true, value: { kind: 'object', entries } };
  }
  return { ok: false };
}

function literalValueSignature(expression: ts.Expression): string | undefined {
  const parsed = literalValue(expression);
  return parsed.ok ? sha256(canonicalJson(parsed.value)) : undefined;
}

function memberPath(expression: ts.Expression): string[] | undefined {
  const value = unwrapExpression(expression);
  if (ts.isIdentifier(value)) return [value.text];
  if (ts.isPropertyAccessExpression(value)) {
    const owner = memberPath(value.expression);
    return owner ? [...owner, value.name.text] : undefined;
  }
  return undefined;
}

function enumSignatureFromCall(call: ts.CallExpression): string | undefined {
  let values: ts.Expression[] | undefined;
  if (call.arguments.length === 1) {
    const only = unwrapExpression(call.arguments[0]!);
    if (ts.isArrayLiteralExpression(only)) values = [...only.elements];
    else if (ts.isObjectLiteralExpression(only)) {
      const property = uniquePropertyInitializer(inspectObject(only), 'values');
      const initializer = property.initializer ? unwrapExpression(property.initializer) : undefined;
      if (!property.ambiguous && initializer && ts.isArrayLiteralExpression(initializer)) values = [...initializer.elements];
    }
  }
  if (!values) values = [...call.arguments];
  if (values.length === 0 || values.some((value) => ts.isSpreadElement(value) || !ts.isStringLiteralLike(unwrapExpression(value)))) {
    return undefined;
  }
  const members = values.map((value) => (unwrapExpression(value) as ts.StringLiteralLike).text.normalize('NFC'));
  if (new Set(members).size !== members.length) return undefined;
  members.sort(compareCanonicalText);
  return sha256(canonicalJson({ kind: 'enum-members', members }));
}

function sequelizeType(
  expression: ts.Expression,
  allowedRoots: ReadonlySet<string>
): { family?: TypeFamily; enumSignature?: string; recognized: boolean } {
  const value = unwrapExpression(expression);
  const target = ts.isCallExpression(value) || ts.isNewExpression(value) ? value.expression : value;
  const path = memberPath(target);
  if (!path || path.length < 2 || !allowedRoots.has(path[0]!)) return { recognized: false };
  const supported = path.slice(1).find((part) => [
    'STRING', 'CHAR', 'TEXT', 'CITEXT',
    'INTEGER', 'BIGINT', 'SMALLINT', 'TINYINT', 'MEDIUMINT', 'DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE', 'REAL',
    'BOOLEAN', 'DATE', 'DATEONLY', 'TIME', 'BLOB', 'JSON', 'JSONB', 'UUID', 'ENUM'
  ].includes(part.toUpperCase()));
  if (!supported) return { recognized: false };
  const upper = supported.toUpperCase();
  let family: TypeFamily;
  if (['STRING', 'CHAR', 'TEXT', 'CITEXT', 'ENUM'].includes(upper)) family = 'text';
  else if (['INTEGER', 'BIGINT', 'SMALLINT', 'TINYINT', 'MEDIUMINT', 'DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE', 'REAL'].includes(upper)) family = 'numeric';
  else if (upper === 'BOOLEAN') family = 'boolean';
  else if (['DATE', 'DATEONLY', 'TIME'].includes(upper)) family = 'temporal';
  else if (upper === 'BLOB') family = 'binary';
  else if (['JSON', 'JSONB'].includes(upper)) family = 'json';
  else family = 'uuid';
  if (upper !== 'ENUM') return { family, enumSignature: ENUM_ABSENT_SIGNATURE, recognized: true };
  const enumSignature = ts.isCallExpression(value) ? enumSignatureFromCall(value) : undefined;
  return { family, ...(enumSignature ? { enumSignature } : {}), recognized: true };
}

function findingId(ruleId: string, tableName: string, columnName: string, anchors: Anchor[]): string {
  return `finding:${sha256(canonicalJson({
    ruleId,
    tableName,
    columnName,
    sources: anchors.map((anchor) => anchor.file.record.path).sort(compareCanonicalText)
  })).slice(0, 24)}`;
}

function maskPrismaComments(source: string): string {
  // Split by UTF-16 code unit so every retained index remains compatible with
  // TypeScript/Node string offsets even when an earlier comment contains an
  // astral Unicode character.
  const characters = source.split('');
  let state: 'normal' | 'string' | 'line-comment' | 'block-comment' = 'normal';
  for (let index = 0; index < characters.length; index += 1) {
    const current = characters[index]!;
    const next = characters[index + 1];
    if (state === 'line-comment') {
      if (current === '\n' || current === '\r') state = 'normal';
      else characters[index] = ' ';
      continue;
    }
    if (state === 'block-comment') {
      if (current === '*' && next === '/') {
        characters[index] = ' ';
        characters[index + 1] = ' ';
        index += 1;
        state = 'normal';
      } else if (current !== '\n' && current !== '\r') {
        characters[index] = ' ';
      }
      continue;
    }
    if (state === 'string') {
      if (current === '\\') index += 1;
      else if (current === '"') state = 'normal';
      continue;
    }
    if (current === '"') {
      state = 'string';
    } else if (current === '/' && next === '/') {
      characters[index] = ' ';
      characters[index + 1] = ' ';
      index += 1;
      state = 'line-comment';
    } else if (current === '/' && next === '*') {
      characters[index] = ' ';
      characters[index + 1] = ' ';
      index += 1;
      state = 'block-comment';
    }
  }
  return characters.join('');
}

function maskPrismaStrings(source: string): string {
  const characters = source.split('');
  let inString = false;
  for (let index = 0; index < characters.length; index += 1) {
    const current = characters[index]!;
    if (!inString) {
      if (current === '"') {
        characters[index] = ' ';
        inString = true;
      }
      continue;
    }
    if (current === '\\') {
      characters[index] = ' ';
      if (index + 1 < characters.length) {
        characters[index + 1] = ' ';
        index += 1;
      }
    } else {
      if (current === '"') inString = false;
      if (current !== '\n' && current !== '\r') characters[index] = ' ';
    }
  }
  return characters.join('');
}

function decodePrismaString(value: string): string | undefined {
  try {
    const decoded = JSON.parse(`"${value}"`) as unknown;
    return typeof decoded === 'string' ? decoded.normalize('NFC') : undefined;
  } catch {
    return undefined;
  }
}

function prismaFamily(typeName: string, attributes: string): TypeFamily | undefined {
  const native = attributes.match(/@db\.([A-Za-z][A-Za-z0-9_]*)/u)?.[1]?.toLowerCase();
  if (native === 'uuid') return 'uuid';
  if (native && ['json', 'jsonb'].includes(native)) return 'json';
  if (native && ['bytea', 'blob', 'binary', 'varbinary'].includes(native)) return 'binary';
  if (native && /^(?:date|time|timestamp|datetime)/u.test(native)) return 'temporal';
  if (native && /^(?:char|varchar|text|citext)/u.test(native)) return 'text';
  if (native && /^(?:int|serial|decimal|numeric|real|float|double|money)/u.test(native)) return 'numeric';
  switch (typeName) {
    case 'String': return 'text';
    case 'Int':
    case 'BigInt':
    case 'Float':
    case 'Decimal': return 'numeric';
    case 'Boolean': return 'boolean';
    case 'DateTime': return 'temporal';
    case 'Bytes': return 'binary';
    case 'Json': return 'json';
    default: return undefined;
  }
}

function literalAttribute(body: string, attributeName: string): {
  mentions: number;
  values: Array<{ value: string; index: number; length: number }>;
} {
  const mentions = [...body.matchAll(new RegExp(`${attributeName}\\b`, 'gu'))].length;
  const pattern = new RegExp(`${attributeName}\\s*\\(\\s*"((?:\\\\.|[^"\\\\])*)"\\s*\\)`, 'gu');
  const values: Array<{ value: string; index: number; length: number }> = [];
  for (const match of body.matchAll(pattern)) {
    const encoded = match[1];
    if (encoded === undefined || match.index === undefined) continue;
    const decoded = decodePrismaString(encoded);
    if (decoded !== undefined) values.push({ value: decoded, index: match.index, length: match[0].length });
  }
  return { mentions, values };
}

function sequelizeDiagnostic(
  state: ParseState,
  file: AnalysisFile,
  sourceFile: ts.SourceFile,
  node: ts.Node,
  code: string,
  severity: DiagnosticRecord['severity'],
  message: string,
  basis: string,
  material: unknown = null
): void {
  state.diagnostics.push(diagnostic(code, severity, message, nodeAnchor(file, sourceFile, node), basis, material));
}

function markValidatorSerializerLimitation(
  state: ParseState,
  file: AnalysisFile,
  sourceFile: ts.SourceFile,
  node: ts.Node
): void {
  if (state.sequelizeLimitationPaths.has(file.record.path)) return;
  state.sequelizeLimitationPaths.add(file.record.path);
  sequelizeDiagnostic(
    state,
    file,
    sourceFile,
    node,
    'DATA_CONTRACT_VALIDATOR_SERIALIZER_SCOPE_LIMITED',
    'info',
    'Sequelize validation or serialization hooks are present; Atlas compares persisted column metadata only and does not infer validator or serializer shapes without symbol-level data-flow proof.',
    'sequelize-validator-serializer-correlation-not-proven',
    { path: file.record.path }
  );
}

function parseSequelizeColumnDefinition(
  file: AnalysisFile,
  sourceFile: ts.SourceFile,
  attributeName: string,
  expression: ts.Expression,
  allowedTypeRoots: ReadonlySet<string>,
  state: ParseState,
  context: 'model' | 'migration',
  underscored: boolean | undefined = false,
  anchorNode?: ts.Node
): ParsedColumnDefinition {
  const value = unwrapExpression(expression);
  let columnName = attributeName.normalize('NFC');
  let typeExpression: ts.Expression = value;
  let nullable: boolean | undefined = true;
  let defaultSignature: string | undefined = DEFAULT_ABSENT_SIGNATURE;

  if (ts.isObjectLiteralExpression(value)) {
    const object = inspectObject(value);
    if (object.dynamic) {
      sequelizeDiagnostic(
        state,
        file,
        sourceFile,
        value,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_COLUMN',
        'warning',
        `A Sequelize ${context} column uses a spread or computed property; Atlas suppressed that column because its persisted mapping can be overwritten.`,
        'dynamic-sequelize-column-object',
        { context, attributeName }
      );
      return { uncertain: true };
    }

    const field = uniquePropertyInitializer(object, 'field');
    if (context === 'model' && field.present) {
      const mapped = !field.ambiguous ? literalString(field.initializer) : undefined;
      if (mapped === undefined) {
        sequelizeDiagnostic(
          state,
          file,
          sourceFile,
          field.node ?? value,
          'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MAPPING',
          'warning',
          `Sequelize attribute ${attributeName} does not have one literal field mapping; Atlas suppressed that attribute.`,
          'dynamic-sequelize-field-mapping',
          { context, attributeName }
        );
        return { uncertain: true };
      }
      columnName = mapped;
    } else if (context === 'model' && underscored !== false && /[A-Z]/u.test(attributeName)) {
      sequelizeDiagnostic(
        state,
        file,
        sourceFile,
        value,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MAPPING',
        'info',
        `Sequelize attribute ${attributeName} relies on an underscored option without a literal field mapping; Atlas did not guess the persisted column name.`,
        'implicit-sequelize-underscored-field-mapping',
        { attributeName, underscoredKnown: underscored !== undefined }
      );
      return { uncertain: true };
    }

    const type = uniquePropertyInitializer(object, 'type');
    if (type.ambiguous || !type.initializer) {
      sequelizeDiagnostic(
        state,
        file,
        sourceFile,
        type.node ?? value,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_TYPE',
        'info',
        `Sequelize ${context} column ${columnName} does not have one inline type expression; type-family comparison was suppressed.`,
        'dynamic-sequelize-column-type',
        { context, attributeName, columnName }
      );
      typeExpression = value;
    } else {
      typeExpression = type.initializer;
    }

    const allowNull = uniquePropertyInitializer(object, 'allowNull');
    const primaryKey = uniquePropertyInitializer(object, 'primaryKey');
    const explicitAllowNull = !allowNull.ambiguous ? literalBoolean(allowNull.initializer) : undefined;
    const explicitPrimaryKey = !primaryKey.ambiguous ? literalBoolean(primaryKey.initializer) : undefined;
    if (allowNull.present && explicitAllowNull === undefined) {
      nullable = undefined;
      sequelizeDiagnostic(
        state,
        file,
        sourceFile,
        allowNull.node ?? value,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_NULLABILITY',
        'info',
        `Sequelize ${context} column ${columnName} uses non-literal allowNull metadata; nullability comparison was suppressed.`,
        'dynamic-sequelize-allow-null',
        { context, attributeName, columnName }
      );
    } else if (explicitAllowNull !== undefined) {
      nullable = explicitAllowNull;
    } else if (primaryKey.present && explicitPrimaryKey === undefined) {
      nullable = undefined;
      sequelizeDiagnostic(
        state,
        file,
        sourceFile,
        primaryKey.node ?? value,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_NULLABILITY',
        'info',
        `Sequelize ${context} column ${columnName} uses non-literal primaryKey metadata; nullability comparison was suppressed.`,
        'dynamic-sequelize-primary-key-nullability',
        { context, attributeName, columnName }
      );
    } else if (explicitPrimaryKey === true) {
      nullable = false;
    }
    if (explicitAllowNull === true && explicitPrimaryKey === true) {
      nullable = undefined;
      sequelizeDiagnostic(
        state,
        file,
        sourceFile,
        allowNull.node ?? value,
        'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_NULLABILITY',
        'warning',
        `Sequelize ${context} column ${columnName} declares both allowNull true and primaryKey true; Atlas suppressed nullability comparison.`,
        'conflicting-sequelize-nullability-metadata',
        { context, attributeName, columnName }
      );
    }

    const defaultValue = uniquePropertyInitializer(object, 'defaultValue');
    if (defaultValue.present) {
      defaultSignature = !defaultValue.ambiguous && defaultValue.initializer
        ? literalValueSignature(defaultValue.initializer)
        : undefined;
      if (!defaultSignature) {
        sequelizeDiagnostic(
          state,
          file,
          sourceFile,
          defaultValue.node ?? value,
          'DATA_CONTRACT_DYNAMIC_SEQUELIZE_DEFAULT',
          'info',
          `Sequelize ${context} column ${columnName} uses a computed or unsupported default; default comparison was suppressed without retaining its value.`,
          'dynamic-sequelize-default-value',
          { context, attributeName, columnName }
        );
      }
    }

    for (const hookName of ['validate', 'get', 'set']) {
      const hook = uniquePropertyInitializer(object, hookName);
      if (hook.present) markValidatorSerializerLimitation(state, file, sourceFile, hook.node ?? value);
    }
  } else if (context === 'model' && underscored !== false && /[A-Z]/u.test(attributeName)) {
    sequelizeDiagnostic(
      state,
      file,
      sourceFile,
      value,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MAPPING',
      'info',
      `Sequelize attribute ${attributeName} relies on an underscored option without a literal field mapping; Atlas did not guess the persisted column name.`,
      'implicit-sequelize-underscored-field-mapping',
      { attributeName, underscoredKnown: underscored !== undefined }
    );
    return { uncertain: true };
  }

  const type = sequelizeType(typeExpression, allowedTypeRoots);
  if (!type.recognized) {
    sequelizeDiagnostic(
      state,
      file,
      sourceFile,
      typeExpression,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_TYPE',
      'info',
      `Sequelize ${context} column ${columnName} uses an unsupported or non-local type expression; type-family comparison was suppressed.`,
      'unsupported-sequelize-type-expression',
      { context, attributeName, columnName }
    );
  } else if (type.family === 'text' && type.enumSignature === undefined) {
    sequelizeDiagnostic(
      state,
      file,
      sourceFile,
      typeExpression,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_ENUM',
      'info',
      `Sequelize ${context} column ${columnName} has a dynamic or unsupported ENUM member list; enum comparison was suppressed without retaining member values.`,
      'dynamic-sequelize-enum-members',
      { context, attributeName, columnName }
    );
  }

  const anchor = nodeAnchor(file, sourceFile, anchorNode ?? (
    expression.parent && ts.isPropertyAssignment(expression.parent) ? expression.parent.name : expression
  ));
  return {
    uncertain: false,
    column: {
      ...anchor,
      attributeName: attributeName.normalize('NFC'),
      columnName: columnName.normalize('NFC'),
      ...(type.family ? { family: type.family } : {}),
      ...(nullable !== undefined ? { nullable } : {}),
      ...(defaultSignature ? { defaultSignature } : {}),
      ...(type.enumSignature ? { enumSignature: type.enumSignature } : {})
    }
  };
}

function parseSequelizeModelCall(
  file: AnalysisFile,
  sourceFile: ts.SourceFile,
  call: ts.CallExpression,
  state: ParseState
): SequelizeModel | undefined {
  const callee = unwrapExpression(call.expression);
  if (!ts.isPropertyAccessExpression(callee)) return undefined;
  const methodName = callee.name.text;
  const isDefine = methodName === 'define' && ts.isIdentifier(callee.expression) && callee.expression.text === 'sequelize';
  const isInit = methodName === 'init' && ts.isIdentifier(callee.expression);
  if (!isDefine && !isInit) return undefined;

  const attributesExpression = call.arguments[isDefine ? 1 : 0];
  const optionsExpression = call.arguments[isDefine ? 2 : 1];
  const modelName = isDefine ? literalString(call.arguments[0]) : callee.expression.text.normalize('NFC');
  if (isDefine && modelName === undefined) {
    sequelizeDiagnostic(
      state, file, sourceFile, call.arguments[0] ?? call,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MODEL', 'warning',
      'A sequelize.define call uses a non-literal model name; Atlas suppressed model-to-table correlation.',
      'dynamic-sequelize-model-name'
    );
    return undefined;
  }
  if (!optionsExpression || !ts.isObjectLiteralExpression(unwrapExpression(optionsExpression))) {
    if (isDefine) {
      sequelizeDiagnostic(
        state, file, sourceFile, optionsExpression ?? call,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MODEL', 'warning',
        `Sequelize model ${modelName ?? 'init'} does not have inline literal options; Atlas suppressed table correlation.`,
        'dynamic-sequelize-model-options',
        { modelKind: isDefine ? 'define' : 'init' }
      );
    }
    return undefined;
  }
  const optionsNode = unwrapExpression(optionsExpression) as ts.ObjectLiteralExpression;
  const options = inspectObject(optionsNode);
  if (options.dynamic) {
    sequelizeDiagnostic(
      state, file, sourceFile, optionsNode,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MODEL', 'warning',
      `Sequelize model ${modelName ?? 'init'} options use a spread or computed property; Atlas suppressed table correlation.`,
      'dynamic-sequelize-model-options',
      { modelKind: isDefine ? 'define' : 'init' }
    );
    return undefined;
  }
  if (isInit && (options.properties.get('sequelize')?.length ?? 0) !== 1) return undefined;

  const tableNameProperty = uniquePropertyInitializer(options, 'tableName');
  const table = !tableNameProperty.ambiguous ? literalString(tableNameProperty.initializer) : undefined;
  if (table === undefined) {
    sequelizeDiagnostic(
      state, file, sourceFile, tableNameProperty.node ?? optionsNode,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MAPPING', 'warning',
      `Sequelize model ${modelName ?? 'init'} does not have one literal tableName; Atlas did not guess pluralization or freezeTableName behavior.`,
      'non-literal-sequelize-table-name',
      { modelKind: isDefine ? 'define' : 'init' }
    );
    return undefined;
  }
  const schemaProperty = uniquePropertyInitializer(options, 'schema');
  const schema = schemaProperty.present && !schemaProperty.ambiguous
    ? literalString(schemaProperty.initializer)
    : undefined;
  if (schemaProperty.present && schema === undefined) {
    sequelizeDiagnostic(
      state, file, sourceFile, schemaProperty.node ?? optionsNode,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MAPPING', 'warning',
      `Sequelize model ${modelName ?? 'init'} uses a non-literal schema; Atlas suppressed table correlation.`,
      'non-literal-sequelize-schema',
      { modelKind: isDefine ? 'define' : 'init', tableName: table }
    );
    return undefined;
  }
  const underscoredProperty = uniquePropertyInitializer(options, 'underscored');
  const underscored = underscoredProperty.present && !underscoredProperty.ambiguous
    ? literalBoolean(underscoredProperty.initializer)
    : false;
  if (underscoredProperty.present && underscored === undefined) {
    sequelizeDiagnostic(
      state, file, sourceFile, underscoredProperty.node ?? optionsNode,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MAPPING', 'info',
      `Sequelize model ${modelName ?? 'init'} uses a non-literal underscored option; attributes without literal field mappings may be suppressed.`,
      'dynamic-sequelize-underscored-option',
      { modelKind: isDefine ? 'define' : 'init', tableName: table }
    );
  }
  if (!attributesExpression || !ts.isObjectLiteralExpression(unwrapExpression(attributesExpression))) {
    sequelizeDiagnostic(
      state, file, sourceFile, attributesExpression ?? call,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MODEL', 'warning',
      `Sequelize model ${modelName ?? 'init'} uses a non-inline attribute map; Atlas suppressed its columns.`,
      'dynamic-sequelize-attribute-map',
      { modelKind: isDefine ? 'define' : 'init', tableName: table }
    );
    return undefined;
  }
  const attributesNode = unwrapExpression(attributesExpression) as ts.ObjectLiteralExpression;
  const attributes = inspectObject(attributesNode);
  if (attributes.dynamic) {
    sequelizeDiagnostic(
      state, file, sourceFile, attributesNode,
      'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MODEL', 'warning',
      `Sequelize model ${modelName ?? 'init'} attributes use a spread or computed property; Atlas suppressed the model because columns can be overwritten.`,
      'dynamic-sequelize-attribute-map',
      { modelKind: isDefine ? 'define' : 'init', tableName: table }
    );
    return undefined;
  }

  const roots = new Set(['DataTypes', 'Sequelize']);
  const fields: SequelizeColumn[] = [];
  const uncertainNames = new Set<string>();
  for (const [attributeName, properties] of attributes.properties) {
    if (properties.length !== 1 || !ts.isPropertyAssignment(properties[0]!)) {
      uncertainNames.add(attributeName);
      sequelizeDiagnostic(
        state, file, sourceFile, properties[0] ?? attributesNode,
        'DATA_CONTRACT_DYNAMIC_SEQUELIZE_COLUMN', 'warning',
        `Sequelize attribute ${attributeName} is duplicated, shorthand, or method-backed; Atlas suppressed that attribute.`,
        'ambiguous-sequelize-attribute-declaration',
        { modelKind: isDefine ? 'define' : 'init', tableName: table, attributeName }
      );
      continue;
    }
    const parsed = parseSequelizeColumnDefinition(
      file, sourceFile, attributeName, properties[0]!.initializer, roots, state, 'model', underscored
    );
    if (parsed.column) fields.push(parsed.column);
    if (parsed.uncertain) uncertainNames.add(attributeName);
  }

  const byColumn = new Map<string, SequelizeColumn[]>();
  for (const field of fields) {
    const values = byColumn.get(field.columnName) ?? [];
    values.push(field);
    byColumn.set(field.columnName, values);
  }
  const ambiguousColumns = new Set<string>();
  for (const [columnName, values] of byColumn) {
    if (values.length <= 1) continue;
    ambiguousColumns.add(columnName);
    sequelizeDiagnostic(
      state, file, sourceFile, attributesNode,
      'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_COLUMN', 'warning',
      `Multiple Sequelize attributes map to ${columnName}; Atlas suppressed that column comparison.`,
      'duplicate-sequelize-column-mapping',
      { tableName: table, columnName }
    );
  }

  const tableName = (schema ? `${schema}.${table}` : table).normalize('NFC');
  return {
    ...nodeAnchor(file, sourceFile, tableNameProperty.node ?? call),
    modelName: (modelName ?? table).normalize('NFC'),
    tableName,
    fields: fields.filter((field) => !ambiguousColumns.has(field.columnName) && !uncertainNames.has(field.attributeName))
  };
}

function parseSequelizeModels(files: AnalysisFile[], state: ParseState): SequelizeModel[] {
  const models: SequelizeModel[] = [];
  for (const file of files) {
    const parsedSource = parseBoundedTypeScript(
      file.record.path,
      file.content.toString('utf8'),
      scriptKind(file.record.path)
    );
    if (parsedSource.state === 'rejected') {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_SEQUELIZE_PARSE_UNCERTAIN',
        'warning',
        boundedTypeScriptDiagnosticMessage(parsedSource.reason),
        anchorFor(file, 0, 1),
        'typescript-ast-resource-limit',
        { path: file.record.path, reason: parsedSource.reason }
      ));
      continue;
    }
    const sourceFile = parsedSource.sourceFile;
    const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (parseDiagnostics.length) {
      const start = parseDiagnostics[0]!.start ?? 0;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_SEQUELIZE_PARSE_UNCERTAIN',
        'warning',
        'A JS/TS parse error prevented Sequelize contract analysis for this file.',
        anchorFor(file, start, start + 1),
        'typescript-parse-diagnostic',
        { path: file.record.path, start }
      ));
      continue;
    }
    function visit(node: ts.Node): void {
      if (ts.isCallExpression(node)) {
        const model = parseSequelizeModelCall(file, sourceFile, node, state);
        if (model) models.push(model);
      }
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }
  return models;
}

function parsePrismaFile(file: AnalysisFile, state: ParseState): PrismaModel[] {
  const source = file.content.toString('utf8');
  const masked = maskPrismaComments(source);
  const structural = maskPrismaStrings(masked);
  const models: PrismaModel[] = [];
  const modelPattern = /\bmodel\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/gu;
  for (const match of structural.matchAll(modelPattern)) {
    if (match.index === undefined || match[1] === undefined) continue;
    const opening = match.index + match[0].lastIndexOf('{');
    let depth = 1;
    let closing = opening + 1;
    while (closing < structural.length && depth > 0) {
      if (structural[closing] === '{') depth += 1;
      else if (structural[closing] === '}') depth -= 1;
      closing += 1;
    }
    const modelAnchor = anchorFor(file, match.index, opening);
    if (depth !== 0) {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_UNSUPPORTED_PRISMA_MODEL',
        'warning',
        `Prisma model ${match[1]} has an unterminated body; Atlas suppressed comparisons for it.`,
        modelAnchor,
        'unsupported-prisma-model-syntax',
        match[1]
      ));
      continue;
    }
    const bodyStart = opening + 1;
    const bodyEnd = closing - 1;
    const body = masked.slice(bodyStart, bodyEnd);
    if (/@@ignore\b/u.test(body)) {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_IGNORED_PRISMA_MODEL',
        'info',
        `Prisma model ${match[1]} is marked @@ignore; Atlas did not compare it with SQL.`,
        modelAnchor,
        'prisma-ignore-directive',
        match[1]
      ));
      continue;
    }
    const continuation = body.match(/^[ \t]*@(?!@)/mu);
    if (continuation?.index !== undefined) {
      const continuationAnchor = anchorFor(
        file,
        bodyStart + continuation.index,
        bodyStart + continuation.index + continuation[0].length
      );
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_UNSUPPORTED_PRISMA_MODEL',
        'warning',
        `Prisma model ${match[1]} contains a multi-line field attribute; Atlas suppressed comparisons because field-to-attribute ownership is uncertain.`,
        continuationAnchor,
        'unsupported-multiline-prisma-field-attribute',
        match[1]
      ));
      continue;
    }

    const tableMapping = literalAttribute(body, '@@map');
    if (tableMapping.mentions > 0 && (tableMapping.mentions !== 1 || tableMapping.values.length !== 1)) {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_DYNAMIC_PRISMA_MAPPING',
        'warning',
        `Prisma model ${match[1]} does not have one literal @@map value; Atlas suppressed comparisons for it.`,
        modelAnchor,
        'non-literal-or-ambiguous-prisma-table-mapping',
        match[1]
      ));
      continue;
    }
    const schemaMapping = literalAttribute(body, '@@schema');
    if (schemaMapping.mentions > 0 && (schemaMapping.mentions !== 1 || schemaMapping.values.length !== 1)) {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_DYNAMIC_PRISMA_MAPPING',
        'warning',
        `Prisma model ${match[1]} does not have one literal @@schema value; Atlas suppressed comparisons for it.`,
        modelAnchor,
        'non-literal-or-ambiguous-prisma-schema-mapping',
        match[1]
      ));
      continue;
    }
    const mappedTable = tableMapping.values[0]?.value ?? match[1];
    const mappedSchema = schemaMapping.values[0]?.value;
    const tableName = (mappedSchema ? `${mappedSchema}.${mappedTable}` : mappedTable).normalize('NFC');
    const fields: PrismaField[] = [];
    const ambiguousColumns = new Set<string>();
    const fieldByColumn = new Map<string, PrismaField>();
    let cursor = 0;
    while (cursor < body.length) {
      const newline = body.indexOf('\n', cursor);
      const lineEnd = newline === -1 ? body.length : newline;
      const line = body.slice(cursor, lineEnd).replace(/\r$/u, '');
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('@@')) {
        const fieldMatch = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)(\[\])?(\?)?(?=\s|$)(.*)$/u);
        if (!fieldMatch || fieldMatch[1] === undefined || fieldMatch[2] === undefined) {
          const lineAnchor = anchorFor(file, bodyStart + cursor, bodyStart + lineEnd);
          state.diagnostics.push(diagnostic(
            'DATA_CONTRACT_UNSUPPORTED_PRISMA_FIELD',
            'info',
            `Atlas could not conservatively parse a field declaration in Prisma model ${match[1]}; that declaration was skipped.`,
            lineAnchor,
            'unsupported-prisma-field-syntax',
            { model: match[1], line: lineAnchor.location.line }
          ));
        } else {
          const fieldName = fieldMatch[1].normalize('NFC');
          const typeName = fieldMatch[2];
          const attributes = fieldMatch[5] ?? '';
          const nameOffset = line.indexOf(fieldMatch[1]);
          const fieldAnchor = anchorFor(
            file,
            bodyStart + cursor + nameOffset,
            bodyStart + cursor + nameOffset + fieldMatch[1].length
          );
          const fieldMapping = literalAttribute(attributes, '@map');
          const ignored = /@ignore\b/u.test(attributes);
          const family = prismaFamily(typeName, attributes);
          if (ignored) {
            state.diagnostics.push(diagnostic(
              'DATA_CONTRACT_IGNORED_PRISMA_FIELD',
              'info',
              `Prisma field ${match[1]}.${fieldName} is marked @ignore and was not compared.`,
              fieldAnchor,
              'prisma-ignore-directive',
              { model: match[1], field: fieldName }
            ));
          } else if (fieldMatch[3]) {
            state.diagnostics.push(diagnostic(
              'DATA_CONTRACT_UNSUPPORTED_PRISMA_FIELD',
              'info',
              `Prisma list field ${match[1]}.${fieldName} was not compared because SQL array semantics are dialect-specific.`,
              fieldAnchor,
              'unsupported-prisma-list-field',
              { model: match[1], field: fieldName }
            ));
          } else if (!family) {
            state.diagnostics.push(diagnostic(
              'DATA_CONTRACT_UNSUPPORTED_PRISMA_FIELD',
              'info',
              `Prisma field ${match[1]}.${fieldName} uses a relation, enum, or unsupported scalar and was not compared.`,
              fieldAnchor,
              'unsupported-prisma-field-type',
              { model: match[1], field: fieldName, typeName }
            ));
          } else if (fieldMapping.mentions > 0 && (fieldMapping.mentions !== 1 || fieldMapping.values.length !== 1)) {
            state.diagnostics.push(diagnostic(
              'DATA_CONTRACT_DYNAMIC_PRISMA_MAPPING',
              'warning',
              `Prisma field ${match[1]}.${fieldName} does not have one literal @map value and was not compared.`,
              fieldAnchor,
              'non-literal-or-ambiguous-prisma-column-mapping',
              { model: match[1], field: fieldName }
            ));
          } else {
            const columnName = (fieldMapping.values[0]?.value ?? fieldName).normalize('NFC');
            const parsed: PrismaField = {
              ...fieldAnchor,
              fieldName,
              columnName,
              family,
              nullable: fieldMatch[4] === '?'
            };
            if (fieldByColumn.has(columnName)) ambiguousColumns.add(columnName);
            else fieldByColumn.set(columnName, parsed);
            fields.push(parsed);
          }
        }
      }
      cursor = lineEnd + (newline === -1 ? 0 : 1);
    }
    for (const columnName of ambiguousColumns) {
      const first = fieldByColumn.get(columnName)!;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_AMBIGUOUS_PRISMA_COLUMN',
        'warning',
        `Multiple Prisma fields in model ${match[1]} map to ${columnName}; Atlas suppressed that column comparison.`,
        first,
        'duplicate-prisma-column-mapping',
        { model: match[1], columnName }
      ));
    }
    models.push({
      ...modelAnchor,
      modelName: match[1].normalize('NFC'),
      tableName,
      fields: fields.filter((field) => !ambiguousColumns.has(field.columnName))
    });
  }
  return models;
}

function tokenizeSql(source: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < source.length) {
    const current = source[index]!;
    if (/\s/u.test(current)) {
      index += 1;
      continue;
    }
    if (current === '-' && source[index + 1] === '-') {
      index += 2;
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (current === '/' && source[index + 1] === '*') {
      index += 2;
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) index += 1;
      index = Math.min(source.length, index + 2);
      continue;
    }
    if (current === '$') {
      const delimiter = source.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/u)?.[0];
      if (delimiter) {
        const start = index;
        const closing = source.indexOf(delimiter, index + delimiter.length);
        index = closing === -1 ? source.length : closing + delimiter.length;
        tokens.push({ kind: 'string', text: source.slice(start, index), value: '', start, end: index });
        continue;
      }
    }
    if (/[A-Za-z_]/u.test(current)) {
      const start = index;
      index += 1;
      while (index < source.length && /[A-Za-z0-9_$]/u.test(source[index]!)) index += 1;
      const text = source.slice(start, index);
      tokens.push({ kind: 'word', text, value: text.normalize('NFC'), start, end: index });
      continue;
    }
    if (current === '"' || current === '`' || current === '[') {
      const start = index;
      const close = current === '[' ? ']' : current;
      index += 1;
      let value = '';
      while (index < source.length) {
        if (source[index] === close) {
          if (source[index + 1] === close) {
            value += close;
            index += 2;
            continue;
          }
          index += 1;
          break;
        }
        value += source[index]!;
        index += 1;
      }
      tokens.push({ kind: 'identifier', text: source.slice(start, index), value: value.normalize('NFC'), start, end: index });
      continue;
    }
    if (current === "'") {
      const start = index;
      index += 1;
      while (index < source.length) {
        if (source[index] === "'") {
          if (source[index + 1] === "'") index += 2;
          else {
            index += 1;
            break;
          }
        } else {
          index += source[index] === '\\' && index + 1 < source.length ? 2 : 1;
        }
      }
      tokens.push({ kind: 'string', text: source.slice(start, index), value: '', start, end: index });
      continue;
    }
    tokens.push({ kind: 'symbol', text: current, value: current, start: index, end: index + 1 });
    index += 1;
  }
  return tokens;
}

function keyword(token: Token | undefined, expected: string): boolean {
  return token?.kind === 'word' && token.value.toUpperCase() === expected;
}

function identifier(token: Token | undefined): boolean {
  return token?.kind === 'word' || token?.kind === 'identifier';
}

function parseQualifiedName(tokens: Token[], start: number): { name: string; next: number; anchor: Token } | undefined {
  const first = tokens[start];
  if (!first || !identifier(first)) return undefined;
  const parts = [first.value];
  let index = start + 1;
  while (tokens[index]?.text === '.' && identifier(tokens[index + 1])) {
    parts.push(tokens[index + 1]!.value);
    index += 2;
  }
  return { name: parts.join('.').normalize('NFC'), next: index, anchor: first };
}

function sqlFamily(tokens: Token[]): TypeFamily | undefined {
  const first = tokens.find((token) => token.kind === 'word')?.value.toLowerCase();
  if (!first) return undefined;
  if (['char', 'character', 'varchar', 'nvarchar', 'text', 'tinytext', 'mediumtext', 'longtext', 'citext', 'clob', 'enum'].includes(first)) return 'text';
  if (['int', 'integer', 'smallint', 'bigint', 'tinyint', 'serial', 'bigserial', 'smallserial', 'decimal', 'numeric', 'number', 'real', 'float', 'double', 'money'].includes(first)) return 'numeric';
  if (['boolean', 'bool'].includes(first)) return 'boolean';
  if (['date', 'time', 'timestamp', 'datetime', 'timestamptz', 'interval'].includes(first)) return 'temporal';
  if (['bytea', 'blob', 'binary', 'varbinary'].includes(first)) return 'binary';
  if (['json', 'jsonb'].includes(first)) return 'json';
  if (first === 'uuid' || first === 'uniqueidentifier') return 'uuid';
  return undefined;
}

function sqlStringValue(token: Token): string | undefined {
  if (token.kind !== 'string' || !token.text.startsWith("'") || !token.text.endsWith("'")) return undefined;
  return token.text.slice(1, -1).replaceAll("''", "'").normalize('NFC');
}

function matchingParenthesis(tokens: Token[], opening: number): number | undefined {
  if (tokens[opening]?.text !== '(') return undefined;
  let depth = 0;
  for (let index = opening; index < tokens.length; index += 1) {
    if (tokens[index]!.text === '(') depth += 1;
    else if (tokens[index]!.text === ')') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function literalSqlStringList(
  tokens: Token[],
  opening: number
): { members: string[]; closing: number } | undefined {
  const closing = matchingParenthesis(tokens, opening);
  if (closing === undefined || closing === opening + 1) return undefined;
  const members: string[] = [];
  let expectValue = true;
  for (let index = opening + 1; index < closing; index += 1) {
    const token = tokens[index]!;
    if (expectValue) {
      const value = sqlStringValue(token);
      if (value === undefined) return undefined;
      members.push(value);
    } else if (token.text !== ',') {
      return undefined;
    }
    expectValue = !expectValue;
  }
  if (expectValue || new Set(members).size !== members.length) return undefined;
  return { members, closing };
}

function unwrapSqlParentheses(tokens: Token[]): Token[] {
  let result = tokens;
  while (result[0]?.text === '(' && matchingParenthesis(result, 0) === result.length - 1) {
    result = result.slice(1, -1);
  }
  return result;
}

function sqlEnumSignature(
  tokens: Token[],
  family: TypeFamily | undefined,
  columnName: string
): string | undefined {
  const firstWordIndex = tokens.findIndex((token) => token.kind === 'word');
  if (firstWordIndex >= 0 && keyword(tokens[firstWordIndex], 'ENUM')) {
    const parsed = literalSqlStringList(tokens, firstWordIndex + 1);
    if (!parsed) return undefined;
    const members = [...parsed.members].sort(compareCanonicalText);
    return sha256(canonicalJson({ kind: 'enum-members', members }));
  }

  const signatures: string[] = [];
  let membershipChecks = 0;
  for (let checkIndex = 0; checkIndex < tokens.length; checkIndex += 1) {
    if (!keyword(tokens[checkIndex], 'CHECK') || tokens[checkIndex + 1]?.text !== '(') continue;
    const checkClosing = matchingParenthesis(tokens, checkIndex + 1);
    if (checkClosing === undefined) continue;
    const expression = unwrapSqlParentheses(tokens.slice(checkIndex + 2, checkClosing));
    const inIndexes = expression.flatMap((token, index) => keyword(token, 'IN') ? [index] : []);
    if (!inIndexes.length) {
      checkIndex = checkClosing;
      continue;
    }
    membershipChecks += 1;
    if (inIndexes.length !== 1) {
      checkIndex = checkClosing;
      continue;
    }
    const inIndex = inIndexes[0]!;
    const left = parseQualifiedName(expression, 0);
    const parsed = literalSqlStringList(expression, inIndex + 1);
    if (
      !left || left.next !== inIndex || left.name.split('.').at(-1) !== columnName ||
      !parsed || parsed.closing !== expression.length - 1
    ) {
      checkIndex = checkClosing;
      continue;
    }
    const members = [...parsed.members].sort(compareCanonicalText);
    signatures.push(sha256(canonicalJson({ kind: 'enum-members', members })));
    checkIndex = checkClosing;
  }
  if (membershipChecks === 0) return family === 'text' ? ENUM_ABSENT_SIGNATURE : undefined;
  if (signatures.length !== membershipChecks || new Set(signatures).size !== 1) return undefined;
  return signatures[0];
}

function splitTopLevel(tokens: Token[]): Token[][] {
  const result: Token[][] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]!.text === '(') depth += 1;
    else if (tokens[index]!.text === ')') depth -= 1;
    else if (tokens[index]!.text === ',' && depth === 0) {
      result.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  result.push(tokens.slice(start));
  return result.filter((entry) => entry.length > 0);
}

function topLevelTokens(tokens: Token[]): Token[] {
  const result: Token[] = [];
  let depth = 0;
  for (const token of tokens) {
    if (token.text === '(') {
      depth += 1;
      continue;
    }
    if (token.text === ')') {
      depth -= 1;
      continue;
    }
    if (depth === 0) result.push(token);
  }
  return result;
}

function includesKeywords(tokens: Token[], first: string, second: string): boolean {
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    if (keyword(tokens[index], first) && keyword(tokens[index + 1], second)) return true;
  }
  return false;
}

function addSqlColumn(
  table: SqlTable,
  file: AnalysisFile,
  tokens: Token[],
  state: ParseState,
  context: 'create' | 'alter-add'
): void {
  const first = tokens[0];
  if (!first || !identifier(first)) {
    table.incompleteColumnSet = true;
    return;
  }
  const leading = first.value.toUpperCase();
  if (['CONSTRAINT', 'PRIMARY', 'UNIQUE', 'FOREIGN', 'CHECK', 'EXCLUDE'].includes(leading)) return;
  if (leading === 'LIKE') {
    table.incompleteColumnSet = true;
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_DDL',
      'warning',
      `SQL table ${table.tableName} inherits columns through LIKE; Atlas suppressed missing-column claims for it.`,
      anchorFor(file, first.start, first.end),
      'unsupported-sql-inherited-columns',
      table.tableName
    ));
    return;
  }
  const columnName = first.value.normalize('NFC');
  const declaration = tokens.slice(1);
  const family = sqlFamily(declaration);
  const enumSignature = sqlEnumSignature(declaration, family, columnName);
  const top = topLevelTokens(declaration);
  const nullable = !(includesKeywords(top, 'NOT', 'NULL') || includesKeywords(top, 'PRIMARY', 'KEY'));
  const anchor = anchorFor(file, first.start, first.end);
  if (!family || declaration.some((token, index) => token.text === '[' && declaration[index + 1]?.text === ']')) {
    table.uncertainColumns.add(columnName);
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_COLUMN',
      'info',
      `SQL column ${table.tableName}.${columnName} has an unsupported or dialect-specific type and was not compared.`,
      anchor,
      'unsupported-sql-column-type',
      { tableName: table.tableName, columnName, context }
    ));
  }
  const column: SqlColumn = {
    ...anchor,
    columnName,
    ...(family ? { family } : {}),
    nullable,
    ...(enumSignature ? { enumSignature } : {})
  };
  const values = table.columns.get(columnName) ?? [];
  values.push(column);
  table.columns.set(columnName, values);
}

function getSqlTable(tables: Map<string, SqlTable>, tableName: string): SqlTable {
  const existing = tables.get(tableName);
  if (existing) return existing;
  const created: SqlTable = {
    tableName,
    anchors: [],
    createAnchors: [],
    columns: new Map(),
    uncertainColumns: new Set(),
    incompleteColumnSet: false,
    uncertainTable: false
  };
  tables.set(tableName, created);
  return created;
}

function statementGroups(tokens: Token[]): Token[][] {
  const groups: Token[][] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]!.text === '(') depth += 1;
    else if (tokens[index]!.text === ')') depth = Math.max(0, depth - 1);
    else if (tokens[index]!.text === ';' && depth === 0) {
      groups.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  if (start < tokens.length) groups.push(tokens.slice(start));
  return groups.filter((group) => group.length > 0);
}

function parseCreateTable(file: AnalysisFile, tokens: Token[], state: ParseState, tables: Map<string, SqlTable>): void {
  if (!keyword(tokens[0], 'CREATE')) return;
  let index = 1;
  if (keyword(tokens[index], 'TEMP') || keyword(tokens[index], 'TEMPORARY') || keyword(tokens[index], 'UNLOGGED')) index += 1;
  if (!keyword(tokens[index], 'TABLE')) return;
  const statementAnchor = anchorFor(file, tokens[0]!.start, tokens[index]!.end);
  index += 1;
  if (keyword(tokens[index], 'IF') && keyword(tokens[index + 1], 'NOT') && keyword(tokens[index + 2], 'EXISTS')) index += 3;
  const name = parseQualifiedName(tokens, index);
  if (!name) {
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_DYNAMIC_SQL_MAPPING',
      'warning',
      'A CREATE TABLE statement does not use a literal identifier; Atlas suppressed comparisons for it.',
      statementAnchor,
      'non-literal-sql-table-name'
    ));
    return;
  }
  index = name.next;
  const table = getSqlTable(tables, name.name);
  table.anchors.push(anchorFor(file, name.anchor.start, name.anchor.end));
  if (tokens[index]?.text !== '(') {
    table.incompleteColumnSet = true;
    table.uncertainTable = true;
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_DDL',
      'warning',
      `CREATE TABLE ${name.name} does not contain a literal column list; Atlas suppressed comparisons for it.`,
      statementAnchor,
      'unsupported-create-table-form',
      name.name
    ));
    return;
  }
  const opening = index;
  let depth = 0;
  let closing = -1;
  for (; index < tokens.length; index += 1) {
    if (tokens[index]!.text === '(') depth += 1;
    else if (tokens[index]!.text === ')') {
      depth -= 1;
      if (depth === 0) {
        closing = index;
        break;
      }
    }
  }
  if (closing === -1) {
    table.incompleteColumnSet = true;
    table.uncertainTable = true;
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_DDL',
      'warning',
      `CREATE TABLE ${name.name} has an unterminated column list; Atlas suppressed comparisons for it.`,
      statementAnchor,
      'unterminated-create-table-column-list',
      name.name
    ));
    return;
  }
  const createAnchor = anchorFor(file, name.anchor.start, name.anchor.end);
  table.createAnchors.push(createAnchor);
  for (const segment of splitTopLevel(tokens.slice(opening + 1, closing))) {
    addSqlColumn(table, file, segment, state, 'create');
  }
  if (tokens.slice(closing + 1).some((token) => keyword(token, 'INHERITS') || keyword(token, 'LIKE') || keyword(token, 'AS'))) {
    table.incompleteColumnSet = true;
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_DDL',
      'warning',
      `CREATE TABLE ${name.name} includes inherited or generated columns; Atlas suppressed missing-column claims for it.`,
      createAnchor,
      'unsupported-create-table-extension',
      name.name
    ));
  }
}

function parseAlterTable(file: AnalysisFile, tokens: Token[], state: ParseState, tables: Map<string, SqlTable>): void {
  if (!keyword(tokens[0], 'ALTER') || !keyword(tokens[1], 'TABLE')) return;
  let index = 2;
  if (keyword(tokens[index], 'IF') && keyword(tokens[index + 1], 'EXISTS')) index += 2;
  const name = parseQualifiedName(tokens, index);
  const statementAnchor = anchorFor(file, tokens[0]!.start, tokens[1]!.end);
  if (!name) {
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_DYNAMIC_SQL_MAPPING',
      'warning',
      'An ALTER TABLE statement does not use a literal identifier; Atlas suppressed comparisons for it.',
      statementAnchor,
      'non-literal-sql-table-name'
    ));
    return;
  }
  const table = getSqlTable(tables, name.name);
  table.anchors.push(anchorFor(file, name.anchor.start, name.anchor.end));
  const actions = splitTopLevel(tokens.slice(name.next));
  for (const action of actions) {
    let actionIndex = 0;
    if (keyword(action[actionIndex], 'ADD')) {
      actionIndex += 1;
      if (keyword(action[actionIndex], 'COLUMN')) actionIndex += 1;
      if (keyword(action[actionIndex], 'IF') && keyword(action[actionIndex + 1], 'NOT') && keyword(action[actionIndex + 2], 'EXISTS')) actionIndex += 3;
      if (keyword(action[actionIndex], 'CONSTRAINT')) continue;
      addSqlColumn(table, file, action.slice(actionIndex), state, 'alter-add');
      continue;
    }
    let affectedIndex = -1;
    if (keyword(action[0], 'ALTER')) affectedIndex = keyword(action[1], 'COLUMN') ? 2 : 1;
    else if (keyword(action[0], 'DROP')) affectedIndex = keyword(action[1], 'COLUMN') ? 2 : 1;
    else if (keyword(action[0], 'RENAME') && keyword(action[1], 'COLUMN')) affectedIndex = 2;
    const affected = action[affectedIndex];
    if (affected && identifier(affected)) {
      table.uncertainColumns.add(affected.value.normalize('NFC'));
      if (keyword(action[0], 'RENAME')) {
        const toIndex = action.findIndex((token, tokenIndex) => tokenIndex > affectedIndex && keyword(token, 'TO'));
        const replacement = toIndex >= 0 ? action[toIndex + 1] : undefined;
        if (replacement && identifier(replacement)) table.uncertainColumns.add(replacement.value.normalize('NFC'));
        else table.uncertainTable = true;
      }
    }
    else table.uncertainTable = true;
    const actionAnchor = action[0] ? anchorFor(file, action[0].start, action[0].end) : statementAnchor;
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_ALTERATION',
      'warning',
      `ALTER TABLE ${name.name} contains an unsupported state-changing action; affected comparisons were suppressed.`,
      actionAnchor,
      'unsupported-sql-table-alteration',
      { tableName: name.name, affectedColumn: affected?.value ?? null }
    ));
  }
}

function parseDropTable(file: AnalysisFile, tokens: Token[], state: ParseState, tables: Map<string, SqlTable>): void {
  if (!keyword(tokens[0], 'DROP') || !keyword(tokens[1], 'TABLE')) return;
  let index = 2;
  if (keyword(tokens[index], 'IF') && keyword(tokens[index + 1], 'EXISTS')) index += 2;
  for (const segment of splitTopLevel(tokens.slice(index))) {
    const name = parseQualifiedName(segment, 0);
    if (!name) {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_DYNAMIC_SQL_MAPPING',
        'warning',
        'A DROP TABLE statement does not use a literal identifier; affected comparisons were suppressed.',
        anchorFor(file, tokens[0]!.start, tokens[1]!.end),
        'non-literal-drop-table-name'
      ));
      continue;
    }
    const table = getSqlTable(tables, name.name);
    table.uncertainTable = true;
    const tableAnchor = anchorFor(file, name.anchor.start, name.anchor.end);
    table.anchors.push(tableAnchor);
    state.diagnostics.push(diagnostic(
      'DATA_CONTRACT_UNSUPPORTED_SQL_DDL',
      'warning',
      `SQL drops table ${name.name}; Atlas suppressed comparisons because migration state is not executed.`,
      tableAnchor,
      'drop-table-state-transition',
      name.name
    ));
  }
}

function parseSqlFiles(files: AnalysisFile[], state: ParseState): Map<string, SqlTable> {
  const tables = new Map<string, SqlTable>();
  for (const file of files) {
    const source = file.content.toString('utf8');
    for (const statement of statementGroups(tokenizeSql(source))) {
      parseCreateTable(file, statement, state, tables);
      parseAlterTable(file, statement, state, tables);
      parseDropTable(file, statement, state, tables);
    }
  }
  for (const table of tables.values()) {
    if (table.createAnchors.length > 1) {
      table.uncertainTable = true;
      const first = [...table.createAnchors].sort((left, right) =>
        compareCanonicalText(left.file.record.path, right.file.record.path) || left.location.line - right.location.line
      )[0]!;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_AMBIGUOUS_SQL_TABLE',
        'warning',
        `Multiple CREATE TABLE declarations describe ${table.tableName}; Atlas suppressed comparisons for that table.`,
        first,
        'duplicate-sql-table-declaration',
        table.tableName
      ));
    }
    for (const [columnName, columns] of table.columns) {
      if (columns.length <= 1) continue;
      table.uncertainColumns.add(columnName);
      const first = [...columns].sort((left, right) =>
        compareCanonicalText(left.file.record.path, right.file.record.path) || left.location.line - right.location.line
      )[0]!;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_AMBIGUOUS_SQL_COLUMN',
        'warning',
        `Multiple SQL declarations describe ${table.tableName}.${columnName}; Atlas suppressed that column comparison.`,
        first,
        'duplicate-sql-column-declaration',
        { tableName: table.tableName, columnName }
      ));
    }
  }
  return tables;
}

type MigrationFunction = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

function migrationFunctions(sourceFile: ts.SourceFile): MigrationFunction[] {
  const result: MigrationFunction[] = [];
  const seen = new Set<ts.Node>();
  function add(node: MigrationFunction): void {
    if (!node.body || seen.has(node)) return;
    seen.add(node);
    result.push(node);
  }
  function visit(node: ts.Node): void {
    if (
      ts.isMethodDeclaration(node) && node.body && node.parent && ts.isObjectLiteralExpression(node.parent) &&
      literalPropertyName(node.name) === 'up'
    ) {
      add(node);
    } else if (
      ts.isPropertyAssignment(node) && literalPropertyName(node.name) === 'up' &&
      (ts.isFunctionExpression(unwrapExpression(node.initializer)) || ts.isArrowFunction(unwrapExpression(node.initializer)))
    ) {
      add(unwrapExpression(node.initializer) as ts.FunctionExpression | ts.ArrowFunction);
    } else if (ts.isFunctionDeclaration(node) && node.body && node.name?.text === 'up') {
      add(node);
    } else if (
      ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'up' && node.initializer &&
      (ts.isFunctionExpression(unwrapExpression(node.initializer)) || ts.isArrowFunction(unwrapExpression(node.initializer)))
    ) {
      add(unwrapExpression(node.initializer) as ts.FunctionExpression | ts.ArrowFunction);
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return result;
}

function enclosingMigrationFunction(
  node: ts.Node,
  functions: ReadonlySet<MigrationFunction>
): { migration?: MigrationFunction; nested: boolean } {
  let current: ts.Node | undefined = node.parent;
  let nested = false;
  while (current) {
    if (functions.has(current as MigrationFunction)) return { migration: current as MigrationFunction, nested };
    if (
      ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) || ts.isArrowFunction(current) ||
      ts.isMethodDeclaration(current) || ts.isGetAccessorDeclaration(current) || ts.isSetAccessorDeclaration(current)
    ) {
      nested = true;
    }
    current = current.parent;
  }
  return { nested };
}

function isConditionalMigrationCall(call: ts.CallExpression, migration: MigrationFunction, nested: boolean): boolean {
  if (nested) return true;
  let current: ts.Node | undefined = call.parent;
  while (current && current !== migration) {
    if (
      ts.isIfStatement(current) || ts.isConditionalExpression(current) || ts.isSwitchStatement(current) ||
      ts.isCaseClause(current) || ts.isDefaultClause(current) || ts.isForStatement(current) ||
      ts.isForInStatement(current) || ts.isForOfStatement(current) || ts.isWhileStatement(current) ||
      ts.isDoStatement(current) || ts.isCatchClause(current)
    ) return true;
    if (
      ts.isBinaryExpression(current) &&
      [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(current.operatorToken.kind)
    ) return true;
    current = current.parent;
  }
  return false;
}

function migrationOrderKey(filePath: string): string | undefined {
  const basename = filePath.replace(/\\/gu, '/').split('/').pop() ?? '';
  return basename.match(/^(\d{8,})/u)?.[1];
}

function isAncestor(ancestor: ts.Node, node: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  while (current) {
    if (current === ancestor) return true;
    current = current.parent;
  }
  return false;
}

function directConstInitializer(
  name: string,
  use: ts.Node,
  migration: MigrationFunction,
  sourceFile: ts.SourceFile
): ts.Expression | undefined {
  const useStart = use.getStart(sourceFile);
  let current: ts.Node | undefined = use.parent;
  while (current) {
    if (ts.isBlock(current) && isAncestor(migration, current)) {
      const matches: ts.VariableDeclaration[] = [];
      for (const statement of current.statements) {
        if (statement.getStart(sourceFile) >= useStart || !ts.isVariableStatement(statement)) continue;
        if ((statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
        for (const declaration of statement.declarationList.declarations) {
          if (ts.isIdentifier(declaration.name) && declaration.name.text === name && declaration.initializer) matches.push(declaration);
        }
      }
      if (matches.length === 1) return matches[0]!.initializer;
      if (matches.length > 1) return undefined;
    }
    if (current === migration) break;
    current = current.parent;
  }
  const topLevel: ts.VariableDeclaration[] = [];
  for (const statement of sourceFile.statements) {
    if (statement.getStart(sourceFile) >= useStart || !ts.isVariableStatement(statement)) continue;
    if ((statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === name && declaration.initializer) topLevel.push(declaration);
    }
  }
  return topLevel.length === 1 ? topLevel[0]!.initializer : undefined;
}

function resolvedConstExpression(
  expression: ts.Expression,
  migration: MigrationFunction,
  sourceFile: ts.SourceFile,
  seen = new Set<string>()
): ts.Expression {
  const value = unwrapExpression(expression);
  if (!ts.isIdentifier(value) || seen.has(value.text)) return value;
  const initializer = directConstInitializer(value.text, value, migration, sourceFile);
  if (!initializer) return value;
  const nextSeen = new Set(seen);
  nextSeen.add(value.text);
  return resolvedConstExpression(initializer, migration, sourceFile, nextSeen);
}

function literalStringCandidates(
  expression: ts.Expression | undefined,
  migration: MigrationFunction,
  sourceFile: ts.SourceFile,
  seen = new Set<string>()
): string[] | undefined {
  if (!expression) return undefined;
  const value = unwrapExpression(expression);
  if (ts.isStringLiteralLike(value)) return [value.text.normalize('NFC')];
  if (!ts.isIdentifier(value) || seen.has(value.text)) return undefined;
  let current: ts.Node | undefined = value.parent;
  while (current && current !== migration) {
    if (ts.isForOfStatement(current) && ts.isVariableDeclarationList(current.initializer)) {
      const declaration = current.initializer.declarations[0];
      if (
        declaration && ts.isIdentifier(declaration.name) && declaration.name.text === value.text &&
        (current.initializer.flags & ts.NodeFlags.Const) !== 0
      ) {
        const collection = resolvedConstExpression(current.expression, migration, sourceFile);
        if (!ts.isArrayLiteralExpression(collection) || collection.elements.length === 0) return undefined;
        const values: string[] = [];
        for (const element of collection.elements) {
          if (ts.isSpreadElement(element)) return undefined;
          const literal = literalStringCandidates(element, migration, sourceFile, new Set(seen));
          if (!literal || literal.length !== 1) return undefined;
          values.push(literal[0]!);
        }
        return [...new Set(values)].sort(compareCanonicalText);
      }
    }
    current = current.parent;
  }
  const initializer = directConstInitializer(value.text, value, migration, sourceFile);
  if (!initializer) return undefined;
  const nextSeen = new Set(seen);
  nextSeen.add(value.text);
  return literalStringCandidates(initializer, migration, sourceFile, nextSeen);
}

function tableReference(
  tableExpression: ts.Expression | undefined,
  optionsExpression: ts.Expression | undefined,
  migration: MigrationFunction,
  sourceFile: ts.SourceFile
): { tableName?: string; candidateTableNames?: string[]; anchor?: ts.Node; dynamic: boolean } {
  if (!tableExpression) return { dynamic: true };
  const tableValue = resolvedConstExpression(tableExpression, migration, sourceFile);
  let tableNames: string[] | undefined;
  let schema: string | undefined;
  let schemaKnown = true;
  if (ts.isStringLiteralLike(tableValue)) {
    tableNames = [tableValue.text.normalize('NFC')];
  } else if (ts.isObjectLiteralExpression(tableValue)) {
    const tableObject = inspectObject(tableValue);
    if (tableObject.dynamic) return { anchor: tableExpression, dynamic: true };
    const tableProperty = uniquePropertyInitializer(tableObject, 'tableName');
    tableNames = !tableProperty.ambiguous
      ? literalStringCandidates(tableProperty.initializer, migration, sourceFile)
      : undefined;
    const schemaProperty = uniquePropertyInitializer(tableObject, 'schema');
    if (schemaProperty.present) {
      const schemas = !schemaProperty.ambiguous
        ? literalStringCandidates(schemaProperty.initializer, migration, sourceFile)
        : undefined;
      schema = schemas?.length === 1 ? schemas[0] : undefined;
      schemaKnown = schema !== undefined;
    }
  } else {
    const candidates = literalStringCandidates(tableExpression, migration, sourceFile);
    if (candidates) tableNames = candidates;
    else return { anchor: tableExpression, dynamic: true };
  }
  if (optionsExpression) {
    const optionsValue = resolvedConstExpression(optionsExpression, migration, sourceFile);
    if (!ts.isObjectLiteralExpression(optionsValue)) return { anchor: tableExpression, dynamic: true };
    const options = inspectObject(optionsValue);
    const optionSchema = uniquePropertyInitializer(options, 'schema');
    if (options.dynamic && schema === undefined) schemaKnown = false;
    if (optionSchema.present) {
      const schemas = !optionSchema.ambiguous
        ? literalStringCandidates(optionSchema.initializer, migration, sourceFile)
        : undefined;
      const literal = schemas?.length === 1 ? schemas[0] : undefined;
      if (literal === undefined || (schema !== undefined && schema !== literal)) schemaKnown = false;
      else schema = literal;
    }
  }
  if (!tableNames?.length || !schemaKnown) return { anchor: tableExpression, dynamic: true };
  const qualified = tableNames.map((tableName) => (schema ? `${schema}.${tableName}` : tableName).normalize('NFC'));
  if (qualified.length !== 1) {
    return { candidateTableNames: qualified.sort(compareCanonicalText), anchor: tableExpression, dynamic: true };
  }
  return {
    tableName: qualified[0]!,
    anchor: tableExpression,
    dynamic: false
  };
}

function queryInterfaceMethod(call: ts.CallExpression, receiverName: string): { method?: string; dynamic: boolean } | undefined {
  const callee = unwrapExpression(call.expression);
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === receiverName) {
    return { method: callee.name.text, dynamic: false };
  }
  if (ts.isElementAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === receiverName) {
    const method = literalString(callee.argumentExpression);
    return method ? { method, dynamic: false } : { dynamic: true };
  }
  return undefined;
}

function isRawQueryCall(call: ts.CallExpression, receiverName: string): boolean {
  const callee = unwrapExpression(call.expression);
  return ts.isPropertyAccessExpression(callee) && callee.name.text === 'query' &&
    ts.isPropertyAccessExpression(callee.expression) && callee.expression.name.text === 'sequelize' &&
    ts.isIdentifier(callee.expression.expression) && callee.expression.expression.text === receiverName;
}

function literalDdlTables(expression: ts.Expression | undefined): { tables: string[]; incomplete: boolean; containsDdl: boolean } {
  if (!expression) return { tables: [], incomplete: false, containsDdl: false };
  const value = unwrapExpression(expression);
  const textValue = ts.isStringLiteralLike(value) || ts.isNoSubstitutionTemplateLiteral(value) ? value.text : undefined;
  if (textValue === undefined) {
    const containsDdl = /\b(?:CREATE|ALTER|DROP)\s+TABLE\b/iu.test(value.getText());
    return { tables: [], incomplete: containsDdl, containsDdl };
  }
  const tokens = tokenizeSql(textValue);
  const tables: string[] = [];
  let declarationCount = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    if (!keyword(tokens[index], 'CREATE') && !keyword(tokens[index], 'ALTER') && !keyword(tokens[index], 'DROP')) continue;
    let nameIndex = index + 1;
    if (keyword(tokens[index], 'CREATE') && (
      keyword(tokens[nameIndex], 'TEMP') || keyword(tokens[nameIndex], 'TEMPORARY') || keyword(tokens[nameIndex], 'UNLOGGED')
    )) nameIndex += 1;
    if (!keyword(tokens[nameIndex], 'TABLE')) continue;
    declarationCount += 1;
    nameIndex += 1;
    if (keyword(tokens[nameIndex], 'IF')) {
      nameIndex += 1;
      if (keyword(tokens[nameIndex], 'NOT')) nameIndex += 1;
      if (keyword(tokens[nameIndex], 'EXISTS')) nameIndex += 1;
    }
    const name = parseQualifiedName(tokens, nameIndex);
    if (name) tables.push(name.name);
  }
  return {
    tables: [...new Set(tables)].sort(compareCanonicalText),
    incomplete: tables.length !== declarationCount,
    containsDdl: declarationCount > 0
  };
}

function createMigrationTable(tableName: string): SequelizeMigrationTable {
  return {
    tableName,
    anchors: [],
    createAnchors: [],
    columns: new Map(),
    removedColumns: new Map(),
    uncertainColumns: new Set(),
    completeColumnSet: false,
    uncertainTable: false
  };
}

function parseSequelizeMigrations(files: AnalysisFile[], state: ParseState): SequelizeMigrationResult {
  const operations: MigrationOperation[] = [];
  const forcedUncertainty = new Map<string, Anchor[]>();
  let globalUncertainty = false;
  let sequence = 0;

  function markTableUncertain(tableName: string, value: Anchor): void {
    const anchors = forcedUncertainty.get(tableName) ?? [];
    anchors.push(value);
    forcedUncertainty.set(tableName, anchors);
  }

  for (const file of files) {
    if (!/(?:^|\/)(?:migrations?|migrate)(?:\/|$)/iu.test(file.record.path.replace(/\\/gu, '/'))) continue;
    const parsedSource = parseBoundedTypeScript(
      file.record.path,
      file.content.toString('utf8'),
      scriptKind(file.record.path)
    );
    if (parsedSource.state === 'rejected') {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_SEQUELIZE_MIGRATION_PARSE_UNCERTAIN',
        'warning',
        boundedTypeScriptDiagnosticMessage(parsedSource.reason),
        anchorFor(file, 0, 1),
        'typescript-ast-resource-limit',
        { path: file.record.path, reason: parsedSource.reason }
      ));
      globalUncertainty = true;
      continue;
    }
    const sourceFile = parsedSource.sourceFile;
    const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (parseDiagnostics.length) {
      const start = parseDiagnostics[0]!.start ?? 0;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_SEQUELIZE_MIGRATION_PARSE_UNCERTAIN',
        'warning',
        'A JS/TS migration parse error prevented conservative QueryInterface correlation for this file.',
        anchorFor(file, start, start + 1),
        'typescript-migration-parse-diagnostic',
        { path: file.record.path, start }
      ));
      globalUncertainty = true;
      continue;
    }
    const upFunctions = migrationFunctions(sourceFile);
    const upSet = new Set(upFunctions);
    for (const migration of upFunctions) {
      const receiver = migration.parameters[0]?.name;
      if (!receiver || !ts.isIdentifier(receiver)) {
        sequelizeDiagnostic(
          state, file, sourceFile, migration,
          'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
          'A migration up function does not expose a literal QueryInterface parameter; Sequelize migration correlation was suppressed for that file.',
          'dynamic-query-interface-binding',
          { path: file.record.path }
        );
        globalUncertainty = true;
      }
    }

    function visit(node: ts.Node): void {
      if (!ts.isCallExpression(node)) {
        ts.forEachChild(node, visit);
        return;
      }
      const enclosing = enclosingMigrationFunction(node, upSet);
      if (!enclosing.migration) {
        ts.forEachChild(node, visit);
        return;
      }
      const receiverNode = enclosing.migration.parameters[0]?.name;
      if (!receiverNode || !ts.isIdentifier(receiverNode)) {
        ts.forEachChild(node, visit);
        return;
      }
      const receiverName = receiverNode.text;
      const conditional = isConditionalMigrationCall(node, enclosing.migration, enclosing.nested);
      const typeRoots = new Set(['DataTypes', 'Sequelize']);
      const typeParameter = enclosing.migration.parameters[1]?.name;
      if (typeParameter && ts.isIdentifier(typeParameter)) typeRoots.add(typeParameter.text);

      if (isRawQueryCall(node, receiverName)) {
        const ddl = literalDdlTables(node.arguments[0]);
        if (ddl.containsDdl) {
          const value = nodeAnchor(file, sourceFile, node);
          for (const tableName of ddl.tables) markTableUncertain(tableName, value);
          if (ddl.incomplete || conditional) globalUncertainty = true;
          sequelizeDiagnostic(
            state, file, sourceFile, node,
            'DATA_CONTRACT_EMBEDDED_SQL_MIGRATION_UNSUPPORTED',
            ddl.incomplete || conditional ? 'warning' : 'info',
            'A migration executes embedded SQL DDL; Atlas does not merge its state transitions with QueryInterface contracts, so affected comparisons were suppressed.',
            'embedded-sql-migration-state-not-executed',
            { affectedTableCount: ddl.tables.length, completeLiteralTableExtraction: !ddl.incomplete, conditional }
          );
        }
        ts.forEachChild(node, visit);
        return;
      }

      const method = queryInterfaceMethod(node, receiverName);
      if (!method) {
        ts.forEachChild(node, visit);
        return;
      }
      if (method.dynamic) {
        globalUncertainty = true;
        sequelizeDiagnostic(
          state, file, sourceFile, node,
          'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
          'A migration invokes QueryInterface through a computed method; Atlas suppressed Sequelize migration mismatch claims target-wide.',
          'dynamic-query-interface-method',
          { path: file.record.path }
        );
        ts.forEachChild(node, visit);
        return;
      }
      const operationKind: Record<string, MigrationOperationKind | undefined> = {
        createTable: 'create',
        addColumn: 'add',
        changeColumn: 'change',
        removeColumn: 'remove',
        renameColumn: 'rename'
      };
      const kind = operationKind[method.method ?? ''];
      if (!kind) {
        ts.forEachChild(node, visit);
        return;
      }

      const table = tableReference(
        node.arguments[0],
        kind === 'create' ? node.arguments[2] : undefined,
        enclosing.migration,
        sourceFile
      );
      if (!table.tableName || table.dynamic) {
        const possibleTables = table.candidateTableNames ?? [];
        const uncertaintyAnchor = nodeAnchor(file, sourceFile, table.anchor ?? node.arguments[0] ?? node);
        for (const tableName of possibleTables) markTableUncertain(tableName, uncertaintyAnchor);
        if (possibleTables.length === 0) globalUncertainty = true;
        sequelizeDiagnostic(
          state, file, sourceFile, table.anchor ?? node.arguments[0] ?? node,
          'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
          possibleTables.length
            ? `A QueryInterface ${method.method} call iterates over a bounded literal table set; Atlas suppressed those tables because loop execution is not modeled.`
            : `A QueryInterface ${method.method} call uses a dynamic table or schema; Atlas suppressed Sequelize migration mismatch claims target-wide.`,
          'dynamic-sequelize-migration-table',
          { operation: kind, path: file.record.path, candidateTableCount: possibleTables.length }
        );
        ts.forEachChild(node, visit);
        return;
      }
      const operationAnchor = nodeAnchor(file, sourceFile, table.anchor ?? node);
      if (conditional) {
        markTableUncertain(table.tableName, operationAnchor);
        sequelizeDiagnostic(
          state, file, sourceFile, node,
          'DATA_CONTRACT_CONDITIONAL_SEQUELIZE_MIGRATION', 'warning',
          `A QueryInterface ${method.method} call for ${table.tableName} is conditional or nested; Atlas suppressed that table because the operation is not a straight-line up migration.`,
          'conditional-sequelize-migration-operation',
          { operation: kind, tableName: table.tableName }
        );
        ts.forEachChild(node, visit);
        return;
      }

      const mutationAnchor = kind === 'create' || !node.arguments[1]
        ? operationAnchor
        : nodeAnchor(file, sourceFile, node.arguments[1]!);
      const base: Omit<MigrationOperation, 'kind'> = {
        ...mutationAnchor,
        tableName: table.tableName,
        sequence
      };
      const orderKey = migrationOrderKey(file.record.path);
      if (orderKey) base.orderKey = orderKey;
      sequence += 1;
      if (kind === 'create') {
        const columnsExpression = node.arguments[1] ? unwrapExpression(node.arguments[1]!) : undefined;
        if (!columnsExpression || !ts.isObjectLiteralExpression(columnsExpression)) {
          markTableUncertain(table.tableName, operationAnchor);
          sequelizeDiagnostic(
            state, file, sourceFile, node.arguments[1] ?? node,
            'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
            `QueryInterface createTable for ${table.tableName} uses a non-inline column map; Atlas suppressed that table.`,
            'dynamic-sequelize-create-table-columns',
            { tableName: table.tableName }
          );
        } else {
          const inspected = inspectObject(columnsExpression);
          if (inspected.dynamic) {
            markTableUncertain(table.tableName, operationAnchor);
            sequelizeDiagnostic(
              state, file, sourceFile, columnsExpression,
              'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
              `QueryInterface createTable for ${table.tableName} uses a spread or computed column; Atlas suppressed that table.`,
              'dynamic-sequelize-create-table-columns',
              { tableName: table.tableName }
            );
          } else {
            const columns: SequelizeColumn[] = [];
            const uncertainColumns: string[] = [];
            for (const [columnName, properties] of inspected.properties) {
              if (properties.length !== 1 || !ts.isPropertyAssignment(properties[0]!)) {
                uncertainColumns.push(columnName);
                continue;
              }
              const parsed = parseSequelizeColumnDefinition(
                file, sourceFile, columnName, properties[0]!.initializer, typeRoots, state, 'migration'
              );
              if (parsed.column) columns.push(parsed.column);
              if (parsed.uncertain) uncertainColumns.push(columnName);
            }
            operations.push({
              ...base,
              kind,
              columns,
              completeColumnSet: true,
              ...(uncertainColumns.length ? { uncertainColumns: uncertainColumns.sort(compareCanonicalText) } : {})
            });
          }
        }
      } else {
        const columnCandidates = literalStringCandidates(node.arguments[1], enclosing.migration, sourceFile);
        const columnName = columnCandidates?.length === 1 ? columnCandidates[0] : undefined;
        if (columnName === undefined) {
          markTableUncertain(table.tableName, operationAnchor);
          sequelizeDiagnostic(
            state, file, sourceFile, node.arguments[1] ?? node,
            'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
            `QueryInterface ${method.method} for ${table.tableName} uses a dynamic column name; Atlas suppressed that table.`,
            'dynamic-sequelize-migration-column',
            { operation: kind, tableName: table.tableName }
          );
        } else if (kind === 'add' || kind === 'change') {
          const definition = node.arguments[2];
          if (!definition) {
            markTableUncertain(table.tableName, operationAnchor);
          } else {
            const parsed = parseSequelizeColumnDefinition(
              file, sourceFile, columnName, definition, typeRoots, state, 'migration', false, node.arguments[1]
            );
            operations.push({
              ...base,
              kind,
              columnName,
              ...(parsed.column ? { column: parsed.column } : {}),
              ...(parsed.uncertain ? { uncertainColumns: [columnName] } : {})
            });
          }
        } else if (kind === 'rename') {
          const replacementCandidates = literalStringCandidates(node.arguments[2], enclosing.migration, sourceFile);
          const replacementName = replacementCandidates?.length === 1 ? replacementCandidates[0] : undefined;
          if (replacementName === undefined) {
            markTableUncertain(table.tableName, operationAnchor);
            sequelizeDiagnostic(
              state, file, sourceFile, node.arguments[2] ?? node,
              'DATA_CONTRACT_DYNAMIC_SEQUELIZE_MIGRATION', 'warning',
              `QueryInterface renameColumn for ${table.tableName}.${columnName} uses a dynamic replacement name; Atlas suppressed that table.`,
              'dynamic-sequelize-rename-column',
              { tableName: table.tableName, columnName }
            );
          } else {
            operations.push({ ...base, kind, columnName, replacementName });
          }
        } else {
          operations.push({ ...base, kind, columnName });
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }

  const operationsByTable = new Map<string, MigrationOperation[]>();
  for (const operation of operations) {
    const values = operationsByTable.get(operation.tableName) ?? [];
    values.push(operation);
    operationsByTable.set(operation.tableName, values);
  }
  const tables = new Map<string, SequelizeMigrationTable>();
  for (const [tableName, tableOperations] of operationsByTable) {
    const table = createMigrationTable(tableName);
    tables.set(tableName, table);
    const filesForTable = [...new Set(tableOperations.map((operation) => operation.file.record.path))];
    if (filesForTable.length > 1) {
      const keys = filesForTable.map((path) => migrationOrderKey(path));
      if (keys.some((key) => key === undefined) || new Set(keys).size !== keys.length) {
        table.uncertainTable = true;
        const first = [...tableOperations].sort((left, right) => left.sequence - right.sequence)[0]!;
        state.diagnostics.push(diagnostic(
          'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_MIGRATION_ORDER',
          'warning',
          `Sequelize migration operations for ${tableName} span files without unique leading timestamp keys; Atlas suppressed that table rather than infer execution order.`,
          first,
          'ambiguous-sequelize-migration-order',
          { tableName, fileCount: filesForTable.length }
        ));
      }
    }
    const ordered = [...tableOperations].sort((left, right) =>
      compareCanonicalText(left.orderKey ?? '', right.orderKey ?? '') ||
      compareCanonicalText(left.file.record.path, right.file.record.path) ||
      left.sequence - right.sequence
    );
    let created = false;
    for (const operation of ordered) {
      table.anchors.push(operation);
      if (operation.kind === 'create') {
        if (created) {
          table.uncertainTable = true;
          state.diagnostics.push(diagnostic(
            'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_TABLE',
            'warning',
            `Multiple literal createTable operations target ${tableName}; Atlas suppressed that table.`,
            operation,
            'duplicate-sequelize-create-table',
            { tableName }
          ));
          continue;
        }
        created = true;
        table.createAnchors.push(operation);
        table.completeColumnSet = operation.completeColumnSet === true;
        table.columns.clear();
        table.removedColumns.clear();
        table.uncertainColumns = new Set(operation.uncertainColumns ?? []);
        for (const column of operation.columns ?? []) table.columns.set(column.columnName, column);
        continue;
      }
      const columnName = operation.columnName!;
      if (operation.kind === 'add') {
        if (table.columns.has(columnName)) {
          table.uncertainColumns.add(columnName);
          state.diagnostics.push(diagnostic(
            'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_COLUMN',
            'warning',
            `QueryInterface addColumn redeclares ${tableName}.${columnName}; Atlas suppressed that column because the literal migration sequence may fail or be non-idempotent.`,
            operation,
            'duplicate-sequelize-add-column',
            { tableName, columnName }
          ));
        } else if (operation.column) {
          table.columns.set(columnName, operation.column);
          table.removedColumns.delete(columnName);
          table.uncertainColumns.delete(columnName);
        } else {
          table.uncertainColumns.add(columnName);
        }
      } else if (operation.kind === 'change') {
        if (operation.column) {
          table.columns.set(columnName, operation.column);
          table.removedColumns.delete(columnName);
          table.uncertainColumns.delete(columnName);
        } else {
          table.uncertainColumns.add(columnName);
        }
      } else if (operation.kind === 'remove') {
        table.columns.delete(columnName);
        table.uncertainColumns.delete(columnName);
        table.removedColumns.set(columnName, operation);
      } else if (operation.kind === 'rename') {
        const replacementName = operation.replacementName!;
        const existing = table.columns.get(columnName);
        table.columns.delete(columnName);
        table.uncertainColumns.delete(columnName);
        table.removedColumns.set(columnName, operation);
        if (table.columns.has(replacementName)) {
          table.uncertainColumns.add(replacementName);
        } else if (existing) {
          table.columns.set(replacementName, { ...existing, columnName: replacementName });
          table.removedColumns.delete(replacementName);
        } else {
          table.uncertainColumns.add(replacementName);
        }
      }
    }
  }
  for (const [tableName, anchors] of forcedUncertainty) {
    const table = tables.get(tableName) ?? createMigrationTable(tableName);
    table.uncertainTable = true;
    table.anchors.push(...anchors);
    tables.set(tableName, table);
  }
  return { tables, globalUncertainty };
}

function relatedPaths(anchors: Anchor[]): string[] {
  return [...new Set(anchors.map((anchor) => anchor.file.record.path))].sort(compareCanonicalText);
}

function mismatchFinding(
  ruleId: DataContractRuleId,
  title: string,
  description: string,
  tableName: string,
  columnName: string,
  severity: FindingRecord['severity'],
  confidence: FindingRecord['confidence'],
  signals: string[],
  prisma: PrismaField,
  sqlAnchors: Anchor[],
  nextValidation: string
): FindingRecord {
  const anchors = [prisma, ...sqlAnchors];
  return {
    schemaVersion: SCHEMA_VERSION,
    id: findingId(ruleId, tableName, columnName, anchors),
    category: 'contract-mismatch',
    ruleId,
    subject: dataContractSubject(ruleId, tableName, columnName, 'prisma', 'sql'),
    status: 'candidate',
    severity,
    confidence,
    title,
    description,
    path: prisma.file.record.path,
    relatedPaths: relatedPaths(sqlAnchors),
    signals,
    evidence: [
      evidence(prisma, 'literal-prisma-model-field'),
      ...sqlAnchors.map((anchor) => evidence(anchor, 'literal-sql-table-or-column-declaration'))
    ],
    nextValidation
  };
}

function sequelizeMismatchFinding(
  ruleId: DataContractRuleId,
  title: string,
  description: string,
  tableName: string,
  columnName: string,
  severity: FindingRecord['severity'],
  confidence: FindingRecord['confidence'],
  signals: string[],
  model: SequelizeColumn,
  storageAnchors: Anchor[],
  storageBasis: SequelizeStorageBasis,
  nextValidation: string
): FindingRecord {
  const anchors = [model, ...storageAnchors];
  return {
    schemaVersion: SCHEMA_VERSION,
    id: findingId(ruleId, tableName, columnName, anchors),
    category: 'contract-mismatch',
    ruleId,
    subject: dataContractSubject(ruleId, tableName, columnName, 'sequelize', sequelizeStorage(storageBasis)),
    status: 'candidate',
    severity,
    confidence,
    title,
    description,
    path: model.file.record.path,
    relatedPaths: relatedPaths(storageAnchors),
    signals,
    evidence: [
      evidence(model, 'literal-sequelize-model-attribute'),
      ...storageAnchors.map((anchor) => evidence(anchor, storageBasis))
    ],
    nextValidation
  };
}

function compareSequelizeModelWithMigration(
  model: SequelizeModel,
  table: SequelizeMigrationTable
): FindingRecord[] {
  if (table.uncertainTable) return [];
  const findings: FindingRecord[] = [];
  for (const field of model.fields) {
    if (table.uncertainColumns.has(field.columnName)) continue;
    const migration = table.columns.get(field.columnName);
    if (!migration) {
      const removal = table.removedColumns.get(field.columnName);
      if (removal) {
        findings.push(sequelizeMismatchFinding(
          'contract/data-column-removed-v1',
          `Sequelize model still maps a removed column: ${table.tableName}.${field.columnName}`,
          `Sequelize attribute ${model.modelName}.${field.attributeName} maps to ${table.tableName}.${field.columnName}, while the ordered literal up-migration sequence removes or renames that column without a later literal restoration.`,
          table.tableName,
          field.columnName,
          'high',
          'high',
          ['literal-sequelize-model-column-removed-by-literal-up-migration'],
          field,
          [removal],
          'literal-sequelize-migration-remove-or-rename-column',
          'Confirm the applied migration ledger and any out-of-band database changes, then remove or remap the Sequelize attribute or restore the intended column.'
        ));
        continue;
      }
      const attributeNamedColumn = field.attributeName !== field.columnName
        ? table.columns.get(field.attributeName)
        : undefined;
      if (attributeNamedColumn && !table.uncertainColumns.has(field.attributeName)) {
        findings.push(sequelizeMismatchFinding(
          'contract/data-column-mapping-v1',
          `Sequelize field mapping differs from migration column: ${table.tableName}.${field.attributeName}`,
          `Sequelize attribute ${model.modelName}.${field.attributeName} maps to ${field.columnName}, while the literal migration contract declares ${field.attributeName} and does not declare the mapped column.`,
          table.tableName,
          field.columnName,
          'medium',
          'high',
          ['literal-sequelize-field-mapping-does-not-match-literal-migration-column'],
          field,
          [attributeNamedColumn],
          'literal-sequelize-migration-column',
          'Confirm the intended persisted column name, then align the Sequelize field option or migration declaration.'
        ));
      } else if (table.completeColumnSet && table.createAnchors.length === 1) {
        findings.push(sequelizeMismatchFinding(
          'contract/data-column-missing-v1',
          `Sequelize column is absent from migrations: ${table.tableName}.${field.columnName}`,
          `Sequelize attribute ${model.modelName}.${field.attributeName} maps to ${table.tableName}.${field.columnName}, but the complete ordered literal QueryInterface contract does not contain that column.`,
          table.tableName,
          field.columnName,
          'medium',
          'medium',
          ['literal-sequelize-model-column-without-literal-migration-column'],
          field,
          table.createAnchors,
          'literal-sequelize-migration-create-table',
          'Confirm the applied migration ledger, generated migrations, and out-of-band database changes before modifying the model or migration contract.'
        ));
      }
      continue;
    }
    if (field.family && migration.family && field.family !== migration.family) {
      findings.push(sequelizeMismatchFinding(
        'contract/data-type-family-v1',
        `Data type family differs: ${table.tableName}.${field.columnName}`,
        `Sequelize model ${model.modelName}.${field.attributeName} and the literal QueryInterface migration declare different broad type families for ${table.tableName}.${field.columnName}.`,
        table.tableName,
        field.columnName,
        'high',
        'high',
        ['literal-sequelize-model-and-migration-type-families-disagree'],
        field,
        [migration],
        'literal-sequelize-migration-column',
        'Confirm the active database dialect and applied migration state, then align the Sequelize type or migration column type.'
      ));
    }
    if (field.nullable !== undefined && migration.nullable !== undefined && field.nullable !== migration.nullable) {
      findings.push(sequelizeMismatchFinding(
        'contract/data-nullability-v1',
        `Nullability differs: ${table.tableName}.${field.columnName}`,
        `Sequelize model ${model.modelName}.${field.attributeName} and the literal QueryInterface migration declare different nullability for ${table.tableName}.${field.columnName}.`,
        table.tableName,
        field.columnName,
        'high',
        'high',
        ['literal-sequelize-model-and-migration-nullability-disagree'],
        field,
        [migration],
        'literal-sequelize-migration-column',
        'Confirm the deployed constraint and migration order, then align allowNull or the migration column definition.'
      ));
    }
    if (
      field.defaultSignature !== undefined && migration.defaultSignature !== undefined &&
      field.defaultSignature !== migration.defaultSignature
    ) {
      findings.push(sequelizeMismatchFinding(
        'contract/data-default-v1',
        `Literal default contract differs: ${table.tableName}.${field.columnName}`,
        `Sequelize model ${model.modelName}.${field.attributeName} and the literal QueryInterface migration declare different default semantics for ${table.tableName}.${field.columnName}; Atlas compared irreversible signatures and retained no default values.`,
        table.tableName,
        field.columnName,
        'medium',
        'high',
        ['hashed-literal-sequelize-default-signatures-disagree'],
        field,
        [migration],
        'literal-sequelize-migration-column',
        'Inspect the source-located defaults and deployed database default, then align them if the difference is not intentional.'
      ));
    }
    if (
      field.enumSignature !== undefined && migration.enumSignature !== undefined &&
      field.enumSignature !== migration.enumSignature
    ) {
      findings.push(sequelizeMismatchFinding(
        'contract/data-enum-v1',
        `Literal ENUM contract differs: ${table.tableName}.${field.columnName}`,
        `Sequelize model ${model.modelName}.${field.attributeName} and the literal QueryInterface migration declare different ENUM member sets for ${table.tableName}.${field.columnName}; Atlas compared irreversible signatures and retained no member values.`,
        table.tableName,
        field.columnName,
        'high',
        'high',
        ['hashed-literal-sequelize-enum-signatures-disagree'],
        field,
        [migration],
        'literal-sequelize-migration-column',
        'Inspect the source-located enum declarations and deployed database type, then reconcile the allowed member set.'
      ));
    }
  }
  return findings;
}

function compareSequelizeModelWithSql(model: SequelizeModel, table: SqlTable): FindingRecord[] {
  if (table.uncertainTable) return [];
  const findings: FindingRecord[] = [];
  for (const field of model.fields) {
    if (table.uncertainColumns.has(field.columnName)) continue;
    const columns = table.columns.get(field.columnName) ?? [];
    if (columns.length === 0) {
      const attributeNamedColumns = field.attributeName !== field.columnName
        ? table.columns.get(field.attributeName) ?? []
        : [];
      if (attributeNamedColumns.length === 1 && !table.uncertainColumns.has(field.attributeName)) {
        findings.push(sequelizeMismatchFinding(
          'contract/data-column-mapping-v1',
          `Sequelize field mapping differs from SQL column: ${table.tableName}.${field.attributeName}`,
          `Sequelize attribute ${model.modelName}.${field.attributeName} maps to ${field.columnName}, while literal SQL declares ${field.attributeName} and does not declare the mapped column.`,
          table.tableName,
          field.columnName,
          'medium',
          'high',
          ['literal-sequelize-field-mapping-does-not-match-literal-sql-column'],
          field,
          attributeNamedColumns,
          'literal-sql-table-or-column-declaration',
          'Confirm the intended persisted column name, then align the Sequelize field option or SQL declaration.'
        ));
      } else if (table.createAnchors.length === 1 && !table.incompleteColumnSet) {
        findings.push(sequelizeMismatchFinding(
          'contract/data-column-missing-v1',
          `Sequelize column is absent from SQL: ${table.tableName}.${field.columnName}`,
          `Sequelize attribute ${model.modelName}.${field.attributeName} maps to ${table.tableName}.${field.columnName}, but the complete literal CREATE TABLE declaration does not declare that column.`,
          table.tableName,
          field.columnName,
          'medium',
          'medium',
          ['literal-sequelize-model-column-without-literal-sql-column'],
          field,
          table.createAnchors,
          'literal-sql-table-or-column-declaration',
          'Confirm migration ordering, generated migrations, and the deployed database definition before changing either contract.'
        ));
      }
      continue;
    }
    const sql = columns[0]!;
    if (field.family && sql.family && field.family !== sql.family) {
      findings.push(sequelizeMismatchFinding(
        'contract/data-type-family-v1',
        `Data type family differs: ${table.tableName}.${field.columnName}`,
        `Sequelize model ${model.modelName}.${field.attributeName} and literal SQL declare different broad type families for ${table.tableName}.${field.columnName}.`,
        table.tableName,
        field.columnName,
        'high',
        'high',
        ['literal-sequelize-model-and-sql-type-families-disagree'],
        field,
        [sql],
        'literal-sql-table-or-column-declaration',
        'Confirm the active database dialect and deployed schema, then align the Sequelize type or SQL column type.'
      ));
    }
    if (field.nullable !== undefined && field.nullable !== sql.nullable) {
      findings.push(sequelizeMismatchFinding(
        'contract/data-nullability-v1',
        `Nullability differs: ${table.tableName}.${field.columnName}`,
        `Sequelize model ${model.modelName}.${field.attributeName} and literal SQL declare different nullability for ${table.tableName}.${field.columnName}.`,
        table.tableName,
        field.columnName,
        'high',
        'high',
        ['literal-sequelize-model-and-sql-nullability-disagree'],
        field,
        [sql],
        'literal-sql-table-or-column-declaration',
        'Confirm the deployed constraint, then align Sequelize allowNull or the SQL NULL/NOT NULL constraint.'
      ));
    }
  }
  return findings;
}

function compareSequelizeMigrationWithSql(
  migration: SequelizeMigrationTable,
  sql: SqlTable
): FindingRecord[] {
  if (migration.uncertainTable || sql.uncertainTable) return [];
  const findings: FindingRecord[] = [];
  for (const [columnName, migrationColumn] of migration.columns) {
    if (migration.uncertainColumns.has(columnName) || sql.uncertainColumns.has(columnName)) continue;
    const sqlColumns = sql.columns.get(columnName) ?? [];
    if (sqlColumns.length !== 1) continue;
    const sqlColumn = sqlColumns[0]!;
    if (
      migrationColumn.enumSignature === undefined || sqlColumn.enumSignature === undefined ||
      migrationColumn.enumSignature === sqlColumn.enumSignature
    ) continue;
    const ruleId = 'contract/data-provisioning-path-enum-v1';
    const anchors: Anchor[] = [migrationColumn, sqlColumn];
    findings.push({
      schemaVersion: SCHEMA_VERSION,
      id: findingId(ruleId, migration.tableName, columnName, anchors),
      category: 'contract-mismatch',
      ruleId,
      subject: {
        kind: 'data-contract',
        table: migration.tableName,
        column: columnName,
        dimension: 'enum-members',
        comparison: 'provisioning-path',
        migration: 'sequelize-migration',
        bootstrap: 'sql-bootstrap'
      },
      status: 'candidate',
      severity: 'low',
      confidence: 'medium',
      title: `Provisioning paths constrain ENUM membership differently: ${migration.tableName}.${columnName}`,
      description: `The ordered QueryInterface migration contract and literal bootstrap SQL describe different enum/check constraints for ${migration.tableName}.${columnName}. This is provisioning-path drift; it is independent from the application-model-to-storage contract. Atlas compared irreversible signatures and retained no member values.`,
      path: migrationColumn.file.record.path,
      relatedPaths: relatedPaths([sqlColumn]),
      signals: [
        'hashed-literal-provisioning-enum-signatures-disagree',
        'migration-and-bootstrap-paths-analyzed-independently'
      ],
      evidence: [
        evidence(migrationColumn, 'literal-sequelize-migration-column'),
        evidence(sqlColumn, 'literal-sql-table-or-column-declaration')
      ],
      nextValidation: 'Determine which provisioning path created each deployed database, then reconcile the migration and bootstrap constraints without inferring deployed state from source alone.'
    });
  }
  return findings;
}

function compareSequelizeContracts(
  models: SequelizeModel[],
  migrations: SequelizeMigrationResult,
  sqlTables: Map<string, SqlTable>,
  state: ParseState
): FindingRecord[] {
  const findings: FindingRecord[] = [];
  const modelsByTable = new Map<string, SequelizeModel[]>();
  for (const model of models) {
    const values = modelsByTable.get(model.tableName) ?? [];
    values.push(model);
    modelsByTable.set(model.tableName, values);
  }
  if (!migrations.globalUncertainty) {
    for (const [tableName, migrationTable] of migrations.tables) {
      const sqlTable = sqlTables.get(tableName);
      if (sqlTable) findings.push(...compareSequelizeMigrationWithSql(migrationTable, sqlTable));
    }
  }
  for (const [tableName, mappedModels] of modelsByTable) {
    if (mappedModels.length !== 1) {
      const first = [...mappedModels].sort((left, right) =>
        compareCanonicalText(left.file.record.path, right.file.record.path) || left.location.line - right.location.line
      )[0]!;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_AMBIGUOUS_SEQUELIZE_TABLE',
        'warning',
        `Multiple Sequelize models map to ${tableName}; Atlas suppressed comparisons for that table.`,
        first,
        'duplicate-sequelize-table-mapping',
        { tableName, modelCount: mappedModels.length }
      ));
      continue;
    }
    const model = mappedModels[0]!;
    if (migrations.globalUncertainty) continue;
    const migrationTable = migrations.tables.get(tableName);
    const sqlTable = sqlTables.get(tableName);
    if (migrationTable) {
      if (sqlTable) {
        state.diagnostics.push(diagnostic(
          'DATA_CONTRACT_MULTIPLE_STORAGE_SOURCES',
          'info',
          `Both QueryInterface migrations and raw SQL describe ${tableName}; Atlas compared the application model with the ordered migration contract and analyzed migration-versus-bootstrap drift separately.`,
          model,
          'independent-model-storage-and-provisioning-path-comparisons',
          { tableName }
        ));
      }
      findings.push(...compareSequelizeModelWithMigration(model, migrationTable));
    } else if (sqlTable) {
      findings.push(...compareSequelizeModelWithSql(model, sqlTable));
    } else {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_TABLE_MAPPING_UNRESOLVED',
        'info',
        `No exact literal QueryInterface migration or SQL table declaration matched Sequelize model ${model.modelName} (${tableName}); Atlas made no mismatch claim.`,
        model,
        'unresolved-exact-sequelize-table-mapping',
        { modelName: model.modelName, tableName }
      ));
    }
  }
  return findings;
}

export function detectDataContractMismatches(
  files: AnalysisFile[]
): { findings: FindingRecord[]; diagnostics: DiagnosticRecord[] } {
  const state: ParseState = { diagnostics: [], sequelizeLimitationPaths: new Set() };
  const orderedFiles = [...files].sort((left, right) => compareCanonicalText(left.record.path, right.record.path));
  const prismaFiles = orderedFiles.filter((file) => file.record.language === 'prisma' || file.record.path.toLowerCase().endsWith('.prisma'));
  const sqlFiles = orderedFiles.filter((file) => file.record.language === 'sql' || file.record.path.toLowerCase().endsWith('.sql'));
  const javascriptFiles = orderedFiles.filter((file) => JAVASCRIPT_LANGUAGES.has(file.record.language));
  const models = prismaFiles.flatMap((file) => parsePrismaFile(file, state));
  const tables = parseSqlFiles(sqlFiles, state);
  const sequelizeModels = parseSequelizeModels(javascriptFiles, state);
  const sequelizeMigrations = parseSequelizeMigrations(javascriptFiles, state);
  const findings: FindingRecord[] = compareSequelizeContracts(sequelizeModels, sequelizeMigrations, tables, state);

  const modelsByTable = new Map<string, PrismaModel[]>();
  for (const model of models) {
    const values = modelsByTable.get(model.tableName) ?? [];
    values.push(model);
    modelsByTable.set(model.tableName, values);
  }
  for (const [tableName, mappedModels] of modelsByTable) {
    if (mappedModels.length > 1) {
      const first = [...mappedModels].sort((left, right) => compareCanonicalText(left.file.record.path, right.file.record.path))[0]!;
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_AMBIGUOUS_PRISMA_TABLE',
        'warning',
        `Multiple Prisma models map to ${tableName}; Atlas suppressed comparisons for that table.`,
        first,
        'duplicate-prisma-table-mapping',
        tableName
      ));
      continue;
    }
    const model = mappedModels[0]!;
    const table = tables.get(tableName);
    if (!table) {
      state.diagnostics.push(diagnostic(
        'DATA_CONTRACT_TABLE_MAPPING_UNRESOLVED',
        'info',
        `No exact literal SQL table declaration matched Prisma model ${model.modelName} (${tableName}); Atlas made no mismatch claim.`,
        model,
        'unresolved-exact-table-mapping',
        { modelName: model.modelName, tableName }
      ));
      continue;
    }
    if (table.uncertainTable) continue;
    for (const field of model.fields) {
      if (table.uncertainColumns.has(field.columnName)) continue;
      const sqlColumns = table.columns.get(field.columnName) ?? [];
      if (sqlColumns.length === 0) {
        if (table.createAnchors.length !== 1 || table.incompleteColumnSet) continue;
        findings.push(mismatchFinding(
          'contract/data-column-missing-v1',
          `Prisma column is absent from SQL: ${tableName}.${field.columnName}`,
          `Prisma field ${model.modelName}.${field.fieldName} maps to ${tableName}.${field.columnName}, but the complete literal CREATE TABLE declaration does not declare that column.`,
          tableName,
          field.columnName,
          'medium',
          'medium',
          ['literal-prisma-column-without-literal-sql-column'],
          field,
          table.createAnchors,
          'Confirm migration ordering, generated migrations, database views, schema selection, and the deployed database definition before changing either contract.'
        ));
        continue;
      }
      const sql = sqlColumns[0]!;
      if (!sql.family) continue;
      if (field.family !== sql.family) {
        findings.push(mismatchFinding(
          'contract/data-type-family-v1',
          `Data type family differs: ${tableName}.${field.columnName}`,
          `Prisma declares ${model.modelName}.${field.fieldName} as ${field.family}, while SQL declares ${tableName}.${field.columnName} as ${sql.family}.`,
          tableName,
          field.columnName,
          'high',
          'high',
          ['literal-prisma-and-sql-type-families-disagree'],
          field,
          [sql],
          'Confirm the active database dialect and migration state, then align the Prisma scalar/native type or SQL column type.'
        ));
      }
      if (field.nullable !== sql.nullable) {
        findings.push(mismatchFinding(
          'contract/data-nullability-v1',
          `Nullability differs: ${tableName}.${field.columnName}`,
          `Prisma declares ${model.modelName}.${field.fieldName} as ${field.nullable ? 'nullable' : 'required'}, while SQL declares ${tableName}.${field.columnName} as ${sql.nullable ? 'nullable' : 'NOT NULL'}.`,
          tableName,
          field.columnName,
          'high',
          'high',
          ['literal-prisma-and-sql-nullability-disagree'],
          field,
          [sql],
          'Confirm the deployed constraint and migration order, then align Prisma optionality or the SQL NULL/NOT NULL constraint.'
        ));
      }
    }
  }

  const uniqueFindings = [...new Map(findings.map((finding) => [finding.id, finding])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  const uniqueDiagnostics = [...new Map(state.diagnostics.map((entry) => [entry.id, entry])).values()]
    .sort((left, right) => compareCanonicalText(left.id, right.id));
  return { findings: uniqueFindings, diagnostics: uniqueDiagnostics };
}
