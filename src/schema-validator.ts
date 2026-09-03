import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import * as formatsModule from 'ajv-formats';
import { AtlasError } from './errors.js';
import { compareCanonicalText } from './util/canonical.js';

const SCHEMA_BASE = 'https://atlas.local/schemas/v1/';
const schemaDirectory = fileURLToPath(new URL('../../schemas/v1/', import.meta.url));
const addFormats = formatsModule.default as unknown as (ajv: Ajv2020) => Ajv2020;

let validatorPromise: Promise<Ajv2020> | undefined;

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  if (!errors?.length) return 'unknown schema error';
  return errors
    .map((error) => `${error.instancePath || '/'} ${error.message ?? error.keyword}`)
    .join('; ');
}

async function loadValidators(): Promise<Ajv2020> {
  if (!validatorPromise) {
    validatorPromise = (async () => {
      const ajv = new Ajv2020({ allErrors: true, strict: true });
      addFormats(ajv);
      const names = (await readdir(schemaDirectory))
        .filter((name) => name.endsWith('.schema.json'))
        .sort(compareCanonicalText);
      for (const name of names) {
        const schema = JSON.parse(await readFile(new URL(`../../schemas/v1/${name}`, import.meta.url), 'utf8')) as object;
        ajv.addSchema(schema);
      }
      return ajv;
    })();
  }
  return validatorPromise;
}

export async function schemaValidator(schemaName: string): Promise<ValidateFunction> {
  const ajv = await loadValidators();
  const validator = ajv.getSchema(`${SCHEMA_BASE}${schemaName}.schema.json`);
  if (!validator) throw new AtlasError('SCHEMA_NOT_FOUND', `No bundled Atlas schema named ${schemaName}.`);
  return validator;
}

export async function assertSchema(schemaName: string, value: unknown, label = schemaName): Promise<void> {
  const validator = await schemaValidator(schemaName);
  if (!validator(value)) {
    throw new AtlasError('SCHEMA_VALIDATION', `${label} failed schema validation: ${formatErrors(validator.errors)}`);
  }
}
