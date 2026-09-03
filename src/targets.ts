import { randomUUID } from 'node:crypto';
import { access, lstat, mkdir, readdir, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { AtlasError } from './errors.js';
import { assertSchema } from './schema-validator.js';
import type { TargetConfig, TargetConsent, TargetRegistration } from './types.js';
import { SCHEMA_VERSION } from './types.js';
import { canonicalJson, compareCanonicalText, readJson, writeCanonicalJson } from './util/canonical.js';
import { isInside, resolveForContainment } from './util/paths.js';

const REGISTRATION_FILE = 'registration.json';

async function exists(value: string): Promise<boolean> {
  try { await access(value); return true; } catch { return false; }
}

function samePath(left: string, right: string): boolean {
  return path.relative(path.resolve(left), path.resolve(right)) === '';
}

function assertSinglyLinkedDescriptor(metadata: Awaited<ReturnType<typeof lstat>>): void {
  if (metadata.nlink !== 1) {
    throw new AtlasError(
      'TARGET_DESCRIPTOR_MULTIPLE_LINKS',
      'Target descriptors must have exactly one filesystem link so target-controlled aliases cannot alter consent.'
    );
  }
}

export function assertTargetDescriptorSeparated(
  targetConfigPath: string,
  targetRoot: string
): void {
  if (isInside(targetRoot, targetConfigPath)) {
    throw new AtlasError(
      'TARGET_DESCRIPTOR_INSIDE_TARGET',
      'Target descriptors contain operator consent and must be stored outside the configured untrusted target root.'
    );
  }
}

export async function resolveTargetDescriptor(targetConfigPathValue: string): Promise<{
  target: TargetConfig;
  targetConfigPath: string;
  targetRoot: string;
}> {
  const requestedPath = path.resolve(targetConfigPathValue);
  const requestedMetadata = await lstat(requestedPath);
  if (!requestedMetadata.isFile() || requestedMetadata.isSymbolicLink()) {
    throw new AtlasError('INVALID_CONFIG', 'Target descriptor must be a regular file, not a link.');
  }
  assertSinglyLinkedDescriptor(requestedMetadata);
  const targetConfigPath = await realpath(requestedPath);
  const configMetadata = await lstat(targetConfigPath);
  if (!configMetadata.isFile() || configMetadata.isSymbolicLink()) {
    throw new AtlasError('INVALID_CONFIG', 'Target descriptor must be a regular file, not a link.');
  }
  assertSinglyLinkedDescriptor(configMetadata);
  const rawTarget = await readJson<unknown>(targetConfigPath);
  await assertSchema('target', rawTarget, 'Target configuration');
  const target = rawTarget as TargetConfig;
  const configuredTargetPath = path.isAbsolute(target.path)
    ? target.path
    : path.resolve(path.dirname(targetConfigPath), target.path);
  const targetRoot = await realpath(configuredTargetPath);
  const targetMetadata = await lstat(targetRoot);
  if (!targetMetadata.isDirectory() || targetMetadata.isSymbolicLink()) {
    throw new AtlasError('INVALID_CONFIG', 'Target path must resolve to a real directory.');
  }
  assertTargetDescriptorSeparated(requestedPath, targetRoot);
  assertTargetDescriptorSeparated(targetConfigPath, targetRoot);
  return { target, targetConfigPath, targetRoot };
}

/** Resolves a descriptor file to its checkout while retaining directory inputs for compatibility. */
export async function resolveTargetRootInput(targetValue: string): Promise<string> {
  const requestedPath = path.resolve(targetValue);
  let metadata: Awaited<ReturnType<typeof lstat>>;
  try {
    metadata = await lstat(requestedPath);
  } catch {
    return requestedPath;
  }
  if (metadata.isFile() && !metadata.isSymbolicLink()) {
    return (await resolveTargetDescriptor(requestedPath)).targetRoot;
  }
  return requestedPath;
}

async function targetRegistryRoot(workspacePath: string): Promise<string> {
  const result = await resolveForContainment(path.join(workspacePath, 'targets'));
  if (!isInside(workspacePath, result)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Target registry resolves outside the selected workspace.');
  }
  return result;
}

async function readRegistrationDirectory(directory: string): Promise<TargetRegistration> {
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new AtlasError('TARGET_REGISTRATION_INVALID', 'Target registration path must be a real directory.');
  }
  const entries = await readdir(directory, { withFileTypes: true });
  if (
    entries.length !== 1 || entries[0]?.name !== REGISTRATION_FILE ||
    !entries[0].isFile() || entries[0].isSymbolicLink()
  ) {
    throw new AtlasError('TARGET_REGISTRATION_INVALID', 'Target registration directory has an invalid artifact set.');
  }
  const registration = await readJson<TargetRegistration>(path.join(directory, REGISTRATION_FILE));
  await assertSchema('target-registration', registration, 'Target registration');
  if (!path.isAbsolute(registration.targetRoot) || !path.isAbsolute(registration.targetConfigPath)) {
    throw new AtlasError('TARGET_REGISTRATION_INVALID', 'Target registration paths must be absolute local paths.');
  }
  return registration;
}

export async function registerTarget(options: {
  targetConfigPath: string;
  workspacePath: string;
}): Promise<{ registration: TargetRegistration; directory: string; reused: boolean }> {
  const workspacePath = await resolveForContainment(options.workspacePath);
  const descriptor = await resolveTargetDescriptor(options.targetConfigPath);
  if (isInside(descriptor.targetRoot, workspacePath)) {
    throw new AtlasError('WORKSPACE_INSIDE_TARGET', 'Atlas workspace must be outside the target repository.');
  }
  const registration: TargetRegistration = {
    schemaVersion: SCHEMA_VERSION,
    targetId: descriptor.target.id,
    targetRoot: descriptor.targetRoot,
    targetConfigPath: descriptor.targetConfigPath,
    consent: descriptor.target.consent
  };
  await assertSchema('target-registration', registration, 'Target registration');
  const registryRoot = await targetRegistryRoot(workspacePath);
  const directory = path.join(registryRoot, registration.targetId);
  if (!isInside(registryRoot, directory)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Target registration ID resolves outside the registry.');
  }
  if (await exists(directory)) {
    const existing = await readRegistrationDirectory(directory);
    if (canonicalJson(existing) !== canonicalJson(registration)) {
      throw new AtlasError(
        'TARGET_REGISTRATION_CONFLICT',
        `Target ID ${registration.targetId} is already bound to a different root or descriptor in this workspace.`
      );
    }
    return { registration: existing, directory, reused: true };
  }
  await mkdir(registryRoot, { recursive: true });
  const temporaryDirectory = path.join(registryRoot, `.tmp-${registration.targetId}-${randomUUID()}`);
  if (!isInside(registryRoot, temporaryDirectory)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Temporary target registration resolves outside the registry.');
  }
  await mkdir(temporaryDirectory, { recursive: false });
  try {
    await writeCanonicalJson(path.join(temporaryDirectory, REGISTRATION_FILE), registration);
    await readRegistrationDirectory(temporaryDirectory);
    await rename(temporaryDirectory, directory);
  } catch (error) {
    if (await exists(temporaryDirectory)) await rm(temporaryDirectory, { recursive: true, force: true });
    if (await exists(directory)) {
      const existing = await readRegistrationDirectory(directory);
      if (canonicalJson(existing) === canonicalJson(registration)) {
        return { registration: existing, directory, reused: true };
      }
    }
    throw error;
  }
  return { registration, directory, reused: false };
}

export async function loadTargetRegistration(
  workspacePathValue: string,
  targetId: string
): Promise<TargetRegistration> {
  const workspacePath = await resolveForContainment(workspacePathValue);
  const registryRoot = await targetRegistryRoot(workspacePath);
  const directory = path.join(registryRoot, targetId);
  if (!isInside(registryRoot, directory)) {
    throw new AtlasError('WORKSPACE_PATH_ESCAPE', 'Target registration ID resolves outside the registry.');
  }
  const registration = await readRegistrationDirectory(directory);
  if (registration.targetId !== targetId) {
    throw new AtlasError('TARGET_REGISTRATION_INVALID', 'Target registration directory and target ID differ.');
  }
  return registration;
}

export async function listTargetRegistrations(workspacePathValue: string): Promise<TargetRegistration[]> {
  const workspacePath = await resolveForContainment(workspacePathValue);
  const registryRoot = await targetRegistryRoot(workspacePath);
  if (!await exists(registryRoot)) return [];
  const entries = await readdir(registryRoot, { withFileTypes: true });
  entries.sort((left, right) => compareCanonicalText(left.name, right.name));
  const registrations: TargetRegistration[] = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.tmp-')) {
      throw new AtlasError('TARGET_REGISTRATION_INVALID', `Incomplete target registration remains: ${entry.name}`);
    }
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      throw new AtlasError('TARGET_REGISTRATION_INVALID', `Invalid target registry entry: ${entry.name}`);
    }
    const registration = await readRegistrationDirectory(path.join(registryRoot, entry.name));
    if (registration.targetId !== entry.name) {
      throw new AtlasError('TARGET_REGISTRATION_INVALID', `Target registry directory and ID differ: ${entry.name}`);
    }
    registrations.push(registration);
  }
  return registrations;
}

export async function verifyTargetRegistrationBinding(options: {
  workspacePath: string;
  targetId: string;
  targetRoot: string;
  targetConfigPath: string;
  consent: TargetConsent;
}): Promise<TargetRegistration> {
  const registration = await loadTargetRegistration(options.workspacePath, options.targetId);
  assertTargetDescriptorSeparated(registration.targetConfigPath, registration.targetRoot);
  const [targetRoot, targetConfigPath] = await Promise.all([
    realpath(options.targetRoot),
    realpath(options.targetConfigPath)
  ]);
  if (!samePath(registration.targetRoot, targetRoot) || !samePath(registration.targetConfigPath, targetConfigPath)) {
    throw new AtlasError('TARGET_REGISTRATION_CONFLICT', 'Target operation does not match the workspace target registration.');
  }
  const descriptorMetadata = await lstat(targetConfigPath);
  if (!descriptorMetadata.isFile() || descriptorMetadata.isSymbolicLink()) {
    throw new AtlasError('TARGET_REGISTRATION_CONFLICT', 'The registered target descriptor must remain a regular file.');
  }
  assertSinglyLinkedDescriptor(descriptorMetadata);
  const escalation = (['agentReview', 'export', 'projectMemory'] as const)
    .find((permission) => options.consent[permission] && !registration.consent[permission]);
  if (escalation) {
    throw new AtlasError(
      'TARGET_CONSENT_ESCALATION',
      `Target consent.${escalation} cannot be enabled beyond the permissions captured at registration.`
    );
  }
  return registration;
}
