import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { lstat, mkdir, readdir, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { z } from 'zod';
import { hasOwnedPrefix, samePath } from './state-migration.js';
import { BridgeError } from './types.js';

const execFileAsync = promisify(execFile);

export const WORKSPACES_DIR_NAME = 'workspaces';
export const TASK_ARCHIVES_DIR_NAME = 'task-archives';
export const WORKSPACE_META_FILE_NAME = 'workspace.json';

const ROOT_KEY_RE = /^[a-f0-9]{32}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;

export interface CanonicalWorkspacePaths {
  stateDirectory: string;
  rootKey: string;
  workspaceDirectory: string;
  copyDirectory: string;
  gitDirectory: string;
  metadataPath: string;
}

const NAMED_CAPABILITY_SID_RE = /^S-1-15-3-1024(?:-\d+){8}$/;

const windowsLpacStateSchema = z.object({
  version: z.literal(1),
  initializedAt: z.string().datetime(),
  dev: z.string().min(1),
  ino: z.string().min(1),
  birthtimeNs: z.string().min(1),
  daclSha256: z.string().regex(SHA256_RE),
  capabilityNonce: z.string().uuid().optional(),
  readCapabilitySid: z.string().regex(NAMED_CAPABILITY_SID_RE).optional(),
  modifyCapabilitySid: z.string().regex(NAMED_CAPABILITY_SID_RE).optional(),
  volume: z.number().int().nonnegative().optional(),
  fileIndexHigh: z.number().int().nonnegative().optional(),
  fileIndexLow: z.number().int().nonnegative().optional(),
  nativeDaclSha256: z.string().regex(SHA256_RE).optional(),
}).strict();

export type WindowsLpacState = z.infer<typeof windowsLpacStateSchema>;

const workspaceMetadataSchema = z.object({
  version: z.literal(1),
  sourceDirectory: z.string().min(1),
  rootKey: z.string().regex(ROOT_KEY_RE),
  currentTaskId: z.string().uuid().optional(),
  currentLineageId: z.string().uuid().optional(),
  fencedAt: z.string().datetime().optional(),
  fencedReason: z.enum(['prepare', 'restore']).optional(),
  updatedAt: z.string().datetime(),
  lastPreparedDurationMs: z.number().nonnegative().optional(),
  windowsLpac: windowsLpacStateSchema.optional(),
}).strict();

export type WorkspaceMetadata = z.infer<typeof workspaceMetadataSchema>;

export type IcaclsRunner = (args: string[]) => Promise<{ stdout: string; stderr: string }>;

const defaultIcaclsRunner: IcaclsRunner = async (args: string[]) => {
  const icacls = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe');
  const result = await execFileAsync(icacls, args, { windowsHide: true, timeout: 10000, maxBuffer: 65536 });
  return { stdout: String(result.stdout ?? ''), stderr: String(result.stderr ?? '') };
};

export function copyIdentity(directory: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === 'win32') {
    const backslash = directory.replaceAll('/', '\\');
    const stripped = backslash
      .replace(/^(?:\\\\[?.]|\\\?\?)\\UNC\\/i, '\\\\')
      .replace(/^(?:\\\\[?.]|\\\?\?)\\(?=[A-Za-z]:)/, '');
    return path.win32.resolve(stripped).toLowerCase();
  }
  return path.posix.resolve(directory);
}

export function workspaceKey(canonicalSourceDirectory: string, platform: NodeJS.Platform = process.platform): string {
  return createHash('sha256').update(copyIdentity(canonicalSourceDirectory, platform)).digest('hex').slice(0, 32);
}

export function assertNoLinkAncestrySync(targetPath: string, stopAt?: string): void {
  const resolved = path.resolve(targetPath);
  const stop = stopAt ? path.resolve(stopAt) : undefined;
  let current = resolved;
  for (;;) {
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) {
        throw new BridgeError('UNSAFE_PROJECT_PATH', 'Refusing symbolic link in private workspace path');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (stop && samePath(current, stop)) break;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

export async function assertNoLinkAncestryAsync(targetPath: string, stopAt?: string): Promise<void> {
  const resolved = path.resolve(targetPath);
  const stop = stopAt ? path.resolve(stopAt) : undefined;
  let current = resolved;
  for (;;) {
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) {
        throw new BridgeError('UNSAFE_PROJECT_PATH', 'Refusing symbolic link in private workspace path');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (stop && samePath(current, stop)) break;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

export function canonicalWorkspacePaths(stateDirectory: string, canonicalSourceDirectory: string): CanonicalWorkspacePaths {
  if (!path.isAbsolute(stateDirectory) || !path.isAbsolute(canonicalSourceDirectory)) {
    throw new BridgeError('UNSAFE_PROJECT_PATH', 'Workspace and state directories must be absolute paths');
  }
  const canonicalState = realpathSync.native(stateDirectory);
  const rootKey = workspaceKey(canonicalSourceDirectory);
  const workspaceDirectory = path.join(canonicalState, WORKSPACES_DIR_NAME, rootKey);
  return {
    stateDirectory: canonicalState,
    rootKey,
    workspaceDirectory,
    copyDirectory: path.join(workspaceDirectory, 'copy'),
    gitDirectory: path.join(workspaceDirectory, 'baseline'),
    metadataPath: path.join(workspaceDirectory, WORKSPACE_META_FILE_NAME),
  };
}

export function isLegacyTempCopyPath(directory: string, kind: 'copy' | 'baseline'): boolean {
  if (!path.isAbsolute(directory)) return false;
  const dirParent = path.dirname(directory);
  const base = path.basename(directory);
  if (!hasOwnedPrefix(base, kind)) return false;
  if (path.relative(os.tmpdir(), dirParent) === '') return true;
  try {
    return path.relative(realpathSync.native(os.tmpdir()), realpathSync.native(dirParent)) === '';
  } catch {
    return false;
  }
}

export function isOwnedWorkspacePath(
  directory: string,
  kind: 'copy' | 'baseline',
  stateDirectories: readonly string[],
  expectedSourceDirectory?: string,
): boolean {
  if (!path.isAbsolute(directory)) return false;
  const resolved = path.resolve(directory);
  if (path.basename(resolved) !== kind) return false;
  const workspaceDir = path.dirname(resolved);
  const key = path.basename(workspaceDir);
  if (!ROOT_KEY_RE.test(key)) return false;
  if (expectedSourceDirectory && workspaceKey(expectedSourceDirectory) !== key) return false;
  const workspacesParent = path.dirname(workspaceDir);
  if (path.basename(workspacesParent) !== WORKSPACES_DIR_NAME) return false;
  const stateRoot = path.dirname(workspacesParent);
  return stateDirectories.some(candidate => {
    if (!candidate || !path.isAbsolute(candidate)) return false;
    if (samePath(stateRoot, candidate)) return true;
    try {
      return samePath(realpathSync.native(stateRoot), realpathSync.native(candidate));
    } catch {
      return false;
    }
  });
}

export function readWorkspaceMetadata(metadataPath: string): WorkspaceMetadata | undefined {
  let info;
  try {
    info = lstatSync(metadataPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw new BridgeError('INVALID_STATE', 'Unreadable workspace metadata');
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size > 1_000_000) {
    throw new BridgeError('INVALID_STATE', 'Unsafe workspace metadata file');
  }
  try {
    return workspaceMetadataSchema.parse(JSON.parse(readFileSync(metadataPath, 'utf8')));
  } catch {
    throw new BridgeError('INVALID_STATE', 'Corrupted workspace metadata');
  }
}

export function writeWorkspaceMetadata(metadataPath: string, metadata: WorkspaceMetadata): void {
  const validated = workspaceMetadataSchema.parse(metadata);
  const dir = path.dirname(metadataPath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertNoLinkAncestrySync(metadataPath, dir);
  const temp = `${metadataPath}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temp, JSON.stringify(validated) + '\n', { flag: 'wx', mode: 0o600, flush: true });
    renameSync(temp, metadataPath);
  } finally {
    rmSync(temp, { force: true });
  }
}

export function invalidateWorkspaceOccupant(
  workspace: CanonicalWorkspacePaths,
  sourceDirectory: string,
  reason: 'prepare' | 'restore',
): void {
  const existing = readWorkspaceMetadata(workspace.metadataPath);
  if (!existing && !existsSync(workspace.copyDirectory) && !existsSync(workspace.gitDirectory)) {
    return;
  }
  writeWorkspaceMetadata(workspace.metadataPath, {
    version: 1,
    sourceDirectory: existing?.sourceDirectory ?? sourceDirectory,
    rootKey: workspace.rootKey,
    fencedAt: new Date().toISOString(),
    fencedReason: reason,
    updatedAt: new Date().toISOString(),
    ...(existing?.lastPreparedDurationMs !== undefined ? { lastPreparedDurationMs: existing.lastPreparedDurationMs } : {}),
    ...(existing?.windowsLpac ? { windowsLpac: existing.windowsLpac } : {}),
  });
}

export function normalizeIcaclsDacl(stdout: string, folderPath: string): { digest: string; hasLingeringAppContainer: boolean } {
  const escaped = folderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const prefixRe = new RegExp(`^${escaped}\\s*`, 'i');
  const lines = stdout
    .split(/\r?\n/)
    .map(line => line.replace(prefixRe, '').trim())
    .filter(line => line.length > 0 && !/^Successfully processed \d+ files/i.test(line));
  const hasLingeringAppContainer = lines.some(line =>
    /S-1-15-2-\d/i.test(line) ||
    /APPLICATION PACKAGE AUTHORITY\\(?:black-gravity\.test\.|agy\.test\.|ALL APPLICATION PACKAGES|ALL RESTRICTED APPLICATION PACKAGES)/i.test(line),
  );
  const canonical = lines.map(line => line.toLowerCase()).sort().join('\n');
  return {
    digest: createHash('sha256').update(canonical, 'utf8').digest('hex'),
    hasLingeringAppContainer,
  };
}

export interface NativeWorkspaceLpacPin {
  capabilityNonce: string;
  readCapabilitySid: string;
  modifyCapabilitySid: string;
  volume: number;
  fileIndexHigh: number;
  fileIndexLow: number;
  nativeDaclSha256: string;
}

export async function recordNativeWorkspaceLpacPin(
  workspace: CanonicalWorkspacePaths,
  sourceDirectory: string,
  pin: NativeWorkspaceLpacPin,
  options?: { platform?: NodeJS.Platform; runIcacls?: IcaclsRunner },
): Promise<WindowsLpacState> {
  const platform = options?.platform ?? process.platform;
  if (platform !== 'win32') {
    throw new BridgeError('WINDOWS_EXECUTOR_UNAVAILABLE', 'Native Windows LPAC workspace pinning is only available on Windows');
  }
  const runner = options?.runIcacls ?? defaultIcaclsRunner;
  await assertNoLinkAncestryAsync(workspace.copyDirectory, workspace.stateDirectory);
  const stat = await lstat(workspace.copyDirectory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new BridgeError('UNSAFE_PROJECT_PATH', 'Fixed workspace directory was replaced or linked');
  }
  const existing = readWorkspaceMetadata(workspace.metadataPath);
  const { stdout } = await runner([workspace.copyDirectory]);
  const { digest, hasLingeringAppContainer } = normalizeIcaclsDacl(stdout, workspace.copyDirectory);
  if (hasLingeringAppContainer) {
    throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder has lingering or generic AppContainer ACEs');
  }
  const state: WindowsLpacState = windowsLpacStateSchema.parse({
    version: 1,
    initializedAt: new Date().toISOString(),
    dev: stat.dev.toString(),
    ino: stat.ino.toString(),
    birthtimeNs: stat.birthtimeNs.toString(),
    daclSha256: digest,
    capabilityNonce: pin.capabilityNonce,
    readCapabilitySid: pin.readCapabilitySid,
    modifyCapabilitySid: pin.modifyCapabilitySid,
    volume: pin.volume,
    fileIndexHigh: pin.fileIndexHigh,
    fileIndexLow: pin.fileIndexLow,
    nativeDaclSha256: pin.nativeDaclSha256,
  });
  writeWorkspaceMetadata(workspace.metadataPath, {
    version: 1,
    sourceDirectory: existing?.sourceDirectory ?? sourceDirectory,
    rootKey: workspace.rootKey,
    ...(existing?.currentTaskId ? { currentTaskId: existing.currentTaskId } : {}),
    ...(existing?.currentLineageId ? { currentLineageId: existing.currentLineageId } : {}),
    ...(existing?.fencedAt && existing?.fencedReason ? { fencedAt: existing.fencedAt, fencedReason: existing.fencedReason } : {}),
    ...(existing?.lastPreparedDurationMs !== undefined ? { lastPreparedDurationMs: existing.lastPreparedDurationMs } : {}),
    updatedAt: new Date().toISOString(),
    windowsLpac: state,
  });
  return state;
}

export async function ensureFixedWorkspaceLpacPermissions(
  workspace: CanonicalWorkspacePaths,
  sourceDirectory: string,
  options?: { platform?: NodeJS.Platform; runIcacls?: IcaclsRunner },
): Promise<WindowsLpacState | undefined> {
  const platform = options?.platform ?? process.platform;
  if (platform !== 'win32') return undefined;
  const runner = options?.runIcacls ?? defaultIcaclsRunner;

  await assertNoLinkAncestryAsync(workspace.copyDirectory, workspace.stateDirectory);
  const stat = await lstat(workspace.copyDirectory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new BridgeError('UNSAFE_PROJECT_PATH', 'Fixed workspace directory was replaced or linked');
  }
  const existing = readWorkspaceMetadata(workspace.metadataPath);
  const { stdout } = await runner([workspace.copyDirectory]);
  const { digest, hasLingeringAppContainer } = normalizeIcaclsDacl(stdout, workspace.copyDirectory);
  if (hasLingeringAppContainer) {
    throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder has lingering AppContainer ACEs; recover before reuse');
  }

  const dev = stat.dev.toString();
  const ino = stat.ino.toString();
  const birthtimeNs = stat.birthtimeNs.toString();

  if (existing?.windowsLpac) {
    const saved = existing.windowsLpac;
    if (saved.dev !== dev || saved.ino !== ino || saved.birthtimeNs !== birthtimeNs) {
      throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder identity changed since LPAC permission baseline was recorded');
    }
    if (saved.daclSha256 !== digest) {
      throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder DACL changed since LPAC permission baseline was recorded');
    }
    return saved;
  }

  const state: WindowsLpacState = {
    version: 1,
    initializedAt: new Date().toISOString(),
    dev,
    ino,
    birthtimeNs,
    daclSha256: digest,
  };
  writeWorkspaceMetadata(workspace.metadataPath, {
    version: 1,
    sourceDirectory: existing?.sourceDirectory ?? sourceDirectory,
    rootKey: workspace.rootKey,
    ...(existing?.currentTaskId ? { currentTaskId: existing.currentTaskId } : {}),
    ...(existing?.currentLineageId ? { currentLineageId: existing.currentLineageId } : {}),
    ...(existing?.fencedAt && existing?.fencedReason ? { fencedAt: existing.fencedAt, fencedReason: existing.fencedReason } : {}),
    ...(existing?.lastPreparedDurationMs !== undefined ? { lastPreparedDurationMs: existing.lastPreparedDurationMs } : {}),
    updatedAt: new Date().toISOString(),
    windowsLpac: state,
  });
  return state;
}

export async function verifyFixedWorkspaceLpacPermissions(
  copyDirectory: string,
  stateDirectory: string,
  options?: { platform?: NodeJS.Platform; runIcacls?: IcaclsRunner },
): Promise<void> {
  const platform = options?.platform ?? process.platform;
  if (platform !== 'win32') return;
  const canonicalState = await realpath(stateDirectory);
  if (!isOwnedWorkspacePath(copyDirectory, 'copy', [canonicalState])) return;
  const workspaceDir = path.dirname(path.resolve(copyDirectory));
  const metadataPath = path.join(workspaceDir, WORKSPACE_META_FILE_NAME);
  const existing = readWorkspaceMetadata(metadataPath);
  if (!existing?.windowsLpac) {
    throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder has no verified LPAC permission baseline');
  }
  const runner = options?.runIcacls ?? defaultIcaclsRunner;
  await assertNoLinkAncestryAsync(copyDirectory, canonicalState);
  const stat = await lstat(copyDirectory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new BridgeError('UNSAFE_PROJECT_PATH', 'Fixed workspace directory was replaced or linked');
  }
  const { stdout } = await runner([copyDirectory]);
  const { digest, hasLingeringAppContainer } = normalizeIcaclsDacl(stdout, copyDirectory);
  if (hasLingeringAppContainer) {
    throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder has lingering AppContainer ACEs');
  }
  if (
    existing.windowsLpac.dev !== stat.dev.toString() ||
    existing.windowsLpac.ino !== stat.ino.toString() ||
    existing.windowsLpac.birthtimeNs !== stat.birthtimeNs.toString() ||
    existing.windowsLpac.daclSha256 !== digest
  ) {
    throw new BridgeError('WINDOWS_LPAC_PERMISSIONS_INVALID', 'Fixed workspace folder identity or DACL no longer matches its verified LPAC baseline');
  }
}

export async function emptyDirectoryContents(directory: string, stopAncestryAt?: string): Promise<void> {
  await assertNoLinkAncestryAsync(directory, stopAncestryAt);
  const info = await lstat(directory).catch(error => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  });
  if (!info) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    return;
  }
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new BridgeError('UNSAFE_PROJECT_PATH', 'Workspace directory was replaced by a non-directory or link');
  }
  const entries = await readdir(directory);
  for (const name of entries) {
    const child = path.join(directory, name);
    await rm(child, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
  const remaining = await readdir(directory);
  if (remaining.length > 0) {
    throw new BridgeError('WORKSPACE_RESET_FAILED', 'Stale files remained after cleaning the workspace directory');
  }
}

export function computeScopeDigest(entries: ReadonlyMap<string, string>): string {
  const hash = createHash('sha256');
  const keys = [...entries.keys()].sort();
  for (const key of keys) {
    hash.update(key + '\0' + entries.get(key)! + '\0');
  }
  return hash.digest('hex');
}

export async function verifyPreparedScopeAgainstOriginal(
  copyDirectory: string,
  expectedOriginalHashes: ReadonlyMap<string, string>,
  managedAuxPaths: ReadonlySet<string>,
): Promise<{ scopeSha256: string; verifiedFiles: number }> {
  const observed = new Map<string, string>();
  async function walk(dir: string, prefix: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        throw new BridgeError('UNSAFE_PROJECT_PATH', 'Prepared workspace contains a symbolic link: ' + rel);
      }
      if (entry.isDirectory()) {
        await walk(full, rel);
      } else if (entry.isFile()) {
        if (managedAuxPaths.has(rel)) continue;
        const data = await readFile(full);
        observed.set(rel, createHash('sha256').update(data).digest('hex'));
      } else {
        throw new BridgeError('UNSAFE_PROJECT_PATH', 'Prepared workspace contains a non-regular file: ' + rel);
      }
    }
  }
  await walk(copyDirectory, '');

  if (observed.size !== expectedOriginalHashes.size) {
    const extra = [...observed.keys()].filter(k => !expectedOriginalHashes.has(k));
    const missing = [...expectedOriginalHashes.keys()].filter(k => !observed.has(k));
    throw new BridgeError(
      'WORKSPACE_VERIFICATION_FAILED',
      `Prepared scope differs from original (extra: ${extra.slice(0, 5).join(', ') || 'none'}; missing: ${missing.slice(0, 5).join(', ') || 'none'})`,
    );
  }
  for (const [rel, expectedSha] of expectedOriginalHashes) {
    if (observed.get(rel) !== expectedSha) {
      throw new BridgeError('SOURCE_CHANGED', `Prepared file hash mismatch against original: ${rel}`);
    }
  }
  const expectedDigest = computeScopeDigest(expectedOriginalHashes);
  const observedDigest = computeScopeDigest(observed);
  if (expectedDigest !== observedDigest) {
    throw new BridgeError('SOURCE_CHANGED', 'Prepared workspace scope digest does not match original source');
  }
  return { scopeSha256: observedDigest, verifiedFiles: observed.size };
}
