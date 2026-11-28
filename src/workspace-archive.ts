import { createHash, randomUUID } from 'node:crypto';
import { lstatSync, realpathSync, renameSync } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { assertNoAgentConfigInCopy } from './agent-config.js';
import { artifactReferenceSchema, validArtifactRelative, type ArtifactReference, type ReadArtifactResult } from './artifacts.js';
import { DEFAULT_PROJECT_LIMITS, type ProjectLimits } from './config.js';
import { stagedExecutionPolicySchema } from './execution-policy.js';
import {
  assertLineEndingsRestored,
  assertManagedCopyPresent,
  checkFenceMarker,
  checkedPath,
  copyGit,
  extractFilePatch,
  fingerprintProjectCopy,
  previewProjectCopy,
  readLineEndingConversionsMarker,
  readProcessCleanupMarkerSync,
  validRelative,
  verifyManagedCopy,
  type BlockedPath,
  type ChangePreview,
  type ProjectCopy,
} from './isolation.js';
import { stageProvidedSkills, stagedSkillsSchema, verifyProvidedSkills, type StagedSkill } from './skills.js';
import { BridgeError } from './types.js';
import { criteriaSchema, reviewSchema, type AcceptanceCriterion, type ReviewEvidence, type VerificationRecord } from './verification.js';
import {
  assertNoLinkAncestryAsync,
  canonicalWorkspacePaths,
  computeScopeDigest,
  emptyDirectoryContents,
  ensureFixedWorkspaceLpacPermissions,
  invalidateWorkspaceOccupant,
  readWorkspaceMetadata,
  TASK_ARCHIVES_DIR_NAME,
  writeWorkspaceMetadata,
} from './workspace-paths.js';

const ARCHIVE_MANIFEST_FILE_NAME = 'manifest.json';
const ARCHIVE_PATCH_FILE_NAME = 'patch.diff';
const ARCHIVE_RECEIPT_FILE_NAME = 'receipt.jsonl';
const ARCHIVE_BLOBS_DIR_NAME = 'blobs';
const ARCHIVE_SKILLS_DIR_NAME = 'skills';

const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

const archivedFileEntrySchema = z.object({
  path: z.string().min(1).max(1000),
  sha256: z.string().regex(SHA256_RE),
  mode: z.number().int().nonnegative(),
  bytes: z.number().int().nonnegative(),
}).strict();

export type ArchivedFileEntry = z.infer<typeof archivedFileEntrySchema>;

const blockedPathSchema = z.object({
  path: z.string(),
  reason: z.enum(['SECRET_FILE', 'SECRET_CONTENT', 'SECRET_EXCLUSION', 'UNSAFE_PATH']),
}).strict();

const previewMetadataSchema = z.object({
  files: z.array(z.object({ status: z.string().min(1).max(8), path: z.string() }).strict()),
  fileSummaries: z.array(z.object({
    status: z.string().min(1).max(8),
    path: z.string(),
    insertions: z.number().int().nonnegative().nullable(),
    deletions: z.number().int().nonnegative().nullable(),
    binary: z.boolean(),
  }).strict()),
  summary: z.object({
    filesChanged: z.number().int().nonnegative(),
    added: z.number().int().nonnegative(),
    modified: z.number().int().nonnegative(),
    deleted: z.number().int().nonnegative(),
    insertions: z.number().int().nonnegative(),
    deletions: z.number().int().nonnegative(),
    binaryFiles: z.number().int().nonnegative(),
  }).strict(),
  sha256: z.string().regex(SHA256_RE),
  sourceDirectory: z.string().min(1),
  copyDirectory: z.string().min(1),
  encodingWarnings: z.array(z.string()).optional(),
}).strict();

const receiptSnapshotSchema = z.object({
  executionId: z.string().uuid(),
  receiptPath: z.string().min(1),
  sha256: z.string().regex(SHA256_RE),
  bytes: z.number().int().nonnegative(),
}).strict();

const taskArchivePayloadSchema = z.object({
  version: z.literal(1),
  taskId: z.string().uuid(),
  lineageId: z.string().uuid(),
  sourceDirectory: z.string().min(1),
  copyDirectory: z.string().min(1),
  gitDirectory: z.string().min(1),
  mode: z.enum(['write', 'read-only']),
  includedFiles: z.array(z.string()),
  blockedFiles: z.array(blockedPathSchema).optional(),
  providedSkills: stagedSkillsSchema.optional(),
  executionPolicy: stagedExecutionPolicySchema.optional(),
  executionStateDirectory: z.string().min(1).optional(),
  modelProofFailure: z.string().max(2000).optional(),
  baseline: z.array(archivedFileEntrySchema),
  baselineTreeSha256: z.string().regex(SHA256_RE),
  files: z.array(archivedFileEntrySchema),
  treeSha256: z.string().regex(SHA256_RE),
  patchSha256: z.string().regex(SHA256_RE),
  preview: previewMetadataSchema,
  artifacts: z.array(artifactReferenceSchema),
  receipt: receiptSnapshotSchema.optional(),
  archivedAt: z.string().datetime(),
}).strict();

const taskArchiveManifestSchema = taskArchivePayloadSchema.extend({
  manifestSha256: z.string().regex(SHA256_RE),
}).strict();

export type TaskArchiveManifest = z.infer<typeof taskArchiveManifestSchema>;

export interface VerifiedTaskArchive {
  manifest: TaskArchiveManifest;
  patch: string;
  archiveDirectory: string;
}

export function archiveDirectoryFor(stateDirectory: string, taskId: string): string {
  if (!UUID_RE.test(taskId)) {
    throw new BridgeError('INVALID_STATE', 'Invalid taskId for archive path');
  }
  const canonicalState = realpathSync.native(stateDirectory);
  return path.join(canonicalState, TASK_ARCHIVES_DIR_NAME, taskId.toLowerCase());
}

export function hasTaskArchive(stateDirectory: string, taskId: string): boolean {
  if (!UUID_RE.test(taskId)) return false;
  try {
    const dir = archiveDirectoryFor(stateDirectory, taskId);
    const stat = lstatSync(path.join(dir, ARCHIVE_MANIFEST_FILE_NAME));
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

async function writeImmutableBlob(blobsDir: string, sha256: string, bytes: Buffer): Promise<void> {
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== sha256) {
    throw new BridgeError('CHECKPOINT_INVALID', 'Blob hash mismatch while archiving checkpoint');
  }
  const target = path.join(blobsDir, sha256);
  try {
    const existing = await lstat(target);
    if (!existing.isFile() || existing.isSymbolicLink() || existing.size !== bytes.length) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Existing archive blob is corrupted or linked');
    }
    const disk = await readFile(target);
    if (createHash('sha256').update(disk).digest('hex') !== sha256) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Existing archive blob digest mismatch');
    }
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const temp = path.join(blobsDir, `${sha256}.${randomUUID()}.tmp`);
  try {
    await writeFile(temp, bytes, { flag: 'wx', mode: 0o600 });
    renameSync(temp, target);
  } finally {
    await rm(temp, { force: true }).catch(() => {});
  }
}

async function readBaselineEntriesFromGit(
  project: ProjectCopy,
  limits: ProjectLimits,
): Promise<Array<{ path: string; sha256: string; mode: number; bytes: Buffer }>> {
  const head = (await copyGit(project, ['--git-dir=' + project.gitDirectory, 'rev-parse', '--verify', 'HEAD^{commit}'])).toString('utf8').trim();
  const lsTreeRaw = await copyGit(project, ['--git-dir=' + project.gitDirectory, 'ls-tree', '-r', '-l', '-z', head]);
  const entries: Array<{ path: string; oid: string; mode: number; size: number }> = [];
  let offset = 0;
  let totalBytes = 0;
  while (offset < lsTreeRaw.length) {
    const nextNull = lsTreeRaw.indexOf(0, offset);
    if (nextNull === -1) throw new BridgeError('GIT_OPERATION_FAILED', 'Unterminated ls-tree record');
    const rec = lsTreeRaw.subarray(offset, nextNull);
    offset = nextNull + 1;
    if (rec.length === 0) continue;
    const tab = rec.indexOf(0x09);
    if (tab === -1) throw new BridgeError('GIT_OPERATION_FAILED', 'Malformed ls-tree record');
    const meta = rec.subarray(0, tab).toString('utf8').trim().split(/\s+/);
    const rel = validRelative(rec.subarray(tab + 1).toString('utf8'));
    const gitMode = meta[0]!;
    const type = meta[1]!;
    const oid = meta[2]!;
    const size = Number(meta[3]!);
    if ((gitMode !== '100644' && gitMode !== '100755') || type !== 'blob' || !Number.isSafeInteger(size) || size < 0) {
      throw new BridgeError('UNSAFE_PROJECT_PATH', 'Baseline contains non-blob or unsafe entry: ' + rel);
    }
    totalBytes += size;
    if (entries.length + 1 > limits.maxCopyFiles || totalBytes > limits.maxCopyBytes) {
      throw new BridgeError('COPY_LIMIT_EXCEEDED', 'Baseline exceeds copy limits while archiving');
    }
    entries.push({ path: rel, oid, mode: gitMode === '100755' ? 0o755 : 0o644, size });
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const out: Array<{ path: string; sha256: string; mode: number; bytes: Buffer }> = [];
  for (const entry of entries) {
    const blob = await copyGit(project, ['--git-dir=' + project.gitDirectory, 'cat-file', 'blob', entry.oid]);
    if (blob.length !== entry.size) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Baseline blob size mismatch: ' + entry.path);
    }
    out.push({
      path: entry.path,
      sha256: createHash('sha256').update(blob).digest('hex'),
      mode: entry.mode,
      bytes: blob,
    });
  }
  return out;
}

function computeManifestDigest(payload: z.infer<typeof taskArchivePayloadSchema>): string {
  return createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

function managedAuxPathsForArchive(project: ProjectCopy): Set<string> {
  const aux = new Set<string>(
    (project.providedSkills ?? []).flatMap(skill => skill.files.map(file => validRelative(file.path))),
  );
  if (project.executionPolicy) {
    aux.add('.agents/hooks.json');
    aux.add('.agents/bridge-execution-hook.mjs');
    aux.add('.agents/bridge-execution-policy.json');
    aux.add('.agents/mcp_config.json');
  } else {
    aux.add('.agents/hooks.json');
    aux.add('.agents/bridge-guard-hook.mjs');
  }
  return aux;
}

async function archiveProvidedSkillBlobs(
  stateDirectory: string,
  taskId: string,
  copyDirectory: string,
  providedSkills: readonly StagedSkill[] | undefined,
): Promise<void> {
  if (!providedSkills?.length) return;
  const canonicalState = await realpath(stateDirectory);
  const archiveDir = archiveDirectoryFor(canonicalState, taskId);
  const skillBlobsDir = path.join(archiveDir, ARCHIVE_SKILLS_DIR_NAME);
  await mkdir(skillBlobsDir, { recursive: true, mode: 0o700 });
  await assertNoLinkAncestryAsync(skillBlobsDir, canonicalState);
  for (const skill of providedSkills) {
    for (const file of skill.files) {
      const source = await checkedPath(copyDirectory, validRelative(file.path), true);
      const bytes = await readFile(source);
      if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) {
        throw new BridgeError('PROVIDED_SKILL_CHANGED', `Provided skill digest mismatch while archiving: ${file.path}`);
      }
      await writeImmutableBlob(skillBlobsDir, file.sha256, bytes);
    }
  }
}

export async function archiveTaskCheckpoint(params: {
  stateDirectory: string;
  taskId: string;
  lineageId: string;
  mode: 'write' | 'read-only';
  project: ProjectCopy;
  artifacts?: readonly ArtifactReference[];
  limits?: ProjectLimits;
  verifyBaselineMap?: boolean;
  requireFreshArchive?: boolean;
}): Promise<TaskArchiveManifest> {
  const limits = params.limits ?? DEFAULT_PROJECT_LIMITS;
  const { project, taskId, lineageId, mode } = params;
  const archiveDir = archiveDirectoryFor(params.stateDirectory, taskId);
  if (params.requireFreshArchive) {
    const existingArchive = await lstat(archiveDir).catch(error => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    });
    if (existingArchive) {
      throw new BridgeError('CHECKPOINT_INVALID', `Checkpoint archive directory already exists for task ${taskId}`);
    }
  }
  await checkFenceMarker(project);
  await assertLineEndingsRestored(project);
  await verifyManagedCopy(project);
  await assertNoAgentConfigInCopy(project, mode);

  const preview = await previewProjectCopy(project, limits);
  const treeSha256 = await fingerprintProjectCopy(project, limits);
  const auxPaths = managedAuxPathsForArchive(project);

  const baselineBlobs = await readBaselineEntriesFromGit(project, limits);
  const baselineMap = new Map(baselineBlobs.map(entry => [entry.path, entry.sha256]));
  if (params.verifyBaselineMap) {
    if (baselineMap.size !== project.baseline.size) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Workspace baseline tree entries do not match persisted task baseline');
    }
    for (const [relative, expectedSha] of project.baseline) {
      if (baselineMap.get(validRelative(relative)) !== expectedSha) {
        throw new BridgeError('CHECKPOINT_INVALID', `Workspace baseline digest mismatch for ${relative}`);
      }
    }
  }
  const baselineTreeSha256 = computeScopeDigest(baselineMap);

  const workingBlobs: Array<{ path: string; sha256: string; mode: number; bytes: Buffer }> = [];
  let workingTotalBytes = 0;
  async function walkWorking(dir: string, prefix: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        throw new BridgeError('UNSAFE_PROJECT_PATH', 'Workspace contains a symbolic link: ' + rel);
      }
      if (entry.isDirectory()) {
        await walkWorking(full, rel);
      } else if (entry.isFile()) {
        if (auxPaths.has(rel)) continue;
        const relValid = validRelative(rel);
        const stat = await lstat(full);
        workingTotalBytes += stat.size;
        if (workingBlobs.length + 1 > limits.maxCopyFiles || workingTotalBytes > limits.maxCopyBytes) {
          throw new BridgeError('COPY_LIMIT_EXCEEDED', 'Workspace exceeds copy limits while archiving');
        }
        const bytes = await readFile(full);
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        workingBlobs.push({ path: relValid, sha256, mode: stat.mode & 0o777, bytes });
      } else {
        throw new BridgeError('UNSAFE_PROJECT_PATH', 'Workspace contains a non-regular file: ' + rel);
      }
    }
  }
  await walkWorking(project.copyDirectory, '');
  workingBlobs.sort((a, b) => a.path.localeCompare(b.path));

  const verifiedArtifacts: ArtifactReference[] = [];
  for (const ref of params.artifacts ?? []) {
    const parsed = artifactReferenceSchema.parse(ref);
    const rel = validArtifactRelative(parsed.path);
    const matched = workingBlobs.find(entry => entry.path === rel);
    if (!matched || matched.sha256 !== parsed.sha256 || matched.bytes.length !== parsed.bytes) {
      throw new BridgeError('CHECKPOINT_INVALID', `Artifact digest mismatch while archiving: ${parsed.path}`);
    }
    verifiedArtifacts.push(parsed);
  }

  let receiptBytes: Buffer | undefined;
  let receiptSnapshot: TaskArchiveManifest['receipt'];
  if (project.executionPolicy) {
    const receiptPath = project.executionPolicy.receiptPath;
    await assertNoLinkAncestryAsync(receiptPath);
    const stat = await lstat(receiptPath, { bigint: true });
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1n ||
      stat.dev.toString() !== project.executionPolicy.receiptIdentity.dev ||
      stat.ino.toString() !== project.executionPolicy.receiptIdentity.ino
    ) {
      throw new BridgeError('INVALID_RECEIPT', 'Execution policy receipt identity mismatch while archiving');
    }
    receiptBytes = await readFile(receiptPath);
    receiptSnapshot = {
      executionId: project.executionPolicy.executionId,
      receiptPath,
      sha256: createHash('sha256').update(receiptBytes).digest('hex'),
      bytes: receiptBytes.length,
    };
  }

  const blobsDir = path.join(archiveDir, ARCHIVE_BLOBS_DIR_NAME);
  await mkdir(blobsDir, { recursive: true, mode: 0o700 });
  await assertNoLinkAncestryAsync(blobsDir, realpathSync.native(params.stateDirectory));

  for (const entry of baselineBlobs) {
    await writeImmutableBlob(blobsDir, entry.sha256, entry.bytes);
  }
  for (const entry of workingBlobs) {
    await writeImmutableBlob(blobsDir, entry.sha256, entry.bytes);
  }
  await archiveProvidedSkillBlobs(params.stateDirectory, taskId, project.copyDirectory, project.providedSkills);

  const patchBytes = Buffer.from(preview.patch, 'utf8');
  if (createHash('sha256').update(patchBytes).digest('hex') !== preview.sha256) {
    throw new BridgeError('CHECKPOINT_INVALID', 'Preview patch digest mismatch while archiving');
  }
  const patchPath = path.join(archiveDir, ARCHIVE_PATCH_FILE_NAME);
  const patchTmp = `${patchPath}.${randomUUID()}.tmp`;
  try {
    await writeFile(patchTmp, patchBytes, { flag: 'wx', mode: 0o600 });
    renameSync(patchTmp, patchPath);
  } finally {
    await rm(patchTmp, { force: true }).catch(() => {});
  }

  if (receiptBytes) {
    const receiptArchivePath = path.join(archiveDir, ARCHIVE_RECEIPT_FILE_NAME);
    const receiptTmp = `${receiptArchivePath}.${randomUUID()}.tmp`;
    try {
      await writeFile(receiptTmp, receiptBytes, { flag: 'wx', mode: 0o600 });
      renameSync(receiptTmp, receiptArchivePath);
    } finally {
      await rm(receiptTmp, { force: true }).catch(() => {});
    }
  }

  const { patch: _ignoredPatch, ...previewMetadata } = preview;
  void _ignoredPatch;
  const payload = taskArchivePayloadSchema.parse({
    version: 1,
    taskId,
    lineageId,
    sourceDirectory: project.sourceDirectory,
    copyDirectory: project.copyDirectory,
    gitDirectory: project.gitDirectory,
    mode,
    includedFiles: [...project.includedFiles],
    ...(project.blockedFiles ? { blockedFiles: project.blockedFiles } : {}),
    ...(project.providedSkills
      ? {
          providedSkills: project.providedSkills.map(skill => ({
            ...skill,
            files: skill.files.map(file => ({ ...file })),
          })),
        }
      : {}),
    ...(project.executionPolicy ? { executionPolicy: project.executionPolicy } : {}),
    ...(project.executionStateDirectory ? { executionStateDirectory: project.executionStateDirectory } : {}),
    ...(project.modelProofFailure ? { modelProofFailure: project.modelProofFailure } : {}),
    baseline: baselineBlobs.map(({ path: p, sha256, mode: m, bytes }) => ({ path: p, sha256, mode: m, bytes: bytes.length })),
    baselineTreeSha256,
    files: workingBlobs.map(({ path: p, sha256, mode: m, bytes }) => ({ path: p, sha256, mode: m, bytes: bytes.length })),
    treeSha256,
    patchSha256: preview.sha256,
    preview: previewMetadata,
    artifacts: verifiedArtifacts,
    ...(receiptSnapshot ? { receipt: receiptSnapshot } : {}),
    archivedAt: new Date().toISOString(),
  });

  const manifest: TaskArchiveManifest = taskArchiveManifestSchema.parse({
    ...payload,
    manifestSha256: computeManifestDigest(payload),
  });

  const manifestPath = path.join(archiveDir, ARCHIVE_MANIFEST_FILE_NAME);
  const manifestTmp = `${manifestPath}.${randomUUID()}.tmp`;
  try {
    await writeFile(manifestTmp, JSON.stringify(manifest) + '\n', { flag: 'wx', mode: 0o600 });
    renameSync(manifestTmp, manifestPath);
  } finally {
    await rm(manifestTmp, { force: true }).catch(() => {});
  }

  await loadVerifiedTaskArchive(params.stateDirectory, taskId, {
    expectedManifestSha256: manifest.manifestSha256,
    verifyAllBlobs: true,
  });

  return manifest;
}

export async function loadVerifiedTaskArchive(
  stateDirectory: string,
  taskId: string,
  options?: { expectedManifestSha256?: string; verifyAllBlobs?: boolean },
): Promise<VerifiedTaskArchive> {
  const canonicalState = await realpath(stateDirectory);
  const archiveDir = archiveDirectoryFor(canonicalState, taskId);
  await assertNoLinkAncestryAsync(archiveDir, canonicalState);

  const manifestPath = path.join(archiveDir, ARCHIVE_MANIFEST_FILE_NAME);
  let manifestText: string;
  try {
    const stat = await lstat(manifestPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 50_000_000) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Archived checkpoint manifest is unsafe or oversized');
    }
    manifestText = await readFile(manifestPath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new BridgeError('CHECKPOINT_MISSING', `Archived checkpoint is missing for task ${taskId}`);
    }
    if (error instanceof BridgeError) throw error;
    throw new BridgeError('CHECKPOINT_INVALID', `Archived checkpoint manifest is unreadable for task ${taskId}`);
  }

  let manifest: TaskArchiveManifest;
  try {
    manifest = taskArchiveManifestSchema.parse(JSON.parse(manifestText));
  } catch {
    throw new BridgeError('CHECKPOINT_INVALID', `Archived checkpoint manifest is malformed for task ${taskId}`);
  }

  if (manifest.taskId.toLowerCase() !== taskId.toLowerCase()) {
    throw new BridgeError('CHECKPOINT_INVALID', 'Archived checkpoint taskId mismatch');
  }
  const { manifestSha256, ...payload } = manifest;
  if (computeManifestDigest(payload) !== manifestSha256) {
    throw new BridgeError('CHECKPOINT_INVALID', 'Archived checkpoint manifest digest mismatch');
  }
  if (options?.expectedManifestSha256 && options.expectedManifestSha256 !== manifestSha256) {
    throw new BridgeError('CHECKPOINT_INVALID', 'Archived checkpoint manifest does not match task record digest');
  }

  const patchPath = path.join(archiveDir, ARCHIVE_PATCH_FILE_NAME);
  await assertNoLinkAncestryAsync(patchPath, archiveDir);
  let patchBuf: Buffer;
  try {
    const stat = await lstat(patchPath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Archived patch is not a regular file');
    }
    patchBuf = await readFile(patchPath);
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    throw new BridgeError('CHECKPOINT_INVALID', 'Archived patch file is missing or unreadable');
  }
  if (createHash('sha256').update(patchBuf).digest('hex') !== manifest.patchSha256 || manifest.preview.sha256 !== manifest.patchSha256) {
    throw new BridgeError('CHECKPOINT_INVALID', 'Archived patch hash mismatch');
  }

  if (manifest.receipt) {
    const receiptPath = path.join(archiveDir, ARCHIVE_RECEIPT_FILE_NAME);
    await assertNoLinkAncestryAsync(receiptPath, archiveDir);
    let receiptBuf: Buffer;
    try {
      const stat = await lstat(receiptPath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== manifest.receipt.bytes) {
        throw new BridgeError('CHECKPOINT_INVALID', 'Archived receipt file identity or size mismatch');
      }
      receiptBuf = await readFile(receiptPath);
    } catch (error) {
      if (error instanceof BridgeError) throw error;
      throw new BridgeError('CHECKPOINT_INVALID', 'Archived receipt file is missing or unreadable');
    }
    if (createHash('sha256').update(receiptBuf).digest('hex') !== manifest.receipt.sha256) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Archived receipt hash mismatch');
    }
  }

  if (options?.verifyAllBlobs !== false) {
    const blobsDir = path.join(archiveDir, ARCHIVE_BLOBS_DIR_NAME);
    const seen = new Set<string>();
    for (const entry of [...manifest.baseline, ...manifest.files]) {
      if (seen.has(entry.sha256)) continue;
      seen.add(entry.sha256);
      const blobPath = path.join(blobsDir, entry.sha256);
      await assertNoLinkAncestryAsync(blobPath, archiveDir);
      let stat;
      try {
        stat = await lstat(blobPath);
      } catch {
        throw new BridgeError('CHECKPOINT_INVALID', `Archived checkpoint blob is missing for ${entry.path}`);
      }
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== entry.bytes) {
        throw new BridgeError('CHECKPOINT_INVALID', `Archived checkpoint blob size/type mismatch for ${entry.path}`);
      }
      const bytes = await readFile(blobPath);
      if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) {
        throw new BridgeError('CHECKPOINT_INVALID', `Archived checkpoint blob hash mismatch for ${entry.path}`);
      }
    }
    if (manifest.providedSkills?.length) {
      const skillBlobsDir = path.join(archiveDir, ARCHIVE_SKILLS_DIR_NAME);
      const seenSkills = new Set<string>();
      for (const skill of manifest.providedSkills) {
        for (const file of skill.files) {
          if (seenSkills.has(file.sha256)) continue;
          seenSkills.add(file.sha256);
          const skillPath = path.join(skillBlobsDir, file.sha256);
          await assertNoLinkAncestryAsync(skillPath, archiveDir);
          let stat;
          try {
            stat = await lstat(skillPath);
          } catch {
            throw new BridgeError('CHECKPOINT_INVALID', `Archived skill blob is missing for ${file.path}`);
          }
          if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2_000_000) {
            throw new BridgeError('CHECKPOINT_INVALID', `Archived skill blob size/type mismatch for ${file.path}`);
          }
          const bytes = await readFile(skillPath);
          if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) {
            throw new BridgeError('CHECKPOINT_INVALID', `Archived skill blob hash mismatch for ${file.path}`);
          }
        }
      }
    }
  }

  return {
    manifest,
    patch: patchBuf.toString('utf8'),
    archiveDirectory: archiveDir,
  };
}

export async function removeTaskArchive(stateDirectory: string, taskId: string): Promise<void> {
  if (!UUID_RE.test(taskId)) return;
  const canonicalState = await realpath(stateDirectory);
  const archiveDir = archiveDirectoryFor(canonicalState, taskId);
  await assertNoLinkAncestryAsync(archiveDir, canonicalState);
  await rm(archiveDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

export function previewFromArchive(archive: VerifiedTaskArchive): ChangePreview {
  return {
    ...archive.manifest.preview,
    patch: archive.patch,
  };
}

export function readPatchFromArchive(archive: VerifiedTaskArchive, expectedSha256: string, relative?: string): string {
  const preview = previewFromArchive(archive);
  if (preview.sha256 !== expectedSha256) {
    throw new BridgeError('REVIEW_CHANGED', 'The patch changed; preview again before reading');
  }
  if (relative === undefined) return preview.patch;
  const file = relative.replaceAll('\\', '/');
  if (!preview.files.some(change => change.path === file)) {
    throw new BridgeError('INVALID_PATCH_PATH', 'Select a changed path from the preview');
  }
  return extractFilePatch(preview, file);
}

export async function readArtifactFromArchive(
  archive: VerifiedTaskArchive,
  reference: ArtifactReference,
  expectedSha256: string,
  offset = 0,
  limit = 65536,
  maxBytes: number = DEFAULT_PROJECT_LIMITS.maxCopyBytes,
): Promise<ReadArtifactResult> {
  const parsedRef = artifactReferenceSchema.parse(reference);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new BridgeError('INVALID_CURSOR', 'offset must be a non-negative safe integer');
  }
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 65536) {
    throw new BridgeError('INVALID_CURSOR', 'limit must be an integer between 1 and 65536');
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new BridgeError('INVALID_CURSOR', 'maxBytes must be a positive integer');
  }
  if (offset > parsedRef.bytes) {
    throw new BridgeError('INVALID_CURSOR', `offset ${offset} exceeds reference bytes ${parsedRef.bytes}`);
  }
  if (typeof expectedSha256 !== 'string' || !SHA256_RE.test(expectedSha256)) {
    throw new BridgeError('INVALID_ARTIFACT_HASH', 'expectedSha256 must be a 64-character lowercase hex string');
  }
  if (expectedSha256 !== parsedRef.sha256) {
    throw new BridgeError('CONTENT_CHANGED', 'expectedSha256 does not match reference sha256');
  }
  if (parsedRef.bytes > maxBytes) {
    throw new BridgeError('COPY_LIMIT_EXCEEDED', `Artifact size (${parsedRef.bytes} bytes) exceeds limit of ${maxBytes} bytes`);
  }
  const archived = archive.manifest.artifacts.find(item => item.path === parsedRef.path);
  if (!archived || archived.sha256 !== parsedRef.sha256 || archived.bytes !== parsedRef.bytes) {
    throw new BridgeError('CONTENT_CHANGED', 'Archived artifact metadata does not match reference');
  }
  const blobPath = path.join(archive.archiveDirectory, ARCHIVE_BLOBS_DIR_NAME, archived.sha256);
  await assertNoLinkAncestryAsync(blobPath, archive.archiveDirectory);
  const handle = await open(blobPath, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size !== parsedRef.bytes) {
      throw new BridgeError('CONTENT_CHANGED', 'Archived artifact blob size mismatch');
    }
    const bytes = await handle.readFile();
    const actualSha256 = createHash('sha256').update(bytes).digest('hex');
    if (actualSha256 !== parsedRef.sha256 || actualSha256 !== expectedSha256) {
      throw new BridgeError('CONTENT_CHANGED', 'Archived artifact blob hash mismatch');
    }
    const windowEnd = Math.min(parsedRef.bytes, offset + limit);
    return {
      path: parsedRef.path,
      sha256: actualSha256,
      bytes: parsedRef.bytes,
      offset,
      nextOffset: windowEnd,
      hasMore: windowEnd < parsedRef.bytes,
      encoding: 'base64',
      content: bytes.subarray(offset, windowEnd).toString('base64'),
      offsetUnit: 'bytes',
    };
  } finally {
    await handle.close().catch(() => {});
  }
}

export async function verifyCriteriaFromArchive(
  archive: VerifiedTaskArchive,
  sha256: string,
  criteria: AcceptanceCriterion[] = [],
  reviews: ReviewEvidence[] = [],
): Promise<VerificationRecord> {
  if (criteria.length) criteria = criteriaSchema.parse(criteria);
  reviews = reviewSchema.parse(reviews);
  if (reviews.some(review => !criteria.some(criterion => criterion.id === review.criterionId))) {
    throw new BridgeError('INVALID_REVIEW', 'Review refers to an unknown acceptance criterion');
  }
  const fileIndex = new Map(archive.manifest.files.map(entry => [entry.path, entry]));
  const fileHashes: Record<string, string | null> = Object.create(null);
  const contents = new Map<string, Buffer | undefined>();

  async function readArchivedFile(relative: string): Promise<Buffer | undefined> {
    const valid = validRelative(relative);
    if (contents.has(valid)) return contents.get(valid);
    const entry = fileIndex.get(valid);
    if (!entry) {
      fileHashes[relative] = null;
      contents.set(valid, undefined);
      return undefined;
    }
    if (entry.bytes > 10_000_000) {
      throw new BridgeError('VERIFICATION_TOO_LARGE', 'Verification file exceeds 10 MB');
    }
    const blobPath = path.join(archive.archiveDirectory, ARCHIVE_BLOBS_DIR_NAME, entry.sha256);
    const bytes = await readFile(blobPath);
    const actualSha = createHash('sha256').update(bytes).digest('hex');
    if (actualSha !== entry.sha256) {
      throw new BridgeError('CHECKPOINT_INVALID', `Archived verification blob hash mismatch for ${valid}`);
    }
    fileHashes[relative] = actualSha;
    contents.set(valid, bytes);
    return bytes;
  }

  const checks: VerificationRecord['checks'] = [];
  for (const criterion of criteria) {
    let checkPassed: boolean | undefined;
    if (criterion.check) {
      const { kind, path: filePath, text } = criterion.check;
      const content = await readArchivedFile(filePath);
      if (kind === 'file-exists') checkPassed = content !== undefined;
      if (kind === 'file-absent') checkPassed = content === undefined;
      if (kind === 'file-contains') checkPassed = content !== undefined && content.toString('utf8').includes(text!);
      if (kind === 'file-not-contains') checkPassed = content !== undefined && !content.toString('utf8').includes(text!);
    }
    const review = reviews.find(item => item.criterionId === criterion.id);
    let grounded = false;
    if (review) {
      const content = await readArchivedFile(review.path);
      const lines = content?.toString('utf8').split(/\r?\n/);
      const quoteLines = review.quote.split(/\r?\n/);
      grounded = Boolean(lines && lines.slice(review.line - 1, review.line - 1 + quoteLines.length).join('\n') === quoteLines.join('\n'));
    }
    const status = checkPassed === false || (review && (!grounded || review.verdict === 'failed'))
      ? 'failed'
      : !review || review.verdict === 'unverified'
        ? 'unverified'
        : 'passed';
    checks.push({
      criterionId: criterion.id,
      status,
      observation: checkPassed === false
        ? 'Artifact check failed'
        : review && !grounded
          ? 'Review quote does not match the file and line'
          : !review
            ? 'Codex review evidence is missing'
            : 'Artifact check: ' + (checkPassed === undefined ? 'not specified' : 'passed') + '; client review: ' + review.verdict,
    });
  }
  const status = checks.some(check => check.status === 'failed')
    ? 'failed'
    : !checks.length || checks.some(check => check.status === 'unverified')
      ? 'unverified'
      : 'passed';
  return {
    sha256,
    checkedAt: new Date().toISOString(),
    status,
    checks,
    review: { source: 'client-reported', evidence: reviews },
    fileHashes,
  };
}

export async function restoreTaskCheckpointIntoWorkspace(params: {
  stateDirectory: string;
  sourceTaskId: string;
  expectedManifestSha256?: string;
  targetLineageId: string;
  targetTaskId: string;
  limits?: ProjectLimits;
  providedSkillsSource?: readonly { name: string; content: string; resources?: readonly { path: string; content: string }[] }[];
  onStage?: (stage: 'after-invalidate' | 'after-empty' | 'before-publish') => void | Promise<void>;
}): Promise<{ project: ProjectCopy; archive: VerifiedTaskArchive; preparationMs: number; scopeSha256: string }> {
  const startMs = performance.now();
  const limits = params.limits ?? DEFAULT_PROJECT_LIMITS;
  const archive = await loadVerifiedTaskArchive(params.stateDirectory, params.sourceTaskId, {
    expectedManifestSha256: params.expectedManifestSha256,
    verifyAllBlobs: true,
  });
  const { manifest } = archive;
  for (const entry of manifest.baseline) validRelative(entry.path);
  for (const entry of manifest.files) validRelative(entry.path);
  for (const skill of manifest.providedSkills ?? []) {
    for (const file of skill.files) validRelative(file.path);
  }
  const workspace = canonicalWorkspacePaths(params.stateDirectory, manifest.sourceDirectory);

  await assertNoLinkAncestryAsync(workspace.copyDirectory, workspace.stateDirectory);
  await assertNoLinkAncestryAsync(workspace.gitDirectory, workspace.stateDirectory);
  const existingGit = await lstat(workspace.gitDirectory).catch(error => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  });
  if (existingGit) {
    if (!existingGit.isDirectory() || existingGit.isSymbolicLink()) {
      throw new BridgeError('UNSAFE_PROJECT_PATH', 'Workspace baseline directory was replaced or linked');
    }
    await checkFenceMarker(workspace);
    const cleanupMarker = readProcessCleanupMarkerSync(workspace);
    if (cleanupMarker && cleanupMarker.entries.length > 0) {
      throw new BridgeError('PROCESS_CLEANUP_UNVERIFIED', 'Cannot restore workspace while an unverified process cleanup marker is present');
    }
    if (await readLineEndingConversionsMarker(workspace)) {
      throw new BridgeError('LINE_ENDINGS_UNRESTORED', 'Cannot restore workspace while line endings remain unrestored');
    }
  }
  const existingCopy = await lstat(workspace.copyDirectory).catch(error => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  });
  if (existingCopy) {
    if (!existingCopy.isDirectory() || existingCopy.isSymbolicLink()) {
      throw new BridgeError('UNSAFE_PROJECT_PATH', 'Workspace copy directory was replaced or linked');
    }
    await ensureFixedWorkspaceLpacPermissions(workspace, manifest.sourceDirectory);
  }
  // Validate existing metadata before any destructive step; corrupted metadata fails closed before mutating bytes.
  readWorkspaceMetadata(workspace.metadataPath);

  // Atomically fence the previous occupant before the first destructive filesystem mutation.
  invalidateWorkspaceOccupant(workspace, manifest.sourceDirectory, 'restore');
  await params.onStage?.('after-invalidate');

  const blobsDir = path.join(archive.archiveDirectory, ARCHIVE_BLOBS_DIR_NAME);
  const baselineMap = new Map<string, string>(manifest.baseline.map(entry => [entry.path, entry.sha256]));
  const restoredProject: ProjectCopy = {
    sourceDirectory: manifest.sourceDirectory,
    copyDirectory: workspace.copyDirectory,
    gitDirectory: workspace.gitDirectory,
    workspaceStateDirectory: workspace.stateDirectory,
    lineageId: params.targetLineageId,
    baseline: baselineMap,
    includedFiles: [...manifest.includedFiles],
    ...(manifest.blockedFiles ? { blockedFiles: manifest.blockedFiles as BlockedPath[] } : {}),
    ...(manifest.modelProofFailure ? { modelProofFailure: manifest.modelProofFailure } : {}),
  };

  try {
    await emptyDirectoryContents(workspace.copyDirectory, workspace.stateDirectory);
    await emptyDirectoryContents(workspace.gitDirectory, workspace.stateDirectory);
    await params.onStage?.('after-empty');
    if (!existingCopy) {
      await ensureFixedWorkspaceLpacPermissions(workspace, manifest.sourceDirectory);
    }

    await copyGit(restoredProject, ['-c', 'init.templateDir=', 'init', '--bare', '--quiet', workspace.gitDirectory]);
    await mkdir(path.join(workspace.gitDirectory, 'info'), { recursive: true });
    await writeFile(path.join(workspace.gitDirectory, 'info', 'attributes'), '* -text !working-tree-encoding -ident\n', { flag: 'wx', mode: 0o600 });

    const baselineWorktree = path.join(workspace.gitDirectory, 'restore-baseline-' + randomUUID());
    await mkdir(baselineWorktree, { mode: 0o700 });
    try {
      for (const entry of manifest.baseline) {
        const target = path.join(baselineWorktree, ...validRelative(entry.path).split('/'));
        await mkdir(path.dirname(target), { recursive: true });
        const blob = await readFile(path.join(blobsDir, entry.sha256));
        if (createHash('sha256').update(blob).digest('hex') !== entry.sha256) {
          throw new BridgeError('CHECKPOINT_INVALID', `Baseline blob hash mismatch during restore: ${entry.path}`);
        }
        await writeFile(target, blob, { flag: 'wx', mode: entry.mode & 0o777 });
        if (process.platform !== 'win32' && (entry.mode & 0o111) !== 0) {
          await chmod(target, entry.mode & 0o777);
        }
      }
      const baseScope = ['--git-dir=' + workspace.gitDirectory, '--work-tree=' + baselineWorktree];
      await copyGit(restoredProject, [...baseScope, 'add', '-A', '-f', '--', '.']);
      await copyGit(restoredProject, [
        ...baseScope,
        '-c', 'user.name=Bridge Snapshot',
        '-c', 'user.email=bridge@invalid.local',
        'commit', '--quiet', '--allow-empty', '-m', 'baseline',
      ]);
    } finally {
      await rm(baselineWorktree, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }

    for (const entry of manifest.files) {
      const target = path.join(workspace.copyDirectory, ...validRelative(entry.path).split('/'));
      await mkdir(path.dirname(target), { recursive: true });
      const blob = await readFile(path.join(blobsDir, entry.sha256));
      if (createHash('sha256').update(blob).digest('hex') !== entry.sha256) {
        throw new BridgeError('CHECKPOINT_INVALID', `Working blob hash mismatch during restore: ${entry.path}`);
      }
      await writeFile(target, blob, { flag: 'wx', mode: entry.mode & 0o777 });
      if (process.platform !== 'win32' && (entry.mode & 0o111) !== 0) {
        await chmod(target, entry.mode & 0o777);
      }
    }

    if (params.providedSkillsSource?.length) {
      const staged = await stageProvidedSkills(workspace.copyDirectory, params.providedSkillsSource, limits);
      if (staged.length) restoredProject.providedSkills = staged;
      await verifyProvidedSkills(workspace.copyDirectory, staged);
    } else if (manifest.providedSkills?.length) {
      const archivedSkillBlobsDir = path.join(archive.archiveDirectory, ARCHIVE_SKILLS_DIR_NAME);
      for (const skill of manifest.providedSkills) {
        for (const file of skill.files) {
          const target = path.join(workspace.copyDirectory, ...validRelative(file.path).split('/'));
          await mkdir(path.dirname(target), { recursive: true });
          const bytes = await readFile(path.join(archivedSkillBlobsDir, file.sha256));
          if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) {
            throw new BridgeError('CHECKPOINT_INVALID', `Archived skill blob mismatch: ${file.path}`);
          }
          await writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
        }
      }
      restoredProject.providedSkills = manifest.providedSkills;
      await verifyProvidedSkills(workspace.copyDirectory, manifest.providedSkills);
    }

    await copyGit(restoredProject, ['--git-dir=' + workspace.gitDirectory, '--work-tree=' + workspace.copyDirectory, 'read-tree', 'HEAD']);
    await assertManagedCopyPresent(restoredProject);
    const restoredTree = await fingerprintProjectCopy(restoredProject, limits);
    if (restoredTree !== manifest.treeSha256) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Restored workspace tree digest does not match archived checkpoint');
    }
    const restoredPreview = await previewProjectCopy(restoredProject, limits);
    if (restoredPreview.sha256 !== manifest.patchSha256) {
      throw new BridgeError('CHECKPOINT_INVALID', 'Restored workspace patch digest does not match archived checkpoint');
    }

    await params.onStage?.('before-publish');
    const preparationMs = Math.round((performance.now() - startMs) * 1000) / 1000;
    const scopeSha256 = computeScopeDigest(new Map(manifest.files.map(entry => [entry.path, entry.sha256])));
    const existingMeta = readWorkspaceMetadata(workspace.metadataPath);
    writeWorkspaceMetadata(workspace.metadataPath, {
      version: 1,
      sourceDirectory: manifest.sourceDirectory,
      rootKey: workspace.rootKey,
      currentTaskId: params.targetTaskId,
      currentLineageId: params.targetLineageId,
      updatedAt: new Date().toISOString(),
      lastPreparedDurationMs: preparationMs,
      ...(existingMeta?.windowsLpac ? { windowsLpac: existingMeta.windowsLpac } : {}),
    });

    return { project: restoredProject, archive, preparationMs, scopeSha256 };
  } catch (error) {
    if (!(error instanceof BridgeError && error.code === 'GIT_CLEANUP_UNVERIFIED')) {
      await emptyDirectoryContents(workspace.copyDirectory, workspace.stateDirectory).catch(() => {});
      await emptyDirectoryContents(workspace.gitDirectory, workspace.stateDirectory).catch(() => {});
    }
    throw error;
  }
}
