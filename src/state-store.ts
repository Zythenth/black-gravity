import { peerMessageInputSchema, peerOriginSchema, peerContextSchema } from './peer-messages.js';
import { groupAssignmentSchema } from './group-contract.js';
import { memorySelectionSchema, memorySnapshotsSchema, summarizeMemory } from './memory-context.js';
import { computeProjectId, memorySummarySchema } from './project-memory.js';
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { z } from 'zod';
import { stagedExecutionPolicySchema } from './execution-policy.js';
import { resolvedAgentPolicySchema, nativeToolsSchema, mcpSelectionSchema } from './agent-policy.js';
import { deliveryModeSchema, persistedBridgeMessageSchema } from './messages.js';
import { stagedSkillsSchema } from './skills.js';
import { BridgeError, type RunOptions, type TaskRecord } from './types.js';
import type { ProjectCopy } from './isolation.js';
import type { BridgeEvent } from './types.js';
import { usageCountersSchema } from './usage.js';
import { roleDefinitionSchema, effortSchema } from './roles.js';
import { parseSandboxPolicySnapshot, sandboxPolicyDigest, sandboxPolicySchema, type SandboxPolicySnapshot } from './sandbox-policy.js';
import { preauthorizedIntegrationRoots, mapFsError } from './integration-policy.js';
import { validateStateDirectory, type ConfigurationIssue } from './config.js';
import { hasOwnedPrefix, readMigrationMarker, samePath } from './state-migration.js';

const uuid = /^[a-f0-9-]{36}$/;
const canonicalUuidSchema = z.string().uuid();
const SANITIZED_CACHE_VERSION = 1;
const maxSandboxPolicyFileBytes = 2 * 20 * 1000 * 6 + 4096;
const modelSelectionSchema = z.object({ version: z.literal(1), model: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/).nullable() }).strict();
const integrationApprovalRootSchema = z.string().min(1).max(1000).refine(root =>
  !root.includes('\0') && path.isAbsolute(root) && path.resolve(root) === root && root !== path.parse(root).root &&
  (process.platform !== 'win32' || root === root.toLowerCase()));
const integrationApprovalsSchema = z.object({ version: z.literal(1), roots: z.array(integrationApprovalRootSchema).max(20) }).strict();
const blockedMetadataSchema = z.object({
  path: z.string(),
  reason: z.enum(['SECRET_FILE', 'SECRET_CONTENT', 'SECRET_EXCLUSION', 'UNSAFE_PATH']),
}).strict();
const executionIdentitySchema = z.object({
  provider: z.string().min(1).max(128),
  adapterId: z.string().min(1).max(128),
  adapterVersion: z.string().min(1).max(128),
  requested: z.object({
    model: z.string().min(1).max(256).nullable(),
    effort: effortSchema.nullable(),
  }).strict(),
  observed: z.object({
    model: z.string().min(1).max(256).nullable(),
    status: z.enum(['observed', 'not-observable']),
  }).strict(),
}).strict();
const deniedReadsSchema = z.object({
  total: z.number().int().nonnegative(),
  items: z.array(z.object({
    toolName: z.string().max(128),
    path: z.string().max(1000).optional(),
    reason: z.string().max(500),
  }).strict()).max(50),
}).strict();
const snapshotSchema = z.object({
  version: z.literal(1), ownerPid: z.number().int().positive(),
  record: z.object({ taskId: z.string().uuid(), workingDirectory: z.string(), prompt: z.string(),
    status: z.enum(['queued', 'starting', 'running', 'streaming', 'completed', 'failed', 'cancelled', 'timeout']),
    createdAt: z.string().datetime(), completedAt: z.string().datetime().optional(), pid: z.number().int().positive().optional(),
    mode: z.enum(['write', 'read-only']).optional(), integratedAt: z.string().datetime().optional(), discardedAt: z.string().datetime().optional(),
    usageIsResume: z.boolean().optional(), usageBaseline: usageCountersSchema.optional(),
    lastObservedCliUsage: usageCountersSchema.optional(), usageProvenance: z.literal('local-executor').optional(),
    deliveryMode: deliveryModeSchema.optional(), messages: z.array(persistedBridgeMessageSchema).max(100).optional(), messageCursor: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
    effort: effortSchema.optional(), execution: executionIdentitySchema.optional(), roleDefinition: roleDefinitionSchema.optional(), providedSkills: stagedSkillsSchema.optional(),
    agentPolicyReceipt: z.object({ sha256: z.string().regex(/^[a-f0-9]{64}$/), decisionCount: z.number().int().nonnegative(), deniedCount: z.number().int().nonnegative(), deniedReadCount: z.number().int().nonnegative().optional() }).strict().optional(),
    deniedReads: deniedReadsSchema.optional(),
    toolErrors: deniedReadsSchema.optional(),
    peerRequests: z.array(z.lazy(() => peerMessageInputSchema)).max(20).optional(),
    peerRequestsTruncated: z.boolean().optional(),
    group: z.lazy(() => groupAssignmentSchema).optional(),
    memory: z.array(z.lazy(() => memorySummarySchema)).max(8).optional(),
    agentPolicy: resolvedAgentPolicySchema.optional(),
    outputSchema: z.record(z.string(), z.unknown()).optional(),
    artifactPaths: z.array(z.string().min(1).max(1000)).min(1).max(100).optional(),
    structuredResult: z.object({ value: z.unknown(), sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict().optional(),
    artifacts: z.array(z.object({ path: z.string().min(1).max(1000), sha256: z.string().regex(/^[a-f0-9]{64}$/), bytes: z.number().int().nonnegative() }).strict()).max(100).optional(),
    continuationTaskId: z.string().uuid().optional(), parentTaskId: z.string().uuid().optional(),
    sourceMessage: z.object({ taskId: z.string().uuid(), messageId: z.string().uuid() }).strict().optional(),
    dispatching: z.object({ messageId: z.string().uuid(), continuationTaskId: z.string().uuid().optional(), ownerId: z.string().uuid().optional() }).strict().optional(),
    inbox: z.array(z.object({
      peerOrigin: z.lazy(() => peerOriginSchema).optional(),
      messageId: z.string().uuid(),
      taskId: z.string().uuid(),
      text: z.string().min(1).max(2000),
      receivedAt: z.string().datetime(),
      receipt: z.object({
        messageId: z.string().uuid(),
        taskId: z.string().uuid(),
        state: z.enum(['queued', 'sent', 'failed', 'cancelled']),
        continuationTaskId: z.string().uuid().optional(),
        error: z.object({ code: z.string(), message: z.string() }).strict().optional(),
      }).strict(),
    }).strict()).max(20).optional(),
  }).passthrough(),
  options: z.object({ peerContext: z.lazy(() => peerContextSchema).optional(), peerOrigin: z.lazy(() => peerOriginSchema).optional(), group: z.lazy(() => groupAssignmentSchema).optional(), memory: z.lazy(() => memorySelectionSchema).optional(), memorySnapshots: z.lazy(() => memorySnapshotsSchema).optional(), allowedTools: nativeToolsSchema.optional(), mcpServers: mcpSelectionSchema.optional(), agentPolicy: resolvedAgentPolicySchema.optional(), prompt: z.string(), workingDirectory: z.string(), effort: effortSchema.optional(), roleDefinition: roleDefinitionSchema.optional(),
    outputSchema: z.record(z.string(), z.unknown()).optional(),
    artifactPaths: z.array(z.string().min(1).max(1000)).min(1).max(100).optional(),
  }).passthrough(),
  project: z.object({ executionPolicy: stagedExecutionPolicySchema.optional(), executionStateDirectory: z.string().optional(), sourceDirectory: z.string(), copyDirectory: z.string(), gitDirectory: z.string(),
    baseline: z.array(z.tuple([z.string(), z.string().regex(/^[a-f0-9]{64}$/)])), includedFiles: z.array(z.string()), providedSkills: stagedSkillsSchema.optional(),
    blockedFiles: z.array(blockedMetadataSchema).optional(),
    modelProofFailure: z.string().max(2000).optional(),
  }).optional(),
  events: z.array(z.object({ taskId: z.string().uuid(), sequence: z.number().int().positive(), timestamp: z.string(), type: z.string(), data: z.unknown(), raw: z.unknown().optional(), rawIsData: z.literal(true).optional(), rawEnvelope: z.string().min(1).max(64).optional() }).refine(event => [event.raw !== undefined, event.rawIsData !== undefined, event.rawEnvelope !== undefined].filter(Boolean).length <= 1 && event.rawEnvelope !== 'event')),
  cursor: z.number().int().nonnegative(),
  // Written by versions that redact before persisting; older state is sanitized when restored.
  redacted: z.literal(true).optional(),
});

export const QUARANTINE_REASONS = [
  'unsafe-file',
  'unreadable',
  'invalid-snapshot',
  'identity-mismatch',
  'messages-mismatch',
  'inbox-mismatch',
  'group-mismatch',
  'memory-mismatch',
  'tool-policy-mismatch',
  'copy-outside-temporary-directory',
  'source-mismatch',
  'execution-policy-mismatch',
] as const;

export type QuarantineReason = (typeof QUARANTINE_REASONS)[number];

export interface QuarantinedSnapshot {
  taskId: string;
  reason: QuarantineReason;
  fingerprint?: string;
  copyHints: string[];
}

class SnapshotRejection extends BridgeError {
  constructor(
    readonly reason: QuarantineReason,
    message: string,
    readonly fingerprint?: string,
    readonly copyHints: string[] = [],
    readonly rawError?: unknown,
  ) {
    super('INVALID_STATE', message);
    this.name = 'SnapshotRejection';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function extractCopyHints(raw: unknown): string[] {
  if (!isRecord(raw)) return [];
  const project = isRecord(raw.project) ? raw.project : undefined;
  const record = isRecord(raw.record) ? raw.record : undefined;
  const candidates = [project?.copyDirectory, project?.gitDirectory, record?.copyDirectory];
  const hints: string[] = [];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length >= 1 && candidate.length <= 4096 && !hints.includes(candidate)) {
      hints.push(candidate);
    }
  }
  return hints;
}

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

export function copyLockName(copyDirectory: string, platform: NodeJS.Platform = process.platform): string {
  return 'copy-' + createHash('sha256').update(copyIdentity(copyDirectory, platform)).digest('hex');
}

export interface StoredTask {
  record: TaskRecord;
  options: RunOptions;
  project?: ProjectCopy;
  ownerPid: number;
  events: BridgeEvent[];
  cursor: number;
  redacted?: true;
  fingerprint?: string;
}

export function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
}

function retryTransient(action: () => void): void {
  const delays = [10, 20, 40, 80, 160];
  for (let attempt = 0; ; attempt++) {
    try { action(); return; }
    catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (process.platform !== 'win32' || !['EPERM', 'EACCES', 'EBUSY'].includes(code ?? '') || attempt >= delays.length) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delays[attempt]);
    }
  }
}

// On Windows a rename succeeds over a file whose ACL denies writing, while opening it for
// writing refuses both that ACL and the read-only attribute, and on POSIX a rename ignores the file mode.
function assertReplaceable(target: string): void {
  retryTransient(() => {
    try { closeSync(openSync(target, 'r+')); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  });
}

// Windows can transiently deny replacement while another process holds the file.
// Keep the existing atomic rename and never unlink the last valid state as a fallback.
export function replaceStateFile(temporary: string, target: string): void {
  retryTransient(() => renameSync(temporary, target));
}

// The sanitized cache never blocks loading or removal: only regular files are removed, and failures are ignored.
function removeCachedFile(file: string): void {
  try { if (lstatSync(file).isFile()) rmSync(file, { force: true }); } catch { /* nothing to remove */ }
}

function compactEvent(event: BridgeEvent): Record<string, unknown> {
  if (event.raw === undefined) return { ...event };
  const { raw, ...rest } = event;
  const serializedRaw = JSON.stringify(raw);
  if (serializedRaw === JSON.stringify(event.data)) return { ...rest, rawIsData: true };
  const name = raw && typeof raw === 'object' && !Array.isArray(raw) && typeof (raw as { event?: unknown }).event === 'string' ? (raw as { event: string }).event : undefined;
  if (name && name !== 'event' && name.length <= 64 && serializedRaw === JSON.stringify({ event: name, [name]: event.data })) {
    return { ...rest, rawEnvelope: name };
  }
  return { ...event };
}

function expandEvent(event: z.infer<typeof snapshotSchema>['events'][number]): BridgeEvent {
  const { rawIsData, rawEnvelope, raw, ...rest } = event;
  const rebuiltRaw = rawIsData ? structuredClone(event.data) : rawEnvelope !== undefined ? { event: rawEnvelope, [rawEnvelope]: structuredClone(event.data) } : raw;
  return rebuiltRaw === undefined ? rest : { ...rest, raw: rebuiltRaw };
}

export type StateDirectoryProblemReason = 'not-absolute' | 'invalid-entry' | 'link' | 'not-directory' | 'unusable';

export function stateDirectoryProblem(directory: string): StateDirectoryProblemReason | undefined {
  const validation = validateStateDirectory(directory);
  if (!validation.valid) return validation.reason;
  try {
    const stat = lstatSync(directory);
    if (stat.isSymbolicLink()) return 'link';
    if (!stat.isDirectory()) return 'not-directory';
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return 'unusable';
  }
  return undefined;
}

export class StateStoreLinkError extends BridgeError {
  constructor(message = 'State directory cannot be a link') {
    super('INVALID_STATE_DIRECTORY', message);
    this.name = 'StateStoreLinkError';
  }
}

export class StateStore {
  constructor(private readonly directory: string) {
    const problem = stateDirectoryProblem(directory);
    if (problem) {
      if (problem === 'link') throw new StateStoreLinkError();
      const message = problem === 'not-directory'
        ? 'State directory must be a directory'
        : problem === 'unusable'
        ? 'State directory is unusable'
        : problem === 'invalid-entry'
        ? 'BRIDGE_STATE_DIRECTORY is invalid'
        : 'BRIDGE_STATE_DIRECTORY must be absolute';
      throw new BridgeError('INVALID_STATE_DIRECTORY', message);
    }
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory);
    if (stat.isSymbolicLink()) {
      throw new StateStoreLinkError();
    }
    if (!stat.isDirectory()) {
      throw new BridgeError('INVALID_STATE_DIRECTORY', 'State directory must be a directory');
    }
  }

  probeWritable(): void {
    readdirSync(this.directory);
    const probeFile = path.join(this.directory, '.startup-probe-' + randomUUID());
    writeFileSync(probeFile, '', { flag: 'wx', mode: 0o600 });
    rmSync(probeFile);
  }

  private file(taskId: string): string {
    if (!uuid.test(taskId)) throw new BridgeError('INVALID_STATE', 'Invalid persisted task ID');
    return path.join(this.directory, taskId + '.json');
  }

  readIntegrationRoots(): { roots: string[]; issues: ConfigurationIssue[] } {
    const variable = 'integration-approvals.json';
    const file = path.join(this.directory, 'integration-approvals.json');
    let stat;
    try {
      stat = lstatSync(file);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { roots: [], issues: [] };
      return { roots: [], issues: [{ variable, reason: mapFsError(error) }] };
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 128 * 1024) {
      return { roots: [], issues: [{ variable, reason: 'unsafe-file' }] };
    }
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { roots: [], issues: [] };
      return { roots: [], issues: [{ variable, reason: mapFsError(error) }] };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      return { roots: [], issues: [{ variable, reason: 'invalid-json' }] };
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { roots: [], issues: [{ variable, reason: 'invalid-format' }] };
    }
    const obj = parsed as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (
      keys.length !== 2 ||
      !Object.hasOwn(obj, 'version') ||
      !Object.hasOwn(obj, 'roots') ||
      obj.version !== 1 ||
      !Array.isArray(obj.roots)
    ) {
      return { roots: [], issues: [{ variable, reason: 'invalid-format' }] };
    }
    if (obj.roots.length > 20) {
      return { roots: [], issues: [{ variable, reason: 'too-many-entries' }] };
    }
    const roots: string[] = [];
    const issues: ConfigurationIssue[] = [];
    for (let i = 0; i < obj.roots.length; i++) {
      const result = integrationApprovalRootSchema.safeParse(obj.roots[i]);
      if (!result.success) {
        issues.push({ variable, index: i, reason: 'invalid-entry' });
      } else {
        roots.push(result.data);
      }
    }
    return { roots, issues };
  }

  loadIntegrationRoots(): string[] {
    const result = this.readIntegrationRoots();
    if (result.issues.length > 0) {
      throw new BridgeError('INVALID_STATE', 'Invalid persisted integration approvals');
    }
    return result.roots;
  }

  rememberIntegrationRoot(directory: string): void {
    const canonical = preauthorizedIntegrationRoots(JSON.stringify([directory]))[0]!;
    const release = this.acquire('integration-approvals');
    const target = path.join(this.directory, 'integration-approvals.json');
    const temporary = target + '.' + randomUUID() + '.tmp';
    try {
      const roots = this.loadIntegrationRoots();
      if (roots.includes(canonical)) return;
      const snapshot = integrationApprovalsSchema.parse({ version: 1, roots: [...roots, canonical] });
      writeFileSync(temporary, JSON.stringify(snapshot), { flag: 'wx', mode: 0o600, flush: true });
      replaceStateFile(temporary, target);
    } finally { rmSync(temporary, { force: true }); release(); }
  }

  loadModel(): { model: string | null } | undefined {
    const file = path.join(this.directory, 'model-selection.json');
    try {
      const stat = lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024) throw new Error('Unsafe model selection');
      return modelSelectionSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new BridgeError('INVALID_STATE', 'Invalid persisted model selection');
    }
  }

  loadSandboxPolicy(): SandboxPolicySnapshot {
    const file = path.join(this.directory, 'sandbox-policy.json');
    try {
      const stat = lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxSandboxPolicyFileBytes) throw new Error('Unsafe sandbox policy');
      return parseSandboxPolicySnapshot(JSON.parse(readFileSync(file, 'utf8')));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        const policy = sandboxPolicySchema.parse({});
        return { version: 1, policy, sha256: sandboxPolicyDigest(policy) };
      }
      throw new BridgeError('INVALID_STATE', 'Invalid persisted sandbox policy');
    }
  }

  saveSandboxPolicy(snapshot: SandboxPolicySnapshot): void {
    let validated: SandboxPolicySnapshot;
    try { validated = parseSandboxPolicySnapshot(snapshot); }
    catch { throw new BridgeError('INVALID_STATE', 'Invalid sandbox policy snapshot'); }
    const target = path.join(this.directory, 'sandbox-policy.json');
    const temporary = target + '.' + randomUUID() + '.tmp';
    try {
      // Callers hold acquire('sandbox-policy') across reload, digest comparison, and this write; do not nest that lock here.
      this.loadSandboxPolicy();
      writeFileSync(temporary, JSON.stringify(validated), { flag: 'wx', mode: 0o600, flush: true });
      replaceStateFile(temporary, target);
    } finally { rmSync(temporary, { force: true }); }
  }

  saveModel(model: string | null): void {
    const selection = modelSelectionSchema.parse({ version: 1, model });
    const release = this.acquire('model-selection');
    const target = path.join(this.directory, 'model-selection.json');
    const temporary = target + '.' + randomUUID() + '.tmp';
    try {
      // Validate an existing record before replacing it, including links and malformed data.
      this.loadModel();
      writeFileSync(temporary, JSON.stringify(selection), { flag: 'wx', mode: 0o600, flush: true });
      replaceStateFile(temporary, target);
    } finally { rmSync(temporary, { force: true }); release(); }
  }

  save(task: StoredTask): void {
    this.writeSnapshot(this.file(task.record.taskId), task);
  }

  private formatSnapshot(task: StoredTask, preserveRedacted: boolean): string {
    const snapshot: Record<string, unknown> = { ...task, version: 1, events: task.events.map(compactEvent), project: task.project && { ...task.project, baseline: [...task.project.baseline] } };
    if (!preserveRedacted) snapshot.redacted = true;
    else if (task.redacted !== true) delete snapshot.redacted;
    delete snapshot.fingerprint;
    return JSON.stringify(snapshot);
  }

  serializeSnapshot(task: StoredTask): string {
    return this.formatSnapshot(task, false);
  }

  // Renames across files cannot be atomic, so a failed rename can leave a prefix of
  // entries published, and callers must order entries so that the next startup can finish the rest.
  saveBatch(entries: ReadonlyArray<{ taskId: string; content: string }>, onPublished: (taskId: string) => void): void {
    const targets = entries.map(entry => {
      const target = this.file(entry.taskId);
      assertReplaceable(target);
      return target;
    });
    const temporaries: string[] = [];
    try {
      const staged: Array<{ temporary: string; target: string; taskId: string }> = [];
      for (let i = 0; i < entries.length; i++) {
        const target = targets[i]!;
        const temporary = target + '.' + randomUUID() + '.tmp';
        temporaries.push(temporary);
        writeFileSync(temporary, entries[i]!.content, { flag: 'wx', mode: 0o600, flush: true });
        staged.push({ temporary, target, taskId: entries[i]!.taskId });
      }
      for (const { temporary, target, taskId } of staged) {
        replaceStateFile(temporary, target);
        onPublished(taskId);
      }
    } finally {
      for (const temporary of temporaries) {
        try { rmSync(temporary, { force: true }); }
        catch { /* a leftover temporary is not state, and must not hide the publication error */ }
      }
    }
  }

  private writeSnapshot(target: string, task: StoredTask, preserveRedacted = false): void {
    const temporary = target + '.' + randomUUID() + '.tmp';
    try {
      writeFileSync(temporary, this.formatSnapshot(task, preserveRedacted), { flag: 'wx', mode: 0o600, flush: true });
      replaceStateFile(temporary, target);
    } finally { rmSync(temporary, { force: true }); }
  }

  private loadSnapshotFile(
    file: string,
    name: string,
    selfRealpath: string,
    migrationOrigin: string | undefined,
  ): StoredTask | undefined {
    let stat;
    try {
      stat = lstatSync(file);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new SnapshotRejection('unreadable', 'Unreadable persisted task: ' + name, undefined, [], error);
    }
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 70_000_000) {
      throw new SnapshotRejection('unsafe-file', 'Unsafe persisted task file');
    }
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new SnapshotRejection('unreadable', 'Invalid persisted task: ' + name);
    }
    const fingerprint = createHash('sha256').update(text).digest('hex');
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new SnapshotRejection('invalid-snapshot', 'Invalid persisted task: ' + name, fingerprint);
    }
    const copyHints = extractCopyHints(parsed);
    let data: z.infer<typeof snapshotSchema>;
    try {
      data = snapshotSchema.parse(parsed);
    } catch {
      throw new SnapshotRejection('invalid-snapshot', 'Invalid persisted task: ' + name, fingerprint, copyHints);
    }
    if (data.record.taskId + '.json' !== name || !path.isAbsolute(data.record.workingDirectory) ||
        data.options.workingDirectory !== data.record.workingDirectory || data.options.prompt !== data.record.prompt ||
        data.events.some(event => event.taskId !== data.record.taskId || event.sequence > data.cursor)) {
      throw new SnapshotRejection('identity-mismatch', 'Persisted task does not match its identity', fingerprint, copyHints);
    }
    const messages = data.record.messages ?? [];
    if (messages.some((message, index) => message.taskId !== data.record.taskId || message.sequence > (data.record.messageCursor ?? 0) ||
      (index > 0 && messages[index - 1]!.sequence >= message.sequence))) {
      throw new SnapshotRejection('messages-mismatch', 'Persisted messages do not match task identity or cursor', fingerprint, copyHints);
    }
    const inbox = data.record.inbox ?? [];
    if (new Set(inbox.map(item => item.messageId.toLowerCase())).size !== inbox.length ||
      inbox.some(item => item.taskId !== data.record.taskId || item.receipt.taskId !== data.record.taskId || item.receipt.messageId !== item.messageId) ||
      (data.record.dispatching && !inbox.some(item => item.messageId === data.record.dispatching!.messageId && item.receipt.state === 'queued'))) {
      throw new SnapshotRejection('inbox-mismatch', 'Persisted inbox does not match task identity', fingerprint, copyHints);
    }
    if (JSON.stringify(data.record.group) !== JSON.stringify(data.options.group)) {
      throw new SnapshotRejection('group-mismatch', 'Persisted group assignment differs from task options', fingerprint, copyHints);
    }
    if ((data.record.peerRequests || data.options.peerContext || data.options.peerOrigin) && !data.record.group) {
      throw new SnapshotRejection('group-mismatch', 'Peer state requires group membership', fingerprint, copyHints);
    }
    if (data.options.peerContext && (data.options.peerContext.groupId.toLowerCase() !== data.record.group!.groupId.toLowerCase() ||
        data.options.peerContext.nodeKey !== data.record.group!.nodeKey)) {
      throw new SnapshotRejection('group-mismatch', 'Peer context differs from task group', fingerprint, copyHints);
    }
    if (data.options.peerOrigin && (!data.record.sourceMessage || data.options.peerOrigin.groupId.toLowerCase() !== data.record.group!.groupId.toLowerCase())) {
      throw new SnapshotRejection('group-mismatch', 'Peer input differs from its continuation', fingerprint, copyHints);
    }
    const snapshots = data.options.memorySnapshots;
    if (snapshots?.some(entry => entry.projectId !== computeProjectId(data.record.workingDirectory)) ||
        JSON.stringify(data.record.memory) !== JSON.stringify(summarizeMemory(snapshots)) ||
        JSON.stringify(data.options.memory) !== JSON.stringify(snapshots?.map(({ specialist, sha256 }) => ({ specialist, sha256 })))) {
      throw new SnapshotRejection('memory-mismatch', 'Persisted private memory differs from its project, hashes or metadata', fingerprint, copyHints);
    }
    if (data.record.agentPolicy?.sha256 !== data.options.agentPolicy?.sha256) {
      throw new SnapshotRejection('tool-policy-mismatch', 'Persisted task tool policies disagree', fingerprint, copyHints);
    }
    if (data.project) {
      for (const [directory, kind] of [[data.project.copyDirectory, 'copy'], [data.project.gitDirectory, 'baseline']] as const) {
        if (!path.isAbsolute(directory) || path.relative(os.tmpdir(), path.dirname(directory)) !== '' || !hasOwnedPrefix(path.basename(directory), kind)) {
          throw new SnapshotRejection('copy-outside-temporary-directory', 'Persisted copy is outside bridge temporary storage', fingerprint, copyHints);
        }
      }
      if (data.project.sourceDirectory !== data.record.workingDirectory) {
        throw new SnapshotRejection('source-mismatch', 'Persisted source differs from task', fingerprint, copyHints);
      }
      if (Boolean(data.project.executionPolicy) !== Boolean(data.project.executionStateDirectory) ||
          (data.project.executionPolicy && data.project.executionPolicy.policy.sha256 !== data.record.agentPolicy?.sha256) ||
          (data.project.executionStateDirectory && !this.tryOwnsExecutionState(data.project.executionStateDirectory, selfRealpath, migrationOrigin))) {
        throw new SnapshotRejection('execution-policy-mismatch', 'Persisted execution policy differs from task or private storage', fingerprint, copyHints);
      }
    }
    try {
      return { ...data, events: data.events.map(expandEvent), fingerprint, record: data.record as unknown as TaskRecord, options: data.options as RunOptions,
        project: data.project && { ...data.project, baseline: new Map(data.project.baseline) } };
    } catch {
      throw new SnapshotRejection('invalid-snapshot', 'Invalid persisted task: ' + name, fingerprint, copyHints);
    }
  }

  // With a source, only that file is read, validated as the snapshot the task file name would hold.
  load(source?: { file: string; name: string }): StoredTask[] {
    const names = source ? [source.name] : readdirSync(this.directory).filter(name => uuid.test(name.slice(0, -5)) && name.endsWith('.json'));
    const selfRealpath = realpathSync.native(this.directory);
    const migrationOrigin = readMigrationMarker(this.directory)?.source;
    const tasks: StoredTask[] = [];
    for (const name of names) {
      const file = source?.file ?? path.join(this.directory, name);
      try {
        const task = this.loadSnapshotFile(file, name, selfRealpath, migrationOrigin);
        if (task) tasks.push(task);
      } catch (error) {
        if (error instanceof SnapshotRejection) {
          if (error.rawError !== undefined) throw error.rawError;
          throw new BridgeError('INVALID_STATE', error.message);
        }
        throw error;
      }
    }
    return tasks.sort((a, b) => a.record.createdAt.localeCompare(b.record.createdAt));
  }

  loadWithQuarantine(): { tasks: StoredTask[]; quarantined: QuarantinedSnapshot[] } {
    const names = readdirSync(this.directory).filter(name => {
      if (!name.endsWith('.json')) return false;
      const stem = name.slice(0, -5);
      return stem === stem.toLowerCase() && canonicalUuidSchema.safeParse(stem).success;
    });
    const selfRealpath = realpathSync.native(this.directory);
    const migrationOrigin = readMigrationMarker(this.directory)?.source;
    const tasks: StoredTask[] = [];
    const quarantined: QuarantinedSnapshot[] = [];
    for (const name of names) {
      const file = path.join(this.directory, name);
      try {
        const task = this.loadSnapshotFile(file, name, selfRealpath, migrationOrigin);
        if (task) tasks.push(task);
      } catch (error) {
        if (error instanceof SnapshotRejection) {
          quarantined.push({
            taskId: name.slice(0, -5),
            reason: error.reason,
            ...(error.fingerprint !== undefined ? { fingerprint: error.fingerprint } : {}),
            copyHints: error.copyHints,
          });
        } else {
          throw error;
        }
      }
    }
    return {
      tasks: tasks.sort((a, b) => a.record.createdAt.localeCompare(b.record.createdAt)),
      quarantined: quarantined.sort((a, b) => a.taskId.localeCompare(b.taskId)),
    };
  }

  private readQuarantinedForDiscard(file: string, expectedFingerprint: string): z.infer<typeof snapshotSchema> {
    let stat;
    try {
      stat = lstatSync(file);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new BridgeError('STATE_BUSY', 'Quarantined task snapshot disappeared before discard');
      }
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 70_000_000) {
      throw new BridgeError('STATE_BUSY', 'Quarantined task snapshot changed before discard');
    }
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new BridgeError('STATE_BUSY', 'Quarantined task snapshot disappeared before discard');
      }
      throw new BridgeError('STATE_BUSY', 'Quarantined task snapshot could not be read for discard');
    }
    const fingerprint = createHash('sha256').update(text).digest('hex');
    if (fingerprint !== expectedFingerprint) {
      throw new BridgeError('STATE_BUSY', 'Quarantined task snapshot changed before discard');
    }
    let data: z.infer<typeof snapshotSchema>;
    try {
      data = snapshotSchema.parse(JSON.parse(text));
    } catch {
      throw new BridgeError('STATE_BUSY', 'Quarantined task snapshot changed before discard');
    }
    if (data.ownerPid !== process.pid && processAlive(data.ownerPid)) {
      throw new BridgeError('TASK_OWNED_BY_OTHER_SERVER', 'Discard the task in the bridge process that owns it');
    }
    if (!['completed', 'failed', 'cancelled', 'timeout'].includes(data.record.status)) {
      throw new BridgeError('TASK_NOT_READY', 'Cancel and wait for the task before discarding');
    }
    return data;
  }

  discardQuarantinedProject(taskId: string, expectedFingerprint: string): StoredTask {
    const file = this.file(taskId);
    let data = this.readQuarantinedForDiscard(file, expectedFingerprint);
    const lockNames = [...new Set(
      [data.project?.copyDirectory, data.record.copyDirectory]
        .filter((value): value is string => typeof value === 'string' && value.length > 0)
        .map(directory => copyLockName(directory)),
    )].sort();
    const releases: Array<() => void> = [];
    try {
      for (const lockName of lockNames) {
        releases.push(this.acquire(lockName));
      }
      if (releases.length > 0) {
        data = this.readQuarantinedForDiscard(file, expectedFingerprint);
      }
      const record = { ...data.record, discardedAt: new Date().toISOString() } as unknown as TaskRecord;
      const updated: StoredTask = {
        record,
        options: data.options as RunOptions,
        ownerPid: data.ownerPid,
        events: data.events.map(expandEvent),
        cursor: data.cursor,
        ...(data.redacted ? { redacted: true as const } : {}),
      };
      this.writeSnapshot(file, updated, true);
      return updated;
    } finally {
      while (releases.length > 0) releases.pop()!();
    }
  }

  // Sanitized copies of legacy snapshots are cached per source file version; the source file itself is left to its writers.
  /** Tasks carried over by the migration keep their receipts in the root they were created in. */
  private ownsExecutionState(directory: string, selfRealpath: string, migrationOrigin?: string): boolean {
    if (migrationOrigin && samePath(directory, migrationOrigin)) return true;
    return path.relative(realpathSync.native(directory), selfRealpath) === '';
  }

  private tryOwnsExecutionState(directory: string, selfRealpath: string, migrationOrigin?: string): boolean {
    try {
      return this.ownsExecutionState(directory, selfRealpath, migrationOrigin);
    } catch {
      return false;
    }
  }

  private sanitizedDirectory(): string {
    const directory = path.join(this.directory, 'sanitized');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (lstatSync(directory).isSymbolicLink() || !lstatSync(directory).isDirectory()) throw new BridgeError('INVALID_STATE', 'Sanitized state cache must be a real directory');
    return directory;
  }

  private sanitizedFile(taskId: string, fingerprint: string): string {
    if (!uuid.test(taskId) || !/^[a-f0-9]{64}$/.test(fingerprint)) throw new BridgeError('INVALID_STATE', 'Invalid sanitized state key');
    return path.join(this.sanitizedDirectory(), taskId + '-' + fingerprint + '.v' + SANITIZED_CACHE_VERSION + '.json');
  }

  loadSanitized(taskId: string, fingerprint: string): StoredTask | undefined {
    let file: string | undefined;
    try {
      file = this.sanitizedFile(taskId, fingerprint);
      const [cached] = this.load({ file, name: taskId + '.json' });
      return cached?.redacted ? cached : undefined;
    } catch {
      // A missing or invalid copy is rebuilt from the source snapshot.
      if (file) removeCachedFile(file);
      return undefined;
    }
  }

  saveSanitized(task: StoredTask, fingerprint: string): void {
    const target = this.sanitizedFile(task.record.taskId, fingerprint);
    this.writeSnapshot(target, task);
    this.dropSanitized(task.record.taskId, target);
  }

  private dropSanitized(taskId: string, keep?: string): void {
    const directory = this.sanitizedDirectory();
    for (const name of readdirSync(directory)) {
      const file = path.join(directory, name);
      if (name.startsWith(taskId + '-') && !name.endsWith('.tmp') && file !== keep) removeCachedFile(file);
    }
  }

  drop(taskId: string): void {
    rmSync(this.file(taskId), { force: true });
    try { this.dropSanitized(taskId); } catch { /* the cache never blocks removing a task */ }
  }

  acquire(name: string): () => void {
    if (!/^[a-zA-Z0-9-]+$/.test(name)) throw new BridgeError('INVALID_STATE', 'Invalid lock name');
    const file = path.join(this.directory, name + '.lock'), token = randomUUID();
    const root = lstatSync(this.directory, { bigint: true });
    const busy = () => new BridgeError('STATE_BUSY', 'Another operation owns this task or copy, or its lock cannot be verified');
    const checkRoot = () => {
      const current = lstatSync(this.directory, { bigint: true });
      if (current.isSymbolicLink() || !current.isDirectory() || current.dev !== root.dev || current.ino !== root.ino) {
        throw new BridgeError('INVALID_STATE', 'Private state storage identity changed');
      }
    };
    const inspect = (target: string) => {
      try {
        const stat = lstatSync(target, { bigint: true });
        if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n || stat.size < 1n || stat.size > 1024n) throw busy();
        const data = JSON.parse(readFileSync(target, 'utf8')) as { pid?: unknown; token?: unknown } | null;
        if (!data || typeof data !== 'object' || Array.isArray(data) || typeof data.pid !== 'number' ||
            !Number.isSafeInteger(data.pid) || data.pid < 1 ||
            (data.token !== undefined && (typeof data.token !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(data.token)))) throw busy();
        return { stat, pid: data.pid, token: data.token as string | undefined };
      } catch { throw busy(); }
    };
    const removeOwned = (target: string, owned: ReturnType<typeof inspect>) => {
      checkRoot();
      const current = inspect(target);
      if (current.stat.dev !== owned.stat.dev || current.stat.ino !== owned.stat.ino ||
          current.pid !== owned.pid || current.token !== owned.token) throw busy();
      rmSync(target);
    };
    for (let attempt = 0; attempt < 3; attempt++) {
      checkRoot();
      let created = false;
      try {
        writeFileSync(file, JSON.stringify({ pid: process.pid, token }), { flag: 'wx', mode: 0o600, flush: true });
        created = true;
      } catch (error) {
        // On Windows, exclusive creation of a delete-pending lock file yields EPERM instead of EEXIST.
        if (process.platform === 'win32' && (error as NodeJS.ErrnoException).code === 'EPERM') continue;
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      if (created) {
        const owned = inspect(file);
        if (owned.pid !== process.pid || owned.token !== token) throw busy();
        let released = false;
        return () => { if (released) return; removeOwned(file, owned); released = true; };
      }
      const observed = inspect(file);
      if (processAlive(observed.pid)) throw busy();
      // Serialize stale recovery. A leftover recovery gate fails closed for inspection.
      const gate = file + '.recovery', gateToken = randomUUID();
      try { writeFileSync(gate, JSON.stringify({ pid: process.pid, token: gateToken }), { flag: 'wx', mode: 0o600, flush: true }); }
      catch { throw busy(); }
      const ownedGate = inspect(gate);
      if (ownedGate.pid !== process.pid || ownedGate.token !== gateToken) throw busy();
      try {
        checkRoot();
        const current = inspect(file);
        if (current.stat.dev !== observed.stat.dev || current.stat.ino !== observed.stat.ino ||
            current.pid !== observed.pid || current.token !== observed.token || processAlive(current.pid)) throw busy();
        rmSync(file);
      } finally { removeOwned(gate, ownedGate); }
    }
    throw busy();
  }
}
