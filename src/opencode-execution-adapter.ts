/**
 * OpenCode CLI execution adapter.
 * Runs `opencode` with `--standalone` so each invocation uses an isolated server and honors adapter environment variables.
 * Write mode permits only file tools inside the isolated copy without an OS sandbox; shell commands, access outside
 * the copy, and web tools are denied by OpenCode configuration, and tests run through the bridge test executor.
 * Never passes `--auto`, so any permission resolving to "ask" is auto-rejected in non-interactive runs and classified as
 * `EXECUTION_INCOMPLETE`. Ordinary read/glob/grep missing-path and binary-file errors inside the copy are classified as
 * bounded `toolErrors` instead of `EXECUTION_INCOMPLETE`, while permission denials, external paths, write-tool errors,
 * disallowed tools, and unclassified errors remain incomplete. Inherited `OPENCODE_*` variables are stripped,
 * project/Claude configs are neutralized via the `OPENCODE_*` environment variables constructed below, and formatters and
 * language servers are disabled in both modes.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { readlinkSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MAX_DENIED_READS } from './agy-execution-adapter.js';
import { cliEnvironment } from './cli-environment.js';
import {
  assertExecutionCapabilities,
  type ExecutionAdapter,
  type ExecutionAdapterIdentity,
  type ExecutionCapabilities,
  type ExecutionContext,
  type ExecutionModel,
  type ExecutionRequest,
  type ExecutionResult,
} from './execution-contract.js';
import { detectBubblewrap, resolveTrustedBwrap } from './linux-executor.js';
import {
  countPidNamespaceMembers,
  expandMatchedTargets,
  listProcessIdentities,
  reconcileTrackedProcesses,
  verifyProcessIdentity,
  type ProcessIdentity,
} from './process-tree.js';
import { LineParser } from './stream-parser.js';
import {
  decodeJsonEscapes,
  redactDiagnostic,
  registerOwnedProcessGroup,
  terminateSubprocess,
  type RedactionState,
} from './subprocess.js';
import { BridgeError, type DeniedRead, type DeniedReads, type TaskRecord } from './types.js';

export const OPENCODE_ADAPTER_VERSION = '3';
export const MAX_OPENCODE_PROVIDER_RETRIES = 3;
export const OPENCODE_TERMINATION_GRACE_MS = 3000;
export const OPENCODE_RESUME_REQUIRES_PID_NAMESPACE = 'OPENCODE_RESUME_REQUIRES_PID_NAMESPACE';
export const OPENCODE_READ_AGENT = 'black-gravity-read';
export const OPENCODE_READ_TOOLS = ['read', 'glob', 'grep'] as const;
export const OPENCODE_WRITE_AGENT = 'black-gravity-write';
export const OPENCODE_WRITE_TOOLS = ['read', 'glob', 'grep', 'edit', 'write'] as const;

const MAX_LINE_CHARS = 2_000_000;
const MAX_RESPONSE_CHARS = 1_048_576;
const MAX_STDERR_CHARS = 10_000;
const MAX_INCOMPLETE_ITEMS = 10;
const MAX_INCOMPLETE_ITEM_CHARS = 300;
const MAX_RAW_TOOL_CALLS = 50;
const MAX_RAW_TOOL_FIELD_CHARS = 100;
const MAX_UNKNOWN_EFFECTS = 10;
const MAX_ERROR_MESSAGE_CHARS = 2000;
const MAX_TRACKED_PROCESSES = 256;

const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const LISTED_MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/\S+$/;
const SESSION_ID_PATTERN = /^ses_[A-Za-z0-9]{1,124}$/;
const VERSION_PATTERN = /^opencode v?(\S+)\s*$/m;
const REGION_UNAVAILABLE_PATTERN = /hosted outside Europe and the United States|privacy#regions/i;
const READ_TOOLS_SET: ReadonlySet<string> = new Set(OPENCODE_READ_TOOLS);
const WRITE_TOOLS_SET: ReadonlySet<string> = new Set(OPENCODE_WRITE_TOOLS);

export interface OpenCodePermissionRule {
  action: string;
  resource: string;
  effect: 'allow' | 'deny' | 'ask';
}

export interface OpenCodeAdapterOptions {
  executable: string;
  prefixArgs?: readonly string[];
  allowedEnvVars?: readonly string[];
  env?: NodeJS.ProcessEnv;
  listProcesses?: () => Promise<ProcessIdentity[]>;
  containment?: 'auto' | 'none';
  bwrapPath?: string;
}

export type OpenCodeExecutionResult = ExecutionResult & {
  readonly processCleanup?: TaskRecord['processCleanup'];
};

export function openCodeSecretReadRules(): OpenCodePermissionRule[] {
  return [
    { action: 'read', resource: '*.env', effect: 'deny' },
    { action: 'read', resource: '*.env.*', effect: 'deny' },
    { action: 'read', resource: '*.env.example', effect: 'allow' },
    { action: 'read', resource: '*.env.sample', effect: 'allow' },
    { action: 'read', resource: '*.env.template', effect: 'allow' },
    { action: 'read', resource: '*.env.dist', effect: 'allow' },
  ];
}

function buildOpenCodePermissions(writeRules: readonly OpenCodePermissionRule[] = []): OpenCodePermissionRule[] {
  return [
    { action: '*', resource: '*', effect: 'deny' },
    { action: 'read', resource: '*', effect: 'allow' },
    { action: 'glob', resource: '*', effect: 'allow' },
    { action: 'grep', resource: '*', effect: 'allow' },
    ...writeRules,
    { action: 'external_directory', resource: '*', effect: 'deny' },
    ...openCodeSecretReadRules(),
  ];
}

export function openCodeReadOnlyPermissions(): OpenCodePermissionRule[] {
  return buildOpenCodePermissions();
}

export function openCodeWritePermissions(): OpenCodePermissionRule[] {
  return buildOpenCodePermissions([
    { action: 'edit', resource: '*', effect: 'allow' },
    { action: 'edit', resource: '/*', effect: 'deny' },
    { action: 'edit', resource: '?:*', effect: 'deny' },
  ]);
}

export function openCodeConfigContent(mode: 'read-only' | 'write' = 'read-only'): string {
  const isWrite = mode === 'write';
  const permissions = isWrite ? openCodeWritePermissions() : openCodeReadOnlyPermissions();
  const agent = isWrite ? OPENCODE_WRITE_AGENT : OPENCODE_READ_AGENT;
  const description = isWrite
    ? 'Black Gravity write executor confined to the isolated copy'
    : 'Black Gravity read-only executor';
  return JSON.stringify({
    formatter: false,
    lsp: false,
    permissions,
    agents: {
      [agent]: {
        description,
        mode: 'primary',
        permissions,
      },
    },
  });
}

export function openCodeEnvironment(
  allowedEnvVars: readonly string[],
  source: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  mode: 'read-only' | 'write' = 'read-only',
): NodeJS.ProcessEnv {
  const env = cliEnvironment(allowedEnvVars, source, platform);
  const isWindows = platform === 'win32';
  for (const key of Object.keys(env)) {
    if (isWindows ? key.toUpperCase().startsWith('OPENCODE_') : key.startsWith('OPENCODE_')) {
      delete env[key];
    }
  }
  env.OPENCODE_DISABLE_PROJECT_CONFIG = '1';
  env.OPENCODE_CONFIG_PROJECT_DISABLE = '1';
  env.OPENCODE_DISABLE_CLAUDE_CODE = '1';
  env.OPENCODE_DISABLE_AUTOUPDATE = '1';
  env.OPENCODE_CONFIG_CONTENT = openCodeConfigContent(mode);
  return env;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asNonNegativeSafeInt(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function asNonNegativeFiniteNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function appendBoundedStderr(current: string, addition: string): string {
  const next = current ? `${current}\n${addition}` : addition;
  return next.length > MAX_STDERR_CHARS ? next.slice(-MAX_STDERR_CHARS) : next;
}

function spawnFailureError(error: unknown, secrets: readonly string[] = []): BridgeError {
  if (error instanceof BridgeError) return error;
  const raw = error instanceof Error ? error.message : String(error);
  return new BridgeError('OPENCODE_UNAVAILABLE', redactChild(`OpenCode CLI unavailable: ${raw}`, secrets));
}

const SECRET_ENV_NAME_PATTERN = /TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIAL/i;

function childEnvironmentSecrets(env: NodeJS.ProcessEnv): string[] {
  return Object.entries(env)
    .flatMap(([name, secret]) =>
      secret && secret.length >= 8 && SECRET_ENV_NAME_PATTERN.test(name)
        ? [secret, ...secret.split(/\r?\n/).filter(line => line !== secret && line.trim().length >= 8)]
        : [],
    )
    .sort((left, right) => right.length - left.length);
}

function redactChild(
  value: string | undefined | null,
  secrets: readonly string[],
  state?: RedactionState,
): string {
  const text = redactDiagnostic(value, state);
  if (!text || secrets.length === 0) return text;
  const replaceSecrets = (input: string): string => {
    let out = input;
    for (const secret of secrets) {
      out = out.split(secret).join('[redacted]');
    }
    return out;
  };
  const literalRedacted = replaceSecrets(text);
  const decoded = decodeJsonEscapes(text);
  if (decoded !== text && secrets.some(secret => decoded.includes(secret))) {
    return replaceSecrets(decoded);
  }
  return literalRedacted;
}

function isInsideOrEqualDirectory(
  candidatePath: string,
  directoryPath: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const pathImpl = platform === 'win32' ? path.win32 : path.posix;
  const from = platform === 'win32' ? directoryPath.toLowerCase() : directoryPath;
  const to = platform === 'win32' ? candidatePath.toLowerCase() : candidatePath;
  const relative = pathImpl.relative(from, to);
  return relative !== '..' && !relative.startsWith(`..${pathImpl.sep}`) && !pathImpl.isAbsolute(relative);
}

export function sanitizeChildPath(
  value: string | undefined,
  untrustedDirectory: string | undefined,
  platform: NodeJS.Platform = process.platform,
): string {
  if (!value) return '';
  const isWin32 = platform === 'win32';
  const delimiter = isWin32 ? ';' : ':';
  const pathImpl = isWin32 ? path.win32 : path.posix;

  let realUntrustedDir: string | undefined;
  if (untrustedDirectory !== undefined) {
    try {
      realUntrustedDir = realpathSync(untrustedDirectory);
    } catch {
      realUntrustedDir = untrustedDirectory;
    }
  }

  const kept: string[] = [];
  const seen = new Set<string>();
  for (const entry of value.split(delimiter)) {
    if (!entry || !pathImpl.isAbsolute(entry)) continue;
    let realEntry: string;
    try {
      realEntry = realpathSync(entry);
    } catch {
      continue;
    }
    if (realUntrustedDir !== undefined && isInsideOrEqualDirectory(realEntry, realUntrustedDir, platform)) {
      continue;
    }
    const dedupeKey = isWin32 ? realEntry.toLowerCase() : realEntry;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    kept.push(realEntry);
  }
  return kept.join(delimiter);
}

function applySanitizedChildPath(env: NodeJS.ProcessEnv, untrustedDirectory: string | undefined): void {
  const pathKey = process.platform === 'win32'
    ? Object.keys(env).find(key => key.toUpperCase() === 'PATH')
    : (Object.hasOwn(env, 'PATH') ? 'PATH' : undefined);
  if (pathKey !== undefined && typeof env[pathKey] === 'string') {
    env[pathKey] = sanitizeChildPath(env[pathKey], untrustedDirectory);
  }
}

interface TokenAccumulator {
  hasInput: boolean;
  input: number;
  hasOutput: boolean;
  output: number;
  hasReasoning: boolean;
  reasoning: number;
  hasCacheRead: boolean;
  cacheRead: number;
  hasTotal: boolean;
  total: number;
  hasCost: boolean;
  cost: number;
}

function createTokenAccumulator(): TokenAccumulator {
  return {
    hasInput: true,
    input: 0,
    hasOutput: true,
    output: 0,
    hasReasoning: true,
    reasoning: 0,
    hasCacheRead: true,
    cacheRead: 0,
    hasTotal: true,
    total: 0,
    hasCost: true,
    cost: 0,
  };
}

function accumulateStepFinish(acc: TokenAccumulator, part: Record<string, unknown> | undefined): void {
  const tokens = part && isRecord(part.tokens) ? part.tokens : undefined;
  const cache = tokens && isRecord(tokens.cache) ? tokens.cache : undefined;

  const input = asNonNegativeSafeInt(tokens?.input);
  if (input === undefined) acc.hasInput = false;
  else acc.input += input;

  const output = asNonNegativeSafeInt(tokens?.output);
  if (output === undefined) acc.hasOutput = false;
  else acc.output += output;

  const reasoning = asNonNegativeSafeInt(tokens?.reasoning);
  if (reasoning === undefined) acc.hasReasoning = false;
  else acc.reasoning += reasoning;

  const cacheRead = asNonNegativeSafeInt(cache?.read);
  if (cacheRead === undefined) acc.hasCacheRead = false;
  else acc.cacheRead += cacheRead;

  const total = asNonNegativeSafeInt(tokens?.total);
  if (total === undefined) acc.hasTotal = false;
  else acc.total += total;

  const cost = asNonNegativeFiniteNumber(part?.cost);
  if (cost === undefined) acc.hasCost = false;
  else acc.cost += cost;
}

function finalizeUsage(acc: TokenAccumulator, stepFinishes: number): Record<string, number> | undefined {
  if (stepFinishes === 0) return undefined;
  const usage: Record<string, number> = {};
  const inputOk = acc.hasInput && Number.isSafeInteger(acc.input);
  const outputOk = acc.hasOutput && Number.isSafeInteger(acc.output);
  const reasoningOk = acc.hasReasoning && Number.isSafeInteger(acc.reasoning);
  const cacheReadOk = acc.hasCacheRead && Number.isSafeInteger(acc.cacheRead);
  const totalOk = acc.hasTotal && Number.isSafeInteger(acc.total);

  if (inputOk) usage.input_tokens = acc.input;
  if (outputOk) usage.output_tokens = acc.output;
  if (reasoningOk) usage.thinking_tokens = acc.reasoning;
  if (cacheReadOk) usage.cache_read_tokens = acc.cacheRead;
  if (totalOk) {
    usage.total_tokens = acc.total;
  } else if (inputOk && outputOk && reasoningOk) {
    const derived = acc.input + acc.output + acc.reasoning;
    if (Number.isSafeInteger(derived)) usage.total_tokens = derived;
  }
  if (acc.hasCost && Number.isFinite(acc.cost)) usage.cost = acc.cost;

  return Object.keys(usage).length > 0 ? usage : undefined;
}

function terminationReason(signal: AbortSignal): 'cancelled' | 'timeout' {
  return signal.reason === 'timeout' ? 'timeout' : 'cancelled';
}

function terminationError(reason: 'cancelled' | 'timeout'): { code: string; message: string } {
  return reason === 'timeout'
    ? { code: 'TASK_TIMEOUT', message: 'Task execution timed out' }
    : { code: 'TASK_CANCELLED', message: 'Task cancelled' };
}

type ProviderErrorCode =
  | 'OPENCODE_REGION_UNAVAILABLE'
  | 'OPENCODE_AUTH_REQUIRED'
  | 'OPENCODE_QUOTA_EXCEEDED';

function classifyProviderError(errType: string | undefined, message: string): ProviderErrorCode | undefined {
  if (REGION_UNAVAILABLE_PATTERN.test(message)) {
    return 'OPENCODE_REGION_UNAVAILABLE';
  }
  if (errType === 'provider.auth') {
    return 'OPENCODE_AUTH_REQUIRED';
  }
  if (errType === 'provider.quota') {
    return 'OPENCODE_QUOTA_EXCEEDED';
  }
  return undefined;
}

const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f\u0085\u2028\u2029]/;
const READ_NOT_FOUND_WITH_DIR_RE = /^File not found: (.+)\n\nThe folder (.+) does not exist\. The nearest folder that does is (.+)\.$/;
const READ_NOT_FOUND_RE = /^File not found: (.+)$/;
const READ_BINARY_RE = /^Cannot read binary file: (.+)$/;
const SEARCH_PATH_MISSING_RE = /^Search path does not exist: (.+)$/;

function extractReadToolError(
  tool: string,
  error: string,
): { path: string; directories?: readonly [string, string] } | undefined {
  if (tool === 'read') {
    const withDir = READ_NOT_FOUND_WITH_DIR_RE.exec(error);
    if (withDir) {
      const [, filePath, missingDir, nearestDir] = withDir;
      if (
        !filePath ||
        !missingDir ||
        !nearestDir ||
        CONTROL_CHAR_RE.test(filePath) ||
        CONTROL_CHAR_RE.test(missingDir) ||
        CONTROL_CHAR_RE.test(nearestDir)
      ) {
        return undefined;
      }
      return { path: filePath, directories: [missingDir, nearestDir] };
    }
    const single = READ_NOT_FOUND_RE.exec(error) ?? READ_BINARY_RE.exec(error);
    if (!single?.[1] || CONTROL_CHAR_RE.test(single[1])) {
      return undefined;
    }
    return { path: single[1] };
  }
  if (tool === 'grep' || tool === 'glob') {
    const match = SEARCH_PATH_MISSING_RE.exec(error);
    if (!match?.[1] || CONTROL_CHAR_RE.test(match[1])) {
      return undefined;
    }
    return { path: match[1] };
  }
  return undefined;
}

export function classifyOpenCodeReadToolError(
  tool: string,
  error: string,
  input: unknown,
  workingDirectory: string,
  secrets: readonly string[] = [],
): DeniedRead | undefined {
  if (typeof tool !== 'string' || typeof error !== 'string' || typeof workingDirectory !== 'string' || !workingDirectory) {
    return undefined;
  }
  const extracted = extractReadToolError(tool, error);
  if (extracted === undefined) {
    return undefined;
  }

  const resolvedWorkingDir = path.resolve(workingDirectory);
  let realWorkingDir: string;
  try {
    realWorkingDir = path.resolve(realpathSync(resolvedWorkingDir));
  } catch {
    realWorkingDir = resolvedWorkingDir;
  }

  const isInsideWorkingDir = (candidate: string): boolean => {
    const resolved = path.resolve(resolvedWorkingDir, candidate);
    return (
      isInsideOrEqualDirectory(resolved, resolvedWorkingDir) ||
      isInsideOrEqualDirectory(resolved, realWorkingDir)
    );
  };

  if (![extracted.path, ...(extracted.directories ?? [])].every(isInsideWorkingDir)) {
    return undefined;
  }

  if (isRecord(input)) {
    for (const field of ['path', 'filePath'] as const) {
      const value = input[field];
      if (typeof value === 'string') {
        if (CONTROL_CHAR_RE.test(value) || !isInsideWorkingDir(value)) {
          return undefined;
        }
      }
    }
  }

  return {
    toolName: tool,
    path: redactChild(extracted.path, secrets).slice(0, 1000),
    reason: redactChild(error, secrets).slice(0, 500),
  };
}

function normalizeComparableDirectory(directory: string): string {
  const resolved = realpathSync(directory);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isChildUnreaped(child: ChildProcess): boolean {
  return child.exitCode === null && child.signalCode === null;
}

async function verifyPidNamespaceEmpty(
  link: string | undefined,
  timeoutMs = 3000,
): Promise<{ verified: boolean; remaining: number }> {
  if (!link) {
    return { verified: false, remaining: 0 };
  }
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let members: number;
    try {
      members = countPidNamespaceMembers(link);
    } catch {
      return { verified: false, remaining: 0 };
    }
    if (members === 0) {
      return { verified: true, remaining: 0 };
    }
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      return { verified: false, remaining: members };
    }
    await new Promise<void>(resolve => {
      setTimeout(resolve, Math.min(100, remainingMs));
    });
  }
}

interface ContainedCommandOptions {
  commandArgs: readonly string[];
  workingDirectory: string;
  executable: string;
  bwrapPath: string | undefined;
  env: NodeJS.ProcessEnv;
  childSecrets: readonly string[];
  context?: ExecutionContext;
  stdinText?: string;
  onStdoutLine: (line: string, requestStop: () => void) => void;
  onStdoutOverflow?: () => void;
  onStderrLine?: (line: string) => void;
  onStderrOverflow?: () => void;
}

interface ContainedCommandResult {
  containmentMode: 'pid-namespace' | 'process-tree';
  exitCode: number | null;
  closeSignal: NodeJS.Signals | null;
  hostStopReason: 'cancelled' | 'timeout' | undefined;
  processCleanup: NonNullable<TaskRecord['processCleanup']>;
}

export class OpenCodeExecutionAdapter implements ExecutionAdapter {
  readonly identity: ExecutionAdapterIdentity = {
    id: 'opencode-cli',
    provider: 'opencode',
    version: OPENCODE_ADAPTER_VERSION,
  };

  readonly capabilities: ExecutionCapabilities = Object.freeze({
    read: 'supported',
    write: 'supported',
    sandbox: 'unsupported',
    network: 'unknown',
    skills: 'unsupported',
    resources: 'unknown',
    structuredOutput: 'unsupported',
    cancel: 'supported',
    resume: 'supported',
    observableUsage: 'supported',
    modelList: 'supported',
  });

  constructor(private readonly options: OpenCodeAdapterOptions) {
    if (!path.isAbsolute(options.executable)) {
      throw new BridgeError('OPENCODE_UNAVAILABLE', 'OpenCode executable must be an absolute path');
    }
    if (options.bwrapPath !== undefined && (!options.bwrapPath || options.bwrapPath.includes('\0') || !path.isAbsolute(options.bwrapPath))) {
      throw new BridgeError('OPENCODE_UNAVAILABLE', 'Bubblewrap path must be an absolute path');
    }
  }

  private resolveBwrapPath(workingDirectory: string): string | undefined {
    const mode = this.options.containment ?? 'auto';
    if (mode === 'none' || process.platform !== 'linux') {
      return undefined;
    }
    if (this.options.bwrapPath !== undefined) {
      const trusted = resolveTrustedBwrap(this.options.bwrapPath, workingDirectory);
      if (!trusted) {
        throw new BridgeError('OPENCODE_UNAVAILABLE', 'Bubblewrap path must be outside the task working directory');
      }
      return trusted;
    }
    const detection = detectBubblewrap({ untrustedDirectory: workingDirectory });
    return detection.available && detection.path ? detection.path : undefined;
  }

  private wrapWithContainment(
    bwrapPath: string | undefined,
    workingDirectory: string,
    executable: string,
    args: readonly string[],
  ): { command: string; args: string[]; containment: 'pid-namespace' | 'process-tree' } {
    if (!bwrapPath) {
      return { command: executable, args: [...args], containment: 'process-tree' };
    }
    return {
      command: bwrapPath,
      args: [
        '--dev-bind', '/', '/',
        '--proc', '/proc',
        '--unshare-pid',
        '--die-with-parent',
        '--chdir', workingDirectory,
        '--',
        executable,
        ...args,
      ],
      containment: 'pid-namespace',
    };
  }

  private resolveExecutable(workingDirectory?: string, secrets: readonly string[] = []): string {
    let realExecutable: string;
    try {
      realExecutable = realpathSync(this.options.executable);
    } catch (error) {
      throw spawnFailureError(error, secrets);
    }
    if (workingDirectory !== undefined) {
      let realWorkingDir: string;
      try {
        realWorkingDir = realpathSync(workingDirectory);
      } catch (error) {
        throw spawnFailureError(error, secrets);
      }
      if (isInsideOrEqualDirectory(realExecutable, realWorkingDir)) {
        throw new BridgeError('OPENCODE_UNAVAILABLE', 'OpenCode executable must be outside the task working directory');
      }
    }
    return realExecutable;
  }

  async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<OpenCodeExecutionResult> {
    assertExecutionCapabilities(request, this.capabilities);

    if (context?.signal?.aborted) {
      const reason = terminationReason(context.signal);
      return {
        taskId: request.taskId,
        status: reason,
        error: terminationError(reason),
      };
    }

    const model = request.model ?? undefined;
    if (model !== undefined && model !== '' && !MODEL_ID_PATTERN.test(model)) {
      throw new BridgeError('INVALID_MODEL', `Invalid OpenCode model identifier: ${redactDiagnostic(model).slice(0, 200)}`);
    }

    if (request.session && !SESSION_ID_PATTERN.test(request.session.id)) {
      throw new BridgeError('INVALID_SESSION', `Invalid OpenCode session identifier: ${redactDiagnostic(request.session.id).slice(0, 200)}`);
    }

    const isWrite = request.mode === 'write';
    const agent = isWrite ? OPENCODE_WRITE_AGENT : OPENCODE_READ_AGENT;
    const allowedTools = isWrite ? WRITE_TOOLS_SET : READ_TOOLS_SET;

    const env = openCodeEnvironment(
      this.options.allowedEnvVars ?? [],
      this.options.env ?? process.env,
      process.platform,
      request.mode,
    );
    applySanitizedChildPath(env, request.workingDirectory);
    env.PWD = request.workingDirectory;
    const childSecrets = childEnvironmentSecrets(env);
    const executable = this.resolveExecutable(request.workingDirectory, childSecrets);
    const bwrapPath = this.resolveBwrapPath(request.workingDirectory);

    if (request.session && bwrapPath === undefined) {
      return {
        taskId: request.taskId,
        status: 'failed',
        error: {
          code: OPENCODE_RESUME_REQUIRES_PID_NAMESPACE,
          message: 'Resuming an OpenCode session requires the Bubblewrap PID namespace (Linux with bwrap available and containment auto); without it the bridge cannot confirm that the session check and the run left no processes. Start a new task instead.',
        },
      };
    }

    let sessionListCleanup: NonNullable<TaskRecord['processCleanup']> | undefined;
    if (request.session) {
      let listStdout = '';
      let listStdoutExceeded = false;
      const sessionListResult = await this.runContainedCommand({
        commandArgs: ['session', 'list', '--standalone', '--format', 'json'],
        workingDirectory: request.workingDirectory,
        executable,
        bwrapPath,
        env,
        childSecrets,
        context,
        onStdoutLine: line => {
          if (listStdoutExceeded) return;
          const next = `${line}\n`;
          if (listStdout.length + next.length > MAX_RESPONSE_CHARS) {
            listStdoutExceeded = true;
            return;
          }
          listStdout += next;
        },
        onStdoutOverflow: () => {
          listStdoutExceeded = true;
        },
      });
      sessionListCleanup = sessionListResult.processCleanup;

      if (sessionListResult.hostStopReason) {
        return {
          taskId: request.taskId,
          status: sessionListResult.hostStopReason,
          error: terminationError(sessionListResult.hostStopReason),
          processCleanup: sessionListResult.processCleanup,
        };
      }

      if (listStdoutExceeded || sessionListResult.exitCode !== 0 || sessionListResult.closeSignal !== null) {
        return {
          taskId: request.taskId,
          status: 'failed',
          error: {
            code: 'OPENCODE_SESSION_NOT_FOUND',
            message: `OpenCode session ${redactChild(request.session.id, childSecrets)} could not be confirmed`,
          },
          processCleanup: sessionListResult.processCleanup,
        };
      }

      let parsedList: unknown;
      try {
        parsedList = JSON.parse(listStdout);
      } catch {
        parsedList = undefined;
      }
      if (!Array.isArray(parsedList)) {
        return {
          taskId: request.taskId,
          status: 'failed',
          error: {
            code: 'OPENCODE_SESSION_NOT_FOUND',
            message: `OpenCode session ${redactChild(request.session.id, childSecrets)} could not be confirmed`,
          },
          processCleanup: sessionListResult.processCleanup,
        };
      }

      let expectedDir: string;
      try {
        expectedDir = normalizeComparableDirectory(request.workingDirectory);
      } catch (error) {
        throw spawnFailureError(error, childSecrets);
      }

      const matched = parsedList.some(entry => {
        if (!isRecord(entry) || entry.id !== request.session!.id || typeof entry.directory !== 'string' || !entry.directory) {
          return false;
        }
        try {
          return normalizeComparableDirectory(entry.directory) === expectedDir;
        } catch {
          return false;
        }
      });

      if (!matched) {
        return {
          taskId: request.taskId,
          status: 'failed',
          error: {
            code: 'OPENCODE_SESSION_NOT_FOUND',
            message: `OpenCode session ${redactChild(request.session.id, childSecrets)} does not belong to this task copy`,
          },
          processCleanup: sessionListResult.processCleanup,
        };
      }
    }

    if (context?.signal?.aborted) {
      const reason = terminationReason(context.signal);
      return {
        taskId: request.taskId,
        status: reason,
        error: terminationError(reason),
        ...(sessionListCleanup ? { processCleanup: sessionListCleanup } : {}),
      };
    }

    const commandArgs = [
      'run', '--standalone', '--format', 'json', '--archived', '--agent', agent,
      ...(model ? ['--model', model] : []),
      ...(request.session ? ['--session', request.session.id] : []),
    ];

    let sessionID: string | undefined;
    let sessionMismatch: string | undefined;
    let stepStarts = 0;
    let stepFinishes = 0;
    let protocolErrors = 0;
    let truncated = false;
    let totalResponseChars = 0;
    let stderr = '';
    const stderrState: RedactionState = {};
    const textParts = new Map<string, string>();
    const toolCalls: Array<{ tool: string; status: string }> = [];
    const latestToolCalls = new Map<string, { tool: string; status: string; detail: string }>();
    let toolCallSeq = 0;
    const incompleteItems: string[] = [];
    const classifiedToolErrorKeys = new Set<string>();
    const toolErrorItems: DeniedRead[] = [];
    let toolErrorTotal = 0;
    const errorMessages: string[] = [];
    let providerRetries = 0;
    let retryLimitStopRequested = false;
    let providerFailure: { code: string; message: string } | undefined;
    const tokenAcc = createTokenAccumulator();

    const addIncomplete = (tool: string, detail: string) => {
      if (incompleteItems.length < MAX_INCOMPLETE_ITEMS) {
        incompleteItems.push(redactChild(`${tool}: ${detail}`, childSecrets).slice(0, MAX_INCOMPLETE_ITEM_CHARS));
      }
    };

    const { containmentMode, exitCode, closeSignal, hostStopReason, processCleanup } = await this.runContainedCommand({
      commandArgs,
      workingDirectory: request.workingDirectory,
      executable,
      bwrapPath,
      env,
      childSecrets,
      context,
      stdinText: request.prompt,
      onStdoutLine: (line, requestStop) => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          protocolErrors += 1;
          return;
        }
        if (!isRecord(parsed)) {
          protocolErrors += 1;
          return;
        }

        const part = isRecord(parsed.part) ? parsed.part : undefined;
        for (const candidate of [parsed.sessionID, part?.sessionID]) {
          if (typeof candidate === 'string' && candidate.length > 0) {
            if (request.session && candidate !== request.session.id) {
              if (!sessionMismatch) {
                sessionMismatch = candidate;
                requestStop();
              }
              return;
            }
            if (sessionID === undefined) sessionID = candidate;
          }
        }

        switch (parsed.type) {
          case 'text': {
            const delta = typeof part?.text === 'string' ? part.text : '';
            const partId = typeof part?.id === 'string' && part.id ? part.id : '__default__';
            const isNew = !textParts.has(partId);
            const sepCost = isNew && textParts.size > 0 ? 2 : 0;
            if (!truncated) {
              const remaining = MAX_RESPONSE_CHARS - totalResponseChars - sepCost;
              if (remaining <= 0) {
                truncated = true;
              } else {
                const kept = delta.slice(0, remaining);
                if (kept.length < delta.length) truncated = true;
                textParts.set(partId, (textParts.get(partId) ?? '') + kept);
                totalResponseChars += sepCost + kept.length;
              }
            }
            break;
          }
          case 'reasoning':
            break;
          case 'tool_use': {
            const tool = typeof part?.tool === 'string' && part.tool ? part.tool : 'unknown';
            const state = part && isRecord(part.state) ? part.state : undefined;
            const status = typeof state?.status === 'string' && state.status ? state.status : 'unknown';
            const redactedTool = redactChild(tool, childSecrets).slice(0, MAX_RAW_TOOL_FIELD_CHARS);
            const redactedStatus = redactChild(status, childSecrets).slice(0, MAX_RAW_TOOL_FIELD_CHARS);
            if (toolCalls.length < MAX_RAW_TOOL_CALLS) {
              toolCalls.push({
                tool: redactedTool,
                status: redactedStatus,
              });
            }
            const callKey = typeof part?.callID === 'string' && part.callID
              ? part.callID
              : typeof part?.id === 'string' && part.id
                ? part.id
                : `__unnamed_${toolCallSeq}`;
            toolCallSeq += 1;
            const rawError = typeof state?.error === 'string' ? state.error : undefined;
            const rawDetail = rawError && rawError.trim()
              ? rawError.trim()
              : status;
            latestToolCalls.set(callKey, { tool: redactedTool, status: redactedStatus, detail: rawDetail });
            const classifiedToolError =
              status === 'error' && allowedTools.has(tool) && rawError !== undefined
                ? classifyOpenCodeReadToolError(tool, rawError, state?.input, request.workingDirectory, childSecrets)
                : undefined;
            if (classifiedToolError) {
              if (!classifiedToolErrorKeys.has(callKey)) {
                classifiedToolErrorKeys.add(callKey);
                toolErrorTotal += 1;
                if (toolErrorItems.length < MAX_DENIED_READS) {
                  toolErrorItems.push(classifiedToolError);
                }
              }
            } else if (!allowedTools.has(tool) || (status !== 'completed' && status !== 'pending' && status !== 'running')) {
              addIncomplete(tool, rawDetail);
            }
            break;
          }
          case 'step_start':
            stepStarts += 1;
            break;
          case 'step_finish':
            stepFinishes += 1;
            accumulateStepFinish(tokenAcc, part);
            break;
          case 'background_wait': {
            const jobs = Array.isArray(parsed.jobs) ? parsed.jobs.length : 0;
            addIncomplete('background_wait', jobs > 0 ? `${jobs} job(s)` : 'pending');
            break;
          }
          case 'error': {
            const errObj = isRecord(parsed.error) ? parsed.error : undefined;
            const errType = typeof errObj?.type === 'string' ? errObj.type.trim() : undefined;
            const rawMsg = typeof errObj?.message === 'string' && errObj.message.trim()
              ? errObj.message.trim()
              : typeof parsed.error === 'string' && parsed.error.trim()
                ? parsed.error.trim()
                : 'OpenCode error event';
            const redactedMsg = redactChild(rawMsg, childSecrets).slice(0, MAX_ERROR_MESSAGE_CHARS);
            errorMessages.push(redactedMsg);
            const classified = classifyProviderError(errType, redactedMsg);
            if (classified && !providerFailure) {
              providerFailure = { code: classified, message: redactedMsg };
              requestStop();
            }
            break;
          }
          case 'retry': {
            if (retryLimitStopRequested) break;
            providerRetries += 1;
            const errObj = isRecord(parsed.error) ? parsed.error : undefined;
            const errType = typeof errObj?.type === 'string' ? errObj.type.trim() : undefined;
            const errStatus = typeof errObj?.status === 'number' && Number.isFinite(errObj.status) ? errObj.status : undefined;
            const rawMsg = typeof errObj?.message === 'string' && errObj.message.trim()
              ? errObj.message.trim()
              : 'OpenCode provider retry';
            const redactedMsg = redactChild(rawMsg, childSecrets).slice(0, MAX_ERROR_MESSAGE_CHARS);
            const classified = classifyProviderError(errType, redactedMsg);
            if (classified && !providerFailure) {
              providerFailure = { code: classified, message: redactedMsg };
              requestStop();
            }
            if (providerRetries > MAX_OPENCODE_PROVIDER_RETRIES) {
              if (!providerFailure) {
                const typeLabel = errType ? redactChild(errType, childSecrets).slice(0, 100) : 'unknown';
                const statusLabel = errStatus !== undefined ? String(errStatus) : 'unknown';
                const message = redactChild(
                  `OpenCode exceeded provider retry limit (${MAX_OPENCODE_PROVIDER_RETRIES}) after ${typeLabel} (${statusLabel}): ${redactedMsg}`,
                  childSecrets,
                ).slice(0, MAX_ERROR_MESSAGE_CHARS);
                providerFailure = { code: 'OPENCODE_RETRY_LIMIT', message };
              }
              retryLimitStopRequested = true;
              requestStop();
            }
            break;
          }
          default:
            break;
        }
      },
      onStdoutOverflow: () => {
        protocolErrors += 1;
      },
      onStderrLine: line => {
        const redacted = redactChild(line, childSecrets, stderrState);
        stderr = appendBoundedStderr(stderr, redacted);
        const lower = redacted.toLowerCase();
        if (lower.includes('permission requested:') || lower.includes('auto-rejecting')) {
          addIncomplete('permission', redacted);
        }
      },
      onStderrOverflow: () => {
        stderr = appendBoundedStderr(stderr, '[stderr line truncated]');
      },
    });

    for (const item of latestToolCalls.values()) {
      if (item.status === 'pending' || item.status === 'running') {
        addIncomplete(item.tool, item.detail);
      }
    }

    const response = redactChild([...textParts.values()].join('\n\n'), childSecrets);
    const usage = finalizeUsage(tokenAcc, stepFinishes);
    const session = sessionID ? { id: sessionID } : undefined;
    const isCompleted =
      !hostStopReason &&
      !sessionMismatch &&
      !providerFailure &&
      incompleteItems.length === 0 &&
      exitCode === 0 &&
      closeSignal === null &&
      errorMessages.length === 0 &&
      protocolErrors === 0 &&
      !truncated &&
      stepFinishes > 0;

    const unknownEffects = isCompleted
      ? []
      : [...latestToolCalls.values()]
          .filter(item => item.status === 'pending' || item.status === 'running')
          .slice(0, MAX_UNKNOWN_EFFECTS)
          .map(({ tool, status }) => ({ tool, status }));

    if (isWrite && !isCompleted && stepStarts > stepFinishes && unknownEffects.length < MAX_UNKNOWN_EFFECTS) {
      if (!unknownEffects.some(item => item.tool === 'unknown' && item.status === 'interrupted')) {
        unknownEffects.push({ tool: 'unknown', status: 'interrupted' });
      }
    }

    const withUnknownEffects = (message: string): string => {
      if (unknownEffects.length === 0) return message;
      const summary = unknownEffects.map(item => `${item.tool}(${item.status})`).join(', ');
      return redactChild(`${message}; effects unknown for: ${summary}; inspect the copy before reuse`, childSecrets);
    };

    const baseRaw = {
      provider: 'opencode',
      containment: containmentMode,
      exitCode,
      signal: closeSignal,
      sessionID: sessionID ? redactChild(sessionID, childSecrets) : null,
      stepFinishes,
      textParts: textParts.size,
      toolCalls,
      protocolErrors,
      truncated,
      ...(providerRetries > 0 ? { providerRetries } : {}),
      ...(unknownEffects.length > 0 ? { unknownEffects } : {}),
      ...(usage ? { usage } : {}),
    };

    if (hostStopReason) {
      const err = terminationError(hostStopReason);
      return {
        taskId: request.taskId,
        ...(session ? { session } : {}),
        ...(usage ? { usage } : {}),
        raw: baseRaw,
        processCleanup,
        status: hostStopReason,
        error: {
          code: err.code,
          message: withUnknownEffects(err.message),
        },
      };
    }

    if (sessionMismatch) {
      return {
        taskId: request.taskId,
        ...(session ? { session } : {}),
        ...(usage ? { usage } : {}),
        raw: baseRaw,
        processCleanup,
        status: 'failed',
        error: {
          code: 'OPENCODE_SESSION_MISMATCH',
          message: withUnknownEffects(
            redactChild(
              `OpenCode returned session ${sessionMismatch} instead of requested session ${request.session?.id ?? ''}`,
              childSecrets,
            ),
          ),
        },
      };
    }

    if (providerFailure) {
      return {
        taskId: request.taskId,
        ...(session ? { session } : {}),
        ...(usage ? { usage } : {}),
        raw: baseRaw,
        processCleanup,
        status: 'failed',
        error: {
          code: providerFailure.code,
          message: withUnknownEffects(providerFailure.message),
        },
      };
    }

    if (incompleteItems.length > 0) {
      return {
        taskId: request.taskId,
        ...(session ? { session } : {}),
        ...(usage ? { usage } : {}),
        raw: baseRaw,
        processCleanup,
        status: 'failed',
        error: {
          code: 'EXECUTION_INCOMPLETE',
          message: withUnknownEffects(`OpenCode run incomplete: ${incompleteItems.join('; ')}`),
        },
      };
    }

    if (exitCode !== 0 || closeSignal !== null || errorMessages.length > 0 || protocolErrors > 0 || truncated) {
      const detail = errorMessages.length > 0
        ? errorMessages.join('; ')
        : stderr.trim()
          ? stderr.trim()
          : closeSignal !== null
            ? `OpenCode terminated with signal ${closeSignal}`
            : exitCode !== 0
              ? `OpenCode exited with code ${exitCode ?? 'unknown'}`
              : protocolErrors > 0
                ? `OpenCode emitted ${protocolErrors} protocol error(s)`
                : 'OpenCode response exceeded 1048576 characters and was truncated';
      return {
        taskId: request.taskId,
        ...(session ? { session } : {}),
        ...(usage ? { usage } : {}),
        raw: baseRaw,
        processCleanup,
        status: 'failed',
        error: {
          code: 'OPENCODE_PROCESS_FAILED',
          message: withUnknownEffects(redactChild(detail, childSecrets)),
        },
      };
    }

    if (stepFinishes === 0) {
      return {
        taskId: request.taskId,
        ...(session ? { session } : {}),
        ...(usage ? { usage } : {}),
        raw: baseRaw,
        processCleanup,
        status: 'failed',
        error: {
          code: 'OPENCODE_PROCESS_FAILED',
          message: withUnknownEffects('OpenCode run produced no finished step'),
        },
      };
    }

    const toolErrors: DeniedReads | undefined = toolErrorTotal > 0
      ? { total: toolErrorTotal, items: toolErrorItems }
      : undefined;

    return {
      taskId: request.taskId,
      ...(session ? { session } : {}),
      ...(usage ? { usage } : {}),
      raw: { ...baseRaw, response },
      processCleanup,
      status: 'completed',
      response,
      ...(toolErrors ? { toolErrors } : {}),
    };
  }

  private async runContainedCommand(options: ContainedCommandOptions): Promise<ContainedCommandResult> {
    const {
      commandArgs,
      workingDirectory,
      executable,
      bwrapPath,
      env,
      childSecrets,
      context,
      stdinText,
      onStdoutLine,
      onStdoutOverflow,
      onStderrLine,
      onStderrOverflow,
    } = options;

    const prefixArgs = this.options.prefixArgs ? [...this.options.prefixArgs] : [];
    const args = [...prefixArgs, ...commandArgs];

    const listProcesses = this.options.listProcesses ?? listProcessIdentities;
    const isPosix = process.platform !== 'win32';
    const usePidNamespace = bwrapPath !== undefined;
    const launch = this.wrapWithContainment(bwrapPath, workingDirectory, executable, args);
    const containmentMode = launch.containment;
    const spawnedAt = Date.now();
    let child: ChildProcess;
    try {
      child = spawn(launch.command, launch.args, {
        cwd: workingDirectory,
        env,
        detached: isPosix,
        windowsHide: true,
        shell: false,
        stdio: [stdinText !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      throw spawnFailureError(error, childSecrets);
    }

    if (isPosix && !usePidNamespace) {
      registerOwnedProcessGroup(child);
    }

    let childClosed = false;
    let exitCode: number | null = null;
    let closeSignal: NodeJS.Signals | null = null;

    const tracked = new Map<string, ProcessIdentity>();
    let rootStart: string | undefined;
    let capturedNsLink: string | undefined;
    let trackingFailed = false;
    const recordTracked = (list: readonly ProcessIdentity[]): ProcessIdentity[] => {
      if (child.pid === undefined) return [];
      const seeds: Array<{ pid: number; start?: string }> = [
        ...(rootStart !== undefined ? [{ pid: child.pid, start: rootStart }] : []),
        ...tracked.values(),
      ];
      const matched = expandMatchedTargets(list, seeds);
      for (const proc of matched) {
        if (proc.pid === child.pid && proc.start === rootStart) continue;
        const key = `${proc.pid}\0${proc.start}`;
        if (tracked.has(key)) continue;
        if (tracked.size >= MAX_TRACKED_PROCESSES) {
          trackingFailed = true;
          break;
        }
        tracked.set(key, proc);
      }
      return matched;
    };

    let initialCaptureDone = false;
    const initialCapturePromise = (async () => {
      if (child.pid === undefined) {
        trackingFailed = true;
        return;
      }
      if (usePidNamespace) {
        let selfNsLink: string;
        try {
          selfNsLink = readlinkSync('/proc/self/ns/pid');
        } catch {
          trackingFailed = true;
          return;
        }
        const deadline = Date.now() + 500;
        for (;;) {
          let list: ProcessIdentity[];
          try {
            list = await listProcesses();
          } catch {
            trackingFailed = true;
            return;
          }
          if (childClosed || !isChildUnreaped(child)) {
            trackingFailed = true;
            return;
          }
          const directChildren = list.filter(p => p.parentPid === child.pid);
          for (const directChild of directChildren) {
            try {
              const nsLink = readlinkSync(`/proc/${directChild.pid}/ns/pid`);
              if (nsLink && nsLink !== selfNsLink) {
                capturedNsLink = nsLink;
                return;
              }
            } catch {
              // Child may have exited or not be readable yet; keep checking.
            }
          }
          const remainingMs = deadline - Date.now();
          if (remainingMs <= 0) {
            trackingFailed = true;
            return;
          }
          await new Promise<void>(resolve => {
            const t = setTimeout(resolve, Math.min(10, remainingMs));
            t.unref();
          });
        }
      }
      try {
        const list = await listProcesses();
        if (childClosed || !isChildUnreaped(child)) {
          trackingFailed = true;
          return;
        }
        const rootEntry = list.find(p => p.pid === child.pid);
        if (rootEntry) {
          rootStart = rootEntry.start;
          recordTracked(list);
        } else {
          trackingFailed = true;
        }
      } catch {
        trackingFailed = true;
      }
    })().finally(() => {
      initialCaptureDone = true;
    });

    let hostStopReason: 'cancelled' | 'timeout' | undefined;
    let stopRequested = false;
    let stopPromise: Promise<void> | undefined;
    let graceTimer: NodeJS.Timeout | undefined;
    let resolveGrace: (() => void) | undefined;
    const graceElapsedPromise = new Promise<void>(resolve => {
      resolveGrace = resolve;
    });

    const clearGrace = () => {
      if (graceTimer) {
        clearTimeout(graceTimer);
        graceTimer = undefined;
      }
      resolveGrace?.();
      resolveGrace = undefined;
    };

    type StopReason = 'host-cancelled' | 'host-timeout' | 'caller';
    const stop = (reason: StopReason) => {
      stopRequested = true;
      if (reason === 'host-cancelled') hostStopReason ??= 'cancelled';
      else if (reason === 'host-timeout') hostStopReason ??= 'timeout';
      if (stopPromise) return;
      stopPromise = (async () => {
        await initialCapturePromise;
        if (childClosed || !isChildUnreaped(child) || child.pid === undefined) {
          clearGrace();
          return;
        }
        if (usePidNamespace) {
          try {
            child.kill('SIGKILL');
          } catch {
            // Ignore if already exited
          }
          return;
        }
        let freshList: ProcessIdentity[] | undefined;
        try {
          freshList = await listProcesses();
        } catch {
          trackingFailed = true;
        }
        if (childClosed || !isChildUnreaped(child) || child.pid === undefined) {
          clearGrace();
          return;
        }
        if (freshList !== undefined) {
          const rootInFresh = rootStart !== undefined && freshList.some(
            p => p.pid === child.pid && p.start === rootStart,
          );
          const matched = recordTracked(freshList);
          if (process.platform === 'win32') {
            if (rootInFresh && isChildUnreaped(child)) {
              try { child.kill(); } catch { /* ignore */ }
            }
          } else {
            if (rootInFresh && isChildUnreaped(child) && child.pid > 1) {
              try {
                process.kill(-child.pid, 'SIGTERM');
              } catch {
                if (isChildUnreaped(child)) {
                  try { child.kill('SIGTERM'); } catch { /* ignore */ }
                }
              }
            }
            for (const proc of matched) {
              if (proc.pid !== child.pid && proc.pid > 1 && verifyProcessIdentity(proc)) {
                try { process.kill(proc.pid, 'SIGTERM'); } catch { /* ignore */ }
              }
            }
          }
        }
        if (!childClosed) {
          graceTimer = setTimeout(() => {
            graceTimer = undefined;
            resolveGrace?.();
            resolveGrace = undefined;
          }, OPENCODE_TERMINATION_GRACE_MS);
          graceTimer.unref();
        } else {
          clearGrace();
        }
      })();
    };

    const requestStop = () => {
      stop('caller');
    };

    const stdoutParser = new LineParser(
      line => onStdoutLine(line, requestStop),
      MAX_LINE_CHARS,
      onStdoutOverflow,
    );
    const stderrParser = new LineParser(
      line => onStderrLine?.(line),
      MAX_LINE_CHARS,
      onStderrOverflow,
    );

    const onStdoutData = (chunk: Buffer) => stdoutParser.write(chunk);
    const onStderrData = (chunk: Buffer) => stderrParser.write(chunk);
    const onStdinError = () => {
      // Ignore EPIPE / closed stdin when child exits early or fails to spawn.
    };
    const onStreamError = () => {
      // Ignore stream errors; exit/close or child error governs settlement.
    };

    const onAbort = () => {
      if (!context?.signal) return;
      stop(terminationReason(context.signal) === 'timeout' ? 'host-timeout' : 'host-cancelled');
    };

    let pollInFlight = false;
    const pollTimer = !usePidNamespace
      ? setInterval(() => {
          if (childClosed || pollInFlight || child.pid === undefined || !initialCaptureDone) return;
          pollInFlight = true;
          void Promise.resolve().then(() => listProcesses()).then(
            list => {
              if (!childClosed) recordTracked(list);
            },
            () => {
              trackingFailed = true;
            },
          ).finally(() => {
            pollInFlight = false;
          });
        }, 1000)
      : undefined;
    pollTimer?.unref();

    const cleanupListeners = () => {
      if (pollTimer) clearInterval(pollTimer);
      clearGrace();
      context?.signal?.removeEventListener('abort', onAbort);
      child.stdin?.removeListener('error', onStdinError);
      child.stdout?.removeListener('data', onStdoutData);
      child.stdout?.removeListener('error', onStreamError);
      child.stderr?.removeListener('data', onStderrData);
      child.stderr?.removeListener('error', onStreamError);
    };

    let spawnError: Error | undefined;
    const closePromise = new Promise<void>(resolve => {
      const onChildError = (error: Error) => {
        if (childClosed) return;
        childClosed = true;
        spawnError = error;
        child.removeListener('close', onClose);
        resolve();
      };
      const onClose = (code: number | null, signal: NodeJS.Signals | null) => {
        if (childClosed) return;
        childClosed = true;
        exitCode = code;
        closeSignal = signal;
        child.removeListener('error', onChildError);
        clearGrace();
        resolve();
      };
      child.once('error', onChildError);
      child.once('close', onClose);
    });

    child.stdin?.on('error', onStdinError);
    child.stdout?.on('data', onStdoutData);
    child.stdout?.on('error', onStreamError);
    child.stderr?.on('data', onStderrData);
    child.stderr?.on('error', onStreamError);

    if (context?.signal) {
      if (context.signal.aborted) {
        onAbort();
      } else {
        context.signal.addEventListener('abort', onAbort, { once: true });
      }
    }

    let startHookError: unknown;
    let hasStartHookError = false;
    if (child.pid !== undefined && context?.onProcessStarted) {
      try {
        context.onProcessStarted(child.pid);
      } catch (error) {
        startHookError = error;
        hasStartHookError = true;
        stop('host-cancelled');
      }
    }

    await initialCapturePromise;
    if (!hasStartHookError) {
      if (stdinText !== undefined) {
        child.stdin?.end(stdinText, 'utf8');
      }
    } else {
      try {
        child.stdin?.destroy();
      } catch {
        // Ignore stdin destroy errors when aborting after hook failure.
      }
    }

    await Promise.race([closePromise, graceElapsedPromise]);
    if (pollTimer) clearInterval(pollTimer);
    context?.signal?.removeEventListener('abort', onAbort);

    if (spawnError && !hasStartHookError) {
      cleanupListeners();
      try {
        child.stdin?.destroy();
        child.stdout?.destroy();
        child.stderr?.destroy();
      } catch {
        // Ignore stream destroy errors during spawn failure cleanup.
      }
      throw spawnFailureError(spawnError, childSecrets);
    }

    if (stopPromise) {
      await stopPromise;
    }

    let cleanupVerified = false;
    let cleanupRemaining = 0;
    if (usePidNamespace) {
      if (!childClosed) {
        await Promise.race([
          closePromise,
          new Promise<void>(resolve => {
            const t = setTimeout(resolve, OPENCODE_TERMINATION_GRACE_MS);
            t.unref();
          }),
        ]);
      }
      if (childClosed && !spawnError && exitCode !== null && closeSignal === null && !stopRequested) {
        // Spontaneous exit counts as proof because bwrap (trusted) reaps the namespace init, and the kernel empties the namespace, before it exits; a bridge-initiated kill does not.
        cleanupVerified = true;
        cleanupRemaining = 0;
      } else {
        const nsCheck = await verifyPidNamespaceEmpty(capturedNsLink);
        cleanupVerified = nsCheck.verified && !trackingFailed;
        cleanupRemaining = nsCheck.remaining;
      }
    } else {
      if (!childClosed && child.pid !== undefined && isChildUnreaped(child)) {
        if (process.platform === 'win32') {
          try { child.kill('SIGKILL'); } catch { /* ignore */ }
        } else if (child.pid > 1) {
          try {
            process.kill(-child.pid, 'SIGKILL');
          } catch {
            if (isChildUnreaped(child)) {
              try { child.kill('SIGKILL'); } catch { /* ignore */ }
            }
          }
        }
      }

      const cleanup = child.pid !== undefined
        ? await reconcileTrackedProcesses(
            { pid: child.pid, ...(rootStart !== undefined ? { start: rootStart } : {}), processGroup: isPosix },
            [...tracked.values()],
            { list: listProcesses },
          )
        : { verified: false, method: 'process-tree' as const, remaining: [] };
      cleanupVerified = cleanup.verified && !trackingFailed;
      cleanupRemaining = cleanup.remaining.length;
    }

    if (!childClosed) {
      await Promise.race([
        closePromise,
        new Promise<void>(resolve => {
          const t = setTimeout(resolve, 250);
          t.unref();
        }),
      ]);
      try {
        child.stdin?.destroy();
        child.stdout?.destroy();
        child.stderr?.destroy();
      } catch {
        // Ignore stream destroy errors after reconciliation.
      }
    }

    cleanupListeners();
    stdoutParser.end();
    stderrParser.end();

    const processCleanup: NonNullable<TaskRecord['processCleanup']> = {
      verified: cleanupVerified,
      spawnedAt: new Date(spawnedAt).toISOString(),
      checkedAt: new Date().toISOString(),
      remaining: cleanupRemaining,
    };
    try {
      context?.onProcessCleanup?.(processCleanup);
    } catch (error) {
      if (!hasStartHookError) {
        throw error;
      }
    }
    if (hasStartHookError) {
      throw startHookError;
    }

    return {
      containmentMode,
      exitCode,
      closeSignal,
      hostStopReason,
      processCleanup,
    };
  }

  async listModels(): Promise<readonly ExecutionModel[]> {
    const stdout = await this.runUtility(['models', '--standalone']);
    const seen = new Set<string>();
    const models: ExecutionModel[] = [];
    for (const rawLine of stdout.split(/\r?\n/)) {
      const trimmed = rawLine.trim();
      if (!LISTED_MODEL_PATTERN.test(trimmed) || seen.has(trimmed)) continue;
      seen.add(trimmed);
      models.push({ id: trimmed });
    }
    return models;
  }

  async version(): Promise<string> {
    const stdout = await this.runUtility(['--version']);
    const match = VERSION_PATTERN.exec(stdout);
    if (!match?.[1]) {
      throw new BridgeError('OPENCODE_PROCESS_FAILED', 'Unexpected OpenCode --version output');
    }
    return match[1];
  }

  private async runUtility(
    commandArgs: readonly string[],
    options?: { cwd?: string; env?: NodeJS.ProcessEnv; signal?: AbortSignal; bwrapPath?: string },
  ): Promise<string> {
    if (options?.signal?.aborted) {
      throw new BridgeError('OPENCODE_PROCESS_FAILED', 'OpenCode utility command aborted');
    }

    const prefixArgs = this.options.prefixArgs ? [...this.options.prefixArgs] : [];
    const args = [...prefixArgs, ...commandArgs];
    const env = options?.env ?? (() => {
      const built = openCodeEnvironment(this.options.allowedEnvVars ?? [], this.options.env ?? process.env);
      applySanitizedChildPath(built, undefined);
      return built;
    })();
    const childSecrets = childEnvironmentSecrets(env);
    const executable = this.resolveExecutable(options?.cwd, childSecrets);
    const utilityCwd = options?.cwd ?? os.tmpdir();
    const launch = this.wrapWithContainment(options?.bwrapPath, utilityCwd, executable, args);

    return await new Promise<string>((resolve, reject) => {
      let child: ChildProcess;
      try {
        child = spawn(launch.command, launch.args, {
          cwd: utilityCwd,
          env,
          windowsHide: true,
          shell: false,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (error) {
        reject(spawnFailureError(error, childSecrets));
        return;
      }

      let settled = false;
      let stdout = '';
      let stdoutExceeded = false;
      let stderr = '';
      const stderrState: RedactionState = {};

      const stdoutParser = new LineParser(
        line => {
          if (stdoutExceeded) return;
          const next = `${line}\n`;
          if (stdout.length + next.length > MAX_RESPONSE_CHARS) {
            stdoutExceeded = true;
            return;
          }
          stdout += next;
        },
        MAX_LINE_CHARS,
        () => {
          stdoutExceeded = true;
        },
      );
      const stderrParser = new LineParser(
        line => {
          stderr = appendBoundedStderr(stderr, redactChild(line, childSecrets, stderrState));
        },
        MAX_LINE_CHARS,
      );

      const onStdoutData = (chunk: Buffer) => stdoutParser.write(chunk);
      const onStderrData = (chunk: Buffer) => stderrParser.write(chunk);
      const onStreamError = () => {
        // Ignore stream errors; child error/close governs settlement.
      };
      const onAbort = () => {
        terminateSubprocess(child);
      };

      const cleanup = () => {
        options?.signal?.removeEventListener('abort', onAbort);
        child.stdout?.removeListener('data', onStdoutData);
        child.stdout?.removeListener('error', onStreamError);
        child.stderr?.removeListener('data', onStderrData);
        child.stderr?.removeListener('error', onStreamError);
        child.removeListener('error', onChildError);
        child.removeListener('close', onClose);
      };

      const onChildError = (error: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        try {
          child.stdout?.destroy();
          child.stderr?.destroy();
        } catch {
          // Ignore stream destroy errors.
        }
        reject(spawnFailureError(error, childSecrets));
      };

      const onClose = (exitCode: number | null, signal: NodeJS.Signals | null) => {
        if (settled) return;
        settled = true;
        cleanup();
        stdoutParser.end();
        stderrParser.end();

        if (stdoutExceeded) {
          reject(new BridgeError('OPENCODE_PROCESS_FAILED', 'OpenCode output exceeded 1048576 characters'));
          return;
        }
        if (exitCode !== 0 || signal !== null) {
          const detail = stderr.trim()
            ? stderr.trim()
            : signal !== null
              ? `OpenCode terminated with signal ${signal}`
              : `OpenCode exited with code ${exitCode ?? 'unknown'}`;
          reject(new BridgeError('OPENCODE_PROCESS_FAILED', redactChild(detail, childSecrets)));
          return;
        }
        resolve(stdout);
      };

      if (options?.signal) {
        if (options.signal.aborted) {
          onAbort();
        } else {
          options.signal.addEventListener('abort', onAbort, { once: true });
        }
      }

      child.stdout?.on('data', onStdoutData);
      child.stdout?.on('error', onStreamError);
      child.stderr?.on('data', onStderrData);
      child.stderr?.on('error', onStreamError);
      child.once('error', onChildError);
      child.once('close', onClose);
    });
  }
}
