/**
 * Read-only OpenCode CLI execution adapter (library-only; write mode, session lifecycle, and cancellation are later work).
 * Runs `opencode` with `--standalone` so each invocation uses an isolated server and honors adapter environment variables.
 * Never passes `--auto`, so any permission resolving to "ask" is auto-rejected in non-interactive runs and classified as
 * `EXECUTION_INCOMPLETE`. Inherited `OPENCODE_*` variables are stripped and project/Claude configs are neutralized via the
 * `OPENCODE_*` environment variables constructed below.
 */
import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { cliEnvironment } from './cli-environment.js';
import {
  assertExecutionCapabilities,
  type ExecutionAdapter,
  type ExecutionAdapterIdentity,
  type ExecutionCapabilities,
  type ExecutionModel,
  type ExecutionRequest,
  type ExecutionResult,
} from './execution-contract.js';
import { LineParser } from './stream-parser.js';
import { decodeJsonEscapes, redactDiagnostic, type RedactionState } from './subprocess.js';
import { BridgeError } from './types.js';

export const OPENCODE_ADAPTER_VERSION = '1';
export const OPENCODE_READ_AGENT = 'black-gravity-read';
export const OPENCODE_READ_TOOLS = ['read', 'glob', 'grep'] as const;

const MAX_LINE_CHARS = 2_000_000;
const MAX_RESPONSE_CHARS = 1_048_576;
const MAX_STDERR_CHARS = 10_000;
const MAX_INCOMPLETE_ITEMS = 10;
const MAX_INCOMPLETE_ITEM_CHARS = 300;
const MAX_RAW_TOOL_CALLS = 50;
const MAX_RAW_TOOL_FIELD_CHARS = 100;

const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const LISTED_MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/\S+$/;
const VERSION_PATTERN = /^opencode v?(\S+)\s*$/m;
const READ_TOOLS_SET: ReadonlySet<string> = new Set(OPENCODE_READ_TOOLS);

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
}

export function openCodeReadOnlyPermissions(): OpenCodePermissionRule[] {
  return [
    { action: '*', resource: '*', effect: 'deny' },
    { action: 'read', resource: '*', effect: 'allow' },
    { action: 'glob', resource: '*', effect: 'allow' },
    { action: 'grep', resource: '*', effect: 'allow' },
  ];
}

export function openCodeConfigContent(): string {
  return JSON.stringify({
    permissions: openCodeReadOnlyPermissions(),
    agents: {
      [OPENCODE_READ_AGENT]: {
        description: 'Black Gravity read-only executor',
        mode: 'primary',
        permissions: openCodeReadOnlyPermissions(),
      },
    },
  });
}

export function openCodeEnvironment(
  allowedEnvVars: readonly string[],
  source: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
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
  env.OPENCODE_CONFIG_CONTENT = openCodeConfigContent();
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

export class OpenCodeExecutionAdapter implements ExecutionAdapter {
  readonly identity: ExecutionAdapterIdentity = {
    id: 'opencode-cli',
    provider: 'opencode',
    version: OPENCODE_ADAPTER_VERSION,
  };

  readonly capabilities: ExecutionCapabilities = Object.freeze({
    read: 'supported',
    write: 'unsupported',
    sandbox: 'unsupported',
    network: 'unknown',
    skills: 'unsupported',
    resources: 'unknown',
    structuredOutput: 'unsupported',
    cancel: 'unsupported',
    resume: 'unsupported',
    observableUsage: 'supported',
    modelList: 'supported',
  });

  constructor(private readonly options: OpenCodeAdapterOptions) {
    if (!path.isAbsolute(options.executable)) {
      throw new BridgeError('OPENCODE_UNAVAILABLE', 'OpenCode executable must be an absolute path');
    }
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

  async execute(request: ExecutionRequest): Promise<ExecutionResult> {
    assertExecutionCapabilities(request, this.capabilities);

    const model = request.model ?? undefined;
    if (model !== undefined && model !== '' && !MODEL_ID_PATTERN.test(model)) {
      throw new BridgeError('INVALID_MODEL', `Invalid OpenCode model identifier: ${redactDiagnostic(model).slice(0, 200)}`);
    }

    const prefixArgs = this.options.prefixArgs ? [...this.options.prefixArgs] : [];
    const args = [
      ...prefixArgs,
      'run', '--standalone', '--format', 'json', '--archived', '--agent', OPENCODE_READ_AGENT,
      ...(model ? ['--model', model] : []),
    ];
    const env = openCodeEnvironment(this.options.allowedEnvVars ?? [], this.options.env ?? process.env);
    applySanitizedChildPath(env, request.workingDirectory);
    env.PWD = request.workingDirectory;
    const childSecrets = childEnvironmentSecrets(env);
    const executable = this.resolveExecutable(request.workingDirectory, childSecrets);

    return await new Promise<ExecutionResult>((resolve, reject) => {
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(executable, args, {
          cwd: request.workingDirectory,
          env,
          windowsHide: true,
          shell: false,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (error) {
        reject(spawnFailureError(error, childSecrets));
        return;
      }

      let settled = false;
      let sessionID: string | undefined;
      let stepFinishes = 0;
      let protocolErrors = 0;
      let truncated = false;
      let totalResponseChars = 0;
      let stderr = '';
      const stderrState: RedactionState = {};
      const textParts = new Map<string, string>();
      const toolCalls: Array<{ tool: string; status: string }> = [];
      const incompleteItems: string[] = [];
      const errorMessages: string[] = [];
      const tokenAcc = createTokenAccumulator();

      const addIncomplete = (tool: string, detail: string) => {
        if (incompleteItems.length < MAX_INCOMPLETE_ITEMS) {
          incompleteItems.push(redactChild(`${tool}: ${detail}`, childSecrets).slice(0, MAX_INCOMPLETE_ITEM_CHARS));
        }
      };

      const stdoutParser = new LineParser(
        line => {
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
          if (sessionID === undefined) {
            const candidate = typeof parsed.sessionID === 'string' && parsed.sessionID
              ? parsed.sessionID
              : typeof part?.sessionID === 'string' && part.sessionID
                ? part.sessionID
                : undefined;
            if (candidate) sessionID = candidate;
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
              if (toolCalls.length < MAX_RAW_TOOL_CALLS) {
                toolCalls.push({
                  tool: redactChild(tool, childSecrets).slice(0, MAX_RAW_TOOL_FIELD_CHARS),
                  status: redactChild(status, childSecrets).slice(0, MAX_RAW_TOOL_FIELD_CHARS),
                });
              }
              if (!READ_TOOLS_SET.has(tool) || status !== 'completed') {
                const rawDetail = typeof state?.error === 'string' && state.error.trim()
                  ? state.error.trim()
                  : status;
                addIncomplete(tool, rawDetail);
              }
              break;
            }
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
              const msg = typeof errObj?.message === 'string' && errObj.message.trim()
                ? errObj.message.trim()
                : typeof parsed.error === 'string' && parsed.error.trim()
                  ? parsed.error.trim()
                  : 'OpenCode error event';
              errorMessages.push(redactChild(msg, childSecrets));
              break;
            }
            default:
              break;
          }
        },
        MAX_LINE_CHARS,
        () => {
          protocolErrors += 1;
        },
      );

      const stderrParser = new LineParser(
        line => {
          const redacted = redactChild(line, childSecrets, stderrState);
          stderr = appendBoundedStderr(stderr, redacted);
          const lower = redacted.toLowerCase();
          if (lower.includes('permission requested:') || lower.includes('auto-rejecting')) {
            addIncomplete('permission', redacted);
          }
        },
        MAX_LINE_CHARS,
        () => {
          stderr = appendBoundedStderr(stderr, '[stderr line truncated]');
        },
      );

      const onStdoutData = (chunk: Buffer) => stdoutParser.write(chunk);
      const onStderrData = (chunk: Buffer) => stderrParser.write(chunk);
      const onStdinError = () => {
        // Ignore EPIPE / closed stdin when child exits early or fails to spawn.
      };
      const onStreamError = () => {
        // Ignore stream errors; exit/close or child error governs settlement.
      };

      const cleanup = () => {
        child.stdin?.removeListener('error', onStdinError);
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
          child.stdin?.destroy();
          child.stdout?.destroy();
          child.stderr?.destroy();
        } catch {
          // Ignore stream destroy errors during spawn failure cleanup.
        }
        reject(spawnFailureError(error, childSecrets));
      };

      const onClose = (exitCode: number | null, signal: NodeJS.Signals | null) => {
        if (settled) return;
        settled = true;
        cleanup();

        stdoutParser.end();
        stderrParser.end();

        const response = redactChild([...textParts.values()].join('\n\n'), childSecrets);
        const usage = finalizeUsage(tokenAcc, stepFinishes);
        const session = sessionID ? { id: sessionID } : undefined;
        const baseRaw = {
          provider: 'opencode',
          exitCode,
          signal,
          sessionID: sessionID ? redactChild(sessionID, childSecrets) : null,
          stepFinishes,
          textParts: textParts.size,
          toolCalls,
          protocolErrors,
          truncated,
          ...(usage ? { usage } : {}),
        };

        if (incompleteItems.length > 0) {
          resolve({
            taskId: request.taskId,
            ...(session ? { session } : {}),
            ...(usage ? { usage } : {}),
            raw: baseRaw,
            status: 'failed',
            error: {
              code: 'EXECUTION_INCOMPLETE',
              message: `OpenCode run incomplete: ${incompleteItems.join('; ')}`,
            },
          });
          return;
        }

        if (exitCode !== 0 || signal !== null || errorMessages.length > 0 || protocolErrors > 0 || truncated) {
          const detail = errorMessages.length > 0
            ? errorMessages.join('; ')
            : stderr.trim()
              ? stderr.trim()
              : signal !== null
                ? `OpenCode terminated with signal ${signal}`
                : exitCode !== 0
                  ? `OpenCode exited with code ${exitCode ?? 'unknown'}`
                  : protocolErrors > 0
                    ? `OpenCode emitted ${protocolErrors} protocol error(s)`
                    : 'OpenCode response exceeded 1048576 characters and was truncated';
          resolve({
            taskId: request.taskId,
            ...(session ? { session } : {}),
            ...(usage ? { usage } : {}),
            raw: baseRaw,
            status: 'failed',
            error: {
              code: 'OPENCODE_PROCESS_FAILED',
              message: redactChild(detail, childSecrets),
            },
          });
          return;
        }

        if (stepFinishes === 0) {
          resolve({
            taskId: request.taskId,
            ...(session ? { session } : {}),
            ...(usage ? { usage } : {}),
            raw: baseRaw,
            status: 'failed',
            error: {
              code: 'OPENCODE_PROCESS_FAILED',
              message: 'OpenCode run produced no finished step',
            },
          });
          return;
        }

        resolve({
          taskId: request.taskId,
          ...(session ? { session } : {}),
          ...(usage ? { usage } : {}),
          raw: { ...baseRaw, response },
          status: 'completed',
          response,
        });
      };

      child.stdin?.on('error', onStdinError);
      child.stdout?.on('data', onStdoutData);
      child.stdout?.on('error', onStreamError);
      child.stderr?.on('data', onStderrData);
      child.stderr?.on('error', onStreamError);
      child.once('error', onChildError);
      child.once('close', onClose);

      child.stdin?.end(request.prompt, 'utf8');
    });
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

  private async runUtility(commandArgs: readonly string[]): Promise<string> {
    const prefixArgs = this.options.prefixArgs ? [...this.options.prefixArgs] : [];
    const args = [...prefixArgs, ...commandArgs];
    const env = openCodeEnvironment(this.options.allowedEnvVars ?? [], this.options.env ?? process.env);
    applySanitizedChildPath(env, undefined);
    const childSecrets = childEnvironmentSecrets(env);
    const executable = this.resolveExecutable(undefined, childSecrets);

    return await new Promise<string>((resolve, reject) => {
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(executable, args, {
          cwd: os.tmpdir(),
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

      const cleanup = () => {
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

      child.stdout?.on('data', onStdoutData);
      child.stdout?.on('error', onStreamError);
      child.stderr?.on('data', onStderrData);
      child.stderr?.on('error', onStreamError);
      child.once('error', onChildError);
      child.once('close', onClose);
    });
  }
}
