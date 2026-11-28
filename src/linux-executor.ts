import { accessSync, constants, realpathSync, statSync, type BigIntStats, type Stats } from 'node:fs';
import { access, chmod, lstat, mkdtemp, readdir, readlink, realpath, rm } from 'node:fs/promises';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import type { Writable } from 'node:stream';
import { defaultStateDirectory } from './config.js';
import { testCommandSchema, type TestCommand } from './native-tests.js';
import type { SandboxSelection } from './sandbox-policy.js';
import { registerOwnedProcessGroup } from './subprocess.js';
import { BridgeError } from './types.js';
import { redactExecutionDiagnostic } from './windows-executor.js';
import { assertNoLinkAncestryAsync, isOwnedWorkspacePath } from './workspace-paths.js';

export interface BubblewrapDetection {
  available: boolean;
  path?: string;
  version?: string;
  code?: string;
  reason?: string;
}

export interface BwrapSyncResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout?: string;
  stderr?: string;
  error?: Error;
}

export type BwrapSyncRunner = (
  file: string,
  args: readonly string[],
  options: { timeout: number; encoding: 'utf8' },
) => BwrapSyncResult;

export interface DetectBubblewrapOptions {
  platform?: NodeJS.Platform;
  bwrapPath?: string;
  env?: NodeJS.ProcessEnv;
  runner?: BwrapSyncRunner;
  useCache?: boolean;
  untrustedDirectory?: string;
}

export interface LinuxExecution {
  nonce: string;
  sandbox: 'linux-bwrap';
  exitCode: number | null;
  output: string;
  truncated: boolean;
  error?: string;
  processesReaped: boolean;
  bwrapVersion?: string;
  sandboxStarted?: boolean;
}

export interface LinuxExecutionOptions {
  timeoutSeconds: number;
  sandbox?: SandboxSelection;
  mode?: 'write' | 'read-only';
  stateDirectory?: string;
  maxFiles?: number;
  protectedPaths?: string[];
  signal?: AbortSignal;
  detection?: BubblewrapDetection;
  onProcess?: (child: ChildProcessWithoutNullStreams) => void;
}

export interface BuildBwrapArgsInput {
  command: TestCommand;
  copyDirectory: string;
  scratchDirectory: string;
  sandbox: SandboxSelection;
  mode?: 'write' | 'read-only';
  systemRootSymlinks?: readonly { path: string; target: string }[];
  toolchainPaths?: readonly string[];
  toolchainAliases?: readonly { source: string; destination: string }[];
  protectedDirs?: readonly string[];
  protectedFiles?: readonly string[];
  hostRuntimeDirectory?: string;
  resolvConfPath?: string;
  statusFd?: number;
  seccompFd?: number;
  environment: Readonly<Record<string, string>>;
}

export const LINUX_SYSTEM_ROOTS = [
  '/usr',
  '/bin',
  '/sbin',
  '/lib',
  '/lib32',
  '/lib64',
  '/libx32',
  '/etc',
  '/opt',
  '/nix/store',
] as const;

const BWRAP_PROBE_ARGS: readonly string[] = [
  '--unshare-all',
  '--unshare-user',
  '--die-with-parent',
  ...LINUX_SYSTEM_ROOTS.flatMap(root => ['--ro-bind-try', root, root]),
  '--proc', '/proc',
  '--dev', '/dev',
  '--setenv', 'PATH', '/usr/sbin:/usr/bin:/sbin:/bin',
  'true',
];

const BPF_LD_W_ABS = 0x20;
const BPF_ALU_AND_K = 0x54;
const BPF_JMP_JEQ_K = 0x15;
const BPF_JMP_JGE_K = 0x35;
const BPF_RET_K = 0x06;

const SECCOMP_DATA_NR_OFFSET = 0;
const SECCOMP_DATA_ARCH_OFFSET = 4;
const SECCOMP_DATA_ARG0_LOW_OFFSET = 16;
const SECCOMP_DATA_ARG1_LOW_OFFSET = 24;

const SECCOMP_RET_ALLOW = 0x7fff0000;
const SECCOMP_RET_ERRNO = 0x00050000;
const EAFNOSUPPORT = 97;
const ENOSYS = 38;
const AF_UNIX = 1;
const SOCK_STREAM = 1;
const SOCK_SEQPACKET = 5;
const SOCK_TYPE_MASK = 0xf;

const AUDIT_ARCH_X86_64 = 0xc000003e;
const AUDIT_ARCH_AARCH64 = 0xc00000b7;
const X64_NR_SOCKET = 41;
const X64_NR_SOCKETPAIR = 53;
const ARM64_NR_SOCKET = 198;
const ARM64_NR_SOCKETPAIR = 199;
const LINUX_NR_IO_URING_SETUP = 425;
const X32_SYSCALL_BIT = 0x40000000;

type FilterLabel = 'allow' | 'enosys' | 'eafnosupport' | 'socket' | 'socketpair';

interface SymbolicFilterInsn {
  label?: FilterLabel;
  code: number;
  jt?: FilterLabel;
  jf?: FilterLabel;
  k: number;
}

interface SockFilterInsn {
  code: number;
  jt: number;
  jf: number;
  k: number;
}

function seccompErrno(errno: number): number {
  return (SECCOMP_RET_ERRNO | (errno & 0xffff)) >>> 0;
}

export function buildUnixSocketSeccompFilter(arch: string): Buffer | undefined {
  const spec = arch === 'x64'
    ? { auditArch: AUDIT_ARCH_X86_64, socketNr: X64_NR_SOCKET, socketpairNr: X64_NR_SOCKETPAIR, x32Bit: X32_SYSCALL_BIT }
    : arch === 'arm64'
      ? { auditArch: AUDIT_ARCH_AARCH64, socketNr: ARM64_NR_SOCKET, socketpairNr: ARM64_NR_SOCKETPAIR, x32Bit: undefined }
      : undefined;
  if (!spec) return undefined;

  const symbolic: SymbolicFilterInsn[] = [
    { code: BPF_LD_W_ABS, k: SECCOMP_DATA_ARCH_OFFSET },
    { code: BPF_JMP_JEQ_K, jf: 'enosys', k: spec.auditArch },
    { code: BPF_LD_W_ABS, k: SECCOMP_DATA_NR_OFFSET },
    ...(spec.x32Bit !== undefined ? [{ code: BPF_JMP_JGE_K, jt: 'enosys' as const, k: spec.x32Bit }] : []),
    { code: BPF_JMP_JEQ_K, jt: 'enosys', k: LINUX_NR_IO_URING_SETUP },
    { code: BPF_JMP_JEQ_K, jt: 'socket', k: spec.socketNr },
    { code: BPF_JMP_JEQ_K, jt: 'socketpair', jf: 'allow', k: spec.socketpairNr },
    { label: 'socket', code: BPF_LD_W_ABS, k: SECCOMP_DATA_ARG0_LOW_OFFSET },
    { code: BPF_JMP_JEQ_K, jt: 'eafnosupport', jf: 'allow', k: AF_UNIX },
    { label: 'socketpair', code: BPF_LD_W_ABS, k: SECCOMP_DATA_ARG1_LOW_OFFSET },
    { code: BPF_ALU_AND_K, k: SOCK_TYPE_MASK },
    { code: BPF_JMP_JEQ_K, jt: 'allow', k: SOCK_STREAM },
    { code: BPF_JMP_JEQ_K, jt: 'allow', jf: 'eafnosupport', k: SOCK_SEQPACKET },
    { label: 'allow', code: BPF_RET_K, k: SECCOMP_RET_ALLOW },
    { label: 'enosys', code: BPF_RET_K, k: seccompErrno(ENOSYS) },
    { label: 'eafnosupport', code: BPF_RET_K, k: seccompErrno(EAFNOSUPPORT) },
  ];

  const labelIndices = new Map<FilterLabel, number>();
  for (let i = 0; i < symbolic.length; i++) {
    const label = symbolic[i]!.label;
    if (label) {
      if (labelIndices.has(label)) {
        throw new Error(`Duplicate seccomp BPF label: ${label}`);
      }
      labelIndices.set(label, i);
    }
  }

  const resolveJump = (target: FilterLabel | undefined, index: number): number => {
    if (!target) return 0;
    const targetIndex = labelIndices.get(target);
    if (targetIndex === undefined) {
      throw new Error(`Unknown seccomp BPF label: ${target}`);
    }
    const offset = targetIndex - (index + 1);
    if (offset < 0 || offset > 255) {
      throw new Error(`Seccomp BPF jump offset out of range (${offset}) from ${index} to ${target}`);
    }
    return offset;
  };

  const insns: SockFilterInsn[] = symbolic.map((insn, index) => ({
    code: insn.code,
    jt: resolveJump(insn.jt, index),
    jf: resolveJump(insn.jf, index),
    k: insn.k,
  }));

  const program = Buffer.alloc(insns.length * 8);
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i]!;
    const offset = i * 8;
    program.writeUInt16LE(insn.code, offset);
    program.writeUInt8(insn.jt, offset + 2);
    program.writeUInt8(insn.jf, offset + 3);
    program.writeUInt32LE(insn.k >>> 0, offset + 4);
  }
  return program;
}

let cachedDetection: BubblewrapDetection | undefined;

function shortReason(value: string): string {
  return redactExecutionDiagnostic(value.replace(/\s+/g, ' ').trim()).slice(0, 500);
}

function defaultBwrapSyncRunner(
  file: string,
  args: readonly string[],
  options: { timeout: number; encoding: 'utf8' },
): BwrapSyncResult {
  const result = spawnSync(file, [...args], {
    shell: false,
    encoding: options.encoding,
    timeout: options.timeout,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    ...(result.error ? { error: result.error } : {}),
  };
}

function isExecutableFile(candidate: string): boolean {
  try {
    if (!statSync(candidate).isFile()) return false;
    accessSync(candidate, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function resolveTrustedBwrap(candidate: string, untrustedDirectory: string): string | undefined {
  if (!candidate || candidate.includes('\0') || !path.isAbsolute(candidate) || !untrustedDirectory || untrustedDirectory.includes('\0')) {
    return undefined;
  }
  let realCandidate: string;
  try {
    realCandidate = realpathSync(candidate);
  } catch {
    return undefined;
  }
  let realUntrustedDir: string;
  try {
    realUntrustedDir = realpathSync(untrustedDirectory);
  } catch {
    realUntrustedDir = untrustedDirectory;
  }
  return posixContains(realUntrustedDir, realCandidate) ? undefined : realCandidate;
}

function findBwrapOnPath(pathValue: string | undefined, untrustedDirectory?: string): string | undefined {
  if (!pathValue) return undefined;
  for (const entry of pathValue.split(path.posix.delimiter)) {
    if (!entry || entry.includes('\0') || !entry.startsWith('/')) continue;
    const candidate = path.posix.join(entry, 'bwrap');
    if (!isExecutableFile(candidate)) continue;
    if (untrustedDirectory === undefined) return candidate;
    const trusted = resolveTrustedBwrap(candidate, untrustedDirectory);
    if (trusted !== undefined) return trusted;
  }
  return undefined;
}

export function detectBubblewrap(options?: DetectBubblewrapOptions): BubblewrapDetection {
  const canReadCache = !options || (
    options.platform === undefined &&
    options.bwrapPath === undefined &&
    options.env === undefined &&
    options.runner === undefined &&
    options.useCache !== false
  );
  const untrustedDirectory = options?.untrustedDirectory;
  const canStoreCache = canReadCache && untrustedDirectory === undefined;
  if (canReadCache && untrustedDirectory === undefined && cachedDetection) return cachedDetection;

  const store = (result: BubblewrapDetection): BubblewrapDetection => {
    if (canStoreCache) cachedDetection = result;
    return result;
  };

  const platform = options?.platform ?? process.platform;
  if (platform !== 'linux') {
    return store({ available: false, code: 'LINUX_BWRAP_MISSING', reason: 'unsupported-platform' });
  }

  let bwrapPath: string | undefined;
  if (options?.bwrapPath !== undefined) {
    if (!options.bwrapPath || options.bwrapPath.includes('\0') || !path.posix.isAbsolute(options.bwrapPath)) {
      return store({ available: false, code: 'LINUX_BWRAP_MISSING', reason: 'bwrap path must be absolute' });
    }
    if (!options.runner && !isExecutableFile(options.bwrapPath)) {
      return store({ available: false, code: 'LINUX_BWRAP_MISSING', reason: 'bwrap binary is missing or not executable' });
    }
    if (untrustedDirectory !== undefined) {
      const trusted = resolveTrustedBwrap(options.bwrapPath, untrustedDirectory);
      if (!trusted) {
        return store({ available: false, code: 'LINUX_BWRAP_MISSING', reason: 'bwrap path must be outside the task copy' });
      }
      bwrapPath = trusted;
    } else {
      bwrapPath = options.bwrapPath;
    }
  } else {
    bwrapPath = findBwrapOnPath((options?.env ?? process.env).PATH, untrustedDirectory);
    if (!bwrapPath) {
      return store({ available: false, code: 'LINUX_BWRAP_MISSING', reason: 'bwrap binary not found on absolute PATH entries' });
    }
  }

  if (canReadCache && untrustedDirectory !== undefined && cachedDetection?.path) {
    try {
      if (realpathSync(cachedDetection.path) === bwrapPath) {
        return { ...cachedDetection, path: bwrapPath };
      }
    } catch {
      // Ignore unresolvable cached path and probe freshly.
    }
  }

  const runner = options?.runner ?? defaultBwrapSyncRunner;
  const ver = runner(bwrapPath, ['--version'], { timeout: 5000, encoding: 'utf8' });
  if (ver.error) {
    const errno = (ver.error as NodeJS.ErrnoException).code;
    const reason = shortReason(ver.error.message) || 'bwrap binary is unavailable';
    if (errno === 'ENOENT' || errno === 'EACCES' || errno === 'ENOTDIR') {
      return store({ available: false, code: 'LINUX_BWRAP_MISSING', reason });
    }
    return store({ available: false, path: bwrapPath, code: 'LINUX_BWRAP_MISSING', reason });
  }
  if (ver.status !== 0) {
    const reason = shortReason(ver.stderr || ver.stdout || `bwrap --version exited with code ${ver.status ?? 'null'}`);
    return store({ available: false, path: bwrapPath, code: 'LINUX_BWRAP_MISSING', reason });
  }
  const version = (ver.stdout ?? '').trim().split(/\r?\n/)[0]?.trim() || undefined;

  const probe = runner(bwrapPath, BWRAP_PROBE_ARGS, { timeout: 5000, encoding: 'utf8' });
  if (probe.error || probe.status !== 0) {
    const raw = probe.stderr || probe.stdout || probe.error?.message || `bwrap namespace probe exited with code ${probe.status ?? 'null'}`;
    return store({
      available: false,
      path: bwrapPath,
      ...(version ? { version } : {}),
      code: 'LINUX_USER_NAMESPACES_BLOCKED',
      reason: shortReason(raw),
    });
  }

  return store({ available: true, path: bwrapPath, ...(version ? { version } : {}) });
}

function posixContains(root: string, target: string): boolean {
  const relative = path.posix.relative(root, target);
  return relative === '' || (!relative.startsWith('../') && relative !== '..' && !path.posix.isAbsolute(relative));
}

function posixOverlaps(left: string, right: string): boolean {
  return posixContains(left, right) || posixContains(right, left);
}

function isRestrictedToolchainPath(target: string, hostRuntimeDirectory?: string): boolean {
  return (
    target === '/' ||
    posixContains(target, '/tmp') ||
    posixContains(target, '/run') ||
    posixOverlaps(target, '/proc') ||
    posixOverlaps(target, '/dev') ||
    posixOverlaps(target, '/sys') ||
    (hostRuntimeDirectory !== undefined && posixOverlaps(target, hostRuntimeDirectory))
  );
}

function normalizePosixPaths(paths: readonly string[]): string[] {
  const normalized: string[] = [];
  for (const entry of paths) {
    if (!entry || entry.includes('\0') || !path.posix.isAbsolute(entry)) continue;
    normalized.push(path.posix.resolve(entry));
  }
  return normalized;
}

export function selectToolchainAliases(input: {
  candidates: readonly { original: string; real: string }[];
  toolchainPaths: readonly string[];
  homeRoots: readonly string[];
  cwd: string;
  protectedPaths: readonly string[];
  hostRuntimeDirectory?: string;
}): { source: string; destination: string }[] {
  if (!input.cwd || input.cwd.includes('\0') || !path.posix.isAbsolute(input.cwd)) return [];
  const cwd = path.posix.resolve(input.cwd);
  const toolchainPaths = normalizePosixPaths(input.toolchainPaths);
  const homeRoots = normalizePosixPaths(input.homeRoots);
  const protectedPaths = normalizePosixPaths(input.protectedPaths);
  const hostRuntimeDirectory =
    input.hostRuntimeDirectory && !input.hostRuntimeDirectory.includes('\0') && path.posix.isAbsolute(input.hostRuntimeDirectory)
      ? path.posix.resolve(input.hostRuntimeDirectory)
      : undefined;

  const selected = new Map<string, string>();
  for (const candidate of input.candidates) {
    if (
      !candidate.original ||
      !candidate.real ||
      candidate.original.includes('\0') ||
      candidate.real.includes('\0') ||
      !path.posix.isAbsolute(candidate.original) ||
      !path.posix.isAbsolute(candidate.real)
    ) {
      continue;
    }
    const original = path.posix.resolve(candidate.original);
    const real = path.posix.resolve(candidate.real);
    if (selected.has(original) || real === original) continue;
    if (
      isRestrictedToolchainPath(real, hostRuntimeDirectory) ||
      homeRoots.some(home => posixContains(real, home)) ||
      posixOverlaps(real, cwd) ||
      protectedPaths.some(blocked => posixOverlaps(real, blocked))
    ) {
      continue;
    }
    if (
      isRestrictedToolchainPath(original, hostRuntimeDirectory) ||
      LINUX_SYSTEM_ROOTS.some(root => posixContains(root, original)) ||
      toolchainPaths.some(toolchain => posixContains(toolchain, original)) ||
      homeRoots.some(home => posixContains(original, home)) ||
      posixOverlaps(original, cwd) ||
      protectedPaths.some(blocked => posixOverlaps(original, blocked))
    ) {
      continue;
    }
    selected.set(original, real);
  }
  return [...selected.entries()].map(([destination, source]) => ({ source, destination }));
}

export function parseBwrapStatus(text: string): { childPid?: number; exitCode?: number } {
  const result: { childPid?: number; exitCode?: number } = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
    const record = parsed as Record<string, unknown>;
    const childPid = record['child-pid'];
    if (typeof childPid === 'number' && Number.isInteger(childPid) && childPid > 0) {
      result.childPid = childPid;
    }
    const exitCode = record['exit-code'];
    if (typeof exitCode === 'number' && Number.isInteger(exitCode)) {
      result.exitCode = exitCode;
    }
  }
  return result;
}

export function buildBwrapArgs(input: BuildBwrapArgsInput): string[] {
  const args: string[] = [
    ...(input.statusFd !== undefined ? ['--json-status-fd', String(input.statusFd)] : []),
    '--unshare-all',
    '--unshare-user',
    ...(input.sandbox.network === true ? ['--share-net'] : []),
    '--die-with-parent',
    '--new-session',
  ];
  const rootSymlinks = new Map<string, string>();
  for (const entry of input.systemRootSymlinks ?? []) {
    if (!entry.path || !entry.target || entry.target.includes('\0')) continue;
    if (!rootSymlinks.has(entry.path)) rootSymlinks.set(entry.path, entry.target);
  }
  for (const root of LINUX_SYSTEM_ROOTS) {
    const symlinkTarget = rootSymlinks.get(root);
    if (symlinkTarget !== undefined) {
      args.push('--symlink', symlinkTarget, root);
    } else {
      args.push('--ro-bind-try', root, root);
    }
  }
  args.push(
    '--dev', '/dev',
    '--proc', '/proc',
    '--tmpfs', '/tmp',
    '--tmpfs', '/run',
  );
  let resolvedHostRuntimeDir: string | undefined;
  let runtimeDir: string | undefined;
  if (input.hostRuntimeDirectory && !input.hostRuntimeDirectory.includes('\0') && path.posix.isAbsolute(input.hostRuntimeDirectory)) {
    resolvedHostRuntimeDir = path.posix.resolve(input.hostRuntimeDirectory);
    if (resolvedHostRuntimeDir !== '/' && !posixContains('/run', resolvedHostRuntimeDir) && !posixContains('/tmp', resolvedHostRuntimeDir)) {
      runtimeDir = resolvedHostRuntimeDir;
      args.push('--tmpfs', runtimeDir);
    }
  }
  if (input.sandbox.network === true && input.resolvConfPath && !input.resolvConfPath.includes('\0') && path.posix.isAbsolute(input.resolvConfPath)) {
    const resolvPath = path.posix.resolve(input.resolvConfPath);
    if (resolvPath !== '/run' && posixContains('/run', resolvPath)) {
      args.push('--ro-bind-try', resolvPath, resolvPath);
    }
  }
  for (const toolchainPath of input.toolchainPaths ?? []) {
    if (!toolchainPath || toolchainPath.includes('\0') || !path.posix.isAbsolute(toolchainPath)) continue;
    if (isRestrictedToolchainPath(path.posix.resolve(toolchainPath), resolvedHostRuntimeDir)) continue;
    args.push('--ro-bind-try', toolchainPath, toolchainPath);
  }
  for (const alias of input.toolchainAliases ?? []) {
    if (
      !alias.source ||
      !alias.destination ||
      alias.source.includes('\0') ||
      alias.destination.includes('\0') ||
      !path.posix.isAbsolute(alias.source) ||
      !path.posix.isAbsolute(alias.destination) ||
      isRestrictedToolchainPath(path.posix.resolve(alias.source), resolvedHostRuntimeDir) ||
      isRestrictedToolchainPath(path.posix.resolve(alias.destination), resolvedHostRuntimeDir)
    ) {
      continue;
    }
    args.push('--ro-bind-try', alias.source, alias.destination);
  }
  for (const dir of input.protectedDirs ?? []) {
    args.push('--tmpfs', dir);
  }
  for (const file of input.protectedFiles ?? []) {
    args.push('--ro-bind', '/dev/null', file);
  }
  args.push(input.mode === 'read-only' ? '--ro-bind' : '--bind', input.copyDirectory, input.copyDirectory);
  args.push('--bind', input.scratchDirectory, input.scratchDirectory);
  for (const readPath of input.sandbox.readPaths) {
    args.push('--ro-bind', readPath, readPath);
  }
  for (const writePath of input.sandbox.writePaths) {
    args.push('--bind', writePath, writePath);
  }
  args.push('--remount-ro', '/run');
  if (runtimeDir) {
    args.push('--remount-ro', runtimeDir);
  }
  for (const dir of input.protectedDirs ?? []) {
    args.push('--remount-ro', dir);
  }
  args.push('--remount-ro', '/');
  if (input.seccompFd !== undefined) {
    args.push('--seccomp', String(input.seccompFd));
  }
  args.push('--chdir', input.copyDirectory, '--clearenv');
  for (const [key, value] of Object.entries(input.environment)) {
    args.push('--setenv', key, value);
  }
  args.push('--', input.command.executable, ...input.command.args);
  return args;
}

function contains(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}

function overlaps(left: string, right: string): boolean {
  return contains(left, right) || contains(right, left);
}

function validateLinuxCommand(command: TestCommand): void {
  const parsed = testCommandSchema.safeParse(command);
  if (!parsed.success || command.executable.includes('\0') || command.args.some(arg => arg.includes('\0'))) {
    throw new BridgeError('INVALID_TEST_COMMAND', 'Test command contains invalid arguments or NUL bytes');
  }
}

async function ownedDirectory(directory: string, temp: string, prefix: string, stateDirectory?: string): Promise<string> {
  const stat = await lstat(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor temporary storage was replaced or linked');
  }
  const canonical = await realpath(directory);
  if (stateDirectory) {
    const canonicalState = await realpath(stateDirectory).catch(() => undefined);
    if (canonicalState && isOwnedWorkspacePath(canonical, 'copy', [canonicalState])) {
      await assertNoLinkAncestryAsync(directory, canonicalState);
      return canonical;
    }
  }
  if (path.dirname(canonical) !== temp || !path.basename(canonical).startsWith(prefix)) {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor temporary storage was replaced or linked');
  }
  return canonical;
}

async function restoreScratchDirectoryPermissions(root: string): Promise<void> {
  const stack: string[] = [root];
  while (stack.length > 0) {
    const current = stack.pop()!;
    let stat: Stats;
    try {
      stat = await lstat(current);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      continue;
    }
    try {
      await chmod(current, 0o700);
    } catch {
      // Ignore chmod errors and continue best-effort restoration.
    }
    let entries: string[];
    try {
      entries = await readdir(current);
    } catch {
      continue;
    }
    for (const entry of entries) {
      stack.push(path.join(current, entry));
    }
  }
}

async function removeOwnedScratch(
  directory: string,
  expectedStat: BigIntStats | undefined,
  temp: string,
  restorePermissions: boolean,
): Promise<void> {
  if (!expectedStat?.isDirectory() || expectedStat.isSymbolicLink()) {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor scratch storage ownership was not captured');
  }
  const baseName = path.basename(directory);
  if (!baseName.startsWith('black-gravity-scratch-') || baseName === '.' || baseName === '..') {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor scratch storage prefix mismatch');
  }
  let stat: BigIntStats;
  try {
    stat = await lstat(directory, { bigint: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor scratch storage was replaced or linked');
  }
  const canonical = await realpath(directory);
  if (path.dirname(canonical) !== temp || path.resolve(canonical) !== path.resolve(directory)) {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor scratch storage was replaced or linked');
  }
  if (stat.dev !== expectedStat.dev || stat.ino !== expectedStat.ino || stat.birthtimeNs !== expectedStat.birthtimeNs) {
    throw new BridgeError('UNSAFE_RUNTIME_PATH', 'Linux executor scratch storage identity changed');
  }
  if (restorePermissions) {
    await restoreScratchDirectoryPermissions(canonical);
  }
  await rm(canonical, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function isProcessGroupGone(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ESRCH';
  }
}

const MAX_FIFO_SCAN_ENTRIES = 200000;

export async function findFifoInTrees(
  roots: readonly string[],
  maxEntries: number,
): Promise<{ fifo?: string; limitExceeded?: boolean; uninspectable?: string }> {
  let visited = 0;
  const stack: string[] = [];
  for (let i = roots.length - 1; i >= 0; i -= 1) {
    const root = roots[i];
    if (root && !root.includes('\0')) {
      stack.push(path.resolve(root));
    }
  }

  while (stack.length > 0) {
    const current = stack.pop()!;
    let stat: Stats;
    try {
      stat = await lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        continue;
      }
      return { uninspectable: current };
    }
    visited += 1;
    if (visited > maxEntries) {
      return { limitExceeded: true };
    }
    if (stat.isSymbolicLink()) {
      continue;
    }
    if (stat.isFIFO()) {
      return { fifo: current };
    }
    if (!stat.isDirectory()) {
      continue;
    }
    try {
      await access(current, constants.X_OK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        continue;
      }
      return { uninspectable: current };
    }
    let entries: string[];
    try {
      entries = await readdir(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        continue;
      }
      return { uninspectable: current };
    }
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      stack.push(path.join(current, entries[i]!));
    }
  }

  return {};
}

export async function executeLinuxTest(
  command: TestCommand,
  copyDirectory: string,
  options: LinuxExecutionOptions,
): Promise<LinuxExecution> {
  options.signal?.throwIfAborted();
  const selection: SandboxSelection = options.sandbox ?? {
    readPaths: [],
    writePaths: [],
    network: false,
    childProcesses: true,
    maxOutputChars: 4000,
  };
  if (selection.childProcesses === false) {
    throw new BridgeError('SANDBOX_PERMISSIONS_UNSUPPORTED', 'Linux bwrap executor cannot enforce childProcesses: false');
  }
  validateLinuxCommand(command);

  const detection = options.detection ?? detectBubblewrap({ untrustedDirectory: copyDirectory });
  if (!detection.available || !detection.path) {
    throw new BridgeError(detection.code ?? 'LINUX_BWRAP_MISSING', detection.reason ?? 'Bubblewrap is unavailable');
  }
  const bwrapPath = resolveTrustedBwrap(detection.path, copyDirectory);
  if (!bwrapPath) {
    throw new BridgeError('LINUX_BWRAP_MISSING', 'bwrap path must be outside the task copy');
  }

  const effectiveStateDir = options.stateDirectory ? path.resolve(options.stateDirectory) : defaultStateDirectory();
  const temp = await realpath(os.tmpdir());
  const cwd = await ownedDirectory(
    copyDirectory,
    temp,
    path.basename(copyDirectory).startsWith('agy-mcp-copy-') ? 'agy-mcp-copy-' : 'black-gravity-copy-',
    effectiveStateDir,
  );

  const candidateProtected = [
    ...(options.protectedPaths ?? []),
    effectiveStateDir,
  ];
  const canonicalProtected: string[] = [];
  const protectedDirSet = new Set<string>();
  const protectedFileSet = new Set<string>();

  for (const rawPath of candidateProtected) {
    if (!rawPath || rawPath.includes('\0')) continue;
    let resolved: string;
    try { resolved = await realpath(rawPath); } catch { resolved = path.resolve(rawPath); }
    canonicalProtected.push(resolved);
    if (resolved === '/' || resolved === '/tmp') continue;
    const info = await lstat(resolved).catch(() => undefined);
    if (!info) continue;
    if (info.isDirectory()) protectedDirSet.add(resolved);
    else if (info.isFile()) protectedFileSet.add(resolved);
  }

  const validateGrantPath = async (grant: string): Promise<string> => {
    if (!path.isAbsolute(grant) || grant.includes('\0')) {
      throw new BridgeError('INVALID_SANDBOX_PATH', 'Linux permission targets must be absolute paths');
    }
    const canonicalGrant = await realpath(grant);
    if (canonicalGrant === '/' || canonicalProtected.some(blocked => overlaps(blocked, canonicalGrant))) {
      throw new BridgeError('SANDBOX_PATH_PROTECTED', 'Linux permission target overlaps a protected path or filesystem root');
    }
    return canonicalGrant;
  };
  const canonicalReadPaths: string[] = [];
  for (const grant of selection.readPaths) {
    canonicalReadPaths.push(await validateGrantPath(grant));
  }
  for (const grant of selection.writePaths) {
    await validateGrantPath(grant);
  }

  const sortedDirs = [...protectedDirSet].sort((a, b) => a.length - b.length || a.localeCompare(b));
  const protectedDirs = sortedDirs.filter(dir => !sortedDirs.some(parent => parent !== dir && contains(parent, dir)));
  const protectedFiles = [...protectedFileSet].sort();

  const nonce = randomUUID();
  const preSpawnFailure = (errorMessage: string): LinuxExecution => ({
    nonce,
    sandbox: 'linux-bwrap',
    exitCode: null,
    output: '',
    truncated: false,
    error: errorMessage,
    processesReaped: true,
    ...(detection.version !== undefined ? { bwrapVersion: detection.version } : {}),
    sandboxStarted: false,
  });

  const seccompFilter = selection.network === true ? undefined : buildUnixSocketSeccompFilter(process.arch);
  if (selection.network !== true && !seccompFilter) {
    return preSpawnFailure(`Unix socket filter is not available for architecture ${process.arch}`);
  }

  const scratch = await realpath(await mkdtemp(path.join(temp, 'black-gravity-scratch-')));
  const scratchStat = await lstat(scratch, { bigint: true });

  const rawRuntimeDir = process.env.XDG_RUNTIME_DIR;
  let hostRuntimeDirectory: string | undefined;
  if (rawRuntimeDir && !rawRuntimeDir.includes('\0') && path.posix.isAbsolute(rawRuntimeDir)) {
    try {
      const resolved = await realpath(rawRuntimeDir);
      if ((await lstat(resolved)).isDirectory()) hostRuntimeDirectory = resolved;
    } catch {
      // Ignore missing or unreadable XDG_RUNTIME_DIR.
    }
  }

  let resolvConfPath: string | undefined;
  if (selection.network === true) {
    try {
      const resolved = await realpath('/etc/resolv.conf');
      if (resolved !== '/run' && posixContains('/run', resolved) && (await lstat(resolved)).isFile()) {
        resolvConfPath = resolved;
      }
    } catch {
      // Ignore missing or unreadable /etc/resolv.conf.
    }
  }

  const systemRootSymlinks: { path: string; target: string }[] = [];
  for (const root of LINUX_SYSTEM_ROOTS) {
    try {
      if ((await lstat(root)).isSymbolicLink()) {
        const target = await readlink(root);
        if (target && !target.includes('\0')) {
          systemRootSymlinks.push({ path: root, target });
        }
      }
    } catch {
      // Ignore missing or unreadable system roots.
    }
  }

  const rawHome = os.homedir();
  const homeRoots: string[] = [];
  if (rawHome && !rawHome.includes('\0') && path.isAbsolute(rawHome)) {
    homeRoots.push(path.resolve(rawHome));
    try {
      const realHome = await realpath(rawHome);
      if (!homeRoots.includes(realHome)) homeRoots.push(realHome);
    } catch {
      // Ignore missing or unreadable home directory.
    }
  }

  const isToolchainCandidate = (normalized: string): boolean => {
    if (isRestrictedToolchainPath(normalized, hostRuntimeDirectory)) return false;
    if (LINUX_SYSTEM_ROOTS.some(root => posixContains(root, normalized))) return false;
    if (homeRoots.some(home => posixContains(normalized, home))) return false;
    if (overlaps(normalized, cwd) || canonicalProtected.some(blocked => overlaps(normalized, blocked))) return false;
    return true;
  };

  const toolchainPathSet = new Set<string>();
  const addToolchainCandidate = (candidate: string) => {
    if (!candidate || candidate.includes('\0') || !path.posix.isAbsolute(candidate)) return;
    const normalized = path.posix.resolve(candidate);
    if (isToolchainCandidate(normalized)) {
      toolchainPathSet.add(normalized);
    }
  };

  const aliasCandidates: string[] = [];
  for (const entry of (process.env.PATH ?? '').split(path.posix.delimiter)) {
    if (!entry || entry.includes('\0') || !path.posix.isAbsolute(entry)) continue;
    aliasCandidates.push(entry);
    try {
      const resolved = await realpath(entry);
      if ((await lstat(resolved)).isDirectory()) addToolchainCandidate(resolved);
    } catch {
      // Ignore missing or unreadable PATH entries.
    }
  }
  aliasCandidates.push(path.dirname(path.dirname(process.execPath)));
  try {
    addToolchainCandidate(path.dirname(path.dirname(await realpath(process.execPath))));
  } catch {
    // Ignore realpath errors on process.execPath.
  }
  if (path.isAbsolute(command.executable)) {
    aliasCandidates.push(path.dirname(command.executable));
    try {
      addToolchainCandidate(path.dirname(await realpath(command.executable)));
    } catch {
      // Ignore realpath errors on command.executable.
    }
  }
  const toolchainPaths = [...toolchainPathSet];

  const resolvedAliasCandidates: { original: string; real: string }[] = [];
  const seenAliasOriginals = new Set<string>();
  for (const rawDir of aliasCandidates) {
    if (!rawDir || rawDir.includes('\0') || !path.posix.isAbsolute(rawDir)) continue;
    const original = path.posix.resolve(rawDir);
    if (seenAliasOriginals.has(original)) continue;
    seenAliasOriginals.add(original);
    try {
      const real = await realpath(original);
      if (!(await lstat(real)).isDirectory()) continue;
      resolvedAliasCandidates.push({ original, real });
    } catch {
      // Ignore missing or unreadable alias candidate directories.
    }
  }
  const toolchainAliases = selectToolchainAliases({
    candidates: resolvedAliasCandidates,
    toolchainPaths,
    homeRoots,
    cwd,
    protectedPaths: canonicalProtected,
    hostRuntimeDirectory,
  });

  const environment: Record<string, string> = {
    PATH: process.env.PATH || '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    HOME: scratch,
    TMPDIR: scratch,
    TMP: scratch,
    TEMP: scratch,
  };
  if (typeof process.env.LANG === 'string') environment.LANG = process.env.LANG;
  if (typeof process.env.LC_ALL === 'string') environment.LC_ALL = process.env.LC_ALL;

  const args = buildBwrapArgs({
    command,
    copyDirectory: cwd,
    scratchDirectory: scratch,
    sandbox: selection,
    mode: options.mode,
    systemRootSymlinks,
    toolchainPaths,
    toolchainAliases,
    protectedDirs,
    protectedFiles,
    hostRuntimeDirectory,
    resolvConfPath,
    statusFd: 3,
    ...(seccompFilter ? { seccompFd: 4 } : {}),
    environment,
  });

  let output = '';
  let truncated = false;
  const maxOutputChars = selection.maxOutputChars;
  const append = (chunk: Buffer) => {
    const text = chunk.toString('utf8');
    if (text.length >= maxOutputChars) {
      truncated = true;
      output = text.slice(-maxOutputChars);
    } else if (output.length + text.length > maxOutputChars) {
      truncated = true;
      output = (output + text).slice(-maxOutputChars);
    } else {
      output += text;
    }
  };

  const fifoScanRoots = [...new Set([
    ...toolchainPaths,
    ...toolchainAliases.map(alias => alias.source),
    ...canonicalReadPaths,
  ])];

  let restorePermissions = true;

  try {
    // System roots in LINUX_SYSTEM_ROOTS are trusted, administrator-controlled, and not scanned;
    // copy, scratch, and writePaths are already writable by design.
    const fifoScan = await findFifoInTrees(fifoScanRoots, MAX_FIFO_SCAN_ENTRIES);
    if (fifoScan.fifo !== undefined) {
      return preSpawnFailure(`Refusing to run: mounted directory contains a FIFO: ${fifoScan.fifo}`);
    }
    if (fifoScan.limitExceeded) {
      return preSpawnFailure('Refusing to run: too many entries to scan mounted directories for FIFOs');
    }
    if (fifoScan.uninspectable !== undefined) {
      return preSpawnFailure(`Refusing to run: cannot inspect mounted directory for FIFOs: ${fifoScan.uninspectable}`);
    }

    if (options.signal?.aborted) {
      return preSpawnFailure('Command cancelled');
    }

    const child = spawn(bwrapPath, args, {
      cwd,
      detached: true,
      shell: false,
      stdio: seccompFilter ? ['pipe', 'pipe', 'pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe', 'pipe'],
    });
    const pgid = child.pid;
    if (pgid !== undefined) {
      registerOwnedProcessGroup(child);
      restorePermissions = false;
    }

    let childClosed = false;
    let spawnError: Error | undefined;
    child.once('error', err => {
      spawnError = err;
    });
    child.once('close', () => {
      childClosed = true;
    });

    const killGroup = () => {
      if (pgid !== undefined) {
        try { process.kill(-pgid, 'SIGKILL'); } catch { /* already exited */ }
      }
      try { child.kill('SIGKILL'); } catch { /* already exited */ }
    };

    const waitForChildClose = () => new Promise<void>(resolve => {
      if (childClosed || (spawnError && pgid === undefined)) {
        resolve();
        return;
      }
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(graceTimer);
        child.removeListener('close', finish);
        child.removeListener('error', onError);
        resolve();
      };
      const onError = () => {
        if (pgid === undefined) finish();
      };
      const graceTimer = setTimeout(finish, 2000);
      graceTimer.unref();
      child.once('close', finish);
      child.once('error', onError);
    });

    const reapProcessGroup = async () => {
      if (pgid === undefined || isProcessGroupGone(pgid)) return;
      try { process.kill(-pgid, 'SIGKILL'); } catch { /* already exited */ }
      const reapDeadline = Date.now() + 1000;
      while (!isProcessGroupGone(pgid) && Date.now() < reapDeadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    };

    let stderrTail = '';
    const statusChunks: Buffer[] = [];
    const statusStream: NodeJS.EventEmitter | null | undefined = child.stdio[3];
    const seccompStream = seccompFilter ? (child.stdio[4] as Writable | null | undefined) : undefined;
    let seccompError: Error | undefined;
    let terminationReason: 'timeout' | 'cancelled' | undefined;
    let stopping = false;
    let closeSettled = false;
    let timer: NodeJS.Timeout | undefined;
    let graceTimer: NodeJS.Timeout | undefined;
    let onAbort: (() => void) | undefined;
    let closed: { code: number | null; signal: NodeJS.Signals | null; exited: boolean };

    try {
      if (seccompFilter && seccompStream) {
        seccompStream.on('error', err => {
          if ((err as NodeJS.ErrnoException).code !== 'EPIPE') {
            seccompError ??= err;
          }
        });
        seccompStream.end(seccompFilter);
      }
      options.onProcess?.(child as ChildProcessWithoutNullStreams);
      child.stdin?.on('error', () => {});
      child.stdin?.end();
      child.stdout?.on('data', append);
      child.stderr?.on('data', chunk => {
        append(chunk);
        stderrTail = (stderrTail + (Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk))).slice(-4096);
      });

      const maxStatusBytes = 64 * 1024;
      let statusBytes = 0;
      if (statusStream) {
        statusStream.on('error', () => {});
        statusStream.on('data', (chunk: Buffer | string) => {
          if (statusBytes >= maxStatusBytes) return;
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          const remaining = maxStatusBytes - statusBytes;
          statusChunks.push(buf.length > remaining ? buf.subarray(0, remaining) : buf);
          statusBytes += Math.min(buf.length, remaining);
        });
      }

      closed = await new Promise<{ code: number | null; signal: NodeJS.Signals | null; exited: boolean }>(resolve => {
        let settled = false;
        const finish = (code: number | null, signal: NodeJS.Signals | null, exited: boolean) => {
          if (settled) return;
          settled = true;
          closeSettled = true;
          if (timer) clearTimeout(timer);
          if (graceTimer) clearTimeout(graceTimer);
          if (onAbort) options.signal?.removeEventListener('abort', onAbort);
          resolve({ code, signal, exited });
        };
        const stop = (reason: 'timeout' | 'cancelled') => {
          terminationReason ??= reason;
          if (stopping) return;
          stopping = true;
          killGroup();
          if (!settled && !graceTimer) {
            graceTimer = setTimeout(() => finish(null, 'SIGKILL', false), 2000);
            graceTimer.unref();
          }
        };
        onAbort = () => stop('cancelled');
        timer = setTimeout(() => stop('timeout'), options.timeoutSeconds * 1000);
        timer.unref();
        if (childClosed || (spawnError && pgid === undefined)) {
          finish(null, null, childClosed);
          return;
        }
        child.once('error', err => {
          spawnError = err;
          if (pgid === undefined) finish(null, null, false);
        });
        child.once('close', (code, signal) => finish(code, signal, true));
        options.signal?.addEventListener('abort', onAbort, { once: true });
        if (options.signal?.aborted) onAbort();
      });
    } catch (error) {
      if (timer) clearTimeout(timer);
      if (graceTimer) clearTimeout(graceTimer);
      if (onAbort) {
        try { options.signal?.removeEventListener('abort', onAbort); } catch { /* ignore */ }
      }
      if (!closeSettled) {
        killGroup();
        child.stdin?.on('error', () => {});
        child.stdin?.destroy();
        if (seccompStream) {
          seccompStream.on('error', () => {});
          seccompStream.destroy();
        }
        child.stdout?.on('error', () => {});
        child.stdout?.resume();
        child.stderr?.on('error', () => {});
        child.stderr?.resume();
        if (statusStream) {
          statusStream.on('error', () => {});
          if ('resume' in statusStream && typeof (statusStream as { resume?: unknown }).resume === 'function') {
            (statusStream as { resume: () => void }).resume();
          }
        }
        await waitForChildClose();
        await reapProcessGroup();
      }
      if (pgid !== undefined) {
        await reapProcessGroup();
        restorePermissions = childClosed && isProcessGroupGone(pgid);
      }
      throw error;
    }

    let processesReaped = false;
    if (pgid !== undefined) {
      await reapProcessGroup();
      processesReaped = closed.exited && isProcessGroupGone(pgid);
    }
    restorePermissions = processesReaped;

    const statusInfo = parseBwrapStatus(Buffer.concat(statusChunks).toString('utf8'));
    const sandboxStarted = statusInfo.childPid !== undefined;

    let error: string | undefined;
    if (spawnError) {
      error = redactExecutionDiagnostic(spawnError.message);
    } else if (terminationReason === 'timeout') {
      error = 'Command timed out';
    } else if (terminationReason === 'cancelled') {
      error = 'Command cancelled';
    } else if (!sandboxStarted) {
      const lastStderrLine = stderrTail
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .at(-1);
      const detail = lastStderrLine ? shortReason(lastStderrLine) : '';
      error = detail ? `Bubblewrap did not start the command: ${detail}` : 'Bubblewrap did not start the command';
    } else if (seccompError) {
      error = redactExecutionDiagnostic(seccompError.message);
    } else if (closed.code === null) {
      error = closed.signal ? `Terminated by signal ${closed.signal}` : 'Process exited without status code';
    }

    return {
      nonce,
      sandbox: 'linux-bwrap',
      exitCode: spawnError ? null : closed.code,
      output,
      truncated,
      ...(error !== undefined ? { error } : {}),
      processesReaped,
      ...(detection.version !== undefined ? { bwrapVersion: detection.version } : {}),
      sandboxStarted,
    };
  } finally {
    await removeOwnedScratch(scratch, scratchStat, temp, restorePermissions);
  }
}
