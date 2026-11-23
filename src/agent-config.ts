import * as crypto from 'node:crypto';
import { createReadStream } from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import type { ProjectCopy } from './isolation.js';
import { BridgeError } from './types.js';

export const AGENT_GUARD_PATHS = [
  '.agents/hooks.json',
  '.agents/bridge-guard-hook.mjs',
] as const;

const GUARD_HOOK_TOOLS = [
  'write_to_file',
  'write_file',
  'replace_file_content',
  'multi_replace_file_content',
  'edit_file',
] as const;

const NODE_SHADOW_NAMES = [
  'node',
  'node.exe',
  'node.com',
  'node.cmd',
  'node.bat',
] as const;

export interface AgentGuardFile {
  path: (typeof AGENT_GUARD_PATHS)[number];
  content: string;
}

function matchesProtectedSegment(
  segment: string,
  platform: NodeJS.Platform,
  includePatchOnly: boolean,
  isLast: boolean,
): boolean {
  const lower = segment.toLowerCase();
  if (lower === '.agents') return true;
  if (includePatchOnly) {
    if (lower === '.git' || lower === '.opencode') return true;
    if (isLast && (lower === 'opencode.json' || lower === 'opencode.jsonc')) return true;
  }
  if (platform !== 'win32') return false;
  return /^agents~\d+$/i.test(segment) || (includePatchOnly && (/^git~\d+$/i.test(segment) || /^openco~\d+(\..*)?$/i.test(segment) || /^op[0-9a-f]{4}~\d+(\..*)?$/i.test(segment)));
}

export function isAgentConfigPath(relative: string, platform: NodeJS.Platform = process.platform): boolean {
  const segments = relative.split(/[\\/]/);
  return segments.some((segment, index) => matchesProtectedSegment(segment, platform, false, index === segments.length - 1));
}

export function isProtectedPatchPath(relative: string, platform: NodeJS.Platform = process.platform): boolean {
  const segments = relative.split(/[\\/]/);
  return segments.some((segment, index) => matchesProtectedSegment(segment, platform, true, index === segments.length - 1));
}

export function assertNoProtectedPatchPaths(files: ReadonlyArray<string | { path: string }>): void {
  const offending = files
    .map(entry => typeof entry === 'string' ? entry : entry.path)
    .filter(entry => isProtectedPatchPath(entry));
  if (offending.length === 0) return;
  const listed = offending.slice(0, 20).join(', ') + (offending.length > 20 ? ` and ${offending.length - 20} more` : '');
  throw new BridgeError(
    'AGENT_CONFIG_IN_PATCH',
    `Changes to protected paths (.agents, .git or OpenCode configuration) cannot be previewed or integrated: ${listed}.`,
  );
}

async function guardHookMain(
  originalCopyRoot: string,
  canonicalCopyRoot: string,
  mode: 'write' | 'read-only',
): Promise<void> {
  const fsp = await import('node:fs/promises');
  const path = await import('node:path');

  const isWindows = process.platform === 'win32';
  const WINDOWS_DEVICE_NAMES = new Set([
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    'CONIN$', 'CONOUT$',
  ]);
  const PATH_LIKE_KEYS = [
    'Path',
    'AbsolutePath',
    'TargetFile',
    'path',
    'filePath',
    'file_path',
    'targetFile',
    'target_file',
    'absolutePath',
    'absolute_path',
  ];
  const GUARDED_TOOLS = new Set([
    'write_to_file',
    'write_file',
    'replace_file_content',
    'multi_replace_file_content',
    'edit_file',
  ]);

  function emitDecision(decision: 'allow' | 'deny', reason: string): never {
    console.log(JSON.stringify({ decision, reason }));
    process.exit(0);
  }

  function isDeviceName(segment: string): boolean {
    const base = segment.split('.')[0]!.toUpperCase();
    return WINDOWS_DEVICE_NAMES.has(base);
  }

  function escapesRoot(rel: string): boolean {
    return rel === '..' || rel.startsWith('../') || (isWindows && rel.startsWith('..\\')) || path.isAbsolute(rel);
  }

  function isInside(parent: string, child: string): boolean {
    const p = isWindows ? path.resolve(parent).toLowerCase() : path.resolve(parent);
    const c = isWindows ? path.resolve(child).toLowerCase() : path.resolve(child);
    const rel = path.relative(p, c);
    return rel === '' || !escapesRoot(rel);
  }

  function isProtectedSegment(segment: string): boolean {
    const lower = segment.toLowerCase();
    return lower === '.agents' || lower === '.git' || (isWindows && (/^agents~\d+$/i.test(segment) || /^git~\d+$/i.test(segment)));
  }

  function hasProtectedSegment(root: string, target: string): boolean {
    const r = isWindows ? path.resolve(root).toLowerCase() : path.resolve(root);
    const t = isWindows ? path.resolve(target).toLowerCase() : path.resolve(target);
    const rel = path.relative(r, t);
    if (rel === '') return false;
    if (escapesRoot(rel)) return true;
    return rel.split(/[\\/]+/).filter(Boolean).some(isProtectedSegment);
  }

  let rawStdin = '';
  try {
    rawStdin = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let total = 0;
      process.stdin.on('data', (chunk: Buffer | string) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += buf.length;
        if (total > 1024 * 1024) {
          process.stdin.pause();
          reject(new Error('STDIN_TOO_LARGE'));
        } else {
          chunks.push(buf);
        }
      });
      process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      process.stdin.on('error', reject);
    });
  } catch {
    emitDecision('deny', 'Failed to read hook input');
  }

  let input: Record<string, unknown>;
  try {
    const parsed = JSON.parse(rawStdin);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      emitDecision('deny', 'Invalid hook input payload');
    }
    input = parsed as Record<string, unknown>;
  } catch {
    emitDecision('deny', 'Invalid hook JSON input');
  }

  const toolCall = input.toolCall as Record<string, unknown> | undefined;
  const toolName = toolCall && typeof toolCall === 'object' && !Array.isArray(toolCall) ? toolCall.name : undefined;
  const args = toolCall && typeof toolCall === 'object' && !Array.isArray(toolCall) ? toolCall.args : undefined;

  if (typeof toolName !== 'string' || !GUARDED_TOOLS.has(toolName)) {
    emitDecision('deny', 'Tool is not permitted by guard hook');
  }

  if (mode !== 'write') {
    emitDecision('deny', 'Write tools are not allowed in read-only mode');
  }

  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    emitDecision('deny', 'Invalid tool arguments');
  }
  const argObj = args as Record<string, unknown>;

  const expectedTargetKey = (toolName === 'write_file' || toolName === 'edit_file') ? 'Path' : 'TargetFile';
  for (const key of PATH_LIKE_KEYS) {
    if (key !== expectedTargetKey && Object.hasOwn(argObj, key)) {
      emitDecision('deny', 'Conflicting path argument keys');
    }
  }

  const rawTarget = argObj[expectedTargetKey];
  if (typeof rawTarget !== 'string' || rawTarget.length === 0 || rawTarget.length > 4000) {
    emitDecision('deny', 'Invalid target file path');
  }
  if (!isWindows && rawTarget.includes('\\')) {
    emitDecision('deny', 'Target path cannot contain backslashes on non-Windows platforms');
  }
  if (!path.isAbsolute(rawTarget)) {
    emitDecision('deny', 'Target path must be absolute');
  }
  if (isWindows) {
    if (!/^[A-Za-z]:[\\/]/.test(rawTarget) || /^(?:\\\\|\/\/|\\\\\?\\)/.test(rawTarget) || rawTarget.slice(2).includes(':')) {
      emitDecision('deny', 'Invalid Windows target path');
    }
  }
  if (/[\x00-\x1f]/.test(rawTarget) || rawTarget.split(/[\\/]+/).some(part => part === '.' || part === '..')) {
    emitDecision('deny', 'Target path contains invalid characters or traversal segments');
  }

  const resolvedTarget = path.resolve(rawTarget);
  const insideOriginal = isInside(originalCopyRoot, resolvedTarget);
  const insideCanonical = isInside(canonicalCopyRoot, resolvedTarget);
  if (!insideOriginal && !insideCanonical) {
    emitDecision('deny', 'Target path is outside copy directory');
  }

  const rootUsed = insideOriginal ? path.resolve(originalCopyRoot) : path.resolve(canonicalCopyRoot);
  let relToRoot = path.relative(rootUsed, resolvedTarget);
  if (isWindows && (relToRoot.startsWith('..') || path.isAbsolute(relToRoot))) {
    relToRoot = path.relative(rootUsed.toLowerCase(), resolvedTarget.toLowerCase());
  }
  const segs = relToRoot.split(/[\\/]+/).filter(Boolean);
  if (segs.length === 0) {
    emitDecision('deny', 'Target cannot be the copy root directory');
  }

  for (const seg of segs) {
    if (seg === '.' || seg === '..' || (isWindows && (/[. ]$/.test(seg) || isDeviceName(seg)))) {
      emitDecision('deny', 'Target path contains invalid segment');
    }
    if (isProtectedSegment(seg)) {
      emitDecision('deny', 'Writes to .agents and .git are denied');
    }
  }

  let current = rootUsed;
  for (let i = 0; i < segs.length - 1; i++) {
    current = path.join(current, segs[i]!);
    let st;
    try {
      st = await fsp.lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') break;
      emitDecision('deny', 'Failed to inspect target ancestor');
    }
    if (st.isSymbolicLink() || !st.isDirectory()) {
      emitDecision('deny', 'Target ancestor is a symlink or not a directory');
    }
    let realAnc: string;
    try {
      realAnc = await fsp.realpath(current);
    } catch {
      emitDecision('deny', 'Failed to resolve target ancestor');
    }
    if (!isInside(canonicalCopyRoot, realAnc) || hasProtectedSegment(canonicalCopyRoot, realAnc)) {
      emitDecision('deny', 'Target ancestor resolves outside canonical copy or into protected directory');
    }
  }

  let leafStat = null;
  try {
    leafStat = await fsp.lstat(resolvedTarget);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      emitDecision('deny', 'Failed to inspect target file');
    }
  }

  if (leafStat) {
    if (leafStat.isSymbolicLink() || !leafStat.isFile() || leafStat.nlink !== 1) {
      emitDecision('deny', 'Target leaf must be a single-link regular file');
    }
    let realLeaf: string;
    try {
      realLeaf = await fsp.realpath(resolvedTarget);
    } catch {
      emitDecision('deny', 'Failed to verify target file realpath');
    }
    if (!isInside(canonicalCopyRoot, realLeaf) || hasProtectedSegment(canonicalCopyRoot, realLeaf)) {
      emitDecision('deny', 'Target file resolves outside canonical copy or into protected directory');
    }
  }

  emitDecision('allow', 'In-copy write permitted by guard hook');
}

export function generateGuardHookSource(
  originalCopyRoot: string,
  canonicalCopyRoot: string,
  mode: 'write' | 'read-only',
): string {
  return (
    `const ORIGINAL_COPY_ROOT = ${JSON.stringify(originalCopyRoot)};\n` +
    `const CANONICAL_COPY_ROOT = ${JSON.stringify(canonicalCopyRoot)};\n` +
    `const GUARD_MODE = ${JSON.stringify(mode)};\n` +
    `(${guardHookMain.toString()})(ORIGINAL_COPY_ROOT, CANONICAL_COPY_ROOT, GUARD_MODE).catch(() => {\n` +
    `  console.log(JSON.stringify({ decision: 'deny', reason: 'Denied by agent guard hook' }));\n` +
    `  process.exit(0);\n` +
    `});\n`
  );
}

export function buildAgentGuardFiles(
  copyDirectory: string,
  canonicalCopyRoot: string,
  mode: 'write' | 'read-only',
): AgentGuardFile[] {
  const hooksJsonContent = JSON.stringify(
    {
      'bridge-guard-hook': {
        PreToolUse: GUARD_HOOK_TOOLS.map(tool => ({
          matcher: tool,
          hooks: [
            {
              type: 'command',
              command: 'node bridge-guard-hook.mjs',
              timeout: 10,
            },
          ],
        })),
      },
    },
    null,
    2,
  ) + '\n';

  return [
    { path: '.agents/hooks.json', content: hooksJsonContent },
    {
      path: '.agents/bridge-guard-hook.mjs',
      content: generateGuardHookSource(copyDirectory, canonicalCopyRoot, mode),
    },
  ];
}

async function lstatIfExists(target: string) {
  try {
    return await fsp.lstat(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

function sha256String(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

async function sha256File(filePath: string): Promise<string> {
  const digest = crypto.createHash('sha256');
  for await (const chunk of createReadStream(filePath)) {
    digest.update(chunk);
  }
  return digest.digest('hex');
}

export async function ensureAgentGuard(project: ProjectCopy, mode: 'write' | 'read-only'): Promise<void> {
  if (project.executionPolicy) return;

  const copyDir = project.copyDirectory;
  const agentsDir = path.join(copyDir, '.agents');

  const agentsStat = await lstatIfExists(agentsDir);
  if (agentsStat && (agentsStat.isSymbolicLink() || !agentsStat.isDirectory())) {
    throw new BridgeError('AGENT_CONFIG_IN_COPY', 'The CLI was not started: .agents in the isolated copy is not a real directory');
  }

  if (agentsStat) {
    for (const name of NODE_SHADOW_NAMES) {
      const stat = await lstatIfExists(path.join(agentsDir, name));
      if (stat) {
        throw new BridgeError('CONFLICTING_EXECUTION_POLICY', 'Project cannot shadow the trusted hook runtime');
      }
    }
  }

  const canonicalCopy = await fsp.realpath(copyDir);
  const expectedFiles = buildAgentGuardFiles(copyDir, canonicalCopy, mode);

  const states: Array<{
    file: AgentGuardFile;
    fullPath: string;
    existing?: Awaited<ReturnType<typeof fsp.lstat>>;
  }> = [];

  for (const file of expectedFiles) {
    const fullPath = path.join(copyDir, ...file.path.split('/'));
    const st = await lstatIfExists(fullPath);
    if (st && (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1)) {
      throw new BridgeError('AGENT_CONFIG_IN_COPY', `The CLI was not started: ${file.path} is not a regular single-link file`);
    }
    states.push({ file, fullPath, existing: st });
  }

  const presentCount = states.filter(state => state.existing !== undefined).length;
  if (presentCount === 0) {
    await fsp.mkdir(agentsDir, { recursive: true, mode: 0o700 });
    for (const { file, fullPath } of states) {
      await fsp.writeFile(fullPath, file.content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    }
    return;
  }

  if (presentCount !== states.length) {
    const missing = states.filter(state => !state.existing).map(state => state.file.path).join(', ');
    throw new BridgeError('AGENT_CONFIG_IN_COPY', `The CLI was not started: incomplete agent guard files in the isolated copy (${missing})`);
  }

  for (const { file, fullPath } of states) {
    const actual = await fsp.readFile(fullPath);
    const expected = Buffer.from(file.content, 'utf8');
    if (!actual.equals(expected)) {
      throw new BridgeError('AGENT_CONFIG_IN_COPY', `The CLI was not started: agent guard file was modified: ${file.path}`);
    }
  }
}

export async function assertNoAgentConfigInCopy(project: ProjectCopy, mode: 'write' | 'read-only'): Promise<void> {
  const copyDir = project.copyDirectory;
  const copyStat = await lstatIfExists(copyDir);
  if (!copyStat || copyStat.isSymbolicLink() || !copyStat.isDirectory()) {
    throw new BridgeError('AGENT_CONFIG_IN_COPY', 'The CLI was not started: copy directory is missing or unsafe');
  }

  const allowedFiles = new Map<string, string>();
  if (project.executionPolicy) {
    for (const file of project.executionPolicy.files) {
      allowedFiles.set(file.path, file.sha256.toLowerCase());
    }
  } else {
    const canonicalCopy = await fsp.realpath(copyDir);
    for (const file of buildAgentGuardFiles(copyDir, canonicalCopy, mode)) {
      allowedFiles.set(file.path, sha256String(file.content));
    }
  }
  for (const skill of project.providedSkills ?? []) {
    for (const file of skill.files) {
      allowedFiles.set(file.path, file.sha256.toLowerCase());
    }
  }

  const allowedDirs = new Set<string>(['.agents']);
  for (const filePath of allowedFiles.keys()) {
    const parts = filePath.split('/');
    for (let i = 1; i < parts.length; i++) {
      allowedDirs.add(parts.slice(0, i).join('/'));
    }
  }

  const offending: string[] = [];
  const rootEntries = await fsp.readdir(copyDir);
  let agentsDirPath: string | undefined;

  const walkNested = async (dirPath: string, relDir: string): Promise<void> => {
    const entries = await fsp.readdir(dirPath);
    for (const name of entries) {
      const fullPath = path.join(dirPath, name);
      const relPath = `${relDir}/${name}`;
      const st = await fsp.lstat(fullPath);
      if (name.toLowerCase() === '.agents') {
        offending.push(relPath);
        continue;
      }
      if (!st.isSymbolicLink() && st.isDirectory()) {
        await walkNested(fullPath, relPath);
      }
    }
  };

  for (const name of rootEntries) {
    const fullPath = path.join(copyDir, name);
    const st = await fsp.lstat(fullPath);
    if (name.toLowerCase() === '.agents') {
      if (name !== '.agents') {
        offending.push(name);
      } else if (st.isSymbolicLink() || !st.isDirectory()) {
        offending.push('.agents');
      } else {
        agentsDirPath = fullPath;
      }
    } else if (!st.isSymbolicLink() && st.isDirectory()) {
      await walkNested(fullPath, name);
    }
  }

  if (agentsDirPath) {
    const walk = async (dirPath: string, relDir: string): Promise<void> => {
      const entries = await fsp.readdir(dirPath);
      for (const name of entries) {
        const fullPath = path.join(dirPath, name);
        const relPath = `${relDir}/${name}`;
        const st = await fsp.lstat(fullPath);
        if (st.isSymbolicLink()) {
          offending.push(relPath);
          continue;
        }
        if (st.isDirectory()) {
          if (!allowedDirs.has(relPath)) {
            offending.push(relPath);
            continue;
          }
          await walk(fullPath, relPath);
        } else if (st.isFile()) {
          const expectedSha = allowedFiles.get(relPath);
          if (!expectedSha || st.nlink !== 1) {
            offending.push(relPath);
            continue;
          }
          const actualSha = await sha256File(fullPath);
          if (actualSha !== expectedSha) {
            offending.push(relPath);
          }
        } else {
          offending.push(relPath);
        }
      }
    };
    await walk(agentsDirPath, '.agents');
  }

  if (offending.length > 0) {
    const uniqueSorted = [...new Set(offending)].sort();
    const listed = uniqueSorted.slice(0, 20).join(', ') + (uniqueSorted.length > 20 ? ` and ${uniqueSorted.length - 20} more` : '');
    throw new BridgeError(
      'AGENT_CONFIG_IN_COPY',
      `The CLI was not started: unexpected or modified agent configuration in the isolated copy: ${listed}.`,
    );
  }
}
