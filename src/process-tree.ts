import { spawn, type ChildProcess } from 'node:child_process';
import { readdirSync, readFileSync, readlinkSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

export interface ObservedProcess {
  pid: number;
  parentPid: number;
  createdAt: number;
}

export interface ProcessIdentity {
  pid: number;
  parentPid: number;
  start: string;
}

export interface ProcessCleanup {
  verified: boolean;
  method: 'process-group' | 'windows-snapshot' | 'process-tree';
  remaining: ObservedProcess[];
}

function runBoundedCommand(executable: string, args: readonly string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    let child: ChildProcess;
    try {
      child = spawn(executable, [...args], {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      reject(err);
      return;
    }

    let settled = false;
    const timer = setTimeout(() => {
      fail(new Error('Process listing timed out after 15s'));
    }, 15000);
    timer.unref();

    function fail(err: Error): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { child.kill(); } catch { /* ignore */ }
      reject(err);
    }

    const chunks: Buffer[] = [];
    let totalBytes = 0;
    const MAX_STDOUT_BYTES = 16 * 1024 * 1024;

    if (child.stdout) {
      child.stdout.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_STDOUT_BYTES) {
          fail(new Error('Process listing stdout exceeded 16 MiB'));
          return;
        }
        chunks.push(chunk);
      });
    }

    if (child.stderr) {
      child.stderr.resume();
    }

    child.on('error', (err) => {
      fail(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (code !== 0) {
        reject(new Error(`Process listing exited with code ${code}`));
        return;
      }
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
  });
}

export async function listWindowsProcesses(): Promise<ObservedProcess[]> {
  const systemRoot = process.env.SystemRoot || 'C:\\Windows';
  const powershell = path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script = 'Get-CimInstance Win32_Process | ForEach-Object { if ($_.CreationDate) { "$($_.ProcessId) $($_.ParentProcessId) $($_.CreationDate.ToFileTimeUtc())" } }';

  const output = await runBoundedCommand(powershell, ['-NoProfile', '-NonInteractive', '-Command', script]);
  const lines = output.split(/\r?\n/);
  const processes: ObservedProcess[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 3) continue;
    const pid = Number(parts[0]);
    const parentPid = Number(parts[1]);
    const ftStr = parts[2];
    if (!Number.isInteger(pid) || pid < 0 || !Number.isInteger(parentPid) || parentPid < 0) {
      continue;
    }
    if (!ftStr || !/^\d+$/.test(ftStr)) {
      continue;
    }
    try {
      const ft = BigInt(ftStr);
      const createdAt = Number(ft / 10000n) - 11644473600000;
      if (!Number.isFinite(createdAt)) continue;
      processes.push({ pid, parentPid, createdAt });
    } catch {
      continue;
    }
  }
  return processes;
}

function parseLinuxProcStat(stat: string): { parentPid: number; start: string } | undefined {
  const closeParen = stat.lastIndexOf(')');
  if (closeParen === -1) return undefined;
  const fields = stat.slice(closeParen + 1).trim().split(/\s+/);
  if (fields.length <= 19) return undefined;
  const parentPid = Number(fields[1]);
  const start = fields[19];
  if (!Number.isInteger(parentPid) || parentPid < 0 || !start) return undefined;
  return { parentPid, start };
}

export function countPidNamespaceMembers(link: string): number {
  if (!link) {
    throw new Error('PID namespace link must be non-empty');
  }
  const entries = readdirSync('/proc');
  let count = 0;
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      if (readlinkSync(`/proc/${entry}/ns/pid`) === link) {
        count += 1;
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === 'ENOENT' || code === 'ESRCH' || code === 'EACCES' || code === 'EPERM') {
        continue;
      }
      throw err;
    }
  }
  return count;
}

export function verifyProcessIdentity(identity: ProcessIdentity): boolean {
  if (process.platform !== 'linux') return true;
  if (!Number.isInteger(identity.pid) || identity.pid <= 1) return false;
  try {
    const stat = readFileSync(`/proc/${identity.pid}/stat`, 'utf8');
    const parsed = parseLinuxProcStat(stat);
    return parsed !== undefined && parsed.start === identity.start;
  } catch {
    return false;
  }
}

export function startOrder(identity: ProcessIdentity): number {
  const trimmed = identity.start.trim();
  if (!trimmed) return Number.NaN;
  if (process.platform === 'linux' || process.platform === 'win32') {
    const value = Number(trimmed);
    return Number.isFinite(value) ? value : Number.NaN;
  }
  const parsed = Date.parse(trimmed);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

export async function listProcessIdentities(): Promise<ProcessIdentity[]> {
  if (process.platform === 'win32') {
    const processes = await listWindowsProcesses();
    return processes.map(p => ({ pid: p.pid, parentPid: p.parentPid, start: String(p.createdAt) }));
  }

  if (process.platform === 'linux') {
    const entries = await readdir('/proc');
    const identities: ProcessIdentity[] = [];
    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = Number(entry);
      if (!Number.isInteger(pid) || pid <= 0) continue;
      let stat: string;
      try {
        stat = await readFile(`/proc/${entry}/stat`, 'utf8');
      } catch (err) {
        const code = (err as NodeJS.ErrnoException | undefined)?.code;
        if (code === 'ENOENT' || code === 'ESRCH') continue;
        throw err;
      }
      const parsed = parseLinuxProcStat(stat);
      if (!parsed) continue;
      identities.push({ pid, parentPid: parsed.parentPid, start: parsed.start });
    }
    return identities;
  }

  const output = await runBoundedCommand('ps', ['-A', '-o', 'pid=', '-o', 'ppid=', '-o', 'lstart=']);
  const identities: ProcessIdentity[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s*(\d+)\s+(\d+)\s+(.+?)\s*$/.exec(line);
    if (!match) continue;
    const pid = Number(match[1]);
    const parentPid = Number(match[2]);
    const start = match[3]!.trim();
    if (!Number.isInteger(pid) || pid < 0 || !Number.isInteger(parentPid) || parentPid < 0 || !start) {
      continue;
    }
    identities.push({ pid, parentPid, start });
  }
  return identities;
}

function collectDescendantEdges(
  list: readonly ProcessIdentity[],
  initialParents: readonly ProcessIdentity[],
  visitedPids: Set<number>,
): ProcessIdentity[] {
  const descendants: ProcessIdentity[] = [];
  const queue: ProcessIdentity[] = [...initialParents];
  let head = 0;
  while (head < queue.length) {
    const parent = queue[head++];
    if (!parent) break;
    const parentOrder = startOrder(parent);
    if (!Number.isFinite(parentOrder)) continue;
    for (const proc of list) {
      if (proc.parentPid === parent.pid && !visitedPids.has(proc.pid)) {
        const childOrder = startOrder(proc);
        if (!Number.isFinite(childOrder) || childOrder < parentOrder) continue;
        visitedPids.add(proc.pid);
        descendants.push(proc);
        queue.push(proc);
      }
    }
  }
  return descendants;
}

export function expandMatchedTargets(
  list: readonly ProcessIdentity[],
  seeds: ReadonlyArray<{ pid: number; start?: string }>,
): ProcessIdentity[] {
  const matchedRoots: ProcessIdentity[] = [];
  const visitedPids = new Set<number>();

  for (const seed of seeds) {
    if (seed.start === undefined) continue;
    const matched = list.find(proc => proc.pid === seed.pid && proc.start === seed.start);
    if (matched && !visitedPids.has(matched.pid)) {
      visitedPids.add(matched.pid);
      matchedRoots.push(matched);
    }
  }

  return [...matchedRoots, ...collectDescendantEdges(list, matchedRoots, visitedPids)];
}

export function descendantIdentities(list: readonly ProcessIdentity[], rootPid: number): ProcessIdentity[] {
  const root = list.find(proc => proc.pid === rootPid);
  if (!root || !Number.isFinite(startOrder(root))) return [];
  const visited = new Set<number>([rootPid]);
  return collectDescendantEdges(list, [root], visited);
}

function toObservedProcess(identity: ProcessIdentity): ObservedProcess {
  const numeric = Number(identity.start);
  const parsed = Number.isFinite(numeric) ? numeric : Date.parse(identity.start);
  return {
    pid: identity.pid,
    parentPid: identity.parentPid,
    createdAt: Number.isFinite(parsed) ? parsed : 0,
  };
}

export function ownedProcesses(
  processes: readonly ObservedProcess[],
  rootPid: number,
  spawnedAt: number
): ObservedProcess[] {
  const root = processes.find(p => p.pid === rootPid && p.createdAt >= spawnedAt - 2000);
  const result: ObservedProcess[] = [];
  const visited = new Set<number>();
  const queue: Array<{ pid: number; createdAt: number }> = [];

  if (root) {
    result.push(root);
    visited.add(root.pid);
    queue.push({ pid: root.pid, createdAt: root.createdAt });
  } else {
    visited.add(rootPid);
    queue.push({ pid: rootPid, createdAt: spawnedAt - 2000 });
  }

  let head = 0;
  while (head < queue.length) {
    const current = queue[head++];
    if (!current) break;
    for (const p of processes) {
      if (p.parentPid === current.pid && p.createdAt >= current.createdAt && !visited.has(p.pid)) {
        visited.add(p.pid);
        result.push(p);
        queue.push({ pid: p.pid, createdAt: p.createdAt });
      }
    }
  }

  return result;
}

// Kept referenced: callers await verification during shutdown, when nothing else holds the event loop open.
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));
}

function killProcess(pid: number): Promise<void> {
  return new Promise(resolve => {
    try {
      const systemRoot = process.env.SystemRoot || 'C:\\Windows';
      const taskkill = path.join(systemRoot, 'System32', 'taskkill.exe');
      const child = spawn(taskkill, ['/PID', String(pid), '/F'], {
        windowsHide: true,
        shell: false,
        stdio: 'ignore',
      });
      child.once('error', () => resolve());
      child.once('close', () => resolve());
    } catch {
      resolve();
    }
  });
}

function isProcessAlive(target: number): boolean {
  try {
    process.kill(target, 0);
    return true;
  } catch (err: unknown) {
    return (err as NodeJS.ErrnoException | undefined)?.code === 'EPERM';
  }
}

export async function reconcileOwnedProcesses(
  root: { pid?: number; spawnedAt: number; processGroup: boolean },
  options?: { graceMs?: number; list?: () => Promise<ObservedProcess[]> }
): Promise<ProcessCleanup> {
  const graceMs = options?.graceMs ?? 3000;

  if (process.platform === 'win32') {
    if (typeof root.pid !== 'number' || root.pid <= 0) {
      return { verified: false, method: 'windows-snapshot', remaining: [] };
    }

    const list = options?.list ?? listWindowsProcesses;
    let targets: ObservedProcess[];
    try {
      const snapshot = await list();
      targets = ownedProcesses(snapshot, root.pid, root.spawnedAt);
    } catch {
      return { verified: false, method: 'windows-snapshot', remaining: [] };
    }

    if (targets.length === 0) {
      return { verified: true, method: 'windows-snapshot', remaining: [] };
    }

    for (const target of targets) {
      await killProcess(target.pid);
    }

    const deadline = Date.now() + graceMs;
    let remaining = targets;

    do {
      if (graceMs > 0) {
        const waitMs = Math.min(250, Math.max(1, deadline - Date.now()));
        await sleep(waitMs);
      }
      let currentList: ObservedProcess[];
      try {
        currentList = await list();
      } catch {
        return { verified: false, method: 'windows-snapshot', remaining };
      }
      remaining = targets.filter(target =>
        currentList.some(p => p.pid === target.pid && Math.abs(p.createdAt - target.createdAt) <= 1)
      );
      if (remaining.length === 0) {
        return { verified: true, method: 'windows-snapshot', remaining: [] };
      }
    } while (Date.now() < deadline);

    return { verified: false, method: 'windows-snapshot', remaining };
  }

  // POSIX
  if (typeof root.pid !== 'number' || root.pid <= 0) {
    return { verified: false, method: 'process-group', remaining: [] };
  }

  const target = root.processGroup ? -root.pid : root.pid;

  if (!isProcessAlive(target)) {
    return { verified: true, method: 'process-group', remaining: [] };
  }

  try {
    process.kill(target, 'SIGKILL');
  } catch {
    // Process already terminated
  }

  const deadline = Date.now() + graceMs;
  do {
    if (graceMs > 0) {
      const waitMs = Math.min(100, Math.max(1, deadline - Date.now()));
      await sleep(waitMs);
    }
    if (!isProcessAlive(target)) {
      return { verified: true, method: 'process-group', remaining: [] };
    }
  } while (Date.now() < deadline);

  return { verified: !isProcessAlive(target), method: 'process-group', remaining: [] };
}

export async function reconcileTrackedProcesses(
  root: { pid: number; start?: string; processGroup?: boolean },
  tracked: readonly ProcessIdentity[],
  options?: {
    graceMs?: number;
    list?: () => Promise<ProcessIdentity[]>;
    kill?: (pid: number, signal: NodeJS.Signals) => void;
    verifyIdentity?: (identity: ProcessIdentity) => boolean;
  }
): Promise<ProcessCleanup> {
  const graceMs = options?.graceMs ?? 3000;
  const list = options?.list ?? listProcessIdentities;
  const kill: (pid: number, signal: NodeJS.Signals) => void =
    options?.kill ?? ((pid, signal) => process.kill(pid, signal));
  const verifyIdentity = options?.verifyIdentity ?? verifyProcessIdentity;

  if (typeof root.pid !== 'number' || root.pid <= 0) {
    return { verified: false, method: 'process-tree', remaining: [] };
  }

  const knownTargets = new Map<string, { pid: number; start: string }>();
  if (root.start !== undefined) {
    knownTargets.set(`${root.pid}\0${root.start}`, { pid: root.pid, start: root.start });
  }
  for (const item of tracked) {
    knownTargets.set(`${item.pid}\0${item.start}`, { pid: item.pid, start: item.start });
  }

  const killedKeys = new Set<string>();

  const killTargets = async (currentTargets: readonly ProcessIdentity[]) => {
    if (process.platform === 'win32' && !options?.kill) {
      for (const target of currentTargets) {
        const key = `${target.pid}\0${target.start}`;
        if (killedKeys.has(key)) continue;
        if (!verifyIdentity(target)) continue;
        killedKeys.add(key);
        if (target.pid > 1) {
          await killProcess(target.pid);
        }
      }
      return;
    }

    for (const target of currentTargets) {
      const key = `${target.pid}\0${target.start}`;
      if (killedKeys.has(key)) continue;
      if (!verifyIdentity(target)) continue;
      killedKeys.add(key);
      if (target.pid > 1) {
        try {
          kill(target.pid, 'SIGKILL');
        } catch {
          // Ignore ESRCH or already terminated process
        }
      }
    }
  };

  let initial: ProcessIdentity[];
  try {
    initial = await list();
  } catch {
    return { verified: false, method: 'process-tree', remaining: [] };
  }

  let remaining = expandMatchedTargets(initial, [...knownTargets.values()]);
  for (const target of remaining) {
    knownTargets.set(`${target.pid}\0${target.start}`, { pid: target.pid, start: target.start });
  }
  if (remaining.length === 0) {
    return { verified: true, method: 'process-tree', remaining: [] };
  }

  await killTargets(remaining);

  const deadline = Date.now() + graceMs;
  do {
    if (graceMs > 0) {
      const waitMs = Math.min(100, Math.max(1, deadline - Date.now()));
      await sleep(waitMs);
    }
    let currentList: ProcessIdentity[];
    try {
      currentList = await list();
    } catch {
      return { verified: false, method: 'process-tree', remaining: remaining.map(toObservedProcess) };
    }
    remaining = expandMatchedTargets(currentList, [...knownTargets.values()]);
    for (const target of remaining) {
      knownTargets.set(`${target.pid}\0${target.start}`, { pid: target.pid, start: target.start });
    }
    if (remaining.length === 0) {
      return { verified: true, method: 'process-tree', remaining: [] };
    }
    await killTargets(remaining);
  } while (Date.now() < deadline);

  return { verified: false, method: 'process-tree', remaining: remaining.map(toObservedProcess) };
}
