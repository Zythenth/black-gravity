import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { CliAdapter } from '../dist/src/cli-adapter.js';
import { loadConfig } from '../dist/src/config.js';
import { readProcessCleanupMarkerSync } from '../dist/src/isolation.js';
import { BOOT_UNAVAILABLE_START, listProcessIdentities, readBootId } from '../dist/src/process-tree.js';
import { TaskManager } from '../dist/src/task-manager.js';
import { canonicalWorkspacePaths } from '../dist/src/workspace-paths.js';

const [root, stateDirectory, taskCountArg, withGroupArg] = process.argv.slice(2);
// The native resolver expands Windows short names, as fs/promises realpath does for the package root.
const isPackageRoot = dir => path.basename(dir).startsWith('black-gravity-package-test-') && path.relative(fs.realpathSync.native(os.tmpdir()), path.dirname(dir)) === '';
if (!root || !path.isAbsolute(root) || !fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw Error('Expected named temporary fixture root');
const realRoot = fs.realpathSync.native(root);
if (!isPackageRoot(realRoot) && !isPackageRoot(path.dirname(realRoot))) throw Error('Expected named temporary fixture root');
if (!stateDirectory || !path.isAbsolute(stateDirectory)) throw Error('Expected absolute stateDirectory');
const taskCount = Number(taskCountArg);
if (!Number.isSafeInteger(taskCount) || taskCount < 0 || !['0', '1'].includes(withGroupArg)) throw Error('Invalid fixture arguments');

const source = path.join(realRoot, 'source');
if (!fs.existsSync(path.join(source, '.git'))) execFileSync('git', ['init', '--quiet', source]);
if (!fs.existsSync(path.join(source, 'source.txt'))) fs.writeFileSync(path.join(source, 'source.txt'), 'source');

const config = loadConfig({
  AGY_PATH: process.execPath,
  DEFAULT_TIMEOUT_SECONDS: '30',
  BRIDGE_TEST_EXECUTOR: 'agy',
  BRIDGE_STATE_DIRECTORY: stateDirectory,
});
const mockPath = fileURLToPath(new URL('./mock-agy.mjs', import.meta.url));
class Adapter extends CliAdapter {
  spawnTask(options, model, cwd) {
    if (!options.group) return super.spawnTask(options, model, cwd);
    const child = new EventEmitter(), stdout = new PassThrough(), sessionId = randomUUID();
    Object.assign(child, { stdin: new PassThrough(), stdout, stderr: new PassThrough(), exitCode: null, killed: false, kill() { return true; } });
    setImmediate(() => {
      stdout.write(JSON.stringify({ event: 'init', conversation_id: sessionId }) + '\n');
      setTimeout(() => {
        const hook = spawnSync(process.execPath, ['bridge-execution-hook.mjs'], { cwd: path.join(cwd, '.agents'), windowsHide: true, encoding: 'utf8',
          input: JSON.stringify({ toolCall: { name: 'finish', args: {} }, workspacePaths: [cwd], conversationId: sessionId }) });
        if (hook.status !== 0 || JSON.parse(hook.stdout).decision !== 'allow') throw Error('Guard did not permit fixture completion');
        stdout.write(JSON.stringify({ event: 'result', result: { status: 'SUCCESS', response: 'Public result.' } }) + '\n');
        stdout.end(); child.exitCode = 0; child.emit('close', 0);
      }, 50);
    });
    return child;
  }
}

const adapter = new Adapter(config, [mockPath]);
await adapter.discover();
const manager = new TaskManager(adapter, config);
const terminal = new Set(['completed', 'failed', 'cancelled', 'timeout']);

const LINUX_START_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(\d+)$/;
const SAFE_CODE_RE = /^[A-Z0-9_-]{1,64}$/i;
const clockOffsetMs = Number(process.env.BRIDGE_TEST_CLOCK_OFFSET_MS ?? '0') || 0;

function safeErrorCode(value, fallback) {
  return typeof value === 'string' && SAFE_CODE_RE.test(value) ? value : fallback;
}

function findWindowsDescendants(identities, rootPid, minCreatedAt, maxCreatedAt) {
  const visited = new Set([rootPid]);
  const queue = [{ pid: rootPid, minCreatedAt, maxCreatedAt }];
  let found = false;
  for (let head = 0; head < queue.length; head++) {
    const current = queue[head];
    for (const proc of identities) {
      if (proc.parentPid !== current.pid || visited.has(proc.pid)) continue;
      const createdAt = Number(proc.start);
      if (!Number.isFinite(createdAt)) return { status: 'unreadable' };
      if (createdAt < current.minCreatedAt) continue;
      if (current.maxCreatedAt !== undefined && createdAt >= current.maxCreatedAt) continue;
      visited.add(proc.pid);
      found = true;
      queue.push({ pid: proc.pid, minCreatedAt: createdAt, maxCreatedAt: undefined });
    }
  }
  return { status: found ? 'found' : 'none' };
}

function classifyStart(start) {
  if (typeof start !== 'string' || !start) return 'none';
  if (start === BOOT_UNAVAILABLE_START) return 'boot-unavailable';
  if (LINUX_START_RE.test(start)) return 'linux-boot-ticks';
  return 'other';
}

function probePosixGroup(pid) {
  try {
    process.kill(-pid, 0);
    return 'alive';
  } catch (error) {
    if (error?.code === 'ESRCH') return 'esrch';
    if (error?.code === 'EPERM') return 'eperm';
    return 'error';
  }
}

function inspectOwnedProcess(snapshot, { pid, start, spawnedAt }) {
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 1) {
    return { verdict: 'inconclusive', reason: 'missing-or-invalid-pid', genuineExitProven: false };
  }
  const platform = process.platform;
  if (platform === 'linux') {
    const parsed = typeof start === 'string' ? LINUX_START_RE.exec(start) : null;
    if (!parsed) {
      return {
        verdict: 'inconclusive',
        reason: start === BOOT_UNAVAILABLE_START ? 'boot-unavailable' : 'missing-linux-birth-identity',
        genuineExitProven: false,
      };
    }
    const currentBoot = readBootId();
    if (!currentBoot) {
      return { verdict: 'inconclusive', reason: 'boot-id-unreadable', genuineExitProven: false };
    }
    if (parsed[1] !== currentBoot) {
      return { verdict: 'confirmed-exited-different-boot', reason: 'different-boot-id', genuineExitProven: true };
    }
    if (!snapshot.ok) {
      return { verdict: 'inconclusive', reason: snapshot.errorCode, genuineExitProven: false };
    }
    const expectedTicks = parsed[2];
    const root = snapshot.identities.find(proc => proc.pid === pid);
    if (root) {
      if (root.start === expectedTicks) {
        return { verdict: 'owned-alive', reason: 'exact-linux-birth-match', genuineExitProven: false };
      }
      const group = probePosixGroup(pid);
      if (group === 'esrch') {
        return { verdict: 'no-traceable-descendants', reason: 'pid-reused-and-group-esrch-detached-possible', genuineExitProven: false };
      }
      return { verdict: 'inconclusive', reason: `pid-reused-group-${group}`, genuineExitProven: false };
    }
    const group = probePosixGroup(pid);
    if (group === 'esrch') {
      return { verdict: 'no-traceable-descendants', reason: 'root-absent-and-group-esrch-detached-possible', genuineExitProven: false };
    }
    return { verdict: 'inconclusive', reason: `root-absent-group-${group}`, genuineExitProven: false };
  }

  if (!snapshot.ok) {
    return { verdict: 'inconclusive', reason: snapshot.errorCode, genuineExitProven: false };
  }
  const root = snapshot.identities.find(proc => proc.pid === pid);
  if (platform === 'win32') {
    const spawnedAtMs = typeof spawnedAt === 'string' ? Date.parse(spawnedAt) : Number.NaN;
    if (!Number.isFinite(spawnedAtMs)) {
      return { verdict: 'inconclusive', reason: 'missing-spawned-at', genuineExitProven: false };
    }
    if (clockOffsetMs !== 0) {
      return { verdict: 'inconclusive', reason: 'clock-offset-active', genuineExitProven: false };
    }
    const hasStart = typeof start === 'string' && start.length > 0;
    if (root) {
      if (hasStart && root.start === start) {
        return { verdict: 'owned-alive', reason: 'exact-windows-birth-match', genuineExitProven: false };
      }
      if (!hasStart) {
        const rootCreatedAt = Number(root.start);
        return {
          verdict: 'inconclusive',
          reason: Number.isFinite(rootCreatedAt) && Math.abs(rootCreatedAt - spawnedAtMs) <= 2000
            ? 'pid-present-birth-near-spawn-unverified'
            : 'pid-present-without-birth-identity',
          genuineExitProven: false,
        };
      }
      const rootCreatedAt = Number(root.start);
      if (!Number.isFinite(rootCreatedAt)) {
        return { verdict: 'inconclusive', reason: 'unreadable-windows-birth', genuineExitProven: false };
      }
      const descendants = findWindowsDescendants(snapshot.identities, pid, spawnedAtMs - 2000, rootCreatedAt);
      if (descendants.status === 'unreadable') {
        return { verdict: 'inconclusive', reason: 'unreadable-descendant-birth', genuineExitProven: false };
      }
      if (descendants.status === 'found') {
        return { verdict: 'owned-descendant-alive', reason: 'windows-descendant-present', genuineExitProven: false };
      }
      return { verdict: 'no-traceable-descendants', reason: 'windows-pid-reused-no-traceable-descendants', genuineExitProven: false };
    }
    const descendants = findWindowsDescendants(snapshot.identities, pid, spawnedAtMs - 2000, undefined);
    if (descendants.status === 'unreadable') {
      return { verdict: 'inconclusive', reason: 'unreadable-descendant-birth', genuineExitProven: false };
    }
    if (descendants.status === 'found') {
      return { verdict: 'owned-descendant-alive', reason: 'windows-descendant-present', genuineExitProven: false };
    }
    return { verdict: 'no-traceable-descendants', reason: 'windows-root-and-traceable-descendants-absent', genuineExitProven: false };
  }

  // Other POSIX platforms (e.g. macOS)
  const hasStart = typeof start === 'string' && start.length > 0;
  if (root) {
    if (hasStart && root.start === start) {
      return { verdict: 'owned-alive', reason: 'exact-posix-birth-match', genuineExitProven: false };
    }
    if (!hasStart) {
      return { verdict: 'inconclusive', reason: 'pid-present-without-birth-identity', genuineExitProven: false };
    }
    const group = probePosixGroup(pid);
    if (group === 'esrch') {
      return { verdict: 'no-traceable-descendants', reason: 'pid-reused-and-group-esrch-detached-possible', genuineExitProven: false };
    }
    return { verdict: 'inconclusive', reason: `pid-reused-group-${group}`, genuineExitProven: false };
  }
  const group = probePosixGroup(pid);
  if (group === 'esrch') {
    return { verdict: 'no-traceable-descendants', reason: 'root-absent-and-group-esrch-detached-possible', genuineExitProven: false };
  }
  return { verdict: 'inconclusive', reason: `root-absent-group-${group}`, genuineExitProven: false };
}

async function captureProcessSnapshot() {
  try {
    const identities = await listProcessIdentities({ signal: AbortSignal.timeout(5000) });
    if (!Array.isArray(identities) || !identities.some(proc => proc.pid === process.pid)) {
      return { ok: false, identities: [], errorCode: 'PARTIAL_SNAPSHOT' };
    }
    return { ok: true, identities, errorCode: null };
  } catch (error) {
    return { ok: false, identities: [], errorCode: safeErrorCode(error?.code, 'PROCESS_LIST_FAILED') };
  }
}

async function summarizeCleanupDiagnostic(phase, attemptIndex, error) {
  const snapshot = await captureProcessSnapshot();
  let markerSummary;
  try {
    const canonical = canonicalWorkspacePaths(stateDirectory, source);
    const marker = readProcessCleanupMarkerSync(canonical);
    const entries = (marker?.entries ?? []).slice(0, 5).map(entry => {
      const processObservation = inspectOwnedProcess(snapshot, {
        pid: entry.pid,
        start: entry.start,
        spawnedAt: entry.spawnedAt,
      });
      return {
        provider: entry.provider,
        containment: entry.containment ?? 'default',
        hasPid: typeof entry.pid === 'number',
        startKind: classifyStart(entry.start),
        processObservation,
      };
    });
    markerSummary = { present: Boolean(marker), readErrorCode: null, entryCount: marker?.entries.length ?? 0, entries };
  } catch (markerError) {
    markerSummary = {
      present: null,
      readErrorCode: safeErrorCode(markerError?.code, 'READ_ERROR'),
      entryCount: null,
      entries: [],
    };
  }
  const listed = manager.list().slice(-5);
  const taskSummaries = listed.map(item => {
    let cleanupEvents = [];
    try {
      cleanupEvents = manager.readEvents(item.taskId).events
        .filter(event => event.type === 'process.cleanup')
        .slice(-3)
        .map(event => {
          const data = event.data && typeof event.data === 'object' ? event.data : {};
          return {
            verified: typeof data.verified === 'boolean' ? data.verified : null,
            method: typeof data.method === 'string' ? data.method : null,
            remaining: typeof data.remaining === 'number' ? data.remaining : null,
            confirmedLater: Boolean(data.confirmedLater),
          };
        });
    } catch {
      cleanupEvents = [];
    }
    const cleanup = item.processCleanup;
    const historicalRemaining = typeof cleanup?.remaining === 'number' ? cleanup.remaining : null;
    const verified = typeof cleanup?.verified === 'boolean' ? cleanup.verified : null;
    const processObservation = inspectOwnedProcess(snapshot, {
      pid: item.pid,
      start: cleanup?.start,
      spawnedAt: cleanup?.spawnedAt,
    });
    const ownedAlive = processObservation.verdict === 'owned-alive' || processObservation.verdict === 'owned-descendant-alive';
    const markerClean = markerSummary.present === false && markerSummary.readErrorCode === null && markerSummary.entryCount === 0;
    const kernelClosureConfirmed =
      cleanup?.containment === 'contained' && verified === true && historicalRemaining === 0 && markerClean && !ownedAlive;
    const trustedClosureConfirmed =
      !ownedAlive && (kernelClosureConfirmed || (processObservation.genuineExitProven === true && verified === true && markerClean));
    const outcome = ownedAlive
      ? 'owned-alive'
      : trustedClosureConfirmed
        ? 'owned-confirmed-exit'
        : processObservation.verdict === 'no-traceable-descendants'
          ? 'no-traceable-descendants'
          : 'inconclusive';
    return {
      status: item.status,
      errorCode: item.error?.code ?? null,
      hasPid: typeof item.pid === 'number',
      containment: cleanup?.containment ?? null,
      method: cleanupEvents.at(-1)?.method ?? null,
      verified,
      historicalRemaining,
      startKind: classifyStart(cleanup?.start),
      trustedClosureConfirmed,
      processObservation,
      cleanupEvents,
      outcome,
    };
  });
  const anyOwnedAlive =
    taskSummaries.some(item => item.outcome === 'owned-alive') ||
    markerSummary.entries.some(entry => entry.processObservation.verdict === 'owned-alive' || entry.processObservation.verdict === 'owned-descendant-alive');
  const allConfirmed =
    taskSummaries.length > 0 &&
    taskSummaries.every(item => item.outcome === 'owned-confirmed-exit') &&
    markerSummary.present === false &&
    markerSummary.readErrorCode === null &&
    markerSummary.entryCount === 0;
  const allNoTraceable =
    taskSummaries.length > 0 &&
    markerSummary.present !== null &&
    markerSummary.readErrorCode === null &&
    taskSummaries.every(item => item.outcome === 'no-traceable-descendants' || item.outcome === 'owned-confirmed-exit') &&
    markerSummary.entries.every(entry => entry.processObservation.verdict === 'no-traceable-descendants' || entry.processObservation.genuineExitProven === true);
  const classification = anyOwnedAlive
    ? 'owned-alive'
    : allConfirmed
      ? 'owned-confirmed-exit'
      : allNoTraceable
        ? 'no-traceable-descendants'
        : 'inconclusive';
  return {
    phase,
    attemptIndex,
    taskCount,
    platform: process.platform,
    snapshotOk: snapshot.ok,
    snapshotErrorCode: snapshot.errorCode,
    errorCode: error?.code !== undefined ? safeErrorCode(error.code, 'ERROR') : null,
    classification,
    marker: markerSummary,
    tasks: taskSummaries,
  };
}

for (let i = 0; i < taskCount; i++) {
  try {
    const { taskId } = await manager.run({ prompt: 'test', workingDirectory: source });
    const deadline = Date.now() + 60000;
    let task = manager.status(taskId);
    while (!terminal.has(task.status)) {
      if (Date.now() >= deadline) throw Error(`Task timed out: ${taskId}`);
      await delay(20);
      task = manager.status(taskId);
    }
    assert.equal(task.status, 'completed');
  } catch (error) {
    try {
      const diag = await summarizeCleanupDiagnostic('task-run', i, error);
      process.stderr.write('aged-state-diagnostic: ' + JSON.stringify(diag) + '\n');
    } catch {
      process.stderr.write('aged-state-diagnostic: ' + JSON.stringify({ phase: 'task-run', attemptIndex: i, classification: 'inconclusive', diagnosticError: true }) + '\n');
    }
    throw error;
  }
}
let groupId = null;
if (withGroupArg === '1') {
  try {
    const group = await manager.groups.create(randomUUID(), {
      workingDirectory: source,
      title: 'Aged state',
      jobs: [{ key: 'a', owner: 'implementer', dependsOn: [], task: { prompt: 'Inspect A.', mode: 'read-only' } }],
    });
    groupId = group.groupId;
    manager.groups.start(groupId, group.definitionSha256);
    const deadline = Date.now() + 120000;
    let status = manager.groups.status(groupId);
    while (!['completed', 'failed', 'cancelled', 'paused'].includes(status.state)) {
      if (Date.now() >= deadline) throw Error(`Group timed out: ${groupId}`);
      await delay(20);
      status = manager.groups.status(groupId);
    }
    assert.equal(status.state, 'completed');
  } catch (error) {
    try {
      const diag = await summarizeCleanupDiagnostic('group-run', 0, error);
      process.stderr.write('aged-state-diagnostic: ' + JSON.stringify(diag) + '\n');
    } catch {
      process.stderr.write('aged-state-diagnostic: ' + JSON.stringify({ phase: 'group-run', attemptIndex: 0, classification: 'inconclusive', diagnosticError: true }) + '\n');
    }
    throw error;
  }
}
const tasks = manager.list().filter(task => task.copyDirectory).map(({ taskId, copyDirectory }) => ({ taskId, copyDirectory }));
console.log(JSON.stringify({ tasks, groupId }));
await manager.shutdown();
