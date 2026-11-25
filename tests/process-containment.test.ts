import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { AgyExecutionAdapter, confirmCleanupByIdentity } from '../src/agy-execution-adapter.js';
import { CliAdapter, type Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import {
  declaredProcessContainment,
  type ExecutionAdapter,
  type ExecutionContext,
  type ExecutionRequest,
  type ExecutionResult,
  type ProcessLaunch,
} from '../src/execution-contract.js';
import {
  discardProjectCopy,
  PROCESS_CLEANUP_MARKER_NAME,
  readProcessCleanupMarkerSync,
  upsertProcessCleanupMarkerEntrySync,
} from '../src/isolation.js';
import { OpenCodeExecutionAdapter } from '../src/opencode-execution-adapter.js';
import { BOOT_UNAVAILABLE_START, listProcessIdentities, PROCESS_LISTING_TIMEOUT_MS, readBootId, reconcileLaunchIdentity, recordedProcessStart, type ProcessIdentity } from '../src/process-tree.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError, type TaskRecord } from '../src/types.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { createReadFixture } from './read-fixture.js';
import { waitForTask } from './wait-for-task.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MOCK_AGY = path.resolve(HERE, '../../tests/mock-agy.mjs');
const MOCK_OPENCODE = path.resolve(HERE, '../../tests/mock-opencode.mjs');

class OpenCodeTestCliAdapter extends ControlledCliAdapter {
  override async listModels(): Promise<Model[]> {
    return [
      { id: 'opencode-go/mock-flash', name: 'Mock Flash' },
      { id: 'opencode-go/mock-pro', name: 'Mock Pro' },
    ];
  }
}

function createWorkspace(t: { after(fn: () => Promise<void> | void): void }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'bg-proc-contain-'));
  const repoDir = path.join(root, 'repo');
  const stateDir = path.join(root, 'state');
  mkdirSync(repoDir, { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  execFileSync('git', ['init'], { cwd: repoDir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repoDir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: repoDir, stdio: 'ignore' });
  execFileSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: repoDir, stdio: 'ignore' });
  writeFileSync(path.join(repoDir, 'README.md'), 'hello\n', 'utf8');
  execFileSync('git', ['add', '.'], { cwd: repoDir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: repoDir, stdio: 'ignore' });

  const managers: TaskManager[] = [];
  t.after(async () => {
    for (const manager of managers) {
      await manager.shutdown();
    }
    try {
      const copies = new Map(
        new StateStore(stateDir)
          .load()
          .filter(entry => entry.project)
          .map(entry => [entry.project!.copyDirectory, entry.project!]),
      );
      for (const project of copies.values()) {
        await discardProjectCopy(project);
      }
    } catch {
      // Cleanup ignores missing or partially initialized test snapshots.
    }
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const config = loadConfig({
    BRIDGE_STATE_DIRECTORY: stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
  });

  return {
    root,
    repoDir,
    stateDir,
    config,
    track(manager: TaskManager) {
      managers.push(manager);
      return manager;
    },
  };
}

function spawnShortLivedExitedPid(): number {
  const result = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  assert.ok(result.pid && result.pid > 1);
  return result.pid;
}

function spawnAndWaitShortLivedChild(): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
    const pid = child.pid;
    child.once('error', reject);
    child.once('close', () => {
      if (typeof pid !== 'number' || pid <= 1) {
        reject(new Error('Expected a valid child PID'));
        return;
      }
      resolve(pid);
    });
  });
}

function createMixedCopySnapshot(
  stateDir: string,
  agyTaskId: string,
  containment: 'tracked' | 'contained' | 'none',
  verifiedOpenCode: boolean,
): { opencodeTaskId: string; gitDirectory: string; copyDirectory: string } {
  const agySnapshotPath = path.join(stateDir, `${agyTaskId}.json`);
  const agySnapshot = JSON.parse(readFileSync(agySnapshotPath, 'utf8')) as {
    version: number;
    ownerPid: number;
    record: TaskRecord;
    options: Record<string, unknown>;
    project: { gitDirectory: string; copyDirectory: string } & Record<string, unknown>;
    events: unknown[];
    cursor: number;
    redacted?: boolean;
  };
  const now = new Date(Date.now() - 1_000).toISOString();
  const opencodeTaskId = randomUUID();
  const opencodeSnapshot = {
    version: agySnapshot.version,
    ownerPid: agySnapshot.ownerPid,
    record: {
      taskId: opencodeTaskId,
      workingDirectory: agySnapshot.record.workingDirectory,
      prompt: agySnapshot.record.prompt,
      status: 'completed',
      createdAt: now,
      startedAt: now,
      completedAt: now,
      mode: agySnapshot.record.mode,
      copyDirectory: agySnapshot.record.copyDirectory,
      includedFiles: agySnapshot.record.includedFiles,
      execution: {
        provider: 'opencode',
        adapterId: 'opencode-cli',
        adapterVersion: '3',
        requested: { model: null, effort: null },
        observed: { model: null, status: 'not-observable' },
      },
      processCleanup: {
        verified: verifiedOpenCode,
        spawnedAt: now,
        checkedAt: now,
        remaining: verifiedOpenCode ? 0 : 1,
        containment,
      },
    },
    options: {
      ...agySnapshot.options,
      provider: 'opencode',
    },
    project: agySnapshot.project,
    events: [],
    cursor: 0,
    ...(agySnapshot.redacted ? { redacted: true } : {}),
  };
  writeFileSync(path.join(stateDir, `${opencodeTaskId}.json`), JSON.stringify(opencodeSnapshot), 'utf8');
  return {
    opencodeTaskId,
    gitDirectory: agySnapshot.project.gitDirectory,
    copyDirectory: agySnapshot.project.copyDirectory,
  };
}

test('C1) containment declarations on Agy, OpenCode, undefined, and omitted adapters', async t => {
  const ws = createWorkspace(t);
  const cli = new CliAdapter(ws.config, [MOCK_AGY]);
  assert.equal(new AgyExecutionAdapter(cli, ws.config).processContainment, 'tracked');

  const ocAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
    containment: 'none',
  });
  assert.equal(ocAdapter.processContainment, 'none');

  const fixture = createReadFixture(ws.repoDir);
  let startedLaunch: ProcessLaunch | undefined;
  let callbackCleanup: TaskRecord['processCleanup'] | undefined;
  const result = await ocAdapter.execute(
    {
      taskId: randomUUID(),
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      role: 'reviewer',
      mode: 'read-only',
    },
    {
      onProcessLaunch(launch) {
        startedLaunch = launch;
      },
      onProcessCleanup(cleanup) {
        callbackCleanup = cleanup;
      },
    },
  );
  assert.equal(result.status, 'completed');
  assert.equal(startedLaunch?.containment, 'none');
  assert.equal(callbackCleanup?.containment, 'none');
  assert.equal(result.processCleanup?.containment, 'none');

  assert.equal(declaredProcessContainment(undefined), 'none');
  const adapterWithoutField: ExecutionAdapter = {
    identity: { id: 'no-containment', provider: 'no-containment', version: '1' },
    capabilities: { read: 'supported' },
    async execute(request) {
      return { taskId: request.taskId, status: 'completed', response: 'ok' };
    },
  };
  assert.equal(declaredProcessContainment(adapterWithoutField), 'none');
});

test('C2) mixed copy cleanup and preview obey containment level instead of executor name', async t => {
  // Part 1: mixed agy + opencode copy whose marker only has tracked entries (dead PID) is previewable and discarded by cleanup().
  {
    const ws = createWorkspace(t);
    const cli = new CliAdapter(ws.config, [MOCK_AGY]);
    const discovery = await cli.discover();
    assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');
    const ocAdapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
    });

    const tasks1 = ws.track(new TaskManager(cli, ws.config, undefined, {
      executors: [{ provider: 'opencode', adapter: ocAdapter }],
    }));
    const queued = await tasks1.run({ prompt: 'write:c2-tracked', workingDirectory: ws.repoDir, mode: 'write' });
    const agyCompleted = await waitForTask(tasks1, queued.taskId);
    assert.equal(agyCompleted.status, 'completed');
    assert.ok(agyCompleted.copyDirectory);
    await tasks1.shutdown();

    const { opencodeTaskId, gitDirectory, copyDirectory } = createMixedCopySnapshot(
      ws.stateDir,
      agyCompleted.taskId,
      'none',
      true,
    );
    const deadPid = spawnShortLivedExitedPid();
    const now = new Date(Date.now() - 1_000).toISOString();
    const agySnapshotPath = path.join(ws.stateDir, `${agyCompleted.taskId}.json`);
    const agySnapshot = JSON.parse(readFileSync(agySnapshotPath, 'utf8')) as { record: TaskRecord };
    agySnapshot.record.pid = deadPid;
    agySnapshot.record.processCleanup = {
      verified: false,
      spawnedAt: now,
      checkedAt: now,
      remaining: 1,
      containment: 'tracked',
    };
    writeFileSync(agySnapshotPath, JSON.stringify(agySnapshot), 'utf8');
    upsertProcessCleanupMarkerEntrySync(
      { gitDirectory },
      {
        launchId: 'c2-tracked-launch',
        taskId: agyCompleted.taskId,
        provider: 'agy',
        pid: deadPid,
        spawnedAt: now,
        containment: 'tracked',
      },
    );

    const tasks2 = ws.track(new TaskManager(cli, ws.config, undefined, {
      executors: [{ provider: 'opencode', adapter: ocAdapter }],
    }));
    const preview = await tasks2.preview(agyCompleted.taskId);
    assert.ok(preview.sha256);
    assert.equal(existsSync(path.join(gitDirectory, PROCESS_CLEANUP_MARKER_NAME)), false);
    await tasks2.shutdown();

    // Re-add a tracked-only unverified entry and confirm cleanup() discards the mixed copy.
    agySnapshot.record.processCleanup = {
      verified: false,
      spawnedAt: now,
      checkedAt: now,
      remaining: 1,
      containment: 'tracked',
    };
    writeFileSync(agySnapshotPath, JSON.stringify(agySnapshot), 'utf8');
    upsertProcessCleanupMarkerEntrySync(
      { gitDirectory },
      {
        launchId: 'c2-tracked-launch-cleanup',
        taskId: agyCompleted.taskId,
        provider: 'agy',
        pid: deadPid,
        spawnedAt: now,
        containment: 'tracked',
      },
    );

    const tasks3 = ws.track(new TaskManager(cli, ws.config, undefined, {
      executors: [{ provider: 'opencode', adapter: ocAdapter }],
    }));
    const cleaned = await tasks3.cleanup(Date.now() + 365 * 24 * 3600_000);
    assert.equal(cleaned.discardedTaskIds.includes(agyCompleted.taskId), true);
    assert.equal(cleaned.discardedTaskIds.includes(opencodeTaskId), true);
    assert.equal(existsSync(copyDirectory), false);
  }

  // Part 2: the same mixed copy with a 'contained' or 'none' entry is kept by cleanup() and preview fails.
  for (const blockingLevel of ['contained', 'none'] as const) {
    const ws = createWorkspace(t);
    const cli = new CliAdapter(ws.config, [MOCK_AGY]);
    const discovery = await cli.discover();
    assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');
    const ocAdapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
    });

    const tasks1 = ws.track(new TaskManager(cli, ws.config, undefined, {
      executors: [{ provider: 'opencode', adapter: ocAdapter }],
    }));
    const queued = await tasks1.run({ prompt: `write:c2-${blockingLevel}`, workingDirectory: ws.repoDir, mode: 'write' });
    const agyCompleted = await waitForTask(tasks1, queued.taskId);
    assert.equal(agyCompleted.status, 'completed');
    await tasks1.shutdown();

    const { opencodeTaskId, gitDirectory, copyDirectory } = createMixedCopySnapshot(
      ws.stateDir,
      agyCompleted.taskId,
      blockingLevel,
      true,
    );
    const deadPid = spawnShortLivedExitedPid();
    const now = new Date(Date.now() - 1_000).toISOString();
    upsertProcessCleanupMarkerEntrySync(
      { gitDirectory },
      {
        launchId: `c2-${blockingLevel}-entry`,
        taskId: opencodeTaskId,
        provider: 'opencode',
        pid: deadPid,
        spawnedAt: now,
        containment: blockingLevel,
      },
    );

    const tasks2 = ws.track(new TaskManager(cli, ws.config, undefined, {
      executors: [{ provider: 'opencode', adapter: ocAdapter }],
    }));
    const cleaned = await tasks2.cleanup(Date.now() + 365 * 24 * 3600_000);
    assert.equal(cleaned.discardedTaskIds.includes(agyCompleted.taskId), false);
    assert.equal(cleaned.discardedTaskIds.includes(opencodeTaskId), false);
    assert.equal(existsSync(copyDirectory), true);

    await assert.rejects(
      () => tasks2.preview(agyCompleted.taskId),
      err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
    );
  }
});

test('C3) fake executors with declared containment control cleanup and preview without executor-name rules', async t => {
  const createExitedTrackingAdapter = (
    provider: string,
    processContainment: 'tracked' | 'contained',
  ): ExecutionAdapter => ({
    identity: { id: `fake-${provider}`, provider, version: '1' },
    capabilities: {
      read: 'supported',
      write: 'supported',
      cancel: 'supported',
      resume: 'supported',
    },
    processContainment,
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      const spawnedAt = new Date().toISOString();
      const pid = await spawnAndWaitShortLivedChild();
      context?.onProcessStarted?.(pid);
      context?.onProcessCleanup?.({
        verified: false,
        spawnedAt,
        checkedAt: new Date().toISOString(),
        remaining: 1,
      });
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: `ses-${provider}-c3` },
        response: 'fake executor done',
      };
    },
  });

  // Part 1: pure synthetic adapter with processContainment: 'tracked'
  {
    const ws = createWorkspace(t);
    const cli = new OpenCodeTestCliAdapter(ws.config);
    const syntheticAdapter = createExitedTrackingAdapter('synthetic', 'tracked');
    const tasks = ws.track(new TaskManager(cli, ws.config, undefined, {
      executors: [{ provider: 'synthetic', adapter: syntheticAdapter }],
    }));

    const queued1 = await tasks.run({
      provider: 'synthetic',
      prompt: 'Synthetic cleanup discard check',
      workingDirectory: ws.repoDir,
      mode: 'write',
    });
    const completed1 = await waitForTask(tasks, queued1.taskId);
    assert.equal(completed1.status, 'completed');
    assert.equal(completed1.processCleanup?.verified, false);
    assert.equal(completed1.processCleanup?.containment, 'tracked');
    assert.ok(completed1.copyDirectory);

    const cleaned = await tasks.cleanup(Date.now() + 365 * 24 * 3600_000);
    assert.equal(cleaned.discardedTaskIds.includes(completed1.taskId), true);
    assert.equal(existsSync(completed1.copyDirectory), false);

    const queued2 = await tasks.run({
      provider: 'synthetic',
      prompt: 'Synthetic preview reconcile check',
      workingDirectory: ws.repoDir,
      mode: 'write',
    });
    const completed2 = await waitForTask(tasks, queued2.taskId);
    assert.equal(completed2.status, 'completed');
    assert.equal(completed2.processCleanup?.verified, false);

    const preview = await tasks.preview(completed2.taskId);
    assert.ok(preview.sha256);
    assert.equal(tasks.status(completed2.taskId).processCleanup?.verified, true);
  }

  // Part 2: fake adapter with provider 'agy' (primary) declaring processContainment: 'contained'
  {
    const ws = createWorkspace(t);
    const cli = new OpenCodeTestCliAdapter(ws.config);
    const containedAgy = createExitedTrackingAdapter('agy', 'contained');
    const tasks = ws.track(new TaskManager(cli, ws.config, containedAgy));

    const queued = await tasks.run({
      prompt: 'Contained primary agy fake',
      workingDirectory: ws.repoDir,
      mode: 'write',
    });
    const completed = await waitForTask(tasks, queued.taskId);
    assert.equal(completed.status, 'completed');
    assert.equal(completed.processCleanup?.verified, false);
    assert.equal(completed.processCleanup?.containment, 'contained');
    assert.ok(completed.copyDirectory);

    await assert.rejects(
      () => tasks.preview(completed.taskId),
      err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
    );

    const cleaned = await tasks.cleanup(Date.now() + 365 * 24 * 3600_000);
    assert.equal(cleaned.discardedTaskIds.includes(completed.taskId), false);
    assert.equal(existsSync(completed.copyDirectory), true);
  }
});

test('C4) reused PID with mismatched identity is never signalled during preview reconciliation', async t => {
  const ws = createWorkspace(t);
  const cli = new CliAdapter(ws.config, [MOCK_AGY]);
  const discovery = await cli.discover();
  assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
    detached: process.platform !== 'win32',
    stdio: 'ignore',
  });
  sleeper.unref();
  const sleeperPid = sleeper.pid;
  assert.ok(sleeperPid && sleeperPid > 1);

  try {
    const tasks1 = ws.track(new TaskManager(cli, ws.config));
    const queued = await tasks1.run({ prompt: 'write:c4', workingDirectory: ws.repoDir, mode: 'write' });
    const completed = await waitForTask(tasks1, queued.taskId);
    assert.equal(completed.status, 'completed');
    await tasks1.shutdown();

    const spawnedAt = new Date(Date.now() - 3600_000).toISOString();
    const snapshotPath = path.join(ws.stateDir, `${completed.taskId}.json`);
    const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
      record: TaskRecord;
      project: { gitDirectory: string };
    };
    const linuxMismatchStart = process.platform === 'linux' ? `${readBootId()}:1` : undefined;
    snapshot.record.pid = sleeperPid;
    snapshot.record.processCleanup = {
      verified: false,
      spawnedAt,
      checkedAt: spawnedAt,
      remaining: 1,
      containment: 'tracked',
      ...(linuxMismatchStart ? { start: linuxMismatchStart } : {}),
    };
    writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');
    upsertProcessCleanupMarkerEntrySync(snapshot.project, {
      launchId: 'c4-reused-pid',
      taskId: completed.taskId,
      provider: 'agy',
      pid: sleeperPid,
      spawnedAt,
      containment: 'tracked',
      ...(linuxMismatchStart ? { start: linuxMismatchStart } : {}),
    });

    const tasks2 = ws.track(new TaskManager(cli, ws.config));
    if (process.platform === 'linux') {
      const preview = await tasks2.preview(completed.taskId);
      assert.ok(preview.sha256);
      assert.doesNotThrow(() => process.kill(sleeperPid, 0));
      assert.equal(readProcessCleanupMarkerSync(snapshot.project), undefined);
    } else {
      await assert.rejects(
        () => tasks2.preview(completed.taskId),
        err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
      );
      assert.doesNotThrow(() => process.kill(sleeperPid, 0));
      assert.ok(readProcessCleanupMarkerSync(snapshot.project));
    }
  } finally {
    if (process.platform === 'win32') {
      try { sleeper.kill('SIGKILL'); } catch { /* already exited */ }
    } else {
      try { process.kill(-sleeperPid, 'SIGKILL'); } catch { /* already exited */ }
    }
  }
});

const BOOT_A = '11111111-2222-4333-8444-555555555555';
const BOOT_B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

test('C5) reconcileLaunchIdentity unit matrix across linux and win32', async () => {
  // 1. Linux matching start with injected currentStart equal -> signals -pid and pid (plus descendant), verified once list empties.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    let listCalls = 0;
    let groupAlive = true;
    const result = await reconcileLaunchIdentity(
      { pid: 2000, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 50,
        bootId: () => BOOT_A,
        currentStart: targetPid => (targetPid === 2000 ? '100' : targetPid === 2001 ? '110' : undefined),
        list: async (): Promise<ProcessIdentity[]> => {
          listCalls += 1;
          if (listCalls === 1) {
            return [
              { pid: 2000, parentPid: 1, start: '100' },
              { pid: 2001, parentPid: 2000, start: '110' },
            ];
          }
          groupAlive = false;
          return [];
        },
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0 && !groupAlive) {
            throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' });
          }
        },
      },
    );
    assert.equal(result.verified, true);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.ok(signals.some(s => s.target === -2000 && s.sig === 'SIGKILL'));
    assert.ok(signals.some(s => s.target === 2000 && s.sig === 'SIGKILL'));
    assert.ok(signals.some(s => s.target === 2001 && s.sig === 'SIGKILL'));
  }

  // 1b. Linux currentStart returning a different start at signal time -> zero signals, unverified.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2050, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        currentStart: () => '999',
        list: async () => [{ pid: 2050, parentPid: 1, start: '100' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(result.verified, false);
    assert.deepEqual(result.remaining.map(p => p.pid), [2050]);
    assert.equal(signals.length, 0);
  }

  // 2. Linux mismatched start -> zero signals, verified via POSIX group rule.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const grouped = await reconcileLaunchIdentity(
      { pid: 2100, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        list: async () => [{ pid: 2100, parentPid: 1, start: '999' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(grouped.verified, true);
    assert.equal(signals.length, 0);

    const ungrouped = await reconcileLaunchIdentity(
      { pid: 2100, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: false },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        list: async () => [{ pid: 2100, parentPid: 1, start: '999' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(ungrouped.verified, false);
    assert.equal(signals.length, 0);
  }

  // 3. Linux unknown start with PID present -> zero signals, unverified.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2200, start: undefined, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        list: async () => [{ pid: 2200, parentPid: 1, start: '500' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(signals.length, 0);
  }

  // 3b. Linux root absent with group alive -> zero termination signals, unverified.
  for (const aliveMode of ['ok', 'eperm'] as const) {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2400, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        list: async () => [],
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0 && aliveMode === 'eperm') {
            throw Object.assign(new Error('EPERM'), { code: 'EPERM' });
          }
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.filter(s => s.sig !== 0).length, 0);
  }

  // 3c. Linux root absent with group gone (ESRCH) -> verified, zero termination signals.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2410, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        list: async () => [],
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0) {
            throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' });
          }
        },
      },
    );
    assert.equal(result.verified, true);
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.filter(s => s.sig !== 0).length, 0);
  }

  // 4. list() throws -> zero signals, unverified.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2300, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        list: async () => {
          throw new Error('list failed');
        },
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(signals.length, 0);
  }

  // 5. win32 root absent and no leftovers (and nothing listed) -> verified with zero kills.
  {
    const kills: number[] = [];
    const spawnedAt = 1_700_000_000_000;
    const onlyPreSpawn = await reconcileLaunchIdentity(
      { pid: 3000, spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [{ pid: 3001, parentPid: 3000, start: String(spawnedAt - 5_000) }],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(onlyPreSpawn.verified, true);
    assert.equal(onlyPreSpawn.remaining.length, 0);
    assert.equal(kills.length, 0);

    const nothingListed = await reconcileLaunchIdentity(
      { pid: 3010, spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(nothingListed.verified, true);
    assert.equal(nothingListed.remaining.length, 0);
    assert.equal(kills.length, 0);
  }

  // 6. win32 root absent with a child created after spawn (and grandchild of that child) -> unverified, zero kills.
  {
    const kills: number[] = [];
    const spawnedAt = 1_700_000_000_000;
    const directChild = await reconcileLaunchIdentity(
      { pid: 3100, spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [{ pid: 3101, parentPid: 3100, start: String(spawnedAt + 500) }],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(directChild.verified, false);
    assert.deepEqual(directChild.remaining.map(p => p.pid), [3101]);
    assert.equal(kills.length, 0);

    const withGrandchild = await reconcileLaunchIdentity(
      { pid: 3150, spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [
          { pid: 3151, parentPid: 3150, start: String(spawnedAt + 500) },
          { pid: 3152, parentPid: 3151, start: String(spawnedAt + 600) },
        ],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(withGrandchild.verified, false);
    assert.deepEqual(withGrandchild.remaining.map(p => p.pid), [3151, 3152]);
    assert.equal(kills.length, 0);
  }

  // 7. win32 root present: no recorded start -> unverified; exact start with currentStart undefined -> unverified; mismatched exact start -> checks leftovers transitively with zero kills.
  {
    const kills: number[] = [];
    const spawnedAt = 1_700_000_000_000;
    const reusedRootStart = spawnedAt + 10_000;

    const noRecordedStart = await reconcileLaunchIdentity(
      { pid: 3300, spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [{ pid: 3300, parentPid: 1, start: String(spawnedAt) }],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(noRecordedStart.verified, false);
    assert.equal(noRecordedStart.remaining.length, 0);
    assert.equal(kills.length, 0);

    const uncheckableStart = await reconcileLaunchIdentity(
      { pid: 3310, start: String(spawnedAt), spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        currentStart: () => undefined,
        list: async () => [{ pid: 3310, parentPid: 1, start: String(spawnedAt) }],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(uncheckableStart.verified, false);
    assert.deepEqual(uncheckableStart.remaining.map(p => p.pid), [3310]);
    assert.equal(kills.length, 0);

    const noOldLeftovers = await reconcileLaunchIdentity(
      { pid: 3200, start: String(spawnedAt), spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [
          { pid: 3200, parentPid: 1, start: String(reusedRootStart) },
          { pid: 3201, parentPid: 3200, start: String(reusedRootStart + 100) },
        ],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(noOldLeftovers.verified, true);
    assert.equal(noOldLeftovers.remaining.length, 0);
    assert.equal(kills.length, 0);

    const withOldLeftover = await reconcileLaunchIdentity(
      { pid: 3200, start: String(spawnedAt), spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        list: async () => [
          { pid: 3200, parentPid: 1, start: String(reusedRootStart) },
          { pid: 3201, parentPid: 3200, start: String(reusedRootStart + 100) },
          { pid: 3202, parentPid: 3200, start: String(spawnedAt + 500) },
          { pid: 3203, parentPid: 3202, start: String(spawnedAt + 600) },
        ],
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(withOldLeftover.verified, false);
    assert.deepEqual(withOldLeftover.remaining.map(p => p.pid), [3202, 3203]);
    assert.equal(kills.length, 0);
  }

  // 8. win32 matched root exits after spawning a child between polls -> unverified, zero kills.
  {
    const kills: number[] = [];
    const spawnedAt = 1_700_000_000_000;
    let listCalls = 0;
    const result = await reconcileLaunchIdentity(
      { pid: 3400, start: String(spawnedAt), spawnedAt, processGroup: false },
      {
        platform: 'win32',
        graceMs: 10,
        currentStart: () => undefined,
        list: async (): Promise<ProcessIdentity[]> => {
          listCalls += 1;
          if (listCalls === 1) {
            return [{ pid: 3400, parentPid: 1, start: String(spawnedAt) }];
          }
          return [{ pid: 3401, parentPid: 3400, start: String(spawnedAt + 500) }];
        },
        killWindows: async pid => {
          kills.push(pid);
        },
      },
    );
    assert.equal(result.verified, false);
    assert.deepEqual(result.remaining.map(p => p.pid), [3401]);
    assert.equal(kills.length, 0);
  }

  // 9. linux matched root spawns a new child between polls -> child receives SIGKILL and result is verified.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    let listCalls = 0;
    let groupAlive = true;
    const result = await reconcileLaunchIdentity(
      { pid: 2500, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 300,
        bootId: () => BOOT_A,
        currentStart: targetPid => (targetPid === 2500 ? '100' : targetPid === 2501 ? '120' : undefined),
        list: async (): Promise<ProcessIdentity[]> => {
          listCalls += 1;
          if (listCalls === 1) {
            return [{ pid: 2500, parentPid: 1, start: '100' }];
          }
          if (listCalls === 2) {
            return [
              { pid: 2500, parentPid: 1, start: '100' },
              { pid: 2501, parentPid: 2500, start: '120' },
            ];
          }
          groupAlive = false;
          return [];
        },
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0 && !groupAlive) {
            throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' });
          }
        },
      },
    );
    assert.equal(result.verified, true);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.ok(signals.some(s => s.target === 2501 && s.sig === 'SIGKILL'));
  }

  // 10. linux root exits and another process with parentPid = root pid appears -> never signalled; verified once group is gone.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    let listCalls = 0;
    let groupAlive = true;
    const result = await reconcileLaunchIdentity(
      { pid: 2600, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 50,
        bootId: () => BOOT_A,
        currentStart: targetPid => (targetPid === 2600 ? '100' : targetPid === 2601 ? '150' : undefined),
        list: async (): Promise<ProcessIdentity[]> => {
          listCalls += 1;
          if (listCalls === 1) {
            return [{ pid: 2600, parentPid: 1, start: '100' }];
          }
          groupAlive = false;
          return [{ pid: 2601, parentPid: 2600, start: '150' }];
        },
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0 && !groupAlive) {
            throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' });
          }
        },
      },
    );
    assert.equal(result.verified, true);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.some(s => s.target === 2601), false);
  }
});

test('C6) Windows later confirmation by identity recovers from initial snapshot listing failure', async t => {
  // (a) Platform-independent: confirmCleanupByIdentity makes a single attempt (no retry), and on-demand reconcileLaunchIdentity confirms with zero kills.
  {
    let calls = 0;
    const launch = { pid: 4242, spawnedAt: Date.now(), processGroup: false };
    const laterResult = await confirmCleanupByIdentity(
      launch,
      {
        platform: 'win32',
        graceMs: 10,
        deadlineAt: Date.now() + 60_000,
        list: async () => {
          calls += 1;
          if (calls === 1) {
            throw new Error('simulated initial Windows snapshot failure');
          }
          return [];
        },
      },
    );
    assert.equal(laterResult.verified, false);
    assert.equal(laterResult.method, 'process-identity');
    assert.equal(laterResult.remaining.length, 0);
    assert.equal(calls, 1);

    const kills: number[] = [];
    const reconciled = await reconcileLaunchIdentity(launch, {
      platform: 'win32',
      graceMs: 10,
      list: async () => [],
      killWindows: async pid => {
        kills.push(pid);
      },
    });
    assert.equal(reconciled.verified, true);
    assert.equal(reconciled.method, 'process-identity');
    assert.equal(reconciled.remaining.length, 0);
    assert.equal(kills.length, 0);
  }

  // (b) Windows-only end-to-end: TaskManager completes and preview on-demand reconciliation confirms without touching a bystander process.
  await t.test('win32 TaskManager end-to-end later confirmation', async st => {
    if (process.platform !== 'win32') {
      st.skip('Windows-only end-to-end later confirmation test');
      return;
    }
    const ws = createWorkspace(st);
    const cli = new CliAdapter(ws.config, [MOCK_AGY]);
    const discovery = await cli.discover();
    assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

    const bystander = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
      stdio: 'ignore',
    });
    bystander.unref();
    const bystanderPid = bystander.pid;
    assert.ok(bystanderPid && bystanderPid > 1);

    try {
      let listCalls = 0;
      const agyAdapter = new AgyExecutionAdapter(cli, ws.config, undefined, {
        listProcesses: async signal => {
          listCalls += 1;
          if (listCalls === 1) {
            throw new Error('simulated post-exit snapshot timeout');
          }
          return await listProcessIdentities({ signal });
        },
      });
      const tasks = ws.track(new TaskManager(cli, ws.config, agyAdapter));
      const queued = await tasks.run({ prompt: 'write:c6-win32', workingDirectory: ws.repoDir, mode: 'write' });
      const completed = await waitForTask(tasks, queued.taskId);

      assert.equal(completed.status, 'completed');
      assert.ok(listCalls >= 1);

      const preview = await tasks.preview(completed.taskId);
      assert.ok(preview.sha256);

      const reconciled = tasks.status(completed.taskId);
      assert.equal(reconciled.processCleanup?.verified, true);
      assert.equal(reconciled.processCleanup?.remaining, 0);

      const stored = new StateStore(ws.stateDir).load().find(item => item.record.taskId === completed.taskId);
      assert.ok(stored?.project?.gitDirectory);
      assert.equal(existsSync(path.join(stored.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME)), false);
      assert.doesNotThrow(() => process.kill(bystanderPid, 0));
    } finally {
      try { bystander.kill('SIGKILL'); } catch { /* already exited */ }
    }
  });

  // (c) Windows-only end-to-end: short deadline skips end-of-task confirmation, leaving a marker, then preview reconciles on demand.
  await t.test('win32 TaskManager end attempt skipped then on-demand confirmation', async st => {
    if (process.platform !== 'win32') {
      st.skip('Windows-only end-to-end skipped attempt then on-demand confirmation test');
      return;
    }
    const ws = createWorkspace(st);
    const cli = new CliAdapter(ws.config, [MOCK_AGY]);
    const discovery = await cli.discover();
    assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

    const bystander = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
      stdio: 'ignore',
    });
    bystander.unref();
    const bystanderPid = bystander.pid;
    assert.ok(bystanderPid && bystanderPid > 1);

    try {
      let listingAvailable = false;
      const agyAdapter = new AgyExecutionAdapter(cli, ws.config, undefined, {
        listProcesses: async signal => {
          if (!listingAvailable) {
            throw new Error('listing unavailable');
          }
          return await listProcessIdentities(signal ? { signal } : undefined);
        },
      });
      const tasks = ws.track(new TaskManager(cli, ws.config, agyAdapter));
      const queued = await tasks.run({
        prompt: 'write:c6-win32-skipped',
        workingDirectory: ws.repoDir,
        mode: 'write',
        timeoutSeconds: 10,
      });
      const completed = await waitForTask(tasks, queued.taskId);

      assert.equal(completed.status, 'completed');
      assert.equal(completed.processCleanup?.verified, false);

      const stored = new StateStore(ws.stateDir).load().find(item => item.record.taskId === completed.taskId);
      assert.ok(stored?.project?.gitDirectory);
      const markerBefore = readProcessCleanupMarkerSync(stored.project);
      assert.ok(markerBefore?.entries.some(entry => entry.taskId === completed.taskId));

      listingAvailable = true;
      const preview = await tasks.preview(completed.taskId);
      assert.ok(preview.sha256);

      const reconciled = tasks.status(completed.taskId);
      assert.equal(reconciled.processCleanup?.verified, true);
      assert.equal(reconciled.processCleanup?.remaining, 0);

      const markerAfter = readProcessCleanupMarkerSync(stored.project);
      assert.ok(markerAfter === undefined || markerAfter.entries.length === 0);
      assert.doesNotThrow(() => process.kill(bystanderPid, 0));
    } finally {
      try { bystander.kill('SIGKILL'); } catch { /* already exited */ }
    }
  });
});

test('C7) recorded Linux identity is bound to the boot', async t => {
  // (a) & (b): different boot -> verified without any SIGKILL (processGroup false and true).
  for (const processGroup of [false, true]) {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2700, start: `${BOOT_A}:100`, spawnedAt: 1_000_000, processGroup },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_B,
        currentStart: () => '100',
        list: async () => [{ pid: 2700, parentPid: 1, start: '100' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(result.verified, true);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.filter(s => s.sig !== 0).length, 0);
    assert.equal(signals.length, 0);
  }

  // (c) & (d): identity without boot (old format) or unreadable current boot -> unverified, zero SIGKILL.
  for (const scenario of [
    { start: '100', bootId: () => BOOT_A },
    { start: `${BOOT_A}:100`, bootId: () => undefined },
  ]) {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 2710, start: scenario.start, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: scenario.bootId,
        currentStart: () => '100',
        list: async () => [{ pid: 2710, parentPid: 1, start: '100' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.filter(s => s.sig !== 0).length, 0);
  }

  // (e) recordedProcessStart formatting and platform/bootId guards.
  if (process.platform === 'linux') {
    const recorded = recordedProcessStart(process.pid, 'linux', () => BOOT_A);
    assert.ok(recorded !== undefined);
    assert.equal(recorded.startsWith(`${BOOT_A}:`), true);
    assert.match(recorded.slice(BOOT_A.length + 1), /^\d+$/);
  }
  assert.equal(recordedProcessStart(process.pid, 'linux', () => undefined), BOOT_UNAVAILABLE_START);
  assert.equal(recordedProcessStart(process.pid, 'win32', () => BOOT_A), undefined);

  // (f) Linux TaskManager end-to-end records boot-bound processCleanup.start.
  await t.test('linux TaskManager records boot-bound processCleanup.start', async st => {
    if (process.platform !== 'linux') {
      st.skip('Linux-only TaskManager boot-bound start test');
      return;
    }
    const ws = createWorkspace(st);
    const cli = new CliAdapter(ws.config, [MOCK_AGY]);
    const discovery = await cli.discover();
    assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

    const tasks = ws.track(new TaskManager(cli, ws.config));
    const queued = await tasks.run({ prompt: 'write:c7-linux', workingDirectory: ws.repoDir, mode: 'write' });
    const completed = await waitForTask(tasks, queued.taskId);
    assert.equal(completed.status, 'completed');
    assert.match(completed.processCleanup?.start ?? '', /^[0-9a-f-]{36}:\d+$/);
  });
});

test('C8) a launch recorded with an unreadable boot stays unconfirmed without signals', async () => {
  const start = recordedProcessStart(4242, 'linux', () => undefined);
  assert.equal(start, 'boot-unavailable');

  // (a) PID absent, process group gone (ESRCH on signal 0), current boot readable -> unverified, no SIGKILL.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 4242, start, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        list: async () => [],
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0) {
            throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' });
          }
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.filter(s => s.sig !== 0).length, 0);
  }

  // (b) PID absent, process group gone (ESRCH on signal 0), current boot unreadable -> unverified, no SIGKILL.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 4242, start, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => undefined,
        list: async () => [],
        signal: (target, sig) => {
          signals.push({ target, sig });
          if (sig === 0) {
            throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' });
          }
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.filter(s => s.sig !== 0).length, 0);
  }

  // (c) Listed root present -> unverified, zero signals of any kind.
  {
    const signals: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
    const result = await reconcileLaunchIdentity(
      { pid: 4242, start, spawnedAt: 1_000_000, processGroup: true },
      {
        platform: 'linux',
        graceMs: 10,
        bootId: () => BOOT_A,
        currentStart: () => '100',
        list: async () => [{ pid: 4242, parentPid: 1, start: '100' }],
        signal: (target, sig) => {
          signals.push({ target, sig });
        },
      },
    );
    assert.equal(result.verified, false);
    assert.equal(result.method, 'process-identity');
    assert.equal(result.remaining.length, 0);
    assert.equal(signals.length, 0);
  }
});

test('C9) a slow process listing with an almost exhausted deadline never extends the task', async t => {
  // (a) Platform-independent unit checks for deadline gating and abort timing.
  {
    let listCalls = 0;
    const startedAt = Date.now();
    const skipped = await confirmCleanupByIdentity(
      { pid: 4242, spawnedAt: startedAt, processGroup: false },
      {
        platform: 'win32',
        deadlineAt: startedAt + 500,
        list: async () => {
          listCalls += 1;
          await new Promise(resolve => setTimeout(resolve, 2000));
          return [];
        },
      },
    );
    const elapsedMs = Date.now() - startedAt;
    assert.equal(skipped.verified, false);
    assert.equal(skipped.method, 'process-identity');
    assert.equal(skipped.remaining.length, 0);
    assert.equal(listCalls, 0);
    assert.ok(elapsedMs < 1000, `expected skipped confirmation in < 1000 ms, got ${elapsedMs} ms`);
  }

  {
    let listCalls = 0;
    let observedSignal: AbortSignal | undefined;
    const deadlineAt = Date.now() + PROCESS_LISTING_TIMEOUT_MS + 1500;
    const aborted = await confirmCleanupByIdentity(
      { pid: 4242, spawnedAt: Date.now(), processGroup: false },
      {
        platform: 'win32',
        deadlineAt,
        list: signal => {
          listCalls += 1;
          observedSignal = signal;
          return new Promise<ProcessIdentity[]>((_, reject) => {
            if (!signal) {
              reject(new Error('expected AbortSignal'));
              return;
            }
            if (signal.aborted) {
              reject(new Error('Process listing aborted'));
              return;
            }
            signal.addEventListener('abort', () => reject(new Error('Process listing aborted')), { once: true });
          });
        },
      },
    );
    assert.equal(aborted.verified, false);
    assert.equal(aborted.method, 'process-identity');
    assert.equal(aborted.remaining.length, 0);
    assert.equal(listCalls, 1);
    assert.equal(observedSignal?.aborted, true);
    assert.ok(Date.now() <= deadlineAt, 'confirmCleanupByIdentity must settle no later than deadlineAt');
  }

  // (b) Windows-only end-to-end check with TaskManager and a short task deadline.
  await t.test('win32 TaskManager slow listing with short deadline completes unverified', async st => {
    if (process.platform !== 'win32') {
      st.skip('Windows-only end-to-end slow listing test');
      return;
    }
    const ws = createWorkspace(st);
    const cli = new CliAdapter(ws.config, [MOCK_AGY]);
    const discovery = await cli.discover();
    assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

    const timeoutSeconds = 20;
    let taskId: string | undefined;
    let listCalls = 0;
    const fallbackStartedAt = Date.now();
    let tasks!: TaskManager;

    const agyAdapter = new AgyExecutionAdapter(cli, ws.config, undefined, {
      listProcesses: async signal => {
        listCalls += 1;
        if (listCalls === 1) {
          const startedEvent = taskId
            ? tasks.readEvents(taskId).events.find(event => event.type === 'process.started')
            : undefined;
          const startedMs = startedEvent ? Date.parse(startedEvent.timestamp) : fallbackStartedAt;
          const approxDeadlineAt = startedMs + timeoutSeconds * 1000;
          const waitMs = Math.max(0, approxDeadlineAt - 2000 - Date.now());
          await new Promise(resolve => setTimeout(resolve, waitMs));
          throw new Error('simulated slow post-exit Windows snapshot failure');
        }
        return await new Promise<ProcessIdentity[]>((_, reject) => {
          if (!signal) return;
          if (signal.aborted) {
            reject(new Error('Process listing aborted'));
            return;
          }
          signal.addEventListener('abort', () => reject(new Error('Process listing aborted')), { once: true });
        });
      },
    });

    tasks = ws.track(new TaskManager(cli, ws.config, agyAdapter));
    const queued = await tasks.run({
      prompt: 'write:c9-win32',
      workingDirectory: ws.repoDir,
      mode: 'write',
      timeoutSeconds,
    });
    taskId = queued.taskId;
    const completed = await waitForTask(tasks, queued.taskId);

    assert.equal(completed.status, 'completed');
    assert.equal(completed.processCleanup?.verified, false);
  });
});
