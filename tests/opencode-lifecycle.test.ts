import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { CliAdapter, type Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { createProjectCopy, discardProjectCopy, PROCESS_CLEANUP_MARKER_NAME, upsertProcessCleanupMarkerEntrySync } from '../src/isolation.js';
import type { ExecutionAdapter, ExecutionContext, ExecutionRequest, ExecutionResult } from '../src/execution-contract.js';
import { detectBubblewrap } from '../src/linux-executor.js';
import {
  MAX_OPENCODE_PROVIDER_RETRIES,
  OPENCODE_ADAPTER_VERSION,
  OPENCODE_RESUME_REQUIRES_PID_NAMESPACE,
  OpenCodeExecutionAdapter,
} from '../src/opencode-execution-adapter.js';
import {
  countPidNamespaceMembers,
  descendantIdentities,
  listProcessIdentities,
  reconcileTrackedProcesses,
  type ProcessIdentity,
} from '../src/process-tree.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError, type TaskRecord } from '../src/types.js';
import { taskTokenUsage } from '../src/usage.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { createReadFixture } from './read-fixture.js';
import { waitForTask } from './wait-for-task.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MOCK_OPENCODE = path.resolve(HERE, '../../tests/mock-opencode.mjs');
const MOCK_AGY = path.resolve(HERE, '../../tests/mock-agy.mjs');
const CLI_ENTRY = fileURLToPath(new URL('../src/index.js', import.meta.url));

class OpenCodeTestCliAdapter extends ControlledCliAdapter {
  override async listModels(): Promise<Model[]> {
    return [
      { id: 'opencode-go/mock-flash', name: 'Mock Flash' },
      { id: 'opencode-go/mock-pro', name: 'Mock Pro' },
    ];
  }
}

function createWorkspace(t: { after(fn: () => Promise<void> | void): void }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'bg-oc-life-'));
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

function readSpawnLog(file: string): Array<{ argv: string[]; pid: number }> {
  if (!existsSync(file)) return [];
  const raw = readFileSync(file, 'utf8').trim();
  if (!raw) return [];
  return raw.split(/\r?\n/).map(line => JSON.parse(line) as { argv: string[]; pid: number });
}

async function waitForFilePid(file: string, timeoutMs = 10_000): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file)) {
      const text = readFileSync(file, 'utf8').trim();
      const pid = Number(text);
      if (Number.isInteger(pid) && pid > 0) return pid;
    }
    await delay(25);
  }
  throw new Error(`Timed out waiting for PID file ${file}`);
}

function assertProcessGone(pid: number): void {
  assert.throws(() => process.kill(pid, 0), (err: NodeJS.ErrnoException) => err.code === 'ESRCH');
}

function canUseLinuxBwrap(): boolean {
  return process.platform === 'linux' && detectBubblewrap().available;
}

async function resolveHostPidInNamespace(rootPid: number, innerPid: number, timeoutMs = 5_000): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const list = await listProcessIdentities();
    for (const desc of descendantIdentities(list, rootPid)) {
      try {
        const status = readFileSync(`/proc/${desc.pid}/status`, 'utf8');
        const match = /^NSpid:\s+(.+)$/m.exec(status);
        if (!match?.[1]) continue;
        const ids = match[1].trim().split(/\s+/).map(Number);
        if (ids.length >= 2 && ids.at(-1) === innerPid) {
          return desc.pid;
        }
      } catch {
        // Process may still be starting or exiting.
      }
    }
    await delay(25);
  }
  throw new Error(`Timed out resolving host PID for namespace PID ${innerPid} under ${rootPid}`);
}

function makeStart(order: number): string {
  return process.platform === 'linux' || process.platform === 'win32'
    ? String(1000 + order)
    : new Date(1_700_000_000_000 + order * 1000).toISOString();
}

function startWaitCli(stateDir: string, taskId: string, extra: readonly string[] = []) {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.BRIDGE_STATE_DIRECTORY;
  const child: ChildProcess = spawn(
    process.execPath,
    [CLI_ENTRY, 'wait', '--state-directory', stateDir, taskId, ...extra],
    {
      windowsHide: true,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let stdout = '';
  let stderr = '';
  child.stdout?.setEncoding('utf8');
  child.stderr?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => { stdout += chunk; });
  child.stderr?.on('data', (chunk: string) => { stderr += chunk; });
  const done = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout, stderr }));
  });
  return { child, done };
}

async function runWaitCli(stateDir: string, taskId: string, extra: readonly string[] = []) {
  const result = await startWaitCli(stateDir, taskId, extra).done;
  assert.equal(result.stderr, '');
  const trimmed = result.stdout.replace(/\r?\n$/, '');
  const lines = trimmed === '' ? [] : trimmed.split(/\r?\n/);
  assert.equal(lines.length, 1, `Expected one stdout line, got: ${JSON.stringify(result.stdout)}`);
  return {
    code: result.code,
    json: JSON.parse(lines[0]!) as Record<string, unknown>,
  };
}

test('L1) cancel kills the whole process tree including detached grandchildren', async t => {
  if (process.platform === 'win32') {
    t.skip('POSIX process-tree test');
    return;
  }

  for (const mode of ['none', 'auto'] as const) {
    await t.test(`containment: ${mode}`, async st => {
      if (mode === 'auto' && !canUseLinuxBwrap()) {
        st.skip('Linux bubblewrap PID namespace unavailable');
        return;
      }
      const ws = createWorkspace(st);
      const rec = path.join(ws.root, `hang-cancel-${mode}.json`);
      const grandchildFile = `${rec}.grandchild-pid`;
      const cli = new OpenCodeTestCliAdapter(ws.config);
      const adapter = new OpenCodeExecutionAdapter({
        executable: process.execPath,
        prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'hang'],
        containment: mode,
      });
      const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

      const queued = await tasks.run({
        prompt: 'Hang until cancelled',
        workingDirectory: ws.repoDir,
        mode: 'write',
        model: 'opencode-go/mock-flash',
      });

      const grandchildInnerPid = await waitForFilePid(grandchildFile);
      while (tasks.status(queued.taskId).pid === undefined) {
        await delay(25);
      }
      const runningPid = tasks.status(queued.taskId).pid!;
      const grandchildHostPid = mode === 'auto'
        ? await resolveHostPidInNamespace(runningPid, grandchildInnerPid)
        : grandchildInnerPid;

      await tasks.cancel(queued.taskId);
      const record = await waitForTask(tasks, queued.taskId);

      assert.equal(record.status, 'cancelled');
      assert.equal(record.error?.code, 'TASK_CANCELLED');
      assert.equal(record.processCleanup?.verified, true);
      assert.equal(record.processCleanup?.remaining, 0);
      const raw = record.result as { containment?: string } | undefined;
      assert.equal(raw?.containment, mode === 'auto' ? 'pid-namespace' : 'process-tree');
      assert.ok(record.pid);
      assertProcessGone(record.pid);
      assertProcessGone(grandchildHostPid);

      const persisted = new StateStore(ws.stateDir).load().find(item => item.record.taskId === queued.taskId);
      assert.ok(persisted);
      assert.equal(persisted.record.status, 'cancelled');
      assert.equal(persisted.record.error?.code, 'TASK_CANCELLED');
      assert.equal(persisted.record.processCleanup?.verified, true);
      assert.equal(persisted.record.processCleanup?.remaining, 0);
    });
  }
});

test('L2) timeout kills the whole process tree and persists cleanup', async t => {
  if (process.platform === 'win32') {
    t.skip('POSIX process-tree test');
    return;
  }

  for (const mode of ['none', 'auto'] as const) {
    await t.test(`containment: ${mode}`, async st => {
      if (mode === 'auto' && !canUseLinuxBwrap()) {
        st.skip('Linux bubblewrap PID namespace unavailable');
        return;
      }
      const ws = createWorkspace(st);
      const rec = path.join(ws.root, `hang-timeout-${mode}.json`);
      const grandchildFile = `${rec}.grandchild-pid`;
      const cli = new OpenCodeTestCliAdapter(ws.config);
      const adapter = new OpenCodeExecutionAdapter({
        executable: process.execPath,
        prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'hang'],
        containment: mode,
      });
      const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

      const queued = await tasks.run({
        prompt: 'Hang until timeout',
        workingDirectory: ws.repoDir,
        mode: 'write',
        model: 'opencode-go/mock-flash',
        timeoutSeconds: 2,
      });

      const grandchildInnerPid = await waitForFilePid(grandchildFile);
      while (tasks.status(queued.taskId).pid === undefined) {
        await delay(25);
      }
      const runningPid = tasks.status(queued.taskId).pid!;
      const grandchildHostPid = mode === 'auto'
        ? await resolveHostPidInNamespace(runningPid, grandchildInnerPid, 1_500)
        : grandchildInnerPid;
      const record = await waitForTask(tasks, queued.taskId);

      assert.equal(record.status, 'timeout');
      assert.equal(record.error?.code, 'TASK_TIMEOUT');
      assert.equal(record.processCleanup?.verified, true);
      assert.equal(record.processCleanup?.remaining, 0);
      const raw = record.result as { containment?: string } | undefined;
      assert.equal(raw?.containment, mode === 'auto' ? 'pid-namespace' : 'process-tree');
      assert.ok(record.pid);
      assertProcessGone(record.pid);
      assertProcessGone(grandchildHostPid);

      const persisted = new StateStore(ws.stateDir).load().find(item => item.record.taskId === queued.taskId);
      assert.ok(persisted);
      assert.equal(persisted.record.status, 'timeout');
      assert.equal(persisted.record.error?.code, 'TASK_TIMEOUT');
      assert.equal(persisted.record.processCleanup?.verified, true);
    });
  }
});

test('L3) provider failures never repeat and retry loops stop at the retry limit', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const cases = [
    { scenario: 'auth-error', code: 'OPENCODE_AUTH_REQUIRED' },
    { scenario: 'quota-error', code: 'OPENCODE_QUOTA_EXCEEDED' },
    { scenario: 'region-error', code: 'OPENCODE_REGION_UNAVAILABLE' },
    { scenario: 'retry-loop', code: 'OPENCODE_RETRY_LIMIT' },
    { scenario: 'retry-auth', code: 'OPENCODE_AUTH_REQUIRED' },
    { scenario: 'retry-quota', code: 'OPENCODE_QUOTA_EXCEEDED' },
  ] as const;

  for (const item of cases) {
    const spawnLog = path.join(ws.root, `spawn-${item.scenario}.jsonl`);
    const adapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--spawn-log', spawnLog, '--scenario', item.scenario],
    });
    const tasks = ws.track(new TaskManager(cli, ws.config, adapter));
    const queued = await tasks.run({
      prompt: `Trigger ${item.scenario}`,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
    });
    const record = await waitForTask(tasks, queued.taskId);

    assert.equal(record.status, 'failed');
    assert.equal(record.error?.code, item.code);
    const runsBeforeWait = readSpawnLog(spawnLog).filter(entry => entry.argv[0] === 'run');
    assert.equal(runsBeforeWait.length, 1);

    await delay(1500);
    const runsAfterWait = readSpawnLog(spawnLog).filter(entry => entry.argv[0] === 'run');
    assert.equal(runsAfterWait.length, 1);

    if (item.scenario === 'retry-loop') {
      const raw = record.result as { providerRetries?: number } | undefined;
      assert.equal(raw?.providerRetries, MAX_OPENCODE_PROVIDER_RETRIES + 1);
      assert.equal(record.processCleanup?.verified, true);
      if (process.platform !== 'win32' && record.pid !== undefined) {
        assertProcessGone(record.pid);
      }
    }
    await tasks.shutdown();
  }

  const genericErrAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'error'],
  });
  const genericResult = await genericErrAdapter.execute({
    taskId: 'l3-generic-error',
    prompt: 'error',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(genericResult.status, 'failed');
  if (genericResult.status === 'failed') {
    assert.equal(genericResult.error.code, 'OPENCODE_PROCESS_FAILED');
  }
});

test('L4) unknown effects, unverified cleanup, and restart recovery block unsafe reuse', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  if (process.platform !== 'win32') {
    const rec = path.join(ws.root, 'tool-running.json');
    const spawnLog = path.join(ws.root, 'tool-running-spawn.jsonl');
    const hangAdapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--spawn-log', spawnLog, '--record', rec, '--scenario', 'tool-running-hang'],
    });
    const hangTasks = ws.track(new TaskManager(cli, ws.config, hangAdapter));
    const queued = await hangTasks.run({
      prompt: 'Run write tool and hang',
      workingDirectory: ws.repoDir,
      mode: 'write',
      model: 'opencode-go/mock-flash',
    });
    while (!existsSync(rec) || hangTasks.status(queued.taskId).pid === undefined) {
      await delay(25);
    }
    await delay(250);
    await hangTasks.cancel(queued.taskId);
    const cancelled = await waitForTask(hangTasks, queued.taskId);
    assert.equal(cancelled.status, 'cancelled');
    const raw = cancelled.result as { unknownEffects?: Array<{ tool: string; status: string }> } | undefined;
    assert.deepEqual(raw?.unknownEffects, [
      { tool: 'write', status: 'running' },
      { tool: 'unknown', status: 'interrupted' },
    ]);
    assert.match(cancelled.error?.message ?? '', /effects unknown/);
    assert.equal(readSpawnLog(spawnLog).filter(entry => entry.argv[0] === 'run').length, 1);
    await assert.rejects(
      () => hangTasks.integrate(cancelled.taskId, '0'.repeat(64), async () => true),
      err => err instanceof BridgeError && err.code === 'TASK_NOT_READY',
    );
    await hangTasks.shutdown();

    for (const mode of ['none', 'auto'] as const) {
      await t.test(`write-hang (containment: ${mode})`, async st => {
        if (mode === 'auto' && !canUseLinuxBwrap()) {
          st.skip('Linux bubblewrap PID namespace unavailable');
          return;
        }
        const hangRec = path.join(ws.root, `write-hang-${mode}.json`);
        const hangGrandchildFile = `${hangRec}.grandchild-pid`;
        const hangSpawnLog = path.join(ws.root, `write-hang-spawn-${mode}.jsonl`);
        const writeHangAdapter = new OpenCodeExecutionAdapter({
          executable: process.execPath,
          prefixArgs: [MOCK_OPENCODE, '--spawn-log', hangSpawnLog, '--record', hangRec, '--scenario', 'hang'],
          containment: mode,
        });
        const writeHangTasks = ws.track(new TaskManager(cli, ws.config, writeHangAdapter));
        const writeHangQueued = await writeHangTasks.run({
          prompt: 'Hang mid-step in write mode',
          workingDirectory: ws.repoDir,
          mode: 'write',
          model: 'opencode-go/mock-flash',
        });
        const writeHangGrandchildInnerPid = await waitForFilePid(hangGrandchildFile);
        while (writeHangTasks.status(writeHangQueued.taskId).pid === undefined) {
          await delay(25);
        }
        const writeHangRunningPid = writeHangTasks.status(writeHangQueued.taskId).pid!;
        const writeHangGrandchildHostPid = mode === 'auto'
          ? await resolveHostPidInNamespace(writeHangRunningPid, writeHangGrandchildInnerPid)
          : writeHangGrandchildInnerPid;
        const persistedRunning = new StateStore(ws.stateDir).load().find(item => item.record.taskId === writeHangQueued.taskId);
        assert.ok(persistedRunning);
        assert.equal(persistedRunning.record.status, 'running');
        assert.equal(persistedRunning.record.processCleanup?.verified, false);
        await delay(100);
        await writeHangTasks.cancel(writeHangQueued.taskId);
        const writeHangCancelled = await waitForTask(writeHangTasks, writeHangQueued.taskId);
        assert.equal(writeHangCancelled.status, 'cancelled');
        assert.equal(writeHangCancelled.processCleanup?.verified, true);
        assertProcessGone(writeHangGrandchildHostPid);
        const writeHangRaw = writeHangCancelled.result as {
          containment?: string;
          unknownEffects?: Array<{ tool: string; status: string }>;
        } | undefined;
        assert.equal(writeHangRaw?.containment, mode === 'auto' ? 'pid-namespace' : 'process-tree');
        assert.deepEqual(writeHangRaw?.unknownEffects, [{ tool: 'unknown', status: 'interrupted' }]);
        assert.match(writeHangCancelled.error?.message ?? '', /effects unknown for: unknown\(interrupted\); inspect the copy before reuse/);
        assert.equal(readSpawnLog(hangSpawnLog).filter(entry => entry.argv[0] === 'run').length, 1);
        await writeHangTasks.shutdown();
      });
    }
  }

  const fixture = createReadFixture(ws.repoDir);
  const throwListAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
    containment: 'none',
    listProcesses: async () => {
      throw new Error('process listing failed');
    },
  });
  const unverifiedTasks = ws.track(new TaskManager(cli, ws.config, throwListAdapter));
  const readQueued = await unverifiedTasks.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const readDone = await waitForTask(unverifiedTasks, readQueued.taskId);
  assert.equal(readDone.status, 'completed');
  assert.equal(readDone.processCleanup?.verified, false);

  await assert.rejects(
    () => unverifiedTasks.preview(readDone.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => unverifiedTasks.resume({ workingDirectory: ws.repoDir, prompt: 'continue' }, readDone.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );

  // Persist a running OpenCode task with dead ownerPid and dead child pid, then reload in a fresh TaskManager.
  const deadOwner = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  const deadChild = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  assert.ok(deadOwner.pid && deadChild.pid);
  const orphanStateDir = path.join(ws.root, 'orphan-state');
  mkdirSync(orphanStateDir, { recursive: true });
  const orphanConfig = loadConfig({
    BRIDGE_STATE_DIRECTORY: orphanStateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
  });
  const orphanTaskId = '00000000-0000-4000-8000-000000000044';
  const orphanProject = await createProjectCopy(ws.repoDir, undefined, undefined, orphanConfig);
  t.after(async () => {
    await discardProjectCopy(orphanProject).catch(() => undefined);
  });
  const orphanLaunchedAt = new Date().toISOString();
  const store = new StateStore(orphanStateDir);
  store.save({
    ownerPid: deadOwner.pid,
    events: [],
    cursor: 0,
    redacted: true,
    project: orphanProject,
    record: {
      taskId: orphanTaskId,
      workingDirectory: ws.repoDir,
      copyDirectory: orphanProject.copyDirectory,
      includedFiles: orphanProject.includedFiles,
      prompt: 'interrupted opencode task',
      status: 'running',
      createdAt: orphanLaunchedAt,
      startedAt: orphanLaunchedAt,
      pid: deadChild.pid,
      mode: 'read-only',
      processCleanup: {
        verified: false,
        spawnedAt: orphanLaunchedAt,
        checkedAt: orphanLaunchedAt,
        remaining: 0,
      },
      execution: {
        provider: 'opencode',
        adapterId: 'opencode-cli',
        adapterVersion: '3',
        requested: { model: null, effort: null },
        observed: { model: null, status: 'not-observable' },
      },
    },
    options: {
      workingDirectory: ws.repoDir,
      prompt: 'interrupted opencode task',
      mode: 'read-only',
    },
  });
  const restartSpawnLog = path.join(ws.root, 'restart-spawn.jsonl');
  const restartAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--spawn-log', restartSpawnLog, '--scenario', 'read'],
  });
  const recovered = ws.track(new TaskManager(cli, orphanConfig, restartAdapter));
  const recoveredRecord = recovered.status(orphanTaskId);
  assert.equal(recoveredRecord.status, 'failed');
  assert.equal(recoveredRecord.error?.code, 'SERVER_RESTARTED');
  assert.equal(recoveredRecord.processCleanup?.verified, false);
  await assert.rejects(
    () => recovered.preview(orphanTaskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(existsSync(restartSpawnLog), false);
});

function createUnverifiedResumeAdapter(sessionId: string, pid: number): ExecutionAdapter {
  return {
    identity: { id: 'fake-opencode', provider: 'opencode', version: OPENCODE_ADAPTER_VERSION },
    capabilities: {
      read: 'supported',
      write: 'supported',
      sandbox: 'unknown',
      network: 'unsupported',
      skills: 'unsupported',
      resources: 'unknown',
      structuredOutput: 'supported',
      cancel: 'supported',
      resume: 'supported',
      observableUsage: 'unknown',
    },
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      const spawnedAt = new Date().toISOString();
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
        session: { id: sessionId },
        response: 'done',
      };
    },
  };
}

test('L5) resume without a PID namespace is refused before any process and leaves the copy unmarked', async t => {
  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const spawnLog = path.join(ws.root, 'resume-none-spawn.jsonl');
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--spawn-log', spawnLog, '--scenario', 'read'],
    containment: 'none',
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));
  const runCompletedReadTask = async (manager: TaskManager) => {
    const queued = await manager.run({
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
    });
    const record = await waitForTask(manager, queued.taskId);
    assert.equal(record.status, 'completed');
    assert.ok(record.sessionId);
    assert.ok(record.copyDirectory);
    return { ...record, sessionId: record.sessionId, copyDirectory: record.copyDirectory };
  };

  const first = await runCompletedReadTask(tasks);
  const spawnLogBeforeResume = readSpawnLog(spawnLog);
  assert.equal(spawnLogBeforeResume.length, 1);

  const resumedQueued = await tasks.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );
  const resumed = await waitForTask(tasks, resumedQueued.taskId);
  assert.equal(resumed.status, 'failed');
  assert.equal(resumed.error?.code, OPENCODE_RESUME_REQUIRES_PID_NAMESPACE);
  assert.deepEqual(readSpawnLog(spawnLog), spawnLogBeforeResume);
  assert.equal(resumed.processCleanup, undefined);
  const resumedEvents = tasks.readEvents(resumed.taskId, 0, 1000).events;
  assert.equal(resumedEvents.some(event => event.type === 'process.started'), false);

  const firstPreview = await tasks.preview(first.taskId);
  const resumedPreview = await tasks.preview(resumed.taskId);
  assert.ok(firstPreview.sha256);
  assert.ok(resumedPreview.sha256);

  // L5e: version 2 persisted snapshot refused before any spawn
  await tasks.shutdown();
  const v2SeedAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
  });
  const v2SeedTasks = ws.track(new TaskManager(cli, ws.config, v2SeedAdapter));
  const v2Base = await runCompletedReadTask(v2SeedTasks);
  await v2SeedTasks.shutdown();
  const snapshotPath = path.join(ws.stateDir, `${v2Base.taskId}.json`);
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
    record: { execution: { adapterVersion: string } };
  };
  snapshot.record.execution.adapterVersion = '2';
  writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');

  const v2SpawnLog = path.join(ws.root, 'v2-spawn.jsonl');
  const v2Adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--spawn-log', v2SpawnLog, '--scenario', 'read'],
  });
  const v2Tasks = ws.track(new TaskManager(cli, ws.config, v2Adapter));
  await assert.rejects(
    () => v2Tasks.resume({ workingDirectory: ws.repoDir, prompt: fixture.prompt }, v2Base.taskId),
    err => err instanceof BridgeError && err.code === 'INVALID_SESSION' && err.message.includes('version 2'),
  );
  assert.equal(existsSync(v2SpawnLog), false);
});

test('L6) wait command parity with agy for terminal and running OpenCode tasks', async t => {
  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const runScenario = async (scenario: string, extraRun?: { timeoutSeconds?: number; cancelWhenRunning?: boolean }) => {
    const adapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', scenario],
    });
    const tasks = ws.track(new TaskManager(cli, ws.config, adapter));
    const queued = await tasks.run({
      prompt: scenario === 'read' ? fixture.prompt : `Run ${scenario}`,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
      ...(extraRun?.timeoutSeconds ? { timeoutSeconds: extraRun.timeoutSeconds } : {}),
    });
    if (extraRun?.cancelWhenRunning) {
      while (tasks.status(queued.taskId).pid === undefined) {
        await delay(25);
      }
      await tasks.cancel(queued.taskId);
    }
    const done = await waitForTask(tasks, queued.taskId);
    await tasks.shutdown();
    return done;
  };

  const completed = await runScenario('read');
  const failed = await runScenario('auth-error');
  const cancelled = await runScenario('hang', { cancelWhenRunning: true });
  const timedOut = await runScenario('hang', { timeoutSeconds: 2 });

  const table = [
    { record: completed, outcome: 'completed', exitCode: 0, reason: null },
    { record: failed, outcome: 'failed', exitCode: 2, reason: 'OPENCODE_AUTH_REQUIRED' },
    { record: cancelled, outcome: 'cancelled', exitCode: 3, reason: null },
    { record: timedOut, outcome: 'timeout', exitCode: 4, reason: null },
  ] as const;

  for (const row of table) {
    const res = await runWaitCli(ws.stateDir, row.record.taskId, ['--timeout', '30']);
    assert.equal(res.code, row.exitCode);
    assert.deepEqual(res.json, {
      taskId: row.record.taskId,
      outcome: row.outcome,
      exitCode: row.exitCode,
      status: row.record.status,
      reason: row.reason,
      after: 0,
      cursor: row.record.messageCursor ?? 0,
    });
  }

  const slowAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'slow-complete'],
  });
  const slowTasks = ws.track(new TaskManager(cli, ws.config, slowAdapter));
  const slowQueued = await slowTasks.run({
    prompt: 'Slow complete',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const waitHandle = startWaitCli(ws.stateDir, slowQueued.taskId, ['--timeout', '30']);
  const waitOutcome = await waitHandle.done;
  assert.equal(waitOutcome.stderr, '');
  assert.equal(waitOutcome.code, 0);
  const waitJson = JSON.parse(waitOutcome.stdout.trim()) as { outcome: string; taskId: string };
  assert.equal(waitJson.taskId, slowQueued.taskId);
  assert.equal(waitJson.outcome, 'completed');
  const slowDone = await waitForTask(slowTasks, slowQueued.taskId);
  assert.equal(slowDone.status, 'completed');
});

test('L7) opt-in real OpenCode lifecycle checks with a local scripted model', {
  skip: !process.env.BRIDGE_OPENCODE_REAL_BIN,
  timeout: 180_000,
}, async () => {
  const tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'bg-oc-real-'));
  type ServerMode =
    | { kind: 'ok' }
    | { kind: 'slow' }
    | { kind: 'http-error'; status: number; body: Record<string, unknown> };
  let mode: ServerMode = { kind: 'ok' };
  const toolsRequests: Array<{ messages: Array<{ role?: string; content?: unknown }> }> = [];
  let slowStreamStarted = false;

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      if (req.method !== 'POST' || req.url !== '/v1/chat/completions') {
        res.writeHead(404);
        res.end();
        return;
      }

      const body = JSON.parse(rawBody) as {
        model?: string;
        messages?: Array<{ role?: string; content?: unknown }>;
        tools?: unknown[];
      };

      const hasTools = Array.isArray(body.tools) && body.tools.length > 0;
      if (hasTools) {
        toolsRequests.push({ messages: body.messages ?? [] });
        if (mode.kind === 'http-error') {
          res.writeHead(mode.status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(mode.body));
          return;
        }
      }

      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
        connection: 'keep-alive',
      });
      const sendChunk = (chunk: Record<string, unknown>) => {
        res.write(
          `data: ${JSON.stringify({
            id: 'chatcmpl-real',
            object: 'chat.completion.chunk',
            created: 0,
            model: body.model ?? 'm1',
            ...chunk,
          })}\n\n`,
        );
      };

      if (!hasTools) {
        sendChunk({ choices: [{ index: 0, delta: { role: 'assistant', content: 'title' }, finish_reason: null }] });
        sendChunk({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
        sendChunk({ choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }

      if (mode.kind === 'slow') {
        slowStreamStarted = true;
        sendChunk({ choices: [{ index: 0, delta: { role: 'assistant', content: 'partial...' }, finish_reason: null }] });
        const keepOpen = setTimeout(() => {
          sendChunk({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
          res.write('data: [DONE]\n\n');
          res.end();
        }, 30_000);
        keepOpen.unref();
        req.on('close', () => clearTimeout(keepOpen));
        return;
      }

      sendChunk({ choices: [{ index: 0, delta: { role: 'assistant', content: 'ok' }, finish_reason: null }] });
      sendChunk({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
      sendChunk({ choices: [], usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 } });
      res.write('data: [DONE]\n\n');
      res.end();
    });
  });

  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');

    const homeDir = path.join(tmpRoot, 'home');
    const cfgDir = path.join(homeDir, 'cfg');
    const dataDir = path.join(homeDir, 'data');
    const stateDir = path.join(homeDir, 'state');
    const cacheDir = path.join(homeDir, 'cache');
    const workDir1 = path.join(tmpRoot, 'work1');
    const workDir2 = path.join(tmpRoot, 'work2');
    mkdirSync(path.join(cfgDir, 'opencode'), { recursive: true });
    mkdirSync(dataDir, { recursive: true });
    mkdirSync(stateDir, { recursive: true });
    mkdirSync(cacheDir, { recursive: true });
    mkdirSync(workDir1, { recursive: true });
    mkdirSync(workDir2, { recursive: true });

    writeFileSync(
      path.join(cfgDir, 'opencode', 'opencode.json'),
      JSON.stringify({
        providers: {
          bgmock: {
            package: '@ai-sdk/openai-compatible',
            settings: { baseURL: `http://127.0.0.1:${addr.port}/v1`, apiKey: 'x' },
            models: { m1: { name: 'm1', tool_call: true } },
          },
        },
      }),
      'utf8',
    );

    const adapter = new OpenCodeExecutionAdapter({
      executable: process.env.BRIDGE_OPENCODE_REAL_BIN!,
      allowedEnvVars: ['HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME'],
      env: {
        HOME: homeDir,
        XDG_CONFIG_HOME: cfgDir,
        XDG_DATA_HOME: dataDir,
        XDG_STATE_HOME: stateDir,
        XDG_CACHE_HOME: cacheDir,
        PATH: process.env.PATH,
      },
    });

    // (a) run + resume in same folder, refuse in another folder
    const res1 = await adapter.execute({
      taskId: 'l7-a-1',
      prompt: 'PROMPT_ONE_MARKER',
      workingDirectory: workDir1,
      role: 'implementer',
      mode: 'read-only',
      model: 'bgmock/m1',
    });
    assert.equal(res1.status, 'completed');
    assert.ok(res1.session?.id);
    const res1Raw = res1.raw as { containment?: string } | undefined;
    if (canUseLinuxBwrap()) {
      assert.equal(res1Raw?.containment, 'pid-namespace');
    } else {
      assert.equal(res1Raw?.containment, 'process-tree');
    }

    const countBeforeResume = toolsRequests.length;
    const res2 = await adapter.execute({
      taskId: 'l7-a-2',
      prompt: 'PROMPT_TWO_MARKER',
      workingDirectory: workDir1,
      role: 'implementer',
      mode: 'read-only',
      model: 'bgmock/m1',
      session: res1.session,
    });
    if (canUseLinuxBwrap()) {
      assert.equal(res2.status, 'completed');
      const secondPayload = JSON.stringify(toolsRequests.at(-1)?.messages ?? []);
      assert.equal(secondPayload.includes('PROMPT_ONE_MARKER'), true);
      assert.equal(secondPayload.includes('PROMPT_TWO_MARKER'), true);
    } else {
      assert.equal(res2.status, 'failed');
      if (res2.status === 'failed') {
        assert.equal(res2.error.code, OPENCODE_RESUME_REQUIRES_PID_NAMESPACE);
      }
      assert.equal(toolsRequests.length, countBeforeResume);
    }

    const countBeforeForeign = toolsRequests.length;
    const resForeign = await adapter.execute({
      taskId: 'l7-a-foreign',
      prompt: 'should not run',
      workingDirectory: workDir2,
      role: 'implementer',
      mode: 'read-only',
      model: 'bgmock/m1',
      session: res1.session,
    });
    assert.equal(resForeign.status, 'failed');
    if (resForeign.status === 'failed') {
      assert.equal(
        resForeign.error.code,
        canUseLinuxBwrap() ? 'OPENCODE_SESSION_NOT_FOUND' : OPENCODE_RESUME_REQUIRES_PID_NAMESPACE,
      );
    }
    assert.equal(toolsRequests.length, countBeforeForeign);

    // (b) slow stream aborted after step_start / descendants observed
    mode = { kind: 'slow' };
    slowStreamStarted = false;
    const controller = new AbortController();
    let rootPid: number | undefined;
    let seenDescendants: ProcessIdentity[] = [];
    const slowPromise = adapter.execute(
      {
        taskId: 'l7-b-slow',
        prompt: 'Stream slowly',
        workingDirectory: workDir1,
        role: 'implementer',
        mode: 'write',
        model: 'bgmock/m1',
      },
      {
        signal: controller.signal,
        onProcessStarted: pid => {
          rootPid = pid;
        },
      },
    );

    const observeDeadline = Date.now() + 30_000;
    while (Date.now() < observeDeadline) {
      if (slowStreamStarted && rootPid !== undefined) {
        const list = await listProcessIdentities();
        seenDescendants = descendantIdentities(list, rootPid);
        if (seenDescendants.length > 0) break;
      }
      await delay(100);
    }
    await delay(200);
    controller.abort('cancelled');
    const slowRes = await slowPromise;
    assert.equal(slowRes.status, 'cancelled');
    assert.equal(slowRes.processCleanup?.verified, true);
    const slowRaw = slowRes.raw as { unknownEffects?: Array<{ tool: string; status: string }> } | undefined;
    assert.ok(
      slowRaw?.unknownEffects?.some(item => item.tool === 'unknown' && item.status === 'interrupted'),
      `Expected unknownEffects to contain interrupted marker, got ${JSON.stringify(slowRaw?.unknownEffects)}`,
    );
    const afterList = await listProcessIdentities();
    for (const desc of seenDescendants) {
      assert.equal(
        afterList.some(proc => proc.pid === desc.pid && proc.start === desc.start),
        false,
        `Expected descendant ${desc.pid} to be terminated`,
      );
    }

    // (c) provider HTTP errors
    const errorCases: Array<{
      status: number;
      body: Record<string, unknown>;
      expectedCode: string;
      maxRequests: number;
    }> = [
      {
        status: 401,
        body: { error: { message: 'Invalid API key provided', type: 'invalid_request_error' } },
        expectedCode: 'OPENCODE_AUTH_REQUIRED',
        maxRequests: 1,
      },
      {
        status: 429,
        body: { error: { message: 'You exceeded your current quota', type: 'insufficient_quota', code: 'insufficient_quota' } },
        expectedCode: 'OPENCODE_QUOTA_EXCEEDED',
        maxRequests: 1,
      },
      {
        status: 403,
        body: { error: { message: 'This OpenCode Go model is hosted outside Europe and the United States. Select Global at https://opencode.ai/console/org_TEST/settings/privacy#regions to use it.' } },
        expectedCode: 'OPENCODE_REGION_UNAVAILABLE',
        maxRequests: 1,
      },
      {
        status: 429,
        body: { error: { message: 'Rate limit reached', type: 'rate_limit_error' } },
        expectedCode: 'OPENCODE_RETRY_LIMIT',
        maxRequests: MAX_OPENCODE_PROVIDER_RETRIES + 2,
      },
    ];

    for (const item of errorCases) {
      const beforeCount = toolsRequests.length;
      mode = { kind: 'http-error', status: item.status, body: item.body };
      const errRes = await adapter.execute({
        taskId: `l7-c-${item.expectedCode}`,
        prompt: 'Trigger HTTP error',
        workingDirectory: workDir1,
        role: 'implementer',
        mode: 'read-only',
        model: 'bgmock/m1',
      });
      assert.equal(errRes.status, 'failed');
      if (errRes.status === 'failed') {
        assert.equal(errRes.error.code, item.expectedCode);
      }
      const delta = toolsRequests.length - beforeCount;
      assert.ok(delta >= 1 && delta <= item.maxRequests, `Expected 1..${item.maxRequests} requests for ${item.expectedCode}, got ${delta}`);
    }
  } finally {
    server.closeAllConnections?.();
    await new Promise<void>(resolve => server.close(() => resolve()));
    rmSync(tmpRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('L8) reconcileTrackedProcesses checks identity, expands reparented descendants, and fails on listing error', async () => {
  // (a) Root PID present with a different start (or undefined root start) is not treated as the root.
  {
    const kills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    const res = await reconcileTrackedProcesses(
      { pid: 900100, start: 'expected-start', processGroup: true },
      [],
      {
        graceMs: 0,
        list: async () => [
          { pid: 900100, parentPid: 1, start: 'foreign-start' },
          { pid: 900101, parentPid: 900100, start: 'foreign-child' },
        ],
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(res.verified, true);
    assert.deepEqual(res.remaining, []);
    assert.equal(kills.length, 0);

    const resNoStart = await reconcileTrackedProcesses(
      { pid: 900100, processGroup: true },
      [],
      {
        graceMs: 0,
        list: async () => [{ pid: 900100, parentPid: 1, start: 'foreign-start' }],
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(resNoStart.verified, true);
    assert.deepEqual(resNoStart.remaining, []);
    assert.equal(kills.length, 0);
  }

  // (b) Tracked identity whose pid now has a different start is not signalled.
  {
    const kills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    const res = await reconcileTrackedProcesses(
      { pid: 900200, start: 'root-start', processGroup: true },
      [{ pid: 900201, parentPid: 900200, start: 'tracked-start' }],
      {
        graceMs: 0,
        list: async () => [
          { pid: 900201, parentPid: 1, start: 'reused-start' },
          { pid: 900202, parentPid: 900201, start: 'reused-child' },
        ],
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(res.verified, true);
    assert.deepEqual(res.remaining, []);
    assert.equal(kills.length, 0);
  }

  // (c) New child of a tracked, reparented process (parentPid = tracked pid, root absent) is signalled and must disappear.
  {
    const trackedStart = makeStart(1);
    const childStart = makeStart(2);
    const grandchildStart = makeStart(3);
    const kills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    let poll = 0;
    const resGone = await reconcileTrackedProcesses(
      { pid: 900300, start: makeStart(0), processGroup: true },
      [{ pid: 900301, parentPid: 1, start: trackedStart }],
      {
        graceMs: 0,
        list: async () => {
          poll += 1;
          if (poll === 1) {
            return [
              { pid: 900301, parentPid: 1, start: trackedStart },
              { pid: 900302, parentPid: 900301, start: childStart },
            ];
          }
          return [];
        },
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(resGone.verified, true);
    assert.deepEqual(resGone.remaining, []);
    assert.deepEqual(kills, [
      { pid: 900301, signal: 'SIGKILL' },
      { pid: 900302, signal: 'SIGKILL' },
    ]);

    const persistKills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    let persistPoll = 0;
    const resRemaining = await reconcileTrackedProcesses(
      { pid: 900400, start: makeStart(0), processGroup: true },
      [{ pid: 900401, parentPid: 1, start: trackedStart }],
      {
        graceMs: 40,
        list: async () => {
          persistPoll += 1;
          if (persistPoll === 1) {
            return [
              { pid: 900401, parentPid: 1, start: trackedStart },
              { pid: 900402, parentPid: 900401, start: childStart },
            ];
          }
          return [
            { pid: 900402, parentPid: 1, start: childStart },
            { pid: 900403, parentPid: 900402, start: grandchildStart },
          ];
        },
        kill: (pid, signal) => persistKills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(resRemaining.verified, false);
    assert.equal(resRemaining.remaining.some(proc => proc.pid === 900402), true);
    assert.equal(resRemaining.remaining.some(proc => proc.pid === 900403), true);
    assert.equal(persistKills.some(call => call.pid === 900401 && call.signal === 'SIGKILL'), true);
    assert.equal(persistKills.some(call => call.pid === 900402 && call.signal === 'SIGKILL'), true);
    assert.equal(persistKills.some(call => call.pid === 900403 && call.signal === 'SIGKILL'), true);
  }

  // (d) Listing failure gives verified: false.
  {
    const kills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    const resInitialFail = await reconcileTrackedProcesses(
      { pid: 900500, start: makeStart(1), processGroup: true },
      [],
      {
        graceMs: 0,
        list: async () => {
          throw new Error('listing failed');
        },
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(resInitialFail.verified, false);
    assert.equal(kills.length, 0);

    let poll = 0;
    const resVerifyFail = await reconcileTrackedProcesses(
      { pid: 900501, start: makeStart(1), processGroup: true },
      [],
      {
        graceMs: 0,
        list: async () => {
          poll += 1;
          if (poll === 1) return [{ pid: 900501, parentPid: 1, start: makeStart(1) }];
          throw new Error('verify listing failed');
        },
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(resVerifyFail.verified, false);
    assert.equal(resVerifyFail.remaining.length, 1);
  }

  // (e) Edge ordering: child whose start order is lower than parent's (or non-finite) is not adopted.
  {
    const parentStart = makeStart(100);
    const edgeList: ProcessIdentity[] = [
      { pid: 900600, parentPid: 1, start: parentStart },
      { pid: 900601, parentPid: 900600, start: makeStart(50) },
      { pid: 900602, parentPid: 900600, start: 'not-a-valid-start' },
      { pid: 900603, parentPid: 900600, start: parentStart },
    ];
    assert.deepEqual(
      descendantIdentities(edgeList, 900600),
      [{ pid: 900603, parentPid: 900600, start: parentStart }],
    );

    const kills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    let poll = 0;
    const res = await reconcileTrackedProcesses(
      { pid: 900600, start: parentStart, processGroup: true },
      [],
      {
        graceMs: 0,
        list: async () => {
          poll += 1;
          return poll === 1 ? edgeList : [];
        },
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: () => true,
      },
    );
    assert.equal(res.verified, true);
    assert.deepEqual(kills, [
      { pid: 900600, signal: 'SIGKILL' },
      { pid: 900603, signal: 'SIGKILL' },
    ]);
  }

  // (f) verifyIdentity returning false prevents signalling and does not record the identity as killed.
  {
    const parentStart = makeStart(10);
    const childStart = makeStart(11);
    const kills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    let poll = 0;
    const resFiltered = await reconcileTrackedProcesses(
      { pid: 900700, start: parentStart, processGroup: true },
      [{ pid: 900701, parentPid: 1, start: parentStart }],
      {
        graceMs: 0,
        list: async () => {
          poll += 1;
          if (poll === 1) {
            return [
              { pid: 900701, parentPid: 1, start: parentStart },
              { pid: 900702, parentPid: 900701, start: childStart },
            ];
          }
          return [];
        },
        kill: (pid, signal) => kills.push({ pid, signal }),
        verifyIdentity: identity => identity.pid !== 900702,
      },
    );
    assert.equal(resFiltered.verified, true);
    assert.deepEqual(kills, [{ pid: 900701, signal: 'SIGKILL' }]);

    const unverifiedKills: Array<{ pid: number; signal: NodeJS.Signals }> = [];
    const resRejected = await reconcileTrackedProcesses(
      { pid: 900703, start: parentStart, processGroup: true },
      [],
      {
        graceMs: 0,
        list: async () => [{ pid: 900703, parentPid: 1, start: parentStart }],
        kill: (pid, signal) => unverifiedKills.push({ pid, signal }),
        verifyIdentity: () => false,
      },
    );
    assert.equal(resRejected.verified, false);
    assert.equal(unverifiedKills.length, 0);
  }
});

test('L9) containment stops and reconciles when onProcessStarted throws and confirms cleanup by the spontaneous end of bwrap when namespace capture fails', async t => {
  if (!canUseLinuxBwrap()) {
    t.skip('Linux bubblewrap PID namespace unavailable');
    return;
  }

  const ws = createWorkspace(t);
  const rec = path.join(ws.root, 'hook-throw.json');
  const grandchildFile = `${rec}.grandchild-pid`;
  const hookError = new Error('onProcessStarted boom');
  let startedPid: number | undefined;
  let observedCleanup: TaskRecord['processCleanup'] | undefined;

  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'hang'],
    containment: 'auto',
  });

  await assert.rejects(
    () => adapter.execute(
      {
        taskId: 'l9-hook-throw',
        prompt: 'Hang while hook throws',
        workingDirectory: ws.repoDir,
        role: 'implementer',
        mode: 'write',
      },
      {
        onProcessStarted: pid => {
          startedPid = pid;
          throw hookError;
        },
        onProcessCleanup: cleanup => {
          observedCleanup = cleanup;
        },
      },
    ),
    err => err === hookError,
  );

  assert.ok(startedPid !== undefined);
  assertProcessGone(startedPid);
  assert.equal(descendantIdentities(await listProcessIdentities(), startedPid).length, 0);
  assert.equal(observedCleanup?.verified, true);
  assert.equal(existsSync(grandchildFile), false);
  assert.ok(countPidNamespaceMembers(readlinkSync('/proc/self/ns/pid')) >= 1);

  const fixture = createReadFixture(ws.repoDir);
  for (const [label, failingList] of [
    ['throw', async (): Promise<ProcessIdentity[]> => { throw new Error('namespace capture failed'); }],
    ['empty', async (): Promise<ProcessIdentity[]> => []],
  ] as const) {
    const failCaptureAdapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
      containment: 'auto',
      listProcesses: failingList,
    });
    const res = await failCaptureAdapter.execute({
      taskId: `l9-capture-${label}`,
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
    });
    assert.equal(res.status, 'completed');
    const raw = res.raw as { containment?: string } | undefined;
    assert.equal(raw?.containment, 'pid-namespace');
    assert.equal(res.processCleanup?.verified, true);
  }
});

test('L10) classified error events stop immediately and count observed retries independently', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const defaultAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'auth-then-retries'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, defaultAdapter));
  const queued = await tasks.run({
    prompt: 'Trigger auth-then-retries',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'failed');
  assert.equal(record.error?.code, 'OPENCODE_AUTH_REQUIRED');
  assert.equal(record.processCleanup?.verified, true);
  if (process.platform !== 'win32' && record.pid !== undefined) {
    assertProcessGone(record.pid);
  }
  const defaultRaw = record.result as { providerRetries?: number } | undefined;
  assert.ok(defaultRaw?.providerRetries === undefined || defaultRaw.providerRetries >= 1);
  await tasks.shutdown();

  // Delayed stop listing on fallback path ensures retries arriving after a classified error are still counted.
  let listCalls = 0;
  const delayedAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'auth-then-retries'],
    containment: 'none',
    listProcesses: async () => {
      listCalls += 1;
      if (listCalls === 2) {
        await delay(180);
      }
      return await listProcessIdentities();
    },
  });
  const delayedTasks = ws.track(new TaskManager(cli, ws.config, delayedAdapter));
  const delayedQueued = await delayedTasks.run({
    prompt: 'Trigger auth-then-retries with observed retries',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const delayedRecord = await waitForTask(delayedTasks, delayedQueued.taskId);

  assert.equal(delayedRecord.status, 'failed');
  assert.equal(delayedRecord.error?.code, 'OPENCODE_AUTH_REQUIRED');
  assert.equal(delayedRecord.processCleanup?.verified, true);
  if (process.platform !== 'win32' && delayedRecord.pid !== undefined) {
    assertProcessGone(delayedRecord.pid);
  }
  const delayedRaw = delayedRecord.result as { providerRetries?: number } | undefined;
  assert.ok((delayedRaw?.providerRetries ?? 0) >= 1);
});

test('L11) preview refuses earlier OpenCode task when a later task on the same copy has unverified cleanup', async t => {
  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const okAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
  });
  const tasks1 = ws.track(new TaskManager(cli, ws.config, okAdapter));
  const firstQueued = await tasks1.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks1, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, true);
  assert.ok(first.sessionId && first.copyDirectory);
  await tasks1.shutdown();

  const tasks2 = ws.track(new TaskManager(cli, ws.config, createUnverifiedResumeAdapter(first.sessionId, 940_001)));
  const secondQueued = await tasks2.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );
  const second = await waitForTask(tasks2, secondQueued.taskId);
  assert.equal(second.status, 'completed');
  assert.equal(second.processCleanup?.verified, false);
  assert.equal(second.copyDirectory, first.copyDirectory);

  await assert.rejects(
    () => tasks2.preview(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks2.preview(second.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
});

test('L12) OpenCode adapter refuses bwrapPath inside the working directory before spawning', async t => {
  if (process.platform !== 'linux') {
    t.skip('Linux bubblewrap containment test');
    return;
  }
  const ws = createWorkspace(t);
  const marker = path.join(ws.root, 'bwrap-ran.marker');
  const evilBwrap = path.join(ws.repoDir, 'bwrap');
  writeFileSync(evilBwrap, `#!/bin/sh\necho ran > ${JSON.stringify(marker)}\nexit 1\n`, 'utf8');
  chmodSync(evilBwrap, 0o755);

  const symlinkBwrap = path.join(ws.root, 'bwrap-link');
  symlinkSync(evilBwrap, symlinkBwrap);

  for (const candidate of [evilBwrap, symlinkBwrap]) {
    const adapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
      bwrapPath: candidate,
    });
    await assert.rejects(
      () => adapter.execute({
        taskId: 'l12-bwrap-in-workdir',
        prompt: 'hello',
        workingDirectory: ws.repoDir,
        role: 'implementer',
        mode: 'read-only',
      }),
      err => err instanceof BridgeError && err.code === 'OPENCODE_UNAVAILABLE' && err.message.includes('Bubblewrap path must be outside the task working directory'),
    );
    assert.equal(existsSync(marker), false);
  }
});

test('L13) retention eviction and cleanup never drop a task or copy with unverified cleanup', async t => {
  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const okAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
  });
  const tasks1 = ws.track(new TaskManager(cli, ws.config, okAdapter));
  const firstQueued = await tasks1.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks1, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, true);
  assert.ok(first.sessionId && first.copyDirectory);
  await tasks1.shutdown();

  const tasks2 = ws.track(new TaskManager(cli, ws.config, createUnverifiedResumeAdapter(first.sessionId, 940_002)));
  const secondQueued = await tasks2.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );
  const second = await waitForTask(tasks2, secondQueued.taskId);
  assert.equal(second.status, 'completed');
  assert.equal(second.processCleanup?.verified, false);
  assert.equal(second.copyDirectory, first.copyDirectory);
  await tasks2.shutdown();

  const retainedCount = tasks2.list().length;
  assert.equal(retainedCount, 2);
  const limitedConfig = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
    MAX_RETAINED_TASKS: String(retainedCount),
  });
  const tasks3 = ws.track(new TaskManager(cli, limitedConfig, okAdapter));
  await assert.rejects(
    () => tasks3.context(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks3.run({
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
      contextTaskId: first.taskId,
      expectedContextSha256: '0'.repeat(64),
    }),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );

  const retainedSecond = tasks3.status(second.taskId);
  assert.equal(retainedSecond.processCleanup?.verified, false);
  await assert.rejects(
    () => tasks3.preview(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );

  const farFuture = Date.now() + 365 * 24 * 3600_000;
  const cleaned = await tasks3.cleanup(farFuture);
  assert.equal(cleaned.discardedTaskIds.includes(first.taskId), false);
  assert.equal(cleaned.discardedTaskIds.includes(second.taskId), false);
  assert.equal(tasks3.status(first.taskId).copyDirectory, first.copyDirectory);
  assert.equal(tasks3.status(second.taskId).copyDirectory, second.copyDirectory);
  assert.equal(existsSync(first.copyDirectory), true);
});

test('L14) preview skips process reconciliation for agy-only copies even with unverified cleanup', async t => {
  const ws = createWorkspace(t);
  const cli = new CliAdapter(ws.config, [MOCK_AGY]);
  const discovery = await cli.discover();
  assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

  const tasks1 = ws.track(new TaskManager(cli, ws.config));
  const queued = await tasks1.run({
    prompt: 'write:l14',
    workingDirectory: ws.repoDir,
    mode: 'write',
  });
  const completed = await waitForTask(tasks1, queued.taskId);
  assert.equal(completed.status, 'completed');
  assert.equal(completed.execution?.provider, 'agy');
  await tasks1.shutdown();

  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
    detached: true,
    stdio: 'ignore',
  });
  sleeper.unref();
  const sleeperPid = sleeper.pid;
  assert.ok(sleeperPid && sleeperPid > 0);
  t.after(() => {
    if (process.platform === 'win32') {
      try { sleeper.kill('SIGKILL'); } catch { /* already exited */ }
    } else {
      try { process.kill(-sleeperPid, 'SIGKILL'); } catch { /* already exited */ }
    }
  });

  const snapshotPath = path.join(ws.stateDir, `${completed.taskId}.json`);
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
    record: TaskRecord;
  };
  const nowIso = new Date().toISOString();
  snapshot.record.pid = sleeperPid;
  snapshot.record.processCleanup = {
    verified: false,
    spawnedAt: nowIso,
    checkedAt: nowIso,
    remaining: 1,
  };
  writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');

  const tasks2 = ws.track(new TaskManager(cli, ws.config));
  const preview = await tasks2.preview(completed.taskId);
  assert.ok(preview.sha256);
  assert.equal(tasks2.status(completed.taskId).processCleanup?.verified, false);
  assert.doesNotThrow(() => process.kill(process.platform === 'win32' ? sleeperPid : -sleeperPid, 0));
});

test('L15) repairs and later launches cannot confirm over an earlier unverified launch', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const capabilities = {
    read: 'supported',
    write: 'supported',
    sandbox: 'unknown',
    network: 'unsupported',
    skills: 'unsupported',
    resources: 'unknown',
    structuredOutput: 'supported',
    cancel: 'supported',
    resume: 'supported',
    observableUsage: 'unknown',
  } as const;

  let calls = 0;
  const resumeAdapter: ExecutionAdapter = {
    identity: { id: 'fake-opencode', provider: 'opencode', version: '3' },
    capabilities,
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      calls += 1;
      const spawnedAt = new Date().toISOString();
      context?.onProcessStarted?.(900_000 + calls);
      if (calls === 1) {
        context?.onProcessCleanup?.({
          verified: false,
          spawnedAt,
          checkedAt: new Date().toISOString(),
          remaining: 1,
        });
      } else {
        context?.onProcessCleanup?.({
          verified: true,
          spawnedAt,
          checkedAt: new Date().toISOString(),
          remaining: 0,
        });
      }
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: 'ses_l15_a' },
        response: `done-${calls}`,
      };
    },
  };

  const tasks = ws.track(new TaskManager(cli, ws.config, resumeAdapter));
  const queued = await tasks.run({
    prompt: 'First unverified write run',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks, queued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, false);

  const stored = new StateStore(ws.stateDir).load().find(item => item.record.taskId === first.taskId);
  assert.ok(stored?.project?.gitDirectory);
  const markerFile = path.join(stored.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  assert.equal(existsSync(markerFile), true);

  await assert.rejects(
    () => tasks.preview(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks.integrate(first.taskId, '0'.repeat(64), async () => true),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks.resume({ workingDirectory: ws.repoDir, prompt: 'continue' }, first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(calls, 1);
  await tasks.shutdown();

  const multiLaunchAdapter: ExecutionAdapter = {
    identity: { id: 'fake-opencode', provider: 'opencode', version: '3' },
    capabilities,
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      const t1 = new Date().toISOString();
      context?.onProcessStarted?.(910_001);
      context?.onProcessCleanup?.({
        verified: false,
        spawnedAt: t1,
        checkedAt: new Date().toISOString(),
        remaining: 1,
      });
      const t2 = new Date().toISOString();
      context?.onProcessStarted?.(910_002);
      context?.onProcessCleanup?.({
        verified: true,
        spawnedAt: t2,
        checkedAt: new Date().toISOString(),
        remaining: 0,
      });
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: 'ses_l15_b' },
        response: 'done-multi',
      };
    },
  };

  const ws2 = createWorkspace(t);
  const cli2 = new OpenCodeTestCliAdapter(ws2.config);
  const tasks2 = ws2.track(new TaskManager(cli2, ws2.config, multiLaunchAdapter));
  const multiQueued = await tasks2.run({
    prompt: 'Two launches in one execution',
    workingDirectory: ws2.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const second = await waitForTask(tasks2, multiQueued.taskId);
  assert.equal(second.status, 'completed');
  assert.equal(second.processCleanup?.verified, true);

  const storedSecond = new StateStore(ws2.stateDir).load().find(item => item.record.taskId === second.taskId);
  assert.ok(storedSecond?.project?.gitDirectory);
  const secondMarkerFile = path.join(storedSecond.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  assert.equal(existsSync(secondMarkerFile), true);
  assert.equal(existsSync(markerFile), true);

  await assert.rejects(
    () => tasks2.preview(second.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks2.integrate(second.taskId, '0'.repeat(64), async () => true),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
});

test('L16) native local test loop stops after unverified repair without rerunning tests or starting repair 2', async t => {
  if (!canUseLinuxBwrap()) {
    t.skip('Linux bubblewrap unavailable');
    return;
  }

  const ws = createWorkspace(t);
  const bwrapConfig = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'linux-bwrap',
    AGY_PATH: process.execPath,
  });
  const cli = new OpenCodeTestCliAdapter(bwrapConfig);

  let execCalls = 0;
  const adapter: ExecutionAdapter = {
    identity: { id: 'fake-opencode', provider: 'opencode', version: '3' },
    capabilities: {
      read: 'supported',
      write: 'supported',
      sandbox: 'unknown',
      network: 'unsupported',
      skills: 'unsupported',
      resources: 'unknown',
      structuredOutput: 'supported',
      cancel: 'supported',
      resume: 'supported',
      observableUsage: 'unknown',
    },
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      execCalls += 1;
      const spawnedAt = new Date().toISOString();
      context?.onProcessStarted?.(920_000 + execCalls);
      context?.onProcessCleanup?.({
        verified: execCalls !== 2,
        spawnedAt,
        checkedAt: new Date().toISOString(),
        remaining: execCalls === 2 ? 1 : 0,
      });
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: 'ses_l16' },
        response: `exec-${execCalls}`,
      };
    },
  };

  const tasks = ws.track(new TaskManager(cli, bwrapConfig, adapter));
  const initialQueued = await tasks.run({
    prompt: 'Initial write for local test loop',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const initial = await waitForTask(tasks, initialQueued.taskId);
  assert.equal(initial.status, 'completed', JSON.stringify(initial.error));
  const preview = await tasks.preview(initial.taskId, false);

  const testQueued = await tasks.startTests(
    initial.taskId,
    preview.sha256,
    { executable: process.execPath, args: ['-e', 'process.exit(1)'] },
    2,
    30,
  );
  const testDone = await waitForTask(tasks, testQueued.taskId);

  assert.equal(testDone.status, 'failed');
  assert.equal(testDone.error?.code, 'PROCESS_CLEANUP_UNVERIFIED');
  assert.equal(execCalls, 2);
  assert.equal(testDone.tests?.length, 1);
});

test('L17) QUEUE_FULL caused by unconfirmed cleanup names the task and says discard frees the slot', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  let calls = 0;
  const adapter: ExecutionAdapter = {
    identity: { id: 'fake-opencode', provider: 'opencode', version: '3' },
    capabilities: {
      read: 'supported',
      write: 'supported',
      sandbox: 'unknown',
      network: 'unsupported',
      skills: 'unsupported',
      resources: 'unknown',
      structuredOutput: 'supported',
      cancel: 'supported',
      resume: 'supported',
      observableUsage: 'unknown',
    },
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      calls += 1;
      const spawnedAt = new Date().toISOString();
      context?.onProcessStarted?.(930_000 + calls);
      context?.onProcessCleanup?.({
        verified: calls !== 1,
        spawnedAt,
        checkedAt: new Date().toISOString(),
        remaining: calls === 1 ? 1 : 0,
      });
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: `ses_l17_${calls}` },
        response: `run-${calls}`,
      };
    },
  };

  const tasks1 = ws.track(new TaskManager(cli, ws.config, adapter));
  const firstQueued = await tasks1.run({
    prompt: 'First run with unverified cleanup',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks1, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, false);
  await tasks1.shutdown();

  const limitedConfig = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
    MAX_RETAINED_TASKS: '1',
  });
  const tasks2 = ws.track(new TaskManager(cli, limitedConfig, adapter));
  assert.equal(tasks2.list().length, 1);

  await assert.rejects(
    () => tasks2.run({
      prompt: 'Blocked by unverified retention',
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
    }),
    err => err instanceof BridgeError
      && err.code === 'QUEUE_FULL'
      && err.message.includes(first.taskId)
      && err.message.includes('discard'),
  );

  const storedFirst = new StateStore(ws.stateDir).load().find(item => item.record.taskId === first.taskId);
  assert.ok(storedFirst?.project?.gitDirectory);
  const markerFile = path.join(storedFirst.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  const markerBefore = readFileSync(markerFile, 'utf8');
  const snapshotBefore = readFileSync(path.join(ws.stateDir, `${first.taskId}.json`), 'utf8');

  await assert.rejects(
    () => tasks2.discard(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(readFileSync(markerFile, 'utf8'), markerBefore);
  assert.equal(readFileSync(path.join(ws.stateDir, `${first.taskId}.json`), 'utf8'), snapshotBefore);
  assert.equal(tasks2.status(first.taskId).discardedAt, undefined);
  assert.equal(existsSync(first.copyDirectory!), true);
});

test('L18) cancel during resume session list stops the tracked tree and records cleanup', async t => {
  if (!canUseLinuxBwrap()) {
    t.skip('Linux bubblewrap PID namespace unavailable');
    return;
  }

  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const sessionsFile = path.join(ws.root, 'l18-sessions-auto.json');
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const okAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--sessions', sessionsFile, '--scenario', 'read'],
    containment: 'auto',
  });
  const tasks1 = ws.track(new TaskManager(cli, ws.config, okAdapter));
  const firstQueued = await tasks1.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks1, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.ok(first.sessionId && first.copyDirectory);
  await tasks1.shutdown();

  writeFileSync(
    sessionsFile,
    JSON.stringify([{ id: first.sessionId, directory: realpathSync(first.copyDirectory) }]),
    'utf8',
  );

  const rec = path.join(ws.root, 'l18-resume-auto.json');
  const sessionListPidFile = `${rec}.session-list-pid`;
  const sessionListGrandchildFile = `${rec}.session-list-grandchild-pid`;
  const hangAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--sessions', sessionsFile, '--session-list-hang', '--scenario', 'read'],
    containment: 'auto',
  });
  const tasks2 = ws.track(new TaskManager(cli, ws.config, hangAdapter));
  const resumedQueued = await tasks2.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );

  const grandchildInnerPid = await waitForFilePid(sessionListGrandchildFile);
  const sessionListInnerPid = await waitForFilePid(sessionListPidFile);
  while (tasks2.status(resumedQueued.taskId).pid === undefined) {
    await delay(25);
  }
  const runningPid = tasks2.status(resumedQueued.taskId).pid!;
  const sessionListHostPid = await resolveHostPidInNamespace(runningPid, sessionListInnerPid);
  const grandchildHostPid = await resolveHostPidInNamespace(runningPid, grandchildInnerPid);

  await tasks2.cancel(resumedQueued.taskId);
  const resumed = await waitForTask(tasks2, resumedQueued.taskId);

  assert.equal(resumed.status, 'cancelled');
  assert.equal(resumed.error?.code, 'TASK_CANCELLED');
  assert.ok(resumed.processCleanup);
  assert.equal(resumed.processCleanup.verified, true);
  assert.equal(resumed.processCleanup.remaining, 0);
  const events = tasks2.readEvents(resumed.taskId, 0, 1000).events;
  assert.equal(events.some(event => event.type === 'process.started'), true);
  assert.ok(resumed.pid);
  assertProcessGone(resumed.pid);
  assertProcessGone(sessionListHostPid);
  assertProcessGone(grandchildHostPid);

  const preview = await tasks2.preview(resumed.taskId);
  assert.ok(preview.sha256);
});

test('L19) cancelled resume session list with failing process listing stays unverified and blocks reuse', async t => {
  if (!canUseLinuxBwrap()) {
    t.skip('Linux bubblewrap PID namespace unavailable');
    return;
  }

  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const sessionsFile = path.join(ws.root, 'l19-sessions.json');
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const okAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--sessions', sessionsFile, '--scenario', 'read'],
    containment: 'auto',
  });
  const tasks1 = ws.track(new TaskManager(cli, ws.config, okAdapter));
  const firstQueued = await tasks1.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks1, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, true);
  assert.ok(first.sessionId && first.copyDirectory);
  await tasks1.shutdown();

  writeFileSync(
    sessionsFile,
    JSON.stringify([{ id: first.sessionId, directory: realpathSync(first.copyDirectory) }]),
    'utf8',
  );

  const rec = path.join(ws.root, 'l19-resume.json');
  const sessionListPidFile = `${rec}.session-list-pid`;
  const sessionListGrandchildFile = `${rec}.session-list-grandchild-pid`;
  const mockPids = new Set<number>();
  t.after(() => {
    for (const pid of mockPids) {
      try { process.kill(pid, 'SIGKILL'); } catch { /* already exited */ }
    }
  });

  const failingAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--sessions', sessionsFile, '--session-list-hang', '--scenario', 'read'],
    containment: 'auto',
    listProcesses: async () => {
      throw new Error('process listing failed');
    },
  });
  const tasks2 = ws.track(new TaskManager(cli, ws.config, failingAdapter));
  const resumedQueued = await tasks2.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );

  const grandchildInnerPid = await waitForFilePid(sessionListGrandchildFile);
  const sessionListInnerPid = await waitForFilePid(sessionListPidFile);
  while (tasks2.status(resumedQueued.taskId).pid === undefined) {
    await delay(25);
  }
  const runningPid = tasks2.status(resumedQueued.taskId).pid!;
  const sessionListHostPid = await resolveHostPidInNamespace(runningPid, sessionListInnerPid);
  mockPids.add(sessionListHostPid);
  const grandchildHostPid = await resolveHostPidInNamespace(runningPid, grandchildInnerPid);
  mockPids.add(grandchildHostPid);

  await tasks2.cancel(resumedQueued.taskId);
  const resumed = await waitForTask(tasks2, resumedQueued.taskId);

  assert.equal(resumed.status, 'cancelled');
  assert.equal(resumed.error?.code, 'TASK_CANCELLED');
  assert.equal(resumed.processCleanup?.verified, false);

  await assert.rejects(
    () => tasks2.preview(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks2.preview(resumed.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
});

test('L20) resume inside the PID namespace validates the session directory, detects mismatch and reports per-run usage', async t => {
  if (!canUseLinuxBwrap()) {
    t.skip('Linux bubblewrap PID namespace unavailable');
    return;
  }

  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const rec = path.join(ws.root, 'resume-rec.json');
  const spawnLog = path.join(ws.root, 'resume-spawn.jsonl');
  const sessionsFile = path.join(ws.root, 'sessions.json');
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--spawn-log', spawnLog, '--sessions', sessionsFile, '--scenario', 'read'],
    containment: 'auto',
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));
  const runCompletedReadTask = async (manager: TaskManager) => {
    const queued = await manager.run({
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
    });
    const record = await waitForTask(manager, queued.taskId);
    assert.equal(record.status, 'completed');
    assert.ok(record.sessionId);
    assert.ok(record.copyDirectory);
    return { ...record, sessionId: record.sessionId, copyDirectory: record.copyDirectory };
  };

  const first = await runCompletedReadTask(tasks);
  const sessionId = first.sessionId;

  writeFileSync(
    sessionsFile,
    JSON.stringify([{ id: sessionId, directory: realpathSync(first.copyDirectory) }]),
    'utf8',
  );

  const resumedQueued = await tasks.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );
  const resumed = await waitForTask(tasks, resumedQueued.taskId);
  assert.equal(resumed.status, 'completed');
  assert.equal(resumed.sessionId, sessionId);
  assert.equal(resumed.processCleanup?.verified, true);
  const resumedPreview = await tasks.preview(resumed.taskId);
  assert.ok(resumedPreview.sha256);
  const recorded = JSON.parse(readFileSync(rec, 'utf8')) as { argv: string[] };
  const sessionFlagIdx = recorded.argv.indexOf('--session');
  assert.ok(sessionFlagIdx !== -1 && recorded.argv[sessionFlagIdx + 1] === sessionId);

  const usage = taskTokenUsage(resumed);
  assert.notEqual(usage.source, 'session-delta');
  assert.equal(usage.counters.inputTokens, 11);
  assert.equal(usage.counters.outputTokens, 7);
  assert.equal(usage.counters.thinkingTokens, 2);
  assert.equal(usage.counters.cacheReadTokens, 3);
  assert.equal(usage.counters.totalTokens, 20);

  // foreign directory
  const otherDir = mkdtempSync(path.join(ws.root, 'other-dir-'));
  writeFileSync(sessionsFile, JSON.stringify([{ id: sessionId, directory: otherDir }]), 'utf8');
  const foreignQueued = await tasks.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    resumed.taskId,
  );
  const foreign = await waitForTask(tasks, foreignQueued.taskId);
  assert.equal(foreign.status, 'failed');
  assert.equal(foreign.error?.code, 'OPENCODE_SESSION_NOT_FOUND');
  assert.equal(readSpawnLog(spawnLog).filter(entry => entry.argv[0] === 'run').length, 2);
  const spawnCountAfterForeign = readSpawnLog(spawnLog).length;
  await assert.rejects(
    () => tasks.resume({ workingDirectory: ws.repoDir, prompt: fixture.prompt }, resumed.taskId),
    err => err instanceof BridgeError && err.code === 'INVALID_SESSION',
  );
  assert.equal(readSpawnLog(spawnLog).length, spawnCountAfterForeign);

  // empty sessions list
  const emptyBase = await runCompletedReadTask(tasks);
  writeFileSync(sessionsFile, '[]', 'utf8');
  const emptyQueued = await tasks.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    emptyBase.taskId,
  );
  const empty = await waitForTask(tasks, emptyQueued.taskId);
  assert.equal(empty.status, 'failed');
  assert.equal(empty.error?.code, 'OPENCODE_SESSION_NOT_FOUND');
  assert.equal(readSpawnLog(spawnLog).filter(entry => entry.argv[0] === 'run').length, 3);

  // session mismatch
  const mismatchBase = await runCompletedReadTask(tasks);
  await tasks.shutdown();
  writeFileSync(
    sessionsFile,
    JSON.stringify([{ id: mismatchBase.sessionId, directory: realpathSync(mismatchBase.copyDirectory) }]),
    'utf8',
  );
  const mismatchAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--sessions', sessionsFile, '--scenario', 'resume-mismatch'],
    containment: 'auto',
  });
  const mismatchTasks = ws.track(new TaskManager(cli, ws.config, mismatchAdapter));
  const mismatchQueued = await mismatchTasks.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    mismatchBase.taskId,
  );
  const mismatch = await waitForTask(mismatchTasks, mismatchQueued.taskId);
  assert.equal(mismatch.status, 'failed');
  assert.equal(mismatch.error?.code, 'OPENCODE_SESSION_MISMATCH');
});

test('L21) readPatch, verify and recordTest refuse a copy with unconfirmed cleanup', async t => {
  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const okAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
  });
  const tasks1 = ws.track(new TaskManager(cli, ws.config, okAdapter));
  const firstQueued = await tasks1.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const first = await waitForTask(tasks1, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, true);
  assert.ok(first.sessionId && first.copyDirectory);
  const { sha256: sha } = await tasks1.preview(first.taskId);
  await tasks1.shutdown();

  const tasks2 = ws.track(new TaskManager(cli, ws.config, createUnverifiedResumeAdapter(first.sessionId, 940_021)));
  const secondQueued = await tasks2.resume(
    { workingDirectory: ws.repoDir, prompt: fixture.prompt },
    first.taskId,
  );
  const second = await waitForTask(tasks2, secondQueued.taskId);
  assert.equal(second.status, 'completed');
  assert.equal(second.processCleanup?.verified, false);
  assert.equal(second.copyDirectory, first.copyDirectory);

  await assert.rejects(
    () => tasks2.readPatch(first.taskId, sha),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks2.verify(first.taskId, sha, []),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => tasks2.recordTest(first.taskId, sha, 'npm test', 0, 'ok'),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
});

test('L22) a marker written by another bridge instance under the copy lock blocks preview, integrate and readPatch', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const writeAdapter: ExecutionAdapter = {
    identity: { id: 'fake-opencode', provider: 'opencode', version: OPENCODE_ADAPTER_VERSION },
    capabilities: {
      read: 'supported',
      write: 'supported',
      sandbox: 'unknown',
      network: 'unsupported',
      skills: 'unsupported',
      resources: 'unknown',
      structuredOutput: 'supported',
      cancel: 'supported',
      resume: 'supported',
      observableUsage: 'unknown',
    },
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      const spawnedAt = new Date().toISOString();
      context?.onProcessStarted?.(940_020);
      writeFileSync(path.join(request.workingDirectory, 'README.md'), 'updated-by-l22\n', 'utf8');
      context?.onProcessCleanup?.({
        verified: true,
        spawnedAt,
        checkedAt: new Date().toISOString(),
        remaining: 0,
      });
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: 'ses_l22' },
        response: 'updated README.md',
      };
    },
  };

  const A = ws.track(new TaskManager(cli, ws.config, writeAdapter));
  const firstQueued = await A.run({
    prompt: 'Update README.md',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
    acceptanceCriteria: [
      {
        id: 'ac1',
        description: 'README.md contains updated-by-l22',
        check: { kind: 'file-contains', path: 'README.md', text: 'updated-by-l22' },
      },
    ],
  });
  const first = await waitForTask(A, firstQueued.taskId);
  assert.equal(first.status, 'completed');
  assert.equal(first.processCleanup?.verified, true);
  assert.ok(first.sessionId && first.copyDirectory);

  const { sha256: sha } = await A.preview(first.taskId);
  const verification = await A.verify(first.taskId, sha, [
    {
      criterionId: 'ac1',
      verdict: 'passed',
      path: 'README.md',
      line: 1,
      quote: 'updated-by-l22',
      explanation: 'Verified updated README content',
    },
  ]);
  assert.equal(verification.status, 'passed');

  const B = ws.track(new TaskManager(cli, ws.config, createUnverifiedResumeAdapter(first.sessionId, 940_022)));
  let bDone = false;
  let secondTaskId: string | undefined;
  const aInternal = A as unknown as {
    withProject: (project: unknown, operation: () => Promise<unknown>, options?: unknown) => Promise<unknown>;
  };
  const original = aInternal.withProject.bind(A);
  aInternal.withProject = async (project: unknown, operation: () => Promise<unknown>, options?: unknown) => {
    if (!bDone) {
      bDone = true;
      const secondQueued = await B.resume(
        { workingDirectory: ws.repoDir, prompt: 'Resume with unverified cleanup' },
        first.taskId,
      );
      const second = await waitForTask(B, secondQueued.taskId);
      secondTaskId = second.taskId;
      assert.equal(second.status, 'completed');
      assert.equal(second.processCleanup?.verified, false);
    }
    return original(project, operation, options);
  };

  await assert.rejects(
    () => A.integrate(first.taskId, sha, async () => true),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(bDone, true);
  assert.ok(secondTaskId);
  assert.equal(readFileSync(path.join(ws.repoDir, 'README.md'), 'utf8'), 'hello\n');

  await assert.rejects(
    () => A.preview(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  await assert.rejects(
    () => A.readPatch(first.taskId, sha),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );

  const storedFirst = new StateStore(ws.stateDir).load().find(item => item.record.taskId === first.taskId);
  assert.ok(storedFirst?.project?.gitDirectory);
  const markerFile = path.join(storedFirst.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  const markerBefore = readFileSync(markerFile, 'utf8');
  const firstSnapshotBefore = readFileSync(path.join(ws.stateDir, `${first.taskId}.json`), 'utf8');
  const secondSnapshotBefore = readFileSync(path.join(ws.stateDir, `${secondTaskId}.json`), 'utf8');
  const copyBytesBefore = readFileSync(path.join(first.copyDirectory, 'README.md'), 'utf8');

  await assert.rejects(
    () => A.discard(first.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(readFileSync(markerFile, 'utf8'), markerBefore);
  assert.equal(readFileSync(path.join(ws.stateDir, `${first.taskId}.json`), 'utf8'), firstSnapshotBefore);
  assert.equal(readFileSync(path.join(ws.stateDir, `${secondTaskId}.json`), 'utf8'), secondSnapshotBefore);
  assert.equal(readFileSync(path.join(first.copyDirectory, 'README.md'), 'utf8'), copyBytesBefore);
  assert.equal(A.status(first.taskId).discardedAt, undefined);
  assert.equal(A.status(secondTaskId).discardedAt, undefined);
});

test('L23) a confirmed agy reconciliation marks the record verified and frees the retention slot', async t => {
  const ws = createWorkspace(t);
  const cli = new CliAdapter(ws.config, [MOCK_AGY]);
  const discovery = await cli.discover();
  assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

  const tasks1 = ws.track(new TaskManager(cli, ws.config));
  const queued = await tasks1.run({ prompt: 'write:l23', workingDirectory: ws.repoDir, mode: 'write' });
  const completed = await waitForTask(tasks1, queued.taskId);
  assert.equal(completed.status, 'completed');
  assert.equal(completed.execution?.provider, 'agy');
  await tasks1.shutdown();

  // A launch whose process already ended: reconciliation can confirm it.
  const ended = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  assert.ok(ended.pid && ended.pid > 0);
  const snapshotPath = path.join(ws.stateDir, `${completed.taskId}.json`);
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as { record: TaskRecord; project: { gitDirectory: string } };
  const spawnedAt = new Date(Date.now() - 1_000).toISOString();
  snapshot.record.pid = ended.pid;
  snapshot.record.processCleanup = { verified: false, spawnedAt, checkedAt: spawnedAt, remaining: 1 };
  writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');
  upsertProcessCleanupMarkerEntrySync(snapshot.project, {
    launchId: 'l23-launch',
    taskId: completed.taskId,
    provider: 'agy',
    pid: ended.pid,
    spawnedAt,
  });
  const markerFile = path.join(snapshot.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  assert.equal(existsSync(markerFile), true);

  const limitedConfig = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
    MAX_RETAINED_TASKS: '1',
  });
  const limitedCli = new CliAdapter(limitedConfig, [MOCK_AGY]);
  assert.equal((await limitedCli.discover()).installed, true);
  const tasks2 = ws.track(new TaskManager(limitedCli, limitedConfig));
  const preview = await tasks2.preview(completed.taskId);
  assert.ok(preview.sha256);
  assert.equal(existsSync(markerFile), false);
  assert.equal(tasks2.status(completed.taskId).processCleanup?.verified, true);
  const stored = new StateStore(ws.stateDir).load().find(item => item.record.taskId === completed.taskId);
  assert.equal(stored?.record.processCleanup?.verified, true);

  const nextQueued = await tasks2.run({ prompt: 'write:l23-next', workingDirectory: ws.repoDir, mode: 'write' });
  const next = await waitForTask(tasks2, nextQueued.taskId);
  assert.equal(next.status, 'completed');
  assert.equal(tasks2.list().some(task => task.taskId === completed.taskId), false);
});

test('L24) copy cleanup rereads the marker under the copy lock and never deletes a copy marked by another instance', async t => {
  {
    const ws = createWorkspace(t);
    const fixture = createReadFixture(ws.repoDir);
    const cli = new OpenCodeTestCliAdapter(ws.config);
    const okAdapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
    });
    const A = ws.track(new TaskManager(cli, ws.config, okAdapter));
    const firstQueued = await A.run({
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
    });
    const first = await waitForTask(A, firstQueued.taskId);
    assert.equal(first.status, 'completed');
    assert.equal(first.processCleanup?.verified, true);
    assert.ok(first.sessionId && first.copyDirectory);
    const stored = new StateStore(ws.stateDir).load().find(item => item.record.taskId === first.taskId);
    assert.ok(stored?.project?.gitDirectory);
    const markerFile = path.join(stored.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);

    const B = ws.track(new TaskManager(cli, ws.config, createUnverifiedResumeAdapter(first.sessionId, 940_024)));
    let bDone = false;
    const aInternal = A as unknown as {
      withProject: (project: unknown, operation: () => Promise<unknown>, options?: unknown) => Promise<unknown>;
    };
    const original = aInternal.withProject.bind(A);
    aInternal.withProject = async (project: unknown, operation: () => Promise<unknown>, options?: unknown) => {
      if (!bDone) {
        bDone = true;
        const secondQueued = await B.resume(
          { workingDirectory: ws.repoDir, prompt: 'Resume with unverified cleanup' },
          first.taskId,
        );
        const second = await waitForTask(B, secondQueued.taskId);
        assert.equal(second.status, 'completed');
        assert.equal(second.processCleanup?.verified, false);
        assert.equal(existsSync(markerFile), true);
      }
      return original(project, operation, options);
    };

    const cleaned = await A.cleanup(Date.now() + 365 * 24 * 3600_000);
    assert.equal(bDone, true);
    assert.equal(cleaned.discardedTaskIds.includes(first.taskId), false);
    assert.equal(existsSync(first.copyDirectory), true);
    assert.equal(existsSync(markerFile), true);
  }
});

test('L25) retention eviction rereads the marker under the copy lock and keeps a marked copy', async t => {
  {
    const ws = createWorkspace(t);
    const fixture = createReadFixture(ws.repoDir);
    const limitedConfig = loadConfig({
      BRIDGE_STATE_DIRECTORY: ws.stateDir,
      BRIDGE_TEST_EXECUTOR: 'agy',
      AGY_PATH: process.execPath,
      MAX_RETAINED_TASKS: '1',
    });
    const cli = new OpenCodeTestCliAdapter(limitedConfig);
    const okAdapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', 'read'],
    });
    const A = ws.track(new TaskManager(cli, limitedConfig, okAdapter));
    const firstQueued = await A.run({
      prompt: fixture.prompt,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
      model: 'opencode-go/mock-flash',
    });
    const first = await waitForTask(A, firstQueued.taskId);
    assert.equal(first.status, 'completed');
    assert.equal(first.processCleanup?.verified, true);
    assert.ok(first.copyDirectory);
    const stored = new StateStore(ws.stateDir).load().find(item => item.record.taskId === first.taskId);
    assert.ok(stored?.project?.gitDirectory);
    const project = stored.project;
    const markerFile = path.join(project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);

    let marked = false;
    const aInternal = A as unknown as {
      withProject: (project: unknown, operation: () => Promise<unknown>, options?: unknown) => Promise<unknown>;
    };
    const original = aInternal.withProject.bind(A);
    aInternal.withProject = async (target: unknown, operation: () => Promise<unknown>, options?: unknown) => {
      if (!marked) {
        marked = true;
        upsertProcessCleanupMarkerEntrySync(project, {
          launchId: 'l24-other-instance',
          taskId: first.taskId,
          provider: 'opencode',
          pid: 940_024,
          spawnedAt: new Date().toISOString(),
        });
      }
      return original(target, operation, options);
    };

    await assert.rejects(
      () => A.run({
        prompt: fixture.prompt,
        workingDirectory: ws.repoDir,
        mode: 'read-only',
        model: 'opencode-go/mock-flash',
      }),
      err => err instanceof BridgeError && err.code === 'QUEUE_FULL' && err.message.includes(first.taskId),
    );
    assert.equal(marked, true);
    assert.equal(existsSync(first.copyDirectory), true);
    assert.equal(existsSync(markerFile), true);
    assert.equal(A.list().some(task => task.taskId === first.taskId), true);
  }
});

test('L26) incomplete tracked cleanup retains state and blocks reuse until valid reconciliation releases the root', async t => {
  const ws = createWorkspace(t);
  const cli = new CliAdapter(ws.config, [MOCK_AGY]);
  const discovery = await cli.discover();
  assert.equal(discovery.installed, true, discovery.error ?? 'mock agy was not discovered');

  const tasks1 = ws.track(new TaskManager(cli, ws.config));
  const queued1 = await tasks1.run({ prompt: 'write:l26', workingDirectory: ws.repoDir, mode: 'write' });
  const completed1 = await waitForTask(tasks1, queued1.taskId);
  assert.equal(completed1.status, 'completed');
  assert.equal(completed1.execution?.provider, 'agy');
  assert.ok(completed1.copyDirectory);
  await tasks1.shutdown();

  const now1 = new Date().toISOString();
  const snapshotPath1 = path.join(ws.stateDir, `${completed1.taskId}.json`);
  const snapshot1 = JSON.parse(readFileSync(snapshotPath1, 'utf8')) as {
    record: TaskRecord;
    project: { gitDirectory: string };
  };
  snapshot1.record.processCleanup = { verified: false, spawnedAt: now1, checkedAt: now1, remaining: 0, containment: 'tracked' };
  delete snapshot1.record.pid;
  writeFileSync(snapshotPath1, JSON.stringify(snapshot1), 'utf8');
  upsertProcessCleanupMarkerEntrySync(snapshot1.project, {
    launchId: 'l26-launch-no-pid',
    taskId: completed1.taskId,
    provider: 'agy',
    spawnedAt: now1,
    containment: 'tracked',
  });
  const marker1Path = path.join(snapshot1.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  const bytes1Before = readFileSync(path.join(completed1.copyDirectory, 'BLACK_GRAVITY_TEST.md'), 'utf8');

  const tasks2 = ws.track(new TaskManager(cli, ws.config));
  const cleaned1 = await tasks2.cleanup(Date.now() + 365 * 24 * 3600_000);
  assert.equal(cleaned1.discardedTaskIds.includes(completed1.taskId), false);
  assert.equal(existsSync(completed1.copyDirectory), true);
  assert.equal(existsSync(marker1Path), true);
  assert.equal(readFileSync(path.join(completed1.copyDirectory, 'BLACK_GRAVITY_TEST.md'), 'utf8'), bytes1Before);
  assert.equal(tasks2.status(completed1.taskId).discardedAt, undefined);
  const tasksBeforeRefused1 = tasks2.list().length;
  await assert.rejects(
    () => tasks2.run({ prompt: 'write:l26-blocked-1', workingDirectory: ws.repoDir, mode: 'write' }),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(tasks2.list().length, tasksBeforeRefused1);
  await tasks2.shutdown();

  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
    detached: true,
    stdio: 'ignore',
  });
  sleeper.unref();
  const sleeperPid = sleeper.pid;
  assert.ok(sleeperPid && sleeperPid > 0);
  t.after(() => {
    if (process.platform === 'win32') {
      try { sleeper.kill('SIGKILL'); } catch { /* already exited */ }
    } else {
      try { process.kill(-sleeperPid, 'SIGKILL'); } catch { /* already exited */ }
    }
  });

  const markUnverifiedWithPid = (stateDir: string, taskId: string, pid: number, launchId: string) => {
    const spawnedAt = new Date(Date.now() - 1_000).toISOString();
    const snapshotPath = path.join(stateDir, `${taskId}.json`);
    const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
      record: TaskRecord;
      project: { gitDirectory: string };
    };
    snapshot.record.pid = pid;
    snapshot.record.processCleanup = { verified: false, spawnedAt, checkedAt: spawnedAt, remaining: 1, containment: 'tracked' };
    writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');
    upsertProcessCleanupMarkerEntrySync(snapshot.project, {
      launchId,
      taskId,
      provider: 'agy',
      pid,
      spawnedAt,
      containment: 'tracked',
    });
  };

  const wsLive = createWorkspace(t);
  const cliLive = new CliAdapter(wsLive.config, [MOCK_AGY]);
  assert.equal((await cliLive.discover()).installed, true);
  const tasks3 = wsLive.track(new TaskManager(cliLive, wsLive.config));
  const queued2 = await tasks3.run({ prompt: 'write:l26', workingDirectory: wsLive.repoDir, mode: 'write' });
  const completed2 = await waitForTask(tasks3, queued2.taskId);
  assert.equal(completed2.status, 'completed');
  assert.equal(completed2.execution?.provider, 'agy');
  assert.ok(completed2.copyDirectory);
  await tasks3.shutdown();

  markUnverifiedWithPid(wsLive.stateDir, completed2.taskId, sleeperPid, 'l26-launch-live-pid');
  const bytes2Before = readFileSync(path.join(completed2.copyDirectory, 'BLACK_GRAVITY_TEST.md'), 'utf8');

  const tasks4 = wsLive.track(new TaskManager(cliLive, wsLive.config));
  const cleaned2 = await tasks4.cleanup(Date.now() + 365 * 24 * 3600_000);
  assert.equal(cleaned2.discardedTaskIds.includes(completed2.taskId), false);
  assert.equal(existsSync(completed2.copyDirectory), true);
  assert.equal(readFileSync(path.join(completed2.copyDirectory, 'BLACK_GRAVITY_TEST.md'), 'utf8'), bytes2Before);
  assert.equal(tasks4.status(completed2.taskId).discardedAt, undefined);
  assert.doesNotThrow(() => process.kill(process.platform === 'win32' ? sleeperPid : -sleeperPid, 0));
  const tasksBeforeRefused2 = tasks4.list().length;
  await assert.rejects(
    () => tasks4.run({ prompt: 'write:l26-blocked-2', workingDirectory: wsLive.repoDir, mode: 'write' }),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(tasks4.list().length, tasksBeforeRefused2);
  assert.doesNotThrow(() => process.kill(process.platform === 'win32' ? sleeperPid : -sleeperPid, 0));
  await tasks4.shutdown();

  // Valid reconciliation releases the root, after which a new task is accepted.
  const ended = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  assert.ok(ended.pid && ended.pid > 0);
  const snapLivePath = path.join(wsLive.stateDir, `${completed2.taskId}.json`);
  const snapLive = JSON.parse(readFileSync(snapLivePath, 'utf8')) as {
    record: TaskRecord;
    project: { gitDirectory: string };
  };
  const endedSpawnedAt = new Date(Date.now() - 1_000).toISOString();
  snapLive.record.pid = ended.pid;
  snapLive.record.processCleanup = { verified: false, spawnedAt: endedSpawnedAt, checkedAt: endedSpawnedAt, remaining: 1, containment: 'tracked' };
  writeFileSync(snapLivePath, JSON.stringify(snapLive), 'utf8');
  writeFileSync(
    path.join(snapLive.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME),
    JSON.stringify({
      version: 1,
      entries: [{ launchId: 'l26-launch-reconcilable', taskId: completed2.taskId, provider: 'agy', pid: ended.pid, spawnedAt: endedSpawnedAt, containment: 'tracked' }],
    }),
    'utf8',
  );

  const tasks5 = wsLive.track(new TaskManager(cliLive, wsLive.config));
  const released = await tasks5.cleanup(Date.now() + 365 * 24 * 3600_000);
  assert.equal(released.discardedTaskIds.includes(completed2.taskId), true);
  assert.equal(existsSync(completed2.copyDirectory), false);
  const nextQueued = await tasks5.run({ prompt: 'write:l26-next', workingDirectory: wsLive.repoDir, mode: 'write' });
  const next = await waitForTask(tasks5, nextQueued.taskId);
  assert.equal(next.status, 'completed');
  assert.doesNotThrow(() => process.kill(process.platform === 'win32' ? sleeperPid : -sleeperPid, 0));
});

test('L27) retry events after the retry-limit stop are not counted', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'retry-burst'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));
  const queued = await tasks.run({
    prompt: 'Trigger retry-burst',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'failed');
  assert.equal(record.error?.code, 'OPENCODE_RETRY_LIMIT');
  const raw = record.result as { providerRetries?: number } | undefined;
  assert.equal(raw?.providerRetries, MAX_OPENCODE_PROVIDER_RETRIES + 1);
  assert.equal(record.processCleanup?.verified, true);
});
