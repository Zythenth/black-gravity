import assert from 'node:assert/strict';
import { execFileSync, execSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AGY_ADAPTER_VERSION } from '../src/agy-execution-adapter.js';
import type { CliProcess, Model } from '../src/cli-adapter.js';
import { loadConfig, type Config } from '../src/config.js';
import type { ExecutionAdapter, ExecutionRequest, ExecutionResult } from '../src/execution-contract.js';
import { discardProjectCopy } from '../src/isolation.js';
import { createMcpServer } from '../src/mcp-server.js';
import { successOutputSchemas } from '../src/output-schemas.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError, type RunOptions } from '../src/types.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { OtherProviderExecutionFixture } from './other-fixture.js';
import { waitForTask } from './wait-for-task.js';

function createMockProcess(events: readonly unknown[], exitCode = 0): CliProcess {
  const child = Object.assign(new EventEmitter(), {
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    pid: undefined,
    killed: false,
    exitCode: null as number | null,
    kill: () => {
      child.killed = true;
      child.exitCode = 0;
      child.emit('close', 0);
      return true;
    },
  });
  setImmediate(() => {
    for (const ev of events) {
      child.stdout.write(JSON.stringify(ev) + '\n');
    }
    child.stdout.end();
    child.exitCode = exitCode;
    child.emit('close', exitCode);
  });
  return child as unknown as CliProcess;
}

class ControlledIdentityCliAdapter extends ControlledCliAdapter {
  spawnCalls = 0;
  nextEvents?: readonly unknown[];
  listedModels: Model[] = [{ id: 'requested-model-1', name: 'Requested Model 1' }];
  onSpawn?: (options: RunOptions, model: string | undefined, cwd: string, sessionId: string) => readonly unknown[] | void;

  override spawnTask(options: RunOptions, model: string | undefined, cwd: string): CliProcess {
    this.spawnCalls += 1;
    const sessionId = options.sessionId ?? `session-${this.spawnCalls}`;
    if (options.agentPolicy) {
      const hook = spawnSync(process.execPath, ['bridge-execution-hook.mjs'], {
        cwd: path.join(cwd, '.agents'),
        windowsHide: true,
        encoding: 'utf8',
        input: JSON.stringify({
          toolCall: { name: 'finish', args: {} },
          workspacePaths: [cwd],
          conversationId: sessionId,
        }),
      });
      assert.equal(hook.status, 0, hook.stderr);
      assert.equal(JSON.parse(hook.stdout).decision, 'allow');
    }
    const hookEvents = this.onSpawn?.(options, model, cwd, sessionId);
    const events = hookEvents ?? this.nextEvents ?? [
      { event: 'init', conversation_id: sessionId },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: sessionId, response: 'ok' } },
    ];
    if (!hookEvents) this.nextEvents = undefined;
    return createMockProcess(events);
  }

  override async listModels(): Promise<Model[]> {
    return this.listedModels;
  }
}

function assertCrossProviderRefused(err: unknown): boolean {
  return (
    err instanceof BridgeError &&
    err.code === 'INVALID_SESSION' &&
    /Cannot resume .* session with .* executor/.test(err.message)
  );
}

function createWorkspace(t: { after(fn: () => Promise<void> | void): void }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'bg-exec-id-'));
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
      // Cleanup ignores intentionally corrupted test snapshots.
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

test('persists requested execution identity (explicit and defaulted) and preserves it identically across reload', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const explicitQueued = await tasks.run({
    prompt: 'explicit model and effort',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    effort: 'high',
  });
  const expectedExplicit = {
    provider: 'agy',
    adapterId: 'agy',
    adapterVersion: AGY_ADAPTER_VERSION,
    requested: { model: 'requested-model-1', effort: 'high' as const },
    observed: { model: null, status: 'not-observable' as const },
  };
  assert.equal(AGY_ADAPTER_VERSION, '1');
  assert.deepEqual(explicitQueued.execution, expectedExplicit);

  const explicitSettled = await waitForTask(tasks, explicitQueued.taskId);
  assert.equal(explicitSettled.status, 'completed');
  assert.deepEqual(explicitSettled.execution, expectedExplicit);

  const defaultedQueued = await tasks.run({
    prompt: 'defaulted model and effort',
    workingDirectory: ws.repoDir,
  });
  const expectedDefaulted = {
    provider: 'agy',
    adapterId: 'agy',
    adapterVersion: AGY_ADAPTER_VERSION,
    requested: { model: null, effort: null },
    observed: { model: null, status: 'not-observable' as const },
  };
  assert.deepEqual(defaultedQueued.execution, expectedDefaulted);

  const defaultedSettled = await waitForTask(tasks, defaultedQueued.taskId);
  assert.equal(defaultedSettled.status, 'completed');
  assert.deepEqual(defaultedSettled.execution, expectedDefaulted);

  await tasks.shutdown();

  const reloaded = new StateStore(ws.stateDir).load();
  const reloadedExplicit = reloaded.find(item => item.record.taskId === explicitQueued.taskId);
  const reloadedDefaulted = reloaded.find(item => item.record.taskId === defaultedQueued.taskId);
  assert.ok(reloadedExplicit);
  assert.ok(reloadedDefaulted);
  assert.equal(JSON.stringify(reloadedExplicit.record.execution), JSON.stringify(explicitSettled.execution));
  assert.equal(JSON.stringify(reloadedDefaulted.record.execution), JSON.stringify(defaultedSettled.execution));
});

test('records observed model from stream init event and persists it across reload', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-observed-1', init: { model: 'observed-model-x' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-observed-1', response: 'done' } },
  ];
  const task = await tasks.run({
    prompt: 'observe init model',
    workingDirectory: ws.repoDir,
  });
  const settled = await waitForTask(tasks, task.taskId);
  assert.equal(settled.status, 'completed');
  assert.deepEqual(settled.execution?.requested, { model: null, effort: null });
  assert.deepEqual(settled.execution?.observed, { model: 'observed-model-x', status: 'observed' });

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-observed-2', init: { model: '  observed-trimmed-model  ' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-observed-2', response: 'done' } },
  ];
  const trimmedTask = await tasks.run({
    prompt: 'trim observed init model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
  });
  const settledTrimmed = await waitForTask(tasks, trimmedTask.taskId);
  assert.equal(settledTrimmed.status, 'completed');
  assert.deepEqual(settledTrimmed.execution?.requested, { model: 'requested-model-1', effort: null });
  assert.deepEqual(settledTrimmed.execution?.observed, { model: 'observed-trimmed-model', status: 'observed' });

  await tasks.shutdown();

  const reloaded = new StateStore(ws.stateDir).load();
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === task.taskId)?.record.execution?.observed,
    { model: 'observed-model-x', status: 'observed' },
  );
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === trimmedTask.taskId)?.record.execution?.observed,
    { model: 'observed-trimmed-model', status: 'observed' },
  );
});

test('records not-observable when init has no usable model or when using a pure non-agy ExecutionAdapter', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const agyTasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-no-model' },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-no-model', response: 'done' } },
  ];
  const noModelTask = await agyTasks.run({
    prompt: 'no init model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    effort: 'medium',
  });
  const settledNoModel = await waitForTask(agyTasks, noModelTask.taskId);
  assert.equal(settledNoModel.status, 'completed');
  assert.deepEqual(settledNoModel.execution?.requested, { model: 'requested-model-1', effort: 'medium' });
  assert.deepEqual(settledNoModel.execution?.observed, { model: null, status: 'not-observable' });

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-blank-model', init: { model: '   ' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-blank-model', response: 'done' } },
  ];
  const blankModelTask = await agyTasks.run({
    prompt: 'blank init model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
  });
  const settledBlankModel = await waitForTask(agyTasks, blankModelTask.taskId);
  assert.equal(settledBlankModel.status, 'completed');
  assert.deepEqual(settledBlankModel.execution?.observed, { model: null, status: 'not-observable' });
  await agyTasks.shutdown();

  const pureTasks = ws.track(
    new TaskManager(
      cli,
      ws.config,
      new OtherProviderExecutionFixture({ outcome: 'done', session: 'other-session-1', text: 'pure ok' }),
    ),
  );
  const pureTask = await pureTasks.run({
    prompt: 'pure non-agy adapter',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    effort: 'low',
  });
  const settledPure = await waitForTask(pureTasks, pureTask.taskId);
  assert.equal(settledPure.status, 'completed');
  assert.deepEqual(settledPure.execution, {
    provider: 'synthetic-provider',
    adapterId: 'other-fixture',
    adapterVersion: '1',
    requested: { model: 'requested-model-1', effort: 'low' },
    observed: { model: null, status: 'not-observable' },
  });
  await pureTasks.shutdown();

  const reloaded = new StateStore(ws.stateDir).load();
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === noModelTask.taskId)?.record.execution?.observed,
    { model: null, status: 'not-observable' },
  );
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === blankModelTask.taskId)?.record.execution?.observed,
    { model: null, status: 'not-observable' },
  );
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === pureTask.taskId)?.record.execution,
    settledPure.execution,
  );
});

test('legacy snapshots load without execution, resume under agy, and refuse cross-provider resume with INVALID_SESSION before spawning', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const initialTasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'legacy-session-1' },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'legacy-session-1', response: 'legacy ok' } },
  ];
  const initial = await initialTasks.run({
    prompt: 'seed legacy snapshot',
    workingDirectory: ws.repoDir,
  });
  const settledInitial = await waitForTask(initialTasks, initial.taskId);
  assert.equal(settledInitial.status, 'completed');
  await initialTasks.shutdown();

  const snapshotFile = path.join(ws.stateDir, `${initial.taskId}.json`);
  const rawSnapshot = JSON.parse(readFileSync(snapshotFile, 'utf8')) as { record: Record<string, unknown> };
  delete rawSnapshot.record.execution;
  const legacyRaw = JSON.stringify(rawSnapshot);
  writeFileSync(snapshotFile, legacyRaw, 'utf8');

  const reloaded = new StateStore(ws.stateDir).load();
  const legacyEntry = reloaded.find(item => item.record.taskId === initial.taskId);
  assert.ok(legacyEntry);
  assert.equal(legacyEntry.record.execution, undefined);
  assert.equal(readFileSync(snapshotFile, 'utf8'), legacyRaw);

  let otherExecuteCalls = 0;
  const spyOtherAdapter: ExecutionAdapter = {
    identity: { id: 'other-fixture', provider: 'synthetic-provider', version: '1' },
    capabilities: new OtherProviderExecutionFixture({ outcome: 'done' }).capabilities,
    async execute(request: ExecutionRequest): Promise<ExecutionResult> {
      otherExecuteCalls += 1;
      return { taskId: request.taskId, status: 'completed', response: 'should not run' };
    },
  };
  cli.spawnCalls = 0;
  const otherTasks = ws.track(new TaskManager(cli, ws.config, spyOtherAdapter));

  await assert.rejects(
    () => otherTasks.resume({ prompt: 'cross-provider by taskId', workingDirectory: ws.repoDir }, initial.taskId),
    assertCrossProviderRefused,
  );
  await assert.rejects(
    () => otherTasks.resume({ prompt: 'cross-provider by sessionId', workingDirectory: ws.repoDir, sessionId: 'legacy-session-1' }),
    assertCrossProviderRefused,
  );
  assert.equal(otherExecuteCalls, 0);
  assert.equal(cli.spawnCalls, 0);
  assert.equal(readFileSync(snapshotFile, 'utf8'), legacyRaw);
  await otherTasks.shutdown();

  const agyTasks = ws.track(new TaskManager(cli, ws.config));
  const resumed = await agyTasks.resume(
    { prompt: 'continue legacy under agy', workingDirectory: ws.repoDir },
    initial.taskId,
  );
  const settledResumed = await waitForTask(agyTasks, resumed.taskId);
  assert.equal(settledResumed.status, 'completed');
  assert.equal(cli.spawnCalls, 1);
  assert.equal(settledResumed.execution?.provider, 'agy');
  assert.equal(readFileSync(snapshotFile, 'utf8'), legacyRaw);
  assert.equal(JSON.parse(readFileSync(snapshotFile, 'utf8')).record.execution, undefined);
});

test('refuses cross-provider resume of a task persisted with execution.provider agy before any process starts', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const agyTasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'agy-session-1', init: { model: 'observed-model-x' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'agy-session-1', response: 'agy ok' } },
  ];
  const initial = await agyTasks.run({
    prompt: 'persisted agy task',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
  });
  const settled = await waitForTask(agyTasks, initial.taskId);
  assert.equal(settled.status, 'completed');
  assert.equal(settled.execution?.provider, 'agy');
  await agyTasks.shutdown();

  let executeCalls = 0;
  const foreignAdapter: ExecutionAdapter = {
    identity: { id: 'foreign', provider: 'foreign-provider', version: '1' },
    capabilities: {
      read: 'supported',
      write: 'supported',
      sandbox: 'unknown',
      network: 'unknown',
      skills: 'unknown',
      resources: 'unknown',
      structuredOutput: 'supported',
      cancel: 'unknown',
      resume: 'supported',
      observableUsage: 'unknown',
    },
    async execute(request: ExecutionRequest): Promise<ExecutionResult> {
      executeCalls += 1;
      return { taskId: request.taskId, status: 'completed', response: 'should not run' };
    },
  };
  cli.spawnCalls = 0;
  const foreignTasks = ws.track(new TaskManager(cli, ws.config, foreignAdapter));

  await assert.rejects(
    () => foreignTasks.resume({ prompt: 'resume under foreign', workingDirectory: ws.repoDir }, initial.taskId),
    assertCrossProviderRefused,
  );
  await assert.rejects(
    () => foreignTasks.resume({ prompt: 'resume under foreign by session', workingDirectory: ws.repoDir, sessionId: 'agy-session-1' }),
    assertCrossProviderRefused,
  );
  assert.equal(executeCalls, 0);
  assert.equal(cli.spawnCalls, 0);
});

test('native-test continuations (windows-lpac and agy) enforce provider guard and start with fresh not-observable identity', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const agyTasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'native-test-session-1', init: { model: 'observed-model-x' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'native-test-session-1', response: 'ready' } },
  ];
  const parent = await agyTasks.run({
    prompt: 'parent write task',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    effort: 'high',
  });
  const settledParent = await waitForTask(agyTasks, parent.taskId);
  assert.equal(settledParent.status, 'completed');
  assert.deepEqual(settledParent.execution?.observed, { model: 'observed-model-x', status: 'observed' });

  const preview = await agyTasks.preview(parent.taskId, false);
  await agyTasks.shutdown();

  let executeCalls = 0;
  const foreignAdapter: ExecutionAdapter = {
    identity: { id: 'foreign', provider: 'foreign-provider', version: '1' },
    capabilities: {
      read: 'supported',
      write: 'supported',
      sandbox: 'unknown',
      network: 'unknown',
      skills: 'unknown',
      resources: 'unknown',
      structuredOutput: 'supported',
      cancel: 'unknown',
      resume: 'supported',
      observableUsage: 'unknown',
    },
    async execute(request: ExecutionRequest): Promise<ExecutionResult> {
      executeCalls += 1;
      return { taskId: request.taskId, status: 'completed', response: 'should not run' };
    },
  };

  cli.spawnCalls = 0;
  const foreignLpacConfig: Config = { ...ws.config, testExecutor: 'agy' };
  const foreignLpacTasks = ws.track(new TaskManager(cli, foreignLpacConfig, foreignAdapter));
  foreignLpacConfig.testExecutor = 'windows-lpac';
  let lpacRunCalls = 0;
  (foreignLpacTasks as unknown as { executeWindowsNativeTest: () => Promise<void> }).executeWindowsNativeTest = async () => {
    lpacRunCalls += 1;
  };
  await assert.rejects(
    () => foreignLpacTasks.startTests(
      parent.taskId,
      preview.sha256,
      { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
    ),
    assertCrossProviderRefused,
  );
  assert.equal(lpacRunCalls, 0);
  assert.equal(executeCalls, 0);
  assert.equal(cli.spawnCalls, 0);
  await foreignLpacTasks.shutdown();

  const foreignAgyTasks = ws.track(new TaskManager(cli, ws.config, foreignAdapter));
  await assert.rejects(
    () => foreignAgyTasks.startTests(
      parent.taskId,
      preview.sha256,
      { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
    ),
    assertCrossProviderRefused,
  );
  assert.equal(executeCalls, 0);
  assert.equal(cli.spawnCalls, 0);
  await foreignAgyTasks.shutdown();

  // Exercise queueWindowsTest directly with LPAC execution stubbed so no real LPAC runtime is spun up.
  const lpacConfig: Config = { ...ws.config, testExecutor: 'agy' };
  const lpacTasks = ws.track(new TaskManager(cli, lpacConfig));
  lpacConfig.testExecutor = 'windows-lpac';
  const internalLpac = lpacTasks as unknown as {
    executeWindowsNativeTest: (task: unknown) => Promise<void>;
    finish: (task: unknown, status: 'completed') => void;
  };
  internalLpac.executeWindowsNativeTest = async task => {
    internalLpac.finish(task, 'completed');
  };

  const lpacQueued = await lpacTasks.startTests(
    parent.taskId,
    preview.sha256,
    { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
  );
  const expectedFreshTestExecution = {
    provider: 'agy',
    adapterId: 'agy',
    adapterVersion: AGY_ADAPTER_VERSION,
    requested: { model: 'requested-model-1', effort: 'high' as const },
    observed: { model: null, status: 'not-observable' as const },
  };
  assert.deepEqual(lpacQueued.execution, expectedFreshTestExecution);
  const lpacSettled = await waitForTask(lpacTasks, lpacQueued.taskId);
  assert.equal(lpacSettled.status, 'completed');
  assert.deepEqual(lpacSettled.execution, expectedFreshTestExecution);
  await lpacTasks.shutdown();

  // Also verify non-LPAC startTests (via run()) creates a fresh identity instead of inheriting parent observed.
  const agyRetestTasks = ws.track(new TaskManager(cli, ws.config));
  cli.nextEvents = [
    { event: 'init', conversation_id: 'native-test-session-1' },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'native-test-session-1', response: 'done' } },
  ];
  const agyTestQueued = await agyRetestTasks.startTests(
    lpacSettled.taskId,
    preview.sha256,
    { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
  );
  assert.deepEqual(agyTestQueued.execution, expectedFreshTestExecution);
  const agyTestSettled = await waitForTask(agyRetestTasks, agyTestQueued.taskId);
  assert.deepEqual(agyTestSettled.execution, expectedFreshTestExecution);
  await agyRetestTasks.shutdown();

  const reloaded = new StateStore(ws.stateDir).load();
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === lpacQueued.taskId)?.record.execution,
    expectedFreshTestExecution,
  );
  assert.deepEqual(
    reloaded.find(item => item.record.taskId === agyTestQueued.taskId)?.record.execution,
    expectedFreshTestExecution,
  );
});

test('StateStore strictly validates persisted execution identity and MCP outputs omit execution', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const server = createMcpServer(cli, tasks);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'exec-id-test-client', version: '1.0.0' }, { capabilities: {} });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  let taskId: string;
  try {
    cli.nextEvents = [
      { event: 'init', conversation_id: 'mcp-conv-1', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'mcp-conv-1', response: 'mcp ok' } },
    ];
    const runRes = await client.callTool({
      name: 'black_gravity_run',
      arguments: { prompt: 'mcp check', workingDirectory: ws.repoDir },
    });
    assert.equal(runRes.isError, undefined);
    const parsedRun = successOutputSchemas.black_gravity_run.parse(runRes.structuredContent);
    assert.equal('execution' in parsedRun.task, false);

    taskId = parsedRun.task.taskId;
    const settled = await waitForTask(tasks, taskId);
    assert.equal(settled.status, 'completed');
    assert.deepEqual(settled.execution?.observed, { model: 'observed-model-x', status: 'observed' });

    const statusRes = await client.callTool({ name: 'black_gravity_status', arguments: { taskId } });
    assert.equal(statusRes.isError, undefined);
    const parsedStatus = successOutputSchemas.black_gravity_status.parse(statusRes.structuredContent);
    assert.equal('execution' in parsedStatus.task, false);

    const listRes = await client.callTool({ name: 'black_gravity_tasks', arguments: {} });
    assert.equal(listRes.isError, undefined);
    const parsedList = successOutputSchemas.black_gravity_tasks.parse(listRes.structuredContent);
    assert.equal(parsedList.tasks.some(item => 'execution' in item), false);

    for (const includeResult of [true, false]) {
      const resultRes = await client.callTool({
        name: 'black_gravity_result',
        arguments: { taskId, includeResult },
      });
      assert.equal(resultRes.isError, undefined, JSON.stringify(resultRes.structuredContent));
      const parsedResult = successOutputSchemas.black_gravity_result.parse(resultRes.structuredContent);
      assert.equal('execution' in parsedResult.task, false);
    }

    // Exercise deliveryMode: 'messages' (compactTask path) across run/status/tasks/result/cancel/discard.
    cli.nextEvents = [
      { event: 'init', conversation_id: 'mcp-conv-msg-1', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'mcp-conv-msg-1', response: 'msg ok' } },
    ];
    const msgRunRes = await client.callTool({
      name: 'black_gravity_run',
      arguments: { prompt: 'mcp messages check', workingDirectory: ws.repoDir, deliveryMode: 'messages' },
    });
    assert.equal(msgRunRes.isError, undefined);
    const parsedMsgRun = successOutputSchemas.black_gravity_run.parse(msgRunRes.structuredContent);
    assert.equal('execution' in parsedMsgRun.task, false);

    const msgTaskId = parsedMsgRun.task.taskId;
    const msgSettled = await waitForTask(tasks, msgTaskId);
    assert.equal(msgSettled.status, 'completed');
    assert.deepEqual(msgSettled.execution?.observed, { model: 'observed-model-x', status: 'observed' });

    const msgStatusRes = await client.callTool({ name: 'black_gravity_status', arguments: { taskId: msgTaskId } });
    assert.equal(msgStatusRes.isError, undefined);
    const parsedMsgStatus = successOutputSchemas.black_gravity_status.parse(msgStatusRes.structuredContent);
    assert.equal('execution' in parsedMsgStatus.task, false);

    const msgListRes = await client.callTool({ name: 'black_gravity_tasks', arguments: {} });
    assert.equal(msgListRes.isError, undefined);
    const parsedMsgList = successOutputSchemas.black_gravity_tasks.parse(msgListRes.structuredContent);
    assert.equal(parsedMsgList.tasks.some(item => 'execution' in item), false);

    for (const includeResult of [true, false]) {
      const msgResultRes = await client.callTool({
        name: 'black_gravity_result',
        arguments: { taskId: msgTaskId, includeResult },
      });
      assert.equal(msgResultRes.isError, undefined, JSON.stringify(msgResultRes.structuredContent));
      const parsedMsgResult = successOutputSchemas.black_gravity_result.parse(msgResultRes.structuredContent);
      assert.equal('execution' in parsedMsgResult.task, false);
    }

    const msgCancelRes = await client.callTool({ name: 'black_gravity_cancel', arguments: { taskId: msgTaskId } });
    assert.equal(msgCancelRes.isError, undefined);
    const parsedMsgCancel = successOutputSchemas.black_gravity_cancel.parse(msgCancelRes.structuredContent);
    assert.equal('execution' in parsedMsgCancel.task, false);

    const msgDiscardRes = await client.callTool({ name: 'black_gravity_discard', arguments: { taskId: msgTaskId } });
    assert.equal(msgDiscardRes.isError, undefined);
    const parsedMsgDiscard = successOutputSchemas.black_gravity_discard.parse(msgDiscardRes.structuredContent);
    assert.equal('execution' in parsedMsgDiscard.task, false);
  } finally {
    await client.close();
    await server.close();
  }

  const badStateDir = path.join(ws.root, 'bad-state');
  mkdirSync(badStateDir, { recursive: true });
  const validText = readFileSync(path.join(ws.stateDir, `${taskId}.json`), 'utf8');
  const invalidPayloads = [
    (obj: any) => { obj.record.execution.provider = ''; },
    (obj: any) => { obj.record.execution.adapterId = ''; },
    (obj: any) => { obj.record.execution.adapterVersion = ''; },
    (obj: any) => { obj.record.execution.observed.status = 'inferred'; },
    (obj: any) => { obj.record.execution.extraField = true; },
    (obj: any) => { obj.record.execution.requested.extraField = true; },
    (obj: any) => { obj.record.execution.observed.extraField = true; },
  ];
  for (const mutate of invalidPayloads) {
    const parsed = JSON.parse(validText);
    mutate(parsed);
    writeFileSync(path.join(badStateDir, `${taskId}.json`), JSON.stringify(parsed), 'utf8');
    assert.throws(
      () => new StateStore(badStateDir).load(),
      (err: unknown) => err instanceof BridgeError && err.code === 'INVALID_STATE',
    );
  }
});

test('treats init.model echo of requested model as not-observable across reload without model.mismatch event', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-echo-1', init: { model: 'requested-model-1' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-echo-1', response: 'done' } },
  ];
  const echoTask = await tasks.run({
    prompt: 'echo init model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    effort: 'high',
  });
  const settledEcho = await waitForTask(tasks, echoTask.taskId);
  assert.equal(settledEcho.status, 'completed');
  assert.deepEqual(settledEcho.execution?.observed, { model: null, status: 'not-observable' });
  assert.equal(
    tasks.readEvents(echoTask.taskId).events.some(event => event.type === 'model.mismatch'),
    false,
  );

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-echo-2', init: { model: '  requested-model-1  ' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-echo-2', response: 'done' } },
  ];
  const paddedEchoTask = await tasks.run({
    prompt: 'padded echo init model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
  });
  const settledPadded = await waitForTask(tasks, paddedEchoTask.taskId);
  assert.deepEqual(settledPadded.execution?.observed, { model: null, status: 'not-observable' });
  assert.equal(
    tasks.readEvents(paddedEchoTask.taskId).events.some(event => event.type === 'model.mismatch'),
    false,
  );

  await tasks.shutdown();

  const reloaded = new StateStore(ws.stateDir).load();
  const reloadedEcho = reloaded.find(item => item.record.taskId === echoTask.taskId);
  assert.ok(reloadedEcho);
  assert.deepEqual(reloadedEcho.record.execution?.observed, { model: null, status: 'not-observable' });
  assert.equal(reloadedEcho.events.some(event => event.type === 'model.mismatch'), false);
});

test('records observed model and emits model.mismatch when init.model differs from requested model', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-mismatch-1', init: { model: 'observed-model-x' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-mismatch-1', response: 'done' } },
  ];
  const task = await tasks.run({
    prompt: 'mismatched init model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    effort: 'medium',
  });
  const settled = await waitForTask(tasks, task.taskId);
  assert.equal(settled.status, 'completed');
  assert.deepEqual(settled.execution?.observed, { model: 'observed-model-x', status: 'observed' });

  const mismatchEvents = tasks.readEvents(task.taskId).events.filter(event => event.type === 'model.mismatch');
  assert.equal(mismatchEvents.length, 1);
  assert.deepEqual(mismatchEvents[0]!.data, { requested: 'requested-model-1', observed: 'observed-model-x' });

  await tasks.shutdown();

  const reloaded = new StateStore(ws.stateDir).load();
  const entry = reloaded.find(item => item.record.taskId === task.taskId);
  assert.ok(entry);
  assert.deepEqual(entry.record.execution?.observed, { model: 'observed-model-x', status: 'observed' });
  const reloadedMismatches = entry.events.filter(event => event.type === 'model.mismatch');
  assert.equal(reloadedMismatches.length, 1);
  assert.deepEqual(reloadedMismatches[0]!.data, { requested: 'requested-model-1', observed: 'observed-model-x' });
});

test('records observed model without model.mismatch when no model was requested', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  cli.nextEvents = [
    { event: 'init', conversation_id: 'conv-noreq-1', init: { model: 'observed-model-x' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-noreq-1', response: 'done' } },
  ];
  const task = await tasks.run({
    prompt: 'no requested model with init model',
    workingDirectory: ws.repoDir,
  });
  const settled = await waitForTask(tasks, task.taskId);
  assert.equal(settled.status, 'completed');
  assert.deepEqual(settled.execution?.requested, { model: null, effort: null });
  assert.deepEqual(settled.execution?.observed, { model: 'observed-model-x', status: 'observed' });
  assert.equal(
    tasks.readEvents(task.taskId).events.some(event => event.type === 'model.mismatch'),
    false,
  );
});

test('verify fails with model-identity check and blocks integrate on mismatch, while echo passes without model-identity check', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  cli.onSpawn = (_options, _model, cwd) => {
    writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
    return [
      { event: 'init', conversation_id: 'conv-verify-mismatch', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-verify-mismatch', response: 'done' } },
    ];
  };
  const mismatched = await tasks.run({
    prompt: 'write file with mismatched model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    acceptanceCriteria: criteria,
  });
  const settledMismatch = await waitForTask(tasks, mismatched.taskId);
  assert.equal(settledMismatch.status, 'completed');

  const mismatchPreview = await tasks.preview(settledMismatch.taskId, false);
  const mismatchVerification = await tasks.verify(settledMismatch.taskId, mismatchPreview.sha256, reviews);
  assert.equal(mismatchVerification.status, 'failed');
  const identityCheck = mismatchVerification.checks.find(check => check.criterionId === 'model-identity');
  assert.ok(identityCheck);
  assert.equal(identityCheck.status, 'failed');
  assert.match(identityCheck.observation, /requested-model-1/);
  assert.match(identityCheck.observation, /observed-model-x/);
  const verifiedEvent = tasks.readEvents(settledMismatch.taskId).events.filter(event => event.type === 'review.verified').at(-1);
  assert.equal((verifiedEvent?.data as { status?: string } | undefined)?.status, 'failed');

  await assert.rejects(
    () => tasks.integrate(settledMismatch.taskId, mismatchPreview.sha256, async () => true),
    (err: unknown) => err instanceof BridgeError && err.code === 'VERIFICATION_REQUIRED',
  );

  cli.onSpawn = (_options, _model, cwd) => {
    writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
    return [
      { event: 'init', conversation_id: 'conv-verify-echo', init: { model: 'requested-model-1' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-verify-echo', response: 'done' } },
    ];
  };
  const echoed = await tasks.run({
    prompt: 'write file with echoed model',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    acceptanceCriteria: criteria,
  });
  const settledEcho = await waitForTask(tasks, echoed.taskId);
  assert.equal(settledEcho.status, 'completed');

  const echoPreview = await tasks.preview(settledEcho.taskId, false);
  const echoVerification = await tasks.verify(settledEcho.taskId, echoPreview.sha256, reviews);
  assert.equal(echoVerification.status, 'passed');
  assert.equal(echoVerification.checks.some(check => check.criterionId === 'model-identity'), false);
});

test('comparison excludes mismatched model opinions, sets complete false, and emits proof warnings', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  cli.listedModels = [
    { id: 'requested-model-1', name: 'Requested Model 1' },
    { id: 'requested-model-2', name: 'Requested Model 2' },
  ];
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const source = await tasks.run({
    prompt: 'source task for comparison',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
  });
  const settledSource = await waitForTask(tasks, source.taskId);
  assert.equal(settledSource.status, 'completed');
  const context = await tasks.context(settledSource.taskId);

  const reviewReport = (message: string) => ({
    summary: 'Review complete',
    reviewedFiles: ['README.md'],
    findings: [
      {
        severity: 'P2' as const,
        path: 'README.md',
        line: 1,
        quote: 'hello',
        message,
        impact: 'Test impact',
        suggestion: 'Test suggestion',
      },
    ],
    unverified: [],
  });

  cli.onSpawn = (options, model) => {
    const convId = options.sessionId ?? `cmp-${model}`;
    const observed = model === 'requested-model-1' ? 'observed-wrong-1' : 'observed-wrong-2';
    return [
      { event: 'init', conversation_id: convId, init: { model: observed } },
      {
        event: 'result',
        result: {
          status: 'SUCCESS',
          conversation_id: convId,
          structured_output: reviewReport(`Finding from ${model}`),
        },
      },
    ];
  };
  const bothMismatch = await tasks.compare(
    settledSource.taskId,
    context.treeSha256,
    ['requested-model-1', 'requested-model-2'],
    'Compare both mismatched',
  );
  for (const taskId of bothMismatch.taskIds) {
    assert.equal((await waitForTask(tasks, taskId)).status, 'completed');
  }
  const bothResult = successOutputSchemas.black_gravity_comparison.parse(await tasks.comparison(bothMismatch.comparisonId));
  assert.equal(bothResult.ready, true);
  assert.equal(bothResult.complete, false);
  assert.deepEqual(bothResult.findings, []);
  assert.ok(
    bothResult.warnings.includes(
      'Model proof failed for requested-model-1: observed observed-wrong-1; its opinion is excluded from the findings.',
    ),
  );
  assert.ok(
    bothResult.warnings.includes(
      'Model proof failed for requested-model-2: observed observed-wrong-2; its opinion is excluded from the findings.',
    ),
  );

  cli.onSpawn = (options, model) => {
    const convId = options.sessionId ?? `cmp-ctrl-${model}`;
    const observed = model === 'requested-model-1' ? 'requested-model-1' : 'observed-wrong-2';
    return [
      { event: 'init', conversation_id: convId, init: { model: observed } },
      {
        event: 'result',
        result: {
          status: 'SUCCESS',
          conversation_id: convId,
          structured_output: reviewReport('Control finding'),
        },
      },
    ];
  };
  const oneMismatch = await tasks.compare(
    settledSource.taskId,
    context.treeSha256,
    ['requested-model-1', 'requested-model-2'],
    'Compare one mismatched',
  );
  for (const taskId of oneMismatch.taskIds) {
    assert.equal((await waitForTask(tasks, taskId)).status, 'completed');
  }
  const oneResult = successOutputSchemas.black_gravity_comparison.parse(await tasks.comparison(oneMismatch.comparisonId));
  assert.equal(oneResult.ready, true);
  assert.equal(oneResult.complete, false);
  assert.equal(oneResult.findings.length, 1);
  assert.deepEqual(
    oneResult.findings[0]!.opinions.map(opinion => opinion.model),
    ['requested-model-1'],
  );
  assert.deepEqual(oneResult.findings[0]!.notReportedBy, ['requested-model-2']);
  assert.ok(
    oneResult.warnings.includes(
      'Model proof failed for requested-model-2: observed observed-wrong-2; its opinion is excluded from the findings.',
    ),
  );
  assert.equal(
    oneResult.warnings.some(warning => warning.includes('Model proof failed for requested-model-1:')),
    false,
  );
});

test('integrate rejects a pre-existing passed verification when the reloaded task has a model mismatch', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  cli.onSpawn = (_options, _model, cwd) => {
    writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
    return [
      { event: 'init', conversation_id: 'conv-stale-verify', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-stale-verify', response: 'done' } },
    ];
  };
  const task = await tasks.run({
    prompt: 'write file with mismatch and legacy passed verification',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    acceptanceCriteria: criteria,
  });
  const settled = await waitForTask(tasks, task.taskId);
  assert.equal(settled.status, 'completed');

  const preview = await tasks.preview(settled.taskId, false);
  const verified = await tasks.verify(settled.taskId, preview.sha256, reviews);
  assert.equal(verified.status, 'failed');
  await tasks.shutdown();

  // Simulate an older persisted snapshot where verification.status was recorded as 'passed' despite model mismatch.
  const snapshotPath = path.join(ws.stateDir, `${settled.taskId}.json`);
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
    record: {
      verification?: {
        status: string;
        checks: Array<{ criterionId: string; status: string; observation: string }>;
      };
    };
  };
  assert.ok(snapshot.record.verification);
  snapshot.record.verification.checks = snapshot.record.verification.checks.filter(
    check => check.criterionId !== 'model-identity',
  );
  snapshot.record.verification.status = 'passed';
  writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');

  const reloaded = ws.track(new TaskManager(cli, ws.config));
  assert.equal(reloaded.status(settled.taskId).verification?.status, 'passed');

  await assert.rejects(
    () => reloaded.integrate(settled.taskId, preview.sha256, async () => true),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'VERIFICATION_REQUIRED' &&
      err.message.includes('Model proof failed') &&
      !err.message.includes('Model proof failed: Model proof failed'),
  );
});

test('workflowSnapshot fails with WORKFLOW_VALIDATION_FAILED on mismatched output task and succeeds without mismatch', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));
  const repoDir = realpathSync(ws.repoDir);

  const criterion = { id: 'readme', description: 'README exists', check: { kind: 'file-exists' as const, path: 'README.md' } };
  const makeWorkflow = (firstPrompt: string, finalPrompt: string) => ({
    workingDirectory: repoDir,
    title: 'Workflow model proof fixture',
    workflow: { finalNode: 'final' },
    jobs: [
      {
        key: 'first',
        owner: 'implementer',
        dependsOn: [],
        task: { prompt: firstPrompt, mode: 'read-only' as const, model: 'requested-model-1', acceptanceCriteria: [criterion] },
      },
      {
        key: 'final',
        owner: 'implementer',
        dependsOn: ['first'],
        task: { prompt: finalPrompt, mode: 'read-only' as const, model: 'requested-model-1', acceptanceCriteria: [criterion] },
      },
    ],
  });

  const until = async (predicate: () => boolean, timeoutMs = 30000) => {
    const deadline = Date.now() + timeoutMs;
    while (!predicate()) {
      if (Date.now() > deadline) throw new Error('Timed out waiting for workflow state');
      await delay(20);
    }
  };

  cli.onSpawn = (_options, _model, _cwd, sessionId) => [
    { event: 'init', conversation_id: sessionId, init: { model: 'observed-model-x' } },
    {
      event: 'result',
      result: { status: 'SUCCESS', conversation_id: sessionId, structured_output: { summary: 'done' } },
    },
  ];
  const mismatchGroup = await tasks.groups.create(randomUUID(), makeWorkflow('step with mismatch', 'final mismatch'));
  tasks.groups.start(mismatchGroup.groupId, mismatchGroup.definitionSha256);
  await until(() => tasks.groups.status(mismatchGroup.groupId).state === 'paused');
  const pausedStatus = tasks.groups.status(mismatchGroup.groupId);
  assert.equal(pausedStatus.error?.code, 'WORKFLOW_VALIDATION_FAILED');
  const mismatchTaskId = pausedStatus.nodes[0]!.taskId!;

  await assert.rejects(
    () => tasks.workflowSnapshot(mismatchTaskId, mismatchTaskId, 'first'),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'WORKFLOW_VALIDATION_FAILED' &&
      err.message.includes('Model proof failed') &&
      !err.message.includes('Model proof failed: Model proof failed'),
  );

  cli.onSpawn = (_options, _model, _cwd, sessionId) => [
    { event: 'init', conversation_id: sessionId, init: { model: 'requested-model-1' } },
    {
      event: 'result',
      result: { status: 'SUCCESS', conversation_id: sessionId, structured_output: { summary: 'done' } },
    },
  ];
  const controlGroup = await tasks.groups.create(randomUUID(), makeWorkflow('step with echo', 'final echo'));
  tasks.groups.start(controlGroup.groupId, controlGroup.definitionSha256);
  await until(() => tasks.groups.status(controlGroup.groupId).state === 'completed');
  const controlTaskId = tasks.groups.status(controlGroup.groupId).nodes[0]!.taskId!;

  const snapshot = await tasks.workflowSnapshot(controlTaskId, controlTaskId, 'first');
  assert.equal(snapshot.phase, 'validated');
});

test('native-test continuation inherits copy-wide model mismatch in verify and integrate, while echo passes', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  const runWriteAndRetest = async (initModel: string, sessionId: string) => {
    cli.onSpawn = (_options, _model, cwd) => {
      writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
      return [
        { event: 'init', conversation_id: sessionId, init: { model: initModel } },
        { event: 'result', result: { status: 'SUCCESS', conversation_id: sessionId, response: 'done' } },
      ];
    };
    const writeTask = await tasks.run({
      prompt: `write file (${sessionId})`,
      workingDirectory: ws.repoDir,
      model: 'requested-model-1',
      acceptanceCriteria: criteria,
    });
    const settledWrite = await waitForTask(tasks, writeTask.taskId);
    assert.equal(settledWrite.status, 'completed');
    const writePreview = await tasks.preview(settledWrite.taskId, false);

    cli.onSpawn = (options, _model, cwd) => {
      const match = options.prompt.match(/<bridge-test-command>(.*?)<\/bridge-test-command>/s);
      assert.ok(match);
      const req = JSON.parse(match[1]!) as { commandLine: string };
      const output = execSync(req.commandLine, {
        cwd,
        encoding: 'utf8',
        windowsHide: true,
        shell: process.platform === 'win32' ? 'powershell.exe' : '/bin/sh',
      });
      return [
        { event: 'init', conversation_id: sessionId },
        {
          event: 'step_update',
          step_update: {
            step_index: 0,
            state: 'DONE',
            step_type: 'tool',
            tool_name: 'run_command',
            tool_info: { name: 'run_command', parameters: { CommandLine: req.commandLine }, output },
          },
        },
        { event: 'result', result: { status: 'SUCCESS', conversation_id: sessionId, response: 'tests passed' } },
      ];
    };
    const retest = await tasks.startTests(
      settledWrite.taskId,
      writePreview.sha256,
      { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
    );
    const settledRetest = await waitForTask(tasks, retest.taskId);
    assert.equal(settledRetest.status, 'completed', JSON.stringify(settledRetest.error));
    assert.deepEqual(settledRetest.execution?.observed, { model: null, status: 'not-observable' });
    const retestPreview = await tasks.preview(settledRetest.taskId, false);
    return { settledRetest, retestPreview };
  };

  const mismatched = await runWriteAndRetest('observed-model-x', 'conv-copy-mismatch');
  const mismatchedVerification = await tasks.verify(
    mismatched.settledRetest.taskId,
    mismatched.retestPreview.sha256,
    reviews,
  );
  assert.equal(mismatchedVerification.status, 'failed');
  assert.equal(
    mismatchedVerification.checks.find(check => check.criterionId === 'model-identity')?.status,
    'failed',
  );
  await assert.rejects(
    () => tasks.integrate(mismatched.settledRetest.taskId, mismatched.retestPreview.sha256, async () => true),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'VERIFICATION_REQUIRED' &&
      err.message.includes('Model proof failed') &&
      !err.message.includes('Model proof failed: Model proof failed'),
  );

  const echoed = await runWriteAndRetest('requested-model-1', 'conv-copy-echo');
  const echoedVerification = await tasks.verify(
    echoed.settledRetest.taskId,
    echoed.retestPreview.sha256,
    reviews,
  );
  assert.equal(echoedVerification.status, 'passed');
  assert.equal(echoedVerification.checks.some(check => check.criterionId === 'model-identity'), false);
  const integrated = await tasks.integrate(echoed.settledRetest.taskId, echoed.retestPreview.sha256, async () => true);
  assert.equal(integrated.summary.added, 1);
});

test('copy-level modelProofFailure survives retention eviction and StateStore reload', async t => {
  const ws = createWorkspace(t);
  const lowRetentionConfig = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
    MAX_RETAINED_TASKS: '1',
  });
  const cli = new ControlledIdentityCliAdapter(lowRetentionConfig);
  const tasks = ws.track(new TaskManager(cli, lowRetentionConfig));

  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  cli.onSpawn = (_options, _model, cwd) => {
    writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
    return [
      { event: 'init', conversation_id: 'conv-evict-a', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-evict-a', response: 'done' } },
    ];
  };
  const taskA = await tasks.run({
    prompt: 'write file with mismatch before eviction',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    acceptanceCriteria: criteria,
  });
  const settledA = await waitForTask(tasks, taskA.taskId);
  assert.equal(settledA.status, 'completed');

  cli.onSpawn = () => [
    { event: 'init', conversation_id: 'conv-evict-a', init: { model: 'requested-model-1' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-evict-a', response: 'resumed ok' } },
  ];
  const taskB = await tasks.resume(
    {
      prompt: 'resume on same copy and evict A',
      workingDirectory: ws.repoDir,
      model: 'requested-model-1',
    },
    settledA.taskId,
  );
  const settledB = await waitForTask(tasks, taskB.taskId);
  assert.equal(settledB.status, 'completed');
  assert.deepEqual(settledB.execution?.observed, { model: null, status: 'not-observable' });

  assert.equal(tasks.list().some(item => item.taskId === settledA.taskId), false);
  assert.throws(
    () => tasks.status(settledA.taskId),
    (err: unknown) => err instanceof BridgeError && err.code === 'TASK_NOT_FOUND',
  );

  const previewB = await tasks.preview(settledB.taskId, false);
  const verifiedB = await tasks.verify(settledB.taskId, previewB.sha256, reviews);
  assert.equal(verifiedB.status, 'failed');
  assert.equal(verifiedB.checks.find(check => check.criterionId === 'model-identity')?.status, 'failed');
  await assert.rejects(
    () => tasks.integrate(settledB.taskId, previewB.sha256, async () => true),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'VERIFICATION_REQUIRED' &&
      err.message.includes('Model proof failed'),
  );

  await tasks.shutdown();

  const reloadedEntries = new StateStore(ws.stateDir).load();
  const storedB = reloadedEntries.find(item => item.record.taskId === settledB.taskId);
  assert.ok(storedB?.project?.modelProofFailure);
  assert.match(storedB.project.modelProofFailure, /Model proof failed/);

  const reloadedTasks = ws.track(new TaskManager(cli, lowRetentionConfig));
  const reloadedVerified = await reloadedTasks.verify(settledB.taskId, previewB.sha256, reviews);
  assert.equal(reloadedVerified.status, 'failed');
  assert.equal(reloadedVerified.checks.find(check => check.criterionId === 'model-identity')?.status, 'failed');
  await assert.rejects(
    () => reloadedTasks.integrate(settledB.taskId, previewB.sha256, async () => true),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'VERIFICATION_REQUIRED' &&
      err.message.includes('Model proof failed'),
  );
});

test('handoff fork inherits copy-level modelProofFailure even when forked task echoes requested model', async t => {
  const ws = createWorkspace(t);
  const cli = new ControlledIdentityCliAdapter(ws.config);
  const tasks = ws.track(new TaskManager(cli, ws.config));

  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  cli.onSpawn = (_options, _model, cwd) => {
    writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
    return [
      { event: 'init', conversation_id: 'conv-handoff-src', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-handoff-src', response: 'done' } },
    ];
  };
  const source = await tasks.run({
    prompt: 'source write task with mismatch',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    acceptanceCriteria: criteria,
  });
  const settledSource = await waitForTask(tasks, source.taskId);
  assert.equal(settledSource.status, 'completed');

  const ctx = await tasks.context(settledSource.taskId);
  cli.onSpawn = () => [
    { event: 'init', conversation_id: 'conv-handoff-fork', init: { model: 'requested-model-1' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-handoff-fork', response: 'fork done' } },
  ];
  const forked = await tasks.run({
    contextTaskId: settledSource.taskId,
    expectedContextSha256: ctx.treeSha256,
    prompt: 'handoff implementer task with echo',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    model: 'requested-model-1',
  });
  const settledFork = await waitForTask(tasks, forked.taskId);
  assert.equal(settledFork.status, 'completed');
  assert.notEqual(settledFork.copyDirectory, settledSource.copyDirectory);
  assert.deepEqual(settledFork.execution?.observed, { model: null, status: 'not-observable' });

  const forkPreview = await tasks.preview(settledFork.taskId, false);
  const forkVerified = await tasks.verify(settledFork.taskId, forkPreview.sha256, reviews);
  assert.equal(forkVerified.status, 'failed');
  assert.equal(forkVerified.checks.find(check => check.criterionId === 'model-identity')?.status, 'failed');
  await assert.rejects(
    () => tasks.integrate(settledFork.taskId, forkPreview.sha256, async () => true),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'VERIFICATION_REQUIRED' &&
      err.message.includes('Model proof failed'),
  );

  await tasks.shutdown();
  const storedFork = new StateStore(ws.stateDir).load().find(item => item.record.taskId === settledFork.taskId);
  assert.ok(storedFork?.project?.modelProofFailure);
  assert.match(storedFork.project.modelProofFailure, /Model proof failed/);
});

test('reloaded legacy mismatch snapshot without project.modelProofFailure blocks verify and integrate after eviction', async t => {
  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  {
    const ws = createWorkspace(t);
    const lowRetentionConfig = loadConfig({
      BRIDGE_STATE_DIRECTORY: ws.stateDir,
      BRIDGE_TEST_EXECUTOR: 'agy',
      AGY_PATH: process.execPath,
      MAX_RETAINED_TASKS: '1',
    });
    const cli = new ControlledIdentityCliAdapter(lowRetentionConfig);
    const initialTasks = ws.track(new TaskManager(cli, lowRetentionConfig));

    cli.onSpawn = (_options, _model, cwd) => {
      writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
      return [
        { event: 'init', conversation_id: 'conv-legacy-evict', init: { model: 'observed-model-x' } },
        { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-legacy-evict', response: 'done' } },
      ];
    };
    const taskA = await initialTasks.run({
      prompt: 'legacy mismatch task before reload',
      workingDirectory: ws.repoDir,
      model: 'requested-model-1',
      acceptanceCriteria: criteria,
    });
    const settledA = await waitForTask(initialTasks, taskA.taskId);
    assert.equal(settledA.status, 'completed');
    await initialTasks.shutdown();

    const snapshotPath = path.join(ws.stateDir, `${settledA.taskId}.json`);
    const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
      project?: { modelProofFailure?: string };
    };
    assert.ok(snapshot.project?.modelProofFailure);
    delete snapshot.project.modelProofFailure;
    writeFileSync(snapshotPath, JSON.stringify(snapshot), 'utf8');

    const storedBeforeReload = new StateStore(ws.stateDir).load().find(item => item.record.taskId === settledA.taskId);
    assert.equal(storedBeforeReload?.project?.modelProofFailure, undefined);
    assert.deepEqual(storedBeforeReload?.record.execution?.observed, { model: 'observed-model-x', status: 'observed' });

    const reloadedTasks = ws.track(new TaskManager(cli, lowRetentionConfig));
    cli.onSpawn = () => [
      { event: 'init', conversation_id: 'conv-legacy-evict', init: { model: 'requested-model-1' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-legacy-evict', response: 'resumed ok' } },
    ];
    const taskB = await reloadedTasks.resume(
      {
        prompt: 'resume reloaded legacy mismatch and evict A',
        workingDirectory: ws.repoDir,
        model: 'requested-model-1',
      },
      settledA.taskId,
    );
    const settledB = await waitForTask(reloadedTasks, taskB.taskId);
    assert.equal(settledB.status, 'completed');
    assert.equal(reloadedTasks.list().some(item => item.taskId === settledA.taskId), false);

    const previewB = await reloadedTasks.preview(settledB.taskId, false);
    const verifiedB = await reloadedTasks.verify(settledB.taskId, previewB.sha256, reviews);
    assert.equal(verifiedB.status, 'failed');
    assert.equal(verifiedB.checks.find(check => check.criterionId === 'model-identity')?.status, 'failed');
    await assert.rejects(
      () => reloadedTasks.integrate(settledB.taskId, previewB.sha256, async () => true),
      (err: unknown) =>
        err instanceof BridgeError &&
        err.code === 'VERIFICATION_REQUIRED' &&
        err.message.includes('Model proof failed'),
    );
  }

  {
    const ws = createWorkspace(t);
    const lowRetentionConfig = loadConfig({
      BRIDGE_STATE_DIRECTORY: ws.stateDir,
      BRIDGE_TEST_EXECUTOR: 'agy',
      AGY_PATH: process.execPath,
      MAX_RETAINED_TASKS: '1',
    });
    const cli = new ControlledIdentityCliAdapter(lowRetentionConfig);
    const initialTasks = ws.track(new TaskManager(cli, lowRetentionConfig));

    cli.onSpawn = (_options, _model, cwd) => {
      writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
      return [
        { event: 'init', conversation_id: 'conv-legacy-ctrl', init: { model: 'requested-model-1' } },
        { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-legacy-ctrl', response: 'done' } },
      ];
    };
    const taskC = await initialTasks.run({
      prompt: 'control non-mismatch task before reload',
      workingDirectory: ws.repoDir,
      model: 'requested-model-1',
      acceptanceCriteria: criteria,
    });
    const settledC = await waitForTask(initialTasks, taskC.taskId);
    assert.equal(settledC.status, 'completed');
    await initialTasks.shutdown();

    const storedControl = new StateStore(ws.stateDir).load().find(item => item.record.taskId === settledC.taskId);
    assert.equal(storedControl?.project?.modelProofFailure, undefined);

    const reloadedTasks = ws.track(new TaskManager(cli, lowRetentionConfig));
    cli.onSpawn = () => [
      { event: 'init', conversation_id: 'conv-legacy-ctrl', init: { model: 'requested-model-1' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-legacy-ctrl', response: 'resumed ok' } },
    ];
    const taskD = await reloadedTasks.resume(
      {
        prompt: 'resume reloaded control and evict C',
        workingDirectory: ws.repoDir,
        model: 'requested-model-1',
      },
      settledC.taskId,
    );
    const settledD = await waitForTask(reloadedTasks, taskD.taskId);
    assert.equal(settledD.status, 'completed');
    assert.equal(reloadedTasks.list().some(item => item.taskId === settledC.taskId), false);

    const previewD = await reloadedTasks.preview(settledD.taskId, false);
    const verifiedD = await reloadedTasks.verify(settledD.taskId, previewD.sha256, reviews);
    assert.equal(verifiedD.status, 'passed');
    assert.equal(verifiedD.checks.some(check => check.criterionId === 'model-identity'), false);
    const integratedD = await reloadedTasks.integrate(settledD.taskId, previewD.sha256, async () => true);
    assert.equal(integratedD.summary.added, 1);
  }
});

test('reloaded legacy mismatch A and echo continuation B persist project.modelProofFailure onto B so evicting A by C survives refresh', async t => {
  const ws = createWorkspace(t);
  const retention2Config = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
    MAX_RETAINED_TASKS: '2',
  });
  const cli = new ControlledIdentityCliAdapter(retention2Config);
  const initialTasks = ws.track(new TaskManager(cli, retention2Config));

  const criteria = [
    {
      id: 'created',
      description: 'Create OUTPUT.txt with expected text',
      check: { kind: 'file-contains' as const, path: 'OUTPUT.txt', text: 'verified-output' },
    },
  ];
  const reviews = [
    {
      criterionId: 'created',
      verdict: 'passed' as const,
      path: 'OUTPUT.txt',
      line: 1,
      quote: 'verified-output',
      explanation: 'Confirmed created artifact content',
    },
  ];

  cli.onSpawn = (_options, _model, cwd) => {
    writeFileSync(path.join(cwd, 'OUTPUT.txt'), 'verified-output\n', 'utf8');
    return [
      { event: 'init', conversation_id: 'conv-ab-legacy', init: { model: 'observed-model-x' } },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-ab-legacy', response: 'done A' } },
    ];
  };
  const taskA = await initialTasks.run({
    prompt: 'legacy task A with mismatch',
    workingDirectory: ws.repoDir,
    model: 'requested-model-1',
    acceptanceCriteria: criteria,
  });
  const settledA = await waitForTask(initialTasks, taskA.taskId);
  assert.equal(settledA.status, 'completed');

  cli.onSpawn = () => [
    { event: 'init', conversation_id: 'conv-ab-legacy', init: { model: 'requested-model-1' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-ab-legacy', response: 'done B' } },
  ];
  const taskB = await initialTasks.resume(
    {
      prompt: 'legacy continuation B with echo',
      workingDirectory: ws.repoDir,
      model: 'requested-model-1',
    },
    settledA.taskId,
  );
  const settledB = await waitForTask(initialTasks, taskB.taskId);
  assert.equal(settledB.status, 'completed');
  assert.equal(settledB.copyDirectory, settledA.copyDirectory);
  assert.deepEqual(settledB.execution?.observed, { model: null, status: 'not-observable' });
  await initialTasks.shutdown();

  for (const taskId of [settledA.taskId, settledB.taskId]) {
    const file = path.join(ws.stateDir, `${taskId}.json`);
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { project?: { modelProofFailure?: string } };
    delete parsed.project?.modelProofFailure;
    writeFileSync(file, JSON.stringify(parsed), 'utf8');
  }
  const beforeReload = new StateStore(ws.stateDir).load();
  assert.equal(beforeReload.find(item => item.record.taskId === settledA.taskId)?.project?.modelProofFailure, undefined);
  assert.equal(beforeReload.find(item => item.record.taskId === settledB.taskId)?.project?.modelProofFailure, undefined);

  const reloadedTasks = ws.track(new TaskManager(cli, retention2Config));
  const diskB = JSON.parse(readFileSync(path.join(ws.stateDir, `${settledB.taskId}.json`), 'utf8')) as {
    project?: { modelProofFailure?: string };
  };
  assert.ok(diskB.project?.modelProofFailure);
  assert.match(diskB.project.modelProofFailure, /Model proof failed/);

  cli.onSpawn = () => [
    { event: 'init', conversation_id: 'conv-c-evict', init: { model: 'requested-model-1' } },
    { event: 'result', result: { status: 'SUCCESS', conversation_id: 'conv-c-evict', response: 'done C' } },
  ];
  const taskC = await reloadedTasks.run({
    prompt: 'independent task C to evict A',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'requested-model-1',
  });
  const settledC = await waitForTask(reloadedTasks, taskC.taskId);
  assert.equal(settledC.status, 'completed');

  // Public list() and status() call refresh() after A has been evicted.
  const listed = reloadedTasks.list();
  assert.equal(listed.some(item => item.taskId === settledA.taskId), false);
  assert.equal(listed.some(item => item.taskId === settledB.taskId), true);
  assert.equal(reloadedTasks.status(settledB.taskId).taskId, settledB.taskId);
  assert.throws(
    () => reloadedTasks.status(settledA.taskId),
    (err: unknown) => err instanceof BridgeError && err.code === 'TASK_NOT_FOUND',
  );

  const previewB = await reloadedTasks.preview(settledB.taskId, false);
  const verifiedB = await reloadedTasks.verify(settledB.taskId, previewB.sha256, reviews);
  assert.equal(verifiedB.status, 'failed');
  assert.equal(verifiedB.checks.find(check => check.criterionId === 'model-identity')?.status, 'failed');
  await assert.rejects(
    () => reloadedTasks.integrate(settledB.taskId, previewB.sha256, async () => true),
    (err: unknown) =>
      err instanceof BridgeError &&
      err.code === 'VERIFICATION_REQUIRED' &&
      err.message.includes('Model proof failed'),
  );
});
