import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
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

  override spawnTask(options: RunOptions, _model: string | undefined, _cwd: string): CliProcess {
    this.spawnCalls += 1;
    const sessionId = options.sessionId ?? 'session-default';
    const events = this.nextEvents ?? [
      { event: 'init', conversation_id: sessionId },
      { event: 'result', result: { status: 'SUCCESS', conversation_id: sessionId, response: 'ok' } },
    ];
    this.nextEvents = undefined;
    return createMockProcess(events);
  }

  override async listModels(): Promise<Model[]> {
    return [{ id: 'requested-model-1', name: 'Requested Model 1' }];
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
    BRIDGE_ANTI_AI_CRAFT: 'off',
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
