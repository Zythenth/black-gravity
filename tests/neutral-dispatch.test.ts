import assert from 'node:assert/strict';
import { execFileSync, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { type Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { discardProjectCopy } from '../src/isolation.js';
import { createMcpServer } from '../src/mcp-server.js';
import { successOutputSchemas } from '../src/output-schemas.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import { TOOL_ANNOTATIONS, toolAnnotationRow, toolAnnotations } from '../src/tool-annotations.js';
import { type ToolProfile } from '../src/tool-profiles.js';
import { type RunOptions } from '../src/types.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { waitForTask } from './wait-for-task.js';

class DispatchTestAdapter extends ControlledCliAdapter {
  spawnCalls = 0;

  override async listModels(): Promise<Model[]> {
    return [
      { id: 'mock-pro', name: 'Mock Pro' },
      { id: 'mock-flash', name: 'Mock Flash' },
    ];
  }

  override spawnTask(options: RunOptions, _model: string | undefined, cwd: string): ChildProcessWithoutNullStreams {
    this.spawnCalls += 1;
    const child = new EventEmitter() as ChildProcessWithoutNullStreams;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const sessionId = options.sessionId ?? randomUUID();

    Object.assign(child, {
      stdin: new PassThrough(),
      stdout,
      stderr,
      pid: undefined,
      exitCode: null,
      killed: false,
      kill: () => {
        Object.assign(child, { exitCode: 0, killed: true });
        child.emit('close', 0);
        return true;
      },
    });

    setImmediate(() => {
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

      const structuredOutput = options.role === 'reviewer'
        ? { summary: 'Fixture review', reviewedFiles: ['source.txt'], findings: [], unverified: [] }
        : undefined;

      stdout.write(JSON.stringify({ event: 'init', conversation_id: sessionId }) + '\n');
      stdout.write(JSON.stringify({
        event: 'result',
        result: {
          status: 'SUCCESS',
          conversation_id: sessionId,
          response: 'ok',
          ...(structuredOutput ? { structured_output: structuredOutput } : {}),
        },
      }) + '\n');
      stdout.end();
      Object.assign(child, { exitCode: 0 });
      child.emit('close', 0);
    });

    return child;
  }
}

async function withServer(
  profile: ToolProfile,
  body: (ctx: {
    repoDir: string;
    stateDir: string;
    adapter: DispatchTestAdapter;
    tasks: TaskManager;
    client: Client;
  }) => Promise<void>,
) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-neutral-dispatch-'));
  const repoDir = path.join(root, 'repo');
  const stateDir = path.join(root, 'state');
  await mkdir(repoDir, { recursive: true });
  await mkdir(stateDir, { recursive: true });
  execFileSync('git', ['init', '--quiet'], { cwd: repoDir });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repoDir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: repoDir });
  execFileSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: repoDir });
  await writeFile(path.join(repoDir, 'source.txt'), 'source\n', 'utf8');
  execFileSync('git', ['add', '.'], { cwd: repoDir });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: repoDir });

  const config = loadConfig({
    BRIDGE_STATE_DIRECTORY: stateDir,
    BRIDGE_TOOL_PROFILE: profile,
    BRIDGE_TEST_EXECUTOR: 'agy',
  });
  const adapter = new DispatchTestAdapter(config);
  const tasks = new TaskManager(adapter, config);
  const server = createMcpServer(adapter, tasks);
  const client = new Client({ name: 'neutral-dispatch-test', version: '1.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  try {
    await body({ repoDir, stateDir, adapter, tasks, client });
  } finally {
    await client.close();
    await server.close();
    await tasks.shutdown();
    for (const project of new Map(
      new StateStore(stateDir).load().filter(item => item.project).map(item => [item.project!.copyDirectory, item.project!]),
    ).values()) {
      await discardProjectCopy(project);
    }
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('black-gravity-neutral-dispatch-'));
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test('tools/list publishes black_gravity_dispatch with strict provider schema and unchanged black_gravity_run', async () => {
  await withServer('full', async ({ client }) => {
    const listed = await client.listTools();
    const dispatchTool = listed.tools.find(tool => tool.name === 'black_gravity_dispatch');
    const runTool = listed.tools.find(tool => tool.name === 'black_gravity_run');
    assert.ok(dispatchTool);
    assert.ok(runTool);

    // Published black_gravity_run input schema before the neutral entry was added; a change here breaks compatibility.
    const runSchemaHash = createHash('sha256').update(JSON.stringify(runTool.inputSchema)).digest('hex');
    assert.equal(runSchemaHash, 'c91c3eb505d0c6aaf3b64e1c4201cfc211bc5b0ab3861830cd16bc500e8037d5');

    const providerSchema = dispatchTool.inputSchema.properties?.provider as { enum?: unknown } | undefined;
    assert.deepEqual(providerSchema?.enum, ['agy']);
    assert.ok(dispatchTool.inputSchema.required?.includes('provider'));
    assert.equal(dispatchTool.inputSchema.additionalProperties, false);

    const runKeys = Object.keys(runTool.inputSchema.properties ?? {}).sort();
    const dispatchKeysWithoutProvider = Object.keys(dispatchTool.inputSchema.properties ?? {})
      .filter(key => key !== 'provider')
      .sort();
    assert.equal(runKeys.includes('provider'), false);
    assert.deepEqual(dispatchKeysWithoutProvider, runKeys);

    const runProperties = (runTool.inputSchema.properties ?? {}) as Record<string, unknown>;
    const dispatchProperties = (dispatchTool.inputSchema.properties ?? {}) as Record<string, unknown>;
    for (const name of Object.keys(runProperties)) {
      assert.deepEqual(dispatchProperties[name], runProperties[name]);
    }
    assert.deepEqual([...(dispatchTool.inputSchema.required ?? [])].sort(), [...(runTool.inputSchema.required ?? []), 'provider'].sort());

    assert.equal(dispatchTool.title, toolAnnotationRow('black_gravity_dispatch').title);
    assert.equal(dispatchTool.title, TOOL_ANNOTATIONS.black_gravity_dispatch!.title);
    assert.deepEqual(dispatchTool.annotations, toolAnnotations('black_gravity_dispatch'));
    assert.deepEqual(dispatchTool.annotations, runTool.annotations);
  });
});

test('black_gravity_dispatch and black_gravity_run produce equivalent task controls and execution identities', async () => {
  await withServer('full', async ({ repoDir, tasks, client }) => {
    const commonArgs = {
      prompt: 'Inspect source.',
      workingDirectory: repoDir,
      mode: 'read-only' as const,
      role: 'reviewer',
      effort: 'high' as const,
      model: 'mock-pro',
      includePaths: ['source.txt'],
      acceptanceCriteria: [
        { id: 'source', description: 'Source file exists', check: { kind: 'file-exists' as const, path: 'source.txt' } },
      ],
      allowedTools: ['view_file' as const],
      deliveryMode: 'messages' as const,
    };

    const runRes = await client.callTool({ name: 'black_gravity_run', arguments: commonArgs });
    assert.equal(runRes.isError, undefined, JSON.stringify(runRes.structuredContent));
    const parsedRun = successOutputSchemas.black_gravity_run.parse(runRes.structuredContent);

    const dispatchRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', ...commonArgs },
    });
    assert.equal(dispatchRes.isError, undefined, JSON.stringify(dispatchRes.structuredContent));
    const parsedDispatch = successOutputSchemas.black_gravity_dispatch.parse(dispatchRes.structuredContent);

    const runSettled = await waitForTask(tasks, parsedRun.task.taskId);
    const dispatchSettled = await waitForTask(tasks, parsedDispatch.task.taskId);
    assert.equal(runSettled.status, 'completed', JSON.stringify(runSettled.error));
    assert.equal(dispatchSettled.status, 'completed', JSON.stringify(dispatchSettled.error));

    const runStatusRes = await client.callTool({ name: 'black_gravity_status', arguments: { taskId: parsedRun.task.taskId } });
    const dispatchStatusRes = await client.callTool({ name: 'black_gravity_status', arguments: { taskId: parsedDispatch.task.taskId } });
    assert.equal(runStatusRes.isError, undefined);
    assert.equal(dispatchStatusRes.isError, undefined);

    const runStatusTask = successOutputSchemas.black_gravity_status.parse(runStatusRes.structuredContent).task;
    const dispatchStatusTask = successOutputSchemas.black_gravity_status.parse(dispatchStatusRes.structuredContent).task;

    for (const field of ['mode', 'role', 'effort', 'model', 'deliveryMode', 'acceptanceCriteria', 'agentPolicy', 'includedFiles'] as const) {
      assert.deepEqual(dispatchStatusTask[field], runStatusTask[field], `status.${field} mismatch`);
    }

    const runInternal = tasks.status(parsedRun.task.taskId);
    const dispatchInternal = tasks.status(parsedDispatch.task.taskId);
    for (const field of ['mode', 'role', 'effort', 'model', 'deliveryMode', 'acceptanceCriteria', 'agentPolicy', 'includedFiles'] as const) {
      assert.deepEqual(dispatchInternal[field], runInternal[field], `internal.${field} mismatch`);
    }
    assert.ok(runInternal.execution);
    assert.ok(dispatchInternal.execution);
    assert.equal(dispatchInternal.execution.provider, runInternal.execution.provider);
    assert.equal(dispatchInternal.execution.adapterId, runInternal.execution.adapterId);
    assert.equal(dispatchInternal.execution.adapterVersion, runInternal.execution.adapterVersion);
  });
});

test('invalid dispatch inputs are rejected before creating a task or spawning an executor process', async () => {
  await withServer('full', async ({ repoDir, adapter, tasks, client }) => {
    const beforeCount = tasks.list().length;
    const beforeSpawns = adapter.spawnCalls;

    let gateCalls = 0;
    const originalUsable = tasks.isStateDirectoryUsable.bind(tasks);
    tasks.isStateDirectoryUsable = () => { gateCalls += 1; return originalUsable(); };
    let runCalls = 0;
    const originalRun = tasks.run.bind(tasks);
    tasks.run = (async (...runArgs: Parameters<TaskManager['run']>) => { runCalls += 1; return originalRun(...runArgs); }) as TaskManager['run'];

    const invalidCases: Array<Record<string, unknown>> = [
      { provider: 'codex', prompt: 'Invalid provider', workingDirectory: repoDir },
      { provider: 'agy', prompt: 'Unknown key', workingDirectory: repoDir, includePath: ['source.txt'] },
      { prompt: 'Missing provider', workingDirectory: repoDir },
      { provider: 'agy', prompt: 123, workingDirectory: repoDir },
    ];

    for (const args of invalidCases) {
      const res = await client.callTool({ name: 'black_gravity_dispatch', arguments: args });
      assert.equal(res.isError, true, `Expected error for ${JSON.stringify(args)}`);
    }

    assert.equal(gateCalls, 0, 'SDK must reject invalid input before bridge wrapper');
    assert.equal(runCalls, 0, 'SDK must reject invalid input before handler');

    const listedTasksRes = await client.callTool({ name: 'black_gravity_tasks', arguments: {} });
    assert.equal(listedTasksRes.isError, undefined);
    const listedTasks = successOutputSchemas.black_gravity_tasks.parse(listedTasksRes.structuredContent);
    assert.equal(listedTasks.tasks.length, beforeCount);
    assert.equal(tasks.list().length, beforeCount);
    assert.equal(adapter.spawnCalls, beforeSpawns);

    const controlRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', prompt: 'Valid control', workingDirectory: repoDir, mode: 'read-only' },
    });
    assert.equal(controlRes.isError, undefined, JSON.stringify(controlRes.structuredContent));
    const parsedControl = successOutputSchemas.black_gravity_dispatch.parse(controlRes.structuredContent);
    assert.ok(gateCalls >= 1);
    assert.equal(runCalls, 1);
    await waitForTask(tasks, parsedControl.task.taskId);
  });
});

test('dispatch shares profile availability and read-only enforcement with run', async () => {
  for (const profile of ['full', 'query', 'review', 'implementation'] as const) {
    await withServer(profile, async ({ repoDir, adapter, tasks, client }) => {
      const names = (await client.listTools()).tools.map(tool => tool.name);
      assert.ok(names.includes('black_gravity_dispatch'), profile);

      if (profile === 'query') {
        const runWrite = await client.callTool({
          name: 'black_gravity_run',
          arguments: { prompt: 'Write refused', workingDirectory: repoDir, mode: 'write' },
        });
        const dispatchWrite = await client.callTool({
          name: 'black_gravity_dispatch',
          arguments: { provider: 'agy', prompt: 'Write refused', workingDirectory: repoDir, mode: 'write' },
        });
        assert.equal(runWrite.isError, true);
        assert.equal(dispatchWrite.isError, true);
        const runCode = (runWrite.structuredContent as { error: { code: string } }).error.code;
        const dispatchCode = (dispatchWrite.structuredContent as { error: { code: string } }).error.code;
        assert.equal(runCode, 'PROFILE_READ_ONLY');
        assert.equal(dispatchCode, runCode);
        assert.equal(tasks.list().length, 0);
        assert.equal(adapter.spawnCalls, 0);
      }
    });
  }
});

test('dispatch always returns a compact task and frozen executor identity even in events mode', async () => {
  await withServer('full', async ({ repoDir, tasks, client }) => {
    const identity = tasks.executorIdentity;
    assert.equal(Object.isFrozen(identity), true);

    const args = {
      prompt: 'Legacy events delivery check',
      workingDirectory: repoDir,
      mode: 'read-only' as const,
      deliveryMode: 'events' as const,
    };

    const runRes = await client.callTool({ name: 'black_gravity_run', arguments: args });
    assert.equal(runRes.isError, undefined, JSON.stringify(runRes.structuredContent));
    const parsedRun = successOutputSchemas.black_gravity_run.parse(runRes.structuredContent);
    assert.equal(parsedRun.task.prompt, args.prompt);

    const dispatchRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: identity.provider, ...args },
    });
    assert.equal(dispatchRes.isError, undefined, JSON.stringify(dispatchRes.structuredContent));
    const parsedDispatch = successOutputSchemas.black_gravity_dispatch.parse(dispatchRes.structuredContent);
    assert.equal(parsedDispatch.task.prompt, undefined);
    assert.deepEqual(parsedDispatch.executor, {
      provider: identity.provider,
      adapterId: identity.id,
      adapterVersion: identity.version,
    });

    await waitForTask(tasks, parsedRun.task.taskId);
    await waitForTask(tasks, parsedDispatch.task.taskId);
  });
});
