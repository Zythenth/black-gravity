import assert from 'node:assert/strict';
import { execFileSync, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test, type TestContext } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { taskPrompt, type Model } from '../src/cli-adapter.js';
import { loadConfig, type Config } from '../src/config.js';
import type { ExecutionAdapter, ExecutionRequest, ExecutionResult } from '../src/execution-contract.js';
import { discardProjectCopy } from '../src/isolation.js';
import { detectBubblewrap, type BubblewrapDetection } from '../src/linux-executor.js';
import { createMcpServer } from '../src/mcp-server.js';
import { OpenCodeExecutionAdapter, OPENCODE_ADAPTER_VERSION } from '../src/opencode-execution-adapter.js';
import { resolveOpenCodeRegistration } from '../src/opencode-registration.js';
import { successOutputSchemas } from '../src/output-schemas.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager, type ExecutorRegistration } from '../src/task-manager.js';
import { type RunOptions } from '../src/types.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { waitForTask } from './wait-for-task.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MOCK_OPENCODE = path.resolve(HERE, '../../tests/mock-opencode.mjs');
const SHIPPED_SKILL_MD = path.resolve(HERE, '../../plugin/skills/black-gravity/SKILL.md');

interface AgyCallRecord {
  options: RunOptions;
  prompt: string;
  cwd: string;
  finish?: () => void;
}

class MockAgyCliAdapter extends ControlledCliAdapter {
  calls: AgyCallRecord[] = [];
  private readonly maxPromptChars: number;

  constructor(config: Config) {
    super(config);
    this.maxPromptChars = config.maxPromptChars;
  }

  override async listModels(): Promise<Model[]> {
    return [
      { id: 'mock-pro', name: 'Mock Pro' },
      { id: 'mock-flash', name: 'Mock Flash' },
    ];
  }

  override spawnTask(options: RunOptions, _model: string | undefined, cwd: string): ChildProcessWithoutNullStreams {
    const child = new EventEmitter() as ChildProcessWithoutNullStreams;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const sessionId = options.sessionId ?? randomUUID();
    const renderedPrompt = taskPrompt(options, this.maxPromptChars);

    Object.assign(child, {
      stdin: new PassThrough(),
      stdout,
      stderr,
      pid: undefined,
      exitCode: null,
      killed: false,
      kill: () => {
        if (child.exitCode !== null) return true;
        Object.assign(child, { exitCode: 0, killed: true });
        child.emit('close', 0);
        return true;
      },
    });

    const complete = () => {
      if (child.exitCode !== null) return;
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
      const createMatch = options.prompt.match(/CREATE_AGY_FILE:([^\r\n]+)/);
      if (createMatch && options.mode !== 'read-only') {
        const relPath = createMatch[1]!.trim();
        void writeFile(path.join(cwd, relPath), 'created-by-agy\n', 'utf8').then(() => {
          emitSuccess();
        });
        return;
      }
      emitSuccess();
    };

    const emitSuccess = () => {
      if (child.exitCode !== null) return;
      stdout.write(JSON.stringify({ event: 'init', conversation_id: sessionId }) + '\n');
      stdout.write(JSON.stringify({
        event: 'result',
        result: {
          status: 'SUCCESS',
          conversation_id: sessionId,
          response: 'agy ok',
          ...(options.role === 'planner' ? {
            structured_output: {
              summary: 'plan',
              steps: [{ description: 'inspect', files: ['source.txt'], verification: 'read' }],
              unverified: [],
            },
          } : {}),
        },
      }) + '\n');
      stdout.end();
      Object.assign(child, { exitCode: 0 });
      child.emit('close', 0);
    };

    const hold = options.prompt.includes('HOLD_AGY');
    const record: AgyCallRecord = {
      options: structuredClone(options),
      prompt: renderedPrompt,
      cwd,
      ...(hold ? { finish: complete } : {}),
    };
    this.calls.push(record);

    if (hold) {
      setImmediate(() => {
        stdout.write(JSON.stringify({ event: 'init', conversation_id: sessionId }) + '\n');
      });
    } else {
      setImmediate(complete);
    }

    return child;
  }
}

async function initGitRepo(repoDir: string): Promise<void> {
  await mkdir(repoDir, { recursive: true });
  execFileSync('git', ['init', '--quiet'], { cwd: repoDir });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repoDir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: repoDir });
  execFileSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: repoDir });
  await writeFile(path.join(repoDir, 'source.txt'), 'source\n', 'utf8');
  execFileSync('git', ['add', '.'], { cwd: repoDir });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: repoDir });
}

async function waitUntil(predicate: () => boolean, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('Timed out waiting for condition');
    }
    await delay(20);
  }
}

function mockOpenCodeAdapter(options: { scenario: string; recordFile?: string; spawnLog?: string }): OpenCodeExecutionAdapter {
  return new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [
      MOCK_OPENCODE,
      ...(options.recordFile ? ['--record', options.recordFile] : []),
      ...(options.spawnLog ? ['--spawn-log', options.spawnLog] : []),
      '--scenario',
      options.scenario,
    ],
  });
}

async function withBridge(
  opts: {
    env?: Record<string, string>;
    executors?: ReadonlyArray<ExecutorRegistration>;
    extraRepos?: number;
    linuxBwrapDetection?: BubblewrapDetection;
  },
  body: (ctx: {
    root: string;
    repoDir: string;
    extraRepos: string[];
    stateDir: string;
    config: Config;
    adapter: MockAgyCliAdapter;
    tasks: TaskManager;
    client: Client;
  }) => Promise<void>,
) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-exec-dispatch-'));
  const repoDir = path.join(root, 'repo');
  const stateDir = path.join(root, 'state');
  const extraRepos: string[] = [];
  await initGitRepo(repoDir);
  for (let i = 0; i < (opts.extraRepos ?? 0); i++) {
    const dir = path.join(root, `repo-${i + 2}`);
    await initGitRepo(dir);
    extraRepos.push(dir);
  }
  await mkdir(stateDir, { recursive: true });

  const config = loadConfig({
    BRIDGE_STATE_DIRECTORY: stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    ...opts.env,
  });
  const adapter = new MockAgyCliAdapter(config);
  const executors = opts.executors ?? [
    { provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'read' }) },
  ];
  const tasks = new TaskManager(adapter, config, undefined, {
    executors,
    ...(opts.linuxBwrapDetection ? { linuxBwrapDetection: opts.linuxBwrapDetection } : {}),
  });
  const server = createMcpServer(adapter, tasks);
  const client = new Client({ name: 'executor-dispatch-test', version: '1.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  try {
    await body({ root, repoDir, extraRepos, stateDir, config, adapter, tasks, client });
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
    assert.ok(path.basename(root).startsWith('black-gravity-exec-dispatch-'));
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test('M1) tools/list exposes agy and opencode providers with unchanged black_gravity_run schema', async () => {
  await withBridge({}, async ({ client }) => {
    const listed = await client.listTools();
    assert.equal(listed.tools.length, 53);

    const dispatchTool = listed.tools.find(t => t.name === 'black_gravity_dispatch');
    const runTool = listed.tools.find(t => t.name === 'black_gravity_run');
    const handoffTool = listed.tools.find(t => t.name === 'black_gravity_handoff');
    const getModelTool = listed.tools.find(t => t.name === 'black_gravity_get_model');
    const setModelTool = listed.tools.find(t => t.name === 'black_gravity_set_model');
    const listModelsTool = listed.tools.find(t => t.name === 'black_gravity_list_models');

    assert.ok(dispatchTool && runTool && handoffTool && getModelTool && setModelTool && listModelsTool);

    const runSchemaHash = createHash('sha256').update(JSON.stringify(runTool.inputSchema)).digest('hex');
    assert.equal(runSchemaHash, 'c91c3eb505d0c6aaf3b64e1c4201cfc211bc5b0ab3861830cd16bc500e8037d5');

    const dispatchProvider = dispatchTool.inputSchema.properties?.provider as { enum?: unknown } | undefined;
    assert.deepEqual(dispatchProvider?.enum, ['agy', 'opencode']);

    for (const tool of [handoffTool, getModelTool, setModelTool, listModelsTool]) {
      const prop = tool.inputSchema.properties?.provider as { enum?: unknown } | undefined;
      assert.deepEqual(prop?.enum, ['agy', 'opencode'], tool.name);
      assert.equal(tool.inputSchema.required?.includes('provider') ?? false, false, tool.name);
    }
  });
});

test('M2) dispatch provider opencode write -> wait -> preview -> verify -> integrate -> status/result/discard', async () => {
  await withBridge({
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'write-inside' }) }],
  }, async ({ repoDir, tasks, client }) => {
    const dispatchRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: 'Write created-by-opencode.txt',
        workingDirectory: repoDir,
        mode: 'write',
        acceptanceCriteria: [
          {
            id: 'ac1',
            description: 'File created-by-opencode.txt exists',
            check: { kind: 'file-exists', path: 'created-by-opencode.txt' },
          },
        ],
      },
    });
    assert.equal(dispatchRes.isError, undefined, JSON.stringify(dispatchRes.structuredContent));
    const parsedDispatch = successOutputSchemas.black_gravity_dispatch.parse(dispatchRes.structuredContent);
    assert.equal(parsedDispatch.executor.provider, 'opencode');
    const taskId = parsedDispatch.task.taskId;

    const waitRes = await client.callTool({
      name: 'black_gravity_wait',
      arguments: { taskId, timeoutSeconds: 30 },
    });
    assert.equal(waitRes.isError, undefined, JSON.stringify(waitRes.structuredContent));
    const parsedWait = successOutputSchemas.black_gravity_wait.parse(waitRes.structuredContent);
    assert.equal(parsedWait.status, 'completed');

    const statusRes = await client.callTool({ name: 'black_gravity_status', arguments: { taskId } });
    assert.equal(statusRes.isError, undefined);
    successOutputSchemas.black_gravity_status.parse(statusRes.structuredContent);
    assert.equal(tasks.status(taskId).execution?.provider, 'opencode');

    const resultRes = await client.callTool({ name: 'black_gravity_result', arguments: { taskId } });
    assert.equal(resultRes.isError, undefined);
    const parsedResult = successOutputSchemas.black_gravity_result.parse(resultRes.structuredContent);
    assert.equal(parsedResult.ready, true);

    const previewRes = await client.callTool({ name: 'black_gravity_preview', arguments: { taskId } });
    assert.equal(previewRes.isError, undefined);
    const parsedPreview = successOutputSchemas.black_gravity_preview.parse(previewRes.structuredContent);
    assert.deepEqual(parsedPreview.files, [{ status: 'A', path: 'created-by-opencode.txt' }]);

    const verifyRes = await client.callTool({
      name: 'black_gravity_verify',
      arguments: {
        taskId,
        expectedSha256: parsedPreview.sha256,
        reviews: [
          {
            criterionId: 'ac1',
            verdict: 'passed',
            path: 'created-by-opencode.txt',
            line: 1,
            quote: 'opencode write fixture',
            explanation: 'Verified created-by-opencode.txt',
          },
        ],
      },
    });
    assert.equal(verifyRes.isError, undefined);
    assert.equal(successOutputSchemas.black_gravity_verify.parse(verifyRes.structuredContent).status, 'passed');

    const integrateRes = await client.callTool({
      name: 'black_gravity_integrate',
      arguments: { taskId, expectedSha256: parsedPreview.sha256 },
    });
    assert.equal(integrateRes.isError, undefined, JSON.stringify(integrateRes.structuredContent));
    successOutputSchemas.black_gravity_integrate.parse(integrateRes.structuredContent);
    assert.equal(await readFile(path.join(repoDir, 'created-by-opencode.txt'), 'utf8'), 'opencode write fixture\n');

    const discardRes = await client.callTool({ name: 'black_gravity_discard', arguments: { taskId } });
    assert.equal(discardRes.isError, undefined);
    assert.ok(successOutputSchemas.black_gravity_discard.parse(discardRes.structuredContent).task.discardedAt);
  });
});

test('M3) model of one executor is refused on the other naming the executor and creates no task', async () => {
  await withBridge({}, async ({ repoDir, tasks, client }) => {
    const agyOnOpenCode = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: 'Wrong model',
        workingDirectory: repoDir,
        mode: 'read-only',
        model: 'mock-pro',
      },
    });
    assert.equal(agyOnOpenCode.isError, true);
    const err1 = (agyOnOpenCode.structuredContent as { error: { code: string; message: string } }).error;
    assert.equal(err1.code, 'MODEL_NOT_AVAILABLE');
    assert.ok(err1.message.includes('opencode'), err1.message);

    const openCodeOnAgy = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'agy',
        prompt: 'Wrong model',
        workingDirectory: repoDir,
        mode: 'read-only',
        model: 'opencode-go/mock-flash',
      },
    });
    assert.equal(openCodeOnAgy.isError, true);
    const err2 = (openCodeOnAgy.structuredContent as { error: { code: string; message: string } }).error;
    assert.equal(err2.code, 'MODEL_NOT_AVAILABLE');
    assert.ok(err2.message.includes('agy'), err2.message);

    const listRes = await client.callTool({ name: 'black_gravity_tasks', arguments: {} });
    assert.deepEqual(successOutputSchemas.black_gravity_tasks.parse(listRes.structuredContent).tasks, []);
    assert.equal(tasks.list().length, 0);
  });
});

test('M4) unavailable executor shows in health and refuses dispatch before any task or copy is created', async () => {
  const unavailableCases: Array<{
    name: string;
    makeExecutor: () => ExecutorRegistration;
    expectedReasonPart: string;
  }> = [
    {
      name: 'no-adapter',
      makeExecutor: () => ({
        provider: 'opencode',
        unavailableReason: 'OPENCODE_UNAVAILABLE: OpenCode executable not found; set OPENCODE_PATH',
      }),
      expectedReasonPart: 'OpenCode executable not found',
    },
    {
      name: 'availability-false',
      makeExecutor: () => {
        const unavailable: ExecutionAdapter = {
          identity: { id: 'opencode-cli', provider: 'opencode', version: OPENCODE_ADAPTER_VERSION },
          capabilities: { read: 'supported', write: 'supported' },
          async execute(request: ExecutionRequest): Promise<ExecutionResult> {
            return { taskId: request.taskId, status: 'completed', response: 'never' };
          },
          availability() {
            return { available: false, reason: 'OPENCODE_UNAVAILABLE: executable check failed' };
          },
        };
        return { provider: 'opencode', adapter: unavailable };
      },
      expectedReasonPart: 'executable check failed',
    },
    {
      name: 'missing-executable',
      makeExecutor: () => ({
        provider: 'opencode',
        adapter: new OpenCodeExecutionAdapter({
          executable: path.join(os.tmpdir(), `black-gravity-missing-opencode-${randomUUID()}`),
        }),
      }),
      expectedReasonPart: 'OPENCODE_UNAVAILABLE:',
    },
  ];

  for (const item of unavailableCases) {
    await withBridge({
      executors: [item.makeExecutor()],
    }, async ({ repoDir, tasks, client }) => {
      const healthRes = await client.callTool({ name: 'black_gravity_health', arguments: {} });
      assert.equal(healthRes.isError, undefined, item.name);
      const parsedHealth = successOutputSchemas.black_gravity_health.parse(healthRes.structuredContent);
      const ocHealth = parsedHealth.executors?.find(e => e.provider === 'opencode');
      assert.ok(ocHealth, item.name);
      assert.equal(ocHealth.available, false);
      assert.ok(ocHealth.reason?.includes(item.expectedReasonPart), ocHealth.reason ?? 'missing reason');

      const dispatchRes = await client.callTool({
        name: 'black_gravity_dispatch',
        arguments: {
          provider: 'opencode',
          prompt: 'Should refuse before lock or copy',
          workingDirectory: repoDir,
          mode: 'read-only',
        },
      });
      assert.equal(dispatchRes.isError, true, item.name);
      const err = (dispatchRes.structuredContent as { error: { code: string; message: string } }).error;
      assert.equal(err.code, 'EXECUTOR_UNAVAILABLE');
      assert.ok(err.message.includes('opencode'), err.message);
      assert.ok(err.message.includes(item.expectedReasonPart), err.message);

      const tasksRes = await client.callTool({ name: 'black_gravity_tasks', arguments: {} });
      assert.deepEqual(successOutputSchemas.black_gravity_tasks.parse(tasksRes.structuredContent).tasks, []);
      assert.equal(tasks.list().length, 0);
    });
  }
});

test('M5) saved model preference is isolated per provider and used when model is omitted', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-exec-models-'));
  const recFile = path.join(root, 'opencode-record.json');
  try {
    await withBridge({
      executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'read', recordFile: recFile }) }],
    }, async ({ repoDir, stateDir, tasks, client }) => {
      const agyModelFile = path.join(stateDir, 'model-selection.json');
      const agyBytes = Buffer.from(JSON.stringify({ version: 1, model: 'mock-pro' }), 'utf8');
      await writeFile(agyModelFile, agyBytes);

      const getAgy = await client.callTool({ name: 'black_gravity_get_model', arguments: { provider: 'agy' } });
      assert.deepEqual(successOutputSchemas.black_gravity_get_model.parse(getAgy.structuredContent), {
        model: 'mock-pro',
        provider: 'agy',
      });

      const getOcBefore = await client.callTool({ name: 'black_gravity_get_model', arguments: { provider: 'opencode' } });
      assert.deepEqual(successOutputSchemas.black_gravity_get_model.parse(getOcBefore.structuredContent), {
        model: null,
        provider: 'opencode',
      });

      const setOc = await client.callTool({
        name: 'black_gravity_set_model',
        arguments: { provider: 'opencode', model: 'opencode-go/mock-flash' },
      });
      assert.equal(setOc.isError, undefined, JSON.stringify(setOc.structuredContent));
      assert.deepEqual(successOutputSchemas.black_gravity_set_model.parse(setOc.structuredContent), {
        model: 'opencode-go/mock-flash',
        provider: 'opencode',
      });

      assert.deepEqual(await readFile(agyModelFile), agyBytes);
      const ocModelFile = path.join(stateDir, 'model-selection-opencode.json');
      assert.deepEqual(JSON.parse(await readFile(ocModelFile, 'utf8')), {
        version: 1,
        model: 'opencode-go/mock-flash',
      });

      const getOcAfter = await client.callTool({ name: 'black_gravity_get_model', arguments: { provider: 'opencode' } });
      assert.deepEqual(successOutputSchemas.black_gravity_get_model.parse(getOcAfter.structuredContent), {
        model: 'opencode-go/mock-flash',
        provider: 'opencode',
      });

      const dispatchRes = await client.callTool({
        name: 'black_gravity_dispatch',
        arguments: {
          provider: 'opencode',
          prompt: 'READ:source.txt',
          workingDirectory: repoDir,
          mode: 'read-only',
        },
      });
      assert.equal(dispatchRes.isError, undefined, JSON.stringify(dispatchRes.structuredContent));
      const dispatched = successOutputSchemas.black_gravity_dispatch.parse(dispatchRes.structuredContent);
      assert.equal(dispatched.task.model, 'opencode-go/mock-flash');

      const settled = await waitForTask(tasks, dispatched.task.taskId);
      assert.equal(settled.status, 'completed', JSON.stringify(settled.error));
      const rec = JSON.parse(await readFile(recFile, 'utf8')) as { argv: string[] };
      const modelIdx = rec.argv.indexOf('--model');
      assert.ok(modelIdx >= 0 && rec.argv[modelIdx + 1] === 'opencode-go/mock-flash');

      // Clearing saved opencode model runs without --model
      const clearOc = await client.callTool({
        name: 'black_gravity_set_model',
        arguments: { provider: 'opencode', model: null },
      });
      assert.equal(clearOc.isError, undefined);
      const dispatchNoModel = await client.callTool({
        name: 'black_gravity_dispatch',
        arguments: {
          provider: 'opencode',
          prompt: 'READ:source.txt',
          workingDirectory: repoDir,
          mode: 'read-only',
        },
      });
      assert.equal(dispatchNoModel.isError, undefined);
      const noModelId = successOutputSchemas.black_gravity_dispatch.parse(dispatchNoModel.structuredContent).task.taskId;
      const settledNoModel = await waitForTask(tasks, noModelId);
      assert.equal(settledNoModel.status, 'completed');
      const rec2 = JSON.parse(await readFile(recFile, 'utf8')) as { argv: string[] };
      assert.equal(rec2.argv.includes('--model'), false);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('M6) black_gravity_run stays on agy even when opencode is registered', async () => {
  await withBridge({}, async ({ repoDir, tasks, client }) => {
    const runRes = await client.callTool({
      name: 'black_gravity_run',
      arguments: {
        prompt: 'Primary run check',
        workingDirectory: repoDir,
        mode: 'read-only',
      },
    });
    assert.equal(runRes.isError, undefined, JSON.stringify(runRes.structuredContent));
    const parsed = successOutputSchemas.black_gravity_run.parse(runRes.structuredContent);
    const settled = await waitForTask(tasks, parsed.task.taskId);
    assert.equal(settled.status, 'completed');
    assert.equal(settled.execution?.provider, 'agy');
  });
});

test('M7) black_gravity_capabilities reports executors with their declared capabilities', async () => {
  await withBridge({}, async ({ adapter, client }) => {
    await adapter.discover();
    const capRes = await client.callTool({ name: 'black_gravity_capabilities', arguments: {} });
    assert.equal(capRes.isError, undefined, JSON.stringify(capRes.structuredContent));
    const parsed = successOutputSchemas.black_gravity_capabilities.parse(capRes.structuredContent);
    assert.equal(parsed.clis.length, 1);
    assert.equal(parsed.executors?.length, 2);

    const agy = parsed.executors!.find(e => e.provider === 'agy');
    const oc = parsed.executors!.find(e => e.provider === 'opencode');
    assert.ok(agy && oc);
    assert.equal(agy.primary, true);
    assert.equal(agy.capabilities.sandbox, 'supported');
    assert.equal(oc.primary, false);
    assert.equal(oc.capabilities.write, 'supported');
    assert.equal(oc.capabilities.sandbox, 'unsupported');
    assert.equal(oc.capabilities.modelList, 'supported');
  });

  await withBridge({
    executors: [{ provider: 'opencode', unavailableReason: 'OPENCODE_UNAVAILABLE: missing' }],
  }, async ({ client }) => {
    const capRes = await client.callTool({ name: 'black_gravity_capabilities', arguments: {} });
    const parsed = successOutputSchemas.black_gravity_capabilities.parse(capRes.structuredContent);
    const oc = parsed.executors?.find(e => e.provider === 'opencode');
    assert.ok(oc);
    assert.equal(oc.available, false);
    assert.deepEqual(oc.capabilities, {});
  });
});

test('M8) handoff agy -> opencode carries copy files and handoff block without session reuse', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-exec-m8-'));
  const recFile = path.join(root, 'handoff-opencode.json');
  try {
    await withBridge({
      executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'read', recordFile: recFile }) }],
    }, async ({ repoDir, tasks, client }) => {
      const agyRes = await client.callTool({
        name: 'black_gravity_dispatch',
        arguments: {
          provider: 'agy',
          prompt: 'CREATE_AGY_FILE:from-agy.txt',
          workingDirectory: repoDir,
          mode: 'write',
        },
      });
      const agyTaskId = successOutputSchemas.black_gravity_dispatch.parse(agyRes.structuredContent).task.taskId;
      const agySettled = await waitForTask(tasks, agyTaskId);
      assert.equal(agySettled.status, 'completed', JSON.stringify(agySettled.error));

      const ctxRes = await client.callTool({ name: 'black_gravity_context', arguments: { taskId: agyTaskId } });
      const ctx = successOutputSchemas.black_gravity_context.parse(ctxRes.structuredContent);

      const handoffRes = await client.callTool({
        name: 'black_gravity_handoff',
        arguments: {
          sourceTaskId: agyTaskId,
          expectedContextSha256: ctx.treeSha256,
          provider: 'opencode',
          role: 'implementer',
          prompt: 'READ:from-agy.txt',
        },
      });
      assert.equal(handoffRes.isError, undefined, JSON.stringify(handoffRes.structuredContent));
      const ocTaskId = successOutputSchemas.black_gravity_handoff.parse(handoffRes.structuredContent).task.taskId;
      const ocSettled = await waitForTask(tasks, ocTaskId);
      assert.equal(ocSettled.status, 'completed', JSON.stringify(ocSettled.error));
      assert.equal(ocSettled.execution?.provider, 'opencode');
      assert.equal(ocSettled.handoff?.sourceTaskId, agyTaskId);
      assert.equal(existsSync(path.join(ocSettled.copyDirectory!, 'from-agy.txt')), true);

      const rec = JSON.parse(await readFile(recFile, 'utf8')) as { argv: string[]; stdin: string };
      assert.equal(rec.argv.includes('--session'), false);
      assert.ok(rec.stdin.includes('Previous task context'));
      assert.ok(rec.stdin.includes(agyTaskId));
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('M9) handoff opencode -> agy carries copy files and taskPrompt handoff without session reuse', async () => {
  await withBridge({
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'write-inside' }) }],
  }, async ({ repoDir, adapter, tasks, client }) => {
    const ocRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: 'Create created-by-opencode.txt',
        workingDirectory: repoDir,
        mode: 'write',
      },
    });
    const ocTaskId = successOutputSchemas.black_gravity_dispatch.parse(ocRes.structuredContent).task.taskId;
    const ocSettled = await waitForTask(tasks, ocTaskId);
    assert.equal(ocSettled.status, 'completed', JSON.stringify(ocSettled.error));

    const ctxRes = await client.callTool({ name: 'black_gravity_context', arguments: { taskId: ocTaskId } });
    const ctx = successOutputSchemas.black_gravity_context.parse(ctxRes.structuredContent);

    const handoffRes = await client.callTool({
      name: 'black_gravity_handoff',
      arguments: {
        sourceTaskId: ocTaskId,
        expectedContextSha256: ctx.treeSha256,
        provider: 'agy',
        role: 'implementer',
        prompt: 'Continue from opencode copy',
      },
    });
    assert.equal(handoffRes.isError, undefined, JSON.stringify(handoffRes.structuredContent));
    const agyTaskId = successOutputSchemas.black_gravity_handoff.parse(handoffRes.structuredContent).task.taskId;
    const agySettled = await waitForTask(tasks, agyTaskId);
    assert.equal(agySettled.status, 'completed', JSON.stringify(agySettled.error));
    assert.equal(agySettled.execution?.provider, 'agy');
    assert.equal(agySettled.handoff?.sourceTaskId, ocTaskId);
    assert.equal(existsSync(path.join(agySettled.copyDirectory!, 'created-by-opencode.txt')), true);

    assert.equal(adapter.calls.length, 1);
    const agyCall = adapter.calls[0]!;
    assert.equal(agyCall.options.sessionId, undefined);
    assert.ok(agyCall.prompt.includes('Previous task context'));
    assert.ok(agyCall.prompt.includes(ocTaskId));
  });
});

test('M10) second task in the same project waits for agy+agy, agy+opencode, and opencode+opencode', async () => {
  // 1) agy + agy same project
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_CONCURRENT_OPENCODE_TASKS: '2' },
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'hold-write' }) }],
  }, async ({ repoDir, adapter, tasks, client }) => {
    const t1 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', prompt: 'HOLD_AGY 1', workingDirectory: repoDir, mode: 'read-only' },
    })).structuredContent).task;
    await waitUntil(() => adapter.calls.length === 1 && tasks.status(t1.taskId).status === 'running');

    const t2 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', prompt: 'Second agy', workingDirectory: repoDir, mode: 'read-only' },
    })).structuredContent).task;
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(adapter.calls.length, 1);

    adapter.calls[0]!.finish!();
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');
    assert.equal(adapter.calls.length, 2);
  });

  // 2) agy + opencode same project
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_CONCURRENT_OPENCODE_TASKS: '2' },
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'hold-write' }) }],
  }, async ({ root, repoDir, adapter, tasks, client }) => {
    const started2 = path.join(root, 'oc-started-2');
    const hold2 = path.join(root, 'oc-hold-2');
    const t1 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', prompt: 'HOLD_AGY 1', workingDirectory: repoDir, mode: 'read-only' },
    })).structuredContent).task;
    await waitUntil(() => adapter.calls.length === 1 && tasks.status(t1.taskId).status === 'running');

    const t2 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: `STARTED:${started2}\nHOLD:${hold2}`,
        workingDirectory: repoDir,
        mode: 'read-only',
      },
    })).structuredContent).task;
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(existsSync(started2), false);

    adapter.calls[0]!.finish!();
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    await waitUntil(() => existsSync(started2));
    await writeFile(hold2, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');
  });

  // 3) opencode + opencode same project
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_CONCURRENT_OPENCODE_TASKS: '2' },
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'hold-write' }) }],
  }, async ({ root, repoDir, tasks, client }) => {
    const started1 = path.join(root, 'oc-s1');
    const hold1 = path.join(root, 'oc-h1');
    const started2 = path.join(root, 'oc-s2');
    const hold2 = path.join(root, 'oc-h2');

    const t1 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: `STARTED:${started1}\nHOLD:${hold1}`,
        workingDirectory: repoDir,
        mode: 'read-only',
      },
    })).structuredContent).task;
    await waitUntil(() => existsSync(started1));

    const t2 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: `STARTED:${started2}\nHOLD:${hold2}`,
        workingDirectory: repoDir,
        mode: 'read-only',
      },
    })).structuredContent).task;
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(existsSync(started2), false);

    await writeFile(hold1, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    await waitUntil(() => existsSync(started2));
    await writeFile(hold2, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');
  });
});

test('M11) second agy task in another project waits while first agy runs', async () => {
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2' },
    extraRepos: 1,
  }, async ({ repoDir, extraRepos, adapter, tasks, client }) => {
    const repo2 = extraRepos[0]!;
    const t1 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', prompt: 'HOLD_AGY repo1', workingDirectory: repoDir, mode: 'read-only' },
    })).structuredContent).task;
    await waitUntil(() => adapter.calls.length === 1 && tasks.status(t1.taskId).status === 'running');

    const t2 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'agy', prompt: 'Second agy repo2', workingDirectory: repo2, mode: 'read-only' },
    })).structuredContent).task;
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(adapter.calls.length, 1);

    adapter.calls[0]!.finish!();
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');
    assert.equal(adapter.calls.length, 2);
  });
});

test('M12) two opencode tasks in different projects run concurrently when limit is 2 and serialize when limit is 1', async () => {
  // Parallel when MAX_CONCURRENT_OPENCODE_TASKS=2
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_CONCURRENT_OPENCODE_TASKS: '2' },
    extraRepos: 1,
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'hold-write' }) }],
  }, async ({ root, repoDir, extraRepos, tasks, client }) => {
    const repo2 = extraRepos[0]!;
    const s1 = path.join(root, 'p2-s1');
    const h1 = path.join(root, 'p2-h1');
    const s2 = path.join(root, 'p2-s2');
    const h2 = path.join(root, 'p2-h2');

    const t1 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'opencode', prompt: `STARTED:${s1}\nHOLD:${h1}`, workingDirectory: repoDir, mode: 'read-only' },
    })).structuredContent).task;
    const t2 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'opencode', prompt: `STARTED:${s2}\nHOLD:${h2}`, workingDirectory: repo2, mode: 'read-only' },
    })).structuredContent).task;

    await waitUntil(() => existsSync(s1) && existsSync(s2));
    assert.equal(tasks.status(t1.taskId).status, 'running');
    assert.equal(tasks.status(t2.taskId).status, 'running');

    await writeFile(h1, 'go', 'utf8');
    await writeFile(h2, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');
  });

  // Serialized when MAX_CONCURRENT_OPENCODE_TASKS=1
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_CONCURRENT_OPENCODE_TASKS: '1' },
    extraRepos: 1,
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'hold-write' }) }],
  }, async ({ root, repoDir, extraRepos, tasks, client }) => {
    const repo2 = extraRepos[0]!;
    const s1 = path.join(root, 'p1-s1');
    const h1 = path.join(root, 'p1-h1');
    const s2 = path.join(root, 'p1-s2');
    const h2 = path.join(root, 'p1-h2');

    const t1 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'opencode', prompt: `STARTED:${s1}\nHOLD:${h1}`, workingDirectory: repoDir, mode: 'read-only' },
    })).structuredContent).task;
    await waitUntil(() => existsSync(s1));

    const t2 = successOutputSchemas.black_gravity_dispatch.parse((await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: { provider: 'opencode', prompt: `STARTED:${s2}\nHOLD:${h2}`, workingDirectory: repo2, mode: 'read-only' },
    })).structuredContent).task;
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(existsSync(s2), false);

    await writeFile(h1, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    await waitUntil(() => existsSync(s2));
    await writeFile(h2, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');
  });
});

test('M13) opencode dispatch with allowedTools or mcpServers refuses with INVALID_AGENT_POLICY and creates no task', async () => {
  await withBridge({}, async ({ repoDir, tasks, client }) => {
    for (const extra of [{ allowedTools: ['view_file'] }, { mcpServers: [] }] as const) {
      const res = await client.callTool({
        name: 'black_gravity_dispatch',
        arguments: {
          provider: 'opencode',
          prompt: 'Policy refused',
          workingDirectory: repoDir,
          mode: 'read-only',
          ...extra,
        },
      });
      assert.equal(res.isError, true);
      const err = (res.structuredContent as { error: { code: string; message: string } }).error;
      assert.equal(err.code, 'INVALID_AGENT_POLICY');
      assert.ok(err.message.includes('opencode'), err.message);
    }
    assert.equal(tasks.list().length, 0);
  });
});

test('M14) SKILL.md contains required executor switching, error offering, and concurrency guidance within CRLF byte limit', async () => {
  const raw = await readFile(SHIPPED_SKILL_MD, 'utf8');
  const crlfBytes = Buffer.byteLength(raw.replace(/\r?\n/g, '\r\n'), 'utf8');
  assert.ok(crlfBytes <= 12_000, `SKILL.md CRLF bytes ${crlfBytes} > 12000`);

  const text = raw.replace(/\r\n/g, '\n');
  assert.ok(text.includes('`agy` or `opencode`'));
  assert.ok(text.includes('Switch executor or model only when the user asks'));
  assert.ok(text.includes('black_gravity_dispatch'));
  assert.ok(text.includes('black_gravity_handoff'));
  assert.ok(text.includes('latest completed task'));
  assert.ok(text.includes('AGY_AUTH_REQUIRED'));
  assert.ok(text.includes('OPENCODE_AUTH_REQUIRED'));
  assert.ok(text.includes('OPENCODE_QUOTA_EXCEEDED'));
  assert.ok(text.includes('OPENCODE_REGION_UNAVAILABLE'));
  assert.ok(text.includes('offer the user the other executor'));
  assert.ok(text.includes('never switch on your own'));
  assert.ok(text.includes('one task at a time per project'));
  assert.ok(text.includes('one task at a time overall'));
  assert.ok(text.includes('MAX_CONCURRENT_OPENCODE_TASKS'));
});

const requireBwrap = process.env.BLACK_GRAVITY_REQUIRE_BWRAP === '1';
const hostDetection = process.platform === 'linux' ? detectBubblewrap() : undefined;

function requireLinuxBwrap(t: TestContext): boolean {
  if (process.platform !== 'linux') {
    if (requireBwrap) assert.fail('BLACK_GRAVITY_REQUIRE_BWRAP=1 requires Linux');
    t.skip('Linux Bubblewrap executor requires Linux');
    return false;
  }
  if (!hostDetection?.available) {
    if (requireBwrap) {
      assert.fail(`BLACK_GRAVITY_REQUIRE_BWRAP=1 but Bubblewrap is unavailable (${hostDetection?.code}: ${hostDetection?.reason})`);
    }
    t.skip(`Bubblewrap unavailable: ${hostDetection?.code} (${hostDetection?.reason})`);
    return false;
  }
  return true;
}

test('M15) local linux-bwrap test task on an opencode write task runs with opencode executor identity', async t => {
  if (!requireLinuxBwrap(t)) return;
  await withBridge({
    env: { BRIDGE_TEST_EXECUTOR: 'linux-bwrap', DEFAULT_TIMEOUT_SECONDS: '30' },
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'write-succeeded' }) }],
    linuxBwrapDetection: hostDetection,
  }, async ({ repoDir, tasks }) => {
    const written = await tasks.run({
      provider: 'opencode',
      prompt: 'Edit in write mode',
      workingDirectory: repoDir,
      mode: 'write',
      model: 'opencode-go/mock-flash',
    });
    const settledWrite = await waitForTask(tasks, written.taskId);
    assert.equal(settledWrite.status, 'completed', JSON.stringify(settledWrite.error));
    assert.equal(settledWrite.execution?.provider, 'opencode');

    const preview = await tasks.preview(settledWrite.taskId, false);
    const tested = await tasks.startTests(
      settledWrite.taskId,
      preview.sha256,
      { executable: process.execPath, args: ['-e', 'process.exit(1)'] },
      0,
      30,
    );
    const testedResult = await waitForTask(tasks, tested.taskId);
    assert.equal(testedResult.status, 'failed');
    assert.equal(testedResult.error?.code, 'TEST_FAILED');
    assert.equal(testedResult.tests?.length, 1);
    assert.equal(testedResult.tests?.[0]?.exitCode, 1);
    assert.equal(testedResult.tests?.[0]?.source, 'linux-executor');
    assert.equal(testedResult.execution?.provider, 'opencode');
  });
});

test('M16) black_gravity_capabilities reports agy and opencode without calling primary adapter.health()', async () => {
  await withBridge({}, async ({ adapter, client }) => {
    let healthCalls = 0;
    adapter.health = async () => {
      healthCalls += 1;
      throw new Error('health() must not be called by black_gravity_capabilities');
    };

    const capRes = await client.callTool({ name: 'black_gravity_capabilities', arguments: {} });
    assert.equal(capRes.isError, undefined, JSON.stringify(capRes.structuredContent));
    const parsed = successOutputSchemas.black_gravity_capabilities.parse(capRes.structuredContent);

    assert.equal(healthCalls, 0);
    assert.equal(parsed.clis.length, 1);
    const cli = parsed.clis[0]!;
    assert.equal(parsed.executors?.length, 2);

    const agy = parsed.executors!.find(e => e.provider === 'agy');
    const oc = parsed.executors!.find(e => e.provider === 'opencode');
    assert.ok(agy && oc);
    assert.equal(agy.primary, true);
    assert.equal(agy.available, cli.installed);
    if (cli.installed) {
      assert.equal(agy.version, cli.version);
      assert.equal(agy.reason, undefined);
    } else {
      assert.equal(agy.version, undefined);
      assert.equal(agy.reason, cli.error);
    }
    assert.equal(oc.primary, false);
    assert.equal(oc.available, true);
  });
});

test('M17) black_gravity_health and black_gravity_capabilities check opencode availability without spawning the executable', async t => {
  if (process.platform === 'win32') {
    t.skip('POSIX executable script test is skipped on Windows');
    return;
  }
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-exec-m17-'));
  try {
    const markerFile = path.join(root, 'spawned.marker');
    const scriptPath = path.join(root, 'fake-opencode.sh');
    await writeFile(scriptPath, `#!/bin/sh\n: > ${JSON.stringify(markerFile)}\nexit 0\n`, 'utf8');
    await chmod(scriptPath, 0o755);

    await withBridge({
      executors: [{ provider: 'opencode', adapter: new OpenCodeExecutionAdapter({ executable: scriptPath }) }],
    }, async ({ client }) => {
      const healthRes = await client.callTool({ name: 'black_gravity_health', arguments: {} });
      assert.equal(healthRes.isError, undefined, JSON.stringify(healthRes.structuredContent));
      const parsedHealth = successOutputSchemas.black_gravity_health.parse(healthRes.structuredContent);
      const ocHealth = parsedHealth.executors?.find(e => e.provider === 'opencode');
      assert.ok(ocHealth);
      assert.equal(ocHealth.available, true);
      assert.equal(ocHealth.version, undefined);
      assert.equal(existsSync(markerFile), false);

      const capRes = await client.callTool({ name: 'black_gravity_capabilities', arguments: {} });
      assert.equal(capRes.isError, undefined, JSON.stringify(capRes.structuredContent));
      const parsedCap = successOutputSchemas.black_gravity_capabilities.parse(capRes.structuredContent);
      const ocCap = parsedCap.executors?.find(e => e.provider === 'opencode');
      assert.ok(ocCap);
      assert.equal(ocCap.available, true);
      assert.equal(ocCap.version, undefined);
      assert.equal(existsSync(markerFile), false);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('M18) black_gravity_run with a completed opencode sessionId is refused with INVALID_SESSION and creates no task', async () => {
  await withBridge({}, async ({ repoDir, adapter, tasks, client }) => {
    const ocRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'opencode',
        prompt: 'READ:source.txt',
        workingDirectory: repoDir,
        mode: 'read-only',
      },
    });
    assert.equal(ocRes.isError, undefined, JSON.stringify(ocRes.structuredContent));
    const ocTaskId = successOutputSchemas.black_gravity_dispatch.parse(ocRes.structuredContent).task.taskId;
    const settled = await waitForTask(tasks, ocTaskId);
    assert.equal(settled.status, 'completed', JSON.stringify(settled.error));
    assert.equal(settled.execution?.provider, 'opencode');
    assert.ok(settled.sessionId);

    const runRes = await client.callTool({
      name: 'black_gravity_run',
      arguments: {
        prompt: 'Attempt cross-provider session reuse',
        workingDirectory: repoDir,
        sessionId: settled.sessionId,
        mode: 'read-only',
      },
    });
    assert.equal(runRes.isError, true);
    const err = (runRes.structuredContent as { error: { code: string; message: string } }).error;
    assert.equal(err.code, 'INVALID_SESSION');
    assert.equal(tasks.list().length, 1);
    assert.equal(adapter.calls.length, 0);
  });
});

test('M19) local linux-bwrap test of an agy task waits while another agy task runs in another project', async t => {
  if (!requireLinuxBwrap(t)) return;
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', BRIDGE_TEST_EXECUTOR: 'linux-bwrap', DEFAULT_TIMEOUT_SECONDS: '30' },
    extraRepos: 1,
    linuxBwrapDetection: hostDetection,
  }, async ({ repoDir, extraRepos, adapter, tasks, client }) => {
    const repoB = extraRepos[0]!;
    const writeRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'agy',
        prompt: 'CREATE_AGY_FILE:from-a.txt',
        workingDirectory: repoDir,
        mode: 'write',
      },
    });
    assert.equal(writeRes.isError, undefined, JSON.stringify(writeRes.structuredContent));
    const writeTaskId = successOutputSchemas.black_gravity_dispatch.parse(writeRes.structuredContent).task.taskId;
    const settledWrite = await waitForTask(tasks, writeTaskId);
    assert.equal(settledWrite.status, 'completed', JSON.stringify(settledWrite.error));
    const preview = await tasks.preview(writeTaskId, false);

    const holdRes = await client.callTool({
      name: 'black_gravity_dispatch',
      arguments: {
        provider: 'agy',
        prompt: 'HOLD_AGY repoB',
        workingDirectory: repoB,
        mode: 'read-only',
      },
    });
    assert.equal(holdRes.isError, undefined, JSON.stringify(holdRes.structuredContent));
    const holdTaskId = successOutputSchemas.black_gravity_dispatch.parse(holdRes.structuredContent).task.taskId;
    await waitUntil(() => adapter.calls.length === 2 && tasks.status(holdTaskId).status === 'running');

    const tested = await tasks.startTests(
      writeTaskId,
      preview.sha256,
      { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
      0,
      30,
    );
    await delay(150);
    assert.equal(tasks.status(tested.taskId).status, 'queued');
    assert.equal(tasks.status(holdTaskId).status, 'running');

    adapter.calls[1]!.finish!();
    assert.equal((await waitForTask(tasks, holdTaskId)).status, 'completed');
    const testedResult = await waitForTask(tasks, tested.taskId);
    assert.equal(testedResult.status, 'completed', JSON.stringify(testedResult.error));
    assert.equal(testedResult.tests?.length, 1);
    assert.equal(testedResult.tests?.[0]?.exitCode, 0);
    assert.equal(testedResult.tests?.[0]?.source, 'linux-executor');
    assert.equal(testedResult.execution?.provider, 'agy');
  });
});

test('M20) compare batching respects MAX_QUEUED_TASKS when earlier tasks are held', async () => {
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_QUEUED_TASKS: '2' },
    extraRepos: 2,
  }, async ({ repoDir, extraRepos, adapter, tasks }) => {
    const repo2 = extraRepos[0]!;
    const repo3 = extraRepos[1]!;

    const planner = await tasks.run({
      provider: 'agy',
      prompt: 'Plan changes',
      workingDirectory: repoDir,
      role: 'planner',
      mode: 'read-only',
    });
    const settledPlanner = await waitForTask(tasks, planner.taskId);
    assert.equal(settledPlanner.status, 'completed', JSON.stringify(settledPlanner.error));
    const ctx = await tasks.context(planner.taskId);

    const heldRunning = await tasks.run({
      provider: 'agy',
      prompt: 'HOLD_AGY running',
      workingDirectory: repo2,
      mode: 'read-only',
    });
    await waitUntil(() => adapter.calls.length === 2 && tasks.status(heldRunning.taskId).status === 'running');

    const heldQueued = await tasks.run({
      provider: 'agy',
      prompt: 'HOLD_AGY queued',
      workingDirectory: repo3,
      mode: 'read-only',
    });
    await delay(150);
    assert.equal(tasks.status(heldQueued.taskId).status, 'queued');
    assert.equal(tasks.list().filter(t => t.status === 'queued').length, 1);

    let comparisonError: unknown;
    let comparisonResult: Awaited<ReturnType<typeof tasks.compare>> | undefined;
    try {
      comparisonResult = await tasks.compare(
        planner.taskId,
        ctx.treeSha256,
        ['mock-pro', 'mock-flash'],
        'Compare opinions',
      );
    } catch (error) {
      comparisonError = error;
    }

    const queuedCount = tasks.list().filter(t => t.status === 'queued').length;
    assert.ok(queuedCount <= 2, `Expected at most 2 queued tasks, got ${queuedCount}`);
    if (comparisonError) {
      assert.equal((comparisonError as { code?: string }).code, 'QUEUE_FULL');
    } else {
      assert.ok(comparisonResult);
      assert.ok(comparisonResult.startErrors.some(e => e.code === 'QUEUE_FULL'));
      for (const id of comparisonResult.taskIds) {
        await tasks.cancel(id);
      }
    }

    await tasks.cancel(heldQueued.taskId);
    adapter.calls[1]!.finish!();
    assert.equal((await waitForTask(tasks, heldRunning.taskId)).status, 'completed');
  });
});

test('M21) cancelling a held queued task removes it without starting and lets the next queued task of the same project start', async () => {
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2' },
  }, async ({ repoDir, adapter, tasks }) => {
    const t1 = await tasks.run({
      provider: 'agy',
      prompt: 'HOLD_AGY 1',
      workingDirectory: repoDir,
      mode: 'read-only',
    });
    await waitUntil(() => adapter.calls.length === 1 && tasks.status(t1.taskId).status === 'running');

    const t2 = await tasks.run({
      provider: 'agy',
      prompt: 'Queued task to cancel',
      workingDirectory: repoDir,
      mode: 'read-only',
    });
    const t3 = await tasks.run({
      provider: 'agy',
      prompt: 'Next queued task',
      workingDirectory: repoDir,
      mode: 'read-only',
    });
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(tasks.status(t3.taskId).status, 'queued');
    assert.equal(adapter.calls.length, 1);

    const cancelled = await tasks.cancel(t2.taskId);
    assert.equal(cancelled.status, 'cancelled');
    assert.equal(cancelled.startedAt, undefined);
    assert.equal(cancelled.error?.code, 'TASK_CANCELLED');
    assert.equal(adapter.calls.length, 1);
    assert.equal(tasks.status(t3.taskId).status, 'queued');

    adapter.calls[0]!.finish!();
    assert.equal((await waitForTask(tasks, t1.taskId)).status, 'completed');
    assert.equal((await waitForTask(tasks, t3.taskId)).status, 'completed');
    assert.equal(adapter.calls.length, 2);
    assert.equal(tasks.status(t2.taskId).status, 'cancelled');
    assert.equal(tasks.status(t2.taskId).startedAt, undefined);
  });
});

test('M22) a running task that fails frees its project and executor slot so a held task queued behind it starts and completes', async () => {
  await withBridge({
    env: { MAX_CONCURRENT_TASKS: '2', MAX_CONCURRENT_OPENCODE_TASKS: '1' },
    extraRepos: 1,
    executors: [{ provider: 'opencode', adapter: mockOpenCodeAdapter({ scenario: 'hold-auth-error' }) }],
  }, async ({ root, repoDir, extraRepos, tasks }) => {
    const repo2 = extraRepos[0]!;
    const s1 = path.join(root, 'm22-s1');
    const h1 = path.join(root, 'm22-h1');
    const s2 = path.join(root, 'm22-s2');
    const h2 = path.join(root, 'm22-h2');
    const s3 = path.join(root, 'm22-s3');
    const h3 = path.join(root, 'm22-h3');

    const t1 = await tasks.run({
      provider: 'opencode',
      prompt: `STARTED:${s1}\nHOLD:${h1}\nFAIL:auth-error`,
      workingDirectory: repoDir,
      mode: 'read-only',
    });
    await waitUntil(() => existsSync(s1));
    assert.equal(tasks.status(t1.taskId).status, 'running');

    const t2 = await tasks.run({
      provider: 'opencode',
      prompt: `STARTED:${s2}\nHOLD:${h2}`,
      workingDirectory: repoDir,
      mode: 'read-only',
    });
    const t3 = await tasks.run({
      provider: 'opencode',
      prompt: `STARTED:${s3}\nHOLD:${h3}`,
      workingDirectory: repo2,
      mode: 'read-only',
    });
    await delay(150);
    assert.equal(tasks.status(t2.taskId).status, 'queued');
    assert.equal(tasks.status(t3.taskId).status, 'queued');
    assert.equal(existsSync(s2), false);
    assert.equal(existsSync(s3), false);

    await writeFile(h1, 'go', 'utf8');
    const t1Result = await waitForTask(tasks, t1.taskId);
    assert.equal(t1Result.status, 'failed');
    assert.equal(t1Result.error?.code, 'OPENCODE_AUTH_REQUIRED');

    await waitUntil(() => existsSync(s2));
    assert.equal(tasks.status(t2.taskId).status, 'running');
    await writeFile(h2, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t2.taskId)).status, 'completed');

    await waitUntil(() => existsSync(s3));
    assert.equal(tasks.status(t3.taskId).status, 'running');
    await writeFile(h3, 'go', 'utf8');
    assert.equal((await waitForTask(tasks, t3.taskId)).status, 'completed');
  });
});

test('unit: config parsing for OPENCODE_PATH and MAX_CONCURRENT_OPENCODE_TASKS', () => {
  const defaults = loadConfig({});
  assert.equal(defaults.openCodePath, undefined);
  assert.equal(defaults.openCodePathInvalid, undefined);
  assert.equal(defaults.maxConcurrentOpenCodeTasks, 1);

  const abs = process.platform === 'win32' ? 'C:\\tools\\opencode.exe' : '/usr/local/bin/opencode';
  const valid = loadConfig({ OPENCODE_PATH: abs, MAX_CONCURRENT_OPENCODE_TASKS: '4' });
  assert.equal(valid.openCodePath, abs);
  assert.equal(valid.openCodePathInvalid, undefined);
  assert.equal(valid.maxConcurrentOpenCodeTasks, 4);

  const rel = loadConfig({ OPENCODE_PATH: 'bin/opencode' });
  assert.equal(rel.openCodePathInvalid, true);
  assert.ok(rel.configurationIssues.some(i => i.variable === 'OPENCODE_PATH' && i.reason === 'not-absolute'));

  const nul = loadConfig({ OPENCODE_PATH: abs + '\0bad' });
  assert.equal(nul.openCodePathInvalid, true);
  assert.ok(nul.configurationIssues.some(i => i.variable === 'OPENCODE_PATH' && i.reason === 'invalid-entry'));

  assert.throws(() => loadConfig({ MAX_CONCURRENT_OPENCODE_TASKS: '0' }));
  assert.throws(() => loadConfig({ MAX_CONCURRENT_OPENCODE_TASKS: '17' }));
});

test('unit: resolveOpenCodeRegistration handles OPENCODE_PATH, PATH lookup, and missing executable', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-oc-reg-'));
  try {
    const invalidReg = resolveOpenCodeRegistration(loadConfig({ OPENCODE_PATH: 'relative/opencode' }), {});
    assert.equal(invalidReg.provider, 'opencode');
    assert.equal(invalidReg.adapter, undefined);
    assert.equal(invalidReg.unavailableReason, 'INVALID_CONFIGURATION: OPENCODE_PATH is invalid');

    const missingReg = resolveOpenCodeRegistration(loadConfig({}), { PATH: 'relative-only' }, 'linux');
    assert.equal(missingReg.provider, 'opencode');
    assert.equal(missingReg.adapter, undefined);
    assert.equal(missingReg.unavailableReason, 'OPENCODE_UNAVAILABLE: OpenCode executable not found; set OPENCODE_PATH');

    const explicitPath = path.join(root, 'explicit-opencode');
    await writeFile(explicitPath, '#!/bin/sh\n', 'utf8');
    const explicitReg = resolveOpenCodeRegistration(loadConfig({ OPENCODE_PATH: explicitPath }), {});
    assert.equal(explicitReg.provider, 'opencode');
    assert.ok(explicitReg.adapter);

    const hostPlatform = process.platform === 'win32' ? 'win32' : 'linux';
    const binaryName = hostPlatform === 'win32' ? 'opencode.exe' : 'opencode';
    const dirNonExec = path.join(root, 'dir-nonexec');
    const dirExec = path.join(root, 'dir-exec');
    await mkdir(dirNonExec);
    await mkdir(dirExec);
    // A directory named like the binary must be skipped; a regular executable file in dirExec must match.
    await mkdir(path.join(dirNonExec, binaryName));
    const binPath = path.join(dirExec, binaryName);
    await writeFile(binPath, '#!/bin/sh\n', 'utf8');
    if (hostPlatform !== 'win32') await chmod(binPath, 0o755);

    const pathReg = resolveOpenCodeRegistration(
      loadConfig({}),
      { PATH: ['relative/entry', dirNonExec, dirExec].join(hostPlatform === 'win32' ? ';' : ':') },
      hostPlatform,
    );
    assert.equal(pathReg.provider, 'opencode');
    assert.ok(pathReg.adapter);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
