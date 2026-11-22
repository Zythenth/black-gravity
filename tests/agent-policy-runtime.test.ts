import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { loadConfig, type Config } from '../src/config.js';
import { TaskManager } from '../src/task-manager.js';
import { StateStore } from '../src/state-store.js';
import { discardProjectCopy, fingerprintProjectCopy } from '../src/isolation.js';
import type { RunOptions, TaskRecord } from '../src/types.js';
import { waitForTask } from './wait-for-task.js';

function hookResult(cwd: string, conversationId: string, name: string, args: unknown): { decision: string; reason: string } {
  const child = spawnSync(process.execPath, ['bridge-execution-hook.mjs'], { cwd: path.join(cwd, '.agents'), input: JSON.stringify({ workspacePaths: [cwd], conversationId, toolCall: { name, args } }), encoding: 'utf8', windowsHide: true, timeout: 60000 });
  assert.equal(child.status, 0, child.stderr);
  const parsed = JSON.parse(child.stdout) as { decision: string; reason: string };
  return { decision: parsed.decision, reason: parsed.reason };
}
function hook(cwd: string, conversationId: string, name: string, args: unknown) {
  return hookResult(cwd, conversationId, name, args).decision;
}
class GuardedAdapter extends ControlledCliAdapter {
  calls: Array<{ options: RunOptions; cwd: string }> = [];
  behavior: 'guarded' | 'guarded-with-silent-denials' | 'guarded-with-denied-read' | 'guarded-with-inflated-read-steps' | 'guarded-with-silent-denied-read' | 'guarded-with-denied-write' | 'bypass' | 'tamper' = 'guarded';
  override spawnTask(options: RunOptions, _model: string | undefined, cwd: string): ChildProcessWithoutNullStreams {
    this.calls.push({ options, cwd });
    const child = new EventEmitter() as ChildProcessWithoutNullStreams, stdout = new PassThrough(), stderr = new PassThrough();
    Object.assign(child, { stdin: new PassThrough(), stdout, stderr, pid: undefined, exitCode: null, killed: false, kill: () => { Object.assign(child, { exitCode: 1, killed: true }); child.emit('close', 1); return true; } });
    setImmediate(() => void (async () => {
      const session = options.sessionId ?? randomUUID();
      stdout.write(JSON.stringify({ event: 'init', conversation_id: session }) + '\n');
      if (this.behavior !== 'bypass') {
        assert.equal(hook(cwd, session, 'view_file', { AbsolutePath: path.join(cwd, 'source.txt') }), 'allow');
        if (this.behavior === 'guarded-with-silent-denials') {
          assert.equal(hook(cwd, session, 'run_command', { CommandLine: 'inert fixture' }), 'deny');
          assert.equal(hook(cwd, session, 'call_mcp_tool', { ServerName: 'unselected', ToolName: 'echo', Arguments: {} }), 'deny');
        }
        if (this.behavior === 'guarded-with-denied-read') {
          let stepIndex = 10;
          for (const targetPath of [path.join(cwd, 'missing-inside.txt'), path.join(path.dirname(cwd), 'outside-copy.txt')]) {
            const res = hookResult(cwd, session, 'view_file', { AbsolutePath: targetPath });
            assert.equal(res.decision, 'deny');
            stdout.write(JSON.stringify({
              event: 'step_update',
              step_update: {
                step_index: stepIndex++,
                step_type: 'tool',
                state: 'ERROR',
                tool_name: 'view_file',
                tool_info: {
                  name: 'view_file',
                  parameters: { AbsolutePath: targetPath },
                  error: { type: 'TOOL_ERROR', message: `tool call denied by pre-tool hook: ${res.reason}` },
                },
              },
            }) + '\n');
          }
        }
        if (this.behavior === 'guarded-with-inflated-read-steps') {
          const targetPath = path.join(cwd, 'missing-inside.txt');
          const res = hookResult(cwd, session, 'view_file', { AbsolutePath: targetPath });
          assert.equal(res.decision, 'deny');
          for (const stepIndex of [10, 11]) {
            stdout.write(JSON.stringify({
              event: 'step_update',
              step_update: {
                step_index: stepIndex,
                step_type: 'tool',
                state: 'ERROR',
                tool_name: 'view_file',
                tool_info: {
                  name: 'view_file',
                  parameters: { AbsolutePath: targetPath },
                  error: { type: 'TOOL_ERROR', message: `tool call denied by pre-tool hook: ${res.reason}` },
                },
              },
            }) + '\n');
          }
        }
        if (this.behavior === 'guarded-with-silent-denied-read') {
          const res = hookResult(cwd, session, 'view_file', { AbsolutePath: path.join(cwd, 'missing-inside.txt') });
          assert.equal(res.decision, 'deny');
        }
        if (this.behavior === 'guarded-with-denied-write') {
          const gitTarget = path.join(cwd, '.git', 'config');
          const res = hookResult(cwd, session, 'write_to_file', { TargetFile: gitTarget });
          assert.equal(res.decision, 'deny');
          stdout.write(JSON.stringify({
            event: 'step_update',
            step_update: {
              step_index: 10,
              step_type: 'tool',
              state: 'ERROR',
              tool_name: 'write_to_file',
              tool_info: {
                name: 'write_to_file',
                parameters: { TargetFile: gitTarget },
                error: { type: 'TOOL_ERROR', message: `tool call denied by pre-tool hook: ${res.reason}` },
              },
            },
          }) + '\n');
        }
        if (options.mode === 'write') {
          assert.equal(hook(cwd, session, 'write_to_file', { TargetFile: path.join(cwd, 'created.txt') }), 'allow');
          await writeFile(path.join(cwd, 'created.txt'), 'created by controlled adapter\n');
        }
        assert.equal(hook(cwd, session, 'finish', {}), 'allow');
      }
      if (this.behavior === 'tamper') await writeFile(path.join(cwd, '.agents/hooks.json'), '{}');
      const result = options.roleDefinition?.baseRole === 'reviewer' ? { summary: 'Inspected fixture.', reviewedFiles: ['source.txt'], findings: [], unverified: [] } : { marker: 'guarded' };
      stdout.write(JSON.stringify({ event: 'result', result: { status: 'SUCCESS', structured_output: result } }) + '\n');
      stdout.end(); Object.assign(child, { exitCode: 0 }); child.emit('close', 0);
    })().catch(error => { stderr.write(String(error)); Object.assign(child, { exitCode: 1 }); child.emit('close', 1); }));
    return child;
  }
}
async function fixture(body: (f: { root: string; source: string; config: Config; adapter: GuardedAdapter; tasks: TaskManager; managers: TaskManager[] }) => Promise<void>, environment: Record<string, string> = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-policy-runtime-')), source = path.join(root, 'source');
  await mkdir(source); execFileSync('git', ['init', '--quiet'], { cwd: source }); await writeFile(path.join(source, 'source.txt'), 'fixture\n');
  const config = loadConfig({ BRIDGE_STATE_DIRECTORY: path.join(root, 'state'), BRIDGE_TEST_EXECUTOR: 'agy', ...environment }), adapter = new GuardedAdapter(config), tasks = new TaskManager(adapter, config), managers = [tasks];
  try { await body({ root, source, config, adapter, tasks, managers }); }
  finally {
    for (const manager of managers) await manager.shutdown();
    for (const project of new Map(new StateStore(config.stateDirectory).load().flatMap(item => item.project ? [[item.project.copyDirectory, item.project] as const] : [])).values()) await discardProjectCopy(project);
    assert.equal(path.dirname(root), path.resolve(os.tmpdir())); assert.ok(path.basename(root).startsWith('black-gravity-policy-runtime-')); await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}
async function end(tasks: TaskManager, task: TaskRecord) { return waitForTask(tasks, task.taskId); }

test('enforced task executes real hooks, excludes managed files from preview and persists policy identity', async () => {
  await fixture(async ({ source, tasks, config }) => {
    const task = await end(tasks, await tasks.run({ prompt: 'Public fixture.', workingDirectory: source, allowedTools: ['view_file', 'write_to_file'], mcpServers: [] }));
    assert.equal(task.status, 'completed', JSON.stringify(task.error)); assert.ok(task.agentPolicyReceipt!.decisionCount >= 3); assert.equal(task.agentPolicyReceipt!.deniedCount, 0);
    assert.deepEqual((await tasks.preview(task.taskId)).files, [{ status: 'A', path: 'created.txt' }]);
    assert.deepEqual(new StateStore(config.stateDirectory).load().find(t => t.record.taskId === task.taskId)!.record.agentPolicy, task.agentPolicy);
    await assert.rejects(readFile(path.join(source, '.agents/hooks.json')), { code: 'ENOENT' });
    await assert.rejects(tasks.startTests(task.taskId, (await tasks.preview(task.taskId)).sha256, { executable: process.execPath, args: ['--version'] }), { code: 'POLICY_TEST_EXECUTOR_UNAVAILABLE' });
  });
});
test('read-only policy includes protected helpers in baseline without changes or patches', async () => {
  await fixture(async ({ source, tasks }) => {
    const task = await end(tasks, await tasks.run({ prompt: 'Read fixture.', workingDirectory: source, mode: 'read-only', allowedTools: ['view_file'] }));
    assert.equal(task.status, 'completed', JSON.stringify(task.error)); assert.deepEqual((await tasks.preview(task.taskId)).files, []);
  });
});
test('old guarded finish cannot validate a new resume that skips native hooks', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    const first = await end(tasks, await tasks.run({ prompt: 'Original.', workingDirectory: source, mode: 'read-only', allowedTools: ['view_file'] })); assert.equal(first.status, 'completed');
    await assert.rejects(tasks.run({ prompt: 'Change selection.', workingDirectory: source, sessionId: first.sessionId, allowedTools: [] }), { code: 'INVALID_AGENT_POLICY' });
    adapter.behavior = 'bypass'; const next = await end(tasks, await tasks.run({ prompt: 'Resume.', workingDirectory: source, sessionId: first.sessionId }));
    assert.equal(next.status, 'failed'); assert.equal(next.error?.code, 'AGENT_POLICY_UNVERIFIED');
  });
});
test('modified hook blocks success even when CLI result says SUCCESS', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    adapter.behavior = 'tamper'; const task = await end(tasks, await tasks.run({ prompt: 'Tamper fixture.', workingDirectory: source, allowedTools: ['view_file', 'write_to_file'] }));
    assert.equal(task.status, 'failed'); assert.equal(task.error?.code, 'EXECUTION_POLICY_VERIFICATION_FAILED');
  });
});
test('handoff restages controls for a separate copy and preserves context tree hash', async () => {
  await fixture(async ({ source, tasks, config }) => {
    const first = await end(tasks, await tasks.run({ prompt: 'Write fixture.', workingDirectory: source, allowedTools: ['view_file', 'write_to_file'] })); assert.equal(first.status, 'completed');
    const context = await tasks.context(first.taskId); const next = await end(tasks, await tasks.run({ prompt: 'Review fixture.', workingDirectory: source, contextTaskId: first.taskId, expectedContextSha256: context.treeSha256, role: 'reviewer' }));
    assert.equal(next.status, 'completed', JSON.stringify(next.error)); assert.notEqual(next.copyDirectory, first.copyDirectory); assert.deepEqual(next.agentPolicy!.nativeTools, ['view_file', 'finish']);
    const saved = new StateStore(config.stateDirectory).load(), a = saved.find(t => t.record.taskId === first.taskId)!.project!, b = saved.find(t => t.record.taskId === next.taskId)!.project!;
    assert.equal(await fingerprintProjectCopy(a, config), await fingerprintProjectCopy(b, config)); assert.notEqual(a.executionPolicy!.receiptPath, b.executionPolicy!.receiptPath);
  });
});
test('restart honors policy snapshot and rejects a revoked human ceiling before provider execution', async () => {
  await fixture(async ({ source, tasks, config, managers }) => {
    const first = await end(tasks, await tasks.run({ prompt: 'Original.', workingDirectory: source, allowedTools: ['view_file', 'write_to_file'] })); assert.equal(first.status, 'completed'); await tasks.shutdown();
    const changed = { ...config, allowedAgyTools: ['view_file' as const] }, adapter = new GuardedAdapter(changed), next = new TaskManager(adapter, changed); managers.push(next);
    await assert.rejects(next.run({ prompt: 'Revoked.', workingDirectory: source, sessionId: first.sessionId }), { code: 'POLICY_NOT_ALLOWED' }); assert.equal(adapter.calls.length, 0);
  });
});


test('discard releases the private execution receipt and allows repeated cleanup', async () => {
  await fixture(async ({ source, tasks, config }) => {
    const task = await end(tasks, await tasks.run({ prompt: 'Discard fixture.', workingDirectory: source, mode: 'read-only', allowedTools: ['view_file'] })); assert.equal(task.status, 'completed');
    const project = new StateStore(config.stateDirectory).load().find(t => t.record.taskId === task.taskId)!.project!;
    const receipt = project.executionPolicy!.receiptPath; assert.ok((await readFile(receipt)).length > 0);
    await tasks.discard(task.taskId); await assert.rejects(readFile(receipt), { code: 'ENOENT' });
    await discardProjectCopy(project);
  });
});


test('omitting caller selectors cannot bypass an explicit human ceiling', async () => {
  await fixture(async ({ source, tasks }) => {
    const task = await end(tasks, await tasks.run({ prompt: 'Use configured ceiling.', workingDirectory: source, mode: 'read-only' }));
    assert.equal(task.status, 'completed', JSON.stringify(task.error)); assert.deepEqual(task.agentPolicy!.nativeTools, ['view_file', 'finish']); assert.ok(task.agentPolicyReceipt);
  }, { BRIDGE_ALLOWED_AGY_TOOLS: '["view_file"]' });
});
test('a newly configured human ceiling cannot silently reuse an unguarded legacy session', async () => {
  await fixture(async ({ source, tasks, adapter, config }) => {
    adapter.behavior = 'bypass'; const first = await end(tasks, await tasks.run({ prompt: 'Legacy fixture.', workingDirectory: source, mode: 'read-only' })); assert.equal(first.status, 'completed'); assert.equal(first.agentPolicy, undefined);
    config.enforceAgentPolicy = true; config.allowedAgyTools = ['view_file'];
    await assert.rejects(tasks.run({ prompt: 'Continue under new ceiling.', workingDirectory: source, sessionId: first.sessionId }), { code: 'AGENT_POLICY_CHANGED' }); assert.equal(adapter.calls.length, 1);
  });
});


test('handoff retains the selected MCP tools when a human ceiling is globally configured', async () => {
  const catalog = [{ id: 'probe', command: process.execPath, args: ['--version'], tools: [{ name: 'echo', readOnly: true }] }];
  await fixture(async ({ source, tasks }) => {
    const first = await end(tasks, await tasks.run({ prompt: 'Original selected MCP.', workingDirectory: source, allowedTools: ['view_file', 'write_to_file'], mcpServers: [{ serverId: 'probe', tools: ['echo'] }] })); assert.equal(first.status, 'completed');
    const context = await tasks.context(first.taskId), next = await end(tasks, await tasks.run({ prompt: 'Review same tools.', workingDirectory: source, contextTaskId: first.taskId, expectedContextSha256: context.treeSha256, role: 'reviewer' }));
    assert.equal(next.status, 'completed', JSON.stringify(next.error)); assert.deepEqual(next.agentPolicy!.mcpServers, first.agentPolicy!.mcpServers); assert.deepEqual(next.agentPolicy!.nativeTools, ['view_file', 'finish']);
  }, { BRIDGE_MCP_CATALOG: JSON.stringify(catalog) });
});


test('Windows restart accepts canonical aliases of the same private state directory', { skip: process.platform !== 'win32' }, async () => {
  await fixture(async ({ source, tasks, config, managers }) => {
    const first = await end(tasks, await tasks.run({ prompt: 'Alias fixture.', workingDirectory: source, mode: 'read-only', allowedTools: ['view_file'] })); assert.equal(first.status, 'completed'); await tasks.shutdown();
    const aliased = { ...config, stateDirectory: config.stateDirectory.toLowerCase() }, adapter = new GuardedAdapter(aliased), next = new TaskManager(adapter, aliased); managers.push(next);
    const resumed = await end(next, await next.run({ prompt: 'Continue through alias.', workingDirectory: source, sessionId: first.sessionId })); assert.equal(resumed.status, 'completed', JSON.stringify(resumed.error)); assert.deepEqual(resumed.agentPolicy, first.agentPolicy);
  });
});

test('silent pre-tool hook denial receipt fails completed CLI run and preserves denial receipt', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    adapter.behavior = 'guarded-with-silent-denials';
    const task = await end(tasks, await tasks.run({ prompt: 'Silent denial fixture.', workingDirectory: source, allowedTools: ['view_file', 'write_to_file'], mcpServers: [] }));
    assert.equal(task.status, 'failed');
    assert.equal(task.error?.code, 'AGY_PROCESS_FAILED');
    assert.match(task.error?.message ?? '', /denied 2 tool calls/i);
    assert.ok(task.agentPolicyReceipt);
    assert.ok(task.agentPolicyReceipt.decisionCount >= 5);
    assert.equal(task.agentPolicyReceipt.deniedCount, 2);
  });
});

test('hook-denied reads with successful CLI complete with deniedReads and allow verify and integrate', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    adapter.behavior = 'guarded-with-denied-read';
    const task = await end(tasks, await tasks.run({
      prompt: 'Denied read fixture.',
      workingDirectory: source,
      allowedTools: ['view_file', 'write_to_file'],
      mcpServers: [],
      acceptanceCriteria: [{ id: 'created', description: 'Create created.txt', check: { kind: 'file-exists', path: 'created.txt' } }],
    }));
    assert.equal(task.status, 'completed', JSON.stringify(task.error));
    assert.equal(task.agentPolicyReceipt?.deniedCount, 2);
    assert.equal(task.agentPolicyReceipt?.deniedReadCount, 2);
    assert.equal(task.deniedReads?.total, 2);
    assert.equal(task.deniedReads?.items.length, 2);
    assert.ok(task.deniedReads?.items.every(item => item.toolName === 'view_file' && /pre-tool hook/i.test(item.reason)));
    const deniedReadEvents = tasks.readEvents(task.taskId).events.filter(event => event.type === 'task.denied-reads');
    assert.equal(deniedReadEvents.length, 1);
    assert.deepEqual(deniedReadEvents[0]!.data, task.deniedReads);

    const preview = await tasks.preview(task.taskId);
    assert.deepEqual(preview.files, [{ status: 'A', path: 'created.txt' }]);
    const verification = await tasks.verify(task.taskId, preview.sha256, [{
      criterionId: 'created',
      verdict: 'passed',
      path: 'created.txt',
      line: 1,
      quote: 'created by controlled adapter',
      explanation: 'Created file exists with expected content',
    }]);
    assert.equal(verification.status, 'passed');
    const integrated = await tasks.integrate(task.taskId, preview.sha256, async () => true);
    assert.deepEqual(integrated.files, [{ status: 'A', path: 'created.txt' }]);
    assert.equal(await readFile(path.join(source, 'created.txt'), 'utf8'), 'created by controlled adapter\n');
  });
});

test('hook-denied write fails even when CLI exits 0 with SUCCESS', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    adapter.behavior = 'guarded-with-denied-write';
    const task = await end(tasks, await tasks.run({
      prompt: 'Denied write fixture.',
      workingDirectory: source,
      allowedTools: ['view_file', 'write_to_file'],
      mcpServers: [],
    }));
    assert.equal(task.status, 'failed');
    assert.equal(task.error?.code, 'AGY_PROCESS_FAILED');
    assert.match(task.error?.message ?? '', /pre-tool hook/i);
  });
});

test('adapter reporting more denied reads than receipt fails with AGY_PROCESS_FAILED', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    adapter.behavior = 'guarded-with-inflated-read-steps';
    const task = await end(tasks, await tasks.run({
      prompt: 'Inflated denied read steps fixture.',
      workingDirectory: source,
      allowedTools: ['view_file', 'write_to_file'],
      mcpServers: [],
    }));
    assert.equal(task.status, 'failed');
    assert.equal(task.error?.code, 'AGY_PROCESS_FAILED');
    assert.match(task.error?.message ?? '', /receipt recorded 1/);
  });
});

test('receipt-only denied read without ERROR step completes with deniedReads and task.denied-reads event', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    adapter.behavior = 'guarded-with-silent-denied-read';
    const task = await end(tasks, await tasks.run({
      prompt: 'Silent denied read fixture.',
      workingDirectory: source,
      allowedTools: ['view_file', 'write_to_file'],
      mcpServers: [],
    }));
    assert.equal(task.status, 'completed', JSON.stringify(task.error));
    assert.equal(task.agentPolicyReceipt?.deniedReadCount, 1);
    assert.deepEqual(task.deniedReads, { total: 1, items: [] });
    const deniedReadEvents = tasks.readEvents(task.taskId).events.filter(event => event.type === 'task.denied-reads');
    assert.equal(deniedReadEvents.length, 1);
    assert.deepEqual(deniedReadEvents[0]!.data, { total: 1, items: [] });
  });
});

test('repair path accumulates deniedReads across windows, caps items at 50, and emits per-window event', async () => {
  await fixture(async ({ source, tasks, adapter }) => {
    const task = await end(tasks, await tasks.run({
      prompt: 'Repair accumulation fixture.',
      workingDirectory: source,
      allowedTools: ['view_file', 'write_to_file'],
      mcpServers: [],
    }));
    assert.equal(task.status, 'completed', JSON.stringify(task.error));

    const internal = tasks as unknown as {
      tasks: Map<string, { record: TaskRecord }>;
      repairLocalTest: (task: unknown, request: unknown, observedExitCode: number, timeoutSeconds: number) => Promise<void>;
    };
    const internalTask = internal.tasks.get(task.taskId)!;
    const repairRequest = { executable: process.execPath, args: ['-e', 'process.exit(0)'] };

    adapter.behavior = 'guarded-with-denied-read';
    await internal.repairLocalTest(internalTask, repairRequest, 1, 30);
    assert.equal(internalTask.record.deniedReads?.total, 2);
    assert.equal(internalTask.record.deniedReads?.items.length, 2);

    await internal.repairLocalTest(internalTask, repairRequest, 1, 30);
    assert.equal(internalTask.record.deniedReads?.total, 4);
    assert.equal(internalTask.record.deniedReads?.items.length, 4);

    internalTask.record.deniedReads = {
      total: 49,
      items: Array.from({ length: 49 }, (_, index) => ({
        toolName: 'view_file',
        path: `prior-${index}.txt`,
        reason: 'denied by pre-tool hook',
      })),
    };
    await internal.repairLocalTest(internalTask, repairRequest, 1, 30);
    assert.equal(internalTask.record.deniedReads?.total, 51);
    assert.equal(internalTask.record.deniedReads?.items.length, 50);
    assert.match(internalTask.record.deniedReads?.items[49]?.path ?? '', /missing-inside\.txt$/);

    const deniedReadEvents = tasks.readEvents(task.taskId).events.filter(event => event.type === 'task.denied-reads');
    assert.equal(deniedReadEvents.length, 3);
    for (const event of deniedReadEvents) {
      const payload = event.data as { total: number; items: unknown[] };
      assert.equal(payload.total, 2);
      assert.equal(payload.items.length, 2);
    }
  });
});
