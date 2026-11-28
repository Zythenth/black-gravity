import assert from 'node:assert/strict';
import { execFileSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { AgyExecutionAdapter, classifyConversationNotFound } from '../src/agy-execution-adapter.js';
import { CliAdapter, formatResumeNotice, taskPrompt, type Model } from '../src/cli-adapter.js';
import { loadConfig, type Config } from '../src/config.js';
import { createProjectCopy } from '../src/isolation.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError, type RunOptions } from '../src/types.js';
import { archiveDirectoryFor, restoreTaskCheckpointIntoWorkspace } from '../src/workspace-archive.js';
import { canonicalWorkspacePaths, readWorkspaceMetadata } from '../src/workspace-paths.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { waitForTask } from './wait-for-task.js';

async function createRepo(parent: string, name: string): Promise<string> {
  const repo = path.join(parent, name);
  await mkdir(repo, { recursive: true });
  execFileSync('git', ['init', '--quiet', repo]);
  await writeFile(path.join(repo, 'source.txt'), 'original-source\n', 'utf8');
  return await realpath(repo);
}

class ScriptedReviewAdapter extends ControlledCliAdapter {
  private readonly adapterConfig: Config;
  calls: Array<{ options: RunOptions; cwd: string; promptText: string; args: string[] }> = [];
  nextBehavior: (ctx: { options: RunOptions; cwd: string; promptText: string; conversationId: string }) => {
    status?: 'SUCCESS' | 'ERROR';
    exitCode?: number;
    conversationId?: string;
    omitSessionId?: boolean;
    errorText?: string;
    stderrText?: string;
    emitToolStep?: boolean;
    response?: string;
    structuredOutput?: unknown;
    onRun?: () => void;
  } = () => ({ status: 'SUCCESS', exitCode: 0 });

  constructor(config: Config) {
    super(config);
    this.adapterConfig = config;
  }

  override async listModels(): Promise<Model[]> {
    return [{ id: 'mock-pro', name: 'Mock Pro' }];
  }

  override spawnTask(options: RunOptions, model: string | undefined, cwd: string): ChildProcessWithoutNullStreams {
    const child = new EventEmitter() as ChildProcessWithoutNullStreams;
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let closed = false;
    const closeOnce = (code: number) => {
      if (closed) return;
      closed = true;
      Object.assign(child, { exitCode: code });
      stdout.end();
      stderr.end();
      child.emit('close', code);
    };
    Object.assign(child, {
      pid: undefined,
      stdin,
      stdout,
      stderr,
      exitCode: null,
      killed: false,
      kill() {
        Object.assign(child, { killed: true });
        closeOnce(1);
        return true;
      },
    });
    const args = [
      '--sandbox',
      '--input-format', 'stream-json',
      '--output-format', 'stream-json',
      '--print-timeout', `${options.timeoutSeconds ?? this.adapterConfig.defaultTimeoutSeconds}s`,
    ];
    if (!options.sessionId) args.push('--new-project');
    args.push('--mode', options.mode === 'read-only' ? 'plan' : 'accept-edits');
    if (model) args.push('--model', model);
    if (options.sessionId) args.push('--conversation', options.sessionId);
    const promptText = taskPrompt(options, this.adapterConfig.maxPromptChars);
    const defaultConversationId = options.sessionId ?? `session-${this.calls.length + 1}`;
    this.calls.push({ options: structuredClone(options), cwd, promptText, args });
    stdin.end(JSON.stringify({ event: 'user', message: { content: promptText } }) + '\n');
    const plan = this.nextBehavior({ options, cwd, promptText, conversationId: defaultConversationId });
    const conversationId = plan.conversationId ?? defaultConversationId;
    setImmediate(() => {
      if (closed) return;
      try {
        if (!plan.omitSessionId) {
          stdout.write(JSON.stringify({ event: 'init', conversation_id: conversationId, init: { cwd, args } }) + '\n');
        }
        if (plan.emitToolStep) {
          stdout.write(JSON.stringify({
            event: 'step_update',
            step_update: { step_index: 0, step_type: 'tool', tool_name: 'view_file', state: 'DONE', tool_info: {} },
          }) + '\n');
        }
        plan.onRun?.();
        if (closed) return;
        if (existsSync(path.join(cwd, '.agents', 'bridge-execution-hook.mjs')) && (plan.status ?? 'SUCCESS') === 'SUCCESS') {
          execFileSync(process.execPath, ['bridge-execution-hook.mjs'], {
            cwd: path.join(cwd, '.agents'),
            windowsHide: true,
            encoding: 'utf8',
            input: JSON.stringify({ toolCall: { name: 'finish', args: {} }, workspacePaths: [cwd], conversationId }),
          });
        }
        if (plan.stderrText) {
          stderr.write(plan.stderrText);
        }
        const status = plan.status ?? 'SUCCESS';
        stdout.write(JSON.stringify({
          event: 'result',
          result: {
            ...(plan.omitSessionId ? {} : { conversation_id: conversationId }),
            status,
            response: plan.response ?? (status === 'SUCCESS' ? promptText : ''),
            ...(plan.structuredOutput !== undefined ? { structured_output: plan.structuredOutput } : {}),
            ...(status === 'ERROR' ? { error: plan.errorText ?? 'scripted failure' } : {}),
          },
        }) + '\n');
        closeOnce(plan.exitCode ?? (status === 'SUCCESS' ? 0 : 1));
      } catch (error) {
        stderr.write(String(error));
        closeOnce(1);
      }
    });
    return child;
  }
}

function unarchiveTaskSnapshot(stateDir: string, taskId: string): void {
  rmSync(archiveDirectoryFor(stateDir, taskId), { recursive: true, force: true });
  const snapshotPath = path.join(stateDir, `${taskId}.json`);
  const snap = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
    project: { archivedAt?: string; archiveSha256?: string };
  };
  delete snap.project.archivedAt;
  delete snap.project.archiveSha256;
  writeFileSync(snapshotPath, JSON.stringify(snap), 'utf8');
}

test('B1: restoring older same-lineage task A refuses when newer sibling B is unarchived occupant, leaving bytes and metadata intact', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-b1-resume-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const managers: TaskManager[] = [];
  t.after(async () => {
    for (const manager of managers) await manager.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const adapter1 = new ScriptedReviewAdapter(config);
  const tasks1 = new TaskManager(adapter1, config);
  managers.push(tasks1);

  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    conversationId: 'conv-lineage-a',
    onRun: () => { writeFileSync(path.join(cwd, 'alpha.txt'), 'alpha-from-A\n', 'utf8'); },
  });
  const taskA = await waitForTask(tasks1, (await tasks1.run({ prompt: 'step A', workingDirectory: repo })).taskId);
  assert.equal(taskA.status, 'completed', JSON.stringify(taskA.error));

  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    conversationId: 'conv-lineage-b',
    onRun: () => { writeFileSync(path.join(cwd, 'beta.txt'), 'precious-unarchived-B\n', 'utf8'); },
  });
  const taskB = await waitForTask(tasks1, (await tasks1.resume({ prompt: 'step B', workingDirectory: repo }, taskA.taskId)).taskId);
  assert.equal(taskB.status, 'completed', JSON.stringify(taskB.error));
  await tasks1.shutdown();

  // Make newer same-lineage occupant B unarchived.
  unarchiveTaskSnapshot(stateDir, taskB.taskId);
  const canonical = canonicalWorkspacePaths(stateDir, repo);
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskB.taskId);

  const adapter2 = new ScriptedReviewAdapter(config);
  const tasks2 = new TaskManager(adapter2, config);
  managers.push(tasks2);

  // Resuming older same-lineage task A MUST refuse without wiping B or launching adapter.
  await assert.rejects(
    () => tasks2.resume({ prompt: 'attempt resume older A', workingDirectory: repo }, taskA.taskId),
    err => err instanceof BridgeError && err.code === 'TASK_NOT_READY',
  );
  assert.equal(adapter2.calls.length, 0);
  assert.equal(readFileSync(path.join(canonical.copyDirectory, 'beta.txt'), 'utf8'), 'precious-unarchived-B\n');
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskB.taskId);

  // Native agy test targeting older task A (distinct sessionId) also refuses without wiping unarchived sibling B.
  const previewA = await tasks2.preview(taskA.taskId);
  await assert.rejects(
    () => tasks2.startTests(taskA.taskId, previewA.sha256, { executable: 'node', args: ['-v'] }),
    err => err instanceof BridgeError && err.code === 'TASK_NOT_READY',
  );
  assert.equal(adapter2.calls.length, 0);
  assert.equal(readFileSync(path.join(canonical.copyDirectory, 'beta.txt'), 'utf8'), 'precious-unarchived-B\n');
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskB.taskId);

  // Positive control: resuming exact positive occupant B in-place is allowed and preserves B's bytes.
  let observedBeta = '';
  adapter2.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    conversationId: 'conv-lineage-b',
    onRun: () => { observedBeta = readFileSync(path.join(cwd, 'beta.txt'), 'utf8'); },
  });
  const resumedB = await waitForTask(tasks2, (await tasks2.resume({ prompt: 'continue exact occupant B', workingDirectory: repo }, taskB.taskId)).taskId);
  assert.equal(resumedB.status, 'completed', JSON.stringify(resumedB.error));
  assert.equal(observedBeta, 'precious-unarchived-B\n');
});

test('B1: local native-test executor refuses to wipe an unarchived occupant when restoring parent checkpoint', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-b1-native-test-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'linux-bwrap',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const managers: TaskManager[] = [];
  t.after(async () => {
    for (const manager of managers) await manager.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const adapter1 = new ScriptedReviewAdapter(config);
  const tasks1 = new TaskManager(adapter1, config, undefined, {
    linuxBwrapDetection: { available: true, path: '/nonexistent/bwrap-should-not-launch', version: '0.11.1' },
  });
  managers.push(tasks1);

  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    conversationId: 'conv-parent-a',
    onRun: () => { writeFileSync(path.join(cwd, 'a.txt'), 'from-A\n', 'utf8'); },
  });
  const taskA = await waitForTask(tasks1, (await tasks1.run({
    prompt: 'task A',
    workingDirectory: repo,
    acceptanceCriteria: [{ id: 'a1', description: 'a.txt exists', check: { kind: 'file-contains', path: 'a.txt', text: 'from-A' } }],
  })).taskId);
  assert.equal(taskA.status, 'completed');

  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    conversationId: 'conv-other-c',
    onRun: () => { writeFileSync(path.join(cwd, 'c.txt'), 'precious-unarchived-C\n', 'utf8'); },
  });
  const taskC = await waitForTask(tasks1, (await tasks1.run({ prompt: 'task C', workingDirectory: repo })).taskId);
  assert.equal(taskC.status, 'completed');
  await tasks1.shutdown();

  // Leave occupant C unarchived while starting a local native test on archived task A.
  unarchiveTaskSnapshot(stateDir, taskC.taskId);
  const canonical = canonicalWorkspacePaths(stateDir, repo);

  const adapter2 = new ScriptedReviewAdapter(config);
  const tasks2 = new TaskManager(adapter2, config, undefined, {
    linuxBwrapDetection: { available: true, path: '/nonexistent/bwrap-should-not-launch', version: '0.11.1' },
  });
  managers.push(tasks2);

  const previewA = await tasks2.preview(taskA.taskId);
  const testTask = await waitForTask(
    tasks2,
    (await tasks2.startTests(taskA.taskId, previewA.sha256, { executable: 'node', args: ['-v'] })).taskId,
  );
  assert.equal(testTask.status, 'failed');
  assert.equal(testTask.error?.code, 'TASK_NOT_READY');
  assert.equal(adapter2.calls.length, 0);
  assert.equal(readFileSync(path.join(canonical.copyDirectory, 'c.txt'), 'utf8'), 'precious-unarchived-C\n');
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskC.taskId);
  // N1: refused pre-prepare test MUST NOT archive C's foreign bytes under testTask.taskId, MUST NOT be resumable, and MUST NOT shadow A.
  assert.equal(existsSync(archiveDirectoryFor(stateDir, testTask.taskId)), false);
  await assert.rejects(
    () => tasks2.resume({ prompt: 'cannot resume refused test', workingDirectory: repo }, testTask.taskId),
    err => err instanceof BridgeError && err.code === 'INVALID_SESSION',
  );
  // Discarding C leaves A as the latest valid task in A's lineage so A can still be verified and integrated cleanly.
  await tasks2.discard(taskC.taskId);
  const verifiedA = await tasks2.verify(taskA.taskId, previewA.sha256, [{
    criterionId: 'a1', verdict: 'passed', path: 'a.txt', line: 1, quote: 'from-A', explanation: 'verified A',
  }]);
  assert.equal(verifiedA.status, 'passed');
  const integratedA = await tasks2.integrate(taskA.taskId, previewA.sha256);
  assert.equal(integratedA.sha256, previewA.sha256);
  assert.equal(await readFile(path.join(repo, 'a.txt'), 'utf8'), 'from-A\n');
  assert.equal(existsSync(path.join(repo, 'c.txt')), false);
});

test('N2: startTests on agy backend restores displaced parent archive, publishes child taskId, keeps parent immutable during repair, enforces POLICY_TEST_EXECUTOR_UNAVAILABLE, and rejects unpinned archives', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-n2-agy-test-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');

  const mockCliPath = path.join(root, 'n2-agy-cli.mjs');
  writeFileSync(mockCliPath, `
import { execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
if (args.includes('--version')) { console.log('agy 2.0.0-mock'); process.exit(0); }
if (args.includes('--help')) {
  console.log('Usage: agy --sandbox --input-format stream-json --output-format stream-json --mode plan accept-edits --model --conversation --new-project --add-dir --json-schema models');
  process.exit(0);
}
if (args[0] === 'models') { console.log('mock-pro Mock Pro'); process.exit(0); }
let stdin = '';
for await (const chunk of process.stdin) stdin += chunk;
const prompt = JSON.parse(stdin.trim()).message.content;
const convIdx = args.indexOf('--conversation');
const convId = convIdx >= 0 ? args[convIdx + 1] : (prompt.includes('task B') ? 'conv-b' : 'conv-a');
console.log(JSON.stringify({ event: 'init', conversation_id: convId, init: { model: 'mock-pro' } }));
const nativeMatch = prompt.match(/<bridge-test-command>(.*?)<\\/bridge-test-command>/s);
if (nativeMatch) {
  const req = JSON.parse(nativeMatch[1]);
  if (!existsSync(path.join(process.cwd(), 'a.txt')) || existsSync(path.join(process.cwd(), 'b.txt'))) {
    process.stderr.write('wrong workspace bytes before native test\\n');
    process.exit(45);
  }
  if (readFileSync(path.join(process.cwd(), 'a.txt'), 'utf8') !== 'from-parent-A\\n') {
    process.stderr.write('parent A bytes mismatch\\n');
    process.exit(46);
  }
  for (let i = 0; i < req.maxAttempts; i++) {
    const out = execSync(req.commandLine, { cwd: process.cwd(), encoding: 'utf8', windowsHide: true, shell: process.platform === 'win32' ? 'powershell.exe' : '/bin/sh' });
    console.log(JSON.stringify({ event: 'step_update', step_update: { step_index: i, state: 'DONE', step_type: 'tool', tool_name: 'run_command', tool_info: { parameters: { CommandLine: req.commandLine }, output: out } } }));
    const receiptB64 = out.trim().split('\\n').at(-1).split(':').at(-1);
    const parsed = JSON.parse(Buffer.from(receiptB64, 'base64').toString('utf8'));
    if (parsed.exitCode === 0) break;
    writeFileSync(path.join(process.cwd(), 'a.txt'), 'repaired-by-child\\n', 'utf8');
  }
  console.log(JSON.stringify({ event: 'result', result: { conversation_id: convId, status: 'SUCCESS', response: 'repaired and passed' } }));
  process.exit(0);
}
if (prompt.includes('task A')) {
  writeFileSync(path.join(process.cwd(), 'a.txt'), 'from-parent-A\\n', 'utf8');
} else if (prompt.includes('task B')) {
  writeFileSync(path.join(process.cwd(), 'b.txt'), 'from-displacing-B\\n', 'utf8');
}
console.log(JSON.stringify({ event: 'result', result: { conversation_id: convId, status: 'SUCCESS', response: 'done' } }));
process.exit(0);
`, 'utf8');

  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const cli = new CliAdapter(config, [mockCliPath]);
  await cli.discover();
  const tasks = new TaskManager(cli, config);
  t.after(async () => {
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const taskA = await waitForTask(tasks, (await tasks.run({ prompt: 'task A', workingDirectory: repo })).taskId);
  assert.equal(taskA.status, 'completed', JSON.stringify(taskA.error));
  const previewA = await tasks.preview(taskA.taskId);

  // Displace A in the canonical workspace with task B.
  const taskB = await waitForTask(tasks, (await tasks.run({ prompt: 'task B', workingDirectory: repo })).taskId);
  assert.equal(taskB.status, 'completed', JSON.stringify(taskB.error));
  const canonical = canonicalWorkspacePaths(stateDir, repo);
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskB.taskId);

  // startTests on displaced parent A with repair (retries: 1) restores A's archive, publishes child taskId, and edits only child.
  const command = {
    executable: process.execPath,
    args: ['-e', "const fs=require('node:fs');process.exit(fs.readFileSync('a.txt','utf8')==='repaired-by-child\\n'?0:9)"],
  };
  const childTest = await waitForTask(tasks, (await tasks.startTests(taskA.taskId, previewA.sha256, command, 1, 20)).taskId);
  assert.equal(childTest.status, 'completed', JSON.stringify(childTest.error));
  assert.deepEqual(childTest.tests?.map(entry => entry.exitCode), [9, 0]);
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, childTest.taskId);
  const childReady = tasks.readEvents(childTest.taskId).events.find(e => e.type === 'copy.ready')?.data as { preparationMs?: number; scopeSha256?: string } | undefined;
  assert.equal(typeof childReady?.preparationMs, 'number');
  assert.match(childReady?.scopeSha256 ?? '', /^[a-f0-9]{64}$/);

  // Parent A remains immutable: same preview hash and original bytes.
  const previewAAfter = await tasks.preview(taskA.taskId);
  assert.equal(previewAAfter.sha256, previewA.sha256);
  const patchA = await tasks.readPatch(taskA.taskId, previewA.sha256, 'a.txt');
  assert.ok(patchA.text.includes('from-parent-A'));
  assert.equal(patchA.text.includes('repaired-by-child'), false);

  // Child test task has its own distinct patch with repaired bytes.
  const previewChild = await tasks.preview(childTest.taskId);
  assert.notEqual(previewChild.sha256, previewA.sha256);
  const patchChild = await tasks.readPatch(childTest.taskId, previewChild.sha256, 'a.txt');
  assert.ok(patchChild.text.includes('repaired-by-child'));

  // Guarded backend contract: tasks with agentPolicy cannot use agy backend for startTests.
  const guardedAdapter = new ScriptedReviewAdapter(config);
  const guardedState = path.join(root, 'state-guarded');
  mkdirSync(guardedState, { recursive: true });
  const guardedConfig = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: guardedState,
  });
  const guardedTasks = new TaskManager(guardedAdapter, guardedConfig);
  t.after(async () => { await guardedTasks.shutdown(); });
  const guarded = await waitForTask(guardedTasks, (await guardedTasks.run({
    prompt: 'guarded task',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
  })).taskId);
  assert.equal(guarded.status, 'completed', JSON.stringify(guarded.error));
  const guardedPreview = await guardedTasks.preview(guarded.taskId);
  await assert.rejects(
    () => guardedTasks.startTests(guarded.taskId, guardedPreview.sha256, { executable: process.execPath, args: ['-v'] }),
    err => err instanceof BridgeError && err.code === 'POLICY_TEST_EXECUTOR_UNAVAILABLE',
  );
});

test('B2: createProjectCopy and restoreTaskCheckpointIntoWorkspace atomically invalidate occupant before first mutation and preserve safe archive reads and integration', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-b2-fence-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new ScriptedReviewAdapter(config);
  const tasks = new TaskManager(adapter, config);
  t.after(async () => {
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'x-work.txt'), 'verified-X-bytes\n', 'utf8'); },
  });
  const taskX = await waitForTask(tasks, (await tasks.run({
    prompt: 'create X',
    workingDirectory: repo,
    acceptanceCriteria: [{ id: 'x1', description: 'x-work exists', check: { kind: 'file-contains', path: 'x-work.txt', text: 'verified-X-bytes' } }],
  })).taskId);
  assert.equal(taskX.status, 'completed', JSON.stringify(taskX.error));
  const previewX = await tasks.preview(taskX.taskId);
  const verifiedX = await tasks.verify(taskX.taskId, previewX.sha256, [{
    criterionId: 'x1', verdict: 'passed', path: 'x-work.txt', line: 1, quote: 'verified-X-bytes', explanation: 'verified X',
  }]);
  assert.equal(verifiedX.status, 'passed');

  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'y-work.txt'), 'foreign-Y-bytes\n', 'utf8'); },
  });
  const taskY = await waitForTask(tasks, (await tasks.run({ prompt: 'create Y', workingDirectory: repo })).taskId);
  assert.equal(taskY.status, 'completed', JSON.stringify(taskY.error));

  const canonical = canonicalWorkspacePaths(stateDir, repo);

  // Restore X cleanly so X is the live occupant before fault injection.
  await restoreTaskCheckpointIntoWorkspace({
    stateDirectory: stateDir,
    sourceTaskId: taskX.taskId,
    targetTaskId: taskX.taskId,
    targetLineageId: randomUUID(),
    limits: config,
  });
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskX.taskId);

  // 1. Preflight failure in createProjectCopy leaves old occupant X and its bytes untouched.
  await assert.rejects(
    () => createProjectCopy(repo, ['nonexistent.txt'], undefined, config, [], undefined, {
      stateDirectory: stateDir,
      lineageId: randomUUID(),
      taskId: randomUUID(),
    }),
    err => err instanceof BridgeError && err.code === 'INVALID_INCLUDE_PATH',
  );
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskX.taskId);
  assert.equal(readFileSync(path.join(canonical.copyDirectory, 'x-work.txt'), 'utf8'), 'verified-X-bytes\n');

  // 2. Post-first-mutation failure in createProjectCopy leaves metadata invalidated (never naming X).
  let invalidatedBeforeCallback = false;
  await assert.rejects(
    () => createProjectCopy(
      repo,
      undefined,
      () => {
        invalidatedBeforeCallback = readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId === undefined;
        throw new Error('injected post-empty createProjectCopy fault');
      },
      config,
      [],
      undefined,
      { stateDirectory: stateDir, lineageId: randomUUID(), taskId: randomUUID() },
    ),
    /injected post-empty createProjectCopy fault/,
  );
  assert.equal(invalidatedBeforeCallback, true);
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, undefined);
  assert.equal(existsSync(path.join(canonical.copyDirectory, 'x-work.txt')), false);

  // Safe archive reads still return X's verified preview/patch/verification despite the emptied workspace.
  const previewXAfterCreateFault = await tasks.preview(taskX.taskId);
  assert.equal(previewXAfterCreateFault.sha256, previewX.sha256);
  const patchXAfterCreateFault = await tasks.readPatch(taskX.taskId, previewX.sha256, 'x-work.txt');
  assert.ok(patchXAfterCreateFault.text.includes('verified-X-bytes'));

  // 3. Restore X cleanly, then inject fault during restore of Y after foreign bytes are written (before-publish).
  await restoreTaskCheckpointIntoWorkspace({
    stateDirectory: stateDir,
    sourceTaskId: taskX.taskId,
    targetTaskId: taskX.taskId,
    targetLineageId: randomUUID(),
    limits: config,
  });
  assert.equal(readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId, taskX.taskId);

  let invalidatedBeforeFirstMutation = false;
  let oldBytesStillPresentAtInvalidate = false;
  await assert.rejects(
    () => restoreTaskCheckpointIntoWorkspace({
      stateDirectory: stateDir,
      sourceTaskId: taskY.taskId,
      targetTaskId: randomUUID(),
      targetLineageId: randomUUID(),
      limits: config,
      onStage: stage => {
        if (stage === 'after-invalidate') {
          invalidatedBeforeFirstMutation = readWorkspaceMetadata(canonical.metadataPath)?.currentTaskId === undefined;
          oldBytesStillPresentAtInvalidate = existsSync(path.join(canonical.copyDirectory, 'x-work.txt'));
        }
        if (stage === 'before-publish') {
          assert.equal(existsSync(path.join(canonical.copyDirectory, 'y-work.txt')), true);
          throw new Error('injected before-publish restore fault');
        }
      },
    }),
    /injected before-publish restore fault/,
  );
  assert.equal(invalidatedBeforeFirstMutation, true);
  assert.equal(oldBytesStillPresentAtInvalidate, true);
  const fencedMeta = readWorkspaceMetadata(canonical.metadataPath);
  assert.equal(fencedMeta?.currentTaskId, undefined);
  assert.equal(fencedMeta?.fencedReason, 'restore');
  assert.equal(typeof fencedMeta?.fencedAt, 'string');

  // Negative guards on fenced failed-prep:
  // (a) Missing fenced metadata refuses integration with COPY_MISSING.
  const savedFencedMetaRaw = readFileSync(canonical.metadataPath, 'utf8');
  writeFileSync(canonical.metadataPath, JSON.stringify({
    version: 1,
    sourceDirectory: repo,
    rootKey: canonical.rootKey,
    updatedAt: new Date().toISOString(),
  }) + '\n', 'utf8');
  await assert.rejects(
    () => tasks.integrate(taskX.taskId, previewX.sha256),
    err => err instanceof BridgeError && err.code === 'COPY_MISSING',
  );
  writeFileSync(canonical.metadataPath, savedFencedMetaRaw, 'utf8');

  // (b) Cleanup fence marker present in baseline refuses integration with GIT_CLEANUP_UNVERIFIED.
  const fenceMarkerPath = path.join(canonical.gitDirectory, 'CLEANUP_UNVERIFIED');
  writeFileSync(fenceMarkerPath, JSON.stringify({ code: 'GIT_CLEANUP_UNVERIFIED', version: 1 }) + '\n', 'utf8');
  await assert.rejects(
    () => tasks.integrate(taskX.taskId, previewX.sha256),
    err => err instanceof BridgeError && err.code === 'GIT_CLEANUP_UNVERIFIED',
  );
  rmSync(fenceMarkerPath, { force: true });

  // Preview, verify, and integrate for X safely use X's archive under verified fenced failed-prep metadata and never publish Y's foreign bytes.
  const previewXAfterRestoreFault = await tasks.preview(taskX.taskId);
  assert.equal(previewXAfterRestoreFault.sha256, previewX.sha256);
  assert.deepEqual(previewXAfterRestoreFault.files.map(f => f.path), ['x-work.txt']);
  const integrated = await tasks.integrate(taskX.taskId, previewX.sha256);
  assert.equal(integrated.sha256, previewX.sha256);
  assert.equal(await readFile(path.join(repo, 'x-work.txt'), 'utf8'), 'verified-X-bytes\n');
  assert.equal(existsSync(path.join(repo, 'y-work.txt')), false);
  const metaAfterIntegrate = readWorkspaceMetadata(canonical.metadataPath);
  assert.equal(metaAfterIntegrate?.currentTaskId, taskX.taskId);
  assert.equal(metaAfterIntegrate?.fencedAt, undefined);
  assert.equal(metaAfterIntegrate?.fencedReason, undefined);
});

test('B3: formatResumeNotice forbids period, colon, semicolon and exclamation anywhere and excludes raw prompt and patch', async t => {
  const withConv = formatResumeNotice({
    hasConversation: true,
    previousTaskId: randomUUID(),
    previousStatus: 'failed',
    knownCause: 'timeout: process failed! see err.log; retry',
  });
  assert.equal(/[.:;!]/.test(withConv), false, withConv);
  assert.equal(withConv.includes('done so far:'), false);
  assert.equal(withConv.includes('; remaining:'), false);

  const withoutConv = formatResumeNotice({
    hasConversation: false,
    previousTaskId: randomUUID(),
    previousStatus: 'failed',
    knownCause: 'error: conversation stale.id; missing!',
    doneFiles: ['src/app.ts', 'weird:name;bang!.txt'],
    remainingSummary: 'finish: step 1. check; done!',
  });
  assert.equal(/[.:;!]/.test(withoutConv), false, withoutConv);
  assert.equal(withoutConv.includes('done so far:'), false);
  assert.equal(withoutConv.includes('; remaining:'), false);
  assert.equal(withoutConv.includes('diff --git'), false);
  assert.ok(withoutConv.includes('2 changed files'));

  // Classifier unit checks (N4): require explicit provider conversation diagnostic tied to exact requested conversation ID;
  // reject wrong IDs, bare generic "session", missing IDs, auth/quota/server errors, and ordinary failures.
  assert.equal(classifyConversationNotFound('Conversation abc-123 not found', 'abc-123')?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(classifyConversationNotFound('Error: no such conversation abc-123', 'abc-123')?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(classifyConversationNotFound('failed to resume conversation abc-123', 'abc-123')?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(classifyConversationNotFound('conversation not found: abc-123', 'abc-123')?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(classifyConversationNotFound('Conversation other-999 not found', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('Conversation ABC-123 not found', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('Error: no such conversation id', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('session abc-123 not found', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('failed to resume session abc-123', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('authentication required: conversation abc-123 not found', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('401 unauthorized: conversation abc-123 not found', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('quota exceeded: conversation abc-123 not found', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('file not found: src/app.ts', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('internal server error', 'abc-123'), undefined);
  assert.equal(classifyConversationNotFound('rate limit exceeded', 'abc-123'), undefined);

  // Verify TaskManager never puts raw new prompt into remainingSummary.
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-b3-noprompt-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new ScriptedReviewAdapter(config);
  const tasks = new TaskManager(adapter, config);
  t.after(async () => {
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  adapter.nextBehavior = ({ cwd }) => ({
    status: 'ERROR',
    exitCode: 1,
    omitSessionId: true,
    onRun: () => { writeFileSync(path.join(cwd, 'part.ts'), 'export const x = 1;\n', 'utf8'); },
  });
  const failed = await waitForTask(tasks, (await tasks.run({
    prompt: 'initial work',
    workingDirectory: repo,
    acceptanceCriteria: [{ id: 'c1', description: 'part exists', check: { kind: 'file-exists', path: 'part.ts' } }],
  })).taskId);
  assert.equal(failed.status, 'failed');

  adapter.nextBehavior = () => ({ status: 'SUCCESS' });
  const rawFollowup = 'RAW_NEW_PROMPT_MARKER_999: please finish step 1. and verify!';
  const resumed = await waitForTask(tasks, (await tasks.resume({ prompt: rawFollowup, workingDirectory: repo }, failed.taskId)).taskId);
  assert.equal(resumed.status, 'completed', JSON.stringify(resumed.error));
  const call = adapter.calls.at(-1)!;
  const noticeLine = call.promptText.split('\n').find(line => line.startsWith('Starting a fresh conversation'));
  assert.ok(noticeLine, call.promptText);
  assert.equal(/[.:;!]/.test(noticeLine), false, noticeLine);
  assert.equal(noticeLine.includes('RAW_NEW_PROMPT_MARKER_999'), false, noticeLine);
  assert.ok(noticeLine.includes('part ts'), noticeLine);
});

test('B3: stale conversation ID with provider-reported absence starts fresh after safe checks while generic errors and unverified cleanup stay refused', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-b3-stale-conv-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');

  // Real subprocess mock CLI script so real process exit proof (processCleanup.verified) is exercised.
  const mockCliPath = path.join(root, 'stale-conv-cli.mjs');
  const behaviorFile = path.join(root, 'behavior.json');
  const logFile = path.join(root, 'invocations.jsonl');
  writeFileSync(mockCliPath, `
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
if (args.includes('--version')) { console.log('agy 2.0.0-mock'); process.exit(0); }
if (args.includes('--help')) {
  console.log('Usage: agy --sandbox --input-format stream-json --output-format stream-json --mode plan accept-edits --model --conversation --new-project --add-dir --json-schema models');
  process.exit(0);
}
if (args[0] === 'models') { console.log('mock-pro Mock Pro'); process.exit(0); }
let stdin = '';
for await (const chunk of process.stdin) stdin += chunk;
const prompt = JSON.parse(stdin.trim()).message.content;
const convIdx = args.indexOf('--conversation');
const convId = convIdx >= 0 ? args[convIdx + 1] : null;
appendFileSync(${JSON.stringify(logFile)}, JSON.stringify({ convId, args, prompt }) + '\\n', 'utf8');
const mode = JSON.parse(readFileSync(${JSON.stringify(behaviorFile)}, 'utf8')).mode;
if (mode === 'initial') {
  writeFileSync(path.join(process.cwd(), 'checkpoint.ts'), 'export const step = 1;\\n', 'utf8');
  console.log(JSON.stringify({ event: 'init', conversation_id: 'stale-conv-123', init: { model: 'mock-pro' } }));
  console.log(JSON.stringify({ event: 'result', result: { conversation_id: 'stale-conv-123', status: 'SUCCESS', response: 'saved checkpoint' } }));
  process.exit(0);
}
if (mode === 'generic-error' && convId === 'stale-conv-123') {
  process.stderr.write('internal backend failure\\n');
  process.exit(1);
}
if (mode === 'wrong-id' && convId === 'stale-conv-123') {
  process.stderr.write('Error: conversation other-conv-999 not found\\n');
  process.exit(1);
}
if (mode === 'auth-and-missing' && convId === 'stale-conv-123') {
  process.stderr.write('authentication required\\nError: conversation stale-conv-123 not found\\n');
  process.exit(1);
}
if (mode === 'quota-and-missing' && convId === 'stale-conv-123') {
  process.stderr.write('429 rate limit exceeded: conversation stale-conv-123 not found\\n');
  process.exit(1);
}
if (mode === 'response-then-missing' && convId === 'stale-conv-123') {
  console.log(JSON.stringify({ event: 'result', result: { status: 'ERROR', response: 'partial model output', error: 'Conversation stale-conv-123 not found' } }));
  process.exit(1);
}
if (mode === 'tool-then-missing' && convId === 'stale-conv-123') {
  console.log(JSON.stringify({ event: 'init', conversation_id: 'stale-conv-123', init: {} }));
  console.log(JSON.stringify({ event: 'step_update', step_update: { step_index: 0, step_type: 'tool', tool_name: 'view_file', state: 'DONE', tool_info: {} } }));
  console.log(JSON.stringify({ event: 'result', result: { status: 'ERROR', error: 'Conversation stale-conv-123 not found' } }));
  process.exit(1);
}
if (mode === 'mutate-then-missing' && convId === 'stale-conv-123') {
  writeFileSync(path.join(process.cwd(), 'mutated.txt'), 'side-effect\\n', 'utf8');
  process.stderr.write('Conversation stale-conv-123 not found\\n');
  process.exit(1);
}
if (mode === 'stale-absent') {
  if (convId === 'stale-conv-123') {
    process.stderr.write('Error: conversation stale-conv-123 not found\\n');
    process.exit(1);
  }
  const existing = readFileSync(path.join(process.cwd(), 'checkpoint.ts'), 'utf8');
  if (!existing.includes('step = 1')) process.exit(44);
  console.log(JSON.stringify({ event: 'init', conversation_id: 'fresh-conv-456', init: { model: 'mock-pro' } }));
  console.log(JSON.stringify({ event: 'result', result: { conversation_id: 'fresh-conv-456', status: 'SUCCESS', response: 'completed in fresh conversation' } }));
  process.exit(0);
}
process.exit(2);
`, 'utf8');

  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const cli = new CliAdapter(config, [mockCliPath]);
  await cli.discover();
  const tasks = new TaskManager(cli, config);
  t.after(async () => {
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const readInvocations = () => existsSync(logFile)
    ? readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as { convId: string | null; args: string[]; prompt: string })
    : [];

  // Initial completed task with conversation ID 'stale-conv-123'.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'initial' }), 'utf8');
  const initial = await waitForTask(tasks, (await tasks.run({ prompt: 'create checkpoint', workingDirectory: repo })).taskId);
  assert.equal(initial.status, 'completed', JSON.stringify(initial.error));
  assert.equal(initial.sessionId, 'stale-conv-123');

  // 1. Generic error -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'generic-error' }), 'utf8');
  const beforeGeneric = readInvocations().length;
  const genericFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume generic', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(genericFail.status, 'failed');
  assert.equal(genericFail.error?.code, 'AGY_PROCESS_FAILED');
  assert.equal(readInvocations().length, beforeGeneric + 1);

  // 1b. Wrong conversation ID -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'wrong-id' }), 'utf8');
  const beforeWrongId = readInvocations().length;
  const wrongIdFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume wrong id', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(wrongIdFail.status, 'failed');
  assert.equal(wrongIdFail.error?.code, 'AGY_PROCESS_FAILED');
  assert.equal(readInvocations().length, beforeWrongId + 1);

  // 1c. Auth error prioritized over absent on stderr -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'auth-and-missing' }), 'utf8');
  const beforeAuth = readInvocations().length;
  const authFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume auth', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(authFail.status, 'failed');
  assert.equal(authFail.error?.code, 'AGY_AUTH_REQUIRED');
  assert.equal(readInvocations().length, beforeAuth + 1);

  // 1d. Quota/rate-limit error prioritized over absent on stderr -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'quota-and-missing' }), 'utf8');
  const beforeQuota = readInvocations().length;
  const quotaFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume quota', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(quotaFail.status, 'failed');
  assert.equal(quotaFail.error?.code, 'AGY_PROCESS_FAILED');
  assert.equal(readInvocations().length, beforeQuota + 1);

  // 1e. Model response text emitted with missing error -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'response-then-missing' }), 'utf8');
  const beforeResp = readInvocations().length;
  const respFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume resp', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(respFail.status, 'failed');
  assert.equal(respFail.error?.code, 'AGY_PROCESS_FAILED');
  assert.equal(readInvocations().length, beforeResp + 1);

  // 2. Tool step executed before missing error -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'tool-then-missing' }), 'utf8');
  const beforeTool = readInvocations().length;
  const toolFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume tool', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(toolFail.status, 'failed');
  assert.equal(toolFail.error?.code, 'AGY_PROCESS_FAILED');
  assert.equal(readInvocations().length, beforeTool + 1);

  // 3. Workspace mutated during failed attempt -> MUST NOT fall back.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'mutate-then-missing' }), 'utf8');
  const beforeMutate = readInvocations().length;
  const mutateFail = await waitForTask(tasks, (await tasks.resume({ prompt: 'try resume mutate', workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(mutateFail.status, 'failed');
  assert.equal(mutateFail.error?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(readInvocations().length, beforeMutate + 1);

  // 4. Reliably identified absent conversation with verified clean process exit and unchanged workspace -> falls back ONCE to fresh conversation.
  writeFileSync(behaviorFile, JSON.stringify({ mode: 'stale-absent' }), 'utf8');
  const beforeStale = readInvocations().length;
  const rawFollowup = 'FOLLOWUP_SECRET_TEXT_42: continue! now.';
  const recovered = await waitForTask(tasks, (await tasks.resume({ prompt: rawFollowup, workingDirectory: repo }, initial.taskId)).taskId);
  assert.equal(recovered.status, 'completed', JSON.stringify(recovered.error));
  assert.equal(recovered.sessionId, 'fresh-conv-456');
  const invocationsAfter = readInvocations();
  assert.equal(invocationsAfter.length, beforeStale + 2);
  const firstAttempt = invocationsAfter[beforeStale]!;
  const secondAttempt = invocationsAfter[beforeStale + 1]!;
  assert.equal(firstAttempt.convId, 'stale-conv-123');
  assert.equal(secondAttempt.convId, null);
  assert.equal(secondAttempt.args.includes('--conversation'), false);
  assert.equal(secondAttempt.args.includes('--new-project'), true);
  const noticeLine = secondAttempt.prompt.split('\n').find(line => line.startsWith('Starting a fresh conversation'));
  assert.ok(noticeLine, secondAttempt.prompt);
  assert.equal(/[.:;!]/.test(noticeLine), false, noticeLine);
  assert.equal(noticeLine.includes('FOLLOWUP_SECRET_TEXT_42'), false, noticeLine);
  assert.ok(noticeLine.includes('checkpoint ts'), noticeLine);
  assert.ok(tasks.readEvents(recovered.taskId).events.some(event => event.type === 'session.fallback'));

  // 5. Missing proof of process exit -> MUST NOT fall back even when provider reports conversation absent.
  const createSeededScenario = async (name: string) => {
    const scenarioState = path.join(root, name);
    mkdirSync(scenarioState, { recursive: true });
    const scenarioConfig = loadConfig({
      AGY_PATH: process.execPath,
      DEFAULT_TIMEOUT_SECONDS: '30',
      BRIDGE_TEST_EXECUTOR: 'agy',
      BRIDGE_STATE_DIRECTORY: scenarioState,
    });
    const scenarioExecutor = new AgyExecutionAdapter(cli, scenarioConfig);
    const scenarioTasks = new TaskManager(cli, scenarioConfig, scenarioExecutor);
    t.after(async () => { await scenarioTasks.shutdown(); });
    writeFileSync(behaviorFile, JSON.stringify({ mode: 'initial' }), 'utf8');
    const seededBase = await waitForTask(
      scenarioTasks,
      (await scenarioTasks.run({ prompt: 'base task', workingDirectory: repo })).taskId,
    );
    assert.equal(seededBase.status, 'completed', JSON.stringify(seededBase.error));
    assert.equal(seededBase.processCleanup?.verified, true, JSON.stringify(seededBase.processCleanup));
    return { scenarioExecutor, scenarioTasks, seededBase };
  };

  const {
    scenarioExecutor: unverifiedExecutor,
    scenarioTasks: unverifiedTasks,
    seededBase: unverifiedBase,
  } = await createSeededScenario('state-unverified');
  const realUnverifiedExecute = unverifiedExecutor.execute.bind(unverifiedExecutor);
  let executeCalls = 0;
  unverifiedExecutor.execute = (async (request, hooks) => {
    executeCalls += 1;
    if (request.session?.id) {
      const nowIso = new Date().toISOString();
      return {
        taskId: request.taskId,
        status: 'failed',
        error: { code: 'AGY_CONVERSATION_NOT_FOUND', message: 'Conversation stale-conv-123 not found' },
        spawnedPid: 999999,
        processCleanup: { verified: false, spawnedAt: nowIso, checkedAt: nowIso, remaining: 1, containment: 'tracked' },
      };
    }
    return realUnverifiedExecute(request, hooks as never);
  }) as typeof unverifiedExecutor.execute;

  const refusedUnverified = await waitForTask(
    unverifiedTasks,
    (await unverifiedTasks.resume({ prompt: 'must not fallback without exit proof', workingDirectory: repo }, unverifiedBase.taskId)).taskId,
  );
  assert.equal(refusedUnverified.status, 'failed');
  assert.equal(refusedUnverified.error?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(executeCalls, 1);

  // 6. Missing spawnedPid AND missing processCleanup (no PID + no proof) -> MUST NOT fall back.
  const {
    scenarioExecutor: noPidExecutor,
    scenarioTasks: noPidTasks,
    seededBase: noPidBase,
  } = await createSeededScenario('state-no-pid');
  const realNoPidExecute = noPidExecutor.execute.bind(noPidExecutor);
  let noPidCalls = 0;
  noPidExecutor.execute = (async (request, hooks) => {
    noPidCalls += 1;
    if (request.session?.id) {
      return {
        taskId: request.taskId,
        status: 'failed',
        error: { code: 'AGY_CONVERSATION_NOT_FOUND', message: 'Conversation stale-conv-123 not found' },
      };
    }
    return realNoPidExecute(request, hooks as never);
  }) as typeof noPidExecutor.execute;

  const refusedNoPid = await waitForTask(
    noPidTasks,
    (await noPidTasks.resume({ prompt: 'must not fallback with no pid and no cleanup proof', workingDirectory: repo }, noPidBase.taskId)).taskId,
  );
  assert.equal(refusedNoPid.status, 'failed');
  assert.equal(refusedNoPid.error?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(noPidCalls, 1);

  // 7. Prior allowed execution policy receipt decision (decisionCount > 0, deniedCount === 0) -> MUST NOT fall back.
  const policyState = path.join(root, 'state-policy-decision');
  mkdirSync(policyState, { recursive: true });
  const policyConfig = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: policyState,
  });
  const policyAdapter = new ScriptedReviewAdapter(policyConfig);
  const policyExecutor = new AgyExecutionAdapter(policyAdapter, policyConfig);
  const policyTasks = new TaskManager(policyAdapter, policyConfig, policyExecutor);
  t.after(async () => { await policyTasks.shutdown(); });

  const policyBase = await waitForTask(policyTasks, (await policyTasks.run({
    prompt: 'guarded base',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
  })).taskId);
  assert.equal(policyBase.status, 'completed', JSON.stringify(policyBase.error));

  const realPolicyExecute = policyExecutor.execute.bind(policyExecutor);
  let policyExecCalls = 0;
  policyExecutor.execute = (async (request, hooks) => {
    policyExecCalls += 1;
    if (request.session?.id) {
      const cwd = (hooks as { spawnWorkingDirectory?: string } | undefined)?.spawnWorkingDirectory ?? request.workingDirectory;
      execFileSync(process.execPath, ['bridge-execution-hook.mjs'], {
        cwd: path.join(cwd, '.agents'),
        windowsHide: true,
        encoding: 'utf8',
        input: JSON.stringify({ toolCall: { name: 'finish', args: {} }, workspacePaths: [cwd], conversationId: request.session.id }),
      });
      const nowIso = new Date().toISOString();
      return {
        taskId: request.taskId,
        status: 'failed',
        error: { code: 'AGY_CONVERSATION_NOT_FOUND', message: `Conversation ${request.session.id} not found` },
        spawnedPid: process.pid,
        processCleanup: { verified: true, spawnedAt: nowIso, checkedAt: nowIso, remaining: 0, containment: 'tracked' },
      };
    }
    return realPolicyExecute(request, hooks as never);
  }) as typeof policyExecutor.execute;

  const refusedPolicyDecision = await waitForTask(
    policyTasks,
    (await policyTasks.resume({ prompt: 'must not fallback after allowed receipt decision', workingDirectory: repo }, policyBase.taskId)).taskId,
  );
  assert.equal(refusedPolicyDecision.status, 'failed');
  assert.equal(refusedPolicyDecision.error?.code, 'AGY_CONVERSATION_NOT_FOUND');
  assert.equal(policyExecCalls, 1);
});

test('metrics: records measured preparationMs and scopeSha256 across fresh, restored resume, and handoff while preserving baseline, receipts and taskId reads', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-metrics-prep-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new ScriptedReviewAdapter(config);
  const tasks = new TaskManager(adapter, config);
  t.after(async () => {
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const canonical = canonicalWorkspacePaths(stateDir, repo);

  // 1. Fresh task
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'one.txt'), 'one-bytes\n', 'utf8'); },
  });
  const fresh = await waitForTask(tasks, (await tasks.run({
    prompt: 'fresh work',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
  })).taskId);
  assert.equal(fresh.status, 'completed', JSON.stringify(fresh.error));
  const freshReady = tasks.readEvents(fresh.taskId).events.find(e => e.type === 'copy.ready')?.data as { preparationMs?: number; scopeSha256?: string } | undefined;
  assert.equal(typeof freshReady?.preparationMs, 'number');
  assert.ok(freshReady!.preparationMs! >= 0);
  assert.match(freshReady?.scopeSha256 ?? '', /^[a-f0-9]{64}$/);
  assert.equal(typeof readWorkspaceMetadata(canonical.metadataPath)?.lastPreparedDurationMs, 'number');

  // 2. Displace fresh task with a second task so resuming fresh forces a checkpoint restore.
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'two.txt'), 'two-bytes\n', 'utf8'); },
  });
  const second = await waitForTask(tasks, (await tasks.run({
    prompt: 'second work',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
  })).taskId);
  assert.equal(second.status, 'completed', JSON.stringify(second.error));

  // 3. Restored resume of first task
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => {
      assert.equal(readFileSync(path.join(cwd, 'one.txt'), 'utf8'), 'one-bytes\n');
      assert.equal(existsSync(path.join(cwd, 'two.txt')), false);
    },
  });
  const restored = await waitForTask(tasks, (await tasks.resume({ prompt: 'resume first', workingDirectory: repo }, fresh.taskId)).taskId);
  assert.equal(restored.status, 'completed', JSON.stringify(restored.error));
  const restoredReady = tasks.readEvents(restored.taskId).events.find(e => e.type === 'copy.ready')?.data as { preparationMs?: number; scopeSha256?: string } | undefined;
  assert.equal(typeof restoredReady?.preparationMs, 'number');
  assert.ok(restoredReady!.preparationMs! >= 0);
  assert.match(restoredReady?.scopeSha256 ?? '', /^[a-f0-9]{64}$/);
  assert.equal(typeof readWorkspaceMetadata(canonical.metadataPath)?.lastPreparedDurationMs, 'number');
  assert.notEqual(restored.agentPolicyReceipt?.sha256, fresh.agentPolicyReceipt?.sha256);

  // 4. Handoff from first task (contextTaskId)
  const ctx = await tasks.context(fresh.taskId);
  adapter.nextBehavior = () => ({
    status: 'SUCCESS',
    response: 'reviewed first work',
    structuredOutput: {
      summary: 'reviewed first work',
      reviewedFiles: ['one.txt'],
      findings: [],
      unverified: ['host build not executed in mock'],
    },
  });
  const handoff = await waitForTask(tasks, (await tasks.run({
    prompt: 'review first work',
    workingDirectory: repo,
    contextTaskId: fresh.taskId,
    expectedContextSha256: ctx.treeSha256,
    role: 'reviewer',
    mode: 'read-only',
  })).taskId);
  assert.equal(handoff.status, 'completed', JSON.stringify(handoff.error));
  const handoffReady = tasks.readEvents(handoff.taskId).events.find(e => e.type === 'copy.ready')?.data as { preparationMs?: number; scopeSha256?: string } | undefined;
  assert.equal(typeof handoffReady?.preparationMs, 'number');
  assert.ok(handoffReady!.preparationMs! >= 0);
  assert.match(handoffReady?.scopeSha256 ?? '', /^[a-f0-9]{64}$/);
  assert.equal(typeof readWorkspaceMetadata(canonical.metadataPath)?.lastPreparedDurationMs, 'number');

  // All prior tasks stay inspectable by taskId with their own files.
  assert.deepEqual((await tasks.preview(fresh.taskId)).files.map(f => f.path), ['one.txt']);
  assert.deepEqual((await tasks.preview(second.taskId)).files.map(f => f.path), ['two.txt']);
});
