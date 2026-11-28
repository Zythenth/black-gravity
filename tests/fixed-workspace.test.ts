import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { CliAdapter, formatResumeNotice, taskPrompt, type Model } from '../src/cli-adapter.js';
import { loadConfig, type Config } from '../src/config.js';
import type { ExecutionAdapter, ExecutionContext, ExecutionRequest, ExecutionResult } from '../src/execution-contract.js';
import { PROCESS_CLEANUP_MARKER_NAME, upsertProcessCleanupMarkerEntrySync } from '../src/isolation.js';
import { BOOT_UNAVAILABLE_START, reconcileLaunchIdentity, recordedProcessStart } from '../src/process-tree.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError, type RunOptions, type TaskRecord } from '../src/types.js';
import { archiveDirectoryFor, loadVerifiedTaskArchive } from '../src/workspace-archive.js';
import {
  canonicalWorkspacePaths,
  ensureFixedWorkspaceLpacPermissions,
  readWorkspaceMetadata,
  verifyFixedWorkspaceLpacPermissions,
  type IcaclsRunner,
} from '../src/workspace-paths.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { waitForTask } from './wait-for-task.js';

const MOCK_AGY = fileURLToPath(new URL('../../tests/mock-agy.mjs', import.meta.url));
const BOOT_A = '11111111-2222-4333-8444-555555555555';
const BOOT_B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

async function createRepo(parent: string, name: string): Promise<string> {
  const repo = path.join(parent, name);
  await mkdir(repo, { recursive: true });
  execFileSync('git', ['init', '--quiet', repo]);
  await writeFile(path.join(repo, 'source.txt'), 'original-source\n', 'utf8');
  return await realpath(repo);
}

class ScriptedGuardedAdapter extends ControlledCliAdapter {
  private readonly adapterConfig: Config;
  calls: Array<{ options: RunOptions; cwd: string; promptText: string; args: string[] }> = [];
  nextBehavior: (ctx: { options: RunOptions; cwd: string; promptText: string; conversationId: string }) => {
    status?: 'SUCCESS' | 'ERROR';
    exitCode?: number;
    omitSessionId?: boolean;
    skipHook?: boolean;
    response?: string;
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
    const conversationId = options.sessionId ?? 'shared-mock-session';
    this.calls.push({ options: structuredClone(options), cwd, promptText, args });
    stdin.end(JSON.stringify({ event: 'user', message: { content: promptText } }) + '\n');
    const plan = this.nextBehavior({ options, cwd, promptText, conversationId });
    setImmediate(() => {
      if (closed) return;
      try {
        if (!plan.omitSessionId) {
          stdout.write(JSON.stringify({ event: 'init', conversation_id: conversationId, init: { cwd, args } }) + '\n');
        }
        plan.onRun?.();
        if (closed) return;
        if (!plan.skipHook && existsSync(path.join(cwd, '.agents', 'bridge-execution-hook.mjs'))) {
          const hook = spawnSync(process.execPath, ['bridge-execution-hook.mjs'], {
            cwd: path.join(cwd, '.agents'),
            windowsHide: true,
            encoding: 'utf8',
            input: JSON.stringify({ toolCall: { name: 'finish', args: {} }, workspacePaths: [cwd], conversationId }),
          });
          if (hook.status !== 0) {
            stderr.write(hook.stderr || 'hook failed');
          }
        }
        if (closed) return;
        const status = plan.status ?? 'SUCCESS';
        stdout.write(JSON.stringify({
          event: 'result',
          result: {
            ...(plan.omitSessionId ? {} : { conversation_id: conversationId }),
            status,
            response: plan.response ?? promptText,
            ...(status === 'ERROR' ? { error: 'scripted failure' } : {}),
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

test('fixed workspace uses one canonical private-state directory per root, cleans untracked build outputs and records preparation metrics', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-fixed-ws-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new CliAdapter(config, [MOCK_AGY]);
  await adapter.discover();
  const tasks = new TaskManager(adapter, config);
  t.after(async () => {
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const expected = canonicalWorkspacePaths(stateDir, repo);
  const first = await waitForTask(tasks, (await tasks.run({ prompt: 'write:one', workingDirectory: repo })).taskId);
  assert.equal(first.status, 'completed', JSON.stringify(first.error));
  assert.equal(first.copyDirectory, expected.copyDirectory);

  const firstReady = tasks.readEvents(first.taskId).events.find(e => e.type === 'copy.ready');
  assert.ok(firstReady);
  const firstReadyData = firstReady.data as { preparationMs?: number; scopeSha256?: string };
  assert.equal(typeof firstReadyData.preparationMs, 'number');
  assert.ok(firstReadyData.preparationMs! >= 0);
  assert.match(firstReadyData.scopeSha256 ?? '', /^[a-f0-9]{64}$/);
  assert.equal(typeof readWorkspaceMetadata(expected.metadataPath)?.lastPreparedDurationMs, 'number');

  // Drop untracked build artifacts into the canonical workspace before launching a second task.
  await mkdir(path.join(expected.copyDirectory, 'dist', 'nested'), { recursive: true });
  await writeFile(path.join(expected.copyDirectory, 'dist', 'nested', 'stale.js'), 'stale-output', 'utf8');
  await writeFile(path.join(expected.copyDirectory, 'stale-root.tmp'), 'leftover', 'utf8');

  const second = await waitForTask(tasks, (await tasks.run({ prompt: 'consult:clean', workingDirectory: repo })).taskId);
  assert.equal(second.status, 'completed', JSON.stringify(second.error));
  assert.equal(second.copyDirectory, expected.copyDirectory);
  assert.equal(existsSync(path.join(expected.copyDirectory, 'dist')), false);
  assert.equal(existsSync(path.join(expected.copyDirectory, 'stale-root.tmp')), false);
  assert.equal(existsSync(path.join(expected.copyDirectory, 'BLACK_GRAVITY_TEST.md')), false);
  assert.equal(await readFile(path.join(expected.copyDirectory, 'source.txt'), 'utf8'), 'original-source\n');
  // First task's archived preview and patch remain intact and inspectable by taskId.
  const firstPreview = await tasks.preview(first.taskId);
  assert.equal(firstPreview.summary.added, 1);
  assert.ok(firstPreview.files.some(f => f.path === 'BLACK_GRAVITY_TEST.md'));
});

test('proof: two tasks on the same path and mock sessionId with different patches resume by taskId after restart with own bytes and immutable receipts', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-proof-ws-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter1 = new ScriptedGuardedAdapter(config);
  const managers: TaskManager[] = [];
  t.after(async () => {
    for (const manager of managers) await manager.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const tasks1 = new TaskManager(adapter1, config);
  managers.push(tasks1);

  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'alpha.txt'), 'alpha-bytes-v1\n', 'utf8'); },
  });
  const taskA = await waitForTask(tasks1, (await tasks1.run({
    prompt: 'create alpha',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
    artifactPaths: ['alpha.txt'],
    acceptanceCriteria: [{ id: 'a', description: 'alpha exists', check: { kind: 'file-contains', path: 'alpha.txt', text: 'alpha-bytes-v1' } }],
  })).taskId);
  assert.equal(taskA.status, 'completed', JSON.stringify(taskA.error));
  assert.equal(taskA.sessionId, 'shared-mock-session');

  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'beta.txt'), 'beta-bytes-v1\n', 'utf8'); },
  });
  const taskB = await waitForTask(tasks1, (await tasks1.run({
    prompt: 'create beta',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
    artifactPaths: ['beta.txt'],
    acceptanceCriteria: [{ id: 'b', description: 'beta exists', check: { kind: 'file-contains', path: 'beta.txt', text: 'beta-bytes-v1' } }],
  })).taskId);
  assert.equal(taskB.status, 'completed', JSON.stringify(taskB.error));
  assert.equal(taskB.sessionId, 'shared-mock-session');
  assert.equal(taskA.copyDirectory, taskB.copyDirectory);

  const store = new StateStore(stateDir);
  const storedA = store.load().find(item => item.record.taskId === taskA.taskId)!;
  const storedB = store.load().find(item => item.record.taskId === taskB.taskId)!;
  const receiptAPath = storedA.project!.executionPolicy!.receiptPath;
  const receiptBPath = storedB.project!.executionPolicy!.receiptPath;
  assert.notEqual(receiptAPath, receiptBPath);
  const receiptABytesBefore = readFileSync(receiptAPath);
  const receiptBBytesBefore = readFileSync(receiptBPath);

  // Archived taskA still serves preview, readPatch, readArtifact, verify and context by taskId while taskB occupies the workspace.
  assert.ok(taskA.agentPolicyReceipt && taskA.agentPolicyReceipt.decisionCount >= 1 && taskA.agentPolicyReceipt.deniedCount === 0);
  assert.ok(taskB.agentPolicyReceipt && taskB.agentPolicyReceipt.decisionCount >= 1 && taskB.agentPolicyReceipt.deniedCount === 0);
  assert.notEqual(taskA.agentPolicyReceipt.sha256, taskB.agentPolicyReceipt.sha256);
  const previewA = await tasks1.preview(taskA.taskId);
  assert.deepEqual(previewA.files.map(f => f.path), ['alpha.txt']);
  const patchA = await tasks1.readPatch(taskA.taskId, previewA.sha256, 'alpha.txt');
  assert.ok(patchA.text.includes('alpha-bytes-v1'));
  const artifactA = await tasks1.readArtifact(taskA.taskId, 'alpha.txt', taskA.artifacts![0]!.sha256);
  assert.equal(Buffer.from(artifactA.content, 'base64').toString('utf8'), 'alpha-bytes-v1\n');
  const verifiedA = await tasks1.verify(taskA.taskId, previewA.sha256, [{
    criterionId: 'a', verdict: 'passed', path: 'alpha.txt', line: 1, quote: 'alpha-bytes-v1', explanation: 'Verified archived alpha',
  }]);
  assert.equal(verifiedA.status, 'passed');

  await tasks1.shutdown();

  // Restart #1: resume taskA by taskId and assert taskA's own bytes, distinct validated receipt, and immutable old receipts.
  const adapter2 = new ScriptedGuardedAdapter(config);
  const tasks2 = new TaskManager(adapter2, config);
  managers.push(tasks2);

  let observedOnResumeA: { alpha: string; hasBeta: boolean } | undefined;
  adapter2.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => {
      observedOnResumeA = {
        alpha: readFileSync(path.join(cwd, 'alpha.txt'), 'utf8'),
        hasBeta: existsSync(path.join(cwd, 'beta.txt')),
      };
    },
  });
  const resumedA = await waitForTask(tasks2, (await tasks2.resume({ prompt: 'continue alpha', workingDirectory: repo }, taskA.taskId)).taskId);
  assert.equal(resumedA.status, 'completed', JSON.stringify(resumedA.error));
  assert.ok(resumedA.agentPolicyReceipt && resumedA.agentPolicyReceipt.decisionCount >= 1 && resumedA.agentPolicyReceipt.deniedCount === 0);
  assert.deepEqual(observedOnResumeA, { alpha: 'alpha-bytes-v1\n', hasBeta: false });
  assert.deepEqual(readFileSync(receiptAPath), receiptABytesBefore);
  const storedResumedA = store.load().find(item => item.record.taskId === resumedA.taskId)!;
  const receiptResumedAPath = storedResumedA.project!.executionPolicy!.receiptPath;
  assert.notEqual(receiptResumedAPath, receiptAPath);
  const receiptResumedABytesBefore = readFileSync(receiptResumedAPath);

  // Old guarded finishes cannot validate a new turn that skips the hook; old receipts remain byte-for-byte unchanged.
  let observedOnBypassA: { hasAlpha: boolean; hasBeta: boolean } | undefined;
  adapter2.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    skipHook: true,
    onRun: () => {
      observedOnBypassA = {
        hasAlpha: existsSync(path.join(cwd, 'alpha.txt')),
        hasBeta: existsSync(path.join(cwd, 'beta.txt')),
      };
    },
  });
  const bypassResumeA = await waitForTask(tasks2, (await tasks2.resume({ prompt: 'bypass finish check', workingDirectory: repo }, resumedA.taskId)).taskId);
  assert.equal(bypassResumeA.status, 'failed');
  assert.equal(bypassResumeA.error?.code, 'AGENT_POLICY_UNVERIFIED');
  assert.deepEqual(observedOnBypassA, { hasAlpha: true, hasBeta: false });
  assert.deepEqual(readFileSync(receiptAPath), receiptABytesBefore);
  assert.deepEqual(readFileSync(receiptResumedAPath), receiptResumedABytesBefore);
  await tasks2.shutdown();

  // Restart #2: resume taskB by taskId and assert taskB's own bytes, validated receipt, and immutable receiptA/receiptB.
  const adapter3 = new ScriptedGuardedAdapter(config);
  const tasks3 = new TaskManager(adapter3, config);
  managers.push(tasks3);

  let observedOnResumeB: { beta: string; hasAlpha: boolean } | undefined;
  adapter3.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => {
      observedOnResumeB = {
        beta: readFileSync(path.join(cwd, 'beta.txt'), 'utf8'),
        hasAlpha: existsSync(path.join(cwd, 'alpha.txt')),
      };
    },
  });
  const resumedB = await waitForTask(tasks3, (await tasks3.resume({ prompt: 'continue beta', workingDirectory: repo }, taskB.taskId)).taskId);
  assert.equal(resumedB.status, 'completed', JSON.stringify(resumedB.error));
  assert.ok(resumedB.agentPolicyReceipt && resumedB.agentPolicyReceipt.decisionCount >= 1 && resumedB.agentPolicyReceipt.deniedCount === 0);
  assert.deepEqual(observedOnResumeB, { beta: 'beta-bytes-v1\n', hasAlpha: false });
  assert.deepEqual(readFileSync(receiptAPath), receiptABytesBefore);
  assert.deepEqual(readFileSync(receiptBPath), receiptBBytesBefore);
  assert.deepEqual(readFileSync(receiptResumedAPath), receiptResumedABytesBefore);
});

test('archive: corrupted checkpoint hash or pending unarchived occupant refuses before deleting bytes or launching next task', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-archive-refusal-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new ScriptedGuardedAdapter(config);
  const managers: TaskManager[] = [];
  t.after(async () => {
    for (const manager of managers) await manager.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const tasks1 = new TaskManager(adapter, config);
  managers.push(tasks1);
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'precious.txt'), 'keep-me-intact\n', 'utf8'); },
  });
  const first = await waitForTask(tasks1, (await tasks1.run({ prompt: 'write precious', workingDirectory: repo })).taskId);
  assert.equal(first.status, 'completed');
  const callsBefore = adapter.calls.length;

  // Tamper with archived patch hash; next task must refuse before overwriting precious.txt or launching adapter.
  const archiveDir = archiveDirectoryFor(stateDir, first.taskId);
  const verified = await loadVerifiedTaskArchive(stateDir, first.taskId);
  const patchPath = path.join(archiveDir, 'patch.diff');
  const originalPatch = readFileSync(patchPath, 'utf8');
  writeFileSync(patchPath, originalPatch + '\n# tampered', 'utf8');

  await assert.rejects(
    () => tasks1.run({ prompt: 'should refuse on hash mismatch', workingDirectory: repo }),
    err => err instanceof BridgeError && err.code === 'ARCHIVE_VERIFICATION_FAILED',
  );
  assert.equal(adapter.calls.length, callsBefore);
  assert.equal(readFileSync(path.join(first.copyDirectory!, 'precious.txt'), 'utf8'), 'keep-me-intact\n');

  // Restore patch, then simulate a pending unarchived task (remove archiveSha256 from persisted snapshot).
  writeFileSync(patchPath, originalPatch, 'utf8');
  assert.equal((await loadVerifiedTaskArchive(stateDir, first.taskId)).manifest.manifestSha256, verified.manifest.manifestSha256);
  await tasks1.shutdown();

  const snapshotPath = path.join(stateDir, `${first.taskId}.json`);
  const snap = JSON.parse(readFileSync(snapshotPath, 'utf8')) as { project: { archivedAt?: string; archiveSha256?: string } };
  delete snap.project.archivedAt;
  delete snap.project.archiveSha256;
  writeFileSync(snapshotPath, JSON.stringify(snap), 'utf8');

  const tasks2 = new TaskManager(adapter, config);
  managers.push(tasks2);
  await assert.rejects(
    () => tasks2.run({ prompt: 'should refuse on unarchived occupant', workingDirectory: repo }),
    err => err instanceof BridgeError && err.code === 'TASK_NOT_READY',
  );
  assert.equal(adapter.calls.length, callsBefore);
  assert.equal(readFileSync(path.join(first.copyDirectory!, 'precious.txt'), 'utf8'), 'keep-me-intact\n');
});

test('resume: failed task with and without conversation uses short continuation or fresh done/remaining notice with no patch', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-resume-notice-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new ScriptedGuardedAdapter(config);
  const managers: TaskManager[] = [];
  t.after(async () => {
    for (const manager of managers) await manager.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  // Format invariants: no period/colon/semicolon/exclamation anywhere, no patch markers when conversation absent.
  const withConv = formatResumeNotice({ hasConversation: true, previousTaskId: randomUUID(), previousStatus: 'failed', knownCause: 'AGY_PROCESS_FAILED' });
  assert.equal(/[.:;!]/.test(withConv), false, withConv);
  assert.ok(withConv.includes('AGY_PROCESS_FAILED'));

  const withoutConv = formatResumeNotice({
    hasConversation: false,
    previousTaskId: randomUUID(),
    previousStatus: 'failed',
    knownCause: 'AGY_PROCESS_FAILED',
    doneFiles: ['partial.txt'],
    remainingSummary: 'finish wiring',
  });
  assert.equal(/[.:;!]/.test(withoutConv), false, withoutConv);
  assert.ok(withoutConv.includes('partial txt'));
  assert.equal(withoutConv.includes('diff --git'), false);
  assert.equal(withoutConv.includes('@@ '), false);

  const tasks1 = new TaskManager(adapter, config);
  managers.push(tasks1);

  // Case 1: failed task WITHOUT sessionId (process died before init emitted a conversation ID).
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'ERROR',
    exitCode: 1,
    omitSessionId: true,
    onRun: () => { writeFileSync(path.join(cwd, 'partial.txt'), 'UNIQUE_PATCH_SECRET_BODY_LINE\n', 'utf8'); },
  });
  const failedNoSession = await waitForTask(tasks1, (await tasks1.run({ prompt: 'work without session', workingDirectory: repo })).taskId);
  assert.equal(failedNoSession.status, 'failed');
  assert.equal(failedNoSession.sessionId, undefined);
  await tasks1.shutdown();

  // Resume after restart -> fresh conversation (no --conversation), exact checkpoint bytes restored, done/remaining notice with NO patch!
  const tasks2 = new TaskManager(adapter, config);
  managers.push(tasks2);
  let observedPartial = '';
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { observedPartial = readFileSync(path.join(cwd, 'partial.txt'), 'utf8'); },
  });
  const freshResumed = await waitForTask(tasks2, (await tasks2.resume({ prompt: 'finish partial work', workingDirectory: repo }, failedNoSession.taskId)).taskId);
  assert.equal(freshResumed.status, 'completed', JSON.stringify(freshResumed.error));
  assert.equal(observedPartial, 'UNIQUE_PATCH_SECRET_BODY_LINE\n');
  const freshCall = adapter.calls.at(-1)!;
  assert.equal(freshCall.args.includes('--conversation'), false);
  assert.equal(freshCall.args.includes('--new-project'), true);
  assert.ok(freshCall.promptText.includes('partial txt'));
  assert.equal(freshCall.promptText.includes('UNIQUE_PATCH_SECRET_BODY_LINE'), false);
  assert.equal(freshCall.promptText.includes('diff --git'), false);
  const freshNoticeLine = freshCall.promptText.split('\n').find(line => line.startsWith('Starting a fresh conversation'));
  assert.ok(freshNoticeLine, freshCall.promptText);
  assert.equal(/[.:;!]/.test(freshNoticeLine), false, freshNoticeLine);

  // Case 2: failed task WITH sessionId -> passes --conversation and short informal continuation notice.
  adapter.nextBehavior = ({ cwd }) => ({
    status: 'ERROR',
    exitCode: 1,
    onRun: () => { writeFileSync(path.join(cwd, 'with-conv.txt'), 'kept-bytes\n', 'utf8'); },
  });
  const failedWithSession = await waitForTask(tasks2, (await tasks2.run({ prompt: 'work with session', workingDirectory: repo })).taskId);
  assert.equal(failedWithSession.status, 'failed');
  assert.equal(failedWithSession.sessionId, 'shared-mock-session');

  adapter.nextBehavior = () => ({ status: 'SUCCESS' });
  const convResumed = await waitForTask(tasks2, (await tasks2.resume({ prompt: 'continue with session', workingDirectory: repo }, failedWithSession.taskId)).taskId);
  assert.equal(convResumed.status, 'completed', JSON.stringify(convResumed.error));
  const convCall = adapter.calls.at(-1)!;
  const convIdx = convCall.args.indexOf('--conversation');
  assert.ok(convIdx >= 0, JSON.stringify(convCall.args));
  assert.equal(convCall.args[convIdx + 1], 'shared-mock-session');
  assert.equal(convCall.args.includes('--new-project'), false);
  const resumeNoticeLine = convCall.promptText.split('\n').find(line => line.startsWith('Hey, picking back up'));
  assert.ok(resumeNoticeLine, convCall.promptText);
  assert.equal(/[.:;!]/.test(resumeNoticeLine), false, resumeNoticeLine);
});

test('contain: Linux different boot confirms termination without signals while boot-unavailable never proves termination', async () => {
  const signalsDiffBoot: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
  const diffBoot = await reconcileLaunchIdentity(
    { pid: 44444, start: `${BOOT_A}:12345`, spawnedAt: Date.now() - 5000, processGroup: true },
    {
      platform: 'linux',
      bootId: () => BOOT_B,
      list: async () => { throw new Error('should not even need to inspect processes across boots'); },
      signal: (target, sig) => { signalsDiffBoot.push({ target, sig }); },
    },
  );
  assert.equal(diffBoot.verified, true);
  assert.equal(signalsDiffBoot.length, 0);

  const signalsUnavailable: Array<{ target: number; sig: NodeJS.Signals | 0 }> = [];
  const bootUnavailable = await reconcileLaunchIdentity(
    { pid: 44444, start: BOOT_UNAVAILABLE_START, spawnedAt: Date.now() - 5000, processGroup: true },
    {
      platform: 'linux',
      bootId: () => BOOT_B,
      list: async () => [],
      signal: (target, sig) => { signalsUnavailable.push({ target, sig }); },
    },
  );
  assert.equal(bootUnavailable.verified, false);
  assert.equal(signalsUnavailable.length, 0);
});

test('contain: manual discard refuses unconfirmed tracked live launch without signalling and allows after valid reconciliation', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-contain-tracked-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const adapter = new CliAdapter(config, [MOCK_AGY]);
  await adapter.discover();
  const managers: TaskManager[] = [];
  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
    detached: true,
    stdio: 'ignore',
  });
  const sleeperExited = new Promise<void>(resolve => { sleeper.once('close', () => resolve()); });
  sleeper.unref();
  assert.ok(sleeper.pid && sleeper.pid > 0);
  const sleeperPid = sleeper.pid;
  const realLinuxStart = process.platform === 'linux' ? recordedProcessStart(sleeperPid) : undefined;
  t.after(async () => {
    for (const manager of managers) await manager.shutdown();
    try {
      if (process.platform === 'win32') sleeper.kill('SIGKILL');
      else process.kill(-sleeperPid, 'SIGKILL');
    } catch { /* exited */ }
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const tasks1 = new TaskManager(adapter, config);
  managers.push(tasks1);
  const done = await waitForTask(tasks1, (await tasks1.run({ prompt: 'write:contain', workingDirectory: repo })).taskId);
  assert.equal(done.status, 'completed');
  await tasks1.shutdown();

  const snapshotPath = path.join(stateDir, `${done.taskId}.json`);
  const snap = JSON.parse(readFileSync(snapshotPath, 'utf8')) as { record: TaskRecord; project: { gitDirectory: string } };
  const nowIso = new Date().toISOString();
  const inconclusiveStart = process.platform === 'linux' ? BOOT_UNAVAILABLE_START : undefined;
  snap.record.pid = sleeperPid;
  snap.record.processCleanup = {
    verified: false,
    spawnedAt: nowIso,
    checkedAt: nowIso,
    remaining: 1,
    containment: 'tracked',
    ...(inconclusiveStart ? { start: inconclusiveStart } : {}),
  };
  writeFileSync(snapshotPath, JSON.stringify(snap), 'utf8');
  upsertProcessCleanupMarkerEntrySync(snap.project, {
    launchId: process.platform === 'linux' ? 'tracked-boot-unavailable' : 'tracked-unconfirmed-live',
    taskId: done.taskId,
    provider: 'agy',
    pid: sleeperPid,
    spawnedAt: nowIso,
    containment: 'tracked',
    ...(inconclusiveStart ? { start: inconclusiveStart } : {}),
  });

  const expectedArtifact = path.join(done.copyDirectory!, 'BLACK_GRAVITY_TEST.md');
  const expectedArtifactBytes = readFileSync(expectedArtifact, 'utf8');
  const markerPath = path.join(snap.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME);
  const markerBytesBefore = readFileSync(markerPath, 'utf8');

  const tasks2 = new TaskManager(adapter, config);
  managers.push(tasks2);
  await assert.rejects(
    () => tasks2.discard(done.taskId),
    err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
  );
  assert.equal(existsSync(done.copyDirectory!), true);
  assert.equal(readFileSync(expectedArtifact, 'utf8'), expectedArtifactBytes);
  assert.equal(existsSync(markerPath), true);
  assert.equal(readFileSync(markerPath, 'utf8'), markerBytesBefore);
  assert.doesNotThrow(() => process.kill(process.platform === 'win32' ? sleeperPid : -sleeperPid, 0));

  // Terminate sleeper and wait for confirmed exit, then verify valid reconciliation allows discard.
  if (process.platform === 'win32') sleeper.kill('SIGKILL');
  else process.kill(-sleeperPid, 'SIGKILL');
  await Promise.race([
    sleeperExited,
    delay(5000).then(() => { throw new Error('Sleeper process did not exit within 5000ms'); }),
  ]);
  assert.throws(() => process.kill(process.platform === 'win32' ? sleeperPid : -sleeperPid, 0));

  if (process.platform !== 'linux') {
    const discarded = await tasks2.discard(done.taskId);
    assert.equal(typeof discarded.discardedAt, 'string');
    assert.equal(existsSync(done.copyDirectory!), false);
    assert.equal(existsSync(markerPath), false);
  } else {
    // On Linux, BOOT_UNAVAILABLE_START must stay unconfirmed even after exit; verify valid proof on a clean recorded identity.
    await assert.rejects(
      () => tasks2.discard(done.taskId),
      err => err instanceof BridgeError && err.code === 'PROCESS_CLEANUP_UNVERIFIED',
    );
    assert.ok(realLinuxStart && realLinuxStart !== BOOT_UNAVAILABLE_START);
    const repoValid = await createRepo(root, 'repo-valid');
    const doneValid = await waitForTask(tasks2, (await tasks2.run({ prompt: 'write:contain-valid', workingDirectory: repoValid })).taskId);
    assert.equal(doneValid.status, 'completed');
    await tasks2.shutdown();

    const validSnapPath = path.join(stateDir, `${doneValid.taskId}.json`);
    const validSnap = JSON.parse(readFileSync(validSnapPath, 'utf8')) as { record: TaskRecord; project: { gitDirectory: string } };
    validSnap.record.pid = sleeperPid;
    validSnap.record.processCleanup = {
      verified: false,
      spawnedAt: nowIso,
      checkedAt: nowIso,
      remaining: 1,
      containment: 'tracked',
      start: realLinuxStart,
    };
    writeFileSync(validSnapPath, JSON.stringify(validSnap), 'utf8');
    upsertProcessCleanupMarkerEntrySync(validSnap.project, {
      launchId: 'tracked-reconcilable',
      taskId: doneValid.taskId,
      provider: 'agy',
      pid: sleeperPid,
      spawnedAt: nowIso,
      containment: 'tracked',
      start: realLinuxStart,
    });

    const tasks3 = new TaskManager(adapter, config);
    managers.push(tasks3);
    const discardedValid = await tasks3.discard(doneValid.taskId);
    assert.equal(typeof discardedValid.discardedAt, 'string');
    assert.equal(existsSync(doneValid.copyDirectory!), false);
    assert.equal(existsSync(path.join(validSnap.project.gitDirectory, PROCESS_CLEANUP_MARKER_NAME)), false);
  }
});

test('queue: serializes same canonical root while preserving cross-root concurrency on distinct roots', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-queue-roots-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repoA = await createRepo(root, 'repo-a');
  const repoB = await createRepo(root, 'repo-b');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    MAX_CONCURRENT_TASKS: '4',
    MAX_CONCURRENT_OPENCODE_TASKS: '4',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDir,
  });
  const cli = new ScriptedGuardedAdapter(config);

  const activeByCwd = new Map<string, number>();
  let maxConcurrentOnSameCwd = 0;
  let maxConcurrentTotal = 0;
  let currentTotal = 0;
  const resolvers = new Map<string, { cwd: string; resolve: () => void }>();
  const arrived = new EventEmitter();

  const concurrentAdapter: ExecutionAdapter = {
    identity: { id: 'fake-concurrent', provider: 'opencode', version: '3' },
    processContainment: 'tracked',
    capabilities: { read: 'supported', write: 'supported', cancel: 'supported', resume: 'supported' },
    async execute(request: ExecutionRequest, context?: ExecutionContext): Promise<ExecutionResult> {
      const cwd = request.workingDirectory;
      activeByCwd.set(cwd, (activeByCwd.get(cwd) ?? 0) + 1);
      currentTotal += 1;
      maxConcurrentOnSameCwd = Math.max(maxConcurrentOnSameCwd, activeByCwd.get(cwd)!);
      maxConcurrentTotal = Math.max(maxConcurrentTotal, currentTotal);
      await new Promise<void>(resolve => {
        resolvers.set(request.taskId, { cwd, resolve });
        arrived.emit('arrived', request.taskId);
      });
      activeByCwd.set(cwd, (activeByCwd.get(cwd) ?? 1) - 1);
      currentTotal -= 1;
      const nowIso = new Date().toISOString();
      context?.onProcessCleanup?.({ verified: true, spawnedAt: nowIso, checkedAt: nowIso, remaining: 0, containment: 'tracked' });
      return { taskId: request.taskId, status: 'completed', session: { id: `ses_${request.taskId}` }, response: 'ok' };
    },
  };

  const tasks = new TaskManager(cli, config, concurrentAdapter);
  const totalAdmissionWaitBudgetMs = 5000;
  let remainingAdmissionWaitMs = totalAdmissionWaitBudgetMs;
  const waitForAdapterExecution = (expectedTaskIds: readonly string[], label: string): Promise<void> => {
    const allArrived = () => expectedTaskIds.every(taskId => resolvers.has(taskId));
    if (allArrived()) return Promise.resolve();
    const waitBudgetMs = Math.max(0, remainingAdmissionWaitMs);
    const waitStartedAt = Date.now();
    const consumeBudget = () => {
      remainingAdmissionWaitMs = Math.max(0, remainingAdmissionWaitMs - (Date.now() - waitStartedAt));
    };
    if (waitBudgetMs === 0) {
      const statuses = tasks.list().map(item => `${item.prompt}:${item.status}${item.error ? `(${item.error.code})` : ''}`);
      return Promise.reject(new Error(`Shared 5000ms admission wait budget exhausted before ${label}: observed=[${[...resolvers.keys()].join(', ')}] expected=[${expectedTaskIds.join(', ')}]; tasks=[${statuses.join(', ')}]`));
    }
    return new Promise<void>((resolve, reject) => {
      const onArrived = () => {
        if (allArrived()) {
          cleanup();
          consumeBudget();
          resolve();
        }
      };
      const timer = setTimeout(() => {
        cleanup();
        consumeBudget();
        const statuses = tasks.list().map(item => `${item.prompt}:${item.status}${item.error ? `(${item.error.code})` : ''}`);
        reject(new Error(`Timed out waiting for ${label} (remaining shared budget ${remainingAdmissionWaitMs}/${totalAdmissionWaitBudgetMs}ms): observed=[${[...resolvers.keys()].join(', ')}] expected=[${expectedTaskIds.join(', ')}]; tasks=[${statuses.join(', ')}]`));
      }, waitBudgetMs);
      const cleanup = () => {
        clearTimeout(timer);
        arrived.off('arrived', onArrived);
      };
      arrived.on('arrived', onArrived);
    });
  };
  const releaseAdapterExecution = (taskId: string) => {
    const entry = resolvers.get(taskId);
    assert.ok(entry, `Expected active adapter resolver for ${taskId}`);
    resolvers.delete(taskId);
    entry.resolve();
  };
  t.after(async () => {
    for (const entry of resolvers.values()) entry.resolve();
    resolvers.clear();
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const assertQueuedReceipt = (taskId: string) => {
    const events = tasks.readEvents(taskId).events;
    assert.equal(events.some(event => event.type === 'task.queued'), true, `Expected durable task.queued receipt for ${taskId}`);
  };

  const a1 = await tasks.run({ prompt: 'a1', workingDirectory: repoA, mode: 'read-only' });
  const a2 = await tasks.run({ prompt: 'a2', workingDirectory: repoA, mode: 'read-only' });
  const b1 = await tasks.run({ prompt: 'b1', workingDirectory: repoB, mode: 'read-only' });
  assertQueuedReceipt(a1.taskId);
  assertQueuedReceipt(a2.taskId);
  assertQueuedReceipt(b1.taskId);
  assert.equal(a2.status, 'queued');

  await waitForAdapterExecution([a1.taskId, b1.taskId], 'a1 and b1 concurrent admission');
  await delay(80);
  // a1 and b1 run concurrently (distinct roots), while a2 waits durably queued behind a1 (same root).
  assert.equal(resolvers.size, 2);
  assert.equal(resolvers.has(a1.taskId), true);
  assert.equal(resolvers.has(b1.taskId), true);
  assert.equal(resolvers.has(a2.taskId), false);
  assert.equal(tasks.status(a2.taskId).status, 'queued');
  assert.equal(tasks.readEvents(a2.taskId).events.some(event => event.type === 'task.started'), false);
  assert.equal(maxConcurrentTotal, 2);
  assert.equal(maxConcurrentOnSameCwd, 1);

  releaseAdapterExecution(a1.taskId);
  releaseAdapterExecution(b1.taskId);
  // Synchronize on a1 terminal boundary only before measuring a2 admission; b1 is on an unrelated root.
  const r1 = await waitForTask(tasks, a1.taskId);
  assert.equal(r1.status, 'completed', JSON.stringify(r1.error));

  await waitForAdapterExecution([a2.taskId], 'a2 queued admission after a1 terminal');
  assert.equal(resolvers.size, 1);
  assert.equal(resolvers.has(a2.taskId), true);
  releaseAdapterExecution(a2.taskId);

  const [r2, r3] = await Promise.all([
    waitForTask(tasks, a2.taskId),
    waitForTask(tasks, b1.taskId),
  ]);
  assert.equal(r2.status, 'completed', JSON.stringify(r2.error));
  assert.equal(r3.status, 'completed', JSON.stringify(r3.error));
  assert.equal(maxConcurrentOnSameCwd, 1);
  // Every task archived independently under its own taskId and another immediate same-root run succeeds without STATE_BUSY.
  const archiveA1 = await loadVerifiedTaskArchive(stateDir, a1.taskId);
  const archiveA2 = await loadVerifiedTaskArchive(stateDir, a2.taskId);
  const archiveB1 = await loadVerifiedTaskArchive(stateDir, b1.taskId);
  assert.equal(archiveA1.manifest.taskId, a1.taskId);
  assert.equal(archiveA2.manifest.taskId, a2.taskId);
  assert.equal(archiveB1.manifest.taskId, b1.taskId);
  assert.notEqual(archiveA1.archiveDirectory, archiveA2.archiveDirectory);
  const a3 = await tasks.run({ prompt: 'a3', workingDirectory: repoA, mode: 'read-only' });
  assertQueuedReceipt(a3.taskId);
  await waitForAdapterExecution([a3.taskId], 'a3 immediate same-root admission');
  assert.equal(resolvers.size, 1);
  assert.equal(resolvers.has(a3.taskId), true);
  releaseAdapterExecution(a3.taskId);
  const r4 = await waitForTask(tasks, a3.taskId);
  assert.equal(r4.status, 'completed', JSON.stringify(r4.error));
  assert.equal(maxConcurrentOnSameCwd, 1);
});

test('compat: Windows LPAC fixed-folder permission baseline pins once and detects DACL drift or lingering AppContainer ACEs per task', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-lpac-fixed-')));
  const stateDir = path.join(root, 'state');
  mkdirSync(stateDir, { recursive: true });
  const repo = await createRepo(root, 'repo');
  t.after(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const workspace = canonicalWorkspacePaths(stateDir, repo);
  mkdirSync(workspace.copyDirectory, { recursive: true });
  mkdirSync(workspace.gitDirectory, { recursive: true });

  let currentAcl = [
    `${workspace.copyDirectory} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)`,
    '                 BUILTIN\\Administrators:(OI)(CI)(F)',
    '                 DESKTOP\\User:(OI)(CI)(F)',
    '',
    'Successfully processed 1 files; Failed processing 0 files',
  ].join('\r\n');
  let icaclsCalls = 0;
  const runner: IcaclsRunner = async () => {
    icaclsCalls += 1;
    return { stdout: currentAcl, stderr: '' };
  };

  // First call pins fixed-folder identity and baseline DACL once.
  const initial = await ensureFixedWorkspaceLpacPermissions(workspace, repo, { platform: 'win32', runIcacls: runner });
  assert.ok(initial);
  assert.equal(icaclsCalls, 1);
  const meta = readWorkspaceMetadata(workspace.metadataPath);
  assert.equal(meta?.windowsLpac?.daclSha256, initial.daclSha256);

  // Subsequent per-task verification succeeds when identity and DACL match.
  await ensureFixedWorkspaceLpacPermissions(workspace, repo, { platform: 'win32', runIcacls: runner });
  await verifyFixedWorkspaceLpacPermissions(workspace.copyDirectory, stateDir, { platform: 'win32', runIcacls: runner });
  assert.equal(icaclsCalls, 3);

  // Lingering AppContainer ACE (S-1-15-2-...) or broadened permission fails closed.
  currentAcl = [
    `${workspace.copyDirectory} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)`,
    '                 *S-1-15-2-12345-67890:(OI)(CI)(M)',
    '                 DESKTOP\\User:(OI)(CI)(F)',
    '',
    'Successfully processed 1 files; Failed processing 0 files',
  ].join('\r\n');
  await assert.rejects(
    () => verifyFixedWorkspaceLpacPermissions(workspace.copyDirectory, stateDir, { platform: 'win32', runIcacls: runner }),
    err => err instanceof BridgeError && err.code === 'WINDOWS_LPAC_PERMISSIONS_INVALID',
  );
  // Sanity check SHA-256 baseline stays intact in metadata.
  assert.equal(readWorkspaceMetadata(workspace.metadataPath)?.windowsLpac?.daclSha256, initial.daclSha256);
  assert.ok(createHash('sha256').update(initial.daclSha256).digest('hex'));
});

function deadPid(): number {
  const exited = spawnSync(process.execPath, ['-e', 'process.exit(0)'], { windowsHide: true });
  assert.ok(exited.pid && exited.pid > 0);
  return exited.pid;
}

test('recovery: interrupted SERVER_RESTARTED task commits first verified archive on reuse and stays resumable by taskId', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-recover-int-')));
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

  const adapter1 = new ScriptedGuardedAdapter(config);
  const tasks1 = new TaskManager(adapter1, config);
  managers.push(tasks1);
  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'wip.txt'), 'interrupted-bytes\n', 'utf8'); },
  });
  const first = await waitForTask(tasks1, (await tasks1.run({
    prompt: 'guarded work',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
  })).taskId);
  assert.equal(first.status, 'completed', JSON.stringify(first.error));
  await tasks1.shutdown();

  // Simulate mid-run crash before any checkpoint archive was committed.
  rmSync(archiveDirectoryFor(stateDir, first.taskId), { recursive: true, force: true });
  const snapshotPath = path.join(stateDir, `${first.taskId}.json`);
  const snap = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
    ownerPid: number;
    record: { status: string; completedAt?: string; pid?: number };
    project: { archivedAt?: string; archiveSha256?: string };
  };
  snap.ownerPid = deadPid();
  snap.record.status = 'running';
  delete snap.record.completedAt;
  delete snap.record.pid;
  delete snap.project.archivedAt;
  delete snap.project.archiveSha256;
  writeFileSync(snapshotPath, JSON.stringify(snap), 'utf8');

  const adapter2 = new ScriptedGuardedAdapter(config);
  const tasks2 = new TaskManager(adapter2, config);
  managers.push(tasks2);
  const recovered = tasks2.status(first.taskId);
  assert.equal(recovered.status, 'failed');
  assert.equal(recovered.error?.code, 'SERVER_RESTARTED');
  assert.equal(existsSync(archiveDirectoryFor(stateDir, first.taskId)), false);

  // Starting a new task on the same root verifies cleanup/occupant/baseline/receipt and commits the first archive before reuse.
  adapter2.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'fresh.txt'), 'fresh-bytes\n', 'utf8'); },
  });
  const next = await waitForTask(tasks2, (await tasks2.run({ prompt: 'fresh task after crash', workingDirectory: repo })).taskId);
  assert.equal(next.status, 'completed', JSON.stringify(next.error));
  const archive = await loadVerifiedTaskArchive(stateDir, first.taskId);
  assert.equal(archive.manifest.taskId, first.taskId);
  await tasks2.shutdown();

  // Restart and resume the recovered interrupted task by taskId -> restores its exact bytes.
  const adapter3 = new ScriptedGuardedAdapter(config);
  const tasks3 = new TaskManager(adapter3, config);
  managers.push(tasks3);
  let restoredWip = '';
  let hasFresh = true;
  adapter3.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => {
      restoredWip = readFileSync(path.join(cwd, 'wip.txt'), 'utf8');
      hasFresh = existsSync(path.join(cwd, 'fresh.txt'));
    },
  });
  const resumed = await waitForTask(tasks3, (await tasks3.resume({ prompt: 'continue interrupted', workingDirectory: repo }, first.taskId)).taskId);
  assert.equal(resumed.status, 'completed', JSON.stringify(resumed.error));
  assert.equal(restoredWip, 'interrupted-bytes\n');
  assert.equal(hasFresh, false);
});

test('recovery: interrupted SERVER_RESTARTED task refuses reuse without touching bytes on tampered receipt, baseline, or existing archive dir', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-recover-fail-')));
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

  const adapter1 = new ScriptedGuardedAdapter(config);
  const tasks1 = new TaskManager(adapter1, config);
  managers.push(tasks1);
  adapter1.nextBehavior = ({ cwd }) => ({
    status: 'SUCCESS',
    onRun: () => { writeFileSync(path.join(cwd, 'keep.txt'), 'do-not-wipe\n', 'utf8'); },
  });
  const first = await waitForTask(tasks1, (await tasks1.run({
    prompt: 'guarded work',
    workingDirectory: repo,
    allowedTools: ['view_file', 'write_to_file'],
    mcpServers: [],
  })).taskId);
  assert.equal(first.status, 'completed', JSON.stringify(first.error));
  await tasks1.shutdown();

  const snapshotPath = path.join(stateDir, `${first.taskId}.json`);
  const origSnap = JSON.parse(readFileSync(snapshotPath, 'utf8')) as {
    ownerPid: number;
    record: { status: string; completedAt?: string; pid?: number };
    project: { archivedAt?: string; archiveSha256?: string; baseline: Array<[string, string]>; executionPolicy?: { receiptPath: string } };
  };
  const archiveDir = archiveDirectoryFor(stateDir, first.taskId);
  rmSync(archiveDir, { recursive: true, force: true });

  const makeInterrupted = (mutate?: (copy: typeof origSnap) => void) => {
    const copy = structuredClone(origSnap);
    copy.ownerPid = deadPid();
    copy.record.status = 'running';
    delete copy.record.completedAt;
    delete copy.record.pid;
    delete copy.project.archivedAt;
    delete copy.project.archiveSha256;
    mutate?.(copy);
    writeFileSync(snapshotPath, JSON.stringify(copy), 'utf8');
  };

  // Case 1: pre-existing corrupt archive directory must never be recreated or overwritten.
  makeInterrupted();
  mkdirSync(archiveDir, { recursive: true });
  writeFileSync(path.join(archiveDir, 'manifest.json'), '{corrupt', 'utf8');
  const adapter2 = new ScriptedGuardedAdapter(config);
  const tasks2 = new TaskManager(adapter2, config);
  managers.push(tasks2);
  await assert.rejects(
    () => tasks2.run({ prompt: 'should refuse existing archive', workingDirectory: repo }),
    err => err instanceof BridgeError && err.code === 'ARCHIVE_VERIFICATION_FAILED',
  );
  assert.equal(adapter2.calls.length, 0);
  assert.equal(readFileSync(path.join(first.copyDirectory!, 'keep.txt'), 'utf8'), 'do-not-wipe\n');
  await tasks2.shutdown();
  rmSync(archiveDir, { recursive: true, force: true });

  // Case 2: baseline digest mismatch fails closed without creating archive or touching workspace bytes.
  makeInterrupted(copy => {
    copy.project.baseline = copy.project.baseline.map(([p]) => [p, '0'.repeat(64)]);
  });
  const adapter3 = new ScriptedGuardedAdapter(config);
  const tasks3 = new TaskManager(adapter3, config);
  managers.push(tasks3);
  await assert.rejects(
    () => tasks3.run({ prompt: 'should refuse baseline mismatch', workingDirectory: repo }),
    err => err instanceof BridgeError && err.code === 'CHECKPOINT_INVALID',
  );
  assert.equal(adapter3.calls.length, 0);
  assert.equal(existsSync(archiveDir), false);
  assert.equal(readFileSync(path.join(first.copyDirectory!, 'keep.txt'), 'utf8'), 'do-not-wipe\n');
  await tasks3.shutdown();

  // Case 3: replaced receipt file (inode identity mismatch) fails closed without creating archive or touching workspace bytes.
  const receiptPath = origSnap.project.executionPolicy!.receiptPath;
  const receiptContent = readFileSync(receiptPath);
  const replacementPath = `${receiptPath}.replacement`;
  writeFileSync(replacementPath, receiptContent);
  renameSync(replacementPath, receiptPath);
  makeInterrupted();
  const adapter4 = new ScriptedGuardedAdapter(config);
  const tasks4 = new TaskManager(adapter4, config);
  managers.push(tasks4);
  await assert.rejects(
    () => tasks4.run({ prompt: 'should refuse receipt swap', workingDirectory: repo }),
    err => err instanceof BridgeError && err.code === 'EXECUTION_POLICY_VERIFICATION_FAILED' && /receipt file identity changed/i.test(err.message),
  );
  assert.equal(adapter4.calls.length, 0);
  assert.equal(existsSync(archiveDir), false);
  assert.equal(readFileSync(path.join(first.copyDirectory!, 'keep.txt'), 'utf8'), 'do-not-wipe\n');
});
