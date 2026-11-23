import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { access, chmod, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CliAdapter } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { writeLineEndingConversions } from '../src/isolation.js';
import { outputSchemas, successOutputSchemas } from '../src/output-schemas.js';
import { copyIdentity, copyLockName, StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import type { TaskRecord } from '../src/types.js';

const mockPath = fileURLToPath(new URL('../../tests/mock-agy.mjs', import.meta.url));
const done = (task: TaskRecord) => ['completed', 'failed', 'cancelled', 'timeout'].includes(task.status);

async function until(tasks: TaskManager, taskId: string, predicate: (record: TaskRecord) => boolean, timeout = 30000): Promise<TaskRecord> {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const task = tasks.status(taskId);
    if (predicate(task)) return task;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error(`Timed out waiting for task: ${JSON.stringify(tasks.status(taskId))}`);
}

interface SnapshotFile {
  version: number;
  ownerPid: number;
  record: {
    taskId: string;
    workingDirectory: string;
    prompt: string;
    status: string;
    createdAt: string;
    [key: string]: unknown;
  };
  options: {
    prompt: string;
    workingDirectory: string;
    [key: string]: unknown;
  };
  project?: {
    sourceDirectory: string;
    copyDirectory: string;
    gitDirectory: string;
    executionPolicy?: unknown;
    executionStateDirectory?: string;
    [key: string]: unknown;
  };
  events: unknown[];
  cursor: number;
  redacted?: true;
}

async function createFinishedTasks(count: number): Promise<{
  dir: string;
  stateDirectory: string;
  config: ReturnType<typeof loadConfig>;
  adapter: CliAdapter;
  finished: TaskRecord[];
  tempDirs: string[];
}> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-quarantine-repo-'));
  const stateDirectory = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-quarantine-state-'));
  execFileSync('git', ['init', '--quiet', dir]);
  await writeFile(path.join(dir, 'source.txt'), 'source');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
    BRIDGE_TEST_EXECUTOR: 'agy',
    BRIDGE_STATE_DIRECTORY: stateDirectory,
  });
  const adapter = new CliAdapter(config, [mockPath]);
  await adapter.discover();

  const manager = new TaskManager(adapter, config);
  const finished: TaskRecord[] = [];
  const tempDirs: string[] = [];
  try {
    for (let i = 0; i < count; i++) {
      const run = await manager.run({ prompt: 'write:test', workingDirectory: dir });
      const record = await until(manager, run.taskId, done);
      assert.equal(record.status, 'completed', JSON.stringify(record.error));
      finished.push(record);
      const snapshot = JSON.parse(await readFile(path.join(stateDirectory, `${record.taskId}.json`), 'utf8')) as SnapshotFile;
      if (snapshot.project) {
        tempDirs.push(snapshot.project.copyDirectory, snapshot.project.gitDirectory);
      }
    }
  } finally {
    await manager.shutdown();
  }
  return { dir, stateDirectory, config, adapter, finished, tempDirs };
}

test('A: copy-outside-temporary-directory quarantines only bad task, refuses operations, and record-only discard leaves decoy untouched', async () => {
  const fixture = await createFinishedTasks(2);
  const valid = fixture.finished[0]!;
  const bad = fixture.finished[1]!;
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-parent-'));
  const decoyCopy = path.join(decoyParent, 'black-gravity-copy-decoy');
  const sentinel = path.join(decoyCopy, 'sentinel.txt');
  const managers: TaskManager[] = [];

  try {
    await mkdir(decoyCopy, { recursive: true });
    await writeFile(sentinel, 'sentinel-bytes');

    const badFile = path.join(fixture.stateDirectory, `${bad.taskId}.json`);
    const badSnapshot = JSON.parse(await readFile(badFile, 'utf8')) as SnapshotFile;
    badSnapshot.project!.copyDirectory = decoyCopy;
    await writeFile(badFile, JSON.stringify(badSnapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.equal(recovered.configurationIssues.some(issue => issue.variable === 'BRIDGE_STATE_DIRECTORY'), false);
    assert.deepEqual(recovered.list().map(task => task.taskId), [valid.taskId]);
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: bad.taskId, reason: 'copy-outside-temporary-directory' }]);
    assert.deepEqual(recovered.lastQuarantinedTasks(), [{ taskId: bad.taskId, reason: 'copy-outside-temporary-directory' }]);

    const freshRun = await recovered.run({ prompt: 'write:fresh', workingDirectory: fixture.dir });
    const freshDone = await until(recovered, freshRun.taskId, done);
    assert.equal(freshDone.status, 'completed', JSON.stringify(freshDone.error));
    const freshSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${freshDone.taskId}.json`), 'utf8')) as SnapshotFile;
    if (freshSnapshot.project) fixture.tempDirs.push(freshSnapshot.project.copyDirectory, freshSnapshot.project.gitDirectory);

    assert.throws(() => recovered.status(bad.taskId), { code: 'TASK_QUARANTINED' });
    assert.throws(() => recovered.result(bad.taskId), { code: 'TASK_QUARANTINED' });
    assert.throws(() => recovered.readEvents(bad.taskId), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.wait(bad.taskId, 0, 1), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.resume({ prompt: 'write:again', workingDirectory: fixture.dir }, bad.taskId), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.recordTest(bad.taskId, '0'.repeat(64), 'node -v', 0), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.startTests(bad.taskId, '0'.repeat(64), { executable: process.execPath, args: ['-v'] }), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.verify(bad.taskId, '0'.repeat(64)), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.preview(bad.taskId), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.integrate(bad.taskId, '0'.repeat(64)), { code: 'TASK_QUARANTINED' });

    const discarded = await recovered.discard(bad.taskId);
    assert.ok(discarded.discardedAt);
    assert.deepEqual(recovered.quarantinedTasks(), []);
    const listedBad = recovered.list().find(task => task.taskId === bad.taskId);
    assert.ok(listedBad?.discardedAt);

    assert.equal(await readFile(sentinel, 'utf8'), 'sentinel-bytes');
    assert.deepEqual(await readdir(decoyParent), ['black-gravity-copy-decoy']);
    assert.deepEqual(await readdir(decoyCopy), ['sentinel.txt']);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('B: garbage snapshot and identity-mismatch snapshot are quarantined without degrading and refuse discard', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const garbageId = randomUUID();
    const garbageFile = path.join(fixture.stateDirectory, `${garbageId}.json`);
    const garbageBytes = '{ not valid json';
    await writeFile(garbageFile, garbageBytes);

    const mismatchId = randomUUID();
    const mismatchFile = path.join(fixture.stateDirectory, `${mismatchId}.json`);
    const validSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8')) as SnapshotFile;
    const mismatchSnapshot: SnapshotFile = {
      ...validSnapshot,
      record: { ...validSnapshot.record, taskId: mismatchId },
      options: { ...validSnapshot.options, prompt: 'different-prompt' },
    };
    const mismatchBytes = JSON.stringify(mismatchSnapshot);
    await writeFile(mismatchFile, mismatchBytes);

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.equal(recovered.configurationIssues.some(issue => issue.variable === 'BRIDGE_STATE_DIRECTORY'), false);
    assert.deepEqual(
      recovered.quarantinedTasks(),
      [
        { taskId: garbageId, reason: 'invalid-snapshot' },
        { taskId: mismatchId, reason: 'identity-mismatch' },
      ].sort((a, b) => a.taskId.localeCompare(b.taskId)),
    );

    await assert.rejects(recovered.discard(garbageId), { code: 'TASK_QUARANTINED' });
    await assert.rejects(recovered.discard(mismatchId), { code: 'TASK_QUARANTINED' });
    assert.equal(await readFile(garbageFile, 'utf8'), garbageBytes);
    assert.equal(await readFile(mismatchFile, 'utf8'), mismatchBytes);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('C: shared copy with quarantined sibling refuses integrate and resume on valid task with TASK_NOT_READY', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const siblingId = randomUUID();
    const validSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8')) as SnapshotFile;
    const siblingSnapshot: SnapshotFile = {
      ...validSnapshot,
      record: {
        ...validSnapshot.record,
        taskId: siblingId,
        createdAt: new Date(Date.now() + 60_000).toISOString(),
      },
      options: { ...validSnapshot.options, prompt: 'different-prompt' },
    };
    await writeFile(path.join(fixture.stateDirectory, `${siblingId}.json`), JSON.stringify(siblingSnapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: siblingId, reason: 'identity-mismatch' }]);
    await assert.rejects(recovered.integrate(valid.taskId, '0'.repeat(64)), { code: 'TASK_NOT_READY' });
    await assert.rejects(recovered.resume({ prompt: 'write:again', workingDirectory: fixture.dir }, valid.taskId), { code: 'TASK_NOT_READY' });
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('D: symlinked or mode-000 state directory still enters degraded mode', async t => {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-quarantine-dir-'));
  const targetDir = path.join(tmpRoot, 'target');
  const linkDir = path.join(tmpRoot, 'link');
  const lockedDir = path.join(tmpRoot, 'locked');

  try {
    await mkdir(targetDir);
    let linkCreated = true;
    try {
      await symlink(targetDir, linkDir, process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      linkCreated = false;
    }

    if (linkCreated) {
      const linkConfig = loadConfig({ AGY_PATH: process.execPath, BRIDGE_STATE_DIRECTORY: linkDir });
      const linkManager = new TaskManager(new CliAdapter(linkConfig), linkConfig);
      try {
        assert.equal(linkManager.isStateDirectoryUsable(), false);
        assert.deepEqual(linkManager.configurationIssues, [{ variable: 'BRIDGE_STATE_DIRECTORY', reason: 'link' }]);
        assert.deepEqual(linkManager.lastQuarantinedTasks(), []);
      } finally {
        await linkManager.shutdown();
      }
    }

    if (process.platform === 'win32' || process.getuid?.() === 0) {
      if (!linkCreated) t.skip('Platform refuses symlinks and skips chmod 0o000');
      return;
    }

    await mkdir(lockedDir);
    await chmod(lockedDir, 0o000);
    const lockedConfig = loadConfig({ AGY_PATH: process.execPath, BRIDGE_STATE_DIRECTORY: lockedDir });
    const lockedManager = new TaskManager(new CliAdapter(lockedConfig), lockedConfig);
    try {
      assert.equal(lockedManager.isStateDirectoryUsable(), false);
      assert.deepEqual(lockedManager.configurationIssues, [{ variable: 'BRIDGE_STATE_DIRECTORY', reason: 'unusable' }]);
      assert.deepEqual(lockedManager.lastQuarantinedTasks(), []);
    } finally {
      await lockedManager.shutdown();
      await chmod(lockedDir, 0o700);
    }
  } finally {
    await chmod(lockedDir, 0o700).catch(() => {});
    await rm(tmpRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('E: StateStore.load() remains strict and throws INVALID_STATE on garbage snapshot', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-store-strict-'));
  try {
    await writeFile(path.join(dir, `${randomUUID()}.json`), '{ not valid json');
    assert.throws(() => new StateStore(dir).load(), { code: 'INVALID_STATE' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('F: output schemas accept quarantinedTasks and reject unknown quarantine reasons', () => {
  const taskId = randomUUID();
  const baseHealth = {
    installed: false,
    path: 'missing-agy',
    authenticated: null,
    error: 'CLI unavailable',
    approvalMode: 'auto',
    capabilities: Object.fromEntries(Object.keys(successOutputSchemas.black_gravity_health.shape.capabilities.shape).map(key => [key, false])),
    integrationApproval: { available: true, mode: 'auto', method: 'automatic' },
  };

  assert.equal(
    outputSchemas.black_gravity_health.safeParse({
      ...baseHealth,
      quarantinedTasks: [{ taskId, reason: 'copy-outside-temporary-directory' }],
    }).success,
    true,
  );
  assert.equal(
    outputSchemas.black_gravity_health.safeParse({
      ...baseHealth,
      quarantinedTasks: [{ taskId, reason: 'unknown-reason' }],
    }).success,
    false,
  );

  assert.equal(
    outputSchemas.black_gravity_tasks.safeParse({
      tasks: [],
      quarantinedTasks: [{ taskId, reason: 'invalid-snapshot' }],
    }).success,
    true,
  );
  assert.equal(
    outputSchemas.black_gravity_tasks.safeParse({
      tasks: [],
      quarantinedTasks: [{ taskId, reason: 'unknown-reason' }],
    }).success,
    false,
  );
});

test('source-mismatch and execution-policy-mismatch quarantine cleanly and discard record-only', async () => {
  const fixture = await createFinishedTasks(2);
  const sourceBad = fixture.finished[0]!;
  const execBad = fixture.finished[1]!;
  const managers: TaskManager[] = [];

  try {
    const sourceFile = path.join(fixture.stateDirectory, `${sourceBad.taskId}.json`);
    const sourceSnapshot = JSON.parse(await readFile(sourceFile, 'utf8')) as SnapshotFile;
    sourceSnapshot.project!.sourceDirectory = path.join(fixture.dir, 'other');
    await writeFile(sourceFile, JSON.stringify(sourceSnapshot));

    const execFile = path.join(fixture.stateDirectory, `${execBad.taskId}.json`);
    const execSnapshot = JSON.parse(await readFile(execFile, 'utf8')) as SnapshotFile;
    execSnapshot.project!.executionStateDirectory = path.join(fixture.stateDirectory, 'missing-exec-state-' + randomUUID());
    await writeFile(execFile, JSON.stringify(execSnapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.deepEqual(
      recovered.quarantinedTasks(),
      [
        { taskId: sourceBad.taskId, reason: 'source-mismatch' },
        { taskId: execBad.taskId, reason: 'execution-policy-mismatch' },
      ].sort((a, b) => a.taskId.localeCompare(b.taskId)),
    );

    const d1 = await recovered.discard(sourceBad.taskId);
    const d2 = await recovered.discard(execBad.taskId);
    assert.ok(d1.discardedAt);
    assert.ok(d2.discardedAt);
    assert.deepEqual(recovered.quarantinedTasks(), []);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('record-only discard preserves absence of redacted flag on legacy snapshots so reload still sanitizes secrets', async () => {
  const fixture = await createFinishedTasks(1);
  const task = fixture.finished[0]!;
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-legacy-'));
  const decoyCopy = path.join(decoyParent, 'black-gravity-copy-decoy');
  const token = 'gh' + 'p_' + 'D'.repeat(36);
  const managers: TaskManager[] = [];

  try {
    await mkdir(decoyCopy, { recursive: true });
    const snapshotFile = path.join(fixture.stateDirectory, `${task.taskId}.json`);
    const snapshot = JSON.parse(await readFile(snapshotFile, 'utf8')) as SnapshotFile;
    delete snapshot.redacted;
    snapshot.project!.copyDirectory = decoyCopy;
    snapshot.record.prompt = snapshot.options.prompt = 'legacy prompt ' + token;
    snapshot.record.tests = [{
      command: 'node check.js',
      exitCode: 1,
      output: 'leaked ' + token,
      sha256: 'b'.repeat(64),
      recordedAt: new Date().toISOString(),
      source: 'client-reported',
    }];
    await writeFile(snapshotFile, JSON.stringify(snapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: task.taskId, reason: 'copy-outside-temporary-directory' }]);

    const discarded = await recovered.discard(task.taskId);
    assert.ok(discarded.discardedAt);
    await recovered.shutdown();

    const diskText = await readFile(snapshotFile, 'utf8');
    assert.equal(diskText.includes('"redacted":true'), false);
    const diskSnapshot = JSON.parse(diskText) as SnapshotFile;
    assert.equal(diskSnapshot.redacted, undefined);
    assert.equal(diskSnapshot.project, undefined);

    const reloaded = new TaskManager(fixture.adapter, fixture.config);
    managers.push(reloaded);
    const loaded = reloaded.status(task.taskId);
    assert.ok(loaded.discardedAt);
    assert.equal(JSON.stringify(loaded).includes(token), false);
    assert.equal(loaded.prompt, 'legacy prompt [redacted]');
    assert.equal(loaded.tests?.[0]?.output, 'leaked [redacted]');
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('shared copy blocks discard, preview, verify, recordTest, and skips cleanup', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const siblingId = randomUUID();
    const validSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8')) as SnapshotFile;
    const siblingSnapshot: SnapshotFile = {
      ...validSnapshot,
      record: {
        ...validSnapshot.record,
        taskId: siblingId,
        createdAt: new Date(Date.now() + 60_000).toISOString(),
      },
      options: { ...validSnapshot.options, prompt: 'different-prompt' },
    };
    await writeFile(path.join(fixture.stateDirectory, `${siblingId}.json`), JSON.stringify(siblingSnapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    await assert.rejects(recovered.discard(valid.taskId), { code: 'TASK_NOT_READY' });
    await assert.rejects(recovered.preview(valid.taskId), { code: 'TASK_NOT_READY' });
    await assert.rejects(recovered.verify(valid.taskId, '0'.repeat(64)), { code: 'TASK_NOT_READY' });
    await assert.rejects(recovered.recordTest(valid.taskId, '0'.repeat(64), 'node -v', 0), { code: 'TASK_NOT_READY' });

    const cleaned = await recovered.cleanup(Date.now() + 365 * 24 * 3600 * 1000);
    assert.deepEqual(cleaned, { discardedTaskIds: [] });
    await access(valid.copyDirectory!);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('record-only discard refuses live ownerPid with TASK_OWNED_BY_OTHER_SERVER and non-terminal status with TASK_NOT_READY', async () => {
  const fixture = await createFinishedTasks(2);
  const liveOwnerTask = fixture.finished[0]!;
  const runningTask = fixture.finished[1]!;
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-owner-'));
  const decoyCopy = path.join(decoyParent, 'black-gravity-copy-decoy');
  const child = spawn(process.execPath, ['-e', 'setTimeout(()=>{},30000)'], { stdio: 'ignore' });
  const managers: TaskManager[] = [];

  try {
    await new Promise<void>((resolve, reject) => {
      if (child.pid) return resolve();
      child.once('spawn', () => resolve());
      child.once('error', reject);
    });
    await mkdir(decoyCopy, { recursive: true });

    const liveFile = path.join(fixture.stateDirectory, `${liveOwnerTask.taskId}.json`);
    const liveSnapshot = JSON.parse(await readFile(liveFile, 'utf8')) as SnapshotFile;
    liveSnapshot.ownerPid = child.pid!;
    liveSnapshot.project!.copyDirectory = decoyCopy;
    const liveBytes = JSON.stringify(liveSnapshot);
    await writeFile(liveFile, liveBytes);

    const runningFile = path.join(fixture.stateDirectory, `${runningTask.taskId}.json`);
    const runningSnapshot = JSON.parse(await readFile(runningFile, 'utf8')) as SnapshotFile;
    runningSnapshot.record.status = 'running';
    runningSnapshot.project!.copyDirectory = decoyCopy;
    const runningBytes = JSON.stringify(runningSnapshot);
    await writeFile(runningFile, runningBytes);

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    await assert.rejects(recovered.discard(liveOwnerTask.taskId), { code: 'TASK_OWNED_BY_OTHER_SERVER' });
    assert.equal(await readFile(liveFile, 'utf8'), liveBytes);

    await assert.rejects(recovered.discard(runningTask.taskId), { code: 'TASK_NOT_READY' });
    assert.equal(await readFile(runningFile, 'utf8'), runningBytes);
  } finally {
    child.kill('SIGKILL');
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('shared copy with trailing separator in quarantined sibling still blocks integrate', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const siblingId = randomUUID();
    const validSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8')) as SnapshotFile;
    const siblingSnapshot: SnapshotFile = {
      ...validSnapshot,
      record: {
        ...validSnapshot.record,
        taskId: siblingId,
        createdAt: new Date(Date.now() + 60_000).toISOString(),
      },
      options: { ...validSnapshot.options, prompt: 'different-prompt' },
      project: {
        ...validSnapshot.project!,
        copyDirectory: validSnapshot.project!.copyDirectory + path.sep,
      },
    };
    await writeFile(path.join(fixture.stateDirectory, `${siblingId}.json`), JSON.stringify(siblingSnapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    await assert.rejects(recovered.integrate(valid.taskId, '0'.repeat(64)), { code: 'TASK_NOT_READY' });
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('structurally invalid executionPolicy without policy object quarantines as execution-policy-mismatch before realpath', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const decoyDir = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-exec-'));
  const managers: TaskManager[] = [];

  try {
    const snapshotFile = path.join(fixture.stateDirectory, `${valid.taskId}.json`);
    const snapshot = JSON.parse(await readFile(snapshotFile, 'utf8')) as SnapshotFile;
    delete snapshot.project!.executionPolicy;
    snapshot.project!.executionStateDirectory = path.join(decoyDir, 'nonexistent-exec-state');
    await writeFile(snapshotFile, JSON.stringify(snapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: valid.taskId, reason: 'execution-policy-mismatch' }]);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('non-UUID 36-hyphen json file is ignored by loadWithQuarantine and quarantinedTasks satisfies black_gravity_tasks schema', async () => {
  const stateDirectory = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-hyphen-state-'));
  const managers: TaskManager[] = [];

  try {
    await writeFile(path.join(stateDirectory, `${'-'.repeat(36)}.json`), '{ not valid json');
    const config = loadConfig({
      AGY_PATH: process.execPath,
      BRIDGE_STATE_DIRECTORY: stateDirectory,
    });
    const recovered = new TaskManager(new CliAdapter(config), config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.deepEqual(recovered.quarantinedTasks(), []);
    assert.equal(
      outputSchemas.black_gravity_tasks.safeParse({
        tasks: recovered.list(),
        quarantinedTasks: recovered.quarantinedTasks(),
      }).success,
      true,
    );
  } finally {
    for (const manager of managers) await manager.shutdown();
    await rm(stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('schema-invalid sibling and baseline-sharing sibling both collect copyHints and block integrate', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const validSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8')) as SnapshotFile;

    const schemaBadId = randomUUID();
    const schemaBadFile = path.join(fixture.stateDirectory, `${schemaBadId}.json`);
    const schemaBadSnapshot = {
      ...validSnapshot,
      record: { ...validSnapshot.record, taskId: schemaBadId, createdAt: new Date(Date.now() + 60_000).toISOString() },
      cursor: 'not-a-number',
    };
    await writeFile(schemaBadFile, JSON.stringify(schemaBadSnapshot));

    const firstRecovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(firstRecovered);
    await assert.rejects(firstRecovered.integrate(valid.taskId, '0'.repeat(64)), { code: 'TASK_NOT_READY' });
    await firstRecovered.shutdown();

    await rm(schemaBadFile, { force: true });

    const baselineSiblingId = randomUUID();
    const baselineSiblingSnapshot: SnapshotFile = {
      ...validSnapshot,
      record: { ...validSnapshot.record, taskId: baselineSiblingId, createdAt: new Date(Date.now() + 60_000).toISOString() },
      project: {
        ...validSnapshot.project!,
        copyDirectory: path.join(os.tmpdir(), 'black-gravity-copy-different-' + randomUUID()),
      },
    };
    await writeFile(path.join(fixture.stateDirectory, `${baselineSiblingId}.json`), JSON.stringify(baselineSiblingSnapshot));

    const secondRecovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(secondRecovered);
    await assert.rejects(secondRecovered.integrate(valid.taskId, '0'.repeat(64)), { code: 'TASK_NOT_READY' });
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('record-only discard acquires copy lock and refuses with STATE_BUSY when held, then succeeds after release', async () => {
  const fixture = await createFinishedTasks(1);
  const bad = fixture.finished[0]!;
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-lock-'));
  const decoyCopy = path.join(decoyParent, 'black-gravity-copy-decoy');
  const managers: TaskManager[] = [];
  let releaseCopy: (() => void) | undefined;

  try {
    await mkdir(decoyCopy, { recursive: true });
    const badFile = path.join(fixture.stateDirectory, `${bad.taskId}.json`);
    const badSnapshot = JSON.parse(await readFile(badFile, 'utf8')) as SnapshotFile;
    badSnapshot.project!.copyDirectory = decoyCopy;
    const badBytes = JSON.stringify(badSnapshot);
    await writeFile(badFile, badBytes);

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    const externalStore = new StateStore(fixture.stateDirectory);
    releaseCopy = externalStore.acquire(copyLockName(decoyCopy));

    await assert.rejects(recovered.discard(bad.taskId), { code: 'STATE_BUSY' });
    assert.equal(await readFile(badFile, 'utf8'), badBytes);

    releaseCopy();
    releaseCopy = undefined;

    const discarded = await recovered.discard(bad.taskId);
    assert.ok(discarded.discardedAt);
    assert.deepEqual(recovered.quarantinedTasks(), []);
  } finally {
    releaseCopy?.();
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('non-UUID 11111111-1111-1111-1111-111111111111.json is ignored by loadWithQuarantine and schemas validate reported lists', async () => {
  const stateDirectory = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-nonrfc-uuid-state-'));
  const managers: TaskManager[] = [];

  try {
    await writeFile(path.join(stateDirectory, '11111111-1111-1111-1111-111111111111.json'), '{ not valid json');
    const config = loadConfig({
      AGY_PATH: process.execPath,
      BRIDGE_STATE_DIRECTORY: stateDirectory,
    });
    const recovered = new TaskManager(new CliAdapter(config), config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.deepEqual(recovered.quarantinedTasks(), []);
    assert.equal(
      outputSchemas.black_gravity_tasks.safeParse({
        tasks: recovered.list(),
        quarantinedTasks: recovered.quarantinedTasks(),
      }).success,
      true,
    );
    const baseHealth = {
      installed: false,
      path: 'missing-agy',
      authenticated: null,
      error: 'CLI unavailable',
      approvalMode: 'auto',
      capabilities: Object.fromEntries(Object.keys(successOutputSchemas.black_gravity_health.shape.capabilities.shape).map(key => [key, false])),
      integrationApproval: { available: true, mode: 'auto', method: 'automatic' },
    };
    assert.equal(
      outputSchemas.black_gravity_health.safeParse({
        ...baseHealth,
        quarantinedTasks: recovered.lastQuarantinedTasks(),
      }).success,
      true,
    );
  } finally {
    for (const manager of managers) await manager.shutdown();
    await rm(stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('snapshot with 20000-level nested rawIsData event quarantines as invalid-snapshot without degrading server', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const validSnapshot = JSON.parse(await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8')) as SnapshotFile;
    const badId = randomUUID();
    const depth = 20_000;
    const nestedJson = '{"a":'.repeat(depth) + '1' + '}'.repeat(depth);
    const eventJson = `{"taskId":${JSON.stringify(badId)},"sequence":1,"timestamp":${JSON.stringify(new Date().toISOString())},"type":"response.chunk","data":${nestedJson},"rawIsData":true}`;
    const { project: _project, events: _events, ...rest } = validSnapshot;
    const { inbox: _inbox, dispatching: _dispatching, ...recordRest } = validSnapshot.record;
    const template = {
      ...rest,
      record: { ...recordRest, taskId: badId, messages: [], messageCursor: 0 },
      cursor: 1,
    };
    const serializedRest = JSON.stringify(template);
    const badText = serializedRest.slice(0, -1) + `,"events":[${eventJson}]}`;
    await writeFile(path.join(fixture.stateDirectory, `${badId}.json`), badText);

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);

    assert.equal(recovered.isStateDirectoryUsable(), true);
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: badId, reason: 'invalid-snapshot' }]);
    assert.deepEqual(recovered.list().map(task => task.taskId), [valid.taskId]);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('assertProcessesReconciled rejects shared quarantined sibling before reading or restoring line endings', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const validFile = path.join(fixture.stateDirectory, `${valid.taskId}.json`);
    const validSnapshot = JSON.parse(await readFile(validFile, 'utf8')) as SnapshotFile;
    const copySourcePath = path.join(validSnapshot.project!.copyDirectory, 'source.txt');
    const convertedContent = 'line1\nline2\n';
    await writeFile(copySourcePath, convertedContent, 'utf8');
    const sha256 = createHash('sha256').update(convertedContent).digest('hex');
    const projectCopy = {
      ...validSnapshot.project!,
      baseline: new Map(validSnapshot.project!.baseline as Array<[string, string]>),
    } as unknown as Parameters<typeof writeLineEndingConversions>[0];
    await writeLineEndingConversions(projectCopy, {
      taskId: valid.taskId,
      files: [{ path: 'source.txt', sha256 }],
      existingBefore: ['source.txt'],
    });
    validSnapshot.record.sessionId ??= randomUUID();
    validSnapshot.record.processCleanup = {
      verified: true,
      spawnedAt: new Date().toISOString(),
      checkedAt: new Date().toISOString(),
      remaining: 0,
    };
    await writeFile(validFile, JSON.stringify(validSnapshot));

    const markerPath = path.join(validSnapshot.project!.gitDirectory, 'LINE_ENDINGS_CONVERTED');
    const markerBefore = await readFile(markerPath);
    const sourceBefore = await readFile(copySourcePath);

    const badId = randomUUID();
    const { inbox: _inbox, dispatching: _dispatching, ...recordRest } = validSnapshot.record;
    await writeFile(
      path.join(fixture.stateDirectory, `${badId}.json`),
      JSON.stringify({
        ...validSnapshot,
        record: { ...recordRest, taskId: badId, messages: [], messageCursor: 0 },
        project: { ...validSnapshot.project!, executionPolicy: 'invalid' },
        events: [],
        cursor: 0,
      }),
    );

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);
    // Schema failure on project.executionPolicy still yields copy hints from parsed JSON.
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: badId, reason: 'invalid-snapshot' }]);

    await assert.rejects(
      () => recovered.startTests(valid.taskId, '0'.repeat(64), { executable: process.execPath, args: ['-v'] }),
      (error: unknown) => (error as { code?: string }).code === 'TASK_NOT_READY',
    );
    await assert.rejects(
      () => recovered.integrate(valid.taskId, '0'.repeat(64)),
      (error: unknown) => (error as { code?: string }).code === 'TASK_NOT_READY',
    );

    assert.deepEqual(await readFile(markerPath), markerBefore);
    assert.deepEqual(await readFile(copySourcePath), sourceBefore);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('record-only discard acquires normalized copy locks for both project.copyDirectory and record.copyDirectory', async () => {
  const fixture = await createFinishedTasks(1);
  const task = fixture.finished[0]!;
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-parent-'));
  const decoyCopy = path.join(decoyParent, 'black-gravity-copy-decoy');
  const realCopy = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-real-copy-'));
  const managers: TaskManager[] = [];

  try {
    const taskFile = path.join(fixture.stateDirectory, `${task.taskId}.json`);
    const snapshot = JSON.parse(await readFile(taskFile, 'utf8')) as SnapshotFile;
    snapshot.project!.copyDirectory = decoyCopy;
    snapshot.record.copyDirectory = realCopy;
    await writeFile(taskFile, JSON.stringify(snapshot));
    const beforeBytes = await readFile(taskFile);

    const locker = new StateStore(fixture.stateDirectory);
    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: task.taskId, reason: 'copy-outside-temporary-directory' }]);

    const releaseProjectLock = locker.acquire(copyLockName(decoyCopy));
    try {
      await assert.rejects(
        () => recovered.discard(task.taskId),
        (error: unknown) => (error as { code?: string }).code === 'STATE_BUSY',
      );
      assert.deepEqual(await readFile(taskFile), beforeBytes);
    } finally {
      releaseProjectLock();
    }

    const releaseRecordLock = locker.acquire(copyLockName(realCopy + path.sep));
    try {
      await assert.rejects(
        () => recovered.discard(task.taskId),
        (error: unknown) => (error as { code?: string }).code === 'STATE_BUSY',
      );
      assert.deepEqual(await readFile(taskFile), beforeBytes);
    } finally {
      releaseRecordLock();
    }

    const discarded = await recovered.discard(task.taskId);
    assert.equal(typeof discarded.discardedAt, 'string');
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(realCopy, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('record-only discard closes pending inbox entries and dispatching claim and persists the update', async () => {
  const fixture = await createFinishedTasks(1);
  const task = fixture.finished[0]!;
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-parent-'));
  const decoyCopy = path.join(decoyParent, 'black-gravity-copy-decoy');
  const managers: TaskManager[] = [];

  try {
    const taskFile = path.join(fixture.stateDirectory, `${task.taskId}.json`);
    const snapshot = JSON.parse(await readFile(taskFile, 'utf8')) as SnapshotFile;
    const queuedId = randomUUID();
    const dispatchingId = randomUUID();
    const now = new Date().toISOString();
    snapshot.ownerPid = 99999999;
    snapshot.project!.copyDirectory = decoyCopy;
    snapshot.record.dispatching = { messageId: dispatchingId, ownerId: randomUUID() };
    snapshot.record.inbox = [
      {
        messageId: queuedId,
        taskId: task.taskId,
        text: 'queued follow-up',
        receivedAt: now,
        receipt: { messageId: queuedId, taskId: task.taskId, state: 'queued' },
      },
      {
        messageId: dispatchingId,
        taskId: task.taskId,
        text: 'in-flight claim',
        receivedAt: now,
        receipt: { messageId: dispatchingId, taskId: task.taskId, state: 'queued' },
      },
    ];
    await writeFile(taskFile, JSON.stringify(snapshot));

    const recovered = new TaskManager(fixture.adapter, fixture.config);
    managers.push(recovered);
    assert.deepEqual(recovered.quarantinedTasks(), [{ taskId: task.taskId, reason: 'copy-outside-temporary-directory' }]);

    await recovered.discard(task.taskId);

    const checkClosedInbox = (entries: ReturnType<TaskManager['inbox']>) => {
      assert.equal(entries.length, 2);
      assert.equal(entries.some(entry => entry.receipt.state === 'queued'), false);
      const queuedEntry = entries.find(entry => entry.messageId === queuedId);
      assert.equal(queuedEntry?.receipt.state, 'cancelled');
      assert.equal(queuedEntry?.receipt.error?.code, 'COPY_DISCARDED');
      const dispatchingEntry = entries.find(entry => entry.messageId === dispatchingId);
      assert.equal(dispatchingEntry?.receipt.state, 'failed');
      assert.equal(dispatchingEntry?.receipt.error?.code, 'DISPATCH_INTERRUPTED');
    };

    checkClosedInbox(recovered.inbox(task.taskId));
    const persisted = JSON.parse(await readFile(taskFile, 'utf8')) as SnapshotFile;
    assert.equal('dispatching' in persisted.record, false);

    const fresh = new TaskManager(fixture.adapter, fixture.config);
    managers.push(fresh);
    assert.deepEqual(fresh.quarantinedTasks(), []);
    assert.equal(typeof fresh.status(task.taskId).discardedAt, 'string');
    checkClosedInbox(fresh.inbox(task.taskId));
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('strict StateStore.load throws BridgeError INVALID_STATE with original messages for invalid snapshots', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const loadStateDir = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-strict-load-'));
  const decoyParent = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-decoy-parent-'));

  try {
    const validText = await readFile(path.join(fixture.stateDirectory, `${valid.taskId}.json`), 'utf8');
    const validSnapshot = JSON.parse(validText) as SnapshotFile;
    const store = new StateStore(loadStateDir);

    const badJsonId = randomUUID();
    const badJsonFile = path.join(loadStateDir, `${badJsonId}.json`);
    await writeFile(badJsonFile, '{ not valid json');
    assert.throws(
      () => store.load(),
      (error: unknown) => (error as Error).name === 'BridgeError'
        && (error as { code?: string }).code === 'INVALID_STATE'
        && (error as Error).message === `Invalid persisted task: ${badJsonId}.json`,
    );
    await rm(badJsonFile, { force: true });

    const mismatchId = randomUUID();
    const mismatchFile = path.join(loadStateDir, `${mismatchId}.json`);
    await writeFile(mismatchFile, validText);
    assert.throws(
      () => store.load(),
      (error: unknown) => (error as Error).name === 'BridgeError'
        && (error as { code?: string }).code === 'INVALID_STATE'
        && (error as Error).message === 'Persisted task does not match its identity',
    );
    await rm(mismatchFile, { force: true });

    const outsideId = randomUUID();
    const outsideFile = path.join(loadStateDir, `${outsideId}.json`);
    const { inbox: _inbox, dispatching: _dispatching, ...recordRest } = validSnapshot.record;
    await writeFile(outsideFile, JSON.stringify({
      ...validSnapshot,
      record: { ...recordRest, taskId: outsideId, messages: [], messageCursor: 0 },
      project: { ...validSnapshot.project!, copyDirectory: path.join(decoyParent, 'black-gravity-copy-decoy') },
      events: [],
      cursor: 0,
    }));
    assert.throws(
      () => store.load(),
      (error: unknown) => (error as Error).name === 'BridgeError'
        && (error as { code?: string }).code === 'INVALID_STATE'
        && (error as Error).message === 'Persisted copy is outside bridge temporary storage',
    );
  } finally {
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(loadStateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(decoyParent, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('copyIdentity and copyLockName normalize Windows namespace aliases and POSIX paths', () => {
  const driveAliases = [
    'C:\\Temp\\x',
    '\\\\?\\C:\\Temp\\x',
    '\\\\.\\C:\\Temp\\x',
    '\\??\\C:\\Temp\\x',
    'C:/Temp/x/',
    '//?/c:/Temp/./x/',
  ];
  const expectedDriveId = copyIdentity('C:\\Temp\\x', 'win32');
  const expectedDriveLock = copyLockName('C:\\Temp\\x', 'win32');
  assert.equal(expectedDriveId, 'c:\\temp\\x');
  for (const alias of driveAliases) {
    assert.equal(copyIdentity(alias, 'win32'), expectedDriveId);
    assert.equal(copyLockName(alias, 'win32'), expectedDriveLock);
  }

  const uncAliases = [
    '\\\\server\\share\\x',
    '\\\\?\\UNC\\server\\share\\x',
    '\\\\.\\UNC\\server\\share\\x',
    '\\??\\UNC\\server\\share\\x',
    '//?/unc/SERVER/Share/x/',
  ];
  const expectedUncId = copyIdentity('\\\\server\\share\\x', 'win32');
  const expectedUncLock = copyLockName('\\\\server\\share\\x', 'win32');
  assert.equal(expectedUncId, '\\\\server\\share\\x');
  for (const alias of uncAliases) {
    assert.equal(copyIdentity(alias, 'win32'), expectedUncId);
    assert.equal(copyLockName(alias, 'win32'), expectedUncLock);
  }

  assert.notEqual(copyIdentity('D:\\Temp\\x', 'win32'), expectedDriveId);
  assert.notEqual(copyLockName('D:\\Temp\\x', 'win32'), expectedDriveLock);
  assert.notEqual(copyIdentity('C:\\Temp\\y', 'win32'), expectedDriveId);
  assert.notEqual(copyLockName('C:\\Temp\\y', 'win32'), expectedDriveLock);

  assert.equal(copyIdentity('/tmp/work/./copy/', 'linux'), '/tmp/work/copy');
  assert.equal(copyLockName('/tmp/work/./copy/', 'linux'), copyLockName('/tmp/work/copy', 'linux'));
  assert.notEqual(copyIdentity('/tmp/work/other', 'linux'), copyIdentity('/tmp/work/copy', 'linux'));
});

test('currentQuarantinedTasks refreshes on demand while lastQuarantinedTasks remains cached until refreshed', async () => {
  const fixture = await createFinishedTasks(1);
  const valid = fixture.finished[0]!;
  const managers: TaskManager[] = [];

  try {
    const manager = new TaskManager(fixture.adapter, fixture.config);
    managers.push(manager);
    assert.deepEqual(manager.lastQuarantinedTasks(), []);
    assert.deepEqual(manager.currentQuarantinedTasks(), []);

    const badId = randomUUID();
    const badFile = path.join(fixture.stateDirectory, `${badId}.json`);
    await writeFile(badFile, '{ garbage json');

    assert.deepEqual(manager.lastQuarantinedTasks(), []);
    assert.deepEqual(manager.currentQuarantinedTasks(), [{ taskId: badId, reason: 'invalid-snapshot' }]);
    assert.deepEqual(manager.list().map(task => task.taskId), [valid.taskId]);

    await rm(badFile, { force: true });
    assert.deepEqual(manager.currentQuarantinedTasks(), []);
  } finally {
    for (const manager of managers) await manager.shutdown();
    for (const tempDir of fixture.tempDirs) await rm(tempDir, { recursive: true, force: true });
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(fixture.stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
