import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { lstat, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CliAdapter } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
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

interface Fixture {
  dir: string;
  stateDirectory: string;
  config: ReturnType<typeof loadConfig>;
  adapter: CliAdapter;
  managers: TaskManager[];
  tasks: TaskManager;
  finished: TaskRecord;
  copyDirectory: string;
  gitDirectory: string;
  spawnedCount: () => number;
}

async function withFixture(runTest: (fixture: Fixture) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-copy-presence-repo-'));
  const stateDirectory = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-state-test-'));
  const managers: TaskManager[] = [];
  let copyDirectory: string | undefined;
  let gitDirectory: string | undefined;
  try {
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
    const spawnTask = adapter.spawnTask.bind(adapter);
    let spawned = 0;
    adapter.spawnTask = (...args) => {
      spawned += 1;
      return spawnTask(...args);
    };

    const tasks = new TaskManager(adapter, config);
    managers.push(tasks);

    const run = await tasks.run({ prompt: 'write:test', workingDirectory: dir });
    const finished = await until(tasks, run.taskId, done);
    assert.equal(finished.status, 'completed', JSON.stringify(finished.error));

    const snapshot = JSON.parse(await readFile(path.join(stateDirectory, `${finished.taskId}.json`), 'utf8')) as {
      project: { copyDirectory: string; gitDirectory: string };
    };
    copyDirectory = snapshot.project.copyDirectory;
    gitDirectory = snapshot.project.gitDirectory;
    assert.equal(copyDirectory, finished.copyDirectory);

    await tasks.shutdown();
    await runTest({
      dir,
      stateDirectory,
      config,
      adapter,
      managers,
      tasks,
      finished,
      copyDirectory,
      gitDirectory,
      spawnedCount: () => spawned,
    });
  } finally {
    for (const manager of managers) await manager.shutdown();
    if (copyDirectory) await rm(copyDirectory, { recursive: true, force: true });
    if (gitDirectory) await rm(gitDirectory, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
    await rm(stateDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

for (const removal of ['copy', 'baseline', 'both'] as const) {
  test(`missing ${removal} directory refuses resume and preview with COPY_MISSING while discard succeeds`, () =>
    withFixture(async ({ dir, config, adapter, managers, finished, copyDirectory, gitDirectory, spawnedCount }) => {
      if (removal === 'copy' || removal === 'both') {
        await rm(copyDirectory, { recursive: true, force: true });
      }
      if (removal === 'baseline' || removal === 'both') {
        await rm(gitDirectory, { recursive: true, force: true });
      }

      const recovered = new TaskManager(adapter, config);
      managers.push(recovered);
      const tasksBefore = recovered.list().map(task => task.taskId);
      const eventsBefore = recovered.readEvents(finished.taskId).events.length;
      const spawnedBefore = spawnedCount();

      await assert.rejects(
        recovered.resume({ prompt: 'write:again', workingDirectory: dir }, finished.taskId),
        { code: 'COPY_MISSING' },
      );

      assert.equal(spawnedCount(), spawnedBefore);
      assert.deepEqual(recovered.list().map(task => task.taskId), tasksBefore);
      assert.equal(recovered.readEvents(finished.taskId).events.length, eventsBefore);
      assert.equal(
        recovered.list().every(task =>
          recovered.readEvents(task.taskId).events.filter(event => event.type === 'process.started').length ===
          (task.taskId === finished.taskId ? 1 : 0),
        ),
        true,
      );

      if (removal === 'copy' || removal === 'both') {
        await assert.rejects(lstat(copyDirectory), { code: 'ENOENT' });
      }
      if (removal === 'baseline' || removal === 'both') {
        await assert.rejects(lstat(gitDirectory), { code: 'ENOENT' });
      }

      assert.equal(await readFile(path.join(dir, 'source.txt'), 'utf8'), 'source');
      await assert.rejects(lstat(path.join(dir, 'BLACK_GRAVITY_TEST.md')), { code: 'ENOENT' });

      await assert.rejects(recovered.preview(finished.taskId), { code: 'COPY_MISSING' });

      const discarded = await recovered.discard(finished.taskId);
      assert.ok(discarded.discardedAt);
    }),
  );
}

test('missing baseline HEAD file refuses resume with COPY_MISSING', () =>
  withFixture(async ({ dir, config, adapter, managers, finished, gitDirectory, spawnedCount }) => {
    await rm(path.join(gitDirectory, 'HEAD'), { force: true });

    const recovered = new TaskManager(adapter, config);
    managers.push(recovered);
    const tasksBefore = recovered.list().map(task => task.taskId);
    const spawnedBefore = spawnedCount();

    await assert.rejects(
      recovered.resume({ prompt: 'write:again', workingDirectory: dir }, finished.taskId),
      { code: 'COPY_MISSING' },
    );

    assert.equal(spawnedCount(), spawnedBefore);
    assert.deepEqual(recovered.list().map(task => task.taskId), tasksBefore);
    await assert.rejects(lstat(path.join(gitDirectory, 'HEAD')), { code: 'ENOENT' });
    assert.equal(await readFile(path.join(dir, 'source.txt'), 'utf8'), 'source');
    await assert.rejects(lstat(path.join(dir, 'BLACK_GRAVITY_TEST.md')), { code: 'ENOENT' });

    const discarded = await recovered.discard(finished.taskId);
    assert.ok(discarded.discardedAt);
  }),
);

test('copy directory replaced by a symbolic link refuses resume with UNSAFE_PROJECT_PATH without touching target', () =>
  withFixture(async ({ dir, config, adapter, managers, finished, copyDirectory, spawnedCount }) => {
    const linkTarget = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-link-target-'));
    try {
      await rm(copyDirectory, { recursive: true, force: true });
      await symlink(linkTarget, copyDirectory, process.platform === 'win32' ? 'junction' : 'dir');

      const recovered = new TaskManager(adapter, config);
      managers.push(recovered);
      const tasksBefore = recovered.list().map(task => task.taskId);
      const spawnedBefore = spawnedCount();

      await assert.rejects(
        recovered.resume({ prompt: 'write:again', workingDirectory: dir }, finished.taskId),
        { code: 'UNSAFE_PROJECT_PATH' },
      );

      assert.equal(spawnedCount(), spawnedBefore);
      assert.deepEqual(recovered.list().map(task => task.taskId), tasksBefore);
      assert.deepEqual(await readdir(linkTarget), []);
    } finally {
      await rm(copyDirectory, { recursive: true, force: true });
      await rm(linkTarget, { recursive: true, force: true });
    }
  }),
);

test('baseline directory replaced by a regular file refuses resume and preview with UNSAFE_PROJECT_PATH', () =>
  withFixture(async ({ dir, config, adapter, managers, finished, gitDirectory, spawnedCount }) => {
    await rm(gitDirectory, { recursive: true, force: true });
    await writeFile(gitDirectory, 'not a directory');
    try {
      const recovered = new TaskManager(adapter, config);
      managers.push(recovered);
      const tasksBefore = recovered.list().map(task => task.taskId);
      const spawnedBefore = spawnedCount();

      await assert.rejects(
        recovered.resume({ prompt: 'write:again', workingDirectory: dir }, finished.taskId),
        { code: 'UNSAFE_PROJECT_PATH' },
      );

      assert.equal(spawnedCount(), spawnedBefore);
      assert.deepEqual(recovered.list().map(task => task.taskId), tasksBefore);
      assert.equal(await readFile(path.join(dir, 'source.txt'), 'utf8'), 'source');
      await assert.rejects(lstat(path.join(dir, 'BLACK_GRAVITY_TEST.md')), { code: 'ENOENT' });

      await assert.rejects(recovered.preview(finished.taskId), { code: 'UNSAFE_PROJECT_PATH' });
    } finally {
      await rm(gitDirectory, { force: true });
    }
  }),
);

test('intact copy resumes cleanly from a new TaskManager and reuses the same copyDirectory', () =>
  withFixture(async ({ dir, config, adapter, managers, finished, copyDirectory }) => {
    const recovered = new TaskManager(adapter, config);
    managers.push(recovered);

    const resumed = await recovered.resume({ prompt: 'write:again', workingDirectory: dir }, finished.taskId);
    const continued = await until(recovered, resumed.taskId, done);
    assert.equal(continued.status, 'completed', JSON.stringify(continued.error));
    assert.equal(continued.copyDirectory, copyDirectory);
    assert.equal(
      await readFile(path.join(copyDirectory, 'BLACK_GRAVITY_TEST.md'), 'utf8'),
      'Antigravity MCP bridge test successful.',
    );

    await recovered.discard(continued.taskId);
  }),
);
