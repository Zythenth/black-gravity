import assert from 'node:assert/strict';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { mkdtemp, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const entryPath = fileURLToPath(new URL('../src/index.js', import.meta.url));
const agySpawnPath = fileURLToPath(new URL('../../tests/agy-spawn.mjs', import.meta.url));
const mockAgyPath = fileURLToPath(new URL('../../tests/mock-agy.mjs', import.meta.url));
const posixSkip = process.platform === 'win32' && 'POSIX signals are not supported on Windows';

interface RpcResponse {
  id?: number;
  result?: Record<string, unknown>;
  error?: { code?: number; message?: string };
}

interface ExitResult {
  code: number | null;
  signal: NodeJS.Signals | null;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

function readTaskStatus(stateDir: string, taskId: string): unknown {
  const snapshot = JSON.parse(readFileSync(path.join(stateDir, `${taskId}.json`), 'utf8')) as {
    record?: { status?: unknown };
  };
  return snapshot.record?.status;
}

async function createTestContext() {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'black-gravity-shutdown-test-')));
  const stateDir = path.join(dir, 'state');
  const nodeCacheDir = path.join(dir, 'node-cache');
  const projectDir = path.join(dir, 'project');
  mkdirSync(projectDir, { recursive: true });
  execFileSync('git', ['init', '--quiet'], { cwd: projectDir, stdio: 'ignore' });
  writeFileSync(path.join(projectDir, 'source.txt'), 'shutdown test\n', 'utf8');
  execFileSync('git', ['add', 'source.txt'], { cwd: projectDir, stdio: 'ignore' });
  execFileSync(
    'git',
    ['-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '--quiet', '-m', 'init'],
    { cwd: projectDir, stdio: 'ignore' },
  );
  return { dir, stateDir, nodeCacheDir, projectDir };
}

function startServer(stateDir: string, nodeCacheDir: string) {
  const child: ChildProcessWithoutNullStreams = spawn(
    process.execPath,
    ['--import', pathToFileURL(agySpawnPath).href, entryPath],
    {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      env: {
        ...process.env,
        AGY_PATH: mockAgyPath,
        BRIDGE_TEST_EXECUTOR: 'agy',
        BRIDGE_TOOL_PROFILE: 'full',
        BRIDGE_STATE_DIRECTORY: stateDir,
        BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY: nodeCacheDir,
      },
    },
  );

  let nextId = 1;
  let stdoutBuffer = '';
  let stderrBuffer = '';
  let stderrLog = '';
  let startedPid: number | undefined;
  let exitResult: ExitResult | undefined;
  const pending = new Map<number, { resolve: (value: Record<string, unknown>) => void; reject: (error: Error) => void }>();
  const pidWaiters = new Set<{ resolve: (pid: number) => void; reject: (error: Error) => void }>();
  const exitWaiters = new Set<(result: ExitResult) => void>();

  const failPending = (reason: string) => {
    const error = new Error(`${reason}; stderr: ${stderrLog}`);
    for (const entry of pending.values()) entry.reject(error);
    pending.clear();
    for (const waiter of pidWaiters) waiter.reject(error);
    pidWaiters.clear();
  };

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    stdoutBuffer += chunk;
    let newline = stdoutBuffer.indexOf('\n');
    while (newline !== -1) {
      const line = stdoutBuffer.slice(0, newline).trim();
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (line) {
        const message = JSON.parse(line) as RpcResponse;
        if (typeof message.id === 'number') {
          const entry = pending.get(message.id);
          if (entry) {
            pending.delete(message.id);
            if (message.error) entry.reject(new Error(`RPC error ${message.error.code ?? ''}: ${message.error.message ?? 'unknown'}`));
            else entry.resolve(message.result ?? {});
          }
        }
      }
      newline = stdoutBuffer.indexOf('\n');
    }
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderrLog = (stderrLog + chunk).slice(-8000);
    stderrBuffer += chunk;
    let newline = stderrBuffer.indexOf('\n');
    while (newline !== -1) {
      const line = stderrBuffer.slice(0, newline).trim();
      stderrBuffer = stderrBuffer.slice(newline + 1);
      if (line) {
        try {
          const parsed = JSON.parse(line) as { type?: unknown; pid?: unknown };
          if (parsed.type === 'process.started' && typeof parsed.pid === 'number') {
            startedPid = parsed.pid;
            for (const waiter of pidWaiters) waiter.resolve(parsed.pid);
            pidWaiters.clear();
          }
        } catch {
          // Ignore non-JSON diagnostic lines on stderr.
        }
      }
      newline = stderrBuffer.indexOf('\n');
    }
  });

  child.stdin.on('error', () => {});

  child.once('error', error => {
    failPending(`Server error: ${error.message}`);
  });

  child.once('close', (code, signal) => {
    exitResult = { code, signal };
    failPending(`Server exited early (code=${code}, signal=${signal})`);
    for (const waiter of exitWaiters) waiter(exitResult);
    exitWaiters.clear();
  });

  const request = (method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> => {
    if (exitResult) return Promise.reject(new Error(`Server already exited (code=${exitResult.code}, signal=${exitResult.signal})`));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  };

  const initialize = async () => {
    await request('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'server-shutdown-test', version: '1.0.0' },
    });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  };

  const startHoldTask = async (projectDir: string): Promise<string> => {
    const result = await request('tools/call', {
      name: 'black_gravity_run',
      arguments: { prompt: 'timeout: hold', workingDirectory: projectDir },
    });
    assert.equal(result.isError, undefined, `black_gravity_run failed: ${JSON.stringify(result)}`);
    const structured = result.structuredContent as { task?: { taskId?: unknown } } | undefined;
    const taskId = structured?.task?.taskId;
    if (typeof taskId !== 'string') {
      assert.fail(`Missing taskId in black_gravity_run result: ${JSON.stringify(result)}`);
    }
    return taskId;
  };

  const waitForStartedPid = (timeoutMs = 10_000): Promise<number> => {
    if (startedPid !== undefined) return Promise.resolve(startedPid);
    if (exitResult) return Promise.reject(new Error(`Server exited before process.started; stderr: ${stderrLog}`));
    return new Promise((resolve, reject) => {
      const waiter = {
        resolve: (pid: number) => {
          clearTimeout(timer);
          resolve(pid);
        },
        reject: (error: Error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      const timer = setTimeout(() => {
        pidWaiters.delete(waiter);
        reject(new Error(`Timed out waiting for process.started after ${timeoutMs} ms; stderr: ${stderrLog}`));
      }, timeoutMs);
      pidWaiters.add(waiter);
    });
  };

  const waitForExit = (timeoutMs: number): Promise<ExitResult> => {
    if (exitResult) return Promise.resolve(exitResult);
    return new Promise((resolve, reject) => {
      const waiter = (result: ExitResult) => {
        clearTimeout(timer);
        resolve(result);
      };
      const timer = setTimeout(() => {
        exitWaiters.delete(waiter);
        reject(new Error(`Server did not exit within ${timeoutMs} ms; stderr: ${stderrLog}`));
      }, timeoutMs);
      exitWaiters.add(waiter);
    });
  };

  const cleanup = async (agyPid?: number) => {
    if (child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGKILL'); } catch { /* already exited */ }
      await waitForExit(2000).catch(() => {});
    }
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
    if (agyPid !== undefined && isProcessAlive(agyPid)) {
      try { process.kill(agyPid, 'SIGKILL'); } catch { /* already exited */ }
    }
  };

  return { child, initialize, startHoldTask, waitForStartedPid, waitForExit, cleanup };
}

test('server exits cleanly with code 0 when client ends stdin with no running task', async () => {
  const { dir, stateDir, nodeCacheDir } = await createTestContext();
  const server = startServer(stateDir, nodeCacheDir);
  try {
    await server.initialize();
    server.child.stdin.end();
    const exit = await server.waitForExit(10_000);
    assert.equal(exit.code, 0);
    assert.equal(exit.signal, null);
  } finally {
    await server.cleanup();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('server waits for running task to complete when client ends stdin', async () => {
  const { dir, stateDir, nodeCacheDir, projectDir } = await createTestContext();
  const server = startServer(stateDir, nodeCacheDir);
  let agyPid: number | undefined;
  try {
    await server.initialize();
    const taskId = await server.startHoldTask(projectDir);
    agyPid = await server.waitForStartedPid();
    assert.equal(isProcessAlive(agyPid), true, 'fake agy must still be running when shutdown starts');
    server.child.stdin.end();
    const exit = await server.waitForExit(30_000);
    assert.equal(exit.code, 0);
    assert.equal(exit.signal, null);
    assert.equal(readTaskStatus(stateDir, taskId), 'completed');
    assert.equal(isProcessAlive(agyPid), false);
  } finally {
    await server.cleanup(agyPid);
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  test(`server cancels running task and exits cleanly on ${signal}`, { skip: posixSkip }, async () => {
    const { dir, stateDir, nodeCacheDir, projectDir } = await createTestContext();
    const server = startServer(stateDir, nodeCacheDir);
    let agyPid: number | undefined;
    try {
      await server.initialize();
      const taskId = await server.startHoldTask(projectDir);
      agyPid = await server.waitForStartedPid();
      assert.equal(isProcessAlive(agyPid), true, 'fake agy must still be running when shutdown starts');
      server.child.kill(signal);
      const exit = await server.waitForExit(10_000);
      assert.equal(exit.code, 0);
      assert.equal(exit.signal, null);
      assert.equal(readTaskStatus(stateDir, taskId), 'cancelled');
      assert.equal(isProcessAlive(agyPid), false);
    } finally {
      await server.cleanup(agyPid);
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
}

test('server lets running task complete and exits cleanly on SIGHUP', { skip: posixSkip }, async () => {
  const { dir, stateDir, nodeCacheDir, projectDir } = await createTestContext();
  const server = startServer(stateDir, nodeCacheDir);
  let agyPid: number | undefined;
  try {
    await server.initialize();
    const taskId = await server.startHoldTask(projectDir);
    agyPid = await server.waitForStartedPid();
    assert.equal(isProcessAlive(agyPid), true, 'fake agy must still be running when shutdown starts');
    server.child.kill('SIGHUP');
    const exit = await server.waitForExit(30_000);
    assert.equal(exit.code, 0);
    assert.equal(exit.signal, null);
    assert.equal(readTaskStatus(stateDir, taskId), 'completed');
    assert.equal(isProcessAlive(agyPid), false);
  } finally {
    await server.cleanup(agyPid);
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
