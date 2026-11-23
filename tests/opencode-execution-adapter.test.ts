import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { discardProjectCopy } from '../src/isolation.js';
import {
  OPENCODE_READ_AGENT,
  OpenCodeExecutionAdapter,
  openCodeEnvironment,
  openCodeReadOnlyPermissions,
  sanitizeChildPath,
} from '../src/opencode-execution-adapter.js';
import { StateStore } from '../src/state-store.js';
import { decodeJsonEscapes } from '../src/subprocess.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError } from '../src/types.js';
import { taskTokenUsage } from '../src/usage.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
import { assertReadFixtureOutcome, createReadFixture } from './read-fixture.js';
import { waitForTask } from './wait-for-task.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MOCK_OPENCODE = path.resolve(HERE, '../../tests/mock-opencode.mjs');

class OpenCodeTestCliAdapter extends ControlledCliAdapter {
  override async listModels(): Promise<Model[]> {
    return [
      { id: 'opencode-go/mock-flash', name: 'Mock Flash' },
      { id: 'opencode-go/mock-pro', name: 'Mock Pro' },
    ];
  }
}

function createWorkspace(t: { after(fn: () => Promise<void> | void): void }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'bg-opencode-'));
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
      // Cleanup ignores missing or partially initialized test snapshots.
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

function seedMarkerRepoConfig(repoDir: string, markerFile: string): void {
  writeFileSync(
    path.join(repoDir, 'opencode.json'),
    JSON.stringify({
      providers: { markerprov: { name: 'MARKER_PROVIDER_9K' } },
      agents: { markeragent: { description: 'MARKER_AGENT_9K' } },
    }, null, 2),
    'utf8',
  );
  mkdirSync(path.join(repoDir, '.opencode', 'plugins'), { recursive: true });
  writeFileSync(
    path.join(repoDir, '.opencode', 'plugins', 'marker.js'),
    `import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
const target = ${JSON.stringify(markerFile)};
mkdirSync(path.dirname(target), { recursive: true });
writeFileSync(target, 'plugin-executed', 'utf8');
`,
    'utf8',
  );
  execFileSync('git', ['add', 'opencode.json', '.opencode/plugins/marker.js'], { cwd: repoDir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'add opencode marker config'], { cwd: repoDir, stdio: 'ignore' });
}

test('a) read fixture executes read-only via TaskManager, aggregates usage, and isolates argv/stdin/cwd', async t => {
  const ws = createWorkspace(t);
  const fixture = createReadFixture(ws.repoDir);
  const rec = path.join(ws.root, 'record-read.json');
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'read'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assertReadFixtureOutcome(record, ws.repoDir, fixture);
  assert.equal(record.execution?.provider, 'opencode');

  const usage = taskTokenUsage(record);
  assert.equal(usage.counters.inputTokens, 11);
  assert.equal(usage.counters.outputTokens, 7);
  assert.equal(usage.counters.thinkingTokens, 2);
  assert.equal(usage.counters.cacheReadTokens, 3);
  assert.equal(usage.counters.totalTokens, 20);

  const recorded = JSON.parse(readFileSync(rec, 'utf8')) as {
    argv: string[];
    cwd: string;
    stdin: string;
    env: Record<string, string>;
  };
  assert.deepEqual(recorded.argv, [
    'run', '--standalone', '--format', 'json', '--archived', '--agent', OPENCODE_READ_AGENT, '--model', 'opencode-go/mock-flash',
  ]);
  assert.equal(recorded.argv.includes('--auto'), false);
  assert.equal(recorded.stdin, fixture.prompt);
  assert.notEqual(realpathSync(recorded.cwd), realpathSync(ws.repoDir));
  assert.equal(recorded.cwd, record.copyDirectory);
  assert.equal(recorded.env.PWD, recorded.cwd);
});

test('b) openCodeEnvironment strips inherited OPENCODE_* variables on Linux and Windows and sets neutralization vars', () => {
  const linuxEnv = openCodeEnvironment(
    ['OPENCODE_CONFIG', 'OPENCODE_CONFIG_DIR'],
    {
      PATH: '/bin',
      OPENCODE_CONFIG: '/x.json',
      OPENCODE_CONFIG_DIR: '/x',
      OPENCODE_SERVER_PASSWORD: 'p',
      OPENCODE_DISABLE_PROJECT_CONFIG: '0',
    },
    'linux',
  );

  assert.equal(linuxEnv.PATH, '/bin');
  assert.equal('OPENCODE_CONFIG' in linuxEnv, false);
  assert.equal('OPENCODE_CONFIG_DIR' in linuxEnv, false);
  assert.equal('OPENCODE_SERVER_PASSWORD' in linuxEnv, false);
  assert.equal(linuxEnv.OPENCODE_DISABLE_PROJECT_CONFIG, '1');
  assert.equal(linuxEnv.OPENCODE_CONFIG_PROJECT_DISABLE, '1');
  assert.equal(linuxEnv.OPENCODE_DISABLE_CLAUDE_CODE, '1');
  assert.equal(linuxEnv.OPENCODE_DISABLE_AUTOUPDATE, '1');
  assert.deepEqual(JSON.parse(linuxEnv.OPENCODE_CONFIG_CONTENT!), {
    permissions: openCodeReadOnlyPermissions(),
    agents: {
      [OPENCODE_READ_AGENT]: {
        description: 'Black Gravity read-only executor',
        mode: 'primary',
        permissions: openCodeReadOnlyPermissions(),
      },
    },
  });

  const winEnv = openCodeEnvironment(
    ['OPENCODE_CONFIG'],
    {
      PATH: 'C:\\Windows\\System32',
      opencode_config: 'C:\\x.json',
      OPENCODE_CONFIG_DIR: 'C:\\x',
    },
    'win32',
  );
  assert.equal('opencode_config' in winEnv, false);
  assert.equal('OPENCODE_CONFIG' in winEnv, false);
  assert.equal('OPENCODE_CONFIG_DIR' in winEnv, false);
  assert.equal(winEnv.OPENCODE_DISABLE_PROJECT_CONFIG, '1');
  assert.equal(winEnv.OPENCODE_CONFIG_PROJECT_DISABLE, '1');
});

test('c) config neutralization skips project opencode.json and .opencode plugins while un-neutralized control executes them', async t => {
  const ws = createWorkspace(t);
  const markerDir = path.join(ws.root, 'outside-markers');
  const markerFile = path.join(markerDir, 'plugin-ran.txt');
  seedMarkerRepoConfig(ws.repoDir, markerFile);

  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'config-probe'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: 'probe project config',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'completed');
  const resultResponse = (record.result as { response?: unknown } | undefined)?.response;
  assert.equal(resultResponse, 'project-config-skipped');
  const finalMsg = [...(record.messages ?? [])].reverse().find(m => m.kind === 'final')?.text;
  assert.equal(finalMsg, 'project-config-skipped');
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes('MARKER_PROVIDER_9K'), false);
  assert.equal(serialized.includes('MARKER_AGENT_9K'), false);
  assert.equal(existsSync(markerFile), false);

  const control = spawnSync(
    process.execPath,
    [MOCK_OPENCODE, '--scenario', 'config-probe', 'run'],
    {
      cwd: ws.repoDir,
      input: 'probe',
      encoding: 'utf8',
      env: { PATH: process.env.PATH },
    },
  );
  assert.equal(control.status, 0, control.stderr);
  assert.equal(existsSync(markerFile), true);
  assert.match(control.stdout, /MARKER_PROVIDER_9K/);
  assert.match(control.stdout, /MARKER_AGENT_9K/);
});

test('d) tool denials, auto-rejected asks, and non-read tools become EXECUTION_INCOMPLETE', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const cases = [
    { scenario: 'write-denied', tool: 'edit' },
    { scenario: 'shell-denied', tool: 'shell' },
    { scenario: 'ask-rejected', tool: 'shell' },
    { scenario: 'write-succeeded', tool: 'edit' },
  ] as const;

  for (const item of cases) {
    const adapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', item.scenario],
    });
    const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

    const queued = await tasks.run({
      prompt: `run ${item.scenario}`,
      workingDirectory: ws.repoDir,
      mode: 'read-only',
    });
    const record = await waitForTask(tasks, queued.taskId);
    assert.equal(record.status, 'failed');
    assert.equal(record.error?.code, 'EXECUTION_INCOMPLETE');
    assert.ok(record.error?.message.startsWith('OpenCode run incomplete: '));
    assert.ok(record.error?.message.includes(item.tool));

    const direct = await adapter.execute({
      taskId: `direct-${item.scenario}`,
      prompt: `run ${item.scenario}`,
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
    });
    assert.equal(direct.status, 'failed');
    if (direct.status === 'failed') {
      assert.equal(direct.error.code, 'EXECUTION_INCOMPLETE');
      assert.ok(direct.error.message.startsWith('OpenCode run incomplete: '));
      assert.ok(direct.error.message.includes(item.tool));
    }
  }
});

test('e) stream errors, missing step_finish, protocol garbage, and missing binary produce typed failures', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const errorAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'error'],
  });
  const errRes = await errorAdapter.execute({
    taskId: 't-err',
    prompt: 'trigger error',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(errRes.status, 'failed');
  if (errRes.status === 'failed') {
    assert.equal(errRes.error.code, 'OPENCODE_PROCESS_FAILED');
    assert.match(errRes.error.message, /Model not found/);
  }

  for (const scenario of ['no-finish', 'garbage'] as const) {
    const adapter = new OpenCodeExecutionAdapter({
      executable: process.execPath,
      prefixArgs: [MOCK_OPENCODE, '--scenario', scenario],
    });
    const res = await adapter.execute({
      taskId: `t-${scenario}`,
      prompt: scenario,
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
    });
    assert.equal(res.status, 'failed');
    if (res.status === 'failed') {
      assert.equal(res.error.code, 'OPENCODE_PROCESS_FAILED');
    }
  }

  const missingAdapter = new OpenCodeExecutionAdapter({
    executable: path.join(ws.root, 'missing-opencode-binary'),
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, missingAdapter));
  const queued = await tasks.run({
    prompt: 'missing binary',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
  });
  const failed = await waitForTask(tasks, queued.taskId);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.error?.code, 'OPENCODE_UNAVAILABLE');
});

test('f) capability gates and invalid model names reject before spawning', async t => {
  const ws = createWorkspace(t);
  const rec = path.join(ws.root, 'should-not-spawn.json');
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'read'],
  });

  await assert.rejects(
    () => adapter.execute({
      taskId: 'gate-write',
      prompt: 'write',
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'write',
    }),
    err => err instanceof TypeError && /Execution capability unavailable/.test(err.message),
  );
  await assert.rejects(
    () => adapter.execute({
      taskId: 'gate-resume',
      prompt: 'resume',
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
      session: { id: 'ses_prev' },
    }),
    err => err instanceof TypeError && /Execution capability unavailable/.test(err.message),
  );
  await assert.rejects(
    () => adapter.execute({
      taskId: 'gate-schema',
      prompt: 'schema',
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
      outputSchema: { type: 'object' },
    }),
    err => err instanceof TypeError && /Execution capability unavailable/.test(err.message),
  );
  await assert.rejects(
    () => adapter.execute({
      taskId: 'gate-model',
      prompt: 'bad model',
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
      model: '--auto',
    }),
    err => err instanceof BridgeError && err.code === 'INVALID_MODEL',
  );
  assert.equal(existsSync(rec), false);
});

test('g) listModels and version parse CLI output and propagate failures', async () => {
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE],
  });
  assert.equal(adapter.capabilities.modelList, 'supported');
  assert.deepEqual(await adapter.listModels(), [
    { id: 'opencode-go/mock-flash' },
    { id: 'opencode-go/mock-pro' },
  ]);
  assert.equal(await adapter.version(), '0.0.0-mock');

  const failingAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'models-fail'],
  });
  await assert.rejects(
    () => failingAdapter.listModels(),
    err => err instanceof BridgeError && err.code === 'OPENCODE_PROCESS_FAILED',
  );
});

test('h) opt-in real opencode configuration neutralization check', { skip: !process.env.BRIDGE_OPENCODE_REAL_BIN }, t => {
  const bin = process.env.BRIDGE_OPENCODE_REAL_BIN!;
  const ws = createWorkspace(t);
  const markerDir = path.join(ws.root, 'outside-real-markers');
  const markerFile = path.join(markerDir, 'real-plugin-ran.txt');
  seedMarkerRepoConfig(ws.repoDir, markerFile);

  const env = openCodeEnvironment([], process.env);
  const configOut = execFileSync(bin, ['debug', 'config', '--standalone'], {
    cwd: ws.repoDir,
    env,
    encoding: 'utf8',
  });
  const agentsOut = execFileSync(bin, ['debug', 'agents', '--standalone'], {
    cwd: ws.repoDir,
    env,
    encoding: 'utf8',
  });

  const repoConfigPath = path.join(ws.repoDir, 'opencode.json');
  const repoOpencodeDir = path.join(ws.repoDir, '.opencode');
  for (const out of [configOut, agentsOut]) {
    assert.equal(out.includes(repoConfigPath), false);
    assert.equal(out.includes(realpathSync(repoConfigPath)), false);
    assert.equal(out.includes(repoOpencodeDir), false);
    assert.equal(out.includes(realpathSync(repoOpencodeDir)), false);
    assert.equal(out.includes('MARKER_AGENT_9K'), false);
  }
  assert.equal(existsSync(markerFile), false);

  const parsedAgents = JSON.parse(agentsOut) as
    | Array<{ name?: string; permissions?: Array<{ action: string; resource: string; effect: string }> }>
    | Record<string, { permissions?: Array<{ action: string; resource: string; effect: string }> }>;
  const readAgent = Array.isArray(parsedAgents)
    ? parsedAgents.find(agent => agent.name === OPENCODE_READ_AGENT)
    : parsedAgents[OPENCODE_READ_AGENT];
  assert.ok(readAgent && Array.isArray(readAgent.permissions), 'Expected black-gravity-read agent permissions');

  const expectedRun = openCodeReadOnlyPermissions();
  const perms = readAgent.permissions;
  let matchIndex = -1;
  for (let i = perms.length - expectedRun.length; i >= 0; i--) {
    const slice = perms.slice(i, i + expectedRun.length);
    if (slice.every((rule, idx) =>
      rule.action === expectedRun[idx]!.action &&
      rule.resource === expectedRun[idx]!.resource &&
      rule.effect === expectedRun[idx]!.effect)) {
      matchIndex = i;
      break;
    }
  }
  assert.ok(matchIndex >= 0, 'Expected openCodeReadOnlyPermissions() as a contiguous run');
  for (const trailing of perms.slice(matchIndex + expectedRun.length)) {
    assert.equal(trailing.effect, 'deny');
  }
});

test('i) executable resolution rejects non-absolute paths and executables inside the task working directory', async t => {
  assert.throws(
    () => new OpenCodeExecutionAdapter({ executable: 'opencode' }),
    err => err instanceof BridgeError && err.code === 'OPENCODE_UNAVAILABLE',
  );

  if (process.platform === 'win32') return;

  const ws = createWorkspace(t);
  const markerFile = path.join(ws.root, 'inside-cwd-executed.txt');
  const fakeBin = path.join(ws.repoDir, 'fake-opencode');
  writeFileSync(fakeBin, `#!/bin/sh\ntouch ${JSON.stringify(markerFile)}\n`, 'utf8');
  chmodSync(fakeBin, 0o755);

  const adapter = new OpenCodeExecutionAdapter({ executable: fakeBin });
  await assert.rejects(
    () => adapter.execute({
      taskId: 'inside-cwd',
      prompt: 'hi',
      workingDirectory: ws.repoDir,
      role: 'implementer',
      mode: 'read-only',
    }),
    err => err instanceof BridgeError && err.code === 'OPENCODE_UNAVAILABLE',
  );
  assert.equal(existsSync(markerFile), false);
});

test('j) child environment secrets are redacted across errors, completed responses, and utility failures', async t => {
  const ws = createWorkspace(t);
  const secret = 'zq-test-opaque-key-0123456789';
  const baseOptions = {
    executable: process.execPath,
    allowedEnvVars: ['MOCK_PROVIDER_API_KEY'],
    env: { ...process.env, MOCK_PROVIDER_API_KEY: secret },
  };

  const leakAdapter = new OpenCodeExecutionAdapter({
    ...baseOptions,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'leak'],
  });
  const leakRes = await leakAdapter.execute({
    taskId: 't-leak',
    prompt: 'leak',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(leakRes.status, 'failed');
  if (leakRes.status === 'failed') {
    assert.equal(leakRes.error.message.includes(secret), false);
    assert.equal(leakRes.error.message.includes('[redacted]'), true);
  }

  const leakOkAdapter = new OpenCodeExecutionAdapter({
    ...baseOptions,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'leak-ok'],
  });
  const leakOkRes = await leakOkAdapter.execute({
    taskId: 't-leak-ok',
    prompt: 'leak-ok',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(leakOkRes.status, 'completed');
  if (leakOkRes.status === 'completed') {
    assert.equal(leakOkRes.response.includes(secret), false);
    assert.equal(leakOkRes.response.includes('[redacted]'), true);
    const rawResponse = (leakOkRes.raw as { response?: string }).response ?? '';
    assert.equal(rawResponse.includes(secret), false);
    assert.equal(rawResponse.includes('[redacted]'), true);
  }

  const modelsLeakAdapter = new OpenCodeExecutionAdapter({
    ...baseOptions,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'models-leak'],
  });
  await assert.rejects(
    () => modelsLeakAdapter.listModels(),
    err =>
      err instanceof BridgeError &&
      !err.message.includes(secret) &&
      err.message.includes('[redacted]'),
  );
});

test('k) sanitizeChildPath drops relative, missing, duplicate, and untrusted-directory PATH entries', async t => {
  const ws = createWorkspace(t);
  const tmpA = realpathSync(mkdtempSync(path.join(ws.root, 'path-a-')));
  const repoBin = path.join(ws.repoDir, 'bin');
  mkdirSync(repoBin, { recursive: true });
  const nonexistent = path.join(ws.root, 'nonexistent-path-entry');

  if (process.platform !== 'win32') {
    const rawPath = ['.', 'relbin', tmpA, tmpA, repoBin, nonexistent].join(':');
    assert.equal(sanitizeChildPath(rawPath, ws.repoDir, 'linux'), tmpA);
    assert.equal(sanitizeChildPath(rawPath, undefined, 'linux'), [tmpA, realpathSync(repoBin)].join(':'));
  } else {
    const rawPath = ['.', 'relbin', tmpA, tmpA, repoBin, nonexistent].join(';');
    assert.equal(sanitizeChildPath(rawPath, ws.repoDir, 'win32'), tmpA);
    assert.equal(sanitizeChildPath(rawPath, undefined, 'win32'), [tmpA, realpathSync(repoBin)].join(';'));
  }

  const fixture = createReadFixture(ws.repoDir);
  const rec = path.join(ws.root, 'record-path.json');
  const nodeDir = path.dirname(process.execPath);
  const inputPath = ['.', 'relbin', repoBin, nodeDir].join(path.delimiter);
  const expectedPath = sanitizeChildPath(inputPath, ws.repoDir);
  const baseEnv = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.toUpperCase() !== 'PATH'),
  );
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'read'],
    env: { ...baseEnv, PATH: inputPath },
  });
  const res = await adapter.execute({
    taskId: 't-path-e2e',
    prompt: fixture.prompt,
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(res.status, 'completed');

  const recorded = JSON.parse(readFileSync(rec, 'utf8')) as { env: Record<string, string> };
  const pathKey = process.platform === 'win32'
    ? Object.keys(recorded.env).find(key => key.toUpperCase() === 'PATH')
    : 'PATH';
  assert.ok(pathKey);
  const recordedPath = recorded.env[pathKey]!;
  assert.equal(recordedPath, expectedPath);
  const parts = recordedPath.split(path.delimiter);
  assert.equal(parts.includes('.'), false);
  assert.equal(parts.includes('relbin'), false);
  assert.equal(parts.includes(repoBin), false);
  assert.equal(parts.includes(realpathSync(repoBin)), false);
});

test('l) tool_use metadata in raw is redacted for child environment secrets', async t => {
  const ws = createWorkspace(t);
  const secret = 'zq-test-opaque-key-0123456789';
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'leak-tool'],
    allowedEnvVars: ['MOCK_PROVIDER_API_KEY'],
    env: { ...process.env, MOCK_PROVIDER_API_KEY: secret },
  });
  const result = await adapter.execute({
    taskId: 't-leak-tool',
    prompt: 'leak-tool',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(JSON.stringify(result.raw).includes(secret), false);
});

test('m) JSON-escaped child environment secrets are redacted in completed responses', async t => {
  const ws = createWorkspace(t);
  const secret = 'zq-test-opaque-key-0123456789';
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'leak-escaped'],
    allowedEnvVars: ['MOCK_PROVIDER_API_KEY'],
    env: { ...process.env, MOCK_PROVIDER_API_KEY: secret },
  });
  const result = await adapter.execute({
    taskId: 't-leak-escaped',
    prompt: 'leak-escaped',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
  });
  assert.equal(result.status, 'completed');
  if (result.status === 'completed') {
    assert.equal(decodeJsonEscapes(result.response).includes(secret), false);
  }
  assert.equal(JSON.stringify(result).includes(secret), false);
});
