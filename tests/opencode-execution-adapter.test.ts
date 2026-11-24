import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { isAgentConfigPath, isProtectedPatchPath } from '../src/agent-config.js';
import type { Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { discardProjectCopy } from '../src/isolation.js';
import { detectBubblewrap } from '../src/linux-executor.js';
import {
  OPENCODE_READ_AGENT,
  OPENCODE_RESUME_REQUIRES_PID_NAMESPACE,
  OPENCODE_WRITE_AGENT,
  OpenCodeExecutionAdapter,
  openCodeConfigContent,
  openCodeEnvironment,
  openCodeReadOnlyPermissions,
  openCodeWritePermissions,
  sanitizeChildPath,
  type OpenCodePermissionRule,
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
    formatter: false,
    lsp: false,
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
  const spawnLog = path.join(ws.root, 'gate-spawn-log.jsonl');
  const resumeAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--spawn-log', spawnLog, '--record', rec, '--scenario', 'read'],
    containment: 'none',
  });
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'read'],
  });

  const writeResumeRes = await resumeAdapter.execute({
    taskId: 'gate-write-resume',
    prompt: 'write resume',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'write',
    session: { id: 'ses_prev' },
  });
  assert.equal(writeResumeRes.status, 'failed');
  if (writeResumeRes.status === 'failed') {
    assert.equal(writeResumeRes.error.code, OPENCODE_RESUME_REQUIRES_PID_NAMESPACE);
  }

  const readResumeRes = await resumeAdapter.execute({
    taskId: 'gate-resume',
    prompt: 'resume',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
    session: { id: 'ses_prev' },
  });
  assert.equal(readResumeRes.status, 'failed');
  if (readResumeRes.status === 'failed') {
    assert.equal(readResumeRes.error.code, OPENCODE_RESUME_REQUIRES_PID_NAMESPACE);
  }

  assert.equal(existsSync(spawnLog), false);

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

test('f2) resume inside the PID namespace checks session list before run', async t => {
  if (process.platform !== 'linux' || !detectBubblewrap().available) {
    t.skip('Linux bubblewrap PID namespace unavailable');
    return;
  }
  const ws = createWorkspace(t);
  const rec = path.join(ws.root, 'f2-should-not-run.json');
  const spawnLog = path.join(ws.root, 'f2-spawn-log.jsonl');
  const resumeAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--spawn-log', spawnLog, '--record', rec, '--scenario', 'read'],
    containment: 'auto',
  });

  const writeResumeRes = await resumeAdapter.execute({
    taskId: 'f2-write-resume',
    prompt: 'write resume',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'write',
    session: { id: 'ses_prev' },
  });
  assert.equal(writeResumeRes.status, 'failed');
  if (writeResumeRes.status === 'failed') {
    assert.equal(writeResumeRes.error.code, 'OPENCODE_SESSION_NOT_FOUND');
  }

  const readResumeRes = await resumeAdapter.execute({
    taskId: 'f2-read-resume',
    prompt: 'resume',
    workingDirectory: ws.repoDir,
    role: 'implementer',
    mode: 'read-only',
    session: { id: 'ses_prev' },
  });
  assert.equal(readResumeRes.status, 'failed');
  if (readResumeRes.status === 'failed') {
    assert.equal(readResumeRes.error.code, 'OPENCODE_SESSION_NOT_FOUND');
  }

  const spawnEntries = readFileSync(spawnLog, 'utf8')
    .trim()
    .split(/\r?\n/)
    .map(line => JSON.parse(line) as { argv: string[] });
  assert.equal(spawnEntries.length, 2);
  assert.ok(spawnEntries.every(entry => entry.argv[0] === 'session' && entry.argv[1] === 'list'));
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

test('n) write mode creates a file only in the copy and yields a hashed patch with provenance', async t => {
  const ws = createWorkspace(t);
  const rec = path.join(ws.root, 'record-write.json');
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'write-inside'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: 'Create created-by-opencode.txt',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);
  assert.equal(record.status, 'completed', JSON.stringify(record.error));

  const recorded = JSON.parse(readFileSync(rec, 'utf8')) as {
    argv: string[];
    cwd: string;
    env: Record<string, string>;
  };
  assert.deepEqual(recorded.argv, [
    'run', '--standalone', '--format', 'json', '--archived', '--agent', OPENCODE_WRITE_AGENT, '--model', 'opencode-go/mock-flash',
  ]);
  assert.notEqual(realpathSync(recorded.cwd), realpathSync(ws.repoDir));
  assert.equal(recorded.cwd, record.copyDirectory);
  assert.equal(recorded.env.OPENCODE_CONFIG_CONTENT, openCodeConfigContent('write'));
  assert.equal(existsSync(path.join(ws.repoDir, 'created-by-opencode.txt')), false);

  const preview = await tasks.preview(record.taskId);
  assert.deepEqual(preview.files, [{ status: 'A', path: 'created-by-opencode.txt' }]);
  assert.match(preview.sha256, /^[0-9a-f]{64}$/);
  assert.equal(typeof preview.patch, 'string');
  const patchText = preview.patch as string;
  assert.equal(preview.sha256, createHash('sha256').update(Buffer.from(patchText, 'utf8')).digest('hex'));

  assert.equal(record.execution?.provider, 'opencode');
  assert.equal(record.execution?.adapterId, 'opencode-cli');
  assert.equal(record.execution?.adapterVersion, '3');
  assert.equal(record.execution?.requested.model, 'opencode-go/mock-flash');
});

test('o) blocked outside writes and commands fail the write task, promote nothing, and leave the original intact', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'write-outside'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: 'Attempt outside write and shell',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);
  assert.equal(record.status, 'failed');
  assert.equal(record.error?.code, 'EXECUTION_INCOMPLETE');
  assert.ok(record.error?.message.includes('external_directory'));
  assert.ok(record.error?.message.includes('shell'));

  await assert.rejects(
    () => tasks.integrate(record.taskId, '0'.repeat(64), async () => true),
    err => err instanceof BridgeError && err.code === 'TASK_NOT_READY',
  );

  assert.equal(existsSync(path.join(ws.repoDir, 'partial.txt')), false);
  assert.equal(readFileSync(path.join(ws.repoDir, 'README.md'), 'utf8'), 'hello\n');
  assert.deepEqual(readdirSync(ws.repoDir).filter(name => name !== '.git'), ['README.md']);
  assert.ok(record.copyDirectory);
  for (const parentDir of [path.dirname(record.copyDirectory), path.dirname(ws.repoDir)]) {
    assert.equal(existsSync(path.join(parentDir, 'outside-target.txt')), false);
    assert.equal(existsSync(path.join(parentDir, 'outside-shell.txt')), false);
  }

  const directDir = mkdtempSync(path.join(ws.root, 'direct-write-outside-'));
  const direct = await adapter.execute({
    taskId: 'direct-write-outside',
    prompt: 'Attempt outside write and shell',
    workingDirectory: directDir,
    role: 'implementer',
    mode: 'write',
  });
  assert.equal(direct.status, 'failed');
  if (direct.status === 'failed') {
    assert.equal(direct.error.code, 'EXECUTION_INCOMPLETE');
  }
  assert.equal(existsSync(path.join(directDir, 'partial.txt')), true);
  assert.equal(existsSync(path.join(ws.repoDir, 'partial.txt')), false);
});

test('p) non-file tools such as opencode_worktree_remove are incomplete in write mode', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);

  const removeAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'worktree-remove'],
  });
  const removeTasks = ws.track(new TaskManager(cli, ws.config, removeAdapter));
  const removeQueued = await removeTasks.run({
    prompt: 'Remove worktree',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const removeRecord = await waitForTask(removeTasks, removeQueued.taskId);
  assert.equal(removeRecord.status, 'failed');
  assert.equal(removeRecord.error?.code, 'EXECUTION_INCOMPLETE');
  assert.ok(removeRecord.error?.message.includes('opencode_worktree_remove'));

  const editAdapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'write-succeeded'],
  });
  const editTasks = ws.track(new TaskManager(cli, ws.config, editAdapter));
  const editQueued = await editTasks.run({
    prompt: 'Edit in write mode',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const editRecord = await waitForTask(editTasks, editQueued.taskId);
  assert.equal(editRecord.status, 'completed', JSON.stringify(editRecord.error));
});

test('q) OpenCode configuration written by the executor is refused at preview and integration', async t => {
  const ws = createWorkspace(t);
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'write-config'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: 'Write opencode config',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);
  assert.equal(record.status, 'completed', JSON.stringify(record.error));

  await assert.rejects(
    () => tasks.preview(record.taskId),
    err => err instanceof BridgeError && err.code === 'AGENT_CONFIG_IN_PATCH',
  );
  await assert.rejects(
    () => tasks.integrate(record.taskId, '0'.repeat(64), async () => true),
    err => err instanceof BridgeError && err.code === 'AGENT_CONFIG_IN_PATCH',
  );

  assert.equal(existsSync(path.join(ws.repoDir, 'opencode.json')), false);
  assert.equal(existsSync(path.join(ws.repoDir, 'nested', 'opencode.jsonc')), false);
  assert.equal(existsSync(path.join(ws.repoDir, '.opencode')), false);
});

test('r) both modes deny reading env files while keeping templates readable', () => {
  const wildcardToRegExp = (pattern: string): RegExp => {
    const normalized = pattern.replaceAll('\\', '/');
    const escaped = normalized.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`^${escaped.replaceAll('*', '.*').replaceAll('?', '.')}$`);
  };
  const evaluatePermission = (
    rules: readonly OpenCodePermissionRule[],
    action: string,
    resource: string,
  ): 'allow' | 'deny' | 'ask' => {
    const normalizedResource = resource.replaceAll('\\', '/');
    let effect: 'allow' | 'deny' | 'ask' = 'ask';
    for (const rule of rules) {
      if (wildcardToRegExp(rule.action).test(action) && wildcardToRegExp(rule.resource).test(normalizedResource)) {
        effect = rule.effect;
      }
    }
    return effect;
  };

  const readRules = openCodeReadOnlyPermissions();
  const writeRules = openCodeWritePermissions();

  for (const rules of [readRules, writeRules]) {
    for (const deniedEnv of ['.env', 'prod.env', 'sub/.env.local', 'config/.env.production']) {
      assert.equal(evaluatePermission(rules, 'read', deniedEnv), 'deny', `Expected deny for ${deniedEnv}`);
    }
    for (const allowedRead of ['.env.example', 'sub/.env.sample', 'src/a.ts']) {
      assert.equal(evaluatePermission(rules, 'read', allowedRead), 'allow', `Expected allow for ${allowedRead}`);
    }
    assert.equal(evaluatePermission(rules, 'external_directory', '/tmp'), 'deny');
    assert.equal(evaluatePermission(rules, 'external_directory', '../outside'), 'deny');
    assert.equal(evaluatePermission(rules, 'shell', 'echo hi'), 'deny');
    assert.equal(evaluatePermission(rules, 'webfetch', 'https://example.com'), 'deny');
  }

  assert.equal(evaluatePermission(writeRules, 'edit', 'src/a.ts'), 'allow');
  assert.equal(evaluatePermission(writeRules, 'edit', 'deep/n/new.txt'), 'allow');
  assert.equal(evaluatePermission(writeRules, 'edit', '/tmp/x'), 'deny');
  assert.equal(evaluatePermission(writeRules, 'edit', 'C:/x'), 'deny');
  assert.equal(evaluatePermission(writeRules, 'edit', 'C:\\x'), 'deny');

  assert.equal(evaluatePermission(readRules, 'edit', 'src/a.ts'), 'deny');

  const writeConfig = JSON.parse(openCodeConfigContent('write')) as {
    agents: Record<string, { permissions: OpenCodePermissionRule[] }>;
  };
  assert.ok(writeConfig.agents[OPENCODE_WRITE_AGENT]);
  assert.deepEqual(writeConfig.agents[OPENCODE_WRITE_AGENT].permissions, writeRules);
  assert.equal(OPENCODE_READ_AGENT in writeConfig.agents, false);

  const readConfig = JSON.parse(openCodeConfigContent()) as {
    agents: Record<string, { permissions: OpenCodePermissionRule[] }>;
  };
  assert.deepEqual(Object.keys(readConfig.agents), [OPENCODE_READ_AGENT]);
});

test('s) write mode does not convert line endings for OpenCode', async t => {
  const ws = createWorkspace(t);
  writeFileSync(path.join(ws.repoDir, 'crlf.txt'), 'a\r\nb\r\n', 'utf8');
  execFileSync('git', ['add', 'crlf.txt'], { cwd: ws.repoDir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'add crlf file'], { cwd: ws.repoDir, stdio: 'ignore' });

  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'write-inside'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: 'Create created-by-opencode.txt',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);
  assert.equal(record.status, 'completed', JSON.stringify(record.error));

  const preview = await tasks.preview(record.taskId);
  assert.deepEqual(preview.files, [{ status: 'A', path: 'created-by-opencode.txt' }]);
  assert.equal(readFileSync(path.join(record.copyDirectory!, 'crlf.txt'), 'utf8'), 'a\r\nb\r\n');

  const events = tasks.readEvents(record.taskId, 0, 1000).events;
  assert.equal(events.some(event => event.type === 'copy.line-endings-converted'), false);
});

test('t) opt-in real OpenCode write confinement with a local scripted model', {
  skip: !process.env.BRIDGE_OPENCODE_REAL_BIN,
  timeout: 120_000,
}, async () => {
  const tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'bg-opencode-real-'));
  const FORMATTER_MARKER = path.join(tmpRoot, 'formatter-ran.txt');
  const requestBodies: string[] = [];
  let currentScript: Array<{ name: string; args: Record<string, unknown> }> = [];

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      requestBodies.push(rawBody);
      if (req.method !== 'POST' || req.url !== '/v1/chat/completions') {
        res.writeHead(404);
        res.end();
        return;
      }

      const body = JSON.parse(rawBody) as {
        model?: string;
        messages?: Array<{ role?: string }>;
        tools?: unknown[];
      };
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
        connection: 'keep-alive',
      });
      const sendChunk = (chunk: Record<string, unknown>) => {
        res.write(
          `data: ${JSON.stringify({
            id: 'chatcmpl-mock',
            object: 'chat.completion.chunk',
            created: 0,
            model: body.model ?? 'm1',
            ...chunk,
          })}\n\n`,
        );
      };

      if (!Array.isArray(body.tools) || body.tools.length === 0) {
        sendChunk({ choices: [{ index: 0, delta: { role: 'assistant', content: 'title' }, finish_reason: null }] });
        sendChunk({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
        sendChunk({ choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }

      const assistantTurns = (body.messages ?? []).filter(m => m.role === 'assistant').length;
      const step = currentScript[assistantTurns];
      if (step) {
        sendChunk({
          choices: [{
            index: 0,
            delta: {
              role: 'assistant',
              tool_calls: [{
                index: 0,
                id: `call_${assistantTurns + 1}`,
                type: 'function',
                function: { name: step.name, arguments: JSON.stringify(step.args) },
              }],
            },
            finish_reason: null,
          }],
        });
        sendChunk({ choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] });
      } else {
        sendChunk({ choices: [{ index: 0, delta: { role: 'assistant', content: 'done' }, finish_reason: null }] });
        sendChunk({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
      }
      sendChunk({ choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
      res.write('data: [DONE]\n\n');
      res.end();
    });
  });

  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');
    const port = addr.port;

    const homeDir = path.join(tmpRoot, 'home');
    const cfgDir = path.join(homeDir, 'cfg');
    const dataDir = path.join(homeDir, 'data');
    const stateDir = path.join(homeDir, 'state');
    const cacheDir = path.join(homeDir, 'cache');
    const workDir = path.join(tmpRoot, 'work');
    const outsideDir = path.join(tmpRoot, 'outside');

    mkdirSync(path.join(cfgDir, 'opencode'), { recursive: true });
    mkdirSync(dataDir, { recursive: true });
    mkdirSync(stateDir, { recursive: true });
    mkdirSync(cacheDir, { recursive: true });
    mkdirSync(workDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });

    writeFileSync(
      path.join(cfgDir, 'opencode', 'opencode.json'),
      JSON.stringify({
        formatter: {
          bgmark: {
            command: [
              process.execPath,
              '-e',
              "require('node:fs').writeFileSync(process.argv[1], 'formatted')",
              FORMATTER_MARKER,
            ],
            extensions: ['.txt'],
          },
        },
        providers: {
          bgmock: {
            package: '@ai-sdk/openai-compatible',
            settings: {
              baseURL: `http://127.0.0.1:${port}/v1`,
              apiKey: 'x',
            },
            models: {
              m1: {
                name: 'm1',
                tool_call: true,
              },
            },
          },
        },
      }),
      'utf8',
    );
    writeFileSync(path.join(workDir, 'a.txt'), 'hello\n', 'utf8');
    writeFileSync(path.join(workDir, 'prod.env'), 'ENVMARK_7Q=1\n', 'utf8');
    writeFileSync(path.join(outsideDir, 'keep.txt'), 'keep\n', 'utf8');

    const adapter = new OpenCodeExecutionAdapter({
      executable: process.env.BRIDGE_OPENCODE_REAL_BIN!,
      allowedEnvVars: ['HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME'],
      env: {
        HOME: homeDir,
        XDG_CONFIG_HOME: cfgDir,
        XDG_DATA_HOME: dataDir,
        XDG_STATE_HOME: stateDir,
        XDG_CACHE_HOME: cacheDir,
        PATH: process.env.PATH,
      },
    });

    currentScript = [
      { name: 'write', args: { path: 'inside.txt', content: 'in\n' } },
      { name: 'write', args: { path: path.join(outsideDir, 'out-abs.txt'), content: 'out\n' } },
      { name: 'write', args: { path: '../outside/out-rel.txt', content: 'out\n' } },
      { name: 'edit', args: { path: path.join(outsideDir, 'keep.txt'), oldString: 'keep', newString: 'pwned' } },
      { name: 'opencode_worktree_remove', args: { directory: outsideDir, force: true } },
      { name: 'shell', args: { command: `touch ${path.join(outsideDir, 'shell.txt')}` } },
      { name: 'read', args: { path: 'prod.env' } },
    ];
    const res1 = await adapter.execute({
      taskId: 'real-write-confinement-1',
      prompt: 'Run scripted confinement checks',
      workingDirectory: workDir,
      role: 'implementer',
      mode: 'write',
      model: 'bgmock/m1',
    });
    assert.equal(res1.status, 'failed');
    if (res1.status === 'failed') {
      assert.equal(res1.error.code, 'EXECUTION_INCOMPLETE');
      for (const expectedDetail of [
        'write: Permission denied: external_directory',
        'edit: Permission denied: external_directory',
        'opencode_worktree_remove: Permission denied: edit',
        'shell: No tool named "shell"',
        'read: Permission denied: read',
      ]) {
        assert.ok(res1.error.message.includes(expectedDetail), `Expected ${expectedDetail} in ${res1.error.message}`);
      }
      assert.equal(res1.error.message.includes('ENVMARK_7Q'), false);
    }
    assert.equal(readFileSync(path.join(workDir, 'inside.txt'), 'utf8'), 'in\n');
    assert.deepEqual(readdirSync(outsideDir), ['keep.txt']);
    assert.equal(readFileSync(path.join(outsideDir, 'keep.txt'), 'utf8'), 'keep\n');
    assert.equal(requestBodies.some(body => body.includes('ENVMARK_7Q')), false);

    currentScript = [
      { name: 'edit', args: { path: 'a.txt', oldString: 'hello', newString: 'bye' } },
    ];
    const res2 = await adapter.execute({
      taskId: 'real-write-confinement-2',
      prompt: 'Edit a.txt',
      workingDirectory: workDir,
      role: 'implementer',
      mode: 'write',
      model: 'bgmock/m1',
    });
    assert.equal(res2.status, 'completed');
    assert.equal(readFileSync(path.join(workDir, 'a.txt'), 'utf8'), 'bye\n');
    assert.equal(existsSync(FORMATTER_MARKER), false);
  } finally {
    server.closeAllConnections?.();
    await new Promise<void>(resolve => server.close(() => resolve()));
    rmSync(tmpRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
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

test('u) both modes disable OpenCode formatters and language servers', () => {
  for (const raw of [openCodeConfigContent(), openCodeConfigContent('write')]) {
    const parsed = JSON.parse(raw) as { formatter?: unknown; lsp?: unknown };
    assert.equal(parsed.formatter, false);
    assert.equal(parsed.lsp, false);
  }
});

test('v) local test repair does not convert line endings for OpenCode', async t => {
  if (!requireLinuxBwrap(t)) return;
  const ws = createWorkspace(t);
  writeFileSync(path.join(ws.repoDir, 'crlf.txt'), 'a\r\nb\r\n', 'utf8');
  execFileSync('git', ['add', 'crlf.txt'], { cwd: ws.repoDir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'add crlf file'], { cwd: ws.repoDir, stdio: 'ignore' });

  const config = loadConfig({
    BRIDGE_STATE_DIRECTORY: ws.stateDir,
    BRIDGE_TEST_EXECUTOR: 'linux-bwrap',
    AGY_PATH: process.execPath,
    DEFAULT_TIMEOUT_SECONDS: '30',
  });
  const cli = new OpenCodeTestCliAdapter(config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'write-succeeded'],
  });
  const tasks = ws.track(new TaskManager(cli, config, adapter, { linuxBwrapDetection: hostDetection }));

  const queued = await tasks.run({
    prompt: 'Edit in write mode',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const written = await waitForTask(tasks, queued.taskId);
  assert.equal(written.status, 'completed', JSON.stringify(written.error));
  assert.ok(written.copyDirectory);

  const preview = await tasks.preview(written.taskId, false);
  const tested = await tasks.startTests(
    written.taskId,
    preview.sha256,
    { executable: process.execPath, args: ['-e', 'process.exit(1)'] },
    1,
    30,
  );
  const testedResult = await waitForTask(tasks, tested.taskId);
  assert.equal(testedResult.tests?.length, 1);
  assert.equal(testedResult.tests?.[0]?.exitCode, 1);
  assert.equal(testedResult.tests?.[0]?.source, 'linux-executor');
  assert.equal(testedResult.status, 'failed');

  const testEvents = tasks.readEvents(tested.taskId, 0, 1000).events;
  assert.equal(testEvents.some(event => event.type === 'copy.line-endings-converted'), false);
  const writeEvents = tasks.readEvents(written.taskId, 0, 1000).events;
  assert.equal(writeEvents.some(event => event.type === 'copy.line-endings-converted'), false);
  assert.equal(readFileSync(path.join(written.copyDirectory, 'crlf.txt'), 'utf8'), 'a\r\nb\r\n');
});

test('w) checksum 8.3 aliases for OpenCode configuration are protected patch paths on win32 only', () => {
  for (const protectedPath of ['OP4B1F~1/plugins/x.js', 'OP4B1F~1.JSO', 'sub/op00ff~2.jso']) {
    assert.equal(isProtectedPatchPath(protectedPath, 'win32'), true, `Expected protected path on win32: ${protectedPath}`);
    assert.equal(isProtectedPatchPath(protectedPath, 'linux'), false, `Expected non-protected path on linux: ${protectedPath}`);
    assert.equal(isAgentConfigPath(protectedPath, 'win32'), false, `Expected isAgentConfigPath false: ${protectedPath}`);
  }
  assert.equal(isProtectedPatchPath('OPZZZZ~1.JSO', 'win32'), false);
});

test('x) write mode refuses non-UTF-8 text before starting OpenCode', async t => {
  const ws = createWorkspace(t);
  writeFileSync(path.join(ws.repoDir, 'latin1.txt'), Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0a]));
  execFileSync('git', ['add', 'latin1.txt'], { cwd: ws.repoDir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'add latin1 file'], { cwd: ws.repoDir, stdio: 'ignore' });

  const rec = path.join(ws.root, 'record-non-utf8.json');
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--record', rec, '--scenario', 'write-inside'],
  });
  const tasks = ws.track(new TaskManager(cli, ws.config, adapter));

  const queued = await tasks.run({
    prompt: 'Create created-by-opencode.txt',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'failed');
  assert.equal(record.error?.code, 'UNSUPPORTED_TEXT_ENCODING');
  assert.equal(existsSync(rec), false);
  assert.ok(record.copyDirectory);
  assert.equal(existsSync(path.join(record.copyDirectory, 'created-by-opencode.txt')), false);
  assert.equal(existsSync(path.join(ws.repoDir, 'created-by-opencode.txt')), false);
});
