import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { discardProjectCopy } from '../src/isolation.js';
import { compactTask } from '../src/messages.js';
import { classifyOpenCodeReadToolError, OpenCodeExecutionAdapter } from '../src/opencode-execution-adapter.js';
import { taskRecordSchema } from '../src/output-schemas.js';
import { StateStore } from '../src/state-store.js';
import { TaskManager } from '../src/task-manager.js';
import type { AcceptanceCriterion } from '../src/verification.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';
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

interface MockToolErrorEntry {
  tool: string;
  status: string;
  error?: string;
  input?: Record<string, unknown>;
  callID?: string;
  writeFile?: string;
}

function createWorkspace(t: { after(fn: () => Promise<void> | void): void }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'bg-oc-toolerr-'));
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

function createToolErrorsTasks(
  ws: ReturnType<typeof createWorkspace>,
  name: string,
  entries: readonly MockToolErrorEntry[],
): TaskManager {
  const entriesFile = path.join(ws.root, `${name}.json`);
  writeFileSync(entriesFile, JSON.stringify(entries), 'utf8');
  const cli = new OpenCodeTestCliAdapter(ws.config);
  const adapter = new OpenCodeExecutionAdapter({
    executable: process.execPath,
    prefixArgs: [MOCK_OPENCODE, '--scenario', 'tool-errors', '--tool-errors', entriesFile],
  });
  return ws.track(new TaskManager(cli, ws.config, adapter));
}

test('T1) read-only task classifies grep and read missing-path errors, emits task.tool-errors, persists, and exposes toolErrors in compactTask', async t => {
  const ws = createWorkspace(t);
  const tasks = createToolErrorsTasks(ws, 't1', [
    {
      tool: 'grep',
      status: 'error',
      input: { path: 'src/state-store.ts' },
      error: 'Search path does not exist: src/state-store.ts',
    },
    {
      tool: 'read',
      status: 'error',
      input: { path: '{cwd}/nope.ts' },
      error: 'File not found: {cwd}/nope.ts',
    },
  ]);

  const queued = await tasks.run({
    prompt: 'Inspect missing paths',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'completed', JSON.stringify(record.error));
  assert.ok(record.copyDirectory);
  assert.equal(record.toolErrors?.total, 2);
  assert.equal(record.toolErrors?.items.length, 2);
  assert.deepEqual(record.toolErrors?.items, [
    {
      toolName: 'grep',
      path: 'src/state-store.ts',
      reason: 'Search path does not exist: src/state-store.ts',
    },
    {
      toolName: 'read',
      path: `${record.copyDirectory}/nope.ts`,
      reason: `File not found: ${record.copyDirectory}/nope.ts`,
    },
  ]);

  const toolErrorEvents = tasks.readEvents(queued.taskId, 0, 1000).events.filter(e => e.type === 'task.tool-errors');
  assert.equal(toolErrorEvents.length, 1);
  assert.deepEqual(toolErrorEvents[0]?.data, record.toolErrors);

  const publicResult = tasks.result(queued.taskId).task;
  assert.deepEqual(publicResult.toolErrors, record.toolErrors);

  const compact = compactTask(record);
  assert.deepEqual(compact.toolErrors, record.toolErrors);
  assert.deepEqual(taskRecordSchema.parse(compact).toolErrors, record.toolErrors);

  const persisted = new StateStore(ws.stateDir).load().find(item => item.record.taskId === queued.taskId);
  assert.deepEqual(persisted?.record.toolErrors, record.toolErrors);
});

test('T2) read-only task classifies missing-folder read, binary read, and glob missing-path errors', async t => {
  const ws = createWorkspace(t);
  const tasks = createToolErrorsTasks(ws, 't2', [
    {
      tool: 'read',
      status: 'error',
      input: { path: 'missing/dir/file.ts' },
      error: 'File not found: missing/dir/file.ts\n\nThe folder {cwd}/missing does not exist. The nearest folder that does is {cwd}.',
    },
    {
      tool: 'read',
      status: 'error',
      input: { path: 'sub/b.dat' },
      error: 'Cannot read binary file: sub/b.dat',
    },
    {
      tool: 'glob',
      status: 'error',
      input: { path: 'nodir' },
      error: 'Search path does not exist: nodir',
    },
  ]);

  const queued = await tasks.run({
    prompt: 'Inspect missing folder, binary file, and missing glob folder',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'completed', JSON.stringify(record.error));
  assert.equal(record.toolErrors?.total, 3);
  assert.equal(record.toolErrors?.items.length, 3);
  assert.deepEqual(
    record.toolErrors?.items.map(item => ({ toolName: item.toolName, path: item.path })),
    [
      { toolName: 'read', path: 'missing/dir/file.ts' },
      { toolName: 'read', path: 'sub/b.dat' },
      { toolName: 'glob', path: 'nodir' },
    ],
  );
});

test('T3) write-mode task records toolErrors alongside completed write and allows preview and integration', async t => {
  const ws = createWorkspace(t);
  const acceptanceCriteria: AcceptanceCriterion[] = [
    { id: 'added', description: 'Create added.txt', check: { kind: 'file-exists', path: 'added.txt' } },
  ];
  const tasks = createToolErrorsTasks(ws, 't3', [
    {
      tool: 'write',
      status: 'completed',
      input: { path: 'added.txt' },
      writeFile: 'added.txt',
    },
    {
      tool: 'grep',
      status: 'error',
      input: { path: 'missing-dir' },
      error: 'Search path does not exist: missing-dir',
    },
  ]);

  const queued = await tasks.run({
    prompt: 'Add added.txt after checking missing-dir',
    workingDirectory: ws.repoDir,
    mode: 'write',
    model: 'opencode-go/mock-flash',
    acceptanceCriteria,
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'completed', JSON.stringify(record.error));
  assert.equal(record.toolErrors?.total, 1);
  assert.deepEqual(record.toolErrors?.items, [
    {
      toolName: 'grep',
      path: 'missing-dir',
      reason: 'Search path does not exist: missing-dir',
    },
  ]);

  const preview = await tasks.preview(record.taskId);
  assert.deepEqual(preview.files, [{ status: 'A', path: 'added.txt' }]);

  const verification = await tasks.verify(record.taskId, preview.sha256, [
    {
      criterionId: 'added',
      verdict: 'passed',
      path: 'added.txt',
      line: 1,
      quote: 'x',
      explanation: 'Verified added.txt content',
    },
  ]);
  assert.equal(verification.status, 'passed');

  await tasks.integrate(record.taskId, preview.sha256, async () => true);
  assert.equal(readFileSync(path.join(ws.repoDir, 'added.txt'), 'utf8'), 'x');
});

test('T4) permission denials, outside paths, write-tool errors, disallowed tools, and unclassified errors remain EXECUTION_INCOMPLETE', async t => {
  const ws = createWorkspace(t);

  const cases: Array<{
    name: string;
    mode: 'read-only' | 'write';
    entries: MockToolErrorEntry[];
    expectedMessage?: string;
  }> = [
    {
      name: 'read-env-denied',
      mode: 'read-only',
      entries: [{ tool: 'read', status: 'error', input: { path: '.env' }, error: 'Permission denied: read' }],
    },
    {
      name: 'read-external-directory',
      mode: 'read-only',
      entries: [{ tool: 'read', status: 'error', input: { path: '../x' }, error: 'Permission denied: external_directory' }],
    },
    {
      name: 'read-missing-absolute-outside',
      mode: 'read-only',
      entries: [
        {
          tool: 'read',
          status: 'error',
          input: { path: '/definitely/outside/nope.ts' },
          error: 'File not found: /definitely/outside/nope.ts',
        },
      ],
    },
    {
      name: 'read-missing-relative-outside',
      mode: 'read-only',
      entries: [{ tool: 'read', status: 'error', input: { path: '../nope.ts' }, error: 'File not found: ../nope.ts' }],
    },
    {
      name: 'read-missing-multiline-with-permission',
      mode: 'read-only',
      entries: [
        {
          tool: 'read',
          status: 'error',
          input: { path: '{cwd}/a.ts' },
          error: 'File not found: {cwd}/a.ts\nPermission denied: read',
        },
      ],
    },
    {
      name: 'grep-invalid-regex',
      mode: 'read-only',
      entries: [
        {
          tool: 'grep',
          status: 'error',
          input: { pattern: '(' },
          error: 'Invalid regex pattern: rg: regex parse error:\n (',
        },
      ],
    },
    {
      name: 'write-mode-edit-missing-file',
      mode: 'write',
      entries: [{ tool: 'edit', status: 'error', input: { path: '{cwd}/nope.ts' }, error: 'File not found: {cwd}/nope.ts' }],
    },
    {
      name: 'write-mode-unable-to-write',
      mode: 'write',
      entries: [{ tool: 'write', status: 'error', input: { path: '{cwd}/sub' }, error: 'Unable to write {cwd}/sub' }],
    },
    {
      name: 'disallowed-skill-tool',
      mode: 'read-only',
      entries: [{ tool: 'skill', status: 'error', input: { name: 'nope' }, error: 'Unable to load skill nope' }],
    },
    {
      name: 'classified-grep-plus-external-directory',
      mode: 'read-only',
      entries: [
        { tool: 'grep', status: 'error', input: { path: 'missing.ts' }, error: 'Search path does not exist: missing.ts' },
        { tool: 'read', status: 'error', input: { path: '../x' }, error: 'Permission denied: external_directory' },
      ],
      expectedMessage: 'external_directory',
    },
    {
      name: 'read-inside-msg-outside-input',
      mode: 'read-only',
      entries: [{ tool: 'read', status: 'error', input: { path: '../outside.ts' }, error: 'File not found: {cwd}/inside.ts' }],
    },
  ];

  for (const item of cases) {
    const tasks = createToolErrorsTasks(ws, `t4-${item.name}`, item.entries);
    const queued = await tasks.run({
      prompt: `Run ${item.name}`,
      workingDirectory: ws.repoDir,
      mode: item.mode,
      model: 'opencode-go/mock-flash',
    });
    const record = await waitForTask(tasks, queued.taskId);
    assert.equal(record.status, 'failed', `${item.name}: expected failed`);
    assert.equal(record.error?.code, 'EXECUTION_INCOMPLETE', `${item.name}: expected EXECUTION_INCOMPLETE`);
    assert.equal(record.toolErrors, undefined, `${item.name}: expected no toolErrors`);
    if (item.expectedMessage) {
      assert.ok(
        record.error?.message.includes(item.expectedMessage),
        `${item.name}: expected message to include ${item.expectedMessage}, got ${record.error?.message}`,
      );
    }
    const toolErrorEvents = tasks.readEvents(queued.taskId, 0, 1000).events.filter(e => e.type === 'task.tool-errors');
    assert.equal(toolErrorEvents.length, 0, `${item.name}: expected no task.tool-errors event`);
  }
});

test('T5) 60 distinct classified grep errors complete with total 60 and 50 items', async t => {
  const ws = createWorkspace(t);
  const entries: MockToolErrorEntry[] = Array.from({ length: 60 }, (_, idx) => ({
    tool: 'grep',
    status: 'error',
    input: { path: `missing-${idx}.ts` },
    error: `Search path does not exist: missing-${idx}.ts`,
  }));
  const tasks = createToolErrorsTasks(ws, 't5', entries);

  const queued = await tasks.run({
    prompt: 'Trigger 60 grep missing path errors',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const record = await waitForTask(tasks, queued.taskId);

  assert.equal(record.status, 'completed', JSON.stringify(record.error));
  assert.equal(record.toolErrors?.total, 60);
  assert.equal(record.toolErrors?.items.length, 50);
  assert.equal(record.toolErrors?.items[0]?.path, 'missing-0.ts');
  assert.equal(record.toolErrors?.items[49]?.path, 'missing-49.ts');
});

test('T6) classifyOpenCodeReadToolError unit edge cases', t => {
  const ws = createWorkspace(t);
  const cwd = ws.repoDir;

  // Control characters in P, D, N are rejected.
  for (const badChar of ['\x00', '\t', '\n', '\r', '\x7f', '\u0085', '\u2028', '\u2029']) {
    assert.equal(
      classifyOpenCodeReadToolError('read', `File not found: a${badChar}b.ts`, { path: 'a.ts' }, cwd),
      undefined,
    );
    assert.equal(
      classifyOpenCodeReadToolError(
        'read',
        `File not found: a/b.ts\n\nThe folder a${badChar} does not exist. The nearest folder that does is .`,
        { path: 'a/b.ts' },
        cwd,
      ),
      undefined,
    );
    assert.equal(
      classifyOpenCodeReadToolError(
        'read',
        `File not found: a/b.ts\n\nThe folder a does not exist. The nearest folder that does is .${badChar}`,
        { path: 'a/b.ts' },
        cwd,
      ),
      undefined,
    );
  }

  // Non-read/search tools are rejected.
  assert.equal(classifyOpenCodeReadToolError('edit', 'File not found: nope.ts', { path: 'nope.ts' }, cwd), undefined);
  assert.equal(classifyOpenCodeReadToolError('write', 'File not found: nope.ts', { path: 'nope.ts' }, cwd), undefined);

  // Trailing text is rejected.
  assert.equal(
    classifyOpenCodeReadToolError('read', 'File not found: nope.ts\nextra', { path: 'nope.ts' }, cwd),
    undefined,
  );
  assert.equal(
    classifyOpenCodeReadToolError(
      'read',
      'File not found: a/b.ts\n\nThe folder a does not exist. The nearest folder that does is . trailing',
      { path: 'a/b.ts' },
      cwd,
    ),
    undefined,
  );

  // Relative escapes are rejected.
  for (const escape of ['../nope.ts', 'sub/../../nope.ts', '..']) {
    assert.equal(
      classifyOpenCodeReadToolError('grep', `Search path does not exist: ${escape}`, { path: 'ok.ts' }, cwd),
      undefined,
    );
  }

  // input.filePath or input.path outside the working directory is rejected.
  assert.equal(
    classifyOpenCodeReadToolError('read', 'File not found: inside.ts', { filePath: '../outside.ts' }, cwd),
    undefined,
  );
  assert.equal(
    classifyOpenCodeReadToolError('read', 'File not found: inside.ts', { filePath: '/definitely/outside/nope.ts' }, cwd),
    undefined,
  );
  assert.equal(
    classifyOpenCodeReadToolError('read', 'File not found: inside.ts', { path: '../outside.ts' }, cwd),
    undefined,
  );

  // Mismatched tool/message pairs are rejected.
  assert.equal(
    classifyOpenCodeReadToolError('read', 'Search path does not exist: inside.ts', { path: 'inside.ts' }, cwd),
    undefined,
  );
  assert.equal(
    classifyOpenCodeReadToolError('grep', 'File not found: inside.ts', { path: 'inside.ts' }, cwd),
    undefined,
  );

  // Valid inside-copy inputs classify and bound path/reason lengths.
  const valid = classifyOpenCodeReadToolError(
    'read',
    'File not found: src/..foo.ts',
    { filePath: 'src/..foo.ts' },
    cwd,
  );
  assert.deepEqual(valid, {
    toolName: 'read',
    path: 'src/..foo.ts',
    reason: 'File not found: src/..foo.ts',
  });

  const longRel = 'a'.repeat(1100);
  const bounded = classifyOpenCodeReadToolError(
    'grep',
    `Search path does not exist: ${longRel}`,
    { path: longRel },
    cwd,
  );
  assert.equal(bounded?.path?.length, 1000);
  assert.equal(bounded?.reason.length, 500);

  // Two-paragraph missing-folder read errors require D and N inside or equal to cwd.
  assert.equal(
    classifyOpenCodeReadToolError(
      'read',
      `File not found: nodir/x.ts\n\nThe folder /etc/nodir does not exist. The nearest folder that does is ${cwd}.`,
      { path: 'nodir/x.ts' },
      cwd,
    ),
    undefined,
  );
  assert.equal(
    classifyOpenCodeReadToolError(
      'read',
      `File not found: nodir/x.ts\n\nThe folder ${cwd}/nodir does not exist. The nearest folder that does is /etc.`,
      { path: 'nodir/x.ts' },
      cwd,
    ),
    undefined,
  );
  const realisticMissingDir = `File not found: nodir/x.ts\n\nThe folder ${cwd}/nodir does not exist. The nearest folder that does is ${cwd}.`;
  assert.deepEqual(
    classifyOpenCodeReadToolError(
      'read',
      realisticMissingDir,
      { path: 'nodir/x.ts' },
      cwd,
    ),
    {
      toolName: 'read',
      path: 'nodir/x.ts',
      reason: realisticMissingDir,
    },
  );
});

test('T7) duplicate callID is counted once and later unclassified event for the same callID still fails', async t => {
  const ws = createWorkspace(t);

  const dupTasks = createToolErrorsTasks(ws, 't7-dup', [
    {
      callID: 'dup_1',
      tool: 'grep',
      status: 'error',
      input: { path: 'missing.ts' },
      error: 'Search path does not exist: missing.ts',
    },
    {
      callID: 'dup_1',
      tool: 'grep',
      status: 'error',
      input: { path: 'missing.ts' },
      error: 'Search path does not exist: missing.ts',
    },
  ]);
  const dupQueued = await dupTasks.run({
    prompt: 'Duplicate callID classified error',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const dupRecord = await waitForTask(dupTasks, dupQueued.taskId);
  assert.equal(dupRecord.status, 'completed', JSON.stringify(dupRecord.error));
  assert.equal(dupRecord.toolErrors?.total, 1);
  assert.equal(dupRecord.toolErrors?.items.length, 1);

  const mixedTasks = createToolErrorsTasks(ws, 't7-mixed', [
    {
      callID: 'mixed_1',
      tool: 'grep',
      status: 'error',
      input: { path: 'missing.ts' },
      error: 'Search path does not exist: missing.ts',
    },
    {
      callID: 'mixed_1',
      tool: 'read',
      status: 'error',
      input: { path: '.env' },
      error: 'Permission denied: read',
    },
  ]);
  const mixedQueued = await mixedTasks.run({
    prompt: 'Classified then unclassified on same callID',
    workingDirectory: ws.repoDir,
    mode: 'read-only',
    model: 'opencode-go/mock-flash',
  });
  const mixedRecord = await waitForTask(mixedTasks, mixedQueued.taskId);
  assert.equal(mixedRecord.status, 'failed');
  assert.equal(mixedRecord.error?.code, 'EXECUTION_INCOMPLETE');
  assert.equal(mixedRecord.toolErrors, undefined);
});
