import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CliAdapter } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { BUNDLED_CRAFT_MANIFEST_SHA256 } from '../src/craft-pin.js';
import { craftStatus, assertPermanentDelivery, PERMANENT_SKILLS } from '../src/craft.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError, type TaskRecord } from '../src/types.js';

const mock = fileURLToPath(new URL('../../tests/mock-agy.mjs', import.meta.url));
const packaged = fileURLToPath(new URL('../../plugin/anti-ai-craft', import.meta.url));
const directories: string[] = [];
after(async () => { for (const directory of directories) await rm(directory, { recursive: true, force: true }); });

async function setup(env: Record<string, string> = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-runtime-'));
  directories.push(root);
  const source = path.join(root, 'source');
  execFileSync('git', ['init', '--quiet', source]);
  await writeFile(path.join(source, 'source.txt'), 'source content\n');
  const state = path.join(root, 'state');
  const config = loadConfig({ AGY_PATH: process.execPath, BRIDGE_TEST_EXECUTOR: 'agy', BRIDGE_STATE_DIRECTORY: state, ...env });
  const adapter = new CliAdapter(config, [mock]);
  await adapter.discover();
  return { root, source, state, config, tasks: new TaskManager(adapter, config) };
}

async function finished(tasks: TaskManager, taskId: string, timeout = 20000): Promise<TaskRecord> {
  const deadline = Date.now() + timeout;
  let record = tasks.status(taskId);
  while (!['completed', 'failed', 'cancelled', 'timeout'].includes(record.status) && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 50));
    record = tasks.status(taskId);
  }
  return record;
}

// A minimal snapshot with the two permanent skills and one situational skill.
async function syntheticSnapshot(root: string) {
  const directory = path.join(root, 'craft');
  const files: Record<string, string> = {
    'skills/anti-ai-code/SKILL.md': '---\nname: anti-ai-code\ndescription: Code rules.\n---\nCODE_BODY\n',
    'skills/anti-ai-code/references/notes.md': 'CODE_REFERENCE\n',
    'skills/anti-ai-security/SKILL.md': '---\nname: anti-ai-security\ndescription: Security rules.\n---\nSECURITY_BODY\n',
    'skills/anti-ai-design/SKILL.md': '---\nname: anti-ai-design\ndescription: Interface design guidance.\n---\nDESIGN_BODY_NOT_IN_PROMPT\n',
  };
  for (const [relative, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(directory, relative)), { recursive: true });
    await writeFile(path.join(directory, relative), content);
  }
  await writeFile(path.join(directory, 'manifest.json'), JSON.stringify({ schemaVersion: 1, origin: 'https://github.com/Zythenth/anti-ai-craft', revision: 'c'.repeat(40), version: '0.0.1',
    skills: ['anti-ai-code', 'anti-ai-security', 'anti-ai-design'],
    files: Object.entries(files).map(([relative, content]) => ({ path: relative, bytes: Buffer.byteLength(content), sha256: createHash('sha256').update(content).digest('hex'), mediaType: 'text/markdown' })) }));
  return directory;
}

test('new sessions receive the two permanent skills and a catalog without situational bodies', async () => {
  const { source, state, tasks } = await setup();
  try {
    const started = await tasks.run({ prompt: 'read:craft', workingDirectory: source, mode: 'read-only' });
    const record = await finished(tasks, started.taskId);
    assert.equal(record.status, 'completed', JSON.stringify(record.error));
    const manifest = JSON.parse(await readFile(path.join(packaged, 'manifest.json'), 'utf8'));
    assert.deepEqual(record.craft, { revision: manifest.revision, manifestSha256: record.craft!.manifestSha256, permanent: ['anti-ai-code', 'anti-ai-security'],
      catalog: ['anti-ai-audit', 'anti-ai-design', 'anti-ai-design-flow', 'anti-ai-remediate'] });
    assert.deepEqual(record.providedSkills?.map(skill => skill.name), ['anti-ai-code', 'anti-ai-security']);
    assert.ok(existsSync(path.join(record.copyDirectory!, '.agents', 'skills', 'anti-ai-security', 'SKILL.md')));
    const prompt = (record.result as { response: string }).response;
    assert.match(prompt, /<anti-ai-craft revision="[a-f0-9]{40}">/);
    const designBody = await readFile(path.join(packaged, 'skills', 'anti-ai-design', 'SKILL.md'), 'utf8');
    assert.equal(prompt.includes(designBody.split('\n').find(line => line.startsWith('## '))!), false);
    const args = (tasks.readEvents(started.taskId).events.find(event => event.type === 'agent.started')!.data as { args: string[] }).args;
    const cache = args[args.lastIndexOf('--add-dir') + 1]!;
    assert.ok(cache.startsWith(path.join(state, 'anti-ai-craft')));
    assert.ok(existsSync(path.join(cache, 'anti-ai-design', 'references', 'visual-library', 'images')));
  } finally {
    await tasks.shutdown();
  }
});

test('opt-out, conflicting names and a tampered snapshot are explicit', async () => {
  const off = await setup({ BRIDGE_ANTI_AI_CRAFT: 'off' });
  try {
    const started = await off.tasks.run({ prompt: 'read:off', workingDirectory: off.source, mode: 'read-only' });
    const record = await finished(off.tasks, started.taskId);
    assert.equal(record.status, 'completed', JSON.stringify(record.error));
    assert.notEqual(record.craft, undefined);
    assert.deepEqual(record.craft?.permanent, ['anti-ai-code', 'anti-ai-security']);
    assert.ok(record.providedSkills?.some(skill => skill.name === 'anti-ai-code'));
    assert.ok(record.providedSkills?.some(skill => skill.name === 'anti-ai-security'));
    assert.equal(off.config.antiAiCraftOptOutRequested, true);
    assert.ok(off.config.configurationIssues.some(issue => issue.variable === 'BRIDGE_ANTI_AI_CRAFT' && issue.reason === 'opt-out-unsupported'));
  } finally {
    await off.tasks.shutdown();
  }
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-synthetic-'));
  directories.push(scratch);
  const snapshot = await syntheticSnapshot(scratch);
  const custom = await setup({ BRIDGE_ANTI_AI_CRAFT_DIRECTORY: snapshot });
  try {
    const started = await custom.tasks.run({ prompt: 'read:custom', workingDirectory: custom.source, mode: 'read-only',
      skills: [{ name: 'anti-ai-code', content: '---\nname: anti-ai-code\ndescription: Code rules.\n---\nCODE_BODY\n', resources: [{ path: 'references/notes.md', content: 'CODE_REFERENCE\n' }] }] });
    const record = await finished(custom.tasks, started.taskId);
    assert.deepEqual(record.providedSkills?.map(skill => skill.name), ['anti-ai-code', 'anti-ai-security']);
    assert.equal((record.result as { response: string }).response.includes('DESIGN_BODY_NOT_IN_PROMPT'), false);
    await assert.rejects(custom.tasks.run({ prompt: 'read:conflict', workingDirectory: custom.source, mode: 'read-only', skills: [{ name: 'anti-ai-security', content: 'different' }] }),
      (error: unknown) => error instanceof BridgeError && error.code === 'SKILL_CONFLICT');
    await writeFile(path.join(snapshot, 'skills', 'anti-ai-design', 'SKILL.md'), 'tampered');
    await assert.rejects(custom.tasks.run({ prompt: 'read:tampered', workingDirectory: custom.source, mode: 'read-only' }),
      (error: unknown) => error instanceof BridgeError && error.code === 'CRAFT_SNAPSHOT_INVALID');
  } finally {
    await custom.tasks.shutdown();
  }
});

test('the private cache must be a real directory and is verified before every execution', async () => {
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-synthetic-'));
  directories.push(scratch);
  const snapshot = await syntheticSnapshot(scratch);
  const custom = await setup({ BRIDGE_ANTI_AI_CRAFT_DIRECTORY: snapshot });
  let cacheName: string | undefined;
  try {
    const started = await custom.tasks.run({ prompt: 'read:initial', workingDirectory: custom.source, mode: 'read-only' });
    const record = await finished(custom.tasks, started.taskId);
    assert.equal(record.status, 'completed', JSON.stringify(record.error));
    const cacheParent = path.join(custom.state, 'anti-ai-craft');
    const entries = await readdir(cacheParent);
    cacheName = entries.find(name => !name.startsWith('.'));
    assert.ok(cacheName);
    const cacheDir = path.join(cacheParent, cacheName);
    await writeFile(path.join(cacheDir, 'skills', 'anti-ai-design', 'SKILL.md'), 'tampered');
    // The refusal may surface from run itself or as the failed resumed task.
    const outcome = await custom.tasks.run({ sessionId: record.sessionId, workingDirectory: custom.source, mode: 'read-only', prompt: 'read:resumed' }).then(
      async resumed => { const failed = await finished(custom.tasks, resumed.taskId); return failed.status + ':' + failed.error?.code; },
      (error: unknown) => 'rejected:' + (error instanceof BridgeError ? error.code : String(error)));
    assert.match(outcome, /^(failed|rejected):CRAFT_SNAPSHOT_INVALID$/);
  } finally {
    await custom.tasks.shutdown();
  }

  assert.ok(cacheName);
  const second = await setup({ BRIDGE_ANTI_AI_CRAFT_DIRECTORY: snapshot });
  try {
    const secondCacheParent = path.join(second.state, 'anti-ai-craft');
    await mkdir(secondCacheParent, { recursive: true });
    await symlink(snapshot, path.join(secondCacheParent, cacheName), process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(
      second.tasks.run({ prompt: 'read:redirected', workingDirectory: second.source, mode: 'read-only' }),
      (error: unknown) => error instanceof BridgeError && error.code === 'CRAFT_SNAPSHOT_INVALID',
    );
    assert.ok(existsSync(path.join(snapshot, 'manifest.json')));
    assert.ok(existsSync(path.join(snapshot, 'skills', 'anti-ai-code', 'SKILL.md')));
    assert.ok(existsSync(path.join(snapshot, 'skills', 'anti-ai-security', 'SKILL.md')));
    assert.ok(existsSync(path.join(snapshot, 'skills', 'anti-ai-design', 'SKILL.md')));
  } finally {
    await second.tasks.shutdown();
  }
});

test('Windows test tasks keep the Anti-AI Craft selection of their source task', { skip: process.platform !== 'win32' }, async () => {
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-synthetic-'));
  directories.push(scratch);
  const snapshot = await syntheticSnapshot(scratch);
  const { source, tasks } = await setup({ BRIDGE_ANTI_AI_CRAFT_DIRECTORY: snapshot, BRIDGE_TEST_EXECUTOR: 'windows-lpac' });
  try {
    const task = await tasks.run({
      prompt: 'write:craft',
      workingDirectory: source,
      mode: 'write',
      acceptanceCriteria: [{
        id: 'craft-test',
        description: 'BLACK_GRAVITY_TEST.md contains successful.',
        check: { kind: 'file-contains', path: 'BLACK_GRAVITY_TEST.md', text: 'successful.' },
      }],
    });
    const record = await finished(tasks, task.taskId);
    assert.equal(record.status, 'completed', JSON.stringify(record.error));
    const preview = await tasks.preview(task.taskId);
    const tested = await tasks.startTests(task.taskId, preview.sha256, { executable: process.execPath, args: ['-e', 'process.exit(0)'] }, 0, 120);
    assert.deepEqual(tasks.status(tested.taskId).craft, tasks.status(task.taskId).craft);
    assert.notEqual(tasks.status(tested.taskId).craft, undefined);
    const testRecord = await finished(tasks, tested.taskId, 180000);
    assert.equal(testRecord.status, 'completed', JSON.stringify(testRecord.error));
  } finally {
    await tasks.shutdown();
  }
});

test('craftStatus reports off, bundled ready, and tampered override without creating state', async () => {
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-status-'));
  directories.push(scratch);
  const untouchedState = path.join(scratch, 'untouched-state');
  const direct = await craftStatus(loadConfig({ BRIDGE_STATE_DIRECTORY: untouchedState }));
  assert.equal(existsSync(untouchedState), false);
  if (!direct.enabled) assert.fail('expected craftStatus to be enabled for default config');
  assert.equal(direct.source, 'bundled');
  assert.equal(direct.ready, true);

  const off = await setup({ BRIDGE_ANTI_AI_CRAFT: 'off' });
  try {
    const status = await off.tasks.antiAiCraftStatus();
    assert.equal(status.enabled, true);
    assert.equal(status.ready, true);
    assert.equal(status.optOutRejected, true);
    assert.equal(
      status.migration,
      'BRIDGE_ANTI_AI_CRAFT=off is no longer supported; anti-ai-code and anti-ai-security always load in every implementer and reviewer session. Remove the variable.',
    );
    assert.equal(existsSync(path.join(off.state, 'anti-ai-craft')), false);
  } finally {
    await off.tasks.shutdown();
  }

  const def = await setup();
  try {
    const status = await def.tasks.antiAiCraftStatus();
    if (!status.enabled) assert.fail('expected antiAiCraftStatus to be enabled');
    const manifest = JSON.parse(await readFile(path.join(packaged, 'manifest.json'), 'utf8'));
    assert.equal(status.source, 'bundled');
    assert.equal(status.ready, true);
    assert.equal(status.revision, '201fec54431bdf7e4c8bb3660100601b41b97b08');
    assert.equal(status.manifestSha256, BUNDLED_CRAFT_MANIFEST_SHA256);
    assert.equal(status.expectedManifestSha256, BUNDLED_CRAFT_MANIFEST_SHA256);
    assert.equal(status.skills?.length, 6);
    assert.deepEqual(status.skills, manifest.skills);
    assert.equal(status.files, manifest.files.length);
    assert.deepEqual(status.permanent, PERMANENT_SKILLS);
    assert.equal(existsSync(path.join(def.state, 'anti-ai-craft')), false);
  } finally {
    await def.tasks.shutdown();
  }

  const snapshot = await syntheticSnapshot(scratch);
  await writeFile(path.join(snapshot, 'skills', 'anti-ai-design', 'SKILL.md'), 'tampered');
  const tampered = await setup({ BRIDGE_ANTI_AI_CRAFT_DIRECTORY: snapshot });
  try {
    const status = await tampered.tasks.antiAiCraftStatus();
    if (!status.enabled) assert.fail('expected antiAiCraftStatus to be enabled for tampered override');
    assert.equal(status.source, 'override');
    assert.equal(status.ready, false);
    assert.equal(status.expectedManifestSha256, undefined);
    assert.equal(status.error?.code, 'CRAFT_SNAPSHOT_INVALID');
    assert.equal(status.error?.message, 'The Anti-AI Craft snapshot failed verification; reinstall this bridge version or fix BRIDGE_ANTI_AI_CRAFT_DIRECTORY');
    assert.equal(status.error?.message.includes('skills/'), false);
    assert.equal(status.error?.message.includes(snapshot), false);
    assert.equal(existsSync(path.join(tampered.state, 'anti-ai-craft')), false);
  } finally {
    await tampered.tasks.shutdown();
  }

  const malformed = path.join(scratch, 'malformed-craft');
  await mkdir(malformed, { recursive: true });
  await writeFile(path.join(malformed, 'manifest.json'), '{ "/secret/private/path": ');
  const malformedStatus = await craftStatus(loadConfig({ BRIDGE_ANTI_AI_CRAFT_DIRECTORY: malformed }));
  if (!malformedStatus.enabled) assert.fail('expected craftStatus to be enabled for malformed override');
  assert.equal(malformedStatus.source, 'override');
  assert.equal(malformedStatus.ready, false);
  assert.equal(malformedStatus.error?.code, 'CRAFT_SNAPSHOT_INVALID');
  assert.equal(malformedStatus.error?.message, 'The Anti-AI Craft snapshot failed verification; reinstall this bridge version or fix BRIDGE_ANTI_AI_CRAFT_DIRECTORY');
  assert.equal(malformedStatus.error?.message.includes('/secret/private/path'), false);
});

test('assertPermanentDelivery enforces snapshot and both permanent skills', () => {
  const selection = {
    revision: 'a'.repeat(40),
    manifestSha256: 'b'.repeat(64),
    root: '/unused/craft/root',
    permanent: [...PERMANENT_SKILLS],
    catalog: [],
  };
  assert.throws(
    () => assertPermanentDelivery(undefined, [{ name: 'anti-ai-code' }, { name: 'anti-ai-security' }]),
    (err: unknown) => err instanceof BridgeError && err.code === 'CRAFT_REQUIRED',
  );
  assert.throws(
    () => assertPermanentDelivery({ ...selection, permanent: ['anti-ai-code'] }, [{ name: 'anti-ai-code' }, { name: 'anti-ai-security' }]),
    (err: unknown) => err instanceof BridgeError && err.code === 'CRAFT_REQUIRED' && err.message.includes('anti-ai-security') && !err.message.includes('/unused/craft/root'),
  );
  assert.throws(
    () => assertPermanentDelivery(selection, [{ name: 'anti-ai-code' }]),
    (err: unknown) => err instanceof BridgeError && err.code === 'CRAFT_REQUIRED' && err.message.includes('anti-ai-security') && !err.message.includes('/unused/craft/root'),
  );
  assert.throws(
    () => assertPermanentDelivery(selection, undefined),
    (err: unknown) => err instanceof BridgeError && err.code === 'CRAFT_REQUIRED' && err.message.includes('anti-ai-code') && err.message.includes('anti-ai-security'),
  );
  assert.doesNotThrow(() => assertPermanentDelivery(selection, [{ name: 'Anti-AI-Code' }, { name: 'ANTI-AI-SECURITY' }]));
});

test('reviewer and implementer sessions record craftLoad delivery evidence without inventing reads', async () => {
  const { source, tasks } = await setup();
  try {
    // Reviewer structured report fixture checks line 1 === 'source'
    await writeFile(path.join(source, 'source.txt'), 'source');
    for (const [role, mode, prompt] of [
      ['reviewer', 'read-only', 'review:craft-load'],
      ['implementer', 'write', 'write:craft-load'],
    ] as const) {
      const started = await tasks.run({ prompt, workingDirectory: source, role, mode });
      const record = await finished(tasks, started.taskId);
      assert.equal(record.status, 'completed', JSON.stringify(record.error));
      assert.ok(record.craftLoad);
      assert.equal(record.craftLoad.initListing, 'not-exposed');
      assert.equal(record.craftLoad.listed, undefined);
      const expectedDelivered = PERMANENT_SKILLS.map(name => {
        const staged = record.providedSkills?.find(skill => skill.name === name);
        assert.ok(staged, `expected staged permanent skill ${name}`);
        return { name: staged.name, sha256: staged.sha256 };
      });
      assert.deepEqual(record.craftLoad.delivered, expectedDelivered);
    }
  } finally {
    await tasks.shutdown();
  }
});

test('craftLoad records initListing listed when CLI init exposes skills', async () => {
  const { source, tasks } = await setup();
  try {
    const started = await tasks.run({ prompt: 'init-skills:craft', workingDirectory: source, mode: 'read-only' });
    const record = await finished(tasks, started.taskId);
    assert.equal(record.status, 'completed', JSON.stringify(record.error));
    assert.ok(record.craftLoad);
    assert.equal(record.craftLoad.initListing, 'listed');
    assert.deepEqual(record.craftLoad.listed, ['anti-ai-code', 'anti-ai-security']);
    assert.deepEqual(
      record.craftLoad.delivered,
      PERMANENT_SKILLS.map(name => {
        const staged = record.providedSkills!.find(skill => skill.name === name)!;
        return { name: staged.name, sha256: staged.sha256 };
      }),
    );
  } finally {
    await tasks.shutdown();
  }
});

test('resume of a legacy session without persisted craft is refused with CRAFT_REQUIRED before starting a process', async () => {
  const { source, state, config, tasks } = await setup();
  let recovered: TaskManager | undefined;
  try {
    const started = await tasks.run({ prompt: 'read:legacy', workingDirectory: source, mode: 'read-only' });
    const record = await finished(tasks, started.taskId);
    assert.equal(record.status, 'completed', JSON.stringify(record.error));
    await tasks.shutdown();

    const snapshotPath = path.join(state, `${record.taskId}.json`);
    const snapshot = JSON.parse(await readFile(snapshotPath, 'utf8'));
    delete snapshot.options.craft;
    delete snapshot.record.craft;
    await writeFile(snapshotPath, JSON.stringify(snapshot));

    const adapter = new CliAdapter(config, [mock]);
    await adapter.discover();
    recovered = new TaskManager(adapter, config);
    await assert.rejects(
      recovered.run({ prompt: 'read:resumed', workingDirectory: source, sessionId: record.sessionId, mode: 'read-only' }),
      (err: unknown) => err instanceof BridgeError && err.code === 'CRAFT_REQUIRED',
    );
    assert.equal(recovered.list().length, 1);
  } finally {
    await recovered?.shutdown();
    await tasks.shutdown();
  }
});
