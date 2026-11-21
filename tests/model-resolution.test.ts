import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AGY_ADAPTER_VERSION } from '../src/agy-execution-adapter.js';
import { buildAgyCapabilityRecord, type CliCapabilityRecord } from '../src/capability-registry.js';
import type { Model } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import { createMcpServer } from '../src/mcp-server.js';
import {
  classifyInitModel,
  evaluateModelProof,
  IDENTITY_STATUSES,
  MODEL_ALIASES,
  RESOLUTION_STATUSES,
  resolveModelAlias,
} from '../src/model-resolution.js';
import { outputSchemas, successOutputSchemas } from '../src/output-schemas.js';
import { TaskManager } from '../src/task-manager.js';
import { BridgeError } from '../src/types.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';

const REAL_MODELS: readonly Model[] = [
  { id: 'gemini-3.8-flash-low', name: 'Gemini 3.8 Flash (Low)' },
  { id: 'gemini-3.8-flash-medium', name: 'Gemini 3.8 Flash (Medium)' },
  { id: 'gemini-3.8-flash-high', name: 'Gemini 3.8 Flash (High)' },
  { id: 'gemini-4-argon-low', name: 'Gemini 4 Argon (Low)' },
  { id: 'gemini-4-argon-medium', name: 'Gemini 4 Argon (Medium)' },
  { id: 'gemini-4-argon-high', name: 'Gemini 4 Argon (High)' },
  { id: 'gemini-4-hydrogen-low', name: 'Gemini 4 Hydrogen (Low)' },
  { id: 'gemini-4-hydrogen-medium', name: 'Gemini 4 Hydrogen (Medium)' },
  { id: 'gemini-4-hydrogen-high', name: 'Gemini 4 Hydrogen (High)' },
  { id: 'gemini-4-hydrogen-xhigh', name: 'Gemini 4 Hydrogen (XHigh)' },
  { id: 'gemini-4-neon-low', name: 'Gemini 4 Neon (Low)' },
  { id: 'gemini-4-neon-medium', name: 'Gemini 4 Neon (Medium)' },
  { id: 'gemini-4-neon-high', name: 'Gemini 4 Neon (High)' },
  { id: 'gemini-4-neon-xhigh', name: 'Gemini 4 Neon (XHigh)' },
  { id: 'gemini-pro-orchestrator-g1-pro', name: 'Orchestrator (Argon)' },
  { id: 'gemini-pro-orchestrator-neon', name: 'Orchestrator (Neon)' },
  { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6' },
  { id: 'gpt-oss-120b-medium', name: 'GPT-OSS 120B (Medium)' },
];

const CLI_1513 = { installed: true, version: '1.5.13' } as const;

class ControlledResolveCliAdapter extends ControlledCliAdapter {
  nextCapabilityRecord?: CliCapabilityRecord;
  nextModels: Model[] = [...REAL_MODELS];
  nextListError?: unknown;

  override async capabilityRecord(identity: { id: string; version: string }): Promise<CliCapabilityRecord> {
    if (this.nextCapabilityRecord) return this.nextCapabilityRecord;
    return buildAgyCapabilityRecord({
      installed: true,
      version: '1.5.13',
      helpText: '--input-format stream-json\n--output-format stream-json\n--model\n--effort\n--sandbox\nmodels',
      platform: process.platform,
      arch: process.arch,
      adapterId: identity.id,
      adapterVersion: identity.version,
    });
  }

  override async listModels(): Promise<Model[]> {
    if (this.nextListError !== undefined) throw this.nextListError;
    return this.nextModels;
  }
}

test('resolveModelAlias resolves flash and argon for available efforts and ignores orchestrator/other IDs', () => {
  assert.deepEqual(MODEL_ALIASES, ['flash', 'argon']);
  assert.deepEqual(RESOLUTION_STATUSES, [
    'resolved',
    'cli-absent',
    'list-unavailable',
    'alias-not-listed',
    'effort-unavailable',
    'ambiguous',
  ]);
  assert.deepEqual(IDENTITY_STATUSES, ['not-observable', 'unknown']);

  const flashHigh = resolveModelAlias({ alias: 'flash', effort: 'high', cli: CLI_1513, models: REAL_MODELS });
  assert.equal(flashHigh.status, 'resolved');
  assert.equal(flashHigh.modelId, 'gemini-3.8-flash-high');
  assert.equal(flashHigh.alias, 'flash');
  assert.equal(flashHigh.requestedEffort, 'high');
  assert.equal(flashHigh.effortEncoding, 'model-id-suffix');
  assert.deepEqual(flashHigh.availableEfforts, ['low', 'medium', 'high']);
  assert.deepEqual(flashHigh.candidates, [
    'gemini-3.8-flash-high',
    'gemini-3.8-flash-low',
    'gemini-3.8-flash-medium',
  ]);
  assert.equal(flashHigh.identity.model, 'not-observable');
  assert.equal(flashHigh.identity.effort, 'not-observable');

  const argonHigh = resolveModelAlias({ alias: 'argon', effort: 'high', cli: CLI_1513, models: REAL_MODELS });
  assert.equal(argonHigh.status, 'resolved');
  assert.equal(argonHigh.modelId, 'gemini-4-argon-high');
  assert.deepEqual(argonHigh.availableEfforts, ['low', 'medium', 'high']);
  assert.deepEqual(argonHigh.candidates, [
    'gemini-4-argon-high',
    'gemini-4-argon-low',
    'gemini-4-argon-medium',
  ]);
  assert.equal(argonHigh.candidates.includes('gemini-pro-orchestrator-g1-pro'), false);
});

test('resolveModelAlias refuses xhigh/max without downgrading and never selects gemini-pro-orchestrator-g1-pro', () => {
  const argonXhigh = resolveModelAlias({ alias: 'argon', effort: 'xhigh', cli: CLI_1513, models: REAL_MODELS });
  assert.equal(argonXhigh.status, 'effort-unavailable');
  assert.equal(argonXhigh.modelId, null);
  assert.deepEqual(argonXhigh.availableEfforts, ['low', 'medium', 'high']);
  assert.match(argonXhigh.detail, /low, medium, high/);
  assert.match(argonXhigh.detail, /Refusing to downgrade/i);

  const flashXhigh = resolveModelAlias({ alias: 'flash', effort: 'xhigh', cli: CLI_1513, models: REAL_MODELS });
  assert.equal(flashXhigh.status, 'effort-unavailable');
  assert.equal(flashXhigh.modelId, null);
  assert.deepEqual(flashXhigh.availableEfforts, ['low', 'medium', 'high']);

  for (const alias of MODEL_ALIASES) {
    const maxEffort = resolveModelAlias({ alias, effort: 'max', cli: CLI_1513, models: REAL_MODELS });
    assert.equal(maxEffort.status, 'effort-unavailable');
    assert.equal(maxEffort.modelId, null);
    assert.deepEqual(maxEffort.availableEfforts, ['low', 'medium', 'high']);
  }

  const withoutArgon = REAL_MODELS.filter(model => !model.id.includes('-argon-'));
  const argonNotListed = resolveModelAlias({ alias: 'argon', effort: 'high', cli: CLI_1513, models: withoutArgon });
  assert.equal(argonNotListed.status, 'alias-not-listed');
  assert.equal(argonNotListed.modelId, null);
  assert.deepEqual(argonNotListed.candidates, []);
  assert.deepEqual(argonNotListed.availableEfforts, []);
  assert.match(argonNotListed.detail, /User-declared access to Argon is preserved/i);
  assert.match(argonNotListed.detail, /gemini-<n>-argon-<effort>/);
  assert.match(argonNotListed.detail, /no model ID was substituted or invented/i);

  const withoutFlash = REAL_MODELS.filter(model => !model.id.includes('-flash-'));
  const flashNotListed = resolveModelAlias({ alias: 'flash', effort: 'high', cli: CLI_1513, models: withoutFlash });
  assert.equal(flashNotListed.status, 'alias-not-listed');
  assert.equal(flashNotListed.modelId, null);
  assert.equal(/User-declared/i.test(flashNotListed.detail), false);
  assert.match(flashNotListed.detail, /gemini-<n>-flash-<effort>/);
});

test('resolveModelAlias handles ambiguity, cli-absent, list-unavailable, and identity observability by CLI version', () => {
  const twoFlashVersions: readonly Model[] = [
    ...REAL_MODELS,
    { id: 'gemini-4-flash-high', name: 'Gemini 4 Flash (High)' },
  ];
  const ambiguous = resolveModelAlias({ alias: 'flash', effort: 'high', cli: CLI_1513, models: twoFlashVersions });
  assert.equal(ambiguous.status, 'ambiguous');
  assert.equal(ambiguous.modelId, null);
  assert.deepEqual(ambiguous.candidates, [
    'gemini-3.8-flash-high',
    'gemini-3.8-flash-low',
    'gemini-3.8-flash-medium',
    'gemini-4-flash-high',
  ]);
  assert.deepEqual(ambiguous.availableEfforts, []);

  const absent = resolveModelAlias({
    alias: 'argon',
    effort: 'high',
    cli: { installed: false, version: null },
    models: REAL_MODELS,
  });
  assert.equal(absent.status, 'cli-absent');
  assert.equal(absent.modelId, null);
  assert.equal(absent.identity.model, 'unknown');
  assert.equal(absent.identity.effort, 'unknown');

  const listUnavailable = resolveModelAlias({
    alias: 'flash',
    effort: 'high',
    cli: CLI_1513,
    models: null,
    listError: { code: 'AGY_AUTH_REQUIRED' },
  });
  assert.equal(listUnavailable.status, 'list-unavailable');
  assert.equal(listUnavailable.modelId, null);
  assert.equal(listUnavailable.errorCode, 'AGY_AUTH_REQUIRED');
  assert.equal(listUnavailable.identity.model, 'not-observable');
  assert.equal(listUnavailable.identity.effort, 'not-observable');

  const otherVersion = resolveModelAlias({
    alias: 'flash',
    effort: 'high',
    cli: { installed: true, version: '1.4.0' },
    models: REAL_MODELS,
  });
  assert.equal(otherVersion.identity.model, 'unknown');
  assert.equal(otherVersion.identity.effort, 'unknown');
  assert.match(otherVersion.identity.detail, /init\.model/);

  const nullVersion = resolveModelAlias({
    alias: 'flash',
    effort: 'high',
    cli: { installed: true, version: null },
    models: REAL_MODELS,
  });
  assert.equal(nullVersion.identity.model, 'unknown');
  assert.equal(nullVersion.identity.effort, 'unknown');
});

test('classifyInitModel distinguishes echoes, blank/non-string values, mismatches, unrequested observations, case sensitivity, and truncation', () => {
  assert.deepEqual(classifyInitModel('gemini-4-argon-high', 'gemini-4-argon-high'), {
    observed: { model: null, status: 'not-observable' },
    echo: true,
    mismatch: false,
  });

  assert.deepEqual(classifyInitModel('gemini-4-argon-high', '  gemini-4-argon-high  '), {
    observed: { model: null, status: 'not-observable' },
    echo: true,
    mismatch: false,
  });

  assert.deepEqual(classifyInitModel('gemini-4-argon-high', '   '), {
    observed: { model: null, status: 'not-observable' },
    echo: false,
    mismatch: false,
  });

  for (const nonString of [undefined, null, 42, { model: 'gemini-4-argon-high' }]) {
    assert.deepEqual(classifyInitModel('gemini-4-argon-high', nonString), {
      observed: { model: null, status: 'not-observable' },
      echo: false,
      mismatch: false,
    });
  }

  assert.deepEqual(classifyInitModel('gemini-4-argon-high', 'gemini-3.8-flash-high'), {
    observed: { model: 'gemini-3.8-flash-high', status: 'observed' },
    echo: false,
    mismatch: true,
  });

  assert.deepEqual(classifyInitModel(null, '  gemini-4-argon-high  '), {
    observed: { model: 'gemini-4-argon-high', status: 'observed' },
    echo: false,
    mismatch: false,
  });

  const longId = 'm'.repeat(300);
  assert.deepEqual(classifyInitModel('requested', longId), {
    observed: { model: 'm'.repeat(256), status: 'observed' },
    echo: false,
    mismatch: true,
  });

  assert.deepEqual(classifyInitModel('gemini-4-argon-high', 'Gemini-4-Argon-High'), {
    observed: { model: 'Gemini-4-Argon-High', status: 'observed' },
    echo: false,
    mismatch: true,
  });
});

test('evaluateModelProof covers all three verdicts and treats matching observed values as not-observable', () => {
  assert.equal(
    evaluateModelProof({
      requested: { model: 'gemini-4-argon-high' },
      observed: { model: null, status: 'not-observable' },
    }).verdict,
    'not-observable',
  );

  const legacyEcho = evaluateModelProof({
    requested: { model: 'gemini-4-argon-high' },
    observed: { model: 'gemini-4-argon-high', status: 'observed' },
  });
  assert.equal(legacyEcho.verdict, 'not-observable');
  assert.match(legacyEcho.detail, /echo/i);
  assert.match(legacyEcho.detail, /not proof/i);

  assert.equal(
    evaluateModelProof({
      requested: { model: 'gemini-4-argon-high' },
      observed: { model: 'gemini-3.8-flash-high', status: 'observed' },
    }).verdict,
    'mismatch',
  );

  assert.equal(
    evaluateModelProof({
      requested: { model: null },
      observed: { model: 'gemini-4-argon-high', status: 'observed' },
    }).verdict,
    'no-request',
  );
});

test('MCP black_gravity_resolve_model validates output schema, handles errors, and leaves saved model unchanged', async t => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'bg-resolve-model-'));
  const repoDir = path.join(root, 'repo');
  const stateDir = path.join(root, 'state');
  mkdirSync(repoDir, { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  execFileSync('git', ['init'], { cwd: repoDir, stdio: 'ignore' });
  writeFileSync(path.join(repoDir, 'README.md'), 'hello\n', 'utf8');

  const config = loadConfig({
    BRIDGE_STATE_DIRECTORY: stateDir,
    BRIDGE_TEST_EXECUTOR: 'agy',
    AGY_PATH: process.execPath,
  });
  const cli = new ControlledResolveCliAdapter(config);
  const tasks = new TaskManager(cli, config);
  const server = createMcpServer(cli, tasks);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'resolve-model-test', version: '1.0.0' }, { capabilities: {} });

  t.after(async () => {
    await client.close().catch(() => {});
    await server.close().catch(() => {});
    await tasks.shutdown();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  await tasks.setModel('gemini-4-hydrogen-high');

  const resolvedRes = await client.callTool({
    name: 'black_gravity_resolve_model',
    arguments: { alias: 'argon' },
  });
  assert.equal(resolvedRes.isError, undefined, JSON.stringify(resolvedRes.structuredContent));
  outputSchemas.black_gravity_resolve_model.parse(resolvedRes.structuredContent);
  const resolved = successOutputSchemas.black_gravity_resolve_model.parse(resolvedRes.structuredContent);
  assert.equal(resolved.resolution.status, 'resolved');
  assert.equal(resolved.resolution.requestedEffort, 'high');
  assert.equal(resolved.resolution.modelId, 'gemini-4-argon-high');
  assert.equal(resolved.resolution.identity.model, 'not-observable');
  assert.equal(tasks.getModel(), 'gemini-4-hydrogen-high');

  cli.nextListError = new BridgeError('AGY_AUTH_REQUIRED', 'Login required');
  const unavailableRes = await client.callTool({
    name: 'black_gravity_resolve_model',
    arguments: { alias: 'flash', effort: 'medium' },
  });
  assert.equal(unavailableRes.isError, undefined, JSON.stringify(unavailableRes.structuredContent));
  const unavailable = successOutputSchemas.black_gravity_resolve_model.parse(unavailableRes.structuredContent);
  assert.equal(unavailable.resolution.status, 'list-unavailable');
  assert.equal(unavailable.resolution.errorCode, 'AGY_AUTH_REQUIRED');
  assert.equal(unavailable.resolution.modelId, null);

  cli.nextListError = undefined;
  cli.nextCapabilityRecord = buildAgyCapabilityRecord({
    installed: false,
    helpText: '',
    error: 'AGY_NOT_FOUND: missing',
    platform: process.platform,
    arch: process.arch,
    adapterId: 'agy',
    adapterVersion: AGY_ADAPTER_VERSION,
  });
  const absentRes = await client.callTool({
    name: 'black_gravity_resolve_model',
    arguments: { alias: 'argon', effort: 'low' },
  });
  assert.equal(absentRes.isError, undefined, JSON.stringify(absentRes.structuredContent));
  const absent = successOutputSchemas.black_gravity_resolve_model.parse(absentRes.structuredContent);
  assert.equal(absent.resolution.status, 'cli-absent');
  assert.equal(absent.resolution.modelId, null);
  assert.equal(tasks.getModel(), 'gemini-4-hydrogen-high');
});
