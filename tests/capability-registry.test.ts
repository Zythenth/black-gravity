import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { AGY_ADAPTER_VERSION } from '../src/agy-execution-adapter.js';
import {
  buildAgyCapabilityRecord,
  CAPABILITY_OBSERVATIONS,
  REGISTRY_CAPABILITIES,
} from '../src/capability-registry.js';
import { outputSchemas, successOutputSchemas } from '../src/output-schemas.js';

const FULL_HELP = [
  '--input-format stream-json',
  '--output-format stream-json',
  '--model',
  '--effort',
  '--conversation',
  '--sandbox',
  '--add-dir',
  '--new-project',
  '--json-schema',
  '--mode (accept-edits, plan)',
  'models',
].join('\n');

const baseInput = {
  installed: true,
  version: '1.2.11',
  helpText: FULL_HELP,
  platform: 'linux' as const,
  arch: 'x64',
  adapterId: 'agy',
  adapterVersion: AGY_ADAPTER_VERSION,
};

test('full help marks help-derived capabilities observed, adapter-derived capabilities by adapter rules, unqueried ones unknown, and returns fresh objects', () => {
  const record = buildAgyCapabilityRecord(baseInput);
  assert.equal(record.cli, 'agy');
  assert.equal(record.installed, true);
  assert.equal(record.version, '1.2.11');
  assert.deepEqual(record.queriedWith, ['--version', '--help']);

  const helpDerived = [
    'read', 'sandbox', 'structuredOutput',
    'resume', 'modelList', 'modelSelection', 'effort',
  ] as const;
  for (const key of helpDerived) {
    assert.equal(record.capabilities[key].status, 'observed', key);
    assert.equal(record.capabilities[key].source, 'help', key);
  }
  for (const key of ['write', 'skills'] as const) {
    assert.equal(record.capabilities[key].status, 'observed', key);
    assert.equal(record.capabilities[key].source, 'adapter', key);
  }
  assert.equal(record.capabilities.observableUsage.status, 'unknown');
  assert.equal(record.capabilities.observableUsage.source, 'adapter');

  const checkedVersionRecord = buildAgyCapabilityRecord({ ...baseInput, version: '1.5.13' });
  assert.equal(checkedVersionRecord.capabilities.observableUsage.status, 'observed');
  assert.equal(checkedVersionRecord.capabilities.observableUsage.source, 'adapter');

  for (const key of ['network', 'resources', 'cancel', 'sessionsList'] as const) {
    assert.equal(record.capabilities[key].status, 'unknown', key);
    assert.equal(record.capabilities[key].source, 'none', key);
  }

  const allowed = new Set<string>(CAPABILITY_OBSERVATIONS);
  for (const key of REGISTRY_CAPABILITIES) {
    assert.ok(allowed.has(record.capabilities[key].status), key);
  }
  assert.ok(allowed.has(record.effectiveModel.status));
  for (const restriction of record.editToolRestrictions) {
    assert.ok(allowed.has(restriction.status));
  }

  record.queriedWith.push('mutated');
  record.editToolRestrictions[0]!.verifiedVersions.push('9.9.9');
  const next = buildAgyCapabilityRecord(baseInput);
  assert.deepEqual(next.queriedWith, ['--version', '--help']);
  assert.deepEqual(next.editToolRestrictions[0]!.verifiedVersions, []);
});

test('missing help flags mark structuredOutput, effort and resume absent rather than unknown or observed', () => {
  const reducedHelp = FULL_HELP
    .replace('--json-schema\n', '')
    .replace('--effort\n', '')
    .replace('--conversation\n', '');
  const record = buildAgyCapabilityRecord({ ...baseInput, helpText: reducedHelp });
  for (const key of ['structuredOutput', 'effort', 'resume'] as const) {
    assert.equal(record.capabilities[key].status, 'absent', key);
    assert.equal(record.capabilities[key].source, 'help', key);
  }

  const noStreamHelp = FULL_HELP.replaceAll('stream-json', '');
  const noStream = buildAgyCapabilityRecord({ ...baseInput, version: '1.5.13', helpText: noStreamHelp });
  assert.equal(noStream.capabilities.observableUsage.status, 'unknown');
  assert.equal(noStream.capabilities.observableUsage.source, 'adapter');
  assert.equal(noStream.capabilities.write.status, 'absent');
  assert.equal(noStream.capabilities.write.source, 'adapter');
});

test('token-aware option, subcommand and read-mode matching reject partial tokens and prose', () => {
  const trickyHelp = [
    '--input-format stream-json',
    '--output-format stream-json',
    '--model-cache',
    'Use agy to list models.',
    '--mode (accept-edits)',
    'plan on another line',
  ].join('\n');
  const record = buildAgyCapabilityRecord({ ...baseInput, helpText: trickyHelp });
  assert.equal(record.capabilities.modelSelection.status, 'absent');
  assert.equal(record.capabilities.modelSelection.source, 'help');
  assert.equal(record.capabilities.modelList.status, 'absent');
  assert.equal(record.capabilities.modelList.source, 'help');
  assert.equal(record.capabilities.read.status, 'absent');
  assert.equal(record.capabilities.read.source, 'help');
});

test('not installed marks every capability and effectiveModel unknown with source none, propagates error and keeps editToolRestrictions', () => {
  const record = buildAgyCapabilityRecord({
    ...baseInput,
    installed: false,
    version: '1.5.13',
    helpText: FULL_HELP,
    error: 'AGY_NOT_FOUND: missing agy',
  });
  assert.equal(record.installed, false);
  assert.equal(record.version, null);
  assert.equal(record.error, 'AGY_NOT_FOUND: missing agy');
  for (const key of REGISTRY_CAPABILITIES) {
    assert.deepEqual(record.capabilities[key], { status: 'unknown', source: 'none', detail: 'CLI could not be queried' }, key);
  }
  assert.deepEqual(record.effectiveModel, { status: 'unknown', source: 'none', detail: 'CLI could not be queried' });
  assert.equal(record.editToolRestrictions.length, 1);
  assert.equal(record.editToolRestrictions[0]!.tool, 'edit_file');
  assert.equal(record.editToolRestrictions[0]!.status, 'observed');
  assert.equal(record.editToolRestrictions[0]!.source, 'recorded');
  assert.deepEqual(record.editToolRestrictions[0]!.verifiedVersions, []);
});

test('effectiveModel records absent for 1.5.13 and unknown for 1.2.11', () => {
  const absentRecord = buildAgyCapabilityRecord({ ...baseInput, version: '1.5.13' });
  assert.equal(absentRecord.effectiveModel.status, 'absent');
  assert.equal(absentRecord.effectiveModel.source, 'adapter');
  assert.ok(absentRecord.effectiveModel.detail.includes('repeats the --model value only when one is passed'));

  const unknownRecord = buildAgyCapabilityRecord({ ...baseInput, version: '1.2.11' });
  assert.equal(unknownRecord.effectiveModel.status, 'unknown');
  assert.equal(unknownRecord.effectiveModel.source, 'adapter');
});

async function runCapabilitiesWithFakeAgy(options: {
  versionOutput?: string;
  versionExitCode?: number;
  helpOutput: string;
}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-capabilities-test-'));
  const logFile = path.join(dir, 'agy-argv.jsonl');
  const fakeAgy = path.join(dir, 'fake-agy.mjs');
  const versionExit = options.versionExitCode ?? 0;
  const fakeScript = [
    "import { appendFileSync } from 'node:fs';",
    'const args = process.argv.slice(2);',
    `appendFileSync(${JSON.stringify(logFile)}, JSON.stringify(args) + '\\n', 'utf8');`,
    `if (args.includes('--version')) { ${options.versionOutput !== undefined ? `console.log(${JSON.stringify(options.versionOutput)}); ` : ''}process.exit(${versionExit}); }`,
    `if (args.includes('--help')) { console.log(${JSON.stringify(options.helpOutput)}); process.exit(0); }`,
    'process.exit(2);',
  ].join('\n');
  await writeFile(fakeAgy, fakeScript, 'utf8');

  const entryPath = fileURLToPath(new URL('../src/index.js', import.meta.url));
  const agySpawn = fileURLToPath(new URL('../../tests/agy-spawn.mjs', import.meta.url));
  const client = new Client({ name: 'capabilities-test', version: '1' });
  try {
    await client.connect(new StdioClientTransport({
      command: process.execPath,
      args: ['--import', pathToFileURL(agySpawn).href, entryPath],
      env: {
        ...process.env as Record<string, string>,
        AGY_PATH: fakeAgy,
        BRIDGE_TEST_EXECUTOR: 'agy',
        BRIDGE_TOOL_PROFILE: 'full',
        BRIDGE_STATE_DIRECTORY: path.join(dir, 'state'),
        BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY: path.join(dir, 'node-cache'),
      },
      stderr: 'pipe',
    }));

    const result = await client.callTool({ name: 'black_gravity_capabilities', arguments: {} });
    assert.equal(result.isError, undefined, JSON.stringify(result.structuredContent));
    outputSchemas.black_gravity_capabilities.parse(result.structuredContent);
    const parsed = successOutputSchemas.black_gravity_capabilities.parse(result.structuredContent);
    assert.equal(parsed.clis.length, 1);
    const cli = parsed.clis[0];
    assert.ok(cli);

    const lines = (await readFile(logFile, 'utf8')).trim().split(/\r?\n/).filter(Boolean);
    const invocations = lines.map(line => JSON.parse(line) as string[]);
    assert.ok(invocations.length >= 2);
    assert.ok(invocations.every(argv => argv.length === 1 && (argv[0] === '--version' || argv[0] === '--help')), JSON.stringify(invocations));
    assert.ok(invocations.some(argv => argv[0] === '--version'));
    assert.ok(invocations.some(argv => argv[0] === '--help'));
    assert.equal(invocations.some(argv => argv.includes('models')), false);
    return cli;
  } finally {
    await client.close().catch(() => {});
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test('MCP black_gravity_capabilities validates against schema and invokes only --version and --help', async () => {
  const cli = await runCapabilitiesWithFakeAgy({
    versionOutput: '1.2.11',
    helpOutput: '--input-format stream-json\n--output-format stream-json\n--model\n--conversation\n--sandbox\n--add-dir\n--new-project\n--json-schema\n--mode (accept-edits, plan)\nmodels',
  });
  assert.equal(cli.cli, 'agy');
  assert.equal(cli.installed, true);
  assert.equal(cli.version, '1.2.11');
  assert.equal(cli.adapterId, 'agy');
  assert.equal(cli.adapterVersion, AGY_ADAPTER_VERSION);
  assert.equal(cli.capabilities.effort.status, 'absent');
  assert.equal(cli.capabilities.read.status, 'observed');
  assert.equal(cli.capabilities.observableUsage.status, 'unknown');
  assert.equal(cli.capabilities.observableUsage.source, 'adapter');
  assert.equal(cli.effectiveModel.status, 'unknown');
});

test('MCP black_gravity_capabilities keeps installed true and marks sandbox and write absent when --sandbox is missing', async () => {
  const helpWithoutSandbox = FULL_HELP.replace('--sandbox\n', '');
  const cli = await runCapabilitiesWithFakeAgy({
    versionOutput: '1.5.13',
    helpOutput: helpWithoutSandbox,
  });
  assert.equal(cli.installed, true);
  assert.equal(cli.version, '1.5.13');
  assert.equal(cli.capabilities.sandbox.status, 'absent');
  assert.equal(cli.capabilities.write.status, 'absent');
  assert.equal(cli.effectiveModel.status, 'absent');
  assert.equal(cli.capabilities.observableUsage.status, 'observed');
});

test('MCP black_gravity_capabilities reports AGY_PROBE_FAILED when --version exits 1', async () => {
  const cli = await runCapabilitiesWithFakeAgy({
    versionExitCode: 1,
    helpOutput: FULL_HELP,
  });
  assert.equal(cli.installed, false);
  assert.equal(cli.version, null);
  for (const key of REGISTRY_CAPABILITIES) {
    assert.equal(cli.capabilities[key].status, 'unknown', key);
  }
  assert.ok(cli.error?.startsWith('AGY_PROBE_FAILED'), String(cli.error));
});
