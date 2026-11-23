import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const rawArgs = process.argv.slice(2);
let recordFile;
let scenario = 'read';
let index = 0;
while (index < rawArgs.length) {
  if (rawArgs[index] === '--record' && index + 1 < rawArgs.length) {
    recordFile = rawArgs[index + 1];
    index += 2;
  } else if (rawArgs[index] === '--scenario' && index + 1 < rawArgs.length) {
    scenario = rawArgs[index + 1];
    index += 2;
  } else {
    break;
  }
}

const argv = rawArgs.slice(index);
const subcommand = argv[0];

function writeRecord(stdinText) {
  if (!recordFile) return;
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (
      key.startsWith('OPENCODE_') ||
      key === 'PWD' ||
      (process.platform === 'win32' ? key.toUpperCase() === 'PATH' : key === 'PATH')
    ) {
      env[key] = value;
    }
  }
  mkdirSync(path.dirname(recordFile), { recursive: true });
  writeFileSync(recordFile, JSON.stringify({ argv, cwd: process.cwd(), stdin: stdinText, env }), 'utf8');
}

if (subcommand === '--version') {
  writeRecord('');
  process.stdout.write('opencode v0.0.0-mock\n');
  process.exit(0);
}

if (subcommand === 'models') {
  writeRecord('');
  if (scenario === 'models-leak') {
    process.stderr.write(`key=${process.env.MOCK_PROVIDER_API_KEY ?? ''}\n`);
    process.exit(2);
  }
  if (scenario === 'models-fail') {
    process.stderr.write('mock models command failed\n');
    process.exit(2);
  }
  process.stdout.write('opencode-go/mock-flash\n\nopencode-go/mock-pro\nnot a model line\n');
  process.exit(0);
}

let stdin = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) {
  stdin += chunk;
}
writeRecord(stdin);

const sessionID = 'ses_mock1';
const send = obj => process.stdout.write(JSON.stringify(obj) + '\n');
const emitStepFinish = (tokens = { input: 1, output: 1, reasoning: 0, cache: { read: 0, write: 0 } }) => {
  send({
    type: 'step_finish',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_finish_1',
      sessionID,
      messageID: 'msg_1',
      type: 'step-finish',
      reason: 'stop',
      snapshot: 'snap_1',
      cost: 0,
      tokens,
    },
  });
};

if (scenario === 'read') {
  const match = stdin.match(/READ:([^\r\n]+)/);
  const relPath = match ? match[1].trim() : '';
  const content = readFileSync(path.join(process.cwd(), relPath), 'utf8');
  const markerLine = content.split(/\r?\n/).find(line => /MARKER_[A-Z0-9_]+/.test(line)) ?? '';
  const fullText = `Found: ${markerLine}`;
  const mid = Math.ceil(fullText.length / 2);

  send({
    type: 'step_start',
    timestamp: Date.now(),
    sessionID,
    part: { id: 'prt_start_1', sessionID, messageID: 'msg_1', type: 'step-start', snapshot: 'snap_1' },
  });
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_1',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      tool: 'read',
      state: { status: 'completed', input: { filePath: relPath }, output: content, title: relPath },
    },
  });
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_1',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: fullText.slice(0, mid),
      time: { start: Date.now(), end: Date.now() },
    },
  });
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_1',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: fullText.slice(mid),
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish({ input: 11, output: 7, reasoning: 2, cache: { read: 3, write: 0 } });
  process.exit(0);
}

if (scenario === 'config-probe') {
  let probeText = 'project-config-skipped';
  if (process.env.OPENCODE_DISABLE_PROJECT_CONFIG !== '1' || process.env.OPENCODE_CONFIG_PROJECT_DISABLE !== '1') {
    let config = {};
    const configPath = path.join(process.cwd(), 'opencode.json');
    if (existsSync(configPath)) {
      config = JSON.parse(readFileSync(configPath, 'utf8'));
    }
    const pluginsDir = path.join(process.cwd(), '.opencode', 'plugins');
    if (existsSync(pluginsDir)) {
      for (const entry of readdirSync(pluginsDir).sort()) {
        if (entry.endsWith('.js')) {
          await import(pathToFileURL(path.join(pluginsDir, entry)).href);
        }
      }
    }
    probeText = JSON.stringify({ providers: config.providers ?? null, agents: config.agents ?? null });
  }
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_probe',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: probeText,
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'write-denied') {
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_1',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      tool: 'edit',
      state: { status: 'error', input: { filePath: 'x' }, error: 'Permission denied: edit' },
    },
  });
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_1',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: 'Could not edit x.',
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'shell-denied') {
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_1',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      tool: 'shell',
      state: { status: 'error', input: { command: 'echo hi' }, error: 'Permission denied: shell' },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'ask-rejected') {
  process.stderr.write('! permission requested: shell (echo hi); auto-rejecting\n');
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_1',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      tool: 'shell',
      state: {
        status: 'error',
        input: { command: 'echo hi' },
        error: 'This non-interactive run cannot ask the user for permission, so the request was rejected. Continue without this action.',
      },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'write-succeeded') {
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_1',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      tool: 'edit',
      state: { status: 'completed', input: { filePath: 'x' }, output: 'edited', title: 'x' },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'error') {
  send({
    type: 'error',
    timestamp: Date.now(),
    sessionID,
    error: { type: 'unknown', message: 'Model not found: x' },
  });
  process.exit(1);
}

if (scenario === 'no-finish') {
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_1',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: 'unfinished output',
      time: { start: Date.now(), end: Date.now() },
    },
  });
  process.exit(0);
}

if (scenario === 'garbage') {
  process.stdout.write('not a json event line\n');
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'leak') {
  const leaked = `key=${process.env.MOCK_PROVIDER_API_KEY ?? ''}`;
  process.stderr.write(`${leaked}\n`);
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_leak',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: leaked,
      time: { start: Date.now(), end: Date.now() },
    },
  });
  send({
    type: 'error',
    timestamp: Date.now(),
    sessionID,
    error: { type: 'unknown', message: `provider failed: ${leaked}` },
  });
  process.exit(1);
}

if (scenario === 'leak-ok') {
  const leaked = `key=${process.env.MOCK_PROVIDER_API_KEY ?? ''}`;
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_leak_ok',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: leaked,
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'leak-tool') {
  const secret = process.env.MOCK_PROVIDER_API_KEY ?? '';
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_leak',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      tool: `read${secret}`,
      state: { status: 'completed', input: {}, output: 'ok', title: 'ok' },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'leak-escaped') {
  const secret = process.env.MOCK_PROVIDER_API_KEY ?? '';
  const escaped = [...secret].map(ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  send({
    type: 'text',
    timestamp: Date.now(),
    sessionID,
    part: {
      id: 'prt_text_leak_escaped',
      sessionID,
      messageID: 'msg_1',
      type: 'text',
      text: `{"apiKey":"${escaped}"}`,
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish();
  process.exit(0);
}

process.stderr.write(`Unknown mock scenario: ${scenario}\n`);
process.exit(2);
