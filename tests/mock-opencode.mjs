import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const rawArgs = process.argv.slice(2);
let recordFile;
let spawnLogFile;
let sessionsFile;
let toolErrorsFile;
let scenario = 'read';
let sessionListHang = false;
let index = 0;
while (index < rawArgs.length) {
  if (rawArgs[index] === '--record' && index + 1 < rawArgs.length) {
    recordFile = rawArgs[index + 1];
    index += 2;
  } else if (rawArgs[index] === '--spawn-log' && index + 1 < rawArgs.length) {
    spawnLogFile = rawArgs[index + 1];
    index += 2;
  } else if (rawArgs[index] === '--sessions' && index + 1 < rawArgs.length) {
    sessionsFile = rawArgs[index + 1];
    index += 2;
  } else if (rawArgs[index] === '--tool-errors' && index + 1 < rawArgs.length) {
    toolErrorsFile = rawArgs[index + 1];
    index += 2;
  } else if (rawArgs[index] === '--scenario' && index + 1 < rawArgs.length) {
    scenario = rawArgs[index + 1];
    index += 2;
  } else if (rawArgs[index] === '--session-list-hang') {
    sessionListHang = true;
    index += 1;
  } else {
    break;
  }
}

const argv = rawArgs.slice(index);
const subcommand = argv[0];

if (spawnLogFile) {
  mkdirSync(path.dirname(spawnLogFile), { recursive: true });
  appendFileSync(spawnLogFile, JSON.stringify({ argv, pid: process.pid }) + '\n', 'utf8');
}

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

if (subcommand === 'session' && argv[1] === 'list') {
  if (sessionListHang) {
    const grandchild = spawn(
      process.execPath,
      ['-e', "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],
      {
        detached: process.platform !== 'win32',
        stdio: 'ignore',
      },
    );
    if (recordFile) {
      mkdirSync(path.dirname(recordFile), { recursive: true });
      writeFileSync(`${recordFile}.session-list-pid`, String(process.pid), 'utf8');
      if (grandchild.pid !== undefined) {
        writeFileSync(`${recordFile}.session-list-grandchild-pid`, String(grandchild.pid), 'utf8');
      }
    }
    process.on('SIGTERM', () => {});
    setInterval(() => {}, 1000);
    await new Promise(() => {});
  }
  if (sessionsFile && existsSync(sessionsFile)) {
    process.stdout.write(readFileSync(sessionsFile, 'utf8'));
  } else {
    process.stdout.write('[]\n');
  }
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

const sessionFlagIndex = argv.indexOf('--session');
const requestedSessionID = sessionFlagIndex !== -1 && sessionFlagIndex + 1 < argv.length
  ? argv[sessionFlagIndex + 1]
  : undefined;
const sessionID = scenario === 'resume-mismatch'
  ? (requestedSessionID === 'ses_mismatch_other' ? 'ses_mismatch_alt' : 'ses_mismatch_other')
  : (requestedSessionID ?? 'ses_mock1');
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

if (scenario === 'read' || scenario === 'resume-mismatch') {
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

if (scenario === 'write-inside') {
  writeFileSync(path.join(process.cwd(), 'created-by-opencode.txt'), 'opencode write fixture\n', 'utf8');
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
      tool: 'write',
      state: { status: 'completed', input: { path: 'created-by-opencode.txt' }, output: 'written', title: 'created-by-opencode.txt' },
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
      text: 'Created created-by-opencode.txt.',
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'write-outside') {
  writeFileSync(path.join(process.cwd(), 'partial.txt'), 'partial\n', 'utf8');
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
      tool: 'write',
      state: { status: 'completed', input: { path: 'partial.txt' }, output: 'written', title: 'partial.txt' },
    },
  });
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_2',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_2',
      tool: 'write',
      state: { status: 'error', input: { path: '../outside-target.txt' }, error: 'Permission denied: external_directory' },
    },
  });
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_3',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_3',
      tool: 'shell',
      state: {
        status: 'error',
        input: { command: 'touch ../outside-shell.txt' },
        error: 'No tool named "shell" is currently available. Please use a tool from the available tool list.',
      },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'write-config') {
  writeFileSync(path.join(process.cwd(), 'opencode.json'), '{"plugins":["./evil.js"]}', 'utf8');
  mkdirSync(path.join(process.cwd(), 'nested'), { recursive: true });
  writeFileSync(path.join(process.cwd(), 'nested', 'opencode.jsonc'), '{}', 'utf8');
  mkdirSync(path.join(process.cwd(), '.opencode', 'agents'), { recursive: true });
  writeFileSync(path.join(process.cwd(), '.opencode', 'agents', 'evil.md'), 'planted', 'utf8');

  const files = ['opencode.json', 'nested/opencode.jsonc', '.opencode/agents/evil.md'];
  files.forEach((filePath, idx) => {
    send({
      type: 'tool_use',
      timestamp: Date.now(),
      sessionID,
      part: {
        partID: `prt_tool_${idx + 1}`,
        sessionID,
        messageID: 'msg_1',
        type: 'tool',
        id: `call_${idx + 1}`,
        tool: 'write',
        state: { status: 'completed', input: { path: filePath }, output: 'written', title: filePath },
      },
    });
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'worktree-remove') {
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
      tool: 'opencode_worktree_remove',
      state: { status: 'completed', input: { directory: '/tmp/somewhere' }, output: 'removed', title: '/tmp/somewhere' },
    },
  });
  emitStepFinish();
  process.exit(0);
}

if (scenario === 'hang') {
  send({
    type: 'step_start',
    timestamp: Date.now(),
    sessionID,
    part: { id: 'prt_start_hang', sessionID, messageID: 'msg_1', type: 'step-start', snapshot: 'snap_1' },
  });
  const grandchild = spawn(
    process.execPath,
    ['-e', "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],
    {
      detached: process.platform !== 'win32',
      stdio: 'ignore',
    },
  );
  if (recordFile && grandchild.pid !== undefined) {
    mkdirSync(path.dirname(recordFile), { recursive: true });
    writeFileSync(`${recordFile}.grandchild-pid`, String(grandchild.pid), 'utf8');
  }
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else if (scenario === 'tool-running-hang') {
  send({
    type: 'step_start',
    timestamp: Date.now(),
    sessionID,
    part: { id: 'prt_start_tool_hang', sessionID, messageID: 'msg_1', type: 'step-start', snapshot: 'snap_1' },
  });
  send({
    type: 'tool_use',
    timestamp: Date.now(),
    sessionID,
    part: {
      partID: 'prt_tool_running',
      sessionID,
      messageID: 'msg_1',
      type: 'tool',
      id: 'call_1',
      callID: 'call_1',
      tool: 'write',
      state: { status: 'running', input: { path: 'partial.txt' } },
    },
  });
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else if (scenario === 'auth-error') {
  send({
    type: 'error',
    timestamp: Date.now(),
    sessionID,
    error: { type: 'provider.auth', message: 'Invalid API key provided', status: 401, response: { body: 'secret-body' } },
  });
  process.exit(1);
} else if (scenario === 'quota-error') {
  send({
    type: 'error',
    timestamp: Date.now(),
    sessionID,
    error: { type: 'provider.quota', message: 'Insufficient quota', status: 429, response: {} },
  });
  process.exit(1);
} else if (scenario === 'region-error') {
  send({
    type: 'error',
    timestamp: Date.now(),
    sessionID,
    error: {
      type: 'unknown',
      message: 'This OpenCode Go model is hosted outside Europe and the United States. Select Global at https://opencode.ai/console/org_TEST/settings/privacy#regions to use it.',
    },
  });
  process.exit(1);
} else if (scenario === 'retry-loop') {
  send({
    type: 'step_start',
    timestamp: Date.now(),
    sessionID,
    part: { id: 'prt_start_retry', sessionID, messageID: 'msg_1', type: 'step-start', snapshot: 'snap_1' },
  });
  let attempt = 0;
  setInterval(() => {
    attempt += 1;
    send({
      type: 'retry',
      timestamp: Date.now(),
      sessionID,
      messageID: 'msg_1',
      attempt,
      nextRetryAt: Date.now() + 50,
      error: { type: 'provider.rate-limit', message: 'Rate limit exceeded', status: 429, response: {} },
    });
  }, 50);
} else if (scenario === 'retry-burst') {
  send({
    type: 'step_start',
    timestamp: Date.now(),
    sessionID,
    part: { id: 'prt_start_retry', sessionID, messageID: 'msg_1', type: 'step-start', snapshot: 'snap_1' },
  });
  for (let attempt = 1; attempt <= 12; attempt += 1) {
    send({
      type: 'retry',
      timestamp: Date.now(),
      sessionID,
      messageID: 'msg_1',
      attempt,
      nextRetryAt: Date.now() + 50,
      error: { type: 'provider.rate-limit', message: 'Rate limit exceeded', status: 429, response: {} },
    });
  }
  setInterval(() => {}, 1000);
} else if (scenario === 'auth-then-retries') {
  send({
    type: 'error',
    timestamp: Date.now(),
    sessionID,
    error: { type: 'provider.auth', message: 'Invalid API key provided', status: 401, response: {} },
  });
  let attempt = 0;
  setInterval(() => {
    attempt += 1;
    send({
      type: 'retry',
      timestamp: Date.now(),
      sessionID,
      messageID: 'msg_1',
      attempt,
      nextRetryAt: Date.now() + 50,
      error: { type: 'provider.rate-limit', message: 'Rate limit exceeded', status: 429, response: {} },
    });
  }, 50);
} else if (scenario === 'retry-auth') {
  send({
    type: 'retry',
    timestamp: Date.now(),
    sessionID,
    messageID: 'msg_1',
    attempt: 1,
    nextRetryAt: Date.now() + 50,
    error: { type: 'provider.auth', message: 'Invalid API key provided', status: 401, response: {} },
  });
  setInterval(() => {}, 1000);
} else if (scenario === 'retry-quota') {
  send({
    type: 'retry',
    timestamp: Date.now(),
    sessionID,
    messageID: 'msg_1',
    attempt: 1,
    nextRetryAt: Date.now() + 50,
    error: { type: 'provider.quota', message: 'Insufficient quota', status: 429, response: {} },
  });
  setInterval(() => {}, 1000);
} else if (scenario === 'slow-complete') {
  send({
    type: 'step_start',
    timestamp: Date.now(),
    sessionID,
    part: { id: 'prt_start_slow', sessionID, messageID: 'msg_1', type: 'step-start', snapshot: 'snap_1' },
  });
  setTimeout(() => {
    send({
      type: 'text',
      timestamp: Date.now(),
      sessionID,
      part: {
        id: 'prt_text_slow',
        sessionID,
        messageID: 'msg_1',
        type: 'text',
        text: 'slow complete',
        time: { start: Date.now(), end: Date.now() },
      },
    });
    emitStepFinish();
    process.exit(0);
  }, 2000);
} else if (scenario === 'tool-errors') {
  const replaceCwd = value => {
    if (typeof value === 'string') return value.replaceAll('{cwd}', process.cwd());
    if (Array.isArray(value)) return value.map(replaceCwd);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replaceCwd(v)]));
    }
    return value;
  };
  const entries = toolErrorsFile ? JSON.parse(readFileSync(toolErrorsFile, 'utf8')) : [];
  if (!Array.isArray(entries)) {
    process.stderr.write('Expected JSON array in --tool-errors file\n');
    process.exit(2);
  }
  entries.forEach((entry, idx) => {
    if (typeof entry.writeFile === 'string') {
      const target = path.resolve(process.cwd(), entry.writeFile);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, 'x', 'utf8');
    }
    const input = entry.input !== undefined ? replaceCwd(entry.input) : {};
    const error = typeof entry.error === 'string' ? replaceCwd(entry.error) : undefined;
    send({
      type: 'tool_use',
      timestamp: Date.now(),
      sessionID,
      part: {
        partID: `prt_tool_${idx + 1}`,
        sessionID,
        messageID: 'msg_1',
        type: 'tool',
        id: entry.callID ?? `call_${idx + 1}`,
        ...(entry.callID !== undefined ? { callID: entry.callID } : {}),
        tool: entry.tool,
        state: {
          status: entry.status,
          input,
          ...(error !== undefined ? { error } : {}),
          ...(entry.status === 'completed' ? { output: 'ok', title: 'ok' } : {}),
        },
      },
    });
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
      text: 'done',
      time: { start: Date.now(), end: Date.now() },
    },
  });
  emitStepFinish();
  process.exit(0);
} else {
  process.stderr.write(`Unknown mock scenario: ${scenario}\n`);
  process.exit(2);
}
