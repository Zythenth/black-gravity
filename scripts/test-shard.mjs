import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// Approximate Windows runner seconds, taken from the per-test durations of a recent main CI run; files not listed weigh 5. Weights only balance the shards, never select which tests run.
const TEST_WEIGHTS = {
  bridge: 461,
  'line-endings': 183,
  'workflow-runtime': 173,
  'windows-recovery': 168,
  'agy-execution-adapter': 162,
  features: 152,
  'portable-node': 139,
  inbox: 125,
  'persistence-redaction': 115,
  'windows-mcp': 110,
  'file-protection': 105,
  'wait-profiles': 105,
  'integration-policy': 90,
  'windows-executor': 89,
  mcp: 66,
  'host-git': 48,
  'windows-permissions': 48,
  'execution-identity': 42,
  'wait-command': 41,
  'agent-policy-runtime': 40,
  'subprocess-robustness': 40,
  'peer-input': 38,
  'skills-api': 35,
  artifacts: 33,
  'craft-runtime': 32,
  'wait-command-multi': 30,
  'project-memory-runtime': 28,
  'tool-events': 24,
  'windows-aliases': 24,
  'group-runtime': 18,
  'execution-contract': 16,
  'specialist-runtime': 13,
  'state-directory-degraded': 13,
  'execution-policy': 12,
  'linux-executor': 11,
  'security-integration': 11,
  'state-migration': 11,
  'windows-runtime': 11,
  'task-results': 10,
  'windows-dos': 10,
};

// Work outside the test files. On Windows each task weighs like a file and runs in the shard that receives it, after that shard's tests; on other platforms there are none, and --list shows the plan of the current platform.
const FIXED_TASKS = [
  { name: 'test:package', weight: 399, command: 'npm run test:package', shell: true, dropEnv: ['BRIDGE_WINDOWS_NODE_RUNTIME'] },
  { name: 'windows-executor-lpac-git', weight: 12, command: process.execPath, args: ['--test', '--test-name-pattern=Windows executor stages real Git inside LPAC', 'dist/tests/windows-executor.test.js'] },
];

const [indexArg, totalArg, modeArg] = process.argv.slice(2);
const listOnly = modeArg === '--list';
const validArgCount = process.argv.length === 4 || (process.argv.length === 5 && listOnly);
const index = Number(indexArg);
const total = Number(totalArg);
if (!validArgCount || !/^[1-9]\d*$/.test(indexArg ?? '') || !/^[1-9]\d*$/.test(totalArg ?? '') || index > total) {
  console.error('Uso: node scripts/test-shard.mjs <indice> <total> [--list]');
  process.exit(2);
}

let files;
try {
  files = readdirSync('dist/tests').filter(name => name.endsWith('.test.js')).sort();
} catch {
  files = [];
}
if (!files.length) {
  console.error('Nenhum arquivo de teste encontrado em dist/tests (build ausente).');
  process.exit(1);
}

const fileKeys = new Set(files.map(name => name.slice(0, -8)));
const obsolete = Object.keys(TEST_WEIGHTS).filter(key => !fileKeys.has(key));
if (obsolete.length) {
  console.error(`Chaves obsoletas na tabela de pesos: ${obsolete.join(', ')}`);
  process.exit(1);
}

const activeTasks = process.platform === 'win32' ? FIXED_TASKS : [];
const items = [
  ...files.map(name => ({ name, weight: TEST_WEIGHTS[name.slice(0, -8)] ?? 5 })),
  ...activeTasks.map(task => ({ name: task.name, weight: task.weight, task })),
].sort((a, b) => b.weight - a.weight || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

const jobs = Array.from({ length: total }, () => ({ load: 0, files: [], tasks: [] }));
for (const item of items) {
  let target = jobs[0];
  for (let i = 1; i < jobs.length; i++) {
    if (jobs[i].load < target.load) target = jobs[i];
  }
  if (item.task) {
    target.tasks.push(item.task);
  } else {
    target.files.push(`dist/tests/${item.name}`);
  }
  target.load += item.weight;
}

const job = jobs[index - 1];
if (listOnly) {
  console.log(JSON.stringify({
    job: index,
    total,
    files: job.files.map(file => file.slice('dist/tests/'.length)),
    tasks: job.tasks.map(task => task.name),
    load: job.load,
  }));
  process.exit(0);
}

if (!job.files.length && !job.tasks.length) {
  console.log(`Job ${index}/${total}: nenhum arquivo de teste atribuído.`);
  process.exit(0);
}

const minutes = (job.load / 60).toFixed(1);
const taskSummary = job.tasks.length ? ` e ${job.tasks.length} tarefas fixas (${job.tasks.map(task => task.name).join(', ')})` : '';
console.log(`Job ${index}/${total}: ${job.files.length} arquivos${taskSummary}, carga estimada ${minutes} min`);

function exitStatus(result) {
  return result.signal || result.status === null ? 1 : result.status;
}

if (job.files.length) {
  const status = exitStatus(spawnSync(process.execPath, ['scripts/run-tests.mjs', ...job.files], { stdio: 'inherit' }));
  if (status !== 0) process.exit(status);
}

for (const task of job.tasks) {
  console.log(`Tarefa fixa: ${task.name}`);
  const env = { ...process.env };
  for (const key of task.dropEnv ?? []) {
    delete env[key];
  }
  const result = task.shell
    ? spawnSync(task.command, { stdio: 'inherit', env, shell: true })
    : spawnSync(task.command, task.args ?? [], { stdio: 'inherit', env });
  const status = exitStatus(result);
  if (status !== 0) process.exit(status);
}

process.exit(0);
