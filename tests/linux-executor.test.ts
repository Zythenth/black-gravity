import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants as fsConstants, existsSync, lstatSync, openSync, readFileSync, readlinkSync, readSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CliAdapter } from '../src/cli-adapter.js';
import { loadConfig } from '../src/config.js';
import type { ExecutionAdapter, ExecutionRequest, ExecutionResult } from '../src/execution-contract.js';
import { buildBwrapArgs, buildUnixSocketSeccompFilter, detectBubblewrap, executeLinuxTest, findFifoInTrees, LINUX_SYSTEM_ROOTS, parseBwrapStatus, selectToolchainAliases, type BwrapSyncRunner } from '../src/linux-executor.js';
import { TaskManager } from '../src/task-manager.js';
import { ControlledCliAdapter } from './controlled-cli-adapter.js';

const mockPath = fileURLToPath(new URL('../../tests/mock-agy.mjs', import.meta.url));
const requireBwrap = process.env.BLACK_GRAVITY_REQUIRE_BWRAP === '1';
const hostDetection = process.platform === 'linux' ? detectBubblewrap() : undefined;
const done = (status: string) => ['completed', 'failed', 'cancelled', 'timeout'].includes(status);

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

async function hashDirectory(root: string): Promise<string> {
  const hash = createHash('sha256');
  const walk = async (dir: string, prefix: string): Promise<void> => {
    const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        hash.update(`D:${rel}\0`);
        await walk(full, rel);
      } else if (entry.isFile()) {
        hash.update(`F:${rel}\0`);
        hash.update(await readFile(full));
        hash.update('\0');
      } else {
        hash.update(`O:${rel}\0`);
      }
    }
  };
  await walk(root, '');
  return hash.digest('hex');
}

async function fixture<T>(run: (copy: string, outside: string, source: string, state: string) => Promise<T>): Promise<T> {
  const temp = await realpath(os.tmpdir());
  const copy = await realpath(await mkdtemp(path.join(temp, 'black-gravity-copy-')));
  const outside = await realpath(await mkdtemp(path.join(temp, 'black-gravity-private-')));
  const source = await realpath(await mkdtemp(path.join(temp, 'black-gravity-source-')));
  const state = await realpath(await mkdtemp(path.join(temp, 'black-gravity-state-')));
  try {
    await writeFile(path.join(copy, 'source.txt'), 'original');
    await writeFile(path.join(outside, 'private.txt'), 'private marker');
    await writeFile(path.join(source, 'project.txt'), 'source marker');
    await writeFile(path.join(state, 'secret-state.txt'), 'SECRET_STATE_MARKER_XYZ');
    return await run(copy, outside, source, state);
  } finally {
    for (const [directory, prefix] of [
      [copy, 'black-gravity-copy-'],
      [outside, 'black-gravity-private-'],
      [source, 'black-gravity-source-'],
      [state, 'black-gravity-state-'],
    ] as const) {
      assert.equal(path.dirname(directory), temp);
      assert.ok(path.basename(directory).startsWith(prefix));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
}

async function waitFor(tasks: TaskManager, taskId: string, timeout = 60000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const current = tasks.status(taskId);
    if (done(current.status)) return current;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for task ' + taskId);
}

test('Config parses BRIDGE_TEST_EXECUTOR=linux-bwrap and tracks explicitness', () => {
  const explicitLinux = loadConfig({ BRIDGE_TEST_EXECUTOR: 'linux-bwrap' });
  assert.equal(explicitLinux.testExecutor, 'linux-bwrap');
  assert.equal(explicitLinux.testExecutorExplicit, true);

  const explicitAgy = loadConfig({ BRIDGE_TEST_EXECUTOR: 'agy' });
  assert.equal(explicitAgy.testExecutor, 'agy');
  assert.equal(explicitAgy.testExecutorExplicit, true);

  const implicit = loadConfig({});
  assert.equal(implicit.testExecutor, process.platform === 'win32' ? 'windows-lpac' : 'agy');
  assert.equal(implicit.testExecutorExplicit, false);

  assert.throws(() => loadConfig({ BRIDGE_TEST_EXECUTOR: 'invalid-backend' }), /BRIDGE_TEST_EXECUTOR must be agy, windows-lpac, or linux-bwrap/);
});

test('detectBubblewrap returns unsupported-platform on non-Linux and LINUX_BWRAP_MISSING when binary is missing or PATH is relative', () => {
  const win = detectBubblewrap({ platform: 'win32' });
  assert.equal(win.available, false);
  assert.equal(win.reason, 'unsupported-platform');

  const mac = detectBubblewrap({ platform: 'darwin' });
  assert.equal(mac.available, false);
  assert.equal(mac.reason, 'unsupported-platform');

  const missingPath = detectBubblewrap({ platform: 'linux', bwrapPath: '/nonexistent/black-gravity-missing/bwrap' });
  assert.equal(missingPath.available, false);
  assert.equal(missingPath.code, 'LINUX_BWRAP_MISSING');

  const relativePathEnv = detectBubblewrap({ platform: 'linux', env: { PATH: 'relative/bin:./local/bin' } });
  assert.equal(relativePathEnv.available, false);
  assert.equal(relativePathEnv.code, 'LINUX_BWRAP_MISSING');
});

test('detectBubblewrap maps failing namespace probe to LINUX_USER_NAMESPACES_BLOCKED with redacted reason', () => {
  const calls: string[][] = [];
  const runner: BwrapSyncRunner = (_file, args) => {
    calls.push([...args]);
    if (args[0] === '--version') {
      return { status: 0, signal: null, stdout: 'bubblewrap 0.9.0\n', stderr: '' };
    }
    return {
      status: 1,
      signal: null,
      stdout: '',
      stderr: 'bwrap: setting up uid map: Permission denied Bearer secret-token-value\n',
    };
  };
  const blocked = detectBubblewrap({ platform: 'linux', bwrapPath: '/usr/bin/bwrap', runner });
  assert.equal(blocked.available, false);
  assert.equal(blocked.path, '/usr/bin/bwrap');
  assert.equal(blocked.version, 'bubblewrap 0.9.0');
  assert.equal(blocked.code, 'LINUX_USER_NAMESPACES_BLOCKED');
  assert.match(blocked.reason ?? '', /Permission denied/);
  assert.doesNotMatch(blocked.reason ?? '', /secret-token-value/);
  assert.equal(calls.length, 2);
  assert.ok(calls[1]!.includes('--unshare-all'));
  assert.ok(calls[1]!.includes('--unshare-user'));
  assert.equal(calls[1]!.indexOf('--unshare-user'), calls[1]!.indexOf('--unshare-all') + 1);
  assert.ok(calls[1]!.includes('--die-with-parent'));
  const trueIdx = calls[1]!.indexOf('true');
  assert.ok(trueIdx >= 3);
  assert.deepEqual(
    calls[1]!.slice(trueIdx - 3, trueIdx + 1),
    ['--setenv', 'PATH', '/usr/sbin:/usr/bin:/sbin:/bin', 'true'],
  );

  const okRunner: BwrapSyncRunner = (_file, args) => ({
    status: 0,
    signal: null,
    stdout: args[0] === '--version' ? 'bubblewrap 0.9.0\n' : '',
    stderr: '',
  });
  const ok = detectBubblewrap({ platform: 'linux', bwrapPath: '/usr/bin/bwrap', runner: okRunner });
  assert.deepEqual(ok, { available: true, path: '/usr/bin/bwrap', version: 'bubblewrap 0.9.0' });
});

test('buildBwrapArgs places system roots, tmpfs mounts, toolchains after /tmp and /run, masks, and isolation flags in order', () => {
  const argsDefault = buildBwrapArgs({
    command: { executable: 'node', args: ['-e', 'console.log(1)'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: ['/data/read'], writePaths: ['/data/write'], network: false, childProcesses: true, maxOutputChars: 4000 },
    toolchainPaths: ['/home/user/.nvm/versions/node/v24.0.0', '/custom/toolchain/bin'],
    toolchainAliases: [{ source: '/opt/node/bin', destination: '/home/user/node-bin' }],
    protectedDirs: ['/var/lib/bg-state', '/srv/source-project'],
    hostRuntimeDirectory: '/var/lib/xdg-runtime',
    resolvConfPath: '/run/systemd/resolve/stub-resolv.conf',
    statusFd: 3,
    environment: { PATH: '/usr/bin', HOME: '/tmp/black-gravity-scratch-1', TMPDIR: '/tmp/black-gravity-scratch-1' },
  });
  assert.equal(argsDefault[0], '--json-status-fd');
  assert.equal(argsDefault[1], '3');
  assert.ok(argsDefault.includes('--unshare-all'));
  assert.ok(argsDefault.includes('--unshare-user'));
  assert.equal(argsDefault.indexOf('--unshare-user'), argsDefault.indexOf('--unshare-all') + 1);
  assert.ok(!argsDefault.includes('--unshare-user-try'));
  assert.ok(argsDefault.includes('--die-with-parent'));
  assert.ok(argsDefault.includes('--new-session'));
  assert.ok(!argsDefault.includes('--share-net'));
  assert.ok(!argsDefault.some((arg, idx) => (arg === '--bind' || arg === '--ro-bind' || arg === '--ro-bind-try') && argsDefault[idx + 1] === '/'));
  assert.ok(!argsDefault.includes('/run/systemd/resolve/stub-resolv.conf'));

  const newSessionIdx = argsDefault.indexOf('--new-session');
  let cursor = newSessionIdx + 1;
  for (const root of LINUX_SYSTEM_ROOTS) {
    assert.deepEqual(argsDefault.slice(cursor, cursor + 3), ['--ro-bind-try', root, root]);
    cursor += 3;
  }
  assert.deepEqual(
    argsDefault.slice(cursor, cursor + 8),
    ['--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/run'],
  );
  const tmpMountIdx = cursor + 5;
  const runMountIdx = cursor + 7;
  cursor += 8;
  assert.deepEqual(argsDefault.slice(cursor, cursor + 2), ['--tmpfs', '/var/lib/xdg-runtime']);
  const runtimeMountIdx = cursor + 1;
  cursor += 2;
  for (const toolchainPath of ['/home/user/.nvm/versions/node/v24.0.0', '/custom/toolchain/bin']) {
    assert.deepEqual(argsDefault.slice(cursor, cursor + 3), ['--ro-bind-try', toolchainPath, toolchainPath]);
    cursor += 3;
  }
  assert.deepEqual(argsDefault.slice(cursor, cursor + 3), ['--ro-bind-try', '/opt/node/bin', '/home/user/node-bin']);
  cursor += 3;
  assert.deepEqual(
    argsDefault.slice(cursor, cursor + 4),
    ['--tmpfs', '/var/lib/bg-state', '--tmpfs', '/srv/source-project'],
  );
  const sourceMountIdx = cursor + 3;
  cursor += 4;

  const copyBindIdx = argsDefault.indexOf('/tmp/black-gravity-copy-1');
  const scratchBindIdx = argsDefault.indexOf('/tmp/black-gravity-scratch-1');
  const readIdx = argsDefault.indexOf('/data/read');
  const writeIdx = argsDefault.indexOf('/data/write');
  const firstRemountIdx = argsDefault.indexOf('--remount-ro');
  const chdirIdx = argsDefault.indexOf('--chdir');
  assert.equal(argsDefault[tmpMountIdx], '/tmp');
  assert.equal(argsDefault[runMountIdx], '/run');
  assert.equal(argsDefault[runtimeMountIdx], '/var/lib/xdg-runtime');
  assert.ok(copyBindIdx > sourceMountIdx);
  assert.equal(argsDefault[copyBindIdx - 1], '--bind');
  assert.ok(scratchBindIdx > copyBindIdx + 1 && argsDefault[scratchBindIdx - 1] === '--bind');
  assert.ok(readIdx > scratchBindIdx + 1 && argsDefault[readIdx - 1] === '--ro-bind');
  assert.ok(writeIdx > readIdx + 1 && argsDefault[writeIdx - 1] === '--bind');
  assert.ok(firstRemountIdx > writeIdx + 1);
  assert.ok(chdirIdx > firstRemountIdx);
  assert.deepEqual(
    argsDefault.slice(writeIdx + 2, chdirIdx),
    [
      '--remount-ro', '/run',
      '--remount-ro', '/var/lib/xdg-runtime',
      '--remount-ro', '/var/lib/bg-state',
      '--remount-ro', '/srv/source-project',
      '--remount-ro', '/',
    ],
  );
  assert.ok(!argsDefault.some((arg, idx) => arg === '--remount-ro' && argsDefault[idx + 1] === '/tmp'));
  assert.deepEqual(argsDefault.slice(chdirIdx - 2, chdirIdx + 2), ['--remount-ro', '/', '--chdir', '/tmp/black-gravity-copy-1']);

  const argsInsideRunOrTmp = buildBwrapArgs({
    command: { executable: 'node', args: ['--version'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: [], writePaths: [], network: false, childProcesses: true, maxOutputChars: 4000 },
    hostRuntimeDirectory: '/run/user/1000',
    environment: { PATH: '/usr/bin' },
  });
  assert.ok(!argsInsideRunOrTmp.includes('/run/user/1000'));

  const argsInsideTmp = buildBwrapArgs({
    command: { executable: 'node', args: ['--version'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: [], writePaths: [], network: false, childProcesses: true, maxOutputChars: 4000 },
    hostRuntimeDirectory: '/tmp/xdg-runtime',
    environment: { PATH: '/usr/bin' },
  });
  assert.ok(!argsInsideTmp.includes('/tmp/xdg-runtime'));

  const argsNet = buildBwrapArgs({
    command: { executable: 'node', args: ['--version'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: [], writePaths: [], network: true, childProcesses: true, maxOutputChars: 4000 },
    hostRuntimeDirectory: '/var/lib/xdg-runtime',
    resolvConfPath: '/run/systemd/resolve/stub-resolv.conf',
    toolchainPaths: ['/tmp/node-bin'],
    toolchainAliases: [{ source: '/opt/node/bin', destination: '/tmp/alias-bin' }],
    protectedDirs: ['/var/lib/bg-state'],
    environment: { PATH: '/usr/bin' },
  });
  assert.ok(argsNet.includes('--share-net'));
  const netRunIdx = argsNet.indexOf('/run');
  const netRuntimeIdx = argsNet.indexOf('/var/lib/xdg-runtime');
  const resolvPathIdx = argsNet.indexOf('/run/systemd/resolve/stub-resolv.conf');
  const netToolchainIdx = argsNet.indexOf('/tmp/node-bin');
  const netAliasIdx = argsNet.indexOf('/tmp/alias-bin');
  const netProtectedIdx = argsNet.indexOf('/var/lib/bg-state');
  const netCopyIdx = argsNet.indexOf('/tmp/black-gravity-copy-1');
  const netScratchIdx = argsNet.indexOf('/tmp/black-gravity-scratch-1');
  const netRemountRunIdx = argsNet.indexOf('--remount-ro', netRunIdx);
  const netChdirIdx = argsNet.indexOf('--chdir');
  assert.ok(netRuntimeIdx > netRunIdx);
  assert.ok(resolvPathIdx > netRuntimeIdx);
  assert.equal(argsNet[resolvPathIdx - 1], '--ro-bind-try');
  assert.equal(argsNet[resolvPathIdx + 1], '/run/systemd/resolve/stub-resolv.conf');
  assert.ok(netToolchainIdx > resolvPathIdx + 1);
  assert.equal(argsNet[netToolchainIdx - 1], '--ro-bind-try');
  assert.ok(netAliasIdx > netToolchainIdx + 1);
  assert.equal(argsNet[netAliasIdx - 2], '--ro-bind-try');
  assert.equal(argsNet[netAliasIdx - 1], '/opt/node/bin');
  assert.ok(netProtectedIdx > netAliasIdx);
  assert.equal(argsNet[netProtectedIdx - 1], '--tmpfs');
  assert.ok(netCopyIdx > netProtectedIdx);
  assert.ok(netScratchIdx > netCopyIdx + 1);
  assert.ok(netRemountRunIdx > netScratchIdx + 1);
  assert.deepEqual(
    argsNet.slice(netRemountRunIdx, netChdirIdx),
    ['--remount-ro', '/run', '--remount-ro', '/var/lib/xdg-runtime', '--remount-ro', '/var/lib/bg-state', '--remount-ro', '/'],
  );
});

test('buildBwrapArgs recreates host-symlink system roots with --symlink instead of --ro-bind-try', () => {
  const args = buildBwrapArgs({
    command: { executable: 'node', args: ['--version'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: [], writePaths: [], network: false, childProcesses: true, maxOutputChars: 4000 },
    systemRootSymlinks: [{ path: '/lib', target: 'usr/lib' }],
    environment: { PATH: '/usr/bin' },
  });
  let cursor = args.indexOf('--new-session') + 1;
  for (const root of LINUX_SYSTEM_ROOTS) {
    if (root === '/lib') {
      assert.deepEqual(args.slice(cursor, cursor + 3), ['--symlink', 'usr/lib', '/lib']);
    } else {
      assert.deepEqual(args.slice(cursor, cursor + 3), ['--ro-bind-try', root, root]);
    }
    cursor += 3;
  }
  assert.ok(!args.some((arg, idx) => arg === '--ro-bind-try' && args[idx + 1] === '/lib' && args[idx + 2] === '/lib'));
  assert.ok(args.some((arg, idx) => arg === '--ro-bind-try' && args[idx + 1] === '/usr' && args[idx + 2] === '/usr'));
});

test('buildBwrapArgs rejects toolchainPaths and toolchainAliases overlapping /proc, /dev, or /sys', () => {
  const args = buildBwrapArgs({
    command: { executable: 'node', args: ['--version'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: [], writePaths: [], network: false, childProcesses: true, maxOutputChars: 4000 },
    toolchainPaths: ['/proc', '/dev/shm', '/sys'],
    toolchainAliases: [
      { source: '/proc/self', destination: '/home/u/proc-alias' },
      { source: '/opt/sdk', destination: '/proc/self' },
      { source: '/dev/shm/bin', destination: '/home/u/dev-alias' },
      { source: '/opt/sdk', destination: '/dev/shm/bin' },
      { source: '/sys/fs/bin', destination: '/home/u/sys-alias' },
      { source: '/opt/sdk', destination: '/sys/fs/bin' },
    ],
    environment: { PATH: '/usr/bin' },
  });
  const roBindTryTargets = args.flatMap((arg, idx) =>
    arg === '--ro-bind-try' ? [[args[idx + 1], args[idx + 2]]] : [],
  );
  for (const forbidden of [
    '/proc',
    '/proc/self',
    '/dev/shm',
    '/dev/shm/bin',
    '/sys',
    '/sys/fs/bin',
    '/home/u/proc-alias',
    '/home/u/dev-alias',
    '/home/u/sys-alias',
    '/opt/sdk',
  ]) {
    assert.ok(
      !roBindTryTargets.some(([src, dst]) => src === forbidden || dst === forbidden),
      `Unexpected --ro-bind-try targeting ${forbidden}`,
    );
  }
  assert.ok(args.some((arg, idx) => arg === '--dev' && args[idx + 1] === '/dev'));
  assert.ok(args.some((arg, idx) => arg === '--proc' && args[idx + 1] === '/proc'));
});

test('selectToolchainAliases enforces overlap and boundary rules for sources and destinations', () => {
  assert.deepEqual(
    selectToolchainAliases({
      candidates: [{ original: '/home/u/sdk-bin', real: '/opt/sdk' }],
      toolchainPaths: [],
      homeRoots: ['/home/u'],
      cwd: '/tmp/black-gravity-copy-1',
      protectedPaths: ['/opt/sdk/state'],
    }),
    [],
  );

  assert.deepEqual(
    selectToolchainAliases({
      candidates: [{ original: '/home/u/sdk-bin', real: '/opt/sdk' }],
      toolchainPaths: [],
      homeRoots: ['/home/u'],
      cwd: '/tmp/black-gravity-copy-1',
      protectedPaths: ['/srv/state'],
    }),
    [{ source: '/opt/sdk', destination: '/home/u/sdk-bin' }],
  );

  assert.deepEqual(
    selectToolchainAliases({
      candidates: [
        { original: '/home/u/copy-equal', real: '/tmp/black-gravity-copy-1' },
        { original: '/home/u/copy-parent', real: '/tmp' },
        { original: '/home/u/copy-child', real: '/tmp/black-gravity-copy-1/bin' },
      ],
      toolchainPaths: [],
      homeRoots: ['/home/u'],
      cwd: '/tmp/black-gravity-copy-1',
      protectedPaths: [],
    }),
    [],
  );

  assert.deepEqual(
    selectToolchainAliases({
      candidates: [
        { original: '/usr/local/sdk-bin', real: '/srv/sdk' },
        { original: '/opt/sdk-alias', real: '/srv/sdk' },
        { original: '/custom/toolchain/bin', real: '/srv/sdk' },
        { original: '/home', real: '/srv/sdk' },
        { original: '/srv/home-alias', real: '/home' },
        { original: '/home/u/same', real: '/home/u/same' },
        { original: '/home/u/dup-bin', real: '/opt/first' },
        { original: '/home/u/dup-bin', real: '/opt/second' },
      ],
      toolchainPaths: ['/custom/toolchain'],
      homeRoots: ['/home/u'],
      cwd: '/tmp/black-gravity-copy-1',
      protectedPaths: ['/srv/state'],
    }),
    [{ source: '/opt/first', destination: '/home/u/dup-bin' }],
  );

  assert.deepEqual(
    selectToolchainAliases({
      candidates: [
        { original: '/home/u/tmp-src', real: '/tmp' },
        { original: '/tmp', real: '/opt/sdk' },
        { original: '/home/u/run-src', real: '/run' },
        { original: '/run', real: '/opt/sdk' },
        { original: '/home/u/root-src', real: '/' },
        { original: '/', real: '/opt/sdk' },
        { original: '/home/u/xdg-src-eq', real: '/var/lib/xdg-runtime' },
        { original: '/home/u/xdg-src-parent', real: '/var/lib' },
        { original: '/home/u/xdg-src-child', real: '/var/lib/xdg-runtime/bin' },
        { original: '/var/lib/xdg-runtime', real: '/opt/sdk' },
        { original: '/var/lib', real: '/opt/sdk' },
        { original: '/var/lib/xdg-runtime/bin', real: '/opt/sdk' },
        { original: '/home/u/proc-src', real: '/proc' },
        { original: '/proc', real: '/opt/sdk' },
        { original: '/home/u/proc-self-src', real: '/proc/self' },
        { original: '/proc/self', real: '/opt/sdk' },
        { original: '/home/u/dev-src', real: '/dev' },
        { original: '/dev', real: '/opt/sdk' },
        { original: '/home/u/dev-shm-src', real: '/dev/shm' },
        { original: '/dev/shm', real: '/opt/sdk' },
        { original: '/home/u/sys-src', real: '/sys' },
        { original: '/sys', real: '/opt/sdk' },
        { original: '/home/u/sys-fs-src', real: '/sys/fs' },
        { original: '/sys/fs', real: '/opt/sdk' },
        { original: '/tmp/node-bin', real: '/opt/node/bin' },
      ],
      toolchainPaths: [],
      homeRoots: ['/home/u'],
      cwd: '/tmp/black-gravity-copy-1',
      protectedPaths: ['/srv/state'],
      hostRuntimeDirectory: '/var/lib/xdg-runtime',
    }),
    [{ source: '/opt/node/bin', destination: '/tmp/node-bin' }],
  );
});

test('buildBwrapArgs emits --seccomp right before --chdir only when seccompFd is provided', () => {
  const baseInput = {
    command: { executable: 'node', args: ['--version'] },
    copyDirectory: '/tmp/black-gravity-copy-1',
    scratchDirectory: '/tmp/black-gravity-scratch-1',
    sandbox: { readPaths: [], writePaths: [], network: false, childProcesses: true, maxOutputChars: 4000 },
    environment: { PATH: '/usr/bin' },
  };
  const withoutSeccomp = buildBwrapArgs(baseInput);
  assert.ok(!withoutSeccomp.includes('--seccomp'));

  const withSeccomp = buildBwrapArgs({ ...baseInput, seccompFd: 4 });
  const chdirIdx = withSeccomp.indexOf('--chdir');
  assert.ok(chdirIdx >= 2);
  assert.deepEqual(withSeccomp.slice(chdirIdx - 2, chdirIdx + 1), ['--seccomp', '4', '--chdir']);
});

function runClassicBpf(program: Buffer, seccompData: Buffer): number {
  assert.equal(program.length % 8, 0);
  const insnCount = program.length / 8;
  let acc = 0;
  let pc = 0;
  let steps = 0;
  while (pc < insnCount) {
    assert.ok(steps < insnCount, 'BPF program exceeded instruction count');
    steps += 1;
    const offset = pc * 8;
    const code = program.readUInt16LE(offset);
    const jt = program.readUInt8(offset + 2);
    const jf = program.readUInt8(offset + 3);
    const k = program.readUInt32LE(offset + 4);
    pc += 1;
    if (code === 0x20) {
      assert.ok(k + 4 <= seccompData.length);
      acc = seccompData.readUInt32LE(k);
    } else if (code === 0x54) {
      acc = (acc & k) >>> 0;
    } else if (code === 0x15) {
      pc += acc === k ? jt : jf;
    } else if (code === 0x35) {
      pc += acc >= k ? jt : jf;
    } else if (code === 0x06) {
      return k;
    } else {
      assert.fail(`Unsupported BPF opcode: 0x${code.toString(16)}`);
    }
  }
  assert.fail('BPF program exited without BPF_RET');
}

function makeSeccompData(arch: number, nr: number, arg0 = 0, arg1 = 0): Buffer {
  const data = Buffer.alloc(64);
  data.writeUInt32LE(nr >>> 0, 0);
  data.writeUInt32LE(arch >>> 0, 4);
  data.writeUInt32LE(arg0 >>> 0, 16);
  data.writeUInt32LE(arg1 >>> 0, 24);
  return data;
}

test('buildUnixSocketSeccompFilter blocks AF_UNIX socket, io_uring_setup, x32, and foreign arches while allowing socketpair and AF_INET', () => {
  const SECCOMP_RET_ALLOW = 0x7fff0000;
  const ERR_EAFNOSUPPORT = (0x00050000 | 97) >>> 0;
  const ERR_ENOSYS = (0x00050000 | 38) >>> 0;
  const AUDIT_ARCH_I386 = 0x40000003;
  const AF_UNIX = 1;
  const AF_INET = 2;
  const SOCK_STREAM = 1;
  const SOCK_DGRAM = 2;
  const SOCK_RAW = 3;
  const SOCK_RDM = 4;
  const SOCK_SEQPACKET = 5;
  const SOCK_NONBLOCK = 0x800;
  const SOCK_CLOEXEC = 0x80000;

  const cases = [
    { arch: 'x64', auditArch: 0xc000003e, socketNr: 41, socketpairNr: 53, ioUringSetupNr: 425, readNr: 0 },
    { arch: 'arm64', auditArch: 0xc00000b7, socketNr: 198, socketpairNr: 199, ioUringSetupNr: 425, readNr: 63 },
  ] as const;

  for (const spec of cases) {
    const filter = buildUnixSocketSeccompFilter(spec.arch);
    assert.ok(Buffer.isBuffer(filter));
    assert.ok(filter.length > 0 && filter.length % 8 === 0);

    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketNr, AF_UNIX)), ERR_EAFNOSUPPORT);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketNr, AF_INET)), SECCOMP_RET_ALLOW);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX)), ERR_EAFNOSUPPORT);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_STREAM)), SECCOMP_RET_ALLOW);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)), SECCOMP_RET_ALLOW);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_SEQPACKET)), SECCOMP_RET_ALLOW);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)), SECCOMP_RET_ALLOW);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_DGRAM)), ERR_EAFNOSUPPORT);
    assert.equal(
      runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK)),
      ERR_EAFNOSUPPORT,
    );
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_RAW)), ERR_EAFNOSUPPORT);
    assert.equal(
      runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK)),
      ERR_EAFNOSUPPORT,
    );
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.socketpairNr, AF_UNIX, SOCK_RDM)), ERR_EAFNOSUPPORT);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.ioUringSetupNr, 0)), ERR_ENOSYS);
    assert.equal(runClassicBpf(filter, makeSeccompData(spec.auditArch, spec.readNr, 0)), SECCOMP_RET_ALLOW);
    assert.equal(runClassicBpf(filter, makeSeccompData(AUDIT_ARCH_I386, spec.socketNr, AF_UNIX)), ERR_ENOSYS);
  }

  const x64Filter = buildUnixSocketSeccompFilter('x64')!;
  assert.equal(runClassicBpf(x64Filter, makeSeccompData(0xc000003e, 0x40000000 | 41, AF_UNIX)), ERR_ENOSYS);
  assert.equal(buildUnixSocketSeccompFilter('ia32'), undefined);
});

test('parseBwrapStatus parses valid status lines and ignores garbage or empty input', () => {
  assert.deepEqual(parseBwrapStatus(''), {});
  assert.deepEqual(parseBwrapStatus('   \n\t\r\n'), {});
  assert.deepEqual(
    parseBwrapStatus('{"child-pid": 4321}\n{"exit-code": 0}\n'),
    { childPid: 4321, exitCode: 0 },
  );
  assert.deepEqual(
    parseBwrapStatus('not-json\n{broken\n[]\n42\n{"child-pid":"99","exit-code":null}\n{"child-pid":777}\n{"exit-code":2}\n'),
    { childPid: 777, exitCode: 2 },
  );
});

test('findFifoInTrees scans nested directories without FIFOs and enforces maxEntries', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'black-gravity-fifo-unit-')));
  try {
    const nested = path.join(root, 'a', 'b');
    await mkdir(nested, { recursive: true });
    await writeFile(path.join(root, 'top.txt'), 'top');
    await writeFile(path.join(nested, 'leaf.txt'), 'leaf');

    assert.deepEqual(await findFifoInTrees([root], 100), {});
    assert.deepEqual(await findFifoInTrees([root], 1), { limitExceeded: true });
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('findFifoInTrees detects nested FIFOs and does not follow directory symlinks', async t => {
  if (process.platform !== 'linux') {
    t.skip('FIFO unit test requires Linux');
    return;
  }
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'black-gravity-fifo-linux-')));
  try {
    const nestedDir = path.join(root, 'scan', 'nested');
    await mkdir(nestedDir, { recursive: true });
    const fifoPath = path.join(nestedDir, 'pipe.fifo');
    execFileSync('mkfifo', [fifoPath]);

    assert.deepEqual(await findFifoInTrees([path.join(root, 'scan')], 100), { fifo: fifoPath });
    assert.deepEqual(await findFifoInTrees([fifoPath], 100), { fifo: fifoPath });

    const symlinkTree = path.join(root, 'via-symlink');
    await mkdir(symlinkTree, { recursive: true });
    await symlink(nestedDir, path.join(symlinkTree, 'linked-dir'));
    assert.deepEqual(await findFifoInTrees([symlinkTree], 100), {});
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('findFifoInTrees reports unlistable and non-traversable directories as uninspectable', async t => {
  if (process.platform !== 'linux') {
    t.skip('FIFO unit test requires Linux');
    return;
  }
  if (process.getuid?.() === 0) {
    t.skip('Permission checks are bypassed when running as root');
    return;
  }
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'black-gravity-fifo-perm-')));
  const locked = path.join(root, 'locked');
  try {
    await mkdir(locked, { recursive: true });
    const fifoPath = path.join(locked, 'pipe.fifo');
    execFileSync('mkfifo', [fifoPath]);

    await chmod(locked, 0o311);
    assert.deepEqual(await findFifoInTrees([root], 100), { uninspectable: locked });

    await chmod(locked, 0o000);
    assert.deepEqual(await findFifoInTrees([root], 100), { uninspectable: locked });
  } finally {
    await chmod(locked, 0o755).catch(() => {});
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('executeLinuxTest aborts before spawning when signal is aborted during preparation', async () => {
  await fixture(async (copy, _outside, _source, state) => {
    const controller = new AbortController();
    let spawned = false;
    const promise = executeLinuxTest(
      { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
      copy,
      {
        timeoutSeconds: 10,
        stateDirectory: state,
        detection: { available: true, path: '/nonexistent/bwrap', version: 'bubblewrap 0.9.0' },
        signal: controller.signal,
        onProcess: () => {
          spawned = true;
        },
      },
    );
    controller.abort();
    const result = await promise;
    assert.equal(spawned, false);
    assert.equal(result.error, 'Command cancelled');
    assert.equal(result.exitCode, null);
    assert.equal(result.processesReaped, true);
    assert.equal(result.output, '');
    assert.equal(result.sandboxStarted, false);
  });
});

test('executeLinuxTest refuses childProcesses=false and unavailable detection without spawning', async () => {
  await fixture(async copy => {
    await assert.rejects(
      executeLinuxTest(
        { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
        copy,
        {
          timeoutSeconds: 10,
          detection: { available: true, path: '/usr/bin/bwrap', version: 'bubblewrap 0.9.0' },
          sandbox: { readPaths: [], writePaths: [], network: false, childProcesses: false, maxOutputChars: 4000 },
        },
      ),
      { code: 'SANDBOX_PERMISSIONS_UNSUPPORTED' },
    );

    await assert.rejects(
      executeLinuxTest(
        { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
        copy,
        {
          timeoutSeconds: 10,
          detection: { available: false, code: 'LINUX_USER_NAMESPACES_BLOCKED', reason: 'blocked in test' },
        },
      ),
      { code: 'LINUX_USER_NAMESPACES_BLOCKED' },
    );
  });
});

test('TaskManager startTests refuses before queuing when linux-bwrap detection is unavailable and starts nothing', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'black-gravity-linux-refusal-')));
  const source = path.join(root, 'source');
  const stateMissing = path.join(root, 'state-missing');
  const stateBlocked = path.join(root, 'state-blocked');
  await mkdir(source, { recursive: true });
  execFileSync('git', ['init', '--quiet', source]);
  await writeFile(path.join(source, 'source.txt'), 'original\n');

  let execCalls = 0;
  const fakeExecutor: ExecutionAdapter = {
    identity: {
      provider: 'agy',
      id: 'fake-agy',
      version: '1.0.0',
    },
    capabilities: { read: 'supported', write: 'supported', sandbox: 'supported', structuredOutput: 'supported', resume: 'supported' },
    async execute(request: ExecutionRequest): Promise<ExecutionResult> {
      execCalls += 1;
      return {
        taskId: request.taskId,
        status: 'completed',
        session: { id: 'session-1' },
        response: 'done',
      };
    },
  };

  const makeTasks = (stateDir: string, detection: { available: boolean; code?: string; reason?: string }) => {
    const config = loadConfig({
      BRIDGE_ANTI_AI_CRAFT: 'off',
      BRIDGE_STATE_DIRECTORY: stateDir,
      BRIDGE_TEST_EXECUTOR: 'linux-bwrap',
    });
    const adapter = new ControlledCliAdapter(config);
    return new TaskManager(adapter, config, fakeExecutor, { linuxBwrapDetection: detection });
  };

  const tasksMissing = makeTasks(stateMissing, { available: false, code: 'LINUX_BWRAP_MISSING', reason: 'bwrap not installed' });
  const tasksBlocked = makeTasks(stateBlocked, { available: false, code: 'LINUX_USER_NAMESPACES_BLOCKED', reason: 'AppArmor denied userns' });
  try {
    const initial = await tasksMissing.run({ prompt: 'Initial edit', workingDirectory: source });
    const completed = await waitFor(tasksMissing, initial.taskId);
    assert.equal(completed.status, 'completed');
    assert.equal(execCalls, 1);
    const preview = await tasksMissing.preview(completed.taskId, false);
    const copyBefore = await hashDirectory(completed.copyDirectory!);

    await assert.rejects(
      () => tasksMissing.startTests(completed.taskId, preview.sha256, { executable: process.execPath, args: ['-e', 'process.exit(0)'] }),
      { code: 'LINUX_BWRAP_MISSING' },
    );
    assert.equal(tasksMissing.list().length, 1);
    assert.equal(execCalls, 1);
    assert.equal(await hashDirectory(completed.copyDirectory!), copyBefore);

    const initial2 = await tasksBlocked.run({ prompt: 'Initial edit', workingDirectory: source });
    const completed2 = await waitFor(tasksBlocked, initial2.taskId);
    const preview2 = await tasksBlocked.preview(completed2.taskId, false);
    const copyBefore2 = await hashDirectory(completed2.copyDirectory!);

    await assert.rejects(
      () => tasksBlocked.startTests(completed2.taskId, preview2.sha256, { executable: process.execPath, args: ['-e', 'process.exit(0)'] }),
      { code: 'LINUX_USER_NAMESPACES_BLOCKED' },
    );
    assert.equal(tasksBlocked.list().length, 1);
    assert.equal(execCalls, 2);
    assert.equal(await hashDirectory(completed2.copyDirectory!), copyBefore2);

    assert.deepEqual(tasksBlocked.testExecutorStatus(), {
      selected: 'linux-bwrap',
      explicit: true,
      linuxBwrap: { available: false, code: 'LINUX_USER_NAMESPACES_BLOCKED', reason: 'AppArmor denied userns' },
    });
  } finally {
    await tasksMissing.shutdown();
    await tasksBlocked.shutdown();
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor runs positive command and returns verified receipt', async t => {
  if (!requireLinuxBwrap(t)) return;
  await fixture(async (copy, _outside, source, state) => {
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', "const fs=require('node:fs');if(fs.readFileSync('source.txt','utf8')!=='original')process.exit(2);fs.writeFileSync('inside.txt','ok');console.log('bwrap-positive-ok');"] },
      copy,
      { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.processesReaped, true);
    assert.equal(result.truncated, false);
    assert.ok(result.bwrapVersion && result.bwrapVersion.length > 0);
    assert.match(result.output, /bwrap-positive-ok/);
    assert.equal(await readFile(path.join(copy, 'inside.txt'), 'utf8'), 'ok');
  });
});

test('Linux bwrap executor blocks writes outside copy to host temp and source directories', async t => {
  if (!requireLinuxBwrap(t)) return;
  const hostRoDir = await realpath(await mkdtemp(path.join(os.homedir(), 'black-gravity-ro-')));
  const hostRoExisting = path.join(hostRoDir, 'existing.txt');
  const hostRoNew = path.join(hostRoDir, 'escaped.txt');
  await writeFile(hostRoExisting, 'immutable-marker');
  try {
    await fixture(async (copy, outside, source, state) => {
      const copyBefore = await hashDirectory(copy);
      const outsideTarget = path.join(outside, 'escaped.txt');
      const sourceTarget = path.join(source, 'escaped.txt');
      const hostRoTarget = path.join(path.dirname(process.execPath), 'black-gravity-escaped.txt');
      const script =
        "const fs=require('node:fs');let failures=0;" +
        `for(const p of [${JSON.stringify(outsideTarget)},${JSON.stringify(sourceTarget)},${JSON.stringify(hostRoTarget)},${JSON.stringify(hostRoNew)},${JSON.stringify(hostRoExisting)},'/escaped.txt']){` +
        "let blocked=false;try{fs.writeFileSync(p,'pwned')}catch(e){blocked=['ENOENT','EACCES','EPERM','EROFS'].includes(e.code)}" +
        "if(!blocked){console.log('wrote:'+p);failures+=1}" +
        "}" +
        "if(failures>0)process.exit(3);" +
        "console.log('outside-writes-checked');";
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source, outside] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.processesReaped, true);
      assert.equal(result.sandboxStarted, true);
      assert.doesNotMatch(result.output, /wrote:/);
      assert.match(result.output, /outside-writes-checked/);
      await assert.rejects(readFile(outsideTarget), { code: 'ENOENT' });
      await assert.rejects(readFile(sourceTarget), { code: 'ENOENT' });
      await assert.rejects(readFile(hostRoNew), { code: 'ENOENT' });
      assert.deepEqual(await readdir(hostRoDir), ['existing.txt']);
      assert.equal(await readFile(hostRoExisting, 'utf8'), 'immutable-marker');
      assert.equal(await readFile(path.join(source, 'project.txt'), 'utf8'), 'source marker');
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    await rm(hostRoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor mounts external XDG_RUNTIME_DIR as read-only empty tmpfs', async t => {
  if (!requireLinuxBwrap(t)) return;
  const xdgDir = await realpath(await mkdtemp(path.join(os.homedir(), 'black-gravity-xdg-')));
  const existingFile = path.join(xdgDir, 'existing.txt');
  const newFile = path.join(xdgDir, 'escaped.txt');
  await writeFile(existingFile, 'xdg-immutable');
  const hadXdgRuntimeDir = Object.prototype.hasOwnProperty.call(process.env, 'XDG_RUNTIME_DIR');
  const previousXdgRuntimeDir = process.env.XDG_RUNTIME_DIR;
  process.env.XDG_RUNTIME_DIR = xdgDir;
  try {
    await fixture(async (copy, _outside, source, state) => {
      const copyBefore = await hashDirectory(copy);
      const script =
        "const fs=require('node:fs');" +
        `const target=${JSON.stringify(newFile)};` +
        "let blocked=false;try{fs.writeFileSync(target,'pwned')}catch(e){blocked=['EACCES','EPERM','EROFS','ENOENT'].includes(e.code)}" +
        "if(!blocked){console.log('wrote:'+target);process.exit(3)}" +
        "console.log('xdg-ro-ok');";
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.processesReaped, true);
      assert.equal(result.sandboxStarted, true);
      assert.doesNotMatch(result.output, /wrote:/);
      assert.match(result.output, /xdg-ro-ok/);
      assert.deepEqual(await readdir(xdgDir), ['existing.txt']);
      assert.equal(await readFile(existingFile, 'utf8'), 'xdg-immutable');
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    if (hadXdgRuntimeDir && previousXdgRuntimeDir !== undefined) {
      process.env.XDG_RUNTIME_DIR = previousXdgRuntimeDir;
    } else {
      delete process.env.XDG_RUNTIME_DIR;
    }
    await rm(xdgDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor masks nested state directories under external XDG_RUNTIME_DIR and /run/user/<uid>', async t => {
  if (!requireLinuxBwrap(t)) return;
  const verifyProtectedState = async (
    copy: string,
    source: string,
    stateDir: string,
    stateFile: string,
    expectedContent: string,
  ): Promise<void> => {
    const copyBefore = await hashDirectory(copy);
    const script =
      "const fs=require('node:fs');" +
      `const target=${JSON.stringify(stateFile)};` +
      "try{fs.readFileSync(target,'utf8');console.log('state-read')}catch{}" +
      "try{fs.writeFileSync(target,'tampered');console.log('state-wrote')}catch{}";
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', script] },
      copy,
      { timeoutSeconds: 15, stateDirectory: stateDir, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.processesReaped, true);
    assert.equal(result.sandboxStarted, true);
    assert.doesNotMatch(result.output, /state-read/);
    assert.doesNotMatch(result.output, /state-wrote/);
    assert.equal(await readFile(stateFile, 'utf8'), expectedContent);
    assert.equal(await hashDirectory(copy), copyBefore);
  };

  const xdgDir = await realpath(await mkdtemp(path.join(os.homedir(), 'black-gravity-xdg-state-')));
  let runStateBase: string | undefined;
  try {
    const xdgStateDir = path.join(xdgDir, 'state');
    await mkdir(xdgStateDir, { recursive: true });
    const xdgStateFile = path.join(xdgStateDir, 'secret-state.txt');
    await writeFile(xdgStateFile, 'XDG_NESTED_STATE_MARKER');

    await fixture(async (copy, _outside, source) => {
      const hadXdgRuntimeDir = Object.prototype.hasOwnProperty.call(process.env, 'XDG_RUNTIME_DIR');
      const previousXdgRuntimeDir = process.env.XDG_RUNTIME_DIR;
      process.env.XDG_RUNTIME_DIR = xdgDir;
      try {
        await verifyProtectedState(copy, source, xdgStateDir, xdgStateFile, 'XDG_NESTED_STATE_MARKER');
      } finally {
        if (hadXdgRuntimeDir && previousXdgRuntimeDir !== undefined) {
          process.env.XDG_RUNTIME_DIR = previousXdgRuntimeDir;
        } else {
          delete process.env.XDG_RUNTIME_DIR;
        }
      }

      if (typeof process.getuid === 'function') {
        const runUserDir = `/run/user/${process.getuid()}`;
        try {
          runStateBase = await realpath(await mkdtemp(path.join(runUserDir, 'black-gravity-run-state-')));
        } catch (error) {
          t.diagnostic(`Skipping /run/user/<uid> nested state test: ${runUserDir} is unavailable or not writable (${(error as Error).message})`);
        }
      } else {
        t.diagnostic('Skipping /run/user/<uid> nested state test: process.getuid is unavailable');
      }

      if (runStateBase) {
        const runStateDir = path.join(runStateBase, 'state');
        await mkdir(runStateDir, { recursive: true });
        const runStateFile = path.join(runStateDir, 'secret-state.txt');
        await writeFile(runStateFile, 'RUN_NESTED_STATE_MARKER');
        await verifyProtectedState(copy, source, runStateDir, runStateFile, 'RUN_NESTED_STATE_MARKER');
      }
    });
  } finally {
    if (runStateBase) {
      await rm(runStateBase, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
    await rm(xdgDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('detectBubblewrap succeeds when host PATH only contains a symlinked bin directory', async t => {
  if (!requireLinuxBwrap(t)) return;
  const initial = detectBubblewrap({ useCache: false });
  assert.equal(initial.available, true, JSON.stringify(initial));
  assert.ok(initial.path);

  const probeDir = await mkdtemp(path.join(os.homedir(), 'black-gravity-probe-'));
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  try {
    const probeBin = path.join(probeDir, 'bin');
    const bwrapDir = path.dirname(await realpath(initial.path));
    await symlink(bwrapDir, probeBin);
    process.env.PATH = probeBin;
    const detected = detectBubblewrap({ useCache: false });
    assert.equal(detected.available, true, JSON.stringify(detected));
  } finally {
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    await rm(probeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor resolves symlinked toolchain directories for absolute executables and PATH entries', async t => {
  if (!requireLinuxBwrap(t)) return;
  const aliasDir = await mkdtemp(path.join(os.homedir(), 'black-gravity-alias-'));
  const aliasBin = path.join(aliasDir, 'bin');
  const nodeBinDir = path.dirname(await realpath(process.execPath));
  await symlink(nodeBinDir, aliasBin);
  const detection = detectBubblewrap();
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  try {
    await fixture(async (copy, _outside, source, state) => {
      const copyBefore = await hashDirectory(copy);

      const absResult = await executeLinuxTest(
        { executable: path.join(aliasBin, 'node'), args: ['-e', "console.log('alias-ok')"] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(absResult.error, undefined, JSON.stringify(absResult));
      assert.equal(absResult.exitCode, 0, absResult.output);
      assert.equal(absResult.sandbox, 'linux-bwrap');
      assert.equal(absResult.processesReaped, true);
      assert.equal(absResult.sandboxStarted, true);
      assert.match(absResult.output, /alias-ok/);
      assert.equal(await hashDirectory(copy), copyBefore);

      process.env.PATH = aliasBin;
      const pathResult = await executeLinuxTest(
        { executable: 'node', args: ['-e', "console.log('alias-ok')"] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source], detection },
      );
      assert.equal(pathResult.error, undefined, JSON.stringify(pathResult));
      assert.equal(pathResult.exitCode, 0, pathResult.output);
      assert.equal(pathResult.sandbox, 'linux-bwrap');
      assert.equal(pathResult.processesReaped, true);
      assert.equal(pathResult.sandboxStarted, true);
      assert.match(pathResult.output, /alias-ok/);
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    await rm(aliasDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor recreates host-symlink system roots as symlinks inside the sandbox', async t => {
  if (!requireLinuxBwrap(t)) return;
  const hostSymlinks: { path: string; target: string }[] = [];
  for (const root of LINUX_SYSTEM_ROOTS) {
    try {
      if (lstatSync(root).isSymbolicLink()) {
        const target = readlinkSync(root);
        if (target && !target.includes('\0')) {
          hostSymlinks.push({ path: root, target });
        }
      }
    } catch {
      // Ignore missing or unreadable system roots.
    }
  }
  if (hostSymlinks.length === 0) {
    t.diagnostic('Skipping host-symlink system root test: no LINUX_SYSTEM_ROOTS entry is a symlink on this host');
    return;
  }

  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const roots = hostSymlinks.map(entry => entry.path);
    const script =
      "const fs=require('node:fs');" +
      `const entries=${JSON.stringify(roots)}.map(r=>({path:r,isSymlink:fs.lstatSync(r).isSymbolicLink(),target:fs.readlinkSync(r)}));` +
      'process.stdout.write(JSON.stringify(entries));';
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', script] },
      copy,
      { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.processesReaped, true);
    assert.equal(result.sandboxStarted, true);
    const observed = JSON.parse(result.output) as Array<{ path: string; isSymlink: boolean; target: string }>;
    assert.deepEqual(
      observed,
      hostSymlinks.map(entry => ({ path: entry.path, isSymlink: true, target: entry.target })),
    );
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor mounts toolchain aliases under /tmp after /tmp tmpfs for absolute executables and PATH entries', async t => {
  if (!requireLinuxBwrap(t)) return;
  const tmpRoot = await realpath(os.tmpdir());
  if (tmpRoot !== '/tmp' && !tmpRoot.startsWith('/tmp/')) {
    t.diagnostic(`Skipping /tmp toolchain alias test: os.tmpdir() (${tmpRoot}) is not under /tmp`);
    t.skip('os.tmpdir() is not under /tmp');
    return;
  }
  const tmpToolDir = await realpath(await mkdtemp(path.join(tmpRoot, 'black-gravity-tmp-tool-')));
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  try {
    const nodeBinAlias = path.join(tmpToolDir, 'node-bin');
    const nodeBinDir = path.dirname(await realpath(process.execPath));
    await symlink(nodeBinDir, nodeBinAlias);
    const detection = detectBubblewrap();
    await fixture(async (copy, _outside, source, state) => {
      if (
        tmpToolDir === copy ||
        copy.startsWith(tmpToolDir + '/') ||
        tmpToolDir.startsWith(copy + '/')
      ) {
        t.diagnostic(`Skipping /tmp toolchain alias test: temp dir (${tmpToolDir}) overlaps copy (${copy})`);
        t.skip('temp dir overlaps copy');
        return;
      }
      const copyBefore = await hashDirectory(copy);

      const absResult = await executeLinuxTest(
        { executable: path.join(nodeBinAlias, 'node'), args: ['-e', 'process.stdout.write("tmp-abs-ok")'] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source], detection },
      );
      assert.equal(absResult.error, undefined, JSON.stringify(absResult));
      assert.equal(absResult.exitCode, 0, absResult.output);
      assert.equal(absResult.sandbox, 'linux-bwrap');
      assert.equal(absResult.processesReaped, true);
      assert.equal(absResult.sandboxStarted, true);
      assert.equal(absResult.output, 'tmp-abs-ok');
      assert.equal(await hashDirectory(copy), copyBefore);

      process.env.PATH = nodeBinAlias;
      const pathResult = await executeLinuxTest(
        { executable: 'node', args: ['-e', 'process.stdout.write("tmp-path-ok")'] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source], detection },
      );
      assert.equal(pathResult.error, undefined, JSON.stringify(pathResult));
      assert.equal(pathResult.exitCode, 0, pathResult.output);
      assert.equal(pathResult.sandbox, 'linux-bwrap');
      assert.equal(pathResult.processesReaped, true);
      assert.equal(pathResult.sandboxStarted, true);
      assert.equal(pathResult.output, 'tmp-path-ok');
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    await rm(tmpToolDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor hides /run and runtime sockets inside empty tmpfs mounts', async t => {
  if (!requireLinuxBwrap(t)) return;
  const candidates: string[] = [];
  if (process.env.XDG_RUNTIME_DIR && path.isAbsolute(process.env.XDG_RUNTIME_DIR)) {
    candidates.push(process.env.XDG_RUNTIME_DIR);
  }
  if (typeof process.getuid === 'function') {
    const runUserDir = `/run/user/${process.getuid()}`;
    if (!candidates.includes(runUserDir)) candidates.push(runUserDir);
  }

  let sockDir: string | undefined;
  let socketPath: string | undefined;
  let server: net.Server | undefined;
  let connections = 0;
  let homeSockDir: string | undefined;
  let homeServer: net.Server | undefined;
  let homeConnections = 0;
  const skipReasons: string[] = [];

  for (const baseDir of candidates) {
    try {
      sockDir = await mkdtemp(path.join(baseDir, 'black-gravity-sock-'));
      socketPath = path.join(sockDir, 'host.sock');
      break;
    } catch (error) {
      skipReasons.push(`${baseDir}: ${(error as Error).message}`);
    }
  }

  const listenUnixSocket = async (targetPath: string, onConnection: () => void): Promise<net.Server> => {
    const srv = net.createServer(socket => {
      onConnection();
      socket.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      srv.once('error', reject);
      srv.listen(targetPath, resolve);
    });
    return srv;
  };

  try {
    homeSockDir = await mkdtemp(path.join(os.homedir(), 'black-gravity-sock-'));
    const homeSocketPath = path.join(homeSockDir, 'host.sock');
    homeServer = await listenUnixSocket(homeSocketPath, () => {
      homeConnections += 1;
    });

    if (socketPath) {
      server = await listenUnixSocket(socketPath, () => {
        connections += 1;
      });
    } else {
      t.diagnostic(`Skipping host runtime Unix socket connect part: no writable runtime dir (${skipReasons.join('; ') || 'none'})`);
    }

    const targets: Array<[string, string]> = [['home', homeSocketPath]];
    if (socketPath) targets.push(['runtime', socketPath]);

    await fixture(async (copy, _outside, source, state) => {
      const copyBefore = await hashDirectory(copy);
      const script =
        "const fs=require('node:fs'),net=require('node:net');const entries=fs.readdirSync('/run');" +
        "console.log('run-entries:'+entries.length);" +
        "if(entries.length!==0){console.error('unexpected-run:'+entries.join(','));process.exit(2);}" +
        `Promise.all(${JSON.stringify(targets)}.map(([label,target])=>new Promise((resolve,reject)=>{` +
        "const s=net.connect(target);" +
        "s.on('connect',()=>{s.destroy();reject(new Error('unexpected-unix-connect:'+label))});" +
        "s.on('error',err=>{console.log('unix-denied:'+label+':'+err.code);resolve(undefined)});" +
        "setTimeout(()=>reject(new Error('timeout:'+label)),3000).unref();" +
        "}))).then(()=>process.exit(0),err=>{console.error(err.message);process.exit(40)});";
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.processesReaped, true);
      assert.equal(result.sandboxStarted, true);
      assert.match(result.output, /run-entries:0/);
      assert.match(result.output, /unix-denied:home:/);
      assert.equal(homeConnections, 0);
      if (socketPath) {
        assert.match(result.output, /unix-denied:runtime:/);
        assert.equal(connections, 0);
      }
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    for (const srv of [server, homeServer]) {
      if (srv?.listening) {
        await new Promise<void>((resolve, reject) => srv.close(err => (err ? reject(err) : resolve())));
      }
    }
    for (const dir of [sockDir, homeSockDir]) {
      if (dir) {
        await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  }
});

test('Linux bwrap executor blocks host Unix sockets inside mounted PATH toolchain directories', async t => {
  if (!requireLinuxBwrap(t)) return;
  const tmpRoot = await realpath(os.tmpdir());
  if (tmpRoot !== '/tmp' && !tmpRoot.startsWith('/tmp/')) {
    t.diagnostic(`Skipping Unix socket in PATH toolchain test: os.tmpdir() (${tmpRoot}) is not under /tmp`);
    t.skip('os.tmpdir() is not under /tmp');
    return;
  }
  const sockToolDir = await realpath(await mkdtemp(path.join(tmpRoot, 'black-gravity-sock-tool-')));
  const binDir = path.join(sockToolDir, 'bin');
  await mkdir(binDir, { recursive: true });
  const socketPath = path.join(binDir, 'proxy.sock');
  let connections = 0;
  const server = net.createServer(socket => {
    connections += 1;
    socket.destroy();
  });
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  process.env.PATH = previousPath ? `${binDir}${path.posix.delimiter}${previousPath}` : binDir;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    await fixture(async (copy, _outside, source, state) => {
      if (
        sockToolDir === copy ||
        copy.startsWith(sockToolDir + '/') ||
        sockToolDir.startsWith(copy + '/')
      ) {
        t.diagnostic(`Skipping Unix socket in PATH toolchain test: temp dir (${sockToolDir}) overlaps copy (${copy})`);
        t.skip('temp dir overlaps copy');
        return;
      }
      const copyBefore = await hashDirectory(copy);
      const script =
        `const net=require('node:net');const s=net.connect(${JSON.stringify(socketPath)});` +
        "s.on('connect',()=>{console.log('connected');s.destroy();process.exit(0)});" +
        "s.on('error',err=>{console.log('blocked:'+(err.code||err.message));process.exit(0)});" +
        "setTimeout(()=>{console.log('timeout');process.exit(1)},3000).unref();";
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.sandboxStarted, true);
      assert.equal(result.processesReaped, true);
      assert.ok(result.output.startsWith('blocked:'), result.output);
      assert.equal(connections, 0);
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    if (server.listening) {
      await new Promise<void>((resolve, reject) => server.close(err => (err ? reject(err) : resolve())));
    }
    await rm(sockToolDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor refuses to run when a mounted PATH toolchain directory contains a FIFO', async t => {
  if (!requireLinuxBwrap(t)) return;
  const tmpRoot = await realpath(os.tmpdir());
  if (tmpRoot !== '/tmp' && !tmpRoot.startsWith('/tmp/')) {
    t.diagnostic(`Skipping FIFO in PATH toolchain test: os.tmpdir() (${tmpRoot}) is not under /tmp`);
    t.skip('os.tmpdir() is not under /tmp');
    return;
  }
  const fifoToolDir = await realpath(await mkdtemp(path.join(tmpRoot, 'black-gravity-fifo-tool-')));
  const binDir = path.join(fifoToolDir, 'bin');
  await mkdir(binDir, { recursive: true });
  const fifoPath = path.join(binDir, 'leak.fifo');
  execFileSync('mkfifo', [fifoPath]);
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  process.env.PATH = previousPath ? `${binDir}${path.posix.delimiter}${previousPath}` : binDir;
  let hostReaderFd: number | undefined;
  try {
    hostReaderFd = openSync(fifoPath, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    await fixture(async (copy, _outside, source, state) => {
      if (
        fifoToolDir === copy ||
        copy.startsWith(fifoToolDir + '/') ||
        fifoToolDir.startsWith(copy + '/')
      ) {
        t.diagnostic(`Skipping FIFO in PATH toolchain test: temp dir (${fifoToolDir}) overlaps copy (${copy})`);
        t.skip('temp dir overlaps copy');
        return;
      }
      const copyBefore = await hashDirectory(copy);
      const script =
        `const fs=require('node:fs');const fd=fs.openSync(${JSON.stringify(fifoPath)},'w');` +
        "fs.writeSync(fd,'leaked-via-fifo');fs.closeSync(fd);";
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.match(result.error ?? '', /mounted directory contains a FIFO/);
      assert.equal(result.sandboxStarted, false);
      assert.equal(result.exitCode, null);
      assert.equal(result.processesReaped, true);
      assert.equal(await hashDirectory(copy), copyBefore);

      const buf = Buffer.alloc(64);
      let bytesRead = 0;
      try {
        bytesRead = readSync(hostReaderFd!, buf, 0, buf.length, null);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        assert.equal(code, 'EAGAIN');
      }
      assert.equal(bytesRead, 0);
    });
  } finally {
    if (hostReaderFd !== undefined) {
      closeSync(hostReaderFd);
    }
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    await rm(fifoToolDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor refuses to run when a mounted PATH toolchain directory contains a traversable unlistable subdirectory', async t => {
  if (!requireLinuxBwrap(t)) return;
  if (process.getuid?.() === 0) {
    t.skip('Permission checks are bypassed when running as root');
    return;
  }
  const tmpRoot = await realpath(os.tmpdir());
  if (tmpRoot !== '/tmp' && !tmpRoot.startsWith('/tmp/')) {
    t.diagnostic(`Skipping uninspectable PATH toolchain test: os.tmpdir() (${tmpRoot}) is not under /tmp`);
    t.skip('os.tmpdir() is not under /tmp');
    return;
  }
  const toolDir = await realpath(await mkdtemp(path.join(tmpRoot, 'black-gravity-uninspectable-tool-')));
  const binDir = path.join(toolDir, 'bin');
  const lockedDir = path.join(binDir, 'locked');
  await mkdir(lockedDir, { recursive: true });
  const fifoPath = path.join(lockedDir, 'leak.fifo');
  execFileSync('mkfifo', [fifoPath]);
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  try {
    await chmod(lockedDir, 0o311);
    process.env.PATH = previousPath ? `${binDir}${path.posix.delimiter}${previousPath}` : binDir;
    await fixture(async (copy, _outside, source, state) => {
      if (
        toolDir === copy ||
        copy.startsWith(toolDir + '/') ||
        toolDir.startsWith(copy + '/')
      ) {
        t.diagnostic(`Skipping uninspectable PATH toolchain test: temp dir (${toolDir}) overlaps copy (${copy})`);
        t.skip('temp dir overlaps copy');
        return;
      }
      const copyBefore = await hashDirectory(copy);
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.match(result.error ?? '', /cannot inspect mounted directory for FIFOs/);
      assert.ok((result.error ?? '').includes(lockedDir), result.error ?? '');
      assert.equal(result.sandboxStarted, false);
      assert.equal(result.exitCode, null);
      assert.equal(result.processesReaped, true);
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    await chmod(lockedDir, 0o755).catch(() => {});
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    await rm(toolDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor refuses to run when a mounted PATH toolchain directory contains a non-traversable subdirectory with a FIFO', async t => {
  if (!requireLinuxBwrap(t)) return;
  if (process.getuid?.() === 0) {
    t.skip('Permission checks are bypassed when running as root');
    return;
  }
  const tmpRoot = await realpath(os.tmpdir());
  if (tmpRoot !== '/tmp' && !tmpRoot.startsWith('/tmp/')) {
    t.diagnostic(`Skipping non-traversable PATH toolchain test: os.tmpdir() (${tmpRoot}) is not under /tmp`);
    t.skip('os.tmpdir() is not under /tmp');
    return;
  }
  let unsharePath: string | undefined;
  try {
    const resolved = execFileSync('which', ['unshare'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0] ?? '';
    if (resolved && path.isAbsolute(resolved)) {
      unsharePath = resolved;
    }
  } catch {
    // Fall back to opening the FIFO directly if unshare is unavailable.
  }
  const toolDir = await realpath(await mkdtemp(path.join(tmpRoot, 'black-gravity-nontraversable-tool-')));
  const binDir = path.join(toolDir, 'bin');
  const lockedDir = path.join(binDir, 'locked');
  await mkdir(lockedDir, { recursive: true });
  const fifoPath = path.join(lockedDir, 'leak.fifo');
  execFileSync('mkfifo', [fifoPath]);
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  let hostReaderFd: number | undefined;
  try {
    hostReaderFd = openSync(fifoPath, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    await chmod(lockedDir, 0o000);
    process.env.PATH = previousPath ? `${binDir}${path.posix.delimiter}${previousPath}` : binDir;
    await fixture(async (copy, _outside, source, state) => {
      if (
        toolDir === copy ||
        copy.startsWith(toolDir + '/') ||
        toolDir.startsWith(copy + '/')
      ) {
        t.diagnostic(`Skipping non-traversable PATH toolchain test: temp dir (${toolDir}) overlaps copy (${copy})`);
        t.skip('temp dir overlaps copy');
        return;
      }
      const copyBefore = await hashDirectory(copy);
      const script = unsharePath
        ? `require('node:child_process').spawnSync(${JSON.stringify(unsharePath)},['-Ur','sh','-c',${JSON.stringify(`printf leaked > ${fifoPath}`)}],{stdio:'inherit'});`
        : `const fs=require('node:fs');const fd=fs.openSync(${JSON.stringify(fifoPath)},'w');fs.writeSync(fd,'leaked');fs.closeSync(fd);`;
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.match(result.error ?? '', /cannot inspect mounted directory for FIFOs/);
      assert.ok((result.error ?? '').includes(lockedDir), result.error ?? '');
      assert.equal(result.sandboxStarted, false);
      assert.equal(result.exitCode, null);
      assert.equal(result.processesReaped, true);
      assert.equal(await hashDirectory(copy), copyBefore);

      const buf = Buffer.alloc(64);
      let bytesRead = 0;
      try {
        bytesRead = readSync(hostReaderFd!, buf, 0, buf.length, null);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        assert.equal(code, 'EAGAIN');
      }
      assert.equal(bytesRead, 0);
    });
  } finally {
    if (hostReaderFd !== undefined) {
      closeSync(hostReaderFd);
    }
    await chmod(lockedDir, 0o755).catch(() => {});
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    await rm(toolDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor blocks datagram socketpair reachability to host Unix dgram sockets inside mounted PATH directories', async t => {
  if (!requireLinuxBwrap(t)) return;
  let python3Path: string;
  try {
    python3Path = execFileSync('which', ['python3'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0] ?? '';
    if (!python3Path || !path.isAbsolute(python3Path)) {
      t.diagnostic(`Skipping Unix datagram socketpair test: python3 path was invalid (${python3Path})`);
      t.skip('python3 not available');
      return;
    }
  } catch (error) {
    t.diagnostic(`Skipping Unix datagram socketpair test: python3 not found (${(error as Error).message})`);
    t.skip('python3 not available');
    return;
  }

  const tmpRoot = await realpath(os.tmpdir());
  if (tmpRoot !== '/tmp' && !tmpRoot.startsWith('/tmp/')) {
    t.diagnostic(`Skipping Unix datagram socketpair test: os.tmpdir() (${tmpRoot}) is not under /tmp`);
    t.skip('os.tmpdir() is not under /tmp');
    return;
  }
  const sockToolDir = await realpath(await mkdtemp(path.join(tmpRoot, 'black-gravity-dgram-tool-')));
  const binDir = path.join(sockToolDir, 'bin');
  await mkdir(binDir, { recursive: true });
  const socketPath = path.join(binDir, 'proxy.dgram');
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  process.env.PATH = previousPath ? `${binDir}${path.posix.delimiter}${previousPath}` : binDir;

  let hostProc: ReturnType<typeof spawn> | undefined;
  let hostExited = false;
  let hostClose: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
  try {
    const hostScript = [
      'import socket',
      's = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)',
      `s.bind(${JSON.stringify(socketPath)})`,
      's.settimeout(60.0)',
      "print('ready', flush=True)",
      'try:',
      '  while True:',
      '    try:',
      '      s.recvfrom(16)',
      "      print('got', flush=True)",
      '    except socket.timeout:',
      '      break',
      'finally:',
      '  s.close()',
    ].join('\n');

    hostProc = spawn(python3Path, ['-c', hostScript], { stdio: ['ignore', 'pipe', 'pipe'] });
    let hostOutput = '';
    let hostStderr = '';
    hostClose = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      hostProc!.once('error', reject);
      hostProc!.once('close', (code, signal) => {
        hostExited = true;
        resolve({ code, signal });
      });
    });
    hostProc.stderr?.on('data', chunk => {
      hostStderr += chunk.toString('utf8');
    });
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(`Timed out waiting for host Python server ready (stdout=${hostOutput}, stderr=${hostStderr})`));
      }, 5000);
      hostProc!.stdout?.on('data', chunk => {
        hostOutput += chunk.toString('utf8');
        if (!settled && hostOutput.split(/\r?\n/).some(line => line.trim() === 'ready')) {
          settled = true;
          clearTimeout(timer);
          resolve();
        }
      });
      hostClose!.then(
        ({ code, signal }) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(new Error(`Host Python server exited before ready (code=${code}, signal=${signal}, stdout=${hostOutput}, stderr=${hostStderr})`));
          }
        },
        err => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(err);
          }
        },
      );
    });

    await fixture(async (copy, _outside, source, state) => {
      if (
        sockToolDir === copy ||
        copy.startsWith(sockToolDir + '/') ||
        sockToolDir.startsWith(copy + '/')
      ) {
        t.diagnostic(`Skipping Unix datagram socketpair test: temp dir (${sockToolDir}) overlaps copy (${copy})`);
        t.skip('temp dir overlaps copy');
        return;
      }
      const copyBefore = await hashDirectory(copy);
      const sandboxScript = [
        'import errno, socket, sys',
        "for name, sock_type in [('SOCK_DGRAM', socket.SOCK_DGRAM), ('SOCK_RAW', socket.SOCK_RAW)]:",
        '  try:',
        '    a, b = socket.socketpair(socket.AF_UNIX, sock_type)',
        '  except OSError as e:',
        "    print(f'{name}:create-blocked:' + errno.errorcode.get(e.errno, str(e)))",
        '    continue',
        '  try:',
        '    try:',
        `      a.sendto(b'x', ${JSON.stringify(socketPath)})`,
        "      print(f'{name}:sent')",
        '    except OSError as e:',
        "      print(f'{name}:send-failed:' + errno.errorcode.get(e.errno, str(e)))",
        '  finally:',
        '    a.close()',
        '    b.close()',
        'sys.exit(0)',
      ].join('\n');
      const result = await executeLinuxTest(
        { executable: python3Path, args: ['-c', sandboxScript] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.sandboxStarted, true);
      assert.equal(result.processesReaped, true);
      const outputLines = result.output.trim().split(/\r?\n/).map(line => line.trim());
      assert.deepEqual(outputLines, [
        'SOCK_DGRAM:create-blocked:EAFNOSUPPORT',
        'SOCK_RAW:create-blocked:EAFNOSUPPORT',
      ], result.output);

      assert.equal(hostProc!.exitCode, null, `Host Python server exited prematurely (stdout=${hostOutput}, stderr=${hostStderr})`);
      hostProc!.kill('SIGKILL');
      await hostClose!;
      assert.ok(!hostOutput.includes('got'), hostOutput);
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
    if (hostProc && !hostExited) {
      try { hostProc.kill('SIGKILL'); } catch { /* already exited */ }
      if (hostClose) await hostClose.catch(() => {});
    }
    await rm(sockToolDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Linux bwrap executor allows child processes with piped stdio when seccomp filter is active', async t => {
  if (!requireLinuxBwrap(t)) return;
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const script =
      "process.stdout.write(require('node:child_process').execFileSync(process.execPath,['-e','process.stdout.write(\"pipe-ok\")']));";
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', script] },
      copy,
      { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.sandboxStarted, true);
    assert.equal(result.processesReaped, true);
    assert.equal(result.output, 'pipe-ok');
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor reports setup failure when no child-pid status is emitted', async t => {
  if (process.platform !== 'linux') {
    t.skip('Linux executor status-fd test requires Linux');
    return;
  }
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
      copy,
      {
        timeoutSeconds: 15,
        stateDirectory: state,
        protectedPaths: [source],
        detection: { available: true, path: process.execPath, version: 'mock-bwrap' },
      },
    );
    assert.equal(result.sandboxStarted, false);
    assert.match(result.error ?? '', /^Bubblewrap did not start the command/);
    assert.equal(result.processesReaped, true);
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor hides bridge state directory and blocks reading state markers', async t => {
  if (!requireLinuxBwrap(t)) return;
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const stateMarker = path.join(state, 'secret-state.txt');
    const script =
      "const fs=require('node:fs');" +
      `try{console.log(fs.readFileSync(${JSON.stringify(stateMarker)},'utf8'))}catch(e){console.log('state-denied:'+e.code)}`;
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', script] },
      copy,
      { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.processesReaped, true);
    assert.doesNotMatch(result.output, /SECRET_STATE_MARKER_XYZ/);
    assert.match(result.output, /state-denied:/);
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor blocks network access to host 127.0.0.1 TCP server by default', async t => {
  if (!requireLinuxBwrap(t)) return;
  let connections = 0;
  const server = net.createServer(socket => {
    connections += 1;
    socket.destroy();
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = (server.address() as net.AddressInfo).port;
    await fixture(async (copy, _outside, source, state) => {
      const copyBefore = await hashDirectory(copy);
      const script =
        `const net=require('node:net');const s=net.connect({host:'127.0.0.1',port:${port}});` +
        "s.on('connect',()=>{console.error('unexpected-connect');process.exit(40)});" +
        "s.on('error',err=>{console.log('network-denied:'+err.code);process.exit(0)});" +
        "setTimeout(()=>process.exit(42),3000).unref();";
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.processesReaped, true);
      assert.match(result.output, /network-denied:/);
      assert.equal(connections, 0);
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    await new Promise<void>((resolve, reject) => server.close(err => (err ? reject(err) : resolve())));
  }
});

test('Linux bwrap executor reaps detached background processes so none survive to write markers', async t => {
  if (!requireLinuxBwrap(t)) return;
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const marker = path.join(copy, 'survived-marker.txt');
    const childScript = `setTimeout(()=>require('node:fs').writeFileSync(${JSON.stringify(marker)},'survived'),2000)`;
    const script =
      `const cp=require('node:child_process');const child=cp.spawn(process.execPath,['-e',${JSON.stringify(childScript)}],{detached:true,stdio:'ignore'});child.unref();console.log('parent-exiting');`;
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', script] },
      copy,
      { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.processesReaped, true);
    await new Promise(resolve => setTimeout(resolve, 3000));
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor kills timed-out commands and reaps their process group', async t => {
  if (!requireLinuxBwrap(t)) return;
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', 'setInterval(()=>{},1000)'] },
      copy,
      { timeoutSeconds: 1, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, 'Command timed out');
    assert.equal(result.exitCode, null);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.processesReaped, true);
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor ignores /proc, /dev, and /sys PATH entries instead of mounting over private namespaces', async t => {
  if (!requireLinuxBwrap(t)) return;
  const hadPath = Object.prototype.hasOwnProperty.call(process.env, 'PATH');
  const previousPath = process.env.PATH;
  const hostHasDevKmsg = existsSync('/dev/kmsg');
  process.env.PATH = `/proc:/proc/self:/dev:/sys:${previousPath ?? ''}`;
  try {
    await fixture(async (copy, _outside, source, state) => {
      const copyBefore = await hashDirectory(copy);
      const script =
        "const fs=require('node:fs');" +
        `const out={hostPidVisible:fs.existsSync('/proc/${process.pid}')` +
        (hostHasDevKmsg ? ",devKmsgVisible:fs.existsSync('/dev/kmsg')" : '') +
        '};process.stdout.write(JSON.stringify(out));';
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.processesReaped, true);
      assert.equal(result.sandboxStarted, true);
      const observed = JSON.parse(result.output) as { hostPidVisible: boolean; devKmsgVisible?: boolean };
      if (process.pid < 10) {
        t.diagnostic(`Skipping host pid visibility assertion: process.pid (${process.pid}) is below 10`);
      } else {
        assert.equal(observed.hostPidVisible, false);
      }
      if (hostHasDevKmsg) {
        assert.equal(observed.devKmsgVisible, false);
      } else {
        t.diagnostic('Host /dev/kmsg does not exist; skipping /dev/kmsg absence assertion');
      }
      assert.equal(await hashDirectory(copy), copyBefore);
    });
  } finally {
    if (hadPath && previousPath !== undefined) {
      process.env.PATH = previousPath;
    } else {
      delete process.env.PATH;
    }
  }
});

test('Linux bwrap executor kills and reaps process group when onProcess throws', async t => {
  if (!requireLinuxBwrap(t)) return;
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    let spawnedPid: number | undefined;
    await assert.rejects(
      () => executeLinuxTest(
        { executable: process.execPath, args: ['-e', 'setInterval(() => {}, 1000)'] },
        copy,
        {
          timeoutSeconds: 30,
          stateDirectory: state,
          protectedPaths: [source],
          onProcess: child => {
            spawnedPid = child.pid;
            throw new Error('onProcess boom');
          },
        },
      ),
      { message: 'onProcess boom' },
    );
    assert.ok(spawnedPid !== undefined);
    const deadline = Date.now() + 2000;
    let reaped = false;
    while (Date.now() < deadline) {
      try {
        process.kill(-spawnedPid, 0);
      } catch (error) {
        assert.equal((error as NodeJS.ErrnoException).code, 'ESRCH');
        reaped = true;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.equal(reaped, true, `Process group ${spawnedPid} was still alive after onProcess threw`);
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('Linux bwrap executor removes scratch directory even when command chmods a non-empty subdirectory to 000', async t => {
  if (!requireLinuxBwrap(t)) return;
  if (process.getuid?.() === 0) {
    t.skip('Permission checks are bypassed when running as root');
    return;
  }
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    let scratchPath: string | undefined;
    try {
      const script =
        "const fs=require('node:fs'),path=require('node:path');" +
        'const tmp=process.env.TMPDIR;' +
        'console.log(tmp);' +
        "const locked=path.join(tmp,'locked');" +
        'fs.mkdirSync(locked,{recursive:true});' +
        "fs.writeFileSync(path.join(locked,'file'),'x');" +
        'fs.chmodSync(locked,0o000);' +
        'process.exit(0);';
      const result = await executeLinuxTest(
        { executable: process.execPath, args: ['-e', script] },
        copy,
        { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
      );
      const firstLine = result.output.split(/\r?\n/)[0]?.trim() ?? '';
      if (firstLine.includes('black-gravity-scratch-')) {
        scratchPath = firstLine;
      }
      assert.equal(result.error, undefined, JSON.stringify(result));
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(result.sandbox, 'linux-bwrap');
      assert.equal(result.sandboxStarted, true);
      assert.equal(result.processesReaped, true);
      assert.ok(firstLine.includes('black-gravity-scratch-'), result.output);
      assert.equal(existsSync(firstLine), false);
      assert.equal(await hashDirectory(copy), copyBefore);
    } finally {
      if (scratchPath && existsSync(scratchPath)) {
        await chmod(path.join(scratchPath, 'locked'), 0o755).catch(() => {});
        await rm(scratchPath, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {});
      }
    }
  });
});

test('Linux bwrap executor restores scratch permissions and removes scratch when onProcess throws', async t => {
  if (!requireLinuxBwrap(t)) return;
  if (process.getuid?.() === 0) {
    t.skip('Permission checks are bypassed when running as root');
    return;
  }
  await fixture(async (copy, _outside, source, state) => {
    let scratchPath: string | undefined;
    try {
      const markerPath = path.join(copy, 'scratch-path.txt');
      const script =
        "const fs=require('node:fs'),path=require('node:path');" +
        'const tmp=process.env.TMPDIR;' +
        "const locked=path.join(tmp,'locked');" +
        'fs.mkdirSync(locked,{recursive:true});' +
        "fs.writeFileSync(path.join(locked,'file'),'x');" +
        'fs.chmodSync(locked,0o000);' +
        "const markerTmp=path.join(process.cwd(),'scratch-path.tmp');" +
        "const marker=path.join(process.cwd(),'scratch-path.txt');" +
        'fs.writeFileSync(markerTmp,tmp);' +
        'fs.renameSync(markerTmp,marker);' +
        'setInterval(()=>{},1000);';
      const waitSignal = new Int32Array(new SharedArrayBuffer(4));
      await assert.rejects(
        () => executeLinuxTest(
          { executable: process.execPath, args: ['-e', script] },
          copy,
          {
            timeoutSeconds: 30,
            stateDirectory: state,
            protectedPaths: [source],
            // Skip seccomp fd so bwrap does not wait for pipe EOF while onProcess blocks the event loop.
            sandbox: { readPaths: [], writePaths: [], network: true, childProcesses: true, maxOutputChars: 4000 },
            onProcess: () => {
              const deadline = Date.now() + 10000;
              while (Date.now() < deadline) {
                if (existsSync(markerPath)) {
                  const content = readFileSync(markerPath, 'utf8').trim();
                  if (content.length > 0) {
                    scratchPath = content;
                    break;
                  }
                }
                Atomics.wait(waitSignal, 0, 0, 25);
              }
              throw new Error('onProcess boom');
            },
          },
        ),
        { message: 'onProcess boom' },
      );
      assert.ok(scratchPath && scratchPath.includes('black-gravity-scratch-'), scratchPath ?? '');
      assert.equal(existsSync(scratchPath), false);
    } finally {
      if (scratchPath && existsSync(scratchPath)) {
        await chmod(path.join(scratchPath, 'locked'), 0o755).catch(() => {});
        await rm(scratchPath, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {});
      }
    }
  });
});

test('Linux bwrap executor requires a real user namespace', async t => {
  if (!requireLinuxBwrap(t)) return;
  const hostUidMap = readFileSync('/proc/self/uid_map', 'utf8').trim();
  await fixture(async (copy, _outside, source, state) => {
    const copyBefore = await hashDirectory(copy);
    const result = await executeLinuxTest(
      { executable: process.execPath, args: ['-e', "process.stdout.write(require('node:fs').readFileSync('/proc/self/uid_map','utf8'))"] },
      copy,
      { timeoutSeconds: 15, stateDirectory: state, protectedPaths: [source] },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.sandbox, 'linux-bwrap');
    assert.equal(result.sandboxStarted, true);
    assert.equal(result.processesReaped, true);
    const sandboxUidMap = result.output.trim();
    assert.notEqual(sandboxUidMap, hostUidMap);
    const lines = sandboxUidMap.split(/\r?\n/).filter(Boolean);
    assert.equal(lines.length, 1, sandboxUidMap);
    const fields = lines[0]!.trim().split(/\s+/);
    assert.equal(fields.length, 3, sandboxUidMap);
    assert.equal(fields[2], '1', sandboxUidMap);
    assert.equal(await hashDirectory(copy), copyBefore);
  });
});

test('TaskManager runs black_gravity_test with linux-bwrap, records linux-executor evidence, and reports health', async t => {
  if (!requireLinuxBwrap(t)) return;
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'black-gravity-linux-tm-')));
  const directory = path.join(root, 'source');
  const stateDirectory = path.join(root, 'state');
  await mkdir(directory, { recursive: true });
  execFileSync('git', ['init', '--quiet', directory]);
  await writeFile(path.join(directory, 'source.txt'), 'source');

  const config = loadConfig({
    BRIDGE_ANTI_AI_CRAFT: 'off',
    AGY_PATH: process.execPath,
    BRIDGE_STATE_DIRECTORY: stateDirectory,
    DEFAULT_TIMEOUT_SECONDS: '20',
  });
  const adapter = new CliAdapter(config, [mockPath]);
  const tasks = new TaskManager(adapter, config);
  try {
    await adapter.discover();
    const health = tasks.testExecutorStatus();
    assert.equal(health.selected, 'linux-bwrap');
    assert.equal(health.explicit, false);
    assert.equal(health.linuxBwrap?.available, true);

    const sourceTask = await tasks.run({ prompt: 'write:test', workingDirectory: directory });
    const written = await waitFor(tasks, sourceTask.taskId);
    assert.equal(written.status, 'completed', JSON.stringify(written.error));
    const preview = await tasks.preview(written.taskId, false);

    const tested = await tasks.startTests(written.taskId, preview.sha256, {
      executable: process.execPath,
      args: ['-e', 'process.stdout.write("bwrap-tm-ok")'],
    }, 0, 30);
    const testedResult = await waitFor(tasks, tested.taskId);
    assert.equal(testedResult.status, 'completed', JSON.stringify(testedResult.error));
    assert.equal(testedResult.tests?.at(-1)?.source, 'linux-executor');
    assert.equal(testedResult.tests?.at(-1)?.sandbox, 'linux-bwrap');
    assert.equal(testedResult.tests?.at(-1)?.exitCode, 0);
    assert.equal(testedResult.tests?.at(-1)?.output, 'bwrap-tm-ok');
    assert.equal(testedResult.tokenUsage?.source, 'local-executor');
    assert.equal(testedResult.tokenUsage?.counters.totalTokens, 0);
  } finally {
    await tasks.shutdown();
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
