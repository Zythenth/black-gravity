import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { tracingChannel } from 'node:diagnostics_channel';
import { readFileSync } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { assertNoPendingMcpCustodyForCopy, executeWindowsTest, recoverWindowsExecutions } from '../src/windows-executor.js';
import { TaskManager } from '../src/task-manager.js';
import { DEFAULT_PROJECT_LIMITS, loadConfig } from '../src/config.js';
import { CliAdapter } from '../src/cli-adapter.js';
import { StateStore } from '../src/state-store.js';
import { discardProjectCopy } from '../src/isolation.js';
import { archiveDirectoryFor } from '../src/workspace-archive.js';
import { resolveAgentPolicy } from '../src/agent-policy.js';
import { removeStagedExecutionPolicyHelpers, stageExecutionPolicy } from '../src/execution-policy.js';
import {
  canonicalWorkspacePaths,
  ensureFixedWorkspaceLpacPermissions,
  readWorkspaceMetadata,
  writeWorkspaceMetadata,
} from '../src/workspace-paths.js';

const settings = { timeoutSeconds: 20, maxRuntimeBytes: 256 * 1024 * 1024 };
type Grant = { path: string; rights: 'read' | 'modify'; directory: boolean; volume: number; fileIndexHigh: number; fileIndexLow: number };
type Lease = {
  version?: number;
  nonce: string;
  profile: string;
  sid: string;
  phase: string;
  controllerPid: number;
  controllerStarted: number;
  cwd: string;
  runtime: string;
  scratch: string;
  grants: Grant[];
  mcpCustody?: {
    executionId: string;
    sourcePath: string;
    custodyDirectory: string;
    custodyPath: string;
    sha256: string;
    bytes: number;
    originalDaclBase64?: string;
    originalDaclSha256?: string;
    custodyDaclBase64?: string;
    custodyDaclSha256?: string;
  };
};
type Announcement = { controllerPid: number; requestPath: string };

const pause = (milliseconds: number) => new Promise(resolve => setTimeout(resolve, milliseconds));

async function eventually<T>(description: string, observe: () => Promise<T | undefined>, timeoutMilliseconds = 30_000): Promise<T> {
  const deadline = Date.now() + timeoutMilliseconds;
  let last: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await observe();
      if (value !== undefined) return value;
      last = value;
    } catch (error) { last = error; }
    await pause(50);
  }
  throw new Error(description + ': ' + String(last));
}

async function ownedTemporaryDirectory(directory: string, prefix: string): Promise<string> {
  const temporary = await realpath(os.tmpdir());
  const canonical = await realpath(directory);
  assert.equal(path.dirname(canonical), temporary, 'temporary target must be directly below os.tmpdir()');
  assert.ok(path.basename(canonical).startsWith(prefix), 'temporary target prefix');
  assert.equal((await lstat(canonical)).isSymbolicLink(), false, 'temporary target cannot be a link');
  return canonical;
}

async function removeOwned(directory: string | undefined, prefix: string): Promise<void> {
  if (!directory) return;
  const canonical = await ownedTemporaryDirectory(directory, prefix);
  await rm(canonical, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function storedAcls(targets: { path: string; mode?: string }[]): string[] {
  const source = `using System;using System.IO;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.AccessControl;
public static class AclFixture {
[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool GetFileSecurity(string p,uint i,byte[] b,uint n,out uint needed);
[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetFileSecurity(string p,uint i,byte[] b);
public static string Apply(string p,string mode){uint n;GetFileSecurity(p,4,null,0,out n);byte[] b=new byte[n];if(!GetFileSecurity(p,4,b,n,out n))throw new Win32Exception();var sd=new RawSecurityDescriptor(b,0);
if(!String.IsNullOrEmpty(mode)){if(mode=="foreign")sd.DiscretionaryAcl.InsertAce(0,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,0x120089,new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3-4567"),false,null));
else if(mode.StartsWith("S-1-"))sd.DiscretionaryAcl.InsertAce(0,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,0x120089,new System.Security.Principal.SecurityIdentifier(mode),false,null));
else {var flags=sd.ControlFlags&~(ControlFlags.DiscretionaryAclProtected|ControlFlags.DiscretionaryAclAutoInherited|ControlFlags.DiscretionaryAclAutoInheritRequired);sd.SetFlags(flags);foreach(GenericAce ace in sd.DiscretionaryAcl){ace.AceFlags&=~AceFlags.Inherited;}}
b=new byte[sd.BinaryLength];sd.GetBinaryForm(b,0);if(!SetFileSecurity(p,4,b))throw new Win32Exception();GetFileSecurity(p,4,null,0,out n);b=new byte[n];if(!GetFileSecurity(p,4,b,n,out n))throw new Win32Exception();sd=new RawSecurityDescriptor(b,0);}
return sd.GetSddlForm(AccessControlSections.Access);}}`;
  const script = "$ErrorActionPreference='Stop'; Add-Type -TypeDefinition $env:BRIDGE_ACL_FIXTURE_SOURCE; $targets = ConvertFrom-Json $env:BRIDGE_ACL_FIXTURE_TARGETS; $values = @($targets | ForEach-Object { [AclFixture]::Apply($_.path, $_.mode) }); ConvertTo-Json -InputObject $values -Compress";
  return JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    windowsHide: true, encoding: 'utf8', env: { ...process.env, BRIDGE_ACL_FIXTURE_SOURCE: source, BRIDGE_ACL_FIXTURE_TARGETS: JSON.stringify(targets) },
  })) as string[];
}

async function readAcl(target: string): Promise<string> {
  const child = spawn('icacls.exe', [target], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', error = '';
  child.stdout.on('data', chunk => { output += String(chunk); });
  child.stderr.on('data', chunk => { error += String(chunk); });
  const code = await new Promise<number | null>(resolve => child.once('close', resolve));
  assert.equal(code, 0, error);
  return output;
}

async function profileExists(sid: string): Promise<boolean> {
  const key = 'HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings\\' + sid;
  const child = spawn('reg.exe', ['query', key], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let error = '';
  child.stderr.on('data', chunk => { error += String(chunk); });
  const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  assert.ok(code === 0 || code === 1, error);
  return code === 0;
}

function ownedProfile(profile: string, action: 'create' | 'remove'): string {
  assert.match(profile, /^(?:black-gravity|agy)\.test\.[0-9a-f]{32}$/);
  const source = 'using System;using System.Runtime.InteropServices;using System.Security.Principal;public static class ProfileFixture {' +
    '[DllImport("userenv.dll",CharSet=CharSet.Unicode)]static extern int CreateAppContainerProfile(string n,string d,string x,IntPtr c,uint z,out IntPtr s);' +
    '[DllImport("userenv.dll",CharSet=CharSet.Unicode)]static extern int DeleteAppContainerProfile(string n);[DllImport("advapi32.dll")]static extern IntPtr FreeSid(IntPtr s);' +
    'public static string Create(string n){IntPtr s;int r=CreateAppContainerProfile(n,n,"Owned test profile",IntPtr.Zero,0,out s);if(r<0)Marshal.ThrowExceptionForHR(r);try{return new SecurityIdentifier(s).Value;}finally{FreeSid(s);}}' +
    'public static void Remove(string n){int r=DeleteAppContainerProfile(n);if(r<0&&r!=unchecked((int)0x80070002)&&r!=unchecked((int)0x80070003))Marshal.ThrowExceptionForHR(r);}}';
  const script = "$ErrorActionPreference='Stop';Add-Type -TypeDefinition $env:BRIDGE_PROFILE_SOURCE;" + (action === 'create' ? '[ProfileFixture]::Create($env:BRIDGE_PROFILE_NAME)' : '[ProfileFixture]::Remove($env:BRIDGE_PROFILE_NAME)');
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, encoding: 'utf8', env: { ...process.env, BRIDGE_PROFILE_SOURCE: source, BRIDGE_PROFILE_NAME: profile } }).trim();
}

async function readLease(state: string): Promise<{ file: string; value: Lease }> {
  const directory = path.join(state, 'windows-lpac-leases');
  const name = await eventually('active lease was not written', async () => (await readdir(directory).catch(() => [])).find(entry => entry.endsWith('.json')));
  const file = path.join(directory, name);
  const value = JSON.parse(await readFile(file, 'utf8')) as Lease;
  assert.equal(value.phase, 'active');
  assert.ok(value.sid.startsWith('S-1-15-2-'));
  assert.ok(value.grants.length > 0);
  return { file, value };
}

async function waitForExit(child: ChildProcessWithoutNullStreams, expected: number): Promise<void> {
  const code = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('worker did not exit')), 30_000);
    child.once('exit', exitCode => { clearTimeout(timer); resolve(exitCode); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
  });
  assert.equal(code, expected);
}

async function launchCrashWorker(copy: string, state: string, grant: string, ready: string, heartbeat: string): Promise<{ worker: ChildProcessWithoutNullStreams; announcement: Announcement }> {
  const executorUrl = new URL('../src/windows-executor.js', import.meta.url).href;
  const childPid = path.join(copy, 'child-pid.txt');
  const lpacScript = "const fs=require('node:fs');let tick=0;fs.writeFileSync(" + JSON.stringify(childPid) + ",String(process.pid));fs.writeFileSync(" + JSON.stringify(ready) + ",'ready');setInterval(()=>fs.writeFileSync(" + JSON.stringify(heartbeat) + ",String(++tick)),100);setInterval(()=>{},1000);";
  const workerSource = "import { readFileSync } from 'node:fs';import { executeWindowsTest } from " + JSON.stringify(executorUrl) + ";" +
    "const settings=JSON.parse(process.argv[1]);const command={executable:process.execPath,args:['-e'," + JSON.stringify(lpacScript) + "]};" +
    "await executeWindowsTest(command,settings.copy,{timeoutSeconds:20,maxRuntimeBytes:268435456,stateDirectory:settings.state,sandbox:{readPaths:[],writePaths:[settings.grant],network:false,childProcesses:true,maxOutputChars:4000},onProcess(child){const requestPath=child.spawnargs.at(-1);if(typeof requestPath!=='string')return;let request;try{request=JSON.parse(readFileSync(requestPath,'utf8'));}catch{return;}if(request.action!=='write')return;process.stdout.write(JSON.stringify({controllerPid:child.pid,requestPath})+'\\n');child.once('exit',()=>process.exit(86));}});process.exit(0);";
  const worker = spawn(process.execPath, ['--input-type=module', '-e', workerSource, JSON.stringify({ copy, state, grant })], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', error = '';
  worker.stdout.on('data', chunk => { output += String(chunk); });
  worker.stderr.on('data', chunk => { error += String(chunk); });
  const announcement = await eventually('worker did not announce a write controller', async () => {
    const line = output.split(/\r?\n/).find(value => value.startsWith('{'));
    if (!line) return undefined;
    const value = JSON.parse(line) as Announcement;
    if (!Number.isInteger(value.controllerPid) || value.controllerPid <= 0 || typeof value.requestPath !== 'string') throw new Error('invalid worker announcement: ' + line + error);
    return value;
  });
  return { worker, announcement };
}

async function verifyControllerAnnouncement(announcement: Announcement, state: string): Promise<void> {
  const temporary = await realpath(os.tmpdir());
  const request = JSON.parse(await readFile(announcement.requestPath, 'utf8')) as { action?: string; stateDirectory?: string };
  assert.equal(request.action, 'write');
  assert.equal(path.resolve(request.stateDirectory || ''), path.resolve(state));
  assert.equal(path.dirname(path.dirname(announcement.requestPath)), temporary);
  assert.ok(path.basename(path.dirname(announcement.requestPath)).startsWith('black-gravity-controller-'));
  process.kill(announcement.controllerPid, 0);
}

async function freshRecovery(state: string): Promise<void> {
  const executorUrl = new URL('../src/windows-executor.js', import.meta.url).href;
  const child = spawn(process.execPath, ['--input-type=module', '-e', "import { recoverWindowsExecutions } from " + JSON.stringify(executorUrl) + ";await recoverWindowsExecutions(process.argv[1]);", state], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output += String(chunk); });
  child.stderr.on('data', chunk => { output += String(chunk); });
  const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  if (code !== 0) throw new Error(output);
}

async function stopController(worker: ChildProcessWithoutNullStreams, announcement: Announcement): Promise<void> {
  process.kill(announcement.controllerPid, 'SIGTERM');
  await waitForExit(worker, 86);
}

async function crashFixture<T>(run: (resources: { copy: string; state: string; grant: string; ready: string; heartbeat: string }) => Promise<T>): Promise<T> {
  const temporary = await realpath(os.tmpdir());
  const copy = await realpath(await mkdtemp(path.join(temporary, 'black-gravity-copy-')));
  const state = await realpath(await mkdtemp(path.join(temporary, 'black-gravity-recovery-state-')));
  const grant = await realpath(await mkdtemp(path.join(temporary, 'black-gravity-recovery-grant-')));
  try {
    storedAcls([{ path: grant, mode: 'explicit' }]);
    return await run({ copy, state, grant, ready: path.join(copy, 'ready.txt'), heartbeat: path.join(copy, 'heartbeat.txt') }); }
  finally {
    for (const [directory, prefix] of [[copy, 'black-gravity-copy-'], [state, 'black-gravity-recovery-state-'], [grant, 'black-gravity-recovery-grant-']] as const) await removeOwned(directory, prefix);
  }
}

test('Windows recovery preserves a live controller, rejects a reused PID as stale, and recovers in a fresh process', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ copy, state, grant, ready, heartbeat }) => {
    let worker: ChildProcessWithoutNullStreams | undefined;
    let controllerDirectory: string | undefined;
    try {
      const beforeAcl = await readAcl(grant);
      const beforeDacl = storedAcls([{ path: grant }])[0]!;
      const launched = await launchCrashWorker(copy, state, grant, ready, heartbeat);
      worker = launched.worker; controllerDirectory = path.dirname(launched.announcement.requestPath);
      await verifyControllerAnnouncement(launched.announcement, state);
      await eventually('LPAC command did not become ready', async () => (await readFile(ready, 'utf8').catch(() => undefined)) === 'ready' ? true : undefined);
      const active = await readLease(state);
      assert.equal(active.value.controllerPid, launched.announcement.controllerPid);
      assert.equal(await profileExists(active.value.sid), true, 'active lease profile must remain available');
      const created = path.join(grant, 'created-during-execution.txt');
      await writeFile(created, 'created');
      storedAcls([{ path: created, mode: 'foreign' }]);
      const childAcl = storedAcls([{ path: created }])[0]!;
      assert.ok(childAcl.includes(active.value.sid), 'a new child must inherit the active profile grant');
      const activeAcl = await readAcl(grant);
      assert.notEqual(activeAcl, beforeAcl); assert.match(activeAcl, new RegExp(active.value.sid));
      const firstHeartbeat = Number(await eventually('LPAC heartbeat was not written', async () => {
        const value = await readFile(heartbeat, 'utf8').catch(() => undefined);
        return value === undefined ? undefined : value;
      }));
      await recoverWindowsExecutions(state);
      assert.deepEqual((await readLease(state)).value, active.value, 'active lease must remain unchanged');
      assert.equal(await readAcl(grant), activeAcl, 'active ACL must remain unchanged');
      await eventually('LPAC heartbeat stopped during active recovery', async () => Number(await readFile(heartbeat, 'utf8')) > firstHeartbeat ? true : undefined);
      await stopController(worker, launched.announcement); worker = undefined;
      assert.equal((await lstat(active.file)).isFile(), true, 'controller crash leaves a lease for a fresh process');
      // Simulate an interrupted Null grant intent that was never written.
      assert.equal((active.value as Lease & { version?: number }).version, 3);
      await writeFile(active.file, JSON.stringify({ ...active.value, controllerPid: process.pid, controllerStarted: 1, nullDeviceGrant: true }), 'utf8');
      await freshRecovery(state);
      process.kill(process.pid, 0);
      await assert.rejects(readFile(active.file));
      assert.equal(await profileExists(active.value.sid), false, 'stale profile must be removed');
      assert.equal(await readAcl(grant), beforeAcl, 'owned grant ACL must be restored');
      assert.equal(storedAcls([{ path: grant }])[0], beforeDacl, 'stored grant DACL must be restored exactly');
      const recoveredChildAcl = storedAcls([{ path: created }])[0]!;
      assert.equal(recoveredChildAcl, childAcl.replace(new RegExp('\\(A;[^)]*;' + active.value.sid + '\\)'), ''), 'recovery removes only the owned child rule and preserves the foreign update');
      assert.ok(recoveredChildAcl.includes('(A;;FR;;;S-1-5-21-1-2-3-4567)'));
      const childPid = Number(await readFile(path.join(copy, 'child-pid.txt'), 'utf8').catch(() => '0'));
      if (childPid > 0) await eventually('LPAC descendant survived recovery', async () => { try { process.kill(childPid, 0); return undefined; } catch { return true; } });
      const fresh = await executeWindowsTest({ executable: process.execPath, args: ['-e', "process.stdout.write('fresh execution')"] }, copy, { ...settings, stateDirectory: state });
      assert.equal(fresh.exitCode, 0, JSON.stringify(fresh)); assert.equal(fresh.output, 'fresh execution');
    } finally {
      if (worker && worker.exitCode === null) worker.kill('SIGTERM');
      await removeOwned(controllerDirectory, 'black-gravity-controller-');
    }
  });
});

test('Windows recovery leaves an existing scratch replacement untouched but skips missing owned temporary targets', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ copy, state, grant, ready, heartbeat }) => {
    let worker: ChildProcessWithoutNullStreams | undefined;
    let controllerDirectory: string | undefined;
    let staleLease: string | undefined;
    try {
      const beforeGrantAcl = await readAcl(grant);
      const beforeGrantDacl = storedAcls([{ path: grant }])[0]!;
      const launched = await launchCrashWorker(copy, state, grant, ready, heartbeat);
      worker = launched.worker; controllerDirectory = path.dirname(launched.announcement.requestPath);
      await verifyControllerAnnouncement(launched.announcement, state);
      await eventually('LPAC command did not become ready', async () => (await readFile(ready, 'utf8').catch(() => undefined)) === 'ready' ? true : undefined);
      const active = await readLease(state); staleLease = active.file;
      const scratch = await ownedTemporaryDirectory(active.value.scratch, 'black-gravity-scratch-');
      const runtime = await ownedTemporaryDirectory(active.value.runtime, 'black-gravity-runtime-');
      assert.ok(active.value.grants.some(grantEntry => grantEntry.path === scratch));
      assert.ok(active.value.grants.some(grantEntry => grantEntry.path === runtime));
      await stopController(worker, launched.announcement); worker = undefined;
      await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await mkdir(scratch);
      const replacementAcl = await readAcl(scratch);
      await writeFile(active.file, JSON.stringify({ ...active.value, controllerPid: process.pid, controllerStarted: 1 }), 'utf8');
      await assert.rejects(freshRecovery(state), /Granted target identity changed/);
      process.kill(process.pid, 0);
      assert.equal(await profileExists(active.value.sid), false, 'identity mismatch does not stop independent profile cleanup');
      assert.equal(await readAcl(scratch), replacementAcl, 'recovery must not change a replacement ACL');
      assert.equal(await readAcl(grant), beforeGrantAcl, 'independent cleanup still restores other owned grants');
      assert.equal(storedAcls([{ path: grant }])[0], beforeGrantDacl, 'independent cleanup must preserve the stored grant DACL');
      await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await rm(runtime, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await freshRecovery(state);
      await assert.rejects(readFile(active.file)); staleLease = undefined;
    } finally {
      if (worker && worker.exitCode === null) worker.kill('SIGTERM');
      if (staleLease) await rm(staleLease, { force: true });
      await removeOwned(controllerDirectory, 'black-gravity-controller-');
    }
  });
});

test('Windows cleanup revokes the owned SID after a child creates a hardlink', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ copy, state }) => {
    const seedPath = path.join(copy, 'seed.txt');
    await writeFile(seedPath, 'seed content');
    storedAcls([{ path: seedPath, mode: 'foreign' }]);
    const beforeSeedDacl = storedAcls([{ path: seedPath }])[0]!;
    assert.ok(beforeSeedDacl.includes('(A;;FR;;;S-1-5-21-1-2-3-4567)'), 'foreign ACE must exist before run');

    const lpacScript = "const fs=require('node:fs');fs.linkSync('seed.txt','alias.txt');process.stdout.write('hardlink-created');";
    const result = await executeWindowsTest({ executable: process.execPath, args: ['-e', lpacScript] }, copy, { ...settings, stateDirectory: state });

    assert.equal(result.exitCode, 0, result.output);
    assert.equal(result.aliasesDeleted, true, 'DOS aliases must be cleaned');
    assert.equal(result.profileDeleted, true, 'AppContainer profile must be deleted');
    assert.equal(result.output, 'hardlink-created');

    const aliasPath = path.join(copy, 'alias.txt');
    const afterSeedDacl = storedAcls([{ path: seedPath }])[0]!;
    const afterAliasDacl = storedAcls([{ path: aliasPath }])[0]!;

    assert.equal(afterSeedDacl, beforeSeedDacl, 'seed DACL must match exactly before the run');
    assert.equal(afterAliasDacl, beforeSeedDacl, 'alias DACL must match exactly before the run');

    const leaseDir = path.join(state, 'windows-lpac-leases');
    const leaseFiles = await readdir(leaseDir).catch(() => []);
    assert.equal(leaseFiles.filter(f => f.endsWith('.json')).length, 0, 'lease file must be deleted after verified cleanup');

    // Verify independent next run in a different owned copy sharing the same state directory
    const temp = await realpath(os.tmpdir());
    const secondCopy = await realpath(await mkdtemp(path.join(temp, 'black-gravity-copy-')));
    try {
      const nextResult = await executeWindowsTest({ executable: process.execPath, args: ['-e', "process.stdout.write('next run ok')"] }, secondCopy, { ...settings, stateDirectory: state });
      assert.equal(nextResult.exitCode, 0, nextResult.output);
      assert.equal(nextResult.output, 'next run ok');
    } finally {
      await removeOwned(secondCopy, 'black-gravity-copy-');
    }

    // Verify preexisting hardlinks are still refused at admission
    const thirdCopy = await realpath(await mkdtemp(path.join(temp, 'black-gravity-copy-')));
    try {
      const pre1 = path.join(thirdCopy, 'pre1.txt');
      const pre2 = path.join(thirdCopy, 'pre2.txt');
      await writeFile(pre1, 'preexisting');
      await link(pre1, pre2);
      await assert.rejects(
        executeWindowsTest({ executable: process.execPath, args: ['-e', 'process.exit(0)'] }, thirdCopy, { ...settings, stateDirectory: state }),
        /hard links|INVALID_SANDBOX_PATH/
      );
    } finally {
      await removeOwned(thirdCopy, 'black-gravity-copy-');
    }
  });
});

test('Windows recovery handles creating leases and missing SID cannot produce invalid cleanup-failed lease', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ copy, state }) => {
    const temp = await realpath(os.tmpdir());
    const scratch = await realpath(await mkdtemp(path.join(temp, 'black-gravity-scratch-')));
    const runtime = await realpath(await mkdtemp(path.join(temp, 'black-gravity-runtime-')));
    try {
      const nonce = randomUUID();
      const profile = 'black-gravity.test.' + nonce.replace(/-/g, '');
      const leaseDirectory = path.join(state, 'windows-lpac-leases');
      await mkdir(leaseDirectory, { recursive: true });
      const leaseFile = path.join(leaseDirectory, nonce.replace(/-/g, '') + '.json');

      // 1. Legacy creating lease without SID but with real nonce-owned profile created
      const creatingLease = {
        version: 3,
        nonce,
        profile,
        sid: '',
        phase: 'creating',
        controllerPid: process.pid,
        controllerStarted: 1, // dead controller start time
        cwd: copy,
        runtime,
        scratch,
        grants: [],
        logon: '00000000.00000000',
        aliases: [
          { kind: 'copy', physicalRoot: copy, customName: 'BLACK_GRAVITY.TEST.' + nonce.toUpperCase() + '.COPY', drive: 'Z:', aliasRoot: 'Z:\\', customTarget: '\\??\\' + copy, driveTarget: '\\??\\BLACK_GRAVITY.TEST.' + nonce.toUpperCase() + '.COPY', volume: 0, fileIndexHigh: 0, fileIndexLow: 0 },
          { kind: 'runtime', physicalRoot: runtime, customName: 'BLACK_GRAVITY.TEST.' + nonce.toUpperCase() + '.RUNTIME', drive: 'Y:', aliasRoot: 'Y:\\', customTarget: '\\??\\' + runtime, driveTarget: '\\??\\BLACK_GRAVITY.TEST.' + nonce.toUpperCase() + '.RUNTIME', volume: 0, fileIndexHigh: 0, fileIndexLow: 0 },
          { kind: 'scratch', physicalRoot: scratch, customName: 'BLACK_GRAVITY.TEST.' + nonce.toUpperCase() + '.SCRATCH', drive: 'X:', aliasRoot: 'X:\\', customTarget: '\\??\\' + scratch, driveTarget: '\\??\\BLACK_GRAVITY.TEST.' + nonce.toUpperCase() + '.SCRATCH', volume: 0, fileIndexHigh: 0, fileIndexLow: 0 },
        ],
        nullDeviceGrant: false,
        jobCreated: false,
      };

      const sid1 = ownedProfile(profile, 'create');
      try {
        assert.equal(await profileExists(sid1), true);
        await writeFile(leaseFile, JSON.stringify(creatingLease), 'utf8');
        await recoverWindowsExecutions(state);
        assert.equal(await profileExists(sid1), false, 'creating lease without SID removes existing nonce-owned profile');
        await assert.rejects(readFile(leaseFile), { code: 'ENOENT' });
      } finally {
        ownedProfile(profile, 'remove');
      }

      // 2. Creating lease with persisted SID
      const nonce2 = randomUUID(), profile2 = 'black-gravity.test.' + nonce2.replaceAll('-', '');
      const file2 = path.join(leaseDirectory, nonce2.replaceAll('-', '') + '.json');
      const sid2 = ownedProfile(profile2, 'create');
      try {
        assert.equal(await profileExists(sid2), true);
        const aliases = creatingLease.aliases.map(alias => {
          const customName = 'BLACK_GRAVITY.TEST.' + nonce2.toUpperCase() + '.' + alias.kind.toUpperCase();
          return { ...alias, customName, driveTarget: '\\??\\' + customName };
        });
        await writeFile(file2, JSON.stringify({ ...creatingLease, nonce: nonce2, profile: profile2, sid: sid2, aliases }), 'utf8');
        await recoverWindowsExecutions(state);
        assert.equal(await profileExists(sid2), false, 'creating recovery must remove only the owned profile');
        await assert.rejects(readFile(file2), { code: 'ENOENT' });
      } finally {
        ownedProfile(profile2, 'remove');
      }
    } finally {
      await removeOwned(scratch, 'black-gravity-scratch-');
      await removeOwned(runtime, 'black-gravity-runtime-');
    }
  });
});

test('Windows recovery settles a lease written before the rename by the names it recorded', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ state }) => {
    const temp = await realpath(os.tmpdir());
    const copy = await realpath(await mkdtemp(path.join(temp, 'agy-mcp-copy-')));
    const scratch = await realpath(await mkdtemp(path.join(temp, 'agy-mcp-scratch-')));
    const runtime = await realpath(await mkdtemp(path.join(temp, 'agy-mcp-runtime-')));
    try {
      const nonce = randomUUID();
      const profile = 'agy.test.' + nonce.replaceAll('-', '');
      const leaseDirectory = path.join(state, 'windows-lpac-leases');
      await mkdir(leaseDirectory, { recursive: true });
      const leaseFile = path.join(leaseDirectory, nonce.replaceAll('-', '') + '.json');
      const alias = (kind: string, physicalRoot: string, drive: string) => {
        const customName = 'AGY.TEST.' + nonce.toUpperCase() + '.' + kind.toUpperCase();
        return { kind, physicalRoot, customName, drive, aliasRoot: drive + '\\', customTarget: '\\??\\' + physicalRoot, driveTarget: '\\??\\' + customName, volume: 0, fileIndexHigh: 0, fileIndexLow: 0 };
      };
      const lease = {
        version: 3, nonce, profile, sid: '', phase: 'creating', controllerPid: process.pid, controllerStarted: 1,
        cwd: copy, runtime, scratch, grants: [], logon: '00000000.00000000',
        aliases: [alias('copy', copy, 'Z:'), alias('runtime', runtime, 'Y:'), alias('scratch', scratch, 'X:')],
        nullDeviceGrant: false, jobCreated: false,
      };
      const sid = ownedProfile(profile, 'create');
      try {
        assert.equal(await profileExists(sid), true);
        await writeFile(leaseFile, JSON.stringify(lease), 'utf8');
        await recoverWindowsExecutions(state, { requireIdle: true });
        assert.equal(await profileExists(sid), false, 'the profile recorded under the earlier name is removed');
        await assert.rejects(readFile(leaseFile), { code: 'ENOENT' });
      } finally {
        ownedProfile(profile, 'remove');
      }
    } finally {
      await removeOwned(copy, 'agy-mcp-copy-');
      await removeOwned(scratch, 'agy-mcp-scratch-');
      await removeOwned(runtime, 'agy-mcp-runtime-');
    }
  });
});

test('Windows cleanup budget allows growth above admission limit and preserves foreign ACL', { skip: process.platform !== 'win32' }, async () => {
  const temp = await realpath(os.tmpdir());
  const compileDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-harness-compile-')));
  const runnerExe = path.join(compileDir, 'runner.exe');
  const harnessExe = path.join(compileDir, 'harness.exe');
  const compiler = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  try {
    execFileSync(compiler, ['/nologo', '/target:exe', '/platform:x64', '/r:System.Web.Extensions.dll', '/nowarn:0649', '/out:' + runnerExe, path.resolve('native/windows-test-runner.cs')], { windowsHide: true });
    execFileSync(compiler, ['/nologo', '/target:exe', '/platform:x64', '/r:System.Web.Extensions.dll', '/nowarn:0649', '/out:' + harnessExe, path.resolve('tests/windows-alias-harness.cs')], { windowsHide: true });
    const output = execFileSync(harnessExe, [runnerExe, 'cleanup-growth'], { windowsHide: true, encoding: 'utf8' });
    assert.equal(output.trim(), '');
  } finally {
    await removeOwned(compileDir, 'black-gravity-harness-compile-');
  }
});

test('Windows cleanup revokes the owned SID from post-grant final reparse point without following destination', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ copy, state, grant, ready, heartbeat }) => {
    let worker: ChildProcessWithoutNullStreams | undefined;
    let controllerDirectory: string | undefined;
    const temp = await realpath(os.tmpdir());
    const destination = await realpath(await mkdtemp(path.join(temp, 'black-gravity-destination-')));
    try {
      const destFile = path.join(destination, 'dest-file.txt');
      await writeFile(destFile, 'destination content');
      storedAcls([{ path: destination, mode: 'foreign' }, { path: destFile, mode: 'foreign' }]);

      const launched = await launchCrashWorker(copy, state, grant, ready, heartbeat);
      worker = launched.worker;
      controllerDirectory = path.dirname(launched.announcement.requestPath);
      await verifyControllerAnnouncement(launched.announcement, state);
      await eventually('LPAC command did not become ready', async () => (await readFile(ready, 'utf8').catch(() => undefined)) === 'ready' ? true : undefined);

      const active = await readLease(state);
      const sibling = path.join(grant, 'sibling.txt');
      await writeFile(sibling, 'sibling content');
      storedAcls([{ path: sibling, mode: 'foreign' }]);

      const junction = path.join(grant, 'junction-link');
      await symlink(destination, junction, 'junction');

      // Add ACE with the real active.value.sid to destination, destFile, and junction
      storedAcls([
        { path: destination, mode: active.value.sid },
        { path: destFile, mode: active.value.sid },
        { path: junction, mode: active.value.sid },
      ]);
      const beforeDestDirDacl = storedAcls([{ path: destination }])[0]!;
      const beforeDestFileDacl = storedAcls([{ path: destFile }])[0]!;
      const beforeJunctionDacl = storedAcls([{ path: junction }])[0]!;
      assert.ok(beforeDestDirDacl.includes(active.value.sid), 'destination intentionally has real execution SID');
      assert.ok(beforeDestFileDacl.includes(active.value.sid), 'destFile intentionally has real execution SID');
      assert.ok(beforeJunctionDacl.includes(active.value.sid), 'junction link has real execution SID');

      await stopController(worker, launched.announcement);
      worker = undefined;

      await freshRecovery(state);

      const afterDestDirDacl = storedAcls([{ path: destination }])[0]!;
      const afterDestFileDacl = storedAcls([{ path: destFile }])[0]!;
      assert.equal(afterDestDirDacl, beforeDestDirDacl, 'destination directory DACL must be untouched and preserve exact SDDL');
      assert.equal(afterDestFileDacl, beforeDestFileDacl, 'destination file DACL must be untouched and preserve exact SDDL');
      assert.ok(afterDestDirDacl.includes(active.value.sid), 'destination intentionally preserved the execution SID');
      assert.ok(afterDestFileDacl.includes(active.value.sid), 'destination file intentionally preserved the execution SID');

      const afterJunctionDacl = storedAcls([{ path: junction }])[0]!;
      assert.ok(!afterJunctionDacl.includes(active.value.sid), 'junction link must have owned execution SID removed');

      const siblingDacl = storedAcls([{ path: sibling }])[0]!;
      assert.ok(siblingDacl.includes('(A;;FR;;;S-1-5-21-1-2-3-4567)'), 'sibling foreign ACE preserved');
      assert.ok(!siblingDacl.includes(active.value.sid), 'owned SID removed from sibling');

      await assert.rejects(readFile(active.file));

      const preJunctionCopy = await realpath(await mkdtemp(path.join(temp, 'black-gravity-copy-')));
      try {
        await symlink(destination, path.join(preJunctionCopy, 'pre-junction'), 'junction');
        await assert.rejects(
          executeWindowsTest(
            { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
            preJunctionCopy,
            { ...settings, stateDirectory: state }
          ),
          /reparse point|INVALID_SANDBOX_PATH/
        );
      } finally {
        await removeOwned(preJunctionCopy, 'black-gravity-copy-');
      }
    } finally {
      if (worker && worker.exitCode === null) worker.kill('SIGTERM');
      await removeOwned(destination, 'black-gravity-destination-');
      await removeOwned(controllerDirectory, 'black-gravity-controller-');
    }
  });
});

test('Windows test admission allows retry of terminal local-executor failure after native recovery while preserving prior failure', { skip: process.platform !== 'win32' }, async () => {
  const temp = await realpath(os.tmpdir());
  const repoDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-repo-')));
  const stateDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-state-')));
  execFileSync('git', ['init', '--quiet', repoDir]);
  await writeFile(path.join(repoDir, 'source.txt'), 'initial source');
  const startupLease = path.join(stateDir, 'windows-lpac-leases', 'initial-invalid.json');
  await mkdir(path.dirname(startupLease), { recursive: true });
  await writeFile(startupLease, 'invalid-initial-lease');
  const mockPath = path.resolve('tests/mock-agy.mjs');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    BRIDGE_TEST_EXECUTOR: 'windows-lpac',
    BRIDGE_STATE_DIRECTORY: stateDir,
    DEFAULT_TIMEOUT_SECONDS: '180',
    BRIDGE_WINDOWS_NODE_RUNTIME: process.env.BRIDGE_WINDOWS_NODE_RUNTIME,
    BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY: process.env.BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY,
  });
  const adapter = new CliAdapter(config, [mockPath]);
  const tasks = new TaskManager(adapter, config);
  const until = async (taskId: string, manager: TaskManager = tasks, timeout = 180000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const task = manager.status(taskId);
      if (['completed', 'failed', 'cancelled', 'timeout'].includes(task.status)) return task;
      await pause(25);
    }
    throw new Error('Task did not finish: ' + JSON.stringify(manager.status(taskId)));
  };
  try {
    await adapter.discover();
    const initTask = await tasks.run({ prompt: 'write:test', workingDirectory: repoDir });
    const initDone = await until(initTask.taskId);
    assert.equal(initDone.status, 'completed');
    const preview = await tasks.preview(initTask.taskId);

    const missingExe = path.join(temp, 'non-existent-executable-' + randomUUID() + '.exe');
    const failedTest = await tasks.startTests(initTask.taskId, preview.sha256, { executable: missingExe, args: [] }, 0, 120);
    const failedDone = await until(failedTest.taskId);
    assert.equal(failedDone.status, 'failed');
    assert.equal(failedDone.usageProvenance, 'local-executor');
    assert.equal(failedDone.error?.code, 'WINDOWS_EXECUTION_RECOVERY_FAILED');
    await assert.rejects(tasks.preview(failedDone.taskId), { code: 'TASK_NOT_READY' });
    await assert.rejects(lstat(archiveDirectoryFor(stateDir, failedDone.taskId)), { code: 'ENOENT' });
    assert.equal(new StateStore(stateDir).load().find(entry => entry.record.taskId === failedDone.taskId)?.project, undefined, 'pre-preparation failed child must not own workspace custody');
    await rm(startupLease, { force: true });

    const validCommand = { executable: process.execPath, args: ['-e', "process.stdout.write('retry-success')"] };
    await assert.rejects(
      tasks.startTests(failedDone.taskId, '0'.repeat(64), validCommand, 0, 120),
      { code: 'REVIEW_CHANGED' }
    );
    const retryAttempt = await tasks.startTests(failedDone.taskId, preview.sha256, validCommand, 0, 120);
    assert.notEqual(retryAttempt.taskId, failedDone.taskId, 'retry must create a new task attempt');
    assert.equal(retryAttempt.parentTaskId, failedDone.taskId, 'new attempt must record parentTaskId');

    const priorTask = tasks.status(failedDone.taskId);
    assert.equal(priorTask.status, 'failed', 'prior failed record must remain failed');
    assert.equal(priorTask.usageProvenance, 'local-executor');

    const retryDone = await until(retryAttempt.taskId);
    assert.equal(retryDone.status, 'completed', JSON.stringify(retryDone));
    assert.equal(retryDone.tests?.at(-1)?.output, 'retry-success');
    await assert.rejects(tasks.preview(failedDone.taskId), { code: 'TASK_NOT_READY' });
    await assert.rejects(lstat(archiveDirectoryFor(stateDir, failedDone.taskId)), { code: 'ENOENT' });
    assert.equal(new StateStore(stateDir).load().find(entry => entry.record.taskId === failedDone.taskId)?.project, undefined, 'retry must not retroactively assign project custody to failed child');
    await assert.rejects(
      tasks.startTests(failedDone.taskId, preview.sha256, validCommand, 0, 120),
      { code: 'TASK_NOT_READY' }
    );

    const secondFailure = await tasks.startTests(retryDone.taskId, preview.sha256, { executable: missingExe, args: [] }, 0, 120);
    const secondFailedDone = await until(secondFailure.taskId);
    assert.equal(secondFailedDone.status, 'failed');
    assert.equal(secondFailedDone.usageProvenance, 'local-executor');

    const leaseDir = path.join(stateDir, 'windows-lpac-leases');
    await mkdir(leaseDir, { recursive: true });
    const corruptLeaseFile = path.join(leaseDir, 'corrupt-lease.json');
    await writeFile(corruptLeaseFile, 'invalid-json-content', 'utf8');
    try {
      await assert.rejects(
        tasks.startTests(secondFailedDone.taskId, preview.sha256, validCommand, 0, 120),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal((err as { code?: string }).code, 'WINDOWS_EXECUTION_RECOVERY_FAILED');
          return true;
        }
      );
    } finally {
      await rm(corruptLeaseFile, { force: true });
    }

    const recovered = await tasks.startTests(secondFailedDone.taskId, preview.sha256, validCommand, 0, 120);
    assert.equal((await until(recovered.taskId)).status, 'completed');
    const modelTask = await tasks.run({ prompt: 'failure:test', workingDirectory: repoDir });
    const modelDone = await until(modelTask.taskId);
    assert.equal(modelDone.status, 'failed');
    assert.notEqual(modelDone.usageProvenance, 'local-executor');
    await assert.rejects(
      tasks.startTests(modelDone.taskId, (await tasks.preview(modelDone.taskId)).sha256, validCommand, 0, 120),
      { code: 'TASK_NOT_READY' }
    );

    const slowTask = await tasks.run({ prompt: 'cancel:test', workingDirectory: repoDir });
    await eventually('cancel fixture did not start', async () => ['running', 'streaming'].includes(tasks.status(slowTask.taskId).status) ? true : undefined, 180000);
    await tasks.cancel(slowTask.taskId);
    assert.equal((await until(slowTask.taskId)).status, 'cancelled');
    await assert.rejects(
      tasks.startTests(slowTask.taskId, (await tasks.preview(slowTask.taskId)).sha256, validCommand, 0, 120),
      { code: 'TASK_NOT_READY' }
    );
    const timed = await tasks.run({ prompt: 'timeout:test', workingDirectory: repoDir, timeoutSeconds: 1 });
    assert.equal((await until(timed.taskId)).status, 'timeout');
    await assert.rejects(tasks.startTests(timed.taskId, (await tasks.preview(timed.taskId)).sha256, validCommand, 0, 120), { code: 'TASK_NOT_READY' });
  } finally {
    await tasks.shutdown();
    await rm(startupLease, { force: true });
    for (const project of new Map(new StateStore(stateDir).load().filter(entry => entry.project).map(entry => [entry.project!.copyDirectory, entry.project!])).values()) await discardProjectCopy(project);
    await ownedTemporaryDirectory(repoDir, 'black-gravity-retry-repo-');
    await ownedTemporaryDirectory(stateDir, 'black-gravity-retry-state-');
    await rm(repoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});


test('Windows recovery retry refuses active leases until owned execution is cancelled', { skip: process.platform !== 'win32' }, async () => {
  await crashFixture(async ({ copy, state, ready }) => {
    const controller = new AbortController();
    const running = executeWindowsTest({ executable: process.execPath, args: ['-e', "require('node:fs').writeFileSync('ready.txt','ready');setInterval(()=>{},1000)"] }, copy,
      { ...settings, timeoutSeconds: 60, stateDirectory: state, signal: controller.signal })
      .then(result => ({ result, error: undefined }), error => ({ result: undefined, error: error as unknown }));
    try {
      await eventually('owned LPAC command did not become ready', async () => await readFile(ready, 'utf8').catch(() => '') === 'ready' ? true : undefined, 60000);
      const active = await readLease(state);
      await assert.rejects(recoverWindowsExecutions(state, { requireIdle: true }), error => {
        assert.ok(error instanceof Error);
        assert.equal((error as { code?: string }).code, 'WINDOWS_EXECUTION_RECOVERY_FAILED');
        assert.match(error.message, /Active Windows executions/);
        return true;
      });
      assert.equal((await readLease(state)).value.nonce, active.value.nonce);
      assert.equal(await profileExists(active.value.sid), true);
    } finally {
      controller.abort();
      const outcome = await running;
      if (outcome.error) throw outcome.error;
      assert.ok(outcome.result);
      assert.equal(outcome.result.error, 'Command cancelled');
      await recoverWindowsExecutions(state, { requireIdle: true });
    }
  });
});

test('Windows pre-preparation retry verifies immutable parent archive while live or displaced and fails closed on missing, tampered, mismatched checkpoint, invalid lease, or non-recovery failure', { skip: process.platform !== 'win32' }, async () => {
  const temp = await realpath(os.tmpdir());
  const repoDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-displaced-repo-')));
  const stateDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-displaced-state-')));
  execFileSync('git', ['init', '--quiet', repoDir]);
  await writeFile(path.join(repoDir, 'source.txt'), 'initial source');
  const startupLease = path.join(stateDir, 'windows-lpac-leases', 'initial-invalid.json');
  await mkdir(path.dirname(startupLease), { recursive: true });
  await writeFile(startupLease, 'invalid-initial-lease');
  const mockPath = path.resolve('tests/mock-agy.mjs');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    BRIDGE_TEST_EXECUTOR: 'windows-lpac',
    BRIDGE_STATE_DIRECTORY: stateDir,
    DEFAULT_TIMEOUT_SECONDS: '180',
    BRIDGE_WINDOWS_NODE_RUNTIME: process.env.BRIDGE_WINDOWS_NODE_RUNTIME,
    BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY: process.env.BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY,
  });
  const adapter = new CliAdapter(config, [mockPath]);
  const tasks = new TaskManager(adapter, config);
  const until = async (taskId: string, manager: TaskManager = tasks, timeout = 180000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const task = manager.status(taskId);
      if (['completed', 'failed', 'cancelled', 'timeout'].includes(task.status)) return task;
      await pause(25);
    }
    throw new Error('Task did not finish: ' + JSON.stringify(manager.status(taskId)));
  };
  const assertFailedChildUntouched = async (manager: TaskManager, failedTaskId: string, expectedTaskCount: number) => {
    assert.equal(manager.list().length, expectedTaskCount, 'refused pre-prep retry must not create or launch a new task');
    const prior = manager.status(failedTaskId);
    assert.equal(prior.status, 'failed');
    await assert.rejects(manager.preview(failedTaskId), { code: 'TASK_NOT_READY' });
    await assert.rejects(lstat(archiveDirectoryFor(stateDir, failedTaskId)), { code: 'ENOENT' });
    assert.equal(
      new StateStore(stateDir).load().find(entry => entry.record.taskId === failedTaskId)?.project,
      undefined,
      'failed child must retain zero workspace custody',
    );
  };
  try {
    await adapter.discover();
    const initTask = await tasks.run({ prompt: 'write:displaced', workingDirectory: repoDir });
    const initDone = await until(initTask.taskId);
    assert.equal(initDone.status, 'completed');
    const previewInit = await tasks.preview(initTask.taskId);

    const missingExe = path.join(temp, 'non-existent-executable-' + randomUUID() + '.exe');
    const failedTest = await tasks.startTests(initTask.taskId, previewInit.sha256, { executable: missingExe, args: [] }, 0, 120);
    const failedDone = await until(failedTest.taskId);
    assert.equal(failedDone.status, 'failed');
    assert.equal(failedDone.error?.code, 'WINDOWS_EXECUTION_RECOVERY_FAILED');
    assert.equal(failedDone.startedAt, undefined);
    const validCommand = {
      executable: process.execPath,
      args: ['-e', "const fs=require('node:fs');if(!fs.existsSync('BLACK_GRAVITY_TEST.md'))process.exit(9);process.stdout.write('displaced-retry-ok')"],
    };
    const countBeforeNegatives = tasks.list().length;

    // Negative 1 (lease still invalid): must reject WINDOWS_EXECUTION_RECOVERY_FAILED with zero executor launch.
    await assert.rejects(
      tasks.startTests(failedDone.taskId, previewInit.sha256, validCommand, 0, 120),
      { code: 'WINDOWS_EXECUTION_RECOVERY_FAILED' },
    );
    await assertFailedChildUntouched(tasks, failedDone.taskId, countBeforeNegatives);
    await rm(startupLease, { force: true });

    // Negative 2 (missing parent archive EVEN WHILE LIVE occupant): no live-only fallback or unarchived exemption.
    const parentArchiveDir = archiveDirectoryFor(stateDir, initTask.taskId);
    const movedArchiveDir = path.join(stateDir, 'moved-archive-' + randomUUID());
    await rename(parentArchiveDir, movedArchiveDir);
    try {
      await assert.rejects(
        tasks.startTests(failedDone.taskId, previewInit.sha256, validCommand, 0, 120),
        { code: 'CHECKPOINT_MISSING' },
      );
      await assertFailedChildUntouched(tasks, failedDone.taskId, countBeforeNegatives);
    } finally {
      await rename(movedArchiveDir, parentArchiveDir);
    }

    // Negative 3 (tampered archive blob EVEN WHILE LIVE occupant): full blob verification at admission.
    const blobsDir = path.join(parentArchiveDir, 'blobs');
    const blobNames = await readdir(blobsDir);
    assert.ok(blobNames.length > 0, 'parent archive must contain verified blobs');
    const firstBlobPath = path.join(blobsDir, blobNames[0]!);
    const originalBlob = await readFile(firstBlobPath);
    await writeFile(firstBlobPath, Buffer.concat([originalBlob, Buffer.from('x')]));
    try {
      await assert.rejects(
        tasks.startTests(failedDone.taskId, previewInit.sha256, validCommand, 0, 120),
        { code: 'CHECKPOINT_INVALID' },
      );
      await assertFailedChildUntouched(tasks, failedDone.taskId, countBeforeNegatives);
    } finally {
      await writeFile(firstBlobPath, originalBlob);
    }

    // Negative 4 (wrong expected patch SHA): must reject REVIEW_CHANGED with zero launch.
    await assert.rejects(
      tasks.startTests(failedDone.taskId, '0'.repeat(64), validCommand, 0, 120),
      { code: 'REVIEW_CHANGED' },
    );
    await assertFailedChildUntouched(tasks, failedDone.taskId, countBeforeNegatives);

    // Displace initTask in the canonical workspace with an unrelated task on the same repo.
    const displacingTask = await tasks.run({ prompt: 'consult:displace', workingDirectory: repoDir });
    const displacingDone = await until(displacingTask.taskId);
    assert.equal(displacingDone.status, 'completed');
    const countAfterDisplace = tasks.list().length;

    // Negative 5 (displaced parent with tampered patch.diff): must fail closed with CHECKPOINT_INVALID and zero launch.
    const parentPatchPath = path.join(parentArchiveDir, 'patch.diff');
    const originalPatch = await readFile(parentPatchPath, 'utf8');
    await writeFile(parentPatchPath, originalPatch + '\n# tampered', 'utf8');
    try {
      await assert.rejects(
        tasks.startTests(failedDone.taskId, previewInit.sha256, validCommand, 0, 120),
        { code: 'CHECKPOINT_INVALID' },
      );
      await assertFailedChildUntouched(tasks, failedDone.taskId, countAfterDisplace);
    } finally {
      await writeFile(parentPatchPath, originalPatch, 'utf8');
    }

    // Positive: with intact parent archive, retry restores initTask's checkpoint, keeps failedDone failed/unarchived, and records causal parentTaskId.
    const retryAttempt = await tasks.startTests(failedDone.taskId, previewInit.sha256, validCommand, 0, 120);
    assert.equal(retryAttempt.parentTaskId, failedDone.taskId);
    const retryDone = await until(retryAttempt.taskId);
    assert.equal(retryDone.status, 'completed', JSON.stringify(retryDone));
    assert.equal(retryDone.tests?.at(-1)?.output, 'displaced-retry-ok');
    assert.equal(tasks.status(failedDone.taskId).status, 'failed');
    await assert.rejects(tasks.preview(failedDone.taskId), { code: 'TASK_NOT_READY' });
    await assert.rejects(lstat(archiveDirectoryFor(stateDir, failedDone.taskId)), { code: 'ENOENT' });
    assert.equal(new StateStore(stateDir).load().find(entry => entry.record.taskId === failedDone.taskId)?.project, undefined);

    // Negative 6 (mismatched recorded pin, non-recovery pre-prep error, and discarded parent).
    await tasks.shutdown();
    await writeFile(startupLease, 'invalid-second-lease');
    const tasks2 = new TaskManager(adapter, config);
    let base2Id = '';
    let failed2Id = '';
    let preview2Sha = '';
    try {
      const base2 = await until((await tasks2.run({ prompt: 'write:discard-parent', workingDirectory: repoDir })).taskId, tasks2);
      assert.equal(base2.status, 'completed');
      base2Id = base2.taskId;
      preview2Sha = (await tasks2.preview(base2.taskId)).sha256;
      const failed2 = await until((await tasks2.startTests(base2.taskId, preview2Sha, { executable: missingExe, args: [] }, 0, 120)).taskId, tasks2);
      assert.equal(failed2.status, 'failed');
      assert.equal(failed2.error?.code, 'WINDOWS_EXECUTION_RECOVERY_FAILED');
      failed2Id = failed2.taskId;
      await rm(startupLease, { force: true });
    } finally {
      await tasks2.shutdown();
    }

    const failed2StateFile = path.join(stateDir, `${failed2Id}.json`);
    const originalFailed2Json = await readFile(failed2StateFile, 'utf8');

    // Negative 6a: mismatched recorded checkpoint pin in failed child options.
    const mismatchedPinData = JSON.parse(originalFailed2Json) as { options: Record<string, unknown> };
    mismatchedPinData.options.parentArchiveSha256 = 'f'.repeat(64);
    await writeFile(failed2StateFile, JSON.stringify(mismatchedPinData), 'utf8');
    const tasksPinCheck = new TaskManager(adapter, config);
    try {
      const countBeforePin = tasksPinCheck.list().length;
      await assert.rejects(
        tasksPinCheck.startTests(failed2Id, preview2Sha, validCommand, 0, 120),
        { code: 'TASK_NOT_READY' },
      );
      await assertFailedChildUntouched(tasksPinCheck, failed2Id, countBeforePin);
    } finally {
      await tasksPinCheck.shutdown();
    }

    // Negative 6b: arbitrary non-recovery pre-prep error (e.g. SANDBOX_POLICY_CHANGED) is refused.
    const nonRecoveryData = JSON.parse(originalFailed2Json) as { record: { error?: { code: string; message: string } } };
    nonRecoveryData.record.error = { code: 'SANDBOX_POLICY_CHANGED', message: 'Simulated non-recovery pre-prep error' };
    await writeFile(failed2StateFile, JSON.stringify(nonRecoveryData), 'utf8');
    const tasksNonRecovery = new TaskManager(adapter, config);
    try {
      const countBeforeNonRecovery = tasksNonRecovery.list().length;
      await assert.rejects(
        tasksNonRecovery.startTests(failed2Id, preview2Sha, validCommand, 0, 120),
        { code: 'TASK_NOT_READY' },
      );
      await assertFailedChildUntouched(tasksNonRecovery, failed2Id, countBeforeNonRecovery);
    } finally {
      await tasksNonRecovery.shutdown();
      await writeFile(failed2StateFile, originalFailed2Json, 'utf8');
    }

    // Negative 6c: discarding parent prevents retrying pre-preparation failure.
    const tasksDiscard = new TaskManager(adapter, config);
    try {
      await tasksDiscard.discard(base2Id);
      const countAfterDiscard = tasksDiscard.list().length;
      await assert.rejects(
        tasksDiscard.startTests(failed2Id, preview2Sha, validCommand, 0, 120),
        { code: 'TASK_NOT_READY' },
      );
      await assertFailedChildUntouched(tasksDiscard, failed2Id, countAfterDiscard);
    } finally {
      await tasksDiscard.shutdown();
    }
  } finally {
    await tasks.shutdown();
    await rm(startupLease, { force: true });
    for (const project of new Map(new StateStore(stateDir).load().filter(entry => entry.project).map(entry => [entry.project!.copyDirectory, entry.project!])).values()) await discardProjectCopy(project);
    await ownedTemporaryDirectory(repoDir, 'black-gravity-retry-displaced-repo-');
    await ownedTemporaryDirectory(stateDir, 'black-gravity-retry-displaced-state-');
    await rm(repoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test('Windows consecutive pre-preparation failures retry through chained original parent checkpoint with zero extra executor launches on rejections', { skip: process.platform !== 'win32' }, async () => {
  const temp = await realpath(os.tmpdir());
  const repoDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-chain-repo-')));
  const otherRepoDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-chain-other-')));
  const stateDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-retry-chain-state-')));
  execFileSync('git', ['init', '--quiet', repoDir]);
  execFileSync('git', ['init', '--quiet', otherRepoDir]);
  await writeFile(path.join(repoDir, 'source.txt'), 'initial chain source');
  await writeFile(path.join(otherRepoDir, 'other.txt'), 'other repo');
  const leaseDir = path.join(stateDir, 'windows-lpac-leases');
  const startupLease = path.join(leaseDir, 'initial-invalid.json');
  const launchLease = path.join(leaseDir, 'launch-invalid.json');
  const blockerReadyFile = path.join(stateDir, 'chain-blocker-ready.txt');
  await mkdir(leaseDir, { recursive: true });
  await writeFile(startupLease, 'invalid-initial-lease', 'utf8');
  const mockPath = path.resolve('tests/mock-agy.mjs');
  const config = loadConfig({
    AGY_PATH: process.execPath,
    BRIDGE_TEST_EXECUTOR: 'windows-lpac',
    BRIDGE_STATE_DIRECTORY: stateDir,
    DEFAULT_TIMEOUT_SECONDS: '180',
    BRIDGE_WINDOWS_NODE_RUNTIME: process.env.BRIDGE_WINDOWS_NODE_RUNTIME,
    BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY: process.env.BRIDGE_WINDOWS_NODE_CACHE_DIRECTORY,
  });
  config.maxConcurrentTasks = 1;
  const blockerPrompt = 'chain-blocker:wait-indefinitely';
  let blockerChild: ChildProcessWithoutNullStreams | undefined;
  let blockerExited = false;
  class ChainBlockerAdapter extends CliAdapter {
    override spawnTask(
      options: Parameters<CliAdapter['spawnTask']>[0],
      model: Parameters<CliAdapter['spawnTask']>[1],
      cwd: Parameters<CliAdapter['spawnTask']>[2],
    ): ReturnType<CliAdapter['spawnTask']> {
      if (options.prompt !== blockerPrompt) {
        return super.spawnTask(options, model, cwd);
      }
      const blockerScript = [
        "const fs=require('node:fs');",
        "process.stdout.write(JSON.stringify({event:'init',conversation_id:'chain-blocker-conv',init:{cwd:process.cwd()}})+'\\n');",
        "fs.writeFileSync(process.env.CHAIN_BLOCKER_READY_FILE,String(process.pid),'utf8');",
        "setInterval(()=>{},60000);",
      ].join('');
      const child = spawn(process.execPath, ['-e', blockerScript], {
        cwd,
        env: { ...process.env, CHAIN_BLOCKER_READY_FILE: blockerReadyFile },
        windowsHide: true,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      blockerChild = child;
      blockerExited = false;
      child.once('exit', () => { blockerExited = true; });
      child.stdin.on('error', () => {});
      child.stdin.end();
      return child;
    }
  }
  const adapter = new ChainBlockerAdapter(config, [mockPath]);
  const tasks = new TaskManager(adapter, config);
  const until = async (taskId: string, manager: TaskManager = tasks, timeout = 180000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const task = manager.status(taskId);
      if (['completed', 'failed', 'cancelled', 'timeout'].includes(task.status)) return task;
      await pause(25);
    }
    throw new Error('Task did not finish: ' + JSON.stringify(manager.status(taskId)));
  };
  const assertBlockerAlive = (blockerId: string, phase: string) => {
    assert.ok(blockerChild && typeof blockerChild.pid === 'number', `${phase}: blocker child process handle must be present`);
    assert.equal(blockerExited, false, `${phase}: blocker child must still be alive`);
    assert.equal(blockerChild.exitCode, null, `${phase}: blocker child exitCode must be null`);
    assert.equal(blockerChild.signalCode, null, `${phase}: blocker child signalCode must be null`);
    const status = tasks.status(blockerId);
    assert.equal(status.pid, blockerChild.pid, `${phase}: managed blocker task must track exact blocker child PID`);
    assert.ok(['running', 'streaming'].includes(status.status), `${phase}: blocker task must remain active, got ${status.status}`);
  };
  const countWindowsExecutorLaunches = (manager: TaskManager): number => {
    let launches = 0;
    for (const item of manager.list()) {
      for (const event of manager.readEvents(item.taskId).events) {
        if (event.type === 'process.started' && (event.data as { executor?: unknown } | undefined)?.executor === 'windows-lpac') {
          launches += 1;
        }
      }
    }
    return launches;
  };
  const assertFailedImmutable = async (manager: TaskManager, failedId: string) => {
    const status = manager.status(failedId);
    assert.equal(status.status, 'failed');
    assert.equal(status.usageProvenance, 'local-executor');
    assert.equal(status.error?.code, 'WINDOWS_EXECUTION_RECOVERY_FAILED');
    assert.equal(status.startedAt, undefined);
    await assert.rejects(manager.preview(failedId), { code: 'TASK_NOT_READY' });
    await assert.rejects(lstat(archiveDirectoryFor(stateDir, failedId)), { code: 'ENOENT' });
    assert.equal(
      new StateStore(stateDir).load().find(entry => entry.record.taskId === failedId)?.project,
      undefined,
      'pre-preparation failed record must never gain workspace custody',
    );
    const startedEvents = manager.readEvents(failedId).events.filter(event => event.type === 'process.started');
    assert.equal(startedEvents.length, 0, 'pre-preparation failed record must have zero process.started events');
  };
  const observedControllerSpawns: Array<{ proc: { pid?: number }; action: string }> = [];
  const observedCommandDispatches: Array<{ proc: { pid?: number }; action: 'write' | 'read-only' }> = [];
  const observerErrors: string[] = [];
  const normalizedTemp = path.resolve(temp).toLowerCase();
  const normalizedStateDir = path.resolve(stateDir).toLowerCase();
  const allowedControllerActions = new Set(['write', 'read-only', 'recover', 'init-workspace', 'commit-workspace-lease']);
  const spawnChannel = tracingChannel('child_process.spawn');
  const onSpawnEnd = (message: unknown): void => {
    try {
      const proc = (message as { process?: unknown } | undefined)?.process as {
        pid?: number;
        spawnfile?: unknown;
        spawnargs?: unknown;
      } | undefined;
      if (!proc || typeof proc.spawnfile !== 'string') return;
      if (path.win32.basename(proc.spawnfile).toLowerCase() !== 'runner.exe') return;
      const controllerDir = path.dirname(proc.spawnfile);
      if (
        !path.basename(controllerDir).startsWith('black-gravity-controller-') ||
        path.resolve(path.dirname(controllerDir)).toLowerCase() !== normalizedTemp
      ) {
        return;
      }
      const requestArg = Array.isArray(proc.spawnargs) && typeof proc.spawnargs[1] === 'string'
        ? proc.spawnargs[1]
        : undefined;
      if (
        !requestArg ||
        path.resolve(path.dirname(requestArg)).toLowerCase() !== path.resolve(controllerDir).toLowerCase() ||
        !path.basename(requestArg).startsWith('request-') ||
        !path.basename(requestArg).endsWith('.json')
      ) {
        return;
      }
      const payload = JSON.parse(readFileSync(requestArg, 'utf8')) as { action?: unknown; stateDirectory?: unknown };
      if (typeof payload.stateDirectory !== 'string' || path.resolve(payload.stateDirectory).toLowerCase() !== normalizedStateDir) {
        return;
      }
      if (typeof payload.action !== 'string' || !allowedControllerActions.has(payload.action)) {
        observerErrors.push(`unexpected controller action: ${String(payload.action)}`);
        return;
      }
      observedControllerSpawns.push({ proc, action: payload.action });
      if (payload.action === 'write' || payload.action === 'read-only') {
        observedCommandDispatches.push({ proc, action: payload.action });
      }
    } catch (error) {
      observerErrors.push(error instanceof Error ? error.message : String(error));
    }
  };
  const assertNoObserverErrors = () => {
    assert.deepEqual(observerErrors, [], 'spawn diagnostic observer must not encounter errors');
  };
  spawnChannel.end.subscribe(onSpawnEnd);
  try {
    await adapter.discover();
    const initTask = await tasks.run({ prompt: 'write:chain', workingDirectory: repoDir });
    const initDone = await until(initTask.taskId);
    assert.equal(initDone.status, 'completed');
    const previewInit = await tasks.preview(initTask.taskId);

    const validCommand = {
      executable: process.execPath,
      args: ['-e', "const fs=require('node:fs');if(!fs.existsSync('BLACK_GRAVITY_TEST.md'))process.exit(9);process.stdout.write('chain-retry-ok')"],
    };

    // First consecutive pre-preparation failure (startup recovery error; parentCheckpointTaskId unset on failed1).
    const failed1 = await tasks.startTests(initTask.taskId, previewInit.sha256, validCommand, 0, 120);
    const failed1Done = await until(failed1.taskId);
    assert.equal(failed1Done.parentTaskId, initTask.taskId);
    await assertFailedImmutable(tasks, failed1Done.taskId);
    assert.equal(countWindowsExecutorLaunches(tasks), 0);
    assert.equal(observedCommandDispatches.length, 0);
    assertNoObserverErrors();
    await rm(startupLease, { force: true });

    // Hold the single concurrency slot with a test-owned indefinitely waiting blocker so failed2 passes admission and fails AT LAUNCH.
    let blockerTaskId: string | undefined;
    let failed2: Awaited<ReturnType<TaskManager['startTests']>> | undefined;
    try {
      const blocker = await tasks.run({ prompt: blockerPrompt, workingDirectory: otherRepoDir });
      blockerTaskId = blocker.taskId;
      await eventually(
        'blocker process did not complete ready handshake',
        async () => {
          if (!blockerChild || typeof blockerChild.pid !== 'number') return undefined;
          const marker = await readFile(blockerReadyFile, 'utf8').catch(() => '');
          if (marker.trim() !== String(blockerChild.pid)) return undefined;
          const status = tasks.status(blocker.taskId);
          return status.pid === blockerChild.pid && ['running', 'streaming'].includes(status.status) ? true : undefined;
        },
        180000,
      );
      assertBlockerAlive(blocker.taskId, 'before failed2 admission');

      failed2 = await tasks.startTests(failed1Done.taskId, previewInit.sha256, validCommand, 0, 120);
      assert.equal(failed2.status, 'queued');
      assert.equal(failed2.parentTaskId, failed1Done.taskId);
      assertBlockerAlive(blocker.taskId, 'before launchLease write');
      assert.equal(tasks.status(failed2.taskId).status, 'queued', 'failed2 must stay queued while blocker holds execution slot');
      assert.equal(countWindowsExecutorLaunches(tasks), 0);
      assert.equal(observedCommandDispatches.length, 0);

      await writeFile(launchLease, 'invalid-launch-lease', 'utf8');
      assertBlockerAlive(blocker.taskId, 'after launchLease write');
      assert.equal(tasks.status(failed2.taskId).status, 'queued', 'failed2 must not launch before blocker is released');
      assert.equal(countWindowsExecutorLaunches(tasks), 0);
      assert.equal(observedCommandDispatches.length, 0);
    } finally {
      if (blockerTaskId && !['completed', 'failed', 'cancelled', 'timeout'].includes(tasks.status(blockerTaskId).status)) {
        await tasks.cancel(blockerTaskId).catch(() => {});
        await until(blockerTaskId).catch(() => {});
      }
      if (blockerChild && !blockerExited && blockerChild.exitCode === null) {
        blockerChild.kill();
      }
    }
    assert.ok(blockerTaskId);
    assert.ok(failed2);
    const blockerId = blockerTaskId;
    assert.equal(tasks.status(blockerId).status, 'cancelled');
    assert.equal(blockerExited, true, 'blocker child must exit after managed cancel');

    const failed2Done = await until(failed2.taskId);
    await assertFailedImmutable(tasks, failed1Done.taskId);
    await assertFailedImmutable(tasks, failed2Done.taskId);
    assert.equal(countWindowsExecutorLaunches(tasks), 0);
    assert.equal(observedCommandDispatches.length, 0);
    assertNoObserverErrors();

    const storedAfterTwo = new StateStore(stateDir).load();
    const storedFailed1 = storedAfterTwo.find(entry => entry.record.taskId === failed1Done.taskId);
    const storedFailed2 = storedAfterTwo.find(entry => entry.record.taskId === failed2Done.taskId);
    assert.equal(storedFailed1?.options.parentCheckpointTaskId, undefined);
    assert.equal(storedFailed2?.options.parentCheckpointTaskId, initTask.taskId);
    const countBeforeNegatives = tasks.list().length;

    // Negative 1 (lease still invalid on second failed child): rejects WINDOWS_EXECUTION_RECOVERY_FAILED with zero launches.
    await assert.rejects(
      tasks.startTests(failed2Done.taskId, previewInit.sha256, validCommand, 0, 120),
      { code: 'WINDOWS_EXECUTION_RECOVERY_FAILED' },
    );
    assert.equal(tasks.list().length, countBeforeNegatives);
    assert.equal(countWindowsExecutorLaunches(tasks), 0);
    assert.equal(observedCommandDispatches.length, 0);
    assertNoObserverErrors();
    await rm(launchLease, { force: true });

    // Negative 2 (older turn in chain: retrying failed1 after failed2 exists): rejects TASK_NOT_READY with zero launches.
    await assert.rejects(
      tasks.startTests(failed1Done.taskId, previewInit.sha256, validCommand, 0, 120),
      { code: 'TASK_NOT_READY' },
    );
    assert.equal(tasks.list().length, countBeforeNegatives);
    assert.equal(countWindowsExecutorLaunches(tasks), 0);
    assert.equal(observedCommandDispatches.length, 0);
    assertNoObserverErrors();

    // Negative 3 (absent parent archive): rejects CHECKPOINT_MISSING with zero launches.
    const parentArchiveDir = archiveDirectoryFor(stateDir, initTask.taskId);
    const movedArchiveDir = path.join(stateDir, 'moved-chain-archive-' + randomUUID());
    await rename(parentArchiveDir, movedArchiveDir);
    try {
      await assert.rejects(
        tasks.startTests(failed2Done.taskId, previewInit.sha256, validCommand, 0, 120),
        { code: 'CHECKPOINT_MISSING' },
      );
      assert.equal(tasks.list().length, countBeforeNegatives);
      assert.equal(countWindowsExecutorLaunches(tasks), 0);
      assert.equal(observedCommandDispatches.length, 0);
      assertNoObserverErrors();
    } finally {
      await rename(movedArchiveDir, parentArchiveDir);
    }

    // Negative 4 (drifted/tampered checkpoint blob): rejects CHECKPOINT_INVALID with zero launches.
    const blobsDir = path.join(parentArchiveDir, 'blobs');
    const blobNames = await readdir(blobsDir);
    assert.ok(blobNames.length > 0);
    const firstBlobPath = path.join(blobsDir, blobNames[0]!);
    const originalBlob = await readFile(firstBlobPath);
    await writeFile(firstBlobPath, Buffer.concat([originalBlob, Buffer.from('z')]));
    try {
      await assert.rejects(
        tasks.startTests(failed2Done.taskId, previewInit.sha256, validCommand, 0, 120),
        { code: 'CHECKPOINT_INVALID' },
      );
      assert.equal(tasks.list().length, countBeforeNegatives);
      assert.equal(countWindowsExecutorLaunches(tasks), 0);
      assert.equal(observedCommandDispatches.length, 0);
      assertNoObserverErrors();
    } finally {
      await writeFile(firstBlobPath, originalBlob);
    }

    // Negative 5 (forged / inconsistent intermediate link on persisted failed1): must fail closed with zero launches.
    await tasks.shutdown();
    const failed1StateFile = path.join(stateDir, `${failed1Done.taskId}.json`);
    const originalFailed1Json = await readFile(failed1StateFile, 'utf8');
    try {
      const forgedCases: Array<(data: { record: Record<string, unknown>; options: Record<string, unknown> }) => void> = [
        data => { data.options.parentCheckpointTaskId = blockerId; },
        data => { data.options.parentTaskId = blockerId; data.record.parentTaskId = blockerId; },
        data => { data.options.parentArchiveSha256 = 'a'.repeat(64); },
      ];
      for (const mutate of forgedCases) {
        const forged = JSON.parse(originalFailed1Json) as { record: Record<string, unknown>; options: Record<string, unknown> };
        mutate(forged);
        await writeFile(failed1StateFile, JSON.stringify(forged), 'utf8');
        const checkManager = new TaskManager(adapter, config);
        try {
          const beforeCount = checkManager.list().length;
          await assert.rejects(
            checkManager.startTests(failed2Done.taskId, previewInit.sha256, validCommand, 0, 120),
            { code: 'TASK_NOT_READY' },
          );
          assert.equal(checkManager.list().length, beforeCount);
          assert.equal(countWindowsExecutorLaunches(checkManager), 0);
          assert.equal(observedCommandDispatches.length, 0);
          assertNoObserverErrors();
          await assertFailedImmutable(checkManager, failed1Done.taskId);
          await assertFailedImmutable(checkManager, failed2Done.taskId);
        } finally {
          await checkManager.shutdown();
        }
      }
    } finally {
      await writeFile(failed1StateFile, originalFailed1Json, 'utf8');
    }

    // Positive: with sanitized lease and intact chain, retry from failed2 restores original initTask patch and dispatches exactly one real command.
    const recoveredTasks = new TaskManager(adapter, config);
    try {
      const retry3 = await recoveredTasks.startTests(failed2Done.taskId, previewInit.sha256, validCommand, 0, 120);
      assert.equal(retry3.parentTaskId, failed2Done.taskId);
      const retry3Done = await until(retry3.taskId, recoveredTasks);
      assert.equal(retry3Done.status, 'completed', JSON.stringify(retry3Done));
      assertNoObserverErrors();
      const retry3Receipts = (retry3Done.tests ?? []).filter(entry => entry.testTaskId === retry3.taskId);
      assert.equal(retry3Receipts.length, 1, 'retry3 must record exactly one completed command receipt');
      assert.equal(retry3Receipts[0]!.source, 'windows-executor');
      assert.equal(retry3Receipts[0]!.exitCode, 0);
      assert.equal(retry3Receipts[0]!.attempt, 1);
      assert.equal(retry3Receipts[0]!.output, 'chain-retry-ok');
      assert.equal(
        (retry3Done.tests ?? []).filter(entry => entry.testTaskId === failed1Done.taskId || entry.testTaskId === failed2Done.taskId).length,
        0,
        'failed pre-prep records must have no command receipts',
      );
      assert.equal(
        observedCommandDispatches.length,
        1,
        `expected exactly one real runner.exe command dispatch, observed=${JSON.stringify(observedControllerSpawns.map(({ proc, action }) => ({ pid: proc.pid, action })))}`,
      );
      const commandDispatch = observedCommandDispatches[0]!;
      assert.equal(commandDispatch.action, 'write');
      const commandPid = commandDispatch.proc.pid;
      assert.equal(typeof commandPid, 'number');
      const retry3StartedPids = recoveredTasks.readEvents(retry3.taskId).events
        .filter(event => event.type === 'process.started' && (event.data as { executor?: unknown } | undefined)?.executor === 'windows-lpac')
        .map(event => (event.data as { pid?: unknown } | undefined)?.pid)
        .filter((pid): pid is number => typeof pid === 'number');
      assert.ok(retry3StartedPids.includes(commandPid!), 'observed runner.exe command PID must map to retry3 process.started events');
      const rawProcessStartsAfterSuccess = countWindowsExecutorLaunches(recoveredTasks);
      assert.equal(retry3StartedPids.length, rawProcessStartsAfterSuccess, 'all windows-lpac process.started events must belong strictly to retry3');
      const controllerSpawnsAfterSuccess = observedControllerSpawns.length;
      await assertFailedImmutable(recoveredTasks, failed1Done.taskId);
      await assertFailedImmutable(recoveredTasks, failed2Done.taskId);

      // Post-success negative: neither failed1 nor failed2 can be retried after retry3 succeeded; raw process/event counts stay unchanged.
      const countAfterSuccess = recoveredTasks.list().length;
      await assert.rejects(recoveredTasks.startTests(failed2Done.taskId, previewInit.sha256, validCommand, 0, 120), { code: 'TASK_NOT_READY' });
      await assert.rejects(recoveredTasks.startTests(failed1Done.taskId, previewInit.sha256, validCommand, 0, 120), { code: 'TASK_NOT_READY' });
      assert.equal(recoveredTasks.list().length, countAfterSuccess);
      assert.equal(countWindowsExecutorLaunches(recoveredTasks), rawProcessStartsAfterSuccess);
      assert.equal(observedCommandDispatches.length, 1);
      assert.equal(observedControllerSpawns.length, controllerSpawnsAfterSuccess);
      assertNoObserverErrors();
    } finally {
      await recoveredTasks.shutdown();
    }
  } finally {
    spawnChannel.end.unsubscribe(onSpawnEnd);
    if (blockerChild && !blockerExited && blockerChild.exitCode === null) {
      blockerChild.kill();
    }
    await tasks.shutdown();
    await rm(startupLease, { force: true });
    await rm(launchLease, { force: true });
    await rm(blockerReadyFile, { force: true });
    for (const project of new Map(new StateStore(stateDir).load().filter(entry => entry.project).map(entry => [entry.project!.copyDirectory, entry.project!])).values()) await discardProjectCopy(project);
    await ownedTemporaryDirectory(repoDir, 'black-gravity-retry-chain-repo-');
    await ownedTemporaryDirectory(otherRepoDir, 'black-gravity-retry-chain-other-');
    await ownedTemporaryDirectory(stateDir, 'black-gravity-retry-chain-state-');
    await rm(repoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(otherRepoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

function mutateOrReadMcpDacl(targetPath: string, mode: 'read' | 'add-deny-and-foreign-allow' | 'add-callback-ace'): string {
  const source = [
    'using System;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.AccessControl;using System.Security.Principal;',
    'public static class McpDaclFixture {',
    '[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool GetFileSecurity(string p,uint i,byte[] b,uint n,out uint needed);',
    '[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetFileSecurity(string p,uint i,byte[] b);',
    'static RawSecurityDescriptor Read(string p){uint n;GetFileSecurity(p,4,null,0,out n);byte[] b=new byte[n];if(!GetFileSecurity(p,4,b,n,out n))throw new Win32Exception();return new RawSecurityDescriptor(b,0);}',
    'public static string Run(string p,string mode){var sd=Read(p);if(mode=="add-deny-and-foreign-allow"){sd.DiscretionaryAcl.InsertAce(0,new CommonAce(AceFlags.None,AceQualifier.AccessDenied,0x00000002,new SecurityIdentifier("S-1-5-21-1-2-3-4567"),false,null));sd.DiscretionaryAcl.InsertAce(sd.DiscretionaryAcl.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,0x00120089,new SecurityIdentifier("S-1-5-21-1-2-3-4568"),false,null));}else if(mode=="add-callback-ace"){sd.DiscretionaryAcl.InsertAce(sd.DiscretionaryAcl.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,0x00120089,new SecurityIdentifier("S-1-1-0"),true,new byte[0]));}',
    'if(mode!="read"){var b=new byte[sd.BinaryLength];sd.GetBinaryForm(b,0);if(!SetFileSecurity(p,4,b))throw new Win32Exception();sd=Read(p);}return sd.GetSddlForm(AccessControlSections.Access);}}',
  ].join('\n');
  const script = "$ErrorActionPreference='Stop'; Add-Type -TypeDefinition $env:BRIDGE_MCP_DACL_SOURCE; [McpDaclFixture]::Run($env:BRIDGE_MCP_DACL_TARGET, $env:BRIDGE_MCP_DACL_MODE)";
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    windowsHide: true,
    encoding: 'utf8',
    timeout: 15_000,
    env: { ...process.env, BRIDGE_MCP_DACL_SOURCE: source, BRIDGE_MCP_DACL_TARGET: targetPath, BRIDGE_MCP_DACL_MODE: mode },
  }).trim();
}

async function readPreparedInitLease(
  state: string,
): Promise<{ file: string; value: Lease & { readCapabilitySid?: string; modifyCapabilitySid?: string } }> {
  const directory = path.join(state, 'windows-lpac-leases');
  const name = await eventually('prepared init lease was not written', async () => (await readdir(directory).catch(() => [])).find(entry => entry.endsWith('.json')));
  const file = path.join(directory, name);
  const value = JSON.parse(await readFile(file, 'utf8')) as Lease & { readCapabilitySid?: string; modifyCapabilitySid?: string };
  assert.equal(value.phase, 'prepared');
  assert.equal(value.version, 6);
  assert.ok(typeof value.readCapabilitySid === 'string' && value.readCapabilitySid.startsWith('S-1-15-3-'));
  assert.ok(typeof value.modifyCapabilitySid === 'string' && value.modifyCapabilitySid.startsWith('S-1-15-3-'));
  assert.ok(value.grants.length > 0);
  assert.ok(value.mcpCustody?.custodyPath);
  return { file, value };
}

test('Windows managed MCP config custody preserves exact DACL, enforces lease versions, guards pending custody, and quarantines when owned copy is gone', { skip: process.platform !== 'win32' }, async () => {
  const temp = await realpath(os.tmpdir());
  const repoDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-custody-repo-')));
  const stateDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-custody-state-')));
  const grantDir = await realpath(await mkdtemp(path.join(temp, 'black-gravity-custody-grant-')));
  let worker: ChildProcessWithoutNullStreams | undefined;
  let controllerDir: string | undefined;
  let guardManager: TaskManager | undefined;
  try {
    execFileSync('git', ['init', '--quiet'], { cwd: repoDir, windowsHide: true });
    await writeFile(path.join(repoDir, 'source.txt'), 'custody fixture\n', 'utf8');
    storedAcls([{ path: grantDir, mode: 'explicit' }]);
    const ws = canonicalWorkspacePaths(stateDir, repoDir);
    await mkdir(ws.copyDirectory, { recursive: true });
    await mkdir(ws.gitDirectory, { recursive: true });
    await writeFile(path.join(ws.copyDirectory, 'source.txt'), 'custody fixture\n', 'utf8');
    writeWorkspaceMetadata(ws.metadataPath, {
      version: 1,
      sourceDirectory: repoDir,
      rootKey: ws.rootKey,
      updatedAt: new Date().toISOString(),
    });
    await ensureFixedWorkspaceLpacPermissions(ws, repoDir);

    const catalog = [{
      id: 'secret-srv',
      command: process.execPath,
      args: ['-e', 'process.exit(0)'],
      env: { BRIDGE_TEST_SECRET: 'TOP_SECRET_MCP_CUSTODY_TOKEN' },
      tools: [{ name: 'ping', readOnly: true }],
    }];
    const policy = resolveAgentPolicy(
      { allowedTools: ['finish', 'view_file'], mcpServers: [{ serverId: 'secret-srv', tools: ['ping'] }] },
      ['finish', 'view_file'],
      catalog,
      'write',
      '28c48913-763e-4ced-aee4-3fe6f0dd25eb',
    );
    const stageConfig = async () => {
      const staged = await stageExecutionPolicy(
        ws.copyDirectory,
        { policy, catalog, stateDirectory: stateDir, executionId: randomUUID() },
        DEFAULT_PROJECT_LIMITS,
      );
      const file = staged.files.find(entry => entry.path === '.agents/mcp_config.json')!;
      return {
        staged,
        binding: { executionId: staged.executionId, executionStateDirectory: stateDir, file },
      };
    };

    const initial = await stageConfig();
    const mcpPath = path.join(ws.copyDirectory, '.agents', 'mcp_config.json');
    const initialStat = await lstat(mcpPath, { bigint: true });
    const initialBytes = await readFile(mcpPath);
    const initialDacl = mutateOrReadMcpDacl(mcpPath, 'read');
    assert.ok(initialBytes.toString('utf8').includes('TOP_SECRET_MCP_CUSTODY_TOKEN'));

    // 1. Interrupted init-workspace at after-prepare: custody init lease uses version 6, recovery revokes pin and restores exact DACL.
    let preparedLeaseVersion: number | undefined;
    await assert.rejects(
      executeWindowsTest(
        { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
        ws.copyDirectory,
        {
          ...settings,
          stateDirectory: stateDir,
          managedMcpConfig: initial.binding,
          async onInitPhase(phase) {
            if (phase === 'after-prepare') {
              preparedLeaseVersion = (await readPreparedInitLease(stateDir)).value.version;
              throw new Error('simulated crash after-prepare');
            }
          },
        },
      ),
      /simulated crash after-prepare/,
    );
    assert.equal(preparedLeaseVersion, 6, 'custody-bearing init lease must use version 6');
    await recoverWindowsExecutions(stateDir, { requireIdle: true });
    assert.equal((await lstat(mcpPath, { bigint: true })).ino, initialStat.ino);
    assert.deepEqual(await readFile(mcpPath), initialBytes);
    assert.equal(mutateOrReadMcpDacl(mcpPath, 'read'), initialDacl, 'after-prepare recovery must restore exact original DACL');
    assert.equal(readWorkspaceMetadata(ws.metadataPath)?.windowsLpac?.capabilityNonce, undefined);

    // 2. Interrupted init-workspace at after-pin: version 6 custody lease recovers while preserving committed pin and exact original DACL.
    await assert.rejects(
      executeWindowsTest(
        { executable: process.execPath, args: ['-e', 'process.exit(0)'] },
        ws.copyDirectory,
        {
          ...settings,
          stateDirectory: stateDir,
          managedMcpConfig: initial.binding,
          onInitPhase(phase) {
            if (phase === 'after-pin') throw new Error('simulated crash after-pin');
          },
        },
      ),
      /simulated crash after-pin/,
    );
    await recoverWindowsExecutions(stateDir, { requireIdle: true });
    assert.equal((await lstat(mcpPath, { bigint: true })).ino, initialStat.ino);
    assert.deepEqual(await readFile(mcpPath), initialBytes);
    assert.equal(mutateOrReadMcpDacl(mcpPath, 'read'), initialDacl, 'after-pin recovery must restore exact original DACL');
    const pinnedMeta = readWorkspaceMetadata(ws.metadataPath);
    assert.ok(pinnedMeta?.windowsLpac?.capabilityNonce, 'committed workspace pin must survive after-pin recovery');

    // 3. Re-stage onto ALREADY-PINNED canonical workspace so the file inherits capability SIDs; add DENY + foreign ALLOW ACEs.
    //    Verify: version 5 run lease; monotonic tightening preserves DENY ACE, strips S-1-15-* and foreign ALLOW, never widens;
    //    LPAC holding modifyCapabilitySid gets ENOENT in copy and EACCES/EPERM on live custody path; exact original DACL restored after exit.
    await removeStagedExecutionPolicyHelpers(ws.copyDirectory);
    const postPin = await stageConfig();
    const postPinStat = await lstat(mcpPath, { bigint: true });
    const postPinBytes = await readFile(mcpPath);
    const exactBeforeDacl = mutateOrReadMcpDacl(mcpPath, 'add-deny-and-foreign-allow');
    assert.ok(exactBeforeDacl.includes('S-1-5-21-1-2-3-4567'), 'fixture must include custom DENY ACE');
    assert.ok(exactBeforeDacl.includes('S-1-5-21-1-2-3-4568'), 'fixture must include foreign ALLOW ACE');
    assert.ok(exactBeforeDacl.includes('S-1-15-3-'), 'post-pin staged config must carry inherited capability SIDs');

    const readyFile = path.join(grantDir, 'probe-ready.txt');
    const targetFile = path.join(grantDir, 'custody-target.txt');
    const resultFile = path.join(grantDir, 'probe-result.json');
    const probeScript = [
      "const fs=require('node:fs');",
      `fs.writeFileSync(${JSON.stringify(readyFile)},'ready');`,
      "const deadline=Date.now()+15000;",
      `while(!fs.existsSync(${JSON.stringify(targetFile)})){if(Date.now()>deadline)process.exit(14);Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,50);}`,
      `const custodyPath=fs.readFileSync(${JSON.stringify(targetFile)},'utf8').trim();`,
      "let copyErr='OK',custodyErr='OK',renameAgentsErr='OK';",
      "try{fs.readFileSync('.agents/mcp_config.json','utf8');}catch(e){copyErr=e.code||String(e);}",
      "try{fs.readFileSync(custodyPath,'utf8');}catch(e){custodyErr=e.code||String(e);}",
      "try{fs.renameSync('.agents','.agents-renamed');}catch(e){renameAgentsErr=e.code||String(e);}",
      `fs.writeFileSync(${JSON.stringify(resultFile)},JSON.stringify({copyErr,custodyErr,renameAgentsErr}));`,
    ].join('');

    const runPromise = executeWindowsTest(
      { executable: process.execPath, args: ['-e', probeScript] },
      ws.copyDirectory,
      {
        ...settings,
        stateDirectory: stateDir,
        managedMcpConfig: postPin.binding,
        sandbox: { readPaths: [], writePaths: [grantDir], network: false, childProcesses: true, maxOutputChars: 4000 },
      },
    );
    await eventually('post-pin LPAC probe did not become ready', async () => (await readFile(readyFile, 'utf8').catch(() => '')) === 'ready' ? true : undefined);
    const activeProbeLease = await readLease(stateDir);
    assert.equal(activeProbeLease.value.version, 5, 'custody-bearing run lease must use version 5');
    assert.ok(activeProbeLease.value.mcpCustody?.originalDaclSha256, 'version 5 lease must record original DACL digest');
    assert.ok(activeProbeLease.value.mcpCustody?.custodyDaclSha256, 'version 5 lease must record tightened custody DACL digest');
    await assert.rejects(lstat(mcpPath), { code: 'ENOENT' }, 'managed MCP config must be absent from copy while LPAC runs');
    const heldCustodyPath = activeProbeLease.value.mcpCustody!.custodyPath;
    assert.equal((await lstat(heldCustodyPath)).isFile(), true, 'held config must exist at custody path');
    const heldCustodyDacl = mutateOrReadMcpDacl(heldCustodyPath, 'read');
    assert.ok(heldCustodyDacl.includes('(D;;FW;;;S-1-5-21-1-2-3-4567)') || heldCustodyDacl.includes('S-1-5-21-1-2-3-4567'), 'monotonic tightening must preserve DENY ACE verbatim');
    assert.equal(heldCustodyDacl.includes('S-1-15-'), false, 'tightened custody DACL must strip all S-1-15-* capability/AppContainer allows');
    assert.equal(heldCustodyDacl.includes('S-1-5-21-1-2-3-4568'), false, 'tightened custody DACL must strip foreign ALLOW ACEs');
    await writeFile(targetFile, heldCustodyPath, 'utf8');

    const probeOutcome = await runPromise;
    assert.equal(probeOutcome.exitCode, 0, JSON.stringify(probeOutcome));
    assert.equal(probeOutcome.mcpConfigCustodyRestored, true);
    const probeReport = JSON.parse(await readFile(resultFile, 'utf8')) as { copyErr: string; custodyErr: string; renameAgentsErr: string };
    assert.equal(probeReport.copyErr, 'ENOENT', 'LPAC must not see managed MCP config in copy');
    assert.ok(probeReport.custodyErr === 'EACCES' || probeReport.custodyErr === 'EPERM', `LPAC must be denied access to exact held custody path after capability pin, got ${probeReport.custodyErr}`);
    assert.ok(
      probeReport.renameAgentsErr === 'EACCES' || probeReport.renameAgentsErr === 'EPERM' || probeReport.renameAgentsErr === 'EBUSY',
      `Pinned .agents parent handle must block rename during active LPAC command, got ${probeReport.renameAgentsErr}`,
    );
    const afterProbeStat = await lstat(mcpPath, { bigint: true });
    assert.equal(afterProbeStat.dev, postPinStat.dev);
    assert.equal(afterProbeStat.ino, postPinStat.ino);
    assert.deepEqual(await readFile(mcpPath), postPinBytes);
    assert.equal(mutateOrReadMcpDacl(mcpPath, 'read'), exactBeforeDacl, 'clean execution must restore exact original DACL byte-for-byte');
    assert.deepEqual(await readdir(path.join(stateDir, 'windows-lpac-custody')).catch(() => []), []);

    // 4. Unrepresentable ACL (callback ACE) and native forged-config replacement must fail closed before any mutation or command execution.
    await removeStagedExecutionPolicyHelpers(ws.copyDirectory);
    const unrep = await stageConfig();
    const unrepStat = await lstat(mcpPath, { bigint: true });
    const unrepBytes = await readFile(mcpPath);
    const callbackDacl = mutateOrReadMcpDacl(mcpPath, 'add-callback-ace');
    const unrepMarker = path.join(ws.copyDirectory, 'unrep-launched.txt');
    await assert.rejects(
      executeWindowsTest(
        { executable: process.execPath, args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(unrepMarker)},'launched')`] },
        ws.copyDirectory,
        { ...settings, stateDirectory: stateDir, managedMcpConfig: unrep.binding },
      ),
      error => error instanceof Error && (error as { code?: string }).code === 'WINDOWS_EXECUTOR_FAILED' && /Unrepresentable callback ACE/i.test(error.message),
    );
    await assert.rejects(lstat(unrepMarker), { code: 'ENOENT' });
    assert.equal((await lstat(mcpPath, { bigint: true })).ino, unrepStat.ino);
    assert.deepEqual(await readFile(mcpPath), unrepBytes);
    assert.equal(mutateOrReadMcpDacl(mcpPath, 'read'), callbackDacl, 'unrepresentable ACL refusal must leave original file and DACL untouched');

    // 4b. Direct native forged-config check (identical bytes, distinct NTFS file ID) must fail closed untouched before payload.
    await removeStagedExecutionPolicyHelpers(ws.copyDirectory);
    const forgedStage = await stageConfig();
    const forgedOrigStat = await lstat(mcpPath, { bigint: true });
    const forgedOrigBytes = await readFile(mcpPath);
    const forgedTmp = mcpPath + '.forged-' + randomUUID();
    await writeFile(forgedTmp, forgedOrigBytes);
    await rm(mcpPath);
    await rename(forgedTmp, mcpPath);
    const forgedNewStat = await lstat(mcpPath, { bigint: true });
    assert.notEqual(forgedNewStat.ino, forgedOrigStat.ino);
    const forgedDacl = mutateOrReadMcpDacl(mcpPath, 'read');
    await assert.rejects(
      executeWindowsTest(
        { executable: process.execPath, args: ['-e', `require('node:fs').writeFileSync(${JSON.stringify(unrepMarker)},'launched')`] },
        ws.copyDirectory,
        { ...settings, stateDirectory: stateDir, managedMcpConfig: forgedStage.binding },
      ),
      error => error instanceof Error && (error as { code?: string }).code === 'WINDOWS_EXECUTOR_FAILED' && /object identity does not match staging witness/i.test(error.message),
    );
    await assert.rejects(lstat(unrepMarker), { code: 'ENOENT' });
    assert.equal((await lstat(mcpPath, { bigint: true })).ino, forgedNewStat.ino);
    assert.deepEqual(await readFile(mcpPath), forgedOrigBytes);
    assert.equal(mutateOrReadMcpDacl(mcpPath, 'read'), forgedDacl);

    // 5. Lease version enforcement: legacy v3/v4 leases with mcpCustody and v5/v6 leases without mcpCustody must be rejected with exact messages.
    const leaseDir = path.join(stateDir, 'windows-lpac-leases');
    await mkdir(leaseDir, { recursive: true });
    for (const invalidCase of [
      { label: 'v3-with-custody', version: 3, hasCustody: true, isInit: false, pattern: /Version 3 lease cannot declare MCP custody/ },
      { label: 'v5-without-custody', version: 5, hasCustody: false, isInit: false, pattern: /Version 5 lease requires MCP custody/ },
      { label: 'v4-with-custody', version: 4, hasCustody: true, isInit: true, pattern: /Version 4 workspace initialization lease cannot declare MCP custody/ },
      { label: 'v6-without-custody', version: 6, hasCustody: false, isInit: true, pattern: /Version 6 workspace initialization lease requires MCP custody/ },
    ]) {
      const fakeNonce = randomUUID();
      const fakeFile = path.join(leaseDir, fakeNonce.replaceAll('-', '') + '.json');
      const fakeLease = invalidCase.isInit
        ? {
            version: invalidCase.version,
            nonce: fakeNonce,
            phase: 'init-workspace',
            controllerPid: 999999,
            controllerStarted: 1,
            cwd: ws.copyDirectory,
            grants: [{ path: ws.copyDirectory, rights: 'read', directory: true, volume: 1, fileIndexHigh: 0, fileIndexLow: 1 }],
            capabilityNonce: pinnedMeta!.windowsLpac!.capabilityNonce,
            readCapabilitySid: pinnedMeta!.windowsLpac!.readCapabilitySid,
            modifyCapabilitySid: pinnedMeta!.windowsLpac!.modifyCapabilitySid,
            ...(invalidCase.hasCustody ? { mcpCustody: activeProbeLease.value.mcpCustody } : {}),
          }
        : {
            version: invalidCase.version,
            nonce: fakeNonce,
            profile: 'black-gravity.test.' + fakeNonce.replaceAll('-', ''),
            phase: 'creating',
            controllerPid: 999999,
            controllerStarted: 1,
            cwd: ws.copyDirectory,
            runtime: path.join(temp, 'black-gravity-runtime-fake'),
            scratch: path.join(temp, 'black-gravity-scratch-fake'),
            grants: [],
            jobCreated: false,
            ...(invalidCase.hasCustody ? { mcpCustody: activeProbeLease.value.mcpCustody } : {}),
          };
      await writeFile(fakeFile, JSON.stringify(fakeLease), 'utf8');
      try {
        await assert.rejects(freshRecovery(stateDir), invalidCase.pattern, invalidCase.label);
      } finally {
        await rm(fakeFile, { force: true });
      }
    }

    // 5b. Benign live restore conflict: LPAC creates a file at .agents/mcp_config.json while real config is in custody.
    //     Must NOT clobber LPAC's file, must quarantine verified original + evidence, fail closed for that execution,
    //     and resolve the custody lease so global recovery succeeds with zero manual intervention.
    await removeStagedExecutionPolicyHelpers(ws.copyDirectory);
    const conflictStage = await stageConfig();
    const conflictOrigStat = await lstat(mcpPath, { bigint: true });
    const conflictOrigBytes = await readFile(mcpPath);
    mutateOrReadMcpDacl(mcpPath, 'add-deny-and-foreign-allow');
    const benignConflictBytes = Buffer.from('{"benign":"created-during-lpac"}\n', 'utf8');
    await assert.rejects(
      executeWindowsTest(
        { executable: process.execPath, args: ['-e', `require('node:fs').writeFileSync('.agents/mcp_config.json',${JSON.stringify(benignConflictBytes.toString('utf8'))})`] },
        ws.copyDirectory,
        { ...settings, stateDirectory: stateDir, managedMcpConfig: conflictStage.binding },
      ),
      error => error instanceof Error && (error as { code?: string }).code === 'WINDOWS_EXECUTOR_FAILED' && /restore-destination-occupied/i.test(error.message),
    );
    assert.deepEqual(await readFile(mcpPath), benignConflictBytes, 'benign restore conflict file must never be clobbered');
    assert.deepEqual(await readdir(path.join(stateDir, 'windows-lpac-custody')).catch(() => []), []);
    assert.deepEqual(await readdir(leaseDir).catch(() => []), [], 'resolved conflict lease must not remain on disk');
    await freshRecovery(stateDir);
    const quarantineRoot = path.join(stateDir, 'windows-lpac-custody-quarantine');
    const liveConflictSlots = await readdir(quarantineRoot);
    assert.equal(liveConflictSlots.length, 1);
    const liveQFile = path.join(quarantineRoot, liveConflictSlots[0]!, 'mcp_config.json');
    const liveQEvidence = JSON.parse(await readFile(path.join(quarantineRoot, liveConflictSlots[0]!, 'evidence.json'), 'utf8')) as Record<string, unknown>;
    assert.equal((await lstat(liveQFile, { bigint: true })).ino, conflictOrigStat.ino);
    assert.deepEqual(await readFile(liveQFile), conflictOrigBytes);
    assert.equal(liveQEvidence.reason, 'restore-destination-occupied');
    assert.equal(liveQEvidence.executionId, conflictStage.binding.executionId.toLowerCase());
    await rm(mcpPath);

    // Re-stage cleanly with DENY + foreign ALLOW for crash, pending-custody guard, no-clobber, and missing-copy quarantine checks.
    await removeStagedExecutionPolicyHelpers(ws.copyDirectory);
    const crashStage = await stageConfig();
    const crashStat = await lstat(mcpPath, { bigint: true });
    const crashBytes = await readFile(mcpPath);
    const crashBeforeDacl = mutateOrReadMcpDacl(mcpPath, 'add-deny-and-foreign-allow');

    const guardConfig = loadConfig({
      AGY_PATH: process.execPath,
      BRIDGE_TEST_EXECUTOR: 'agy',
      BRIDGE_STATE_DIRECTORY: stateDir,
    });
    const guardAdapter = new CliAdapter(guardConfig, [path.resolve('tests/mock-agy.mjs')]);
    await guardAdapter.discover();
    guardManager = new TaskManager(guardAdapter, guardConfig);

    const spawnCrashCustodyRun = async (readyMarkerPath: string) => {
      const executorUrl = new URL('../src/windows-executor.js', import.meta.url).href;
      const crashLpacScript = `require('node:fs').writeFileSync(${JSON.stringify(readyMarkerPath)},'ready');setInterval(()=>{},1000);`;
      const workerSource =
        `import { readFileSync } from 'node:fs';import { executeWindowsTest } from ${JSON.stringify(executorUrl)};` +
        `const s=JSON.parse(process.argv[1]);` +
        `await executeWindowsTest({executable:process.execPath,args:['-e',${JSON.stringify(crashLpacScript)}]},s.copy,{timeoutSeconds:20,maxRuntimeBytes:268435456,stateDirectory:s.state,managedMcpConfig:s.binding,sandbox:{readPaths:[],writePaths:[s.grant],network:false,childProcesses:true,maxOutputChars:4000},onProcess(child){const req=child.spawnargs.at(-1);if(typeof req!=='string')return;let p;try{p=JSON.parse(readFileSync(req,'utf8'));}catch{return;}if(p.action!=='write')return;process.stdout.write(JSON.stringify({controllerPid:child.pid,requestPath:req})+'\\n');child.once('exit',()=>process.exit(86));}});process.exit(0);`;
      const child = spawn(
        process.execPath,
        ['--input-type=module', '-e', workerSource, JSON.stringify({ copy: ws.copyDirectory, state: stateDir, grant: grantDir, binding: crashStage.binding })],
        { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
      );
      worker = child;
      let workerOut = '', workerErr = '';
      child.stdout.on('data', chunk => { workerOut += String(chunk); });
      child.stderr.on('data', chunk => { workerErr += String(chunk); });
      const ann = await eventually('custody crash worker did not announce controller', async () => {
        const line = workerOut.split(/\r?\n/).find(value => value.startsWith('{'));
        if (!line) return undefined;
        const parsed = JSON.parse(line) as Announcement;
        if (!Number.isInteger(parsed.controllerPid) || parsed.controllerPid <= 0) throw new Error('invalid worker announcement: ' + line + workerErr);
        return parsed;
      });
      controllerDir = path.dirname(ann.requestPath);
      await verifyControllerAnnouncement(ann, stateDir);
      await eventually('custody crash LPAC did not become ready', async () => (await readFile(readyMarkerPath, 'utf8').catch(() => '')) === 'ready' ? true : undefined);
      const leaseSnapshot = await readLease(stateDir);
      assert.equal(leaseSnapshot.value.version, 5);
      assert.ok(leaseSnapshot.value.mcpCustody);
      await stopController(child, ann);
      worker = undefined;
      await removeOwned(controllerDir, 'black-gravity-controller-');
      controllerDir = undefined;
      return leaseSnapshot;
    };

    // 6. Crash controller mid-execution: verify owner-specific pending custody guard (including TaskManager reuse/rematerialization),
    //    and clean exact-DACL crash recovery.
    const crashReady1 = path.join(grantDir, 'crash-ready-1.txt');
    const crashedLease = await spawnCrashCustodyRun(crashReady1);
    await assert.rejects(lstat(mcpPath), { code: 'ENOENT' });
    assert.equal((await lstat(crashedLease.value.mcpCustody!.custodyPath)).isFile(), true);

    await assert.rejects(
      assertNoPendingMcpCustodyForCopy(stateDir, ws.copyDirectory),
      { code: 'WINDOWS_EXECUTION_RECOVERY_FAILED' },
      'pending custody must block destructive operations on the owning copy',
    );
    await assertNoPendingMcpCustodyForCopy(stateDir, path.join(stateDir, 'workspaces', '0'.repeat(32), 'copy'));
    await assert.rejects(
      guardManager.run({ workingDirectory: repoDir, prompt: 'rematerialization must be blocked while custody is pending', mode: 'write' }),
      { code: 'WINDOWS_EXECUTION_RECOVERY_FAILED' },
      'TaskManager must refuse workspace rematerialization/restage while custody is pending',
    );
    assert.equal((await lstat(crashedLease.value.mcpCustody!.custodyPath)).isFile(), true, 'pending custody refusal must leave held config intact');

    await freshRecovery(stateDir);
    await assert.rejects(readFile(crashedLease.file), { code: 'ENOENT' });
    const restoredStat = await lstat(mcpPath, { bigint: true });
    assert.equal(restoredStat.dev, crashStat.dev);
    assert.equal(restoredStat.ino, crashStat.ino);
    assert.deepEqual(await readFile(mcpPath), crashBytes);
    assert.equal(mutateOrReadMcpDacl(mcpPath, 'read'), crashBeforeDacl, 'crash recovery must restore exact original DACL byte-for-byte');
    assert.deepEqual(await readdir(path.join(stateDir, 'windows-lpac-custody')).catch(() => []), []);

    // With no active custody slots, an unrelated malformed generic lease does not block the custody guard,
    // while native recovery still rejects it; conversely, a present custody slot with missing/malformed lease fails closed.
    const unrelatedMalformedLease = path.join(leaseDir, 'unrelated-invalid.json');
    await writeFile(unrelatedMalformedLease, 'invalid-generic-lease', 'utf8');
    try {
      await assertNoPendingMcpCustodyForCopy(stateDir, ws.copyDirectory);
      await assert.rejects(freshRecovery(stateDir), /Windows LPAC recovery failed:.*unrelated-invalid\.json/);
    } finally {
      await rm(unrelatedMalformedLease, { force: true });
    }
    const orphanSlot = path.join(stateDir, 'windows-lpac-custody', '0'.repeat(32));
    await mkdir(orphanSlot, { recursive: true });
    try {
      await assert.rejects(
        assertNoPendingMcpCustodyForCopy(stateDir, ws.copyDirectory),
        { code: 'WINDOWS_EXECUTION_RECOVERY_FAILED', message: /no readable lease/ },
        'present custody slot with missing lease must fail closed',
      );
      const corruptCustodyLease = path.join(leaseDir, '0'.repeat(32) + '.json');
      await writeFile(corruptCustodyLease, 'corrupt-custody-lease', 'utf8');
      try {
        await assert.rejects(
          assertNoPendingMcpCustodyForCopy(stateDir, ws.copyDirectory),
          { code: 'WINDOWS_EXECUTION_RECOVERY_FAILED', message: /Unreadable Windows LPAC custody lease/ },
          'present custody slot with malformed lease must fail closed',
        );
      } finally {
        await rm(corruptCustodyLease, { force: true });
      }
    } finally {
      await rm(orphanSlot, { recursive: true, force: true });
    }

    // 7. Crash + confirmed restore destination occupied (decoy): recovery must NOT clobber decoy, must quarantine verified
    //    original + evidence, and resolve the lease with ZERO manual intervention so global recovery is not wedged.
    const crashReady2 = path.join(grantDir, 'crash-ready-2.txt');
    const decoyCrashLease = await spawnCrashCustodyRun(crashReady2);
    const decoyBytes = Buffer.from('DECOY_DO_NOT_CLOBBER\n', 'utf8');
    await writeFile(mcpPath, decoyBytes);
    const decoyStat = await lstat(mcpPath, { bigint: true });
    await freshRecovery(stateDir);
    await assert.rejects(readFile(decoyCrashLease.file), { code: 'ENOENT' });
    assert.equal((await lstat(mcpPath, { bigint: true })).ino, decoyStat.ino, 'decoy at restore destination must never be clobbered');
    assert.deepEqual(await readFile(mcpPath), decoyBytes);
    assert.deepEqual(await readdir(path.join(stateDir, 'windows-lpac-custody')).catch(() => []), []);
    const decoyQSlot = path.join(quarantineRoot, decoyCrashLease.value.nonce.replaceAll('-', ''));
    const decoyQFile = path.join(decoyQSlot, 'mcp_config.json');
    assert.equal((await lstat(decoyQFile, { bigint: true })).ino, crashStat.ino);
    assert.deepEqual(await readFile(decoyQFile), crashBytes);
    const decoyQDacl = mutateOrReadMcpDacl(decoyQFile, 'read');
    assert.ok(decoyQDacl.includes('S-1-5-21-1-2-3-4567'), 'quarantined original must keep monotonic DENY ACE');
    assert.equal(decoyQDacl.includes('S-1-15-'), false, 'quarantined original must deny LPAC');
    const decoyQEvidence = JSON.parse(await readFile(path.join(decoyQSlot, 'evidence.json'), 'utf8')) as Record<string, unknown>;
    assert.equal(decoyQEvidence.reason, 'restore-destination-occupied');
    assert.equal(decoyQEvidence.originalDaclSha256, decoyCrashLease.value.mcpCustody!.originalDaclSha256);

    // 8. Crash + missing .agents parent -> terminal quarantine with agents-parent-missing; then crash + missing owned copy -> owned-copy-missing.
    await removeStagedExecutionPolicyHelpers(ws.copyDirectory);
    const parentStage = await stageConfig();
    const parentStat = await lstat(mcpPath, { bigint: true });
    const parentBytes = await readFile(mcpPath);
    mutateOrReadMcpDacl(mcpPath, 'add-deny-and-foreign-allow');
    crashStage.binding = parentStage.binding;
    const crashReady3 = path.join(grantDir, 'crash-ready-3.txt');
    const missingAgentsLease = await spawnCrashCustodyRun(crashReady3);
    await rm(path.join(ws.copyDirectory, '.agents'), { recursive: true, force: true });
    await freshRecovery(stateDir);
    await assert.rejects(readFile(missingAgentsLease.file), { code: 'ENOENT' });
    const agentsQSlot = path.join(quarantineRoot, missingAgentsLease.value.nonce.replaceAll('-', ''));
    assert.equal((await lstat(path.join(agentsQSlot, 'mcp_config.json'), { bigint: true })).ino, parentStat.ino);
    assert.deepEqual(await readFile(path.join(agentsQSlot, 'mcp_config.json')), parentBytes);
    const agentsQEvidence = JSON.parse(await readFile(path.join(agentsQSlot, 'evidence.json'), 'utf8')) as Record<string, unknown>;
    assert.equal(agentsQEvidence.reason, 'agents-parent-missing');

    await mkdir(path.join(ws.copyDirectory, '.agents'), { recursive: true });
    const missingCopyStage = await stageConfig();
    const missingCopyStat = await lstat(mcpPath, { bigint: true });
    const missingCopyBytes = await readFile(mcpPath);
    mutateOrReadMcpDacl(mcpPath, 'add-deny-and-foreign-allow');
    crashStage.binding = missingCopyStage.binding;
    const crashReady4 = path.join(grantDir, 'crash-ready-4.txt');
    const missingCopyLease = await spawnCrashCustodyRun(crashReady4);
    await rm(ws.copyDirectory, { recursive: true, force: true });
    await freshRecovery(stateDir);
    await assert.rejects(readFile(missingCopyLease.file), { code: 'ENOENT' });
    assert.deepEqual(await readdir(path.join(stateDir, 'windows-lpac-custody')).catch(() => []), []);
    const copyQSlot = path.join(quarantineRoot, missingCopyLease.value.nonce.replaceAll('-', ''));
    const copyQFile = path.join(copyQSlot, 'mcp_config.json');
    const qStat = await lstat(copyQFile, { bigint: true });
    assert.equal(qStat.dev, missingCopyStat.dev);
    assert.equal(qStat.ino, missingCopyStat.ino, 'quarantined file must be the exact original NTFS object, never recreated or deleted');
    assert.deepEqual(await readFile(copyQFile), missingCopyBytes);
    const qDacl = mutateOrReadMcpDacl(copyQFile, 'read');
    assert.ok(qDacl.includes('S-1-5-21-1-2-3-4567'), 'quarantined file must keep monotonic DENY ACE');
    assert.equal(qDacl.includes('S-1-15-'), false, 'quarantined file must deny LPAC');
    const evidence = JSON.parse(await readFile(path.join(copyQSlot, 'evidence.json'), 'utf8')) as Record<string, unknown>;
    assert.equal(evidence.reason, 'owned-copy-missing');
    assert.equal(evidence.leaseVersion, 5);
    assert.equal(evidence.executionId, missingCopyStage.binding.executionId.toLowerCase());
    assert.equal(evidence.sha256, missingCopyStage.binding.file.sha256);
    assert.equal(evidence.originalDaclSha256, missingCopyLease.value.mcpCustody!.originalDaclSha256);
  } finally {
    await guardManager?.shutdown();
    if (worker && worker.exitCode === null) worker.kill('SIGTERM');
    await removeOwned(controllerDir, 'black-gravity-controller-');
    await ownedTemporaryDirectory(repoDir, 'black-gravity-custody-repo-');
    await ownedTemporaryDirectory(stateDir, 'black-gravity-custody-state-');
    await ownedTemporaryDirectory(grantDir, 'black-gravity-custody-grant-');
    await rm(repoDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(grantDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
