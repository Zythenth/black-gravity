import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { BridgeError } from '../src/types.js';
import {
  executeWindowsTest,
  parseWindowsExecutionResult,
  recoverWindowsExecutions,
  type WindowsExecutionOptions,
} from '../src/windows-executor.js';
import {
  canonicalWorkspacePaths,
  normalizeIcaclsDacl,
  readWorkspaceMetadata,
  recordNativeWorkspaceLpacPin,
  writeWorkspaceMetadata,
  type IcaclsRunner,
} from '../src/workspace-paths.js';

const runtime = loadConfig();
const settings: WindowsExecutionOptions = {
  timeoutSeconds: 20,
  maxRuntimeBytes: 256 * 1024 * 1024,
  windowsNodeRuntime: runtime.windowsNodeRuntime,
  portableNodeCacheDirectory: runtime.windowsNodeCacheDirectory,
};

const nodeCommand = (script: string) => ({ executable: process.execPath, args: ['-e', script] });

async function createCanonicalWorkspaceFixture(stateDir: string, sourceDir: string): Promise<ReturnType<typeof canonicalWorkspacePaths>> {
  const workspace = canonicalWorkspacePaths(stateDir, sourceDir);
  await mkdir(workspace.copyDirectory, { recursive: true });
  await mkdir(workspace.gitDirectory, { recursive: true });
  writeWorkspaceMetadata(workspace.metadataPath, {
    version: 1,
    sourceDirectory: sourceDir,
    rootKey: workspace.rootKey,
    updatedAt: new Date().toISOString(),
  });
  return workspace;
}

test('LPAC unit: normalizeIcaclsDacl rejects generic AppContainer SIDs and friendly names while allowing scoped named capability SIDs', () => {
  const folder = 'C:\\state\\workspaces\\0123456789abcdef0123456789abcdef\\copy';
  const cleanWithNamedCapabilities = [
    `${folder} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)`,
    '         *S-1-15-3-1024-1-2-3-4-5-6-7-8:(OI)(CI)(RX)',
    '         *S-1-15-3-1024-8-7-6-5-4-3-2-1:(OI)(CI)(M)',
    '         DESKTOP\\User:(OI)(CI)(F)',
    'Successfully processed 1 files; Failed processing 0 files',
  ].join('\r\n');
  assert.equal(normalizeIcaclsDacl(cleanWithNamedCapabilities, folder).hasLingeringAppContainer, false);

  for (const forbidden of [
    '*S-1-15-2-1:(OI)(CI)(RX)',
    '*S-1-15-2-2:(OI)(CI)(RX)',
    '*S-1-15-2-100-200-300:(OI)(CI)(M)',
    'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(RX)',
    'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)',
    'APPLICATION PACKAGE AUTHORITY\\black-gravity.test.deadbeef:(OI)(CI)(M)',
  ]) {
    const acl = `${folder} ${forbidden}\r\n`;
    assert.equal(normalizeIcaclsDacl(acl, folder).hasLingeringAppContainer, true, forbidden);
  }
});

test('LPAC unit: recordNativeWorkspaceLpacPin stores native capability identity and parseWindowsExecutionResult accepts workspaceLpacValidated', async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-lpac-pin-unit-')));
  const stateDir = path.join(root, 'state');
  const repoDir = path.join(root, 'repo');
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(repoDir, { recursive: true });
  t.after(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const workspace = await createCanonicalWorkspaceFixture(stateDir, repoDir);
  const currentTaskId = randomUUID();
  const currentLineageId = randomUUID();
  writeWorkspaceMetadata(workspace.metadataPath, {
    version: 1,
    sourceDirectory: repoDir,
    rootKey: workspace.rootKey,
    currentTaskId,
    currentLineageId,
    updatedAt: new Date().toISOString(),
  });

  const runner: IcaclsRunner = async () => ({
    stdout: `${workspace.copyDirectory} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\r\n                 *S-1-15-3-1024-1-2-3-4-5-6-7-8:(OI)(CI)(RX)\r\n`,
    stderr: '',
  });
  const capabilityNonce = randomUUID();
  const pin = await recordNativeWorkspaceLpacPin(
    workspace,
    repoDir,
    {
      capabilityNonce,
      readCapabilitySid: 'S-1-15-3-1024-1-2-3-4-5-6-7-8',
      modifyCapabilitySid: 'S-1-15-3-1024-8-7-6-5-4-3-2-1',
      volume: 100,
      fileIndexHigh: 1,
      fileIndexLow: 2,
      nativeDaclSha256: 'a'.repeat(64),
    },
    { platform: 'win32', runIcacls: runner },
  );
  assert.equal(pin.capabilityNonce, capabilityNonce);
  const saved = readWorkspaceMetadata(workspace.metadataPath);
  assert.equal(saved?.currentTaskId, currentTaskId);
  assert.equal(saved?.currentLineageId, currentLineageId);
  assert.equal(saved?.windowsLpac?.readCapabilitySid, 'S-1-15-3-1024-1-2-3-4-5-6-7-8');
  assert.equal(saved?.windowsLpac?.modifyCapabilitySid, 'S-1-15-3-1024-8-7-6-5-4-3-2-1');
  assert.equal(saved?.windowsLpac?.nativeDaclSha256, 'a'.repeat(64));

  const nonce = randomUUID();
  const parsed = parseWindowsExecutionResult(
    {
      code: 0,
      stdout: JSON.stringify({
        nonce,
        pid: 1234,
        sandbox: 'windows-lpac',
        exitCode: 0,
        output: 'ok',
        truncated: false,
        profileDeleted: true,
        aliasesDeleted: true,
        workspaceLpacValidated: true,
        pathMappings: [
          { kind: 'copy', aliasRoot: 'Z:\\', physicalRoot: workspace.copyDirectory },
          { kind: 'runtime', aliasRoot: 'Y:\\', physicalRoot: 'C:\\temp\\black-gravity-runtime-1' },
          { kind: 'scratch', aliasRoot: 'X:\\', physicalRoot: 'C:\\temp\\black-gravity-scratch-1' },
        ],
      }),
    },
    {
      expectedNonce: nonce,
      roots: {
        copy: workspace.copyDirectory,
        runtime: 'C:\\temp\\black-gravity-runtime-1',
        scratch: 'C:\\temp\\black-gravity-scratch-1',
      },
      maxOutputChars: 4000,
    },
  );
  assert.equal(parsed.workspaceLpacValidated, true);
});

test('LPAC Windows native: canonical workspace grants scoped capability ACEs once, validates per turn, enforces write vs read-only, and isolates cross-root/state paths', { skip: process.platform !== 'win32' }, async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-win-lpac-canon-')));
  const stateDir = path.join(root, 'state');
  const repoA = path.join(root, 'repo-a');
  const repoB = path.join(root, 'repo-b');
  const outside = path.join(root, 'outside');
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(repoA, { recursive: true });
  mkdirSync(repoB, { recursive: true });
  mkdirSync(outside, { recursive: true });
  t.after(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const wsA = await createCanonicalWorkspaceFixture(stateDir, repoA);
  const wsB = await createCanonicalWorkspaceFixture(stateDir, repoB);
  await writeFile(path.join(wsA.copyDirectory, 'source.txt'), 'canonical-A\n', 'utf8');
  await writeFile(path.join(wsB.copyDirectory, 'secret-b.txt'), 'secret-in-B\n', 'utf8');
  await writeFile(path.join(outside, 'private.txt'), 'outside-secret\n', 'utf8');

  const observedActions: string[] = [];
  const trackActions: NonNullable<WindowsExecutionOptions['onProcess']> = child => {
    const reqPath = child.spawnargs.at(-1);
    if (typeof reqPath === 'string' && reqPath.endsWith('.json') && existsSync(reqPath)) {
      const req = JSON.parse(readFileSync(reqPath, 'utf8')) as { action?: string };
      if (req.action) observedActions.push(req.action);
    }
  };

  // Turn 1 (write): initializes fixed-folder scoped capability ACEs once, writes inside A, blocks B/state/outside.
  const turn1Script = [
    "const fs = require('node:fs');",
    "if (fs.readFileSync('source.txt', 'utf8') !== 'canonical-A\\n') process.exit(20);",
    "fs.writeFileSync('turn1.txt', 'written-in-turn1\\n');",
    `for (const target of [${JSON.stringify(path.join(wsB.copyDirectory, 'secret-b.txt'))}, ${JSON.stringify(wsA.metadataPath)}, ${JSON.stringify(path.join(outside, 'private.txt'))}]) {`,
    "  let denied = false;",
    "  try { fs.readFileSync(target); } catch (e) { denied = ['EACCES', 'EPERM', 'ENOENT'].includes(e.code); }",
    "  if (!denied) process.exit(21);",
    "}",
    "console.log('canonical-turn1-ok');",
  ].join('');
  const turn1 = await executeWindowsTest(nodeCommand(turn1Script), wsA.copyDirectory, {
    ...settings,
    mode: 'write',
    stateDirectory: stateDir,
    onProcess: trackActions,
  });
  assert.equal(turn1.error, undefined, JSON.stringify(turn1));
  assert.equal(turn1.exitCode, 0, turn1.output);
  assert.equal(turn1.sandbox, 'windows-lpac');
  assert.equal(turn1.profileDeleted, true);
  assert.equal(turn1.aliasesDeleted, true);
  assert.equal(turn1.workspaceLpacValidated, true);
  assert.match(turn1.output, /canonical-turn1-ok/);
  assert.equal(await readFile(path.join(wsA.copyDirectory, 'turn1.txt'), 'utf8'), 'written-in-turn1\n');
  assert.equal(observedActions.filter(a => a === 'init-workspace').length, 1);
  assert.equal(observedActions.filter(a => a === 'commit-workspace-lease').length, 1);

  const metaAfterTurn1 = readWorkspaceMetadata(wsA.metadataPath);
  assert.ok(metaAfterTurn1?.windowsLpac?.capabilityNonce);
  assert.ok(metaAfterTurn1?.windowsLpac?.readCapabilitySid?.startsWith('S-1-15-3-1024-'));
  assert.ok(metaAfterTurn1?.windowsLpac?.modifyCapabilitySid?.startsWith('S-1-15-3-1024-'));
  assert.match(metaAfterTurn1?.windowsLpac?.nativeDaclSha256 ?? '', /^[a-f0-9]{64}$/);

  const icaclsAfterTurn1 = execFileSync('icacls.exe', [wsA.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(normalizeIcaclsDacl(icaclsAfterTurn1, wsA.copyDirectory).hasLingeringAppContainer, false, icaclsAfterTurn1);

  // Turn 2 (write): MUST NOT re-run init-workspace or commit-workspace-lease, reuses pinned scoped ACEs with fresh ephemeral profile.
  observedActions.length = 0;
  const turn2Script = "const fs=require('node:fs');if(fs.readFileSync('turn1.txt','utf8')!=='written-in-turn1\\n')process.exit(30);fs.writeFileSync('turn2.txt','written-in-turn2\\n');console.log('canonical-turn2-ok');";
  const turn2 = await executeWindowsTest(nodeCommand(turn2Script), wsA.copyDirectory, {
    ...settings,
    mode: 'write',
    stateDirectory: stateDir,
    onProcess: trackActions,
  });
  assert.equal(turn2.error, undefined, JSON.stringify(turn2));
  assert.equal(turn2.exitCode, 0, turn2.output);
  assert.equal(turn2.workspaceLpacValidated, true);
  assert.equal(turn2.profileDeleted, true);
  assert.notEqual(turn2.nonce, turn1.nonce);
  assert.equal(observedActions.includes('init-workspace'), false, JSON.stringify(observedActions));
  assert.equal(observedActions.includes('commit-workspace-lease'), false, JSON.stringify(observedActions));
  assert.equal(readWorkspaceMetadata(wsA.metadataPath)?.windowsLpac?.initializedAt, metaAfterTurn1!.windowsLpac!.initializedAt);
  assert.equal(execFileSync('icacls.exe', [wsA.copyDirectory], { windowsHide: true, encoding: 'utf8' }), icaclsAfterTurn1);

  // Turn 3 (read-only): MUST NOT re-run init-workspace or commit-workspace-lease, allows reading copy and writing scratch, DENIES writing copy.
  observedActions.length = 0;
  const turn3Script = [
    "const fs = require('node:fs'), p = require('node:path');",
    "if (fs.readFileSync('turn2.txt', 'utf8') !== 'written-in-turn2\\n') process.exit(40);",
    "let denied = false;",
    "try { fs.writeFileSync('turn2.txt', 'must-fail'); } catch (e) { denied = ['EACCES', 'EPERM'].includes(e.code); }",
    "if (!denied) process.exit(41);",
    "fs.writeFileSync(p.join(process.env.TEMP, 'scratch-ok.txt'), 'ok');",
    "console.log('canonical-readonly-ok');",
  ].join('');
  const turn3 = await executeWindowsTest(nodeCommand(turn3Script), wsA.copyDirectory, {
    ...settings,
    mode: 'read-only',
    stateDirectory: stateDir,
    onProcess: trackActions,
  });
  assert.equal(turn3.error, undefined, JSON.stringify(turn3));
  assert.equal(turn3.exitCode, 0, turn3.output);
  assert.equal(turn3.workspaceLpacValidated, true);
  assert.equal(observedActions.includes('init-workspace'), false, JSON.stringify(observedActions));
  assert.equal(observedActions.includes('commit-workspace-lease'), false, JSON.stringify(observedActions));
  assert.equal(await readFile(path.join(wsA.copyDirectory, 'turn2.txt'), 'utf8'), 'written-in-turn2\n');
});

test('LPAC Windows native: refuses generic AppContainer ACE drift, forged workspace metadata, arbitrary state paths, and recovers interrupted canonical leases', { skip: process.platform !== 'win32' }, async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-win-lpac-refuse-')));
  const stateDir = path.join(root, 'state');
  const repoA = path.join(root, 'repo-a');
  const repoB = path.join(root, 'repo-b');
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(repoA, { recursive: true });
  mkdirSync(repoB, { recursive: true });
  t.after(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  // 1. Arbitrary directory under stateDirectory is rejected.
  const arbitraryDir = path.join(stateDir, 'arbitrary-copy');
  mkdirSync(arbitraryDir, { recursive: true });
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('no')"), arbitraryDir, { ...settings, stateDirectory: stateDir }),
    err => err instanceof BridgeError && err.code === 'UNSAFE_RUNTIME_PATH',
  );

  // 2. Forged workspace.json whose sourceDirectory does not match rootKey is rejected.
  const wsA = await createCanonicalWorkspaceFixture(stateDir, repoA);
  writeWorkspaceMetadata(wsA.metadataPath, {
    version: 1,
    sourceDirectory: repoB,
    rootKey: wsA.rootKey,
    updatedAt: new Date().toISOString(),
  });
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('no')"), wsA.copyDirectory, { ...settings, stateDirectory: stateDir }),
    err => err instanceof BridgeError && err.code === 'WINDOWS_LPAC_PERMISSIONS_INVALID',
  );

  // Restore valid metadata, initialize once, then inject generic ALL APPLICATION PACKAGES (S-1-15-2-1) -> must fail closed.
  writeWorkspaceMetadata(wsA.metadataPath, {
    version: 1,
    sourceDirectory: repoA,
    rootKey: wsA.rootKey,
    updatedAt: new Date().toISOString(),
  });
  const okTurn = await executeWindowsTest(nodeCommand("console.log('init-ok')"), wsA.copyDirectory, { ...settings, stateDirectory: stateDir });
  assert.equal(okTurn.exitCode, 0, JSON.stringify(okTurn));

  execFileSync('icacls.exe', [wsA.copyDirectory, '/grant', '*S-1-15-2-1:(OI)(CI)RX'], { windowsHide: true });
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('must-fail')"), wsA.copyDirectory, { ...settings, stateDirectory: stateDir }),
    err => err instanceof BridgeError && err.code === 'WINDOWS_LPAC_PERMISSIONS_INVALID',
  );
  execFileSync('icacls.exe', [wsA.copyDirectory, '/remove', '*S-1-15-2-1'], { windowsHide: true });

  // 3. N3 two-phase crash BEFORE pin commit: prepared v4 lease remains on disk, recovery revokes capability ACEs and allows clean re-init.
  const wsB = await createCanonicalWorkspaceFixture(stateDir, repoB);
  const leaseDir = path.join(stateDir, 'windows-lpac-leases');
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('crash-before-pin')"), wsB.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-prepare') throw new Error('simulated crash after prepare before pin');
      },
    }),
    /simulated crash after prepare before pin/,
  );
  const leasesBeforePinRecover = readdirSync(leaseDir).filter(name => name.endsWith('.json'));
  assert.equal(leasesBeforePinRecover.length, 1);
  const preparedLeaseBeforePin = JSON.parse(readFileSync(path.join(leaseDir, leasesBeforePinRecover[0]!), 'utf8')) as {
    version: number;
    phase: string;
    readCapabilitySid: string;
    modifyCapabilitySid: string;
  };
  assert.equal(preparedLeaseBeforePin.version, 4);
  assert.equal(preparedLeaseBeforePin.phase, 'prepared');
  assert.equal(readWorkspaceMetadata(wsB.metadataPath)?.windowsLpac?.capabilityNonce, undefined);
  const icaclsBeforePinRecover = execFileSync('icacls.exe', [wsB.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(icaclsBeforePinRecover.includes(preparedLeaseBeforePin.readCapabilitySid), true, icaclsBeforePinRecover);
  assert.equal(icaclsBeforePinRecover.includes(preparedLeaseBeforePin.modifyCapabilitySid), true, icaclsBeforePinRecover);

  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.deepEqual(readdirSync(leaseDir).filter(name => name.endsWith('.json')), []);
  const icaclsAfterPinRecover = execFileSync('icacls.exe', [wsB.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(icaclsAfterPinRecover.includes(preparedLeaseBeforePin.readCapabilitySid), false, icaclsAfterPinRecover);
  assert.equal(icaclsAfterPinRecover.includes(preparedLeaseBeforePin.modifyCapabilitySid), false, icaclsAfterPinRecover);

  // 4. N3 two-phase crash AFTER pin commit BEFORE lease ack: recovery verifies committed pin, keeps valid ACEs intact, and clears lease without re-init.
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('crash-after-pin')"), wsB.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-pin') throw new Error('simulated crash after pin before ack');
      },
    }),
    /simulated crash after pin before ack/,
  );
  const leasesAfterPin = readdirSync(leaseDir).filter(name => name.endsWith('.json'));
  assert.equal(leasesAfterPin.length, 1);
  const committedMetaB = readWorkspaceMetadata(wsB.metadataPath);
  assert.ok(committedMetaB?.windowsLpac?.capabilityNonce);
  assert.ok(committedMetaB?.windowsLpac?.readCapabilitySid);
  assert.ok(committedMetaB?.windowsLpac?.modifyCapabilitySid);

  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.deepEqual(readdirSync(leaseDir).filter(name => name.endsWith('.json')), []);
  const icaclsAfterCommitRecover = execFileSync('icacls.exe', [wsB.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(icaclsAfterCommitRecover.includes(committedMetaB!.windowsLpac!.readCapabilitySid!), true, icaclsAfterCommitRecover);
  assert.equal(icaclsAfterCommitRecover.includes(committedMetaB!.windowsLpac!.modifyCapabilitySid!), true, icaclsAfterCommitRecover);

  const observedAfterRecover: string[] = [];
  const reusedAfterRecover = await executeWindowsTest(nodeCommand("console.log('reused-committed-pin')"), wsB.copyDirectory, {
    ...settings,
    stateDirectory: stateDir,
    onProcess: child => {
      const reqPath = child.spawnargs.at(-1);
      if (typeof reqPath === 'string' && reqPath.endsWith('.json') && existsSync(reqPath)) {
        const req = JSON.parse(readFileSync(reqPath, 'utf8')) as { action?: string };
        if (req.action) observedAfterRecover.push(req.action);
      }
    },
  });
  assert.equal(reusedAfterRecover.exitCode, 0, JSON.stringify(reusedAfterRecover));
  assert.equal(reusedAfterRecover.workspaceLpacValidated, true);
  assert.equal(observedAfterRecover.includes('init-workspace'), false, JSON.stringify(observedAfterRecover));

  // 5. Interrupted v4 init-workspace lease (uncommitted phase "init-workspace") for existing canonical workspace A revokes both capability ACEs from NTFS.
  mkdirSync(leaseDir, { recursive: true });
  const exited = execFileSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { windowsHide: true, encoding: 'utf8' });
  const deadPid = Number(exited.trim());
  const metaA = readWorkspaceMetadata(wsA.metadataPath)!;
  const liveLeaseNonce = randomUUID();
  const liveLeasePath = path.join(leaseDir, `${liveLeaseNonce.replaceAll('-', '')}.json`);
  writeFileSync(liveLeasePath, JSON.stringify({
    version: 4,
    nonce: liveLeaseNonce,
    phase: 'init-workspace',
    controllerPid: deadPid,
    controllerStarted: 1,
    cwd: wsA.copyDirectory,
    grants: [{
      path: wsA.copyDirectory,
      rights: 'read',
      directory: true,
      volume: metaA.windowsLpac!.volume!,
      fileIndexHigh: metaA.windowsLpac!.fileIndexHigh!,
      fileIndexLow: metaA.windowsLpac!.fileIndexLow!,
    }],
    capabilityNonce: metaA.windowsLpac!.capabilityNonce!,
    readCapabilitySid: metaA.windowsLpac!.readCapabilitySid,
    modifyCapabilitySid: metaA.windowsLpac!.modifyCapabilitySid,
  }), 'utf8');
  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.equal(existsSync(liveLeasePath), false);
  const icaclsAfterRecover = execFileSync('icacls.exe', [wsA.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(icaclsAfterRecover.includes(metaA.windowsLpac!.readCapabilitySid!), false, icaclsAfterRecover);
  assert.equal(icaclsAfterRecover.includes(metaA.windowsLpac!.modifyCapabilitySid!), false, icaclsAfterRecover);

  // 6. Interrupted v4 lease for a missing/discarded canonical workspace C is cleanly recovered and deleted.
  const repoC = path.join(root, 'repo-c');
  mkdirSync(repoC, { recursive: true });
  const wsC = await createCanonicalWorkspaceFixture(stateDir, repoC);
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('crash-for-discarded')"), wsC.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-prepare') throw new Error('simulated crash before discard');
      },
    }),
    /simulated crash before discard/,
  );
  assert.equal(readdirSync(leaseDir).filter(name => name.endsWith('.json')).length, 1);
  rmSync(wsC.copyDirectory, { recursive: true, force: true });
  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.deepEqual(readdirSync(leaseDir).filter(name => name.endsWith('.json')), []);
});

test('LPAC Windows native (N5): protects prepared grant across concurrent cross-root recovery, cleans real orphans, preserves crash points, and never revokes referenced grants on inconclusive checks', { skip: process.platform !== 'win32' }, async t => {
  const root = await realpath(mkdtempSync(path.join(os.tmpdir(), 'bg-win-lpac-n5-')));
  const stateDir = path.join(root, 'state');
  const repoOrphan = path.join(root, 'repo-orphan');
  const repoA = path.join(root, 'repo-a');
  const repoB = path.join(root, 'repo-b');
  const repoC = path.join(root, 'repo-c');
  const repoD = path.join(root, 'repo-d');
  for (const dir of [stateDir, repoOrphan, repoA, repoB, repoC, repoD]) {
    mkdirSync(dir, { recursive: true });
  }
  t.after(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const leaseDir = path.join(stateDir, 'windows-lpac-leases');
  const listLeaseFiles = (ext: '.json' | '.hold') =>
    existsSync(leaseDir) ? readdirSync(leaseDir).filter(name => name.endsWith(ext)).sort() : [];
  const readPreparedLease = (fileName: string) =>
    JSON.parse(readFileSync(path.join(leaseDir, fileName), 'utf8')) as {
      version: number;
      nonce: string;
      phase: string;
      cwd: string;
      readCapabilitySid: string;
      modifyCapabilitySid: string;
    };
  const createActionTracker = () => {
    const actions: string[] = [];
    const onProcess: NonNullable<WindowsExecutionOptions['onProcess']> = child => {
      const reqPath = child.spawnargs.at(-1);
      if (typeof reqPath === 'string' && reqPath.endsWith('.json') && existsSync(reqPath)) {
        const req = JSON.parse(readFileSync(reqPath, 'utf8')) as { action?: string };
        if (req.action) actions.push(req.action);
      }
    };
    return { actions, onProcess };
  };

  const wsOrphan = await createCanonicalWorkspaceFixture(stateDir, repoOrphan);
  const wsA = await createCanonicalWorkspaceFixture(stateDir, repoA);
  const wsB = await createCanonicalWorkspaceFixture(stateDir, repoB);
  const wsC = await createCanonicalWorkspaceFixture(stateDir, repoC);
  const wsD = await createCanonicalWorkspaceFixture(stateDir, repoD);

  // 1. Seed a positively orphaned prepared lease on wsOrphan (crash after prepare before pin).
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('orphan-crash')"), wsOrphan.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-prepare') throw new Error('simulated orphan crash after prepare');
      },
    }),
    /simulated orphan crash after prepare/,
  );
  const orphanLeases = listLeaseFiles('.json');
  assert.equal(orphanLeases.length, 1);
  assert.deepEqual(listLeaseFiles('.hold'), []);
  const orphanLeaseFile = orphanLeases[0]!;
  const orphanLease = readPreparedLease(orphanLeaseFile);
  assert.equal(orphanLease.version, 4);
  assert.equal(orphanLease.phase, 'prepared');
  const orphanAclBefore = execFileSync('icacls.exe', [wsOrphan.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(orphanAclBefore.includes(orphanLease.readCapabilitySid), true, orphanAclBefore);
  assert.equal(orphanAclBefore.includes(orphanLease.modifyCapabilitySid), true, orphanAclBefore);

  // 2. Same-process cross-root recovery at after-prepare and after-pin:
  //    wsA holds its prepared grant while wsB executes concurrently (triggering pre- and post-execution global recovery)
  //    and real orphan cleanup still revokes wsOrphan.
  let wsAPreparedLeaseFile = '';
  let wsAPreparedReadSid = '';
  let wsAPreparedModifySid = '';
  let afterPrepareRan = false;
  let afterPinRan = false;

  const rootAResult = await executeWindowsTest(
    nodeCommand("const fs=require('node:fs');fs.writeFileSync('root-a.txt','from-root-a\\n');console.log('root-a-ok');"),
    wsA.copyDirectory,
    {
      ...settings,
      mode: 'write',
      stateDirectory: stateDir,
      onInitPhase: async phase => {
        if (phase === 'after-prepare') {
          afterPrepareRan = true;
          const activeLeases = listLeaseFiles('.json');
          const wsALeaseName = activeLeases.find(name => name !== orphanLeaseFile);
          assert.ok(wsALeaseName, `expected wsA prepared lease alongside orphan: ${JSON.stringify(activeLeases)}`);
          wsAPreparedLeaseFile = wsALeaseName;
          const wsALease = readPreparedLease(wsAPreparedLeaseFile);
          assert.equal(wsALease.version, 4);
          assert.equal(wsALease.phase, 'prepared');
          wsAPreparedReadSid = wsALease.readCapabilitySid;
          wsAPreparedModifySid = wsALease.modifyCapabilitySid;
          assert.equal(existsSync(path.join(leaseDir, wsAPreparedLeaseFile.replace(/\.json$/, '.hold'))), true);
          assert.equal(readWorkspaceMetadata(wsA.metadataPath)?.windowsLpac?.capabilityNonce, undefined);

          // Concurrent root B executes end-to-end (runs global recovery before and after execution).
          const rootBResult = await executeWindowsTest(
            nodeCommand("const fs=require('node:fs');fs.writeFileSync('root-b.txt','from-root-b\\n');console.log('root-b-ok');"),
            wsB.copyDirectory,
            { ...settings, mode: 'write', stateDirectory: stateDir },
          );
          assert.equal(rootBResult.exitCode, 0, JSON.stringify(rootBResult));
          assert.equal(rootBResult.workspaceLpacValidated, true);
          assert.equal(await readFile(path.join(wsB.copyDirectory, 'root-b.txt'), 'utf8'), 'from-root-b\n');

          // Real orphan on wsOrphan MUST be cleaned, while wsA's prepared lease and ACEs MUST survive intact.
          assert.equal(existsSync(path.join(leaseDir, orphanLeaseFile)), false);
          const orphanAclAfter = execFileSync('icacls.exe', [wsOrphan.copyDirectory], { windowsHide: true, encoding: 'utf8' });
          assert.equal(orphanAclAfter.includes(orphanLease.readCapabilitySid), false, orphanAclAfter);
          assert.equal(orphanAclAfter.includes(orphanLease.modifyCapabilitySid), false, orphanAclAfter);

          assert.equal(existsSync(path.join(leaseDir, wsAPreparedLeaseFile)), true);
          const wsAAclDuringPrepare = execFileSync('icacls.exe', [wsA.copyDirectory], { windowsHide: true, encoding: 'utf8' });
          assert.equal(wsAAclDuringPrepare.includes(wsAPreparedReadSid), true, wsAAclDuringPrepare);
          assert.equal(wsAAclDuringPrepare.includes(wsAPreparedModifySid), true, wsAAclDuringPrepare);

          // Idle-requiring recovery must see the active prepared init without revoking it.
          await assert.rejects(
            () => recoverWindowsExecutions(stateDir, { requireIdle: true }),
            err => err instanceof BridgeError && err.code === 'WINDOWS_EXECUTION_RECOVERY_FAILED',
          );
          assert.equal(existsSync(path.join(leaseDir, wsAPreparedLeaseFile)), true);
        } else if (phase === 'after-pin') {
          afterPinRan = true;
          // Another cross-root execution after wsA commits workspace.json but before commit-workspace-lease ack
          // must keep wsA's lease on disk so wsA's own ack succeeds.
          const rootBTurn2 = await executeWindowsTest(
            nodeCommand("console.log('root-b-turn2-ok');"),
            wsB.copyDirectory,
            { ...settings, mode: 'read-only', stateDirectory: stateDir },
          );
          assert.equal(rootBTurn2.exitCode, 0, JSON.stringify(rootBTurn2));
          assert.equal(rootBTurn2.workspaceLpacValidated, true);
          assert.equal(existsSync(path.join(leaseDir, wsAPreparedLeaseFile)), true);
        }
      },
    },
  );
  assert.equal(afterPrepareRan, true);
  assert.equal(afterPinRan, true);
  assert.equal(rootAResult.exitCode, 0, JSON.stringify(rootAResult));
  assert.equal(rootAResult.workspaceLpacValidated, true);
  assert.equal(await readFile(path.join(wsA.copyDirectory, 'root-a.txt'), 'utf8'), 'from-root-a\n');
  assert.deepEqual(listLeaseFiles('.json'), []);
  assert.deepEqual(listLeaseFiles('.hold'), []);

  // Following execution on wsA reuses its committed pin without re-initializing.
  const followTracker = createActionTracker();
  const rootAFollow = await executeWindowsTest(
    nodeCommand("const fs=require('node:fs');if(fs.readFileSync('root-a.txt','utf8')!=='from-root-a\\n')process.exit(50);console.log('root-a-follow-ok');"),
    wsA.copyDirectory,
    { ...settings, mode: 'read-only', stateDirectory: stateDir, onProcess: followTracker.onProcess },
  );
  assert.equal(rootAFollow.exitCode, 0, JSON.stringify(rootAFollow));
  assert.equal(rootAFollow.workspaceLpacValidated, true);
  assert.equal(followTracker.actions.includes('init-workspace'), false, JSON.stringify(followTracker.actions));
  assert.equal(followTracker.actions.includes('commit-workspace-lease'), false, JSON.stringify(followTracker.actions));

  // 3. Both prior crash points still work cleanly on wsC after owner hold is released on error.
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('c-before-pin')"), wsC.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-prepare') throw new Error('simulated wsC crash after prepare');
      },
    }),
    /simulated wsC crash after prepare/,
  );
  const wsCBeforePinLeases = listLeaseFiles('.json');
  assert.equal(wsCBeforePinLeases.length, 1);
  assert.deepEqual(listLeaseFiles('.hold'), []);
  const wsCBeforePinLease = readPreparedLease(wsCBeforePinLeases[0]!);
  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.deepEqual(listLeaseFiles('.json'), []);
  const wsCAclAfterBeforePinRecover = execFileSync('icacls.exe', [wsC.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(wsCAclAfterBeforePinRecover.includes(wsCBeforePinLease.readCapabilitySid), false, wsCAclAfterBeforePinRecover);
  assert.equal(wsCAclAfterBeforePinRecover.includes(wsCBeforePinLease.modifyCapabilitySid), false, wsCAclAfterBeforePinRecover);

  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('c-after-pin')"), wsC.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-pin') throw new Error('simulated wsC crash after pin');
      },
    }),
    /simulated wsC crash after pin/,
  );
  assert.equal(listLeaseFiles('.json').length, 1);
  assert.deepEqual(listLeaseFiles('.hold'), []);
  const wsCMetaAfterPin = readWorkspaceMetadata(wsC.metadataPath);
  assert.ok(wsCMetaAfterPin?.windowsLpac?.readCapabilitySid);
  assert.ok(wsCMetaAfterPin?.windowsLpac?.modifyCapabilitySid);
  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.deepEqual(listLeaseFiles('.json'), []);
  const wsCAclAfterPinRecover = execFileSync('icacls.exe', [wsC.copyDirectory], { windowsHide: true, encoding: 'utf8' });
  assert.equal(wsCAclAfterPinRecover.includes(wsCMetaAfterPin!.windowsLpac!.readCapabilitySid!), true, wsCAclAfterPinRecover);
  assert.equal(wsCAclAfterPinRecover.includes(wsCMetaAfterPin!.windowsLpac!.modifyCapabilitySid!), true, wsCAclAfterPinRecover);

  // 4. Inconclusive check on an already-referenced grant (wsD) MUST fail closed WITHOUT revoking ACEs or mutating the prepared lease.
  await assert.rejects(
    () => executeWindowsTest(nodeCommand("console.log('d-after-pin')"), wsD.copyDirectory, {
      ...settings,
      stateDirectory: stateDir,
      onInitPhase: phase => {
        if (phase === 'after-pin') throw new Error('simulated wsD crash after pin');
      },
    }),
    /simulated wsD crash after pin/,
  );
  const wsDLeases = listLeaseFiles('.json');
  assert.equal(wsDLeases.length, 1);
  const wsDLeaseFile = wsDLeases[0]!;
  const wsDMeta = readWorkspaceMetadata(wsD.metadataPath)!;
  const wsDReadSid = wsDMeta.windowsLpac!.readCapabilitySid!;
  const wsDModifySid = wsDMeta.windowsLpac!.modifyCapabilitySid!;
  const wsDExpectedNativeDaclSha256 = wsDMeta.windowsLpac?.nativeDaclSha256 ?? '';
  assert.match(wsDExpectedNativeDaclSha256, /^[a-f0-9]{64}$/);
  const wsDDaclPathEnvVar = 'BG_LPAC_WSD_PATH';
  const wsDDaclOpEnvVar = 'BG_LPAC_WSD_OP';
  const wsDDaclSnapshotEnvVar = 'BG_LPAC_WSD_SNAPSHOT_PATH';
  const wsDDaclHelperEncoded = Buffer.from(
    [
      "$ErrorActionPreference = 'Stop'",
      "$ProgressPreference = 'SilentlyContinue'",
      `$targetPath = [Environment]::GetEnvironmentVariable('${wsDDaclPathEnvVar}')`,
      `$op = [Environment]::GetEnvironmentVariable('${wsDDaclOpEnvVar}')`,
      `$snapshotPath = [Environment]::GetEnvironmentVariable('${wsDDaclSnapshotEnvVar}')`,
      "if ([string]::IsNullOrEmpty($targetPath) -or [string]::IsNullOrEmpty($op)) { throw 'Missing helper inputs' }",
      "$source = @'",
      'using System;',
      'using System.Globalization;',
      'using System.IO;',
      'using System.Runtime.InteropServices;',
      'using System.Security.AccessControl;',
      'using System.Security.Cryptography;',
      'using System.Text;',
      'public static class BgNativeDaclHelper',
      '{',
      '    [DllImport("advapi32.dll", EntryPoint = "GetFileSecurityW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]',
      '    private static extern bool GetFileSecurityW(string path, uint information, byte[] descriptor, uint length, out uint needed);',
      '    [DllImport("advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]',
      '    private static extern bool SetFileSecurityW(string path, uint information, byte[] descriptor);',
      '    private static string CanonicalPath(string path)',
      '    {',
      '        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);',
      '    }',
      '    private static byte[] ReadDaclBytes(string path)',
      '    {',
      '        string canonical = CanonicalPath(path);',
      '        uint needed;',
      '        if (!GetFileSecurityW(canonical, 4, null, 0, out needed))',
      '        {',
      '            int err = Marshal.GetLastWin32Error();',
      '            if (err != 122) throw new Exception("Measure target DACL failed");',
      '        }',
      '        if (needed == 0 || needed > 1024 * 1024) throw new Exception("Invalid target DACL size");',
      '        byte[] data = new byte[needed];',
      '        if (!GetFileSecurityW(canonical, 4, data, needed, out needed)) throw new Exception("Read target DACL failed");',
      '        return data;',
      '    }',
      '    private static string ComputeDaclSha256(RawSecurityDescriptor descriptor)',
      '    {',
      '        if (descriptor == null || descriptor.DiscretionaryAcl == null) throw new Exception("Target has no DACL");',
      '        byte[] flagBytes = BitConverter.GetBytes((int)descriptor.ControlFlags);',
      '        byte[] aclBytes = new byte[descriptor.DiscretionaryAcl.BinaryLength];',
      '        descriptor.DiscretionaryAcl.GetBinaryForm(aclBytes, 0);',
      '        byte[] combined = new byte[flagBytes.Length + aclBytes.Length];',
      '        Buffer.BlockCopy(flagBytes, 0, combined, 0, flagBytes.Length);',
      '        Buffer.BlockCopy(aclBytes, 0, combined, flagBytes.Length, aclBytes.Length);',
      '        using (SHA256 sha = SHA256.Create())',
      '        {',
      '            byte[] hash = sha.ComputeHash(combined);',
      '            StringBuilder sb = new StringBuilder(hash.Length * 2);',
      '            for (int index = 0; index < hash.Length; index++) sb.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));',
      '            return sb.ToString();',
      '        }',
      '    }',
      '    public static string Digest(string path)',
      '    {',
      '        return ComputeDaclSha256(new RawSecurityDescriptor(ReadDaclBytes(path), 0));',
      '    }',
      '    public static string Snapshot(string path, string snapshotPath)',
      '    {',
      '        if (String.IsNullOrEmpty(snapshotPath)) throw new Exception("Missing snapshot path");',
      '        byte[] data = ReadDaclBytes(path);',
      '        string digest = ComputeDaclSha256(new RawSecurityDescriptor(data, 0));',
      '        using (FileStream stream = new FileStream(snapshotPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))',
      '        {',
      '            stream.Write(data, 0, data.Length);',
      '            stream.Flush(true);',
      '        }',
      '        return digest;',
      '    }',
      '    public static string Restore(string path, string snapshotPath)',
      '    {',
      '        if (String.IsNullOrEmpty(snapshotPath)) throw new Exception("Missing snapshot path");',
      '        FileAttributes attrs = File.GetAttributes(snapshotPath);',
      '        if ((attrs & FileAttributes.ReparsePoint) != 0 || (attrs & FileAttributes.Directory) != 0) throw new Exception("Invalid snapshot file");',
      '        byte[] data = File.ReadAllBytes(snapshotPath);',
      '        if (data.Length == 0 || data.Length > 1024 * 1024) throw new Exception("Invalid DACL snapshot size");',
      '        RawSecurityDescriptor descriptor = new RawSecurityDescriptor(data, 0);',
      '        if (descriptor.DiscretionaryAcl == null) throw new Exception("Snapshot has no DACL");',
      '        ControlFlags storedFlags = descriptor.ControlFlags;',
      '        if ((storedFlags & ControlFlags.DiscretionaryAclAutoInherited) != 0) descriptor.SetFlags(storedFlags | ControlFlags.DiscretionaryAclAutoInheritRequired);',
      '        byte[] writeData = new byte[descriptor.BinaryLength];',
      '        descriptor.GetBinaryForm(writeData, 0);',
      '        string canonical = CanonicalPath(path);',
      '        if (!SetFileSecurityW(canonical, 4, writeData)) throw new Exception("Restore target DACL failed");',
      '        return Digest(canonical);',
      '    }',
      '}',
      "'@",
      'Add-Type -TypeDefinition $source',
      "if ($op -eq 'snapshot') {",
      '  [Console]::Out.Write([BgNativeDaclHelper]::Snapshot($targetPath, $snapshotPath))',
      "} elseif ($op -eq 'restore') {",
      '  [Console]::Out.Write([BgNativeDaclHelper]::Restore($targetPath, $snapshotPath))',
      "} elseif ($op -eq 'digest') {",
      '  [Console]::Out.Write([BgNativeDaclHelper]::Digest($targetPath))',
      '} else {',
      "  throw 'Unsupported helper operation'",
      '}',
    ].join('\n'),
    'utf16le',
  ).toString('base64');
  const systemRoot = process.env.SystemRoot || 'C:\\Windows';
  const powershellFullPath = path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const powershellExe = existsSync(powershellFullPath) ? powershellFullPath : 'powershell.exe';
  const wsDDaclSnapshotPath = path.join(root, '.ws-d-dacl-snapshot.bin');
  const runWsDNativeDaclHelper = (op: 'snapshot' | 'restore' | 'digest'): string => {
    let raw: string;
    try {
      raw = execFileSync(
        powershellExe,
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', wsDDaclHelperEncoded],
        {
          cwd: os.tmpdir(),
          env: {
            ...process.env,
            [wsDDaclPathEnvVar]: wsD.copyDirectory,
            [wsDDaclOpEnvVar]: op,
            ...(op === 'digest' ? {} : { [wsDDaclSnapshotEnvVar]: wsDDaclSnapshotPath }),
          },
          encoding: 'utf8',
          maxBuffer: 16 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 15_000,
          windowsHide: true,
        },
      ).trim();
    } catch (error: unknown) {
      const timedOut = typeof error === 'object' && error !== null && 'code' in error && (error as { code?: unknown }).code === 'ETIMEDOUT';
      throw new Error(timedOut ? `wsD native DACL helper timed out during ${op}` : `wsD native DACL helper failed during ${op}`);
    }
    if (!/^[a-f0-9]{64}$/.test(raw)) {
      throw new Error(`wsD native DACL helper returned invalid digest during ${op}`);
    }
    return raw;
  };

  // 4a. DACL verification failure on a referenced grant -> inconclusive -> MUST NOT revoke.
  let wsDDaclMutated = false;
  let wsDDigestAfterRestore = '';
  try {
    const wsDDigestBeforeGrant = runWsDNativeDaclHelper('snapshot');
    assert.match(wsDDigestBeforeGrant, /^[a-f0-9]{64}$/);
    assert.equal(wsDDigestBeforeGrant, wsDExpectedNativeDaclSha256);

    execFileSync('icacls.exe', [wsD.copyDirectory, '/grant', '*S-1-15-2-1:(OI)(CI)RX'], { windowsHide: true });
    wsDDaclMutated = true;

    await assert.rejects(
      () => recoverWindowsExecutions(stateDir, { requireIdle: true }),
      err => err instanceof BridgeError && err.code === 'WINDOWS_EXECUTION_RECOVERY_FAILED',
    );
    assert.equal(existsSync(path.join(leaseDir, wsDLeaseFile)), true);
    assert.equal(readPreparedLease(wsDLeaseFile).phase, 'prepared');
    const wsDAclAfterInconclusiveDacl = execFileSync('icacls.exe', [wsD.copyDirectory], { windowsHide: true, encoding: 'utf8' });
    assert.equal(wsDAclAfterInconclusiveDacl.includes(wsDReadSid), true);
    assert.equal(wsDAclAfterInconclusiveDacl.includes(wsDModifySid), true);
  } finally {
    try {
      if (wsDDaclMutated) {
        wsDDigestAfterRestore = runWsDNativeDaclHelper('restore');
      }
    } finally {
      rmSync(wsDDaclSnapshotPath, { force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
  assert.match(wsDDigestAfterRestore, /^[a-f0-9]{64}$/);
  assert.equal(wsDDigestAfterRestore, wsDExpectedNativeDaclSha256);

  // 4b. Unparseable workspace.json while prepared lease exists -> inconclusive -> MUST NOT revoke.
  const validWsDMetaRaw = readFileSync(wsD.metadataPath, 'utf8');
  writeFileSync(wsD.metadataPath, '{invalid-json', 'utf8');
  try {
    await assert.rejects(
      () => recoverWindowsExecutions(stateDir, { requireIdle: true }),
      err => err instanceof BridgeError && err.code === 'WINDOWS_EXECUTION_RECOVERY_FAILED',
    );
    assert.equal(existsSync(path.join(leaseDir, wsDLeaseFile)), true);
    assert.equal(readPreparedLease(wsDLeaseFile).phase, 'prepared');
    const wsDAclAfterCorruptMeta = execFileSync('icacls.exe', [wsD.copyDirectory], { windowsHide: true, encoding: 'utf8' });
    assert.equal(wsDAclAfterCorruptMeta.includes(wsDReadSid), true);
    assert.equal(wsDAclAfterCorruptMeta.includes(wsDModifySid), true);
  } finally {
    writeFileSync(wsD.metadataPath, validWsDMetaRaw, 'utf8');
  }

  // 4c. Once the inconclusive condition clears, recovery confirms the committed pin, clears the lease, and wsD executes without re-init.
  const wsDDigestBefore4c = runWsDNativeDaclHelper('digest');
  assert.match(wsDDigestBefore4c, /^[a-f0-9]{64}$/);
  assert.equal(wsDDigestBefore4c, wsDExpectedNativeDaclSha256);
  await recoverWindowsExecutions(stateDir, { requireIdle: true });
  assert.deepEqual(listLeaseFiles('.json'), []);
  assert.deepEqual(listLeaseFiles('.hold'), []);
  const wsDFollowTracker = createActionTracker();
  const wsDFollow = await executeWindowsTest(
    nodeCommand("console.log('ws-d-reused-ok');"),
    wsD.copyDirectory,
    { ...settings, mode: 'read-only', stateDirectory: stateDir, onProcess: wsDFollowTracker.onProcess },
  );
  assert.equal(wsDFollow.exitCode, 0, JSON.stringify(wsDFollow));
  assert.equal(wsDFollow.workspaceLpacValidated, true);
  assert.equal(wsDFollowTracker.actions.includes('init-workspace'), false, JSON.stringify(wsDFollowTracker.actions));
});
