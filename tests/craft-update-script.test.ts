import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../scripts/update-anti-ai-craft.mjs', import.meta.url));
const SKILLS = ['anti-ai-audit', 'anti-ai-code', 'anti-ai-design', 'anti-ai-design-flow', 'anti-ai-remediate', 'anti-ai-security'];

test('update-anti-ai-craft --check catches same-length file tampering under skills/', async () => {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-fixture-'));
  const work = await mkdtemp(path.join(os.tmpdir(), 'black-gravity-craft-work-'));
  try {
    const fixture = path.join(fixtureRoot, 'repo');
    await mkdir(path.join(fixture, 'plugins', 'anti-ai-craft', '.codex-plugin'), { recursive: true });
    await writeFile(path.join(fixture, 'plugins', 'anti-ai-craft', '.codex-plugin', 'plugin.json'), '{"version":"0.0.1"}\n');
    for (const skill of SKILLS) {
      const dir = path.join(fixture, 'plugins', 'anti-ai-craft', 'skills', skill);
      await mkdir(dir, { recursive: true });
      await writeFile(path.join(dir, 'SKILL.md'), `---\nname: ${skill}\n---\nSkill ${skill}.\n`);
    }
    const refDir = path.join(fixture, 'plugins', 'anti-ai-craft', 'skills', 'anti-ai-code', 'references');
    await mkdir(refDir, { recursive: true });
    await writeFile(path.join(refDir, 'a.md'), 'Reference alpha.\n');

    execFileSync('git', ['-c', 'core.autocrlf=false', 'init', '--quiet'], { cwd: fixture, encoding: 'utf8', windowsHide: true });
    execFileSync('git', ['-c', 'core.autocrlf=false', 'add', '.'], { cwd: fixture, encoding: 'utf8', windowsHide: true });
    execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '--quiet', '-m', 'init'],
      { cwd: fixture, encoding: 'utf8', windowsHide: true });
    const revision = execFileSync('git', ['-c', 'core.autocrlf=false', 'rev-parse', 'HEAD'], { cwd: fixture, encoding: 'utf8', windowsHide: true }).trim();

    await mkdir(path.join(work, 'src'), { recursive: true });
    await mkdir(path.join(work, 'plugin'), { recursive: true });
    const runScript = (...args: string[]) =>
      spawnSync(process.execPath, [script, ...args, '--source', fixture],
        { cwd: work, encoding: 'utf8', timeout: 120_000, windowsHide: true });

    const updated = runScript('--revision', revision);
    assert.equal(updated.status, 0, updated.stderr);
    const manifestPath = path.join(work, 'plugin', 'anti-ai-craft', 'manifest.json');
    const manifestBytes = await readFile(manifestPath);
    const manifestSha256 = createHash('sha256').update(manifestBytes).digest('hex');
    const pinText = await readFile(path.join(work, 'src', 'craft-pin.ts'), 'utf8');
    assert.ok(pinText.includes(manifestSha256));

    const checked = runScript('--check');
    assert.equal(checked.status, 0, checked.stderr);

    const committedRef = path.join(work, 'plugin', 'anti-ai-craft', 'skills', 'anti-ai-code', 'references', 'a.md');
    const original = await readFile(committedRef, 'utf8');
    const tamperedBytes = 'X'.repeat(Buffer.byteLength(original, 'utf8'));
    assert.notEqual(tamperedBytes, original);
    assert.equal(Buffer.byteLength(tamperedBytes, 'utf8'), Buffer.byteLength(original, 'utf8'));
    await writeFile(committedRef, tamperedBytes, 'utf8');

    const tampered = runScript('--check');
    assert.notEqual(tampered.status, 0);
    assert.equal(tampered.status, 1, tampered.stderr);
    assert.ok(tampered.stderr.includes('skills/anti-ai-code/references/a.md'), tampered.stderr);

    await writeFile(committedRef, original, 'utf8');
    const restored = runScript('--check');
    assert.equal(restored.status, 0, restored.stderr);

    const skillsPath = path.join(work, 'plugin', 'anti-ai-craft', 'skills');
    const externalSkills = path.join(work, 'external-skills');
    await rename(skillsPath, externalSkills);
    try {
      await symlink(externalSkills, skillsPath, process.platform === 'win32' ? 'junction' : 'dir');
      const symlinkSkills = runScript('--check');
      assert.equal(symlinkSkills.status, 1, symlinkSkills.stderr);
      assert.ok(symlinkSkills.stderr.includes('skills'), symlinkSkills.stderr);
    } finally {
      await rm(skillsPath, { recursive: true, force: true });
      await rename(externalSkills, skillsPath);
    }

    const externalManifest = path.join(work, 'external-manifest.json');
    await rename(manifestPath, externalManifest);
    let manifestLinked = false;
    try {
      try {
        await symlink(externalManifest, manifestPath, 'file');
        manifestLinked = true;
      } catch (error) {
        if (process.platform !== 'win32' || (error as NodeJS.ErrnoException).code !== 'EPERM') throw error;
      }
      if (manifestLinked) {
        const symlinkManifest = runScript('--check');
        assert.equal(symlinkManifest.status, 1, symlinkManifest.stderr);
        assert.ok(symlinkManifest.stderr.includes('manifest.json'), symlinkManifest.stderr);
      }
    } finally {
      if (manifestLinked) await rm(manifestPath, { force: true });
      await rename(externalManifest, manifestPath);
    }
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
    await rm(work, { recursive: true, force: true });
  }
});
