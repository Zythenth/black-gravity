// Maintainer tool: replaces plugin/anti-ai-craft with one pinned revision of the official repository, or checks reproducibility.
// Usage: node scripts/update-anti-ai-craft.mjs --revision <40-hex> [--source <git url or path>]
//        node scripts/update-anti-ai-craft.mjs --check [--revision <40-hex>] [--source <git url or path>]
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const LIMITS = { maxTotalBytes: 64 * 1024 * 1024, maxFiles: 2000, maxFileBytes: 16 * 1024 * 1024 };
const SKILLS = ['anti-ai-audit', 'anti-ai-code', 'anti-ai-design', 'anti-ai-design-flow', 'anti-ai-remediate', 'anti-ai-security'];
// Catalog research tooling is development material; only the summary that ATTRIBUTIONS.md cites is kept.
const EXCLUDED = ['skills/anti-ai-design/references/visual-library/research/'];
const KEPT = ['skills/anti-ai-design/references/visual-library/research/superseded-link-only-summary.jsonl'];
const MEDIA = { '.md': 'text/markdown', '.yaml': 'text/yaml', '.yml': 'text/yaml', '.json': 'application/json', '.jsonl': 'application/x-ndjson',
  '.txt': 'text/plain', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' };

const target = path.resolve('plugin', 'anti-ai-craft');
const pinFile = path.resolve('src', 'craft-pin.ts');
const check = process.argv.includes('--check');
const option = name => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };

async function lstatExpected(fullPath, label, kind) {
  let st;
  try {
    st = await lstat(fullPath);
  } catch (error) {
    return { error: `${label}: missing or inaccessible (${error.code ?? error.message})` };
  }
  if (st.isSymbolicLink()) return { error: `${label}: symbolic link is not allowed` };
  if (kind === 'dir' && !st.isDirectory()) return { error: `${label}: not a directory` };
  if (kind === 'file' && !st.isFile()) return { error: `${label}: not a regular file` };
  return { stat: st };
}

const manifestPath = path.join(target, 'manifest.json');
const skillsPath = path.join(target, 'skills');
const earlyRootCheck = check ? await lstatExpected(target, 'plugin/anti-ai-craft', 'dir') : undefined;
const earlyManifestCheck = check && !earlyRootCheck?.error
  ? await lstatExpected(manifestPath, 'plugin/anti-ai-craft/manifest.json', 'file')
  : undefined;
const earlySkillsCheck = check && !earlyRootCheck?.error
  ? await lstatExpected(skillsPath, 'plugin/anti-ai-craft/skills', 'dir')
  : undefined;

let revision = option('--revision');
let aborted = false;
if (check && !revision) {
  if (earlyRootCheck?.error || earlyManifestCheck?.error) {
    for (const difference of [earlyRootCheck?.error, earlyManifestCheck?.error, earlySkillsCheck?.error].filter(Boolean)) {
      console.error(difference);
    }
    process.exitCode = 1;
    aborted = true;
  } else {
    revision = JSON.parse(await readFile(manifestPath, 'utf8')).revision;
  }
}
const source = option('--source') ?? 'https://github.com/Zythenth/anti-ai-craft.git';
if (!aborted) {
  if (!/^[a-f0-9]{40}$/.test(revision ?? '')) throw new Error('Pass --revision with a full 40-character commit hash');

  const work = await mkdtemp(path.join(os.tmpdir(), 'anti-ai-craft-'));
  // No hooks, no symlinks and no checkout of the default branch: only the pinned tree is read.
  const git = (...args) => execFileSync('git', ['-c', 'core.hooksPath=', '-c', 'core.symlinks=false', '-c', 'protocol.file.allow=always', ...args],
    { cwd: work, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  try {
    git('init', '--quiet');
    git('fetch', '--quiet', '--depth', '1', '--no-tags', source, revision);
    if (git('rev-parse', 'FETCH_HEAD').trim() !== revision) throw new Error('Fetched revision does not match the requested hash');
    const version = JSON.parse(git('show', `${revision}:plugins/anti-ai-craft/.codex-plugin/plugin.json`)).version;
    const entries = git('ls-tree', '-r', '-z', '--long', revision, 'plugins/anti-ai-craft/skills/').split('\0').filter(Boolean);
    const files = [];
    for (const entry of entries) {
      const [meta, name] = entry.split('\t');
      const [mode, type] = meta.split(/\s+/);
      if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) throw new Error('Unsupported tree entry: ' + name);
      const relative = name.slice('plugins/anti-ai-craft/'.length);
      if (EXCLUDED.some(prefix => relative.startsWith(prefix)) && !KEPT.includes(relative)) continue;
      if (!/^skills\/[a-z0-9-]+\/[^\\:]+$/.test(relative) || relative.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe path: ' + relative);
      files.push(relative);
    }
    if (files.length > LIMITS.maxFiles) throw new Error('Too many files in the snapshot');
    const missing = SKILLS.filter(skill => !files.includes(`skills/${skill}/SKILL.md`));
    if (missing.length) throw new Error('Missing skills: ' + missing.join(', '));
    // Blobs are read as exact bytes, so no checkout filter or line-ending conversion can alter them.
    const staged = path.join(work, 'tree');
    const manifestFiles = [];
    let total = 0;
    for (const relative of files.sort()) {
      const bytes = execFileSync('git', ['cat-file', 'blob', `${revision}:plugins/anti-ai-craft/${relative}`], { cwd: work, maxBuffer: LIMITS.maxFileBytes + 1, windowsHide: true });
      if (bytes.length > LIMITS.maxFileBytes) throw new Error('File exceeds the per-resource limit: ' + relative);
      total += bytes.length;
      const file = path.join(staged, ...relative.split('/'));
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, bytes, { flag: 'wx' });
      manifestFiles.push({ path: relative, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
        mediaType: MEDIA[path.extname(relative).toLowerCase()] ?? 'application/octet-stream' });
    }
    if (total > LIMITS.maxTotalBytes) throw new Error('Snapshot exceeds the installed size limit');
    const manifest = { schemaVersion: 1, origin: source.replace(/\.git$/, ''), revision, version, skills: SKILLS, files: manifestFiles };
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    const manifestDigest = createHash('sha256').update(manifestBytes).digest('hex');
    if (check) {
      const differences = [];
      const rootCheck = await lstatExpected(target, 'plugin/anti-ai-craft', 'dir');
      if (rootCheck.error) {
        differences.push(rootCheck.error);
      } else {
        const manifestCheck = await lstatExpected(manifestPath, 'plugin/anti-ai-craft/manifest.json', 'file');
        if (manifestCheck.error) {
          differences.push(manifestCheck.error);
        } else {
          let committedManifestBytes;
          try {
            committedManifestBytes = await readFile(manifestPath);
          } catch (error) {
            differences.push(`committed manifest.json could not be read (${error.code ?? error.message})`);
          }
          if (committedManifestBytes && !committedManifestBytes.equals(manifestBytes)) {
            differences.push('committed plugin/anti-ai-craft/manifest.json bytes differ from generated manifest');
          }
        }
      }
      let pinText;
      try {
        pinText = await readFile(pinFile, 'utf8');
      } catch (error) {
        differences.push(`src/craft-pin.ts could not be read (${error.code ?? error.message})`);
      }
      if (pinText !== undefined) {
        const match = /export\s+const\s+BUNDLED_CRAFT_MANIFEST_SHA256\s*=\s*['"]([a-f0-9]{64})['"]\s*;/.exec(pinText);
        if (!match) {
          differences.push('src/craft-pin.ts does not contain a valid BUNDLED_CRAFT_MANIFEST_SHA256 64-hex digest');
        } else if (match[1] !== manifestDigest) {
          differences.push(`src/craft-pin.ts BUNDLED_CRAFT_MANIFEST_SHA256 (${match[1]}) differs from generated manifest digest (${manifestDigest})`);
        }
      }
      if (!rootCheck.error) {
        const skillsCheck = await lstatExpected(skillsPath, 'plugin/anti-ai-craft/skills', 'dir');
        if (skillsCheck.error) {
          differences.push(skillsCheck.error);
        } else {
          try {
            const diskEntries = await readdir(skillsPath, { recursive: true, withFileTypes: true });
            const diskFiles = new Set();
            for (const item of diskEntries) {
              const relPath = path.relative(target, path.join(item.parentPath ?? item.path, item.name)).replaceAll('\\', '/');
              if (item.isSymbolicLink()) {
                differences.push(`symbolic link under plugin/anti-ai-craft: ${relPath}`);
              } else if (item.isFile()) {
                diskFiles.add(relPath);
              } else if (!item.isDirectory()) {
                differences.push(`non-regular entry under plugin/anti-ai-craft: ${relPath}`);
              }
            }
            const expectedFiles = new Set(manifestFiles.map(file => file.path));
            const missing = [...expectedFiles].filter(file => !diskFiles.has(file)).sort();
            const extra = [...diskFiles].filter(file => !expectedFiles.has(file)).sort();
            if (missing.length) differences.push(`missing files under plugin/anti-ai-craft/skills: ${missing.join(', ')}`);
            if (extra.length) differences.push(`extra files under plugin/anti-ai-craft/skills: ${extra.join(', ')}`);
            for (const entry of manifestFiles) {
              const diskPath = path.join(target, ...entry.path.split('/'));
              const entryCheck = await lstatExpected(diskPath, entry.path, 'file');
              if (entryCheck.error) {
                differences.push(entryCheck.error);
                continue;
              }
              if (entryCheck.stat.size !== entry.bytes) {
                differences.push(`${entry.path}: size differs (committed ${entryCheck.stat.size}, expected ${entry.bytes})`);
                continue;
              }
              let diskBytes;
              try {
                diskBytes = await readFile(diskPath);
              } catch (error) {
                differences.push(`${entry.path}: could not be read (${error.code ?? error.message})`);
                continue;
              }
              const diskSha256 = createHash('sha256').update(diskBytes).digest('hex');
              if (diskSha256 !== entry.sha256) {
                differences.push(`${entry.path}: sha256 differs (committed ${diskSha256}, expected ${entry.sha256})`);
              }
            }
          } catch (error) {
            differences.push(`plugin/anti-ai-craft/skills could not be read (${error.code ?? error.message})`);
          }
        }
      }
      if (differences.length) {
        for (const difference of differences) console.error(difference);
        process.exitCode = 1;
      } else {
        console.log(`Anti-AI Craft ${version} at ${revision} reproduces the committed snapshot (${manifestFiles.length} files, manifest ${manifestDigest}).`);
      }
    } else {
      await rm(target, { recursive: true, force: true });
      await mkdir(target, { recursive: true });
      await cp(path.join(staged, 'skills'), skillsPath, { recursive: true });
      await writeFile(manifestPath, manifestBytes);
      const listed = (await readdir(skillsPath, { recursive: true, withFileTypes: true })).filter(item => item.isFile()).length;
      if (listed !== manifestFiles.length) throw new Error('Copied tree differs from the manifest');
      const writtenDigest = createHash('sha256').update(await readFile(manifestPath)).digest('hex');
      await writeFile(pinFile, `// Rewritten by scripts/update-anti-ai-craft.mjs when the pinned Anti-AI Craft snapshot changes.\nexport const BUNDLED_CRAFT_MANIFEST_SHA256 = '${writtenDigest}';\n`, 'utf8');
      console.log(`Anti-AI Craft ${version} at ${revision}: ${manifestFiles.length} files, ${total} bytes, manifest ${writtenDigest}.`);
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
