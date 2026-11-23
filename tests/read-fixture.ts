import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { TaskRecord } from '../src/types.js';

export interface ReadFixture {
  readonly relativePath: string;
  readonly marker: string;
  readonly prompt: string;
}

export function createReadFixture(repoDir: string): ReadFixture {
  const relativePath = 'notes/read-fixture.md';
  const marker = 'MARKER_READ_FIXTURE_7Q2';
  mkdirSync(path.join(repoDir, 'notes'), { recursive: true });
  mkdirSync(path.join(repoDir, 'src'), { recursive: true });
  writeFileSync(
    path.join(repoDir, relativePath),
    `Read fixture header\n${marker}\nRead fixture footer\n`,
    'utf8',
  );
  writeFileSync(path.join(repoDir, 'src', 'read-fixture.txt'), 'secondary fixture file\n', 'utf8');
  execFileSync('git', ['add', 'notes/read-fixture.md', 'src/read-fixture.txt'], { cwd: repoDir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'add read fixture'], { cwd: repoDir, stdio: 'ignore' });
  return {
    relativePath,
    marker,
    prompt: `READ:${relativePath}\nRead the file and reply with the marker line.`,
  };
}

export function assertReadFixtureOutcome(record: TaskRecord, repoDir: string, fixture: ReadFixture): void {
  assert.equal(record.status, 'completed');
  assert.equal(record.mode, 'read-only');
  const resultJson = record.result !== undefined ? JSON.stringify(record.result) : '';
  const finalMessage = [...(record.messages ?? [])].reverse().find(message => message.kind === 'final')?.text ?? '';
  assert.ok(
    resultJson.includes(fixture.marker) || finalMessage.includes(fixture.marker),
    `Expected final response to contain ${fixture.marker}`,
  );
  const gitStatus = execFileSync('git', ['status', '--porcelain'], { cwd: repoDir, encoding: 'utf8' });
  assert.equal(gitStatus.trim(), '');
}
