import { accessSync, constants, statSync } from 'node:fs';
import path from 'node:path';
import { isFullWindowsPath, type Config } from './config.js';
import type { ExecutionAdapter } from './execution-contract.js';
import { OpenCodeExecutionAdapter } from './opencode-execution-adapter.js';

export interface OpenCodeRegistration {
  provider: 'opencode';
  adapter?: ExecutionAdapter;
  unavailableReason?: string;
}

function readPathEnv(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | undefined {
  if (platform === 'win32') {
    const key = Object.keys(env).find(name => name.toUpperCase() === 'PATH');
    return key ? env[key] : undefined;
  }
  return Object.hasOwn(env, 'PATH') ? env.PATH : undefined;
}

function findOpenCodeInPath(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | undefined {
  const pathValue = readPathEnv(env, platform);
  if (!pathValue) return undefined;
  const binaryName = platform === 'win32' ? 'opencode.exe' : 'opencode';
  const delimiter = platform === 'win32' ? ';' : ':';
  for (const entry of pathValue.split(delimiter)) {
    if (!entry || entry.includes('\0')) continue;
    const isAbsolute = platform === 'win32' ? isFullWindowsPath(entry) : path.posix.isAbsolute(entry);
    if (!isAbsolute) continue;
    const candidate = platform === 'win32' ? path.win32.join(entry, binaryName) : path.posix.join(entry, binaryName);
    try {
      const stat = statSync(candidate);
      if (!stat.isFile()) continue;
      if (platform !== 'win32') accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Continue checking remaining PATH entries.
    }
  }
  return undefined;
}

export function resolveOpenCodeRegistration(
  config: Pick<Config, 'openCodePath' | 'openCodePathInvalid' | 'allowedEnvVars'>,
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): OpenCodeRegistration {
  if (config.openCodePathInvalid) {
    return {
      provider: 'opencode',
      unavailableReason: 'INVALID_CONFIGURATION: OPENCODE_PATH is invalid',
    };
  }
  const executable = config.openCodePath ?? findOpenCodeInPath(env, platform);
  if (!executable) {
    return {
      provider: 'opencode',
      unavailableReason: 'OPENCODE_UNAVAILABLE: OpenCode executable not found; set OPENCODE_PATH',
    };
  }
  return {
    provider: 'opencode',
    adapter: new OpenCodeExecutionAdapter({
      executable,
      allowedEnvVars: config.allowedEnvVars,
    }),
  };
}
