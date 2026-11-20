export type CapabilityObservation = 'observed' | 'absent' | 'unknown';
export type CapabilitySource = 'help' | 'adapter' | 'recorded' | 'none';

export const CAPABILITY_OBSERVATIONS = ['observed', 'absent', 'unknown'] as const satisfies readonly CapabilityObservation[];
export const CAPABILITY_SOURCES = ['help', 'adapter', 'recorded', 'none'] as const satisfies readonly CapabilitySource[];

export interface CapabilityEntry {
  status: CapabilityObservation;
  source: CapabilitySource;
  detail: string;
}

export const REGISTRY_CAPABILITIES = [
  'read', 'write', 'sandbox', 'network', 'skills', 'resources',
  'structuredOutput', 'cancel', 'resume', 'observableUsage',
  'modelList', 'modelSelection', 'effort', 'sessionsList',
] as const;

export type RegistryCapability = typeof REGISTRY_CAPABILITIES[number];

export interface EditToolRestriction {
  tool: string;
  restriction: string;
  status: CapabilityObservation;
  source: 'recorded';
  verifiedVersions: string[];
  bridgeMitigation: string;
}

export interface CliCapabilityRecord {
  cli: 'agy';
  adapterId: string;
  adapterVersion: string;
  installed: boolean;
  version: string | null;
  platform: NodeJS.Platform;
  arch: string;
  queriedWith: string[];
  capabilities: Record<RegistryCapability, CapabilityEntry>;
  effectiveModel: CapabilityEntry;
  editToolRestrictions: EditToolRestriction[];
  error?: string;
}

export const EFFECTIVE_MODEL_ABSENT_VERSIONS: readonly string[] = ['1.5.13'];
export const USAGE_OBSERVED_VERSIONS: readonly string[] = ['1.5.13'];

function entry(status: CapabilityObservation, source: CapabilitySource, detail: string): CapabilityEntry {
  return { status, source, detail };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasOption(help: string, flag: string): boolean {
  return new RegExp('(^|[\\s,\\[(|])' + escapeRegExp(flag) + '(?=$|[\\s,=\\])|])', 'm').test(help);
}

function hasSubcommand(help: string, name: string): boolean {
  return new RegExp('^\\s*' + escapeRegExp(name) + '(?=\\s|$)', 'm').test(help);
}

function recordedEditToolRestrictions(): EditToolRestriction[] {
  return [{
    tool: 'edit_file',
    restriction: 'Target text must match exactly, including line endings; on CRLF files searches written with LF fail with "target content not found".',
    status: 'observed',
    source: 'recorded',
    verifiedVersions: [],
    bridgeMitigation: 'Pure-CRLF text files up to 16 MiB are handed to the executor as LF and restored to their original bytes before preview, tests and integration.',
  }];
}

function unqueriedCapabilities(): Record<RegistryCapability, CapabilityEntry> {
  return Object.fromEntries(
    REGISTRY_CAPABILITIES.map(key => [key, entry('unknown', 'none', 'CLI could not be queried')]),
  ) as Record<RegistryCapability, CapabilityEntry>;
}

function installedCapabilities(help: string, version: string | null): Record<RegistryCapability, CapabilityEntry> {
  const helpFlag = (flag: string, detail = flag): CapabilityEntry =>
    entry(hasOption(help, flag) ? 'observed' : 'absent', 'help', detail);
  const hasStreamJson = help.includes('stream-json');
  const hasOutputFormat = hasOption(help, '--output-format');
  const hasSandbox = hasOption(help, '--sandbox');
  const hasReadMode = help.split(/\r?\n/).some(line => hasOption(line, '--mode') && /\bplan\b/.test(line));
  const hasObservableUsage = hasStreamJson && version !== null && USAGE_OBSERVED_VERSIONS.includes(version);

  return {
    read: entry(hasReadMode ? 'observed' : 'absent', 'help', '--mode and plan'),
    write: entry(
      hasSandbox && hasStreamJson && hasOutputFormat ? 'observed' : 'absent',
      'adapter',
      'usable through this adapter only when --sandbox and stream-json output are both advertised; the adapter writes only inside an isolated copy under agy --sandbox',
    ),
    sandbox: helpFlag('--sandbox'),
    network: entry('unknown', 'none', 'the CLI help does not declare it'),
    skills: entry(
      hasOption(help, '--add-dir') ? 'observed' : 'absent',
      'adapter',
      'this adapter delivers skills by adding their directories with --add-dir',
    ),
    resources: entry('unknown', 'none', 'the CLI help does not declare it'),
    structuredOutput: helpFlag('--json-schema'),
    cancel: entry('unknown', 'none', 'the CLI help does not declare it; the bridge terminates the process for cancel, which is not native CLI cancel'),
    resume: helpFlag('--conversation'),
    observableUsage: hasObservableUsage
      ? entry('observed', 'adapter', 'the stream-json result event of this version carries usage counters')
      : entry('unknown', 'adapter', 'not checked for this version'),
    modelList: entry(hasSubcommand(help, 'models') ? 'observed' : 'absent', 'help', 'models'),
    modelSelection: helpFlag('--model'),
    effort: helpFlag('--effort'),
    sessionsList: entry('unknown', 'none', 'the CLI help does not declare it'),
  };
}

function effectiveModelEntry(installed: boolean, version: string | null): CapabilityEntry {
  if (!installed) {
    return entry('unknown', 'none', 'CLI could not be queried');
  }
  if (version !== null && EFFECTIVE_MODEL_ABSENT_VERSIONS.includes(version)) {
    return entry(
      'absent',
      'adapter',
      "In this version the stream-json init event repeats the --model value only when one is passed and has no model field otherwise; the result event has none. No event reports the model actually resolved; an init model value is an echo of the request, not proof of the model used.",
    );
  }
  return entry('unknown', 'adapter', 'not checked for this version');
}

export function buildAgyCapabilityRecord(input: {
  installed: boolean;
  version?: string;
  helpText: string;
  error?: string;
  platform: NodeJS.Platform;
  arch: string;
  adapterId: string;
  adapterVersion: string;
}): CliCapabilityRecord {
  const version = input.installed ? (input.version ?? null) : null;
  return {
    cli: 'agy',
    adapterId: input.adapterId,
    adapterVersion: input.adapterVersion,
    installed: input.installed,
    version,
    platform: input.platform,
    arch: input.arch,
    queriedWith: ['--version', '--help'],
    capabilities: input.installed ? installedCapabilities(input.helpText, version) : unqueriedCapabilities(),
    effectiveModel: effectiveModelEntry(input.installed, version),
    editToolRestrictions: recordedEditToolRestrictions(),
    ...(input.error !== undefined ? { error: input.error } : {}),
  };
}
