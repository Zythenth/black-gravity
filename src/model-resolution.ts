import { EFFECTIVE_MODEL_ABSENT_VERSIONS } from './capability-registry.js';
import type { Effort } from './roles.js';

export const MODEL_ALIASES = ['flash', 'argon'] as const;
export type ModelAlias = typeof MODEL_ALIASES[number];

export const RESOLUTION_STATUSES = [
  'resolved',
  'cli-absent',
  'list-unavailable',
  'alias-not-listed',
  'effort-unavailable',
  'ambiguous',
] as const;
export type ResolutionStatus = typeof RESOLUTION_STATUSES[number];

export const IDENTITY_STATUSES = ['not-observable', 'unknown'] as const;
export type IdentityStatus = typeof IDENTITY_STATUSES[number];

type SuffixEffort = Exclude<Effort, 'max'>;

const SUFFIX_EFFORT_ORDER: readonly SuffixEffort[] = ['low', 'medium', 'high', 'xhigh'];
const MODEL_ID_PATTERN = /^gemini-(\d+(?:\.\d+)*)-(flash|argon)-(low|medium|high|xhigh)$/;
const MAX_OBSERVED_MODEL_CHARS = 256;

export interface ModelIdentityReport {
  model: IdentityStatus;
  effort: IdentityStatus;
  detail: string;
}

export interface ModelResolution {
  alias: ModelAlias;
  requestedEffort: Effort;
  status: ResolutionStatus;
  modelId: string | null;
  candidates: string[];
  availableEfforts: Effort[];
  effortEncoding: 'model-id-suffix';
  detail: string;
  identity: ModelIdentityReport;
  errorCode?: string;
}

export interface ResolveModelAliasInput {
  alias: ModelAlias;
  effort: Effort;
  cli: { installed: boolean; version: string | null };
  models: ReadonlyArray<{ id: string; name: string }> | null;
  listError?: { code: string };
}

export interface InitModelClassification {
  observed: { model: string | null; status: 'observed' | 'not-observable' };
  echo: boolean;
  mismatch: boolean;
}

export type ModelProofVerdict = 'not-observable' | 'mismatch' | 'no-request';

export interface ModelProofEvaluation {
  verdict: ModelProofVerdict;
  detail: string;
}

function buildIdentity(cli: { installed: boolean; version: string | null }): ModelIdentityReport {
  if (cli.installed && cli.version !== null && EFFECTIVE_MODEL_ABSENT_VERSIONS.includes(cli.version)) {
    return {
      model: 'not-observable',
      effort: 'not-observable',
      detail: 'agy does not report the effective model or effort in this version; stream-json init.model only repeats the requested --model value and carries no effort field.',
    };
  }
  return {
    model: 'unknown',
    effort: 'unknown',
    detail: 'Effective model and effort observability is not verified for this CLI version; agy does not report the effective model or effort in checked versions, where stream-json init.model only repeats the requested --model value.',
  };
}

function aliasNotListedDetail(alias: ModelAlias): string {
  if (alias === 'argon') {
    return 'User-declared access to Argon is preserved, but this CLI does not list any gemini-<n>-argon-<effort> ID in agy models; no model ID was substituted or invented.';
  }
  return 'This CLI does not list any gemini-<n>-flash-<effort> ID in agy models; no model ID was substituted or invented.';
}

/**
 * Purely resolves a `flash` or `argon` alias and requested effort against the exact IDs listed by `agy models`.
 * Never substitutes another model or downgrades the requested effort.
 */
export function resolveModelAlias(input: ResolveModelAliasInput): ModelResolution {
  const base = {
    alias: input.alias,
    requestedEffort: input.effort,
    effortEncoding: 'model-id-suffix' as const,
    identity: buildIdentity(input.cli),
  };

  if (!input.cli.installed) {
    return {
      ...base,
      status: 'cli-absent',
      modelId: null,
      candidates: [],
      availableEfforts: [],
      detail: 'Antigravity CLI (agy) is not installed or could not be queried; cannot resolve model alias.',
    };
  }

  if (input.models === null) {
    return {
      ...base,
      status: 'list-unavailable',
      modelId: null,
      candidates: [],
      availableEfforts: [],
      detail: input.listError?.code
        ? `Could not list models from agy (${input.listError.code}); cannot resolve model alias.`
        : 'Could not list models from agy; cannot resolve model alias.',
      ...(input.listError?.code ? { errorCode: input.listError.code } : {}),
    };
  }

  const candidateIds = new Set<string>();
  const families = new Map<string, Map<SuffixEffort, string>>();

  for (const model of input.models) {
    const match = MODEL_ID_PATTERN.exec(model.id);
    if (!match) continue;
    const version = match[1]!;
    const alias = match[2] as ModelAlias;
    const effort = match[3] as SuffixEffort;
    if (alias !== input.alias) continue;
    candidateIds.add(model.id);
    let efforts = families.get(version);
    if (!efforts) {
      efforts = new Map<SuffixEffort, string>();
      families.set(version, efforts);
    }
    if (!efforts.has(effort)) {
      efforts.set(effort, model.id);
    }
  }

  const candidates = Array.from(candidateIds).sort();

  if (families.size === 0) {
    return {
      ...base,
      status: 'alias-not-listed',
      modelId: null,
      candidates: [],
      availableEfforts: [],
      detail: aliasNotListedDetail(input.alias),
    };
  }

  if (families.size > 1) {
    const versions = Array.from(families.keys()).sort();
    return {
      ...base,
      status: 'ambiguous',
      modelId: null,
      candidates,
      availableEfforts: [],
      detail: `Multiple ${input.alias} model versions are listed (${versions.join(', ')}); refusing to select one automatically.`,
    };
  }

  const [version, efforts] = Array.from(families.entries())[0]!;
  const availableEfforts = SUFFIX_EFFORT_ORDER.filter(effort => efforts.has(effort));
  const resolvedId = input.effort === 'max' ? undefined : efforts.get(input.effort);

  if (resolvedId === undefined) {
    return {
      ...base,
      status: 'effort-unavailable',
      modelId: null,
      candidates,
      availableEfforts,
      detail: `Requested effort "${input.effort}" is not available for ${input.alias} (version ${version}); available efforts: ${availableEfforts.join(', ')}. Refusing to downgrade effort or substitute another model.`,
    };
  }

  return {
    ...base,
    status: 'resolved',
    modelId: resolvedId,
    candidates,
    availableEfforts,
    detail: `Resolved ${input.alias} (${input.effort}) to listed model ID ${resolvedId}.`,
  };
}

/**
 * Classifies a stream `init.model` field against the requested model, treating echoes of the request as not-observable.
 */
export function classifyInitModel(requested: string | null, initModel: unknown): InitModelClassification {
  if (typeof initModel !== 'string') {
    return { observed: { model: null, status: 'not-observable' }, echo: false, mismatch: false };
  }
  const trimmed = initModel.trim();
  if (!trimmed) {
    return { observed: { model: null, status: 'not-observable' }, echo: false, mismatch: false };
  }
  if (requested !== null && trimmed === requested) {
    return { observed: { model: null, status: 'not-observable' }, echo: true, mismatch: false };
  }
  return {
    observed: { model: trimmed.slice(0, MAX_OBSERVED_MODEL_CHARS), status: 'observed' },
    echo: false,
    mismatch: requested !== null,
  };
}

/**
 * Evaluates whether persisted execution identity disproves or cannot observe the requested model.
 * An observed value equal to the requested model cannot be distinguished from an echo and never counts as proof.
 */
export function evaluateModelProof(execution: {
  requested: { model: string | null };
  observed: { model: string | null; status: 'observed' | 'not-observable' };
}): ModelProofEvaluation {
  if (execution.observed.status === 'not-observable' || execution.observed.model === null) {
    return {
      verdict: 'not-observable',
      detail: 'Effective model identity is not observable; model proof is neither established nor failed.',
    };
  }
  if (execution.requested.model === null) {
    return {
      verdict: 'no-request',
      detail: `Observed model "${execution.observed.model}" was reported when no specific model was requested.`,
    };
  }
  if (execution.observed.model === execution.requested.model) {
    return {
      verdict: 'not-observable',
      detail: `Observed value "${execution.observed.model}" matches the requested model, cannot be distinguished from an echo, and is not proof.`,
    };
  }
  return {
    verdict: 'mismatch',
    detail: `Model proof failed: requested "${execution.requested.model}", but observed "${execution.observed.model}".`,
  };
}
