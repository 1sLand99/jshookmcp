/**
 * Rejected-region history for search tuning (RRSI mechanisms #3 and #4).
 *
 * Two jobs, both about negative information:
 *   - Pruner input: which candidates the critic already rejected, so the same
 *     region is not re-evaluated at full cost.
 *   - Exploration bias: which parameter keys correlate with rejection, so the
 *     sampler can steer away from them instead of resampling a dead corner.
 *
 * Records persist as JSONL under `artifacts/search-tuning/`, which is covered
 * by `.gitignore` — tuning history is machine-local, not repository state.
 */

import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve as pathResolve } from 'node:path';

import {
  loadSearchSpace,
  type TunableParamDef,
  type TunableParamKey,
  type TrialParams,
} from './search-space';

// ── public types ──

export interface RejectionEntry {
  readonly trialId: string;
  readonly params: TrialParams;
  readonly evolveScore: number;
  readonly holdoutScore: number;
  readonly reasons: readonly string[];
  /** ISO-8601 timestamp; the caller supplies it so this module stays pure-clock. */
  readonly timestamp: string;
}

export interface DuplicateRegionVerdict {
  readonly duplicate: boolean;
  /** Rejection this candidate collides with, or null when the region is new. */
  readonly matched: RejectionEntry | null;
  /** Normalized Euclidean distance to the nearest rejected candidate. */
  readonly distance: number;
  /** Tolerance the distance was compared against. */
  readonly tolerance: number;
  /** Keys whose normalized delta dominated the distance (top 3). */
  readonly dominantKeys: readonly string[];
}

export interface ParamRejectionStat {
  readonly key: string;
  /** Records that specify this parameter. */
  readonly occurrences: number;
  /** Sample standard deviation of the parameter's value across those records. */
  readonly stdDev: number;
  /** Midpoint of the rejected range for this parameter. */
  readonly mean: number;
  readonly min: number;
  readonly max: number;
}

export interface HistorySummary {
  readonly totalRejections: number;
  /**
   * Parameter keys sorted by how strongly their values cluster (low stdDev
   * against a wide domain), most-clustered first — the strongest candidates
   * for regions the sampler should avoid.
   */
  readonly rankedKeys: readonly ParamRejectionStat[];
  /** Distinct rejection reasons with counts, most frequent first. */
  readonly reasonCounts: ReadonlyMap<string, number>;
  /** Rejection timestamps, for callers that want to decay old entries. */
  readonly newestTimestamp: string | null;
  readonly oldestTimestamp: string | null;
}

export interface DuplicateRegionOptions {
  /**
   * Tolerance as a multiple of each parameter's `step`. Defaults to
   * {@link DEFAULT_TOLERANCE_STEPS}: a candidate within two steps of a rejected
   * point on every axis counts as the same region.
   */
  readonly tolerance?: number;
  /** Parameter definitions used to normalize each axis. */
  readonly defs?: readonly TunableParamDef[];
}

// ── defaults ──

/** Default history path, relative to the repository root. */
export const DEFAULT_HISTORY_PATH = 'artifacts/search-tuning/regression-history.jsonl';

/** Steps-per-axis radius that still counts as the same rejected region. */
export const DEFAULT_TOLERANCE_STEPS = 2;

// ── public API ──

/**
 * Append one rejection record to the JSONL history, creating parent
 * directories as needed. Failures propagate — the caller decides whether a lost
 * record is fatal.
 */
export async function appendRejection(
  entry: RejectionEntry,
  path: string = DEFAULT_HISTORY_PATH,
): Promise<void> {
  const target = pathResolve(path);
  await mkdir(dirname(target), { recursive: true });
  await appendFile(target, JSON.stringify(entry) + '\n', 'utf-8');
}

/**
 * Read every rejection record from the JSONL history. A missing file reads as
 * an empty history; malformed lines are skipped rather than aborting the load,
 * because a truncated final line is a normal outcome of a killed process.
 */
export async function loadHistory(
  path: string = DEFAULT_HISTORY_PATH,
): Promise<readonly RejectionEntry[]> {
  const target = pathResolve(path);
  let raw: string;
  try {
    raw = await readFile(target, 'utf-8');
  } catch (error) {
    // Only ENOENT is an expected condition here (first run, cleaned artifacts).
    if (isEnoent(error)) return [];
    throw error;
  }

  const entries: RejectionEntry[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    try {
      entries.push(JSON.parse(trimmed) as RejectionEntry);
    } catch {
      // Partial write or foreign line — skip it and keep the rest of history.
      continue;
    }
  }
  return entries;
}

/**
 * Decide whether `params` falls inside an already-rejected region.
 *
 * Distance is the Euclidean norm over axes normalized by each parameter's step,
 * so a 0.02-step float and a 1-step int contribute comparably. Parameters
 * absent from either vector are skipped: a candidate that leaves an axis at its
 * default is not evidence about that axis.
 */
export function isDuplicateRegion(
  params: TrialParams,
  history: readonly RejectionEntry[],
  tolerance: number | DuplicateRegionOptions = DEFAULT_TOLERANCE_STEPS,
): DuplicateRegionVerdict {
  const options: DuplicateRegionOptions = typeof tolerance === 'number' ? { tolerance } : tolerance;
  const radius = options.tolerance ?? DEFAULT_TOLERANCE_STEPS;
  const defs = options.defs ?? [];
  const stepByKey = new Map<string, number>(defs.map((d) => [d.key, d.step]));

  let nearest: RejectionEntry | null = null;
  let nearestDistance = Number.POSITIVE_INFINITY;
  let nearestDominant: readonly string[] = [];

  for (const entry of history) {
    const deltas = normalizedDeltas(params, entry.params, stepByKey);
    if (deltas.size === 0) continue;
    // RMS (not the raw Euclidean norm) so `tolerance` reads as a per-axis step
    // radius: 2 means "within two steps on every axis in the worst case",
    // independent of how many parameters a candidate happens to set.
    const distance = rmsDistance([...deltas.values()]);
    if (distance < nearestDistance) {
      nearestDistance = distance;
      nearest = entry;
      nearestDominant = [...deltas.entries()]
        .toSorted((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
        .slice(0, 3)
        .map(([key]) => key);
    }
  }

  const duplicate = nearest !== null && nearestDistance <= radius;
  return {
    duplicate,
    matched: duplicate ? nearest : null,
    distance: nearestDistance,
    tolerance: radius,
    dominantKeys: duplicate ? nearestDominant : [],
  };
}

/**
 * Summarize what the rejection record says about the parameter space: which
 * keys cluster tightly (strong avoid-signal) and which rejection reasons
 * recur.
 */
export function summarizeHistory(history: readonly RejectionEntry[]): HistorySummary {
  const byKey = new Map<string, number[]>();
  const reasonCounts = new Map<string, number>();
  let newest: string | null = null;
  let oldest: string | null = null;

  for (const entry of history) {
    for (const [key, value] of Object.entries(entry.params)) {
      if (value === undefined) continue;
      const bucket = byKey.get(key);
      if (bucket) bucket.push(value);
      else byKey.set(key, [value]);
    }
    for (const reason of entry.reasons) {
      reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
    }
    if (newest === null || entry.timestamp > newest) newest = entry.timestamp;
    if (oldest === null || entry.timestamp < oldest) oldest = entry.timestamp;
  }

  const rankedKeys: ParamRejectionStat[] = [];
  for (const [key, values] of byKey) {
    const mean = values.reduce((s, v) => s + v, 0) / values.length;
    // Sample variance (n-1): a single observation carries no spread signal.
    const variance =
      values.length > 1 ? values.reduce((s, v) => s + (v - mean) ** 2, 0) / (values.length - 1) : 0;
    rankedKeys.push({
      key,
      occurrences: values.length,
      stdDev: Math.sqrt(variance),
      mean,
      min: Math.min(...values),
      max: Math.max(...values),
    });
  }
  rankedKeys.sort((a, b) => {
    // Cluster strength: low spread relative to observation count, most first.
    const aScore = a.stdDev / Math.sqrt(a.occurrences);
    const bScore = b.stdDev / Math.sqrt(b.occurrences);
    return aScore - bScore;
  });

  const sortedReasons = new Map([...reasonCounts.entries()].toSorted((a, b) => b[1] - a[1]));

  return {
    totalRejections: history.length,
    rankedKeys,
    reasonCounts: sortedReasons,
    newestTimestamp: newest,
    oldestTimestamp: oldest,
  };
}

/** Extract rejection reasons from a critic verdict for entry construction. */
export function buildRejectionEntry(
  trialId: string,
  params: TrialParams,
  evolveScore: number,
  holdoutScore: number,
  reasons: readonly string[],
  timestamp: string = new Date().toISOString(),
): RejectionEntry {
  return { trialId, params, evolveScore, holdoutScore, reasons, timestamp };
}

// ── internal helpers ──

function normalizedDeltas(
  candidate: TrialParams,
  rejected: TrialParams,
  stepByKey: ReadonlyMap<string, number>,
): Map<string, number> {
  const deltas = new Map<string, number>();
  for (const [key, candidateValue] of Object.entries(candidate)) {
    if (candidateValue === undefined) continue;
    const rejectedValue = rejected[key as TunableParamKey];
    if (rejectedValue === undefined) continue;
    const step = stepByKey.get(key) ?? 1;
    deltas.set(key, (candidateValue - rejectedValue) / step);
  }
  return deltas;
}

/**
 * Root-mean-square of the per-axis normalized deltas. Used instead of the raw
 * Euclidean norm so the tolerance is a per-axis radius rather than a value
 * that grows with the number of tuned parameters.
 */
function rmsDistance(values: readonly number[]): number {
  if (values.length === 0) return Number.POSITIVE_INFINITY;
  let sum = 0;
  for (const v of values) sum += v * v;
  return Math.sqrt(sum / values.length);
}

function isEnoent(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'ENOENT'
  );
}

/** Parameter definitions, for callers that want to pass explicit tolerance defs. */
export async function loadToleranceDefs(): Promise<readonly TunableParamDef[]> {
  return loadSearchSpace();
}
