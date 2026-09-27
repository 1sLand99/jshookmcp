/**
 * Candidate critic for search tuning (RRSI mechanism #2).
 *
 * The critic exists because a harness that only sees its evolve score will
 * happily accept benchmark-specific edits: an objective that rises on the
 * tuning cases while stalling on held-out cases is a fit to those cases, not
 * an improvement to search. `critiqueCandidate` compares the two slices and
 * rejects on three signals — generalization gap, holdout regression, and gain
 * below the noise floor.
 *
 * Pure function: metrics in, verdict out. No I/O, no clock, no randomness.
 */

import type { CaseMetrics } from './metrics';

// ── public types ──

export type CritiqueVerdict = 'accept' | 'reject';

export interface CandidateComparison {
  /** Mean objective score over the evolve slice. */
  readonly evolveScore: number;
  /** Mean objective score over the holdout slice. */
  readonly holdoutScore: number;
  /** `evolveScore - holdoutScore`; positive means the candidate overfits evolve. */
  readonly generalizationGap: number;
  /** Holdout score of the incumbent candidate, when supplied by the caller. */
  readonly baselineScore: number | null;
  /** `holdoutScore - baselineScore`, or null when no baseline was supplied. */
  readonly holdoutDelta: number | null;
  /** `evolveScore - baselineScore`, or null when no baseline was supplied. */
  readonly evolveDelta: number | null;
  /** Binomial standard error for the holdout slice size. */
  readonly noiseFloor: number;
  /** Case count behind `evolveScore`. */
  readonly evolveCaseCount: number;
  /** Case count behind `holdoutScore`. */
  readonly holdoutCaseCount: number;
}

export interface CritiqueResult {
  readonly verdict: CritiqueVerdict;
  /** Human-readable reject causes; empty when the verdict is `accept`. */
  readonly reasons: readonly string[];
  readonly evolveScore: number;
  readonly holdoutScore: number;
  readonly generalizationGap: number;
  /** Full comparison, so callers can log why the verdict came out as it did. */
  readonly comparison: CandidateComparison;
}

export interface CriticOptions {
  /**
   * Maximum tolerated `evolveScore - holdoutScore`. Above this the candidate is
   * judged to have fit the evolve slice. Defaults to
   * {@link GENERALIZATION_GAP_THRESHOLD}.
   */
  readonly gapThreshold?: number;
  /**
   * Holdout score of the current incumbent. When supplied, the critic also
   * rejects on holdout regression and on gain below the noise floor.
   */
  readonly baselineScore?: number;
  /**
   * Override the noise floor (typically {@link estimateNoiseFloor} on the
   * holdout size). Supplied by callers that want a tighter or looser floor.
   */
  readonly noiseFloor?: number;
  /**
   * Minimum holdout gain over the baseline for the candidate to count as
   * generalizing. Defaults to the noise floor.
   */
  readonly minGeneralizationGain?: number;
  /**
   * When true, a candidate that does not beat the baseline is rejected even if
   * the gap and regression checks pass. Default false: without a baseline there
   * is nothing to compare against, so the critic only screens for overfit.
   */
  readonly requireImprovement?: boolean;
}

// ── defaults ──

/** Evolve/holdout gap above which a candidate is treated as overfit. */
export const GENERALIZATION_GAP_THRESHOLD = 0.15;

/** Worst-case hit-rate spread for the binomial noise estimate. */
const NOISE_FLOOR_WORST_CASE_P = 0.5;

// ── public API ──

/**
 * Estimate the standard error of a hit-rate measured on `nCases` cases, using
 * p = 0.5 (the maximum-variance case) and `sqrt(p(1-p)/n)`.
 *
 * This is the threshold below which a holdout delta is indistinguishable from
 * sampling noise — a 3-case holdout has a floor near 0.29, so any gain smaller
 * than that carries no evidence at all.
 */
export function estimateNoiseFloor(nCases: number): number {
  if (!Number.isFinite(nCases) || nCases <= 0) return 1;
  const p = NOISE_FLOOR_WORST_CASE_P;
  return Math.sqrt((p * (1 - p)) / nCases);
}

/**
 * Compare a candidate's evolve and holdout metrics and return a verdict.
 *
 * Rejection reasons accumulate rather than short-circuit, so a candidate that
 * both overfits and regresses reports both.
 */
export function critiqueCandidate(
  evolveMetrics: readonly CaseMetrics[],
  holdoutMetrics: readonly CaseMetrics[],
  options: CriticOptions = {},
): CritiqueResult {
  const gapThreshold = options.gapThreshold ?? GENERALIZATION_GAP_THRESHOLD;
  const holdoutCaseCount = holdoutMetrics.length;
  const noiseFloor = options.noiseFloor ?? estimateNoiseFloor(holdoutCaseCount);
  const minGain = options.minGeneralizationGain ?? noiseFloor;

  const evolveScore = meanObjectivity(evolveMetrics);
  const holdoutScore = meanObjectivity(holdoutMetrics);
  const generalizationGap = evolveScore - holdoutScore;

  const baselineScore = options.baselineScore ?? null;
  const holdoutDelta = baselineScore === null ? null : holdoutScore - baselineScore;
  const evolveDelta = baselineScore === null ? null : evolveScore - baselineScore;

  const comparison: CandidateComparison = {
    evolveScore,
    holdoutScore,
    generalizationGap,
    baselineScore,
    holdoutDelta,
    evolveDelta,
    noiseFloor,
    evolveCaseCount: evolveMetrics.length,
    holdoutCaseCount,
  };

  const reasons: string[] = [];

  if (evolveMetrics.length === 0 || holdoutCaseCount === 0) {
    reasons.push('insufficient signal: empty evolve or holdout slice');
    return { verdict: 'reject', reasons, evolveScore, holdoutScore, generalizationGap, comparison };
  }

  if (generalizationGap > gapThreshold) {
    reasons.push(
      `overfit: evolve/holdout gap ${fmt(generalizationGap)} exceeds threshold ${fmt(gapThreshold)}`,
    );
  }

  if (holdoutDelta !== null && holdoutDelta < 0) {
    // baselineScore is non-null here because holdoutDelta is only computed
    // when a baseline was supplied.
    reasons.push(`holdout regression: ${fmt(holdoutScore)} below baseline ${fmt(baselineScore!)}`);
  }

  if (holdoutDelta !== null && evolveDelta !== null) {
    // The RRSI case this catches: evolve moves, holdout does not. A gain under
    // the noise floor is not evidence that the candidate generalized.
    if (evolveDelta > 0 && holdoutDelta < minGain) {
      reasons.push(
        `no generalization gain: evolve +${fmt(evolveDelta)} but holdout ` +
          `${fmt(holdoutDelta)} is below the noise floor ${fmt(minGain)}`,
      );
    }
  }

  if (options.requireImprovement === true && holdoutDelta !== null && holdoutDelta <= 0) {
    reasons.push(`no improvement over baseline: holdout delta ${fmt(holdoutDelta)}`);
  }

  if (reasons.length > 0) {
    return { verdict: 'reject', reasons, evolveScore, holdoutScore, generalizationGap, comparison };
  }

  return { verdict: 'accept', reasons, evolveScore, holdoutScore, generalizationGap, comparison };
}

/**
 * Mean of the four hit/rank signals the tuner optimizes. Deliberately mirrors
 * `aggregateSearchMetrics`' objective except for the NDCG term, so a candidate
 * judged here cannot pass on a signal the objective ignores.
 */
export function meanObjectivity(metrics: readonly CaseMetrics[]): number {
  if (metrics.length === 0) return 0;
  let total = 0;
  for (const m of metrics) total += caseObjectivity(m);
  return total / metrics.length;
}

// ── internal helpers ──

function caseObjectivity(m: CaseMetrics): number {
  // 0.45*MRR + 0.25*NDCG + 0.15*P@1 + 0.15*Success@3 — the same weighting the
  // tuner's objective uses, so the critic's scores are comparable to it.
  return 0.45 * m.reciprocalRankAt10 + 0.25 * m.ndcgAt10 + 0.15 * m.hitAt1 + 0.15 * m.hitAt3;
}

function fmt(value: number): string {
  return value.toFixed(4);
}
