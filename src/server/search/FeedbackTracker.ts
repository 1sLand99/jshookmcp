/**
 * Feedback-based vector weight adjustment for tool search.
 *
 * Tracks which tools were selected after searches and adjusts the vector
 * signal weight based on how well the vector ranking predicted the user's
 * choice. The learning rates and "top N" window are configurable via env
 * (see `src/constants.ts`), which lets operators tune convergence speed
 * vs. stability without patching the code.
 *
 * Learning scheme:
 *   - rank < LEARN_TOP_N          → strong up-step (`LEARN_UP`)
 *   - LEARN_TOP_N ≤ rank < 2×N    → weak up-step (30% of `LEARN_UP`)
 *   - rank ≥ 2×N or unseen        → down-step (`LEARN_DOWN`)
 *
 * Bounds: weight ∈ [0.1, 0.8] to guarantee a minimum of lexical + vector
 * blend even in the pessimistic case.
 *
 * Learning can be disabled via `SearchConfig.vectorDynamicWeight` (mirrors
 * the `SEARCH_VECTOR_DYNAMIC_WEIGHT` env default): when false the weight
 * stays at its initial value, which is how the static-model A/B baseline in
 * `scripts/search-tune/compare-static-model.ts` isolates the feedback signal.
 *
 * The learned weight is exportable via `exportSnapshot` so it can outlive a
 * process restart (see the SnapshotSource contract in
 * `src/server/persistence/RuntimeSnapshotScheduler.ts`).
 */

import {
  SEARCH_VECTOR_COSINE_WEIGHT,
  SEARCH_VECTOR_DYNAMIC_WEIGHT,
  SEARCH_VECTOR_LEARN_DOWN,
  SEARCH_VECTOR_LEARN_TOP_N,
  SEARCH_VECTOR_LEARN_UP,
} from '@src/constants';
import type { SearchConfig } from '@internal-types/config';
import type { SnapshotSource } from '@server/persistence/RuntimeSnapshotScheduler';

const MIN_WEIGHT = 0.1;
const MAX_WEIGHT = 0.8;

/**
 * Serialized learning state. Only the vector weight is learned; the ranking
 * history and feedback query are session-scoped and not persisted.
 */
export interface FeedbackTrackerSnapshot {
  vectorWeight: number;
}

export class FeedbackTracker implements SnapshotSource {
  private vectorWeight: number;
  private lastVectorRanking: Map<string, number> | null = null;
  /**
   * The query that accompanied the most recent tool-call feedback. Recorded
   * for quality analysis (see SearchQualityTracker); it takes no part in the
   * learning logic. `null` when no feedback has been recorded yet or the
   * caller had no query context (the call_tool path passes an empty string).
   */
  private lastFeedbackQuery: string | null = null;
  private dirty = false;

  private readonly topN: number;
  private readonly learnUp: number;
  private readonly learnDown: number;
  private readonly dynamicWeightEnabled: boolean;

  constructor(searchConfig?: SearchConfig) {
    this.vectorWeight = searchConfig?.vectorCosineWeight ?? SEARCH_VECTOR_COSINE_WEIGHT;
    this.topN = Math.max(1, SEARCH_VECTOR_LEARN_TOP_N);
    this.learnUp = Math.max(0, SEARCH_VECTOR_LEARN_UP);
    this.learnDown = Math.max(0, SEARCH_VECTOR_LEARN_DOWN);
    this.dynamicWeightEnabled = searchConfig?.vectorDynamicWeight ?? SEARCH_VECTOR_DYNAMIC_WEIGHT;
  }

  getVectorWeight(): number {
    return this.vectorWeight;
  }

  /**
   * The query from the most recent tool-call feedback, or `null` when no
   * feedback has been recorded (or the caller had no query to pass).
   */
  getLastFeedbackQuery(): string | null {
    return this.lastFeedbackQuery;
  }

  /**
   * Store the vector ranking from the most recent search. Called by the
   * search engine after the vector signal has been scored.
   *
   * @param ranking Map of tool name → rank (0-based; lower = better)
   */
  recordVectorRanking(ranking: Map<string, number>): void {
    this.lastVectorRanking = ranking;
  }

  /**
   * Record feedback from a tool call and nudge the vector weight.
   * Returns `true` if the weight actually moved.
   *
   * @param toolName The tool that was invoked after the last search
   * @param vectorEnabled Whether the embedding engine is active
   * @param lastQuery The search query that led to this tool call. Recorded for
   *   quality analysis only — it never influences the learned weight.
   */
  recordToolCallFeedback(toolName: string, vectorEnabled: boolean, lastQuery?: string): boolean {
    if (lastQuery && lastQuery.length > 0) {
      this.lastFeedbackQuery = lastQuery;
      this.dirty = true;
    }

    if (!this.lastVectorRanking || !vectorEnabled) return false;
    // SEARCH_VECTOR_DYNAMIC_WEIGHT gate: A/B baselines
    // (scripts/search-tune/compare-static-model.ts) disable learning by
    // passing vectorDynamicWeight: false; the weight then stays at its
    // configured initial value for the whole run.
    if (!this.dynamicWeightEnabled) return false;

    const vectorRank = this.lastVectorRanking.get(toolName);
    const before = this.vectorWeight;

    if (vectorRank === undefined) {
      this.vectorWeight = Math.max(MIN_WEIGHT, this.vectorWeight - this.learnDown);
    } else if (vectorRank < this.topN) {
      this.vectorWeight = Math.min(MAX_WEIGHT, this.vectorWeight + this.learnUp);
    } else if (vectorRank < this.topN * 2) {
      this.vectorWeight = Math.min(MAX_WEIGHT, this.vectorWeight + this.learnUp * 0.3);
    } else {
      this.vectorWeight = Math.max(MIN_WEIGHT, this.vectorWeight - this.learnDown);
    }

    if (this.vectorWeight !== before) this.dirty = true;
    return this.vectorWeight !== before;
  }

  // ── Snapshot persistence ──────────────────────────────────────────────
  //
  // The learned vector weight is process state worth surviving a restart;
  // without persistence every process re-learns from the initial 0.53. The
  // methods below implement the RuntimeSnapshotScheduler's SnapshotSource
  // contract (dirty flag + export/restore).
  //
  // TODO: registering this tracker with the RuntimeSnapshotScheduler
  // (snapshotScheduler.register('feedback-tracker.json', tracker) + wiring
  // notifyDirty through the search engine) is cross-module wiring and belongs
  // to a follow-up task; this class only provides the source contract.

  isPersistDirty(): boolean {
    return this.dirty;
  }

  markPersisted(): void {
    this.dirty = false;
  }

  exportSnapshot(): FeedbackTrackerSnapshot {
    return { vectorWeight: this.vectorWeight };
  }

  restoreSnapshot(data: unknown): void {
    if (!data || typeof data !== 'object') return;
    const snapshot = data as { vectorWeight?: unknown };
    if (typeof snapshot.vectorWeight !== 'number') return;
    // Clamp on restore: a snapshot written by a future version (or hand-edited)
    // may carry a weight outside the bounds the learning relies on.
    this.vectorWeight = Math.min(MAX_WEIGHT, Math.max(MIN_WEIGHT, snapshot.vectorWeight));
    this.dirty = false;
  }
}
