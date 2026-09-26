/**
 * History-access abstraction for history-aware workflow predicates.
 *
 * Stage 2 of the adaptive-workflow-orchestration plan ("predicate expansion").
 * The branch predicates in `WorkflowPredicates.ts` need to reason about the
 * past runs of *this* workflow — "this keeps failing, switch paths" — but must
 * not depend on the concrete `WorkflowRunStore`, which stage 1 is reworking in
 * parallel. This port is the seam: predicates program against it, and stage 3
 * will supply an adapter that maps the real run store onto it.
 *
 * Deliberately minimal. Every quantity the predicates need is derived from
 * `getHistory` by the pure helpers below, so stage 1/3 only has to implement
 * one method plus an entry mapping.
 *
 * Ordering contract: `getHistory` returns runs **most-recent-first**. The
 * concrete store (`WorkflowRunStore.listRuns`) currently yields oldest-first
 * by insertion order, so the stage-3 adapter must reverse before returning.
 * Predicates slice `[0, window)` from the front and treat that as "recent";
 * an adapter that returns oldest-first would silently make "recent" mean
 * "oldest", so this is load-bearing, not cosmetic.
 */

/** Outcome of a single past workflow run, as seen by history-aware predicates. */
export interface WorkflowHistoryEntry {
  readonly workflowId: string;
  readonly runId: string;
  /** Terminal status of the run. */
  readonly status: 'success' | 'error';
  /** Number of steps that failed within this run (0 for a clean success). */
  readonly failedStepCount: number;
  /**
   * Number of `fallback` nodes that took their backup arm in this run.
   *
   * Distinct from `failedStepCount`: a run that recovers through a fallback is
   * a `success`, so this is the only signal that a route keeps needing its
   * backup. A history-aware branch that only read terminal status would never
   * notice a degrading path.
   */
  readonly fallbackCount: number;
  /** ISO-8601 start timestamp; used only for ordering, never for arithmetic. */
  readonly startedAt: string;
}

/**
 * Read-only view onto the run history of a workflow.
 *
 * All methods are total: an unknown workflow, or one with no recorded runs,
 * yields an empty array, never `undefined` — callers distinguish "no history"
 * from "history says X" by array length, which is what the predicates want.
 */
export interface WorkflowHistoryPort {
  /**
   * Return up to `limit` most-recent runs for `workflowId`, newest first.
   * `limit` is a cap, not a promise: fewer runs may be returned. When omitted,
   * the port may cap at its own retention bound.
   */
  getHistory(
    workflowId: string,
    options?: { readonly limit?: number },
  ): readonly WorkflowHistoryEntry[];
}

/**
 * Failure rate over a slice of run entries, as a percentage 0-100.
 *
 * Returns `undefined` for an empty slice rather than 0, because the predicates
 * must distinguish "no history to judge" from "history is flawless" — the two
 * warrant opposite defaults (see `WorkflowPredicates.ts`).
 */
export function computeFailureRate(entries: readonly WorkflowHistoryEntry[]): number | undefined {
  if (entries.length === 0) {
    return undefined;
  }

  const failures = entries.filter((entry) => entry.status === 'error').length;
  return (failures / entries.length) * 100;
}

/**
 * Worst failed-step count across a slice of run entries.
 *
 * `undefined` for an empty slice, same reason as `computeFailureRate`: the
 * "how bad did it get recently" predicate must not mistake absence of history
 * for a clean run.
 */
export function computeMaxFailedSteps(
  entries: readonly WorkflowHistoryEntry[],
): number | undefined {
  if (entries.length === 0) {
    return undefined;
  }

  return entries.reduce((worst, entry) => Math.max(worst, entry.failedStepCount), 0);
}

/**
 * Fraction of runs in the slice that needed at least one fallback arm, as a
 * percentage 0-100. `undefined` for an empty slice, same reasoning as
 * {@link computeFailureRate}.
 *
 * Separate from the failure rate on purpose: these runs succeeded, so a branch
 * asking "is this route degrading?" gets an answer that terminal status alone
 * cannot give.
 */
export function computeFallbackRate(entries: readonly WorkflowHistoryEntry[]): number | undefined {
  if (entries.length === 0) {
    return undefined;
  }

  const degraded = entries.filter((entry) => entry.fallbackCount > 0).length;
  return (degraded / entries.length) * 100;
}
