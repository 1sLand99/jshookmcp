/**
 * Adapter from the concrete `WorkflowRunStore` onto the `WorkflowHistoryPort`
 * seam that history-aware predicates program against.
 *
 * Stage 3 of the adaptive-workflow-orchestration plan ("engine wiring"). The
 * port exists so predicates never depend on the run store's shape; this is the
 * one place that knows both.
 *
 * Ordering: `WorkflowRunStore.getHistory` already returns newest-first (it
 * sorts by `finishedAt` descending), which is exactly the port's contract, so
 * the mapping is a field rename rather than a reversal. That is load-bearing —
 * predicates slice `[0, window)` and call it "recent" — so the port's own
 * ordering test covers it; if `getHistory`'s ordering ever changes, the
 * predicate tests fail rather than the predicates silently reasoning backwards.
 */

import type { WorkflowRunStore } from '@server/workflows/WorkflowRunStore';
import type {
  WorkflowHistoryEntry,
  WorkflowHistoryPort,
} from '@server/workflows/WorkflowHistoryPort';

/**
 * Count the failed steps recorded for a run.
 *
 * `stepOutcomes` is absent for runs recorded before stage 1 added it (and for
 * error runs whose caller had no per-step summary), so fall back to the run's
 * own terminal status: an error run with no step detail is one failed run, not
 * zero. Reporting 0 there would make `recent_steps_failing_L` read a hard
 * failure as clean.
 */
function failedStepCount(run: {
  status: 'success' | 'error';
  stepOutcomes?: readonly { status: 'success' | 'error' }[];
}): number {
  if (run.stepOutcomes && run.stepOutcomes.length > 0) {
    return run.stepOutcomes.filter((outcome) => outcome.status === 'error').length;
  }
  return run.status === 'error' ? 1 : 0;
}

/** Wrap a run store as a read-only history port. */
export function createWorkflowHistoryPort(store: WorkflowRunStore): WorkflowHistoryPort {
  return {
    getHistory(
      workflowId: string,
      options?: { readonly limit?: number },
    ): readonly WorkflowHistoryEntry[] {
      return store.getHistory(workflowId, options?.limit).map((run) => ({
        workflowId: run.workflowId,
        runId: run.runId,
        status: run.status,
        failedStepCount: failedStepCount(run),
        fallbackCount: run.fallbackCount ?? 0,
        startedAt: run.startedAt,
      }));
    },
  };
}
