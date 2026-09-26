import { describe, expect, it, vi } from 'vitest';
import { evaluatePredicate } from '@server/workflows/WorkflowPredicates';
import {
  computeFailureRate,
  computeFallbackRate,
  computeMaxFailedSteps,
  type WorkflowHistoryEntry,
  type WorkflowHistoryPort,
} from '@server/workflows/WorkflowHistoryPort';
import { toolStep, type BranchNode } from '@server/workflows/WorkflowContract';
import type { InternalExecutionContext } from '@server/workflows/WorkflowEngine.types';

/**
 * History-aware predicates (stage 2). `evaluatePredicate` reaches the run
 * history through the optional `history` field on the execution context —
 * optional because stage 3 has not wired the real run store in yet, so every
 * predicate must degrade sensibly when it is absent. Those degradation paths
 * are the safety net for the temporary ctx bridge and are tested first.
 */

function historyEntry(
  workflowId: string,
  runId: string,
  status: WorkflowHistoryEntry['status'],
  failedStepCount = 0,
  startedAt = '2026-09-01T00:00:00.000Z',
  fallbackCount = 0,
): WorkflowHistoryEntry {
  return { workflowId, runId, status, failedStepCount, startedAt, fallbackCount };
}

function historyPort(entries: WorkflowHistoryEntry[]): WorkflowHistoryPort {
  return {
    getHistory: (workflowId, options) => {
      const filtered = entries.filter((entry) => entry.workflowId === workflowId);
      const limit = options?.limit;
      return typeof limit === 'number' ? filtered.slice(0, limit) : filtered;
    },
  };
}

function createContext(options?: {
  history?: WorkflowHistoryPort;
  workflowId?: string;
}): InternalExecutionContext {
  return {
    workflowRunId: 'run-123',
    profile: 'workflow',
    stepResults: new Map(),
    dataBus: null as unknown as InternalExecutionContext['dataBus'],
    // Temporary bridge: `history` and `workflowId` are not yet declared on
    // InternalExecutionContext (stage 3 adds them). Predicates read them
    // through an optional-field accessor, so a literal object like this one is
    // all a caller needs to supply.
    ...(options?.history ? { history: options.history } : {}),
    ...(options?.workflowId ? { workflowId: options.workflowId } : {}),
    invokeTool: vi.fn(async () => undefined),
    emitSpan: vi.fn(),
    emitMetric: vi.fn(),
    getConfig: <T>(_path: string, fallback?: T) => fallback as T,
  } as InternalExecutionContext;
}

function branch(predicateId: string): BranchNode {
  return {
    kind: 'branch',
    id: 'branch-under-test',
    predicateId,
    whenTrue: toolStep('t-branch', 'tool.alpha'),
  };
}

/** Evaluate a single predicate against an optional port, without a full ctx. */
async function evalPredicate(
  predicateId: string,
  port: WorkflowHistoryPort | undefined,
): Promise<boolean> {
  const ctx = createContext(port ? { history: port, workflowId: 'wf' } : { workflowId: 'wf' });
  return evaluatePredicate(branch(predicateId), ctx);
}

describe('history-aware predicates', () => {
  describe('degradation without a history port', () => {
    it('rate and last-run and failing-step predicates are false when no port is attached', async () => {
      const ctx = createContext();
      for (const predicateId of [
        'history_failure_rate_gte_50',
        'history_failure_rate_lte_50',
        'last_run_failed',
        'recent_steps_failing_2',
      ]) {
        await expect(evaluatePredicate(branch(predicateId), ctx)).resolves.toBe(false);
      }
    });

    it('last_run_failed falls back to the ctx workflowId when no port is attached', async () => {
      const ctx = createContext({ workflowId: 'wf-explicit' });
      await expect(evaluatePredicate(branch('last_run_failed:wf-explicit'), ctx)).resolves.toBe(
        false,
      );
    });
  });

  describe('degradation with a port but no history', () => {
    it('treats an unknown workflow as no history and stays false', async () => {
      const ctx = createContext({ history: historyPort([]), workflowId: 'wf-empty' });
      for (const predicateId of [
        'history_failure_rate_gte_50',
        'history_failure_rate_lte_50',
        'last_run_failed',
        'recent_steps_failing_1',
      ]) {
        await expect(evaluatePredicate(branch(predicateId), ctx)).resolves.toBe(false);
      }
    });
  });

  describe('history_failure_rate_gte_N', () => {
    it('is true when the recent failure rate meets the threshold', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'error'),
        historyEntry('wf', 'r2', 'success'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gte_50'), ctx)).resolves.toBe(
        true,
      );
      await expect(evaluatePredicate(branch('history_failure_rate_gte_51'), ctx)).resolves.toBe(
        false,
      );
    });

    it('is false when the recent failure rate is below the threshold', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'success'),
        historyEntry('wf', 'r2', 'success'),
        historyEntry('wf', 'r3', 'error'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gte_50'), ctx)).resolves.toBe(
        false,
      );
      await expect(evaluatePredicate(branch('history_failure_rate_gte_33'), ctx)).resolves.toBe(
        true,
      );
    });

    it('looks only at the most recent runs when history outgrows the window', async () => {
      // 6 recent failures out of 10 recent runs, preceded by 10 clean runs.
      const entries: WorkflowHistoryEntry[] = [
        ...Array.from({ length: 6 }, (_, index) =>
          historyEntry('wf', `recent-fail-${index}`, 'error'),
        ),
        ...Array.from({ length: 4 }, (_, index) =>
          historyEntry('wf', `recent-ok-${index}`, 'success'),
        ),
        ...Array.from({ length: 10 }, (_, index) =>
          historyEntry('wf', `old-ok-${index}`, 'success'),
        ),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gte_60'), ctx)).resolves.toBe(
        true,
      );
      await expect(evaluatePredicate(branch('history_failure_rate_gte_61'), ctx)).resolves.toBe(
        false,
      );
    });

    it('counts every run when history is shorter than the window', async () => {
      const entries: WorkflowHistoryEntry[] = [historyEntry('wf', 'r1', 'error')];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gte_100'), ctx)).resolves.toBe(
        true,
      );
      await expect(evaluatePredicate(branch('history_failure_rate_gte_0'), ctx)).resolves.toBe(
        true,
      );
    });

    it('ignores runs from other workflows', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf-other', 'x1', 'error'),
        historyEntry('wf-other', 'x2', 'error'),
        historyEntry('wf', 'r1', 'success'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gte_50'), ctx)).resolves.toBe(
        false,
      );
    });

    it('honors an explicit workflowId suffix over the ctx workflowId', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf-explicit', 'r1', 'error'),
        historyEntry('wf-implicit', 'r1', 'success'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf-implicit' });

      await expect(
        evaluatePredicate(branch('history_failure_rate_gte_50:wf-explicit'), ctx),
      ).resolves.toBe(true);
    });
  });

  describe('history_failure_rate_lte_N', () => {
    it('is true when the recent failure rate is at or below the threshold', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'success'),
        historyEntry('wf', 'r2', 'error'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_lte_50'), ctx)).resolves.toBe(
        true,
      );
      await expect(evaluatePredicate(branch('history_failure_rate_lte_49'), ctx)).resolves.toBe(
        false,
      );
    });

    it('is true for a spotless recent history at threshold 0', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'success'),
        historyEntry('wf', 'r2', 'success'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_lte_0'), ctx)).resolves.toBe(
        true,
      );
    });

    it('is false when the recent failure rate exceeds the threshold', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'error'),
        historyEntry('wf', 'r2', 'error'),
        historyEntry('wf', 'r3', 'success'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_lte_50'), ctx)).resolves.toBe(
        false,
      );
    });
  });

  describe('last_run_failed', () => {
    it('is true when the most recent run errored', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r2', 'error', 1, '2026-09-02T00:00:00.000Z'),
        historyEntry('wf', 'r1', 'success', 0, '2026-09-01T00:00:00.000Z'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('last_run_failed'), ctx)).resolves.toBe(true);
    });

    it('is false when the most recent run succeeded', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r2', 'success', 0, '2026-09-02T00:00:00.000Z'),
        historyEntry('wf', 'r1', 'error', 1, '2026-09-01T00:00:00.000Z'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('last_run_failed'), ctx)).resolves.toBe(false);
    });

    it('honors an explicit workflowId suffix', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf-explicit', 'r1', 'error'),
        historyEntry('wf-implicit', 'r1', 'success'),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf-implicit' });

      await expect(evaluatePredicate(branch('last_run_failed:wf-explicit'), ctx)).resolves.toBe(
        true,
      );
      await expect(evaluatePredicate(branch('last_run_failed'), ctx)).resolves.toBe(false);
    });

    it('is false when the port returns history for the wrong workflow only', async () => {
      const entries: WorkflowHistoryEntry[] = [historyEntry('wf-other', 'r1', 'error')];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('last_run_failed'), ctx)).resolves.toBe(false);
    });
  });

  describe('recent_steps_failing_L', () => {
    it('is true when the worst recent run failed at least L steps', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'error', 3),
        historyEntry('wf', 'r2', 'error', 1),
        historyEntry('wf', 'r3', 'success', 0),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('recent_steps_failing_3'), ctx)).resolves.toBe(true);
      await expect(evaluatePredicate(branch('recent_steps_failing_4'), ctx)).resolves.toBe(false);
    });

    it('is false when recent runs failed fewer steps than L', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf', 'r1', 'error', 2),
        historyEntry('wf', 'r2', 'success', 0),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('recent_steps_failing_3'), ctx)).resolves.toBe(false);
    });

    it('is true at the boundary L=0 when history exists', async () => {
      const entries: WorkflowHistoryEntry[] = [historyEntry('wf', 'r1', 'success', 0)];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('recent_steps_failing_0'), ctx)).resolves.toBe(true);
    });

    it('looks only at the most recent runs when history outgrows the window', async () => {
      // Worst recent run failed 2 steps; an older run (outside the window)
      // failed 9. The window must hide the ancient blow-up.
      const entries: WorkflowHistoryEntry[] = [
        ...Array.from({ length: 10 }, (_, index) =>
          historyEntry('wf', `recent-${index}`, 'error', 2),
        ),
        historyEntry('wf', 'ancient', 'error', 9),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('recent_steps_failing_9'), ctx)).resolves.toBe(false);
      await expect(evaluatePredicate(branch('recent_steps_failing_2'), ctx)).resolves.toBe(true);
    });

    it('honors an explicit workflowId suffix', async () => {
      const entries: WorkflowHistoryEntry[] = [
        historyEntry('wf-explicit', 'r1', 'error', 5),
        historyEntry('wf-implicit', 'r1', 'error', 1),
      ];
      const ctx = createContext({ history: historyPort(entries), workflowId: 'wf-implicit' });

      await expect(
        evaluatePredicate(branch('recent_steps_failing_5:wf-explicit'), ctx),
      ).resolves.toBe(true);
    });
  });

  describe('invalid predicate ids', () => {
    it('throws for a malformed rate threshold', async () => {
      const ctx = createContext({ history: historyPort([]), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gte_abc'), ctx)).rejects.toThrow(
        'Unknown workflow predicateId "history_failure_rate_gte_abc"',
      );
    });

    it('throws for an unsupported rate comparator', async () => {
      const ctx = createContext({ history: historyPort([]), workflowId: 'wf' });

      await expect(evaluatePredicate(branch('history_failure_rate_gt_50'), ctx)).rejects.toThrow(
        'Unknown workflow predicateId "history_failure_rate_gt_50"',
      );
    });
  });

  describe('history helpers', () => {
    it('computeFailureRate distinguishes empty history from a clean record', () => {
      expect(computeFailureRate([])).toBeUndefined();
      expect(computeFailureRate([historyEntry('wf', 'r1', 'success')])).toBe(0);
      expect(
        computeFailureRate([
          historyEntry('wf', 'r1', 'error'),
          historyEntry('wf', 'r2', 'success'),
        ]),
      ).toBe(50);
      expect(
        computeFailureRate([historyEntry('wf', 'r1', 'error'), historyEntry('wf', 'r2', 'error')]),
      ).toBe(100);
    });

    it('computeMaxFailedSteps distinguishes empty history from a clean record', () => {
      expect(computeMaxFailedSteps([])).toBeUndefined();
      expect(computeMaxFailedSteps([historyEntry('wf', 'r1', 'success', 0)])).toBe(0);
      expect(
        computeMaxFailedSteps([
          historyEntry('wf', 'r1', 'error', 1),
          historyEntry('wf', 'r2', 'error', 4),
        ]),
      ).toBe(4);
    });
  });

  /**
   * Runs that recover through a fallback terminate as `success`, so failure-rate
   * predicates cannot see a route that keeps needing its backup. These cover the
   * signal that closes that blind spot.
   */
  describe('history_fallback_rate_gte_N', () => {
    it('is true when degraded-but-successful runs meet the threshold', async () => {
      const port = historyPort([
        // Both succeeded — but only via their fallback arm.
        historyEntry('wf', 'r1', 'success', 0, '2026-09-02T00:00:00.000Z', 1),
        historyEntry('wf', 'r2', 'success', 0, '2026-09-02T00:00:00.000Z', 1),
      ]);
      expect(await evalPredicate('history_fallback_rate_gte_50', port)).toBe(true);
    });

    it('is false when runs succeeded on their primary path', async () => {
      const port = historyPort([
        historyEntry('wf', 'r1', 'success', 0, '2026-09-02T00:00:00.000Z', 0),
        historyEntry('wf', 'r2', 'success', 0, '2026-09-02T00:00:00.000Z', 0),
      ]);
      expect(await evalPredicate('history_fallback_rate_gte_50', port)).toBe(false);
    });

    it('is blind to pure failures, which the failure-rate predicate covers', async () => {
      // An error run has no fallback arm to speak of; reporting it as "degraded"
      // here would double-count what history_failure_rate_* already reports.
      const port = historyPort([
        historyEntry('wf', 'r1', 'error', 1, '2026-09-02T00:00:00.000Z', 0),
        historyEntry('wf', 'r2', 'error', 1, '2026-09-02T00:00:00.000Z', 0),
      ]);
      expect(await evalPredicate('history_fallback_rate_gte_50', port)).toBe(false);
    });

    it('reports a mixed history as the proportion that degraded', async () => {
      const port = historyPort([
        historyEntry('wf', 'r1', 'success', 0, '2026-09-02T00:00:00.000Z', 1),
        historyEntry('wf', 'r2', 'success', 0, '2026-09-02T00:00:00.000Z', 0),
      ]);
      // 50% degraded: meets a 50 threshold, misses a 51 one.
      expect(await evalPredicate('history_fallback_rate_gte_50', port)).toBe(true);
      expect(await evalPredicate('history_fallback_rate_gte_51', port)).toBe(false);
    });

    it('degrades to false without a port or without history', async () => {
      expect(await evalPredicate('history_fallback_rate_gte_50', undefined)).toBe(false);
      expect(await evalPredicate('history_fallback_rate_gte_50', historyPort([]))).toBe(false);
    });

    it('computeFallbackRate separates no-history from a spotless record', () => {
      expect(computeFallbackRate([])).toBeUndefined();
      expect(computeFallbackRate([historyEntry('wf', 'r1', 'success', 0, undefined, 0)])).toBe(0);
      expect(computeFallbackRate([historyEntry('wf', 'r1', 'success', 0, undefined, 2)])).toBe(100);
    });
  });
});
