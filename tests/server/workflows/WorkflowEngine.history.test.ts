import { beforeEach, describe, expect, it, vi } from 'vitest';
import { branchStep, defineWorkflow, toolStep } from '@server/workflows/WorkflowContract';

/**
 * Stage-3 wiring: the engine must hand branch predicates a live view of the
 * workflow's own run history, so a workflow can react to "this keeps failing".
 *
 * These tests drive the real `executeExtensionWorkflow` against the real global
 * run store — no mocked port — because the failure mode being guarded against is
 * exactly a wiring gap: the port exists, the predicates work, but nothing
 * injects one into the execution context, leaving every history predicate
 * silently evaluating `false`.
 */

function successResponse(payload: Record<string, unknown>) {
  return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...payload }) }] };
}

function failureResponse(error: string) {
  return { content: [{ type: 'text', text: JSON.stringify({ success: false, error }) }] };
}

describe('WorkflowEngine stage 3: history port injection', () => {
  beforeEach(() => {
    vi.useRealTimers();
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('injects a history port so history predicates reflect prior runs', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const { getWorkflowRunStore } = await import('@server/workflows/WorkflowEngine');
    getWorkflowRunStore().clear();

    const ctx = {
      baseTier: 'workflow',
      config: {},
      executeToolWithTracking: vi.fn(async (name: string) => successResponse({ name })),
    };

    // Branch on the workflow's own failure history. With no history the
    // predicate is false, so this takes `whenFalse`; once failures accumulate it
    // must take `whenTrue` — proving the port is actually wired, not absent.
    const workflow = defineWorkflow('wf-history-branch', 'History Branch', (w) =>
      w.buildGraph(() =>
        branchStep('gate', 'history_failure_rate_gte_50', (b) => {
          b.whenTrue(toolStep('recovered', 'tool_after_failures'));
          b.whenFalse(toolStep('first_try', 'tool_first_time'));
        }),
      ),
    );

    const store = getWorkflowRunStore();

    // Two failed runs recorded directly into the store the engine reads from.
    store.recordError('wf-history-branch', 'run-fail-1', new Date().toISOString(), new Error('a'));
    store.recordError('wf-history-branch', 'run-fail-2', new Date().toISOString(), new Error('b'));

    const result = await executeExtensionWorkflow(ctx as never, workflow);

    const invoked = (ctx.executeToolWithTracking as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => call[0],
    );
    expect(invoked).toContain('tool_after_failures');
    expect(invoked).not.toContain('tool_first_time');
    expect(result.stepResults).toHaveProperty('recovered');
  });

  it('leaves history predicates false when a workflow has no recorded history', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const { getWorkflowRunStore } = await import('@server/workflows/WorkflowEngine');
    getWorkflowRunStore().clear();

    const ctx = {
      baseTier: 'workflow',
      config: {},
      executeToolWithTracking: vi.fn(async (name: string) => successResponse({ name })),
    };

    const workflow = defineWorkflow('wf-no-history', 'No History', (w) =>
      w.buildGraph(() =>
        branchStep('gate', 'history_failure_rate_gte_50', (b) => {
          b.whenTrue(toolStep('should_not_run', 'tool_after_failures'));
          b.whenFalse(toolStep('expected', 'tool_first_time'));
        }),
      ),
    );

    await executeExtensionWorkflow(ctx as never, workflow);

    const invoked = (ctx.executeToolWithTracking as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => call[0],
    );
    expect(invoked).toContain('tool_first_time');
    expect(invoked).not.toContain('tool_after_failures');
  });

  it('records partial step outcomes when a run fails mid-graph', async () => {
    const { executeExtensionWorkflow, getWorkflowRunStore } =
      await import('@server/workflows/WorkflowEngine');
    const store = getWorkflowRunStore();
    store.clear();

    const ctx = {
      baseTier: 'workflow',
      config: {},
      executeToolWithTracking: vi.fn(async (name: string) => {
        if (name === 'tool_boom') return failureResponse('step exploded');
        return successResponse({ name });
      }),
    };

    const workflow = defineWorkflow('wf-partial-failure', 'Partial Failure', (w) =>
      w.buildGraph(() => {
        const first = toolStep('ok_step', 'tool_ok');
        return {
          kind: 'sequence',
          id: 'seq',
          steps: [first, toolStep('bad_step', 'tool_boom')],
        };
      }),
    );

    await expect(executeExtensionWorkflow(ctx as never, workflow)).rejects.toThrow();

    const lastFailure = store.getLastFailure('wf-partial-failure');
    expect(lastFailure?.status).toBe('error');
    expect(lastFailure?.errorMessage).toContain('step exploded');
    // The failing run carries a per-step summary rather than an empty array, so
    // `recent_steps_failing_L` can count what actually broke.
    expect(lastFailure?.stepOutcomes?.length ?? 0).toBeGreaterThan(0);
    const failedSteps = lastFailure?.stepOutcomes?.filter((o) => o.status === 'error') ?? [];
    expect(failedSteps.map((o) => o.stepId)).toContain('bad_step');
  });
});
