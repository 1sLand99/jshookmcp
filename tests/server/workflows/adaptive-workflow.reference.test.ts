import { describe, expect, it, vi } from 'vitest';
import {
  defineWorkflow,
  fallbackStep,
  sequenceStep,
  toolStep,
} from '@server/workflows/WorkflowContract';
import { getWorkflowRunStore } from '@server/workflows/WorkflowEngine';

/**
 * Reference workflow for the adaptive-orchestration capability built in stage
 * 1–3: a branch that picks its path from the workflow's own recorded run
 * history rather than from values available in the current run.
 *
 * This is intentionally a test-local definition rather than a builtin. No
 * builtin workflow uses `branchStep` at all today, so shipping one here would
 * mean inventing a workflow to justify the feature; what the capability needs
 * from us is proof that it composes end to end and a template extension authors
 * can copy. The scenario models a real reverse-engineering pattern: when the
 * stealth path keeps failing against a target, stop retrying it and go straight
 * to the fallback instrumentation route.
 */

function successResponse(payload: Record<string, unknown>) {
  return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...payload }) }] };
}

function failureResponse(error: string) {
  return { content: [{ type: 'text', text: JSON.stringify({ success: false, error }) }] };
}

/**
 * An `ExecuteWorkflowResult` for a run that succeeded only by way of a fallback
 * arm. Built directly rather than by driving the engine, because the point of
 * that shape is that the engine must have *recovered* — reproducing it through
 * a real run means the primary arm has to fail, which is the other test's job.
 */
function degradedResult(workflowId: string, runId: string) {
  const at = new Date().toISOString();
  return {
    workflowId,
    displayName: workflowId,
    runId,
    profile: 'workflow',
    startedAt: at,
    finishedAt: at,
    durationMs: 1,
    result: undefined,
    stepResults: { stealth_attempt: { success: true } },
    metrics: [],
    spans: [
      { name: 'workflow.node.start', attrs: { nodeId: 'stealth_attempt' }, at },
      { name: 'workflow.node.fallback', attrs: { nodeId: 'stealth_attempt' }, at },
      { name: 'workflow.node.finish', attrs: { nodeId: 'stealth_attempt' }, at },
    ],
  } as never;
}

const adaptiveStealthWorkflow = defineWorkflow(
  'workflow.adaptive-stealth.v1',
  'Adaptive Stealth Instrumentation',
  (w) =>
    w
      .description(
        'Instrument a target through the stealth path, switching to the fallback route once this workflow has a recorded history of stealth failures.',
      )
      .tags(['workflow', 'adaptive', 'instrumentation'])
      .buildGraph(() =>
        sequenceStep('adaptive-root', (s) =>
          s
            .branch('route', 'history_fallback_rate_gte_50', (b) =>
              b
                .whenTrue(
                  // Repeated stealth failures: skip the retry loop entirely.
                  toolStep('fallback_route', 'debugger_pause'),
                )
                .whenFalse(
                  fallbackStep('stealth_attempt', (f) =>
                    f
                      .primary(toolStep('stealth_primary', 'hook_stealth_inject'))
                      .fallback(toolStep('stealth_backup', 'hook_inject')),
                  ),
                ),
            )
            .tool('verify', 'debugger_evaluate'),
        ),
      ),
);

describe('adaptive workflow reference: history-driven branch selection', () => {
  it('takes the fallback route once fallback-degraded runs dominate the history', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const store = getWorkflowRunStore();
    store.clear();

    const ctx = {
      baseTier: 'workflow',
      config: {},
      executeToolWithTracking: vi.fn(async (name: string) => successResponse({ name })),
    };

    // Two runs that succeeded only by taking the fallback arm. They terminate
    // as `success`, so this history is invisible to a failure-rate predicate —
    // which is exactly why the fallback-rate signal exists.
    store.recordSuccess(degradedResult('workflow.adaptive-stealth.v1', 'r1'));
    store.recordSuccess(degradedResult('workflow.adaptive-stealth.v1', 'r2'));

    await executeExtensionWorkflow(ctx as never, adaptiveStealthWorkflow);

    const invoked = (ctx.executeToolWithTracking as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => call[0],
    );
    expect(invoked).toContain('debugger_pause');
    expect(invoked).not.toContain('hook_stealth_inject');
    // The sequence continues after the branch regardless of which arm ran.
    expect(invoked).toContain('debugger_evaluate');
  });

  it('attempts the stealth path with its fallback when history is clean', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const store = getWorkflowRunStore();
    store.clear();

    const ctx = {
      baseTier: 'workflow',
      config: {},
      executeToolWithTracking: vi.fn(async (name: string) => successResponse({ name })),
    };

    await executeExtensionWorkflow(ctx as never, adaptiveStealthWorkflow);

    const invoked = (ctx.executeToolWithTracking as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => call[0],
    );
    expect(invoked).toContain('hook_stealth_inject');
    expect(invoked).not.toContain('debugger_pause');
  });

  it('resolves the fallback arm when the stealth attempt itself fails', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const store = getWorkflowRunStore();
    store.clear();

    const ctx = {
      baseTier: 'workflow',
      config: {},
      executeToolWithTracking: vi.fn(async (name: string) => {
        if (name === 'hook_stealth_inject') return failureResponse('stealth rejected');
        return successResponse({ name });
      }),
    };

    await executeExtensionWorkflow(ctx as never, adaptiveStealthWorkflow);

    const invoked = (ctx.executeToolWithTracking as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => call[0],
    );
    // fallbackStep moves to its fallback arm rather than aborting the run.
    expect(invoked).toContain('hook_inject');
  });

  it('adapts across consecutive runs of the same workflow', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const store = getWorkflowRunStore();
    store.clear();

    const takePath = async () => {
      const ctx = {
        baseTier: 'workflow',
        config: {},
        executeToolWithTracking: vi.fn(async (name: string) =>
          name === 'hook_stealth_inject'
            ? failureResponse('stealth rejected')
            : successResponse({ name }),
        ),
      };
      await executeExtensionWorkflow(ctx as never, adaptiveStealthWorkflow);
      return (ctx.executeToolWithTracking as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]);
    };

    // Run 1: no history at all → the stealth path runs, and its primary arm
    // fails against this target, so the run degrades through its fallback.
    expect(await takePath()).toContain('hook_stealth_inject');
    // That single degraded run is already 100% of the recorded history, so the
    // branch flips on its own — no caller-side change required, and no second
    // failed attempt needed.
    const second = await takePath();
    expect(second).toContain('debugger_pause');
    expect(second).not.toContain('hook_stealth_inject');
    // And it stays flipped while the degraded history is in the window.
    const third = await takePath();
    expect(third).toContain('debugger_pause');
    expect(third).not.toContain('hook_stealth_inject');
  });
});
