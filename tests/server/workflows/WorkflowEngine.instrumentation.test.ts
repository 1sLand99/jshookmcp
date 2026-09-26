/**
 * Instrumentation wiring for the workflow engine.
 *
 * The engine already had its own span/metric arrays, but they dead-end inside
 * the run result — nothing outside the process ever saw them, which is how
 * `InstrumentationContract` sat unwired while the engine looked instrumented.
 * These tests pin the run-scope wiring, and pin the thing that made renaming
 * dangerous: the engine's `workflow.node.*` spans are read by
 * `MacroRunner.buildProgress`, so `workflow.run` had to be added ALONGSIDE them,
 * never instead of them.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ randomUUID: vi.fn(() => 'run-123') }));
vi.mock('node:crypto', () => ({ randomUUID: state.randomUUID }));

import { defineWorkflow, sequenceStep } from '@server/workflows/WorkflowContract';
import {
  INSTRUMENTATION_DOMAIN_KEY,
  MetricNames,
  SpanNames,
} from '@server/observability/InstrumentationContract';
import { RecordingInstrumentation } from '@tests/shared/recording-instrumentation';

function successResponse(payload: Record<string, unknown>) {
  return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...payload }) }] };
}

function createCtx(
  instrumentation: RecordingInstrumentation,
  execute: (name: string, args: Record<string, unknown>) => Promise<unknown>,
) {
  return {
    baseTier: 'workflow',
    config: {},
    executeToolWithTracking: vi.fn(execute),
    getDomainInstance: <T>(key: string): T | undefined =>
      key === INSTRUMENTATION_DOMAIN_KEY ? (instrumentation as unknown as T) : undefined,
  };
}

describe('WorkflowEngine — instrumentation wiring', () => {
  let instrumentation: RecordingInstrumentation;

  beforeEach(() => {
    vi.clearAllMocks();
    instrumentation = new RecordingInstrumentation();
  });

  it('emits a run span, step spans and success metrics', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const ctx = createCtx(instrumentation, async (name, args) => successResponse({ name, args }));
    const workflow = defineWorkflow('wf-instr', 'Instrumented', (w) =>
      w.buildGraph(() =>
        sequenceStep('root', (s) => {
          s.tool('step-1', 'page_navigate');
          s.tool('step-2', 'page_click');
        }),
      ),
    );

    await executeExtensionWorkflow(ctx as never, workflow, {});

    const run = instrumentation.spansNamed(SpanNames.workflowRun);
    expect(run).toHaveLength(1);
    expect(run[0]!.attrs).toMatchObject({ workflowId: 'wf-instr', runId: 'run-123' });
    expect(run[0]!.ended).toBe(true);
    expect(run[0]!.endAttrs).toEqual({ status: 'success' });

    // One span per node — the step granularity, distinct from the engine's own
    // `workflow.node.start`/`finish` pair.
    const steps = instrumentation.spansNamed(SpanNames.workflowStep);
    expect(steps.length).toBeGreaterThanOrEqual(1);
    expect(steps.every((span) => span.ended)).toBe(true);
    expect(steps.map((span) => span.attrs?.['nodeId'])).toContain('step-1');

    expect(instrumentation.metricsNamed(MetricNames.workflowRunsTotal)).toEqual([
      {
        name: MetricNames.workflowRunsTotal,
        value: 1,
        type: 'counter',
        attrs: { profile: expect.any(String), status: 'success' },
      },
    ]);
    expect(instrumentation.metricsNamed(MetricNames.workflowDurationMs)).toHaveLength(1);
    expect(instrumentation.metricsNamed(MetricNames.workflowErrorsTotal)).toHaveLength(0);
  });

  it('ends the run span with status error and counts the error on failure', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const ctx = createCtx(instrumentation, async () => {
      throw new Error('step exploded');
    });
    const workflow = defineWorkflow('wf-fail', 'Failing', (w) =>
      w.buildGraph(() => sequenceStep('root', (s) => s.tool('step-1', 'page_navigate'))),
    );

    await expect(executeExtensionWorkflow(ctx as never, workflow, {})).rejects.toThrow(
      'step exploded',
    );

    const run = instrumentation.spansNamed(SpanNames.workflowRun);
    expect(run).toHaveLength(1);
    // Ended BEFORE the user-supplied onError hook runs, so a throwing hook cannot
    // leave the span open.
    expect(run[0]!.ended).toBe(true);
    expect(run[0]!.endAttrs).toMatchObject({ status: 'error', error: 'step exploded' });

    expect(instrumentation.metricsNamed(MetricNames.workflowRunsTotal)[0]!.attrs).toMatchObject({
      status: 'error',
    });
    expect(instrumentation.metricsNamed(MetricNames.workflowErrorsTotal)).toHaveLength(1);
    expect(instrumentation.metricsNamed(MetricNames.workflowDurationMs)[0]!.attrs).toMatchObject({
      status: 'error',
    });
  });

  it('leaves the engine-owned workflow.node.* spans intact', async () => {
    const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
    const ctx = createCtx(instrumentation, async (name, args) => successResponse({ name, args }));
    const workflow = defineWorkflow('wf-nodes', 'Nodes', (w) =>
      w.buildGraph(() => sequenceStep('root', (s) => s.tool('step-1', 'page_navigate'))),
    );

    const result = await executeExtensionWorkflow(ctx as never, workflow, {});

    // MacroRunner.buildProgress derives per-step durations by matching these
    // exact names plus attrs.nodeId. The instrumentation wiring must not have
    // renamed or replaced them — a rename would silently blank out macro
    // progress, with no test failing.
    const nodeNames = result.spans.map((span) => span.name);
    expect(nodeNames).toContain('workflow.node.start');
    expect(nodeNames).toContain('workflow.node.finish');
    expect(nodeNames).not.toContain(SpanNames.workflowStep);
  });
});
