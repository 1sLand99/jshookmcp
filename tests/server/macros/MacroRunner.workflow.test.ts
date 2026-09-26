import { describe, expect, it, vi } from 'vitest';
import { MacroRunner } from '@server/macros/MacroRunner';
import type { MacroDefinition } from '@server/macros/types';

function successResponse(payload: Record<string, unknown> = {}) {
  return {
    content: [{ type: 'text', text: JSON.stringify({ success: true, ...payload }) }],
  };
}

function failureResponse(error = 'failed') {
  return {
    content: [{ type: 'text', text: JSON.stringify({ success: false, error }) }],
  };
}

function mockContext(executeToolWithTracking: ReturnType<typeof vi.fn>) {
  return {
    baseTier: 'workflow',
    config: {},
    executeToolWithTracking,
  } as any;
}

describe('MacroRunner workflow integration', () => {
  it('continues after optional step failures', async () => {
    const executeToolWithTracking = vi.fn(async (name: string) => {
      if (name === 'unstable_tool') {
        return failureResponse('optional failure');
      }
      return successResponse({ name });
    });
    const runner = new MacroRunner(mockContext(executeToolWithTracking));
    const def: MacroDefinition = {
      id: 'optional_macro',
      displayName: 'Optional Macro',
      description: 'Optional step should not stop the macro',
      tags: [],
      steps: [
        { id: 'maybe', toolName: 'unstable_tool', optional: true },
        { id: 'after', toolName: 'stable_tool' },
      ],
    };

    const result = await runner.execute(def);

    expect(result.ok).toBe(true);
    expect(result.stepsCompleted).toBe(1);
    expect(result.progress.map((step) => step.status)).toEqual(['skipped', 'complete']);
    expect(result.stepResults).not.toHaveProperty('maybe');
    expect(result.stepResults).toHaveProperty('after');
    expect(executeToolWithTracking).toHaveBeenCalledWith('stable_tool', {});
  });

  it('executes nested parallel, branch, and retry macro steps', async () => {
    let flakyAttempts = 0;
    const executeToolWithTracking = vi.fn(async (name: string) => {
      if (name === 'seed_tool') {
        return successResponse({ route: 'fast' });
      }
      if (name === 'flaky_tool') {
        flakyAttempts += 1;
        return flakyAttempts === 1
          ? failureResponse('retry me')
          : successResponse({ attempt: flakyAttempts });
      }
      return successResponse({ name });
    });
    const runner = new MacroRunner(mockContext(executeToolWithTracking));
    const def: MacroDefinition = {
      id: 'rich_macro',
      displayName: 'Rich Macro',
      description: 'Uses non-linear orchestration',
      tags: ['workflow'],
      steps: [
        { id: 'seed', toolName: 'seed_tool' },
        {
          id: 'fanout',
          parallelSteps: [
            { id: 'probe_a', toolName: 'probe_a_tool' },
            { id: 'probe_b', toolName: 'probe_b_tool' },
          ],
          maxConcurrency: 2,
          failFast: true,
        },
        {
          id: 'route',
          branchStep: {
            predicateId: 'variable_equals_seed.route_fast',
            whenTrue: { id: 'fast_path', toolName: 'fast_tool' },
            whenFalse: { id: 'slow_path', toolName: 'slow_tool' },
          },
        },
        {
          id: 'flaky',
          toolName: 'flaky_tool',
          retry: { maxAttempts: 2, backoffMs: 0, multiplier: 1 },
        },
      ],
    };

    const result = await runner.execute(def);

    expect(result.ok).toBe(true);
    expect(result.stepsCompleted).toBe(4);
    expect(result.progress.every((step) => step.status === 'complete')).toBe(true);
    expect(result.stepResults).toHaveProperty('fanout');
    expect(result.stepResults).toHaveProperty('fast_path');
    expect(result.stepResults).not.toHaveProperty('slow_path');
    expect(flakyAttempts).toBe(2);
    expect(executeToolWithTracking).toHaveBeenCalledWith('fast_tool', {});
  });

  it('derives per-step durations from the engine own node spans', async () => {
    // The end-to-end pairing test. `MacroRunner.buildProgress` reads the engine's
    // node spans BY NAME to derive each step's duration; as bare string literals
    // on both sides, a rename on either would have made both lookups return
    // undefined and silently blanked `durationMs`, with no test failing — the
    // same shape as the `adb:device_connected` regression, just not yet fired.
    // Both sides now share `WorkflowSpanNames`, and this drives the REAL engine
    // (no engine mock) so the pairing is checked by behaviour rather than by a
    // fixture that repeats the consumer's assumption back at it.
    const executeToolWithTracking = vi.fn(async (name: string) => successResponse({ name }));
    const runner = new MacroRunner(mockContext(executeToolWithTracking));
    const def: MacroDefinition = {
      id: 'timed_macro',
      displayName: 'Timed Macro',
      description: 'Per-step durations must come from real engine spans',
      tags: [],
      steps: [
        { id: 'first', toolName: 'some_tool' },
        { id: 'second', toolName: 'another_tool' },
      ],
    };

    const result = await runner.execute(def);

    expect(result.ok).toBe(true);
    expect(result.progress).toHaveLength(2);
    for (const step of result.progress) {
      expect(step.status).toBe('complete');
      // undefined here means the consumer's name lookup missed the producer's
      // emission — the failure this test exists to make loud.
      expect(step.durationMs).toBeTypeOf('number');
      expect(step.durationMs).toBeGreaterThanOrEqual(0);
    }
  });
});
