/**
 * `createInstrumentation` — the config switch.
 *
 * A config key that changes nothing is its own instance of the defect class this
 * work exists to remove, so the switch is asserted to select a DIFFERENT object
 * with DIFFERENT behaviour, not merely to return without throwing.
 */
import { describe, expect, it } from 'vitest';
import { createInstrumentation } from '@server/observability/createInstrumentation';
import { InMemoryInstrumentation } from '@server/observability/InMemoryInstrumentation';
import { NoopInstrumentation } from '@server/observability/InstrumentationContract';

describe('createInstrumentation', () => {
  it('defaults to the zero-overhead no-op when the section is absent', () => {
    expect(createInstrumentation({})).toBeInstanceOf(NoopInstrumentation);
  });

  it('defaults to the no-op for an explicit "none" exporter', () => {
    expect(createInstrumentation({ observability: { exporter: 'none' } })).toBeInstanceOf(
      NoopInstrumentation,
    );
  });

  it('selects the in-memory recorder for the "memory" exporter', () => {
    expect(createInstrumentation({ observability: { exporter: 'memory' } })).toBeInstanceOf(
      InMemoryInstrumentation,
    );
  });

  it('honours the configured span window', () => {
    const recorder = createInstrumentation({
      observability: { exporter: 'memory', maxSpans: 2 },
    }) as InMemoryInstrumentation;

    for (let index = 0; index < 3; index += 1) recorder.startSpan('probe.span');
    expect(recorder.snapshot().spans).toHaveLength(2);
    expect(recorder.snapshot().droppedSpans).toBe(1);
  });

  it('the two implementations actually behave differently', () => {
    // The switch is real only if the objects differ in observable behaviour.
    const noop = createInstrumentation({ observability: { exporter: 'none' } });
    const memory = createInstrumentation({ observability: { exporter: 'memory' } });

    noop.startSpan('probe.span').end();
    memory.startSpan('probe.span').end();

    expect((memory as InMemoryInstrumentation).snapshot().spanCount).toBe(1);
    // The no-op has no snapshot to inspect — which is the point of the option.
    expect(noop).not.toBeInstanceOf(InMemoryInstrumentation);
  });
});
