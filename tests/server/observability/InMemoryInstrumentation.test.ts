/**
 * `InMemoryInstrumentation` — the option that makes "is the instrumentation
 * actually working?" answerable from inside the process.
 *
 * The bounds are the interesting part. A recorder that grows without limit is a
 * leak, and a recorder that silently discards is the same defect class this repo
 * keeps finding elsewhere — so every drop is asserted to be COUNTED, not just
 * performed.
 */
import { describe, expect, it } from 'vitest';
import { InMemoryInstrumentation } from '@server/observability/InMemoryInstrumentation';
import { SpanNames, MetricNames } from '@server/observability/InstrumentationContract';

describe('InMemoryInstrumentation — spans', () => {
  it('records a span with its name, attributes and duration', async () => {
    const recorder = new InMemoryInstrumentation();
    const span = recorder.startSpan(SpanNames.toolExecute, { toolName: 'page_navigate' });
    await new Promise((resolve) => setTimeout(resolve, 2));
    span.end({ ok: true });

    const snapshot = recorder.snapshot();
    expect(snapshot.spans).toHaveLength(1);
    const record = snapshot.spans[0]!;
    expect(record.name).toBe(SpanNames.toolExecute);
    // Start attrs and end attrs are merged, not replaced.
    expect(record.attrs).toEqual({ toolName: 'page_navigate', ok: true });
    expect(record.durationMs).toBeGreaterThanOrEqual(0);
    expect(record.endTime).not.toBeNull();
  });

  it('leaves an unended span with a null duration', () => {
    const recorder = new InMemoryInstrumentation();
    recorder.startSpan(SpanNames.workflowRun);
    expect(recorder.snapshot().spans[0]!.durationMs).toBeNull();
  });

  it('treats a double end as a no-op so the first real duration survives', async () => {
    const recorder = new InMemoryInstrumentation();
    const span = recorder.startSpan(SpanNames.workflowStep);
    await new Promise((resolve) => setTimeout(resolve, 5));
    span.end({ first: true });
    const firstDuration = recorder.snapshot().spans[0]!.durationMs;

    // The error path plus a finally is the realistic way this happens.
    await new Promise((resolve) => setTimeout(resolve, 5));
    span.end({ second: true });

    const record = recorder.snapshot().spans[0]!;
    expect(record.durationMs).toBe(firstDuration);
    expect(record.attrs).toEqual({ first: true });
  });

  it('records span events in order', () => {
    const recorder = new InMemoryInstrumentation();
    const span = recorder.startSpan(SpanNames.pluginLifecycle);
    span.addEvent('loaded');
    span.addEvent('activated');
    expect(recorder.snapshot().spans[0]!.events.map((event) => event.name)).toEqual([
      'loaded',
      'activated',
    ]);
  });

  it('drops the oldest span past the window and COUNTS the loss', () => {
    const recorder = new InMemoryInstrumentation(3);
    for (let index = 0; index < 5; index += 1) {
      recorder.startSpan(SpanNames.toolExecute, { index });
    }

    const snapshot = recorder.snapshot();
    expect(snapshot.spans).toHaveLength(3);
    expect(snapshot.spans.map((span) => span.attrs?.['index'])).toEqual([2, 3, 4]);
    // Lifetime total counts everything; the drop is visible, not silent.
    expect(snapshot.spanCount).toBe(5);
    expect(snapshot.droppedSpans).toBe(2);
  });

  it('keeps at least one span even when asked for a zero-sized window', () => {
    const recorder = new InMemoryInstrumentation(0);
    recorder.startSpan(SpanNames.toolExecute);
    expect(recorder.snapshot().spans).toHaveLength(1);
  });
});

describe('InMemoryInstrumentation — metrics', () => {
  it('aggregates repeated samples of one name instead of appending them', () => {
    const recorder = new InMemoryInstrumentation();
    recorder.emitMetric(MetricNames.toolDurationMs, 10, 'histogram');
    recorder.emitMetric(MetricNames.toolDurationMs, 30, 'histogram');
    recorder.emitMetric(MetricNames.toolDurationMs, 20, 'histogram');

    const metrics = recorder.snapshot().metrics;
    expect(metrics).toHaveLength(1);
    expect(metrics[0]).toMatchObject({
      name: MetricNames.toolDurationMs,
      count: 3,
      sum: 60,
      min: 10,
      max: 30,
      last: 20,
    });
  });

  it('refuses a non-finite sample and counts it as a drop', () => {
    const recorder = new InMemoryInstrumentation();
    // A NaN would poison min/max/sum for the whole process lifetime.
    recorder.emitMetric(MetricNames.toolCallsTotal, Number.NaN, 'counter');
    recorder.emitMetric(MetricNames.toolCallsTotal, Number.POSITIVE_INFINITY, 'counter');
    recorder.emitMetric(MetricNames.toolCallsTotal, 1, 'counter');

    const snapshot = recorder.snapshot();
    expect(snapshot.metrics).toHaveLength(1);
    expect(snapshot.metrics[0]).toMatchObject({ count: 1, sum: 1, min: 1, max: 1 });
    expect(snapshot.droppedMetrics).toBe(2);
  });

  it('caps the number of distinct metric names and counts the excess', () => {
    const recorder = new InMemoryInstrumentation();
    for (let index = 0; index < 300; index += 1) {
      recorder.emitMetric(`probe_metric_${String(index)}`, 1, 'counter');
    }

    const snapshot = recorder.snapshot();
    expect(snapshot.metrics).toHaveLength(256);
    expect(snapshot.droppedMetrics).toBe(44);
  });

  it('tracks a gauge as a level, not a total', () => {
    const recorder = new InMemoryInstrumentation();
    recorder.emitMetric(MetricNames.pluginActiveTotal, 3, 'gauge');
    recorder.emitMetric(MetricNames.pluginActiveTotal, 1, 'gauge');

    const metric = recorder.snapshot().metrics[0]!;
    expect(metric.type).toBe('gauge');
    // `last` is the current level; `sum` is an artefact of aggregation and is
    // deliberately not presented as the value.
    expect(metric.last).toBe(1);
  });
});

describe('InMemoryInstrumentation — snapshot isolation', () => {
  it('hands out a copy that cannot mutate the recorder', () => {
    const recorder = new InMemoryInstrumentation();
    const span = recorder.startSpan(SpanNames.toolExecute, { a: 1 });
    span.addEvent('e');
    recorder.emitMetric(MetricNames.toolCallsTotal, 1, 'counter');

    const snapshot = recorder.snapshot();
    (snapshot.spans[0]!.attrs as Record<string, unknown>)['a'] = 'mutated';
    (snapshot.metrics[0] as { count: number }).count = 999;
    snapshot.spans[0]!.events.length = 0;

    const fresh = recorder.snapshot();
    expect(fresh.spans[0]!.attrs).toEqual({ a: 1 });
    expect(fresh.metrics[0]!.count).toBe(1);
    expect(fresh.spans[0]!.events).toHaveLength(1);
  });

  it('reset clears the recorded data but keeps the lifetime counters', () => {
    const recorder = new InMemoryInstrumentation();
    recorder.startSpan(SpanNames.toolExecute);
    recorder.emitMetric(MetricNames.toolCallsTotal, 1, 'counter');
    recorder.reset();

    const snapshot = recorder.snapshot();
    expect(snapshot.spans).toHaveLength(0);
    expect(snapshot.metrics).toHaveLength(0);
    expect(snapshot.spanCount).toBe(1);
  });

  it('flush resolves — there is no buffer to drain', async () => {
    await expect(new InMemoryInstrumentation().flush()).resolves.toBeUndefined();
  });
});
