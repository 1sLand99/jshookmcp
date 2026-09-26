/**
 * Behaviour of the instrumentation contract's own primitives.
 *
 * The load-bearing claim here is the FALLBACK: `resolveInstrumentation` must
 * never be the reason a tool call fails. Tests and degraded startup paths pass
 * partial contexts (`ctx as never`) with no domain-instance map at all, so a
 * missing instrumentation has to resolve to a working no-op rather than throw.
 */
import { afterEach, describe, expect, it } from 'vitest';
import {
  getGlobalInstrumentation,
  INSTRUMENTATION_DOMAIN_KEY,
  MetricNames,
  NoopInstrumentation,
  resetGlobalInstrumentation,
  resolveInstrumentation,
  setGlobalInstrumentation,
  SpanNames,
} from '@server/observability/InstrumentationContract';
import { RecordingInstrumentation } from '@tests/shared/recording-instrumentation';

describe('InstrumentationContract — declared names', () => {
  it('every span name is a lowercase segment plus a separator segment', () => {
    // Span names are dotted (`tool.execute`, `workflow.run`) — the same shape the
    // audit's scanner recognises for events.
    const names = Object.values(SpanNames);
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect(name).toMatch(/^[a-z][a-z0-9-]*([:.][a-z0-9_-]+)+$/);
    }
  });

  it('every metric name is lowercase snake_case', () => {
    // Metric names are NOT event-shaped: `tool_calls_total` has no `:`/`.`
    // separator, so the audit's EVENT_NAME_RE would not match it. That is fine —
    // check 8 matches `MetricNames.x` member accesses, not literals — but the
    // distinction is worth pinning so a future rename does not assume the two
    // families share a shape.
    const names = Object.values(MetricNames);
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect(name).toMatch(/^[a-z][a-z0-9_]*$/);
    }
  });

  it('declares no duplicate values across spans and metrics', () => {
    const names = [...Object.values(SpanNames), ...Object.values(MetricNames)];
    expect(new Set(names).size).toBe(names.length);
  });
});

describe('NoopInstrumentation', () => {
  it('returns a usable span whose methods never throw', () => {
    const noop = new NoopInstrumentation();
    const span = noop.startSpan(SpanNames.toolExecute, { toolName: 'x' });
    expect(span.name).toBe(SpanNames.toolExecute);
    expect(span.startTime).toBeGreaterThan(0);
    expect(() => span.addEvent('event')).not.toThrow();
    expect(() => span.end({ ok: true })).not.toThrow();
  });

  it('emitMetric accepts every metric type without throwing', () => {
    const noop = new NoopInstrumentation();
    expect(() => noop.emitMetric('x', 1, 'counter')).not.toThrow();
    expect(() => noop.emitMetric('x', 2, 'gauge', { a: 1 })).not.toThrow();
    expect(() => noop.emitMetric('x', 3, 'histogram')).not.toThrow();
  });
});

describe('resolveInstrumentation', () => {
  it('reads the implementation registered under the instrumentation domain key', () => {
    const recording = new RecordingInstrumentation();
    const host = {
      getDomainInstance: <T>(key: string): T | undefined =>
        key === INSTRUMENTATION_DOMAIN_KEY ? (recording as unknown as T) : undefined,
    };

    expect(resolveInstrumentation(host)).toBe(recording);
  });

  it('falls back to a no-op when the host has no domain-instance map', () => {
    // `{} as MCPServerContext` is the shape a partial test context has.
    expect(() => resolveInstrumentation({} as never)).not.toThrow();
    expect(resolveInstrumentation({} as never)).toBeInstanceOf(NoopInstrumentation);
    expect(resolveInstrumentation(undefined)).toBeInstanceOf(NoopInstrumentation);
  });

  it('falls back to a no-op when the key is absent from the map', () => {
    const host = { getDomainInstance: <T>(_key: string): T | undefined => undefined };
    expect(resolveInstrumentation(host)).toBeInstanceOf(NoopInstrumentation);
  });

  it('does not consult a host whose getDomainInstance is not callable', () => {
    const host = { getDomainInstance: 'not a function' } as unknown as {
      getDomainInstance: <T>(key: string) => T | undefined;
    };
    expect(resolveInstrumentation(host)).toBeInstanceOf(NoopInstrumentation);
  });
});

describe('global instrumentation', () => {
  afterEach(() => {
    resetGlobalInstrumentation();
  });

  it('defaults to a no-op before anything installs one', () => {
    expect(getGlobalInstrumentation()).toBeInstanceOf(NoopInstrumentation);
  });

  it('installs and restores', () => {
    const recording = new RecordingInstrumentation();
    setGlobalInstrumentation(recording);
    expect(getGlobalInstrumentation()).toBe(recording);

    resetGlobalInstrumentation();
    expect(getGlobalInstrumentation()).toBeInstanceOf(NoopInstrumentation);
  });
});
