/**
 * Instrumentation wiring for the native bridge.
 *
 * `bridgeFetch` is the single funnel all four `handle*Bridge` methods go
 * through, and it is a module-level function with no server context — so it
 * resolves the process-wide instrumentation. The interesting case for a bridge
 * is the transport failure, which is why the span is ended in a `finally` and
 * records the error as an EVENT rather than a second `end()`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeBridgeHandlers } from '@server/domains/native-bridge/index';
import {
  MetricNames,
  resetGlobalInstrumentation,
  setGlobalInstrumentation,
  SpanNames,
} from '@server/observability/InstrumentationContract';
import { RecordingInstrumentation } from '@tests/shared/recording-instrumentation';

const GHIDRA = 'http://127.0.0.1:18080';
const IDA = 'http://127.0.0.1:18081';

let instrumentation: RecordingInstrumentation;

beforeEach(() => {
  instrumentation = new RecordingInstrumentation();
  setGlobalInstrumentation(instrumentation);
});

afterEach(() => {
  resetGlobalInstrumentation();
  vi.unstubAllGlobals();
});

describe('native bridge — instrumentation wiring', () => {
  it('emits a bridge span and metrics on a healthy response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ status: 200, json: async () => ({ ok: true, version: '1' }) })),
    );
    const handlers = new NativeBridgeHandlers(GHIDRA, IDA);

    await handlers.handleNativeBridgeStatus({});

    const spans = instrumentation.spansNamed(SpanNames.bridgeRequest);
    expect(spans.length).toBeGreaterThanOrEqual(1);
    expect(spans[0]!.attrs).toMatchObject({ method: 'GET' });
    expect(spans[0]!.ended).toBe(true);
    // The HTTP status is the span's outcome — '200', not a boolean.
    expect(spans[0]!.endAttrs).toEqual({ status: '200' });
    expect(spans[0]!.events).toEqual([]);

    const requests = instrumentation.metricsNamed(MetricNames.bridgeRequestsTotal);
    expect(requests.length).toBeGreaterThanOrEqual(1);
    expect(requests[0]).toEqual({
      name: MetricNames.bridgeRequestsTotal,
      value: 1,
      type: 'counter',
      attrs: { status: '200' },
    });
    expect(instrumentation.metricsNamed(MetricNames.bridgeDurationMs)[0]!.type).toBe('histogram');
  });

  it('records a transport failure as a span event and still ends the span', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('connect ECONNREFUSED');
      }),
    );
    const handlers = new NativeBridgeHandlers(GHIDRA, IDA);

    // The handler swallows the error into a tool response; the instrumentation
    // must have observed it regardless.
    await handlers.handleNativeBridgeStatus({});

    const spans = instrumentation.spansNamed(SpanNames.bridgeRequest);
    expect(spans.length).toBeGreaterThanOrEqual(1);
    const failed = spans[0]!;
    expect(failed.ended).toBe(true);
    expect(failed.endAttrs).toEqual({ status: 'transport_error' });
    expect(failed.events).toEqual(['error']);

    expect(instrumentation.metricsNamed(MetricNames.bridgeRequestsTotal)[0]!.attrs).toEqual({
      status: 'transport_error',
    });
  });

  it('treats a non-JSON 200 as unreachable without losing the status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        status: 200,
        json: async () => {
          throw new Error('not json');
        },
      })),
    );
    const handlers = new NativeBridgeHandlers(GHIDRA, IDA);

    await handlers.handleNativeBridgeStatus({});

    // The status is recorded even though the body could not be parsed — that is
    // what makes a misconfigured sidecar distinguishable from a dead one.
    expect(instrumentation.spansNamed(SpanNames.bridgeRequest)[0]!.endAttrs).toEqual({
      status: '200',
    });
  });
});
