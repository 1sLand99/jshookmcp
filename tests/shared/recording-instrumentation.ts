/**
 * A recording `InstrumentationContract` for tests.
 *
 * Deliberately not a `vi.fn()` mock. The assertions that matter here are about
 * pairing and ordering — a span that was started and never ended, a metric
 * emitted with the wrong type, a gauge emitted when nothing changed — and those
 * are far easier to state against plain record arrays than against
 * `mock.calls[0][2]`.
 *
 * `ended` is tracked separately from `endAttrs` because "the span was closed"
 * and "the span was closed with these attributes" are different claims, and a
 * span that leaks (never ended) is invisible to the second one.
 */
import type {
  InstrumentationContract,
  MetricType,
  SpanLike,
} from '@server/observability/InstrumentationContract';

export interface RecordedSpan {
  name: string;
  attrs: Record<string, unknown> | undefined;
  endAttrs: Record<string, unknown> | undefined;
  events: string[];
  ended: boolean;
}

export interface RecordedMetric {
  name: string;
  value: number;
  type: MetricType;
  attrs: Record<string, unknown> | undefined;
}

export class RecordingInstrumentation implements InstrumentationContract {
  readonly spans: RecordedSpan[] = [];
  readonly metrics: RecordedMetric[] = [];

  startSpan(name: string, attrs?: Record<string, unknown>): SpanLike {
    const record: RecordedSpan = { name, attrs, endAttrs: undefined, events: [], ended: false };
    this.spans.push(record);
    return {
      name,
      startTime: Date.now(),
      end: (endAttrs) => {
        record.ended = true;
        record.endAttrs = endAttrs;
      },
      addEvent: (eventName) => {
        record.events.push(eventName);
      },
    };
  }

  emitMetric(name: string, value: number, type: MetricType, attrs?: Record<string, unknown>): void {
    this.metrics.push({ name, value, type, attrs });
  }

  /** Spans with this name, in start order. */
  spansNamed(name: string): RecordedSpan[] {
    return this.spans.filter((span) => span.name === name);
  }

  /** Metrics with this name, in emit order. */
  metricsNamed(name: string): RecordedMetric[] {
    return this.metrics.filter((metric) => metric.name === name);
  }
}
