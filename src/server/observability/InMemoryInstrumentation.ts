/**
 * In-memory implementation of `InstrumentationContract`.
 *
 * The contract's default is `NoopInstrumentation`: zero overhead, records
 * nothing. That is the right default for a library, but it makes "is the
 * instrumentation actually working?" unanswerable from inside the process —
 * which is exactly how `InstrumentationContract` sat unwired for six months
 * without anyone noticing. This implementation answers that question: it is
 * inspectable, bounded, and cheap enough to leave on while diagnosing.
 *
 * BOUNDED ON PURPOSE
 * ------------------
 * A long-running server that keeps one span per tool call forever is a memory
 * leak, and a metrics sink whose key space grows without limit is a
 * denial-of-service aimed at itself. So:
 *   - spans live in a fixed-size window; the oldest are dropped and counted
 *   - metrics are AGGREGATED per name (count/sum/min/max/last), never appended
 *   - the number of distinct metric names is capped; excess names are counted,
 *     not stored
 * `droppedSpans` / `droppedMetrics` are part of the snapshot precisely so the
 * loss is visible rather than silent — a buffer that quietly discards is the
 * same defect class this repo keeps finding elsewhere.
 *
 * Not a general-purpose metrics store: no quantiles, no labels/dimensions, no
 * time buckets. It exists to prove the wiring works and to answer "what has
 * this process been doing" from a health endpoint. A real backend (OTLP,
 * Prometheus) implements the same interface and replaces it wholesale.
 */

import type { InstrumentationContract, MetricType, SpanLike } from './InstrumentationContract';

/** Span window size. Small enough that the O(n) drop-oldest is irrelevant. */
const DEFAULT_MAX_SPANS = 512;
/** Cap on distinct metric names held at once. */
const DEFAULT_MAX_METRICS = 256;

export interface SpanRecord {
  readonly name: string;
  attrs: Record<string, unknown> | undefined;
  readonly startTime: number;
  endTime: number | null;
  durationMs: number | null;
  readonly events: { name: string; attrs?: Record<string, unknown>; at: number }[];
}

export interface MetricRecord {
  readonly name: string;
  type: MetricType;
  count: number;
  sum: number;
  min: number;
  max: number;
  last: number;
}

export interface InstrumentationSnapshot {
  readonly spans: readonly SpanRecord[];
  /** Spans started over the process lifetime, including dropped ones. */
  readonly spanCount: number;
  readonly droppedSpans: number;
  readonly metrics: readonly MetricRecord[];
  /** Metric samples rejected because the name cap was reached. */
  readonly droppedMetrics: number;
}

/**
 * Copy an attribute bag one level deep.
 *
 * `{ ...span }` copies the span but leaves `attrs` pointing at the recorder's
 * own object, so a caller mutating `snapshot.spans[0].attrs` would rewrite the
 * recorded data. One level is the honest depth: the contract types `attrs` as
 * `Record<string, unknown>`, so nested objects are the caller's problem, but the
 * top level is the recorder's.
 */
function copyAttrs(
  attrs: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return attrs === undefined ? undefined : { ...attrs };
}

export class InMemoryInstrumentation implements InstrumentationContract {
  private readonly spans: SpanRecord[] = [];
  private readonly metrics = new Map<string, MetricRecord>();
  private readonly maxSpans: number;
  private spanCount = 0;
  private droppedSpans = 0;
  private droppedMetrics = 0;

  constructor(maxSpans: number = DEFAULT_MAX_SPANS) {
    this.maxSpans = Math.max(1, maxSpans);
  }

  startSpan(name: string, attrs?: Record<string, unknown>): SpanLike {
    const record: SpanRecord = {
      name,
      attrs,
      startTime: Date.now(),
      endTime: null,
      durationMs: null,
      events: [],
    };
    this.spanCount += 1;
    if (this.spans.length >= this.maxSpans) {
      this.spans.shift();
      this.droppedSpans += 1;
    }
    this.spans.push(record);

    return {
      name,
      startTime: record.startTime,
      // `end` is idempotent: a double-end (e.g. an error path plus a finally)
      // must not overwrite the first, real duration.
      end: (endAttrs) => {
        if (record.endTime !== null) return;
        record.endTime = Date.now();
        record.durationMs = record.endTime - record.startTime;
        if (endAttrs) record.attrs = { ...record.attrs, ...endAttrs };
      },
      addEvent: (eventName, eventAttrs) => {
        record.events.push({ name: eventName, attrs: eventAttrs, at: Date.now() });
      },
    };
  }

  emitMetric(
    name: string,
    value: number,
    type: MetricType,
    _attrs?: Record<string, unknown>,
  ): void {
    // A NaN or Infinity would poison min/max/sum for the whole process
    // lifetime, so it is refused at the door and counted as a drop.
    if (!Number.isFinite(value)) {
      this.droppedMetrics += 1;
      return;
    }

    const existing = this.metrics.get(name);
    if (existing) {
      existing.count += 1;
      existing.sum += value;
      if (value < existing.min) existing.min = value;
      if (value > existing.max) existing.max = value;
      existing.last = value;
      existing.type = type;
      return;
    }

    if (this.metrics.size >= DEFAULT_MAX_METRICS) {
      this.droppedMetrics += 1;
      return;
    }
    this.metrics.set(name, {
      name,
      type,
      count: 1,
      sum: value,
      min: value,
      max: value,
      last: value,
    });
  }

  /**
   * Point-in-time copy. Callers cannot mutate the recorder through it.
   *
   * A unit test caught this returning live references: the docstring claimed the
   * snapshot was safe to mutate while `{ ...span }` left `attrs` shared, so
   * `snapshot.spans[0].attrs.x = ...` rewrote the recorded data.
   */
  snapshot(): InstrumentationSnapshot {
    return {
      spans: this.spans.map((span) => ({
        ...span,
        attrs: copyAttrs(span.attrs),
        events: span.events.map((event) => ({ ...event, attrs: copyAttrs(event.attrs) })),
      })),
      spanCount: this.spanCount,
      droppedSpans: this.droppedSpans,
      metrics: [...this.metrics.values()].map((metric) => ({ ...metric })),
      droppedMetrics: this.droppedMetrics,
    };
  }

  /** Clear recorded data but keep the lifetime counters. */
  reset(): void {
    this.spans.length = 0;
    this.metrics.clear();
  }

  /** In-memory: there is no buffer to drain. Present to satisfy the contract. */
  async flush(): Promise<void> {
    /* nothing to flush */
  }
}
