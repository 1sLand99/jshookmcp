import { describe, expect, it } from 'vitest';
import { ToolCallTraceRecorder } from '@server/observability/ToolCallTraceRecorder';

describe('ToolCallTraceRecorder', () => {
  it('assigns monotonic seq and detects consecutive repeats per session', () => {
    const rec = new ToolCallTraceRecorder({ sessionId: 's1' });
    rec.recordToolCall({
      toolName: 'page_navigate',
      domain: 'browser',
      startedAt: 1,
      durationMs: 10,
      ok: true,
    });
    rec.recordToolCall({
      toolName: 'page_navigate',
      domain: 'browser',
      startedAt: 2,
      durationMs: 20,
      ok: true,
    });
    rec.recordToolCall({
      toolName: 'network_enable',
      domain: 'network',
      startedAt: 3,
      durationMs: 30,
      ok: true,
    });
    const trace = rec.snapshot('s1');
    expect(trace.entries.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(trace.entries[0]!.repeated).toBe(false);
    expect(trace.entries[1]!.repeated).toBe(true);
    expect(trace.entries[2]!.repeated).toBe(false);
  });

  it('does not mark repeats across different sessions', () => {
    const rec = new ToolCallTraceRecorder({ sessionId: 's1' });
    rec.recordToolCall(
      { toolName: 'page_navigate', domain: 'browser', startedAt: 1, durationMs: 10, ok: true },
      's1',
    );
    rec.recordToolCall(
      { toolName: 'page_navigate', domain: 'browser', startedAt: 2, durationMs: 10, ok: true },
      's2',
    );
    expect(rec.snapshot('s1').entries[1]).toBeUndefined();
    expect(rec.snapshot('s2').entries[0]!.repeated).toBe(false);
  });

  it('evicts oldest entries past the cap and reports the loss honestly', () => {
    const rec = new ToolCallTraceRecorder({ sessionId: 's1', maxEntries: 3 });
    for (let i = 1; i <= 5; i++) {
      rec.recordToolCall({
        toolName: `t${i}`,
        domain: null,
        startedAt: i,
        durationMs: 1,
        ok: true,
      });
    }
    const trace = rec.snapshot('s1');
    expect(trace.entries.map((e) => e.toolName)).toEqual(['t3', 't4', 't5']);
    expect(trace.droppedEntries).toBe(2);
    expect(trace.totalRecorded).toBe(5);
  });

  it('serializes to JSONL with sessionId on every line', () => {
    const rec = new ToolCallTraceRecorder({ sessionId: 's1' });
    rec.recordToolCall({
      toolName: 'debugger_pause',
      domain: 'debugger',
      startedAt: 1000,
      durationMs: 5,
      ok: false,
      errorKind: 'handler',
    });
    const jsonl = rec.toJSONL('s1');
    const lines = jsonl.trim().split('\n');
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(parsed['sessionId']).toBe('s1');
    expect(parsed['toolName']).toBe('debugger_pause');
    expect(parsed['seq']).toBe(1);
  });

  it('returns empty trace for unknown session', () => {
    const rec = new ToolCallTraceRecorder();
    const trace = rec.snapshot('nope');
    expect(trace.entries).toEqual([]);
    expect(trace.totalRecorded).toBe(0);
  });

  it('reset clears only the targeted session', () => {
    const rec = new ToolCallTraceRecorder({ sessionId: 's1' });
    rec.recordToolCall(
      { toolName: 'a', domain: null, startedAt: 1, durationMs: 1, ok: true },
      's1',
    );
    rec.recordToolCall(
      { toolName: 'b', domain: null, startedAt: 2, durationMs: 1, ok: true },
      's2',
    );
    rec.reset('s1');
    expect(rec.snapshot('s1').entries).toEqual([]);
    expect(rec.snapshot('s2').entries).toHaveLength(1);
  });

  it('clamps non-positive maxEntries to one', () => {
    const rec = new ToolCallTraceRecorder({ sessionId: 's1', maxEntries: 0 });
    rec.recordToolCall({ toolName: 'a', domain: null, startedAt: 1, durationMs: 1, ok: true });
    rec.recordToolCall({ toolName: 'b', domain: null, startedAt: 2, durationMs: 1, ok: true });
    const trace = rec.snapshot('s1');
    expect(trace.entries).toHaveLength(1);
    expect(trace.droppedEntries).toBe(1);
  });
});
