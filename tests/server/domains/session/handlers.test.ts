import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SessionProgressHandlers } from '@server/domains/session/index';
import { parseJson } from '@tests/server/domains/shared/mock-factories';
import type { SessionProgressRecordResult } from '@server/domains/session/handlers';

interface CoverageResult {
  sessionId: string;
  counts: { process: number; hookPoint: number; protocolField: number };
  total: number;
  entries: Array<{
    kind: string;
    key: string;
    recordedAt: string;
    metadata?: Record<string, unknown>;
  }>;
}

interface RecordResponse extends SessionProgressRecordResult {
  success: boolean;
  error?: string;
}

interface CoverageResponse extends CoverageResult {
  success: boolean;
}

interface ClearResponse {
  success: boolean;
  cleared: number;
  sessionId: string;
  kind?: string;
  error?: string;
}

async function record(
  handlers: SessionProgressHandlers,
  args: Record<string, unknown>,
): Promise<RecordResponse> {
  return parseJson<RecordResponse>(await handlers.handleRecordProgressTool(args));
}

async function coverage(
  handlers: SessionProgressHandlers,
  args: Record<string, unknown> = {},
): Promise<CoverageResponse> {
  return parseJson<CoverageResponse>(await handlers.handleGetCoverageTool(args));
}

async function clear(
  handlers: SessionProgressHandlers,
  args: Record<string, unknown> = {},
): Promise<ClearResponse> {
  return parseJson<ClearResponse>(await handlers.handleClearProgressTool(args));
}

describe('SessionProgressHandlers', () => {
  let handlers: SessionProgressHandlers;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    handlers = new SessionProgressHandlers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── record ──

  describe('session_progress_record', () => {
    it('records a new entry and reports per-kind counts', async () => {
      const body = await record(handlers, { kind: 'process', key: 'pid:4210' });

      expect(body.success).toBe(true);
      expect(body.recorded).toBe(true);
      expect(body.created).toBe(true);
      expect(body.sessionId).toBe('default');
      expect(body.kind).toBe('process');
      expect(body.key).toBe('pid:4210');
      expect(body.kindCounts).toEqual({ process: 1, hookPoint: 0, protocolField: 0 });
      expect(body.totalEntries).toBe(1);
    });

    it('accumulates counts across all three kinds', async () => {
      await record(handlers, { kind: 'process', key: 'pid:4210' });
      await record(handlers, { kind: 'hook-point', key: 'libfoo.so!0x12345' });
      await record(handlers, { kind: 'protocol-field', key: 'TLS.handshake.client_random' });
      const body = await record(handlers, { kind: 'process', key: 'pid:9999' });

      expect(body.kindCounts).toEqual({ process: 2, hookPoint: 1, protocolField: 1 });
      expect(body.totalEntries).toBe(4);
    });

    it('is idempotent for the same (kind, key): updates metadata, no duplicate', async () => {
      const first = await record(handlers, {
        kind: 'hook-point',
        key: 'libfoo.so!0x1000',
        metadata: { module: 'libfoo.so' },
      });
      vi.advanceTimersByTime(1000);
      const second = await record(handlers, {
        kind: 'hook-point',
        key: 'libfoo.so!0x1000',
        metadata: { module: 'libfoo.so', notes: 'confirmed' },
      });

      expect(first.created).toBe(true);
      expect(second.created).toBe(false);
      expect(second.recorded).toBe(true);

      const body = await coverage(handlers, { kind: 'hook-point' });
      expect(body.entries).toHaveLength(1);
      expect(body.entries[0]?.metadata).toEqual({ module: 'libfoo.so', notes: 'confirmed' });
      expect(body.counts.hookPoint).toBe(1);
    });

    it('keeps the original recordedAt when re-recording', async () => {
      await record(handlers, { kind: 'process', key: 'pid:1', metadata: { v: 1 } });
      const before = (await coverage(handlers)).entries[0]?.recordedAt;
      vi.advanceTimersByTime(5000);
      await record(handlers, { kind: 'process', key: 'pid:1', metadata: { v: 2 } });
      const after = (await coverage(handlers)).entries[0]?.recordedAt;

      expect(after).toBe(before);
    });

    it('rejects an invalid kind with an actionable error', async () => {
      const body = await record(handlers, { kind: 'bogus', key: 'x' });

      expect(body.success).toBe(false);
      expect(body.error).toContain('Invalid kind');
    });

    it('rejects an empty key', async () => {
      const body = await record(handlers, { kind: 'process', key: '' });

      expect(body.success).toBe(false);
      expect(body.error).toContain('key is required');
    });

    it('rejects non-object metadata', async () => {
      const body = await record(handlers, { kind: 'process', key: 'x', metadata: 'oops' });

      expect(body.success).toBe(false);
      expect(body.error).toContain('metadata must be a plain object');
    });

    it('rejects a new entry beyond the per-(session, kind) cap but keeps updates working', async () => {
      for (let i = 0; i < 500; i++) {
        await record(handlers, { kind: 'protocol-field', key: `field.${i}` });
      }
      const overCap = await record(handlers, { kind: 'protocol-field', key: 'field.overflow' });

      expect(overCap.success).toBe(false);
      expect(overCap.error).toContain('maximum of 500');
      expect(overCap.error).toContain('session "default"');

      // Existing (kind, key) updates stay allowed at the cap
      const update = await record(handlers, {
        kind: 'protocol-field',
        key: 'field.0',
        metadata: { patched: true },
      });
      expect(update.success).toBe(true);
      expect(update.created).toBe(false);

      // Other kinds are unaffected by the cap on this kind
      const otherKind = await record(handlers, { kind: 'process', key: 'pid:1' });
      expect(otherKind.success).toBe(true);
    });
  });

  // ── coverage ──

  describe('session_progress_coverage', () => {
    it('returns zero counts and empty entries for an unknown session', async () => {
      const body = await coverage(handlers, { sessionId: 'unknown' });

      expect(body.success).toBe(true);
      expect(body.sessionId).toBe('unknown');
      expect(body.counts).toEqual({ process: 0, hookPoint: 0, protocolField: 0 });
      expect(body.entries).toEqual([]);
      expect(body.total).toBe(0);
    });

    it('sorts entries newest-first by recordedAt', async () => {
      await record(handlers, { kind: 'process', key: 'a.first' });
      vi.advanceTimersByTime(100);
      await record(handlers, { kind: 'hook-point', key: 'b.second' });
      vi.advanceTimersByTime(100);
      await record(handlers, { kind: 'protocol-field', key: 'c.third' });

      const body = await coverage(handlers);

      expect(body.entries.map((e) => e.key)).toEqual(['c.third', 'b.second', 'a.first']);
      expect(body.total).toBe(3);
      // ISO timestamps
      expect(body.entries[0]?.recordedAt).toBe('2026-01-01T00:00:00.200Z');
    });

    it('filters entries by kind while counts stay session-wide', async () => {
      await record(handlers, { kind: 'process', key: 'p1' });
      await record(handlers, { kind: 'hook-point', key: 'h1' });
      await record(handlers, { kind: 'hook-point', key: 'h2' });

      const body = await coverage(handlers, { kind: 'hook-point' });

      expect(body.counts).toEqual({ process: 1, hookPoint: 2, protocolField: 0 });
      // Same-millisecond records tie-break deterministically by key
      expect(body.entries.map((e) => e.key)).toEqual(['h1', 'h2']);
      expect(body.total).toBe(2);
    });

    it('includes metadata on entries when recorded', async () => {
      await record(handlers, {
        kind: 'protocol-field',
        key: 'msg.seq',
        metadata: { wireType: 0, offset: 12 },
      });
      await record(handlers, { kind: 'process', key: 'pid:7' });

      const body = await coverage(handlers);
      const withMeta = body.entries.find((e) => e.key === 'msg.seq');

      expect(withMeta?.metadata).toEqual({ wireType: 0, offset: 12 });
      expect(body.entries.find((e) => e.key === 'pid:7')?.metadata).toBeUndefined();
    });
  });

  // ── clear ──

  describe('session_progress_clear', () => {
    it('clears all kinds for the session and reports the removed count', async () => {
      await record(handlers, { kind: 'process', key: 'p1' });
      await record(handlers, { kind: 'hook-point', key: 'h1' });
      await record(handlers, { kind: 'protocol-field', key: 'f1' });

      const cleared = await clear(handlers);
      const body = await coverage(handlers);

      expect(cleared.cleared).toBe(3);
      expect(cleared.sessionId).toBe('default');
      expect(body.counts).toEqual({ process: 0, hookPoint: 0, protocolField: 0 });
      expect(body.entries).toEqual([]);
    });

    it('clears only the requested kind', async () => {
      await record(handlers, { kind: 'process', key: 'p1' });
      await record(handlers, { kind: 'hook-point', key: 'h1' });
      await record(handlers, { kind: 'hook-point', key: 'h2' });

      const cleared = await clear(handlers, { kind: 'hook-point' });
      const body = await coverage(handlers);

      expect(cleared.cleared).toBe(2);
      expect(cleared.kind).toBe('hook-point');
      expect(body.counts).toEqual({ process: 1, hookPoint: 0, protocolField: 0 });
    });

    it('returns cleared 0 for an unknown session', async () => {
      const cleared = await clear(handlers, { sessionId: 'nope' });

      expect(cleared.cleared).toBe(0);
      expect(cleared.success).toBe(true);
    });

    it('clears are repeatable (idempotent)', async () => {
      await record(handlers, { kind: 'process', key: 'p1' });
      expect((await clear(handlers)).cleared).toBe(1);
      expect((await clear(handlers)).cleared).toBe(0);
    });
  });

  // ── multi-session isolation ──

  describe('multi-session isolation', () => {
    it('keeps per-session ledgers independent', async () => {
      await record(handlers, { sessionId: 'target-a', kind: 'process', key: 'pid:1' });
      await record(handlers, { sessionId: 'target-b', kind: 'hook-point', key: 'h!1' });

      const a = await coverage(handlers, { sessionId: 'target-a' });
      const b = await coverage(handlers, { sessionId: 'target-b' });
      const fallback = await coverage(handlers);

      expect(a.counts).toEqual({ process: 1, hookPoint: 0, protocolField: 0 });
      expect(a.entries.map((e) => e.key)).toEqual(['pid:1']);
      expect(b.counts).toEqual({ process: 0, hookPoint: 1, protocolField: 0 });
      expect(b.entries.map((e) => e.key)).toEqual(['h!1']);
      expect(fallback.counts).toEqual({ process: 0, hookPoint: 0, protocolField: 0 });
    });

    it('clearing one session leaves others untouched', async () => {
      await record(handlers, { sessionId: 'target-a', kind: 'process', key: 'pid:1' });
      await record(handlers, { sessionId: 'target-b', kind: 'process', key: 'pid:2' });

      const cleared = await clear(handlers, { sessionId: 'target-a' });
      const b = await coverage(handlers, { sessionId: 'target-b' });

      expect(cleared.cleared).toBe(1);
      expect(b.counts.process).toBe(1);
    });

    it('enforces the per-kind cap independently per session', async () => {
      for (let i = 0; i < 500; i++) {
        await record(handlers, { sessionId: 's1', kind: 'process', key: `p.${i}` });
      }
      const s1Over = await record(handlers, { sessionId: 's1', kind: 'process', key: 'p.new' });
      const s2SameKey = await record(handlers, { sessionId: 's2', kind: 'process', key: 'p.0' });

      expect(s1Over.success).toBe(false);
      expect(s2SameKey.success).toBe(true);
      expect(s2SameKey.sessionId).toBe('s2');
    });
  });
});
