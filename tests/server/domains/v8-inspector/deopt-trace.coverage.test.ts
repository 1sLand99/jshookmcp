/**
 * Coverage tests for handleDeoptTrace — exercises the no-CDP-session early
 * return and the natives-unavailable path (mock page that yields a session
 * whose Runtime.evaluate reports natives syntax missing).
 */

import { describe, expect, it, vi } from 'vitest';
import { handleDeoptTrace } from '@server/domains/v8-inspector/handlers/deopt-trace';

describe('handleDeoptTrace — no CDP session', () => {
  it('returns unavailable when getPage resolves to undefined', async () => {
    const r = await handleDeoptTrace({ durationMs: 100, maxEvents: 5 }, async () => undefined);
    expect(r.success).toBe(false);
    expect(r.mode).toBe('unavailable');
    expect(r.eventCount).toBe(0);
    expect(r.summary).toMatch(/CDP session unavailable/);
  });

  it('returns unavailable when getPage is omitted entirely', async () => {
    const r = await handleDeoptTrace({ durationMs: 100 });
    expect(r.success).toBe(false);
    expect(r.mode).toBe('unavailable');
  });
});

describe('handleDeoptTrace — natives syntax unavailable', () => {
  it('returns unavailable-mode when the target lacks %TraceDeoptimizations', async () => {
    // Mock page exposing createCDPSession; the resulting session's evaluate
    // throws → checkNativesSupport returns false → early "natives unavailable".
    const send = vi.fn().mockRejectedValue(new Error('not available'));
    const session = { send, detach: vi.fn().mockResolvedValue(undefined) };
    const page = {
      createCDPSession: async () => session,
    };
    const r = await handleDeoptTrace({ durationMs: 100 }, async () => page);
    expect(r.success).toBe(true);
    expect(r.mode).toBe('unavailable');
    expect(r.summary).toMatch(/natives syntax/);
    expect(session.detach).toHaveBeenCalled();
  });
});
