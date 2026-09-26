/**
 * Production wiring for `AutoPruner` inside `ActivationController`.
 *
 * Two "the name promises, the code no-ops" defects are pinned down here:
 *
 *  1. `onPrune` only logged. The sweep announced a prune (a log line plus
 *     `activation:domain_pruned`, whose only subscriber also just logged) while
 *     every tool stayed activated and routed, so the event asserted a state
 *     change that never happened.
 *  2. `markAutoActivated` had no production caller at all. `autoActivatedDomains`
 *     therefore stayed empty for the life of the process and
 *     `AUTOPRUNE_AUTO_INACTIVITY_MS` was unreachable — the "auto-activated
 *     domains get a shorter leash" half of the documented design never ran.
 *
 * `AutoPruner` itself (threshold arithmetic, base-tier exclusion, event
 * emission) is already covered by `AutoPruner.test.ts`. These tests cover only
 * the controller-level wiring, so `deactivateDomainOnExpiry` is mocked and the
 * assertion is on the call that was missing.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventBus, type ServerEventMap } from '@server/EventBus';
import { AUTOPRUNE_CHECK_INTERVAL_MS, AUTOPRUNE_MANUAL_INACTIVITY_MS } from '@src/constants';

const state = vi.hoisted(() => ({
  handleActivateDomain: vi.fn(
    async (ctx: { enabledDomains: Set<string> }, args: { domain: string }) => {
      ctx.enabledDomains.add(args.domain);
      return { content: [{ type: 'text', text: '{"success":true}' }] };
    },
  ),
  deactivateDomainOnExpiry: vi.fn(async () => undefined),
}));

vi.mock('@server/ToolCatalog', () => ({
  getToolDomain: vi.fn((name: string) => {
    if (name.startsWith('page_')) return 'browser';
    if (name.startsWith('debug_')) return 'debugger';
    return null;
  }),
  getProfileDomains: vi.fn(() => ['browser']),
}));

vi.mock('@server/MCPServer.search.handlers.domain', () => ({
  handleActivateDomain: state.handleActivateDomain,
}));

vi.mock('@server/MCPServer.activation.ttl', () => ({
  deactivateDomainOnExpiry: state.deactivateDomainOnExpiry,
  startDomainTtl: vi.fn(),
  refreshDomainTtl: vi.fn(),
  refreshDomainTtlForTool: vi.fn(),
  clearDomainTtl: vi.fn(),
}));

describe('activation/ActivationController -> AutoPruner (production wiring)', () => {
  let eventBus: EventBus<ServerEventMap>;
  let mockCtx: { enabledDomains: Set<string>; baseTier: string };

  beforeEach(() => {
    vi.resetModules();
    eventBus = new EventBus<ServerEventMap>();
    mockCtx = { enabledDomains: new Set<string>(), baseTier: 'search' };
    state.handleActivateDomain.mockClear();
    state.deactivateDomainOnExpiry.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('evicts the pruned domain through the TTL teardown instead of only logging', async () => {
    vi.useFakeTimers();
    const { ActivationController } = await import('@server/activation/ActivationController');
    const controller = new ActivationController(eventBus, mockCtx as never);

    // 'debugger' is not base tier, so it is prunable. Recording activity is what
    // the sweep iterates; the tool:called -> recordActivity link is covered by
    // the existing "tracks domain activity" test.
    controller.getAutoPruner().recordActivity('debugger');

    // One sweep tick past the manual-inactivity threshold.
    vi.advanceTimersByTime(AUTOPRUNE_MANUAL_INACTIVITY_MS + AUTOPRUNE_CHECK_INTERVAL_MS);

    expect(state.deactivateDomainOnExpiry).toHaveBeenCalledWith(mockCtx, 'debugger');

    controller.dispose();
  });

  it('never evicts a base-tier domain', async () => {
    vi.useFakeTimers();
    const { ActivationController } = await import('@server/activation/ActivationController');
    const controller = new ActivationController(eventBus, mockCtx as never);

    // 'browser' is base tier via getProfileDomains.
    controller.getAutoPruner().recordActivity('browser');

    vi.advanceTimersByTime(AUTOPRUNE_MANUAL_INACTIVITY_MS * 2);

    expect(state.deactivateDomainOnExpiry).not.toHaveBeenCalled();

    controller.dispose();
  });

  it('flags a boosted domain as auto-activated so it earns the shorter leash', async () => {
    const { ActivationController } = await import('@server/activation/ActivationController');
    const controller = new ActivationController(eventBus, mockCtx as never);

    // debugger:breakpoint_hit is a default boost rule -> attemptBoost('debugger').
    await eventBus.emit('debugger:breakpoint_hit', {
      scriptId: '1',
      lineNumber: 10,
      timestamp: new Date().toISOString(),
    });
    // attemptBoost is fire-and-forget; let its awaited activation settle.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(state.handleActivateDomain).toHaveBeenCalledTimes(1);
    expect(controller.getAutoPruner().isAutoActivated('debugger')).toBe(true);

    controller.dispose();
  });

  it('does not flag a boost as auto-activation when activation reports failure', async () => {
    // handleActivateDomain reports a rejected domain by RETURNING
    // { success: false } and never throws, so gating on "did not throw" used to
    // mark an unregistered domain as auto-activated — seeding lastActivity and
    // letting the pruner later emit activation:domain_pruned for a domain that
    // was never activated.
    state.handleActivateDomain.mockImplementationOnce(
      async (ctx: { enabledDomains: Set<string> }, args: { domain: string }) => {
        ctx.enabledDomains.add(args.domain);
        return {
          content: [{ type: 'text', text: '{"success":false,"error":"Unknown domain"}' }],
        };
      },
    );

    const { ActivationController } = await import('@server/activation/ActivationController');
    const controller = new ActivationController(eventBus, mockCtx as never);

    await eventBus.emit('debugger:breakpoint_hit', {
      scriptId: '1',
      lineNumber: 10,
      timestamp: new Date().toISOString(),
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(state.handleActivateDomain).toHaveBeenCalledTimes(1);
    expect(controller.getAutoPruner().isAutoActivated('debugger')).toBe(false);
    // markAutoActivated also seeds lastActivity; a failed boost must seed neither.
    expect(controller.getAutoPruner().getLastActivity('debugger')).toBeUndefined();

    controller.dispose();
  });

  it('does not flag plain activity as auto-activation (control)', async () => {
    const { ActivationController } = await import('@server/activation/ActivationController');
    const controller = new ActivationController(eventBus, mockCtx as never);

    // Deliberately driven through recordActivity alone rather than a
    // tool:called event: that event also feeds the predictive booster, which
    // can legitimately reach attemptBoost and mark the domain auto-activated.
    // The point of this control is narrower and exact — tracking activity must
    // not by itself set the auto-activated flag, otherwise the test above would
    // pass for the wrong reason.
    controller.getAutoPruner().recordActivity('memory');

    expect(controller.getAutoPruner().isAutoActivated('memory')).toBe(false);
    expect(controller.getAutoPruner().getLastActivity('memory')).toBeGreaterThan(0);

    controller.dispose();
  });
});
