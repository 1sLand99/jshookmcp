import { describe, expect, it, vi } from 'vitest';
import { BrowserSessionCoordinator } from '@server/runtime/BrowserSessionCoordinator';

describe('BrowserSessionCoordinator', () => {
  it('provides isolated TabRegistry instances per session', () => {
    const collector = {
      selectPage: vi.fn(async () => undefined),
      attachCdpTarget: vi.fn(async () => ({ targetId: 't-1' })),
    } as any;
    const coordinator = new BrowserSessionCoordinator(() => collector);

    const a = coordinator.getTabRegistry('session-a');
    const b = coordinator.getTabRegistry('session-b');

    expect(a).not.toBe(b);

    a.setSharedContext('owner', 'a');
    b.setSharedContext('owner', 'b');

    expect(a.getSharedContext('owner').value).toBe('a');
    expect(b.getSharedContext('owner').value).toBe('b');
  });

  it('restores saved page context when switching sessions', async () => {
    const collector = {
      selectPage: vi.fn(async () => undefined),
      attachCdpTarget: vi.fn(async () => ({ targetId: 't-1' })),
    } as any;
    const coordinator = new BrowserSessionCoordinator(() => collector);

    coordinator.noteToolResult('session-a', 'browser_attach', {
      currentTabIndex: 2,
      currentPageId: 'tab-2',
      currentTargetId: null,
    });
    coordinator.noteToolResult('session-b', 'browser_attach_cdp_target', {
      currentTabIndex: 4,
      currentPageId: 'tab-4',
      currentTargetId: 'target-4',
    });

    await coordinator.restoreSessionContext('session-a');
    await coordinator.restoreSessionContext('session-b');

    expect(collector.selectPage).toHaveBeenNthCalledWith(1, 2);
    expect(collector.selectPage).toHaveBeenNthCalledWith(2, 4);
    expect(collector.attachCdpTarget).toHaveBeenCalledWith('target-4');
  });

  it('drops state when the owning HTTP session closes', () => {
    const coordinator = new BrowserSessionCoordinator(() => null);
    const original = coordinator.getTabRegistry('session-a');
    original.setSharedContext('owner', 'a');

    expect(coordinator.dropSession('session-a')).toBe(true);
    expect(coordinator.dropSession('session-a')).toBe(false);
    expect(coordinator.getTabRegistry('session-a')).not.toBe(original);
  });
});
