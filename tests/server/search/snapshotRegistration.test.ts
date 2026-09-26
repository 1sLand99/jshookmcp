/**
 * Tests for search-tracker snapshot registration.
 *
 * The FeedbackTracker and SearchQualityTracker both implement the
 * SnapshotSource contract, but they live inside the lazily-built
 * ToolSearchEngine, so wiring them into the RuntimeSnapshotScheduler happens
 * at engine-construction time via registerSearchSnapshotSources
 * (src/server/search/snapshotRegistration.ts).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { resolve } from 'node:path';
import {
  registerSearchSnapshotSources,
  registerSearchSnapshotSourcesFromCtx,
} from '@server/search/snapshotRegistration';
import {
  RuntimeSnapshotScheduler,
  getStateDir,
} from '@server/persistence/RuntimeSnapshotScheduler';
import type { ToolSearchEngine } from '@server/search/ToolSearchEngine';

function fakeEngine(trackers: { feedback?: unknown; quality?: unknown } = {}): unknown {
  return {
    getFeedbackTracker: () => trackers.feedback ?? { name: 'feedback' },
    getSearchQualityTracker: () => trackers.quality ?? { name: 'quality' },
  };
}

const state = vi.hoisted(() => ({
  engine: {} as ToolSearchEngine,
}));

// getSearchEngine is mocked to return a real engine instance built by each
// test; the handlers then exercise the real registration path.
vi.mock('@server/MCPServer.search.helpers', () => ({
  getSearchEngine: async () => state.engine,
  getActiveToolNames: () => new Set<string>(),
  getVisibleDomainsForTier: () => new Set<string>(),
  getBaseTier: () => 'search',
}));

vi.mock('@server/domains/shared/response', () => ({
  asTextResponse: (text: string) => ({ content: [{ type: 'text', text }] }),
}));

vi.mock('@server/ToolRouter', () => ({
  describeTool: () => ({ name: 'x', inputSchema: {} }),
  generateExampleArgs: () => ({}),
}));

vi.mock('@server/MCPServer.search.handlers.activate', () => ({
  activateToolNames: async () => ({ activated: [], alreadyActive: [], notFound: [] }),
  notifyToolListChanged: async () => undefined,
}));

vi.mock('@src/constants', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@src/constants')>()),
  SEARCH_AUTO_ACTIVATE_DOMAINS: false,
  ACTIVATION_TTL_MINUTES: 30,
}));

import { handleSearchTools } from '@server/MCPServer.search.handlers.search';

describe('registerSearchSnapshotSources', () => {
  it('registers both trackers under distinct file names in the state dir', () => {
    const register = vi.fn();
    const scheduler = { register } as unknown as RuntimeSnapshotScheduler;

    const registered = registerSearchSnapshotSources(
      scheduler,
      fakeEngine() as never,
      resolve('tmp-state'),
    );

    expect(registered.feedbackTracker).toEqual({ name: 'feedback' });
    expect(registered.qualityTracker).toEqual({ name: 'quality' });

    expect(register).toHaveBeenCalledTimes(2);
    expect(register).toHaveBeenCalledWith(
      resolve('tmp-state', 'search-feedback.json'),
      expect.objectContaining({ name: 'feedback' }),
    );
    expect(register).toHaveBeenCalledWith(
      resolve('tmp-state', 'search-quality.json'),
      expect.objectContaining({ name: 'quality' }),
    );
  });

  it('skips gracefully when the ctx has no scheduler or state dir', () => {
    // A bare ctx (no domain instances) must not throw — registration is a
    // no-op, exactly like a profile whose engine was never built.
    expect(() =>
      registerSearchSnapshotSourcesFromCtx({} as never, fakeEngine() as never),
    ).not.toThrow();
  });

  it('skips gracefully when getDomainInstance is missing entirely', () => {
    expect(() =>
      registerSearchSnapshotSourcesFromCtx(
        { getDomainInstance: undefined } as never,
        fakeEngine() as never,
      ),
    ).not.toThrow();
  });

  it('is idempotent: a second registration does not grow the scheduler sources', () => {
    // The engine is cached per ctx, so registerSearchSnapshotSources can run
    // on every search/route/call_tool — the scheduler must not accumulate
    // duplicate entries.
    const scheduler = new RuntimeSnapshotScheduler();

    registerSearchSnapshotSources(scheduler, fakeEngine() as never, resolve('tmp-state'));
    registerSearchSnapshotSources(scheduler, fakeEngine() as never, resolve('tmp-state'));

    expect(scheduler.getRegisteredSources()).toHaveLength(2);
    expect(scheduler.getRegisteredSources()?.map((s) => s.filePath)).toEqual([
      resolve('tmp-state', 'search-feedback.json'),
      resolve('tmp-state', 'search-quality.json'),
    ]);
  });

  it('works with real tracker instances (SnapshotSource contract shape)', () => {
    const scheduler = new RuntimeSnapshotScheduler();
    const feedback = {
      isPersistDirty: () => true,
      exportSnapshot: () => ({ vectorWeight: 0.55 }),
      restoreSnapshot: () => undefined,
      markPersisted: () => undefined,
    };
    const quality = {
      isPersistDirty: () => false,
      exportSnapshot: () => ({ lastRecordId: null, records: [] }),
      restoreSnapshot: () => undefined,
      markPersisted: () => undefined,
    };
    const registered = registerSearchSnapshotSources(
      scheduler,
      fakeEngine({ feedback, quality }) as never,
      resolve('tmp-state'),
    );

    expect(registered.feedbackTracker).toBe(feedback);
    expect(registered.qualityTracker).toBe(quality);
    expect(scheduler.getRegisteredSources()).toHaveLength(2);
  });
});

describe('handler registration wiring', () => {
  let scheduler: RuntimeSnapshotScheduler;
  let stateDir: string;

  beforeEach(() => {
    scheduler = new RuntimeSnapshotScheduler();
    stateDir = getStateDir();
  });

  it('handleSearchTools registers the engine trackers with the scheduler', async () => {
    // A real engine exposes real FeedbackTracker / SearchQualityTracker
    // instances; both must end up in the scheduler after one search.
    const engine = {
      search: vi.fn(async () => []),
      getFeedbackTracker: () => ({ isPersistDirty: () => false }),
      getSearchQualityTracker: () => ({
        getEnhancementSuggestions: () => null,
        isPersistDirty: () => false,
      }),
    };
    state.engine = engine as unknown as ToolSearchEngine;

    const ctx = {
      enabledDomains: new Set<string>(),
      mcpLog: { info: vi.fn() },
      getDomainInstance: <T>(key: string) =>
        (key === 'snapshotScheduler'
          ? scheduler
          : key === 'snapshotStateDir'
            ? stateDir
            : undefined) as unknown as T,
    } as any;

    await handleSearchTools(ctx, { query: 'hook fetch' });

    const sources = scheduler.getRegisteredSources();
    expect(sources.map((s) => s.filePath)).toEqual([
      resolve(stateDir, 'search-feedback.json'),
      resolve(stateDir, 'search-quality.json'),
    ]);
  });

  it('skips registration gracefully when no scheduler/state dir is configured', async () => {
    // ctx without domain instances (bare test context) must not throw.
    const engine = {
      search: vi.fn(async () => []),
      getFeedbackTracker: () => ({ isPersistDirty: () => false }),
      getSearchQualityTracker: () => ({
        getEnhancementSuggestions: () => null,
        isPersistDirty: () => false,
      }),
    };
    state.engine = engine as unknown as ToolSearchEngine;

    const ctx = {
      enabledDomains: new Set<string>(),
      mcpLog: { info: vi.fn() },
      getDomainInstance: () => undefined,
    } as any;

    await expect(handleSearchTools(ctx, { query: 'hook fetch' })).resolves.toBeDefined();
  });
});
