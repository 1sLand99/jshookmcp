import { describe, expect, it, vi, beforeEach } from 'vitest';
import { CoordinationHandlers } from '@server/domains/coordination/index';
import { TEST_URLS, withPath } from '@tests/shared/test-urls';

/* eslint-disable @typescript-eslint/no-explicit-any */

describe('CoordinationHandlers — page snapshots (IndexedDB capture)', () => {
  const pageController: any = { getPage: vi.fn() };
  let handlers: CoordinationHandlers;

  beforeEach(() => {
    vi.clearAllMocks();
    handlers = new CoordinationHandlers({ pageController } as any);
  });

  function makePage(opts: { idb: unknown; cookies?: unknown[] }) {
    return {
      url: () => withPath(TEST_URLS.root, 'app'),
      createCDPSession: vi.fn().mockResolvedValue({
        send: vi.fn().mockResolvedValue({ cookies: opts.cookies ?? [] }),
        detach: vi.fn(),
      }),
      evaluate: vi.fn().mockImplementation((arg: unknown) => {
        // The IndexedDB probe is sent as a serialized string; localStorage and
        // sessionStorage captures are sent as functions. Route accordingly.
        if (typeof arg === 'string') return Promise.resolve(opts.idb);
        return Promise.resolve({});
      }),
    };
  }

  it('save_page_snapshot captures IndexedDB metadata when present', async () => {
    const idb = [
      {
        name: 'authDB',
        version: 1,
        stores: [{ name: 'tokens', count: 3, keyPath: 'id' }],
      },
    ];
    pageController.getPage.mockResolvedValue(makePage({ idb }));

    const res = (await handlers.handleSavePageSnapshot({
      label: 'with-idb',
    })) as Record<string, unknown>;

    expect(res.snapshotId).toBeDefined();
    expect(res.indexedDBDatabaseCount).toBe(1);
    expect(res.url).toBe(withPath(TEST_URLS.root, 'app'));
  });

  it('save_page_snapshot captures multiple IndexedDB databases', async () => {
    const idb = [
      { name: 'cacheDb', stores: [{ name: 'responses', count: 12 }] },
      { name: 'firebaseDb', version: 4, stores: [{ name: 'users', count: 2 }] },
    ];
    pageController.getPage.mockResolvedValue(makePage({ idb }));

    const res = (await handlers.handleSavePageSnapshot({})) as Record<string, unknown>;

    expect(res.indexedDBDatabaseCount).toBe(2);
  });

  it('save_page_snapshot proceeds without IndexedDB (null capture)', async () => {
    pageController.getPage.mockResolvedValue(makePage({ idb: null }));

    const res = (await handlers.handleSavePageSnapshot({
      label: 'no-idb',
    })) as Record<string, unknown>;

    expect(res.snapshotId).toBeDefined();
    expect(res.indexedDBDatabaseCount).toBe(0);
  });

  it('save_page_snapshot is resilient when IndexedDB capture throws (cross-origin)', async () => {
    const page = makePage({ idb: [] });
    page.evaluate.mockImplementation((arg: unknown) => {
      if (typeof arg === 'string') return Promise.reject(new Error('cross-origin blocked'));
      return Promise.resolve({});
    });
    pageController.getPage.mockResolvedValue(page);

    const res = (await handlers.handleSavePageSnapshot({})) as Record<string, unknown>;

    expect(res.snapshotId).toBeDefined();
    expect(res.indexedDBDatabaseCount).toBe(0);
  });
});
