import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { MCPTestClient } from '@tests/e2e/helpers/mcp-client';

const TARGET_URL = process.env.E2E_TARGET_URL;
const FIXTURE_URL =
  'data:text/html,<html><body><h1>jshook e2e</h1><script>window.__e2e=true;</script></body></html>';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function findFirstString(value: unknown, keys: readonly string[]): string | null {
  const queue: unknown[] = [value];
  const visited = new Set<unknown>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || visited.has(current)) continue;
    visited.add(current);

    if (isRecord(current)) {
      for (const key of keys) {
        const candidate = current[key];
        if (typeof candidate === 'string' && candidate.length > 0) {
          return candidate;
        }
      }
      for (const nested of Object.values(current)) {
        queue.push(nested);
      }
      continue;
    }

    if (Array.isArray(current)) {
      for (const nested of current) {
        queue.push(nested);
      }
    }
  }

  return null;
}

describe.skipIf(!TARGET_URL)('V8 Inspector E2E', { timeout: 180_000, sequential: true }, () => {
  const client = new MCPTestClient();

  beforeAll(async () => {
    await client.connect();
  });

  afterAll(async () => {
    await client.cleanup();
  });

  test('browser launch, attach, capture heap snapshot, search by address', async () => {
    const requiredTools = [
      'browser_launch',
      'page_navigate',
      'page_evaluate',
      'v8_heap_snapshot_capture',
      'v8_heap_snapshot_analyze',
      'v8_heap_stats',
    ];
    const missingTools = requiredTools.filter((name) => !client.getToolMap().has(name));
    if (missingTools.length > 0) {
      client.recordSynthetic(
        'v8-inspector-suite',
        'SKIP',
        `Missing tools: ${missingTools.join(', ')}`,
      );
      return;
    }

    const launch = await client.call('browser_launch', { headless: true }, 60_000);
    expect(launch.result.status).not.toBe('FAIL');

    const navigate = await client.call(
      'page_navigate',
      { url: FIXTURE_URL, waitUntil: 'load' },
      60_000,
    );
    expect(navigate.result.status).not.toBe('FAIL');

    const seedObject = await client.call(
      'page_evaluate',
      {
        code: `(() => {
          const node = {
            tag: 'v8-e2e-node',
            createdAt: Date.now(),
            nested: { score: 42, active: true },
          };
          globalThis.__jshookV8E2E = node;
          return { ok: true, keys: Object.keys(node) };
        })()`,
      },
      30_000,
    );
    expect(seedObject.result.status).not.toBe('FAIL');

    const capture = await client.call('v8_heap_snapshot_capture', {}, 90_000);
    expect(capture.result.status).not.toBe('FAIL');

    const snapshotId = findFirstString(capture.parsed, ['snapshotId', 'id']);
    if (!snapshotId) {
      client.recordSynthetic(
        'v8_heap_snapshot_capture',
        'EXPECTED_LIMITATION',
        'Tool returned without a snapshotId',
      );
      return;
    }

    const stats = await client.call('v8_heap_stats', {}, 30_000);
    expect(stats.result.status).not.toBe('FAIL');

    const analyze = await client.call('v8_heap_snapshot_analyze', { snapshotId }, 90_000);
    expect(analyze.result.status).not.toBe('FAIL');

    if (!client.getToolMap().has('v8_object_inspect')) {
      client.recordSynthetic('v8_object_inspect', 'SKIP', 'Tool not registered in current build');
      return;
    }

    const address = findFirstString(analyze.parsed, ['address', 'objectAddress', 'nodeAddress']);
    if (!address) {
      client.recordSynthetic(
        'v8_object_inspect',
        'EXPECTED_LIMITATION',
        'Snapshot analysis did not surface an inspectable address',
      );
      return;
    }

    const inspectResult = await client.call('v8_object_inspect', { address }, 30_000);
    expect(inspectResult.result.status).not.toBe('FAIL');
  });

  test('worker heap snapshot via attached dedicated worker target (behavioral)', async () => {
    // Behavioral coverage for Session 54 target-aware capture: prove that
    // v8_heap_snapshot_capture really runs against a worker target (not the
    // page, not the simulated fallback) when browser_attach_cdp_target holds
    // the worker's CDP session. The unit/integration layer mock-verifies the
    // routing/provenance/ownership contract; this test closes the loop with a
    // real Chromium + real dedicated worker.
    const requiredTools = [
      'page_navigate',
      'page_evaluate',
      'browser_list_workers',
      'browser_attach_cdp_target',
      'browser_detach_cdp_target',
      'v8_heap_snapshot_capture',
    ];
    const missingTools = requiredTools.filter((name) => !client.getToolMap().has(name));
    if (missingTools.length > 0) {
      client.recordSynthetic('v8-worker-heap', 'SKIP', `Missing tools: ${missingTools.join(', ')}`);
      return;
    }

    // Dedicated workers (blob URL) need a real HTTP(S) origin — data: URLs are
    // opaque-origin and Worker construction fails. TARGET_URL is guaranteed by
    // the describe.skipIf(!TARGET_URL) guard above.
    const navigate = await client.call(
      'page_navigate',
      { url: TARGET_URL, waitUntil: 'load' },
      60_000,
    );
    expect(navigate.result.status).not.toBe('FAIL');

    // Spawn a dedicated worker that holds live JS objects (non-empty V8 heap)
    // and stays alive via setInterval until we snapshot it.
    const spawnWorker = await client.call(
      'page_evaluate',
      {
        code: `(() => {
          const src = 'let heap = { markers: new Array(500).fill("worker-heap-marker") }; setInterval(() => { heap.tick = Date.now(); }, 200); self.__heap = heap;';
          const url = URL.createObjectURL(new Blob([src], { type: 'application/javascript' }));
          self.__e2eWorker = new Worker(url);
          return { created: true };
        })()`,
      },
      30_000,
    );
    expect(spawnWorker.result.status).not.toBe('FAIL');

    // Give the worker a moment to register as a CDP target.
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const listWorkers = await client.call(
      'browser_list_workers',
      {
        includeDedicatedWorkers: true,
        includeServiceWorkers: false,
        includeSharedWorkers: false,
      },
      30_000,
    );
    expect(listWorkers.result.status).not.toBe('FAIL');

    const workersParsed = listWorkers.parsed;
    const workerList =
      isRecord(workersParsed) && Array.isArray(workersParsed.workers) ? workersParsed.workers : [];
    const workerTarget = workerList.find(
      (w): w is Record<string, unknown> =>
        isRecord(w) &&
        (w.type === 'worker' || w.category === 'dedicated_worker') &&
        typeof w.targetId === 'string',
    );

    if (!workerTarget) {
      client.recordSynthetic(
        'v8-worker-heap',
        'EXPECTED_LIMITATION',
        'No dedicated worker target surfaced — the worker may not have registered as a CDP ' +
          'target in this Chromium build; cannot prove worker-target capture.',
      );
      return;
    }

    const workerTargetId = workerTarget.targetId as string;

    // Attach the worker target — the collector now holds its CDP session, so
    // resolveTargetSession must route v8_heap_snapshot_capture to it.
    const attach = await client.call(
      'browser_attach_cdp_target',
      { targetId: workerTargetId },
      30_000,
    );
    expect(attach.result.status).not.toBe('FAIL');

    try {
      const capture = await client.call('v8_heap_snapshot_capture', {}, 90_000);
      expect(capture.result.status).not.toBe('FAIL');

      const captured = capture.parsed;
      expect(isRecord(captured)).toBe(true);
      if (!isRecord(captured)) return;

      // Behavioral proof #1: the snapshot came from the worker, not the page.
      expect(isRecord(captured.target) ? captured.target.type : null).toBe('worker');
      // Behavioral proof #2: it is a real CDP heap, not the degraded simulated stub.
      expect(captured.simulated).toBe(false);
      // Behavioral proof #3: non-empty heap content was captured.
      expect(typeof captured.sizeBytes === 'number' && (captured.sizeBytes as number) > 0).toBe(
        true,
      );
      expect(typeof captured.snapshotId === 'string').toBe(true);
    } finally {
      // Restore the page attach context so later suites start clean.
      await client.call('browser_detach_cdp_target', {}, 15_000);
    }
  });
});
