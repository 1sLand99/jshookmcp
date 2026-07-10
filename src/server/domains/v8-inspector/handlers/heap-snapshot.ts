import { V8InspectorClient } from '@modules/v8-inspector/V8InspectorClient';
import { enforceSnapshotRetention, persistSnapshot } from './snapshot-persistence';

export interface StoredHeapSnapshot {
  id: string;
  chunks: string[];
  capturedAt: string;
  sizeBytes: number;
  /** True when the snapshot is a degraded/size-only capture rather than real CDP data. */
  simulated?: boolean;
  /** Optional provenance hint (page URL) captured alongside the snapshot. */
  targetUrl?: string | null;
  /** Absolute + project-relative path of the persisted .heapsnapshot file, when written. */
  persisted?: { absolutePath: string; displayPath: string };
}

const snapshotCache = new Map<string, StoredHeapSnapshot>();

export interface HeapSnapshotHandlerOptions {
  getPage: () => Promise<unknown>;
  getSnapshot: () => string | null;
  setSnapshot: (snapshot: string | null) => void;
  client?: V8InspectorClient;
  /** Persist the captured snapshot to artifacts/heap-snapshots/ (default: true). */
  persist?: boolean;
  /** Optional accessor for the current page URL, recorded as snapshot provenance. */
  getTargetUrl?: () => Promise<string | null>;
}

export function getSnapshotCache(): Map<string, StoredHeapSnapshot> {
  return snapshotCache;
}

export function clearSnapshotCache(): void {
  snapshotCache.clear();
}

export function storeSnapshot(snapshot: StoredHeapSnapshot): StoredHeapSnapshot {
  snapshotCache.set(snapshot.id, snapshot);
  return snapshot;
}

export function getSnapshot(snapshotId: string): StoredHeapSnapshot | undefined {
  return snapshotCache.get(snapshotId);
}

/**
 * Read optional retention caps from the environment. Both default to 0
 * (no eviction) so persistence never surprises the user with deletions; set
 * MCP_V8_HEAP_SNAPSHOT_MAX_COUNT / MCP_V8_HEAP_SNAPSHOT_MAX_TOTAL_MB to bound it.
 */
function getRetentionConfig(): { maxCount: number; maxTotalBytes: number } {
  const env = process.env;
  const maxCount = Math.max(0, parseInt(env.MCP_V8_HEAP_SNAPSHOT_MAX_COUNT ?? '0', 10) || 0);
  const maxTotalMb = Math.max(0, parseInt(env.MCP_V8_HEAP_SNAPSHOT_MAX_TOTAL_MB ?? '0', 10) || 0);
  return { maxCount, maxTotalBytes: maxTotalMb * 1024 * 1024 };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function isCDPPageLike(v: unknown): v is {
  createCDPSession: () => Promise<unknown>;
  evaluate: (...args: unknown[]) => Promise<unknown>;
} {
  return (
    isRecord(v) &&
    typeof v['createCDPSession'] === 'function' &&
    typeof v['evaluate'] === 'function'
  );
}

function unwrapRuntimeValue(value: unknown): unknown {
  if (!isRecord(value)) {
    return value;
  }

  if ('value' in value) {
    return unwrapRuntimeValue(value['value']);
  }

  if ('result' in value) {
    return unwrapRuntimeValue(value['result']);
  }

  return value;
}

interface CaptureReturn {
  success: boolean;
  snapshotId: string;
  capturedAt: string;
  sizeBytes: number;
  chunks: string[];
  simulated: boolean;
  warnings: string[];
  persisted?: { displayPath: string; bytesWritten: number };
  evicted?: string[];
}

export async function handleHeapSnapshotCapture(
  _args: Record<string, unknown>,
  options: HeapSnapshotHandlerOptions,
): Promise<CaptureReturn> {
  const snapshotId = `snapshot_${Date.now().toString(36)}`;
  const capturedAt = new Date().toISOString();
  const warnings: string[] = [];
  const persist = options.persist !== false;

  let targetUrl: string | null = null;
  if (persist && options.getTargetUrl) {
    try {
      targetUrl = await options.getTargetUrl();
    } catch {
      targetUrl = null;
    }
  }

  /**
   * Persist (when enabled), enforce retention caps, and build the final
   * capture return. Persistence is fail-soft: a disk failure pushes a warning
   * but the in-memory snapshot remains usable.
   */
  const finalize = async (
    stored: StoredHeapSnapshot,
    simulated: boolean,
  ): Promise<CaptureReturn> => {
    options.setSnapshot(stored.id);
    const base: CaptureReturn = {
      success: true,
      snapshotId: stored.id,
      capturedAt: stored.capturedAt,
      sizeBytes: stored.sizeBytes,
      chunks: [],
      simulated,
      warnings,
    };

    if (!persist) {
      return base;
    }

    try {
      const persisted = await persistSnapshot({
        id: stored.id,
        chunks: stored.chunks,
        capturedAt: stored.capturedAt,
        sizeBytes: stored.sizeBytes,
        simulated,
        targetUrl,
      });
      // Refresh the cache entry so list/export can resolve the on-disk path.
      snapshotCache.set(stored.id, {
        ...stored,
        ...(typeof targetUrl === 'string' ? { targetUrl } : {}),
        persisted: { absolutePath: persisted.absolutePath, displayPath: persisted.displayPath },
      });

      const retention = getRetentionConfig();
      const evicted = await enforceSnapshotRetention(retention);

      return {
        ...base,
        persisted: { displayPath: persisted.displayPath, bytesWritten: persisted.bytesWritten },
        ...(evicted.evictedIds.length > 0 ? { evicted: evicted.evictedIds } : {}),
      };
    } catch (e) {
      warnings.push(
        `heap snapshot persistence failed: ${e instanceof Error ? e.message : String(e)}`,
      );
      return base;
    }
  };

  if (options.client) {
    // Real CDP heap snapshot capture
    try {
      const chunks: string[] = [];
      const totalSize = await options.client.takeHeapSnapshot((chunk) => {
        chunks.push(chunk);
      });
      const stored = storeSnapshot({
        id: snapshotId,
        chunks,
        capturedAt,
        sizeBytes: totalSize,
        simulated: false,
      });
      return await finalize(stored, false);
    } catch (e: unknown) {
      // Fall through to graceful degradation
      warnings.push(
        `Direct CDP snapshot capture failed: ${e instanceof Error ? e.message : String(e)}. Trying page-evaluate fallback...`,
      );
    }
  }

  // Graceful degradation: PageController fallback via JS evaluate
  try {
    const page = await options.getPage();

    if (isCDPPageLike(page)) {
      const session = await page.createCDPSession();
      const sessionSend = (method: string, params?: Record<string, unknown>) =>
        (session as { send: (m: string, p?: Record<string, unknown>) => Promise<unknown> }).send(
          method,
          params,
        );
      const sessionDetach = () => (session as { detach: () => Promise<void> }).detach();

      await sessionSend('HeapProfiler.enable');
      const response = await sessionSend('Runtime.evaluate', {
        expression: `
          (() => {
            const m = performance.memory;
            return m
              ? {
                  jsHeapSizeUsed: m.usedJSHeapSize,
                  jsHeapSizeTotal: m.totalJSHeapSize,
                  jsHeapSizeLimit: m.jsHeapSizeLimit
                }
              : null;
          })()
        `,
        returnByValue: true,
      });
      await sessionDetach().catch(() => undefined);

      const result = unwrapRuntimeValue(response);
      const parsedResult =
        typeof result === 'string'
          ? (() => {
              try {
                return JSON.parse(result) as unknown;
              } catch {
                return null;
              }
            })()
          : result;
      let sizeBytes = 0;
      if (isRecord(parsedResult) && typeof parsedResult['jsHeapSizeUsed'] === 'number') {
        sizeBytes = parsedResult['jsHeapSizeUsed'];
      }

      const stored = storeSnapshot({
        id: snapshotId,
        chunks: [`{"simulated":true,"sizeBytes":${sizeBytes}}`],
        capturedAt,
        sizeBytes,
        simulated: true,
      });
      return await finalize(stored, true);
    }
  } catch (e: unknown) {
    // Fall through to minimal fallback
    warnings.push(`Page-evaluate fallback failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Minimal fallback: attempt to get performance.memory via page.evaluate
  let fallbackSizeBytes = 0;
  try {
    const page = await options.getPage();
    const pageWithEvaluate = page as { evaluate?: (fn: () => unknown) => Promise<unknown> };
    if (pageWithEvaluate && typeof pageWithEvaluate.evaluate === 'function') {
      const memInfo = (await pageWithEvaluate.evaluate(() => {
        const m = (performance as any).memory;
        return m
          ? {
              usedJSHeapSize: m.usedJSHeapSize ?? 0,
              totalJSHeapSize: m.totalJSHeapSize ?? 0,
              jsHeapSizeLimit: m.jsHeapSizeLimit ?? 0,
            }
          : null;
      })) as { usedJSHeapSize?: number } | null;
      if (memInfo && typeof memInfo.usedJSHeapSize === 'number') {
        fallbackSizeBytes = memInfo.usedJSHeapSize;
      }
    }
  } catch (e: unknown) {
    warnings.push(
      `performance.memory fallback failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  const stored = storeSnapshot({
    id: snapshotId,
    chunks:
      fallbackSizeBytes > 0
        ? [`{"simulated":true,"approximateHeapSize":${fallbackSizeBytes}}`]
        : ['{}'],
    capturedAt,
    sizeBytes: fallbackSizeBytes,
    simulated: true,
  });
  return await finalize(stored, true);
}

export async function handleHeapSearch(
  args: Record<string, unknown>,
  options: HeapSnapshotHandlerOptions,
): Promise<{ success: boolean; snapshotId: string; query: string; matches: string[] }> {
  const query = typeof args.query === 'string' && args.query.length > 0 ? args.query : '.*';
  const snapshotId =
    typeof args.snapshotId === 'string' && args.snapshotId.length > 0
      ? args.snapshotId
      : options.getSnapshot();

  await options.getPage();

  if (!snapshotId) {
    throw new Error('snapshotId is required');
  }

  const snapshot = getSnapshot(snapshotId);
  if (!snapshot) {
    throw new Error(`Snapshot ${snapshotId} not found`);
  }

  return {
    success: true,
    snapshotId,
    query,
    matches: snapshot.chunks.filter((chunk) => chunk.includes(query)),
  };
}
