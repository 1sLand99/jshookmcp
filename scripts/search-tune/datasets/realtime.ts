/**
 * Realtime dataset loader — converts persisted search-quality history
 * (~/.jshookmcp/state/search-quality.json) into SearchEvalCase[] so the
 * search-tune pipeline can evaluate against real traffic instead of the
 * synthetic fixture.
 *
 * Ground-truth rule: only a record with BOTH usedTool and usedToolRank is an
 * "answer". A search where the user never called a tool has no answer label;
 * a usage recorded without a rank contributes nothing to MRR and is dropped
 * the same way SearchQualityTracker.computeMetrics treats it.
 *
 * The conversion is deliberately NOT enriched with the record's other
 * returnedTools: those reflect the old engine's output, not user relevance —
 * labeling them as expectations would make the tuning circular (optimizing
 * toward the engine that produced the traffic).
 */
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { Tool } from '@modelcontextprotocol/server';
import type {
  SearchQualityTrackerSnapshot,
  SearchQueryRecord,
} from '../../../src/server/search/SearchQualityTracker';
import type { SearchEvalCase } from '../../../tests/server/search/fixtures/search-quality.fixture';

export const REALTIME_SNAPSHOT_FILENAME = 'search-quality.json';

/** Matches the fixture convention and metrics.ts' hard-coded slice-at-10. */
export const REALTIME_EVAL_TOP_K = 10;

export interface LoadRealtimeDatasetOptions {
  /** Directory containing the snapshot file (default: JSHOOK_STATE_DIR or ~/.jshookmcp/state). */
  readonly dir?: string;
  /**
   * Tool catalog carried on the dataset (informational). Realtime cases are
   * evaluated against the full registry engine the worker builds — their
   * idealTools reference real registry names, not the 85-tool fixture subset.
   */
  readonly tools?: readonly Tool[];
  readonly domainOverrides?: ReadonlyMap<string, string>;
}

export interface LoadedRealtimeDataset {
  readonly name: 'realtime';
  readonly sourceFile: string;
  readonly tools: readonly Tool[];
  readonly domainOverrides: ReadonlyMap<string, string>;
  readonly cases: readonly SearchEvalCase[];
}

/** Same default the server uses (RuntimeSnapshotScheduler.getStateDir). */
export function defaultRealtimeStateDir(): string {
  const overridden = process.env.JSHOOK_STATE_DIR?.trim();
  return overridden ? resolve(homedir(), overridden) : resolve(homedir(), '.jshookmcp', 'state');
}

/**
 * Defensive parse of the on-disk snapshot. Unlike the tracker's all-or-nothing
 * restore, a corrupt record is skipped in isolation — a tuning input tolerates
 * one bad row without discarding the rest of the history.
 */
export function parseSearchQualitySnapshot(data: unknown): SearchQualityTrackerSnapshot {
  if (!data || typeof data !== 'object') return { lastRecordId: null, records: [] };
  const raw = data as { lastRecordId?: unknown; records?: unknown };
  if (!Array.isArray(raw.records)) return { lastRecordId: null, records: [] };

  const records: SearchQueryRecord[] = [];
  for (const item of raw.records) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as Record<string, unknown>;
    if (typeof rec.id !== 'string' || typeof rec.query !== 'string') continue;
    if (typeof rec.timestamp !== 'number' || typeof rec.latencyMs !== 'number') continue;
    if (!Array.isArray(rec.returnedTools) || !Array.isArray(rec.returnedScores)) continue;

    const usedTool = typeof rec.usedTool === 'string' ? rec.usedTool : undefined;
    const usedToolRank = typeof rec.usedToolRank === 'number' ? rec.usedToolRank : undefined;
    records.push({
      id: rec.id,
      query: rec.query,
      timestamp: rec.timestamp,
      returnedTools: rec.returnedTools as string[],
      returnedScores: rec.returnedScores as number[],
      latencyMs: rec.latencyMs,
      usedTool,
      usedToolRank,
    });
  }

  return {
    lastRecordId: typeof raw.lastRecordId === 'string' ? raw.lastRecordId : null,
    records,
  };
}

/**
 * Pure conversion: snapshot → evaluation cases.
 *
 * Filtering rules:
 *  - no usedTool (user searched but called no tool) → dropped, no answer label
 *  - usedTool without usedToolRank → dropped (same rule as the tracker's
 *    computeMetrics: a usage without a rank dilutes MRR instead of informing it)
 *  - empty/whitespace query → dropped (degenerate, unanswerable)
 *  - usedToolRank beyond the eval window → KEPT as an honest hard case
 *    (MRR@10 scores it 0 — that is the correct signal)
 *  - duplicate queries → kept; frequency is real demand weight, not noise
 */
export function convertSearchQualitySnapshot(
  snapshot: SearchQualityTrackerSnapshot,
): SearchEvalCase[] {
  const cases: SearchEvalCase[] = [];
  for (const record of snapshot.records) {
    if (record.usedTool === undefined || record.usedToolRank === undefined) continue;
    const query = record.query.trim();
    if (query.length === 0) continue;
    cases.push({
      id: `rt-${record.id}`,
      title: `realtime: "${query}" → ${record.usedTool} (was rank ${record.usedToolRank})`,
      query,
      topK: REALTIME_EVAL_TOP_K,
      expectations: [{ tool: record.usedTool, gain: 3 }],
      idealTool: record.usedTool,
      tags: ['realtime'],
    });
  }
  return cases;
}

/**
 * Loader: reads the persisted snapshot from disk. A missing or corrupt file
 * yields an EMPTY dataset, not an error — optimize.ts' `--dataset realtime`
 * path fails fast on zero cases before tuning anything.
 */
export async function loadRealtimeDataset(
  options: LoadRealtimeDatasetOptions = {},
): Promise<LoadedRealtimeDataset> {
  const sourceFile = resolve(options.dir ?? defaultRealtimeStateDir(), REALTIME_SNAPSHOT_FILENAME);
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(sourceFile, 'utf-8'));
  } catch {
    // No snapshot yet (server never ran search traffic with persistence, or
    // all queries lacked tool usage) — empty dataset, not an error.
    return {
      name: 'realtime',
      sourceFile,
      tools: options.tools ?? [],
      domainOverrides: options.domainOverrides ?? new Map<string, string>(),
      cases: [],
    };
  }
  return {
    name: 'realtime',
    sourceFile,
    tools: options.tools ?? [],
    domainOverrides: options.domainOverrides ?? new Map<string, string>(),
    cases: convertSearchQualitySnapshot(parseSearchQualitySnapshot(parsed)),
  };
}
