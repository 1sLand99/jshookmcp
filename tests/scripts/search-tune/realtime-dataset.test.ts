/**
 * Realtime dataset loader tests (scripts/search-tune/datasets/realtime.ts).
 *
 * The loader converts persisted search-quality history
 * (~/.jshookmcp/state/search-quality.json) into SearchEvalCase[] so the
 * search-tune pipeline can evaluate against real traffic. Conversion is a
 * pure function over the snapshot shape — tests feed mock snapshots, never
 * a real persistence file.
 */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SearchQualityTrackerSnapshot } from '../../../src/server/search/SearchQualityTracker';
import {
  REALTIME_EVAL_TOP_K,
  REALTIME_SNAPSHOT_FILENAME,
  convertSearchQualitySnapshot,
  defaultRealtimeStateDir,
  loadRealtimeDataset,
  parseSearchQualitySnapshot,
} from '../../../scripts/search-tune/datasets/realtime';

function makeRecord(
  partial: Partial<SearchQualityTrackerSnapshot['records'][number]>,
): SearchQualityTrackerSnapshot['records'][number] {
  return {
    id: 'sq-1000-1',
    query: 'capture network requests',
    timestamp: 1700000000000,
    returnedTools: ['network_enable', 'network_monitor', 'network_get_requests'],
    returnedScores: [0.9, 0.6, 0.4],
    latencyMs: 12,
    usedTool: 'network_enable',
    usedToolRank: 1,
    ...partial,
  };
}

const MOCK_SNAPSHOT: SearchQualityTrackerSnapshot = {
  lastRecordId: 'sq-1000-5',
  records: [
    makeRecord({ id: 'sq-1000-1', usedTool: 'network_enable', usedToolRank: 1 }),
    makeRecord({
      id: 'sq-1000-2',
      query: 'attach frida to process',
      usedTool: 'frida_attach',
      usedToolRank: 2,
    }),
    // User searched but never called a tool → no answer label → dropped.
    makeRecord({ id: 'sq-1000-3', usedTool: undefined, usedToolRank: undefined }),
    // Usage recorded without a rank (older callers) → dropped.
    makeRecord({ id: 'sq-1000-4', usedTool: 'debug_pause', usedToolRank: undefined }),
    // Degenerate empty query → dropped.
    makeRecord({ id: 'sq-1000-5', query: '   ', usedTool: 'page_navigate', usedToolRank: 1 }),
    // Rank beyond the eval window is KEPT — an honest hard case (MRR@10 = 0).
    makeRecord({
      id: 'sq-1000-6',
      query: 'deep rank tool',
      usedTool: 'some_tool',
      usedToolRank: 14,
    }),
  ],
};

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'realtime-ds-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  vi.unstubAllEnvs();
});

describe('convertSearchQualitySnapshot', () => {
  it('converts each record with usedTool+usedToolRank into one SearchEvalCase', () => {
    const cases = convertSearchQualitySnapshot(MOCK_SNAPSHOT);

    // sq-1000-3 (no usedTool), sq-1000-4 (no rank), sq-1000-5 (empty query) dropped.
    expect(cases).toHaveLength(3);
    expect(cases.map((c) => c.id)).toEqual(['rt-sq-1000-1', 'rt-sq-1000-2', 'rt-sq-1000-6']);
  });

  it('maps query/idealTool/expectations/tags per the fixture single-tool shape', () => {
    const [first, second] = convertSearchQualitySnapshot(MOCK_SNAPSHOT);

    expect(first).toMatchObject({
      id: 'rt-sq-1000-1',
      title: expect.stringContaining('capture network requests'),
      query: 'capture network requests',
      idealTool: 'network_enable',
      tags: ['realtime'],
    });
    expect(first!.expectations).toEqual([{ tool: 'network_enable', gain: 3 }]);
    expect(first!.topK).toBe(REALTIME_EVAL_TOP_K);

    expect(second!.expectations).toEqual([{ tool: 'frida_attach', gain: 3 }]);
    expect(second!.idealTool).toBe('frida_attach');
  });

  it('keeps records whose usedToolRank exceeds the eval window (hard cases)', () => {
    const cases = convertSearchQualitySnapshot(MOCK_SNAPSHOT);
    const deep = cases.find((c) => c.id === 'rt-sq-1000-6');
    expect(deep).toBeDefined();
    expect(deep!.idealTool).toBe('some_tool');
    expect(deep!.title).toContain('rank 14');
  });

  it('returns an empty list for an empty snapshot', () => {
    expect(convertSearchQualitySnapshot({ lastRecordId: null, records: [] })).toEqual([]);
  });
});

describe('parseSearchQualitySnapshot', () => {
  it('returns empty records for non-object or non-array data', () => {
    expect(parseSearchQualitySnapshot(null)).toEqual({ lastRecordId: null, records: [] });
    expect(parseSearchQualitySnapshot('nope')).toEqual({ lastRecordId: null, records: [] });
    expect(parseSearchQualitySnapshot({ records: 'not-an-array' })).toEqual({
      lastRecordId: null,
      records: [],
    });
  });

  it('skips malformed records per-record and keeps the valid ones', () => {
    const parsed = parseSearchQualitySnapshot({
      lastRecordId: 'sq-9',
      records: [
        {
          id: 7,
          query: 'broken id',
          timestamp: 1,
          returnedTools: [],
          returnedScores: [],
          latencyMs: 1,
        },
        makeRecord({ id: 'sq-ok-1', usedTool: 'page_navigate', usedToolRank: 3 }),
        { id: 'sq-ok-2', query: 'no timestamp' },
      ],
    });

    expect(parsed.lastRecordId).toBe('sq-9');
    expect(parsed.records).toHaveLength(1);
    expect(parsed.records[0]!.id).toBe('sq-ok-1');
    expect(parsed.records[0]!.usedTool).toBe('page_navigate');
    expect(parsed.records[0]!.usedToolRank).toBe(3);
  });

  it('coerces non-string usedTool / non-number usedToolRank to undefined', () => {
    const parsed = parseSearchQualitySnapshot({
      lastRecordId: null,
      records: [
        {
          id: 'sq-bad-1',
          query: 'q1',
          timestamp: 1,
          returnedTools: [],
          returnedScores: [],
          latencyMs: 1,
          usedTool: 42,
          usedToolRank: 1,
        },
        {
          id: 'sq-bad-2',
          query: 'q2',
          timestamp: 1,
          returnedTools: [],
          returnedScores: [],
          latencyMs: 1,
          usedTool: 'ok',
          usedToolRank: 'first',
        },
      ],
    });

    expect(parsed.records[0]!.usedTool).toBeUndefined();
    expect(parsed.records[0]!.usedToolRank).toBe(1);
    expect(parsed.records[1]!.usedTool).toBe('ok');
    expect(parsed.records[1]!.usedToolRank).toBeUndefined();
  });
});

describe('loadRealtimeDataset', () => {
  it('returns an empty dataset (not throw) when the snapshot file is missing', async () => {
    const dir = await makeTempDir();
    const dataset = await loadRealtimeDataset({ dir });

    expect(dataset.name).toBe('realtime');
    expect(dataset.cases).toEqual([]);
    expect(dataset.sourceFile).toBe(resolve(dir, REALTIME_SNAPSHOT_FILENAME));
  });

  it('returns an empty dataset for a corrupt snapshot file', async () => {
    const dir = await makeTempDir();
    await writeFile(join(dir, REALTIME_SNAPSHOT_FILENAME), '{not json', 'utf-8');
    const dataset = await loadRealtimeDataset({ dir });
    expect(dataset.cases).toEqual([]);
  });

  it('loads and converts a valid snapshot file', async () => {
    const dir = await makeTempDir();
    await writeFile(join(dir, REALTIME_SNAPSHOT_FILENAME), JSON.stringify(MOCK_SNAPSHOT), 'utf-8');

    const dataset = await loadRealtimeDataset({ dir });
    expect(dataset.cases).toHaveLength(3);
    expect(dataset.cases[0]!.idealTool).toBe('network_enable');
  });

  it('carries provided tools/domainOverrides on the dataset', async () => {
    const dir = await makeTempDir();
    await writeFile(join(dir, REALTIME_SNAPSHOT_FILENAME), JSON.stringify(MOCK_SNAPSHOT), 'utf-8');
    const tools = [
      {
        name: 'network_enable',
        description: 'x',
        inputSchema: { type: 'object' as const, properties: {} },
      },
    ];
    const domainOverrides = new Map<string, string>([['network_enable', 'network']]);

    const dataset = await loadRealtimeDataset({ dir, tools, domainOverrides });
    expect(dataset.tools).toBe(tools);
    expect(dataset.domainOverrides).toBe(domainOverrides);
  });
});

describe('defaultRealtimeStateDir', () => {
  it('defaults to ~/.jshookmcp/state', () => {
    expect(defaultRealtimeStateDir()).toBe(resolve(homedir(), '.jshookmcp', 'state'));
  });

  it('honors JSHOOK_STATE_DIR, resolved relative to the home dir like the server', () => {
    vi.stubEnv('JSHOOK_STATE_DIR', 'custom/state');
    expect(defaultRealtimeStateDir()).toBe(resolve(homedir(), 'custom/state'));
  });
});
