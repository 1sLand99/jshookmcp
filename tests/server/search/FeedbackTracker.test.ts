/**
 * Tests for FeedbackTracker.ts
 *
 * FeedbackTracker manages adaptive vector weight adjustment based on tool call feedback.
 *
 * Learning rates come from env defaults in src/constants.ts:
 *   SEARCH_VECTOR_COSINE_WEIGHT (initial weight)
 *   SEARCH_VECTOR_LEARN_UP       (rank < LEARN_TOP_N)
 *   SEARCH_VECTOR_LEARN_DOWN     (rank ≥ 2 × LEARN_TOP_N or unseen)
 *   SEARCH_VECTOR_LEARN_TOP_N
 *   Between [N, 2N) the up step is scaled by 0.3.
 *
 * Learning is gated by SearchConfig.vectorDynamicWeight (mirrors
 * SEARCH_VECTOR_DYNAMIC_WEIGHT): when false the weight never moves — used by
 * scripts/search-tune/compare-static-model.ts for A/B baselines.
 *
 * The last feedback query is recorded (not learned from) and the learned
 * vector weight survives process restarts via export/restoreSnapshot.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { FeedbackTracker } from '@server/search/FeedbackTracker';
import {
  SEARCH_VECTOR_COSINE_WEIGHT,
  SEARCH_VECTOR_LEARN_UP,
  SEARCH_VECTOR_LEARN_DOWN,
  SEARCH_VECTOR_LEARN_TOP_N,
} from '@src/constants';

// Block `.env` loading so the learning-rate constants resolve to their source
// defaults. A local (gitignored, search-tune generated) `.env` would otherwise
// be injected by the env-bootstrap that runs when the constants module loads,
// overriding SEARCH_VECTOR_LEARN_UP/DOWN and breaking the bound assertions.
// Mirrors the isolation pattern used by tests/utils/config.test.ts.
const { dotenvMock } = vi.hoisted(() => ({
  dotenvMock: {
    config: vi.fn(() => ({ error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) })),
  },
}));

vi.mock('dotenv', () => dotenvMock);

const EPS = 1e-9;
const INIT = SEARCH_VECTOR_COSINE_WEIGHT;
const UP = SEARCH_VECTOR_LEARN_UP;
const DOWN = SEARCH_VECTOR_LEARN_DOWN;
const N = SEARCH_VECTOR_LEARN_TOP_N;

describe('FeedbackTracker', () => {
  describe('initialization', () => {
    it('uses default vector weight from constants when no config provided', () => {
      const tracker = new FeedbackTracker();
      expect(tracker.getVectorWeight()).toBe(INIT);
    });

    it('uses custom vector weight from search config', () => {
      const tracker = new FeedbackTracker({ vectorCosineWeight: 0.6 } as any);
      expect(tracker.getVectorWeight()).toBe(0.6);
    });

    it('uses config value of 0 if explicitly set', () => {
      const tracker = new FeedbackTracker({ vectorCosineWeight: 0 } as any);
      expect(tracker.getVectorWeight()).toBe(0);
    });
  });

  describe('recordVectorRanking', () => {
    it('stores the vector ranking for feedback tracking', () => {
      const tracker = new FeedbackTracker();
      const ranking = new Map([
        ['tool_a', 0],
        ['tool_b', 1],
        ['tool_c', 5],
      ]);

      tracker.recordVectorRanking(ranking);
      expect(tracker.getVectorWeight()).toBe(INIT);
    });
  });

  describe('recordToolCallFeedback', () => {
    let tracker: FeedbackTracker;

    beforeEach(() => {
      tracker = new FeedbackTracker();
    });

    it('returns false when no ranking was recorded', () => {
      const result = tracker.recordToolCallFeedback('tool_a', true);
      expect(result).toBe(false);
      expect(tracker.getVectorWeight()).toBe(INIT);
    });

    it('returns false when vector is not enabled', () => {
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      const result = tracker.recordToolCallFeedback('tool_a', false);
      expect(result).toBe(false);
      expect(tracker.getVectorWeight()).toBe(INIT);
    });

    it('increases weight when tool was in vector top-N (rank 0)', () => {
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      const result = tracker.recordToolCallFeedback('tool_a', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(INIT + UP, 10);
    });

    it('increases weight when tool was in vector top-N (rank N-1)', () => {
      tracker.recordVectorRanking(new Map([['tool_d', N - 1]]));
      const result = tracker.recordToolCallFeedback('tool_d', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(INIT + UP, 10);
    });

    it('applies reduced up-step for intermediate rank zone [N, 2N)', () => {
      tracker.recordVectorRanking(new Map([['tool_mid', N + 1]]));
      const result = tracker.recordToolCallFeedback('tool_mid', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(INIT + UP * 0.3, 10);
    });

    it('decreases weight when tool was outside 2N window (rank 2N+1)', () => {
      tracker.recordVectorRanking(new Map([['tool_far', 2 * N + 1]]));
      const result = tracker.recordToolCallFeedback('tool_far', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(Math.max(0.1, INIT - DOWN), 10);
    });

    it('decreases weight when tool was outside 2N window (rank 100)', () => {
      tracker.recordVectorRanking(new Map([['tool_x', 100]]));
      const result = tracker.recordToolCallFeedback('tool_x', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(Math.max(0.1, INIT - DOWN), 10);
    });

    it('decreases weight when tool was not in ranking at all', () => {
      tracker.recordVectorRanking(new Map([['other_tool', 0]]));
      const result = tracker.recordToolCallFeedback('unlisted_tool', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(Math.max(0.1, INIT - DOWN), 10);
    });

    it('respects upper bound of 0.8', () => {
      const highTracker = new FeedbackTracker({ vectorCosineWeight: 0.77 } as any);
      highTracker.recordVectorRanking(new Map([['tool', 0]]));

      highTracker.recordToolCallFeedback('tool', true); // 0.77 + UP → clamp 0.8
      expect(highTracker.getVectorWeight()).toBe(0.8);

      highTracker.recordVectorRanking(new Map([['tool', 0]]));
      highTracker.recordToolCallFeedback('tool', true); // already at max
      expect(highTracker.getVectorWeight()).toBe(0.8);
    });

    it('respects lower bound of 0.1', () => {
      const lowTracker = new FeedbackTracker({ vectorCosineWeight: 0.11 } as any);
      lowTracker.recordVectorRanking(new Map([['tool', 100]]));

      lowTracker.recordToolCallFeedback('tool', true); // 0.11 - DOWN → clamp 0.1
      expect(lowTracker.getVectorWeight()).toBe(0.1);

      lowTracker.recordVectorRanking(new Map([['tool', 100]]));
      lowTracker.recordToolCallFeedback('tool', true); // already at min
      expect(lowTracker.getVectorWeight()).toBe(0.1);
    });

    it('accumulates weight changes over multiple feedback calls', () => {
      tracker.recordVectorRanking(new Map([['good', 0]]));
      tracker.recordToolCallFeedback('good', true); // INIT → INIT+UP

      tracker.recordVectorRanking(new Map([['good', 1]]));
      tracker.recordToolCallFeedback('good', true); // INIT+UP → INIT+2*UP

      tracker.recordVectorRanking(new Map([['bad', 2 * N + 1]]));
      tracker.recordToolCallFeedback('bad', true); // → -DOWN

      const expected = Math.max(0.1, INIT + 2 * UP - DOWN);
      expect(tracker.getVectorWeight()).toBeCloseTo(expected, 2);
    });
  });

  describe('vectorDynamicWeight switch', () => {
    it('defaults to learning enabled when config is undefined', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      const result = tracker.recordToolCallFeedback('tool_a', true);
      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(INIT + UP, 10);
    });

    it('skips weight adjustment when vectorDynamicWeight is false', () => {
      const tracker = new FeedbackTracker({ vectorDynamicWeight: false } as any);
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      const result = tracker.recordToolCallFeedback('tool_a', true);

      expect(result).toBe(false);
      expect(tracker.getVectorWeight()).toBe(INIT);
    });

    it('keeps the initial weight across many feedback calls when disabled', () => {
      const tracker = new FeedbackTracker({ vectorDynamicWeight: false } as any);
      for (let i = 0; i < 5; i++) {
        tracker.recordVectorRanking(new Map([['tool_a', 0]]));
        tracker.recordToolCallFeedback('tool_a', true);
        tracker.recordVectorRanking(new Map([['tool_far', 100]]));
        tracker.recordToolCallFeedback('tool_far', true);
      }
      expect(tracker.getVectorWeight()).toBe(INIT);
    });

    it('still records the feedback query when learning is disabled', () => {
      const tracker = new FeedbackTracker({ vectorDynamicWeight: false } as any);
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true, 'find memory scanner');
      expect(tracker.getLastFeedbackQuery()).toBe('find memory scanner');
    });
  });

  describe('lastFeedbackQuery', () => {
    it('starts as null', () => {
      const tracker = new FeedbackTracker();
      expect(tracker.getLastFeedbackQuery()).toBeNull();
    });

    it('records the query from the tool call feedback', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true, 'search query');
      expect(tracker.getLastFeedbackQuery()).toBe('search query');
    });

    it('records the latest query on repeated feedback calls', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true, 'first query');
      tracker.recordToolCallFeedback('tool_a', true, 'second query');
      expect(tracker.getLastFeedbackQuery()).toBe('second query');
    });

    it('records an empty string as null', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true, '');
      expect(tracker.getLastFeedbackQuery()).toBeNull();
    });

    it('does not require a ranking to record the query', () => {
      const tracker = new FeedbackTracker();
      tracker.recordToolCallFeedback('tool_a', true, 'query without ranking');
      expect(tracker.getLastFeedbackQuery()).toBe('query without ranking');
    });
  });

  describe('snapshot persistence', () => {
    it('exports the current vector weight', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true);

      const snapshot = tracker.exportSnapshot();
      expect(snapshot.vectorWeight).toBeCloseTo(INIT + UP, 10);
    });

    it('round-trips the vector weight through export/restore', () => {
      const source = new FeedbackTracker();
      source.recordVectorRanking(new Map([['tool_a', 0]]));
      source.recordToolCallFeedback('tool_a', true);
      const exported = source.exportSnapshot();

      const target = new FeedbackTracker();
      target.restoreSnapshot(exported);
      expect(target.getVectorWeight()).toBeCloseTo(exported.vectorWeight, 10);
    });

    it('is marked dirty after learning and clean after markPersisted', () => {
      const tracker = new FeedbackTracker();
      expect(tracker.isPersistDirty()).toBe(false);

      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      // A feedback call that does not move the weight must not mark it dirty.
      tracker.recordToolCallFeedback('tool_a', false);
      expect(tracker.isPersistDirty()).toBe(false);

      tracker.recordToolCallFeedback('tool_a', true);
      expect(tracker.isPersistDirty()).toBe(true);

      tracker.markPersisted();
      expect(tracker.isPersistDirty()).toBe(false);
    });

    it('marks itself dirty when learning is disabled', () => {
      // Learning off still mutates lastFeedbackQuery, so a snapshot taken
      // before the call would miss it.
      const tracker = new FeedbackTracker({ vectorDynamicWeight: false } as any);
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true, 'query');
      expect(tracker.isPersistDirty()).toBe(true);
    });

    it('marks itself clean after restore', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool_a', 0]]));
      tracker.recordToolCallFeedback('tool_a', true);
      expect(tracker.isPersistDirty()).toBe(true);

      tracker.restoreSnapshot({ vectorWeight: 0.42 });
      expect(tracker.isPersistDirty()).toBe(false);
      expect(tracker.getVectorWeight()).toBeCloseTo(0.42, 10);
    });

    it('clamps restored weight into the [0.1, 0.8] bounds', () => {
      const tracker = new FeedbackTracker();
      tracker.restoreSnapshot({ vectorWeight: 5 });
      expect(tracker.getVectorWeight()).toBe(0.8);
      tracker.restoreSnapshot({ vectorWeight: -3 });
      expect(tracker.getVectorWeight()).toBe(0.1);
    });

    it('ignores malformed snapshot payloads', () => {
      const tracker = new FeedbackTracker();
      const before = tracker.getVectorWeight();

      tracker.restoreSnapshot(null);
      tracker.restoreSnapshot({});
      tracker.restoreSnapshot({ vectorWeight: 'nope' });
      tracker.restoreSnapshot('string');
      tracker.restoreSnapshot(42);

      expect(tracker.getVectorWeight()).toBe(before);
    });
  });

  describe('edge cases', () => {
    it('handles empty ranking map', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map());

      const result = tracker.recordToolCallFeedback('any_tool', true);
      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(Math.max(0.1, INIT - DOWN), 10);
    });

    it('handles ranking with negative rank (counts as top hit)', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool', -1]]));
      const result = tracker.recordToolCallFeedback('tool', true);

      expect(result).toBe(true);
      expect(tracker.getVectorWeight()).toBeCloseTo(INIT + UP, 10);
    });

    it('handles boundary rank of N (first outside top-N)', () => {
      const tracker = new FeedbackTracker();
      tracker.recordVectorRanking(new Map([['tool', N]]));
      const result = tracker.recordToolCallFeedback('tool', true);

      expect(result).toBe(true);
      // Rank N is in the [N, 2N) zone → small positive step
      expect(Math.abs(tracker.getVectorWeight() - (INIT + UP * 0.3))).toBeLessThan(EPS);
    });
  });
});
