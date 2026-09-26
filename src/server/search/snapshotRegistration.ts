/**
 * Register a search engine's feedback + quality trackers as snapshot sources.
 *
 * The trackers live inside the ToolSearchEngine instance, which is built lazily
 * by getSearchEngine() only when a search actually runs (see
 * MCPServer.search.helpers). That makes registration inherently conditional:
 * under the stdio transport SEARCH_VECTOR_ENABLED is false and the engine is
 * still constructed on first search, but in profiles that never issue a search
 * the engine never exists and there is nothing to persist — registration is
 * simply skipped.
 *
 * Both trackers implement the SnapshotSource contract
 * (src/server/persistence/RuntimeSnapshotScheduler.ts); the scheduler owns the
 * file I/O (atomic tmp+rename into the state dir). Returns the registered
 * sources so callers (e.g. tests) can assert the wiring.
 */
import type { ToolSearchEngine } from '@server/search/ToolSearchEngine';
import type { RuntimeSnapshotScheduler } from '@server/persistence/RuntimeSnapshotScheduler';
import type { MCPServerContext } from '@server/MCPServer.context';
import { resolve } from 'node:path';

export function registerSearchSnapshotSources(
  scheduler: RuntimeSnapshotScheduler,
  engine: ToolSearchEngine,
  stateDir: string,
): { feedbackTracker: unknown; qualityTracker: unknown } {
  const feedbackTracker = engine.getFeedbackTracker();
  const qualityTracker = engine.getSearchQualityTracker();
  scheduler.register(resolve(stateDir, 'search-feedback.json'), feedbackTracker);
  scheduler.register(resolve(stateDir, 'search-quality.json'), qualityTracker);
  return { feedbackTracker, qualityTracker };
}

/**
 * Register a ctx-held engine's trackers with the ctx-held scheduler, if both
 * exist. Safe to call on every search/route/call_tool — the scheduler dedupes
 * by source, and a ctx without domain instances (bare test contexts, or a
 * profile that never built an engine) simply skips registration.
 */
export function registerSearchSnapshotSourcesFromCtx(
  ctx: MCPServerContext,
  engine: ToolSearchEngine,
): void {
  const getInst =
    typeof ctx.getDomainInstance === 'function' ? ctx.getDomainInstance.bind(ctx) : null;
  const scheduler = getInst?.<RuntimeSnapshotScheduler>('snapshotScheduler');
  const stateDir = getInst?.<string>('snapshotStateDir');
  if (scheduler && stateDir) {
    registerSearchSnapshotSources(scheduler, engine, stateDir);
  }
}
