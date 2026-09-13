/**
 * Session-scoped reverse-engineering progress tracking (session domain).
 * Prefixes: SESSION_*
 */

import { int, str } from './helpers.js';

/**
 * Default session bucket used by session_progress_* tools when the caller
 * omits `sessionId`. One logical reverse-engineering engagement = one session.
 *
 * @env SESSION_PROGRESS_DEFAULT_SESSION_ID
 * @default "default"
 */
export const SESSION_PROGRESS_DEFAULT_SESSION_ID = str(
  'SESSION_PROGRESS_DEFAULT_SESSION_ID',
  'default',
);

/**
 * Maximum number of progress entries retained per (sessionId, kind) pair.
 * A record call that would create a NEW entry beyond this cap is rejected
 * (re-recording an existing (kind, key) is still allowed — it updates
 * metadata in place). This bounds per-session memory; the store itself is
 * server-lifetime in-memory state.
 *
 * @env SESSION_PROGRESS_MAX_ENTRIES_PER_KIND
 * @default 500
 */
export const SESSION_PROGRESS_MAX_ENTRIES_PER_KIND = int(
  'SESSION_PROGRESS_MAX_ENTRIES_PER_KIND',
  500,
);
