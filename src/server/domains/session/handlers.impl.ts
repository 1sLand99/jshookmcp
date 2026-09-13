/**
 * Session progress handlers — session-scoped reverse-engineering coverage
 * ledger (evidence write → coverage query → gap audit).
 *
 * Storage is deliberately in-memory and scoped to the handler instance, which
 * the manifest `ensure()` caches on the server context (`domainInstanceMap`).
 * It therefore lives for the lifetime of the MCP server process and is lost on
 * restart — the tool descriptions state this explicitly. No SQLite/persistent
 * store: the repo has no per-session persistence facility (coordination's
 * snapshots serve a different, handoff-oriented purpose) and a coverage
 * self-audit only needs server-lifetime state.
 *
 * Bounds: at most SESSION_PROGRESS_MAX_ENTRIES_PER_KIND entries per
 * (sessionId, kind); creating a new entry beyond the cap is rejected.
 */
import { handleSafe, type ToolResponse } from '@server/domains/shared/ResponseBuilder';
import {
  SESSION_PROGRESS_DEFAULT_SESSION_ID,
  SESSION_PROGRESS_MAX_ENTRIES_PER_KIND,
} from '@src/constants';

// ── Types ──

export type SessionProgressKind = 'process' | 'hook-point' | 'protocol-field';

const PROGRESS_KINDS: readonly SessionProgressKind[] = ['process', 'hook-point', 'protocol-field'];

/** camelCase keys used in `kindCounts` / `counts` responses. */
const KIND_COUNT_KEYS: Readonly<Record<SessionProgressKind, string>> = {
  process: 'process',
  'hook-point': 'hookPoint',
  'protocol-field': 'protocolField',
};

export interface SessionProgressEntry {
  kind: SessionProgressKind;
  key: string;
  /** Epoch ms of the FIRST record for this (kind, key). */
  recordedAt: number;
  metadata?: Record<string, unknown>;
}

export interface SessionProgressRecordResult {
  recorded: true;
  /** true when a new entry was created, false when an existing one was updated in place. */
  created: boolean;
  sessionId: string;
  kind: SessionProgressKind;
  key: string;
  kindCounts: { process: number; hookPoint: number; protocolField: number };
  totalEntries: number;
}

export interface SessionProgressCoverageEntry {
  kind: SessionProgressKind;
  key: string;
  recordedAt: string;
  metadata?: Record<string, unknown>;
}

export interface SessionProgressCoverageResult {
  sessionId: string;
  counts: { process: number; hookPoint: number; protocolField: number };
  total: number;
  entries: SessionProgressCoverageEntry[];
}

export interface SessionProgressClearResult {
  cleared: number;
  sessionId: string;
  kind?: SessionProgressKind;
}

/** Per-kind key → entry map for one session bucket. */
type KindMap = Map<SessionProgressKind, Map<string, SessionProgressEntry>>;

// ── Handler ──

export class SessionProgressHandlers {
  /** sessionId → per-kind entry maps. Lazily created by record calls only. */
  private readonly sessions = new Map<string, KindMap>();

  // No constructor / ctx dependencies: the ledger is pure in-memory state
  // owned by this handler instance (cached on the ctx via the domain
  // instance map by the manifest ensure() factory).

  // ── session_progress_record ──

  async handleRecordProgressTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleRecordProgress(args));
  }

  async handleRecordProgress(args: Record<string, unknown>): Promise<SessionProgressRecordResult> {
    const kind = readKindArg(args.kind);
    const key = readKeyArg(args.key);
    const sessionId = readSessionIdArg(args.sessionId);
    const metadata = readMetadataArg(args.metadata);

    const kindMap = this.getOrCreateKindMap(sessionId, kind);
    const existing = kindMap.get(key);

    let created: boolean;
    if (existing) {
      // Idempotent re-record: replace metadata, keep the original recordedAt.
      if (metadata === undefined) {
        delete existing.metadata;
      } else {
        existing.metadata = metadata;
      }
      created = false;
    } else {
      if (kindMap.size >= SESSION_PROGRESS_MAX_ENTRIES_PER_KIND) {
        throw new Error(
          `session_progress_record rejected: session "${sessionId}" already holds the maximum of ` +
            `${SESSION_PROGRESS_MAX_ENTRIES_PER_KIND} '${kind}' entries ` +
            '(SESSION_PROGRESS_MAX_ENTRIES_PER_KIND). Clear entries with session_progress_clear ' +
            'or record under a different sessionId.',
        );
      }
      const entry: SessionProgressEntry = { kind, key, recordedAt: Date.now() };
      if (metadata !== undefined) entry.metadata = metadata;
      kindMap.set(key, entry);
      created = true;
    }

    const counts = this.kindCountsFor(sessionId);
    return {
      recorded: true,
      created,
      sessionId,
      kind,
      key,
      kindCounts: counts,
      totalEntries: counts.process + counts.hookPoint + counts.protocolField,
    };
  }

  // ── session_progress_coverage ──

  async handleGetCoverageTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleGetCoverage(args));
  }

  async handleGetCoverage(args: Record<string, unknown>): Promise<SessionProgressCoverageResult> {
    const sessionId = readSessionIdArg(args.sessionId);
    const kindFilter = args.kind === undefined ? undefined : readKindArg(args.kind);

    const bucket = this.sessions.get(sessionId);
    const counts = this.kindCountsFor(sessionId);

    const entries: SessionProgressEntry[] = [];
    for (const kind of PROGRESS_KINDS) {
      if (kindFilter && kind !== kindFilter) continue;
      const kindMap = bucket?.get(kind);
      if (!kindMap) continue;
      entries.push(...kindMap.values());
    }

    // Newest-first by first-recorded time; deterministic tie-break on kind then key.
    entries.sort(
      (a, b) =>
        b.recordedAt - a.recordedAt || a.kind.localeCompare(b.kind) || a.key.localeCompare(b.key),
    );

    return {
      sessionId,
      counts,
      total: entries.length,
      entries: entries.map(serializeEntry),
    };
  }

  // ── session_progress_clear ──

  async handleClearProgressTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleClearProgress(args));
  }

  async handleClearProgress(args: Record<string, unknown>): Promise<SessionProgressClearResult> {
    const sessionId = readSessionIdArg(args.sessionId);
    const kindFilter = args.kind === undefined ? undefined : readKindArg(args.kind);

    const bucket = this.sessions.get(sessionId);
    if (!bucket) {
      return kindFilter ? { cleared: 0, sessionId, kind: kindFilter } : { cleared: 0, sessionId };
    }

    let cleared = 0;
    for (const kind of PROGRESS_KINDS) {
      if (kindFilter && kind !== kindFilter) continue;
      const kindMap = bucket.get(kind);
      if (!kindMap) continue;
      cleared += kindMap.size;
      bucket.delete(kind);
    }

    // Drop the session bucket entirely once empty so cleared sessions do not
    // accumulate in the sessions map.
    if (bucket.size === 0) {
      this.sessions.delete(sessionId);
    }

    return kindFilter ? { cleared, sessionId, kind: kindFilter } : { cleared, sessionId };
  }

  // ── Helpers ──

  private getOrCreateKindMap(
    sessionId: string,
    kind: SessionProgressKind,
  ): Map<string, SessionProgressEntry> {
    let bucket = this.sessions.get(sessionId);
    if (!bucket) {
      bucket = new Map();
      this.sessions.set(sessionId, bucket);
    }
    let kindMap = bucket.get(kind);
    if (!kindMap) {
      kindMap = new Map();
      bucket.set(kind, kindMap);
    }
    return kindMap;
  }

  private kindCountsFor(sessionId: string): {
    process: number;
    hookPoint: number;
    protocolField: number;
  } {
    const counts = { process: 0, hookPoint: 0, protocolField: 0 };
    const bucket = this.sessions.get(sessionId);
    if (!bucket) return counts;
    for (const kind of PROGRESS_KINDS) {
      counts[KIND_COUNT_KEYS[kind] as keyof typeof counts] = bucket.get(kind)?.size ?? 0;
    }
    return counts;
  }
}

// ── Arg helpers ──

function readKindArg(value: unknown): SessionProgressKind {
  if (isProgressKind(value)) return value;
  throw new Error(
    `Invalid kind. Expected one of: ${PROGRESS_KINDS.map((k) => `'${k}'`).join(', ')}`,
  );
}

function isProgressKind(value: unknown): value is SessionProgressKind {
  return value === 'process' || value === 'hook-point' || value === 'protocol-field';
}

function readKeyArg(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('key is required and must be a non-empty string');
  }
  return value;
}

function readSessionIdArg(value: unknown): string {
  if (typeof value === 'string' && value.length > 0) return value;
  return SESSION_PROGRESS_DEFAULT_SESSION_ID;
}

function readMetadataArg(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('metadata must be a plain object when provided');
  }
  return value as Record<string, unknown>;
}

function serializeEntry(entry: SessionProgressEntry): SessionProgressCoverageEntry {
  return {
    kind: entry.kind,
    key: entry.key,
    recordedAt: new Date(entry.recordedAt).toISOString(),
    ...(entry.metadata !== undefined ? { metadata: entry.metadata } : {}),
  };
}
