/**
 * GET /events — unified Server-Sent Events mirror of the server EventBus.
 *
 * A single bus drives MCP execution telemetry and this SSE surface (the
 * "shared-mirror" pattern): long-running clients (e.g. orchestration agents)
 * subscribe to tool execution / gate / activation events without holding an
 * MCP session open.
 *
 * Contract:
 * - Each bus event is written as exactly one frame: `data: {json}\n\n` where
 *   the JSON is `{ event, payload }` (single line — JSON escapes newlines).
 * - Heartbeat comment frames (`:ping\n\n`) every SSE_EVENTS_HEARTBEAT_MS to
 *   defeat idle proxy timeouts.
 * - Only the metadata-only allowlisted events are mirrored. Payloads are
 *   additionally scrubbed of sensitive keys as defense in depth — tool
 *   arguments and results must never reach this stream.
 * - Client disconnects unsubscribe; a bounded replay buffer (most recent
 *   events observed while at least one subscriber was attached) is flushed to
 *   each new connection before live events.
 * - Authentication is NOT applied here: the route in MCPServer.transport.ts
 *   runs the same checkOrigin/checkAuth/checkRateLimit chain as POST /mcp
 *   (Bearer MCP_AUTH_TOKEN when configured). This handler never bypasses it.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { EventBus, ServerEventMap } from '@server/EventBus';
import { logger } from '@utils/logger';

/** Heartbeat interval for /events (comment frames keep idle proxies open). */
export const SSE_EVENTS_HEARTBEAT_MS = 15_000;

/** Replay buffer capacity: most recent mirrored events flushed to new clients. */
export const SSE_EVENTS_REPLAY_LIMIT = 100;

/** Upper bound on concurrent /events streams (each is a long-lived socket). */
export const SSE_EVENTS_MAX_CLIENTS = 32;

/**
 * Bus events mirrored to SSE subscribers. Metadata-only by contract — see the
 * corresponding payloads in @server/EventBus ServerEventMap.
 */
export const SSE_EVENT_ALLOWLIST: ReadonlySet<string> = new Set([
  'tool.execution.started',
  'tool.execution.finished',
  'tool.gate.denied',
  'tool.activation.changed',
]);

/**
 * Payload keys stripped defensively before an event reaches the stream. The
 * allowlisted events never carry these, but a future emitter regression must
 * not turn /events into a data-exfiltration channel.
 */
const SENSITIVE_PAYLOAD_KEYS: ReadonlySet<string> = new Set([
  'args',
  'result',
  'content',
  'params',
  '_meta',
]);

/**
 * Shallow-clone and strip sensitive keys from an event payload. Non-object
 * payloads pass through untouched.
 */
export function sanitizeEventPayload(payload: unknown): unknown {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return payload;
  }
  const source = payload as Record<string, unknown>;
  let scrubbed: Record<string, unknown> | null = null;
  for (const key of Object.keys(source)) {
    if (!SENSITIVE_PAYLOAD_KEYS.has(key)) continue;
    scrubbed ??= { ...source };
    delete scrubbed[key];
  }
  return scrubbed ?? source;
}

/**
 * Pure SSE frame builder: one bus event → one `data:` line + blank line.
 * JSON.stringify escapes embedded newlines, so the payload can never split
 * the frame across multiple lines.
 */
export function formatBusEventFrame(event: string, payload: unknown): string {
  return `data: ${JSON.stringify({ event, payload: sanitizeEventPayload(payload) })}\n\n`;
}

interface RecordedEvent {
  event: string;
  payload: unknown;
}

export interface EventsEndpointStats {
  activeClients: number;
  buffered: number;
}

export interface EventsEndpoint {
  handleRequest(req: IncomingMessage, res: ServerResponse): void;
  /** Test/observability introspection. */
  getStats(): EventsEndpointStats;
}

export interface EventsEndpointOptions {
  heartbeatMs?: number;
  replayLimit?: number;
  maxClients?: number;
}

/**
 * Create the /events request handler bound to one EventBus.
 *
 * A wildcard recorder is attached lazily while at least one client is
 * connected (zero overhead otherwise); the bounded buffer survives after the
 * last client disconnects so a reconnecting consumer still gets a replay.
 * The recorder is detached when idle — no lifecycle coupling to server close.
 */
export function createEventsEndpoint(
  eventBus: EventBus<ServerEventMap> | undefined | null,
  options: EventsEndpointOptions = {},
): EventsEndpoint {
  const heartbeatMs = options.heartbeatMs ?? SSE_EVENTS_HEARTBEAT_MS;
  const replayLimit = options.replayLimit ?? SSE_EVENTS_REPLAY_LIMIT;
  const maxClients = options.maxClients ?? SSE_EVENTS_MAX_CLIENTS;

  let activeClients = 0;
  let recorderAttached = false;
  let detachRecorder: (() => void) | null = null;
  const replayBuffer: RecordedEvent[] = [];

  const ensureRecorder = (): void => {
    if (recorderAttached || !eventBus || typeof eventBus.onAny !== 'function') return;
    recorderAttached = true;
    detachRecorder = eventBus.onAny(({ event, payload }) => {
      if (!SSE_EVENT_ALLOWLIST.has(event)) return;
      replayBuffer.push({ event, payload: sanitizeEventPayload(payload) });
      if (replayBuffer.length > replayLimit) {
        replayBuffer.splice(0, replayBuffer.length - replayLimit);
      }
    });
  };

  const maybeDetachRecorder = (): void => {
    if (!recorderAttached || activeClients > 0) return;
    detachRecorder?.();
    detachRecorder = null;
    recorderAttached = false;
  };

  const handleRequest = (req: IncomingMessage, res: ServerResponse): void => {
    if (!eventBus || typeof eventBus.onAny !== 'function') {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('Service Unavailable – event bus not initialized');
      return;
    }
    if ((req.method ?? 'GET').toUpperCase() !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed – use GET /events');
      return;
    }
    if (activeClients >= maxClients) {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end(`Service Unavailable – /events stream limit reached (${maxClients})`);
      return;
    }

    activeClients += 1;
    // Attach the recorder BEFORE reading the buffer inside this synchronous
    // setup: events emitted before this call are already buffered, events
    // after it reach the live subscription — no gap, no duplicates.
    ensureRecorder();

    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    // Auth/contract documentation lives in comment frames (SSE clients ignore
    // colon-prefixed lines). Auth itself is enforced by the /events route in
    // MCPServer.transport.ts — same chain as POST /mcp.
    res.write(': jshookmcp unified event stream (GET /events)\n');
    res.write(
      ': auth mirrors POST /mcp (Bearer MCP_AUTH_TOKEN when configured); ' +
        'payloads are metadata-only\n\n',
    );
    for (const recorded of replayBuffer) {
      res.write(formatBusEventFrame(recorded.event, recorded.payload));
    }

    // Per-connection teardown state. A holder object keeps the hoisted
    // cleanup/write helpers free of use-before-declaration ordering hazards.
    const stream: {
      cleanedUp: boolean;
      heartbeat?: NodeJS.Timeout;
      unsubscribe?: () => void;
    } = { cleanedUp: false };

    // Hoisted function declarations: the live subscription, heartbeat, and
    // disconnect handlers all close over these.
    function cleanupClient(): void {
      if (stream.cleanedUp) return;
      stream.cleanedUp = true;
      if (stream.heartbeat) clearInterval(stream.heartbeat);
      try {
        stream.unsubscribe?.();
      } catch (error) {
        logger.warn('Failed to unsubscribe /events client:', error);
      }
      activeClients = Math.max(0, activeClients - 1);
      maybeDetachRecorder();
    }

    function writeFrame(frame: string): void {
      if (stream.cleanedUp) return;
      try {
        res.write(frame);
      } catch (error) {
        logger.debug?.('Failed to write /events frame:', error);
        cleanupClient();
      }
    }

    stream.unsubscribe = eventBus.onAny(({ event, payload }) => {
      if (!SSE_EVENT_ALLOWLIST.has(event)) return;
      writeFrame(formatBusEventFrame(event, payload));
    });

    stream.heartbeat = setInterval(() => {
      // Colon-prefixed comment frames are ignored by SSE clients but keep the
      // connection (and intermediate proxies) alive.
      writeFrame(':ping\n\n');
    }, heartbeatMs);
    // A heartbeat must never keep the process alive on its own.
    stream.heartbeat.unref?.();

    // Client disconnect (abort/close) and socket errors both terminate the
    // subscription; cleanup is idempotent.
    res.on('close', cleanupClient);
    res.on('error', (error) => {
      logger.debug?.('/events stream error:', error);
      cleanupClient();
    });
  };

  return {
    handleRequest,
    getStats(): EventsEndpointStats {
      return { activeClients, buffered: replayBuffer.length };
    },
  };
}
