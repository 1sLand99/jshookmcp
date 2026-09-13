/**
 * GET /events unified SSE endpoint tests.
 *
 * Pure-function coverage (frame formatting, payload sanitization) plus a
 * lightweight integration suite against a real node:http server bound to
 * 127.0.0.1:0. All assertions are event-driven (stream reads / state polls) —
 * no fixed sleeps.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createServerEventBus, type ServerEventMap } from '@server/EventBus';
import {
  SSE_EVENT_ALLOWLIST,
  createEventsEndpoint,
  formatBusEventFrame,
  sanitizeEventPayload,
  type EventsEndpoint,
} from '@server/http/EventsEndpoint';

describe('formatBusEventFrame / sanitizeEventPayload (pure)', () => {
  it('renders one single-line data frame per bus event', () => {
    const frame = formatBusEventFrame('tool.execution.started', {
      toolName: 'page_navigate',
      sessionId: null,
    });
    expect(frame).toBe(
      `data: ${JSON.stringify({
        event: 'tool.execution.started',
        payload: { toolName: 'page_navigate', sessionId: null },
      })}\n\n`,
    );
    // JSON escapes newlines — the payload can never split the frame.
    expect(frame.slice(0, -2)).not.toContain('\n');
  });

  it('strips sensitive payload keys defensively', () => {
    const scrubbed = sanitizeEventPayload({
      toolName: 'page_evaluate',
      args: { expr: 'secret()' },
      result: { success: true },
      content: [{ type: 'text', text: 'secret' }],
      _meta: { sessionId: 's' },
      durationMs: 5,
    });
    expect(scrubbed).toEqual({ toolName: 'page_evaluate', durationMs: 5 });
  });

  it('passes through non-object payloads untouched', () => {
    expect(sanitizeEventPayload('plain')).toBe('plain');
    expect(sanitizeEventPayload(null)).toBeNull();
    expect(sanitizeEventPayload([1, 2])).toEqual([1, 2]);
  });
});

describe('SSE_EVENT_ALLOWLIST', () => {
  it('mirrors exactly the metadata-only execution/gate/activation topics', () => {
    expect([...SSE_EVENT_ALLOWLIST].toSorted()).toEqual([
      'tool.activation.changed',
      'tool.execution.finished',
      'tool.execution.started',
      'tool.gate.denied',
    ]);
  });
});

// ── Integration: real HTTP server on an ephemeral port ──────────────────────

interface RunningEndpoint {
  server: Server;
  endpoint: EventsEndpoint;
  url: string;
}

const runningServers: RunningEndpoint[] = [];

async function startEventsServer(options?: Parameters<typeof createEventsEndpoint>[1]): Promise<
  {
    bus: ReturnType<typeof createServerEventBus>;
  } & RunningEndpoint
> {
  const bus = createServerEventBus();
  const endpoint = createEventsEndpoint(bus, options);
  const server = createServer((req, res) => {
    endpoint.handleRequest(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const running: RunningEndpoint = { server, endpoint, url: `http://127.0.0.1:${port}/events` };
  runningServers.push(running);
  return { bus, ...running };
}

async function stopAll(): Promise<void> {
  const servers = runningServers.splice(0, runningServers.length);
  for (const { server } of servers) {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function splitFrames(raw: string): string[] {
  return raw.split('\n\n').filter((frame) => frame.length > 0);
}

/** Event-driven stream reader: resolves once the collected frames satisfy `predicate`. */
async function readUntil(
  res: Response,
  predicate: (frames: string[], raw: string) => boolean,
): Promise<{ frames: string[]; raw: string }> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let raw = '';
  for (;;) {
    const frames = splitFrames(raw);
    if (predicate(frames, raw)) return { frames, raw };
    const { done, value } = await reader.read();
    if (done) return { frames: splitFrames(raw), raw };
    raw += decoder.decode(value, { stream: true });
  }
}

function dataFrames(frames: string[]): { event: string; payload: unknown }[] {
  return frames
    .filter((frame) => frame.startsWith('data: '))
    .map(
      (frame) => JSON.parse(frame.slice('data: '.length)) as { event: string; payload: unknown },
    );
}

async function connect(url: string): Promise<{ res: Response; abort: () => void }> {
  const controller = new AbortController();
  const res = await fetch(url, { signal: controller.signal });
  return { res, abort: () => controller.abort() };
}

afterEach(async () => {
  await stopAll();
});

describe('GET /events (integration, ephemeral port)', () => {
  it('streams bus events as SSE data frames and unsubscribes on client abort', async () => {
    const { bus, endpoint, url } = await startEventsServer();
    const { res, abort } = await connect(url);

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/event-stream');

    await bus.emit('tool.execution.started', {
      toolName: 'page_navigate',
      domain: 'browser',
      sessionId: 'sess-1',
      timestamp: new Date().toISOString(),
    } satisfies ServerEventMap['tool.execution.started']);

    const { frames, raw } = await readUntil(res, (collected) =>
      collected.some((frame) => frame.startsWith('data: ')),
    );
    const events = dataFrames(frames);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      event: 'tool.execution.started',
      payload: { toolName: 'page_navigate', sessionId: 'sess-1' },
    });
    expect(endpoint.getStats().activeClients).toBe(1);

    // Abort → server-side unsubscribe (event-driven via the close listener).
    abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));
    expect(raw).not.toContain('secret');
  });

  it('keeps the stream alive with :ping heartbeat comment frames', async () => {
    const { endpoint, url } = await startEventsServer({ heartbeatMs: 25 });
    const { res, abort } = await connect(url);

    const { frames } = await readUntil(res, (collected) => collected.includes(':ping'));
    expect(frames).toContain(':ping');
    abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));
  });

  it('replays the bounded buffer to a reconnecting client', async () => {
    const { bus, url } = await startEventsServer();

    const first = await connect(url);
    await bus.emit('tool.gate.denied', {
      toolName: 'page_navigate',
      source: 'rules',
      rule: { tool: 'page/*', action: 'deny' },
      sessionId: null,
      timestamp: new Date().toISOString(),
    } satisfies ServerEventMap['tool.gate.denied']);
    await bus.emit('tool.execution.finished', {
      toolName: 'page_navigate',
      domain: 'browser',
      sessionId: null,
      durationMs: 12,
      ok: true,
      timestamp: new Date().toISOString(),
    } satisfies ServerEventMap['tool.execution.finished']);
    first.abort();

    const second = await connect(url);
    const { frames } = await readUntil(
      second.res,
      (collected) => collected.filter((frame) => frame.startsWith('data: ')).length >= 2,
    );
    const events = dataFrames(frames);
    expect(events.map((entry) => entry.event)).toEqual([
      'tool.gate.denied',
      'tool.execution.finished',
    ]);
    second.abort();
  });

  it('caps concurrent streams and rejects non-GET requests', async () => {
    const { url } = await startEventsServer({ maxClients: 1 });

    const first = await connect(url);
    expect(first.res.status).toBe(200);

    const secondController = new AbortController();
    const second = await fetch(url, { signal: secondController.signal });
    expect(second.status).toBe(503);
    secondController.abort();

    const post = await fetch(url, { method: 'POST' });
    expect(post.status).toBe(405);

    first.abort();
  });

  it('never delivers non-allowlisted bus events or sensitive payload keys', async () => {
    const { bus, url } = await startEventsServer();
    const { res, abort } = await connect(url);

    // Sensitive internal event: must not reach the stream at all.
    await bus.emit('tool:called', {
      toolName: 'page_evaluate',
      domain: 'browser',
      sessionId: null,
      timestamp: new Date().toISOString(),
      success: true,
      args: { expr: 'TOP-SECRET-ARGS' },
      result: { success: true },
    });

    await bus.emit('tool.execution.started', {
      toolName: 'page_evaluate',
      domain: 'browser',
      sessionId: null,
      timestamp: new Date().toISOString(),
    } satisfies ServerEventMap['tool.execution.started']);

    const { raw } = await readUntil(res, (collected) =>
      collected.some((frame) => frame.includes('tool.execution.started')),
    );

    expect(raw).not.toContain('tool:called');
    expect(raw).not.toContain('TOP-SECRET-ARGS');
    abort();
  });

  it('returns 503 when the endpoint is created without an event bus', async () => {
    const server = createServer((req, res) => {
      createEventsEndpoint(undefined).handleRequest(req, res);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/events`);
      expect(res.status).toBe(503);
    } finally {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
