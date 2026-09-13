/**
 * GET /events unified SSE endpoint tests.
 *
 * Pure-function coverage (frame formatting with sequence numbers, gap notices,
 * resume-point parsing, payload sanitization) plus a lightweight integration
 * suite against a real node:http server bound to 127.0.0.1:0. All assertions
 * are event-driven (stream reads / state polls) — no fixed sleeps.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createServerEventBus, type ServerEventMap } from '@server/EventBus';
import {
  SSE_EVENT_ALLOWLIST,
  createEventsEndpoint,
  formatBusEventFrame,
  formatGapFrame,
  parseResumeSequence,
  sanitizeEventPayload,
  type EventsEndpoint,
} from '@server/http/EventsEndpoint';

describe('formatBusEventFrame / sanitizeEventPayload (pure)', () => {
  it('renders one id+data frame per bus event with the seq only in the id line', () => {
    const payload = { toolName: 'page_navigate', sessionId: null };
    const frame = formatBusEventFrame('tool.execution.started', payload, 7);
    const json = JSON.stringify({ event: 'tool.execution.started', payload });
    expect(frame).toBe(`id: 7\ndata: ${json}\n\n`);
    // Exactly one id line and one single-line data line — the JSON payload can
    // never split the frame across extra lines, and no seq key leaks into it.
    expect(frame.split('\n')).toEqual([`id: 7`, `data: ${json}`, '', '']);
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

describe('formatGapFrame (pure)', () => {
  it('renders an event: gap frame naming the requested and oldest sequences', () => {
    expect(formatGapFrame(1, 3)).toBe('event: gap\ndata: {"since":1,"oldestAvailable":3}\n\n');
  });
});

describe('parseResumeSequence (pure)', () => {
  it('prefers the standard Last-Event-ID header over ?since=', () => {
    expect(parseResumeSequence({ headers: { 'last-event-id': '4' }, url: '/events?since=9' })).toBe(
      4,
    );
  });

  it('falls back to the ?since= query parameter', () => {
    expect(parseResumeSequence({ headers: {}, url: '/events?since=9' })).toBe(9);
    expect(
      parseResumeSequence({ headers: { 'last-event-id': 'bogus' }, url: '/events?since=9' }),
    ).toBe(9);
    expect(parseResumeSequence({ headers: {}, url: '/events' })).toBeNull();
    expect(parseResumeSequence({ headers: {}, url: undefined })).toBeNull();
  });

  it('accepts zero and array-form headers, treats unusable values as absent', () => {
    expect(parseResumeSequence({ headers: { 'last-event-id': ['7'] }, url: '/events' })).toBe(7);
    expect(parseResumeSequence({ headers: {}, url: '/events?since=0' })).toBe(0);
    expect(
      parseResumeSequence({ headers: { 'last-event-id': 'not-a-number' }, url: '/events' }),
    ).toBeNull();
    expect(parseResumeSequence({ headers: { 'last-event-id': '-3' }, url: '/events' })).toBeNull();
    expect(
      parseResumeSequence({ headers: { 'last-event-id': '' }, url: '/events?since=oops' }),
    ).toBeNull();
  });

  it('survives a malformed request target', () => {
    expect(parseResumeSequence({ headers: {}, url: 'http://[' })).toBeNull();
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

interface RecordedFrame {
  seq: number;
  event: string;
  payload: unknown;
}

/** Parse `id: N` + `data: {...}` event frames (comments, heartbeats, gap notices excluded). */
function eventFrames(frames: string[]): RecordedFrame[] {
  const parsed: RecordedFrame[] = [];
  for (const frame of frames) {
    if (!frame.startsWith('id: ')) continue;
    const lines = frame.split('\n');
    const idLine = lines.find((line) => line.startsWith('id: '));
    const dataLine = lines.find((line) => line.startsWith('data: '));
    if (!idLine || !dataLine) continue;
    const body = JSON.parse(dataLine.slice('data: '.length)) as {
      event: string;
      payload: unknown;
    };
    parsed.push({
      seq: Number(idLine.slice('id: '.length)),
      event: body.event,
      payload: body.payload,
    });
  }
  return parsed;
}

function startedEvent(toolName: string): ServerEventMap['tool.execution.started'] {
  return {
    toolName,
    domain: 'browser',
    sessionId: 'sess-1',
    timestamp: new Date().toISOString(),
  };
}

async function connect(
  url: string,
  headers?: Record<string, string>,
): Promise<{ res: Response; abort: () => void }> {
  const controller = new AbortController();
  const res = await fetch(url, { signal: controller.signal, headers });
  return { res, abort: () => controller.abort() };
}

afterEach(async () => {
  await stopAll();
});

describe('GET /events (integration, ephemeral port)', () => {
  it('streams bus events as id+data SSE frames and unsubscribes on client abort', async () => {
    const { bus, endpoint, url } = await startEventsServer();
    const { res, abort } = await connect(url);

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/event-stream');

    await bus.emit('tool.execution.started', startedEvent('page_navigate'));

    const { frames, raw } = await readUntil(res, (collected) => eventFrames(collected).length >= 1);
    const events = eventFrames(frames);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      seq: 1,
      event: 'tool.execution.started',
      payload: { toolName: 'page_navigate', sessionId: 'sess-1' },
    });
    // Sequence lives in the id line only — the JSON payload stays pure.
    expect(raw).not.toContain('"seq"');
    expect(endpoint.getStats().activeClients).toBe(1);

    // Abort → server-side unsubscribe (event-driven via the close listener).
    abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));
    expect(raw).not.toContain('secret');
  });

  it('keeps the stream alive with :ping heartbeat comment frames that carry no id', async () => {
    const { endpoint, url } = await startEventsServer({ heartbeatMs: 25 });
    const { res, abort } = await connect(url);

    const { frames } = await readUntil(res, (collected) => collected.includes(':ping'));
    const ping = frames.find((frame) => frame === ':ping');
    expect(ping).toBe(':ping');
    expect(ping).not.toContain('id:');
    abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));
  });

  it('numbers frames with a server-wide monotonic sequence shared across connections and replays', async () => {
    const { bus, endpoint, url } = await startEventsServer();

    const first = await connect(url);
    await bus.emit('tool.execution.started', startedEvent('e1'));
    await bus.emit('tool.execution.started', startedEvent('e2'));
    const live = await readUntil(first.res, (collected) => eventFrames(collected).length >= 2);
    expect(eventFrames(live.frames).map((frame) => frame.seq)).toEqual([1, 2]);
    expect(endpoint.getStats().lastSeq).toBe(2);
    first.abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));

    // Second connection: replay carries the SAME seqs, live continues the counter.
    const second = await connect(url);
    await bus.emit('tool.execution.started', startedEvent('e3'));
    const replayed = await readUntil(second.res, (collected) => eventFrames(collected).length >= 3);
    expect(eventFrames(replayed.frames).map((frame) => frame.seq)).toEqual([1, 2, 3]);
    expect(endpoint.getStats().lastSeq).toBe(3);
    second.abort();
  });

  it('replays the bounded buffer to a reconnecting client without Last-Event-ID (legacy behavior)', async () => {
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
      (collected) => eventFrames(collected).length >= 2,
    );
    const events = eventFrames(frames);
    expect(events.map((entry) => entry.event)).toEqual([
      'tool.gate.denied',
      'tool.execution.finished',
    ]);
    // Replay frames share the live counter and are contiguous.
    expect(events.map((entry) => entry.seq)).toEqual([1, 2]);
    second.abort();
  });

  it('resumes from Last-Event-ID and replays only frames newer than the resume point', async () => {
    const { bus, endpoint, url } = await startEventsServer();

    const first = await connect(url);
    for (const toolName of ['e1', 'e2', 'e3']) {
      await bus.emit('tool.execution.started', startedEvent(toolName));
    }
    await readUntil(first.res, (collected) => eventFrames(collected).length >= 3);
    first.abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));

    const second = await connect(url, { 'Last-Event-ID': '1' });
    await bus.emit('tool.execution.started', startedEvent('e4'));
    const resumed = await readUntil(second.res, (collected) => eventFrames(collected).length >= 3);
    const events = eventFrames(resumed.frames);
    // Only seqs 2 and 3 replayed, then the live event arrives as seq 4 — no
    // duplicates of seq 1, and no gap notice (the buffer covers seq 2+).
    expect(events.map((frame) => frame.seq)).toEqual([2, 3, 4]);
    expect(resumed.frames.some((frame) => frame.startsWith('event: gap'))).toBe(false);
    second.abort();
  });

  it('accepts ?since= as an equivalent resume point', async () => {
    const { bus, url } = await startEventsServer();

    const first = await connect(url);
    for (const toolName of ['e1', 'e2', 'e3']) {
      await bus.emit('tool.execution.started', startedEvent(toolName));
    }
    await readUntil(first.res, (collected) => eventFrames(collected).length >= 3);
    first.abort();

    const second = await connect(`${url}?since=2`);
    await bus.emit('tool.execution.started', startedEvent('e4'));
    const resumed = await readUntil(second.res, (collected) => eventFrames(collected).length >= 2);
    expect(eventFrames(resumed.frames).map((frame) => frame.seq)).toEqual([3, 4]);
    second.abort();
  });

  it('emits an event: gap notice when the resume point predates the oldest buffered frame', async () => {
    const { bus, endpoint, url } = await startEventsServer({ replayLimit: 3 });

    const first = await connect(url);
    for (let i = 1; i <= 5; i++) {
      await bus.emit('tool.execution.started', startedEvent(`e${i}`));
    }
    await readUntil(first.res, (collected) => eventFrames(collected).length >= 5);
    first.abort();
    await vi.waitFor(() => expect(endpoint.getStats().activeClients).toBe(0));

    // Buffer now holds seqs [3, 4, 5]; resuming at 1 means seq 2 is lost forever.
    const second = await connect(url, { 'Last-Event-ID': '1' });
    const resumed = await readUntil(second.res, (collected) => eventFrames(collected).length >= 3);
    expect(resumed.frames).toContain('event: gap\ndata: {"since":1,"oldestAvailable":3}');
    expect(eventFrames(resumed.frames).map((frame) => frame.seq)).toEqual([3, 4, 5]);
    second.abort();
  });

  it('treats an unparseable resume point as absent (legacy full replay)', async () => {
    const { bus, url } = await startEventsServer();

    const first = await connect(url);
    for (const toolName of ['e1', 'e2']) {
      await bus.emit('tool.execution.started', startedEvent(toolName));
    }
    await readUntil(first.res, (collected) => eventFrames(collected).length >= 2);
    first.abort();

    const second = await connect(url, { 'Last-Event-ID': 'not-a-number' });
    const replayed = await readUntil(second.res, (collected) => eventFrames(collected).length >= 2);
    expect(eventFrames(replayed.frames).map((frame) => frame.seq)).toEqual([1, 2]);
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

    await bus.emit('tool.execution.started', startedEvent('page_evaluate'));

    const { raw } = await readUntil(res, (collected) => eventFrames(collected).length >= 1);

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
