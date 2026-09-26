/**
 * Production wiring for `ServerEventMap['task:update']`.
 *
 * TaskManager is the genuine status-transition point (MCP 2.0 Tasks protocol):
 * its `TaskRecord` already carries `taskId` / `status` / `sessionId`, and its
 * `working -> completed | failed | cancelled` machine is exactly what a
 * session-scoped SSE stream is meant to observe. These tests prove the emitter
 * is real: one `task:update` per transition, carrying the real taskId/status,
 * and a session-scoped `SseStream` subscriber actually receives it.
 */

import { describe, expect, it } from 'vitest';
import type { ServerResponse } from 'node:http';
import { createServerEventBus, type ServerEventMap } from '@server/EventBus';
import { SseStream } from '@server/http/SseStream';
import { runWithToolRequestContext } from '@server/runtime/ToolRequestContext';
import { TaskManager } from '@server/tasks/TaskManager';

type TaskUpdate = ServerEventMap['task:update'];

function collect(bus: ReturnType<typeof createServerEventBus>): TaskUpdate[] {
  const seen: TaskUpdate[] = [];
  bus.on('task:update', (payload) => {
    seen.push(payload);
  });
  return seen;
}

function createMockResponse() {
  const writes: string[] = [];
  const mockRes = {
    writes,
    writableEnded: false,
    writeHead: () => mockRes,
    setHeader: () => {},
    write: (chunk: string) => {
      writes.push(chunk);
      return true;
    },
    end: () => {
      mockRes.writableEnded = true;
    },
    on: () => {},
  };
  return mockRes;
}

const settle = (ms = 25) => new Promise((resolve) => setTimeout(resolve, ms));

describe('TaskManager -> task:update (production wiring)', () => {
  it('emits exactly one task:update per status transition, with the real taskId/status/sessionId', async () => {
    const bus = createServerEventBus();
    const manager = new TaskManager({ eventBus: bus });
    const seen = collect(bus);

    const task = await runWithToolRequestContext({ sessionId: 'session-a' }, () =>
      manager.createTask({ name: 'frida_scan', executor: async () => ({ matched: 42 }) }),
    );
    await settle();

    // One emission per transition — no duplicates, no missed transition.
    expect(seen.map((e) => e.status)).toEqual(['working', 'completed']);

    const completed = seen.filter((e) => e.status === 'completed');
    expect(completed).toHaveLength(1);
    expect(completed[0]!.taskId).toBe(task.taskId);
    expect(completed[0]!.sessionId).toBe('session-a');
    expect(typeof completed[0]!.timestamp).toBe('string');
    // Real progress metadata, not a constant placeholder.
    expect(completed[0]!.data?.name).toBe('frida_scan');
    expect(completed[0]!.data?.progress).toBe(100);
  });

  it('emits a single cancelled transition when a working task is cancelled', async () => {
    const bus = createServerEventBus();
    const manager = new TaskManager({ eventBus: bus });
    const seen = collect(bus);

    const task = await runWithToolRequestContext({ sessionId: 'session-a' }, () =>
      manager.createTask({
        name: 'hung_scan',
        executor: () => new Promise(() => undefined),
      }),
    );
    await manager.cancelTask(task.taskId, 'session-a');
    await settle();

    expect(seen.map((e) => e.status)).toEqual(['working', 'cancelled']);
    expect(seen.at(-1)!.taskId).toBe(task.taskId);
    expect(seen.at(-1)!.sessionId).toBe('session-a');
  });

  it('omits sessionId for process-level tasks instead of inventing one', async () => {
    const bus = createServerEventBus();
    const manager = new TaskManager({ eventBus: bus });
    const seen = collect(bus);

    // No request context -> task.sessionId is null.
    await manager.createTask({ name: 'process_task', executor: async () => 'ok' });
    await settle();

    expect(seen).not.toHaveLength(0);
    for (const event of seen) {
      expect(event.sessionId).toBeUndefined();
    }
  });

  it('reaches a session-scoped SseStream subscriber (the existing subscriber finally fires)', async () => {
    const bus = createServerEventBus();
    const manager = new TaskManager({ eventBus: bus });
    const res = createMockResponse();
    const stream = new SseStream(bus, { sessionId: 'session-a' });
    stream.start(res as unknown as ServerResponse);

    try {
      await runWithToolRequestContext({ sessionId: 'session-a' }, () =>
        manager.createTask({ name: 'pcap_capture', executor: async () => 'ok' }),
      );
      await settle(50);

      const frames = res.writes.filter((w) => w.includes('event: task:update'));
      expect(frames.length).toBeGreaterThan(0);
      expect(frames.some((f) => f.includes('session-a'))).toBe(true);
    } finally {
      stream.close();
    }
  });

  it("drops a foreign session's task:update (proves sessionId is the owning session, not a constant)", async () => {
    const bus = createServerEventBus();
    const manager = new TaskManager({ eventBus: bus });
    const res = createMockResponse();
    const stream = new SseStream(bus, { sessionId: 'session-b' });
    stream.start(res as unknown as ServerResponse);

    try {
      await runWithToolRequestContext({ sessionId: 'session-a' }, () =>
        manager.createTask({ name: 'owned_by_a', executor: async () => 'ok' }),
      );
      await settle(50);

      const frames = res.writes.filter((w) => w.includes('event: task:update'));
      expect(frames).toHaveLength(0);
    } finally {
      stream.close();
    }
  });
});
