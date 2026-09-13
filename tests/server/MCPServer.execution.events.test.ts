/**
 * Unified event-stream publication tests for executeToolWithTracking().
 *
 * Covers the metadata-only tool.execution.started / tool.execution.finished /
 * tool.gate.denied events (shape + pairing + sensitive-payload absence) and
 * observer-fault isolation: a throwing event listener must never break tool
 * execution.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
  getToolDomain: vi.fn(() => 'browser'),
  refreshDomainTtlForTool: vi.fn(),
  getToolRequestContext: vi.fn(() => null),
  shouldCollectExecutionMetrics: vi.fn(() => false),
  BrowserSessionQueueError: class extends Error {
    code = 'QUEUE_FULL';
    retryAfterMs = 100;
    queueDepth = 3;
    queueLimit = 5;
  },
  BrowserFleetLeaseError: class extends Error {},
  SessionScopedResourcePoolCapacityError: class extends Error {},
}));

vi.mock('@utils/logger', () => ({ logger: mocks.logger }));
vi.mock('@server/ToolCatalog', () => ({ getToolDomain: mocks.getToolDomain }));
vi.mock('@server/MCPServer.activation.ttl', () => ({
  refreshDomainTtlForTool: mocks.refreshDomainTtlForTool,
}));
vi.mock('@server/runtime/ToolRequestContext', () => ({
  getToolRequestContext: mocks.getToolRequestContext,
}));
vi.mock('@server/MCPServer.metrics', () => ({
  shouldCollectExecutionMetrics: mocks.shouldCollectExecutionMetrics,
}));
vi.mock('@server/runtime/BrowserSessionCoordinator', () => ({
  BrowserSessionQueueError: mocks.BrowserSessionQueueError,
  parseBrowserSessionSnapshot: vi.fn(() => ({})),
}));
vi.mock('@server/runtime/BrowserFleetRouter', () => ({
  BrowserFleetLeaseError: mocks.BrowserFleetLeaseError,
}));
vi.mock('@server/runtime/SessionScopedResourcePool', () => ({
  SessionScopedResourcePoolCapacityError: mocks.SessionScopedResourcePoolCapacityError,
}));
vi.mock('@server/runtime/ServerRuntimeState', () => ({
  getRuntimeState: () => undefined,
}));

import { createServerEventBus, type ServerEventMap } from '@server/EventBus';
import { executeToolWithTracking } from '@server/MCPServer.execution';
import { R } from '@server/domains/shared/ResponseBuilder';
import type { MCPServerContext } from '@server/MCPServer.context';

type StartedEvent = ServerEventMap['tool.execution.started'];
type FinishedEvent = ServerEventMap['tool.execution.finished'];
type GateDeniedEvent = ServerEventMap['tool.gate.denied'];

function createCtx(
  routerExecute: () => Promise<unknown>,
  overrides: { doomLoopTrip?: unknown } = {},
): MCPServerContext {
  return {
    circuitBreaker: {
      shouldBlock: vi.fn(() => false),
      getState: () => null,
      getRecoveryMs: () => 30_000,
      recordSuccess: vi.fn(),
      recordFailure: vi.fn(),
    },
    contextGuard: {
      isContextSensitive: () => false,
      recordCall: vi.fn(),
      recordDoomLoopCall: vi.fn(() => overrides.doomLoopTrip ?? null),
      enrichResponse: (_name: string, response: unknown) => response,
    },
    router: { execute: routerExecute },
    largeDataOffloader: { offload: vi.fn() },
    getDomainInstance: () => undefined,
    tokenBudget: { recordToolCall: vi.fn() },
    activatedToolNames: new Set<string>(),
    domainTtlEntries: new Map(),
    extensionToolsByName: new Map(),
    eventBus: createServerEventBus(),
    mcpLog: { info: vi.fn() },
    server: { sendToolListChanged: vi.fn(async () => undefined) },
    enabledDomains: new Set(['browser']),
    selectedTools: [],
    activatedRegisteredTools: new Map(),
    routerImpl: undefined,
  } as unknown as MCPServerContext;
}

function withToolExecutionConfig(
  ctx: MCPServerContext,
  toolExecution: Record<string, unknown>,
): MCPServerContext {
  (ctx as unknown as { config: Record<string, unknown> }).config = { toolExecution };
  return ctx;
}

/** Collector wiring: subscribe to the three event-stream topics up front. */
function collect(ctx: MCPServerContext): {
  started: StartedEvent[];
  finished: FinishedEvent[];
  gateDenied: GateDeniedEvent[];
} {
  const bus = (ctx as unknown as { eventBus: ReturnType<typeof createServerEventBus> }).eventBus;
  const started: StartedEvent[] = [];
  const finished: FinishedEvent[] = [];
  const gateDenied: GateDeniedEvent[] = [];
  bus.on('tool.execution.started', (payload) => {
    started.push(payload);
  });
  bus.on('tool.execution.finished', (payload) => {
    finished.push(payload);
  });
  bus.on('tool.gate.denied', (payload) => {
    gateDenied.push(payload);
  });
  return { started, finished, gateDenied };
}

/** Flush the fire-and-forget emit chain (microtasks + wildcard allSettled). */
async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

describe('executeToolWithTracking — unified event stream publication', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('emits started then finished with metadata-only payloads on success', async () => {
    const ctx = createCtx(async () => R.ok().json());
    const events = collect(ctx);

    const response = await executeToolWithTracking(ctx, 'page_navigate', {
      url: 'https://secret.example',
    });
    await settle();

    expect(response).not.toMatchObject({ isError: true });
    expect(events.started).toHaveLength(1);
    expect(events.finished).toHaveLength(1);

    const started = events.started[0]!;
    expect(started).toEqual({
      toolName: 'page_navigate',
      domain: 'browser',
      sessionId: null,
      timestamp: expect.any(String),
    });

    const finished = events.finished[0]!;
    expect(finished).toEqual({
      toolName: 'page_navigate',
      domain: 'browser',
      sessionId: null,
      durationMs: expect.any(Number),
      ok: true,
      timestamp: expect.any(String),
    });
    expect(finished.durationMs).toBeGreaterThanOrEqual(0);
    // Metadata-only contract: no args/result/response payloads on the stream.
    expect(Object.keys(finished).toSorted()).toEqual([
      'domain',
      'durationMs',
      'ok',
      'sessionId',
      'timestamp',
      'toolName',
    ]);
    expect(JSON.stringify(events)).not.toContain('secret.example');
  });

  it('emits started + finished(ok:false) with a message-only errorSummary on throw', async () => {
    const ctx = createCtx(async () => {
      throw new Error('handler exploded');
    });
    const events = collect(ctx);

    await expect(executeToolWithTracking(ctx, 'page_navigate', {})).rejects.toThrow(
      'handler exploded',
    );
    await settle();

    expect(events.started).toHaveLength(1);
    expect(events.finished).toHaveLength(1);
    const finished = events.finished[0]!;
    expect(finished.ok).toBe(false);
    expect(finished.errorSummary).toBe('handler exploded');
    expect(finished.durationMs).toBeGreaterThanOrEqual(0);
    expect(JSON.stringify(finished)).not.toContain('stack');
  });

  it('emits gate.denied (source rules) and NO execution events on a rules deny', async () => {
    const routerExecute = vi.fn();
    const ctx = withToolExecutionConfig(createCtx(routerExecute), {
      allowTools: [],
      rules: [{ tool: 'page/*', action: 'deny' }],
    });
    const events = collect(ctx);

    const response = await executeToolWithTracking(ctx, 'page_navigate', {
      url: 'https://secret.example',
    });
    await settle();

    expect(response).toMatchObject({ isError: true });
    expect(routerExecute).not.toHaveBeenCalled();
    expect(events.started).toHaveLength(0);
    expect(events.finished).toHaveLength(0);
    expect(events.gateDenied).toHaveLength(1);

    const denied = events.gateDenied[0]!;
    expect(denied).toEqual({
      toolName: 'page_navigate',
      source: 'rules',
      rule: { tool: 'page/*', action: 'deny' },
      sessionId: null,
      timestamp: expect.any(String),
    });
    expect(JSON.stringify(denied)).not.toContain('secret.example');
  });

  it('reports the allowTools whitelist as the deny source for unlisted tools', async () => {
    const ctx = withToolExecutionConfig(createCtx(vi.fn()), {
      allowTools: ['page_navigate'],
      rules: [],
    });
    const events = collect(ctx);

    await executeToolWithTracking(ctx, 'console_execute', {});
    await settle();

    expect(events.gateDenied).toHaveLength(1);
    expect(events.gateDenied[0]).toMatchObject({
      toolName: 'console_execute',
      source: 'allowTools',
      rule: { tool: '*', action: 'deny' },
    });
  });

  it('emits gate.denied (source doom-loop) with trip counters and no rule', async () => {
    const ctx = createCtx(vi.fn(), {
      doomLoopTrip: { count: 5, threshold: 5, fullAdvisory: true },
    });
    const events = collect(ctx);

    const response = await executeToolWithTracking(ctx, 'page_navigate', { url: 'https://x' });
    await settle();

    expect(response).toMatchObject({ isError: true });
    expect(events.gateDenied).toHaveLength(1);
    expect(events.gateDenied[0]).toEqual({
      toolName: 'page_navigate',
      source: 'doom-loop',
      rule: null,
      consecutiveCount: 5,
      threshold: 5,
      sessionId: null,
      timestamp: expect.any(String),
    });
    expect(events.started).toHaveLength(0);
  });

  it('keeps tool execution working when an event observer throws', async () => {
    const ctx = createCtx(async () => R.ok().json());
    const bus = (ctx as unknown as { eventBus: ReturnType<typeof createServerEventBus> }).eventBus;
    bus.on('tool.execution.started', () => {
      throw new Error('observer blew up');
    });
    bus.on('tool.execution.finished', () => {
      throw new Error('observer blew up again');
    });

    const response = await executeToolWithTracking(ctx, 'page_navigate', {});
    await settle();

    expect(response).not.toMatchObject({ isError: true });
    expect(ctx.circuitBreaker.recordSuccess).toHaveBeenCalledWith('page_navigate');
  });

  it('resolves the sessionId from _meta for event metadata', async () => {
    const ctx = createCtx(async () => R.ok().json());
    const events = collect(ctx);

    await executeToolWithTracking(ctx, 'page_navigate', {
      _meta: { sessionId: '  agent-session-1  ' },
    });
    await settle();

    expect(events.started[0]!.sessionId).toBe('agent-session-1');
    expect(events.finished[0]!.sessionId).toBe('agent-session-1');
  });
});
