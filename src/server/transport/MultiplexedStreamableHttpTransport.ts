import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type {
  Transport,
  TransportSendOptions,
} from '@modelcontextprotocol/sdk/shared/transport.js';
import type {
  JSONRPCMessage,
  MessageExtraInfo,
  RequestId,
} from '@modelcontextprotocol/sdk/types.js';
import {
  isJSONRPCErrorResponse,
  isJSONRPCNotification,
  isJSONRPCRequest,
  isJSONRPCResultResponse,
} from '@modelcontextprotocol/sdk/types.js';
import { logger } from '@utils/logger';

interface SessionRecord {
  sessionId: string;
  transport: StreamableHTTPServerTransport;
}

interface RequestRouteRecord {
  sessionId: string;
  originalId: RequestId;
  transport: StreamableHTTPServerTransport;
}

export interface MultiplexedStreamableHttpTransportOptions {
  onSessionClosed?: (sessionId: string) => void;
}

function getSessionHeader(req: IncomingMessage): string | null {
  const raw = req.headers['mcp-session-id'];
  if (Array.isArray(raw)) {
    return typeof raw[0] === 'string' && raw[0].trim().length > 0 ? raw[0].trim() : null;
  }
  return typeof raw === 'string' && raw.trim().length > 0 ? raw.trim() : null;
}

function keyForRequestId(id: RequestId): string {
  return typeof id === 'string' ? `s:${id}` : `n:${String(id)}`;
}

export class MultiplexedStreamableHttpTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;
  sessionId?: string;

  private started = false;
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly requestRoutes = new Map<string, RequestRouteRecord>();
  private readonly sessionOriginalToInternal = new Map<string, Map<string, string>>();
  private requestSequence = 0;

  constructor(private readonly options: MultiplexedStreamableHttpTransportOptions = {}) {}

  async start(): Promise<void> {
    if (this.started) {
      throw new Error('MultiplexedStreamableHttpTransport already started');
    }
    this.started = true;
  }

  async close(): Promise<void> {
    const sessions = [...this.sessions.values()];
    this.sessions.clear();
    this.requestRoutes.clear();
    this.sessionOriginalToInternal.clear();
    for (const session of sessions) this.notifySessionClosed(session.sessionId);
    await Promise.allSettled(sessions.map((session) => session.transport.close()));
    this.onclose?.();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    const routeKey = this.resolveRouteKey(message, options);
    if (routeKey) {
      const route = this.requestRoutes.get(routeKey);
      if (route) {
        const translatedMessage =
          isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)
            ? { ...message, id: route.originalId }
            : message;
        const translatedOptions =
          options?.relatedRequestId !== undefined
            ? { ...options, relatedRequestId: route.originalId }
            : options;
        await route.transport.send(translatedMessage, translatedOptions);
        if (isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) {
          this.releaseRequestRoute(routeKey, route);
        }
        return;
      }
    }

    const sessions = [...this.sessions.values()];
    if (sessions.length === 0) {
      return;
    }

    if (isJSONRPCNotification(message)) {
      await Promise.allSettled(sessions.map((session) => session.transport.send(message, options)));
      return;
    }

    if (sessions.length === 1) {
      await sessions[0]!.transport.send(message, options);
      return;
    }

    throw new Error('Ambiguous HTTP session for outbound request/response routing.');
  }

  async handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<void> {
    const sessionId = getSessionHeader(req);

    if (sessionId) {
      const existing = this.sessions.get(sessionId);
      if (!existing) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: `Unknown MCP session: ${sessionId}`,
            },
            id: null,
          }),
        );
        return;
      }
      await existing.transport.handleRequest(req, res, parsedBody);
      return;
    }

    const transport = this.createInnerTransport();
    await transport.handleRequest(req, res, parsedBody);

    if (transport.sessionId && !this.sessions.has(transport.sessionId)) {
      this.sessions.set(transport.sessionId, {
        sessionId: transport.sessionId,
        transport,
      });
    }
  }

  private createInnerTransport(): StreamableHTTPServerTransport {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });

    // eslint-disable-next-line unicorn/prefer-add-event-listener
    transport.onmessage = (message, extra) => {
      const currentSessionId = transport.sessionId;
      const rewritten = currentSessionId
        ? this.rewriteInboundMessage(currentSessionId, transport, message)
        : message;

      this.onmessage?.(rewritten as typeof message, {
        ...extra,
      });
    };

    // eslint-disable-next-line unicorn/prefer-add-event-listener
    transport.onerror = (error) => {
      this.onerror?.(error);
    };

    // eslint-disable-next-line unicorn/prefer-add-event-listener
    transport.onclose = () => {
      if (transport.sessionId) {
        this.dropSession(transport.sessionId);
      }
    };

    return transport;
  }

  private rewriteInboundMessage(
    sessionId: string,
    transport: StreamableHTTPServerTransport,
    message: JSONRPCMessage,
  ): JSONRPCMessage {
    if (isJSONRPCRequest(message)) {
      const internalId = `http:${sessionId}:${++this.requestSequence}`;
      this.requestRoutes.set(internalId, {
        sessionId,
        originalId: message.id,
        transport,
      });
      let perSession = this.sessionOriginalToInternal.get(sessionId);
      if (!perSession) {
        perSession = new Map<string, string>();
        this.sessionOriginalToInternal.set(sessionId, perSession);
      }
      perSession.set(keyForRequestId(message.id), internalId);
      const params =
        typeof message.params === 'object' && message.params !== null
          ? (message.params as Record<string, unknown>)
          : {};
      const meta =
        typeof params['_meta'] === 'object' && params['_meta'] !== null
          ? (params['_meta'] as Record<string, unknown>)
          : {};
      return {
        ...message,
        id: internalId,
        params: {
          ...params,
          _meta: {
            ...meta,
            sessionId,
          },
        },
      };
    }

    if (isJSONRPCNotification(message) && message.method === 'notifications/cancelled') {
      const params =
        typeof message.params === 'object' && message.params !== null
          ? (message.params as Record<string, unknown>)
          : null;
      const requestId = params?.['requestId'];
      if (typeof requestId === 'string' || typeof requestId === 'number') {
        const internalId = this.sessionOriginalToInternal
          .get(sessionId)
          ?.get(keyForRequestId(requestId as RequestId));
        if (internalId) {
          return {
            ...message,
            params: {
              ...params,
              requestId: internalId,
            },
          };
        }
      }
    }

    return message;
  }

  private resolveRouteKey(message: JSONRPCMessage, options?: TransportSendOptions): string | null {
    if (options?.relatedRequestId !== undefined) {
      return String(options.relatedRequestId);
    }
    if (isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) {
      return String(message.id);
    }
    return null;
  }

  private releaseRequestRoute(routeKey: string, route: RequestRouteRecord): void {
    this.requestRoutes.delete(routeKey);
    const perSession = this.sessionOriginalToInternal.get(route.sessionId);
    if (!perSession) {
      return;
    }
    perSession.delete(keyForRequestId(route.originalId));
    if (perSession.size === 0) {
      this.sessionOriginalToInternal.delete(route.sessionId);
    }
  }

  private dropSession(sessionId: string): void {
    const existed = this.sessions.delete(sessionId);
    this.sessionOriginalToInternal.delete(sessionId);
    for (const [routeKey, route] of this.requestRoutes) {
      if (route.sessionId === sessionId) {
        this.requestRoutes.delete(routeKey);
      }
    }
    if (existed) this.notifySessionClosed(sessionId);
    logger.info(`[http] MCP session closed: ${sessionId}`);
  }

  private notifySessionClosed(sessionId: string): void {
    try {
      this.options.onSessionClosed?.(sessionId);
    } catch (error) {
      logger.warn(
        `[http] session cleanup failed for ${sessionId}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
