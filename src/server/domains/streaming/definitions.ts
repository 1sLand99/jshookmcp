import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { tool } from '@server/registry/tool-builder';

export const streamingTools: Tool[] = [
  tool('ws_monitor', (t) =>
    t
      .desc('Enable or disable WebSocket frame capture.')
      .enum('action', ['enable', 'disable'], 'Monitor action')
      .string('urlFilter', 'Regex filter for WebSocket URL (action=enable)')
      .number('maxFrames', 'Maximum frames in memory (action=enable, default: 1000)', {
        default: 1000,
        minimum: 1,
        maximum: 20000,
      })
      .required('action')
      .destructive(),
  ),
  tool('ws_get_frames', (t) =>
    t
      .desc('Get captured WebSocket frames with pagination and payload filter.')
      .enum('direction', ['sent', 'received', 'all'], 'Frame direction filter', { default: 'all' })
      .number('limit', 'Maximum frames to return', { default: 100, minimum: 1, maximum: 10000 })
      .number('offset', 'Pagination offset', { default: 0, minimum: 0 })
      .string('payloadFilter', 'Regex filter on frame payload')
      .boolean('fullPayload', 'Include the full captured payload for each returned frame', {
        default: false,
      })
      .readOnly(),
  ),
  tool('ws_get_connections', (t) =>
    t.desc('Get tracked WebSocket connections, frame counts, and timing metadata.').readOnly(),
  ),
  tool('ws_export_capture', (t) =>
    t
      .desc('Export captured WebSocket frames to artifacts/captures as JSON or NDJSON.')
      .enum('format', ['json', 'ndjson'], 'Export file format', { default: 'json' })
      .enum('direction', ['sent', 'received', 'all'], 'Frame direction filter', { default: 'all' })
      .string('payloadFilter', 'Regex filter on frame payload')
      .boolean('includePayload', 'Include full captured payloads in the artifact', {
        default: true,
      })
      .openWorld(),
  ),
  tool('sse_monitor_enable', (t) =>
    t
      .desc('Enable SSE monitoring by injecting EventSource interceptor.')
      .string('urlFilter', 'Regex filter for EventSource URL')
      .number('maxEvents', 'Maximum SSE events in memory', {
        default: 2000,
        minimum: 1,
        maximum: 50000,
      })
      .boolean('persistent', 'Survive page navigations via evaluateOnNewDocument'),
  ),
  tool('sse_get_events', (t) =>
    t
      .desc('Get captured SSE events with filters and pagination.')
      .string('sourceUrl', 'Filter by EventSource URL')
      .string('eventType', 'Filter by SSE event type')
      .number('limit', 'Maximum events', { default: 100, minimum: 1, maximum: 10000 })
      .number('offset', 'Pagination offset', { default: 0, minimum: 0 })
      .boolean('fullData', 'Include full captured SSE event data when available', {
        default: false,
      })
      .readOnly(),
  ),
  tool('sse_export_capture', (t) =>
    t
      .desc('Export captured SSE events to artifacts/captures as JSON or NDJSON.')
      .enum('format', ['json', 'ndjson'], 'Export file format', { default: 'json' })
      .string('sourceUrl', 'Filter by EventSource URL')
      .string('eventType', 'Filter by SSE event type')
      .boolean('includeData', 'Include full captured event data in the artifact', {
        default: true,
      })
      .openWorld(),
  ),
];
