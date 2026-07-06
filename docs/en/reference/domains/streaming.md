# Streaming

Domain: `streaming`

WebSocket and SSE monitoring domain.

## Profiles

- workflow
- full

## Typical scenarios

- Capture WebSocket frames
- Monitor SSE events

## Common combinations

- browser + streaming + network

## Full tool list (7)

| Tool | Description |
| --- | --- |
| `ws_monitor` | Enable or disable WebSocket frame capture. |
| `ws_get_frames` | Get captured WebSocket frames with pagination and payload filter. |
| `ws_get_connections` | Get tracked WebSocket connections, frame counts, and timing metadata. |
| `ws_export_capture` | Export captured WebSocket frames to artifacts/captures as JSON or NDJSON. |
| `sse_monitor_enable` | Enable SSE monitoring by injecting EventSource interceptor. |
| `sse_get_events` | Get captured SSE events with filters and pagination. |
| `sse_export_capture` | Export captured SSE events to artifacts/captures as JSON or NDJSON. |
