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

## Full tool list (9)

| Tool | Description |
| --- | --- |
| `ws_monitor` | Enable or disable WebSocket frame capture. |
| `ws_get_frames` | Get captured WebSocket frames with pagination and payload filter. |
| `ws_get_connections` | Get tracked WebSocket connections, frame counts, and timing metadata. |
| `ws_export_capture` | Export captured WebSocket frames to artifacts/captures as JSON or NDJSON. |
| `sse_monitor_enable` | Enable SSE monitoring by injecting EventSource interceptor. |
| `sse_get_events` | Get captured SSE events with filters and pagination. |
| `sse_export_capture` | Export captured SSE events to artifacts/captures as JSON or NDJSON. |
| `grpc_monitor` | Enable or disable live capture of gRPC / gRPC-Web calls. gRPC calls are detected by content-type application/grpc(-web)?(+proto)? on the HTTP/2 response. On loadingFinished the response body is pulled (base64) and split into length-prefixed messages; feed each message payloadBase64 to protobuf_decode_raw to complete the decode chain. Must be enabled before navigating so requests are captured from the start. |
| `grpc_get_calls` | Get captured gRPC / gRPC-Web calls with parsed message summaries. Set fullMessages=true to include the parsed message arrays (each carries payloadBase64 — feed to protobuf_decode_raw). Without fullMessages only per-call counts and flags are returned. |
