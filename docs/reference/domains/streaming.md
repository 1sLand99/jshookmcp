# 流式

域名：`streaming`

WebSocket 与 SSE 监控域。

## Profile

- workflow
- full

## 典型场景

- WS 帧采集
- SSE 事件监控

## 常见组合

- browser + streaming + network

## 工具清单（7）

| 工具 | 说明 |
| --- | --- |
| `ws_monitor` | 通过 CDP Network 事件启用或禁用 WebSocket 帧捕获。 |
| `ws_get_frames` | 获取已捕获的 WebSocket 帧，支持分页、载荷过滤，并可按需返回完整载荷。 |
| `ws_get_connections` | 获取已跟踪的 WebSocket 连接、帧统计、握手状态和连接时序。 |
| `ws_export_capture` | 将已捕获的 WebSocket 帧导出到 artifacts/captures，支持 JSON 或 NDJSON 格式。 |
| `sse_monitor_enable` | 启用 SSE 事件流监控。 |
| `sse_get_events` | 获取已捕获的 SSE 事件，支持过滤、分页，并可按需返回完整事件数据。 |
| `sse_export_capture` | 将已捕获的 SSE 事件导出到 artifacts/captures，支持 JSON 或 NDJSON 格式。 |
