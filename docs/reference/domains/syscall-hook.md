# 系统调用挂钩

域名：`syscall-hook`

系统调用挂钩域，提供系统调用监控和映射能力。

## Profile

- full

## 典型场景

- 系统调用监控
- API 挂钩
- 行为分析

## 常见组合

- syscall-hook + process
- syscall-hook + instrumentation

## 工具清单（13）

| 工具 | 说明 |
| --- | --- |
| `syscall_start_monitor` | 使用 ETW、strace 或 dtrace 启动系统调用监控。 |
| `syscall_stop_monitor` | 停止系统调用监控。 |
| `syscall_capture_events` | 从活跃或上一次监控会话中捕获系统调用事件。 |
| `syscall_correlate_js` | 将捕获的系统调用与可能的 JavaScript 函数关联。 |
| `syscall_filter` | 按系统调用名称过滤已捕获的系统调用事件。 |
| `syscall_get_stats` | 获取系统调用监控统计。 |
| `syscall_ebpf_trace` | 通过 Linux eBPF/bpftrace 追踪系统调用。需要 root 或 CAP_BPF。 |
| `syscall_resolve_ssn` | 待补充中文：Resolve NT syscall service numbers (SSN) from on-disk ntdll.dll. Parses the export table to extract Zw* → SSN mappings and locates a syscall;ret gadget for direct invocation stubs. Win32 only. |
| `syscall_direct_invoke` | 待补充中文：Direct NT syscall invocation guidance. Resolves SSN for a given NT function and returns a stub template with usage instructions for in-process direct syscall invocation. Bypasses user-mode hooks on ntdll.dll. Win32 only. |
| `syscall_stack_capture` | 待补充中文：Correlate captured syscall events with real JS call stacks via debugger integration. Goes beyond static heuristics by querying live CDP call stacks for syscall→JS mapping. Falls back to heuristic-only mode when no debugger is attached. |
| `syscall_trace_compare` | 待补充中文：Diff two syscall trace snapshots to find appeared/disappeared syscalls and frequency changes. Useful for understanding what OS calls a JS operation triggers. Capture baseline → perform operation → capture target → compare. |
| `syscall_trace_export` | 待补充中文：Export captured syscall events to portable NDJSON with optional time-range filtering and deduplication. Returns both structured array and NDJSON string. |
| `syscall_ebpf_attach` | 待补充中文：Live eBPF syscall attach — spawns a bpftrace process, captures syscall events as structured JSON in real time, and returns them directly. Unlike syscall_ebpf_trace (script-generator), this tool actually runs bpftrace and captures output. Falls back to script mode on non-Linux or when bpftrace is unavailable. Requires bpftrace + CAP_BPF or root on Linux. |
