# 会话进度

域名：`session`

会话级逆向进度台账域：记录已 Hook 的进程、Hook 点与已解析协议字段，量化覆盖度并暴露覆盖缺口（服务端内存态，随服务器重启清空）。

## Profile

- workflow
- full

## 典型场景

- 记录逆向进度证据
- 审计覆盖度并发现缺口
- 切换/清理会话台账

## 常见组合

- session + coordination
- session + instrumentation
- session + protocol-analysis

## 工具清单（3）

| 工具 | 说明 |
| --- | --- |
| `session_progress_record` | 记录当前会话的逆向进度证据（已 Hook 的进程、Hook 点或已解析的协议字段）；相同 (kind, key) 重复记录幂等，仅原地更新 metadata，不产生重复条目。 |
| `session_progress_coverage` | 查询会话进度台账：各类证据条目计数与按记录时间倒序的条目列表，用于审计逆向覆盖面并发现覆盖缺口。 |
| `session_progress_clear` | 清空会话进度条目：不指定 kind 时重置整个会话台账，指定 kind 时仅清空该类证据，返回移除的条目数。 |
