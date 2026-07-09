# 全域 10/10 冲刺规划 v2（未完成，2026-07-06，同步到 Session 23）

> **数据来源**：7 个并行 research agent 深读每域 definitions/handlers/manifest/CLAUDE.md，产出功能级 enhancement profile（不是质量维度）。
> **当前状态**：P0/P1、全 research/profile、Phase 2 wrapper pass、Phase 3 大批 feature、以及 Session 23 strict input contract pass 已完成；这不是全域 10/10 完成态。诚实 10/10 仍需剩余 feature、Phase 4 adversarial/boundary 覆盖、跨平台 parity。
> **详细研究**：`.ccg/tasks/military-grade-audit/research/<domain>.md`（每域一份）
> **当前评分主账本**：`.ccg/tasks/military-grade-audit/current-status.md`
> **客观扫描**：`scripts/scan-domain-audit.mjs` → `scripts/domain-audit.json`（6 维指标）
> **v8-inspector 已 done（9.5）**，已补独立 research；本规划覆盖其余 33 份 profile。`native-bridge` 已从 legacy externalized 升级到 runtime manifest + 6-tool surface。

---

## 🔴 P0 — 真 bug（必修，生产正确性问题）✅ DONE 2026-07-05

research 抓出**5 个生产路径上的真 bug**，优先级最高，每修复一个对应域评分 +0.3~0.5：

| 域 | 文件:line | bug | 修法 | 提升 | 状态 |
|----|-----------|-----|------|------|------|
| **memory** | `find-accesses.ts:200-209` | `memory_find_accesses`（"find what writes"MWT 工作流）指令字节返回**占位零**，disassembler 被接成 `null` → 每次 find-accesses 都吐**伪造反汇编** | 接真 disassembler + readMemory（capstone + koffi ReadProcessMemory） | +0.5 | ✅ |
| **boringssl** | `TLSKeyLogExtractor.ts:138-154` | `decryptPayload` 实例方法是 **no-op stub**，`tls_parse_handshake({decrypt:true})` 把密文前 16 字节当 "decryptedPreviewHex" 报告 | 删 stub + 移除 decrypt 参 + 指向 tls_decrypt_payload | +0.3 | ✅ |
| **wasm** | `browser-handlers.ts:229` | `wasm_memory_inspect` **只读 `instances[0]`**，多实例 WASM 模块全部漏检 | 加 instanceIndex + 每调返 totalInstances/availableInstances 清单 | +0.1 | ✅ |
| **exploit-dev** | `one-gadget.ts:117-167` | heuristic scanner 是 stub，把 `/bin/sh` 字符串偏移**当 gadget 地址**返回 | capstone x64 真扫 lea→syscall 链；x86/arm64/arm 诚实返空 | +0.5 | ✅ |
| **canvas** | `ENGINE_ANCHORS` vs `adapterFactories` | ENGINE_ANCHORS 列 Babylon/Three/Unity，但 adapterFactories 只 4 项 → `scene_dump` 对 3D 引擎**静默 stub** | 补 Three.js + Babylon adapter；Unity 诚实 message | +0.3 | ✅ |

**P0 执行**：✅ 2026-07-05 完成。3 并行 agent（memory/exploit-dev/canvas）+ 2 直做（wasm/boringssl）。P0 当时全绿；Phase 1 后当前门禁为 540 tools / 15750 tests passed。

---

## 🟡 P1 — 近免费赢 ✅ DONE 2026-07-05

| 域 | 机会 | 实现结果 | 提升 | commit |
|----|------|----------|------|--------|
| **process** | 暴露 `process_suspend`/`process_resume` 为工具 | 新增工具定义、handler、manifest 注册，复用 scanner suspend/resume | +0.3 | `9b697462` |
| **process** | `includeMemoryDump` schema 参数接线 | 返回最多 3 节、每节 64KB 的 memory/disk hex bytes，并标记 truncated | +0.1 | `9b697462` |
| **network** | CLAUDE.md 工具数同步 | 已在文档审计中同步为 37 tools | +0.1 | docs |
| **boringssl** | CLAUDE.md 工具数同步 | 已在 P0 文档同步为 28 tools | +0.1 | docs |
| **extension-registry** | CLAUDE.md 工具数同步 + phantom routing 清理 | CLAUDE 已标注 5 tools；workflow routing 去掉 phantom BLE/HID/serial 触发 | +0.2 | `bca86720` |
| **webgpu** | `command-capture.ts` 等待策略 | 已从固定 sleep 改为轮询 `getGPUCommandTrace`，达到 captureCount 即提前返回 | +0.1 | `fecd9750` |
| **debugger** | 缺 function-name 断点 | `breakpoint({ type:'function', functionName })` 接 `Debugger.setBreakpointOnFunctionCall` | +0.3 | `250805e9` |
| **syscall-hook** | `syscall_filter` PID/returnValue 过滤 | 支持 `pid`, `returnValueMin`, `returnValueMax`, `errorOnly` | +0.2 | `1b5a695e` |
| **trace** | `export_trace` 硬编码 `pid:1 tid:1` | 按 category 派生 tid，并写入 `thread_name` metadata | +0.1 | `bd56096b` |

**P1 执行**：1 个会话，7 commit。最终 `pnpm check` 通过：540 tools，15750 tests passed。

---

## 🟢 P2 — 高杠杆 feature（M/L，每域一个会话）

按"提升分/工作量比"排序，**每个 = 独立 feature 级会话**：

| 域 | feature | 工作量 | 提升 |
|----|---------|--------|------|
| analysis | **DONE** 过程间污点传播（intra→inter-procedural，接 sanitizer wrapper） | L | +0.5 | ✅ Session 17 |
| binary-instrument | **DONE** `frida_spawn` 早期 instrumentation + 真 `Interceptor.attach` 生成器 | M | +0.5 | ✅ `99c7127e` |
| native-emulator | session diagnostics + Java mock strict value exclusivity done；SIMD vector FP/SABDL/crypto remains | L | +0.2 done / +0.5 remaining | ✅ partial |
| transform | AST-backed transform work + chain metadata echo done；parser-backed hardening remains | L | +0.1 done / +0.4 remaining | ✅ partial |
| cross-domain | **DONE** live pullFromDomains + expanded classifier + evidence query + strict chain validation | M | +0.6 | ✅ `852459d2`, `676d107f`, `814544df`, `11b3f4b1` |
| proxy | **DONE** body/timing capture + active rule lifecycle + arbitrary methods + strict rule inputs | M | +0.7 | ✅ |
| workflow | **DONE** macro DSL parallel/branch/fallback/retry | M | +0.4 | ✅ `d4c52e25` |
| graphql | **DONE** Apollo Federation `_service.sdl`; ws subscriptions/APQ remain | M | +0.3 | ✅ `8e1762d4` |
| coordination | **DONE** persisted handoffs/insights + tagged filters + handoff updates + severity validation | M | +0.6 | ✅ |
| platform | **DONE** ASAR SHA256/SHA512 algorithm awareness; Authenticode/notarization remains | M | +0.2 done / +0.3 remaining | ✅ partial |
| encoding | **DONE** magic signatures + base32/58/85 + compression codecs | M | +0.5 | ✅ `f1177317` |
| dart-inspector | **DONE** Dart-aware classifiers + strict Smi width; obfuscation map remains | M | +0.2 | ✅ partial |
| mojo-ipc | **DONE** encode/filter surface + expanded decoder/header metadata + field labels; Frida hook remains | M | +0.6 | ✅ |
| trace | runtime diagnostics done; samples/flame graph remains | M | +0.2 done / +0.5 remaining | ✅ partial |
| adb-bridge | **DONE** install/input/proc maps/root/screenshot/screenrecord + port mapping lifecycle/validation | M（多个 S） | +0.6 | ✅ |
| instrumentation | **DONE** session export + operation stop/status + strict type/artifact validation | M | +0.4 | ✅ |
| browser | **DONE Session 24** worker inspection (`browser_list_workers` + `browser_worker_scripts`) + `browser_font_fingerprint` (queryLocalFonts-first); cookies/launch validation done earlier | M | +0.6 (9.2→9.5) | ✅ |
| streaming | **DONE** payload export + cap schema/runtime alignment; gRPC/fetch/WebRTC remain | M | +0.3 | ✅ partial |
| sourcemap | **DONE Session 26+31** indexed flattening + reconstruct_tree inferMissing（null sourcesContent skeleton，零内置特征库） | M | +0.4 | ✅ |
| native-bridge | **DONE** runtime manifest + Binary Ninja/rizin bridge parity | M | +1.1 |
| protocol-analysis | **DONE** proto_fingerprint 6→11 协议（MQTT/STUN/QUIC/SOCKS5/HTTP2）+ pcap_read 拒 PCAPNG | M | +0.5 | ✅ Session 18 `61767044` |
| maintenance | **DONE** sandbox 加 mem limit + tool whitelist + redaction + category-aware cleanup/routing | M | +0.8 |

**P2 执行**：每 feature 独立会话，2-3 commit，TDD。按用户优先级排期。

---

## 各域 10/10 阻塞点一览（research 摘要）

<details><summary>browser（65 tools, 9 子主题）</summary>
Top: SW/Worker 检查（M+0.2）/ page_cookies 丢 HttpOnly（S+0.1）/ font fingerprint（S+0.1）/ indexeddb cursor 流式（M+0.1）/ page_handle_dialog（S+0.1）
</details>
<details><summary>canvas（8 tools）</summary>
阻塞: 3D 引擎 adapter 缺（L+0.3）/ draw_hook 注入（M+0.2）/ 节点 expose texture/program（M+0.2）/ scene_search 过滤（S+0.1）/ trace_click race（S+0.1）
</details>
<details><summary>wasm（12 tools）</summary>
P0 bug: instances[0]（S+0.1）/ string_extract 缺（S+0.1）/ wasm_diff 缺（M+0.2）/ dump auto-inject hook（S+0.1）/ 真 binary instrumentation（L+0.2）
</details>
<details><summary>webgpu（6 tools, Phase 3 done）</summary>
**P1 ✅ setTimeout 改 condition wait** / shader_source_capture hook（M+0.2）/ error_capture（M+0.2）/ pipeline_dump layout（M+0.2）/ WGSL 真 grammar（L+0.2）
</details>
<details><summary>debugger（18 tools）</summary>
**P1 ✅ function-name BP** / run-to-location（S+0.1）/ pause 自动 snapshot（M+0.1）/ disassembly-at-pause（M+0.2）
</details>
<details><summary>memory（34 tools）</summary>
**P0 bug find_accesses（+0.5）**/ memory_disassemble（capstone 已有，S+0.2）/ 跨平台 watchpoint（L+0.3）
</details>
<details><summary>process（25 tools）</summary>
**P1 ✅ suspend/resume 暴露 + includeMemoryDump** / Linux/macOS inject（L+0.3）/ handle 枚举跨平台（M+0.2）
</details>
<details><summary>network（37 tools）</summary>
http2_frame_parser 逆（M+0.2）/ SigV4+DPoP+client_assertion（M+0.2）/ TLS fingerprint 吃 ClientHello（M+0.1）/ bot-detect 接 JA3/JA4（S+0.1）/ DNS 不绑系统解析器（M+0.1）
</details>
<details><summary>protocol-analysis（20 tools）</summary>
fingerprint 6→11 协议（M+0.2）/ proto_dissect_tls（M+0.2）/ MQTT+WS-frame+HTTP2 dissectors（M+0.2）/ pcap_read 吃 PCAPNG（S+0.1）/ Kaitai .ksy export（M+0.2）
</details>
<details><summary>boringssl（28 tools）</summary>
**P0 bug decryptPayload stub（+0.3）**/ keylog_enable 到 CDP Chrome（M+0.2）/ cipher_suites IANA 注册表（S+0.1）/ 证书 subject/SAN/SPKI（M+0.1）/ QUIC/HTTP3 探测（M+0.2）
</details>
<details><summary>mojo-ipc（5 tools, 大量 stub）</summary>
decoder 5→20 wire 类型（M+0.2）/ mojom schema 映射（M+0.2）/ header 全解析（M+0.1）/ Frida 脚本接真 hook（M+0.2）/ encodeMessage 暴露工具（S+0.1）
</details>
<details><summary>streaming（7 tools）</summary>
**P3 ✅ full payload + WS/SSE export + connection metadata** / gRPC-stream+fetch-stream+WebRTC（M+0.2）/ SSE 漏 fetch 消费者（S+0.1）/ replay/send（M+0.2）
</details>
<details><summary>analysis（25 tools）</summary>
过程间污点（L+0.5）/ 原型污染 sink（M+0.2）/ SSRF+open-redirect+path-traversal+ReDoS 检测器（M+0.2）/ member-chain 污点（S+0.1）/ WASM-VM obfuscation 标记（S+0.1）
</details>
<details><summary>exploit-dev（20 tools, 无 CLAUDE.md）</summary>
**P0 bug one-gadget stub（+0.5）**/ ret2libc/ret2dlresolve chain（M+0.2）/ ARM64 shellcode encoder（M+0.2）/ V8 现代堆喷（M+0.2）/ Windows CFG gadget 分类（M+0.2）/ **先建 CLAUDE.md**
</details>
<details><summary>transform（7 tools）</summary>
regex→真 Babel AST（L+0.5）/ rename_vars `_0xabcd`（M+0.2）/ control_flow_flatten 多 dispatcher（M+0.2）/ workbench 加 AES+hex+gzip（S+0.2）/ string_decrypt base64/hex fallback（S+0.1）
</details>
<details><summary>sourcemap（6 tools）</summary>
reconstruct_tree null sourcesContent 推断（M+0.2）/ indexed source maps（M+0.2）/ reverse lookup（S+0.1）/ sourcemap_diff（M+0.2）/ v4 scopes 持久化（M+0.2）
</details>
<details><summary>binary-instrument（38 tools）</summary>
frida_spawn（M+0.5）/ 真 Interceptor.attach 生成器（S+0.2）/ Frida 内存 scan/read（M+0.2）/ apktool_build（S+0.2）/ Unidbg hook 注册（M+0.2）
</details>
<details><summary>native-emulator（21 tools）</summary>
SIMD vector FP（L+0.5）/ SABDL/UABAL（M+0.2）/ SM3/SM4/SHA-3/SHA-512（M+0.2）/ CRC32（S+0.1）/ breakpoint_set PC-stop（M+0.2）
</details>
<details><summary>adb-bridge（12 tools）</summary>
adb_install/uninstall（S+0.2）/ adb_input tap/swipe/keyevent（S+0.2）/ adb_proc_maps（S+0.2）/ adb_root_check（S+0.1）/ adb_screenshot（S+0.1）
</details>
<details><summary>native-bridge（4 tools, externalized legacy surface）</summary>
Binary Ninja + rizin 桥（M+0.2）/ **P3 ✅ ida_bridge search_strings + get_segments 对齐** / **P3 ✅ capability advertisement + CLAUDE.md** / symbol_sync SQLite+增量（M+0.1）/ manifest 是否恢复为内置 catalog 是产品决策
</details>
<details><summary>dart-inspector（12 tools）</summary>
obfuscation map 自动探测（M+0.2）/ dart_call_graph PCDescriptors（L+0.2）/ pool_search（S+0.1）/ snapshot session cache（M+0.2）/ Dart 标识符启发（S+0.1）
</details>
<details><summary>platform（16 tools）</summary>
Authenticode+notarization（M+0.3）/ verify_integrity 算法感知（S+0.2）/ ASAR repack/write（M+0.2）/ entropy+packer-detect（M+0.1）/ MiniApp iOS 子包+支付宝/字节（M+0.2）
</details>
<details><summary>syscall-hook（15 tools）</summary>
ETW 单 flag 硬编码（S+0.2）/ dtrace `:entry` only → returnValue 缺（M+0.1）/ strace `-yy`（S+0.1）/ **P1 ✅ syscall_filter PID/returnValue** / direct-NT 模块接通（M+0.2）
</details>
<details><summary>trace（9 tools）</summary>
DB samples 表（M+0.2）/ console_logs+exceptions 表（M+0.1）/ **P1 ✅ export_trace category tid** / diff_heap_snapshots 加 retained（S+0.1）/ monotonic seek 加 memory+heap（M+0.2）
</details>
<details><summary>instrumentation（10 tools）</summary>
session 磁盘 export（M+0.2）/ stop/cancel 操作（S+0.1）/ InstrumentationType 扩 DOM/storage/WebAPI（M+0.1）/ preset return-value mutation（M+0.1）/ cross-session diff（M+0.1）
</details>
<details><summary>maintenance（13 tools）</summary>
**P3 ✅ sandbox mem limit+tool whitelist+redaction（M+0.5，安全）** / cache_stats per-namespace（S+0.1）/ cleanup_artifacts 分类过滤（S+0.1）/ doctor 浏览器/GPU 探测（S+0.1）/ list_extensions version drift（S+0.1）
</details>
<details><summary>graphql（6 tools）</summary>
Federation _service.sdl（M+0.3）/ batch+APQ+persisted-query replay（M+0.2）/ ws subscriptions（M+0.3）/ call_graph/script_replace 路由错域（S+0.1）
</details>
<details><summary>encoding（5 tools）</summary>
magic sig 6→12（gzip/ELF/PE/Mach-O/Brotli/Zstd）（M+0.2）/ base32/58/85 codec（M+0.3）/ protobuf schema 链接（M+0.3）/ chi-square+serial 熵（M+0.2）/ requestId 跨页（M+0.2）
</details>
<details><summary>coordination（10 tools）</summary>
handoffs/insights 持久化（M+0.3）/ 任务依赖图（M+0.2）/ snapshot 加 IndexedDB+Cache+SW+scroll+forms（M+0.3）/ state-board watch EventBus（S+0.2）/ confidence 有界+insight tags（S+0.1）
</details>
<details><summary>cross-domain（6 tools）</summary>
**live pullFromDomains（M+0.5）**/ 3 hardcoded→可配置 workflow（M+0.3）/ V5_DOMAIN_NAMES 10→36（S+0.2）/ correlator 4→10 edge 类型（M+0.3）/ correlate_all minConfidence（S+0.2）
</details>
<details><summary>extension-registry（5 tools）</summary>
extension_install/info 真实现（M+0.3）/ **execute_in_context 接 QuickJSSandbox（M+0.3，安全）**/ webhook url 真转发（S+0.2）/ HMAC 强制校验（S+0.2）/ CommandQueue ACK/retry/DLQ（M+0.2）/ **同步 CLAUDE.md**
</details>
<details><summary>proxy（8 tools）</summary>
**P3 ✅ capture body+timing** / rewrite+latency+redirect+WS（M+0.3）/ per-rule remove/list（S+0.2）/ 非 canonical method（S+0.2）/ chaining+SOCKS+auth（M+0.2）
</details>
<details><summary>workflow（9 tools）</summary>
macro DSL parallel/branch/retry（M+0.4）/ reverse_session.plan 硬编码→可配置（M+0.3）/ api_probe_batch 并发+限流（S+0.2）/ js_bundle_search cache forceRefresh（S+0.1）/ page_script_register LRU+可设 protected（S+0.1）
</details>

---

## 执行编排（替换 v1 的纯质量维度编排）

### Phase 0（紧急，1 会话，5 commit）— P0 真 bug 修复
**这是最高优先级** — 5 个生产路径 bug，每修一个对应域 +0.3~0.5。spawn 5 并行 agent（每 bug 一个）。
- memory find_accesses / boringssl decryptPayload / wasm instances[0] / exploit-dev one-gadget / canvas 3D adapter
- **预期拉分**：memory 9.2→9.7, boringssl 8.8→9.1, wasm 9.0→9.1, exploit-dev 8.8→9.3, canvas 9.0→9.3

### Phase 1（快赢，1 会话，7 commit）— P1 近免费赢 + 文档同步 ✅ DONE
- process suspend/resume 暴露 + includeMemoryDump 解注（done）
- syscall_filter 实现 + trace category tid/thread_name 修（done）
- network/boringssl/extension-registry CLAUDE.md 同步，extension-registry workflow routing 去 phantom
- debugger function-name BP
- webgpu setTimeout 改 condition wait
- **实际拉分**：process 8.5→8.9, debugger 8.2→8.5, syscall-hook 8.5→8.7, trace 8.8→8.9, webgpu 9.0→9.1, extension-registry 8.5→8.7

### Phase 2（中赢，4 会话）— handleSafe 统一（v1 Stream 2）✅ DONE
- **已完成小域批次（Session 10）**：mojo-ipc/cross-domain/proxy/trace/adb-bridge；manifest 指向 `*Tool` wrapper，direct handler 测试语义保留；targeted 261 tests pass。
- **实际拉分（保守）**：adb-bridge 8.5→8.6, cross-domain 8.5→8.6, mojo-ipc 8.5→8.6, proxy 8.0→8.2, trace 8.9→9.0。
- **已完成中域批次（Session 11）**：streaming/workflow/syscall-hook/canvas/encoding/transform；workflow macro 和 canvas Skia secondary handlers 一并切 wrapper；targeted 1674 tests pass。
- **实际拉分（保守）**：streaming 8.5→8.6, syscall-hook 8.7→8.8, canvas 9.3→9.4, encoding 9.0→9.1, transform 9.0→9.1, workflow 9.0→9.1。
- **已完成大域批次（Session 12）**：graphql/sourcemap/platform/process；targeted 1063 tests pass。
- **实际拉分（保守）**：graphql 9.0→9.1, sourcemap 9.0→9.1, platform 9.0→9.1, process 8.9→9.0。
- **已完成 residual 批次（Session 13）**：boringssl-inspector/coordination/extension-registry/native-bridge/protocol-analysis/wasm；targeted 517 tests pass，扫描确认无 residual `hs=0`。
- **实际拉分（保守）**：boringssl-inspector 9.1→9.2, coordination 8.5→8.6, extension-registry 8.7→8.8, native-bridge 8.0→8.1, protocol-analysis 9.0→9.1, wasm 9.1→9.2。`native-bridge` 仍是 legacy surface；Session 14 已补 CLAUDE.md，但未恢复 runtime manifest。

### Phase 3（feature 级，每域独立会话）— P2 高杠杆 feature
按用户/业务优先级排期，每 feature 一个会话。详见上表 + 各域 research 文件。

- **native-bridge Session 14 ✅**：保持 externalized ToolCatalog 契约；补 `/capabilities` 能力广告、IDA `search_strings`、Ghidra/IDA `get_segments`、本地域 CLAUDE.md。保守拉分 8.1→8.4。
- **proxy Session 15 ✅**：`proxy_get_requests` 返回 request/response body preview + timing；response entry 回填 method/url，保守拉分 8.2→8.6。
- **maintenance Session 16 ✅**：`execute_sandbox_script` 接 QuickJS `memoryLimitBytes`、MCP `allowedTools` allowlist、默认返回 redaction；legacy `mcp.call` stub 也执行 allowlist 校验。保守拉分 8.5→9.0。
- **analysis Session 17 ✅**：interprocedural taint summaries + ordering bug fix，拉到 9.8。
- **protocol-analysis Session 18 ✅**：MQTT/STUN/QUIC/SOCKS5/HTTP2 fingerprint expansion，拉到 9.6。
- **phase3-quad Session 19 ✅**：transform/cross-domain/trace/mojo-ipc 并行执行；cross-domain/mojo 完成主要拉分，transform/trace 留诚实缺口。
- **broad feature wave Session 20-21 ✅**：binary-instrument、adb-bridge、streaming、encoding、workflow、coordination、graphql、platform、instrumentation、extension-registry、native-bridge、proxy、debugger、syscall-hook、browser、network、maintenance 等进入 9.2+。
- **strict contract wave Session 22-23 ✅**：schema/runtime validation 收敛到 debugger/coordination/cross-domain/instrumentation/network/process/syscall/browser/native-emulator/maintenance/proxy 等域；最低分组升到 9.2。

### Phase 4（当前）— 从 9.2 到 10 的真实冲刺

下一步不再做笼统“拉分脚本”。每个域必须按以下顺序推进：

1. 选一个 9.2 域的真实缺口（优先 `browser` workers/font fingerprint、`network` HTTP/2/SigV4/DPoP、`syscall-hook` ETW/DTrace parity、`streaming` gRPC/fetch/WebRTC、`sourcemap` indexed map、`native-emulator` SIMD/crypto）。
2. 实现 feature，同时补 schema/runtime validation。
3. 加成功、负例、边界、恶意输入测试。
4. 跑 targeted tests、`pnpm metadata:check`、`node scripts/scan-domain-audit.mjs`、`$env:VITEST_MAX_WORKERS='4'; pnpm check`。
5. 更新 `current-status.md`、本计划、`INDEX.md`、`handoff.md`、对应 `research/<domain>.md`，再原子提交。

---

## 工具
- `node scripts/scan-domain-audit.mjs` — 6 维扫描，每 phase 后重跑
- `current-status.md` — CCG 评分主账本，每 phase 后先更新
- `node scripts/update-domain-scores.mjs` — 辅助刷新各域 CLAUDE.md Audit Score，不作为主记录
- `.ccg/tasks/military-grade-audit/research/<domain>.md` — 每域详细 enhancement profile
