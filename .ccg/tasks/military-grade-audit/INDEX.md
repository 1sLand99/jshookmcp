# 全域 10/10 冲刺 — 索引（未完成，当前约 9.32）

> **所有路径相对项目根** `D:\coding\reverse\jshookmcp\`（与 `.ccg/` 在 gitignore，文件仅本地）。
> 本文件是 navigation hub：从 domain → research 文件 → 具体增强项 → file:line。
> 同目录文件（相对本文件 `./`）：`current-status.md`、`handoff.md`、`domain-10-plan.md`、`research/`、`phase3-quad/`。
>
> **当前不是全域 10/10**：P0/P1、全 research/profile、Phase 2 wrapper pass、Phase 3 大批 feature、Session 23 strict input contract pass、Session 24 browser worker+font、Session 25 network http2-parse+auth-signatures、Session 26 sourcemap indexed+reverse-lookup、Session 27 syscall-hook dtrace-pairing+ETW multi-provider 已完成。当前 34 域人工平均约 **9.37**，最低分组是 **9.2**。剩余工作是每域真实 capability closure、adversarial/boundary 覆盖、跨平台 parity、以及工具契约收敛。

## 一句话导航
- **接手第一行**：读 `current-status.md` → `handoff.md` 顶部状态表 → 本 INDEX → `domain-10-plan.md` v2 → 对应 `research/<domain>.md`
- **工具**：`node scripts/scan-domain-audit.mjs`（6 维扫描→`scripts/domain-audit.json`）；`node scripts/update-domain-scores.mjs` 只作为 CLAUDE.md 辅助刷新，CCG 分数主记录在 `current-status.md` / 本目录文档。

---

## Phase 0 — 5 个真 bug（生产路径，必修，最高 ROI）✅ DONE 2026-07-05

每 bug 一个并行 agent，每修一个对应域 +0.3~0.5。research 文件含 file:line + 修法。

| 域 | bug | file:line | research 文件 | 提升 | 状态 |
|----|-----|-----------|---------------|------|------|
| memory | `memory_find_accesses`（MWT 工作流）指令字节占位零，disassembler 接 null → 伪造反汇编 | `find-accesses.ts:200-209` | `research/memory.md` | +0.5 | ✅ |
| boringssl | `decryptPayload` no-op stub，密文前 16 字节当 "decryptedPreviewHex" | `TLSKeyLogExtractor.ts:138-154` | `research/boringssl-inspector.md` | +0.3 | ✅ |
| wasm | `wasm_memory_inspect` 只读 `instances[0]` | `browser-handlers.ts:229` | `research/wasm.md` | +0.1 | ✅ |
| exploit-dev | `one-gadget` 把 `/bin/sh` 字符串偏移当 gadget 地址返回 | `one-gadget.ts:117-167` | `research/exploit-dev.md` | +0.5 | ✅ |
| canvas | ENGINE_ANCHORS 列 3D 引擎但 adapterFactories 只 4 → scene_dump 静默 stub | `shared.ts`（ENGINE_ANCHORS / adapterFactories） | `research/canvas.md` | +0.3 | ✅ |

## Phase 1 — 近免费赢 + 文档同步 ✅ DONE 2026-07-05

| 域 | 机会 | commit | research 文件 | 提升 | 状态 |
|----|------|--------|---------------|------|------|
| process | `process_suspend`/`resume` 暴露为工具 | `9b697462` | `research/process.md` | +0.3 | ✅ |
| process | `includeMemoryDump` 返回受限 memory/disk bytes | `9b697462` | `research/process.md` | +0.1 | ✅ |
| syscall-hook | `syscall_filter` PID/returnValue/errorOnly | `1b5a695e` | `research/syscall-hook.md` | +0.2 | ✅ |
| debugger | function-name BP (`type=function`) | `250805e9` | `research/debugger.md` | +0.3 | ✅ |
| trace | `export_trace` category→tid + thread_name metadata | `bd56096b` | `research/trace.md` | +0.1 | ✅ |
| webgpu | command-capture 固定 5s sleep → condition wait | `fecd9750` | `research/webgpu.md` | +0.1 | ✅ |
| network | CLAUDE.md 工具数同步到 37 | 已完成于文档审计 | `research/network.md` | +0.1 | ✅ |
| boringssl | CLAUDE.md 工具数同步到 28 | 已完成于 P0 文档 | `research/boringssl-inspector.md` | +0.1 | ✅ |
| extension-registry | CLAUDE.md 5 tools + manifest routing 去 phantom | `bca86720` | `research/extension-registry.md` | +0.2 | ✅ |

## Phase 2 — handleSafe 统一 ✅ DONE 2026-07-05（教训 #47 翻测试）

参考样板：v8-inspector B1（`b7a66d3b`）。按"小→中→大"：
- **小**（2026-07-05 Session 10 ✅）：mojo-ipc / cross-domain / proxy / trace / adb-bridge；manifest 入口切到 `*Tool` wrapper，direct handler 语义保留；targeted 261 tests pass。
- **中**（2026-07-05 Session 11 ✅）：streaming / workflow / syscall-hook / canvas / encoding / transform；主 facade + workflow macro + canvas Skia 均切 wrapper；targeted 1674 tests pass。
- **大**（2026-07-05 Session 12 ✅）：graphql / sourcemap / platform / process；targeted 1063 tests pass。
- **Residual**（2026-07-05 Session 13 ✅）：boringssl-inspector / coordination / extension-registry / native-bridge / protocol-analysis / wasm；扫描确认全部 `hs>0`，targeted 517 tests pass。`native-bridge` 仅补 legacy wrapper，仍缺 manifest/CLAUDE.md。

## Phase 3 — P2 高杠杆 feature（每域独立会话，按业务优先级排期）

- **native-bridge Session 14 ✅**：补 `/capabilities` 能力广告（remote + static fallback）、IDA `search_strings`、Ghidra/IDA `get_segments`、本地域 `CLAUDE.md`；保持 bridge tools externalized，不恢复 runtime manifest。
- **proxy Session 15 ✅**：`proxy_get_requests` 返回 request/response body preview + timing，response entry 回填 method/url 以支持 `urlFilter` 查询完整请求/响应对。
- **maintenance Session 16 ✅**：`execute_sandbox_script` 暴露 QuickJS `memoryLimitBytes`、MCP `allowedTools` allowlist、默认输出/日志/error redaction；legacy `mcp.call` stub 也执行 allowlist 校验。
- **Session 17-18 ✅**：analysis interprocedural taint；protocol-analysis +5 fingerprints。
- **Session 19 ✅**：phase3-quad 执行完成：transform / cross-domain / trace / mojo-ipc；详见 `phase3-quad/` 的完成态记录。
- **Session 20-21 ✅**：binary-instrument、adb-bridge、streaming、encoding、workflow、coordination、graphql、platform、instrumentation、extension-registry、native-bridge、proxy、debugger、syscall-hook、browser、network、maintenance 等 feature / lifecycle wave。
- **Session 22-23 ✅**：全域 strict contract wave：schema/runtime validation、SSRF policy reuse、cache scoping、rule input validation、Java mock exclusivity、capture filter validation 等。
- **Session 24 ✅**：browser Phase 3 worker inspection（`browser_list_workers` + `browser_worker_scripts`，CDP Debugger.enable scriptParsed replay + source hydration）+ `browser_font_fingerprint`（queryLocalFonts-first，document.fonts.check probe fallback，spoof override，stable hash）。573→576 tools。
- **Session 25 ✅**：network Phase 3 `http2_frame_parse`（lenient 逆解码，build+parse 对称）+ `extract_auth` 签名方案识别（AWS SigV4 header/presigned query、Aliyun ACS3、DPoP、OAuth2 client_assertion；新 `source:'signature'`+`scheme` 字段；form-urlencoded body fallback）。576→577 tools。
- **Session 26 ✅**：sourcemap Phase 3 indexed（sectioned）source map flattening（`flattenIndexedSourceMap`，sources/names 去重 + offset 重映射，对全链路透明）+ `sourcemap_lookup` 反向模式（original source:line:col → generated position，调试器断点风格）。无新工具（577 不变），16129→16140 tests。
- **Session 27 ✅**：syscall-hook Phase 3 `parseDTraceLine` entry/return probe 配对（`dtracePendingEntries` 缓冲，捕获 returnValue+duration，无匹配 entry 时降级 best-effort）+ `captureWithDTrace` 同时发 `:entry`/`:return` 探针带 dtrace monotonic `timestamp` + `ETW_PROVIDERS` const map（kernel-process/network/file/image GUID）+ `buildEtwProviderArgs` + `etwProviders` 选项经 `syscall_start_monitor` 透传（省略时保留 legacy NT Kernel Logger session）。无新工具（577 不变），16140→16145 tests。
- **Session 28 ✅**：network Phase 3 `network_tls_fingerprint` 新增 `parse_client_hello` mode — 从真实 ClientHello wire bytes（hex）解析（RFC 5246 §7.4.1.2 / RFC 8446 §4.1.2），输出真实 **JA3**（Salesforce MD5：`version,ciphers,extensions,ec_point_formats,elliptic_curves`）+ **JA4**（FoxIO，复用 `computeTlsFingerprint` Part A/B/C）。新纯函数 `clienthello-parser.ts`（`parseClientHello` lenient / `computeJa3` / `computeJa4FromClientHello`），解析 SNI/ALPN/supported_versions→negotiatedVersion/elliptic_curves/ec_point_formats/signature_algorithms，GREASE 正确剥离。无新工具（577 不变，是既有工具的 mode 扩展），16145→16167 tests。

| 域 | feature | 工作量 | 提升 | research 文件 |
|----|---------|--------|------|---------------|
| analysis | 过程间污点传播（intra→inter-procedural） | L | +0.5 | `research/analysis.md` — **DONE Session 17 (2026-07-06)** |
| binary-instrument | **DONE** `frida_spawn` 早期 instrumentation + 真 Interceptor.attach 生成器 | M | +0.5 | `research/binary-instrument.md` |
| native-emulator | session diagnostics + Java mock strict value exclusivity；next: SIMD vector FP + SABDL/UABAL + SM3/SM4/SHA-3 | L | +0.2 / next +0.5 | `research/native-emulator.md` |
| transform | AST-backed work + chain metadata echo；next: harden parser-backed coverage to replace remaining regex gaps | L | +0.1 / next +0.4 | `research/transform.md` |
| cross-domain | **DONE** live pullFromDomains + classifier/evidence/validation wave | M | +0.6 | `research/cross-domain.md` |
| proxy | **DONE** capture 只存 headers → 加 body+timing | M | +0.4 | `research/proxy.md` |
| workflow | **DONE** macro DSL parallel/branch/fallback/retry | M | +0.4 | `research/workflow.md` |
| graphql | **DONE** Apollo Federation `_service.sdl`; next: ws subscriptions / APQ replay | M | +0.3 | `research/graphql.md` |
| coordination | **DONE** persisted handoffs/insights + tagged filters + severity validation | M | +0.6 | `research/coordination.md` |
| platform | **DONE** ASAR 算法感知；next: Authenticode/notarization | M | +0.2 | `research/platform.md` |
| encoding | **DONE** magic sig + base32/58/85 + compression codecs | M | +0.5 | `research/encoding.md` |
| dart-inspector | **DONE** Dart-aware classifiers + strict Smi width；next: obfuscation map 自动探测 + 调用图 | M | +0.2 | `research/dart-inspector.md` |
| mojo-ipc | **DONE** decoder/header/field-label/encode surface；next: Frida 真 hook | M | +0.6 | `research/mojo-ipc.md` |
| trace | runtime diagnostics/seek context done；next: DB samples 表 + flame graph | M | +0.2 | `research/trace.md` |
| adb-bridge | **DONE** install/input/proc maps/root/screenshot/screenrecord + port mappings | M | +0.6 | `research/adb-bridge.md` |
| instrumentation | **DONE** session export + stop/status + strict validation | M | +0.4 | `research/instrumentation.md` |
| browser | **DONE** all-origin cookies + page-data/launch validation；next: browser_list_workers + font fingerprint | M | +0.3 | `research/browser.md` |
| streaming | **DONE** payload export + capture cap alignment；next: gRPC/fetch/WebRTC + SSE fetch 消费者 | M | +0.3 | `research/streaming.md` |
| sourcemap | indexed source maps（sections）+ null sourcesContent 推断 | M | +0.2 | `research/sourcemap.md` |
| native-bridge | **DONE** runtime manifest + Binary Ninja + rizin 桥 | M | +1.1 | `research/native-bridge.md` |
| protocol-analysis | proto_fingerprint 6→11 协议 + pcap_read 吃 PCAPNG | M | +0.2 | `research/protocol-analysis.md` |
| maintenance | **DONE** sandbox 加 mem limit + tool whitelist + redaction + category-aware cleanup/routing | M | +0.8 | `research/maintenance.md` |
| extension-registry | **DONE** install/info lifecycle；next: QuickJSSandbox execute_in_context + webhook ACK/retry | M | +0.6 | `research/extension-registry.md` |

---

## 全 34 份 research/profile 索引（按字母序）

每域 research 文件结构：**Purpose**（1-2 句）/ **Current tool inventory**（工具数+清单）/ **Concrete enhancement opportunities**（3-5 项，每项 What/Why/Effort/Score-lift，file:line 落地）/ **Honest gap to 10/10**。

所有文件路径：`.ccg/tasks/military-grade-audit/research/<domain>.md`

| 域 | 当前分 | 工具数 | research 文件 | #1 增强 |
|----|--------|--------|---------------|---------|
| adb-bridge | 9.2 | 23 | `research/adb-bridge.md` | **DONE** install/input/proc maps/root/screenshot/screenrecord + port mappings + strict mapping validation |
| analysis | 9.8 | 25 | `research/analysis.md` | **P3 ✅ interprocedural taint (function summaries + member-chain + two-pass ordering-bug fix)** |
| binary-instrument | 9.5 | 40 | `research/binary-instrument.md` | **DONE** Frida spawn/resume + real Interceptor.attach generation |
| boringssl-inspector | 9.2 | 28 | `research/boringssl-inspector.md` | **P0 ✅ decryptPayload stub removed；P2 ✅ MCP-safe wrappers**；next: CDP keylog / QUIC |
| browser | 9.5 | 72 | `research/browser.md` | **DONE Session 24** browser_list_workers + browser_worker_scripts + browser_font_fingerprint；next: browser_list_workers runtime parity / deeper SW event hooks |
| canvas | 9.4 | 8 | `research/canvas.md` | **P0 ✅ Three.js + Babylon adapters；P2 ✅ MCP-safe wrappers** |
| coordination | 9.2 | 11 | `research/coordination.md` | **DONE** persisted handoffs/insights + tagged filtering + severity validation |
| cross-domain | 9.2 | 7 | `research/cross-domain.md` | **DONE** live state hydration + classifier/evidence queries + chain direction validation |
| dart-inspector | 9.2 | 12 | `research/dart-inspector.md` | **DONE** Dart-aware classifiers + Smi width validation；next: obfuscation map 自动探测 |
| debugger | 9.2 | 20 | `research/debugger.md` | **DONE** run-to-location + hit context + condition/lifecycle validation |
| encoding | 9.6 | 5 | `research/encoding.md` | **DONE** magic signatures + base32/base58/base85/compression codecs |
| exploit-dev | 9.3 | 20 | `research/exploit-dev.md` | **P0 ✅ capstone x64 one-gadget scan + CLAUDE.md** |
| extension-registry | 9.4 | 7 | `research/extension-registry.md` | **DONE** install/info lifecycle with no-import manifest inspection |
| graphql | 9.4 | 6 | `research/graphql.md` | **DONE** Apollo Federation `_service.sdl` introspection |
| instrumentation | 9.2 | 16 | `research/instrumentation.md` | **DONE** session export + stop/status + strict operation/artifact validation |
| maintenance | 9.3 | 13 | `research/maintenance.md` | **DONE** sandbox hardening + category-aware artifact cleanup/routing |
| memory | 9.7 | 34 | `research/memory.md` | **P0 ✅ find_accesses wired readMemory+capstone+pid**；跨平台 stub 已标注 (Session 29，等 Mac 真机接 ptrace/mach) |
| mojo-ipc | 9.2 | 6 | `research/mojo-ipc.md` | **DONE** encode/filter surface + expanded decoder/header metadata + field labels |
| native-bridge | 9.5 | 6 | `research/native-bridge.md` | **DONE** runtime manifest + Rizin/Binary Ninja parity |
| native-emulator | 9.2 | 22 | `research/native-emulator.md` | **DONE** session diagnostics + strict Java mock values；next: SIMD/crypto depth |
| network | 9.8 | 38 | `research/network.md` | **DONE Session 30** bot_detect_analyze JA3/JA4 integration（user-supplied knownBad lists，零内置特征库）；**Session 28** parse_client_hello（真实 JA3+JA4）；**Session 25** http2_frame_parse + extract_auth signing-scheme；next: DNS resolver override #6 / streaming replay #5 / HTTP/2 SETTINGS fingerprint |
| platform | 9.3 | 16 | `research/platform.md` | **DONE** ASAR integrity SHA256/SHA512 awareness；next: Authenticode/notarization |
| process | 9.2 | 27 | `research/process.md` | **DONE** suspend/resume + dumps + thread diagnostics + memory pattern validation |
| protocol-analysis | 9.6 | 20 | `research/protocol-analysis.md` | **P3 ✅ +5 fingerprints: MQTT/STUN/QUIC/SOCKS5/HTTP2（Session 18）** |
| proxy | 9.3 | 10 | `research/proxy.md` | **DONE** body/timing capture + active rules + arbitrary methods + strict rule validation |
| sourcemap | 9.6 | 6 | `research/sourcemap.md` | **DONE Session 31** reconstruct_tree inferMissing（sourcesContent null 推断 skeleton，零内置特征库）；**Session 26** indexed flattening + reverse lookup；next: sourcemap_diff (#4) / v4 scopes into reconstruct_tree (#5) |
| streaming | 9.2 | 7 | `research/streaming.md` | **DONE** payload export + cap schema/runtime alignment；next: gRPC/fetch/WebRTC |
| syscall-hook | 9.4 | 15 | `research/syscall-hook.md` | **DONE Session 27** dtrace entry/return 配对（returnValue+duration）+ ETW multi-provider（kernel-process/network/file/image GUID）；next: native direct-NT live hook (#4) / Frida 跨平台 live (#5) |
| trace | 9.2 | 9 | `research/trace.md` | **DONE** thread tracks + runtime diagnostics；next: samples/flame graph |
| transform | 9.2 | 7 | `research/transform.md` | **DONE** chain metadata echo + AST work; next: parser-backed hardening |
| v8-inspector | **9.5 ✅** | 19 | `research/v8-inspector.md` | **已 done（Tier A+B+D+C 全完成）**；next: snapshot 持久化（M+0.2） |
| wasm | 9.2 | 12 | `research/wasm.md` | **P0 ✅ instances[0]→instanceIndex+inventory；P2 ✅ MCP-safe wrappers** |
| webgpu | 9.2 | 6 | `research/webgpu.md` | **DONE** condition wait + format-aware shader caches；next: shader source hook |
| workflow | 9.5 | 9 | `research/workflow.md` | **DONE** macro DSL parallel/branch/fallback/retry orchestration |

---

## 评分分布基线（Session 28 后）
| 分数 | 数 | 域 |
|------|-----|-----|
| 9.6–9.8 | 4 | **analysis (9.8)**, **memory (9.7)**, **network (9.6)**, **browser (9.5)** |
| 9.4 | 8 | encoding (9.6), protocol-analysis (9.6), binary-instrument (9.5), native-bridge (9.5), sourcemap (9.4), syscall-hook (9.4), v8-inspector (9.5), workflow (9.5) |
| 9.3–9.4 | 7 | canvas (9.4), extension-registry (9.4), graphql (9.4), exploit-dev (9.3), maintenance (9.3), platform (9.3), proxy (9.3) |
| 9.2 | 15 | adb-bridge, boringssl-inspector, coordination, cross-domain, dart-inspector, debugger, instrumentation, mojo-ipc, native-emulator, process, streaming, trace, transform, wasm, webgpu |

全域平均 **~9.38**（34 域人工同步估算）。Phase 2 wrapper pass 和 Phase 3 大批 feature/hardening 已完成；诚实 10/10 仍需更多 feature + 100% 边界覆盖 + 跨平台 parity，多 session。

## 执行后每 phase
1. `node scripts/scan-domain-audit.mjs` — 重扫看维度变化
2. 更新 `current-status.md` / 本 INDEX / `domain-10-plan.md` / `handoff.md` / touched `research/<domain>.md`
3. `node scripts/update-domain-scores.mjs` — 仅用于辅助刷新各域 CLAUDE.md Audit Score
