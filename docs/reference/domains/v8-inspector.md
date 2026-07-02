# V8 检查器

域名：`v8-inspector`

V8 检查器域，提供堆快照分析、CPU 分析和内存检查。

## Profile

- workflow
- full

## 典型场景

- 堆快照分析
- CPU 性能分析
- 内存泄漏检测

## 常见组合

- v8-inspector + browser
- v8-inspector + debugger

## 工具清单（16）

| 工具 | 说明 |
| --- | --- |
| `v8_heap_snapshot_capture` | 从活跃浏览器目标捕获 V8 堆快照。 |
| `v8_heap_snapshot_analyze` | 分析先前捕获的 V8 堆快照。 |
| `v8_heap_diff` | 对比两个已捕获的 V8 堆快照。 |
| `v8_object_inspect` | 按地址检查 V8 堆对象。 |
| `v8_heap_stats` | 返回 V8 堆快照统计。 |
| `v8_bytecode_extract` | 从 V8 脚本派生伪字节码。 |
| `v8_version_detect` | 检测 V8 引擎版本和功能支持。 |
| `v8_jit_inspect` | 检查 V8 脚本的 JIT 优化状态。 |
| `v8_heap_find_leaks` | 在堆快照中查找疑似内存泄漏。返回按置信度排序的泄漏候选，包括分离的 DOM 节点、大数组、闭包泄漏和意外保留的大对象。 |
| `v8_heap_retainers` | 待补充中文：Trace retainer chains from suspect leak objects back to GC roots. For each nodeId, walks the immediate-dominator chain to produce a "what keeps it alive" path: leaf → ... → GC root. Each step includes nodeId, name, className, shallowSize, retainedSize, and distance from the leaf. Use after v8_heap_find_leaks or v8_heap_snapshot_analyze to understand why a specific object is not being collected. |
| `v8_deopt_trace` | 待补充中文：Trace V8 deoptimization events during a capture window. Enables %TraceDeoptimizations via natives syntax and captures deopt events (function name, reason, bailout position). Requires V8 natives syntax. Falls back gracefully when unavailable. |
| `v8_turbofan_inspect` | 待补充中文：Inspect TurboFan compilation state for functions in a script. Reports optimization tier (interpreted/maglev/turbofan). Supports actions: inspect (default), optimize (%OptimizeFunctionOnNextCall), deoptimize (%DeoptimizeFunction). Requires V8 natives syntax. |
| `v8_turbofan_graph` | 待补充中文：Collect and visualize V8 TurboFan IR (sea-of-nodes / Turboshaft graph). Two modes: (1) Provide JS source code — spawns an isolated V8 child with --trace-turbo to generate IR JSON, then parses nodes, edges, phases, and opcode histogram. (2) Provide a traceDir path to read already-generated turbo-*.json files (e.g. from a browser launched with --trace-turbo). Returns per-function graph summaries with phase-level node/edge counts, sample nodes, and opcode distribution. |
| `v8_function_retained` | 待补充中文：Find all heap objects retained by functions matching a name pattern. Walks the dominator tree to find objects whose constructor/class name matches the given pattern, then returns each with its retainer chain. Useful for understanding which objects a specific function/class is holding alive. |
| `v8_object_compare` | 待补充中文：Compare heap objects by shallow/retained size, class name, and property count. Same-snapshot mode (objectIds only) does all-pairs comparison (n-choose-2). Cross-snapshot mode (anotherSnapshotId + anotherObjectIds) does pairwise A[i]↔B[i] comparison. Use to track object growth over time, find memory regression candidates, or compare leaked vs healthy objects of the same class. |
| `v8_wasm_inspect` | 待补充中文：Inspect WebAssembly modules and garbage-collected WASM objects in the page. Discovers .wasm script resources, detects WASM GC (struct/array/ref-types) availability, and enumerates feature flags (gc/threads/simd). Supports optional scriptId filter to inspect a specific WASM module. Requires browser/page CDP context. |
