# WASM

Domain: `wasm`

WebAssembly dump, disassembly, decompilation, optimization, and offline execution domain.

## Profiles

- full

## Typical scenarios

- Dump WASM modules
- Recover WAT or pseudo-C
- Run exported functions offline

## Common combinations

- browser + wasm
- core + wasm

## Full tool list (15)

| Tool | Description |
| --- | --- |
| `wasm_capabilities` | Report WASM tool availability. |
| `wasm_dump` | Dump a captured WebAssembly module from the current page. |
| `wasm_disassemble` | Disassemble a .wasm binary to WAT text format. |
| `wasm_decompile` | Decompile .wasm bytecode to readable pseudo-code with type info. |
| `wasm_inspect_sections` | Parse .wasm section headers: imports, exports, memory, tables, code. |
| `wasm_offline_run` | Run an exported .wasm function. |
| `wasm_optimize` | Optimize a .wasm binary for size or speed. |
| `wasm_vmp_trace` | Read captured WASM VMP import-call traces from the current page. |
| `wasm_memory_inspect` | Inspect exported WebAssembly.Memory from the current page. Pages often load multiple WASM modules (crypto/DRM/app) — the response always includes totalInstances + an instance inventory; pass instanceIndex to target a specific module. |
| `wasm_to_c` | Transpile .wasm bytecode to C source and header files. |
| `wasm_detect_obfuscation` | Detect WASM obfuscation: opaque predicates, control-flow flattening, bogus ops. |
| `wasm_instrument_trace` | Generate a JS instrumentation wrapper for a .wasm module. |
| `wasm_string_extract` | Extract printable strings from a .wasm binary, grouped by section, with name-section function-name recovery and classification (url/base64/hex-hash/file-path). Wasm-aware alternative to generic binary strings tools. |
| `wasm_diff` | Patch-diff two .wasm binaries (original vs. patched) for vulnerability research: disassembles both via wasm2wat and emits a structured function-level diff (added/removed/changed) plus a per-function WAT line-level unified diff. The full diff is written to an artifact; the response carries summaries and previews. |
| `wasm_instrument_binary` | Real wasm-level binary instrumentation: disassembles via wasm2wat, inserts a call to an imported trace function at every function entry, and reassembles via wat2wasm. Unlike wasm_instrument_trace (which only proxies JS-visible exports), this rewrites the code section so every function entry is observable. Honest boundary: function-ENTRY-level tracing, not basic-block — the host must supply the trace_fn import at instantiation. |
