# Harness 模式模板：Long Proof（并行候选 + Falsifier + 合成）

> 源自 Stellar Colosseum（arXiv:2609.15983）的 Colosseum 工作流，已集成进 Google Antigravity 的 Teamwork "Long Proof" pattern。这里沉淀为 jshookmcp extension workflow 模板，供 `MCP_WORKFLOW_ROOTS` 外部仓库直接引用。**所有 API 已对照 extension-sdk v0.3.3 源码验证。**

## 适用场景

- 需要对同一目标做**多路线并行分析**再合并结论（逆向取证、混淆代码分析、协议推断）
- 需要**对抗性验证**：每个候选路线配一个专职"找茬"阶段
- 路线成熟度依赖**历史运行记录**（readiness gate：失败率过高时不推进）

## 核心原语（真实 SDK API）

| Stellar 概念                 | jshookmcp 原语                          | 真实 API                                                                          |
| ---------------------------- | --------------------------------------- | --------------------------------------------------------------------------------- |
| 工作流图                     | `buildGraph((ctx) => node)`             | `WorkflowSpec.buildGraph`                                                         |
| 并行候选生成                 | `parallelStep(id, cfg?)`                | 返回 ParallelBuilder（`.step(builder)` 可嵌套）                                   |
| Falsifier（对抗验证）        | `sequenceStep(id, cfg?)` 内串接验证工具 | SequenceBuilder `.tool(id, name, cfg?)`                                           |
| Readiness gate               | `branchStep(id, predicateId, cfg?)`     | BranchBuilder `.predicateFn(fn)` + `.whenTrue(nodeOrBuilder)` / `.whenFalse(...)` |
| 合成（tournament merge）     | `toolStep(id, name)` + `.retry(policy)` | ToolBuilder `.input({...})` `.retry({ maxAttempts })`                             |
| 跨轮学习（pitfall registry） | `chainsWith()` / `prerequisites()`      | `WorkflowSpec.chainsWith([...])`                                                  |

**关键 API 事实（已验证）**：

- 顶层用 `buildGraph((ctx) => ...)`，**没有** `.step()` 链式入口
- `whenTrue` / `whenFalse` 接受 **node 或 builder**（内部 `buildNode` 统一处理），所以可传 `parallelStep(...)` 或 `toolStep(...)` 的返回值
- `ToolStep` 传参用 `.input({...})`（**不是** `args()`）
- **`WorkflowExecutionContext` 类型上没有 `history` 字段**——历史感知谓词通过 `predicateId` 注册（`last_run_failed:<workflowId>`，见 `src/server/workflows/WorkflowPredicates.ts`），**不要**在模板里访问 `ctx.history`

## 模板 1：并行候选 + 合成（无 falsifier 的最小版）

```ts
import {
  defineWorkflow,
  parallelStep,
  sequenceStep,
  toolStep,
  branchStep,
} from "@jshookmcp/extension-sdk/workflow";

export default defineWorkflow(
  "harness.parallel_candidates",
  "Parallel candidates + merge",
  (w) =>
    w
      .description(
        "Run N independent analysis routes on the same target, then merge the strongest result.",
      )
      .tags(["harness", "parallel", "synthesis"])
      .defaultMaxConcurrency(4)
      .route({
        kind: "preset",
        steps: [
          {
            pattern: "analyze|investigate|recover",
            tools: ["analysis_understand_code", "trace_export"],
          },
        ],
      })
      // Readiness gate: only fan out when the last run of this workflow did not fail.
      .buildGraph(() =>
        sequenceStep("main", (sq) =>
          sq
            .step(
              branchStep(
                "gate",
                "last_run_failed:harness.parallel_candidates",
                (b) =>
                  b
                    .whenTrue(
                      parallelStep("routes", (p) =>
                        p
                          .step(
                            toolStep(
                              "route-a",
                              "analysis_understand_code",
                              (t) => t.input({ mode: "route-a" }),
                            ),
                          )
                          .step(
                            toolStep("route-b", "trace_export", (t) =>
                              t.input({ mode: "route-b" }),
                            ),
                          )
                          .step(
                            toolStep(
                              "route-c",
                              "instrumentation_hook_preset",
                              (t) => t.input({ mode: "route-c" }),
                            ),
                          ),
                      ),
                    )
                    // Immature route: cheap single attempt.
                    .whenFalse(
                      toolStep(
                        "fallback-route",
                        "analysis_understand_code",
                        (t) => t.input({ mode: "single" }),
                      ),
                    ),
              ),
            )
            .step(
              toolStep("merge", "workflow_run_inspect", (t) =>
                t.input({ combine: "best-of" }),
              ),
            ),
        ),
      )
      .chainsWith(["harness.verify"])
      .prerequisites(["harness.context"]),
);
```

## 模板 2：Falsifier 专职找茬（Stellar 核心）

每个候选在合并前必须经过一个**专职验证阶段**——用与分析路线不同域的工具主动找漏洞：

```ts
import {
  defineWorkflow,
  parallelStep,
  sequenceStep,
  toolStep,
} from "@jshookmcp/extension-sdk/workflow";

export default defineWorkflow(
  "harness.falsify",
  "Candidate + falsifier review",
  (w) =>
    w
      .description(
        "Each candidate route gets a dedicated adversarial review pass before merge.",
      )
      .tags(["harness", "falsifier", "review"])
      .buildGraph(() =>
        sequenceStep("main", (sq) =>
          sq
            .step(
              parallelStep("candidates", (p) =>
                p
                  // Candidate 1 + its falsifier (analysis domain)
                  .step(
                    sequenceStep("cand-1", (c1) =>
                      c1
                        .tool("produce-1", "analysis_understand_code")
                        .tool("falsify-1", "debugger_disassemble", (t) =>
                          t.input({ attack: "find-flaws" }),
                        ),
                    ),
                  )
                  // Candidate 2 + its falsifier (trace domain — independent perspective)
                  .step(
                    sequenceStep("cand-2", (c2) =>
                      c2
                        .tool("produce-2", "trace_export")
                        .tool("falsify-2", "protocol_analyze", (t) =>
                          t.input({ attack: "find-flaws" }),
                        ),
                    ),
                  ),
              ),
            )
            // Synthesis: only falsifier-clean candidates reach the merge step.
            // retry bounces a failed combined result back to the candidate phase.
            .step(
              toolStep("merge", "workflow_run_inspect", (t) =>
                t
                  .input({ combine: "verified-only" })
                  .retry({ maxAttempts: 2, backoffMs: 500 }),
              ),
            ),
        ),
      ),
);
```

## 模板 3：Readiness gate 完整形态（历史感知谓词）

```ts
import {
  defineWorkflow,
  parallelStep,
  sequenceStep,
  toolStep,
  branchStep,
} from "@jshookmcp/extension-sdk/workflow";

export default defineWorkflow(
  "harness.gated_research",
  "Readiness-gated long research",
  (w) =>
    w
      .description(
        "Route maturity decides how deep the analysis goes — failed routes retry cheap first.",
      )
      .tags(["harness", "readiness", "research"])
      // DAG metadata: this workflow only makes sense after context is gathered
      // and its output feeds the synthesis stage.
      .prerequisites(["harness.context"])
      .chainsWith(["harness.synthesize"])
      .buildGraph(() =>
        sequenceStep("plan", (sq) =>
          sq.step(
            // `last_run_failed:<workflowId>` is a registered history predicate in
            // WorkflowPredicates — degrades to "no history" on first run (false),
            // so the shallow branch runs until the route has a track record.
            branchStep("depth", "last_run_failed:harness.gated_research", (b) =>
              b
                .whenTrue(
                  sequenceStep("full", (f) =>
                    f
                      .step(
                        parallelStep("subproblems", (sp) =>
                          sp
                            .step(toolStep("sub-a", "trace_export"))
                            .step(toolStep("sub-b", "network_capture"))
                            .step(
                              toolStep("sub-c", "analysis_understand_code"),
                            ),
                        ),
                      )
                      .tool("verify", "workflow_run_inspect"),
                  ),
                )
                // Immature route: single shallow attempt, low cost.
                .whenFalse(
                  toolStep("probe", "search_tools", (t) =>
                    t.input({ depth: "shallow" }),
                  ),
                ),
            ),
          ),
        ),
      ),
);
```

## 接线要点

1. **模板文件位置**：外部 workflow 仓库（如 jshook_workflow_template）根目录，`export default defineWorkflow(...)` 默认导出，入口文件名 `workflow.ts`（TS-first 编译规约）。
2. **注册**：主进程 `export MCP_WORKFLOW_ROOTS=<path>` 后由 `run_extension_workflow` / `list_extension_workflows` 发现。
3. **历史谓词**：`last_run_failed:<workflowId>` 是 `WorkflowPredicates` 已注册的谓词 id（读最近 `DEFAULT_HISTORY_WINDOW=10` 次运行）。**首次运行无历史时谓词为 false**（走 whenFalse 分支），符合"新路线先浅试"的语义。**不要**在模板里读 `ctx.history`（类型上不存在）。
4. **合成步骤的 retry**：`retry({ maxAttempts })` 把验证失败弹回候选阶段（Stellar 的 verifier 反馈路由），`maxAttempts` 防死循环。
5. **工具名核对**：模板里的工具名（如 analysis_understand_code、debugger_disassemble）是**占位符**——接入前用 `search_tools` 或 `list_extension_workflows` 核对实际注册名，避免运行期 miss。
6. **不内置特征**：falsifier 的攻击参数只描述意图（`attack: 'find-flaws'`），不携带具体 payload/IOC——符合零内置特征库约束。

## 与论文的映射（诚实边界）

- 可移植：并行候选、对抗验证、readiness gate、DAG 分解、反馈路由——全部由 jshookmcp 工具原语承载。
- **不可移植**：Stellar 的性能（TCS-Bench 71%）来自 Gemini 3.1 Pro 的研究能力 + Google 规模，不是工具层创新。jshookmcp 提供的是**编排原语**，研究智能由外部 agent 提供。
- falsifier 的"反驳质量"没有自动度量——`workflow_run_inspect` 只确认执行成功，不评判论证强度。这是工具服务器的诚实边界。
- 历史感知 gate 目前只有 `last_run_failed:` 一种（失败率阈值不可配）——需要更细粒度门控时在外部仓库用 `predicateFn` 内联实现（参考 `WorkflowPredicates` 的 `computeFailureRate` 导出）。
