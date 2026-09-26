import type { RetryPolicy, WorkflowExecutionContext } from '@server/workflows/WorkflowContract';
import type { WorkflowHistoryPort } from '@server/workflows/WorkflowHistoryPort';

type JsonRecord = Record<string, unknown>;

export interface WorkflowMetric {
  name: string;
  value: number;
  type: 'counter' | 'gauge' | 'histogram';
  attrs?: Record<string, unknown>;
  at: string;
}

export interface WorkflowSpan {
  name: string;
  attrs?: Record<string, unknown>;
  at: string;
}

export interface ExecuteWorkflowOptions {
  profile?: string;
  config?: JsonRecord;
  preflightMode?: 'warn' | 'strict' | 'skip';
  nodeInputOverrides?: Record<string, Record<string, unknown>>;
  timeoutMs?: number;
  /** Global retry policy used as fallback when a tool node has no per-node retry config. */
  retryPolicy?: RetryPolicy;
}

export interface PreflightWarning {
  nodeId: string;
  toolName: string;
  condition: string;
  fix: string;
}

export class PreflightError extends Error {
  readonly warnings: PreflightWarning[];
  constructor(warnings: PreflightWarning[]) {
    super(`Workflow preflight failed with ${warnings.length} unsatisfied prerequisite(s)`);
    this.warnings = warnings;
    this.name = 'PreflightError';
  }
}

export interface ExecuteWorkflowResult {
  workflowId: string;
  displayName: string;
  runId: string;
  profile: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  result: unknown;
  stepResults: Record<string, unknown>;
  metrics: WorkflowMetric[];
  spans: WorkflowSpan[];
}

export interface InternalExecutionContext<TDataBus = unknown> extends WorkflowExecutionContext {
  readonly stepResults: Map<string, unknown>;
  readonly dataBus: TDataBus;
  /**
   * Read-only view onto this workflow's past runs, for history-aware branch
   * predicates (`history_failure_rate_gte_N`, `last_run_failed`, …).
   *
   * Optional, and deliberately so: contexts constructed without it (the
   * `workflow_conditional_step` stub context, unit tests) make those predicates
   * evaluate to `false` — an absent history source must not flip branch
   * behaviour. See `WorkflowPredicates.ts` for the degradation rule.
   */
  readonly history?: WorkflowHistoryPort;
  /**
   * Id of the workflow being executed, so predicates without an explicit
   * `:workflowId` suffix can resolve which history to read.
   */
  readonly workflowId?: string;
}

export interface ParallelResult {
  [stepId: string]: unknown;
  __order: string[];
}

export type { JsonRecord };
