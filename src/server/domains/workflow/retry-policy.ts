import type { RetryPolicy } from '@server/workflows/WorkflowContract';

let globalRetryPolicy: RetryPolicy | undefined;

export function getGlobalRetryPolicy(): RetryPolicy | undefined {
  return globalRetryPolicy ? { ...globalRetryPolicy } : undefined;
}

export function setGlobalRetryPolicy(policy: RetryPolicy): void {
  globalRetryPolicy = { ...policy };
}
