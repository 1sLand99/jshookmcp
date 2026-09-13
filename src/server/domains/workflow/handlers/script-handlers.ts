/**
 * Script management and extension workflow sub-handler.
 */

import { logger } from '@utils/logger';
import { argNumber, argObject } from '@server/domains/shared/parse-args';
import type { WorkflowSharedState } from './shared';
import type { RetryPolicy } from '@server/workflows/WorkflowContract';
import {
  WORKFLOW_CONSTANTS,
  getOptionalString,
  getOptionalRecord,
  escapeInlineScriptLiteral,
  jsonTextResult,
} from './shared';

export class ScriptHandlers {
  private state: WorkflowSharedState;

  constructor(state: WorkflowSharedState) {
    this.state = state;
  }

  async handlePageScriptRegister(args: Record<string, unknown>) {
    const name = getOptionalString(args.name);
    const code = getOptionalString(args.code);
    const description = getOptionalString(args.description) ?? '';

    if (!name || !code) {
      return jsonTextResult({ success: false, error: 'name and code are required' });
    }

    // Explicit `protected` arg wins; otherwise inherit from an existing entry (update case).
    const protectedArg = typeof args.protected === 'boolean' ? args.protected : undefined;

    const isUpdate = this.state.scriptRegistry.has(name);
    if (!isUpdate && this.state.scriptRegistry.size >= WORKFLOW_CONSTANTS.MAX_SCRIPTS) {
      // LRU eviction: drop the non-protected entry with the oldest lastUsedAt.
      // Never-run entries (lastUsedAt undefined) are treated as oldest; Map insertion
      // order is the natural tiebreaker among ties, so FIFO holds for never-run scripts.
      let victimName: string | undefined;
      let victimLastUsed = Infinity;
      for (const [scriptName, entry] of this.state.scriptRegistry) {
        if (entry.protectedFromEviction) continue;
        const lastUsed = entry.lastUsedAt ?? -Infinity;
        if (lastUsed < victimLastUsed) {
          victimLastUsed = lastUsed;
          victimName = scriptName;
        }
      }
      if (victimName !== undefined) {
        this.state.scriptRegistry.delete(victimName);
      }
    }
    const existingEntry = this.state.scriptRegistry.get(name);
    this.state.scriptRegistry.set(name, {
      code,
      description,
      source: existingEntry?.source ?? 'user',
      protectedFromEviction: protectedArg ?? existingEntry?.protectedFromEviction ?? false,
      lastUsedAt: existingEntry?.lastUsedAt,
    });

    return jsonTextResult({
      success: true,
      action: isUpdate ? 'updated' : 'registered',
      name,
      description,
      protected: this.state.scriptRegistry.get(name)?.protectedFromEviction ?? false,
      totalScripts: this.state.scriptRegistry.size,
      available: Array.from(this.state.scriptRegistry.keys()),
    });
  }

  async handlePageScriptRun(args: Record<string, unknown>) {
    const name = getOptionalString(args.name);
    const params = getOptionalRecord(args.params);

    const entry = name ? this.state.scriptRegistry.get(name) : undefined;
    if (!entry) {
      const available = Array.from(this.state.scriptRegistry.keys());
      return jsonTextResult({ success: false, error: `Script "${name}" not found`, available });
    }

    // Mark access for LRU eviction. Built-in scripts are protected so this is a no-op
    // for them in practice, but tracking is uniform and cheap.
    entry.lastUsedAt = Date.now();

    let codeToRun: string;
    if (params !== undefined) {
      const paramsPayloadLiteral = escapeInlineScriptLiteral(
        JSON.stringify(JSON.stringify(params)),
      );
      codeToRun = `(function(){const __params__=JSON.parse(${paramsPayloadLiteral});return(${entry.code});})()`;
    } else {
      codeToRun = entry.code;
    }

    try {
      return await this.state.deps.browserHandlers.handlePageEvaluate({ code: codeToRun });
    } catch (error) {
      logger.error(`[page_script_run] Script "${name}" failed:`, error);
      return jsonTextResult({
        success: false,
        script: name,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  async handleListExtensionWorkflows() {
    const ctx = this.state.deps.serverContext;
    if (!ctx) {
      return jsonTextResult({
        success: false,
        error: 'Extension workflow runtime is unavailable in this handler context',
      });
    }

    const { ensureWorkflowsLoaded } = await import('@server/extensions/ExtensionManager');
    await ensureWorkflowsLoaded(ctx);
    const workflows = [...ctx.extensionWorkflowsById.values()].filter(
      (record) => record.route?.kind !== 'preset',
    );
    workflows.sort((a, b) => a.id.localeCompare(b.id));
    const serializedWorkflows = workflows.map((record) => ({
      id: record.id,
      displayName: record.displayName,
      description: record.description,
      tags: record.tags,
      timeoutMs: record.timeoutMs,
      defaultMaxConcurrency: record.defaultMaxConcurrency,
      // Chain metadata is only emitted when declared so listing output stays
      // stable for workflows that opt out of the chaining graph.
      ...(record.chainsWith && record.chainsWith.length > 0
        ? { chainsWith: record.chainsWith }
        : {}),
      ...(record.prerequisites && record.prerequisites.length > 0
        ? { prerequisites: record.prerequisites }
        : {}),
      source: record.source,
      route: record.route
        ? {
            kind: record.route.kind,
            priority: record.route.priority,
            requiredDomains: record.route.requiredDomains,
            triggerPatterns: record.route.triggerPatterns.map((pattern) => pattern.source),
            steps: record.route.steps,
          }
        : undefined,
    }));

    return jsonTextResult({
      success: true,
      count: serializedWorkflows.length,
      workflows: serializedWorkflows,
    });
  }

  /**
   * Recommend next workflows from the chainsWith / prerequisites metadata
   * declared by loaded extension workflows, based on the client-supplied list
   * of already-executed workflow ids (the server keeps no execution history).
   *
   * chainsWith edges are outgoing ("after this workflow, run these"), so a
   * candidate is chain-recommended when an executed workflow's chainsWith
   * lists it. Ranking: chain hits first (the reason names which executed
   * workflow recommended the candidate), then fewer missing prerequisites,
   * then id. Candidates without any chain metadata are never suggested —
   * with an empty metadata graph the result is honestly empty.
   */
  async handleWorkflowSuggest(args: Record<string, unknown>) {
    const ctx = this.state.deps.serverContext;
    if (!ctx) {
      return jsonTextResult({
        success: false,
        error: 'Extension workflow runtime is unavailable in this handler context',
      });
    }

    const executedArg = args.executed;
    if (!Array.isArray(executedArg)) {
      return jsonTextResult({
        success: false,
        error: 'executed is required and must be an array of workflow ids',
      });
    }
    const executed: string[] = [];
    for (const entry of executedArg) {
      if (typeof entry !== 'string') {
        return jsonTextResult({
          success: false,
          error: 'executed must contain workflow id strings only',
        });
      }
      if (entry.length > 0 && !executed.includes(entry)) {
        executed.push(entry);
      }
    }

    const { ensureWorkflowsLoaded } = await import('@server/extensions/ExtensionManager');
    await ensureWorkflowsLoaded(ctx);
    const records = [...ctx.extensionWorkflowsById.values()].filter(
      (record) => record.route?.kind !== 'preset',
    );
    const knownIds = new Set(records.map((record) => record.id));
    const executedSet = new Set(executed);
    const unmatched = executed.filter((id) => !knownIds.has(id));

    // chainsWith edges are declared on the upstream workflow ("after me, run
    // these"), so reverse-index them: target id -> sources that chain to it.
    // A candidate is chain-recommended when an executed workflow lists it.
    const chainSources = new Map<string, string[]>();
    for (const record of records) {
      for (const target of record.chainsWith ?? []) {
        const sources = chainSources.get(target);
        if (sources) {
          if (!sources.includes(record.id)) {
            sources.push(record.id);
          }
        } else {
          chainSources.set(target, [record.id]);
        }
      }
    }

    const candidates = [];
    for (const record of records) {
      if (executedSet.has(record.id)) {
        continue;
      }
      const prerequisites = record.prerequisites ?? [];
      const chainHits = (chainSources.get(record.id) ?? []).filter((id) => executedSet.has(id));
      const missingPrerequisites = prerequisites.filter((id) => !executedSet.has(id));

      // Grounded recommendations only: a candidate must either chain from an
      // executed workflow or declare prerequisites. No metadata → no suggestion.
      if (chainHits.length === 0 && prerequisites.length === 0) {
        continue;
      }

      const reasons: string[] = [];
      if (chainHits.length > 0) {
        reasons.push(`Chained from "${chainHits.join('", "')}" via chainsWith`);
      }
      if (prerequisites.length > 0) {
        reasons.push(
          missingPrerequisites.length === 0
            ? `All prerequisites satisfied: ${prerequisites.join(', ')}`
            : `Missing prerequisites: ${missingPrerequisites.join(', ')}`,
        );
      }

      candidates.push({
        id: record.id,
        chainHit: chainHits.length > 0,
        missingPrerequisites,
        reason: reasons.join('; '),
      });
    }

    candidates.sort((a, b) => {
      if (a.chainHit !== b.chainHit) {
        return a.chainHit ? -1 : 1;
      }
      if (a.missingPrerequisites.length !== b.missingPrerequisites.length) {
        return a.missingPrerequisites.length - b.missingPrerequisites.length;
      }
      return a.id.localeCompare(b.id);
    });

    const suggestions = candidates.map((candidate) => ({
      name: candidate.id,
      reason: candidate.reason,
      missingPrerequisites: candidate.missingPrerequisites,
    }));

    return jsonTextResult({ success: true, suggestions, unmatched });
  }

  async handleRunExtensionWorkflow(args: Record<string, unknown>, retryPolicy?: RetryPolicy) {
    const ctx = this.state.deps.serverContext;
    if (!ctx) {
      return jsonTextResult({
        success: false,
        error: 'Extension workflow runtime is unavailable in this handler context',
      });
    }

    const workflowId = getOptionalString(args.workflowId) ?? getOptionalString(args.id);
    if (!workflowId) {
      return jsonTextResult({ success: false, error: 'workflowId is required' });
    }

    const { ensureWorkflowsLoaded } = await import('@server/extensions/ExtensionManager');
    await ensureWorkflowsLoaded(ctx);
    const runtimeRecord = ctx.extensionWorkflowRuntimeById.get(workflowId);
    if (!runtimeRecord) {
      const available = [...ctx.extensionWorkflowsById.values()]
        .filter((record) => record.route?.kind !== 'preset')
        .map((record) => record.id);
      available.sort((a, b) => a.localeCompare(b));
      return jsonTextResult({
        success: false,
        error: `Extension workflow "${workflowId}" not found`,
        available,
      });
    }

    if (runtimeRecord.route?.kind === 'preset') {
      return jsonTextResult({
        success: false,
        workflowId,
        error:
          `Extension workflow "${workflowId}" is a routing preset and cannot be executed directly. ` +
          'Use route_tool or the suggested preset steps instead.',
      });
    }

    const profile = getOptionalString(args.profile);
    const config = getOptionalRecord(args.config);
    const nodeInputOverrides = argObject(args, 'nodeInputOverrides') as
      | Record<string, Record<string, unknown>>
      | undefined;
    const timeoutMs = argNumber(args, 'timeoutMs');

    try {
      const { executeExtensionWorkflow } = await import('@server/workflows/WorkflowEngine');
      const result = await executeExtensionWorkflow(ctx, runtimeRecord.workflow, {
        profile,
        config,
        nodeInputOverrides,
        timeoutMs,
        retryPolicy,
      });
      return jsonTextResult({ success: true, ...result });
    } catch (error) {
      logger.error(`[run_extension_workflow] Workflow "${workflowId}" failed:`, error);
      return jsonTextResult({
        success: false,
        workflowId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
}
