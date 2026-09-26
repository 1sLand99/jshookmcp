/**
 * Handlers for activate_tools and deactivate_tools meta-tools.
 */
import { logger } from '@utils/logger';
import { emitBusEvent } from '@server/EventBus';
import {
  registerExtensionToolRecord,
  unregisterExtensionToolRecord,
} from '@server/extensions/ExtensionManager.tools';
import { asTextResponse } from '@server/domains/shared/response';
import { createToolHandlerMap } from '@server/ToolHandlerMap';
import type { MCPServerContext } from '@server/MCPServer.context';
import type { ToolResponse } from '@server/types';
import { normalizeToolName, validateToolNameArray } from '@server/MCPServer.search.validation';
import {
  createActivationBudgetTracker,
  getActiveToolNames,
  summarizeActivationBudget,
  type ActivationBudgetSummary,
} from '@server/MCPServer.search.helpers';
import { loadSearchCatalog } from '@server/registry/SearchCatalog';
import { ensureDomainLoaded, getRegistrationByName } from '@server/registry/index';
import { deactivateToolCore } from '@server/tool-lifecycle';

interface ActivationSummary {
  activated: string[];
  alreadyActive: string[];
  notFound: string[];
  /** Tools skipped because they did not fit the activation budget. */
  budgetExceeded: string[];
  totalActive: number;
  budget: ActivationBudgetSummary;
}

async function notifyToolListChanged(ctx: MCPServerContext, changed: boolean): Promise<void> {
  if (!changed) {
    return;
  }

  try {
    await ctx.server.sendToolListChanged();
  } catch (e) {
    logger.warn('sendToolListChanged failed:', e);
  }
}

export async function activateToolNames(
  ctx: MCPServerContext,
  names: string[],
): Promise<ActivationSummary> {
  // Dynamic import keeps the module graph acyclic: search.ts registers the
  // handlers defined in this module, so a static import would form a cycle.
  const { META_TOOL_NAMES } = await import('@server/MCPServer.search');
  const activeNames = getActiveToolNames(ctx);
  const activated: string[] = [];
  const alreadyActive: string[] = [];
  const notFound: string[] = [];
  const budgetExceeded: string[] = [];
  /**
   * Owning domain of each newly activated tool, keyed by name. Filled at the
   * same point as `activated` (see below), so its keys are exactly that list,
   * in order — never the whole request, only the tools that transitioned.
   */
  const activatedDomains = new Map<string, string>();
  const budget = await createActivationBudgetTracker(ctx);

  for (const rawName of names) {
    const name = normalizeToolName(rawName);
    // Meta-tools are always registered as top-level tools and never appear in
    // the domain search catalog, so report them as already active instead of
    // notFound.
    if (META_TOOL_NAMES.has(name)) {
      alreadyActive.push(name);
      continue;
    }

    if (activeNames.has(name)) {
      alreadyActive.push(name);
      continue;
    }

    /**
     * Owning domain of this tool, resolved on whichever branch registers it.
     * Both branches assign it before falling through to the push below; every
     * path that skips registration `continue`s out first.
     */
    let domain: string;
    const extensionRecord = ctx.extensionToolsByName.get(name);
    if (extensionRecord) {
      if (!budget.admit(extensionRecord.tool)) {
        budgetExceeded.push(name);
        continue;
      }
      registerExtensionToolRecord(ctx, extensionRecord, 'activate_tools');
      domain = extensionRecord.domain;
    } else {
      const catalog = await loadSearchCatalog();
      const catalogEntry = catalog.entryByName.get(name);
      if (!catalogEntry) {
        notFound.push(name);
        continue;
      }
      // Budget is checked against the catalog definition before loading the
      // domain, so rejected tools never trigger a domain load.
      if (!budget.admit(catalogEntry.tool)) {
        budgetExceeded.push(name);
        continue;
      }
      await ensureDomainLoaded(catalogEntry.domain, ctx.eventBus);
      const toolDef = getRegistrationByName(name)?.tool;
      if (!toolDef) {
        notFound.push(name);
        continue;
      }
      const registeredTool = ctx.registerSingleTool(toolDef);
      ctx.activatedToolNames.add(name);
      ctx.activatedRegisteredTools.set(name, registeredTool);
      ctx.enabledDomains.add(catalogEntry.domain);
      domain = catalogEntry.domain;
      const newToolNames = new Set([name]);
      const newHandlers = createToolHandlerMap(ctx.handlerDeps, newToolNames);
      ctx.router.addHandlers(newHandlers);
    }

    activated.push(name);
    activatedDomains.set(name, domain);
    activeNames.add(name);
  }

  await notifyToolListChanged(ctx, activated.length > 0);

  logger.info(
    `activate_tools: activated ${activated.length}, already_active ${alreadyActive.length}, not_found ` +
      `${notFound.length}, budget_exceeded ${budgetExceeded.length}`,
  );

  if (activated.length > 0) {
    const timestamp = new Date().toISOString();
    emitBusEvent(ctx.eventBus, 'tool.activation.changed', {
      action: 'activated',
      toolNames: activated,
      timestamp,
    });
    // Per-tool companion to the batch event above. `tool.activation.changed`
    // reports the whole batch and carries no domain; `tool:activated` reports
    // each tool that actually transitioned, with the domain it belongs to.
    // `activatedDomains` is filled at the same point as `activated`, so the two
    // cannot drift — one event per transition, never one per request.
    for (const [toolName, domain] of activatedDomains) {
      emitBusEvent(ctx.eventBus, 'tool:activated', { toolName, domain, timestamp });
    }
  }
  if (budgetExceeded.length > 0) {
    emitBusEvent(ctx.eventBus, 'tool.activation.changed', {
      action: 'budget-rejected',
      toolNames: budgetExceeded,
      timestamp: new Date().toISOString(),
    });
  }

  return {
    activated,
    alreadyActive,
    notFound,
    budgetExceeded,
    totalActive: activeNames.size,
    budget: summarizeActivationBudget(budget),
  };
}

// ── activate_tools handler ──

export async function handleActivateTools(
  ctx: MCPServerContext,
  args: Record<string, unknown>,
): Promise<ToolResponse> {
  // Handle both array and JSON-string formats (anyOf schema may pass either)
  let namesArg = args.names;
  if (typeof namesArg === 'string' && namesArg.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(namesArg);
      if (Array.isArray(parsed)) namesArg = parsed;
    } catch {
      /* malformed — fall through */
    }
  }

  const { names, error } = validateToolNameArray({ names: namesArg });
  if (error) {
    return asTextResponse(JSON.stringify({ success: false, error }));
  }

  const result = await activateToolNames(ctx, names);

  const hint =
    result.budgetExceeded.length > 0
      ? `Skipped ${result.budgetExceeded.length} tool(s) over the activation budget ` +
        `(used ${result.budget.usedTokens}/${result.budget.maxTokens} tokens, ` +
        `${result.budget.activeTools}/${result.budget.maxTools} tools): ` +
        `${result.budgetExceeded.join(', ')}. Deactivate unused tools first or raise ` +
        `MCP_TOOL_ACTIVATION_BUDGET_TOKENS / MCP_TOOL_MAX_ACTIVE_TOOLS.`
      : result.activated.length > 0
        ? 'Tools activated. If they do not appear in your tool list, use call_tool({ name: "<tool>", args: {...} ' +
          '}) to invoke them.'
        : undefined;

  return asTextResponse(
    JSON.stringify({
      success: true,
      ...result,
      hint,
    }),
  );
}

// ── deactivate_tools handler ──

export async function handleDeactivateTools(
  ctx: MCPServerContext,
  args: Record<string, unknown>,
): Promise<ToolResponse> {
  const { names, error } = validateToolNameArray(args);
  if (error) {
    return asTextResponse(JSON.stringify({ success: false, error }));
  }

  const deactivated: string[] = [];
  const notActivated: string[] = [];
  /**
   * Owning domain of each newly deactivated tool. Filled only for tools that
   * actually transitioned, so `tool:deactivated` is per-transition, never per
   * request.
   */
  const deactivatedDomains = new Map<string, string>();
  const catalog = await loadSearchCatalog();

  for (const rawName of names) {
    const name = normalizeToolName(rawName);
    if (!ctx.activatedToolNames.has(name)) {
      notActivated.push(name);
      continue;
    }

    // Resolve the domain before any removal mutates the extension registry, so
    // the event reports the domain the tool actually belonged to.
    const domain =
      ctx.extensionToolsByName.get(name)?.domain ?? catalog.entryByName.get(name)?.domain;
    if (domain) {
      deactivatedDomains.set(name, domain);
    } else {
      logger.warn(
        `deactivate_tools: could not resolve a domain for active tool "${name}"; ` +
          'no tool:deactivated event will be emitted for it',
      );
    }

    const registeredTool = ctx.activatedRegisteredTools.get(name);
    if (registeredTool && !ctx.extensionToolsByName.has(name)) {
      try {
        registeredTool.remove();
      } catch (e) {
        logger.warn(`Failed to remove activated tool "${name}":`, e);
      }
    }

    const extensionRecord = ctx.extensionToolsByName.get(name);
    if (extensionRecord) {
      unregisterExtensionToolRecord(ctx, extensionRecord, {
        onRemoveError: (removeError) => {
          logger.warn(`Failed to remove activated tool "${name}":`, removeError);
        },
      });
    } else {
      deactivateToolCore(name, {
        activatedToolNames: ctx.activatedToolNames,
        activatedRegisteredTools: ctx.activatedRegisteredTools,
        router: ctx.router,
        extensionToolsByName: ctx.extensionToolsByName,
      });
    }
    deactivated.push(name);
  }

  await notifyToolListChanged(ctx, deactivated.length > 0);

  logger.info(
    `deactivate_tools: deactivated ${deactivated.length}, not_activated ${notActivated.length}`,
  );

  if (deactivated.length > 0) {
    const timestamp = new Date().toISOString();
    emitBusEvent(ctx.eventBus, 'tool.activation.changed', {
      action: 'deactivated',
      toolNames: deactivated,
      timestamp,
    });
    // Per-tool companion to the batch event above — see the activation site.
    for (const name of deactivated) {
      const domain = deactivatedDomains.get(name);
      if (domain === undefined) continue;
      emitBusEvent(ctx.eventBus, 'tool:deactivated', { toolName: name, domain, timestamp });
    }
  }

  return asTextResponse(
    JSON.stringify({
      success: true,
      deactivated,
      notActivated,
      hint: 'Deactivated tools are no longer available. Search again to find alternatives.',
    }),
  );
}
