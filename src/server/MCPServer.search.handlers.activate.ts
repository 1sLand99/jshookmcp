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

    const extensionRecord = ctx.extensionToolsByName.get(name);
    if (extensionRecord) {
      if (!budget.admit(extensionRecord.tool)) {
        budgetExceeded.push(name);
        continue;
      }
      registerExtensionToolRecord(ctx, extensionRecord, 'activate_tools');
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
      await ensureDomainLoaded(catalogEntry.domain);
      const toolDef = getRegistrationByName(name)?.tool;
      if (!toolDef) {
        notFound.push(name);
        continue;
      }
      const registeredTool = ctx.registerSingleTool(toolDef);
      ctx.activatedToolNames.add(name);
      ctx.activatedRegisteredTools.set(name, registeredTool);
      ctx.enabledDomains.add(catalogEntry.domain);
      const newToolNames = new Set([name]);
      const newHandlers = createToolHandlerMap(ctx.handlerDeps, newToolNames);
      ctx.router.addHandlers(newHandlers);
    }

    activated.push(name);
    activeNames.add(name);
  }

  await notifyToolListChanged(ctx, activated.length > 0);

  logger.info(
    `activate_tools: activated ${activated.length}, already_active ${alreadyActive.length}, not_found ` +
      `${notFound.length}, budget_exceeded ${budgetExceeded.length}`,
  );

  if (activated.length > 0) {
    emitBusEvent(ctx.eventBus, 'tool.activation.changed', {
      action: 'activated',
      toolNames: activated,
      timestamp: new Date().toISOString(),
    });
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

  for (const rawName of names) {
    const name = normalizeToolName(rawName);
    if (!ctx.activatedToolNames.has(name)) {
      notActivated.push(name);
      continue;
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
    emitBusEvent(ctx.eventBus, 'tool.activation.changed', {
      action: 'deactivated',
      toolNames: deactivated,
      timestamp: new Date().toISOString(),
    });
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
