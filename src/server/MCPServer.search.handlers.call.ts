/**
 * Handler for the call_tool proxy meta-tool.
 *
 * Bridges the gap for MCP clients that do not support `tools/list_changed`
 * notifications. After activate_tools / activate_domain registers a tool
 * server-side, such clients still cannot see it in their cached tool list.
 * call_tool lets them invoke any catalogued tool by name + args, with
 * automatic on-demand activation when the tool is not yet registered.
 *
 * Meta-tools themselves (search_tools, activate_tools, coverage_report, ...)
 * are top-level tools that live in neither the router nor the search catalog;
 * call_tool dispatches them directly to their registered handlers.
 */
import { logger } from '@utils/logger';
import { asTextResponse, asErrorResponse } from '@server/domains/shared/response';
import type { MCPServerContext } from '@server/MCPServer.context';
import type { ToolResponse } from '@server/types';
import { normalizeToolName } from '@server/MCPServer.search.validation';
import { getSearchEngine } from '@server/MCPServer.search.helpers';
import { getRuntimeState } from '@server/runtime/ServerRuntimeState';
import { getToolInputSchema } from '@server/ToolRouter.probe';
import { loadSearchCatalog } from '@server/registry/SearchCatalog';
import { validateToolArgsAgainstSchema } from '@server/MCPServer.search.validation.runtime';

/** Structural mirror of the meta-tool handler type exported by MCPServer.search. */
type MetaToolDispatchHandler = (
  ctx: MCPServerContext,
  args: Record<string, unknown>,
) => Promise<ToolResponse>;

interface CallToolMetadata {
  wasAutoActivated?: boolean;
  activatedTools?: string[];
}

function buildCallToolMetadata(
  wasAutoActivated: boolean,
  activatedTools: string[],
): CallToolMetadata {
  return {
    wasAutoActivated,
    activatedTools,
  };
}

function attachCallToolMetadata(response: ToolResponse, metadata: CallToolMetadata): ToolResponse {
  if (!response?.content || !Array.isArray(response.content)) {
    return response;
  }
  return {
    ...response,
    content: response.content.map((item) => {
      if (item.type !== 'text' || !('text' in item) || typeof item.text !== 'string') {
        return item;
      }

      try {
        const parsed = JSON.parse(item.text) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return item;
        }

        return {
          ...item,
          text: JSON.stringify(
            {
              ...(parsed as Record<string, unknown>),
              ...metadata,
            },
            null,
            2,
          ),
        };
      } catch {
        return item;
      }
    }),
  };
}

/**
 * Dispatch a meta-tool through its registered handler, mirroring the top-level
 * registration wrapper in registerSearchMetaTools (record the call; wrap
 * handler throws in asErrorResponse so failures match direct invocation).
 */
async function dispatchMetaTool(
  ctx: MCPServerContext,
  name: string,
  toolArgs: Record<string, unknown>,
  callMetadata: CallToolMetadata,
  getMetaToolHandler: (handlerName: string) => MetaToolDispatchHandler | undefined,
): Promise<ToolResponse> {
  if (name === 'call_tool') {
    // Self-reference would recurse infinitely — call_tool must be invoked
    // directly as a top-level tool instead. Rejected before gating: the
    // top-level registration wrapper already evaluated call_tool's rules,
    // and a self-reference must never dispatch (or double-gate).
    return asTextResponse(
      JSON.stringify({
        success: false,
        error:
          'Tool "call_tool" cannot be invoked through call_tool itself. Call it directly as a top-level tool.',
        ...callMetadata,
      }),
    );
  }

  // Gate the dispatched meta tool under its own name before dispatch — the
  // call_tool proxy path must not bypass the toolExecution rules or the
  // doom-loop breaker (dynamic import keeps the graph acyclic; see
  // registerSearchMetaTools for the ToolCallContextGuard cycle).
  const { runToolExecutionGate } = await import('@server/ToolCallContextGuard');
  const gateResponse = runToolExecutionGate(ctx, name, toolArgs);
  if (gateResponse) {
    return attachCallToolMetadata(gateResponse, callMetadata);
  }

  const handler = getMetaToolHandler(name);
  if (!handler) {
    // Defensive only: META_TOOL_NAMES and the handler registry share one source.
    return asTextResponse(
      JSON.stringify({
        success: false,
        error: `Tool "${name}" is a meta tool but no handler is registered for it.`,
        ...callMetadata,
      }),
    );
  }

  try {
    const response = await handler(ctx, toolArgs);
    // Mirror the top-level wrapper so coverage_report sees call_tool-routed
    // meta calls too.
    getRuntimeState(ctx)?.recordToolCall(name, toolArgs);
    return attachCallToolMetadata(response, callMetadata);
  } catch (error) {
    // Match the direct-call failure path instead of call_tool's own JSON error.
    logger.error(`call_tool: meta tool "${name}" failed`, error);
    return asErrorResponse(error);
  }
}

export async function handleCallTool(
  ctx: MCPServerContext,
  args: Record<string, unknown>,
): Promise<ToolResponse> {
  const searchCatalog = await loadSearchCatalog();
  const rawName = typeof args.name === 'string' ? args.name : '';
  const defaultMetadata = buildCallToolMetadata(false, []);

  if (!rawName) {
    return asTextResponse(
      JSON.stringify({
        success: false,
        error: 'name must be a non-empty string',
        ...defaultMetadata,
      }),
    );
  }

  const name = normalizeToolName(rawName);
  // Accept three argument formats:
  // 1. { args: { ... } }                — schema-defined name
  // 2. { parameters: "{...}" }          — JSON-serialized string (some MCP clients)
  // 3. { arguments: "{...}" }           — MCP clients that stringify the wrapper
  // 4. { url: ..., method: ... }        — spread flat (params are top-level keys, no wrapper)
  let toolArgs: Record<string, unknown> = {};
  let wrapperError: string | null = null;
  const argsValue = args.args;
  const parametersValue = args.parameters;
  const argumentsValue = args.arguments;

  if (argsValue && typeof argsValue === 'object' && !Array.isArray(argsValue)) {
    toolArgs = argsValue as Record<string, unknown>;
  } else if (parametersValue !== undefined) {
    if (parametersValue && typeof parametersValue === 'object' && !Array.isArray(parametersValue)) {
      toolArgs = parametersValue as Record<string, unknown>;
    } else if (typeof parametersValue === 'string' && parametersValue.trim().length > 0) {
      try {
        const parsed = JSON.parse(parametersValue);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          toolArgs = parsed as Record<string, unknown>;
        }
      } catch {
        /* malformed parameters JSON — treated as no arguments */
      }
    }
  } else if (argumentsValue !== undefined) {
    // The arguments wrapper must never be silently dropped: the client
    // explicitly sent it, so an unusable value is reported instead of
    // invoking the tool with empty arguments.
    if (typeof argumentsValue === 'string') {
      if (argumentsValue.trim().length === 0) {
        wrapperError = 'arguments must be a non-empty JSON string';
      } else {
        try {
          const parsed = JSON.parse(argumentsValue);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            toolArgs = parsed as Record<string, unknown>;
          } else {
            wrapperError = 'arguments must decode to a JSON object';
          }
        } catch {
          wrapperError = 'arguments must be valid JSON';
        }
      }
    } else if (
      argumentsValue &&
      typeof argumentsValue === 'object' &&
      !Array.isArray(argumentsValue)
    ) {
      toolArgs = argumentsValue as Record<string, unknown>;
    } else {
      wrapperError = 'arguments must be a JSON object or a JSON string';
    }
  }

  // Format 4 (spread flat): only when neither args, parameters, nor arguments was
  // provided, and no wrapper was successfully parsed — collect remaining keys as tool arguments.
  if (
    Object.keys(toolArgs).length === 0 &&
    !('args' in args) &&
    !('parameters' in args) &&
    !('arguments' in args)
  ) {
    for (const [k, v] of Object.entries(args)) {
      if (k !== 'name') {
        toolArgs[k] = v;
      }
    }
  }

  if (wrapperError && Object.keys(toolArgs).length === 0) {
    return asTextResponse(
      JSON.stringify({
        success: false,
        error: wrapperError,
        ...defaultMetadata,
      }),
    );
  }

  const callMetadata = defaultMetadata;

  // Meta-tools live in neither the router nor the search catalog — dispatch
  // them straight to their registered handlers before auto-activation logic.
  // Dynamic import keeps the graph acyclic: search.ts registers handleCallTool
  // (implemented here), so a static import of META_TOOL_NAMES would cycle.
  const { META_TOOL_NAMES, getMetaToolHandler } = await import('@server/MCPServer.search');
  if (META_TOOL_NAMES.has(name)) {
    return dispatchMetaTool(ctx, name, toolArgs, callMetadata, getMetaToolHandler);
  }

  // Auto-activate the tool if it's known but not yet registered.
  // This bridges the gap for MCP clients that cannot see tools/list_changed
  // and for search-tier sessions where the tool was discovered via search_tools
  // but not yet activated (e.g., when search returned 0 results and domain
  // fallback activation was triggered).
  if (!ctx.router.has(name)) {
    let autoActivated = false;
    try {
      const catalogEntry = searchCatalog.entryByName.get(name);
      if (catalogEntry) {
        const { activateToolNames } = await import('@server/MCPServer.search.handlers.activate');
        const domain = catalogEntry.domain;
        if (domain && !ctx.enabledDomains.has(domain)) {
          const { handleActivateDomain } = await import('@server/MCPServer.search.handlers.domain');
          try {
            await handleActivateDomain(ctx, {
              domain,
              ttlMinutes: (await import('@src/constants')).ACTIVATION_TTL_MINUTES,
            });
          } catch {
            /* fall through to individual activation */
          }
        }
        if (!ctx.router.has(name)) {
          await activateToolNames(ctx, [name]);
        }
        callMetadata.wasAutoActivated = true;
        callMetadata.activatedTools = [name];
        autoActivated = true;
      }
    } catch {
      /* registry not initialised — fall through to error */
    }

    if (!autoActivated) {
      return asTextResponse(
        JSON.stringify({
          success: false,
          error: `Tool "${name}" is not currently active. Use activate_tools or activate_domain first, then call it directly.`,
          ...callMetadata,
        }),
      );
    }
  }

  // Dispatch to the actual tool handler via executeToolWithTracking
  try {
    const validatedArgs = validateToolArgsAgainstSchema(
      name,
      getToolInputSchema(name, ctx),
      toolArgs,
    );
    const response = await ctx.executeToolWithTracking(name, validatedArgs);

    // Record feedback for vector weight tuning (Phase 8).
    // call_tool has no search query in scope — the caller supplies only the
    // tool name and args. Query→tool association for this path is handled by
    // SearchQualityTracker.associateLastSearch from MCPServer.execution.
    try {
      const engine = await getSearchEngine(ctx);
      engine.recordToolCallFeedback(name, '');
    } catch {
      /* non-critical — ignore feedback errors */
    }

    return attachCallToolMetadata(response, callMetadata);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`call_tool: execution of "${name}" failed`, error);
    return asTextResponse(
      JSON.stringify({
        success: false,
        error: `Tool "${name}" failed: ${message}`,
        ...callMetadata,
      }),
    );
  }
}
