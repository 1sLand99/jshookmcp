/**
 * MCPServer.execution — Tool execution orchestration with tracking
 *
 * Extracted from MCPServer.ts to isolate the execution pipeline:
 * - Circuit breaker checks
 * - Browser session coordination
 * - Large data offloading
 * - Context enrichment
 * - Token budget tracking
 * - Domain TTL refresh
 * - Event bus notifications
 * - Execution metrics collection (E2E performance testing)
 */

import { logger } from '@utils/logger';
import { asErrorResponse } from '@server/domains/shared/response';
import { getToolDomain } from '@server/ToolCatalog';
import { refreshDomainTtlForTool } from '@server/MCPServer.activation.ttl';
import type { MCPServerContext } from '@server/MCPServer.context';
import type { ToolArgs } from '@server/types';
import type { BrowserSessionCoordinator } from '@server/runtime/BrowserSessionCoordinator';
import { parseBrowserSessionSnapshot } from '@server/runtime/BrowserSessionCoordinator';
import type { ServerRuntimeState } from '@server/runtime/ServerRuntimeState';
import {
  shouldCollectExecutionMetrics,
  captureExecutionMetricMemory,
  buildExecutionMetrics,
  appendExecutionMetrics,
} from '@server/MCPServer.metrics';

/**
 * Executes a tool with full tracking: circuit breaker, session coordination,
 * offloading, context enrichment, token budget, domain TTL, event emission.
 *
 * This is the main execution pipeline for all tool calls.
 */
export async function executeToolWithTracking(ctx: MCPServerContext, name: string, args: ToolArgs) {
  let timeoutTimer: NodeJS.Timeout | undefined;
  const timeoutMs = 30000;
  const collectExecutionMetrics = shouldCollectExecutionMetrics();
  const executionStartedAt = collectExecutionMetrics ? new Date().toISOString() : null;
  const executionStartTime = collectExecutionMetrics ? performance.now() : 0;
  const executionCpuStart = collectExecutionMetrics ? process.cpuUsage() : null;
  const executionMemoryBefore = collectExecutionMetrics ? captureExecutionMetricMemory() : null;
  try {
    ctx.setDomainInstance('activeToolArgs', args);
    timeoutTimer = setTimeout(() => {
      try {
        const safeArgs = JSON.stringify(args).slice(0, 500);
        logger.warn(
          `Telemetry Alert [ERR-03]: Tool execution hung (>30s) for '${name}'. Args preview: ${safeArgs}...`,
        );
      } catch {
        logger.warn(`Telemetry Alert [ERR-03]: Tool execution hung (>30s) for '${name}'.`);
      }
    }, timeoutMs);
    timeoutTimer.unref();

    if (ctx.circuitBreaker.shouldBlock(name)) {
      const state = ctx.circuitBreaker.getState(name);
      const retryAfter = state
        ? Math.ceil(
            (ctx.circuitBreaker.getRecoveryMs() - (Date.now() - state.lastFailureTime)) / 1000,
          )
        : 30;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              success: false,
              error: `Circuit breaker open for tool "${name}"`,
              reason: `Tool has failed consecutively ${state?.failureCount ?? 0} times`,
              retryAfterSeconds: retryAfter,
            }),
          },
        ],
        isError: true,
      };
    }

    let response;
    try {
      const browserCoordinator =
        getToolDomain(name) === 'browser'
          ? ctx.getDomainInstance<BrowserSessionCoordinator>('browserSessionCoordinator')
          : null;
      const sessionId = (args['_meta'] as { sessionId?: string } | undefined)?.sessionId ?? null;
      response = browserCoordinator
        ? await browserCoordinator.runExclusive(sessionId, async () => {
            await browserCoordinator.restoreSessionContext(sessionId);
            return await ctx.router.execute(name, args);
          })
        : await ctx.router.execute(name, args);
    } finally {
      if (timeoutTimer) clearTimeout(timeoutTimer);
    }

    // Offload large response data (>512KB) to disk / DetailedDataManager
    // to prevent context bloat while preserving data for later retrieval.
    ctx.largeDataOffloader.offload(name, response);

    if (getToolDomain(name) === 'browser') {
      const browserCoordinator = ctx.getDomainInstance<BrowserSessionCoordinator>(
        'browserSessionCoordinator',
      );
      const sessionId = (args['_meta'] as { sessionId?: string } | undefined)?.sessionId ?? null;
      browserCoordinator?.noteToolResult(sessionId, name, parseBrowserSessionSnapshot(response));
    }

    // Track consecutive tool calls for repeat loop detection
    ctx.contextGuard.recordCall(name);
    ctx.getDomainInstance<ServerRuntimeState>('serverRuntimeState')?.recordToolCall(name, args);
    // Enrich context-sensitive tool responses with current tab metadata
    let enriched = ctx.contextGuard.enrichResponse(name, response);
    if (
      collectExecutionMetrics &&
      executionStartedAt &&
      executionCpuStart &&
      executionMemoryBefore
    ) {
      enriched = appendExecutionMetrics(
        enriched,
        buildExecutionMetrics(
          executionStartedAt,
          executionStartTime,
          timeoutMs,
          executionCpuStart,
          executionMemoryBefore,
        ),
      );
    }
    try {
      ctx.tokenBudget.recordToolCall(name, args, enriched);
    } catch (trackingError) {
      logger.warn('Token tracking failed, continuing without tracking this call:', trackingError);
    }
    // Refresh domain TTL when an activated tool is used
    if (ctx.activatedToolNames.has(name)) {
      refreshDomainTtlForTool(ctx, name);
    }
    let toolResultSuccess = !enriched.isError;
    if (enriched?.structuredContent && typeof enriched.structuredContent === 'object') {
      const resultPayload = enriched.structuredContent as Record<string, unknown>;
      toolResultSuccess = resultPayload.success !== false;
    } else if (enriched?.content?.[0]?.type === 'text' && 'text' in enriched.content[0]) {
      try {
        const parsed = JSON.parse(enriched.content[0].text) as Record<string, unknown>;
        toolResultSuccess = parsed.success !== false;
      } catch {
        toolResultSuccess = !enriched.isError;
      }
    }
    // Circuit breaker: record success or failure
    if (toolResultSuccess) {
      ctx.circuitBreaker.recordSuccess(name);
    } else {
      ctx.circuitBreaker.recordFailure(name);
    }
    // Emit tool:called event for ActivationController
    void ctx.eventBus.emit('tool:called', {
      toolName: name,
      domain: getToolDomain(name) ?? null,
      timestamp: new Date().toISOString(),
      success: toolResultSuccess,
      args,
      result: {
        success: toolResultSuccess,
        isError: enriched.isError === true,
      },
    });
    const searchQualityTracker =
      ctx.getDomainInstance<import('@server/search/SearchQualityTracker').SearchQualityTracker>(
        'searchQualityTracker',
      );
    searchQualityTracker?.associateLastSearch(name);
    ctx.mcpLog.info('jshookmcp', {
      event: 'tool_called',
      toolName: name,
      domain: getToolDomain(name) ?? null,
      success: toolResultSuccess,
    });
    // Commit pending resource updates to prevent stream flooding
    ctx
      .getDomainInstance<import('@server/evidence/ReverseEvidenceGraph').ReverseEvidenceGraph>(
        'evidenceGraph',
      )
      ?.commit();
    return enriched;
  } catch (error) {
    ctx.circuitBreaker.recordFailure(name);
    const errorResponse = asErrorResponse(error);
    try {
      ctx.tokenBudget.recordToolCall(name, args, errorResponse);
    } catch (trackingError) {
      logger.warn('Token tracking failed on error path:', trackingError);
    }
    ctx
      .getDomainInstance<import('@server/evidence/ReverseEvidenceGraph').ReverseEvidenceGraph>(
        'evidenceGraph',
      )
      ?.commit();
    throw error;
  } finally {
    ctx.setDomainInstance('activeToolArgs', undefined);
  }
}
