import { type TokenBudgetManager } from '@utils/TokenBudgetManager';
import { type UnifiedCacheManager } from '@utils/UnifiedCacheManager';
import type { ToolResponse } from '@server/types';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';
import { cleanupArtifacts } from '@utils/artifactRetention';
import { runEnvironmentDoctor } from '@utils/environmentDoctor';

interface CoreMaintenanceHandlerDeps {
  tokenBudget: TokenBudgetManager;
  unifiedCache: UnifiedCacheManager;
  artifactCleanup?: typeof cleanupArtifacts;
  environmentDoctor?: typeof runEnvironmentDoctor;
}

export class CoreMaintenanceHandlers {
  private readonly tokenBudget: TokenBudgetManager;
  private readonly unifiedCache: UnifiedCacheManager;
  private readonly artifactCleanup: typeof cleanupArtifacts;
  private readonly environmentDoctor: typeof runEnvironmentDoctor;

  constructor(deps: CoreMaintenanceHandlerDeps) {
    this.tokenBudget = deps.tokenBudget;
    this.unifiedCache = deps.unifiedCache;
    this.artifactCleanup = deps.artifactCleanup ?? cleanupArtifacts;
    this.environmentDoctor = deps.environmentDoctor ?? runEnvironmentDoctor;
  }

  async handleGetTokenBudgetStats(): Promise<ToolResponse> {
    return handleSafe(async () => {
      const stats = this.tokenBudget.getStats();
      return {
        ...stats,
        sessionDuration: `${Math.round((Date.now() - stats.sessionStartTime) / 1000)}s`,
      };
    });
  }

  async handleManualTokenCleanup(): Promise<ToolResponse> {
    return handleSafe(async () => {
      const beforeStats = this.tokenBudget.getStats();
      this.tokenBudget.manualCleanup();
      const afterStats = this.tokenBudget.getStats();
      const freed = beforeStats.currentUsage - afterStats.currentUsage;
      return {
        message: 'Manual cleanup completed',
        before: { usage: beforeStats.currentUsage, percentage: beforeStats.usagePercentage },
        after: { usage: afterStats.currentUsage, percentage: afterStats.usagePercentage },
        freed: { tokens: freed, percentage: Math.round((freed / beforeStats.maxTokens) * 100) },
      };
    });
  }

  async handleResetTokenBudget(): Promise<ToolResponse> {
    return handleSafe(async () => {
      this.tokenBudget.reset();
      return {
        message: 'Token budget reset successfully',
        currentUsage: 0,
        maxTokens: 200000,
        usagePercentage: 0,
      };
    });
  }

  async handleGetCacheStats(): Promise<ToolResponse> {
    return handleSafe(async () => this.unifiedCache.getGlobalStats());
  }

  async handleSmartCacheCleanup(targetSize?: number): Promise<ToolResponse> {
    return handleSafe(async () => this.unifiedCache.smartCleanup(targetSize));
  }

  async handleClearAllCaches(): Promise<ToolResponse> {
    return handleSafe(async () => {
      await this.unifiedCache.clearAll();
      return { message: 'All caches cleared' };
    });
  }

  async handleCleanupArtifacts(args: {
    retentionDays?: number;
    maxTotalBytes?: number;
    dryRun?: boolean;
  }): Promise<ToolResponse> {
    return handleSafe(async () =>
      this.artifactCleanup({
        retentionDays: args.retentionDays,
        maxTotalBytes: args.maxTotalBytes,
        dryRun: args.dryRun,
      }),
    );
  }

  async handleEnvironmentDoctor(args: { includeBridgeHealth?: boolean }): Promise<ToolResponse> {
    return handleSafe(async () =>
      this.environmentDoctor({ includeBridgeHealth: args.includeBridgeHealth }),
    );
  }
}
