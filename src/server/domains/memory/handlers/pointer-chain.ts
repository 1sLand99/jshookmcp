import type { PointerChainEngine } from '@native/PointerChainEngine';
import type { PointerChain } from '@native/PointerChainEngine.types';
import type { UnifiedProcessManager } from '@server/domains/shared/modules/native';
import type { MCPServerContext } from '@server/MCPServer.context';
import { resolveMemoryDomainPid } from '@server/domains/memory/pid-resolver';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';

export class PointerChainHandlers {
  constructor(
    private readonly ptrEngine: PointerChainEngine,
    private readonly processManager?: UnifiedProcessManager,
    private readonly ctx?: MCPServerContext,
  ) {}

  private async resolvePid(value: unknown): Promise<number> {
    if (!this.processManager) {
      return value as number;
    }
    return await resolveMemoryDomainPid(value, this.processManager, this.ctx);
  }

  async handlePointerChainScan(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const result = await this.ptrEngine.scan(pid, args.targetAddress as string, {
        maxDepth: args.maxDepth as number | undefined,
        maxOffset: args.maxOffset as number | undefined,
        staticOnly: args.staticOnly as boolean | undefined,
        modules: args.modules as string[] | undefined,
        maxResults: args.maxResults as number | undefined,
      });
      return {
        ...result,
        hint:
          result.totalFound > 0
            ? `Found ${result.totalFound} pointer chains. Static chains survive process restarts.`
            : 'No pointer chains found. Try increasing maxDepth or maxOffset.',
      };
    });
  }

  async handlePointerChainValidate(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const chains = JSON.parse(args.chains as string) as PointerChain[];
      const results = await this.ptrEngine.validateChains(pid, chains);
      return {
        results,
        validCount: results.filter((r) => r.isValid).length,
        totalChecked: chains.length,
      };
    });
  }

  async handlePointerChainResolve(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const chain = JSON.parse(args.chain as string) as PointerChain;
      const resolved = await this.ptrEngine.resolveChain(pid, chain);
      return {
        chainId: chain.id,
        resolvedAddress: resolved,
        isResolvable: resolved !== null,
      };
    });
  }

  async handlePointerChainExport(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const chains = JSON.parse(args.chains as string) as PointerChain[];
      return {
        exportedData: this.ptrEngine.exportChains(chains),
        chainCount: chains.length,
      };
    });
  }
}
