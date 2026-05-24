import type { MemoryScanner } from '@native/MemoryScanner';
import type {
  ScanCompareMode,
  ScanOptions,
  ScanValueType,
} from '@native/NativeMemoryManager.types';
import type { EventBus, ServerEventMap } from '@server/EventBus';
import { MEMORY_SCAN_MAX_RESULTS } from '@src/constants';
import type { UnifiedProcessManager } from '@server/domains/shared/modules/native';
import type { MCPServerContext } from '@server/MCPServer.context';
import { resolveMemoryDomainPid } from '@server/domains/memory/pid-resolver';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';

function capMaxResults(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value) || value <= 0) return MEMORY_SCAN_MAX_RESULTS;
  return Math.min(value, MEMORY_SCAN_MAX_RESULTS);
}

export class ScanHandlers {
  constructor(
    private readonly scanner: MemoryScanner,
    private readonly eventBus?: EventBus<ServerEventMap>,
    private readonly processManager?: UnifiedProcessManager,
    private readonly ctx?: MCPServerContext,
  ) {}

  private async resolvePid(value: unknown): Promise<number> {
    if (!this.processManager) {
      return value as number;
    }
    return await resolveMemoryDomainPid(value, this.processManager, this.ctx);
  }

  async handleFirstScan(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const options: ScanOptions = {
        valueType: args.valueType as ScanValueType,
        alignment: args.alignment as number | undefined,
        maxResults: capMaxResults(args.maxResults as number | undefined),
        regionFilter: args.regionFilter as ScanOptions['regionFilter'],
        onProgress: args.onProgress as ((p: number, t?: number) => void) | undefined,
      };
      const result = await this.scanner.firstScan(pid, args.value as string, options);
      void this.eventBus?.emit('memory:scan_completed', {
        scanType: 'first',
        resultCount: result.totalMatches ?? 0,
        timestamp: new Date().toISOString(),
      });
      return {
        ...result,
        hint:
          result.totalMatches > 0
            ? `Found ${result.totalMatches} matches. Use memory_next_scan with sessionId "${result.sessionId}" to narrow down.`
            : 'No matches found. Try a different value or type.',
      };
    });
  }

  async handleNextScan(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const result = await this.scanner.nextScan(
        args.sessionId as string,
        args.mode as ScanCompareMode,
        args.value as string | undefined,
        args.value2 as string | undefined,
      );
      return {
        ...result,
        hint:
          result.totalMatches <= 10
            ? 'Few matches remaining — inspect these addresses.'
            : `${result.totalMatches} matches remain. Continue narrowing with memory_next_scan.`,
      };
    });
  }

  async handleUnknownScan(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const options: ScanOptions = {
        valueType: args.valueType as ScanValueType,
        alignment: args.alignment as number | undefined,
        maxResults: capMaxResults(args.maxResults as number | undefined),
        regionFilter: args.regionFilter as ScanOptions['regionFilter'],
        onProgress: args.onProgress as ((p: number, t?: number) => void) | undefined,
      };
      const result = await this.scanner.unknownInitialScan(pid, options);
      return {
        ...result,
        hint: `Captured ${result.totalMatches} addresses. Use memory_next_scan with changed/unchanged/increased/decreased to narrow.`,
      };
    });
  }

  async handlePointerScan(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const result = await this.scanner.pointerScan(pid, args.targetAddress as string, {
        maxResults: capMaxResults(args.maxResults as number | undefined),
        moduleOnly: args.moduleOnly as boolean | undefined,
      });
      return { ...result };
    });
  }

  async handleGroupScan(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const result = await this.scanner.groupScan(
        pid,
        args.pattern as Array<{ offset: number; value: string; type: ScanValueType }>,
        {
          alignment: args.alignment as number | undefined,
          maxResults: capMaxResults(args.maxResults as number | undefined),
        },
      );
      return { ...result };
    });
  }
}
