import type { MemoryController } from '@native/MemoryController';
import type { UnifiedProcessManager } from '@server/domains/shared/modules/native';
import type { MCPServerContext } from '@server/MCPServer.context';
import { resolveMemoryDomainPid } from '@server/domains/memory/pid-resolver';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';

export class ReadWriteHandlers {
  constructor(
    private readonly memCtrl: MemoryController,
    private readonly processManager?: UnifiedProcessManager,
    private readonly ctx?: MCPServerContext,
  ) {}

  private async resolvePid(value: unknown): Promise<number> {
    if (!this.processManager) {
      return value as number;
    }
    return await resolveMemoryDomainPid(value, this.processManager, this.ctx);
  }

  async handleWriteValue(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const entry = await this.memCtrl.writeValue(
        pid,
        args.address as string,
        args.value as string,
        args.valueType as string,
      );
      return {
        ...entry,
        hint: "Use memory_write_history with action='undo' to revert.",
      };
    });
  }

  async handleFreeze(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const entry = await this.memCtrl.freeze(
        pid,
        args.address as string,
        args.value as string,
        args.valueType as string,
        args.intervalMs as number | undefined,
      );
      return {
        ...entry,
        hint: `Frozen. Use memory_freeze with action="unfreeze" and freezeId "${entry.id}" to stop.`,
      };
    });
  }

  async handleUnfreeze(args: Record<string, unknown>) {
    return handleSafe(async () => ({
      unfrozen: await this.memCtrl.unfreeze(args.freezeId as string),
    }));
  }

  async handleDump(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const hexDump = await this.memCtrl.dumpMemoryHex(
        pid,
        args.address as string,
        (args.size as number) ?? 256,
      );
      return { dump: hexDump };
    });
  }

  async handleWriteUndo(_args: Record<string, unknown>) {
    return handleSafe(async () => {
      const entry = await this.memCtrl.undo();
      return { undone: entry !== null, entry };
    });
  }

  async handleWriteRedo(_args: Record<string, unknown>) {
    return handleSafe(async () => {
      const entry = await this.memCtrl.redo();
      return { redone: entry !== null, entry };
    });
  }
}
