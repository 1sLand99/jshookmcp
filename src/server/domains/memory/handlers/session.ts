import type { MemoryScanSessionManager } from '@native/MemoryScanSession';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';

export class SessionHandlers {
  constructor(private readonly sessionManager: MemoryScanSessionManager) {}

  async handleScanList(_args: Record<string, unknown>) {
    return handleSafe(async () => {
      const sessions = this.sessionManager.listSessions();
      return { sessions, count: sessions.length };
    });
  }

  async handleScanDelete(args: Record<string, unknown>) {
    return handleSafe(async () => ({
      deleted: this.sessionManager.deleteSession(args.sessionId as string),
    }));
  }

  async handleScanExport(args: Record<string, unknown>) {
    return handleSafe(async () => ({
      exportedData: this.sessionManager.exportSession(args.sessionId as string),
    }));
  }
}
