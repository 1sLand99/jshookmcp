import { describe, expect, it, vi } from 'vitest';
import type { CodeCollector } from '@server/domains/shared/modules/collector';
import type { AntiDebugToolHandlers } from '@server/domains/antidebug/handlers';
import type { MCPServerContext } from '@server/domains/shared/registry';

// Import after mocks
import manifest from '@server/domains/antidebug/manifest';

describe('Antidebug Manifest', () => {
  describe('ensure', () => {
    it('initializes context components if missing', async () => {
      const registerCachesMock = vi.fn();
      const mockCtx: any = {
        config: { puppeteer: {} },
        registerCaches: registerCachesMock,
      };

      const handler = await manifest.ensure(mockCtx as MCPServerContext);

      expect(mockCtx.collector).toBeDefined();
      expect(registerCachesMock).toHaveBeenCalled();
      expect(mockCtx.antidebugHandlers).toBeDefined();
      expect(handler).toBe(mockCtx.antidebugHandlers);
    });

    it('returns existing handlers if already initialized', async () => {
      const existingHandler = {} as AntiDebugToolHandlers;
      const existingCollector = {} as CodeCollector;
      const mockCtx: any = {
        collector: existingCollector,
        antidebugHandlers: existingHandler,
      };

      const handler = await manifest.ensure(mockCtx as MCPServerContext);

      expect(handler).toBe(existingHandler);
    });
  });

  describe('registrations', () => {
    it('binds correctly to handler methods', async () => {
      const mockHandler = {
        handleAntidebugBypass: vi.fn(),
        handleAntiDebugDetectProtections: vi.fn(),
      } as unknown as AntiDebugToolHandlers;

      const args = { foo: 'bar' };

      for (const reg of manifest.registrations) {
        await reg.bind({ antidebugHandlers: mockHandler as any })(args as any);
      }

      expect(mockHandler.handleAntidebugBypass).toHaveBeenCalledWith(args);
      expect(mockHandler.handleAntiDebugDetectProtections).toHaveBeenCalledWith(args);
    });
  });
});
