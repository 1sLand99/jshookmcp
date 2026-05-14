import { describe, expect, it, vi } from 'vitest';
import type { PageController } from '@server/domains/shared/modules/collector';
import type { HookPresetToolHandlers } from '@server/domains/hooks/preset-handlers';
import type { AIHookToolHandlers } from '@server/domains/hooks/ai-handlers';
import type { MCPServerContext } from '@server/domains/shared/registry';

vi.mock('@server/domains/shared/registry', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    bindByDepKey: (_key: string, fn: any) => fn,
    getDep: (deps: any, key: string) => deps[key],
    ensureBrowserCore: vi.fn(),
  };
});

import manifest from '@server/domains/hooks/manifest';
import { ensureBrowserCore } from '@server/domains/shared/registry';

describe('Hooks Manifest', () => {
  describe('ensure', () => {
    it('initializes context components if missing', async () => {
      const mockCtx: any = {
        config: { puppeteer: {} },
        pageController: {} as PageController,
      };

      const ai = await manifest.ensure(mockCtx as MCPServerContext);

      expect(ensureBrowserCore).toHaveBeenCalledWith(mockCtx);
      expect(mockCtx.hookPresetHandlers).toBeDefined();
      expect(mockCtx.aiHookHandlers).toBeDefined();
      expect(ai).toBe(mockCtx.aiHookHandlers);
    });

    it('returns existing handlers if already initialized', async () => {
      const existingPreset = {} as HookPresetToolHandlers;
      const existingAI = {} as AIHookToolHandlers;
      const mockCtx: any = {
        hookPresetHandlers: existingPreset,
        aiHookHandlers: existingAI,
        pageController: {} as PageController,
      };

      const ai = await manifest.ensure(mockCtx as MCPServerContext);

      expect(ai).toBe(existingAI);
    });
  });

  describe('registrations', () => {
    it('binds correctly to handler methods', async () => {
      const mockPresetHandler = {
        handleHookPreset: vi.fn(),
      } as unknown as HookPresetToolHandlers;

      const mockAIHandler = {
        handleAIHook: vi.fn(),
      } as unknown as AIHookToolHandlers;

      const args = { foo: 'bar' };

      for (const reg of manifest.registrations) {
        const fn = reg.bind as any;
        const bound =
          reg.tool.name === 'hook_preset'
            ? fn({ hookPresetHandlers: mockPresetHandler })
            : fn({ aiHookHandlers: mockAIHandler });
        await bound(args);
      }

      expect(mockPresetHandler.handleHookPreset).toHaveBeenCalledWith(args);
      expect(mockAIHandler.handleAIHook).toHaveBeenCalledWith(args);
    });
  });
});
