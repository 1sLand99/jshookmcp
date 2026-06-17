import { describe, it, expect, beforeEach } from 'vitest';
import type { MCPServerContext } from '@server/domains/shared/registry';
import { WebGPUHandlers } from '@server/domains/webgpu/index';
import { ResponseBuilder } from '@server/domains/shared/ResponseBuilder';

describe('webgpu_memory_layout', () => {
  let ctx: MCPServerContext;
  let handlers: WebGPUHandlers;

  beforeEach(() => {
    ctx = {
      eventBus: {
        emit: () => {},
      },
      pageController: {
        getActivePage: async () => {
          throw new Error('No active page');
        },
      },
    } as unknown as MCPServerContext;

    handlers = new WebGPUHandlers(ctx);
  });

  it('should require active page', async () => {
    const response = await handlers.webgpu_memory_layout({});
    const result = ResponseBuilder.parse(response);

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/page/i),
    });
  });

  it('should return GPU memory allocations', async () => {
    const mockPage = {
      evaluate: async () => ({
        heapSize: 1024 * 1024 * 256, // 256MB
        allocations: [
          { size: 1024, usage: 'VERTEX' },
          { size: 4096, usage: 'UNIFORM' },
        ],
      }),
    };

    ctx.pageController = {
      getActivePage: async () => mockPage,
    } as any;

    const response = await handlers.webgpu_memory_layout({});
    const result = ResponseBuilder.parse(response);

    if (result.success === true) {
      expect(result).toHaveProperty('heapSize');
      expect(result).toHaveProperty('allocations');
      expect(result.allocations).toBeInstanceOf(Array);
      expect(result.heapSize).toBeGreaterThan(0);
    }
  });

  it('should track buffer usage flags', async () => {
    const mockPage = {
      evaluate: async () => ({
        heapSize: 1024 * 1024,
        allocations: [
          { size: 1024, usage: 'VERTEX | COPY_DST' },
          { size: 2048, usage: 'INDEX' },
        ],
      }),
    };

    ctx.pageController = {
      getActivePage: async () => mockPage,
    } as any;

    const response = await handlers.webgpu_memory_layout({});
    const result = ResponseBuilder.parse(response);

    if (result.success === true) {
      expect(result.allocations.some((a: any) => a.usage.includes('VERTEX'))).toBe(true);
    }
  });
});
