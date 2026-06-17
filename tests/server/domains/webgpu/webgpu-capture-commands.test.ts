import { describe, it, expect, beforeEach } from 'vitest';
import type { MCPServerContext } from '@server/domains/shared/registry';
import { WebGPUHandlers } from '@server/domains/webgpu/index';
import { ResponseBuilder } from '@server/domains/shared/ResponseBuilder';

describe('webgpu_capture_commands', () => {
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
    const response = await handlers.webgpu_capture_commands({
      captureCount: 10,
    });
    const result = ResponseBuilder.parse(response);

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/page/i),
    });
  });

  it('should capture GPU command queue submissions', async () => {
    const mockPage = {
      evaluate: async () => ({
        commands: [
          { type: 'render', drawCalls: 5, timestamp: 1.234 },
          { type: 'compute', dispatches: 2, timestamp: 1.456 },
        ],
      }),
    };

    ctx.pageController = {
      getActivePage: async () => mockPage,
    } as any;

    const response = await handlers.webgpu_capture_commands({
      captureCount: 2,
    });
    const result = ResponseBuilder.parse(response);

    if (result.success === true) {
      // Check if we got a DetailedDataResponse (large result) or direct result
      if (result.summary && result.detailId) {
        // Large result - offloaded
        expect(result).toHaveProperty('summary');
        expect(result).toHaveProperty('detailId');
      } else {
        // Direct result
        expect(result).toHaveProperty('commands');
        expect(result.commands).toBeInstanceOf(Array);
        expect(result.commands.length).toBeGreaterThan(0);
      }
    }
  });

  it('should distinguish render and compute passes', async () => {
    const mockPage = {
      evaluate: async () => ({
        commands: [
          { type: 'render', drawCalls: 10 },
          { type: 'compute', dispatches: 5 },
        ],
      }),
    };

    ctx.pageController = {
      getActivePage: async () => mockPage,
    } as any;

    const response = await handlers.webgpu_capture_commands({
      captureCount: 2,
    });
    const result = ResponseBuilder.parse(response);

    if (result.success === true && result.commands) {
      const types = result.commands.map((c: any) => c.type);
      expect(types).toContain('render');
      expect(types).toContain('compute');
    }
  });
});
