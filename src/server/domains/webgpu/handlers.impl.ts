import type { MCPServerContext } from '@server/domains/shared/registry';
import { handleSafe, type ToolResponse } from '@server/domains/shared/ResponseBuilder';
import { argString, argNumber, argBool } from '@server/domains/shared/parse-args';
import { DetailedDataManager } from '@utils/DetailedDataManager';
import { getPageLockManager } from '@modules/webgpu/PageLockManager';
import {
  getShaderCompileCache,
  getShaderDisassemblyCache,
} from '@modules/webgpu/ShaderCache';
import {
  getGPUMemoryStats,
  injectGPUCommandHook,
  getGPUCommandTrace,
  analyzeCommandTrace,
} from '@modules/webgpu/CDPIntegration';
import type {
  GPUAdapterInfo,
  ShaderMetadata,
  GPUCommand,
  GPUMemoryAllocation,
  TimingStats,
  WebGPUDomainDependencies,
} from './types';

export class WebGPUHandlers {
  private deps: WebGPUDomainDependencies;
  private ddm: DetailedDataManager;
  private pageLockManager = getPageLockManager();
  private compileCache = getShaderCompileCache();
  private disassemblyCache = getShaderDisassemblyCache();

  constructor(
    private ctx: MCPServerContext,
    deps?: WebGPUDomainDependencies
  ) {
    this.deps = deps ?? {
      pageController: ctx.pageController,
    };
    this.ddm = DetailedDataManager.getInstance();
  }

  async webgpu_adapter_info(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => {
      const page = await this.getActivePage();
      if (!page) {
        throw new Error('No active page. Call browser_launch or browser_attach first.');
      }

      const pageId = page.url();

      // Acquire page lock to prevent concurrent GPU context access
      return await this.pageLockManager.withLock(pageId, async () => {
        const adapterInfo = await page.evaluate(async () => {
          if (!navigator.gpu) {
            throw new Error('WebGPU not available in this browser');
          }

          const adapter = await navigator.gpu.requestAdapter();
          if (!adapter) {
            throw new Error('Failed to request GPU adapter');
          }

          const info = adapter.info ?? (adapter as any).requestAdapterInfo?.();

          return {
            vendor: info?.vendor ?? 'unknown',
            architecture: info?.architecture ?? 'unknown',
            device: info?.device ?? 'unknown',
            description: info?.description ?? 'unknown',
          };
        });

        return {
          adapter: adapterInfo,
        };
      });
    });
  }

  async webgpu_shader_compile(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => {
      const shaderCode = argString(args, 'shaderCode');
      if (!shaderCode) {
        throw new Error('Missing required argument: shaderCode');
      }

      const format = argString(args, 'format', 'wgsl');
      if (format !== 'wgsl') {
        throw new Error('Only WGSL format is currently supported');
      }

      // Check cache first
      const cached = this.compileCache.get(shaderCode);
      if (cached) {
        return {
          ...cached,
          _cached: true,
        };
      }

      const page = await this.getActivePage();
      if (!page) {
        throw new Error('No active page. Call browser_launch or browser_attach first.');
      }

      const pageId = page.url();

      // Acquire page lock to prevent concurrent GPU context access
      const result = await this.pageLockManager.withLock(pageId, async () => {
        return await page.evaluate(
          async (code: string) => {
            if (!navigator.gpu) {
              throw new Error('WebGPU not available');
            }

            const adapter = await navigator.gpu.requestAdapter();
            if (!adapter) {
              throw new Error('Failed to request GPU adapter');
            }

            const device = await adapter.requestDevice();

            try {
              const shaderModule = device.createShaderModule({
                code,
              });

              // Extract metadata from shader code
              const entryPoints: Array<{ name: string; stage: string }> = [];

              // Simple regex-based parsing (real implementation would use proper WGSL parser)
              const vertexMatch = code.match(/@vertex\s+fn\s+(\w+)/);
              const fragmentMatch = code.match(/@fragment\s+fn\s+(\w+)/);
              const computeMatch = code.match(/@compute\s+fn\s+(\w+)/);

              if (vertexMatch) {
                entryPoints.push({ name: vertexMatch[1], stage: 'vertex' });
              }
              if (fragmentMatch) {
                entryPoints.push({ name: fragmentMatch[1], stage: 'fragment' });
              }
              if (computeMatch) {
                entryPoints.push({ name: computeMatch[1], stage: 'compute' });
              }

              return {
                compiled: true,
                metadata: {
                  entryPoints,
                },
              };
            } catch (err: any) {
              throw new Error(`Shader compilation failed: ${err.message}`);
            }
          },
          shaderCode
        );
      });

      // Cache the result
      this.compileCache.set(shaderCode, result);

      return result;
    });
  }

  async webgpu_shader_disassemble(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => {
      const shaderCode = argString(args, 'shaderCode');
      if (!shaderCode) {
        throw new Error('Missing required argument: shaderCode');
      }

      const format = argString(args, 'format', 'wgsl');
      if (format !== 'wgsl') {
        throw new Error('Only WGSL format is currently supported');
      }

      // Check cache first
      const cached = this.disassemblyCache.get(shaderCode);
      if (cached) {
        return {
          ...cached,
          _cached: true,
        };
      }

      // Report progress for large shaders
      const meta = args['_meta'] as Record<string, unknown> | undefined;
      const progressToken = meta ? argString(meta, 'progressToken') : undefined;

      if (progressToken && shaderCode.length > 10000) {
        this.reportProgress(progressToken, 0.1, 'Parsing shader AST...');
      }

      // Simple AST extraction (real implementation would use @webgpu/wgsl-parser)
      const functions: string[] = [];
      const functionMatches = shaderCode.matchAll(/fn\s+(\w+)/g);
      for (const match of functionMatches) {
        functions.push(match[1]);
      }

      const ast = {
        type: 'Module',
        functions,
      };

      if (progressToken && shaderCode.length > 10000) {
        this.reportProgress(progressToken, 0.5, 'Generating disassembly...');
      }

      const disassembly = this.generateDisassembly(shaderCode);

      if (progressToken && shaderCode.length > 10000) {
        this.reportProgress(progressToken, 1.0, 'Disassembly complete');
      }

      // Check if disassembly is large and should be offloaded
      const result = {
        ast,
        disassembly,
      };

      // Cache the result before offloading
      this.disassemblyCache.set(shaderCode, result);

      return this.ddm.smartHandle(result, 25000);
    });
  }

  async webgpu_timing_analysis(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => {
      const iterations = argNumber(args, 'iterations');
      if (!iterations || iterations <= 0) {
        throw new Error('Missing or invalid required argument: iterations (must be > 0)');
      }

      const detectAnomalies = argBool(args, 'detectAnomalies', false);
      const meta = args['_meta'] as Record<string, unknown> | undefined;
      const progressToken = meta ? argString(meta, 'progressToken') : undefined;

      const page = await this.getActivePage();
      if (!page) {
        throw new Error('No active page. Call browser_launch or browser_attach first.');
      }

      const pageId = page.url();

      // Acquire page lock to prevent concurrent GPU context access
      return await this.pageLockManager.withLock(pageId, async () => {
        const stats = await page.evaluate(
          async ({ iterations, detectAnomalies }: { iterations: number; detectAnomalies: boolean }) => {
            if (!navigator.gpu) {
              throw new Error('WebGPU not available');
            }

            const adapter = await navigator.gpu.requestAdapter();
            if (!adapter) {
              throw new Error('Failed to request GPU adapter');
            }

            const device = await adapter.requestDevice();
            const timings: number[] = [];

            for (let i = 0; i < iterations; i++) {
              const start = performance.now();

              // Simple GPU timing test: create buffer and wait for completion
              const buffer = device.createBuffer({
                size: 1024,
                usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ,
              });

              await device.queue.onSubmittedWorkDone();

              const end = performance.now();
              timings.push(end - start);

              buffer.destroy();

              // Report progress every 20%
              if ((window as any).__webgpuProgressCallback && i % Math.ceil(iterations / 5) === 0) {
                (window as any).__webgpuProgressCallback(i / iterations);
              }
            }

            const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
            const variance =
              timings.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / timings.length;
            const stddev = Math.sqrt(variance);
            const min = Math.min(...timings);
            const max = Math.max(...timings);

            const result: any = {
              timings,
              mean,
              stddev,
              min,
              max,
            };

            if (detectAnomalies) {
              const threshold = 2.0; // 2 standard deviations
              result.anomalies = timings
                .map((val, idx) => ({
                  index: idx,
                  value: val,
                  deviation: Math.abs(val - mean) / stddev,
                }))
                .filter((a) => a.deviation > threshold);
            }

            return result;
          },
          { iterations, detectAnomalies }
        );

        return stats;
      });
    });
  }

  async webgpu_memory_layout(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => {
      const page = await this.getActivePage();
      if (!page) {
        throw new Error('No active page. Call browser_launch or browser_attach first.');
      }

      const pageId = page.url();

      // Acquire page lock to prevent concurrent GPU context access
      return await this.pageLockManager.withLock(pageId, async () => {
        // Use real CDP integration to get GPU memory stats
        const memoryStats = await getGPUMemoryStats(page);

        return {
          heapSize: memoryStats.heapSize,
          usedHeapSize: memoryStats.usedHeapSize,
          allocations: memoryStats.allocations,
        };
      });
    });
  }

  async webgpu_capture_commands(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => {
      const captureCount = argNumber(args, 'captureCount');
      if (!captureCount || captureCount <= 0) {
        throw new Error('Missing or invalid required argument: captureCount (must be > 0)');
      }

      const page = await this.getActivePage();
      if (!page) {
        throw new Error('No active page. Call browser_launch or browser_attach first.');
      }

      const pageId = page.url();

      // Acquire page lock to prevent concurrent GPU context access
      return await this.pageLockManager.withLock(pageId, async () => {
        // Inject GPUQueue.submit hook
        await injectGPUCommandHook(page, captureCount);

        // Wait for commands to be captured (or timeout after 5 seconds)
        await new Promise((resolve) => setTimeout(resolve, 5000));

        // Retrieve captured commands
        const trace = await getGPUCommandTrace(page);

        // Analyze command patterns
        const analyzed = analyzeCommandTrace(trace);

        const result = {
          commands: analyzed.commands,
          totalSubmissions: analyzed.totalSubmissions,
          captureWindow: {
            start: analyzed.captureStartTime,
            end: analyzed.captureEndTime,
            duration: analyzed.captureEndTime - analyzed.captureStartTime,
          },
          inferredTypes: analyzed.inferredTypes,
        };

        // Handle large command arrays
        return this.ddm.smartHandle(result, 25000);
      });
    });
  }

  // ── Helper methods ──

  private async getActivePage(): Promise<any> {
    if (!this.deps.pageController) {
      return null;
    }

    try {
      return await this.deps.pageController.getActivePage();
    } catch {
      return null;
    }
  }

  private generateDisassembly(shaderCode: string): string {
    // Simple disassembly - real implementation would use proper WGSL parser
    const lines = shaderCode.split('\n');
    return lines
      .map((line, idx) => `${String(idx + 1).padStart(4, ' ')} | ${line}`)
      .join('\n');
  }

  private reportProgress(token: string | undefined, progress: number, message: string): void {
    if (!token || !this.ctx.eventBus) {
      return;
    }

    this.ctx.eventBus.emit('tool:progress', {
      token,
      progress,
      message,
    });
  }
}

export default WebGPUHandlers;
