import { logger } from '@utils/logger';
import {
  argBool,
  argEnum,
  argNumber,
  argObject,
  argString,
  argStringRequired,
} from '@server/domains/shared/parse-args';
import { asJsonResponse, asTextResponse, serializeError } from '@server/domains/shared/response';
import type {
  AdvancedDeobfuscator,
  CodeAnalyzer,
  CryptoDetector,
  Deobfuscator,
  HookManager,
  ObfuscationDetector,
  ScriptManager,
} from '@server/domains/shared/modules';
import type { CodeCollector } from '@server/domains/shared/modules/collector';
import type { ToolArgs, ToolResponse } from '@server/types';
import {
  ANALYSIS_MAX_SUMMARY_FILES,
  ANALYSIS_MAX_SAFE_COLLECTED_BYTES,
  ANALYSIS_MAX_SAFE_RESPONSE_BYTES,
} from '@src/constants';
import {
  applyConstantFold,
  applyControlFlowFlatten,
  applyDeadCodeRemove,
  applyRenameVars,
} from '@server/domains/analysis/handlers/inline-deobfuscation';
import { solveConstraints } from '@server/domains/analysis/handlers/solve-constraints';
import { buildVmAnalysisResponse } from '@server/domains/analysis/handlers/vm-analysis';
import { runWebpackEnumerate } from '@server/domains/analysis/handlers.web-tools';
import type { DeobfuscateMappingRule } from '@internal-types/deobfuscator';
import { JSVMPDeobfuscator } from '@modules/deobfuscator/JSVMPDeobfuscator';
import { runWebcrack } from '@modules/deobfuscator/webcrack';

const SMART_MODES = new Set(['summary', 'priority', 'incremental', 'full'] as const);
const FOCUS_MODES = new Set(['structure', 'business', 'security', 'all'] as const);
const HOOK_TYPES = new Set([
  'function',
  'xhr',
  'fetch',
  'websocket',
  'localstorage',
  'cookie',
] as const);
const HOOK_ACTIONS = new Set(['log', 'block', 'modify'] as const);

interface CoreAnalysisHandlerDeps {
  collector: CodeCollector;
  scriptManager: ScriptManager;
  deobfuscator: Deobfuscator;
  advancedDeobfuscator: AdvancedDeobfuscator;
  obfuscationDetector: ObfuscationDetector;
  analyzer: CodeAnalyzer;
  cryptoDetector: CryptoDetector;
  hookManager: HookManager;
}

export class CoreAnalysisHandlers {
  private readonly collector: CodeCollector;
  private readonly scriptManager: ScriptManager;
  private readonly deobfuscator: Deobfuscator;
  private readonly advancedDeobfuscator: AdvancedDeobfuscator;
  private readonly obfuscationDetector: ObfuscationDetector;
  private readonly analyzer: CodeAnalyzer;
  private readonly cryptoDetector: CryptoDetector;
  private readonly hookManager: HookManager;
  private readonly jsvmpDeobfuscator: JSVMPDeobfuscator;

  constructor(deps: CoreAnalysisHandlerDeps) {
    this.collector = deps.collector;
    this.scriptManager = deps.scriptManager;
    this.deobfuscator = deps.deobfuscator;
    this.advancedDeobfuscator = deps.advancedDeobfuscator;
    this.obfuscationDetector = deps.obfuscationDetector;
    this.analyzer = deps.analyzer;
    this.cryptoDetector = deps.cryptoDetector;
    this.hookManager = deps.hookManager;
    this.jsvmpDeobfuscator = new JSVMPDeobfuscator();
  }

  private requireCodeArg(args: ToolArgs, toolName: string): string | null {
    const code = args.code;
    if (typeof code !== 'string' || code.trim().length === 0) {
      logger.warn(`${toolName} called without valid code argument`);
      return null;
    }
    return code;
  }

  private extractWebcrackArgs(args: ToolArgs) {
    const extracted: Record<string, unknown> = {};

    const unpack = argBool(args, 'unpack');
    const unminify = argBool(args, 'unminify');
    const jsx = argBool(args, 'jsx');
    const mangle = argBool(args, 'mangle');
    const forceOutput = argBool(args, 'forceOutput');
    const includeModuleCode = argBool(args, 'includeModuleCode');
    const outputDir = argString(args, 'outputDir');
    const maxBundleModules = argNumber(args, 'maxBundleModules');

    if (unpack !== undefined) extracted.unpack = unpack;
    if (unminify !== undefined) extracted.unminify = unminify;
    if (jsx !== undefined) extracted.jsx = jsx;
    if (mangle !== undefined) extracted.mangle = mangle;
    if (forceOutput !== undefined) extracted.forceOutput = forceOutput;
    if (includeModuleCode !== undefined) extracted.includeModuleCode = includeModuleCode;
    if (outputDir?.trim()) extracted.outputDir = outputDir;
    if (maxBundleModules !== undefined) extracted.maxBundleModules = maxBundleModules;

    if (Array.isArray(args.mappings)) {
      extracted.mappings = (args.mappings as unknown[]).filter(
        (item): item is DeobfuscateMappingRule =>
          typeof item === 'object' &&
          item !== null &&
          typeof (item as { path?: unknown }).path === 'string' &&
          typeof (item as { pattern?: unknown }).pattern === 'string',
      );
    }

    return extracted;
  }

  async handleCollectCode(args: ToolArgs): Promise<ToolResponse> {
    const returnSummaryOnly = argBool(args, 'returnSummaryOnly', false);
    let smartMode = argEnum(args, 'smartMode', SMART_MODES);
    const maxSummaryFiles = ANALYSIS_MAX_SUMMARY_FILES;

    const summarizeFiles = (
      files: Array<{
        url: string;
        type: string;
        size: number;
        content: string;
        metadata?: { truncated?: boolean };
      }>,
    ) =>
      files.slice(0, maxSummaryFiles).map((file) => ({
        url: file.url,
        type: file.type,
        size: file.size,
        sizeKB: (file.size / 1024).toFixed(2),
        truncated: file.metadata?.truncated || false,
        preview: `${file.content.substring(0, 200)}...`,
      }));

    const summarizeResult = (
      result: Awaited<ReturnType<CoreAnalysisHandlerDeps['collector']['collect']>>,
    ) => {
      const rawEntries =
        Array.isArray(result.summaries) && result.summaries.length > 0
          ? result.summaries
          : summarizeFiles(
              result.files as Array<{
                url: string;
                type: string;
                size: number;
                content: string;
                metadata?: { truncated?: boolean };
              }>,
            );
      const entries = rawEntries.slice(0, maxSummaryFiles);
      const filesCount = Array.isArray(result.summaries)
        ? result.summaries.length
        : result.files.length;
      const totalSize =
        result.totalSize > 0
          ? result.totalSize
          : Array.isArray(result.summaries)
            ? result.summaries.reduce(
                (sum, entry) => sum + (typeof entry.size === 'number' ? entry.size : 0),
                0,
              )
            : result.files.reduce((sum, file) => sum + file.size, 0);

      return {
        totalSize,
        totalSizeKB: (totalSize / 1024).toFixed(2),
        filesCount,
        summarizedFiles: entries.length,
        omittedFiles: Math.max(0, filesCount - entries.length),
        collectTime: result.collectTime,
        summary: entries,
      };
    };

    // Default to 'summary' mode to prevent full-collection payload bloat
    if (!smartMode) {
      smartMode = returnSummaryOnly ? 'summary' : 'summary';
    }

    const result = await this.collector.collect({
      url: argStringRequired(args, 'url'),
      includeInline: argBool(args, 'includeInline'),
      includeExternal: argBool(args, 'includeExternal'),
      includeDynamic: argBool(args, 'includeDynamic'),
      smartMode,
      compress: argBool(args, 'compress'),
      maxTotalSize: argNumber(args, 'maxTotalSize'),
      maxFileSize: args.maxFileSize ? argNumber(args, 'maxFileSize', 0) * 1024 : undefined,
      priorities: args.priorities as string[] | undefined,
    });

    if (returnSummaryOnly) {
      const summaryResult = summarizeResult(result);
      return asJsonResponse({
        mode: 'summary',
        ...summaryResult,
        hint: 'Use get_script_source for specific files.',
      });
    }

    const maxSafeCollectedSize = ANALYSIS_MAX_SAFE_COLLECTED_BYTES;
    const maxSafeResponseSize = ANALYSIS_MAX_SAFE_RESPONSE_BYTES;
    const estimatedResponseSize = Buffer.byteLength(JSON.stringify(result), 'utf8');

    if (result.totalSize > maxSafeCollectedSize || estimatedResponseSize > maxSafeResponseSize) {
      logger.warn(
        `Collected code is too large (collected=${(result.totalSize / 1024).toFixed(2)}KB, response=` +
          `${(estimatedResponseSize / 1024).toFixed(2)}KB), returning summary mode.`,
      );

      const summaryResult = summarizeResult(result);
      return asJsonResponse({
        warning: 'Code size exceeds safe response threshold; summary returned.',
        ...summaryResult,
        estimatedResponseSize,
        estimatedResponseSizeKB: (estimatedResponseSize / 1024).toFixed(2),
        recommendations: [
          'Use get_script_source for targeted files.',
          'Use more specific priority filters.',
          'Use smartMode=summary for initial reconnaissance.',
        ],
      });
    }

    return asJsonResponse(result);
  }

  async handleSearchInScripts(args: ToolArgs): Promise<ToolResponse> {
    await this.scriptManager.init();

    const keyword = argString(args, 'keyword');
    if (!keyword) {
      return asJsonResponse({ success: false, error: 'keyword is required' });
    }

    const maxMatches = argNumber(args, 'maxMatches', 100);
    const returnSummary = argBool(args, 'returnSummary', false);
    const maxContextSize = argNumber(args, 'maxContextSize', 50000);

    const result = await this.scriptManager.searchInScripts(keyword, {
      isRegex: argBool(args, 'isRegex'),
      caseSensitive: argBool(args, 'caseSensitive'),
      contextLines: argNumber(args, 'contextLines'),
      maxMatches,
    });
    type ScriptSearchMatch = {
      scriptId?: string | number;
      url?: string;
      line?: number;
      context?: string;
    };

    const resultSize = JSON.stringify(result).length;
    const shouldSummarize = returnSummary || resultSize > maxContextSize;

    if (shouldSummarize) {
      const matches = (result.matches ?? []) as ScriptSearchMatch[];
      return asJsonResponse({
        success: true,
        keyword: args.keyword,
        totalMatches: matches.length,
        resultSize,
        resultSizeKB: (resultSize / 1024).toFixed(2),
        truncated: resultSize > maxContextSize,
        reason:
          resultSize > maxContextSize
            ? `Result too large (${(resultSize / 1024).toFixed(2)}KB > ${(maxContextSize / 1024).toFixed(2)}KB)`
            : 'Summary mode enabled',
        matchesSummary: matches.slice(0, 10).map((match) => ({
          scriptId: match.scriptId,
          url: match.url,
          line: match.line,
          preview: `${(match.context ?? '').substring(0, 100)}...`,
        })),
        recommendations: [
          'Use more specific keywords.',
          `Reduce maxMatches (current: ${maxMatches}).`,
          'Use get_script_source for targeted file retrieval.',
        ],
      });
    }

    return asJsonResponse(result);
  }

  async handleExtractFunctionTree(args: ToolArgs): Promise<ToolResponse> {
    const scriptId = argString(args, 'scriptId');
    const functionName = argString(args, 'functionName');

    // Validate required parameters
    if (!scriptId) {
      return asJsonResponse({
        success: false,
        error: 'scriptId is required',
        hint: 'Use get_all_scripts() to list available scripts and their scriptIds',
      });
    }

    if (!functionName) {
      return asJsonResponse({
        success: false,
        error: 'functionName is required',
        hint: 'Specify the name of the function to extract',
      });
    }

    await this.scriptManager.init();

    // Check if script exists before attempting extraction
    const scripts = await this.scriptManager.getAllScripts();
    const scriptExists = scripts.some((s) => String(s.scriptId) === String(scriptId));

    if (!scriptExists) {
      const availableScripts = scripts.slice(0, 10).map((s) => ({
        scriptId: s.scriptId,
        url: s.url?.substring(0, 80),
      }));

      return asJsonResponse({
        success: false,
        error: `Script not found: ${scriptId}`,
        hint: 'The specified scriptId does not exist. Use get_all_scripts() to list available scripts.',
        availableScripts:
          availableScripts.length > 0
            ? availableScripts
            : 'No scripts loaded. Navigate to a page first.',
        totalScripts: scripts.length,
      });
    }

    try {
      const result = await this.scriptManager.extractFunctionTree(scriptId, functionName, {
        maxDepth: argNumber(args, 'maxDepth'),
        maxSize: argNumber(args, 'maxSize'),
        includeComments: argBool(args, 'includeComments'),
      });
      return asJsonResponse({ success: true, ...result });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      return asJsonResponse({
        success: false,
        error: errorMsg,
        hint: 'Make sure the function name exists in the specified script',
      });
    }
  }

  async handleDeobfuscate(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'deobfuscate');
    if (!code) {
      return asJsonResponse({
        success: false,
        error: 'code is required and must be a non-empty string',
      });
    }

    const engine = argEnum(args, 'engine', new Set(['auto', 'webcrack'] as const), 'auto');

    // webcrack engine = former advanced_deobfuscate path
    if (engine === 'webcrack') {
      const result = await this.advancedDeobfuscator.deobfuscate({
        code,
        ...this.extractWebcrackArgs(args),
        ...(typeof args.detectOnly === 'boolean' ? { detectOnly: args.detectOnly } : {}),
      });
      return asJsonResponse(result);
    }

    // auto engine = former deobfuscate path
    const result = await this.deobfuscator.deobfuscate({
      code,
      ...this.extractWebcrackArgs(args),
    });

    // Ensure failures always carry an error field for LLM clarity
    if (
      result &&
      typeof result === 'object' &&
      'success' in result &&
      result.success === false &&
      !('error' in result)
    ) {
      return asJsonResponse({
        ...result,
        error: (result as Record<string, unknown>).reason || 'deobfuscation failed',
      });
    }

    return asJsonResponse(result);
  }

  async handleUnderstandCode(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'understand_code');
    if (!code) {
      return asJsonResponse({
        success: false,
        error: 'code is required and must be a non-empty string',
      });
    }

    const result = await this.analyzer.understand({
      code,
      context: argObject(args, 'context'),
      focus: argEnum(args, 'focus', FOCUS_MODES, 'all'),
    });

    return asJsonResponse(result);
  }

  async handleDetectCrypto(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'detect_crypto');
    if (!code) {
      return asJsonResponse({
        success: false,
        error: 'code is required and must be a non-empty string',
      });
    }

    const result = await this.cryptoDetector.detect({
      code,
    });

    return asJsonResponse(result);
  }

  async handleManageHooks(args: ToolArgs): Promise<ToolResponse> {
    const action = argStringRequired(args, 'action');

    switch (action) {
      case 'create': {
        const result = await this.hookManager.createHook({
          target: argStringRequired(args, 'target'),
          type: argEnum(args, 'type', HOOK_TYPES) ?? 'function',
          action: argEnum(args, 'hookAction', HOOK_ACTIONS, 'log'),
          customCode: argString(args, 'customCode'),
        });
        return asJsonResponse(result);
      }
      case 'list':
        return asJsonResponse({ hooks: this.hookManager.getAllHooks() });
      case 'records':
        return asJsonResponse({
          records: this.hookManager.getHookRecords(argStringRequired(args, 'hookId')),
        });
      case 'clear':
        this.hookManager.clearHookRecords(argString(args, 'hookId'));
        return asJsonResponse({ success: true, message: 'Hook records cleared' });
      default:
        return asJsonResponse({
          success: false,
          message: `Unknown hook action: ${action}. Valid actions: create, list, records, clear`,
        });
    }
  }

  async handleDetectObfuscation(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'detect_obfuscation');
    if (!code) {
      return asJsonResponse({
        success: false,
        error: 'code is required and must be a non-empty string',
      });
    }

    const generateReport = argBool(args, 'generateReport', true);
    const result = this.obfuscationDetector.detect(code);

    if (!generateReport) {
      return asJsonResponse(result);
    }

    const report = this.obfuscationDetector.generateReport(result);
    return asTextResponse(`${JSON.stringify(result, null, 2)}\n\n${report}`);
  }

  async handleWebcrackUnpack(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'webcrack_unpack');
    if (!code) {
      return asJsonResponse({
        success: false,
        error: 'code is required and must be a non-empty string',
      });
    }

    const result = await runWebcrack(code, {
      unpack: argBool(args, 'unpack', true),
      unminify: argBool(args, 'unminify', true),
      jsx: argBool(args, 'jsx', true),
      mangle: argBool(args, 'mangle', false),
      ...this.extractWebcrackArgs(args),
    });

    if (!result.applied) {
      return asJsonResponse({
        success: false,
        error: result.reason || 'webcrack execution failed',
        optionsUsed: result.optionsUsed,
        engine: 'webcrack',
      });
    }

    return asJsonResponse({
      success: true,
      code: result.code,
      bundle: result.bundle,
      savedTo: result.savedTo,
      savedArtifacts: result.savedArtifacts,
      optionsUsed: result.optionsUsed,
      engine: 'webcrack',
    });
  }

  async handleWebpackEnumerate(args: ToolArgs): Promise<ToolResponse> {
    return runWebpackEnumerate(this.collector, args);
  }

  async handleClearCollectedData(): Promise<ToolResponse> {
    try {
      await this.collector.clearAllData();
      this.scriptManager.clear();
      return asJsonResponse({
        success: true,
        message: 'All collected data cleared.',
        cleared: {
          fileCache: true,
          compressionCache: true,
          collectedUrls: true,
          scriptManager: true,
        },
      });
    } catch (error) {
      logger.error('Failed to clear collected data:', error);
      return asJsonResponse(serializeError(error));
    }
  }

  async handleGetCollectionStats(): Promise<ToolResponse> {
    try {
      const stats = await this.collector.getAllStats();
      return asJsonResponse({
        success: true,
        stats,
        summary: {
          totalCachedFiles: stats.cache.memoryEntries + stats.cache.diskEntries,
          totalCacheSize: `${(stats.cache.totalSize / 1024).toFixed(2)} KB`,
          compressionRatio: `${stats.compression.averageRatio.toFixed(1)}%`,
          cacheHitRate:
            stats.compression.cacheHits > 0
              ? `${(
                  (stats.compression.cacheHits /
                    (stats.compression.cacheHits + stats.compression.cacheMisses)) *
                  100
                ).toFixed(1)}%`
              : '0%',
          collectedUrls: stats.collector.collectedUrls,
        },
      });
    } catch (error) {
      logger.error('Failed to get collection stats:', error);
      return asJsonResponse(serializeError(error));
    }
  }

  async handleJsDeobfuscateJsvmp(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'js_deobfuscate_jsvmp');
    if (!code) {
      return asJsonResponse({
        success: false,
        error: 'code is required and must be a non-empty string',
      });
    }

    const detectOnly = argBool(args, 'detectOnly', false);
    const result = await this.jsvmpDeobfuscator.deobfuscate({
      code,
      aggressive: argBool(args, 'aggressive', false),
      extractInstructions: argBool(args, 'extractInstructions', true),
      timeout: argNumber(args, 'timeout', 30000),
    });

    if (detectOnly) {
      return asJsonResponse({
        success: true,
        isJSVMP: result.isJSVMP,
        vmType: result.vmType,
        vmFeatures: result.vmFeatures,
        confidence: result.confidence,
        instructionCount: result.instructions?.length,
      });
    }

    return asJsonResponse({
      success: result.isJSVMP,
      isJSVMP: result.isJSVMP,
      vmType: result.vmType,
      vmFeatures: result.vmFeatures,
      instructions: result.instructions,
      deobfuscatedCode: result.deobfuscatedCode,
      confidence: result.confidence,
      warnings: result.warnings,
      unresolvedParts: result.unresolvedParts,
      stats: result.stats,
    });
  }

  async handleJsDeobfuscatePipeline(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'js_deobfuscate_pipeline');
    if (!code) {
      return asJsonResponse({ success: false, error: 'code is required' });
    }

    const useWebcrack = argBool(args, 'useWebcrack', true);
    const aggressive = argBool(args, 'aggressive', false);
    const humanize = argBool(args, 'humanize', true);
    const returnStageDetails = argBool(args, 'returnStageDetails', false);
    const startTime = Date.now();

    // Stage 1: Preprocessor — constant folding, dead code removal
    let preprocessed = code;
    const ppTransforms: string[] = [];

    const afterFold = applyConstantFold(preprocessed);
    if (afterFold !== preprocessed) {
      preprocessed = afterFold;
      ppTransforms.push('constant_fold');
    }

    const afterDeadCode = applyDeadCodeRemove(preprocessed);
    if (afterDeadCode !== preprocessed) {
      preprocessed = afterDeadCode;
      ppTransforms.push('dead_code_remove');
    }

    // Stage 2: Deobfuscator — webcrack
    let deobfuscated = preprocessed;
    let webcrackApplied = false;
    let webcrackWarning: string | undefined;
    let webcrackError: string | undefined;
    if (useWebcrack) {
      try {
        const result = await runWebcrack(preprocessed, { unminify: true, unpack: true });
        if (result.applied) {
          deobfuscated = result.code;
          webcrackApplied = true;
        } else {
          webcrackWarning = result.reason
            ? `webcrack stage did not apply: ${result.reason}`
            : 'webcrack stage did not apply any transformation.';
        }
      } catch (error) {
        webcrackError = error instanceof Error ? error.message : String(error);
      }
    }

    if (aggressive) {
      const afterCFF = applyControlFlowFlatten(deobfuscated);
      if (afterCFF !== deobfuscated) {
        deobfuscated = afterCFF;
      }
    }

    // Stage 3: Humanizer — variable renaming
    let humanized = deobfuscated;
    let renameCount = 0;
    if (humanize) {
      const result = applyRenameVars(humanized);
      if (result.code !== humanized) {
        humanized = result.code;
        renameCount = result.count;
      }
    }

    const totalMs = Date.now() - startTime;
    const reductionRate = code.length > 0 ? 1 - humanized.length / code.length : 0;
    const pipelineSuccess = !webcrackWarning && !webcrackError;

    const response: Record<string, unknown> = {
      success: pipelineSuccess,
      deobfuscatedCode: humanized,
      ...(webcrackWarning ? { warning: webcrackWarning } : {}),
      ...(webcrackError ? { error: `webcrack stage failed: ${webcrackError}` } : {}),
      stats: {
        originalSize: code.length,
        finalSize: humanized.length,
        reductionRate: Math.round(reductionRate * 1000) / 10,
        processingTimeMs: totalMs,
        stages: {
          preprocessor: { transforms: ppTransforms, sizeAfter: preprocessed.length },
          deobfuscator: {
            webcrackApplied,
            sizeAfter: deobfuscated.length,
            ...(webcrackWarning ? { warning: webcrackWarning } : {}),
            ...(webcrackError ? { error: webcrackError } : {}),
          },
          humanizer: { renameCount, sizeAfter: humanized.length },
        },
      },
    };

    if (returnStageDetails) {
      response.stageDetails = {
        preprocessed: preprocessed.substring(0, 5000),
        deobfuscated: deobfuscated.substring(0, 5000),
      };
    }

    return asJsonResponse(response);
  }

  async handleJsAnalyzeVm(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'js_analyze_vm');
    if (!code) {
      return asJsonResponse({ success: false, error: 'code is required' });
    }

    const extractBytecode = argBool(args, 'extractBytecode', true);
    const mapOpcodes = argBool(args, 'mapOpcodes', true);

    const vmResult = await this.jsvmpDeobfuscator.deobfuscate({
      code,
      aggressive: false,
      extractInstructions: extractBytecode,
      timeout: 15000,
    });
    return asJsonResponse(
      buildVmAnalysisResponse({
        code,
        extractBytecode,
        mapOpcodes,
        vmResult,
      }),
    );
  }

  async handleJsSolveConstraints(args: ToolArgs): Promise<ToolResponse> {
    const code = this.requireCodeArg(args, 'js_solve_constraints');
    if (!code) {
      return asJsonResponse({ success: false, error: 'code is required' });
    }

    const replaceInPlace = argBool(args, 'replaceInPlace', true);
    const maxIterations = argNumber(args, 'maxIterations', 100);

    return asJsonResponse(
      solveConstraints({
        code,
        replaceInPlace,
        maxIterations,
      }),
    );
  }
}
