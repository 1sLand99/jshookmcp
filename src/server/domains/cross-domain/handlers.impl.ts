import type { MCPServerContext } from '@server/domains/shared/registry';
import { asJsonResponse } from '@server/domains/shared/response';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';
import { argBool, argNumber, argString } from '@server/domains/shared/parse-args';
import type { ToolResponse } from '@server/types';
import type { EvidenceGraphSnapshot } from '@server/evidence/types';
import type { CrossDomainEvidenceBridge } from './handlers/evidence-graph-bridge';
import { correlateSkiaToJS } from './handlers/skia-correlator';
import { correlateMojoToCDP } from './handlers/mojo-cdp-correlator';
import { correlateSyscallToJS } from './handlers/syscall-js-correlator';
import { buildBinaryToJSPipeline } from './handlers/binary-to-js-pipeline';
import { LiveStateFetcher } from './handlers/live-state-fetcher';
import {
  extractCDPEvents,
  extractGhidraOutput,
  extractJSObjectArray,
  extractJSStacks,
  extractMojoMessages,
  extractNetworkRequests,
  extractSkiaSceneTree,
  extractSyscallEvents,
} from './handlers/input-extractors';
import { WORKFLOWS, type CrossDomainWorkflowDefinition } from './workflows/missions';

const V5_DOMAIN_NAMES = [
  'adb-bridge',
  'analysis',
  'binary-instrument',
  'boringssl-inspector',
  'browser',
  'network',
  'canvas',
  'coordination',
  'cross-domain',
  'dart-inspector',
  'debugger',
  'encoding',
  'exploit-dev',
  'extension-registry',
  'graphql',
  'instrumentation',
  'maintenance',
  'memory',
  'v8-inspector',
  'mojo-ipc',
  'native-bridge',
  'native-emulator',
  'platform',
  'process',
  'protocol-analysis',
  'proxy',
  'sourcemap',
  'streaming',
  'syscall-hook',
  'trace',
  'transform',
  'wasm',
  'webgpu',
  'workflow',
];

export class CrossDomainWorkflowClassifier {
  constructor(
    private readonly ctx: MCPServerContext,
    private readonly evidenceBridgeReady: boolean,
  ) {}

  getCapabilities(): {
    availableDomains: string[];
    missingDomains: string[];
    supportedDomains: string[];
    workflows: Array<{
      workflowKey: string;
      id: string;
      displayName: string;
      stepCount: number;
      requiredDomains: string[];
      availableDomains: string[];
      missingDomains: string[];
      coverage: number;
    }>;
  } {
    const availableDomains = this.getAvailableDomains();
    const missingDomains = V5_DOMAIN_NAMES.filter((d) => !availableDomains.includes(d));

    const workflows = Object.entries(WORKFLOWS).map(([workflowKey, workflow]) => {
      const evaluation = this.evaluateWorkflow(workflow);
      return {
        workflowKey,
        id: workflow.id,
        displayName: workflow.displayName,
        stepCount: workflow.steps.length,
        ...evaluation,
      };
    });

    return { availableDomains, missingDomains, supportedDomains: [...V5_DOMAIN_NAMES], workflows };
  }

  suggestWorkflow(
    goal: string,
    preferAvailableOnly: boolean,
  ): {
    workflowKey: string;
    id: string;
    displayName: string;
    reason: string;
    requiredDomains: string[];
    availableDomains: string[];
    missingDomains: string[];
    coverage: number;
  } {
    const normalizedGoal = goal.toLowerCase();
    const scored = Object.entries(WORKFLOWS).map(([workflowKey, workflow]) => {
      const keywordScore = this.scoreWorkflowGoal(normalizedGoal, workflow);
      const evaluation = this.evaluateWorkflow(workflow);
      return { workflowKey, workflow, keywordScore, evaluation };
    });

    const candidates = preferAvailableOnly
      ? scored.filter((item) => item.evaluation.missingDomains.length === 0)
      : scored;

    const rankedPool = candidates.length > 0 ? candidates : scored;
    rankedPool.sort((a, b) => {
      if (b.keywordScore !== a.keywordScore) {
        return b.keywordScore - a.keywordScore;
      }
      return b.evaluation.coverage - a.evaluation.coverage;
    });

    const selected = rankedPool[0];
    if (!selected) {
      throw new Error('No workflow definitions are available for cross-domain suggestion');
    }
    const reason = this.describeWorkflowReason(normalizedGoal, selected.evaluation);

    return {
      workflowKey: selected.workflowKey,
      id: selected.workflow.id,
      displayName: selected.workflow.displayName,
      reason,
      ...selected.evaluation,
    };
  }

  getHealth(): {
    evidenceBridgeReady: boolean;
    orchestratorReady: boolean;
    availableDomains: string[];
    missingDomains: string[];
  } {
    const availableDomains = this.getAvailableDomains();
    return {
      evidenceBridgeReady: this.evidenceBridgeReady,
      orchestratorReady: true,
      availableDomains,
      missingDomains: V5_DOMAIN_NAMES.filter((d) => !availableDomains.includes(d)),
    };
  }

  private getAvailableDomains(): string[] {
    const currentEnabledDomains =
      this.ctx.enabledDomains.size > 0
        ? this.ctx.enabledDomains
        : this.ctx.resolveEnabledDomains(this.ctx.selectedTools);

    const available: string[] = [];
    for (const d of V5_DOMAIN_NAMES) {
      if (currentEnabledDomains.has(d)) {
        available.push(d);
      }
    }
    return available;
  }

  private evaluateWorkflow(workflow: CrossDomainWorkflowDefinition): {
    requiredDomains: string[];
    availableDomains: string[];
    missingDomains: string[];
    coverage: number;
  } {
    const requiredSet = new Set<string>();
    for (const step of workflow.steps) {
      for (const d of this.inferDomainsForTool(step.tool)) {
        requiredSet.add(d);
      }
    }
    const requiredDomains = [...requiredSet];
    const available = this.getAvailableDomains().filter((d) => requiredSet.has(d));
    const missing = requiredDomains.filter((d) => !available.includes(d));
    const coverage = requiredDomains.length === 0 ? 1 : available.length / requiredDomains.length;
    return { requiredDomains, availableDomains: available, missingDomains: missing, coverage };
  }

  private inferDomainsForTool(toolName: string): string[] {
    if (toolName.startsWith('deobfuscate') || toolName.startsWith('advanced_deobfuscate')) {
      return ['analysis'];
    }
    if (toolName.startsWith('adb_')) return ['adb-bridge'];
    if (toolName.startsWith('js_heap') || toolName.startsWith('performance_take_heap_snapshot')) {
      return ['v8-inspector'];
    }
    if (toolName.startsWith('v8_')) return ['v8-inspector'];
    if (toolName.startsWith('webgpu_')) return ['webgpu'];
    if (toolName.startsWith('wasm_')) return ['wasm'];
    if (toolName.startsWith('transform_')) return ['transform'];
    if (toolName.startsWith('sourcemap_')) return ['sourcemap'];
    if (toolName.startsWith('debugger_')) return ['debugger'];
    if (
      toolName === 'breakpoint' ||
      toolName === 'get_call_stack' ||
      toolName === 'get_scope_variables_enhanced' ||
      toolName === 'get_object_properties'
    ) {
      return ['debugger'];
    }
    if (toolName.startsWith('memory_')) return ['memory'];
    if (toolName.startsWith('process_')) return ['process'];
    if (toolName.startsWith('protocol_') || toolName.startsWith('proto_'))
      return ['protocol-analysis'];
    if (toolName.startsWith('proxy_')) return ['proxy'];
    if (toolName.startsWith('graphql_')) return ['graphql'];
    if (toolName.startsWith('encoding_') || toolName.startsWith('encode_')) return ['encoding'];
    if (toolName.startsWith('coordinate_') || toolName.startsWith('coordination_'))
      return ['coordination'];
    if (toolName.startsWith('dart_')) return ['dart-inspector'];
    if (toolName.startsWith('native_emulate_') || toolName.startsWith('native_emulator_'))
      return ['native-emulator'];
    if (toolName.startsWith('native_bridge_')) return ['native-bridge'];
    if (toolName.startsWith('platform_')) return ['platform'];
    if (toolName.startsWith('stream_') || toolName.startsWith('streaming_')) return ['streaming'];
    if (
      toolName.startsWith('trace_') ||
      toolName.startsWith('start_trace_') ||
      toolName.startsWith('stop_trace_')
    ) {
      return ['trace'];
    }
    if (toolName.startsWith('workflow_')) return ['workflow'];
    if (toolName.startsWith('exploit_')) return ['exploit-dev'];
    if (toolName.startsWith('maintenance_')) return ['maintenance'];
    if (toolName.startsWith('network_')) return ['network'];
    if (toolName.startsWith('console_') || toolName.startsWith('page_')) return ['browser'];
    if (toolName.startsWith('tls_') || toolName.startsWith('net_raw_'))
      return ['boringssl-inspector'];
    if (toolName.startsWith('canvas_')) return ['canvas'];
    if (toolName.startsWith('skia_')) return ['canvas'];
    if (toolName.startsWith('mojo_')) return ['mojo-ipc'];
    if (toolName.startsWith('syscall_')) return ['syscall-hook'];
    if (
      toolName.startsWith('ghidra_') ||
      toolName.startsWith('frida_') ||
      toolName.startsWith('generate_hooks') ||
      toolName.startsWith('unidbg_') ||
      toolName.startsWith('export_hook_script')
    ) {
      return ['binary-instrument'];
    }
    if (toolName.startsWith('extension_') || toolName === 'webhook') {
      return ['extension-registry'];
    }
    if (toolName.startsWith('cross_domain_')) {
      return ['cross-domain'];
    }
    if (toolName.startsWith('evidence_') || toolName.startsWith('instrument_')) {
      return ['instrumentation'];
    }
    if (toolName.startsWith('boringssl_')) {
      return ['boringssl-inspector'];
    }
    return [];
  }

  private scoreWorkflowGoal(
    normalizedGoal: string,
    workflow: CrossDomainWorkflowDefinition,
  ): number {
    let score = 0;

    const goalTokens = tokenizeForWorkflowScoring(normalizedGoal);
    for (const keyword of workflow.keywords) {
      const normalizedKeyword = keyword.toLowerCase();
      if (normalizedGoal.includes(normalizedKeyword)) {
        score += normalizedKeyword.includes(' ') ? 4 : 3;
        continue;
      }
      if (goalTokens.has(normalizedKeyword)) {
        score += 3;
        continue;
      }
      if (
        normalizedKeyword.length >= 4 &&
        [...goalTokens].some(
          (token) =>
            token.length >= 4 &&
            (token.includes(normalizedKeyword) || normalizedKeyword.includes(token)),
        )
      ) {
        score += 1;
      }
    }

    for (const displayToken of tokenizeForWorkflowScoring(workflow.displayName.toLowerCase())) {
      if (goalTokens.has(displayToken)) {
        score += 1;
      }
    }

    const workflowDomains = new Set<string>();
    for (const step of workflow.steps) {
      for (const domain of this.inferDomainsForTool(step.tool)) {
        workflowDomains.add(domain);
      }
    }
    for (const domain of workflowDomains) {
      const spacedDomain = domain.replaceAll('-', ' ');
      if (normalizedGoal.includes(domain) || normalizedGoal.includes(spacedDomain)) {
        score += 1;
      }
    }

    return score;
  }

  private describeWorkflowReason(
    normalizedGoal: string,
    evaluation: { missingDomains: string[]; coverage: number },
  ): string {
    if (evaluation.missingDomains.length === 0) {
      return `Matched goal "${normalizedGoal}" and all required domains are enabled.`;
    }
    return (
      `Matched goal "${normalizedGoal}" with ${Math.round(evaluation.coverage * 100)}% domain coverage. ` +
      `Missing: ` +
      `${evaluation.missingDomains.join(', ')}.`
    );
  }
}

export class CrossDomainHandlers {
  constructor(
    private readonly evidenceBridge: CrossDomainEvidenceBridge,
    private readonly workflowClassifier?: CrossDomainWorkflowClassifier,
    private readonly ctx?: MCPServerContext,
  ) {}

  async handleCapabilitiesTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleCapabilities(args));
  }

  async handleSuggestWorkflowTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleSuggestWorkflow(args));
  }

  async handleHealthTool(): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleHealth());
  }

  async handleCorrelateAllTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleCorrelateAll(args));
  }

  async handleEvidenceExportTool(): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleEvidenceExport());
  }

  async handleEvidenceStatsTool(): Promise<ToolResponse> {
    return handleSafe(async () => await this.handleEvidenceStats());
  }

  async handleCapabilities(_args: Record<string, unknown>): Promise<ToolResponse> {
    const capabilities = {
      evidenceGraphAvailable: true,
      workflowClassifierAvailable: this.workflowClassifier !== undefined,
    };
    if (this.workflowClassifier) {
      return asJsonResponse({
        capabilities,
        ...this.workflowClassifier.getCapabilities(),
      });
    }
    return asJsonResponse({ capabilities });
  }

  async handleSuggestWorkflow(args: Record<string, unknown>): Promise<ToolResponse> {
    const query = argString(args, 'query', '') || argString(args, 'goal', '');
    const preferAvailableOnly = argBool(args, 'preferAvailableOnly', true);
    if (this.workflowClassifier && query) {
      return asJsonResponse(this.workflowClassifier.suggestWorkflow(query, preferAvailableOnly));
    }
    return asJsonResponse({
      message: 'Cross-domain workflow suggestion requires a classifier and query.',
    });
  }

  async handleHealth(): Promise<ToolResponse> {
    const stats = this.evidenceBridge.getStats();
    if (this.workflowClassifier) {
      const health = this.workflowClassifier.getHealth();
      return asJsonResponse({ ...health, evidenceGraph: stats });
    }
    return asJsonResponse({
      evidenceBridgeReady: true,
      orchestratorReady: false,
      evidenceGraph: stats,
    });
  }

  async handleCorrelateAll(args: Record<string, unknown>): Promise<ToolResponse> {
    const errors: string[] = [];
    const results: Record<string, unknown> = {};
    const pullFromDomains = argBool(args, 'pullFromDomains', false);
    const minConfidence = Math.max(0, Math.min(1, argNumber(args, 'minConfidence', 0)));
    const maxEdgesPerType = Math.max(0, Math.floor(argNumber(args, 'maxEdgesPerType', 0)));
    let correlateArgs = args;
    let liveSources: Record<string, unknown> | undefined;

    if (pullFromDomains) {
      const live = await new LiveStateFetcher(this.ctx).hydrate(args);
      correlateArgs = live.args;
      liveSources = live.sources;
      errors.push(...live.errors.map((error) => `LIVE: ${error}`));
    }

    // SKIA-03
    try {
      const sceneTree = extractSkiaSceneTree(correlateArgs['sceneTree']);
      const jsObjects = extractJSObjectArray(correlateArgs['jsObjects']);
      results['skia'] = correlateSkiaToJS(this.evidenceBridge, { sceneTree, jsObjects });
    } catch (e) {
      errors.push(`SKIA-03: ${e instanceof Error ? e.message : String(e)}`);
    }

    // MOJO-03
    try {
      const mojoMessages = extractMojoMessages(correlateArgs['mojoMessages']);
      const cdpEvents = extractCDPEvents(correlateArgs['cdpEvents']);
      const networkRequests = extractNetworkRequests(correlateArgs['networkRequests']);
      results['mojo'] = correlateMojoToCDP(
        this.evidenceBridge,
        mojoMessages,
        cdpEvents,
        networkRequests,
      );
    } catch (e) {
      errors.push(`MOJO-03: ${e instanceof Error ? e.message : String(e)}`);
    }

    // SYSCALL-02
    try {
      const syscallEvents = extractSyscallEvents(correlateArgs['syscallEvents']);
      const jsStacks = extractJSStacks(correlateArgs['jsStacks']);
      results['syscall'] = correlateSyscallToJS(this.evidenceBridge, syscallEvents, jsStacks);
    } catch (e) {
      errors.push(`SYSCALL-02: ${e instanceof Error ? e.message : String(e)}`);
    }

    // BIN-04
    try {
      const ghidraOutput = extractGhidraOutput(correlateArgs['ghidraOutput']);
      if (ghidraOutput) {
        results['binary'] = buildBinaryToJSPipeline(this.evidenceBridge, ghidraOutput);
      }
    } catch (e) {
      errors.push(`BIN-04: ${e instanceof Error ? e.message : String(e)}`);
    }

    const snapshot = filterEvidenceSnapshot(
      this.evidenceBridge.exportGraph(),
      minConfidence,
      maxEdgesPerType,
    );

    return asJsonResponse({
      correlationResults: {
        ...results,
        errors,
        liveState: pullFromDomains ? { pullFromDomains, sources: liveSources } : undefined,
        edgeFilters: { minConfidence, maxEdgesPerType },
      },
      evidenceGraph: snapshot,
    });
  }

  async handleEvidenceExport(): Promise<ToolResponse> {
    return asJsonResponse(this.evidenceBridge.exportGraph());
  }

  async handleEvidenceStats(): Promise<ToolResponse> {
    return asJsonResponse(this.evidenceBridge.getStats());
  }
}

function tokenizeForWorkflowScoring(value: string): Set<string> {
  return new Set(value.split(/[^a-z0-9+#.-]+/i).filter((token) => token.length > 1));
}

function edgeConfidence(edge: EvidenceGraphSnapshot['edges'][number]): number {
  const metadata = edge.metadata ?? {};
  const confidence = metadata['confidence'];
  const matchScore = metadata['matchScore'];
  if (typeof confidence === 'number' && Number.isFinite(confidence)) return confidence;
  if (typeof matchScore === 'number' && Number.isFinite(matchScore)) return matchScore;
  if (confidence === 'high') return 0.9;
  if (confidence === 'medium') return 0.6;
  if (confidence === 'low') return 0.3;
  return 1;
}

function filterEvidenceSnapshot(
  snapshot: EvidenceGraphSnapshot,
  minConfidence: number,
  maxEdgesPerType: number,
): EvidenceGraphSnapshot & { edgeFilterSummary?: Record<string, unknown> } {
  const perType = new Map<string, number>();
  const truncatedByType: Record<string, number> = {};
  const edges = snapshot.edges.filter((edge) => {
    if (edgeConfidence(edge) < minConfidence) return false;
    if (maxEdgesPerType <= 0) return true;
    const count = perType.get(edge.type) ?? 0;
    if (count >= maxEdgesPerType) {
      truncatedByType[edge.type] = (truncatedByType[edge.type] ?? 0) + 1;
      return false;
    }
    perType.set(edge.type, count + 1);
    return true;
  });

  const removedByConfidence =
    snapshot.edges.length -
    edges.length -
    Object.values(truncatedByType).reduce((a, b) => a + b, 0);
  return {
    ...snapshot,
    edges,
    edgeFilterSummary: {
      originalEdges: snapshot.edges.length,
      returnedEdges: edges.length,
      removedByConfidence,
      truncatedByType,
    },
  };
}
