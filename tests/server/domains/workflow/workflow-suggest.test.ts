import { parseJson } from '@tests/server/domains/shared/mock-factories';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@src/server/extensions/ExtensionManager', () => ({
  ensureWorkflowsLoaded: vi.fn(async () => {}),
}));

import { WorkflowHandlers } from '@server/domains/workflow/handlers';
import { defineWorkflow, toolStep } from '@server/workflows/WorkflowContract';
import type { ExtensionWorkflowRecord } from '@server/extensions/types';

interface SuggestResponse {
  success: boolean;
  error?: string;
  suggestions: Array<{
    name: string;
    reason: string;
    missingPrerequisites: string[];
  }>;
  unmatched: string[];
}

interface ListResponse {
  success: boolean;
  count: number;
  workflows: Array<{
    id: string;
    chainsWith?: string[];
    prerequisites?: string[];
  }>;
}

/**
 * Fixture ids mimic the canonical reverse-engineering chain:
 * frida hook → SSL pinning bypass → traffic decode.
 */
const CHAIN_FIXTURES: ExtensionWorkflowRecord[] = [
  {
    id: 'workflow.frida_hook.v1',
    displayName: 'Frida Hook Intake',
    source: 'fixtures/frida-hook.workflow.ts',
    chainsWith: ['workflow.ssl_bypass.v1', 'workflow.traffic_decode.v1'],
  },
  {
    id: 'workflow.ssl_bypass.v1',
    displayName: 'SSL Pinning Bypass',
    source: 'fixtures/ssl-bypass.workflow.ts',
    prerequisites: ['workflow.frida_hook.v1'],
    chainsWith: ['workflow.traffic_decode.v1'],
  },
  {
    id: 'workflow.traffic_decode.v1',
    displayName: 'Traffic Decode',
    source: 'fixtures/traffic-decode.workflow.ts',
    prerequisites: ['workflow.ssl_bypass.v1'],
  },
  {
    id: 'workflow.standalone.v1',
    displayName: 'No Chain Metadata',
    source: 'fixtures/standalone.workflow.ts',
  },
];

function createHandlersWithWorkflows(workflows: ExtensionWorkflowRecord[]): WorkflowHandlers {
  const deps = {
    browserHandlers: {
      handlePageEvaluate: vi.fn(),
      handlePageNavigate: vi.fn(),
      handlePageClick: vi.fn(),
      handlePageType: vi.fn(),
      handleNetworkGetRequests: vi.fn(),
    },
    advancedHandlers: {
      handleNetworkEnable: vi.fn(),
      handleConsoleInjectFetchInterceptor: vi.fn(),
      handleConsoleInjectXhrInterceptor: vi.fn(),
      handleNetworkGetStats: vi.fn(),
      handleNetworkGetRequests: vi.fn(),
      handleNetworkExtractAuth: vi.fn(),
      handleNetworkExportHar: vi.fn(),
    },
    serverContext: {
      extensionWorkflowsById: new Map(workflows.map((record) => [record.id, record])),
      extensionWorkflowRuntimeById: new Map(),
      executeToolWithTracking: vi.fn(),
      baseTier: 'workflow',
      config: {},
    },
  };
  return new WorkflowHandlers(deps as unknown as ConstructorParameters<typeof WorkflowHandlers>[0]);
}

describe('workflow_suggest chain recommendations', () => {
  let handlers: WorkflowHandlers;

  beforeEach(() => {
    vi.clearAllMocks();
    handlers = createHandlersWithWorkflows(CHAIN_FIXTURES.map((record) => ({ ...record })));
  });

  it('validates the executed argument', async () => {
    const missing = parseJson<SuggestResponse>(await handlers.handleWorkflowSuggest({}));
    expect(missing.success).toBe(false);
    expect(missing.error).toContain('executed is required');

    const wrongType = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({ executed: 'workflow.frida_hook.v1' }),
    );
    expect(wrongType.success).toBe(false);
    expect(wrongType.error).toContain('array of workflow ids');

    const wrongItems = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({ executed: [42] }),
    );
    expect(wrongItems.success).toBe(false);
    expect(wrongItems.error).toContain('workflow id strings only');
  });

  it('returns honest empty suggestions when no workflow carries chain metadata', async () => {
    const bare = createHandlersWithWorkflows([
      {
        id: 'workflow.plain.v1',
        displayName: 'Plain Workflow',
        source: 'fixtures/plain.workflow.ts',
      },
    ]);

    const body = parseJson<SuggestResponse>(
      await bare.handleWorkflowSuggest({ executed: ['workflow.plain.v1'] }),
    );
    expect(body.success).toBe(true);
    expect(body.suggestions).toEqual([]);
    expect(body.unmatched).toEqual([]);
  });

  it('recommends only workflows chained from executed ones and names the chain in the reason', async () => {
    const body = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({ executed: ['workflow.frida_hook.v1'] }),
    );

    expect(body.success).toBe(true);
    expect(body.suggestions.map((suggestion) => suggestion.name)).toEqual([
      'workflow.ssl_bypass.v1',
      'workflow.traffic_decode.v1',
    ]);
    expect(body.suggestions[0]?.reason).toContain('workflow.frida_hook.v1');
    expect(body.suggestions[0]?.reason).toContain('chainsWith');
    expect(body.suggestions[1]?.reason).toContain('workflow.frida_hook.v1');
    // The standalone workflow without metadata is never recommended.
    expect(body.suggestions.map((suggestion) => suggestion.name)).not.toContain(
      'workflow.standalone.v1',
    );
  });

  it('ranks satisfied prerequisites before missing ones and lists the gaps', async () => {
    const body = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({
        executed: ['workflow.frida_hook.v1'],
      }),
    );

    const sslBypass = body.suggestions.find(
      (suggestion) => suggestion.name === 'workflow.ssl_bypass.v1',
    );
    expect(sslBypass?.missingPrerequisites).toEqual([]);
    expect(sslBypass?.reason).toContain('All prerequisites satisfied');

    const trafficDecode = body.suggestions.find(
      (suggestion) => suggestion.name === 'workflow.traffic_decode.v1',
    );
    expect(trafficDecode?.missingPrerequisites).toEqual(['workflow.ssl_bypass.v1']);
    expect(trafficDecode?.reason).toContain('Missing prerequisites');
    expect(trafficDecode?.reason).toContain('workflow.ssl_bypass.v1');
  });

  it('surfaces missing prerequisites without a chain hit', async () => {
    const body = parseJson<SuggestResponse>(await handlers.handleWorkflowSuggest({ executed: [] }));

    // No chain hits at all; prerequisite-declared workflows still surface with gaps.
    const sslBypass = body.suggestions.find(
      (suggestion) => suggestion.name === 'workflow.ssl_bypass.v1',
    );
    expect(sslBypass?.missingPrerequisites).toEqual(['workflow.frida_hook.v1']);
    // Standalone workflow stays excluded because it declares nothing.
    expect(
      body.suggestions.find((suggestion) => suggestion.name === 'workflow.standalone.v1'),
    ).toBeUndefined();
  });

  it('never re-suggests already-executed workflows and reports unmatched ids', async () => {
    const body = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({
        executed: [
          'workflow.frida_hook.v1',
          'workflow.traffic_decode.v1',
          'workflow.not_loaded.v1',
        ],
      }),
    );

    const names = body.suggestions.map((suggestion) => suggestion.name);
    expect(names).not.toContain('workflow.frida_hook.v1');
    expect(names).not.toContain('workflow.traffic_decode.v1');
    expect(body.unmatched).toEqual(['workflow.not_loaded.v1']);
  });

  it('deduplicates executed ids for deterministic ranking', async () => {
    const first = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({ executed: ['workflow.frida_hook.v1'] }),
    );
    const second = parseJson<SuggestResponse>(
      await handlers.handleWorkflowSuggest({
        executed: ['workflow.frida_hook.v1', 'workflow.frida_hook.v1'],
      }),
    );

    expect(second.suggestions).toEqual(first.suggestions);
    expect(second.unmatched).toEqual(first.unmatched);
  });
});

describe('workflow chain metadata plumbing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('round-trips chainsWith / prerequisites through defineWorkflow and the run store record', () => {
    const workflow = defineWorkflow('workflow.chain_meta.v1', 'Chain Metadata Fixture', (w) =>
      w
        .description('fixture')
        .prerequisites(['workflow.frida_hook.v1'])
        .chainsWith(['workflow.traffic_decode.v1'])
        .buildGraph(() => toolStep('node', 'demo_tool')),
    );

    expect(workflow.chainsWith).toEqual(['workflow.traffic_decode.v1']);
    expect(workflow.prerequisites).toEqual(['workflow.frida_hook.v1']);
  });

  it('lists extension workflows with chain metadata only when declared', async () => {
    const handlers = createHandlersWithWorkflows([
      {
        id: 'workflow.chained.v1',
        displayName: 'Chained',
        source: 'fixtures/chained.workflow.ts',
        chainsWith: ['workflow.traffic_decode.v1'],
        prerequisites: ['workflow.frida_hook.v1'],
      },
      {
        id: 'workflow.bare.v1',
        displayName: 'Bare',
        source: 'fixtures/bare.workflow.ts',
      },
    ]);

    const body = parseJson<ListResponse>(await handlers.handleListExtensionWorkflows());
    expect(body.success).toBe(true);
    expect(body.count).toBe(2);

    const chained = body.workflows.find((workflow) => workflow.id === 'workflow.chained.v1');
    expect(chained?.chainsWith).toEqual(['workflow.traffic_decode.v1']);
    expect(chained?.prerequisites).toEqual(['workflow.frida_hook.v1']);

    const bare = body.workflows.find((workflow) => workflow.id === 'workflow.bare.v1');
    expect(bare?.chainsWith).toBeUndefined();
    expect(bare?.prerequisites).toBeUndefined();
  });
});
