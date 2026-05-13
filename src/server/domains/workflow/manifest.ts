import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import {
  defineMethodRegistrations,
  ensureBrowserCore,
  toolLookup,
} from '@server/domains/shared/registry';
import { workflowToolDefinitions } from '@server/domains/workflow/definitions';
import type { WorkflowHandlers } from '@server/domains/workflow/index';

const DOMAIN = 'workflow' as const;
const DEP_KEY = 'workflowHandlers' as const;
type H = WorkflowHandlers;
const t = toolLookup(workflowToolDefinitions);
const registrations = defineMethodRegistrations<
  H,
  (typeof workflowToolDefinitions)[number]['name']
>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  entries: [
    { tool: 'page_script_register', method: 'handlePageScriptRegister' },
    { tool: 'page_script_run', method: 'handlePageScriptRun' },
    { tool: 'api_probe_batch', method: 'handleApiProbeBatch' },
    { tool: 'js_bundle_search', method: 'handleJsBundleSearch' },
    { tool: 'list_extension_workflows', method: 'handleListExtensionWorkflows' },
    { tool: 'run_extension_workflow', method: 'handleRunExtensionWorkflow' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { WorkflowHandlers } = await import('@server/domains/workflow/index');
  await ensureBrowserCore(ctx);

  // Delegate via handlerDeps proxy, not direct imports
  const browserHandlers = ctx.handlerDeps.browserHandlers as typeof ctx.browserHandlers;
  const advancedHandlers = ctx.handlerDeps.advancedHandlers as typeof ctx.advancedHandlers;

  if (!ctx.workflowHandlers) {
    ctx.workflowHandlers = new WorkflowHandlers({
      browserHandlers: browserHandlers!,
      advancedHandlers: advancedHandlers!,
      serverContext: ctx,
    });
  }
  return ctx.workflowHandlers;
}

const manifest = {
  kind: 'domain-manifest',
  version: 1,
  domain: DOMAIN,
  depKey: DEP_KEY,
  profiles: ['workflow', 'full'],
  ensure,

  workflowRule: {
    patterns: [/(workflow|extension|run)/i, /(工作流|扩展|运行)/i],
    priority: 95,
    tools: ['run_extension_workflow', 'list_extension_workflows'],
    hint: 'Extension workflow: list available workflows -> run the best matching workflow',
  },

  // Surface the implicit dependency on browser/network domains: most workflow
  // tools call into a live page or recorded network state. Declaring this
  // here ensures the activation/router layer can show useful guidance instead
  // of letting handlers fall over on the first call.
  prerequisites: {
    page_script_run: [
      { condition: 'Browser must be launched', fix: 'Call browser_launch or browser_attach first' },
    ],
    api_probe_batch: [
      { condition: 'Browser must be launched', fix: 'Call browser_launch or browser_attach first' },
      {
        condition: 'Network monitoring must be enabled',
        fix: 'Call network_monitor(enable) first',
      },
    ],
    js_bundle_search: [
      { condition: 'Browser must be launched', fix: 'Call browser_launch or browser_attach first' },
    ],
    run_extension_workflow: [
      { condition: 'Browser must be launched', fix: 'Call browser_launch or browser_attach first' },
    ],
  },

  registrations,
} satisfies DomainManifest<typeof DEP_KEY, H, typeof DOMAIN>;

export default manifest;
