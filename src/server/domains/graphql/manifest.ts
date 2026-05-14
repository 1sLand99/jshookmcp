import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import { defineMethodRegistrations, toolLookup } from '@server/domains/shared/registry';
import { graphqlTools } from '@server/domains/graphql/definitions';
import type { GraphQLToolHandlers } from '@server/domains/graphql/index';

const DOMAIN = 'graphql' as const;
const DEP_KEY = 'graphqlHandlers' as const;
type H = GraphQLToolHandlers;
const t = toolLookup(graphqlTools);
const registrations = defineMethodRegistrations<H, (typeof graphqlTools)[number]['name']>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  entries: [
    { tool: 'call_graph_analyze', method: 'handleCallGraphAnalyze' },
    { tool: 'script_replace_persist', method: 'handleScriptReplacePersist' },
    { tool: 'graphql_introspect', method: 'handleGraphqlIntrospect' },
    { tool: 'graphql_extract_queries', method: 'handleGraphqlExtractQueries' },
    { tool: 'graphql_replay', method: 'handleGraphqlReplay' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { CodeCollector, ConsoleMonitor } =
    await import('@server/domains/shared/modules/collector');
  const { GraphQLToolHandlers } = await import('@server/domains/graphql/index');
  if (!ctx.collector) {
    ctx.collector = new CodeCollector(ctx.config.puppeteer);
    void ctx.registerCaches();
  }
  if (!ctx.consoleMonitor) {
    ctx.consoleMonitor = new ConsoleMonitor(ctx.collector);
  }
  if (!ctx.graphqlHandlers) {
    ctx.graphqlHandlers = new GraphQLToolHandlers({
      collector: ctx.collector,
      consoleMonitor: ctx.consoleMonitor,
    });
  }
  return ctx.graphqlHandlers;
}

const manifest: DomainManifest<typeof DEP_KEY, H, typeof DOMAIN> = {
  kind: 'domain-manifest',
  version: 1,
  domain: DOMAIN,
  depKey: DEP_KEY,
  profiles: ['workflow', 'full'],
  ensure,
  registrations,
};

export default manifest;
