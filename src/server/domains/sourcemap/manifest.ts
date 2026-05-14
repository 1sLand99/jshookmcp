import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import { defineMethodRegistrations, toolLookup } from '@server/domains/shared/registry';
import { sourcemapTools } from '@server/domains/sourcemap/definitions';
import type { SourcemapToolHandlers } from '@server/domains/sourcemap/index';

const DOMAIN = 'sourcemap' as const;
const DEP_KEY = 'sourcemapHandlers' as const;
type H = SourcemapToolHandlers;
const t = toolLookup(sourcemapTools);
const registrations = defineMethodRegistrations<H, (typeof sourcemapTools)[number]['name']>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  entries: [
    { tool: 'sourcemap_discover', method: 'handleSourcemapDiscover' },
    { tool: 'sourcemap_fetch_and_parse', method: 'handleSourcemapFetchAndParse' },
    { tool: 'sourcemap_reconstruct_tree', method: 'handleSourcemapReconstructTree' },
    { tool: 'sourcemap_parse_v4', method: 'handleSourcemapParseV4' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { CodeCollector } = await import('@server/domains/shared/modules/collector');
  const { SourcemapToolHandlers } = await import('@server/domains/sourcemap/index');
  if (!ctx.collector) {
    ctx.collector = new CodeCollector(ctx.config.puppeteer);
    void ctx.registerCaches();
  }
  if (!ctx.sourcemapHandlers) ctx.sourcemapHandlers = new SourcemapToolHandlers(ctx.collector);
  return ctx.sourcemapHandlers;
}

const manifest = {
  kind: 'domain-manifest',
  version: 1,
  domain: DOMAIN,
  depKey: DEP_KEY,
  profiles: ['full'],
  ensure,
  registrations,
} satisfies DomainManifest<typeof DEP_KEY, H, typeof DOMAIN>;

export default manifest;
