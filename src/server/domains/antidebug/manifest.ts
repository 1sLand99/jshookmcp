import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import { defineMethodRegistrations, toolLookup } from '@server/domains/shared/registry';
import { antidebugTools } from '@server/domains/antidebug/definitions';
import type { AntiDebugToolHandlers } from '@server/domains/antidebug/index';

const DOMAIN = 'antidebug' as const;
const DEP_KEY = 'antidebugHandlers' as const;
type H = AntiDebugToolHandlers;
const t = toolLookup(antidebugTools);
const registrations = defineMethodRegistrations<H, (typeof antidebugTools)[number]['name']>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  entries: [
    { tool: 'antidebug_bypass', method: 'handleAntidebugBypass' },
    { tool: 'antidebug_detect_protections', method: 'handleAntiDebugDetectProtections' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { CodeCollector } = await import('@server/domains/shared/modules/collector');
  const { AntiDebugToolHandlers } = await import('@server/domains/antidebug/index');
  if (!ctx.collector) {
    ctx.collector = new CodeCollector(ctx.config.puppeteer);
    void ctx.registerCaches();
  }
  if (!ctx.antidebugHandlers) {
    ctx.antidebugHandlers = new AntiDebugToolHandlers(ctx.collector);
  }
  return ctx.antidebugHandlers;
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
