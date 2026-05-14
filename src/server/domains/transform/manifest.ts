import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import { defineMethodRegistrations, toolLookup } from '@server/domains/shared/registry';
import { transformTools } from '@server/domains/transform/definitions';
import type { TransformToolHandlers } from '@server/domains/transform/index';

const DOMAIN = 'transform' as const;
const DEP_KEY = 'transformHandlers' as const;
type H = TransformToolHandlers;
const t = toolLookup(transformTools);
const registrations = defineMethodRegistrations<H, (typeof transformTools)[number]['name']>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  entries: [
    { tool: 'ast_transform_preview', method: 'handleAstTransformPreview' },
    { tool: 'ast_transform_chain', method: 'handleAstTransformChain' },
    { tool: 'ast_transform_apply', method: 'handleAstTransformApply' },
    { tool: 'crypto_extract_standalone', method: 'handleCryptoExtractStandalone' },
    { tool: 'crypto_test_harness', method: 'handleCryptoTestHarness' },
    { tool: 'crypto_compare', method: 'handleCryptoCompare' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { CodeCollector } = await import('@server/domains/shared/modules/collector');
  const { TransformToolHandlers } = await import('@server/domains/transform/index');
  if (!ctx.collector) {
    ctx.collector = new CodeCollector(ctx.config.puppeteer);
    void ctx.registerCaches();
  }
  if (!ctx.transformHandlers) ctx.transformHandlers = new TransformToolHandlers(ctx.collector);
  return ctx.transformHandlers;
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
