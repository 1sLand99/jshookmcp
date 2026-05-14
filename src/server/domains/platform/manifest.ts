import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import { defineMethodRegistrations, toolLookup } from '@server/domains/shared/registry';
import { platformTools } from '@server/domains/platform/definitions';
import type { PlatformToolHandlers } from '@server/domains/platform/index';

const DOMAIN = 'platform' as const;
const DEP_KEY = 'platformHandlers' as const;
type H = PlatformToolHandlers;
const t = toolLookup(platformTools);
const registrations = defineMethodRegistrations<H, (typeof platformTools)[number]['name']>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  entries: [
    { tool: 'platform_capabilities', method: 'handlePlatformCapabilities' },
    { tool: 'miniapp_pkg_scan', method: 'handleMiniappPkgScan' },
    { tool: 'miniapp_pkg_unpack', method: 'handleMiniappPkgUnpack' },
    { tool: 'miniapp_pkg_analyze', method: 'handleMiniappPkgAnalyze' },
    { tool: 'asar_extract', method: 'handleAsarExtract' },
    { tool: 'electron_inspect_app', method: 'handleElectronInspectApp' },
    { tool: 'electron_scan_userdata', method: 'handleElectronScanUserdata' },
    { tool: 'asar_search', method: 'handleAsarSearch' },
    { tool: 'electron_check_fuses', method: 'handleElectronCheckFuses' },
    { tool: 'electron_patch_fuses', method: 'handleElectronPatchFuses' },
    { tool: 'v8_bytecode_decompile', method: 'handleV8BytecodeDecompile' },
    { tool: 'electron_launch_debug', method: 'handleElectronLaunchDebug' },
    { tool: 'electron_debug_status', method: 'handleElectronDebugStatus' },
    { tool: 'electron_ipc_sniff', method: 'handleElectronIPCSniff' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { CodeCollector } = await import('@server/domains/shared/modules/collector');
  const { PlatformToolHandlers } = await import('@server/domains/platform/index');
  if (!ctx.collector) {
    ctx.collector = new CodeCollector(ctx.config.puppeteer);
    void ctx.registerCaches();
  }
  if (!ctx.platformHandlers) ctx.platformHandlers = new PlatformToolHandlers(ctx.collector);
  return ctx.platformHandlers;
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
