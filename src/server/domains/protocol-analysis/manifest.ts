import type { DomainManifest, MCPServerContext } from '@server/domains/shared/registry';
import { defineMethodRegistrations, toolLookup } from '@server/domains/shared/registry';
import { asToolResponse } from '@server/domains/shared/response';
import { protocolAnalysisTools } from './definitions';
import type { ProtocolAnalysisHandlers } from './handlers';

const DOMAIN = 'protocol-analysis';
const DEP_KEY = 'protocolAnalysisHandlers';
type H = ProtocolAnalysisHandlers;
const t = toolLookup(protocolAnalysisTools);
const registrations = defineMethodRegistrations<H, (typeof protocolAnalysisTools)[number]['name']>({
  domain: DOMAIN,
  depKey: DEP_KEY,
  lookup: t,
  wrapResult: asToolResponse,
  entries: [
    { tool: 'proto_define_pattern', method: 'handleDefinePattern' },
    { tool: 'proto_auto_detect', method: 'handleAutoDetect' },
    { tool: 'proto_infer_fields', method: 'handleInferFields' },
    { tool: 'proto_infer_state_machine', method: 'handleInferStateMachine' },
    { tool: 'proto_export_schema', method: 'handleExportSchema' },
    { tool: 'proto_visualize_state', method: 'handleVisualizeState' },
    { tool: 'payload_template_build', method: 'handlePayloadTemplateBuild' },
    { tool: 'payload_mutate', method: 'handlePayloadMutate' },
    { tool: 'ethernet_frame_build', method: 'handleEthernetFrameBuild' },
    { tool: 'arp_build', method: 'handleArpBuild' },
    { tool: 'raw_ip_packet_build', method: 'handleRawIpPacketBuild' },
    { tool: 'icmp_echo_build', method: 'handleIcmpEchoBuild' },
    { tool: 'checksum_apply', method: 'handleChecksumApply' },
    { tool: 'pcap_write', method: 'handlePcapWrite' },
    { tool: 'pcap_read', method: 'handlePcapRead' },
    { tool: 'proto_fingerprint', method: 'handleProtoFingerprint' },
  ],
});

async function ensure(ctx: MCPServerContext): Promise<H> {
  const { ProtocolAnalysisHandlers } = await import('./handlers');
  const existing = ctx.getDomainInstance<H>(DEP_KEY);
  if (existing) {
    return existing;
  }

  const handlers = new ProtocolAnalysisHandlers(undefined, undefined, ctx.eventBus);
  ctx.setDomainInstance(DEP_KEY, handlers);
  return handlers;
}

const manifest = {
  kind: 'domain-manifest',
  version: 1,
  domain: DOMAIN,
  depKey: DEP_KEY,
  profiles: ['full'],
  ensure,
  registrations,
  prerequisites: {
    proto_auto_detect: [
      {
        condition: 'At least one hex payload sample is required',
        fix: 'Capture traffic using network monitoring tools first',
      },
    ],
    proto_infer_state_machine: [
      {
        condition: 'Multiple message samples are required for state machine inference',
        fix: 'Capture message sequences with mojo-ipc or network tools',
      },
    ],
  },
  workflowRule: {
    patterns: [
      /protocol\s+(reverse|analysis|pattern|state\s*machine|schema)/i,
      /custom\s+protocol|binary\s+protocol|wire\s+format/i,
      /infer\s+(protocol|fields|state\s*machine)/i,
      /proto.*export|proto.*schema|proto.*diagram/i,
      /payload\s+(template|build|mutate)|packet\s+(template|mutate)/i,
      /ethernet|arp|ipv4|ipv6|pcap|internet\s+checksum|raw\s+packet/i,
    ],
    priority: 0.6,
    tools: [
      'proto_auto_detect',
      'proto_infer_fields',
      'proto_define_pattern',
      'proto_infer_state_machine',
      'proto_export_schema',
      'proto_visualize_state',
      'payload_template_build',
      'payload_mutate',
      'ethernet_frame_build',
      'arp_build',
      'raw_ip_packet_build',
      'icmp_echo_build',
      'checksum_apply',
      'pcap_write',
      'pcap_read',
    ],
    hint: 'Capture or craft packet bytes -> build Ethernet/ARP/IP/ICMP headers -> apply deterministic checksums and payload mutations -> read/write compact PCAP files -> infer fields or state machines from resulting payloads',
  },
  toolDependencies: [
    {
      from: 'network',
      to: 'protocol-analysis',
      relation: 'uses',
      weight: 0.7,
    },
  ],
} satisfies DomainManifest<typeof DEP_KEY, H, typeof DOMAIN>;

export default manifest;
