/**
 * ProtocolAnalysisPcapHandlers — classic PCAP read/write handlers.
 */

import type { ToolArgs } from '@server/types';
import type {
  PacketEndianness,
  PacketTimestampPrecision,
  PcapHeader,
  PcapPacketSummary,
} from './shared';
import {
  buildClassicPcap,
  parsePcapLinkType,
  parsePcapPacketInput,
  parsePacketEndianness,
  parsePositiveInteger,
  parseTimestampPrecision,
  readClassicPcap,
  readFile,
  writeFile,
} from './shared';
import { ProtocolAnalysisPacketBuildHandlers } from './packet-build-handlers';

export class ProtocolAnalysisPcapHandlers extends ProtocolAnalysisPacketBuildHandlers {
  async handlePcapWrite(args: ToolArgs): Promise<{
    path: string;
    packetCount: number;
    byteLength: number;
    endianness: PacketEndianness | null;
    timestampPrecision: PacketTimestampPrecision | null;
    linkType: number | null;
    success?: boolean;
    error?: string;
  }> {
    try {
      const path = this.parseRequiredPath(args);
      if (!Array.isArray(args.packets)) {
        throw new Error('packets must be an array');
      }

      const packets = args.packets.map((entry, index) => parsePcapPacketInput(entry, index));
      const endianness = parsePacketEndianness(args.endianness);
      const timestampPrecision = parseTimestampPrecision(args.timestampPrecision);
      const snapLength =
        args.snapLength === undefined ? 65535 : parsePositiveInteger(args.snapLength, 'snapLength');
      const linkType = parsePcapLinkType(args.linkType ?? 'ethernet', 'linkType');
      const buffer = buildClassicPcap({
        packets,
        endianness,
        timestampPrecision,
        snapLength,
        linkType,
      });
      await writeFile(path, buffer);
      this.emitEvent('protocol:pcap_written', {
        path,
        packetCount: packets.length,
        byteLength: buffer.length,
      });
      return {
        path,
        packetCount: packets.length,
        byteLength: buffer.length,
        endianness,
        timestampPrecision,
        linkType,
        success: true,
      };
    } catch (error) {
      return {
        path: typeof args.path === 'string' ? args.path : '',
        packetCount: 0,
        byteLength: 0,
        endianness: null,
        timestampPrecision: null,
        linkType: null,
        success: false,
        error: this.errorMessage(error),
      };
    }
  }

  async handlePcapRead(args: ToolArgs): Promise<{
    path: string;
    header: PcapHeader | null;
    packets: PcapPacketSummary[];
    success?: boolean;
    error?: string;
  }> {
    try {
      const path = this.parseRequiredPath(args);
      const maxPackets =
        args.maxPackets === undefined
          ? undefined
          : parsePositiveInteger(args.maxPackets, 'maxPackets');
      const maxBytesPerPacket =
        args.maxBytesPerPacket === undefined
          ? undefined
          : parsePositiveInteger(args.maxBytesPerPacket, 'maxBytesPerPacket');
      const buffer = await readFile(path);
      const { header, packets } = readClassicPcap(buffer, maxPackets, maxBytesPerPacket);
      this.emitEvent('protocol:pcap_read', {
        path,
        packetCount: packets.length,
      });
      return {
        path,
        header,
        packets,
        success: true,
      };
    } catch (error) {
      return {
        path: typeof args.path === 'string' ? args.path : '',
        header: null,
        packets: [],
        success: false,
        error: this.errorMessage(error),
      };
    }
  }

  protected parseRequiredPath(args: ToolArgs): string {
    if (typeof args.path !== 'string' || args.path.trim().length === 0) {
      throw new Error('path must be a non-empty string');
    }

    return args.path;
  }
}
