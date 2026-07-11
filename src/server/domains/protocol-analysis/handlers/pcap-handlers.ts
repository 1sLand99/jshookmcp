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
  parsePcapng,
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
    format: 'pcap' | 'pcapng';
    header: PcapHeader | null;
    packets: PcapPacketSummary[];
    endianness?: string | null;
    blockCount?: number;
    warnings?: string[];
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
      // Auto-detect PCAPNG (Section Header Block magic 0x0a0d0d0a at byte 0)
      // and dispatch transparently — the file extension is unreliable and this
      // is the most common user mistake (research #5).
      if (buffer.length >= 4 && buffer.readUInt32BE(0) === 0x0a0d0d0a) {
        const offloadPacket = (hex: string, packetIndex: number): string =>
          this.detailedDataManager.store({ packetIndex, hex });
        const result = parsePcapng(buffer, {
          maxPackets,
          maxBytesPerPacket,
          offloadPacket,
        });
        this.emitEvent('protocol:pcap_read', {
          path,
          packetCount: result.packets.length,
        });
        return {
          path,
          format: 'pcapng',
          header: null,
          packets: result.packets as unknown as PcapPacketSummary[],
          endianness: result.endianness,
          blockCount: result.blockCount,
          warnings: result.warnings,
          success: true,
        };
      }
      const { header, packets } = readClassicPcap(buffer, maxPackets, maxBytesPerPacket);
      this.emitEvent('protocol:pcap_read', {
        path,
        packetCount: packets.length,
      });
      return {
        path,
        format: 'pcap',
        header,
        packets,
        success: true,
      };
    } catch (error) {
      return {
        path: typeof args.path === 'string' ? args.path : '',
        format: 'pcap',
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
