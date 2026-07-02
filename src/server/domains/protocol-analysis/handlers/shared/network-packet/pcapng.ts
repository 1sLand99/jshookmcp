/**
 * PCAPNG (pcap-ng) format parser and builder.
 *
 * Implements the block-based capture container format described in
 * https://github.com/pcapng/pcapng/ (IETF draft). The format is a sequence of
 * blocks, each carrying a Block Type + Block Total Length + Body + trailing
 * Block Total Length. Byte order is determined per Section Header Block via the
 * Byte-Order Magic 0x1A2B3C4D.
 */

import type { PacketEndianness } from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Standard PCAPNG block type magic numbers. */
export const PCAPNG_BLOCK_TYPE = {
  SECTION_HEADER: 0x0a0d0d0a,
  INTERFACE_DESCRIPTION: 0x00000001,
  /** @deprecated Obsolete Packet Block, superseded by Enhanced Packet Block. */
  PACKET_OBSOLETE: 0x00000002,
  SIMPLE_PACKET: 0x00000003,
  NAME_RESOLUTION: 0x00000004,
  INTERFACE_STATISTICS: 0x00000005,
  ENHANCED_PACKET: 0x00000006,
} as const;

/** Byte-Order Magic inside every Section Header Block. */
export const PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;

const BLOCK_TYPE_NAMES: Record<number, string> = {
  [PCAPNG_BLOCK_TYPE.SECTION_HEADER]: 'SectionHeader',
  [PCAPNG_BLOCK_TYPE.INTERFACE_DESCRIPTION]: 'InterfaceDescription',
  [PCAPNG_BLOCK_TYPE.PACKET_OBSOLETE]: 'PacketObsolete',
  [PCAPNG_BLOCK_TYPE.SIMPLE_PACKET]: 'SimplePacket',
  [PCAPNG_BLOCK_TYPE.NAME_RESOLUTION]: 'NameResolution',
  [PCAPNG_BLOCK_TYPE.INTERFACE_STATISTICS]: 'InterfaceStatistics',
  [PCAPNG_BLOCK_TYPE.ENHANCED_PACKET]: 'EnhancedPacket',
};

/** PCAPNG option codes (subset relevant to dissection). */
const OPT_END_OF_OPT = 0;
const OPT_COMMENT = 1;
const OPT_IF_NAME = 2;
const OPT_IF_TSRESOL = 9;

/** Name Resolution Block record types. */
const NRB_RECORD_END = 0;
const NRB_RECORD_IPV4 = 1;
const NRB_RECORD_IPV6 = 2;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface PcapngOption {
  code: number;
  name: string;
  valueHex: string;
  /** Decoded text for comment/if_name options; undefined otherwise. */
  text?: string;
}

export interface PcapngSectionInfo {
  byteOrderMagic: number;
  endianness: PacketEndianness;
  majorVersion: number;
  minorVersion: number;
  /** 64-bit section length as an unsigned hex string (may exceed 2^53). */
  sectionLengthHex: string;
  sectionLengthUnspecified: boolean;
  options: PcapngOption[];
}

export interface PcapngInterfaceInfo {
  index: number;
  linkType: number;
  snapLen: number;
  options: PcapngOption[];
  name?: string;
  /** Timestamp resolution power (default 6 = microseconds when undefined). */
  tsresol?: number;
  tsresolBase2?: boolean;
}

export type PcapngPacketSummary = {
  index: number;
  blockIndex: number;
  kind: 'enhanced' | 'simple';
  interfaceId: number | null;
  timestampHigh: number | null;
  timestampLow: number | null;
  /** Full 64-bit timestamp as unsigned hex (high || low). */
  timestampHex: string | null;
  capturedLength: number;
  originalLength: number;
  dataHex: string;
  truncated: boolean;
};

export interface PcapngNameResolutionRecord {
  type: number;
  typeName: string;
  address: string;
  name: string;
}

export interface PcapngInterfaceStatistics {
  index: number;
  blockIndex: number;
  interfaceId: number;
  timestampHigh: number;
  timestampLow: number;
  timestampHex: string;
  options: PcapngOption[];
}

export interface PcapngUnknownBlock {
  blockIndex: number;
  type: number;
  typeName: string;
  totalLength: number;
  bodyHex: string;
}

export interface PcapngReadResult {
  endianness: PacketEndianness;
  sections: PcapngSectionInfo[];
  interfaces: PcapngInterfaceInfo[];
  packets: PcapngPacketSummary[];
  nameResolutionRecords: PcapngNameResolutionRecord[];
  interfaceStatistics: PcapngInterfaceStatistics[];
  unknownBlocks: PcapngUnknownBlock[];
  blockCount: number;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Write input types
// ---------------------------------------------------------------------------

export interface PcapngWriteInterface {
  linkType: number;
  snapLen?: number;
  name?: string;
}

export interface PcapngWritePacket {
  dataHex: string;
  interfaceId?: number;
  timestampHigh?: number;
  timestampLow?: number;
  originalLength?: number;
}

export interface PcapngWriteInput {
  endianness?: PacketEndianness;
  majorVersion?: number;
  minorVersion?: number;
  interfaces: PcapngWriteInterface[];
  packets: PcapngWritePacket[];
}

// ---------------------------------------------------------------------------
// Byte readers (endianness-aware)
// ---------------------------------------------------------------------------

function readU16(buffer: Buffer, offset: number, endian: PacketEndianness): number {
  return endian === 'little' ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function readU32(buffer: Buffer, offset: number, endian: PacketEndianness): number {
  return endian === 'little' ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function writeU16(buffer: Buffer, offset: number, value: number, endian: PacketEndianness): void {
  if (endian === 'little') {
    buffer.writeUInt16LE(value, offset);
  } else {
    buffer.writeUInt16BE(value, offset);
  }
}

function writeU32(buffer: Buffer, offset: number, value: number, endian: PacketEndianness): void {
  if (endian === 'little') {
    buffer.writeUInt32LE(value, offset);
  } else {
    buffer.writeUInt32BE(value, offset);
  }
}

function padTo4(n: number): number {
  return (n + 3) & ~3;
}

function blockTypeName(type: number): string {
  return BLOCK_TYPE_NAMES[type] ?? `Unknown(0x${type.toString(16).padStart(8, '0')})`;
}

// ---------------------------------------------------------------------------
// Options parser
// ---------------------------------------------------------------------------

function parseOptions(
  buffer: Buffer,
  start: number,
  end: number,
  endian: PacketEndianness,
  warnings: string[],
): PcapngOption[] {
  const options: PcapngOption[] = [];
  let offset = start;

  while (offset + 4 <= end) {
    const code = readU16(buffer, offset, endian);
    const length = readU16(buffer, offset + 2, endian);
    offset += 4;
    if (code === OPT_END_OF_OPT) {
      break;
    }
    if (offset + length > end) {
      warnings.push(`option code ${code} declares ${length} bytes but exceeds body bounds`);
      break;
    }
    const value = buffer.subarray(offset, offset + length);
    const entry: PcapngOption = {
      code,
      name: optionName(code),
      valueHex: value.toString('hex'),
    };
    if (code === OPT_COMMENT || code === OPT_IF_NAME) {
      entry.text = value.toString('utf8');
    }
    options.push(entry);
    offset = start + padTo4(offset + length - start);
  }

  return options;
}

function optionName(code: number): string {
  switch (code) {
    case OPT_COMMENT:
      return 'opt_comment';
    case OPT_IF_NAME:
      return 'if_name';
    case OPT_IF_TSRESOL:
      return 'if_tsresol';
    default:
      return `opt_${code}`;
  }
}

function buildOptions(entries: { code: number; value: Buffer }[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const header = Buffer.alloc(4);
    header.writeUInt16LE(entry.code, 0);
    header.writeUInt16LE(entry.value.length, 2);
    const paddedLength = padTo4(entry.value.length);
    const padded = Buffer.alloc(paddedLength);
    entry.value.copy(padded);
    parts.push(header, padded);
  }
  const endOpt = Buffer.alloc(4); // opt_endofopt (code=0, length=0)
  parts.push(endOpt);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// Block-level parsing
// ---------------------------------------------------------------------------

interface ParsedBlock {
  type: number;
  totalLength: number;
  bodyStart: number;
  bodyEnd: number;
}

function readBlockHeader(
  buffer: Buffer,
  offset: number,
  endian: PacketEndianness,
): ParsedBlock | null {
  if (offset + 8 > buffer.length) {
    return null;
  }
  const type = readU32(buffer, offset, endian);
  const totalLength = readU32(buffer, offset + 4, endian);
  if (totalLength < 12 || offset + totalLength > buffer.length) {
    return null;
  }
  const trailingLength = readU32(buffer, offset + totalLength - 4, endian);
  if (trailingLength !== totalLength) {
    return null;
  }
  return {
    type,
    totalLength,
    bodyStart: offset + 8,
    bodyEnd: offset + totalLength - 4,
  };
}

function detectEndianness(buffer: Buffer): PacketEndianness | null {
  if (buffer.length < 8) return null;
  // SHB block type 0x0A0D0D0A is endian-agnostic.
  const firstType = buffer.readUInt32BE(0);
  if (firstType !== PCAPNG_BLOCK_TYPE.SECTION_HEADER) return null;
  // The Byte-Order Magic at offset 8 reveals endianness.
  const bomBe = buffer.readUInt32BE(8);
  const bomLe = buffer.readUInt32LE(8);
  if (bomBe === PCAPNG_BYTE_ORDER_MAGIC) return 'big';
  if (bomLe === PCAPNG_BYTE_ORDER_MAGIC) return 'little';
  return null;
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

export interface PcapngParseOptions {
  maxPackets?: number;
  maxBytesPerPacket?: number;
  interfaceFilter?: number;
  /** When true, include raw bodyHex on every block (verbose). Default false. */
  includeRawBodies?: boolean;
}

export function parsePcapng(buffer: Buffer, options: PcapngParseOptions = {}): PcapngReadResult {
  const warnings: string[] = [];
  const endian = detectEndianness(buffer);
  if (endian === null) {
    throw new Error('Not a PCAPNG file: missing Section Header Block with valid Byte-Order Magic');
  }

  const result: PcapngReadResult = {
    endianness: endian,
    sections: [],
    interfaces: [],
    packets: [],
    nameResolutionRecords: [],
    interfaceStatistics: [],
    unknownBlocks: [],
    blockCount: 0,
    warnings,
  };

  let offset = 0;
  let packetIndex = 0;
  let interfaceIndex = 0;
  let currentEndian = endian;

  while (offset + 8 <= buffer.length) {
    const block = readBlockHeader(buffer, offset, currentEndian);
    if (block === null) {
      warnings.push(`truncated or malformed block at offset ${offset}`);
      break;
    }
    result.blockCount++;

    switch (block.type) {
      case PCAPNG_BLOCK_TYPE.SECTION_HEADER:
        currentEndian = parseSectionHeader(buffer, block, currentEndian, result, warnings);
        break;
      case PCAPNG_BLOCK_TYPE.INTERFACE_DESCRIPTION:
        parseInterfaceDescription(buffer, block, currentEndian, result, interfaceIndex);
        interfaceIndex++;
        break;
      case PCAPNG_BLOCK_TYPE.ENHANCED_PACKET:
        parseEnhancedPacket(buffer, block, currentEndian, result, packetIndex, options);
        packetIndex++;
        break;
      case PCAPNG_BLOCK_TYPE.SIMPLE_PACKET:
        parseSimplePacket(buffer, block, currentEndian, result, packetIndex, options);
        packetIndex++;
        break;
      case PCAPNG_BLOCK_TYPE.NAME_RESOLUTION:
        parseNameResolution(buffer, block, currentEndian, result, warnings);
        break;
      case PCAPNG_BLOCK_TYPE.INTERFACE_STATISTICS:
        parseInterfaceStatistics(buffer, block, currentEndian, result);
        break;
      default: {
        const body = buffer.subarray(block.bodyStart, block.bodyEnd);
        result.unknownBlocks.push({
          blockIndex: result.blockCount - 1,
          type: block.type,
          typeName: blockTypeName(block.type),
          totalLength: block.totalLength,
          bodyHex: body.toString('hex'),
        });
        if (block.type === PCAPNG_BLOCK_TYPE.PACKET_OBSOLETE) {
          warnings.push('obsolete Packet Block (type 0x02) encountered; use Enhanced Packet Block');
        }
      }
    }

    if (options.maxPackets !== undefined && result.packets.length >= options.maxPackets) {
      break;
    }
    offset += block.totalLength;
  }

  if (options.interfaceFilter !== undefined) {
    result.packets = result.packets.filter(
      (packet) => packet.kind === 'simple' || packet.interfaceId === options.interfaceFilter,
    );
  }

  return result;
}

function parseSectionHeader(
  buffer: Buffer,
  block: ParsedBlock,
  endian: PacketEndianness,
  result: PcapngReadResult,
  warnings: string[],
): PacketEndianness {
  const bom = readU32(buffer, block.bodyStart, endian);
  let resolvedEndian = endian;
  if (bom === PCAPNG_BYTE_ORDER_MAGIC) {
    resolvedEndian = endian;
  } else {
    // Re-check raw bytes in case the initial guess was wrong.
    const bomBe = buffer.readUInt32BE(block.bodyStart);
    if (bomBe === PCAPNG_BYTE_ORDER_MAGIC) {
      resolvedEndian = 'big';
    } else {
      resolvedEndian = 'little';
    }
    warnings.push(
      `Section Header Block byte-order magic mismatch (expected 0x${PCAPNG_BYTE_ORDER_MAGIC.toString(16)}, got 0x${bom.toString(16)})`,
    );
  }

  const majorVersion = readU16(buffer, block.bodyStart + 4, resolvedEndian);
  const minorVersion = readU16(buffer, block.bodyStart + 6, resolvedEndian);
  const sectionLengthHigh = readU32(buffer, block.bodyStart + 8, resolvedEndian);
  const sectionLengthLow = readU32(buffer, block.bodyStart + 12, resolvedEndian);
  const sectionLengthUnspecified =
    sectionLengthHigh === 0xffffffff && sectionLengthLow === 0xffffffff;
  const sectionLengthHex = sectionLengthUnspecified
    ? 'unspecified'
    : (sectionLengthHigh >>> 0).toString(16).padStart(8, '0') +
      (sectionLengthLow >>> 0).toString(16).padStart(8, '0');

  const optionsStart = block.bodyStart + 16;
  const options = parseOptions(buffer, optionsStart, block.bodyEnd, resolvedEndian, warnings);

  result.sections.push({
    byteOrderMagic: bom,
    endianness: resolvedEndian,
    majorVersion,
    minorVersion,
    sectionLengthHex,
    sectionLengthUnspecified,
    options,
  });

  return resolvedEndian;
}

function parseInterfaceDescription(
  buffer: Buffer,
  block: ParsedBlock,
  endian: PacketEndianness,
  result: PcapngReadResult,
  interfaceIndex: number,
): void {
  const linkType = readU16(buffer, block.bodyStart, endian);
  const snapLen = readU32(buffer, block.bodyStart + 4, endian);
  const options = parseOptions(buffer, block.bodyStart + 8, block.bodyEnd, endian, result.warnings);

  const entry: PcapngInterfaceInfo = {
    index: interfaceIndex,
    linkType,
    snapLen,
    options,
  };

  for (const option of options) {
    if (option.code === OPT_IF_NAME && option.text) {
      entry.name = option.text;
    } else if (option.code === OPT_IF_TSRESOL && option.valueHex.length >= 2) {
      const raw = Number.parseInt(option.valueHex.slice(0, 2), 16);
      entry.tsresolBase2 = (raw & 0x80) !== 0;
      entry.tsresol = raw & 0x7f;
    }
  }

  result.interfaces.push(entry);
}

function parseEnhancedPacket(
  buffer: Buffer,
  block: ParsedBlock,
  endian: PacketEndianness,
  result: PcapngReadResult,
  packetIndex: number,
  options: PcapngParseOptions,
): void {
  const interfaceId = readU32(buffer, block.bodyStart, endian);
  const timestampHigh = readU32(buffer, block.bodyStart + 4, endian);
  const timestampLow = readU32(buffer, block.bodyStart + 8, endian);
  const capturedLength = readU32(buffer, block.bodyStart + 12, endian);
  const originalLength = readU32(buffer, block.bodyStart + 16, endian);

  const dataStart = block.bodyStart + 20;
  const paddedCaptured = padTo4(capturedLength);
  if (dataStart + paddedCaptured > block.bodyEnd) {
    result.warnings.push(
      `Enhanced Packet Block ${packetIndex} declares ${capturedLength} captured bytes exceeding body`,
    );
    return;
  }

  const packetBytes = buffer.subarray(dataStart, dataStart + capturedLength);
  const limit = options.maxBytesPerPacket ?? packetBytes.length;
  const visibleLength = Math.min(limit, packetBytes.length);

  result.packets.push({
    index: packetIndex,
    blockIndex: result.blockCount - 1,
    kind: 'enhanced',
    interfaceId,
    timestampHigh,
    timestampLow,
    timestampHex: timestampToHex(timestampHigh, timestampLow),
    capturedLength,
    originalLength,
    dataHex: packetBytes.subarray(0, visibleLength).toString('hex'),
    truncated: visibleLength < packetBytes.length,
  });
}

function parseSimplePacket(
  buffer: Buffer,
  block: ParsedBlock,
  endian: PacketEndianness,
  result: PcapngReadResult,
  packetIndex: number,
  options: PcapngParseOptions,
): void {
  const originalLength = readU32(buffer, block.bodyStart, endian);
  const dataStart = block.bodyStart + 4;
  // Simple Packet Block packets fill the rest of the body (already 4-byte aligned).
  const available = block.bodyEnd - dataStart;
  const capturedLength = Math.min(originalLength, available);
  const packetBytes = buffer.subarray(dataStart, dataStart + capturedLength);
  const limit = options.maxBytesPerPacket ?? packetBytes.length;
  const visibleLength = Math.min(limit, packetBytes.length);

  result.packets.push({
    index: packetIndex,
    blockIndex: result.blockCount - 1,
    kind: 'simple',
    interfaceId: null,
    timestampHigh: null,
    timestampLow: null,
    timestampHex: null,
    capturedLength,
    originalLength,
    dataHex: packetBytes.subarray(0, visibleLength).toString('hex'),
    truncated: visibleLength < packetBytes.length,
  });
}

function parseNameResolution(
  buffer: Buffer,
  block: ParsedBlock,
  endian: PacketEndianness,
  result: PcapngReadResult,
  warnings: string[],
): void {
  let offset = block.bodyStart;
  while (offset + 4 <= block.bodyEnd) {
    const recordType = readU16(buffer, offset, endian);
    const recordLength = readU16(buffer, offset + 2, endian);
    offset += 4;
    if (recordType === NRB_RECORD_END) {
      break;
    }
    if (offset + recordLength > block.bodyEnd) {
      warnings.push('Name Resolution record exceeds block bounds');
      break;
    }
    const value = buffer.subarray(offset, offset + recordLength);
    const { address, name, typeName } = decodeNameResolutionRecord(recordType, value);
    result.nameResolutionRecords.push({ type: recordType, typeName, address, name });
    offset = block.bodyStart + padTo4(offset + recordLength - block.bodyStart);
  }
}

function decodeNameResolutionRecord(
  type: number,
  value: Buffer,
): { address: string; name: string; typeName: string } {
  if (type === NRB_RECORD_IPV4 && value.length >= 5) {
    const address = [value[0], value[1], value[2], value[3]].map((b) => String(b)).join('.');
    const name = stripAtNull(value.subarray(4).toString('utf8'));
    return { address, name, typeName: 'IPv4' };
  }
  if (type === NRB_RECORD_IPV6 && value.length >= 17) {
    const address = Array.from(value.subarray(0, 16))
      .map((b, i) =>
        i % 2 === 1
          ? `${value[i - 1]!.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`
          : '',
      )
      .filter(Boolean)
      .join(':');
    const name = stripAtNull(value.subarray(16).toString('utf8'));
    return { address, name, typeName: 'IPv6' };
  }
  return { address: value.toString('hex'), name: '', typeName: `type_${type}` };
}

/** Strip a trailing NUL-terminated C string down to its first NUL boundary. */
function stripAtNull(text: string): string {
  const nullIndex = text.indexOf('\u0000');
  return nullIndex >= 0 ? text.slice(0, nullIndex) : text;
}

function parseInterfaceStatistics(
  buffer: Buffer,
  block: ParsedBlock,
  endian: PacketEndianness,
  result: PcapngReadResult,
): void {
  const interfaceId = readU32(buffer, block.bodyStart, endian);
  const timestampHigh = readU32(buffer, block.bodyStart + 4, endian);
  const timestampLow = readU32(buffer, block.bodyStart + 8, endian);
  const options = parseOptions(
    buffer,
    block.bodyStart + 12,
    block.bodyEnd,
    endian,
    result.warnings,
  );
  result.interfaceStatistics.push({
    index: result.interfaceStatistics.length,
    blockIndex: result.blockCount - 1,
    interfaceId,
    timestampHigh,
    timestampLow,
    timestampHex: timestampToHex(timestampHigh, timestampLow),
    options,
  });
}

function timestampToHex(high: number, low: number): string {
  return (high >>> 0).toString(16).padStart(8, '0') + (low >>> 0).toString(16).padStart(8, '0');
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

function buildSectionHeader(
  endian: PacketEndianness,
  majorVersion: number,
  minorVersion: number,
): Buffer {
  // Fixed body: BOM(4) + version(4) + sectionLength(8) = 16 bytes.
  const body = Buffer.alloc(16);
  writeU32(body, 0, PCAPNG_BYTE_ORDER_MAGIC, endian);
  writeU16(body, 4, majorVersion, endian);
  writeU16(body, 6, minorVersion, endian);
  // Section length unspecified (0xFFFFFFFFFFFFFFFF).
  writeU32(body, 8, 0xffffffff, endian);
  writeU32(body, 12, 0xffffffff, endian);
  return wrapBlock(PCAPNG_BLOCK_TYPE.SECTION_HEADER, body, endian);
}

function buildInterfaceDescription(entry: PcapngWriteInterface, endian: PacketEndianness): Buffer {
  const optionEntries: { code: number; value: Buffer }[] = [];
  if (entry.name) {
    optionEntries.push({ code: OPT_IF_NAME, value: Buffer.from(entry.name, 'utf8') });
  }
  const options = buildOptions(optionEntries);
  const body = Buffer.alloc(8 + options.length);
  writeU16(body, 0, entry.linkType, endian);
  writeU16(body, 2, 0, endian); // reserved
  writeU32(body, 4, entry.snapLen ?? 0x00040000, endian); // default 262144
  options.copy(body, 8);
  return wrapBlock(PCAPNG_BLOCK_TYPE.INTERFACE_DESCRIPTION, body, endian);
}

function buildEnhancedPacket(packet: PcapngWritePacket, endian: PacketEndianness): Buffer {
  const data = Buffer.from(packet.dataHex.replace(/\s+/g, ''), 'hex');
  const paddedDataLength = padTo4(data.length);
  // Fixed header: interfaceId(4) + tsHigh(4) + tsLow(4) + capturedLen(4) + originalLen(4) = 20 bytes.
  const body = Buffer.alloc(20 + paddedDataLength);
  writeU32(body, 0, packet.interfaceId ?? 0, endian);
  writeU32(body, 4, packet.timestampHigh ?? 0, endian);
  writeU32(body, 8, packet.timestampLow ?? 0, endian);
  writeU32(body, 12, data.length, endian);
  writeU32(body, 16, packet.originalLength ?? data.length, endian);
  data.copy(body, 20);
  return wrapBlock(PCAPNG_BLOCK_TYPE.ENHANCED_PACKET, body, endian);
}

function wrapBlock(type: number, body: Buffer, endian: PacketEndianness): Buffer {
  const totalLength = 8 + body.length + 4;
  const header = Buffer.alloc(8);
  writeU32(header, 0, type, endian);
  writeU32(header, 4, totalLength, endian);
  const trailer = Buffer.alloc(4);
  writeU32(trailer, 0, totalLength, endian);
  return Buffer.concat([header, body, trailer]);
}

export function buildPcapng(input: PcapngWriteInput): Buffer {
  if (input.interfaces.length === 0) {
    throw new Error('at least one interface is required');
  }
  const endian: PacketEndianness = input.endianness === 'big' ? 'big' : 'little';
  const major = input.majorVersion ?? 1;
  const minor = input.minorVersion ?? 0;

  const parts: Buffer[] = [buildSectionHeader(endian, major, minor)];
  for (const entry of input.interfaces) {
    parts.push(buildInterfaceDescription(entry, endian));
  }
  for (const packet of input.packets) {
    parts.push(buildEnhancedPacket(packet, endian));
  }
  return Buffer.concat(parts);
}
