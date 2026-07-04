/**
 * Coverage tests for MinidumpParser.parseMinidump — exercises file-read errors,
 * the header signature check, the stream-directory loop, and best-effort
 * stream-skip via synthesized minidump buffers (readFileSync mocked).
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockReadFileSync = vi.fn();

vi.mock('node:fs', () => ({
  readFileSync: (p: string) => mockReadFileSync(p),
}));

import { parseMinidump } from '@native/MinidumpParser';

beforeEach(() => {
  mockReadFileSync.mockReset();
});

/** Build a 32-byte MINIDUMP_HEADER with the given streamCount + directory RVA. */
function header(streamCount: number, streamDirRva: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(0x504d444d, 0); // 'MDMP' signature (bytes 0-3)
  b.writeUInt16LE(0xa793, 4); // versionLo (bytes 4-5)
  b.writeUInt16LE(0x0000, 6); // versionHi (bytes 6-7)
  b.writeUInt32LE(streamCount, 8); // bytes 8-11
  b.writeUInt32LE(streamDirRva, 12); // bytes 12-15
  // checksum(16) + timestamp(20) + flags(24, 8 bytes) stay zero
  return b;
}

/** One stream-directory entry: streamType(4) + size(4) + locationRva(4) = 12 bytes. */
function dirEntry(streamType: number, size: number, locationRva: number): Buffer {
  const b = Buffer.alloc(12);
  b.writeUInt32LE(streamType, 0);
  b.writeUInt32LE(size, 4);
  b.writeUInt32LE(locationRva, 8);
  return b;
}

describe('parseMinidump — file read + header validation', () => {
  it('returns a structured error when the file cannot be read', () => {
    mockReadFileSync.mockImplementation(() => {
      throw new Error('ENOENT');
    });
    const r = parseMinidump('/nope.dmp');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/Cannot read file/);
    expect(r.filePath).toBe('/nope.dmp');
  });

  it('rejects a buffer with the wrong signature', () => {
    const bad = Buffer.alloc(32);
    bad.writeUInt32LE(0xdeadbeef, 0);
    mockReadFileSync.mockReturnValue(bad);
    const r = parseMinidump('/bad.dmp');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/bad signature/);
  });

  it('parses a valid header with zero streams (empty summary)', () => {
    // Header points stream dir at offset 32 (right after header); 0 streams.
    mockReadFileSync.mockReturnValue(header(0, 32));
    const r = parseMinidump('/empty.dmp');
    expect(r.success).toBe(true);
    expect(r.streamCount).toBe(0);
    expect(r.streams).toEqual([]);
    expect(r.modules).toEqual([]);
    expect(r.threads).toEqual([]);
    expect(r.memoryRanges).toEqual([]);
    expect(r.hasMemory64).toBe(false);
    expect(r.fileSize).toBe(32);
  });

  it('catches a truncated header and returns the thrown error', () => {
    mockReadFileSync.mockReturnValue(Buffer.from([0x4d, 0x44, 0x4d, 0x50])); // sig OK, rest missing
    const r = parseMinidump('/trunc.dmp');
    // readU16 past end → throws → caught → success=false with message
    expect(r.success).toBe(false);
    expect(r.error).toBeDefined();
  });
});

describe('parseMinidump — stream directory loop', () => {
  it('reads the stream directory entries with their type names', () => {
    const buf = Buffer.concat([
      header(2, 32),
      dirEntry(7, 0, 9999), // SystemInfoStream — invalid RVA → parseStream throws → skipped
      dirEntry(99, 0, 9999), // Unknown stream type
    ]);
    mockReadFileSync.mockReturnValue(buf);

    const r = parseMinidump('/streams.dmp');
    expect(r.success).toBe(true);
    expect(r.streamCount).toBe(2);
    expect(r.streams).toHaveLength(2);
    expect(r.streams[0]?.streamName).toBe('SystemInfoStream');
    expect(r.streams[1]?.streamName).toBe('Unknown(99)');
    // parseStream failures are best-effort (caught), so overall success stays true
  });

  it('parses a SystemInfoStream when the location is valid', () => {
    // Minimal SystemInfo layout per MINIDUMP_SYSTEM_INFO:
    //   processorArch(u16) + level(u16) + revision(u16) + numCpus(u8) +
    //   productType(u8) + major(u32) + minor(u32) + build(u32) + platformId(u32)
    //   + csdVersionRva(u32) + csdVersion (UTF-16LE string at csd offset)
    const sysInfo = Buffer.alloc(56);
    sysInfo.writeUInt16LE(9, 0); // x64
    sysInfo.writeUInt16LE(15, 2); // level
    sysInfo.writeUInt16LE(0x100, 4); // revision
    sysInfo.writeUInt8(4, 6); // 4 CPUs
    sysInfo.writeUInt8(1, 7); // productType
    sysInfo.writeUInt32LE(10, 8); // major
    sysInfo.writeUInt32LE(0, 12); // minor
    sysInfo.writeUInt32LE(19045, 16); // build
    sysInfo.writeUInt32LE(2, 20); // platformId (VER_PLATFORM_WIN32_NT)
    sysInfo.writeUInt32LE(0, 24); // csdVersionRva (0 = empty)

    const dirOffset = 32;
    const sysInfoOffset = dirOffset + 12; // right after one dir entry
    const buf = Buffer.concat([
      header(1, dirOffset),
      dirEntry(7, sysInfo.length, sysInfoOffset),
      sysInfo,
    ]);
    mockReadFileSync.mockReturnValue(buf);

    const r = parseMinidump('/sysinfo.dmp');
    expect(r.success).toBe(true);
    expect(r.systemInfo).toBeDefined();
    expect(r.systemInfo?.processorArchitecture).toBe('x64');
    expect(r.systemInfo?.numberOfProcessors).toBe(4);
    expect(r.systemInfo?.buildNumber).toBe(19045);
  });
});
