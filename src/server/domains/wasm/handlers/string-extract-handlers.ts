/**
 * wasm_string_extract — section-aware printable-string extraction for .wasm.
 *
 * Differs from binary-instrument's generic `binary_strings_extract` by being
 * wasm-aware: it parses the wasm section layout so every string is attributed
 * to its source section (data / code / import / export / custom), and recovers
 * function names from the custom "name" section — the primary anti-stripping /
 * deobfuscation artifact in a wasm module. Pure TS, no wabt dependency.
 */

import { readFile } from 'node:fs/promises';
import { argNumber, argStringRequired } from '@server/domains/shared/parse-args';
import { ExternalToolHandlersBase } from './external-base';

/** wasm section id → human name (index 0 is custom, resolved per-section). */
const SECTION_NAMES = [
  'custom',
  'type',
  'import',
  'function',
  'table',
  'memory',
  'global',
  'export',
  'start',
  'element',
  'code',
  'data',
  'datacount',
] as const;

export interface WasmSection {
  id: number;
  name: string;
  bodyStart: number;
  bodyEnd: number;
}

export interface WasmStringEntry {
  value: string;
  section: string;
  offset: number;
  categories: string[];
}

export interface WasmFunctionName {
  index: number;
  name: string;
}

export interface WasmStringResult {
  sectionCount: number;
  totalStrings: number;
  returnedStrings: number;
  truncated: boolean;
  functionNames: WasmFunctionName[];
  bySection: Record<string, number>;
  classified: Record<string, WasmStringEntry[]>;
  strings: WasmStringEntry[];
}

/** Read an unsigned LEB128 (wasm varuint32). Returns [value, nextOffset]. */
function readU32Leb128(bytes: Buffer, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let pos = offset;
  for (;;) {
    if (pos >= bytes.length) throw new Error('truncated LEB128');
    const byte = bytes[pos++]!;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 35) throw new Error('LEB128 exceeds u32 range');
  }
  return [result >>> 0, pos];
}

const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d]; // \0asm

/** Parse the wasm section directory. Throws on bad magic / truncated size. */
export function parseWasmSections(bytes: Buffer): WasmSection[] {
  if (
    bytes.length < 8 ||
    bytes[0] !== WASM_MAGIC[0] ||
    bytes[1] !== WASM_MAGIC[1] ||
    bytes[2] !== WASM_MAGIC[2] ||
    bytes[3] !== WASM_MAGIC[3]
  ) {
    throw new Error('Not a valid wasm binary (missing \\0asm magic header)');
  }
  const sections: WasmSection[] = [];
  let offset = 8; // skip magic + version
  while (offset < bytes.length) {
    const id = bytes[offset++]!;
    const [size, bodyStart] = readU32Leb128(bytes, offset);
    const bodyEnd = bodyStart + size;
    if (bodyEnd > bytes.length) {
      throw new Error(
        `Section ${id} declares ${size} bytes but only ${bytes.length - bodyStart} remain`,
      );
    }
    let name: string = SECTION_NAMES[id] ?? `section-${id}`;
    if (id === 0) {
      // custom section body starts with a name string (length-prefixed)
      try {
        const [nameLen, nameStart] = readU32Leb128(bytes, bodyStart);
        const customName = bytes.subarray(nameStart, nameStart + nameLen).toString('utf8');
        name = `custom:${customName || 'unnamed'}`;
      } catch {
        name = 'custom:unnamed';
      }
    }
    sections.push({ id, name, bodyStart, bodyEnd });
    offset = bodyEnd;
  }
  return sections;
}

/** Recover function names (name-section subsection 2) from a custom:name section. */
export function parseFunctionNames(
  bytes: Buffer,
  bodyStart: number,
  bodyEnd: number,
): WasmFunctionName[] {
  try {
    let pos = bodyStart;
    // skip the section name string ("name")
    const [nameLen, afterNameLen] = readU32Leb128(bytes, pos);
    pos = afterNameLen + nameLen;
    const names: WasmFunctionName[] = [];
    while (pos < bodyEnd) {
      const subId = bytes[pos++]!;
      const [subSize, subPayloadStart] = readU32Leb128(bytes, pos);
      const subEnd = subPayloadStart + subSize;
      pos = subEnd; // advance past this subsection regardless of parse success
      if (subId === 2) {
        let p = subPayloadStart;
        const [count, afterCount] = readU32Leb128(bytes, p);
        p = afterCount;
        for (let i = 0; i < count && p < subEnd; i++) {
          const [idx, afterIdx] = readU32Leb128(bytes, p);
          p = afterIdx;
          const [nl, afterNl] = readU32Leb128(bytes, p);
          p = afterNl;
          const name = bytes.subarray(p, p + nl).toString('utf8');
          p += nl;
          names.push({ index: idx, name });
        }
      }
    }
    return names;
  } catch {
    return [];
  }
}

/** Classify a string into high-value RE categories. */
export function classifyString(value: string): string[] {
  const cats: string[] = [];
  if (/^https?:\/\//i.test(value) || /^wss?:\/\//i.test(value)) cats.push('url');
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(value)) cats.push('ip');
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) cats.push('email');
  if (/^[0-9a-fA-F]{32,64}$/.test(value)) cats.push('hex-hash');
  if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(value)) cats.push('base64');
  if (
    /(?:^|[/\\])[\w.-]+\.(?:js|wasm|json|png|jpe?g|html?|css|so|dex|apk|proto|wat|pem|crt)(?:$|\?)/i.test(
      value,
    )
  ) {
    cats.push('file-path');
  }
  return cats;
}

function scanPrintableRuns(
  bytes: Buffer,
  start: number,
  end: number,
  minLength: number,
): Array<{ value: string; offset: number }> {
  const out: Array<{ value: string; offset: number }> = [];
  let runStart = -1;
  const flush = (rs: number, re: number): void => {
    if (re - rs >= minLength) {
      out.push({ value: bytes.subarray(rs, re).toString('latin1'), offset: rs });
    }
  };
  for (let i = start; i < end; i++) {
    const b = bytes[i]!;
    if (b >= 0x20 && b <= 0x7e) {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      flush(runStart, i);
      runStart = -1;
    }
  }
  if (runStart >= 0) flush(runStart, end);
  return out;
}

export interface ExtractWasmStringsOptions {
  minLength?: number;
  maxStrings?: number;
}

export function extractWasmStrings(
  bytes: Buffer,
  opts: ExtractWasmStringsOptions = {},
): WasmStringResult {
  const minLength = Math.max(1, opts.minLength ?? 4);
  const maxStrings = Math.max(1, opts.maxStrings ?? 200);
  const sections = parseWasmSections(bytes);

  const allStrings: WasmStringEntry[] = [];
  const bySection: Record<string, number> = {};
  let functionNames: WasmFunctionName[] = [];

  for (const section of sections) {
    if (section.name === 'custom:name') {
      functionNames = parseFunctionNames(bytes, section.bodyStart, section.bodyEnd);
    }
    const found = scanPrintableRuns(bytes, section.bodyStart, section.bodyEnd, minLength);
    if (found.length === 0) continue;
    bySection[section.name] = (bySection[section.name] ?? 0) + found.length;
    for (const s of found) {
      allStrings.push({
        value: s.value,
        section: section.name,
        offset: s.offset,
        categories: classifyString(s.value),
      });
    }
  }

  const classified: Record<string, WasmStringEntry[]> = {};
  for (const s of allStrings) {
    for (const cat of s.categories) {
      (classified[cat] ??= []).push(s);
    }
  }

  const truncated = allStrings.length > maxStrings;
  const returned = allStrings.slice(0, maxStrings);

  return {
    sectionCount: sections.length,
    totalStrings: allStrings.length,
    returnedStrings: returned.length,
    truncated,
    functionNames,
    bySection,
    classified,
    strings: returned,
  };
}

export class StringExtractHandlers extends ExternalToolHandlersBase {
  async handleWasmStringExtract(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const minLength = argNumber(args, 'minLength', 4);
    const maxStrings = argNumber(args, 'maxStrings', 200);

    let bytes: Buffer;
    try {
      bytes = await readFile(inputPath);
    } catch (error) {
      return this.fail(
        `Failed to read wasm file: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    try {
      const result = extractWasmStrings(bytes, { minLength, maxStrings });
      return this.ok({ inputPath, ...result });
    } catch (error) {
      return this.fail(error instanceof Error ? error.message : String(error));
    }
  }
}
