/**
 * ProtocolAnalysisFingerprintHandlers — protocol fingerprint heuristics.
 */

import { argStringArray } from '@server/domains/shared/parse-args';
import { asJsonResponse } from '@server/domains/shared/response';
import type { ToolArgs, ToolResponse } from '@server/types';
import {
  PROTO_HTTP_CONFIDENCE,
  PROTO_SSH_CONFIDENCE,
  PROTO_TLS_CONFIDENCE,
  PROTO_TLS_MIN_RECORD_LEN,
  PROTO_WS_CONFIDENCE,
} from '@src/constants';
import {
  HTTP_METHODS,
  isLikelyDnsHeader,
  parseDnsHeader,
  parseTlsClientHello,
  readU16,
  readU8,
  WS_OPCODES,
} from './fingerprint-utils';
import { ProtocolAnalysisPacketHandlers } from './packet-handlers';

export class ProtocolAnalysisFingerprintHandlers extends ProtocolAnalysisPacketHandlers {
  async handleProtoFingerprint(args: ToolArgs): Promise<ToolResponse> {
    const hexPayloads = argStringArray(args, 'hexPayloads');
    const includeKnown = args.includeKnownProtocols !== false;
    const includeHints = args.includeFieldHints !== false;

    if (hexPayloads.length === 0) {
      return asJsonResponse({ success: false, error: 'hexPayloads is required' });
    }

    const results = hexPayloads.map((hex, index) => {
      const clean = hex.replace(/\s/g, '');
      const matches: Array<{ protocol: string; layer: string; confidence: number }> = [];
      const actualBytes = clean.length / 2;
      const tlsRecordLen = actualBytes >= 5 ? readU16(clean, 3) : -1;
      const hasCompleteTlsRecord =
        Number.isFinite(tlsRecordLen) && tlsRecordLen >= 0 && actualBytes >= 5 + tlsRecordLen;
      const isTlsClientHello =
        hasCompleteTlsRecord &&
        tlsRecordLen >= PROTO_TLS_MIN_RECORD_LEN &&
        readU8(clean, 0) === 0x16 &&
        readU8(clean, 5) === 0x01;
      const isDns = isLikelyDnsHeader(clean);
      const isHttp = Object.keys(HTTP_METHODS).some((method) =>
        clean.toUpperCase().startsWith(method),
      );
      const isSsh = clean.toUpperCase().startsWith('5353482D');
      const isWs =
        clean.length >= 4 &&
        (() => {
          const b0 = readU8(clean, 0);
          const b1 = readU8(clean, 1);
          const opcode = b0 & 0x0f;
          if (opcode === 0) return false;

          const validOpcode = opcode <= 10 && !(opcode >= 3 && opcode <= 7);
          const masked = ((b1 >> 7) & 1) === 1;
          const wsByteCount = clean.length / 2;
          let payloadLen = b1 & 0x7f;
          let headerBytes = 2;

          if (payloadLen === 126) {
            if (wsByteCount < 4) return false;
            payloadLen = readU16(clean, 2);
            headerBytes = 4;
          } else if (payloadLen === 127) {
            if (wsByteCount < 10) return false;
            const hi32 = (readU16(clean, 2) << 16) | readU16(clean, 4);
            const lo32 = (readU16(clean, 6) << 16) | readU16(clean, 8);
            payloadLen = hi32 > 0 ? 0xffffffff : lo32;
            headerBytes = 10;
          }

          return validOpcode && wsByteCount >= headerBytes + (masked ? 4 : 0) + payloadLen;
        })();

      let deepParse: Record<string, unknown> | null = null;

      if (isTlsClientHello) {
        matches.push({
          protocol: 'TLS ClientHello',
          layer: 'L6-TLS',
          confidence: PROTO_TLS_CONFIDENCE,
        });
        if (includeHints) {
          deepParse = parseTlsClientHello(clean);
        }
      } else if (isHttp) {
        matches.push({
          protocol: 'HTTP/1.x',
          layer: 'L7-HTTP',
          confidence: PROTO_HTTP_CONFIDENCE,
        });
        if (includeHints) {
          const method =
            Object.entries(HTTP_METHODS).find(([prefix]) =>
              clean.toUpperCase().startsWith(prefix),
            )?.[1] ?? 'UNKNOWN';
          deepParse = {
            method,
            httpVersion: clean.indexOf('2048545450') > 0 ? '1.x' : 'unknown',
          };
        }
      } else if (isSsh) {
        matches.push({ protocol: 'SSH', layer: 'L7-SSH', confidence: PROTO_SSH_CONFIDENCE });
        if (includeHints && clean.length >= 20) {
          deepParse = {
            banner: Buffer.from(clean.substring(0, Math.min(clean.length, 80)), 'hex').toString(
              'ascii',
            ),
          };
        }
      } else if (isWs) {
        matches.push({ protocol: 'WebSocket', layer: 'L7-WS', confidence: PROTO_WS_CONFIDENCE });
        if (includeHints && clean.length >= 4) {
          const b0 = readU8(clean, 0);
          const b1 = readU8(clean, 1);
          const opcode = b0 & 0xf;
          const masked = (b1 >> 7) & 1;
          let payloadLen = b1 & 0x7f;
          let headerSize = 2;
          if (payloadLen === 126) {
            payloadLen = clean.length >= 4 ? readU16(clean, 2) : 0;
            headerSize = 4;
          } else if (payloadLen === 127) {
            if (clean.length >= 20) {
              const hi32 = (readU16(clean, 2) << 16) | readU16(clean, 4);
              const lo32 = (readU16(clean, 6) << 16) | readU16(clean, 8);
              payloadLen = hi32 > 0 ? 0xffffffff : lo32;
            } else {
              payloadLen = 0;
            }
            headerSize = 10;
          }
          if (masked) headerSize += 4;
          deepParse = {
            fin: (b0 >> 7) & 1,
            rsv1: (b0 >> 6) & 1,
            opcode,
            opcodeName: WS_OPCODES[opcode] ?? `reserved(${opcode})`,
            masked: !!masked,
            payloadLength: payloadLen,
            headerSize,
          };
        }
      } else if (isDns) {
        matches.push({ protocol: 'DNS', layer: 'L7-DNS', confidence: 0.85 });
        if (includeHints) {
          deepParse = parseDnsHeader(clean);
        }
      }

      if (includeKnown && matches.length === 0) {
        if (hasCompleteTlsRecord && /^160301|^160302|^160303/i.test(clean.substring(0, 8))) {
          matches.push({ protocol: 'TLS Record', layer: 'L6-TLS', confidence: 0.9 });
        }
        if (clean.substring(0, 8).startsWith('50524920')) {
          matches.push({ protocol: 'HTTP/2 PRI', layer: 'L7-HTTP2', confidence: 0.9 });
        }
      }

      const fieldHints: Array<{ offset: number; hint: string }> = [];
      if (includeHints && !deepParse && clean.length >= 8) {
        const first2 = readU16(clean, 0);
        if (first2 > 0 && first2 < clean.length / 2) {
          fieldHints.push({ offset: 0, hint: `possible length field (${first2} bytes)` });
        }
      }

      return {
        index,
        size: actualBytes,
        protocolMatches:
          matches.length > 0 ? matches : [{ protocol: 'unknown', layer: 'unknown', confidence: 0 }],
        ...(deepParse ? { parsedFields: deepParse } : {}),
        ...(fieldHints.length > 0 ? { fieldHints } : {}),
      };
    });

    return asJsonResponse({ success: true, fingerprints: results });
  }
}
