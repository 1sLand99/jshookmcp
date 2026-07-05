/**
 * BoringsslInspectorTlsHandlers — keylog and TLS parsing helpers.
 */

import {
  decryptPayload as decryptPayloadFunc,
  disableKeyLog,
  enableKeyLog,
  getKeyLogFilePath,
  lookupSecret as lookupSecretEntry,
  parseKeyLog as parseKeyLogEntries,
  summarizeKeyLog as summarizeKeyLogEntries,
} from '@modules/boringssl-inspector';
import { argString } from '@server/domains/shared/parse-args';
import { asJsonResponse } from '@server/domains/shared/response';
import type { ToolResponse } from '@server/types';
import {
  contentTypeName,
  normalizeHex,
  parseCertificateChain,
  parseClientHello,
  tlsVersionName,
} from './shared';
import { BoringsslInspectorBaseHandlers } from './base';

export class BoringsslInspectorTlsHandlers extends BoringsslInspectorBaseHandlers {
  async handleTlsKeylogEnable(_args: Record<string, unknown>): Promise<unknown> {
    const keyLogPath = await this.keyLogExtractor.enableKeyLog();
    return {
      enabled: true,
      keyLogPath,
      environmentVariable: 'SSLKEYLOGFILE',
    };
  }

  async handleTlsKeylogDisable(args: Record<string, unknown>): Promise<unknown> {
    const path = argString(args, 'path') ?? null;
    if (path) {
      await this.keyLogExtractor.disableKeyLog();
    } else {
      disableKeyLog();
    }
    return {
      disabled: true,
      previousPath: path ?? getKeyLogFilePath(),
    };
  }

  async handleTlsKeylogParse(args: Record<string, unknown>): Promise<unknown> {
    const path = argString(args, 'path') ?? null;
    const entries = this.keyLogExtractor.parseKeyLog(path ?? undefined);
    const summary = this.keyLogExtractor.summarizeKeyLog(path ?? undefined);

    return {
      path: path ?? this.keyLogExtractor.getKeyLogFilePath(),
      entries,
      summary,
    };
  }

  async handleTlsDecryptPayload(args: Record<string, unknown>): Promise<unknown> {
    const encryptedHex = argString(args, 'encryptedHex') ?? null;
    const keyHex = argString(args, 'keyHex') ?? null;
    const nonceHex = argString(args, 'nonceHex') ?? null;
    const algorithm = argString(args, 'algorithm') ?? 'aes-256-gcm';
    const authTagHex = argString(args, 'authTagHex') ?? null;

    if (!encryptedHex || !keyHex || !nonceHex) {
      return { ok: false, error: 'encryptedHex, keyHex, and nonceHex are required' };
    }

    const decrypted = decryptPayloadFunc(
      encryptedHex,
      keyHex,
      nonceHex,
      algorithm,
      authTagHex ?? undefined,
    );
    return {
      ok: true,
      algorithm,
      decrypted,
      isFailed: decrypted.startsWith('DECRYPTION_FAILED:'),
    };
  }

  async handleTlsKeylogSummarize(args: Record<string, unknown>): Promise<unknown> {
    const content = argString(args, 'content') ?? null;
    if (content) {
      const entries = parseKeyLogEntries(content);
      return summarizeKeyLogEntries(entries);
    }

    this.keyLogExtractor.parseKeyLog();
    return this.keyLogExtractor.summarizeKeyLog();
  }

  async handleTlsKeylogLookupSecret(args: Record<string, unknown>): Promise<unknown> {
    const clientRandom = argString(args, 'clientRandom') ?? null;
    const label = argString(args, 'label') ?? undefined;

    if (!clientRandom) {
      return { ok: false, error: 'clientRandom is required' };
    }

    const cached = this.keyLogExtractor.lookupSecret(clientRandom);
    if (cached) {
      return { ok: true, clientRandom: normalizeHex(clientRandom), secret: cached };
    }

    const secret = lookupSecretEntry(this.keyLogExtractor.parseKeyLog(), clientRandom, label);
    return {
      ok: secret !== null,
      clientRandom: normalizeHex(clientRandom),
      secret: secret ?? null,
    };
  }

  async handleTlsCertPinBypass(args: Record<string, unknown>): Promise<unknown> {
    const target = argString(args, 'target') ?? null;
    if (target !== 'android' && target !== 'ios' && target !== 'desktop') {
      return {
        error: 'target must be one of android, ios, or desktop',
      };
    }

    const strategyByTarget: Record<'android' | 'ios' | 'desktop', string> = {
      android: 'hook-trust-manager',
      ios: 'replace-sec-trust-evaluation',
      desktop: 'patch-custom-verifier',
    };

    const instructionsByTarget: Record<'android' | 'ios' | 'desktop', string[]> = {
      android: [
        'Inject a Frida script that overrides X509TrustManager checks.',
        'Re-run the target flow after SSLKEYLOGFILE capture is enabled.',
      ],
      ios: [
        'Hook SecTrustEvaluateWithError and return success for the target session.',
        'Collect TLS keys after the app resumes the failing request.',
      ],
      desktop: [
        'Patch the custom verifier callback or disable pin comparison in the client.',
        'Capture a fresh handshake after the patched build starts.',
      ],
    };

    return {
      bypassStrategy: strategyByTarget[target],
      affectedDomains: ['*'],
      instructions: instructionsByTarget[target],
    };
  }

  async handleParseHandshake(args: Record<string, unknown>): Promise<ToolResponse> {
    const rawHex = argString(args, 'rawHex') ?? null;
    if (!rawHex) {
      return asJsonResponse({
        success: false,
        error: 'rawHex is required',
      });
    }

    const normalizedHex = normalizeHex(rawHex);
    if (!/^(?:[0-9a-f]{2})+$/i.test(normalizedHex)) {
      return asJsonResponse({
        success: false,
        error: 'Invalid hex payload',
      });
    }

    const record = Buffer.from(normalizedHex, 'hex');
    if (record.length < 5) {
      return asJsonResponse({
        success: false,
        error: 'TLS record is too short',
      });
    }

    const contentType = record[0]!;
    const versionMajor = record[1]!;
    const versionMinor = record[2]!;
    const declaredLength = record.readUInt16BE(3);
    const payload = record.subarray(5);

    const clientHello =
      contentType === 0x16 && payload.length > 0 && payload[0] === 1
        ? parseClientHello(payload)
        : undefined;

    // Note: this tool no longer attempts in-line decryption. The previous
    // `decrypt:true` path called a no-op stub that returned the ciphertext
    // unchanged (silently misleading). For payload decryption, use the
    // `tls_decrypt_payload` tool with explicit keyHex + nonceHex + authTagHex.
    return asJsonResponse({
      success: true,
      record: {
        contentType,
        contentTypeName: contentTypeName(contentType),
        version: tlsVersionName(versionMajor, versionMinor),
        declaredLength,
        actualLength: payload.length,
      },
      handshake: {
        version: tlsVersionName(versionMajor, versionMinor),
        contentType: contentTypeName(contentType),
        ...(clientHello
          ? {
              type: 'client_hello',
              serverName: clientHello.serverName,
              cipherSuites: clientHello.cipherSuites,
              extensions: clientHello.extensions,
            }
          : {
              cipherSuite: [],
              extensions: [],
            }),
      },
      sni: clientHello?.serverName ? { serverName: clientHello.serverName } : undefined,
    });
  }

  async handleKeyLogEnable(args: Record<string, unknown>): Promise<ToolResponse> {
    const filePath = argString(args, 'filePath') ?? '/tmp/sslkeylog.log';
    enableKeyLog(filePath);
    void this.eventBus?.emit('tls:keylog_started', {
      filePath,
      timestamp: new Date().toISOString(),
    });
    return asJsonResponse({
      success: true,
      filePath,
      currentFilePath: getKeyLogFilePath(),
    });
  }

  async handleCipherSuites(args: Record<string, unknown>): Promise<ToolResponse> {
    const filter = argString(args, 'filter') ?? null;
    const allSuites = [
      'TLS_AES_128_GCM_SHA256',
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_CCM_SHA256',
      'TLS_AES_128_CCM_8_SHA256',
      'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
      'TLS_RSA_WITH_AES_128_GCM_SHA256',
      'TLS_RSA_WITH_AES_256_GCM_SHA384',
    ];
    const filteredSuites = filter ? allSuites.filter((suite) => suite.includes(filter)) : allSuites;
    return asJsonResponse({
      success: true,
      filter,
      total: filteredSuites.length,
      suites: filteredSuites,
    });
  }

  async handleParseCertificate(args: Record<string, unknown>): Promise<ToolResponse> {
    const rawHex = argString(args, 'rawHex') ?? null;
    if (!rawHex) {
      return asJsonResponse({
        success: false,
        error: 'rawHex is required',
      });
    }

    const certs = parseCertificateChain(rawHex);
    return asJsonResponse({
      success: true,
      certificateCount: certs.length,
      fingerprints: certs.map((cert) => ({
        sha256: cert.sha256,
        length: cert.length,
      })),
    });
  }
}
