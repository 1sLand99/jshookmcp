import type { ConsoleMonitor } from '@server/domains/shared/modules/collector';
import { R } from '@server/domains/shared/ResponseBuilder';
import {
  argBool,
  argEnum,
  argNumber,
  argString,
  argStringArray,
  argStringRequired,
} from '@server/domains/shared/parse-args';
import { BOT_DETECT_LIMIT_DEFAULT } from '@src/constants';
import { toHex4, isGrease } from './fingerprint-utils';
import { computeTlsFingerprint } from './tls-fingerprint';
import { computeHttpFingerprint, normalizeObservedHttpVersion } from './http-fingerprint';
import { detectBotSignals } from './bot-detection';
import { computeJa3, computeJa4FromClientHello, parseClientHello } from './clienthello-parser';

const TLS_FINGERPRINT_MODES = new Set([
  'compute_tls',
  'compute_http',
  'analyze_request',
  'parse_client_hello',
] as const);
const TLS_PROTOCOLS = new Set(['tls', 'quic', 'dtls'] as const);

function getSecurityDetails(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : undefined;
}

interface BotDetectSample {
  requestId?: string;
  url?: string;
  method?: string;
  httpVersion?: string;
  headers?: Record<string, string>;
  securityDetails?: unknown;
}

interface BotDetectFingerprints {
  jaFingerprint:
    | { ja3?: string; ja4?: string; knownBadJa3?: string[]; knownBadJa4?: string[] }
    | undefined;
  h2Fingerprint: { hash?: string; knownBadH2?: string[] } | undefined;
}

interface BotDetectAccumulator {
  signals: string[];
  details: Array<Record<string, unknown>>;
  totalBotScore: number;
  httpFingerprints: Map<string, number>;
  uaDriftCount: number;
  headerOrderDriftCount: number;
}

/** Optional JA3/JA4 and HTTP/2 fingerprints. Empty input yields undefined. */
function readBotDetectFingerprints(args: Record<string, unknown>): BotDetectFingerprints {
  // Zero hardcoded library — the caller decides which hashes are "bot-like".
  const ja3 = argString(args, 'ja3', '');
  const ja4 = argString(args, 'ja4', '');
  const knownBadJa3 = argStringArray(args, 'knownBadJa3');
  const knownBadJa4 = argStringArray(args, 'knownBadJa4');
  const jaFingerprint =
    ja3 || ja4 || knownBadJa3.length || knownBadJa4.length
      ? {
          ja3: ja3 || undefined,
          ja4: ja4 || undefined,
          knownBadJa3: knownBadJa3.length ? knownBadJa3 : undefined,
          knownBadJa4: knownBadJa4.length ? knownBadJa4 : undefined,
        }
      : undefined;

  const h2Hash = argString(args, 'h2Hash', '');
  const knownBadH2 = argStringArray(args, 'knownBadH2');
  const h2Fingerprint =
    h2Hash || knownBadH2.length
      ? { hash: h2Hash || undefined, knownBadH2: knownBadH2.length ? knownBadH2 : undefined }
      : undefined;

  return { jaFingerprint, h2Fingerprint };
}

/** Score one captured request and fold it into the running tallies. */
function accumulateBotDetectRequest(
  req: BotDetectSample,
  fingerprints: BotDetectFingerprints,
  acc: BotDetectAccumulator,
  seenUserAgents: Map<string, string>,
  headerOrder: { baseline: string | null },
  includeDetails: boolean,
): void {
  const headers = req.headers || {};
  const headerNames = Object.keys(headers);
  const ua = headers['user-agent'] || headers['User-Agent'] || '';
  const url = req.url || '';
  const method = req.method || 'GET';
  const cookieHeader = headers['cookie'] || headers['Cookie'] || '';
  const acceptLanguage = headers['accept-language'] || headers['Accept-Language'] || '';
  const httpVersion = normalizeObservedHttpVersion(req.httpVersion);

  // securityDetails lives on NetworkResponse, but the ConsoleMonitor/Playwright
  // path may attach it to the request at runtime — probe reflectively.
  const secDetails = getSecurityDetails(req.securityDetails);
  const tlsSignalsForBot =
    secDetails && typeof secDetails === 'object'
      ? {
          cipherCount:
            typeof secDetails['cipherCount'] === 'number' ? secDetails['cipherCount'] : 5,
          extensionCount:
            typeof secDetails['extensionCount'] === 'number' ? secDetails['extensionCount'] : 10,
          tlsVersion: typeof secDetails['protocol'] === 'string' ? secDetails['protocol'] : '',
        }
      : undefined;
  const reqSignals = detectBotSignals(
    ua,
    headerNames,
    tlsSignalsForBot,
    fingerprints.jaFingerprint,
    fingerprints.h2Fingerprint,
  );

  const { http } = computeHttpFingerprint(
    method,
    headerNames,
    httpVersion,
    cookieHeader,
    acceptLanguage,
  );
  acc.httpFingerprints.set(http, (acc.httpFingerprints.get(http) ?? 0) + 1);

  if (seenUserAgents.has(http)) {
    if (seenUserAgents.get(http) !== ua) acc.uaDriftCount++;
  } else {
    seenUserAgents.set(http, ua);
  }
  if (headerOrder.baseline === null) {
    headerOrder.baseline = headerNames.join(',');
  } else if (headerNames.join(',') !== headerOrder.baseline) {
    acc.headerOrderDriftCount++;
  }

  acc.totalBotScore += reqSignals.score;
  if (reqSignals.score > 0.5) {
    acc.signals.push(`Request ${req.requestId}: ${reqSignals.signals.join(', ')}`);
  }

  if (includeDetails) {
    const reqDetail: Record<string, unknown> = {
      requestId: req.requestId,
      url: url.length > 100 ? url.substring(0, 100) + '...' : url,
      method,
      http,
      botScore: reqSignals.score,
      signals: reqSignals.signals,
    };
    if (/\/api\/|\/v\d+\/|\/graphql/i.test(url)) reqDetail.apiPattern = true;
    acc.details.push(reqDetail);
  }
}

/** Diversity and cross-request consistency verdicts derived from the tallies. */
function summarizeBotDetectSample(sampleSize: number, acc: BotDetectAccumulator) {
  const uniqueFingerprints = acc.httpFingerprints.size;
  const fingerprintDiversity = uniqueFingerprints / sampleSize;

  const diversitySignals: string[] = [];
  if (fingerprintDiversity > 0.8) {
    diversitySignals.push(
      `High fingerprint diversity (${uniqueFingerprints} unique HTTP fingerprints in ${sampleSize} requests) — ` +
        `may indicate multiple clients or rotation`,
    );
  }
  if (fingerprintDiversity === 1 && sampleSize > 5) {
    diversitySignals.push(
      `Every request has a unique HTTP fingerprint — likely automated tool rotating headers`,
    );
  }

  const interRequestSignals: string[] = [];
  if (acc.uaDriftCount > 0) {
    interRequestSignals.push(
      `${acc.uaDriftCount} request(s) with different UA for same HTTP fingerprint — UA drift detected`,
    );
  }
  if (acc.headerOrderDriftCount > 0) {
    interRequestSignals.push(
      `${acc.headerOrderDriftCount} request(s) with different header order — header rotation detected`,
    );
  }
  const consistencyScore =
    sampleSize > 1
      ? Math.max(0, 1 - (acc.uaDriftCount + acc.headerOrderDriftCount) / (sampleSize * 2))
      : 1.0;

  return {
    uniqueFingerprints,
    fingerprintDiversity,
    diversitySignals,
    interRequestSignals,
    consistencyScore,
  };
}

/** `compute_tls`: JA3-style fingerprint from caller-supplied cipher and extension lists. */
function fingerprintComputeTls(
  args: Record<string, unknown>,
  includeAnalysis: boolean,
): ReturnType<typeof R.ok> {
  const tlsVersions = argStringArray(args, 'tlsVersions');
  const ciphers = argStringArray(args, 'ciphers');
  const extensions = argStringArray(args, 'extensions');
  const signatureAlgorithms = argStringArray(args, 'signatureAlgorithms');
  const protocol = argEnum(args, 'protocol', TLS_PROTOCOLS, 'tls');
  const sni = argBool(args, 'sni', true);
  const alpn = argString(args, 'alpn', '');

  if (ciphers.length === 0) {
    return R.fail('ciphers array is required for compute_tls mode');
  }

  // Use the highest non-GREASE TLS version from the list.
  const nonGreaseVersions = tlsVersions.map(toHex4).filter((v) => !isGrease(v));
  const sortedVersions = nonGreaseVersions.toSorted();
  const tlsVersion =
    sortedVersions.length > 0 ? sortedVersions[sortedVersions.length - 1]! : '0303';

  const { tls, tls_raw } = computeTlsFingerprint({
    protocol,
    tlsVersion,
    hasSni: sni,
    ciphers,
    extensions,
    signatureAlgorithms,
    alpn,
  });

  const result: Record<string, unknown> = { success: true, mode: 'tls', tls, tls_raw };
  if (includeAnalysis) {
    const filteredCiphers = ciphers.map(toHex4).filter((c) => !isGrease(c));
    const filteredExts = extensions.map(toHex4).filter((e) => !isGrease(e));
    result.analysis = {
      protocol: protocol.toUpperCase(),
      tlsVersion,
      sni,
      cipherCount: filteredCiphers.length,
      extensionCount: filteredExts.length,
      signatureAlgorithmCount: signatureAlgorithms.length,
      alpn: alpn || '(none)',
      sortedCiphers: filteredCiphers.toSorted(),
      sortedExtensions: filteredExts.filter((e) => e !== '0000' && e !== '0010').toSorted(),
    };
  }
  return R.ok().merge(result);
}

/** `compute_http`: HTTP fingerprint from a caller-supplied header list. */
function fingerprintComputeHttp(
  args: Record<string, unknown>,
  includeAnalysis: boolean,
): ReturnType<typeof R.ok> {
  const headers = argStringArray(args, 'httpHeaders');
  const ua = argString(args, 'userAgent', '');
  const method = argString(args, 'httpMethod', 'GET');
  const httpVersion = argString(args, 'httpVersion', '1.1');
  const cookieHeader = argString(args, 'cookieHeader', '');
  const acceptLanguage = argString(args, 'acceptLanguage', '');

  if (headers.length === 0) {
    return R.fail('httpHeaders array is required for compute_http mode');
  }

  const { http } = computeHttpFingerprint(
    method,
    headers,
    httpVersion,
    cookieHeader,
    acceptLanguage,
  );
  const result: Record<string, unknown> = { success: true, mode: 'http', http };
  if (includeAnalysis) {
    const lowerHeaders = headers.map((h) => h.toLowerCase());
    result.analysis = {
      method,
      httpVersion,
      headerCount: headers.length,
      nonCookieRefererHeaders: lowerHeaders.filter((h) => h !== 'cookie' && h !== 'referer').length,
      hasCookie: lowerHeaders.includes('cookie'),
      hasAcceptLanguage: lowerHeaders.includes('accept-language'),
      sortedHeaders: lowerHeaders
        .filter((h) => h !== 'cookie' && h !== 'referer' && !h.startsWith(':'))
        .toSorted(),
      userAgentLength: ua.length,
    };
  }
  return R.ok().merge(result);
}

/**
 * `parse_client_hello`: JA3 (Salesforce MD5) and JA4 (FoxIO) from raw wire
 * bytes, so the fingerprint reflects the real handshake rather than whatever
 * cipher and extension arrays the caller passed in.
 */
function fingerprintParseClientHello(
  args: Record<string, unknown>,
  includeAnalysis: boolean,
): ReturnType<typeof R.ok> {
  const clientHelloHex = argStringRequired(args, 'clientHelloHex');
  const parsed = parseClientHello(clientHelloHex);
  if (!parsed.valid) {
    return R.fail(`Failed to parse ClientHello: ${parsed.error ?? 'unknown'}`);
  }
  const { ja3, ja3_raw } = computeJa3(parsed);
  const { ja4, ja4_raw } = computeJa4FromClientHello(parsed);
  const result: Record<string, unknown> = {
    success: true,
    mode: 'parse_client_hello',
    ja3,
    ja3_raw,
    ja4,
    ja4_raw,
    recordVersion: parsed.recordVersion,
    legacyVersion: parsed.legacyVersion,
    negotiatedVersion: parsed.negotiatedVersion,
    hasSni: parsed.hasSni,
    alpn: parsed.alpn,
  };
  if (includeAnalysis) {
    result.analysis = {
      ciphers: parsed.ciphers,
      ciphersCount: parsed.ciphers!.length,
      extensions: parsed.extensions!.map((e) => ({ type: e.type, length: e.data.length / 2 })),
      supportedVersions: parsed.supportedVersions,
      ellipticCurves: parsed.ellipticCurves,
      ecPointFormats: parsed.ecPointFormats,
      signatureAlgorithms: parsed.signatureAlgorithms,
      greaseCipherCount: parsed.ciphers!.filter((c) => isGrease(c)).length,
      greaseExtensionCount: parsed.extensions!.filter((e) => isGrease(e.type)).length,
    };
  }
  return R.ok().merge(result);
}

export class TlsBotHandlers {
  private consoleMonitor: ConsoleMonitor;

  constructor(deps: { consoleMonitor: ConsoleMonitor }) {
    this.consoleMonitor = deps.consoleMonitor;
  }

  async handleNetworkTlsFingerprint(args: Record<string, unknown>) {
    const modeRaw = argString(args, 'mode');
    const includeAnalysis = argBool(args, 'includeAnalysis', true);

    if (
      !modeRaw ||
      !TLS_FINGERPRINT_MODES.has(
        modeRaw as typeof TLS_FINGERPRINT_MODES extends Set<infer T> ? T : never,
      )
    ) {
      return R.fail(
        `Invalid mode: "${String(args['mode'])}". Expected one of: ${[...TLS_FINGERPRINT_MODES].join(', ')}`,
      ).json();
    }
    const mode = modeRaw;

    try {
      if (mode === 'compute_tls') {
        return fingerprintComputeTls(args, includeAnalysis).json();
      }

      if (mode === 'compute_http') {
        return fingerprintComputeHttp(args, includeAnalysis).json();
      }

      // parse_client_hello fingerprints the real handshake bytes rather than
      // re-hashing whatever cipher and extension arrays the caller passed in.
      if (mode === 'parse_client_hello') {
        return fingerprintParseClientHello(args, includeAnalysis).json();
      }

      // mode === 'analyze_request' (fallthrough after the compute modes)
      const requestId = argStringRequired(args, 'requestId');
      const requests = this.consoleMonitor.getNetworkRequests();
      const req = requests.find((r: { requestId?: string }) => r.requestId === requestId);
      if (!req) {
        return R.fail(`Request ${requestId} not found`).json();
      }
      const headers = req.headers || {};
      const headerNames = Object.keys(headers);
      const ua = headers['user-agent'] || headers['User-Agent'] || '';
      const method = req.method || 'GET';
      const cookieHeader = headers['cookie'] || headers['Cookie'] || '';
      const acceptLanguage = headers['accept-language'] || headers['Accept-Language'] || '';
      const httpVersion = normalizeObservedHttpVersion(req.httpVersion);
      const { http } = computeHttpFingerprint(
        method,
        headerNames,
        httpVersion,
        cookieHeader,
        acceptLanguage,
      );

      // NetworkRequest doesn't declare securityDetails at the type level (it
      // lives on NetworkResponse), but the ConsoleMonitor/Playwright path may
      // attach it to the request object at runtime — probe reflectively and
      // let getSecurityDetails narrow it.
      const secDetails = getSecurityDetails(
        (req as unknown as Record<string, unknown>)['securityDetails'],
      );
      const tlsSignalsForBot =
        secDetails && typeof secDetails === 'object'
          ? {
              cipherCount:
                typeof secDetails['cipherCount'] === 'number' ? secDetails['cipherCount'] : 5,
              extensionCount:
                typeof secDetails['extensionCount'] === 'number'
                  ? secDetails['extensionCount']
                  : 10,
              tlsVersion: typeof secDetails['protocol'] === 'string' ? secDetails['protocol'] : '',
            }
          : undefined;
      const result: Record<string, unknown> = {
        success: true,
        mode: 'analyze_request',
        requestId,
        url: req.url,
        method,
        httpVersion: httpVersion ?? 'unknown',
        http,
      };
      const analysis: Record<string, unknown> = {
        requestId,
        url: req.url,
        method,
        httpVersion: httpVersion ?? 'unknown',
        http,
        headerCount: headerNames.length,
        headerOrder: headerNames.join(', '),
        userAgent: ua.length > 80 ? ua.substring(0, 80) + '...' : ua,
        // Response-only headers stay undefined in request analysis.
        securityHeaders: {
          hasCSP: undefined,
          hasHSTS: undefined,
          hasCORS: undefined,
        },
        botSignals: detectBotSignals(ua, headerNames, tlsSignalsForBot),
      };

      if (includeAnalysis) {
        result.analysis = analysis;
      }

      return R.ok().merge(result).json();
    } catch (error) {
      return R.fail(error instanceof Error ? error.message : String(error)).json();
    }
  }

  async handleNetworkBotDetectAnalyze(args: Record<string, unknown>) {
    const limit = Math.max(
      1,
      Math.min(500, argNumber(args, 'limit', BOT_DETECT_LIMIT_DEFAULT) ?? BOT_DETECT_LIMIT_DEFAULT),
    );
    const includeDetails = argBool(args, 'includeDetails', false);
    const fingerprints = readBotDetectFingerprints(args);

    const requests = this.consoleMonitor.getNetworkRequests();
    const sample = requests.slice(0, limit) as BotDetectSample[];

    if (sample.length === 0) {
      return R.ok()
        .merge({
          analyzed: 0,
          summary: 'No captured requests to analyze. Enable network monitoring first.',
        })
        .json();
    }

    const acc: BotDetectAccumulator = {
      signals: [],
      details: [],
      totalBotScore: 0,
      httpFingerprints: new Map<string, number>(),
      uaDriftCount: 0,
      headerOrderDriftCount: 0,
    };
    const seenUserAgents = new Map<string, string>();
    const headerOrder: { baseline: string | null } = { baseline: null };
    for (const req of sample) {
      accumulateBotDetectRequest(
        req,
        fingerprints,
        acc,
        seenUserAgents,
        headerOrder,
        includeDetails,
      );
    }

    const avgBotScore = sample.length > 0 ? acc.totalBotScore / sample.length : 0;
    const summary = summarizeBotDetectSample(sample.length, acc);

    return R.ok()
      .merge({
        analyzed: sample.length,
        totalRequests: requests.length,
        averageBotScore: Math.round(avgBotScore * 100) / 100,
        suspiciousRequests: acc.signals.length,
        httpFingerprintSummary: {
          uniqueFingerprints: summary.uniqueFingerprints,
          diversity: Math.round(summary.fingerprintDiversity * 100) / 100,
          topFingerprints: [...acc.httpFingerprints.entries()]
            .toSorted((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([fp, count]) => ({ http_fingerprint: fp, count })),
        },
        signals: acc.signals.slice(0, 20),
        ...(summary.diversitySignals.length > 0
          ? { diversitySignals: summary.diversitySignals }
          : {}),
        interRequestConsistency: {
          consistencyScore: Math.round(summary.consistencyScore * 100) / 100,
          uaDriftCount: acc.uaDriftCount,
          headerOrderDriftCount: acc.headerOrderDriftCount,
          ...(summary.interRequestSignals.length > 0
            ? { signals: summary.interRequestSignals }
            : {}),
        },
        details: includeDetails ? acc.details : undefined,
        recommendations:
          avgBotScore > 0.5
            ? [
                'High bot-like signal detected. Consider TLS fingerprint rotation.',
                'Review User-Agent consistency across requests.',
                'Check header ordering matches real browser behavior.',
                'HTTP fingerprint diversity can distinguish botnets from real users.',
              ]
            : summary.fingerprintDiversity > 0.8
              ? ['Traffic appears human but fingerprint diversity is high — investigate further.']
              : ['Traffic appears to follow normal browser patterns.'],
      })
      .json();
  }
}
