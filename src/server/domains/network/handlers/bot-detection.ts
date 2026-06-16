export function detectBotSignals(
  ua: string,
  headerNames: string[],
  tlsSignals?: { cipherCount: number; extensionCount: number; tlsVersion: string },
): { score: number; signals: string[] } {
  const signals: string[] = [];
  let score = 0;

  if (!ua || ua.length === 0) {
    signals.push('missing-user-agent');
    score += 0.3;
  } else {
    const botPatterns =
      /bot|crawler|spider|headless|selenium|puppeteer|playwright|phantom|curl|wget|python|java|go-http|httpclient|okhttp|requests\/|aiohttp|axios|node-fetch|undici/i;
    if (botPatterns.test(ua)) {
      signals.push(`bot-ua: ${ua.substring(0, 40)}`);
      score += 0.5;
    }
    if (/headless/i.test(ua)) {
      signals.push('headless-browser');
      score += 0.4;
    }
    // Real browsers have long, detailed UA strings
    if (ua.length < 30 && !/bot|curl|wget|python/i.test(ua)) {
      signals.push('suspiciously-short-ua');
      score += 0.2;
    }
  }

  const lowerHeaders = headerNames.map((h) => h.toLowerCase());
  if (!lowerHeaders.includes('accept')) {
    signals.push('missing-accept-header');
    score += 0.15;
  }
  if (!lowerHeaders.includes('accept-language')) {
    signals.push('missing-accept-language');
    score += 0.1;
  }
  if (!lowerHeaders.includes('accept-encoding')) {
    signals.push('missing-accept-encoding');
    score += 0.1;
  }

  const headerCount = headerNames.length;
  if (headerCount < 4) {
    signals.push(`suspicious-few-headers: ${headerCount}`);
    score += 0.2;
  }

  // TLS-based signals (per arxiv 2602.09606 — bot detection via TLS fingerprints)
  if (tlsSignals) {
    // Real Chrome/Firefox browsers have 5-15 cipher suites
    if (tlsSignals.cipherCount <= 2) {
      signals.push(
        `anomalous-cipher-count: ${tlsSignals.cipherCount} (real browsers typically 5-15)`,
      );
      score += 0.3;
    }
    // Real browsers have many extensions (10-25+)
    if (tlsSignals.extensionCount < 5) {
      signals.push(`few-tls-extensions: ${tlsSignals.extensionCount} (real browsers 10-25+)`);
      score += 0.2;
    }
    // TLS 1.0/1.1 is rare for modern browsers
    if (/\bTLS\s*1\.[01]\b|\b1\.0\b|\b1\.1\b|\bSSL/i.test(tlsSignals.tlsVersion)) {
      signals.push(`outdated-tls-version: ${tlsSignals.tlsVersion}`);
      score += 0.25;
    }
  }

  // Header ordering signal: real browsers send headers in consistent order
  const expectedBrowserOrder = [
    'host',
    'connection',
    'cache-control',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'upgrade-insecure-requests',
    'user-agent',
    'accept',
    'sec-fetch-site',
    'sec-fetch-mode',
    'sec-fetch-user',
    'sec-fetch-dest',
    'referer',
    'accept-encoding',
    'accept-language',
  ];
  if (lowerHeaders.length >= 5) {
    const orderMatchCount = lowerHeaders
      .slice(0, 5)
      .filter((h, i) => h === expectedBrowserOrder[i]).length;
    if (orderMatchCount === 0) {
      signals.push('header-order-does-not-match-known-browser');
      score += 0.1;
    }
  }

  return { score: Math.min(score, 1.0), signals };
}
