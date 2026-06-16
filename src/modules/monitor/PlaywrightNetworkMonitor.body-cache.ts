import { logger } from '@utils/logger';

export class ResponseBodyCache {
  private cache = new Map<string, { body: string; base64Encoded: boolean }>();
  private maxEntries: number;

  constructor(maxEntries = 200) {
    this.maxEntries = maxEntries;
  }

  setMaxEntries(max: number): void {
    this.maxEntries = max;
  }

  set(
    requestId: string,
    body: string,
    base64Encoded: boolean,
    mimeType: string,
    sizeBytes: number,
  ): void {
    if (sizeBytes > 1_048_576) {
      logger.debug(`[PW-BodyCache] Skipping oversized body for ${requestId} (${sizeBytes} bytes)`);
      return;
    }

    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }

    this.cache.set(requestId, { body, base64Encoded });
    logger.debug(`[PW-BodyCache] Cached body for ${requestId} (${sizeBytes} bytes)`);
  }

  get(requestId: string): { body: string; base64Encoded: boolean } | null {
    const cached = this.cache.get(requestId);
    if (cached) {
      // LRU refresh: move to end
      this.cache.delete(requestId);
      this.cache.set(requestId, cached);
      logger.debug(`[PW-BodyCache] Cache hit for ${requestId}`);
      return cached;
    }
    logger.warn(`getResponseBody: no cached body for ${requestId} in Playwright mode`);
    return null;
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

export function isTextMimeType(mimeType: string): boolean {
  return /^(text\/|application\/(json|javascript|xml|x-www-form-urlencoded))/i.test(mimeType);
}
