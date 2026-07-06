import { writeFile } from 'node:fs/promises';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { resolveArtifactPath } from '@utils/artifacts';
import { StreamingToolHandlers } from '@server/domains/streaming/handlers';
import { parseJson } from '@tests/server/domains/shared/mock-factories';
import { TEST_URLS, TEST_WS_URLS, withPath } from '@tests/shared/test-urls';

vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@utils/artifacts', () => ({
  resolveArtifactPath: vi.fn(async ({ toolName, ext }: { toolName: string; ext: string }) => ({
    absolutePath: `D:/project/artifacts/captures/${toolName}.${ext}`,
    displayPath: `artifacts/captures/${toolName}.${ext}`,
  })),
}));

describe('streaming capture exports', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('exports websocket frames with full payloads to an artifact', async () => {
    const handlers = new StreamingToolHandlers({ getActivePage: vi.fn() } as any);
    (handlers as any).wsConnections.set('r1', {
      requestId: 'r1',
      url: withPath(TEST_WS_URLS.api, 'ws'),
      status: 'open',
      framesCount: 1,
      createdTimestamp: 1,
      handshakeStatus: 101,
    });
    (handlers as any).wsFrameOrder.push({
      requestId: 'r1',
      frame: {
        requestId: 'r1',
        timestamp: 2,
        direction: 'sent',
        opcode: 1,
        payloadLength: 11,
        payloadPreview: 'hello-secret',
        payloadSample: 'hello-secret',
        payload: 'hello-secret',
        isBinary: false,
      },
    });

    const body = parseJson<any>(
      await handlers.handleWsExportCapture({ direction: 'sent', format: 'ndjson' }),
    );

    expect(resolveArtifactPath).toHaveBeenCalledWith(
      expect.objectContaining({
        category: 'captures',
        toolName: 'ws-capture',
        target: 'sent',
        ext: 'ndjson',
      }),
    );
    expect(writeFile).toHaveBeenCalledWith(
      'D:/project/artifacts/captures/ws-capture.ndjson',
      expect.stringContaining('"payload":"hello-secret"'),
      'utf8',
    );
    expect(body).toMatchObject({
      success: true,
      artifactPath: 'artifacts/captures/ws-capture.ndjson',
      format: 'ndjson',
      recordCount: 1,
    });
  });

  it('exports sse events with captured data to an artifact', async () => {
    const page = {
      evaluate: vi.fn().mockResolvedValue({
        success: true,
        monitor: {
          enabled: true,
          patched: true,
          maxEvents: 2000,
          urlFilter: null,
          sourceCount: 1,
        },
        filters: { sourceUrl: null, eventType: 'message', includeData: true },
        events: [
          {
            sourceUrl: withPath(TEST_URLS.api, 'events'),
            eventType: 'message',
            dataPreview: 'chunk',
            data: 'chunk-data',
            dataLength: 10,
            lastEventId: 'evt-1',
            timestamp: 123,
          },
        ],
      }),
    };
    const handlers = new StreamingToolHandlers({
      getActivePage: vi.fn().mockResolvedValue(page),
    } as any);

    const body = parseJson<any>(
      await handlers.handleSseExportCapture({ eventType: 'message', format: 'json' }),
    );

    expect(resolveArtifactPath).toHaveBeenCalledWith(
      expect.objectContaining({
        category: 'captures',
        toolName: 'sse-capture',
        target: 'message',
        ext: 'json',
      }),
    );
    expect(writeFile).toHaveBeenCalledWith(
      'D:/project/artifacts/captures/sse-capture.json',
      expect.stringContaining('"data": "chunk-data"'),
      'utf8',
    );
    expect(body).toMatchObject({
      success: true,
      artifactPath: 'artifacts/captures/sse-capture.json',
      format: 'json',
      recordCount: 1,
    });
  });
});
