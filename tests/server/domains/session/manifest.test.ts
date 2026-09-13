import { describe, expect, it } from 'vitest';
import manifest from '@server/domains/session/manifest';
import { sessionToolDefinitions } from '@server/domains/session/definitions';
import type { SessionProgressHandlers } from '@server/domains/session/handlers';
import { parseJson } from '@tests/server/domains/shared/mock-factories';

/**
 * Minimal mock context: the session domain's ensure() must work with a ctx
 * that only exposes the shared domain-instance map accessors (the same
 * tolerance pattern transport tests rely on). No MCPServerContext field is
 * required and none is added.
 */
function createMinimalMockCtx() {
  const instances = new Map<string, unknown>();
  return {
    getDomainInstance: <T>(key: string) => instances.get(key) as T | undefined,
    setDomainInstance: (key: string, value: unknown) => {
      instances.set(key, value);
    },
  } as any;
}

describe('session manifest', () => {
  it('declares the session domain with workflow/full profiles', () => {
    expect(manifest.kind).toBe('domain-manifest');
    expect(manifest.version).toBe(1);
    expect(manifest.domain).toBe('session');
    expect(manifest.depKey).toBe('sessionProgressHandlers');
    expect(manifest.profiles).toEqual(['workflow', 'full']);
  });

  it('registers the three session_progress tools bound to handler methods', () => {
    const registeredNames = manifest.registrations.map((r) => r.tool.name);

    expect(registeredNames).toEqual([
      'session_progress_record',
      'session_progress_coverage',
      'session_progress_clear',
    ]);
    expect(manifest.registrations.map((r) => r.tool)).toEqual(sessionToolDefinitions);
  });

  it('ensure() lazily creates the handler on a minimal mock ctx and is idempotent', async () => {
    const ctx = createMinimalMockCtx();

    const first = await manifest.ensure(ctx);
    const second = await manifest.ensure(ctx);

    expect(first).toBe(second);
    expect(ctx.getDomainInstance('sessionProgressHandlers') as SessionProgressHandlers).toBe(first);
  });

  it('ensure() tolerates a ctx without any session state pre-initialized', async () => {
    const ctx = createMinimalMockCtx();
    expect(ctx.getDomainInstance('sessionProgressHandlers')).toBeUndefined();

    const handlers = await manifest.ensure(ctx);
    const body = parseJson<{ recorded: boolean }>(
      await handlers.handleRecordProgressTool({ kind: 'process', key: 'pid:1' }),
    );
    expect(body.recorded).toBe(true);
  });

  it('registration bind() routes args to the handler methods via the dep key', async () => {
    const handlers = await manifest.ensure(createMinimalMockCtx());
    const record = manifest.registrations.find((r) => r.tool.name === 'session_progress_record');
    const coverage = manifest.registrations.find(
      (r) => r.tool.name === 'session_progress_coverage',
    );

    expect(record).toBeDefined();
    expect(coverage).toBeDefined();

    const invokeRecord = record!.bind({ sessionProgressHandlers: handlers });
    const recordBody = parseJson<{ success: boolean; recorded: boolean }>(
      await invokeRecord({ kind: 'hook-point', key: 'libfoo.so!0x12345' }),
    );
    expect(recordBody.success).toBe(true);
    expect(recordBody.recorded).toBe(true);

    const invokeCoverage = coverage!.bind({ sessionProgressHandlers: handlers });
    const coverageBody = parseJson<{ counts: { hookPoint: number } }>(await invokeCoverage({}));
    expect(coverageBody.counts.hookPoint).toBe(1);
  });

  it('bind() fails fast when the domain handler dependency is missing', () => {
    const record = manifest.registrations.find((r) => r.tool.name === 'session_progress_record');
    const invoke = record!.bind({});
    // getDep() throws synchronously when the bound args function is invoked
    expect(() => invoke({ kind: 'process', key: 'pid:1' })).toThrow(
      /Missing dependency: "sessionProgressHandlers"/,
    );
  });
});
