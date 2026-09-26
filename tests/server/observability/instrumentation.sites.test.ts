/**
 * Wiring tests for the emission sites that live BELOW the server layer.
 *
 * These are the ones that made the original module un-wireable: `bridgeFetch`
 * and `discoverDomainManifests` are module-level functions with no context, and
 * `CaptchaDetector` is constructed inside the browser module. They resolve the
 * process-wide instrumentation instead, which is why `setGlobalInstrumentation`
 * exists — and why it needs a test proving the same object is reached.
 *
 * The point of every case here is that a REAL code path is driven and the
 * declared name comes out the other end. Asserting that a function calls
 * `emitMetric` would prove nothing about whether anything ever calls the
 * function.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const loggerState = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));
vi.mock('@utils/logger', () => ({ logger: loggerState }));
vi.mock('@src/utils/logger', () => ({ logger: loggerState }));

import {
  MetricNames,
  resetGlobalInstrumentation,
  setGlobalInstrumentation,
  SpanNames,
} from '@server/observability/InstrumentationContract';
import { RecordingInstrumentation } from '@tests/shared/recording-instrumentation';

let instrumentation: RecordingInstrumentation;

beforeEach(() => {
  vi.clearAllMocks();
  instrumentation = new RecordingInstrumentation();
  setGlobalInstrumentation(instrumentation);
});

afterEach(() => {
  resetGlobalInstrumentation();
});

describe('registry.discovery', () => {
  it('is emitted by discoverDomainManifests, and reports what was loaded', async () => {
    const { discoverDomainManifests } = await import('@server/registry/discovery');

    const manifests = await discoverDomainManifests(new Set());

    expect(manifests).toEqual([]);
    const spans = instrumentation.spansNamed(SpanNames.registryDiscovery);
    expect(spans).toHaveLength(1);
    expect(spans[0]!.ended).toBe(true);
    expect(spans[0]!.attrs).toEqual({ requested: 0 });
    expect(spans[0]!.endAttrs).toEqual({ manifests: 0, tools: 0 });
  });

  it('counts a real domain load rather than only the empty case', async () => {
    const { discoverDomainManifests, getLoaderMetadata } =
      await import('@server/registry/discovery');
    const first = getLoaderMetadata()[0];
    expect(first).toBeDefined();

    const manifests = await discoverDomainManifests(new Set([first!.domain]));

    expect(manifests).toHaveLength(1);
    const end = instrumentation.spansNamed(SpanNames.registryDiscovery)[0]!.endAttrs!;
    expect(end['manifests']).toBe(1);
    expect(end['tools']).toBeGreaterThan(0);
  });
});

describe('plugin.lifecycle and plugin_active_total', () => {
  let registryRoot: string;
  let pluginEntry: string;

  beforeEach(() => {
    registryRoot = mkdtempSync(join(tmpdir(), 'jshook-plugin-registry-'));
    pluginEntry = join(registryRoot, 'probe-plugin.mjs');
    writeFileSync(pluginEntry, 'export const probe = true;\n', 'utf8');
  });

  afterEach(() => {
    rmSync(registryRoot, { recursive: true, force: true });
  });

  async function makeRegistry() {
    const { PluginRegistry } = await import('@modules/extension-registry/PluginRegistry');
    const registry = new PluginRegistry(registryRoot);
    await registry.register({
      id: 'probe',
      name: 'probe',
      version: '1.0.0',
      entry: pluginEntry,
    });
    return registry;
  }

  it('emits a span and a gauge on load, then the level again on unload', async () => {
    const registry = await makeRegistry();

    await registry.loadPlugin('probe');

    const loadSpans = instrumentation.spansNamed(SpanNames.pluginLifecycle);
    expect(loadSpans).toHaveLength(1);
    expect(loadSpans[0]!.attrs).toEqual({ action: 'load', pluginId: 'probe' });
    expect(loadSpans[0]!.ended).toBe(true);
    expect(loadSpans[0]!.endAttrs).toEqual({ status: 'ok', loaded: 1 });

    // A gauge of the CURRENT level: 1 loaded, not a running total of 1.
    expect(instrumentation.metricsNamed(MetricNames.pluginActiveTotal)).toEqual([
      {
        name: MetricNames.pluginActiveTotal,
        value: 1,
        type: 'gauge',
        attrs: { action: 'load', pluginId: 'probe' },
      },
    ]);

    await registry.unloadPlugin('probe');

    const unloadSpans = instrumentation.spansNamed(SpanNames.pluginLifecycle);
    expect(unloadSpans).toHaveLength(2);
    expect(unloadSpans[1]!.attrs).toEqual({ action: 'unload', pluginId: 'probe' });
    expect(unloadSpans[1]!.endAttrs).toEqual({ status: 'ok', loaded: 0 });
    expect(instrumentation.metricsNamed(MetricNames.pluginActiveTotal)[1]!.value).toBe(0);
  });

  it('emits a span but NO gauge when unloading an unknown plugin', async () => {
    const registry = await makeRegistry();

    await registry.unloadPlugin('does-not-exist');

    // The attempt is observable...
    const spans = instrumentation.spansNamed(SpanNames.pluginLifecycle);
    expect(spans).toHaveLength(1);
    expect(spans[0]!.ended).toBe(true);
    // ...but the loaded set never changed, so a gauge sample would be a
    // measurement of nothing.
    expect(instrumentation.metricsNamed(MetricNames.pluginActiveTotal)).toHaveLength(0);
  });

  it('ends the span with status error when the load throws', async () => {
    const registry = await makeRegistry();

    await expect(registry.loadPlugin('missing-plugin')).rejects.toThrow('Plugin not found');

    const spans = instrumentation.spansNamed(SpanNames.pluginLifecycle);
    expect(spans).toHaveLength(1);
    // An unended span on the throw path would leak, and the failure would be
    // indistinguishable from a hang.
    expect(spans[0]!.ended).toBe(true);
    expect(spans[0]!.endAttrs).toEqual({ status: 'error' });
    expect(instrumentation.metricsNamed(MetricNames.pluginActiveTotal)).toHaveLength(0);
  });
});

describe('captcha.detect', () => {
  it('is emitted by CaptchaDetector.detect, and named detect rather than solve', async () => {
    const { CaptchaDetector } = await import('@modules/captcha/CaptchaDetector');
    const detector = new CaptchaDetector();
    const page = {
      url: () => 'https://example.com/',
      title: async () => 'home',
      $: async () => null,
      evaluate: async () => false,
    };

    await detector.detect(page as never);

    const spans = instrumentation.spansNamed(SpanNames.captchaDetect);
    expect(spans).toHaveLength(1);
    expect(spans[0]!.ended).toBe(true);
    expect(spans[0]!.endAttrs).toMatchObject({ detected: false });
  });
});
