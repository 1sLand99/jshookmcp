import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PluginRegistry } from '@modules/extension-registry/PluginRegistry';
import { EventBus } from '@server/EventBus';
import { TEST_URLS, withPath } from '@tests/shared/test-urls';

describe('PluginRegistry', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(path.join(tmpdir(), 'jshook-plugin-registry-'));
    vi.restoreAllMocks();
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
    vi.unstubAllGlobals();
  });

  it('registers plugins, sanitizes ids, and persists installed manifests', async () => {
    const registry = new PluginRegistry(tempDir);

    const pluginId = await registry.register({
      id: 'Team/Feature Plugin!!',
      name: 'Feature Plugin',
      version: '1.2.3',
      entry: './plugin.mjs',
      permissions: ['network'],
    });

    expect(pluginId).toBe('team-feature-plugin-');
    expect(registry.listInstalled()).toEqual([
      {
        id: 'team-feature-plugin-',
        name: 'Feature Plugin',
        version: '1.2.3',
        permissions: ['network'],
        status: 'unloaded',
      },
    ]);
    expect(registry.getInstalled(pluginId)).toMatchObject({
      id: 'team-feature-plugin-',
      name: 'Feature Plugin',
      version: '1.2.3',
      entry: './plugin.mjs',
      permissions: ['network'],
      status: 'unloaded',
    });

    const disk = JSON.parse(await readFile(path.join(tempDir, 'plugins.json'), 'utf8')) as Array<{
      id: string;
      name: string;
      version: string;
      entry: string;
      permissions: string[];
      status: string;
    }>;
    expect(disk[0]).toMatchObject({
      id: 'team-feature-plugin-',
      name: 'Feature Plugin',
      version: '1.2.3',
      permissions: ['network'],
      status: 'unloaded',
    });
  });

  it('loads local file-url plugins, caches exports, unloads, and unregisters them', async () => {
    const registry = new PluginRegistry(tempDir);
    const modulePath = path.join(tempDir, 'local-plugin.mjs');
    await writeFile(
      modulePath,
      'export const marker = 42; export default { marker }; export const ping = () => "pong";',
      'utf8',
    );

    const pluginId = await registry.register({
      id: 'local-plugin',
      name: 'Local Plugin',
      version: '0.0.1',
      entry: pathToFileURL(modulePath).href,
    });

    const firstLoad = await registry.loadPlugin(pluginId);
    const secondLoad = await registry.loadPlugin(pluginId);

    expect(firstLoad.manifest).toMatchObject({
      id: 'local-plugin',
      name: 'Local Plugin',
      version: '0.0.1',
      entry: pathToFileURL(modulePath).href,
      permissions: [],
    });
    expect(firstLoad.exports['marker']).toBe(42);
    expect(typeof firstLoad.exports['ping']).toBe('function');
    expect(secondLoad.exports).toBe(firstLoad.exports);
    expect(registry.listInstalled()[0]?.status).toBe('loaded');

    await registry.unloadPlugin(pluginId);
    expect(registry.listInstalled()[0]?.status).toBe('unloaded');

    await registry.unregister(pluginId);
    expect(registry.listInstalled()).toEqual([]);
    // Removal must be durable, not just in-memory: persist() is what makes it
    // survive a restart, and nothing else in this file asserts the written file.
    const disk = JSON.parse(
      await readFile(path.join(tempDir, 'plugins.json'), 'utf8'),
    ) as unknown[];
    expect(disk).toEqual([]);
  });

  it('downloads remote plugin modules into the local cache before loading them', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () =>
        'export const remoteValue = "remote"; export default { remoteValue }; export const probe = () => "ok";',
    });
    vi.stubGlobal('fetch', fetchMock);

    const registry = new PluginRegistry(tempDir);
    const pluginId = await registry.register({
      id: 'remote/plugin',
      name: 'Remote Plugin',
      version: '1.0.0',
      entry: withPath(TEST_URLS.root, 'remote-plugin.mjs'),
    });

    const loaded = await registry.loadPlugin(pluginId);

    expect(fetchMock).toHaveBeenCalledWith(withPath(TEST_URLS.root, 'remote-plugin.mjs'));
    expect(loaded.exports['remoteValue']).toBe('remote');
    expect(existsSync(path.join(tempDir, 'modules', 'remote-plugin.mjs'))).toBe(true);
  });

  it('rejects remote plugin downloads when fetch fails', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);

    const registry = new PluginRegistry(tempDir);
    const pluginId = await registry.register({
      id: 'remote-plugin',
      name: 'Remote Plugin',
      version: '1.0.0',
      entry: withPath(TEST_URLS.root, 'remote-plugin.mjs'),
    });

    await expect(registry.loadPlugin(pluginId)).rejects.toThrow(
      'Failed to download plugin module: 503 Service Unavailable',
    );
  });

  it('publishes extension:loaded once per real load and extension:unloaded once per real unload', async () => {
    const bus = new EventBus();
    const loaded: Array<{
      pluginId: string;
      toolCount: number;
      source: string;
      timestamp: string;
    }> = [];
    const unloaded: Array<{ pluginId: string; timestamp: string }> = [];
    bus.on('extension:loaded', (payload) => {
      loaded.push(payload);
    });
    bus.on('extension:unloaded', (payload) => {
      unloaded.push(payload);
    });

    const registry = new PluginRegistry(tempDir, bus);
    const modulePath = path.join(tempDir, 'event-plugin.mjs');
    // Two invocable contexts: a top-level function and a function on `default`.
    // A non-callable export must NOT be counted as a tool.
    await writeFile(
      modulePath,
      'export const marker = 42; export const ping = () => "pong"; export default { run: () => 1 };',
      'utf8',
    );

    const pluginId = await registry.register({
      id: 'event-plugin',
      name: 'Event Plugin',
      version: '1.0.0',
      entry: pathToFileURL(modulePath).href,
    });

    await registry.loadPlugin(pluginId);
    // A cached second load must not re-announce a load that already happened.
    await registry.loadPlugin(pluginId);

    expect(loaded).toHaveLength(1);
    expect(loaded[0]).toMatchObject({
      pluginId: 'event-plugin',
      toolCount: 2,
      source: pathToFileURL(modulePath).href,
    });
    expect(typeof loaded[0]?.timestamp).toBe('string');

    await registry.unloadPlugin(pluginId);
    expect(unloaded).toHaveLength(1);
    expect(unloaded[0]).toMatchObject({ pluginId: 'event-plugin' });
    expect(typeof unloaded[0]?.timestamp).toBe('string');

    // Unloading an already-unloaded plugin is not a transition — no event.
    await registry.unloadPlugin(pluginId);
    expect(unloaded).toHaveLength(1);
  });

  it('emits no lifecycle events when constructed without an event bus', async () => {
    const registry = new PluginRegistry(tempDir);
    const modulePath = path.join(tempDir, 'no-bus-plugin.mjs');
    await writeFile(modulePath, 'export const ping = () => "pong";', 'utf8');

    const pluginId = await registry.register({
      id: 'no-bus-plugin',
      name: 'No Bus Plugin',
      version: '1.0.0',
      entry: pathToFileURL(modulePath).href,
    });

    await expect(registry.loadPlugin(pluginId)).resolves.toBeDefined();
    await expect(registry.unloadPlugin(pluginId)).resolves.toBeUndefined();
  });
});
