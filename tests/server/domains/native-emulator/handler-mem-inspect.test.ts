/**
 * nemu_mem_inspect — convergence pilot tests.
 *
 * Guards the subcommand contract: each `action` routes to the wrapped tool's
 * existing handler method with the parsed arguments passed through unchanged,
 * unknown actions fail loudly, per-subcommand required parameters are enforced
 * by the `action`-discriminated union, the tool definition mirrors every
 * wrapped parameter with aligned annotations, and the pre-existing flat tools
 * are untouched (nothing migrated, nothing removed).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { NativeEmulatorHandlers } from '@server/domains/native-emulator/handlers.impl';
import {
  MEM_INSPECT_ACTIONS,
  formatMemInspectIssues,
  memInspectSchema,
} from '@server/domains/native-emulator/handler-mem-inspect';
import { nativeEmulatorTools } from '@server/domains/native-emulator/definitions';
import manifest from '@server/domains/native-emulator/manifest';
import { SessionManager } from '@modules/native-emulator/SessionManager';

/** action → wrapped tool name (the definition-level 1:1 mapping). */
const WRAPPED_TOOLS = {
  read: 'nemu_read_memory',
  dump: 'nemu_data_dump',
  chain: 'nemu_pointer_chain',
  frame: 'nemu_dump_frame',
  scan: 'nemu_scan_memory',
} as const;

/** Parse the JSON payload out of an MCP text response. */
function payload(res: {
  content: Array<{ type: string; text?: string }>;
}): Record<string, unknown> {
  const text = res.content.find((c) => c.type === 'text')?.text ?? '{}';
  return JSON.parse(text) as Record<string, unknown>;
}

function toolByName(name: string) {
  const found = nativeEmulatorTools.find((t) => t.name === name);
  expect(found, `tool ${name} must stay registered`).toBeDefined();
  return found!;
}

describe('nemu_mem_inspect — discriminated union schema', () => {
  it('exposes exactly the five documented subcommands', () => {
    expect(MEM_INSPECT_ACTIONS).toEqual(['read', 'dump', 'chain', 'frame', 'scan']);
  });

  it('parses minimal valid arguments for every subcommand', () => {
    expect(
      memInspectSchema.safeParse({ action: 'read', sessionId: 's1', address: 4096, length: 16 })
        .success,
    ).toBe(true);
    expect(
      memInspectSchema.safeParse({ action: 'dump', sessionId: 's1', address: 4096 }).success,
    ).toBe(true);
    expect(
      memInspectSchema.safeParse({ action: 'chain', sessionId: 's1', base: 4096 }).success,
    ).toBe(true);
    expect(
      memInspectSchema.safeParse({ action: 'frame', sessionId: 's1', address: 4096 }).success,
    ).toBe(true);
    expect(
      memInspectSchema.safeParse({
        action: 'scan',
        sessionId: 's1',
        pattern: 'AQID',
        startAddr: 0,
        endAddr: 4096,
      }).success,
    ).toBe(true);
  });

  it('rejects an unknown action and names the discriminant', () => {
    const result = memInspectSchema.safeParse({ action: 'explode', sessionId: 's1' });
    expect(result.success).toBe(false);
    if (!result.success) {
      const message = formatMemInspectIssues(result.error);
      expect(message).toMatch(/action/i);
    }
  });

  it('enforces per-subcommand required parameters (read needs length)', () => {
    const result = memInspectSchema.safeParse({ action: 'read', sessionId: 's1', address: 4096 });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(formatMemInspectIssues(result.error)).toMatch(/length/);
    }
  });

  it('enforces scan required range parameters', () => {
    const result = memInspectSchema.safeParse({ action: 'scan', sessionId: 's1', pattern: 'AQID' });
    expect(result.success).toBe(false);
    if (!result.success) {
      const message = formatMemInspectIssues(result.error);
      expect(message).toMatch(/startAddr/);
      expect(message).toMatch(/endAddr/);
    }
  });

  it('rejects wrong parameter types per variant', () => {
    const result = memInspectSchema.safeParse({
      action: 'read',
      sessionId: 's1',
      address: '0x1000',
      length: 16,
    });
    expect(result.success).toBe(false);
  });
});

describe('nemu_mem_inspect — routing & passthrough over a live session', () => {
  let handlers: NativeEmulatorHandlers;
  let sessionId: string;
  let addr: number;

  afterEach(() => handlers.dispose());

  /** Fresh session with a 4 KB region holding deterministic fixtures. */
  async function setup(): Promise<void> {
    handlers = new NativeEmulatorHandlers(
      new SessionManager({ emulatorOptions: { syscalls: false } }),
    );
    const created = payload(await handlers.handleCreateSession({ installSyscalls: false }));
    sessionId = created.sessionId as string;
    const alloc = payload(await handlers.handleAllocMemory({ sessionId, size: 0x1000 }));
    addr = alloc.address as number;
    // Known bytes at the region base.
    await handlers.handleWriteMemory({
      sessionId,
      address: addr,
      dataBase64: Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]).toString('base64'),
    });
    // Pointer chain fixture: [addr+0x40] → addr+0x80.
    const ptr = Buffer.alloc(8);
    ptr.writeBigUInt64LE(BigInt(addr + 0x80));
    await handlers.handleWriteMemory({
      sessionId,
      address: addr + 0x40,
      dataBase64: ptr.toString('base64'),
    });
    // Scan marker at addr+0x100.
    await handlers.handleWriteMemory({
      sessionId,
      address: addr + 0x100,
      dataBase64: Buffer.from([0xca, 0xfe, 0xba, 0xbe]).toString('base64'),
    });
  }

  it('routes action="read" to handleReadMemory and passes parsed args through', async () => {
    await setup();
    const direct = payload(
      await handlers.handleReadMemory({ sessionId, address: addr, length: 8 }),
    );
    const spy = vi.spyOn(handlers, 'handleReadMemory');
    const viaWrapper = payload(
      await handlers.handleMemInspect({ action: 'read', sessionId, address: addr, length: 8 }),
    );
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'read', sessionId, address: addr, length: 8 }),
    );
    // Parsed output carries exactly the variant's declared keys (no cross-subcommand bleed).
    expect(Object.keys(spy.mock.calls[0]![0] as object).toSorted()).toEqual(
      ['action', 'sessionId', 'address', 'length'].toSorted(),
    );
    expect(viaWrapper).toEqual(direct);
  });

  it('routes action="dump" to handleDataDump and passes optional params through', async () => {
    await setup();
    const direct = payload(
      await handlers.handleDataDump({ sessionId, address: addr, count: 2, wordSize: 'u32' }),
    );
    const spy = vi.spyOn(handlers, 'handleDataDump');
    const viaWrapper = payload(
      await handlers.handleMemInspect({
        action: 'dump',
        sessionId,
        address: addr,
        count: 2,
        wordSize: 'u32',
      }),
    );
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'dump',
        sessionId,
        address: addr,
        count: 2,
        wordSize: 'u32',
      }),
    );
    expect(viaWrapper).toEqual(direct);
    expect(viaWrapper.success).toBe(true);
  });

  it('routes action="chain" to handlePointerChain and follows the fixture pointer', async () => {
    await setup();
    const direct = payload(await handlers.handlePointerChain({ sessionId, base: addr + 0x40 }));
    const spy = vi.spyOn(handlers, 'handlePointerChain');
    const viaWrapper = payload(
      await handlers.handleMemInspect({ action: 'chain', sessionId, base: addr + 0x40 }),
    );
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'chain', sessionId, base: addr + 0x40 }),
    );
    expect(viaWrapper).toEqual(direct);
    const hops = viaWrapper.hops as Array<Record<string, unknown>>;
    expect(hops.length).toBeGreaterThan(0);
    expect(String(hops[0]!['pointer'])).toContain((addr + 0x80).toString(16));
  });

  it('routes action="frame" to handleDumpFrame', async () => {
    await setup();
    const direct = payload(await handlers.handleDumpFrame({ sessionId, address: addr + 0x180 }));
    const spy = vi.spyOn(handlers, 'handleDumpFrame');
    const viaWrapper = payload(
      await handlers.handleMemInspect({ action: 'frame', sessionId, address: addr + 0x180 }),
    );
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'frame', sessionId, address: addr + 0x180 }),
    );
    expect(viaWrapper).toEqual(direct);
    expect(viaWrapper.success).toBe(true);
  });

  it('routes action="scan" to handleScanMemory and finds the fixture marker', async () => {
    await setup();
    const marker = Buffer.from([0xca, 0xfe, 0xba, 0xbe]).toString('base64');
    const direct = payload(
      await handlers.handleScanMemory({
        sessionId,
        pattern: marker,
        startAddr: addr,
        endAddr: addr + 0x400,
      }),
    );
    const spy = vi.spyOn(handlers, 'handleScanMemory');
    const viaWrapper = payload(
      await handlers.handleMemInspect({
        action: 'scan',
        sessionId,
        pattern: marker,
        startAddr: addr,
        endAddr: addr + 0x400,
      }),
    );
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'scan',
        sessionId,
        pattern: marker,
        startAddr: addr,
        endAddr: addr + 0x400,
      }),
    );
    expect(viaWrapper).toEqual(direct);
    expect(viaWrapper.count).toBe(1);
    expect(viaWrapper.matches).toEqual([`0x${(addr + 0x100).toString(16)}`]);
  });

  it('fails loudly for an unknown action', async () => {
    await setup();
    const data = payload(
      await handlers.handleMemInspect({ action: 'explode', sessionId } as Record<string, unknown>),
    );
    expect(data.success).toBe(false);
    const message = String(data.error);
    expect(message).toContain('nemu_mem_inspect');
    expect(message).toMatch(/action/i);
  });

  it('fails when a subcommand misses its required parameters', async () => {
    await setup();
    const data = payload(await handlers.handleMemInspect({ action: 'read', sessionId }));
    expect(data.success).toBe(false);
    expect(String(data.error)).toMatch(/length/);
  });
});

describe('nemu_mem_inspect — definition & manifest contract', () => {
  it('is registered once with a bound handler method', () => {
    const registrations = manifest.registrations.filter((r) => r.tool.name === 'nemu_mem_inspect');
    expect(registrations).toHaveLength(1);
    const handlers = new NativeEmulatorHandlers();
    const bound = registrations[0]!.bind({ nativeEmulatorHandlers: handlers });
    expect(typeof bound).toBe('function');
    handlers.dispose();
  });

  it('declares every wrapped tool parameter in its flat inputSchema', () => {
    const wrapper = toolByName('nemu_mem_inspect');
    const wrapperProps = Object.keys(wrapper.inputSchema.properties as object);
    for (const toolName of Object.values(WRAPPED_TOOLS)) {
      const wrapped = toolByName(toolName);
      for (const param of Object.keys(wrapped.inputSchema.properties as object)) {
        expect(wrapperProps, `${toolName}.${param} must be declared`).toContain(param);
      }
    }
  });

  it('aligns annotations with the strictest wrapped operation (no overclaiming)', () => {
    // nemu_scan_memory's legacy definition declares no .query() hints, so the
    // strictest alignment is the intersection: the wrapper must not claim
    // read-only/idempotent for the whole tool even though every subcommand is
    // behaviorally read-only. Assert the intersection rule field by field.
    const wrapper = toolByName('nemu_mem_inspect');
    const wrapped = Object.values(WRAPPED_TOOLS).map((toolName) => toolByName(toolName));
    const hintKeys = [
      'readOnlyHint',
      'destructiveHint',
      'idempotentHint',
      'openWorldHint',
    ] as const;
    for (const key of hintKeys) {
      const intersection = wrapped.every((t) => t.annotations?.[key] === true);
      expect(wrapper.annotations?.[key], `annotation ${key}`).toBe(intersection);
    }
    // The wrapped tools themselves keep their original annotations.
    expect(toolByName('nemu_read_memory').annotations).toEqual(
      expect.objectContaining({ readOnlyHint: true, idempotentHint: true }),
    );
    expect(toolByName('nemu_scan_memory').annotations).toEqual(
      expect.objectContaining({ readOnlyHint: false, idempotentHint: false }),
    );
  });

  it('requires only action + sessionId at the flat-schema level', () => {
    const wrapper = toolByName('nemu_mem_inspect');
    expect(wrapper.inputSchema.required).toEqual(['action', 'sessionId']);
    const action = wrapper.inputSchema.properties?.action as { enum?: string[] };
    expect(action.enum).toEqual([...MEM_INSPECT_ACTIONS]);
  });
});

describe('nemu_mem_inspect — existing tools unaffected (pure additive pilot)', () => {
  it('keeps all 56 pre-existing tools registered and adds exactly one', () => {
    expect(nativeEmulatorTools).toHaveLength(57);
    const names = nativeEmulatorTools.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length); // no duplicates
    for (const toolName of Object.values(WRAPPED_TOOLS)) {
      expect(names).toContain(toolName);
    }
  });

  it('leaves the wrapped tool definitions byte-for-byte equivalent in shape', () => {
    const readMemory = toolByName('nemu_read_memory');
    expect(readMemory.inputSchema.required).toEqual(['sessionId', 'address', 'length']);
    expect(readMemory.annotations).toEqual(
      expect.objectContaining({ readOnlyHint: true, idempotentHint: true }),
    );
    const scanMemory = toolByName('nemu_scan_memory');
    expect(scanMemory.inputSchema.required).toEqual([
      'sessionId',
      'pattern',
      'startAddr',
      'endAddr',
    ]);
  });

  it('keeps the manifest registration set equal to the definition set', () => {
    expect(manifest.registrations).toHaveLength(nativeEmulatorTools.length);
    const registered = manifest.registrations.map((r) => r.tool.name).toSorted();
    expect(registered).toEqual(nativeEmulatorTools.map((t) => t.name).toSorted());
  });
});
