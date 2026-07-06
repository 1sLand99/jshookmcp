import { beforeEach, describe, expect, it } from 'vitest';
import { MojoDecoder } from '@modules/mojo-ipc';

describe('MojoDecoder', () => {
  let decoder: MojoDecoder;

  beforeEach(() => {
    decoder = new MojoDecoder();
  });

  it('normalizes hex input', () => {
    expect(decoder.cleanHex('00 01 0')).toBe('000010');
  });

  it('decodes a short payload into header and raw summary', () => {
    const decoded = decoder.decodePayload('0001', 'test');
    expect(decoded.header.version).toBe(0);
    expect(decoded.raw).toBe('0001');
    expect(decoded._raw_summary).toBeDefined();
  });

  it('decodes boolean, integer and string fields', () => {
    const encoded = decoder.encodeMessage('network.mojom.NetworkService', '1', [true, 42, 'hello']);
    const decoded = decoder.decodePayload(encoded, 'network');
    expect(decoded.fields.field0).toBe(true);
    expect(decoded.fields.field1).toBe(42);
    expect(decoded.fields.field2).toBe('hello');
  });

  it('round-trips typed primitive fields', () => {
    const encoded = decoder.encodeMessage('network.mojom.NetworkService', '0x22', [
      { type: 'int16', value: -2 },
      { type: 'uint16', value: 65535 },
      { type: 'int32', value: -42 },
      { type: 'uint32', value: 42 },
      { type: 'int64', value: '-9007199254740991' },
      { type: 'uint64', value: '9007199254740991' },
      { type: 'float', value: 1.5 },
      { type: 'double', value: 2.25 },
      { type: 'nullableString', value: null },
    ]);

    const decoded = decoder.decodePayload(encoded);
    expect(decoded.header.messageType).toBe(0x22);
    expect(decoded.fields.field0).toBe(-2);
    expect(decoded.fields.field1).toBe(65535);
    expect(decoded.fields.field2).toBe(-42);
    expect(decoded.fields.field3).toBe(42);
    expect(decoded.fields.field4).toBe(-9007199254740991n);
    expect(decoded.fields.field5).toBe(9007199254740991n);
    expect(decoded.fields.field6).toBeCloseTo(1.5);
    expect(decoded.fields.field7).toBe(2.25);
    expect(decoded.fields.field8).toBeNull();
  });

  it('round-trips arrays, structs, and handle-like typed fields', () => {
    const encoded = decoder.encodeMessage('network.mojom.URLLoaderFactory', 'CreateLoader', [
      { type: 'array', elementType: 'uint16', values: [1, 65535] },
      {
        type: 'struct',
        fields: [
          { type: 'bool', value: true },
          { type: 'string', value: 'nested' },
          { type: 'handle', handle: 9 },
        ],
      },
      { type: 'pending_remote', handle: 12 },
    ]);

    const decoded = decoder.decodePayload(encoded);
    expect(decoded.fields.field0).toEqual([1, 65535]);
    expect(decoded.fields.field1).toEqual({
      field0: true,
      field1: 'nested',
      field2: { handle: 9 },
    });
    expect(decoded.fields.field2).toEqual({ kind: 'pending_remote', handle: 12 });
    expect(decoded.handles).toBe(2);
  });

  it('decodes payloads with a v2 extended header', () => {
    const decoded = decoder.decodePayload('0200030100000000000000000000000000000101');
    expect(decoded.header.version).toBe(2);
    expect(decoded.fields.field0).toBe(true);
  });

  it('records unknown field types and continues when bytes can be skipped', () => {
    const decoded = decoder.decodePayload('010001020000feaa0101');
    expect(decoded.fields.field0).toEqual({ unknownType: 0xfe, skippedBytes: 1 });
    expect(decoded.fields.field1).toBe(true);
    expect(decoded._raw_summary).toContain('unknown field type 0xfe');
  });

  it('encodes handle fields and reports handle count', () => {
    const encoded = decoder.encodeMessage('network.mojom.NetworkService', '2', [{ handle: 5 }]);
    const decoded = decoder.decodePayload(encoded);
    expect(decoded.handles).toBe(1);
    expect(decoded.fields.field0).toEqual({ handle: 5 });
  });
});
