import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Tool } from '@modelcontextprotocol/server';
import { validateToolArgsAgainstSchema } from '@server/MCPServer.search.validation.runtime';

describe('MCPServer.search.validation.runtime', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const schema = {
    type: 'object',
    properties: {
      pid: { type: 'number', minimum: 1 },
      mode: { type: 'string', enum: ['a', 'b', 'c'] },
      flag: { type: 'boolean' },
    },
    required: ['mode'],
  } as unknown as Tool['inputSchema'];

  it('passes through valid args and coerces string inputs', () => {
    const result = validateToolArgsAgainstSchema('test_tool', schema, {
      pid: '42',
      mode: 'b',
      flag: 'true',
    });
    // coerceNumberInput/coerceBooleanInput run through z.preprocess; the
    // compiled validator must keep the same coercion behaviour.
    expect(result.pid).toBe(42);
    expect(result.flag).toBe(true);
  });

  it('throws a descriptive error for invalid args', () => {
    expect(() => validateToolArgsAgainstSchema('test_tool', schema, { mode: 'x' })).toThrow(
      /Invalid arguments for "test_tool"/,
    );
  });

  it('caches the compiled validator across calls with the same schema object', () => {
    expect(validateToolArgsAgainstSchema('test_tool', schema, { mode: 'a' })).toEqual({
      mode: 'a',
    });
    // Second call with the identical schema object — must still validate.
    expect(validateToolArgsAgainstSchema('test_tool', schema, { mode: 'c', pid: 7 })).toEqual({
      mode: 'c',
      pid: 7,
    });
  });

  it('rebuilds when the caller passes a different schema object for the same tool', () => {
    validateToolArgsAgainstSchema('test_tool', schema, { mode: 'a' });

    const stricter = {
      type: 'object',
      properties: { mode: { type: 'string', enum: ['a'] } },
      required: ['mode'],
    } as unknown as Tool['inputSchema'];
    expect(validateToolArgsAgainstSchema('test_tool', stricter, { mode: 'a' })).toEqual({
      mode: 'a',
    });
    expect(() => validateToolArgsAgainstSchema('test_tool', stricter, { mode: 'b' })).toThrow(
      /Invalid arguments for "test_tool"/,
    );
  });

  it('returns args unchanged when the schema has no properties', () => {
    const emptySchema = { type: 'object', properties: {} } as unknown as Tool['inputSchema'];
    const args = { anything: 1 };
    expect(validateToolArgsAgainstSchema('test_tool', emptySchema, args)).toBe(args);
  });

  it('passes through when schema is undefined', () => {
    const args = { anything: 1 };
    expect(validateToolArgsAgainstSchema('test_tool', undefined, args)).toBe(args);
  });

  it('keeps tool-name cache isolation between tools', () => {
    expect(validateToolArgsAgainstSchema('tool_a', schema, { mode: 'a' })).toEqual({ mode: 'a' });
    const schemaB = {
      type: 'object',
      properties: { n: { type: 'number' } },
      required: ['n'],
    } as unknown as Tool['inputSchema'];
    expect(() => validateToolArgsAgainstSchema('tool_b', schemaB, {})).toThrow(
      /Invalid arguments for "tool_b"/,
    );
    // tool_a's entry is untouched by tool_b's failure.
    expect(validateToolArgsAgainstSchema('tool_a', schema, { mode: 'b' })).toEqual({ mode: 'b' });
  });
});
