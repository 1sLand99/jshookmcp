import { describe, expect, it } from 'vitest';
import { sessionToolDefinitions } from '@server/domains/session/definitions';

const KINDS = ['process', 'hook-point', 'protocol-field'];

function getTool(name: string) {
  return sessionToolDefinitions.find((tool) => tool.name === name);
}

describe('session domain definitions', () => {
  it('defines exactly the three session_progress tools with valid shapes', () => {
    expect(sessionToolDefinitions.map((tool) => tool.name)).toEqual([
      'session_progress_record',
      'session_progress_coverage',
      'session_progress_clear',
    ]);
    for (const tool of sessionToolDefinitions) {
      expect(tool.description).toBeDefined();
      expect(tool.description?.length).toBeGreaterThan(0);
      expect(tool.inputSchema).toBeDefined();
    }
  });

  it('documents the in-memory, server-lifetime state limitation in every description', () => {
    for (const tool of sessionToolDefinitions) {
      expect(tool.description).toMatch(/in-memory/i);
      expect(tool.description).toMatch(/restart/i);
    }
  });

  it('session_progress_record requires kind + key and exposes optional sessionId/metadata', () => {
    const tool = getTool('session_progress_record');
    expect(tool?.inputSchema.required).toEqual(['kind', 'key']);
    expect((tool?.inputSchema.properties?.kind as any)?.enum).toEqual(KINDS);
    expect(tool?.inputSchema.properties).toHaveProperty('sessionId');
    expect(tool?.inputSchema.properties).toHaveProperty('metadata');
    expect((tool?.inputSchema.properties?.metadata as any)?.additionalProperties).toBe(true);
    expect(tool?.annotations?.idempotentHint).toBe(true);
  });

  it('session_progress_coverage is a read-only query with an optional kind filter', () => {
    const tool = getTool('session_progress_coverage');
    expect(tool?.inputSchema.required).toBeUndefined();
    expect((tool?.inputSchema.properties?.kind as any)?.enum).toEqual(KINDS);
    expect(tool?.annotations?.readOnlyHint).toBe(true);
    expect(tool?.annotations?.idempotentHint).toBe(true);
  });

  it('session_progress_clear is destructive and idempotent (resettable)', () => {
    const tool = getTool('session_progress_clear');
    expect(tool?.inputSchema.required).toBeUndefined();
    expect((tool?.inputSchema.properties?.kind as any)?.enum).toEqual(KINDS);
    expect(tool?.annotations?.destructiveHint).toBe(true);
    expect(tool?.annotations?.idempotentHint).toBe(true);
  });

  it('explains the sessionId defaulting semantics', () => {
    const tool = getTool('session_progress_record');
    expect((tool?.inputSchema.properties?.sessionId as any)?.description).toMatch(/'default'/);
  });
});
