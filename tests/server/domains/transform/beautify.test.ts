/**
 * `beautify` — the 6th transform kind, and the `ast_transform_beautify` tool.
 *
 * Background: `docs/custom-macros.md` shipped a macro example whose second step
 * called `"toolName": "ast_transform_beautify"`, but no such tool was registered
 * and no `beautify` transform kind existed either — the documented macro could
 * never run. These tests pin the capability added to close that gap, plus the
 * two contracts that make it safe to compose with the other transforms:
 *
 *   1. it never changes program semantics — it only re-prints the parsed AST;
 *   2. it reports itself as NOT applied when the input is already in its own
 *      output form, so `applyTransforms` cannot claim work it did not do.
 */
import { parseJson } from '@tests/server/domains/shared/mock-factories';
import { describe, expect, it, vi } from 'vitest';
import { TransformToolHandlers } from '@server/domains/transform/handlers';
import { transformTools } from '@server/domains/transform/definitions';
import { transformBeautifyAst } from '@server/domains/transform/handlers/ast-ops';
import { parseTransforms } from '@server/domains/transform/handlers/shared';
import { applyTransforms } from '@server/domains/transform/handlers/transform-operations';

const MINIFIED = 'var a=1;function b(c){return c+1}';

/** Mirrors the helper used by tests/server/domains/browser/definitions.test.ts. */
function transformsEnumOf(toolName: string): unknown {
  const tool = transformTools.find((candidate) => candidate.name === toolName);
  const schema = tool?.inputSchema as
    | { properties?: Record<string, { items?: { enum?: unknown } }> }
    | undefined;
  return schema?.properties?.['transforms']?.items?.enum;
}

function createHandlers(): TransformToolHandlers {
  return new TransformToolHandlers({ getActivePage: vi.fn() } as never);
}

describe('beautify transform kind', () => {
  it('is accepted by the runtime transform validator', () => {
    expect(parseTransforms(['beautify'])).toEqual(['beautify']);
  });

  it('is offered by every ast_transform_* tool that takes a transforms list', () => {
    for (const toolName of [
      'ast_transform_preview',
      'ast_transform_chain',
      'ast_transform_apply',
    ]) {
      expect(transformsEnumOf(toolName), toolName).toContain('beautify');
    }
  });

  it('re-indents minified source and reports itself as applied', () => {
    const result = applyTransforms(MINIFIED, ['beautify']);
    expect(result.appliedTransforms).toEqual(['beautify']);
    expect(result.transformed).toContain('\n  return c + 1;\n');
  });

  it('preserves program semantics', () => {
    const source = 'var __r=(function(a){return a+1})(41);';
    const { transformed } = applyTransforms(source, ['beautify']);
    const run = (code: string) => new Function(`${code};return __r;`)();
    expect(run(transformed)).toBe(run(source));
    expect(run(transformed)).toBe(42);
  });

  it('is idempotent and reports itself as NOT applied on its own output', () => {
    const once = applyTransforms(MINIFIED, ['beautify']).transformed;
    const twice = applyTransforms(once, ['beautify']);
    expect(twice.transformed).toBe(once);
    expect(twice.appliedTransforms).toEqual([]);
  });

  it('returns unparseable input untouched instead of throwing', () => {
    const broken = 'function ( { ]';
    const result = applyTransforms(broken, ['beautify']);
    expect(result.transformed).toBe(broken);
    expect(result.appliedTransforms).toEqual([]);
  });

  it('round-trips generator-canonical input byte-for-byte', () => {
    const canonical = 'var a = 1;\nfunction b(c) {\n  return c + 1;\n}';
    expect(transformBeautifyAst(canonical)).toBe(canonical);
    expect(applyTransforms(canonical, ['beautify']).appliedTransforms).toEqual([]);
  });

  it('normalises a trailing newline away', () => {
    // Pinned as an intentional contract rather than an accident: every
    // transform in this module returns generator-canonical output, and
    // @babel/generator never terminates its output with a newline.
    expect(transformBeautifyAst('var a = 1;\n')).toBe('var a = 1;');
    expect(applyTransforms('var a = 1;\n', ['beautify']).appliedTransforms).toEqual(['beautify']);
  });

  it('has nothing left to do after a transform that already normalised the code', () => {
    // constant_fold / dead_code_remove emit through normalizeGeneratedCode, so
    // the intermediate string is already generator-canonical. Beautify then
    // correctly reports itself as not applied — chaining it is safe and
    // idempotent, not a silently-dropped step.
    const result = applyTransforms('var a=2+3;if(false){dead();}', [
      'constant_fold',
      'dead_code_remove',
      'beautify',
    ]);
    expect(result.appliedTransforms).toEqual(['constant_fold', 'dead_code_remove']);
    expect(result.transformed).not.toContain('dead');
    expect(result.transformed).toContain('var a = 5');
  });
});

describe('ast_transform_beautify tool', () => {
  it('is a declared tool', () => {
    expect(transformTools.map((tool) => tool.name)).toContain('ast_transform_beautify');
  });

  it('beautifies code, reports the change, and omits the diff by default', async () => {
    const body = parseJson<{
      beautified: string;
      changed: boolean;
      diff?: string;
      stats: { originalLines: number; beautifiedLines: number; originalSize: number };
    }>(await createHandlers().handleAstTransformBeautifyTool({ code: MINIFIED }));

    expect(body.changed).toBe(true);
    expect(body.beautified).toContain('\n  return c + 1;\n');
    expect(body.stats.originalLines).toBe(1);
    expect(body.stats.beautifiedLines).toBeGreaterThan(1);
    expect(body.stats.originalSize).toBe(MINIFIED.length);
    expect(body.diff).toBeUndefined();
  });

  it('reports changed=false for already formatted input', async () => {
    const formatted = applyTransforms(MINIFIED, ['beautify']).transformed;
    const body = parseJson<{ beautified: string; changed: boolean }>(
      await createHandlers().handleAstTransformBeautifyTool({ code: formatted }),
    );
    expect(body.changed).toBe(false);
    expect(body.beautified).toBe(formatted);
  });

  it('includes a diff when asked', async () => {
    const body = parseJson<{ diff: string }>(
      await createHandlers().handleAstTransformBeautifyTool({
        code: MINIFIED,
        includeDiff: true,
      }),
    );
    expect(typeof body.diff).toBe('string');
    expect(body.diff).toContain('+');
  });

  it('errors when neither code nor scriptId is provided', async () => {
    const body = parseJson<{ tool: string; error: string }>(
      await createHandlers().handleAstTransformBeautifyTool({}),
    );
    expect(body.tool).toBe('ast_transform_beautify');
    expect(body.error).toContain('Either code or scriptId');
  });

  it('keeps wrapper responses un-nested', async () => {
    const body = parseJson<{ content?: unknown }>(
      await createHandlers().handleAstTransformBeautifyTool({ code: MINIFIED }),
    );
    expect(body.content).toBeUndefined();
  });
});
