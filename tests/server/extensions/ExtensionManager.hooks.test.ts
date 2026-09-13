import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const loggerMock = vi.hoisted(() => ({
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}));

vi.mock('@utils/logger', () => ({ logger: loggerMock }));

import {
  applyToolExecuteAfterHooks,
  applyToolExecuteBeforeHooks,
  normalizeHookList,
  wrapExtensionToolHandler,
} from '@server/extensions/ExtensionManager.hooks';
import type {
  ExtensionToolHandler,
  PluginLifecycleContext,
  ToolExecuteAfterHook,
  ToolExecuteBeforeHook,
} from '@server/plugins/PluginContract';

const noopContext = {} as PluginLifecycleContext;

function passthroughHandler(result: unknown = { ok: true }): ExtensionToolHandler {
  return vi.fn(async (args: Record<string, unknown>) => ({
    content: [{ type: 'text', text: JSON.stringify({ ok: true, args, result }) }],
  })) as unknown as ExtensionToolHandler;
}

function textPayload(response: unknown): Record<string, unknown> {
  const content = (response as { content: Array<{ type: string; text: string }> }).content;
  return JSON.parse(content[0]!.text) as Record<string, unknown>;
}

describe('ExtensionManager.hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('normalizeHookList', () => {
    it('returns the list when it is an array and an empty list otherwise', () => {
      const hooks: ToolExecuteBeforeHook[] = [async () => undefined];
      expect(normalizeHookList(hooks)).toBe(hooks);
      expect(normalizeHookList(undefined)).toEqual([]);
    });
  });

  describe('applyToolExecuteBeforeHooks', () => {
    it('chains rewritten args between hooks in registration order', async () => {
      const seen: unknown[] = [];
      const first: ToolExecuteBeforeHook = async (_toolName, args) => {
        seen.push(args);
        return { action: 'allow', args: { step: 1 } };
      };
      const second: ToolExecuteBeforeHook = async (_toolName, args) => {
        seen.push(args);
        return { action: 'allow', args: { step: 2 } };
      };

      const outcome = await applyToolExecuteBeforeHooks('p', [first, second], 'p_tool', {
        step: 0,
      });

      expect(outcome).toEqual({ action: 'allow', args: { step: 2 } });
      expect(seen).toEqual([{ step: 0 }, { step: 1 }]);
    });

    it('short-circuits with deny and reports the reason', async () => {
      const later = vi.fn();
      const outcome = await applyToolExecuteBeforeHooks(
        'p',
        [
          async () => ({ action: 'deny', reason: 'blocked' }),
          later as unknown as ToolExecuteBeforeHook,
        ],
        'p_tool',
        {},
      );

      expect(outcome).toEqual({ action: 'deny', reason: 'blocked' });
      expect(later).not.toHaveBeenCalled();
    });

    it('keeps args unchanged for allow without args, void, and undefined-args decisions', async () => {
      const original = { keep: true };
      const outcome = await applyToolExecuteBeforeHooks(
        'p',
        [
          async () => ({ action: 'allow' }),
          async () => undefined,
          async () => ({ action: 'allow', args: undefined }),
        ],
        'p_tool',
        original,
      );
      expect(outcome).toEqual({ action: 'allow', args: original });
    });

    it('is fail-open: a throwing hook is skipped with a warning', async () => {
      const outcome = await applyToolExecuteBeforeHooks(
        'p',
        [
          async () => {
            throw new Error('hook boom');
          },
        ],
        'p_tool',
        { a: 1 },
      );

      expect(outcome).toEqual({ action: 'allow', args: { a: 1 } });
      expect(loggerMock.warn).toHaveBeenCalledWith(
        expect.stringContaining(
          'toolExecuteBefore hook for "p_tool" threw and was ignored (fail-open)',
        ),
        expect.any(Error),
      );
    });
  });

  describe('applyToolExecuteAfterHooks', () => {
    it('chains rewritten results between hooks in registration order', async () => {
      const seen: unknown[] = [];
      const first: ToolExecuteAfterHook = async (_t, _a, result) => {
        seen.push(result);
        return { action: 'allow', result: { v: 1 } };
      };
      const second: ToolExecuteAfterHook = async (_t, _a, result) => {
        seen.push(result);
        return { action: 'allow', result: { v: 2 } };
      };

      const outcome = await applyToolExecuteAfterHooks(
        'p',
        [first, second],
        'p_tool',
        {},
        { v: 0 },
      );

      expect(outcome).toEqual({ action: 'allow', result: { v: 2 } });
      expect(seen).toEqual([{ v: 0 }, { v: 1 }]);
    });

    it('short-circuits with redact and reports the reason', async () => {
      const later = vi.fn();
      const outcome = await applyToolExecuteAfterHooks(
        'p',
        [
          async () => ({ action: 'redact', reason: 'secret' }),
          later as unknown as ToolExecuteAfterHook,
        ],
        'p_tool',
        {},
        { secret: true },
      );

      expect(outcome).toEqual({ action: 'redact', reason: 'secret' });
      expect(later).not.toHaveBeenCalled();
    });

    it('is fail-open: a throwing after-hook is skipped with a warning and the result is kept', async () => {
      const outcome = await applyToolExecuteAfterHooks(
        'p',
        [
          async () => {
            throw new Error('after boom');
          },
        ],
        'p_tool',
        {},
        { keep: 'me' },
      );

      expect(outcome).toEqual({ action: 'allow', result: { keep: 'me' } });
      expect(loggerMock.warn).toHaveBeenCalledWith(
        expect.stringContaining(
          'toolExecuteAfter hook for "p_tool" threw and was ignored (fail-open)',
        ),
        expect.any(Error),
      );
    });
  });

  describe('wrapExtensionToolHandler', () => {
    it('returns the original handler untouched when the plugin has no hooks', () => {
      const handler = passthroughHandler();
      const wrapped = wrapExtensionToolHandler({
        pluginId: 'p',
        toolName: 'p_tool',
        beforeHooks: [],
        afterHooks: [],
        handler,
      });
      expect(wrapped).toBe(handler);
    });

    it('deny: returns an isError response with reason and plugin name and never executes the tool', async () => {
      const handler = passthroughHandler();
      const wrapped = wrapExtensionToolHandler({
        pluginId: 'guardian',
        toolName: 'p_tool',
        beforeHooks: [async () => ({ action: 'deny', reason: 'nope' })],
        afterHooks: [],
        handler,
      });

      const response = await wrapped({ q: 1 }, noopContext);

      expect((response as { isError?: boolean }).isError).toBe(true);
      expect(textPayload(response)).toMatchObject({
        success: false,
        tool: 'p_tool',
        deniedBy: 'guardian',
        reason: 'nope',
      });
      expect(handler).not.toHaveBeenCalled();
    });

    it('allow with rewrite: the tool receives the rewritten args and its result is returned', async () => {
      const handler = passthroughHandler();
      const wrapped = wrapExtensionToolHandler({
        pluginId: 'p',
        toolName: 'p_tool',
        beforeHooks: [
          async (_t, args) => ({ action: 'allow', args: { ...(args as object), injected: true } }),
        ],
        afterHooks: [],
        handler,
      });

      const response = await wrapped({ q: 1 }, noopContext);

      expect(textPayload(response).args).toEqual({ q: 1, injected: true });
    });

    it('redact: the tool result is replaced with a placeholder carrying reason and plugin name', async () => {
      const handler = passthroughHandler({ secret: 's3cr3t' });
      const wrapped = wrapExtensionToolHandler({
        pluginId: 'redactor',
        toolName: 'p_tool',
        beforeHooks: [],
        afterHooks: [async () => ({ action: 'redact', reason: 'sensitive' })],
        handler,
      });

      const response = await wrapped({}, noopContext);

      expect((response as { isError?: boolean }).isError).toBeUndefined();
      expect(textPayload(response)).toMatchObject({
        success: true,
        tool: 'p_tool',
        redacted: true,
        redactedBy: 'redactor',
        reason: 'sensitive',
      });
      expect(JSON.stringify(textPayload(response))).not.toContain('s3cr3t');
    });

    it('allow with rewrite in after-hooks replaces the result (full response shape)', async () => {
      const handler = passthroughHandler({ raw: true });
      const wrapped = wrapExtensionToolHandler({
        pluginId: 'p',
        toolName: 'p_tool',
        beforeHooks: [],
        afterHooks: [
          async (_toolName, _args, result) => ({
            action: 'allow' as const,
            result: {
              content: [
                {
                  type: 'text' as const,
                  text: JSON.stringify({ rewritten: true, prior: result !== undefined }),
                },
              ],
            },
          }),
        ],
        handler,
      });

      const response = await wrapped({}, noopContext);

      expect(textPayload(response)).toEqual({ rewritten: true, prior: true });
    });

    it('fail-open end to end: throwing before-hook lets the tool run with original args', async () => {
      const handler = passthroughHandler();
      const wrapped = wrapExtensionToolHandler({
        pluginId: 'p',
        toolName: 'p_tool',
        beforeHooks: [
          async () => {
            throw new Error('before boom');
          },
        ],
        afterHooks: [
          async () => {
            throw new Error('after boom');
          },
        ],
        handler,
      });

      const response = await wrapped({ original: true }, noopContext);

      expect(handler).toHaveBeenCalledWith({ original: true }, noopContext);
      expect(textPayload(response).args).toEqual({ original: true });
      expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    });
  });
});
