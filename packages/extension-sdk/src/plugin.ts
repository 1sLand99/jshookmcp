import type { CallToolResult, JSONValue, Tool } from '@modelcontextprotocol/server';
import { toTextResponse, toErrorResponse } from '@extension-sdk/bridges/shared';
import type { WorkflowContract } from './workflow.js';

export type ToolProfileId = 'search' | 'workflow' | 'full';
export type ToolArgs = Record<string, unknown>;
export type ToolResponse = CallToolResult;

export type PluginState =
  | 'loaded'
  | 'validated'
  | 'registered'
  | 'activated'
  | 'deactivated'
  | 'unloaded';

export interface PluginLifecycleContext {
  readonly pluginId: string;
  readonly pluginRoot: string;
  readonly config: Record<string, unknown>;
  readonly state: PluginState;
  registerMetric(metricName: string): void;
  invokeTool(name: string, args?: ToolArgs): Promise<ToolResponse>;
  /**
   * Check whether the plugin has a given capability.
   *
   * @experimental Currently always returns `true`. A fine-grained permission
   * model is planned for a future release — call sites should still guard on
   * the return value so they work correctly once enforcement is enabled.
   */
  hasPermission(capability: string): boolean;
  getConfig<T = unknown>(path: string, fallback?: T): T;
  setRuntimeData(key: string, value: unknown): void;
  getRuntimeData<T = unknown>(key: string): T | undefined;
}

export type ExtensionToolHandler = (
  args: ToolArgs,
  ctx: PluginLifecycleContext,
) => Promise<ToolResponse>;

export type ExtensionToolInputSchema = Tool['inputSchema'];

export interface ExtensionToolDefinition {
  name: string;
  description: string;
  schema: ExtensionToolInputSchema;
  handler: ExtensionToolHandler;
  /** Profile tiers this tool should be available in (default: ['full']). */
  profiles?: ToolProfileId[];
}

export type ExtensionWorkflowDefinition = WorkflowContract;

// ── Tool-execution interception hooks ──
//
// Hooks let a plugin observe — and programmatically gate or rewrite — calls to
// the tools it declared in its own manifest. They are intentionally scoped to
// the plugin's own tools (least privilege); platform-wide interception of
// unrelated tools is left to a future opt-in config switch.

/**
 * Decision returned by a `ToolExecuteBeforeHook`.
 *
 * - `allow`  → execution proceeds; `args` (when provided and not `undefined`)
 *              replaces the arguments passed to the tool. Omitting `args` (or
 *              returning plain `void`) leaves the incoming arguments unchanged.
 * - `deny`   → the tool is NOT executed; the caller receives an error response
 *              carrying `reason` and the denying plugin's id.
 */
export type ToolExecuteBeforeResult =
  | { action: 'allow'; args?: unknown }
  | { action: 'deny'; reason: string };

/**
 * Decision returned by a `ToolExecuteAfterHook`.
 *
 * - `allow`  → the tool result is kept; `result` (when provided and not
 *              `undefined`) replaces the result. Omitting `result` (or
 *              returning plain `void`) leaves the result unchanged.
 * - `redact` → the tool result is replaced with a placeholder that surfaces
 *              `reason` (and the redacting plugin's id) to the caller; the
 *              original result is discarded and only the `reason` is logged.
 *
 * The `result` a hook receives — and any value it rewrites with — is the tool's
 * full response value (an MCP `CallToolResult`-shaped object), not a bare
 * payload.
 */
export type ToolExecuteAfterResult =
  | { action: 'allow'; result?: unknown }
  | { action: 'redact'; reason: string };

/**
 * Runs before the plugin's tool executes. Multiple hooks chain: the args
 * rewritten by one hook are the input of the next.
 *
 * Returning `undefined` (or nothing) means "allow, no rewrite".
 */
export type ToolExecuteBeforeHook = (
  toolName: string,
  args: unknown,
) => Promise<ToolExecuteBeforeResult | void>;

/**
 * Runs after the plugin's tool executed successfully (a thrown handler error
 * skips after hooks). Multiple hooks chain: the result rewritten by one hook is
 * the input of the next.
 *
 * Returning `undefined` (or nothing) means "allow, no rewrite".
 */
export type ToolExecuteAfterHook = (
  toolName: string,
  args: unknown,
  result: unknown,
) => Promise<ToolExecuteAfterResult | void>;

// ── Response helpers (delegates to bridge) ──

/** Build a success JSON response for an MCP tool. Alias of `toTextResponse`. */
export const jsonResponse: (payload: Record<string, unknown>) => ToolResponse = toTextResponse;

/** Build an error JSON response for an MCP tool. Alias of `toErrorResponse`. */
export const errorResponse: (
  tool: string,
  error: unknown,
  extra?: Record<string, unknown>,
) => ToolResponse = toErrorResponse;

// ── ExtensionBuilder ──

export class ExtensionBuilder {
  // ── state ──
  private readonly idValue: string;
  private readonly versionValue: string;
  private compatibleCoreValue: string = '>=0.1.0';
  private profilesValue: ToolProfileId[] = ['full'];
  private toolsValue: ExtensionToolDefinition[] = [];
  private workflowsValue: ExtensionWorkflowDefinition[] = [];
  private allowedCommandsValue: string[] = [];
  private allowedHostsValue: string[] = [];
  private allowedToolsValue: string[] = [];
  private metricsValue: string[] = [];
  private configDefaultsValue: Record<string, unknown> = {};
  private onLoadHandlerValue?: (ctx: PluginLifecycleContext) => Promise<void> | void;
  private onValidateHandlerValue?: (
    ctx: PluginLifecycleContext,
  ) => Promise<{ valid: boolean; errors: string[] }> | { valid: boolean; errors: string[] };
  private onActivateHandlerValue?: (ctx: PluginLifecycleContext) => Promise<void> | void;
  private onDeactivateHandlerValue?: (ctx: PluginLifecycleContext) => Promise<void> | void;
  private toolExecuteBeforeHooksValue: ToolExecuteBeforeHook[] = [];
  private toolExecuteAfterHooksValue: ToolExecuteAfterHook[] = [];

  constructor(id: string, version: string) {
    this.idValue = id;
    this.versionValue = version;
  }

  // ── accessors ──

  get id(): string {
    return this.idValue;
  }
  get version(): string {
    return this.versionValue;
  }
  get compatibleCoreRange(): string {
    return this.compatibleCoreValue;
  }
  get profiles(): ToolProfileId[] {
    return this.profilesValue;
  }
  get tools(): ExtensionToolDefinition[] {
    return this.toolsValue;
  }
  get workflows(): ExtensionWorkflowDefinition[] {
    return this.workflowsValue;
  }
  get allowedCommands(): string[] {
    return this.allowedCommandsValue;
  }
  get allowedHosts(): string[] {
    return this.allowedHostsValue;
  }
  get allowedTools(): string[] {
    return this.allowedToolsValue;
  }
  get declaredMetrics(): string[] {
    return this.metricsValue;
  }
  get configDefaults(): Record<string, unknown> {
    return this.configDefaultsValue;
  }
  get onLoadHandler(): ((ctx: PluginLifecycleContext) => Promise<void> | void) | undefined {
    return this.onLoadHandlerValue;
  }
  get onValidateHandler():
    | ((
        ctx: PluginLifecycleContext,
      ) => Promise<{ valid: boolean; errors: string[] }> | { valid: boolean; errors: string[] })
    | undefined {
    return this.onValidateHandlerValue;
  }
  get onActivateHandler(): ((ctx: PluginLifecycleContext) => Promise<void> | void) | undefined {
    return this.onActivateHandlerValue;
  }
  get onDeactivateHandler(): ((ctx: PluginLifecycleContext) => Promise<void> | void) | undefined {
    return this.onDeactivateHandlerValue;
  }
  /** Registered before-execution hooks, in registration order. */
  get toolExecuteBeforeHooks(): ToolExecuteBeforeHook[] {
    return this.toolExecuteBeforeHooksValue;
  }
  /** Registered after-execution hooks, in registration order. */
  get toolExecuteAfterHooks(): ToolExecuteAfterHook[] {
    return this.toolExecuteAfterHooksValue;
  }

  // ── setters ──

  compatibleCore(range: string): this {
    this.compatibleCoreValue = range;
    return this;
  }
  profile(p: ToolProfileId | ToolProfileId[]): this {
    this.profilesValue = Array.isArray(p) ? p : [p];
    return this;
  }
  allowCommand(cmd: string | string[]): this {
    this.allowedCommandsValue.push(...(Array.isArray(cmd) ? cmd : [cmd]));
    return this;
  }
  allowHost(host: string | string[]): this {
    this.allowedHostsValue.push(...(Array.isArray(host) ? host : [host]));
    return this;
  }
  allowTool(tool: string | string[]): this {
    this.allowedToolsValue.push(...(Array.isArray(tool) ? tool : [tool]));
    return this;
  }
  metric(m: string | string[]): this {
    this.metricsValue.push(...(Array.isArray(m) ? m : [m]));
    return this;
  }
  configDefault(key: string, value: unknown): this {
    this.configDefaultsValue[key] = value;
    return this;
  }

  /**
   * Register a tool exposed by this extension.
   *
   * @param name    Unique tool name (must not collide with built-in tools).
   * @param desc    Human-readable description shown to the AI model.
   * @param schema  JSON-Schema **properties** object — the builder automatically
   *                wraps it in `{ type: 'object', properties: … }`, so you only
   *                need to pass the inner properties map.
   *                Example: `{ text: { type: 'string', description: 'Input' } }`
   * @param handler Async function `(args, ctx) => ToolResponse`.
   * @param profiles Optional profile tiers for this specific tool (defaults to extension-level profiles).
   */
  tool(
    name: string,
    desc: string,
    schema: Record<string, JSONValue>,
    handler: ExtensionToolHandler,
    profiles?: ToolProfileId[],
  ): this {
    this.toolsValue.push({
      name,
      description: desc,
      schema: { type: 'object', properties: schema },
      handler,
      profiles,
    });
    return this;
  }

  /**
   * Register one or more workflow contracts exposed by this extension.
   *
   * These workflows are registered by the core extension manager alongside
   * standalone workflow roots, while still preserving plugin ownership.
   */
  workflow(workflow: ExtensionWorkflowDefinition | ExtensionWorkflowDefinition[]): this {
    this.workflowsValue.push(...(Array.isArray(workflow) ? workflow : [workflow]));
    return this;
  }

  onLoad(h: (ctx: PluginLifecycleContext) => Promise<void> | void): this {
    this.onLoadHandlerValue = h;
    return this;
  }
  onValidate(
    h: (
      ctx: PluginLifecycleContext,
    ) => Promise<{ valid: boolean; errors: string[] }> | { valid: boolean; errors: string[] },
  ): this {
    this.onValidateHandlerValue = h;
    return this;
  }
  onActivate(h: (ctx: PluginLifecycleContext) => Promise<void> | void): this {
    this.onActivateHandlerValue = h;
    return this;
  }
  onDeactivate(h: (ctx: PluginLifecycleContext) => Promise<void> | void): this {
    this.onDeactivateHandlerValue = h;
    return this;
  }

  /**
   * Register a hook that runs before this plugin's tools execute. May be called
   * multiple times; hooks run in registration order and chain their `args`
   * rewrites. A hook that throws is ignored (fail-open) by the runtime.
   */
  onToolExecuteBefore(h: ToolExecuteBeforeHook): this {
    this.toolExecuteBeforeHooksValue.push(h);
    return this;
  }

  /**
   * Register a hook that runs after this plugin's tools execute successfully.
   * May be called multiple times; hooks run in registration order and chain
   * their `result` rewrites. A hook that throws is ignored (fail-open) by the
   * runtime.
   */
  onToolExecuteAfter(h: ToolExecuteAfterHook): this {
    this.toolExecuteAfterHooksValue.push(h);
    return this;
  }
}

export function createExtension(id: string, version: string): ExtensionBuilder {
  return new ExtensionBuilder(id, version);
}
