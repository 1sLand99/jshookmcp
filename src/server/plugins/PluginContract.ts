// Re-export from the canonical extension-sdk package
export {
  type ToolProfileId,
  type ToolArgs,
  type ToolResponse,
  type PluginState,
  type PluginLifecycleContext,
  type ExtensionToolHandler,
  type ExtensionToolDefinition,
  type ExtensionWorkflowDefinition,
  type ToolExecuteBeforeHook,
  type ToolExecuteBeforeResult,
  type ToolExecuteAfterHook,
  type ToolExecuteAfterResult,
  ExtensionBuilder,
  createExtension,
  jsonResponse,
  errorResponse,
} from '@jshookmcp/extension-sdk/plugin';
