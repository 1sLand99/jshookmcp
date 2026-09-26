/**
 * Canonical list of transform kinds for the transform domain.
 *
 * Single source of truth for the two consumers that used to keep their own
 * hand-maintained copies of this list:
 *   - `definitions.ts`     — JSON-schema `enum` for the `ast_transform_*` tools
 *   - `handlers/shared.ts` — runtime validation set used by `parseTransforms`
 *
 * Those copies drifted (a `beautify` kind existed in neither), which is exactly
 * the failure mode this module removes: adding a kind here is now the only edit
 * required for it to be accepted by both the schema and the runtime validator.
 *
 * Deliberately dependency-free. `definitions.ts` is imported eagerly by the
 * domain registry at server start, so it must not transitively pull in handler
 * runtime dependencies (WorkerPool, ScriptManager, ...).
 */
export const SUPPORTED_TRANSFORMS = [
  'constant_fold',
  'string_decrypt',
  'dead_code_remove',
  'control_flow_flatten',
  'rename_vars',
  'beautify',
] as const;

export type TransformKind = (typeof SUPPORTED_TRANSFORMS)[number];
