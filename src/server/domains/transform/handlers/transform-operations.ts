/**
 * Standalone transform operations for the transform domain.
 *
 * These were extracted from the legacy `TransformToolHandlersOps` monolith
 * (since removed) and are now the only implementation: the production chain is
 * `handlers.impl.core.ts` -> `handlers/*`.
 */

import type { TransformKind, ApplyResult, TransformChainDefinition } from './shared';
import { TransformLimit, parseTransforms } from './shared';
import { buildLineDiff } from './diff';
import {
  transformBeautifyAst,
  transformConstantFoldAst,
  transformControlFlowFlattenAst,
  transformDeadCodeRemoveAst,
  transformRenameVarsAst,
  transformStringDecryptAst,
} from './ast-ops';

export function resolveTransformsForApply(
  chains: Map<string, TransformChainDefinition>,
  chainName: string,
  transformsRaw: unknown,
): TransformKind[] {
  if (chainName.length > 0) {
    const chain = chains.get(chainName);
    if (!chain) throw new Error(`Transform chain not found: ${chainName}`);
    return [...chain.transforms];
  }
  return parseTransforms(transformsRaw);
}

export function applyTransforms(code: string, transforms: TransformKind[]): ApplyResult {
  let transformed = code;
  const appliedTransforms: TransformKind[] = [];
  for (const transform of transforms) {
    const before = transformed;
    transformed = applySingleTransform(transformed, transform);
    if (transformed !== before) appliedTransforms.push(transform);
  }
  return { transformed, appliedTransforms };
}

function transformConstantFold(code: string): string {
  return transformConstantFoldAst(code);
}

function transformStringDecrypt(code: string): string {
  return transformStringDecryptAst(code);
}

function transformDeadCodeRemove(code: string): string {
  return transformDeadCodeRemoveAst(code);
}

function transformControlFlowFlatten(code: string): string {
  return transformControlFlowFlattenAst(code);
}

function transformRenameVars(code: string): string {
  return transformRenameVarsAst(code);
}

function transformBeautify(code: string): string {
  return transformBeautifyAst(code);
}

/**
 * Exhaustive dispatch table.
 *
 * Typing this as `Record<TransformKind, ...>` turns "a member was added to
 * `TransformKind` but its implementation was not wired up" into a compile
 * error. The `switch` this replaced ended in `default: return code`, so the
 * same mistake instead produced a silent no-op: the tool accepted the new kind,
 * reported success, and changed nothing.
 */
const TRANSFORM_IMPLS: Record<TransformKind, (code: string) => string> = {
  constant_fold: transformConstantFold,
  string_decrypt: transformStringDecrypt,
  dead_code_remove: transformDeadCodeRemove,
  control_flow_flatten: transformControlFlowFlatten,
  rename_vars: transformRenameVars,
  beautify: transformBeautify,
};

function applySingleTransform(code: string, transform: TransformKind): string {
  return TRANSFORM_IMPLS[transform](code);
}

export function buildDiff(original: string, transformed: string): string {
  return buildLineDiff(original, transformed, {
    maxLcsCells: TransformLimit.MAX_LCS_CELLS,
  });
}
