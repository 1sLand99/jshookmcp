/**
 * canvas_scene_search — search a previously-dumped scene tree for nodes
 * matching a name / type / property query.
 *
 * Pure-compute: takes the JSON output of canvas_scene_dump (or any scene tree
 * shaped like { name, type, children }) and walks it without a browser. Useful
 * for locating specific game objects across a large dumped tree without
 * re-running the browser-side extraction.
 */

import type { ToolResponse } from '@server/types';
import { asJsonResponse } from '@server/domains/shared/response';

interface SceneNode {
  name?: unknown;
  type?: unknown;
  id?: unknown;
  children?: unknown;
  [key: string]: unknown;
}

interface SearchMatch {
  name: string;
  type: string;
  path: string[];
  depth: number;
  id?: string;
  properties: Record<string, unknown>;
}

interface SceneSearchResult {
  success: boolean;
  error?: string;
  matchedCount: number;
  truncated: boolean;
  matches: SearchMatch[];
  nodesScanned: number;
}

const META_KEYS = new Set([
  'name',
  'type',
  'id',
  'children',
  'parent',
  'x',
  'y',
  'width',
  'height',
]);

function asString(value: unknown): string {
  return typeof value === 'string'
    ? value
    : value === undefined || value === null
      ? ''
      : String(value);
}

function isSceneNode(value: unknown): value is SceneNode {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Normalize the dumped JSON into a list of root nodes to walk. */
function collectRoots(tree: unknown): SceneNode[] {
  if (Array.isArray(tree)) {
    return tree.filter(isSceneNode);
  }
  if (!isSceneNode(tree)) {
    return [];
  }
  // If the object already looks like a scene node (has name/type), treat as bare root.
  if (tree.name !== undefined || tree.type !== undefined) {
    return [tree];
  }
  // Otherwise unwrap a common wrapper key (root/tree/scene/nodes/children).
  for (const key of ['root', 'tree', 'scene', 'nodes', 'children']) {
    const inner = tree[key];
    if (isSceneNode(inner)) {
      return [inner];
    }
    if (Array.isArray(inner)) {
      const filtered = inner.filter(isSceneNode);
      if (filtered.length > 0) return filtered;
    }
  }
  return [];
}

function buildProperties(node: SceneNode): Record<string, unknown> {
  const props: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (!META_KEYS.has(key)) {
      props[key] = value;
    }
  }
  return props;
}

export async function handleSceneSearch(args: Record<string, unknown>): Promise<ToolResponse> {
  const tree = args['sceneTree'];
  if (tree === undefined || tree === null) {
    return asJsonResponse({
      success: false,
      error: 'sceneTree is required (pass the output of canvas_scene_dump)',
    });
  }

  const namePattern = typeof args['namePattern'] === 'string' ? args['namePattern'] : undefined;
  const typeFilter = typeof args['typeFilter'] === 'string' ? args['typeFilter'] : undefined;
  const maxResults =
    typeof args['maxResults'] === 'number' && args['maxResults'] > 0 ? args['maxResults'] : 100;

  let nameRegex: RegExp | undefined;
  if (namePattern) {
    try {
      nameRegex = new RegExp(namePattern, 'i');
    } catch {
      return asJsonResponse({
        success: false,
        error: `Invalid namePattern regex: ${namePattern}`,
      });
    }
  }

  const roots = collectRoots(tree);
  if (roots.length === 0) {
    return asJsonResponse({
      success: false,
      error: 'sceneTree did not contain any recognizable scene nodes',
    });
  }

  const matches: SearchMatch[] = [];
  let nodesScanned = 0;

  const walk = (node: SceneNode, path: string[], depth: number): void => {
    nodesScanned++;
    const name = asString(node.name);
    const type = asString(node.type);

    const nameMatch = !nameRegex || nameRegex.test(name);
    const typeMatch = !typeFilter || type.toLowerCase() === typeFilter.toLowerCase();
    if (nameMatch && typeMatch && (nameRegex || typeFilter)) {
      matches.push({
        name,
        type,
        path: [...path, name || type || '<anonymous>'],
        depth,
        ...(typeof node.id === 'string' || typeof node.id === 'number'
          ? { id: String(node.id) }
          : {}),
        properties: buildProperties(node),
      });
    }

    if (Array.isArray(node.children)) {
      const childPath = [...path, name || type || '<anonymous>'];
      for (const child of node.children) {
        if (isSceneNode(child)) {
          walk(child, childPath, depth + 1);
        }
      }
    }
  };

  for (const root of roots) {
    walk(root, [], 0);
    if (matches.length >= maxResults) break;
  }

  const truncated = matches.length > maxResults;
  const capped = matches.slice(0, maxResults);

  const result: SceneSearchResult = {
    success: true,
    matchedCount: matches.length,
    truncated,
    matches: capped,
    nodesScanned,
  };
  return asJsonResponse(result);
}
