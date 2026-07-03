import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { tool } from '@server/registry/tool-builder';

export const canvasTools: Tool[] = [
  tool('canvas_engine_fingerprint', (t) =>
    t.desc('Detect Canvas/WebGL game engines in the page.').query(),
  ),
  tool('canvas_scene_dump', (t) =>
    t
      .desc('Extract the full scene tree / display list from a detected canvas engine.')
      .string('canvasId', 'Canvas element ID or index to target')
      .number('maxDepth', 'Maximum tree traversal depth', { default: 20 })
      .boolean('onlyInteractive', 'Only include interactive (mouseEnabled) nodes', {
        default: false,
      })
      .boolean('onlyVisible', 'Only include visible nodes', { default: false })
      .query(),
  ),
  tool('canvas_pick_object_at_point', (t) =>
    t
      .desc(
        "Pick / hit-test the topmost object at a given screen coordinate using the engine's hit-test system",
      )
      .number('x', 'Screen X coordinate')
      .number('y', 'Screen Y coordinate')
      .string('canvasId', 'Canvas element ID or index to target')
      .boolean('highlight', 'Draw a highlight rectangle on the picked object', { default: false })
      .required('x', 'y')
      .readOnly(),
  ),
  tool('canvas_trace_click_handler', (t) =>
    t
      .desc('Trace a click event from DOM to JS call stack.')
      .number('x', 'Screen X coordinate to click')
      .number('y', 'Screen Y coordinate to click')
      .string('canvasId', 'Canvas element ID or index to target')
      .enum('breakpointType', ['click', 'mousedown', 'pointerdown'], 'Event breakpoint type', {
        default: 'click',
      })
      .number('maxFrames', 'Maximum call stack frames to capture', { default: 50 })
      .requiredOpenWorld('x', 'y'),
  ),
  tool('canvas_scene_search', (t) =>
    t
      .desc(
        'Search a previously-dumped scene tree (canvas_scene_dump output) for nodes by name ' +
          'regex and/or type. Pure-compute — no browser session required. Returns matching ' +
          'nodes with their path from root, depth, and engine-specific properties.',
      )
      .prop('sceneTree', {
        type: 'object',
        description: 'Scene tree JSON (the output of canvas_scene_dump)',
        additionalProperties: true,
      })
      .string('namePattern', 'Optional regex matched against node name (case-insensitive)')
      .string('typeFilter', 'Optional exact node type to match (e.g. "Sprite", "Container")')
      .number('maxResults', 'Maximum matches to return', {
        default: 100,
        minimum: 1,
        maximum: 1000,
      })
      .required('sceneTree')
      .query(),
  ),
];
