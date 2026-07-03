import { describe, expect, it } from 'vitest';
import { handleSceneSearch } from '@server/domains/canvas/handlers/scene-search';

function parseJson(res: unknown): Record<string, unknown> {
  const r = res as { content: Array<{ type: string; text: string }> };
  return JSON.parse(r.content[0]!.text);
}

const SAMPLE_TREE = {
  root: {
    name: 'Stage',
    type: 'Container',
    children: [
      {
        name: 'Background',
        type: 'Sprite',
        texture: 'bg.png',
        children: [],
      },
      {
        name: 'Player',
        type: 'Container',
        children: [
          { name: 'PlayerSprite', type: 'Sprite', texture: 'hero.png', visible: true },
          { name: 'HealthBar', type: 'Graphics', percent: 100 },
        ],
      },
      {
        name: 'EnemyBoss',
        type: 'Sprite',
        texture: 'boss.png',
        hp: 5000,
      },
    ],
  },
};

describe('handleSceneSearch', () => {
  it('matches nodes by name regex (case-insensitive)', async () => {
    const res = await handleSceneSearch({ sceneTree: SAMPLE_TREE, namePattern: 'player' });
    const json = parseJson(res);

    expect(json.success).toBe(true);
    const matches = json.matches as Array<{ name: string }>;
    const names = matches.map((m) => m.name);
    expect(names).toContain('Player');
    expect(names).toContain('PlayerSprite');
  });

  it('matches nodes by exact type', async () => {
    const res = await handleSceneSearch({ sceneTree: SAMPLE_TREE, typeFilter: 'Sprite' });
    const json = parseJson(res);

    const matches = json.matches as Array<{ type: string }>;
    expect(matches.every((m) => m.type === 'Sprite')).toBe(true);
    expect(matches.length).toBe(3); // Background, PlayerSprite, EnemyBoss
  });

  it('combines name pattern and type filter', async () => {
    const res = await handleSceneSearch({
      sceneTree: SAMPLE_TREE,
      namePattern: 'boss',
      typeFilter: 'Sprite',
    });
    const json = parseJson(res);

    const matches = json.matches as Array<{ name: string }>;
    expect(matches.map((m) => m.name)).toEqual(['EnemyBoss']);
  });

  it('reports the path from root for each match', async () => {
    const res = await handleSceneSearch({ sceneTree: SAMPLE_TREE, namePattern: 'HealthBar' });
    const json = parseJson(res);

    const match = (json.matches as Array<{ path: string[]; depth: number }>)[0]!;
    expect(match.path).toEqual(['Stage', 'Player', 'HealthBar']);
    expect(match.depth).toBe(2);
  });

  it('preserves engine-specific properties on matches', async () => {
    const res = await handleSceneSearch({ sceneTree: SAMPLE_TREE, namePattern: 'EnemyBoss' });
    const json = parseJson(res);

    const match = (json.matches as Array<{ properties: Record<string, unknown> }>)[0]!;
    expect(match.properties.hp).toBe(5000);
    expect(match.properties.texture).toBe('boss.png');
  });

  it('respects maxResults to cap the match list', async () => {
    const res = await handleSceneSearch({
      sceneTree: SAMPLE_TREE,
      typeFilter: 'Sprite',
      maxResults: 1,
    });
    const json = parseJson(res);

    expect(json.matchedCount).toBe(3);
    expect(json.truncated).toBe(true);
    expect((json.matches as unknown[]).length).toBe(1);
  });

  it('counts total nodes scanned', async () => {
    const res = await handleSceneSearch({ sceneTree: SAMPLE_TREE, typeFilter: 'Container' });
    const json = parseJson(res);

    expect(json.nodesScanned).toBe(6); // Stage + 3 children + Player's 2 children
  });

  it('accepts a bare array of nodes as the tree', async () => {
    const res = await handleSceneSearch({
      sceneTree: [{ name: 'A', type: 'Sprite', children: [] }],
      typeFilter: 'Sprite',
    });
    const json = parseJson(res);
    expect((json.matches as unknown[]).length).toBe(1);
  });

  it('returns a structured error when sceneTree is missing', async () => {
    const res = await handleSceneSearch({});
    const json = parseJson(res);
    expect(json.success).toBe(false);
    expect(json.error).toContain('sceneTree');
  });

  it('returns a structured error for an invalid regex', async () => {
    const res = await handleSceneSearch({ sceneTree: SAMPLE_TREE, namePattern: '(' });
    const json = parseJson(res);
    expect(json.success).toBe(false);
    expect(json.error).toContain('Invalid namePattern');
  });
});
