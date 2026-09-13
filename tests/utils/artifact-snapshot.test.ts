import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  ArtifactSnapshotManager,
  SnapshotError,
  deriveSnapshotStoreDir,
} from '@utils/artifact-snapshot';

const execFileAsync = promisify(execFile);

/**
 * The suite exercises real git — skipped entirely on machines without a git
 * binary (probe once per worker).
 */
const gitAvailable = await execFileAsync('git', ['--version'])
  .then(() => true)
  .catch(() => false);

const describeIfGit = gitAvailable ? describe : describe.skip;

describeIfGit('ArtifactSnapshotManager', () => {
  let root: string;
  let workTree: string;
  let storeDir: string;
  let manager: ArtifactSnapshotManager;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'jshook-snapshot-'));
    workTree = join(root, 'work');
    storeDir = join(root, 'store');
    await mkdir(workTree, { recursive: true });
    manager = new ArtifactSnapshotManager({ storeDir, workTree });
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  async function readWorkFile(relativePath: string): Promise<string | null> {
    try {
      return await readFile(join(workTree, relativePath), 'utf8');
    } catch {
      return null;
    }
  }

  it('restores file contents after modification (snapshot -> modify -> restore)', async () => {
    await writeFile(join(workTree, 'a.txt'), 'v1');

    const record = await manager.snapshot('before-change');
    expect(record.id).toMatch(/^snap-/);
    expect(record.treeHash).toMatch(/^[0-9a-f]{40}$/i);
    expect(record.label).toBe('before-change');
    expect(record.timestamp).toBeTruthy();

    await writeFile(join(workTree, 'a.txt'), 'v2-changed');

    const result = await manager.restore(record.id);
    expect(result.snapshotId).toBe(record.id);
    expect(result.restoredFiles).toBe(1);
    expect(result.deletedFiles).toBe(0);
    expect(await readWorkFile('a.txt')).toBe('v1');
  });

  it('deletes files created after the snapshot and recreates deleted ones', async () => {
    await mkdir(join(workTree, 'nested', 'deep'), { recursive: true });
    await writeFile(join(workTree, 'a.txt'), 'v1');
    await writeFile(join(workTree, 'nested', 'deep', 'b.txt'), 'nested-v1');

    const record = await manager.snapshot();

    // New file after the snapshot -> must be gone after restore.
    await writeFile(join(workTree, 'c.txt'), 'new');
    // Deleted after the snapshot -> must be written back.
    await rm(join(workTree, 'nested', 'deep', 'b.txt'), { force: true });
    await writeFile(join(workTree, 'a.txt'), 'v2');

    const result = await manager.restore(record.id);

    expect(result.deletedFiles).toBe(1);
    expect(result.deletedSample).toEqual(['c.txt']);
    expect(await readWorkFile('c.txt')).toBeNull();
    expect(await readWorkFile('a.txt')).toBe('v1');
    expect(await readWorkFile(join('nested', 'deep', 'b.txt'))).toBe('nested-v1');
    expect(result.restoredFiles).toBe(2);
  });

  it('lists snapshots newest first with labels and timestamps', async () => {
    const first = await manager.snapshot('first');
    const second = await manager.snapshot('second');

    const snapshots = await manager.list();
    expect(snapshots).toHaveLength(2);
    expect(snapshots.map((entry) => entry.id)).toEqual([second.id, first.id]);
    expect(snapshots[1]?.label).toBe('first');
    expect(snapshots[0]?.label).toBe('second');
    expect(Number.isNaN(Date.parse(snapshots[0]?.timestamp ?? 'x'))).toBe(false);
  });

  it('persists snapshots across manager instances (store-backed metadata)', async () => {
    await writeFile(join(workTree, 'a.txt'), 'v1');
    const record = await manager.snapshot('persisted');

    const reopened = new ArtifactSnapshotManager({ storeDir, workTree });
    const snapshots = await reopened.list();
    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]?.id).toBe(record.id);

    await writeFile(join(workTree, 'a.txt'), 'v2');
    await reopened.restore(record.id);
    expect(await readWorkFile('a.txt')).toBe('v1');
  });

  it('gc removes expired snapshots, keeps recent ones, and prune keeps recent trees', async () => {
    await writeFile(join(workTree, 'a.txt'), 'v1');
    const old = await manager.snapshot('old');
    const recent = await manager.snapshot('recent');

    // Backdate the first snapshot inside the store metadata (white-box).
    const metadataPath = join(storeDir, 'snapshots.json');
    const metadata = JSON.parse(await readFile(metadataPath, 'utf8')) as {
      snapshots: Array<{ id: string; timestamp: string }>;
    };
    const oldTimestamp = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    metadata.snapshots = metadata.snapshots.map((entry) =>
      entry.id === old.id ? { ...entry, timestamp: oldTimestamp } : entry,
    );
    await writeFile(metadataPath, JSON.stringify(metadata, null, 2));

    const result = await manager.gc(7);
    expect(result.removedSnapshots).toBe(1);
    expect(result.remainingSnapshots).toBe(1);
    expect(result.pruned).toBe(true);

    const snapshots = await manager.list();
    expect(snapshots.map((entry) => entry.id)).toEqual([recent.id]);

    // Recent snapshot still restorable after gc (protection ref worked).
    await writeFile(join(workTree, 'a.txt'), 'drifted');
    await manager.restore(recent.id);
    expect(await readWorkFile('a.txt')).toBe('v1');
  });

  it('gc without expired snapshots is a no-op', async () => {
    await manager.snapshot('fresh');
    const result = await manager.gc(7);
    expect(result).toEqual({
      removedSnapshots: 0,
      remainingSnapshots: 1,
      pruned: false,
    });
  });

  it('restore throws SNAPSHOT_NOT_FOUND for unknown ids', async () => {
    const error = await manager.restore('snap-does-not-exist').catch((caught) => caught);
    expect(error).toBeInstanceOf(SnapshotError);
    expect((error as SnapshotError).code).toBe('SNAPSHOT_NOT_FOUND');
  });

  it('rejects a store dir inside the work tree at construction', () => {
    expect(
      () => new ArtifactSnapshotManager({ storeDir: join(workTree, 'store'), workTree }),
    ).toThrowError(/outside the work tree/);
  });

  it('snapshots an empty directory via the empty tree', async () => {
    const record = await manager.snapshot('empty');
    expect(record.treeHash).toMatch(/^[0-9a-f]{40}$/i);

    await writeFile(join(workTree, 'later.txt'), 'x');
    const result = await manager.restore(record.id);
    expect(result.deletedFiles).toBe(1);
    expect(await readWorkFile('later.txt')).toBeNull();
  });

  it('does not index the shadow store during add -A', async () => {
    await writeFile(join(workTree, 'a.txt'), 'v1');
    const record = await manager.snapshot();

    // The store lives outside the work tree, so a later snapshot's tree must
    // be identical to the first when nothing changed.
    const second = await manager.snapshot();
    expect(second.treeHash).toBe(record.treeHash);
    const files = await readdir(workTree);
    expect(files).toEqual(['a.txt']);
  });
});

describeIfGit('deriveSnapshotStoreDir', () => {
  it('is deterministic and keyed by the resolved target', () => {
    const base = resolve(tmpdir(), 'snapshot-stores');
    const target = resolve(tmpdir(), 'some', 'target');
    const a = deriveSnapshotStoreDir(target, base, tmpdir());
    const b = deriveSnapshotStoreDir(target, base, tmpdir());
    expect(a).toBe(b);
    expect(a).toContain('target-');
  });

  it('falls back when the primary base sits inside the target', () => {
    const target = resolve(tmpdir(), 'proj-root');
    const baseInside = join(target, '.cache', 'artifact-snapshots');
    const store = deriveSnapshotStoreDir(target, baseInside, resolve(tmpdir(), 'fallback'));
    expect(store.startsWith(resolve(tmpdir(), 'fallback'))).toBe(true);
  });
});

describe('ArtifactSnapshotManager input validation (no git needed)', () => {
  it('rejects empty storeDir/workTree', () => {
    expect(() => new ArtifactSnapshotManager({ storeDir: '', workTree: '/tmp/w' })).toThrowError(
      SnapshotError,
    );
    expect(() => new ArtifactSnapshotManager({ storeDir: '/tmp/s', workTree: '' })).toThrowError(
      SnapshotError,
    );
  });
});
