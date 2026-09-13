import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { UnidbgRunner } from '@modules/binary-instrument/UnidbgRunner';

// Standalone worker fixture (plain .mjs — no TS loader needed): answers every
// request with a successful JVM-shaped result containing session JSON.
const ECHO_WORKER_SOURCE = `
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\\n');
}
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let index = buffer.indexOf('\\n');
  while (index !== -1) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (line.length > 0) handleLine(line);
    index = buffer.indexOf('\\n');
  }
});
function handleLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.type === 'start') {
    send({
      type: 'result',
      id: msg.id,
      result: { stdout: '{"id":"fake-session","pid":4321}\\n', stderr: '', exitCode: 0 },
    });
  }
}
`;

describe('UnidbgRunner', () => {
  const originalUnidbgJar = process.env['UNIDBG_JAR'];

  beforeEach(() => {
    delete process.env['UNIDBG_JAR'];
  });

  afterEach(() => {
    if (originalUnidbgJar === undefined) {
      delete process.env['UNIDBG_JAR'];
    } else {
      process.env['UNIDBG_JAR'] = originalUnidbgJar;
    }
  });

  describe('close', () => {
    it('does not throw when closing an unlaunched runner', () => {
      const r = new UnidbgRunner();
      expect(() => r.close()).not.toThrow();
    });

    it('can be called multiple times safely', () => {
      const r = new UnidbgRunner();
      r.close();
      expect(() => r.close()).not.toThrow();
    });
  });

  describe('launch', () => {
    it('does not register a stub session when the unidbg subprocess fails', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'unidbg-runner-'));
      const soPath = join(dir, 'libtarget.so');
      const jarPath = join(dir, 'not-a-real-unidbg.jar');
      await writeFile(soPath, new Uint8Array([0x7f, 0x45, 0x4c, 0x46]));
      await writeFile(jarPath, 'not a jar', 'utf8');

      const runner = new UnidbgRunner();
      await expect(runner.launch(soPath, 'arm64', jarPath)).rejects.toThrow();
      expect(runner.listSessions()).toEqual([]);
      runner.close();
      await rm(dir, { recursive: true, force: true });
    });

    it('drives the JVM invocation through the subprocess worker channel', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'unidbg-runner-e2e-'));
      const workerPath = join(dir, 'unidbg-fixture-worker.mjs');
      const soPath = join(dir, 'libtarget.so');
      const jarPath = join(dir, 'fake-unidbg.jar');
      await writeFile(workerPath, ECHO_WORKER_SOURCE, 'utf8');
      await writeFile(soPath, new Uint8Array([0x7f, 0x45, 0x4c, 0x46]));
      await writeFile(jarPath, 'fake jar', 'utf8');

      const runner = new UnidbgRunner({ workerPath });
      try {
        const launch = await runner.launch(soPath, 'arm64', jarPath);
        expect(launch.sessionId).toBe('fake-session');
        expect(launch.soPath).toBe(soPath);
        expect(launch.arch).toBe('arm64');

        const sessions = runner.listSessions();
        expect(sessions).toHaveLength(1);
        expect(sessions[0]).toMatchObject({ id: 'fake-session', soPath, arch: 'arm64' });
        // The parsed JVM pid lands in the session record (private map, same
        // access pattern as the seedSession helper in this file).
        const internal = (
          runner as unknown as {
            sessions: Map<string, { childProcess?: { pid: number } }>;
          }
        ).sessions.get('fake-session');
        expect(internal?.childProcess?.pid).toBe(4321);
      } finally {
        runner.close();
        await rm(dir, { recursive: true, force: true });
      }
    });
  });

  describe('callFunction', () => {
    it('throws when no session exists', async () => {
      const runner = new UnidbgRunner();
      await expect(runner.callFunction('nonexistent', 'testFunc', {})).rejects.toThrow();
      runner.close();
    });

    it('throws instead of returning a mock result when UNIDBG_JAR is missing', async () => {
      const runner = new UnidbgRunner();
      seedSession(runner, 'session-1');
      await expect(runner.callFunction('session-1', 'testFunc', {})).rejects.toThrow(/UNIDBG_JAR/i);
      runner.close();
    });
  });

  describe('trace', () => {
    it('throws when no session exists', async () => {
      const runner = new UnidbgRunner();
      await expect(runner.trace('nonexistent')).rejects.toThrow();
      runner.close();
    });

    it('throws instead of returning a mock trace when UNIDBG_JAR is missing', async () => {
      const runner = new UnidbgRunner();
      seedSession(runner, 'session-1');
      await expect(runner.trace('session-1')).rejects.toThrow(/UNIDBG_JAR/i);
      runner.close();
    });
  });
});

function seedSession(runner: UnidbgRunner, id: string): void {
  (
    runner as unknown as {
      sessions: Map<string, { id: string; soPath: string; arch: string; startedAt: string }>;
    }
  ).sessions.set(id, {
    id,
    soPath: '/tmp/libtarget.so',
    arch: 'arm64',
    startedAt: new Date(0).toISOString(),
  });
}
