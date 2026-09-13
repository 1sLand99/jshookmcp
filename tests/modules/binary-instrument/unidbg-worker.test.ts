import { describe, expect, it } from 'vitest';

import { executeUnidbgCommand } from '@modules/binary-instrument/unidbg-worker';

/**
 * Unit tests for the unidbg worker handler. The JVM path itself needs
 * java + a real unidbg jar, so these drive the same execFile plumbing with
 * `node -e` children — deterministic and dependency-free.
 */

function noopSignal(): AbortSignal {
  return new AbortController().signal;
}

describe('executeUnidbgCommand', () => {
  it('captures stdout of a successful command', async () => {
    const result = await executeUnidbgCommand(
      {
        file: process.execPath,
        args: ['-e', 'console.log("return=0x42")'],
        timeoutMs: 10_000,
        maxBuffer: 1024 * 1024,
      },
      { signal: noopSignal() },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('return=0x42');
  }, 15_000);

  it('rejects when the command exits non-zero', async () => {
    await expect(
      executeUnidbgCommand(
        {
          file: process.execPath,
          args: ['-e', 'process.stderr.write("jvm exploded\\n"); process.exit(3)'],
          timeoutMs: 10_000,
          maxBuffer: 1024 * 1024,
        },
        { signal: noopSignal() },
      ),
    ).rejects.toThrow(/jvm exploded|Command failed|exited with/i);
  }, 15_000);

  it('rejects when the command times out', async () => {
    await expect(
      executeUnidbgCommand(
        {
          file: process.execPath,
          args: ['-e', 'setInterval(() => {}, 1000)'],
          timeoutMs: 400,
          maxBuffer: 1024 * 1024,
        },
        { signal: noopSignal() },
      ),
    ).rejects.toThrow(/timed out after 400ms/);
  }, 15_000);

  it('kills the command when the signal aborts', async () => {
    const controller = new AbortController();
    const pending = executeUnidbgCommand(
      {
        file: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000)'],
        timeoutMs: 30_000,
        maxBuffer: 1024 * 1024,
      },
      { signal: controller.signal },
    );
    // The child is spawned synchronously inside the handler, so aborting
    // right after the call is deterministic: the kill lands before the
    // 30s deadline.
    controller.abort();
    await expect(pending).rejects.toThrow(/aborted/);
  }, 15_000);

  it('validates the request shape', async () => {
    await expect(
      executeUnidbgCommand(
        { file: '', args: [], timeoutMs: 1000, maxBuffer: 1024 },
        { signal: noopSignal() },
      ),
    ).rejects.toThrow(/file/);
    await expect(
      executeUnidbgCommand(
        {
          file: 'java',
          args: 'not-an-array' as unknown as string[],
          timeoutMs: 1000,
          maxBuffer: 1024,
        },
        { signal: noopSignal() },
      ),
    ).rejects.toThrow(/args/);
  });
});
