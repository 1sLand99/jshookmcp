/**
 * Unidbg worker — standalone subprocess entry for {@link UnidbgRunner}.
 *
 * Why a separate process: every Unidbg operation drives a real JVM
 * (`java -jar <unidbg.jar> …`). Running that lifecycle inside the MCP server
 * process means a hung/killed JVM is managed by the server itself, aborts are
 * impossible, and a crashed spawn leaves the tool layer wedged. This entry
 * moves the JVM invocation into a supervised subprocess (see
 * `@utils/subprocess-worker`): the server talks JSONL over stdin/stdout, each
 * request runs one `execFile` with the same options the in-server path used,
 * and stray worker-side exceptions are absorbed by the crash-tolerance
 * window instead of killing the whole session batch.
 *
 * Transport: UTF-8 JSON lines on stdin/stdout (one object per line):
 *   → { type: 'start', id, options: UnidbgWorkerRequest }
 *   → { type: 'abort', id }
 *   ← { type: 'result', id, result: UnidbgWorkerResult }
 *   ← { type: 'error', id, message }
 */

import { execFile, type ChildProcess, type ExecFileException } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve as resolvePath } from 'node:path';

import { runSubprocessWorker } from '@utils/subprocess-worker';

/** One JVM invocation, mirroring the previous in-server `execFile` options. */
export interface UnidbgWorkerRequest {
  /** Java executable (absolute via JAVA_HOME, or bare `java`). */
  file: string;
  /** JVM arguments, e.g. `['-jar', jarPath, '--so', soPath, '--arch', arch, '--server']`. */
  args: string[];
  /** Per-invocation deadline in ms (UNIDBG_TIMEOUT_MS). */
  timeoutMs: number;
  /** Stdout/stderr cap in bytes (UNIDBG_MAX_BUFFER_BYTES). */
  maxBuffer: number;
}

export interface UnidbgWorkerResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Terminate a JVM child and (on Windows) its tree — java ignores SIGTERM there. */
function killJvm(child: ChildProcess): void {
  try {
    child.kill('SIGKILL');
  } catch {
    // already gone
  }
  if (child.pid !== undefined && child.pid > 0 && process.platform === 'win32') {
    execFile('taskkill', ['/F', '/T', '/PID', String(child.pid)], () => {});
  }
}

/**
 * Run one unidbg JVM invocation. Behavior-compatible with the previous
 * in-server `execFileUtf8`: success (exit 0) resolves with captured output;
 * non-zero exit, timeout, abort, or spawn failure throws so the parent sees
 * a normalized error frame.
 */
export function executeUnidbgCommand(
  request: UnidbgWorkerRequest,
  context: { signal: AbortSignal },
): Promise<UnidbgWorkerResult> {
  // The abort frame can race the handler's first microtask — honour an
  // already-aborted signal before spawning the JVM.
  if (context.signal.aborted) {
    return Promise.reject(new Error('unidbg command aborted before start'));
  }
  const { file, args, timeoutMs, maxBuffer } = request;
  if (typeof file !== 'string' || file.length === 0) {
    return Promise.reject(new Error('unidbg worker: "file" is required'));
  }
  if (!Array.isArray(args)) {
    return Promise.reject(new Error('unidbg worker: "args" must be an array'));
  }

  return new Promise<UnidbgWorkerResult>((resolve, reject) => {
    const child = execFile(
      file,
      args,
      {
        timeout: timeoutMs,
        windowsHide: true,
        maxBuffer,
        encoding: 'utf8',
      },
      (error, stdout, stderr) => {
        finish(error ?? null, stdout, stderr);
      },
    );

    let settled = false;
    const finish = (error: Error | null, stdout?: string | null, stderr?: string | null): void => {
      if (settled) return;
      settled = true;
      context.signal.removeEventListener('abort', onAbort);
      if (error) {
        // Node types the callback error as Error; execFile failures are
        // ExecFileException which carries `killed`/`signal`.
        const execError = error as ExecFileException;
        const stdoutText = typeof stdout === 'string' ? stdout : '';
        const stderrText = typeof stderr === 'string' ? stderr : '';
        const detail = (stderrText.trim() || stdoutText.trim()).slice(0, 500);
        // execFile kills on timeout (SIGTERM + killed flag) and aborts land
        // here as a killed child as well — distinguish via the signal.
        if (execError.killed) {
          if (context.signal.aborted) {
            reject(new Error(`unidbg command aborted${detail ? `: ${detail}` : ''}`));
          } else {
            reject(
              new Error(
                `unidbg command timed out after ${timeoutMs}ms${detail ? `: ${detail}` : ''}`,
              ),
            );
          }
          return;
        }
        reject(new Error(detail ? `${error.message}: ${detail}` : error.message));
        return;
      }
      resolve({
        stdout: typeof stdout === 'string' ? stdout : '',
        stderr: typeof stderr === 'string' ? stderr : '',
        exitCode: 0,
      });
    };

    // Parent-initiated abort (AbortSignal propagated through the worker
    // protocol): force-kill the JVM; the pending execFile callback then
    // reports the killed child and finish() rejects as 'aborted'.
    const onAbort = (): void => {
      killJvm(child);
    };
    context.signal.addEventListener('abort', onAbort, { once: true });

    child.on('error', (error) => {
      finish(error as Error, '', '');
    });
  });
}

// ============================================================
// Entry bootstrap
// ============================================================

/** True when this module is the spawned entry (not imported by tests/tools). */
function isMainEntry(): boolean {
  const argvPath = process.argv[1];
  if (!argvPath) return false;
  try {
    // Case-insensitive compare: Windows drive-letter casing can differ
    // between import.meta.url and the spawned argv path.
    return resolvePath(argvPath).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
  } catch {
    return false;
  }
}

if (isMainEntry()) {
  runSubprocessWorker<UnidbgWorkerRequest, UnidbgWorkerResult>(executeUnidbgCommand);
}
