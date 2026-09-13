import { randomUUID } from 'node:crypto';
import { access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { UNIDBG_TIMEOUT_MS } from '@src/constants';
import { ToolError } from '@errors/ToolError';
import { PrerequisiteError } from '@errors/PrerequisiteError';
import { readEnvNullableString } from '@src/config/environment';
import {
  SubprocessWorker,
  SubprocessWorkerError,
  type SubprocessWorkerRequestOptions,
} from '@utils/subprocess-worker';
import type { UnidbgWorkerRequest, UnidbgWorkerResult } from './unidbg-worker';

const UNIDBG_MAX_BUFFER_BYTES = 8 * 1024 * 1024;
/**
 * Slack added on top of the per-invocation JVM deadline when guarding the
 * worker round-trip: the in-worker java `execFile` timeout
 * (UNIDBG_TIMEOUT_MS) must fire first so the ToolError message still reports
 * the unidbg timeout, with the worker deadline acting as a backstop against a
 * wedged worker process.
 */
const WORKER_TIMEOUT_SLACK_MS = 15_000;

export interface UnidbgRunnerOptions {
  /**
   * Override the worker entry path (tests inject a fixture worker). Defaults
   * to the compiled `unidbg-worker.mjs` chunk next to the dist bundle, or the
   * adjacent `.ts` source under tsx dev — the same resolution strategy as the
   * search EmbeddingWorker.
   */
  workerPath?: string;
}

interface UnidbgSession {
  id: string;
  soPath: string;
  arch: string;
  startedAt: string;
  childProcess?: { pid: number };
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

/**
 * Resolve the unidbg worker entry for the current runtime:
 * dist → `dist/modules/binary-instrument/unidbg-worker.mjs` (declared as a
 * dedicated tsdown entry), dev/test → the adjacent `.ts` source executed via
 * the tsx loader (`@utils/subprocess-worker` forwards execArgv / injects
 * `--import tsx`).
 */
function resolveUnidbgWorkerPath(): string {
  const bundledWorkerUrl = new URL(
    './modules/binary-instrument/unidbg-worker.mjs',
    import.meta.url,
  );
  const bundledWorkerPath = fileURLToPath(bundledWorkerUrl);
  if (existsSync(bundledWorkerPath)) {
    return bundledWorkerPath;
  }
  return fileURLToPath(new URL('./unidbg-worker.ts', import.meta.url));
}

export class UnidbgRunner {
  private readonly sessions = new Map<string, UnidbgSession>();
  private readonly workerPath: string;
  private worker: SubprocessWorker | null = null;

  constructor(options: UnidbgRunnerOptions = {}) {
    this.workerPath = options.workerPath ?? resolveUnidbgWorkerPath();
  }

  close(): void {
    for (const session of this.sessions.values()) {
      // Signal child process to terminate if present
      if (session.childProcess) {
        try {
          process.kill(session.childProcess.pid, 'SIGTERM');
        } catch {
          // child already exited
        }
      }
    }
    this.sessions.clear();
    void this.worker?.dispose();
    this.worker = null;
  }

  /**
   * Lazily create the JSONL worker channel. One supervised subprocess serves
   * every launch/call/trace operation of this runner; it survives stray
   * worker-side exceptions (tolerance window) and respawns after a crash.
   */
  private ensureWorker(): SubprocessWorker {
    if (!this.worker) {
      this.worker = new SubprocessWorker({
        name: 'unidbg-worker',
        workerPath: this.workerPath,
      });
    }
    return this.worker;
  }

  /**
   * Launch a .so library in the Unidbg emulator via JVM subprocess.
   * Returns a sessionId for subsequent call/trace operations.
   * The optional `signal` aborts the in-flight JVM invocation.
   */
  async launch(
    soPath: string,
    arch: string = 'arm',
    jarPath?: string,
    options?: { signal?: AbortSignal },
  ): Promise<{ sessionId: string; soPath: string; arch: string }> {
    const resolvedJar = jarPath ?? readEnvNullableString('UNIDBG_JAR', { trim: true });
    if (!resolvedJar) {
      throw new PrerequisiteError(
        'UNIDBG_JAR is not configured. Set the UNIDBG_JAR env var or pass jarPath.',
      );
    }

    try {
      await access(resolvedJar);
    } catch {
      throw new ToolError('NOT_FOUND', `Unidbg JAR not found: ${resolvedJar}`);
    }

    try {
      await access(soPath);
    } catch {
      throw new ToolError('NOT_FOUND', `Shared library not found: ${soPath}`);
    }

    const sessionId = randomUUID();

    const command = this.getJavaCommand();
    const args = ['-jar', resolvedJar, '--so', soPath, '--arch', arch, '--server'];

    try {
      const result = await this.execViaWorker(command, args, UNIDBG_TIMEOUT_MS, options?.signal);
      // Parse session info from JVM output (expected: JSON with {sessionId, pid})
      const sessionInfo = this.parseLaunchOutput(result.stdout, sessionId);

      const session: UnidbgSession = {
        id: sessionInfo.id,
        soPath,
        arch,
        startedAt: new Date().toISOString(),
        childProcess: sessionInfo.pid ? { pid: sessionInfo.pid } : undefined,
      };

      // Key by the session id the JVM reported (randomUUID is only the parse
      // fallback) — call/trace look up sessions by the id launch returned.
      this.sessions.set(sessionInfo.id, session);

      return { sessionId: sessionInfo.id, soPath, arch };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new ToolError('RUNTIME', `Unidbg launch failed: ${message}`);
    }
  }

  async callFunction(
    sessionId: string,
    functionName: string,
    args: Record<string, unknown> = {},
    options?: { signal?: AbortSignal },
  ): Promise<unknown> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new ToolError('NOT_FOUND', `No unidbg session found for ${sessionId}`);
    }

    const jarPath = readEnvNullableString('UNIDBG_JAR', { trim: true });
    if (!jarPath) {
      throw new PrerequisiteError(
        'UNIDBG_JAR is not configured. Set the UNIDBG_JAR env var before calling Unidbg.',
      );
    }

    const command = this.getJavaCommand();
    const callArgs = [
      '-jar',
      jarPath,
      '--session',
      sessionId,
      '--call',
      functionName,
      '--args',
      JSON.stringify(args),
    ];

    try {
      const result = await this.execViaWorker(
        command,
        callArgs,
        UNIDBG_TIMEOUT_MS,
        options?.signal,
      );
      return {
        sessionId,
        functionName,
        args,
        returnValue: this.extractReturnValue(result.stdout),
        stdout: result.stdout.trim(),
        stderr: result.stderr.trim(),
        trace: [],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new ToolError('RUNTIME', `Unidbg call failed: ${message}`);
    }
  }

  async trace(sessionId: string, options?: { signal?: AbortSignal }): Promise<unknown> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new ToolError('NOT_FOUND', `No unidbg session found for ${sessionId}`);
    }

    const jarPath = readEnvNullableString('UNIDBG_JAR', { trim: true });
    if (!jarPath) {
      throw new PrerequisiteError(
        'UNIDBG_JAR is not configured. Set the UNIDBG_JAR env var before tracing Unidbg.',
      );
    }

    const command = this.getJavaCommand();
    const traceArgs = ['-jar', jarPath, '--session', sessionId, '--trace'];

    try {
      const result = await this.execViaWorker(
        command,
        traceArgs,
        UNIDBG_TIMEOUT_MS,
        options?.signal,
      );
      return {
        sessionId,
        trace: this.parseTraceOutput(result.stdout),
        instructionCount: this.countInstructions(result.stdout),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new ToolError('RUNTIME', `Unidbg trace failed: ${message}`);
    }
  }

  /**
   * Get info about an active Unidbg session.
   */
  getSessionInfo(sessionId: string): UnidbgSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * List all active Unidbg sessions.
   */
  listSessions(): Array<{ id: string; soPath: string; arch: string; startedAt: string }> {
    return Array.from(this.sessions.values()).map((s) => ({
      id: s.id,
      soPath: s.soPath,
      arch: s.arch,
      startedAt: s.startedAt,
    }));
  }

  // ── Private helpers ──

  private getJavaCommand(): string {
    return process.env['JAVA_HOME'] ? `${process.env['JAVA_HOME']}/bin/java` : 'java';
  }

  private parseLaunchOutput(
    stdout: string,
    fallbackId: string,
  ): {
    id: string;
    pid: number | null;
  } {
    // Try to parse JSON output from Unidbg server
    const lines = stdout.split(/\r?\n/).filter((l) => l.trim().length > 0);
    for (const line of lines.toReversed()) {
      try {
        const parsed = JSON.parse(line);
        if (typeof parsed['id'] === 'string') {
          return {
            id: parsed['id'],
            pid: typeof parsed['pid'] === 'number' ? parsed['pid'] : null,
          };
        }
      } catch {
        // not JSON, continue
      }
    }
    return { id: fallbackId, pid: null };
  }

  private extractReturnValue(stdout: string): string {
    const match = /return[=:\s]+(0x[0-9a-fA-F]+|-?\d+)/.exec(stdout);
    if (match?.[1]) {
      return match[1];
    }
    return '0x0';
  }

  private parseTraceOutput(stdout: string): string[] {
    return stdout
      .split(/\r?\n/)
      .filter((line) => line.trim().length > 0 && !line.startsWith('{'))
      .slice(0, 10000);
  }

  private countInstructions(stdout: string): number {
    return stdout
      .split(/\r?\n/)
      .filter(
        (line) =>
          line.trim().length > 0 &&
          !line.startsWith('{') &&
          /\b(ldr|str|mov|bl|b|add|sub)\b/i.test(line),
      ).length;
  }

  /**
   * Execute one JVM invocation through the unidbg worker subprocess.
   *
   * Previously this ran `execFile` in the MCP server process with a fixed
   * timeout and no abort. It now goes through
   * `@utils/subprocess-worker`: the JVM lifecycle is isolated from the
   * server, the deadline is enforced by the worker's own `execFile` timeout
   * (preserving the ToolError timing), and an optional `AbortSignal` kills
   * the java process tree. Success/failure shapes are unchanged.
   */
  private async execViaWorker(
    file: string,
    args: string[],
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<CommandResult> {
    const requestOptions: SubprocessWorkerRequestOptions = {
      timeoutMs: timeoutMs + WORKER_TIMEOUT_SLACK_MS,
      signal,
    };
    try {
      const request: UnidbgWorkerRequest = {
        file,
        args,
        timeoutMs,
        maxBuffer: UNIDBG_MAX_BUFFER_BYTES,
      };
      return await this.ensureWorker().request<UnidbgWorkerRequest, UnidbgWorkerResult>(
        request,
        requestOptions,
      );
    } catch (error) {
      // Normalize worker-protocol failures into the same plain-Error shape
      // the old execFile path produced; the public methods wrap it into a
      // ToolError('RUNTIME', 'Unidbg … failed: …') exactly as before.
      if (error instanceof SubprocessWorkerError && error.code === 'TIMEOUT') {
        throw new Error(`unidbg command timed out after ${timeoutMs}ms (worker deadline)`, {
          cause: error,
        });
      }
      throw new Error(error instanceof Error ? error.message : String(error), { cause: error });
    }
  }
}
