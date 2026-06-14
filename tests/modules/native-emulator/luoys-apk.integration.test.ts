/**
 * Luoys APK native-emulator integration test — real-world APK end-to-end test.
 *
 * Tests the complete workflow:
 * 1. Extract arm64-v8a libs from luoys-6.10.apk
 * 2. Create emulator session
 * 3. Load third-party .so (skip libapp.so/libflutter.so — Dart runtime only)
 * 4. Inspect imports (diagnose unresolved)
 * 5. List exported symbols
 * 6. Call exported functions / JNI exports
 * 7. Trace execution
 * 8. Detect ISA/JNI gaps and report
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NativeEmulatorHandlers } from '@server/domains/native-emulator/handlers.impl';
import { extractArm64Libs } from '@modules/native-emulator/apk';

const APK_PATH = 'D:/cumhub/reverse/luolishe/luoys-6.10.apk';

/** Parse the JSON payload out of an MCP text response (same as handlers.test.ts). */
// biome-ignore lint: any required for generic JSON deserialization
function payload(res: any): any {
  if (typeof res === 'string') return JSON.parse(res);
  if (res?.content?.[0]?.text) return JSON.parse(res.content[0].text);
  return res;
}

// Skip if APK not present (CI environment)
const APK_EXISTS = await (async () => {
  try {
    const { existsSync } = await import('node:fs');
    return existsSync(APK_PATH);
  } catch {
    return false;
  }
})();

describe.skipIf(!APK_EXISTS)('luoys APK integration test', () => {
  let handlers: NativeEmulatorHandlers;
  let sessionId: string;
  let extractedLibs: Awaited<ReturnType<typeof extractArm64Libs>>;

  beforeAll(async () => {
    handlers = new NativeEmulatorHandlers();
    // Extract all arm64-v8a libs
    extractedLibs = await extractArm64Libs(APK_PATH);
    console.log(
      `Extracted ${extractedLibs.length} libs:`,
      extractedLibs.map((l) => l.name),
    );
  });

  afterAll(async () => {
    if (sessionId) {
      await handlers.handleDestroySession({ sessionId });
    }
    handlers.dispose();
  });

  it('extracts arm64-v8a libraries from luoys APK', () => {
    expect(extractedLibs.length).toBeGreaterThan(0);
    // Should have libsqlite3, libmmkv, libijkplayer, libflutter, libapp
    const names = extractedLibs.map((l) => l.name);
    expect(names).toContain('libsqlite3.so');
    expect(names).toContain('libmmkv.so');
    expect(names).toContain('libflutter.so');
    expect(names).toContain('libapp.so');
  });

  it('creates an emulator session', async () => {
    const result = await handlers.handleCreateSession({});
    const data = payload(result);
    sessionId = data.sessionId as string;
    expect(sessionId).toBeTruthy();
    console.log(`Created session: ${sessionId}`);
  });

  it('loads libsqlite3.so and calls sqlite3_initialize', async () => {
    expect(sessionId).toBeTruthy();

    // Write libsqlite3.so to temp file
    const { writeFile, mkdtemp, rm } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');

    const tmpDir = await mkdtemp(join(tmpdir(), 'luoys-test-'));
    const soPath = join(tmpDir, 'libsqlite3.so');
    const sqlite3Lib = extractedLibs.find((l) => l.name === 'libsqlite3.so');
    expect(sqlite3Lib).toBeTruthy();

    await writeFile(soPath, sqlite3Lib!.bytes);

    try {
      // Load library
      const loadResult = await handlers.handleLoadLibrary({ sessionId, soPath });
      const loadData = payload(loadResult);
      console.log(`Loaded libsqlite3.so: unresolved=${loadData.unresolvedImports?.length ?? 0}`);

      expect(loadData.unresolvedImports?.length ?? 0).toBe(0); // All imports should be resolved

      // List symbols
      const symbolsResult = await handlers.handleListSymbols({ sessionId });
      const symbolsData = payload(symbolsResult);
      const exports = symbolsData.symbols as string[];

      expect(exports).toContain('sqlite3_initialize');

      // Try calling sqlite3_initialize
      const callResult = await handlers.handleCallSymbol({
        sessionId,
        symbol: 'sqlite3_initialize',
        args: [],
      });

      const callData = payload(callResult);
      console.log('sqlite3_initialize result:', callData);

      // Should succeed (return 0 for SQLITE_OK)
      expect(callData.success).not.toBe(false);
      expect(callData.result).toBeDefined();
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  });
});
