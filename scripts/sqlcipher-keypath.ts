/**
 * sqlcipher-keypath — orchestrate the *real* SQLCipher key-derivation call chain.
 *
 * The baseline probe (sqlcipher-probe.ts) blind-called symbols with zero args,
 * which only surfaces null-deref noise. This script feeds the real API contract:
 *   sqlite3_open_v2(":memory:", &db, flags, 0)   → real db handle
 *   sqlite3_key_v2(db, "main", key, keylen)      → triggers PBKDF2-HMAC-SHA KDF
 * and runs with a ring-buffer instruction trace so that when it hits a genuine
 * integration gap (missing bionic fn, syscall, memory semantic) we can dump the
 * last N instructions and locate it — the fastest way to find what's missing on
 * the actual decrypt hot path. Output is persisted as a process file.
 *
 *   npx tsx scripts/sqlcipher-keypath.ts [apkPath]
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { extractArm64Libs } from '../src/modules/native-emulator/apk';
import { CpuEngine, type TraceEvent } from '../src/modules/native-emulator/CpuEngine';
import { createBionicLibrary } from '../src/modules/native-emulator/bionic';
import { installAndroidSyscalls } from '../src/modules/native-emulator/syscalls';

const DEFAULT_APK = 'D:/cumhub/reverse/oiodm/oio动漫.apk';
const apkPath = process.argv[2] ?? DEFAULT_APK;
const OUT_DIR = '.ccg/tasks/sqlcipher-decrypt-chain';

// SQLite open flags.
const SQLITE_OPEN_READWRITE = 0x2;
const SQLITE_OPEN_CREATE = 0x4;
const SQLITE_OPEN_MEMORY = 0x80;

// A scratch arena well clear of the ELF image, bionic heap (0x100000), and
// the syscall mmap base (0x5000_0000).
const SCRATCH = 0x10000000;
const SCRATCH_SIZE = 0x10000;

function writeCString(engine: CpuEngine, addr: number, s: string): number {
  const bytes = new TextEncoder().encode(s);
  const buf = new Uint8Array(bytes.length + 1);
  buf.set(bytes);
  engine.writeCode(addr, buf);
  return bytes.length;
}

/** Read a little-endian u64 from guest memory as a JS number. */
function readU64(engine: CpuEngine, addr: number): number {
  const b = engine.readMemory(addr, 8);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i] ?? 0);
  return Number(v);
}

interface TraceRing {
  events: TraceEvent[];
  push(e: TraceEvent): void;
}
function makeRing(size: number): TraceRing {
  const events: TraceEvent[] = [];
  return {
    events,
    push(e) {
      events.push(e);
      if (events.length > size) events.shift();
    },
  };
}

/** Call a symbol with a bounded instruction trace; on throw, dump the tail. */
function tracedCall(
  engine: CpuEngine,
  label: string,
  sym: string,
  args: number[],
  log: string[],
): { ok: boolean; ret?: number; tail: TraceEvent[]; error?: string } {
  const ring = makeRing(60);
  const unsub = engine.addInstructionHook((e) => ring.push(e));
  try {
    const ret = engine.callSymbol(sym, args);
    unsub();
    log.push(
      `✓ ${label}: ${sym}(${args.map((a) => '0x' + (a >>> 0).toString(16)).join(',')}) → 0x${(ret >>> 0).toString(16)}`,
    );
    return { ok: true, ret, tail: ring.events };
  } catch (e) {
    unsub();
    const error = String(e);
    log.push(`✗ ${label}: ${sym} threw — ${error.slice(0, 120)}`);
    log.push(`  --- last ${ring.events.length} instructions before fault ---`);
    for (const ev of ring.events.slice(-30)) {
      log.push(
        `  step=${ev.step} pc=0x${ev.pc.toString(16)} insn=0x${ev.insn.toString(16).padStart(8, '0')}`,
      );
    }
    return { ok: false, tail: ring.events, error };
  }
}

async function main(): Promise<void> {
  const log: string[] = [];
  const say = (s: string): void => {
    console.log(s);
    log.push(s);
  };

  const libs = await extractArm64Libs(apkPath);
  const lib = libs.find((l) => l.name === 'libsqlcipher.so');
  if (!lib) {
    say('[keypath] libsqlcipher.so not found in APK');
    process.exit(0);
  }
  say(`[keypath] libsqlcipher.so = ${lib.bytes.length} bytes`);

  const engine = new CpuEngine();
  // Capture log output and getrandom so we can see the KDF asking for entropy.
  let getrandomCalls = 0;
  installAndroidSyscalls(engine, {
    onGetrandom: (len) => {
      getrandomCalls++;
      return new Uint8Array(len).fill(0x42);
    },
  });
  engine.loadElf(
    lib.bytes,
    createBionicLibrary(engine, {
      onLog: (prio, tag, msg) => say(`  [android_log prio=${prio} ${tag}] ${msg}`),
    }),
  );
  engine.mapMemory(SCRATCH, SCRATCH_SIZE);

  // Layout in scratch: filename, dbname "main", passphrase, ppDb output slot.
  const filenamePtr = SCRATCH;
  const fnLen = writeCString(engine, filenamePtr, ':memory:');
  const dbNamePtr = filenamePtr + fnLen + 1 + 8;
  writeCString(engine, dbNamePtr, 'main');
  const keyPtr = dbNamePtr + 16;
  const keyStr = 'test-passphrase-1234';
  const keyLen = writeCString(engine, keyPtr, keyStr);
  const ppDbPtr = SCRATCH + 0x800; // 8-byte aligned output slot for sqlite3**
  engine.writeCode(ppDbPtr, new Uint8Array(8)); // zero it

  say(`\n[keypath] === step 1: sqlite3_open_v2(":memory:", &db, RW|CREATE|MEMORY, 0) ===`);
  const flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY;
  const open = tracedCall(engine, 'open', 'sqlite3_open_v2', [filenamePtr, ppDbPtr, flags, 0], log);

  if (open.ok) {
    const db = readU64(engine, ppDbPtr);
    say(`[keypath] db handle = 0x${db.toString(16)} (open returned ${open.ret})`);
    if (db !== 0) {
      say(`\n[keypath] === step 2: sqlite3_key_v2(db, "main", "${keyStr}", ${keyLen}) ===`);
      const hasKeyV2 = engine.exportedSymbolNames().includes('sqlite3_key_v2');
      const keyed = hasKeyV2
        ? tracedCall(engine, 'key', 'sqlite3_key_v2', [db, dbNamePtr, keyPtr, keyLen], log)
        : tracedCall(engine, 'key', 'sqlite3_key', [db, keyPtr, keyLen], log);
      say(`[keypath] getrandom calls so far: ${getrandomCalls}`);
      void keyed;
    } else {
      say(`[keypath] db handle is NULL — open_v2 did not populate ppDb (gap in VFS/alloc path)`);
    }
  }

  say(`\n[keypath] getrandom total: ${getrandomCalls}`);
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(`${OUT_DIR}/keypath-trace.txt`, log.join('\n'));
  say(`[keypath] wrote ${OUT_DIR}/keypath-trace.txt`);
}

main().catch((e) => {
  console.error('[keypath] fatal:', e);
  process.exit(1);
});
