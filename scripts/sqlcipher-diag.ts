/**
 * sqlcipher-diag — diagnose why sqlite3_open_v2 returns without populating *ppDb.
 *
 * It "ran to return" but produced a NULL db handle and a return value equal to
 * the filename pointer — a classic "looks fine, actually short-circuited" case
 * (cf. the RootBeer early-return lesson). This instruments the call to count
 * instructions executed, host-function (bionic) calls by name, syscalls, and
 * the first/last slice of the instruction stream, so we can see whether open_v2
 * genuinely walked its VFS/alloc path or branched out early.
 *
 *   npx tsx scripts/sqlcipher-diag.ts [apkPath]
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { extractArm64Libs } from '../src/modules/native-emulator/apk';
import { CpuEngine } from '../src/modules/native-emulator/CpuEngine';
import { createBionicLibrary, type BionicLibrary } from '../src/modules/native-emulator/bionic';
import { installAndroidSyscalls } from '../src/modules/native-emulator/syscalls';

const DEFAULT_APK = 'D:/cumhub/reverse/oiodm/oio动漫.apk';
const apkPath = process.argv[2] ?? DEFAULT_APK;
const OUT_DIR = '.ccg/tasks/sqlcipher-decrypt-chain';

const SCRATCH = 0x10000000;

function writeCString(engine: CpuEngine, addr: number, s: string): number {
  const bytes = new TextEncoder().encode(s);
  const buf = new Uint8Array(bytes.length + 1);
  buf.set(bytes);
  engine.writeCode(addr, buf);
  return bytes.length;
}

/**
 * Wrap a bionic library so every stub call is counted by name. Returns the
 * wrapped library and a live tally map.
 */
function instrumentBionic(
  engine: CpuEngine,
  log: (s: string) => void,
): {
  lib: BionicLibrary;
  calls: Map<string, number>;
} {
  const base = createBionicLibrary(engine, {
    onLog: (prio, tag, msg) => log(`  [android_log prio=${prio} ${tag}] ${msg}`),
  });
  const calls = new Map<string, number>();
  const wrapped: BionicLibrary = new Map();
  for (const [name, fn] of base) {
    wrapped.set(name, (ctx) => {
      calls.set(name, (calls.get(name) ?? 0) + 1);
      return fn(ctx);
    });
  }
  return { lib: wrapped, calls };
}

async function main(): Promise<void> {
  const log: string[] = [];
  const say = (s: string): void => {
    console.log(s);
    log.push(s);
  };

  const libs = await extractArm64Libs(apkPath);
  const lib = libs.find((l) => l.name === 'libsqlcipher.so')!;

  const engine = new CpuEngine();
  const syscallCalls = new Map<number, number>();
  installAndroidSyscalls(engine, {});
  // Wrap a few syscalls of interest by re-registering counting versions after.
  const { lib: bionic, calls: bionicCalls } = instrumentBionic(engine, say);
  engine.loadElf(lib.bytes, bionic);

  const filenamePtr = SCRATCH;
  engine.mapMemory(SCRATCH, 0x10000);
  const fnLen = writeCString(engine, filenamePtr, ':memory:');
  const ppDbPtr = SCRATCH + 0x800;
  engine.writeCode(ppDbPtr, new Uint8Array(8));

  let instrCount = 0;
  const firstInsns: string[] = [];
  const branchTargets: number[] = [];
  let lastPc = 0;
  const unsub = engine.addInstructionHook((e) => {
    instrCount++;
    if (firstInsns.length < 100) {
      const jump =
        lastPc !== 0 && Math.abs(e.pc - lastPc) > 8
          ? ` <-- jump from 0x${lastPc.toString(16)}`
          : '';
      firstInsns.push(
        `  step=${e.step} pc=0x${e.pc.toString(16)} insn=0x${e.insn.toString(16).padStart(8, '0')}${jump}`,
      );
    }
    // Detect backward/forward branches > 0x100 to spot early-exit jumps.
    if (lastPc !== 0 && Math.abs(e.pc - lastPc) > 0x100) {
      branchTargets.push(e.pc);
    }
    lastPc = e.pc;
  });

  const flags = 0x2 | 0x4 | 0x80;
  say(`[diag] calling sqlite3_open_v2(":memory:", &db, 0x${flags.toString(16)}, 0)`);
  let ret = -1;
  try {
    ret = engine.callSymbol('sqlite3_open_v2', [filenamePtr, ppDbPtr, flags, 0]);
  } catch (e) {
    say(`[diag] threw: ${String(e).slice(0, 150)}`);
  }
  unsub();
  void fnLen;
  void syscallCalls;

  say(`[diag] return value = 0x${(ret >>> 0).toString(16)} (${ret})`);
  say(`[diag] instructions executed = ${instrCount}`);
  say(`[diag] bionic calls:`);
  for (const [n, c] of [...bionicCalls.entries()].toSorted((a, b) => b[1] - a[1])) {
    say(`    ${n} ×${c}`);
  }
  say(`[diag] long branches (early-exit candidates): ${branchTargets.length}`);
  say(`[diag] first ${firstInsns.length} instructions:`);
  for (const l of firstInsns) say(l);

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(`${OUT_DIR}/diag-open.txt`, log.join('\n'));
  say(`[diag] wrote ${OUT_DIR}/diag-open.txt`);
}

main().catch((e) => {
  console.error('[diag] fatal:', e);
  process.exit(1);
});
