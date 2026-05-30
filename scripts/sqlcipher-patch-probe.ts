/**
 * sqlcipher-patch-probe — test whether the NULL function pointer at 0x4f4f08 is
 * the sole blocker. Experimentally point that slot at a stub that returns 0
 * (SQLITE_OK), then re-run open_v2 and see if initialization proceeds, db gets
 * allocated, and how far the key path now gets. This distinguishes "single
 * missing init pointer" from "deeper control-flow problem" — without touching
 * production code (the patch is applied to guest memory in the probe only).
 */
import { extractArm64Libs } from '../src/modules/native-emulator/apk';
import { CpuEngine } from '../src/modules/native-emulator/CpuEngine';
import { createBionicLibrary } from '../src/modules/native-emulator/bionic';
import { installAndroidSyscalls } from '../src/modules/native-emulator/syscalls';

const apkPath = process.argv[2] ?? 'D:/cumhub/reverse/oiodm/oio动漫.apk';

function u64le(v: number): Uint8Array {
  const b = new Uint8Array(8);
  let x = BigInt(v);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

async function main(): Promise<void> {
  const libs = await extractArm64Libs(apkPath);
  const lib = libs.find((l) => l.name === 'libsqlcipher.so')!.bytes;
  const engine = new CpuEngine();
  installAndroidSyscalls(engine, {});
  let okStubCalls = 0;
  engine.loadElf(
    lib,
    createBionicLibrary(engine, { onLog: (p, t, m) => console.log(`  [log ${t}] ${m}`) }),
  );

  // Register an "init returns SQLITE_OK" stub at a spare host address, then write
  // its address into the GlobalConfig slot the BLR reads.
  const OK_STUB = 0x6f000000;
  engine.registerHostFunction(OK_STUB, () => {
    okStubCalls++;
    return 0n;
  });
  engine.mapMemory(0x10000000, 0x10000);
  engine.writeCode(0x10000000, new TextEncoder().encode(':memory:\0'));
  engine.writeCode(0x10000800, new Uint8Array(8));
  // Patch the slot 0x4f4f08 → OK_STUB.
  engine.writeCode(0x4f4f08, u64le(OK_STUB));

  // Trace how many NULL indirect calls remain and how far we get.
  let nullCalls = 0;
  let maxStep = 0;
  const newSlots = new Set<number>();
  engine.addInstructionHook((e) => {
    maxStep = e.step;
    const u = e.insn >>> 0;
    if ((u & 0xfffffc1f) === 0xd63f0000 || (u & 0xfffffc1f) === 0xd61f0000) {
      const rn = (u >>> 5) & 0x1f;
      if (Number(e.x(rn)) === 0) {
        nullCalls++;
        newSlots.add(e.pc);
      }
    }
  });

  console.log('[patch] open_v2 with 0x4f4f08 patched to an OK stub...');
  try {
    const r = engine.callSymbol('sqlite3_open_v2', [0x10000000, 0x10000800, 0x86, 0]);
    console.log(`[patch] returned 0x${(r >>> 0).toString(16)}, steps=${maxStep}`);
  } catch (e) {
    console.log(`[patch] threw at step ${maxStep}: ${String(e).slice(0, 120)}`);
  }
  const db = engine.readMemory(0x10000800, 8);
  let dbh = 0n;
  for (let i = 7; i >= 0; i--) dbh = (dbh << 8n) | BigInt(db[i] ?? 0);
  console.log(`[patch] OK-stub called ${okStubCalls}×`);
  console.log(
    `[patch] db handle = 0x${dbh.toString(16)} ${dbh !== 0n ? '← DB ALLOCATED!' : '(still NULL)'}`,
  );
  console.log(
    `[patch] remaining NULL indirect calls: ${nullCalls} at pcs ${[...newSlots].map((p) => '0x' + p.toString(16)).join(', ')}`,
  );
  console.log(
    `\n[patch] VERDICT: ${
      dbh !== 0n
        ? 'single missing init pointer was the blocker — populating it unblocks open'
        : okStubCalls > 0
          ? 'slot was reached & called, but more NULL pointers remain (a table of init fns needs filling)'
          : 'patch had no effect — control flow differs from assumption'
    }`,
  );
}

main().catch((e) => console.error('[patch] fatal:', e));
