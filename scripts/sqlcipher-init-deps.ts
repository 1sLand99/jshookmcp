/**
 * sqlcipher-init-deps — probe SQLite's initialization dependency graph directly.
 * Calls sqlite3_initialize, sqlite3_os_init, sqlcipher_init_memmethods,
 * sqlcipher_openssl_setup in isolation (with a NULL-indirect-call detector) to
 * map which one is supposed to populate the GlobalConfig function pointer the
 * open path indirect-calls, and whether each runs to a real return or hits a
 * NULL pointer / missing stub.
 */
import { extractArm64Libs } from '../src/modules/native-emulator/apk';
import { CpuEngine } from '../src/modules/native-emulator/CpuEngine';
import { createBionicLibrary } from '../src/modules/native-emulator/bionic';
import { installAndroidSyscalls } from '../src/modules/native-emulator/syscalls';

const apkPath = process.argv[2] ?? 'D:/cumhub/reverse/oiodm/oio动漫.apk';

function freshEngine(lib: Uint8Array): { engine: CpuEngine; bionicCalls: Map<string, number> } {
  const engine = new CpuEngine();
  installAndroidSyscalls(engine, {});
  const calls = new Map<string, number>();
  const base = createBionicLibrary(engine, {});
  const wrapped = new Map(
    [...base].map(([n, fn]) => [
      n,
      (ctx: Parameters<typeof fn>[0]) => {
        calls.set(n, (calls.get(n) ?? 0) + 1);
        return fn(ctx);
      },
    ]),
  );
  engine.loadElf(lib, wrapped);
  return { engine, bionicCalls: calls };
}

async function main(): Promise<void> {
  const libs = await extractArm64Libs(apkPath);
  const lib = libs.find((l) => l.name === 'libsqlcipher.so')!.bytes;

  const targets = [
    'sqlite3_initialize',
    'sqlite3_os_init',
    'sqlcipher_init_memmethods',
    'sqlcipher_openssl_setup',
    'sqlite3_config',
  ];

  for (const sym of targets) {
    const { engine, bionicCalls } = freshEngine(lib);
    if (!engine.exportedSymbolNames().includes(sym)) {
      console.log(`\n=== ${sym}: NOT EXPORTED ===`);
      continue;
    }
    let steps = 0;
    let nullCall = '';
    const blrTargets = new Set<number>();
    engine.addInstructionHook((e) => {
      steps++;
      const u = e.insn >>> 0;
      if ((u & 0xfffffc1f) === 0xd63f0000 || (u & 0xfffffc1f) === 0xd61f0000) {
        const rn = (u >>> 5) & 0x1f;
        const tgt = Number(e.x(rn));
        blrTargets.add(tgt);
        if (tgt === 0 && !nullCall)
          nullCall = `step${e.step} pc=0x${e.pc.toString(16)} BLR/BR x${rn}=0 (NULL indirect call)`;
      }
    });
    let result = '';
    try {
      const r = engine.callSymbol(sym, [0, 0, 0, 0]);
      result = `ran to return, x0=0x${(r >>> 0).toString(16)}`;
    } catch (e) {
      result = `threw: ${String(e).slice(0, 90)}`;
    }
    console.log(`\n=== ${sym} ===`);
    console.log(`  result: ${result}`);
    console.log(`  instructions: ${steps}`);
    console.log(`  NULL indirect call: ${nullCall || '(none)'}`);
    console.log(
      `  distinct indirect-call targets: ${[...blrTargets].map((t) => '0x' + (t >>> 0).toString(16)).join(', ') || '(none)'}`,
    );
    const bc = [...bionicCalls.entries()].toSorted((a, b) => b[1] - a[1]);
    console.log(
      `  bionic calls: ${bc.length ? bc.map(([n, c]) => `${n}×${c}`).join(', ') : '(none)'}`,
    );
  }
}

main().catch((e) => console.error('[init-deps] fatal:', e));
