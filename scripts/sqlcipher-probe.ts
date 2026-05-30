/**
 * sqlcipher-probe — semantic-level stress probe of libsqlcipher.so from a real APK.
 *
 * The opcode-level gaps for libsqlcipher were already closed (barriers landed,
 * 4→0 unsupported opcodes). This probe goes a layer deeper: it builds a *symbol
 * call baseline* — load the library, classify its ~468 symbols (crypto / public
 * sqlite3_* API / internal), then invoke a curated set and record, per symbol,
 * whether it ran to return, hit an unsupported opcode, or tripped a missing
 * bionic/syscall stub. This surfaces *integration* gaps the histogram can't:
 * a libc function sqlcipher's I/O path needs that we never stubbed, etc.
 *
 *   npx tsx scripts/sqlcipher-probe.ts [apkPath]
 *
 * Default APK: D:/cumhub/reverse/oiodm/oio动漫.apk
 * The .so is read out of the APK in-memory (never written to disk).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { extractArm64Libs } from '../src/modules/native-emulator/apk';
import { CpuEngine } from '../src/modules/native-emulator/CpuEngine';
import { createBionicLibrary } from '../src/modules/native-emulator/bionic';

const BASELINE_DIR = '.ccg/tasks/sqlcipher-decrypt-chain';

const DEFAULT_APK = 'D:/cumhub/reverse/oiodm/oio动漫.apk';
const apkPath = process.argv[2] ?? DEFAULT_APK;
const TARGET = 'libsqlcipher.so';

/** Classify a symbol so the baseline groups by concern. */
function classify(sym: string): 'crypto' | 'sqlite3-public' | 'codec' | 'internal' {
  if (/aes|sha|hmac|pbkdf|rand|cipher|codec|^EVP_|^RAND_|^SHA|^AES|^HMAC/i.test(sym)) {
    return /codec/i.test(sym) ? 'codec' : 'crypto';
  }
  if (sym.startsWith('sqlite3')) return 'sqlite3-public';
  return 'internal';
}

/** Pull "0x........" opcode out of an unsupported-opcode throw. */
function opcodeOf(message: string): string | null {
  const m = /Unsupported ARM64 opcode (0x[0-9a-f]+)/.exec(message);
  return m ? m[1]! : null;
}

/** Categorise a failure so we can tell opcode gaps from integration gaps. */
function categorize(err: string): { kind: string; detail: string } {
  const op = opcodeOf(err);
  if (op) return { kind: 'opcode', detail: op };
  if (/No host function registered/.test(err))
    return { kind: 'missing-stub', detail: err.slice(0, 80) };
  if (/No syscall/.test(err)) return { kind: 'missing-syscall', detail: err.slice(0, 80) };
  if (/Unmapped|out of bounds|read.*0x0\b/i.test(err))
    return { kind: 'memory', detail: err.slice(0, 80) };
  if (/MAX_STEPS|step limit/i.test(err)) return { kind: 'runaway', detail: err.slice(0, 80) };
  if (/__stack_chk_fail/.test(err)) return { kind: 'stack-canary', detail: err.slice(0, 60) };
  return { kind: 'other', detail: err.slice(0, 100) };
}

async function main(): Promise<void> {
  console.log(`[sqlcipher-probe] extracting ${TARGET} from ${apkPath}`);
  const libs = await extractArm64Libs(apkPath);
  const names = libs.map((l) => l.name);
  console.log(`[sqlcipher-probe] APK arm64-v8a libs: ${names.join(', ')}`);
  const lib = libs.find((l) => l.name === TARGET);
  if (!lib) {
    console.log(`[sqlcipher-probe] ${TARGET} not in APK — aborting`);
    process.exit(0);
  }
  console.log(`[sqlcipher-probe] ${TARGET} = ${lib.bytes.length} bytes`);

  // Map + relocate once to list symbols.
  const base = new CpuEngine();
  base.loadElf(lib.bytes, createBionicLibrary(base));
  const symbols = base.exportedSymbolNames();
  console.log(`[sqlcipher-probe] resolved ${symbols.length} symbols`);

  const groups = new Map<string, string[]>();
  for (const s of symbols) {
    const g = classify(s);
    (groups.get(g) ?? groups.set(g, []).get(g)!).push(s);
  }
  for (const [g, list] of [...groups.entries()].toSorted()) {
    console.log(`  ${g}: ${list.length}`);
  }

  // Dump the crypto-relevant symbols by name — these are the candidate entry
  // points for directly exercising the KDF / cipher path with known vectors.
  const cryptoNames = symbols.filter((s) =>
    /aes|sha|hmac|pbkdf|kdf|derive|cipher|codec|rand|^EVP_|^RAND_|sqlcipher/i.test(s),
  );
  console.log(`\n[sqlcipher-probe] crypto/KDF-relevant symbols (${cryptoNames.length}):`);
  for (const s of cryptoNames.toSorted()) console.log(`  ${s}`);

  // Persist the full classified symbol list as the baseline (process file).
  mkdirSync(BASELINE_DIR, { recursive: true });
  const lines: string[] = [`# libsqlcipher.so symbol baseline`, ``, `Total: ${symbols.length}`, ``];
  for (const [g, list] of [...groups.entries()].toSorted()) {
    lines.push(`## ${g} (${list.length})`, ``, ...list.toSorted().map((s) => `- ${s}`), ``);
  }
  writeFileSync(`${BASELINE_DIR}/symbol-baseline.md`, lines.join('\n'));
  console.log(`\n[sqlcipher-probe] wrote ${BASELINE_DIR}/symbol-baseline.md`);

  // Key symbols on the SQLCipher decrypt path, in dependency order.
  const keyPath = [
    'sqlite3_key',
    'sqlite3_key_v2',
    'sqlite3_rekey',
    'sqlite3_open',
    'sqlite3_open_v2',
    'sqlite3_prepare_v2',
    'sqlite3_libversion',
    'sqlite3_libversion_number',
    'sqlite3_sourceid',
    'sqlite3_threadsafe',
  ].filter((s) => symbols.includes(s));

  console.log(`\n[sqlcipher-probe] === key-path symbols present: ${keyPath.length} ===`);
  const failureKinds = new Map<string, number>();
  for (const sym of keyPath) {
    const probe = new CpuEngine();
    probe.loadElf(lib.bytes, createBionicLibrary(probe));
    try {
      const r = probe.callSymbol(sym, [0, 0, 0, 0, 0, 0]);
      console.log(`  ✓ ${sym} → ran to return, x0=0x${(r >>> 0).toString(16)}`);
    } catch (e) {
      const cat = categorize(String(e));
      failureKinds.set(cat.kind, (failureKinds.get(cat.kind) ?? 0) + 1);
      console.log(`  ✗ ${sym} → [${cat.kind}] ${cat.detail}`);
    }
  }

  // Broad sweep: invoke a sample across all groups to catch integration gaps.
  console.log(`\n[sqlcipher-probe] === broad sweep (sample per group) ===`);
  const opcodeHist = new Map<string, number>();
  const stubHist = new Map<string, number>();
  let ran = 0;
  let failed = 0;
  for (const [, list] of groups) {
    for (const sym of list.slice(0, 40)) {
      const probe = new CpuEngine();
      try {
        probe.loadElf(lib.bytes, createBionicLibrary(probe));
        probe.callSymbol(sym, [0, 0, 0, 0]);
        ran++;
      } catch (e) {
        failed++;
        const cat = categorize(String(e));
        failureKinds.set(cat.kind, (failureKinds.get(cat.kind) ?? 0) + 1);
        if (cat.kind === 'opcode')
          opcodeHist.set(cat.detail, (opcodeHist.get(cat.detail) ?? 0) + 1);
        if (cat.kind === 'missing-stub')
          stubHist.set(cat.detail, (stubHist.get(cat.detail) ?? 0) + 1);
      }
    }
  }
  console.log(`\n[sqlcipher-probe] swept: ran-to-return=${ran}, failed=${failed}`);
  console.log(`[sqlcipher-probe] failure kinds:`);
  for (const [k, n] of [...failureKinds.entries()].toSorted((a, b) => b[1] - a[1])) {
    console.log(`  ${k}: ${n}`);
  }
  if (opcodeHist.size > 0) {
    console.log(`[sqlcipher-probe] unsupported opcodes:`);
    for (const [op, n] of [...opcodeHist.entries()].toSorted((a, b) => b[1] - a[1]).slice(0, 20)) {
      console.log(`  ${op} ×${n}`);
    }
  }
  if (stubHist.size > 0) {
    console.log(`[sqlcipher-probe] missing stubs:`);
    for (const [s, n] of [...stubHist.entries()].toSorted((a, b) => b[1] - a[1])) {
      console.log(`  ${s} ×${n}`);
    }
  }
}

main().catch((e) => {
  console.error('[sqlcipher-probe] fatal:', e);
  process.exit(1);
});
