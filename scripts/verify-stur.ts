/**
 * verify-stur — does CpuEngine correctly execute STUR Xt,[Xn,#imm9] (unscaled
 * store)? The SQLCipher mutex-table copy uses STUR with positive imm9 (e.g.
 * 0xf809c11f = STUR xzr,[x8,#156]). If the engine mis-decodes it, the copy
 * silently fails and GlobalConfig.mutex.xMutexInit stays NULL. This builds a
 * tiny program exercising STUR (store) and LDUR (load) and checks the result.
 */
import { CpuEngine } from '../src/modules/native-emulator/CpuEngine';

function u32(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

function main(): void {
  const engine = new CpuEngine();
  const CODE = 0x1000;
  const DATA = 0x8000;
  engine.mapMemory(CODE, 0x1000);
  engine.mapMemory(DATA, 0x1000);

  // Program:
  //   MOVZ x1, #0xbeef          ; value to store
  //   MOVZ x2, #0x8000, lsl #0  ; base = DATA (fits in 16 bits here)
  //   STUR x1, [x2, #16]        ; store x1 at DATA+16  (unscaled)
  //   LDUR x3, [x2, #16]        ; load it back into x3
  //   STUR xzr,[x2, #24]        ; store zero at DATA+24
  //   RET
  // Encodings:
  //   MOVZ x1,#0xbeef = 0xd2800000 | (0xbeef<<5) | 1
  const movz_x1 = (0xd2800000 | (0xbeef << 5) | 1) >>> 0;
  const movz_x2 = (0xd2800000 | (0x8000 << 5) | 2) >>> 0;
  //   STUR x1,[x2,#16]: 0xf8000000 | (imm9<<12) | (Rn<<5) | Rt ; imm9=16
  const stur_x1 = (0xf8000000 | (16 << 12) | (2 << 5) | 1) >>> 0;
  //   LDUR x3,[x2,#16]: 0xf8400000 | (imm9<<12)|(Rn<<5)|Rt
  const ldur_x3 = (0xf8400000 | (16 << 12) | (2 << 5) | 3) >>> 0;
  //   STUR xzr,[x2,#24]
  const stur_xzr = (0xf8000000 | (24 << 12) | (2 << 5) | 31) >>> 0;
  const ret = 0xd65f03c0;

  let p = CODE;
  for (const insn of [movz_x1, movz_x2, stur_x1, ldur_x3, stur_xzr, ret]) {
    engine.writeCode(p, u32(insn));
    p += 4;
  }
  // Pre-fill DATA+24 with nonzero so we can see STUR xzr clear it.
  engine.writeCode(DATA + 24, Uint8Array.of(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));

  engine.writeRegister('x30', 0);
  engine.mapMemory(0x7ffe0000, 0x10000);
  engine.writeRegister('sp', 0x7fff0000);
  try {
    engine.start(CODE, 0);
  } catch (e) {
    console.log(`THREW: ${String(e)}`);
  }

  const x3 = engine.readRegister('x3');
  const stored = engine.readMemory(DATA + 16, 8);
  const cleared = engine.readMemory(DATA + 24, 8);
  let storedV = 0n;
  for (let i = 7; i >= 0; i--) storedV = (storedV << 8n) | BigInt(stored[i] ?? 0);
  let clearedV = 0n;
  for (let i = 7; i >= 0; i--) clearedV = (clearedV << 8n) | BigInt(cleared[i] ?? 0);

  console.log(`STUR x1,[x2,#16] then LDUR x3 → x3 = 0x${(x3 >>> 0).toString(16)} (expect 0xbeef)`);
  console.log(`memory at DATA+16 = 0x${storedV.toString(16)} (expect 0xbeef)`);
  console.log(`STUR xzr,[x2,#24] → DATA+24 = 0x${clearedV.toString(16)} (expect 0x0)`);
  const ok = x3 >>> 0 === 0xbeef && storedV === 0xbeefn && clearedV === 0n;
  console.log(
    `\nVERDICT: STUR/LDUR ${ok ? 'WORKS ✓' : 'BROKEN ✗ — this is the SQLCipher copy-loop failure'}`,
  );
}

main();
