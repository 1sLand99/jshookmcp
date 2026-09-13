/**
 * PAC — ARMv8.3 Pointer Authentication instruction tests.
 *
 * Every instruction word below is verified against capstone 5.0.7 disassembly:
 *
 * - PAC/AUT register form (Data Processing -- Register dispatch, 1-source window):
 *     base 0xDAC10000, bits[20:16] = 00001 (fixed), opcode = bits[12:10]
 *     (0 pacia, 1 pacib, 2 pacda, 3 pacdb, 4 autia, 5 autib, 6 autda, 7 autdb),
 *     Rn = bits[9:5] modifier (31 = SP), Rd = bits[4:0] pointer (signed/authenticated
 *     in place, also the destination). e.g. 0xDAC10043 `pacia x3, x2`,
 *     0xDAC11043 `autia x3, x2`, 0xDAC103E0 `pacia x0, sp`.
 * - PACGA (3-source): base 0x9AC03000, bits[15:10] = 001100 (fixed),
 *     Rm = bits[20:16] modifier (31 = SP), Rn = bits[9:5] pointer, Rd = bits[4:0].
 *     e.g. 0x9AC13043 `pacga x3, x2, x1`, 0x9ADF3041 `pacga x1, x2, sp`.
 * - HINT form (0xD5032xxxF): CRm=3 op2 0..7 = paciaz/paciasp/pacibz/pacibsp/
 *     autiaz/autiasp/autibz/autibsp (LR + XZR/SP modifier); CRm=1 even op2 =
 *     pacia1716/pacib1716/autia1716/autib1716 (X17 + X16); CRm=0 op2=7 = xpaclri.
 * - XPACI/XPACD (Data Processing -- 1-source window): 0xDAC143E0|Xd /
 *     0xDAC147E0|Xd (mask 0xFFFFFFE0; bits[15:10] = 01000D, bits[9:5] fixed
 *     11111, Rd = bits[4:0]) — unverified in-place strip of Rd.
 *     e.g. 0xDAC143E5 `xpaci x5`, 0xDAC147E0 `xpacd x0`, 0xDAC143FE `xpaci x30`.
 *
 * Covers:
 * - QARMA5 cipher vectors (known-answer test from dkales/qarma64-python)
 * - PACIA / AUTIA round-trip through instruction execution
 * - paciaz on LR + PAC field insertion
 * - A/B and IA/DA key-slot divergence
 * - PACGA full 64-bit cipher output (Rm and SP modifier forms)
 * - HINT-space PACIASP / AUTIASP / paciaz / autiaz prologue/epilogue on LR
 * - HINT-space 1716 variants signing X17 (A and B key)
 * - HINT-space key-B family: pacibz/pacibsp/autibz/autibsp diverge from the
 *   A-key forms
 * - XPACI/XPACD register strip (incl. idempotency, the refuted 0xD5032xxx
 *   candidate encoding staying a NOP, and z-register paciza-family forms
 *   keeping their safe-NOP degradation)
 * - HINT-space CRm=0 gate: WFE/SEV-range hints never touch LR or X17
 * - setPacKeys / nemu_set_pac_key slot update
 */

import { describe, expect, it } from 'vitest';
import { CpuEngine } from '@modules/native-emulator/CpuEngine';
import { qarma5Encrypt } from '@modules/native-emulator/decoder/PointerAuth';

const BASE = 0x10000;
const MASK64 = (1n << 64n) - 1n;
const PAC_MASK = 0x00ff000000000000n;
const stripPac = (p: bigint) => p & ~PAC_MASK & MASK64;
// Dirty 64-bit test vector, built by shifts instead of a hex literal: a
// literal's leading zero bytes are silently dropped (a "dirty top byte" vector
// written as 0x7faa00abc000 is really a 48-bit value — caught by review
// round 2). Layout: top byte bits[63:56]=0x7f, PAC field bits[55:48]=0xaa,
// plaintext bits[47:0]=0x7f0000abc000.
const DIRTY = (0x7fn << 56n) | (0xaan << 48n) | 0x7f0000abc000n;

// ── QARMA5 cipher vector ────────────────────────────────────────────────────

describe('QARMA5 cipher', () => {
  it('matches the official test vector (r=5, S-box 0)', () => {
    const P = 0xfb623599da6e8127n;
    const T = 0x477d469dec0b8762n;
    const key = '84be85ce9804e94bec2802d4e0a488e9';
    const got = qarma5Encrypt(P, T, key);
    expect(got).toBe(0x3ee99a6c82af0c38n);
  });
});

// ── Builders (capstone-verified layouts) ────────────────────────────────────

/** PAC/AUT register form: base 0xDAC10000, op bits[12:10], Rn modifier bits[9:5]
 *  (31 = SP), Rd pointer bits[4:0] (in place). */
function pacReg(op: number, modifierRn: number, rd: number): number {
  return (0xdac10000 | ((op & 7) << 10) | ((modifierRn & 31) << 5) | (rd & 31)) >>> 0;
}

/** PACGA: base 0x9AC03000, Rm modifier bits[20:16] (31 = SP), Rn pointer bits[9:5], Rd bits[4:0]. */
function pacgaReg(modifierRm: number, pointerRn: number, rd: number): number {
  return (0x9ac03000 | ((modifierRm & 31) << 16) | ((pointerRn & 31) << 5) | (rd & 31)) >>> 0;
}

/** Write a 4-byte instruction and execute it. Engine map + PC = BASE → BASE+4. */
function exec1(insn: number, regs?: Record<string, number | bigint>): CpuEngine {
  const e = new CpuEngine();
  e.mapMemory(BASE, 0x1000);
  e.writeRegister('sp', BASE + 0x800);
  if (regs) for (const [k, v] of Object.entries(regs)) e.writeRegister(k, v);
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, insn, true);
  e.writeCode(BASE, buf);
  e.start(BASE, BASE + 4);
  return e;
}

/** Execute two 4-byte instructions back-to-back. */
function exec2(insn1: number, insn2: number, regs?: Record<string, number | bigint>): CpuEngine {
  const e = new CpuEngine();
  e.mapMemory(BASE, 0x1000);
  e.writeRegister('sp', BASE + 0x800);
  if (regs) for (const [k, v] of Object.entries(regs)) e.writeRegister(k, v);
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setUint32(0, insn1, true);
  new DataView(buf.buffer).setUint32(4, insn2, true);
  e.writeCode(BASE, buf);
  e.start(BASE, BASE + 8);
  return e;
}

/** Execute three 4-byte instructions back-to-back. */
function exec3(
  insn1: number,
  insn2: number,
  insn3: number,
  regs?: Record<string, number | bigint>,
): CpuEngine {
  const e = new CpuEngine();
  e.mapMemory(BASE, 0x1000);
  e.writeRegister('sp', BASE + 0x800);
  if (regs) for (const [k, v] of Object.entries(regs)) e.writeRegister(k, v);
  const buf = new Uint8Array(12);
  const dv = new DataView(buf.buffer);
  [insn1, insn2, insn3].forEach((w, i) => dv.setUint32(i * 4, w, true));
  e.writeCode(BASE, buf);
  e.start(BASE, BASE + 12);
  return e;
}

// ── PAC/AUT register form ───────────────────────────────────────────────────

describe('PAC register-form instruction execution', () => {
  it('PACIA + AUTIA round-trips a pointer (A-key, same modifier)', () => {
    const orig = 0x7f0000abc000n;
    // pacia x1, x3: sign x1 in place with modifier x3 (0xDAC10061)
    const pacia = pacReg(0, 3, 1);
    // autia x1, x3: authenticate x1 with modifier x3 → restored (0xDAC11061)
    const autia = pacReg(4, 3, 1);

    const e = exec2(pacia, autia, { x1: Number(orig), x3: 0x11223344 });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(1)).toBe(orig);
  });

  it('register form with Rn=31 reads the modifier from SP (pacia x1, sp)', () => {
    const orig = 0x7f0000abc000n;
    // pacia x1, sp (0xDAC103E1) then autia x1, sp (0xDAC113E1).
    const e = exec2(pacReg(0, 31, 1), pacReg(4, 31, 1), { x1: Number(orig) });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(1)).toBe(orig);
  });

  it('PACIA inserts a non-zero PAC field that differs from the bare pointer', () => {
    const orig = 0x7f0000abc000n;
    // pacia x1, x2 (0xDAC10041)
    const e = exec1(pacReg(0, 2, 1), { x1: Number(orig), x2: 0x11223344 });
    const signed = e.readGpr(1);
    expect(signed & PAC_MASK).not.toBe(0n);
    expect(signed).not.toBe(orig);
    expect(stripPac(signed)).toBe(orig);
  });

  it('paciaz (0xD503231F) signs LR with a zero modifier', () => {
    const orig = 0x7f0000abc000n;
    const e = exec1(0xd503231f, { x30: Number(orig) });
    const signed = e.readGpr(30);
    expect(signed & PAC_MASK).not.toBe(0n);
    expect(stripPac(signed)).toBe(orig);
  });

  it('A-key and B-key PACIA/PACIB both preserve address bits', () => {
    const orig = 0x7f0000abc000n;
    const a = exec1(pacReg(0, 2, 1), { x1: Number(orig), x2: 0x11223344 }).readGpr(1);
    const b = exec1(pacReg(1, 2, 1), { x1: Number(orig), x2: 0x11223344 }).readGpr(1);
    expect(stripPac(a)).toBe(orig);
    expect(stripPac(b)).toBe(orig);
  });

  it('autib authenticates what pacib signed (opcode 5 round-trip)', () => {
    const orig = 0x7f0000abc000n;
    // pacib x1, x2 (op=1) signs; autib x1, x2 (op=5) authenticates in place.
    const e = exec2(pacReg(1, 2, 1), pacReg(5, 2, 1), { x1: Number(orig), x2: 0x11223344 });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(1)).toBe(orig);
  });
});

// ── XPACI/XPACD (register strip, 1-source window) ───────────────────────────

describe('XPACI/XPACD register strip', () => {
  // The vector is DIRTY (top byte 0x7f + PAC field 0xaa): a strip that
  // under-clears leaves the signed field behind, one that over-clears wipes
  // the top byte — both observable. See DIRTY for why it is shift-built.
  const orig = DIRTY;
  const base = stripPac(orig);

  it('test vector sanity: top byte and PAC field are both dirty', () => {
    // Guards the guard: if the vector ever loses a dirty plane, the
    // over-clear/residue assertions below go blind while staying green.
    expect(orig >> 56n).toBe(0x7fn);
    expect(orig & PAC_MASK).toBe(0xaan << 48n);
    expect(base).not.toBe(orig);
  });

  it('xpaci x5 (0xDAC143E5) strips the PAC field from a signed x5', () => {
    // pacia x5, x2 (0xDAC10045) then xpaci x5 (0xDAC143E5): unverified strip,
    // PAC field at bits[55:48] cleared, everything above and below preserved.
    const e = exec2(pacReg(0, 2, 5), 0xdac143e5, { x5: orig, x2: 0x11223344 });
    expect(e.readGpr(5) & PAC_MASK).toBe(0n);
    expect(e.readGpr(5)).toBe(base);
  });

  it('xpacd x0 (0xDAC147E0) strips a signed x0 (D variant)', () => {
    const e = exec2(pacReg(0, 2, 0), 0xdac147e0, { x0: orig, x2: 0x11223344 });
    expect(e.readGpr(0) & PAC_MASK).toBe(0n);
    expect(e.readGpr(0)).toBe(base);
  });

  it('xpaci is idempotent across signing: xpaci → pacia → xpaci recovers the base', () => {
    const e = exec3(0xdac143e5, pacReg(0, 2, 5), 0xdac143e5, {
      x5: orig,
      x2: 0x11223344,
    });
    expect(e.readGpr(5) & PAC_MASK).toBe(0n);
    expect(e.readGpr(5)).toBe(base);
  });

  it('xpaci x30 (0xDAC143FE) strips a PAC-signed LR in place', () => {
    const e = exec2(0xd503231f /* paciaz */, 0xdac143fe /* xpaci x30 */, { x30: orig });
    expect(e.readGpr(30)).toBe(base);
  });

  it('the refuted XPACI candidate encoding (0xD5032045) stays a NOP', () => {
    // 0xD5032040|Xd was refuted against WFE (HINT space) — it must not strip.
    // Seed x5 with a signed value (non-zero PAC field) so a mutant that
    // implements the candidate as a strip is observably different from a NOP.
    const signed = exec1(pacReg(0, 2, 5), { x5: orig, x2: 0x11223344 }).readGpr(5);
    expect(signed & PAC_MASK).not.toBe(0n);
    const e = exec2(pacReg(0, 2, 5), 0xd5032045, { x5: orig, x2: 0x11223344 });
    expect(e.readGpr(5)).toBe(signed);
  });

  it('z-register forms (paciza family) keep their safe-NOP degradation', () => {
    // paciza x5 (0xDAC123E5): 1-source opcode 001000 with Rn fixed 11111 —
    // outside both XPACI guards by construction; a guard-widening mutant that
    // absorbs this word as a strip would clear the seeded dirty field.
    const e = exec1(0xdac123e5, { x5: orig });
    expect(e.readGpr(5)).toBe(orig);
  });
});

// ── PACGA ───────────────────────────────────────────────────────────────────

describe('PACGA (3-source, full 64-bit cipher)', () => {
  it('writes the full 64-bit QARMA output, not an 8-bit field', () => {
    const orig = 0x7f0000abc000n;
    // pacga x1, x2, x3 (0x9AC33041): digest over pointer x2 with modifier x3 → x1
    const e = exec1(pacgaReg(3, 2, 1), { x2: Number(orig), x3: 0x11223344 });
    const v = e.readGpr(1);
    expect(v).not.toBe(0n);
    // Unlike the register form's 8-bit PAC field at bits[55:48], PACGA writes
    // the whole cipher: the TOP BYTE must be populated. Asserting bits[55:48]
    // alone would pass even if the implementation regressed to the truncated
    // 8-bit field (its value lands non-zero at bits[55:48]).
    expect(v >> 56n).not.toBe(0n);
    expect(v).not.toBe(orig);
    // Digest must vary with both the modifier and the pointer.
    const otherModifier = exec1(pacgaReg(3, 2, 1), { x2: Number(orig), x3: 0x55667788 }).readGpr(1);
    const otherPointer = exec1(pacgaReg(3, 2, 1), {
      x2: Number(orig) + 0x1000,
      x3: 0x11223344,
    }).readGpr(1);
    expect(otherModifier).not.toBe(v);
    expect(otherPointer).not.toBe(v);
  });

  it('digest diverges when the ga key differs', () => {
    const orig = 0x7f0000abc000n;
    const run = (gaKey: string): bigint => {
      const e = new CpuEngine();
      e.setPacKeys({ ...e.pacKeys, ga: gaKey });
      e.mapMemory(BASE, 0x1000);
      e.writeRegister('sp', BASE + 0x800);
      e.writeRegister('x2', Number(orig));
      e.writeRegister('x3', 0x11223344);
      const buf = new Uint8Array(4);
      new DataView(buf.buffer).setUint32(0, pacgaReg(3, 2, 1), true);
      e.writeCode(BASE, buf);
      e.start(BASE, BASE + 4);
      return e.readGpr(1);
    };
    const withDefaultGa = run('c0ffee00112233445566778899aabbcc');
    const withOtherGa = run('11111111111111111111111111111111');
    expect(withDefaultGa).not.toBe(0n);
    expect(withOtherGa).not.toBe(withDefaultGa);
  });

  it('Rm=31 reads the modifier from SP (pacga x1, x2, sp)', () => {
    const orig = 0x7f0000abc000n;
    const spValue = BASE + 0x800; // exec1 seeds SP with this
    // pacga x1, x2, sp (0x9ADF3041) vs pacga x1, x2, x1 with x1 seeded to SP's value.
    const viaSp = exec1(pacgaReg(31, 2, 1), { x2: Number(orig) }).readGpr(1);
    const viaX1 = exec1(pacgaReg(1, 2, 1), { x1: spValue, x2: Number(orig) }).readGpr(1);
    expect(viaSp).toBe(viaX1);
    expect(viaSp).not.toBe(0n);
  });
});

// ── HINT PAC ────────────────────────────────────────────────────────────────

describe('HINT PAC (PACIASP / AUTIASP)', () => {
  it('PACIASP signs LR and AUTIASP restores it', () => {
    const paciasp = 0xd503233f;
    const autiasp = 0xd50323bf;
    const orig = 0x7f0000abc000n;

    const e = exec2(paciasp, autiasp, { x30: Number(orig) });
    const lr = e.readGpr(30);
    expect(stripPac(lr)).toBe(orig);
  });

  it('XPACLRI strips LR unconditionally', () => {
    const paciasp = 0xd503233f;
    const xpaclri = 0xd50320ff;
    const orig = 0x7f0000abc000n;

    // Sign LR, then strip: should recover the original lower bits
    const e = exec2(paciasp, xpaclri, { x30: Number(orig) });
    const lr = e.readGpr(30);
    expect(stripPac(lr)).toBe(orig);
  });

  it('autiaz (0xD503239F) authenticates LR after paciaz with no mismatch', () => {
    const orig = 0x7f0000abc000n;
    const e = exec2(0xd503231f /* paciaz */, 0xd503239f /* autiaz */, { x30: Number(orig) });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(30)).toBe(orig);
  });

  it('autiaz on an unsigned LR records a mismatch', () => {
    const orig = 0x7f0000abc000n;
    const e = exec1(0xd503239f /* autiaz */, { x30: Number(orig) });
    const log = e.pacDiagSnapshot();
    expect(log.length).toBe(1);
    // Strip-anyway policy keeps control flow alive: LR is still recoverable.
    expect(stripPac(e.readGpr(30))).toBe(orig);
  });

  it('1716 variants sign and authenticate X17 with X16 as modifier', () => {
    const orig = 0x7f0000abc000n;
    // pacia1716 (0xD503211F): sign X17 in place with modifier X16.
    const e = exec2(0xd503211f, 0xd503219f /* autia1716 */, {
      x17: Number(orig),
      x16: 0x11223344,
    });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(17)).toBe(orig);
  });

  it('pacia1716 inserts a non-zero PAC field on X17', () => {
    const orig = 0x7f0000abc000n;
    const e = exec1(0xd503211f, { x17: Number(orig), x16: 0x11223344 });
    const signed = e.readGpr(17);
    expect(signed & PAC_MASK).not.toBe(0n);
    expect(stripPac(signed)).toBe(orig);
  });
});

// ── HINT PAC key-B branch (B-key downgrade regression guard) ────────────────

describe('HINT-space key-B family (pacibz / autibz / 1716-B)', () => {
  // DEFAULT_PAC_KEYS has ia === ib, which would mask a B→A key downgrade; every
  // test here must setPacKeys first so the ib slot is observably distinct.
  const keys = {
    ia: '11111111111111111111111111111111',
    ib: '22222222222222222222222222222222',
    da: '33333333333333333333333333333333',
    db: '44444444444444444444444444444444',
    ga: '55555555555555555555555555555555',
  };
  const runWithKeys = (insns: number[], regs: Record<string, number | bigint>): CpuEngine => {
    const e = new CpuEngine();
    e.setPacKeys(keys);
    e.mapMemory(BASE, 0x1000);
    e.writeRegister('sp', BASE + 0x800);
    for (const [k, v] of Object.entries(regs)) e.writeRegister(k, v);
    const buf = new Uint8Array(insns.length * 4);
    const dv = new DataView(buf.buffer);
    insns.forEach((w, i) => dv.setUint32(i * 4, w, true));
    e.writeCode(BASE, buf);
    e.start(BASE, BASE + insns.length * 4);
    return e;
  };

  it('pacibz (0xD503235F) signs LR with the ib key — PAC field differs from paciaz', () => {
    const orig = 0x7f0000abc000n;
    const viaB = runWithKeys([0xd503235f], { x30: Number(orig) }).readGpr(30);
    const viaA = runWithKeys([0xd503231f], { x30: Number(orig) }).readGpr(30);
    expect(stripPac(viaB)).toBe(orig);
    expect(viaB & PAC_MASK).not.toBe(0n);
    // ib ≠ ia → the 8-bit PAC fields must diverge.
    expect(viaB & PAC_MASK).not.toBe(viaA & PAC_MASK);
  });

  it('autibz (0xD50323DF) round-trips an LR signed by pacibz with no mismatch', () => {
    const orig = 0x7f0000abc000n;
    const e = runWithKeys([0xd503235f, 0xd50323df], { x30: Number(orig) });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(30)).toBe(orig);
  });

  it('pacibsp (0xD503237F) / autibsp (0xD50323FF) round-trip the SP-modifier slot with the ib key', () => {
    const orig = 0x7f0000abc000n;
    const viaB = runWithKeys([0xd503237f], { x30: Number(orig) }).readGpr(30);
    const viaA = runWithKeys([0xd503233f], { x30: Number(orig) }).readGpr(30);
    expect(viaB & PAC_MASK).not.toBe(0n);
    // ib ≠ ia at the same SP modifier → the 8-bit PAC fields must diverge.
    expect(viaB & PAC_MASK).not.toBe(viaA & PAC_MASK);
    const e = runWithKeys([0xd503237f, 0xd50323ff], { x30: Number(orig) });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(30)).toBe(orig);
  });

  it('pacib1716 (0xD503215F) / autib1716 (0xD50321DF) round-trip X17 with the ib key', () => {
    const orig = 0x7f0000abc000n;
    const e = runWithKeys([0xd503215f, 0xd50321df], { x17: Number(orig), x16: 0x11223344 });
    expect(e.pacDiagSnapshot()).toEqual([]);
    expect(e.readGpr(17)).toBe(orig);
  });
});

// ── Key management ──────────────────────────────────────────────────────────

describe('PAC key management', () => {
  it('setPacKeys replaces the active key set', () => {
    const e = new CpuEngine();
    const custom = {
      ia: 'deadbeef000000000000000000000001',
      ib: 'deadbeef000000000000000000000002',
      da: 'deadbeef000000000000000000000003',
      db: 'deadbeef000000000000000000000004',
      ga: 'deadbeef000000000000000000000005',
    };
    e.setPacKeys(custom);
    expect(e.pacKeys.ia).toBe(custom.ia);
    expect(e.pacKeys.ga).toBe(custom.ga);
  });
});

// ── PAC semantics hardening ─────────────────────────────────────────────────

describe('PAC key divergence', () => {
  const keys = {
    ia: '11111111111111111111111111111111',
    ib: '22222222222222222222222222222222',
    da: '33333333333333333333333333333333',
    db: '44444444444444444444444444444444',
    ga: '55555555555555555555555555555555',
  };
  const run = (insn: number): bigint => {
    const e = new CpuEngine();
    e.setPacKeys(keys);
    e.mapMemory(BASE, 0x1000);
    e.writeRegister('sp', BASE + 0x800);
    e.writeRegister('x1', Number(0x7f0000abc000n));
    e.writeRegister('x2', 0x11223344);
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, insn, true);
    e.writeCode(BASE, buf);
    e.start(BASE, BASE + 4);
    return e.readGpr(1);
  };
  it('A-key and B-key signing produce different PAC fields when keys differ', () => {
    expect(run(pacReg(0, 2, 1)) & PAC_MASK).not.toBe(run(pacReg(1, 2, 1)) & PAC_MASK);
  });
  it('IA and DA signing produce different PAC fields when keys differ', () => {
    expect(run(pacReg(0, 2, 1)) & PAC_MASK).not.toBe(run(pacReg(2, 2, 1)) & PAC_MASK);
  });
  it('PACDA/PACDB round-trip through AUTDA/AUTDB with no mismatch', () => {
    const orig = 0x7f0000abc000n;
    const da = exec2(pacReg(2, 2, 1), pacReg(6, 2, 1), { x1: Number(orig), x2: 0x11223344 });
    expect(da.pacDiagSnapshot()).toEqual([]);
    expect(da.readGpr(1)).toBe(orig);
    const db = exec2(pacReg(3, 2, 1), pacReg(7, 2, 1), { x1: Number(orig), x2: 0x11223344 });
    expect(db.pacDiagSnapshot()).toEqual([]);
    expect(db.readGpr(1)).toBe(orig);
  });
});

describe('PAC AUT mismatch diagnostics', () => {
  it('records AUT mismatches in the bounded engine log', () => {
    const orig = 0x7f0000abc000n;
    const pacia = pacReg(0, 3, 1); // pacia x1, x3 — sign with modifier x3
    const autia = pacReg(4, 4, 1); // autia x1, x4 — auth with modifier x4 → mismatch
    const e = new CpuEngine();
    e.mapMemory(BASE, 0x1000);
    e.writeRegister('sp', BASE + 0x800);
    e.writeRegister('x1', Number(orig));
    e.writeRegister('x3', 0x11223344);
    e.writeRegister('x4', 0x55667788);
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setUint32(0, pacia, true);
    new DataView(buf.buffer).setUint32(4, autia, true);
    e.writeCode(BASE, buf);
    e.start(BASE, BASE + 8);
    const log = e.pacDiagSnapshot();
    expect(log.length).toBe(1);
    // Label carries the real mnemonic so trace lines cross-grep with disasm.
    expect(log[0]).toContain('autia mismatch');
    // Strip-anyway policy keeps control flow alive: x1 recovered the address.
    expect(e.readGpr(1)).toBe(orig);
  });

  it('AUT with matching modifier records no mismatch', () => {
    const orig = 0x7f0000abc000n;
    const e = exec2(pacReg(0, 3, 1), pacReg(4, 3, 1), { x1: Number(orig), x3: 0x11223344 });
    expect(e.pacDiagSnapshot()).toEqual([]);
  });

  it('mismatch log is capped at 32 entries', () => {
    const e = new CpuEngine();
    for (let i = 0; i < 40; i++) e.recordPacMismatch(`mismatch ${i}`);
    expect(e.pacDiagSnapshot().length).toBe(32);
  });
});

describe('HINT-space CRm gate', () => {
  it('YIELD and WFI are no-ops on LR instead of LR signing/auth', () => {
    const orig = 0x7f0000abc000n;
    // YIELD = 0xD503203F (CRm=0, op2=1), WFI = 0xD503207F (CRm=0, op2=3) —
    // only CRm=3 (zero/SP modifier family) and CRm=1 (1716 family) are PAC
    // instructions; other CRm values must fall through to the blanket NOP.
    for (const hint of [0xd503203f, 0xd503207f]) {
      const e = exec1(hint, { x30: Number(orig) });
      expect(e.readGpr(30)).toBe(orig);
    }
  });

  it('WFE and the SEV-range slot leave LR and X17 untouched (blanket NOP)', () => {
    // CRm=0, even op2: WFE (0xD503205F, op2=2) and 0xD503209F (op2=4; capstone
    // 5.0.7 labels it `sev`). Seeded with the dirty vector: if the CRm gate
    // were removed, 0xD503209F would fall into the 1716 AUT path (stripping
    // the dirty field + logging a mismatch diag) and WFE into the sign path
    // (overwriting X17) — both observable. Neither may touch LR or X17.
    for (const hint of [0xd503205f, 0xd503209f]) {
      const e = exec1(hint, { x30: DIRTY, x17: DIRTY });
      expect(e.pacDiagSnapshot()).toEqual([]);
      expect(e.readGpr(30)).toBe(DIRTY);
      expect(e.readGpr(17)).toBe(DIRTY);
    }
  });
});
