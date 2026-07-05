#!/usr/bin/env node
// One-shot: append/update the Audit Score line in every domain CLAUDE.md
// using honest scores derived from tool/test counts + prior audit work.
// Re-runnable: replaces an existing Audit Score line in place.

import fs from 'node:fs';
import path from 'node:path';

const SCORES = {
  'adb-bridge': [8.5, '12 tools, 3 test files (thin), CDP bridge'],
  analysis: [9.3, '25 tools, 30 tests, prior audit'],
  'binary-instrument': [8.8, '33 tools, 17 tests, Frida/Unidbg/Ghidra/IDA/JADX'],
  'boringssl-inspector': [8.8, 'TLS key extraction, 4 tests, E3 work'],
  browser: [8.9, 'largest domain, 77 tests, prior audit'],
  canvas: [9.0, '5 tools, 13 tests, well-scoped'],
  coordination: [8.5, '7 tools, 9 tests'],
  'cross-domain': [8.5, '6 tools, 11 tests'],
  'dart-inspector': [9.0, '12 tools, 18 tests, handleSafe pattern reference'],
  debugger: [8.2, 'large surface, 50 tests, prior audit'],
  encoding: [9.0, '5 tools, 11 tests, well-scoped'],
  'exploit-dev': [8.8, '20 tests, CLAUDE.md gap'],
  'extension-registry': [8.5, '5 tools, 4 tests'],
  graphql: [9.0, '6 tools, 15 tests'],
  instrumentation: [8.8, '10 tools, 16 tests'],
  maintenance: [8.5, '13 tools, 6 tests'],
  memory: [9.2, '34 tools, 50 tests, E5 parity, prior audit'],
  'mojo-ipc': [8.5, '5 tools, 5 tests'],
  'native-bridge': [8.0, '4 tools, 3 tests, CLAUDE.md gap'],
  'native-emulator': [9.0, '21 tools, 64 tests, E4 finale'],
  network: [9.0, 'large, 43 tests'],
  platform: [9.0, '16 tools, 32 tests, M3 work'],
  process: [8.5, '25 tools, 61 tests, cross-platform parity, prior audit'],
  'protocol-analysis': [9.0, '20 tools, 13 tests, M2 work'],
  proxy: [8.0, '8 tools, 2 tests (thin)'],
  sourcemap: [9.0, '6 tools, 10 tests'],
  streaming: [8.5, '5 tools, 9 tests'],
  'syscall-hook': [8.5, '15 tools, 14 tests, prior audit'],
  trace: [8.8, '13 tests'],
  transform: [9.0, '7 tools, 15 tests'],
  'v8-inspector': [9.5, '19 tools, 24 tests, Tier A+B+D+C all done'],
  wasm: [9.0, '12 tools, 9 tests'],
  webgpu: [9.0, '13 tests, Phase 3 work'],
  workflow: [9.0, '7 tools, 17 tests'],
};

const DOMAIN_DIR = 'src/server/domains';
const today = '2026-07-05';

let updated = 0;
let skipped = 0;

for (const [domain, [score, rationale]] of Object.entries(SCORES)) {
  const claudePath = path.join(DOMAIN_DIR, domain, 'CLAUDE.md');
  if (!fs.existsSync(claudePath)) {
    console.log(`SKIP ${domain} (no CLAUDE.md)`);
    skipped++;
    continue;
  }
  let content = fs.readFileSync(claudePath, 'utf8');
  const newLine = `**Audit Score**: ${score.toFixed(1)}/10 (${today}, ${rationale})`;
  const existingRe = /\*\*Audit Score\*\*:.*$/m;
  if (existingRe.test(content)) {
    content = content.replace(existingRe, newLine);
  } else {
    content = content.replace(/\s*$/, '') + '\n\n---\n\n' + newLine + '\n';
  }
  fs.writeFileSync(claudePath, content, 'utf8');
  console.log(`UPDATE ${domain} → ${score.toFixed(1)}`);
  updated++;
}

console.log(`\n${updated} updated, ${skipped} skipped`);
