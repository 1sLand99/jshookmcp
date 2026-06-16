/**
 * Apktool decode handler.
 */

import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { probeCommand } from '@modules/external/ToolProbe';
import {
  readRequiredString,
  readOptionalString,
  readOptionalBoolean,
  jsonResponse,
  execFileUtf8,
} from './shared';

export class ApktoolHandlers {
  async handleApktoolDecode(args: Record<string, unknown>): Promise<unknown> {
    const apkPath = readRequiredString(args, 'apkPath');
    const explicitOutputDir = readOptionalString(args, 'outputDir');
    const force = readOptionalBoolean(args, 'force') ?? false;
    const apktoolProbe = await probeCommand('apktool', ['--version']);
    if (!apktoolProbe.available) {
      return jsonResponse({
        available: false,
        capability: 'apktool_cli',
        fix: 'Install apktool and ensure it is on PATH.',
        apkPath,
        reason: apktoolProbe.reason ?? 'apktool is not available',
      });
    }

    const outputDir = explicitOutputDir ?? join(tmpdir(), `jshook-apktool-${Date.now()}`);
    if (explicitOutputDir) {
      await mkdir(outputDir, { recursive: true });
    }

    try {
      const argsList = ['decode', '--output', outputDir];
      if (force) argsList.push('--force');
      argsList.push(apkPath);

      const result = await execFileUtf8(apktoolProbe.path ?? 'apktool', argsList, 120_000);
      return jsonResponse({
        available: true,
        apkPath,
        outputDir,
        force,
        stdout: result.stdout.trim(),
        stderr: result.stderr.trim(),
      });
    } catch (error) {
      return jsonResponse({
        available: true,
        apkPath,
        outputDir,
        force,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
}
