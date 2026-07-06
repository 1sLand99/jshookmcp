import type { EmulatorSession } from '@modules/native-emulator/SessionManager';
import type { JavaMethodCall } from '@modules/native-emulator/jni';
import { argNumber, argString } from '@server/domains/shared/parse-args';
import type { ToolArgs } from '@server/types';
import { toUint8 } from './handler-memory';

export interface JavaMockImpl {
  kind: 'int' | 'string' | 'bytes' | 'void';
  fn: (call: JavaMethodCall) => bigint | number | void;
}

export interface JavaFieldValue {
  kind: 'int' | 'string' | 'bytes';
  value: bigint;
}

function providedKeys(args: ToolArgs, keys: string[]): string[] {
  return keys.filter((key) => args[key] !== undefined && args[key] !== null);
}

function assertSingleJavaMockReturn(args: ToolArgs): void {
  const provided = providedKeys(args, ['returnInt', 'returnString', 'returnBytes']);
  if (provided.length > 1) {
    throw new Error(
      'returnInt, returnString, and returnBytes are mutually exclusive; provide only one return value.',
    );
  }
}

function assertSingleJavaFieldValue(args: ToolArgs): void {
  const provided = providedKeys(args, ['valueInt', 'valueString', 'valueBytes']);
  if (provided.length > 1) {
    throw new Error(
      'valueInt, valueString, and valueBytes are mutually exclusive; provide only one field value.',
    );
  }
}

export function buildJavaMockImpl(args: ToolArgs): JavaMockImpl {
  assertSingleJavaMockReturn(args);
  const returnInt = argNumber(args, 'returnInt');
  const returnString = argString(args, 'returnString');
  const returnBytes = argString(args, 'returnBytes');

  if (returnInt !== undefined) {
    return { kind: 'int', fn: () => BigInt(Math.trunc(returnInt)) };
  }
  if (returnString !== undefined) {
    return {
      kind: 'string',
      fn: (call) => BigInt(call.jni.allocHandle({ kind: 'string', value: returnString })),
    };
  }
  if (returnBytes !== undefined) {
    const bytes = toUint8(Buffer.from(returnBytes, 'base64'));
    return {
      kind: 'bytes',
      fn: (call) => BigInt(call.jni.allocHandle({ kind: 'bytes', value: bytes })),
    };
  }
  return { kind: 'void', fn: () => undefined };
}

export function buildJavaFieldValue(session: EmulatorSession, args: ToolArgs): JavaFieldValue {
  assertSingleJavaFieldValue(args);
  const valueInt = argNumber(args, 'valueInt');
  const valueString = argString(args, 'valueString');
  const valueBytes = argString(args, 'valueBytes');

  if (valueInt !== undefined) {
    return { kind: 'int', value: BigInt(Math.trunc(valueInt)) };
  }
  if (valueString !== undefined) {
    const handle = session.emulator.jni.allocHandle({ kind: 'string', value: valueString });
    return { kind: 'string', value: BigInt(handle) };
  }
  if (valueBytes !== undefined) {
    const bytes = toUint8(Buffer.from(valueBytes, 'base64'));
    const handle = session.emulator.newByteArray(bytes);
    return { kind: 'bytes', value: BigInt(handle) };
  }
  return { kind: 'int', value: 0n };
}
