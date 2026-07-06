export interface DecodedPayload {
  header: {
    version: number;
    flags: number;
    messageType: number;
    numFields: number;
    handles: number;
  };
  fields: Record<string, unknown>;
  handles: number;
  raw: string;
  _raw_summary?: string;
}

interface HandleField {
  handle: number;
}

interface TypedField {
  type: string;
  value?: unknown;
  values?: unknown[];
  fields?: unknown[];
  elementType?: string;
  handle?: number;
}

interface DecodedField {
  value: unknown;
  cursor: number;
  handles: number;
  complete: boolean;
  summary?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const FIELD_TYPE_BOOL = 0x01;
const FIELD_TYPE_INT16 = 0x04;
const FIELD_TYPE_UINT16 = 0x05;
const FIELD_TYPE_INT32 = 0x06;
const FIELD_TYPE_INT64 = 0x07;
const FIELD_TYPE_UINT32 = 0x08;
const FIELD_TYPE_UINT64 = 0x09;
const FIELD_TYPE_FLOAT = 0x0a;
const FIELD_TYPE_DOUBLE = 0x0b;
const FIELD_TYPE_STRING = 0x0c;
const FIELD_TYPE_NULLABLE_STRING = 0x0d;
const FIELD_TYPE_ARRAY = 0x0e;
const FIELD_TYPE_STRUCT = 0x0f;
const FIELD_TYPE_HANDLE = 0x10;
const FIELD_TYPE_INTERFACE = 0x11;
const FIELD_TYPE_PENDING_REMOTE = 0x12;
const FIELD_TYPE_PENDING_RECEIVER = 0x13;
const FIELD_TYPE_PENDING_ASSOCIATED_REMOTE = 0x14;
const FIELD_TYPE_PENDING_ASSOCIATED_RECEIVER = 0x15;

const FIELD_TYPE_BY_NAME: Record<string, number> = {
  bool: FIELD_TYPE_BOOL,
  boolean: FIELD_TYPE_BOOL,
  int16: FIELD_TYPE_INT16,
  uint16: FIELD_TYPE_UINT16,
  int32: FIELD_TYPE_INT32,
  int64: FIELD_TYPE_INT64,
  uint32: FIELD_TYPE_UINT32,
  uint64: FIELD_TYPE_UINT64,
  float: FIELD_TYPE_FLOAT,
  double: FIELD_TYPE_DOUBLE,
  string: FIELD_TYPE_STRING,
  nullable_string: FIELD_TYPE_NULLABLE_STRING,
  nullableString: FIELD_TYPE_NULLABLE_STRING,
  array: FIELD_TYPE_ARRAY,
  struct: FIELD_TYPE_STRUCT,
  handle: FIELD_TYPE_HANDLE,
  interface: FIELD_TYPE_INTERFACE,
  pending_remote: FIELD_TYPE_PENDING_REMOTE,
  pendingRemote: FIELD_TYPE_PENDING_REMOTE,
  pending_receiver: FIELD_TYPE_PENDING_RECEIVER,
  pendingReceiver: FIELD_TYPE_PENDING_RECEIVER,
  pending_associated_remote: FIELD_TYPE_PENDING_ASSOCIATED_REMOTE,
  pendingAssociatedRemote: FIELD_TYPE_PENDING_ASSOCIATED_REMOTE,
  pending_associated_receiver: FIELD_TYPE_PENDING_ASSOCIATED_RECEIVER,
  pendingAssociatedReceiver: FIELD_TYPE_PENDING_ASSOCIATED_RECEIVER,
};

const HANDLE_LIKE_TYPES = new Set([
  FIELD_TYPE_HANDLE,
  FIELD_TYPE_INTERFACE,
  FIELD_TYPE_PENDING_REMOTE,
  FIELD_TYPE_PENDING_RECEIVER,
  FIELD_TYPE_PENDING_ASSOCIATED_REMOTE,
  FIELD_TYPE_PENDING_ASSOCIATED_RECEIVER,
]);

function isHandleField(value: unknown): value is HandleField {
  return isRecord(value) && typeof value['handle'] === 'number';
}

function isTypedField(value: unknown): value is TypedField {
  return isRecord(value) && typeof value['type'] === 'string';
}

function normalizeHexInput(hex: string): string {
  const cleaned = hex.replace(/\s+/g, '');
  if (cleaned.length % 2 === 0) {
    return cleaned.toLowerCase();
  }

  return `0${cleaned.toLowerCase()}`;
}

function typeName(typeCode: number): string {
  for (const [name, value] of Object.entries(FIELD_TYPE_BY_NAME)) {
    if (value === typeCode) return name;
  }
  return `0x${typeCode.toString(16).padStart(2, '0')}`;
}

export class MojoDecoder {
  decodePayload(hex: string, context?: string): DecodedPayload {
    const raw = this.cleanHex(hex);
    const bytes = Buffer.from(raw, 'hex');

    const version = this.readUInt8(bytes, 0);
    const flags = this.readUInt8(bytes, 1);
    const messageType = this.readUInt8(bytes, 2);
    const numFields = this.readUInt8(bytes, 3);
    const declaredHandles = this.readUInt16LE(bytes, 4);

    const fields: Record<string, unknown> = {};
    const summaryParts: string[] = [];
    let cursor = this.payloadCursor(bytes, version);
    let actualHandles = 0;

    for (let index = 0; index < numFields; index += 1) {
      if (cursor >= bytes.length) {
        summaryParts.push('payload ended before all fields were decoded');
        break;
      }

      const fieldName = `field${index}`;
      const decoded = this.decodeField(bytes, cursor, fieldName);
      fields[fieldName] = decoded.value;
      actualHandles += decoded.handles;
      cursor = decoded.cursor;
      if (decoded.summary) summaryParts.push(decoded.summary);
      if (!decoded.complete) break;
    }

    const summary =
      summaryParts.length > 0
        ? summaryParts.join('; ')
        : this.buildSummary(context, Object.keys(fields).length, numFields, actualHandles);

    return {
      header: {
        version,
        flags,
        messageType,
        numFields,
        handles: declaredHandles,
      },
      fields,
      handles: actualHandles,
      raw,
      _raw_summary: summary,
    };
  }

  encodeMessage(interfaceName: string, messageType: string | number, fields: unknown[]): string {
    const encodedParts: Buffer[] = [];
    let handles = 0;

    for (const field of fields) {
      const encoded = this.encodeField(field);
      encodedParts.push(encoded.buffer);
      handles += encoded.handles;
    }

    const messageTypeCode = this.resolveMessageType(interfaceName, messageType);
    const fieldCount = Math.min(fields.length, 255);
    const header = Buffer.alloc(6);
    header.writeUInt8(1, 0);
    header.writeUInt8(0, 1);
    header.writeUInt8(messageTypeCode, 2);
    header.writeUInt8(fieldCount, 3);
    header.writeUInt16LE(handles, 4);

    return Buffer.concat([header, ...encodedParts]).toString('hex');
  }

  cleanHex(hex: string): string {
    return normalizeHexInput(hex);
  }

  private payloadCursor(bytes: Buffer, version: number): number {
    if (version >= 2 && bytes.length >= 18) {
      return 18;
    }
    return 6;
  }

  private decodeField(bytes: Buffer, cursor: number, fieldName: string): DecodedField {
    const typeCode = this.readUInt8(bytes, cursor);
    return this.decodeFieldValue(bytes, cursor + 1, typeCode, fieldName);
  }

  private decodeFieldValue(
    bytes: Buffer,
    cursor: number,
    typeCode: number,
    fieldName: string,
  ): DecodedField {
    if (typeCode === FIELD_TYPE_BOOL) {
      if (!this.hasBytes(bytes, cursor, 1)) return this.truncated(fieldName, 'bool', bytes);
      return {
        value: this.readUInt8(bytes, cursor) !== 0,
        cursor: cursor + 1,
        handles: 0,
        complete: true,
      };
    }

    if (typeCode === FIELD_TYPE_INT16) {
      if (!this.hasBytes(bytes, cursor, 2)) return this.truncated(fieldName, 'int16', bytes);
      return { value: bytes.readInt16LE(cursor), cursor: cursor + 2, handles: 0, complete: true };
    }

    if (typeCode === FIELD_TYPE_UINT16) {
      if (!this.hasBytes(bytes, cursor, 2)) return this.truncated(fieldName, 'uint16', bytes);
      return { value: bytes.readUInt16LE(cursor), cursor: cursor + 2, handles: 0, complete: true };
    }

    if (typeCode === FIELD_TYPE_INT32) {
      if (!this.hasBytes(bytes, cursor, 4)) return this.truncated(fieldName, 'int32', bytes);
      return { value: bytes.readInt32LE(cursor), cursor: cursor + 4, handles: 0, complete: true };
    }

    if (typeCode === FIELD_TYPE_UINT32) {
      if (!this.hasBytes(bytes, cursor, 4)) return this.truncated(fieldName, 'uint32', bytes);
      return { value: bytes.readUInt32LE(cursor), cursor: cursor + 4, handles: 0, complete: true };
    }

    if (typeCode === FIELD_TYPE_INT64) {
      if (!this.hasBytes(bytes, cursor, 8)) return this.truncated(fieldName, 'int64', bytes);
      return {
        value: bytes.readBigInt64LE(cursor),
        cursor: cursor + 8,
        handles: 0,
        complete: true,
      };
    }

    if (typeCode === FIELD_TYPE_UINT64) {
      if (!this.hasBytes(bytes, cursor, 8)) return this.truncated(fieldName, 'uint64', bytes);
      return {
        value: bytes.readBigUInt64LE(cursor),
        cursor: cursor + 8,
        handles: 0,
        complete: true,
      };
    }

    if (typeCode === FIELD_TYPE_FLOAT) {
      if (!this.hasBytes(bytes, cursor, 4)) return this.truncated(fieldName, 'float', bytes);
      return { value: bytes.readFloatLE(cursor), cursor: cursor + 4, handles: 0, complete: true };
    }

    if (typeCode === FIELD_TYPE_DOUBLE) {
      if (!this.hasBytes(bytes, cursor, 8)) return this.truncated(fieldName, 'double', bytes);
      return { value: bytes.readDoubleLE(cursor), cursor: cursor + 8, handles: 0, complete: true };
    }

    if (typeCode === FIELD_TYPE_STRING || typeCode === FIELD_TYPE_NULLABLE_STRING) {
      return this.decodeString(bytes, cursor, fieldName, typeCode === FIELD_TYPE_NULLABLE_STRING);
    }

    if (typeCode === FIELD_TYPE_ARRAY) {
      return this.decodeArray(bytes, cursor, fieldName);
    }

    if (typeCode === FIELD_TYPE_STRUCT) {
      return this.decodeStruct(bytes, cursor, fieldName);
    }

    if (HANDLE_LIKE_TYPES.has(typeCode)) {
      if (!this.hasBytes(bytes, cursor, 4)) {
        return this.truncated(fieldName, typeName(typeCode), bytes);
      }
      const handle = bytes.readUInt32LE(cursor);
      return {
        value: typeCode === FIELD_TYPE_HANDLE ? { handle } : { kind: typeName(typeCode), handle },
        cursor: cursor + 4,
        handles: 1,
        complete: true,
      };
    }

    const skip = cursor < bytes.length ? 1 : 0;
    return {
      value: { unknownType: typeCode, skippedBytes: skip },
      cursor: cursor + skip,
      handles: 0,
      complete: true,
      summary: `unknown field type 0x${typeCode.toString(16).padStart(2, '0')}`,
    };
  }

  private decodeString(
    bytes: Buffer,
    cursor: number,
    fieldName: string,
    nullable: boolean,
  ): DecodedField {
    if (!this.hasBytes(bytes, cursor, 2)) {
      return this.truncated(fieldName, 'length prefix', bytes);
    }

    const length = this.readUInt16LE(bytes, cursor);
    cursor += 2;

    if (nullable && length === 0xffff) {
      return { value: null, cursor, handles: 0, complete: true };
    }

    if (!this.hasBytes(bytes, cursor, length)) {
      return this.truncated(fieldName, 'string data', bytes);
    }

    return {
      value: bytes.subarray(cursor, cursor + length).toString('utf8'),
      cursor: cursor + length,
      handles: 0,
      complete: true,
    };
  }

  private decodeArray(bytes: Buffer, cursor: number, fieldName: string): DecodedField {
    if (!this.hasBytes(bytes, cursor, 3)) return this.truncated(fieldName, 'array header', bytes);
    const elementType = this.readUInt8(bytes, cursor);
    const count = this.readUInt16LE(bytes, cursor + 1);
    cursor += 3;

    const values: unknown[] = [];
    let handles = 0;
    const summaries: string[] = [];
    for (let i = 0; i < count; i += 1) {
      const decoded = this.decodeFieldValue(bytes, cursor, elementType, `${fieldName}[${i}]`);
      values.push(decoded.value);
      handles += decoded.handles;
      cursor = decoded.cursor;
      if (decoded.summary) summaries.push(decoded.summary);
      if (!decoded.complete) {
        return {
          value: values,
          cursor,
          handles,
          complete: false,
          summary: summaries.join('; ') || decoded.summary,
        };
      }
    }

    return {
      value: values,
      cursor,
      handles,
      complete: true,
      summary: summaries.length > 0 ? summaries.join('; ') : undefined,
    };
  }

  private decodeStruct(bytes: Buffer, cursor: number, fieldName: string): DecodedField {
    if (!this.hasBytes(bytes, cursor, 1)) return this.truncated(fieldName, 'struct header', bytes);
    const count = this.readUInt8(bytes, cursor);
    cursor += 1;

    const values: Record<string, unknown> = {};
    let handles = 0;
    const summaries: string[] = [];
    for (let i = 0; i < count; i += 1) {
      const decoded = this.decodeField(bytes, cursor, `${fieldName}.${i}`);
      values[`field${i}`] = decoded.value;
      handles += decoded.handles;
      cursor = decoded.cursor;
      if (decoded.summary) summaries.push(decoded.summary);
      if (!decoded.complete) {
        return {
          value: values,
          cursor,
          handles,
          complete: false,
          summary: summaries.join('; ') || decoded.summary,
        };
      }
    }

    return {
      value: values,
      cursor,
      handles,
      complete: true,
      summary: summaries.length > 0 ? summaries.join('; ') : undefined,
    };
  }

  private encodeField(field: unknown): { buffer: Buffer; handles: number } {
    if (isTypedField(field)) {
      const typeCode = this.typeCodeFor(field.type);
      return {
        buffer: Buffer.concat([Buffer.from([typeCode]), this.encodeValue(typeCode, field)]),
        handles: HANDLE_LIKE_TYPES.has(typeCode) ? 1 : this.countHandles(field),
      };
    }

    if (typeof field === 'boolean') {
      return { buffer: Buffer.from([FIELD_TYPE_BOOL, field ? 1 : 0]), handles: 0 };
    }

    if (typeof field === 'bigint') {
      const chunk = Buffer.alloc(9);
      const typeCode = field < 0n ? FIELD_TYPE_INT64 : FIELD_TYPE_UINT64;
      chunk.writeUInt8(typeCode, 0);
      if (typeCode === FIELD_TYPE_INT64) chunk.writeBigInt64LE(field, 1);
      else chunk.writeBigUInt64LE(field, 1);
      return { buffer: chunk, handles: 0 };
    }

    if (typeof field === 'number' && Number.isInteger(field) && field >= 0) {
      const chunk = Buffer.alloc(5);
      chunk.writeUInt8(FIELD_TYPE_UINT32, 0);
      chunk.writeUInt32LE(field, 1);
      return { buffer: chunk, handles: 0 };
    }

    if (typeof field === 'number' && Number.isInteger(field)) {
      const chunk = Buffer.alloc(5);
      chunk.writeUInt8(FIELD_TYPE_INT32, 0);
      chunk.writeInt32LE(field, 1);
      return { buffer: chunk, handles: 0 };
    }

    if (isHandleField(field)) {
      const chunk = Buffer.alloc(5);
      chunk.writeUInt8(FIELD_TYPE_HANDLE, 0);
      chunk.writeUInt32LE(field.handle, 1);
      return { buffer: chunk, handles: 1 };
    }

    return {
      buffer: Buffer.concat([Buffer.from([FIELD_TYPE_STRING]), this.encodeStringValue(field)]),
      handles: 0,
    };
  }

  private encodeValue(typeCode: number, field: TypedField): Buffer {
    const value = field.value;
    switch (typeCode) {
      case FIELD_TYPE_BOOL:
        return Buffer.from([value ? 1 : 0]);
      case FIELD_TYPE_INT16: {
        const chunk = Buffer.alloc(2);
        chunk.writeInt16LE(Number(value ?? 0), 0);
        return chunk;
      }
      case FIELD_TYPE_UINT16: {
        const chunk = Buffer.alloc(2);
        chunk.writeUInt16LE(Number(value ?? 0), 0);
        return chunk;
      }
      case FIELD_TYPE_INT32: {
        const chunk = Buffer.alloc(4);
        chunk.writeInt32LE(Number(value ?? 0), 0);
        return chunk;
      }
      case FIELD_TYPE_UINT32: {
        const chunk = Buffer.alloc(4);
        chunk.writeUInt32LE(Number(value ?? 0), 0);
        return chunk;
      }
      case FIELD_TYPE_INT64: {
        const chunk = Buffer.alloc(8);
        chunk.writeBigInt64LE(BigInt(String(value ?? 0)), 0);
        return chunk;
      }
      case FIELD_TYPE_UINT64: {
        const chunk = Buffer.alloc(8);
        chunk.writeBigUInt64LE(BigInt(String(value ?? 0)), 0);
        return chunk;
      }
      case FIELD_TYPE_FLOAT: {
        const chunk = Buffer.alloc(4);
        chunk.writeFloatLE(Number(value ?? 0), 0);
        return chunk;
      }
      case FIELD_TYPE_DOUBLE: {
        const chunk = Buffer.alloc(8);
        chunk.writeDoubleLE(Number(value ?? 0), 0);
        return chunk;
      }
      case FIELD_TYPE_STRING:
        return this.encodeStringValue(value);
      case FIELD_TYPE_NULLABLE_STRING:
        return value === null || value === undefined
          ? Buffer.from([0xff, 0xff])
          : this.encodeStringValue(value);
      case FIELD_TYPE_ARRAY:
        return this.encodeArrayValue(field);
      case FIELD_TYPE_STRUCT:
        return this.encodeStructValue(field.fields ?? []);
      default:
        if (HANDLE_LIKE_TYPES.has(typeCode)) {
          const chunk = Buffer.alloc(4);
          chunk.writeUInt32LE(Number(field.handle ?? value ?? 0), 0);
          return chunk;
        }
        return Buffer.alloc(0);
    }
  }

  private encodeStringValue(value: unknown): Buffer {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    const textBuffer = Buffer.from(text ?? '', 'utf8');
    const header = Buffer.alloc(2);
    header.writeUInt16LE(textBuffer.length, 0);
    return Buffer.concat([header, textBuffer]);
  }

  private encodeArrayValue(field: TypedField): Buffer {
    const elementType = this.typeCodeFor(field.elementType ?? 'string');
    const values = Array.isArray(field.values) ? field.values : [];
    const header = Buffer.alloc(3);
    header.writeUInt8(elementType, 0);
    header.writeUInt16LE(Math.min(values.length, 0xffff), 1);
    const encodedValues = values.map((value) =>
      this.encodeValue(elementType, { type: typeName(elementType), value }),
    );
    return Buffer.concat([header, ...encodedValues]);
  }

  private encodeStructValue(fields: unknown[]): Buffer {
    const header = Buffer.from([Math.min(fields.length, 255)]);
    const encodedFields = fields.map((field) => this.encodeField(field).buffer);
    return Buffer.concat([header, ...encodedFields]);
  }

  private countHandles(field: TypedField): number {
    const typeCode = this.typeCodeFor(field.type);
    if (HANDLE_LIKE_TYPES.has(typeCode)) return 1;
    if (typeCode === FIELD_TYPE_ARRAY) {
      const elementType = this.typeCodeFor(field.elementType ?? 'string');
      return HANDLE_LIKE_TYPES.has(elementType) ? (field.values?.length ?? 0) : 0;
    }
    if (typeCode === FIELD_TYPE_STRUCT) {
      return (field.fields ?? []).reduce<number>(
        (count, item) => count + this.encodeField(item).handles,
        0,
      );
    }
    return 0;
  }

  private typeCodeFor(type: string): number {
    const typeCode = FIELD_TYPE_BY_NAME[type];
    if (typeCode !== undefined) return typeCode;
    const normalized = type.trim().toLowerCase();
    if (normalized.startsWith('0x')) return Number.parseInt(normalized.slice(2), 16) & 0xff;
    return FIELD_TYPE_BY_NAME[normalized] ?? FIELD_TYPE_STRING;
  }

  private resolveMessageType(interfaceName: string, messageType: string | number): number {
    if (typeof messageType === 'number' && Number.isFinite(messageType)) {
      return Math.trunc(messageType) & 0xff;
    }

    messageType = String(messageType);
    const decimalMatch = /^[0-9]+$/.test(messageType);
    if (decimalMatch) {
      return Number.parseInt(messageType, 10) & 0xff;
    }

    const hexMatch = /^0x[0-9a-f]+$/i.test(messageType);
    if (hexMatch) {
      return Number.parseInt(messageType.slice(2), 16) & 0xff;
    }

    let hash = 0;
    const seed = `${interfaceName}:${messageType}`;
    for (const char of seed) {
      hash = (hash * 31 + char.charCodeAt(0)) & 0xff;
    }

    return hash;
  }

  private buildSummary(
    context: string | undefined,
    decodedFields: number,
    declaredFields: number,
    handles: number,
  ): string {
    const prefix = context ? `${context}: ` : '';
    return `${prefix}decoded ${decodedFields}/${declaredFields} fields, ${handles} handle(s)`;
  }

  private truncated(fieldName: string, segment: string, bytes: Buffer): DecodedField {
    return {
      value: null,
      cursor: bytes.length,
      handles: 0,
      complete: false,
      summary: `${fieldName} ${segment} truncated`,
    };
  }

  private readUInt8(bytes: Buffer, offset: number): number {
    if (!this.hasBytes(bytes, offset, 1)) {
      return 0;
    }

    return bytes.readUInt8(offset);
  }

  private readUInt16LE(bytes: Buffer, offset: number): number {
    if (!this.hasBytes(bytes, offset, 2)) {
      return 0;
    }

    return bytes.readUInt16LE(offset);
  }

  private hasBytes(bytes: Buffer, offset: number, length: number): boolean {
    return offset >= 0 && length >= 0 && offset + length <= bytes.length;
  }
}
