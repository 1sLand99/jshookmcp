import type { StructureAnalyzer } from '@native/StructureAnalyzer';
import type { FieldType, InferredStruct } from '@native/StructureAnalyzer.types';
import type { UnifiedProcessManager } from '@server/domains/shared/modules/native';
import type { MCPServerContext } from '@server/MCPServer.context';
import { resolveMemoryDomainPid } from '@server/domains/memory/pid-resolver';
import { handleSafe } from '@server/domains/shared/ResponseBuilder';

const FIELD_TYPE_ALIASES: Record<string, FieldType> = {
  int8_t: 'int8',
  uint8_t: 'uint8',
  int16_t: 'int16',
  uint16_t: 'uint16',
  int32_t: 'int32',
  uint32_t: 'uint32',
  int64_t: 'int64',
  uint64_t: 'uint64',
  void_ptr: 'pointer',
  char_ptr: 'string_ptr',
};

function normalizeFieldType(value: unknown): FieldType {
  if (typeof value !== 'string' || value.length === 0) return 'unknown';
  const normalized = value.toLowerCase().replace(/\s+/g, '_').replace(/\*/g, '_ptr');
  return FIELD_TYPE_ALIASES[normalized] ?? (normalized as FieldType);
}

function normalizeStructureForExport(raw: unknown): InferredStruct {
  if (!raw || typeof raw !== 'object') {
    throw new Error('structure must be a JSON object');
  }

  const source = raw as Record<string, unknown>;
  const rawFields = Array.isArray(source.fields) ? source.fields : [];
  const fields = rawFields.map((entry, index) => {
    const field = entry as Record<string, unknown>;
    const offset = typeof field.offset === 'number' ? field.offset : 0;
    const size = typeof field.size === 'number' ? field.size : 1;

    return {
      offset,
      size,
      type: normalizeFieldType(field.type),
      name: typeof field.name === 'string' && field.name.length > 0 ? field.name : `field_${index}`,
      value: typeof field.value === 'string' ? field.value : '',
      confidence: typeof field.confidence === 'number' ? field.confidence : 1,
      notes: typeof field.notes === 'string' ? field.notes : undefined,
    };
  });
  const inferredSize = fields.reduce((max, field) => Math.max(max, field.offset + field.size), 0);
  const totalSize =
    typeof source.totalSize === 'number'
      ? source.totalSize
      : typeof source.size === 'number'
        ? source.size
        : inferredSize;

  return {
    baseAddress: typeof source.baseAddress === 'string' ? source.baseAddress : '0x0',
    totalSize,
    fields,
    vtableAddress: typeof source.vtableAddress === 'string' ? source.vtableAddress : undefined,
    className: typeof source.className === 'string' ? source.className : undefined,
    baseClasses: Array.isArray(source.baseClasses)
      ? source.baseClasses.filter((entry): entry is string => typeof entry === 'string')
      : undefined,
    timestamp: typeof source.timestamp === 'number' ? source.timestamp : Date.now(),
  };
}

export class StructureHandlers {
  constructor(
    private readonly structAnalyzer: StructureAnalyzer,
    private readonly processManager?: UnifiedProcessManager,
    private readonly ctx?: MCPServerContext,
  ) {}

  private async resolvePid(value: unknown): Promise<number> {
    if (!this.processManager) {
      return value as number;
    }
    return await resolveMemoryDomainPid(value, this.processManager, this.ctx);
  }

  async handleStructureAnalyze(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const result = await this.structAnalyzer.analyzeStructure(pid, args.address as string, {
        size: args.size as number | undefined,
        otherInstances: args.otherInstances as string[] | undefined,
        parseRtti: args.parseRtti as boolean | undefined,
      });
      return {
        ...result,
        hint: result.className
          ? `Detected class: ${result.className}` +
            `${result.baseClasses?.length ? ` (inherits: ${result.baseClasses.join(' → ')})` : ''}`
          : `Inferred ${result.fields.length} fields. Use memory_structure_export_c to export as C struct.`,
      };
    });
  }

  async handleVtableParse(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      return { ...(await this.structAnalyzer.parseVtable(pid, args.vtableAddress as string)) };
    });
  }

  async handleStructureExportC(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const parsed = JSON.parse(args.structure as string);
      const structure = normalizeStructureForExport(parsed);
      return { ...this.structAnalyzer.exportToCStruct(structure, args.name as string | undefined) };
    });
  }

  async handleStructureCompare(args: Record<string, unknown>) {
    return handleSafe(async () => {
      const pid = await this.resolvePid(args.pid);
      const result = await this.structAnalyzer.compareInstances(
        pid,
        args.address1 as string,
        args.address2 as string,
        args.size as number | undefined,
      );
      return {
        matchingFieldCount: result.matching.length,
        differingFieldCount: result.differing.length,
        ...result,
      };
    });
  }
}
