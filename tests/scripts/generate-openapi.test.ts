import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

interface JsonSchema {
  type?: string;
  properties?: Record<string, unknown>;
  required?: string[];
  [key: string]: unknown;
}

interface CatalogEntry {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  annotations?: Record<string, unknown> | null;
  domain: string;
  profiles?: string[] | null;
}

interface MetaTool {
  name: string;
  description: string;
  inputSchema: JsonSchema;
}

interface PostOperation {
  operationId: string;
  summary: string;
  description: string;
  tags: string[];
  'x-domain'?: string;
  'x-profiles'?: string[];
  requestBody: {
    required: boolean;
    content: Record<string, { schema: { $ref: string } }>;
  };
  responses: Record<string, unknown>;
}

interface OpenApiDocument {
  openapi: string;
  info: { title: string; version: string; description: string };
  servers: Array<{ url: string; description: string; variables?: Record<string, unknown> }>;
  tags: Array<{ name: string; description?: string }>;
  paths: Record<string, { post: PostOperation }>;
  components: { schemas: Record<string, JsonSchema> };
}

interface OpenApiLib {
  OPENAPI_SPEC_VERSION: string;
  META_DOMAIN: string;
  sanitizeSchemaKeyPart(value: string): string;
  collectSchemaKeys(entries: Array<{ name: string; domain: string }>): Map<string, string>;
  buildToolSummary(description: string | undefined): string;
  normalizeInputSchema(schema: JsonSchema | null): JsonSchema;
  buildOpenApiDocument(input: {
    name: string;
    version: string;
    description: string;
    catalogEntries: CatalogEntry[];
    metaTools: MetaTool[];
  }): OpenApiDocument;
  sortDeep(value: unknown): unknown;
  serializeDocument(document: OpenApiDocument): string;
  findFirstDifference(actual: unknown, expected: unknown, path?: string): string | null;
}

// scripts/ sits outside the tsc include set (allowJs: false), so load the plain
// .mjs lib through require (same approach as tests/scripts/postinstall.test.ts).
const require = createRequire(import.meta.url);
const lib = require(
  join(resolve(dirname(fileURLToPath(import.meta.url)), '../..'), 'scripts/lib/openapi-lib.mjs'),
) as OpenApiLib;

const CATALOG_ENTRY_A: CatalogEntry = {
  name: 'sample_analyze',
  description: 'Analyze a sample. Returns a report.',
  inputSchema: {
    type: 'object',
    properties: { target: { type: 'string', description: 'Target id' } },
    required: ['target'],
  },
  domain: 'sample-domain',
};

const CATALOG_ENTRY_B: CatalogEntry = {
  name: 'sample_pull',
  description: 'Pull a sample to disk',
  inputSchema: {
    type: 'object',
    properties: { outputPath: { type: 'string' } },
  },
  domain: 'sample-domain',
  profiles: ['search', 'full'],
};

const META_TOOL_A: MetaTool = {
  name: 'search_tools',
  description: 'Search tools across domains.',
  inputSchema: {
    type: 'object',
    properties: { query: { type: 'string' } },
    required: ['query'],
  },
};

function buildTestDocument(): OpenApiDocument {
  return lib.buildOpenApiDocument({
    name: '@jshookmcp/jshook',
    version: '0.0.0-test',
    description: 'Test server description',
    catalogEntries: [CATALOG_ENTRY_A, CATALOG_ENTRY_B],
    metaTools: [META_TOOL_A],
  });
}

function postOf(document: OpenApiDocument, path: string): PostOperation {
  const pathItem = document.paths[path];
  if (!pathItem) {
    throw new Error(`expected path ${path} to exist`);
  }
  return pathItem.post;
}

describe('sanitizeSchemaKeyPart', () => {
  it('replaces non-alphanumeric runs with underscores', () => {
    expect(lib.sanitizeSchemaKeyPart('adb-bridge')).toBe('adb_bridge');
    expect(lib.sanitizeSchemaKeyPart('a b--c')).toBe('a_b_c');
  });
});

describe('collectSchemaKeys', () => {
  it('builds <domain>_<tool> keys', () => {
    const keys = lib.collectSchemaKeys([
      { name: 'sample_analyze', domain: 'sample-domain' },
      { name: 'search_tools', domain: lib.META_DOMAIN },
    ]);
    expect(keys.get('sample_analyze')).toBe('sample_domain_sample_analyze');
    expect(keys.get('search_tools')).toBe('meta_search_tools');
  });

  it('suffixes collisions to keep keys unique', () => {
    // Distinct tool names whose sanitized forms collide ('dup.tool' vs 'dup_tool').
    const keys = lib.collectSchemaKeys([
      { name: 'dup.tool', domain: 'domain-a' },
      { name: 'dup_tool', domain: 'domain.a' },
    ]);
    const values = [...keys.values()];
    expect(new Set(values).size).toBe(values.length);
    expect(values[0]).toBe('domain_a_dup_tool');
    expect(values[1]).toBe('domain_a_dup_tool_2');
  });
});

describe('buildToolSummary', () => {
  it('takes the first sentence of the first line', () => {
    expect(lib.buildToolSummary('Analyze a sample. Returns a report.\nMore details')).toBe(
      'Analyze a sample.',
    );
  });

  it('truncates long summaries with an ellipsis', () => {
    const summary = lib.buildToolSummary('x'.repeat(200));
    expect(summary.length).toBe(120);
    expect(summary.endsWith('...')).toBe(true);
  });

  it('falls back for empty descriptions', () => {
    expect(lib.buildToolSummary('')).toBe('Invoke the tool.');
    expect(lib.buildToolSummary(undefined)).toBe('Invoke the tool.');
  });
});

describe('normalizeInputSchema', () => {
  it('defaults missing or invalid schemas to an object schema', () => {
    expect(lib.normalizeInputSchema(null)).toEqual({ type: 'object', properties: {} });
    expect(lib.normalizeInputSchema({ properties: { a: { type: 'string' } } })).toEqual({
      type: 'object',
      properties: { a: { type: 'string' } },
    });
  });

  it('preserves a declared type and does not mutate the input', () => {
    const schema: JsonSchema = { type: 'object', properties: {}, required: [] };
    const normalized = lib.normalizeInputSchema(schema);
    expect(normalized.type).toBe('object');
    expect(normalized).not.toBe(schema);
    expect(schema).toEqual({ type: 'object', properties: {}, required: [] });
  });
});

describe('buildOpenApiDocument', () => {
  const document = buildTestDocument();

  it('uses OpenAPI 3.1 with package info and transport servers', () => {
    expect(document.openapi).toBe('3.1.0');
    expect(document.info).toEqual({
      title: '@jshookmcp/jshook',
      version: '0.0.0-test',
      description: 'Test server description',
    });
    expect(document.servers).toHaveLength(2);
    expect(document.servers[0]?.url).toBe('stdio://jshookmcp');
    expect(document.servers[1]?.url).toBe('http://127.0.0.1:{port}/mcp');
    expect(document.servers[1]?.variables).toMatchObject({ port: { default: '3000' } });
  });

  it('emits one POST path per catalog tool with x-domain and conditional x-profiles', () => {
    const analyze = postOf(document, '/sample-domain/sample_analyze');
    expect(analyze.operationId).toBe('sample_analyze');
    expect(analyze.tags).toEqual(['sample-domain']);
    expect(analyze['x-domain']).toBe('sample-domain');
    expect(analyze['x-profiles']).toBeUndefined();
    expect(analyze.requestBody).toEqual({
      required: true,
      content: {
        'application/json': {
          schema: { $ref: '#/components/schemas/sample_domain_sample_analyze' },
        },
      },
    });
    expect(analyze.responses['200']).toMatchObject({
      content: { 'text/plain': { schema: { type: 'string' } } },
    });

    const pull = postOf(document, '/sample-domain/sample_pull');
    expect(pull['x-profiles']).toEqual(['search', 'full']);
  });

  it('places meta tools under /meta/{tool} with their own schemas', () => {
    const meta = postOf(document, '/meta/search_tools');
    expect(meta.operationId).toBe('search_tools');
    expect(meta.tags).toEqual([lib.META_DOMAIN]);
    expect(meta['x-domain']).toBeUndefined();
    expect(meta.requestBody).toEqual({
      required: true,
      content: {
        'application/json': { schema: { $ref: '#/components/schemas/meta_search_tools' } },
      },
    });
    expect(document.components.schemas.meta_search_tools).toBeDefined();
  });

  it('references every path to an existing component schema', () => {
    for (const [path, pathItem] of Object.entries(document.paths)) {
      const jsonContent = pathItem.post.requestBody.content['application/json'];
      if (!jsonContent) {
        throw new Error(`expected application/json requestBody for path ${path}`);
      }
      const schemaKey = jsonContent.schema.$ref.replace('#/components/schemas/', '');
      expect(document.components.schemas[schemaKey], `path ${path}`).toBeDefined();
    }
  });

  it('lists domain tags plus the meta tag', () => {
    expect(document.tags.map((tag) => tag.name)).toEqual(['sample-domain', lib.META_DOMAIN]);
  });
});

describe('serializeDocument determinism', () => {
  it('is byte-stable regardless of input order', () => {
    const first = lib.serializeDocument(buildTestDocument());
    const reordered = lib.buildOpenApiDocument({
      name: '@jshookmcp/jshook',
      version: '0.0.0-test',
      description: 'Test server description',
      catalogEntries: [CATALOG_ENTRY_B, CATALOG_ENTRY_A],
      metaTools: [META_TOOL_A],
    });
    expect(lib.serializeDocument(reordered)).toBe(first);
  });

  it('sorts object keys deeply but keeps array order', () => {
    const sorted = lib.sortDeep({ b: 1, a: { y: 1, x: [3, 1, 2] } }) as {
      a: { x: number[]; y: number };
      b: number;
    };
    expect(Object.keys(sorted)).toEqual(['a', 'b']);
    expect(Object.keys(sorted.a)).toEqual(['x', 'y']);
    expect(sorted.a.x).toEqual([3, 1, 2]);
  });
});

describe('--check drift detection', () => {
  const baseline = lib.serializeDocument(buildTestDocument());

  function serializeWithCatalogEntry(entry: CatalogEntry): string {
    return lib.serializeDocument(
      lib.buildOpenApiDocument({
        name: '@jshookmcp/jshook',
        version: '0.0.0-test',
        description: 'Test server description',
        catalogEntries: [entry, CATALOG_ENTRY_B],
        metaTools: [META_TOOL_A],
      }),
    );
  }

  it('detects a tampered tool description and reports the drift path', () => {
    const tampered = serializeWithCatalogEntry({
      ...structuredClone(CATALOG_ENTRY_A),
      description: 'Drifted description.',
    });
    expect(tampered).not.toBe(baseline);
    const difference = lib.findFirstDifference(JSON.parse(tampered), JSON.parse(baseline));
    expect(difference).toBe('$.paths["/sample-domain/sample_analyze"].post.description');
  });

  it('detects a tampered input schema property', () => {
    const entry = structuredClone(CATALOG_ENTRY_A);
    const targetProperty = entry.inputSchema.properties?.target as Record<string, unknown>;
    targetProperty.description = 'Changed parameter description';
    const tampered = serializeWithCatalogEntry(entry);
    expect(tampered).not.toBe(baseline);
    const difference = lib.findFirstDifference(JSON.parse(tampered), JSON.parse(baseline));
    expect(difference).toBe(
      '$.components.schemas.sample_domain_sample_analyze.properties.target.description',
    );
  });

  it('detects a removed tool as a missing schema component', () => {
    const withoutTool = lib.serializeDocument(
      lib.buildOpenApiDocument({
        name: '@jshookmcp/jshook',
        version: '0.0.0-test',
        description: 'Test server description',
        catalogEntries: [CATALOG_ENTRY_B],
        metaTools: [META_TOOL_A],
      }),
    );
    expect(withoutTool).not.toBe(baseline);
    const difference = lib.findFirstDifference(JSON.parse(withoutTool), JSON.parse(baseline));
    // `components` sorts before `paths`, so the missing schema is reported first.
    expect(difference).toBe('$.components.schemas.sample_domain_sample_analyze');
  });

  it('reports no difference for identical documents', () => {
    expect(lib.findFirstDifference(JSON.parse(baseline), JSON.parse(baseline))).toBeNull();
  });
});
