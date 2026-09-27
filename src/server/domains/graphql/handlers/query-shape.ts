/**
 * GraphQL query shape analyzer — pure structural analysis without executing.
 *
 * Walks a GraphQL operation string (no external parser dependency) to report
 * selection depth, per-level breadth, a heuristic cost score, operation type,
 * and fragment-spread cycle detection. Used to enrich extracted queries with
 * shape signal so analysts can spot deep / wide / cyclic DoS-shaped queries
 * (e.g. `user { friends { friends { friends } } }`) without eyeballing raw text.
 *
 * This is a conservative heuristic, not a spec-complete GraphQL parser:
 * - String literals and `#` comments are stripped so their braces never count.
 * - Argument lists `(...)` and list literals `[...]` are skipped wholesale, so
 *   object-literal input values inside args do not inflate depth.
 * - Fields inside `fragment ... on T { ... }` bodies are tracked for cycle
 *   detection but do NOT inflate the operation's breadth (the operation is the
 *   unit being shaped; fragments are expansion units).
 * - Sibling fields are recognized with or without commas (GraphQL allows both).
 */

export type GraphQLOperationType = 'query' | 'mutation' | 'subscription' | 'unknown';

export interface QueryShape {
  operationType: GraphQLOperationType;
  operationName: string | null;
  /** Max selection-set nesting depth of the operation root (0 = no fields). */
  depth: number;
  /** Field count at each depth level of the operation (index 0 = top-level). */
  breadthByLevel: number[];
  maxBreadth: number;
  totalFields: number;
  /** Heuristic cost: Σ breadth[i] × (i + 1) — depth-weighted field pressure. */
  costScore: number;
  fragments: {
    definitions: number;
    spreads: number;
    inline: number;
  };
  /** True iff any fragment-spread graph contains a cycle. */
  hasCycle: boolean;
}

const TOKEN_RE = /\.\.\.|[{}()[\]:,@!|]|[_A-Za-z][_0-9A-Za-z]*|-?\d+(?:\.\d+)?/g;
const OPERATION_KEYWORDS = new Set(['query', 'mutation', 'subscription']);
const IDENT_RE = /^[_A-Za-z][_0-9A-Za-z]*$/;

/** Tokens whose follower identifier is NOT a field (alias target / type / directive / spread name). */
const NON_FIELD_PRIOR = new Set([':', 'on', '@', '...']);

/**
 * Strip `#` line comments and string/block-string literals, replacing each
 * literal with `""` so braces / hashes inside them never affect tokenization.
 */
function stripLiterals(input: string): string {
  let out = '';
  let i = 0;
  const n = input.length;
  while (i < n) {
    const ch = input[i];
    if (ch === '#') {
      while (i < n && input[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '"') {
      if (input[i + 1] === '"' && input[i + 2] === '"') {
        i += 3;
        while (i < n) {
          if (input[i] === '"' && input[i + 1] === '"' && input[i + 2] === '"') {
            i += 3;
            break;
          }
          i += 1;
        }
        out += '""';
        continue;
      }
      i += 1;
      while (i < n && input[i] !== '"' && input[i] !== '\n') {
        if (input[i] === '\\') i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function tokenize(stripped: string): string[] {
  TOKEN_RE.lastIndex = 0;
  return stripped.match(TOKEN_RE) ?? [];
}

/**
 * DFS cycle detection over the fragment reference graph. Only back edges
 * (a fragment reachable from itself) count — forward/cross edges are legal.
 */
function detectCycle(fragmentRefs: Map<string, string[]>): boolean {
  const visited = new Set<string>();
  const stack = new Set<string>();
  const dfs = (name: string): boolean => {
    if (stack.has(name)) return true;
    if (visited.has(name)) return false;
    visited.add(name);
    stack.add(name);
    const refs = fragmentRefs.get(name);
    if (refs) {
      for (const ref of refs) {
        if (fragmentRefs.has(ref) && dfs(ref)) return true;
      }
    }
    stack.delete(name);
    return false;
  };
  for (const name of fragmentRefs.keys()) {
    if (dfs(name)) return true;
  }
  return false;
}

interface QueryScanState {
  operationType: GraphQLOperationType;
  operationName: string | null;
  depth: number;
  breadthByLevel: number[];
  totalFields: number;
  parenDepth: number;
  bracketDepth: number;
  lastToken: string;
  inFragmentBody: boolean;
  currentFragmentName: string | null;
  fragmentDefinitions: number;
  spreads: number;
  inlineFragments: number;
  fragmentRefs: Map<string, string[]>;
}

function createQueryScanState(): QueryScanState {
  return {
    operationType: 'unknown',
    operationName: null,
    depth: -1,
    breadthByLevel: [],
    totalFields: 0,
    parenDepth: 0,
    bracketDepth: 0,
    lastToken: '',
    inFragmentBody: false,
    currentFragmentName: null,
    fragmentDefinitions: 0,
    spreads: 0,
    inlineFragments: 0,
    fragmentRefs: new Map<string, string[]>(),
  };
}

/** Delimiter tokens adjust depth and never count as fields. Returns true when consumed. */
function consumeDelimiter(state: QueryScanState, token: string): boolean {
  switch (token) {
    case '(':
      state.parenDepth += 1;
      break;
    case ')':
      if (state.parenDepth > 0) state.parenDepth -= 1;
      break;
    case '[':
      state.bracketDepth += 1;
      break;
    case ']':
      if (state.bracketDepth > 0) state.bracketDepth -= 1;
      break;
    case '{':
      state.depth += 1;
      if (state.breadthByLevel[state.depth] === undefined) state.breadthByLevel[state.depth] = 0;
      break;
    case '}':
      if (state.depth === 0 && state.inFragmentBody) {
        state.inFragmentBody = false;
        state.currentFragmentName = null;
      }
      if (state.depth >= 0) state.depth -= 1;
      break;
    case ',':
      break;
    default:
      return false;
  }
  state.lastToken = token;
  return true;
}

/** `...Name` spreads and `... on Type` inline fragments. Returns true when consumed. */
function consumeSpread(state: QueryScanState, tokens: string[], index: number): boolean {
  if (tokens[index] !== '...') return false;
  const next = tokens[index + 1];
  if (next === 'on') {
    state.inlineFragments += 1;
  } else if (next !== undefined && IDENT_RE.test(next) && state.currentFragmentName) {
    state.spreads += 1;
    const refs = state.fragmentRefs.get(state.currentFragmentName) ?? [];
    refs.push(next);
    state.fragmentRefs.set(state.currentFragmentName, refs);
  } else if (next !== undefined && IDENT_RE.test(next)) {
    state.spreads += 1;
  }
  state.lastToken = '...';
  return true;
}

/**
 * Operation keyword and name, plus `fragment Name on Type`. Only the first
 * significant token can open the operation — GraphQL requires it (or the
 * shorthand `{`) at the document start. Returns true when consumed.
 */
function consumeDefinition(state: QueryScanState, tokens: string[], index: number): boolean {
  const token = tokens[index];
  if (token === undefined) return false;

  if (index === 0 && OPERATION_KEYWORDS.has(token)) {
    state.operationType = token as GraphQLOperationType;
    state.lastToken = token;
    return true;
  }

  if (OPERATION_KEYWORDS.has(state.lastToken) && IDENT_RE.test(token)) {
    state.operationName = token;
    state.lastToken = token;
    return true;
  }

  if (token === 'fragment' && state.depth < 0) {
    const next = tokens[index + 1];
    if (next && IDENT_RE.test(next) && next !== 'on') {
      state.currentFragmentName = next;
      state.fragmentDefinitions += 1;
      state.fragmentRefs.set(next, []);
      state.inFragmentBody = true; // armed; the body brace is consumed next
    }
    state.lastToken = 'fragment';
    return true;
  }

  return false;
}

/**
 * A follower identifier inside the operation body is a field unless the prior
 * token marks it as an alias target (`:`), a type name (`on`), or a directive
 * (`@`). Fragment bodies feed cycle detection instead of breadth.
 */
function consumeField(state: QueryScanState, token: string): void {
  if (
    state.depth >= 0 &&
    !state.inFragmentBody &&
    IDENT_RE.test(token) &&
    !NON_FIELD_PRIOR.has(state.lastToken)
  ) {
    if (state.operationType === 'unknown') state.operationType = 'query'; // shorthand `{ ... }`
    state.breadthByLevel[state.depth] = (state.breadthByLevel[state.depth] ?? 0) + 1;
    state.totalFields += 1;
  }
  state.lastToken = token;
}

export function analyzeQueryShape(query: string): QueryShape {
  const stripped = stripLiterals(typeof query === 'string' ? query : '');
  const tokens = tokenize(stripped);
  const state = createQueryScanState();

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (!token) continue;
    if (consumeDelimiter(state, token)) continue;
    if (state.parenDepth > 0 || state.bracketDepth > 0) continue;
    if (consumeSpread(state, tokens, i)) continue;
    if (consumeDefinition(state, tokens, i)) continue;
    if (token === 'on' || token === '@') {
      state.lastToken = token;
      continue;
    }
    consumeField(state, token);
  }

  // Trim trailing zero levels left by deep-but-empty fragment bodies.
  let realDepth = state.breadthByLevel.length;
  while (realDepth > 0 && (state.breadthByLevel[realDepth - 1] ?? 0) === 0) {
    realDepth -= 1;
  }
  const trimmedBreadth = state.breadthByLevel.slice(0, realDepth);
  const maxBreadth = trimmedBreadth.reduce((max, b) => (b > max ? b : max), 0);
  const costScore = trimmedBreadth.reduce((sum, b, level) => sum + b * (level + 1), 0);

  return {
    operationType: state.operationType,
    operationName: state.operationName,
    depth: realDepth,
    breadthByLevel: trimmedBreadth,
    maxBreadth,
    totalFields: state.totalFields,
    costScore,
    fragments: {
      definitions: state.fragmentDefinitions,
      spreads: state.spreads,
      inline: state.inlineFragments,
    },
    hasCycle: detectCycle(state.fragmentRefs),
  };
}
