import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { DataFlow } from '@internal-types/index';

import { logger } from '@utils/logger';
import { checkSanitizer } from '@modules/analyzer/SecurityCodeAnalyzer';
import {
  buildFunctionSummaries,
  calleeName,
  identifySource,
  type SourceInfo,
} from '@modules/analyzer/CodeAnalyzerDataFlow.summaries';

type SinkType = DataFlow['sinks'][number]['type'];

interface SinkSite {
  args: Array<t.Expression | t.SpreadElement | t.ArgumentPlaceholder>;
  sinkType: SinkType;
  line: number;
}

function normalizeSourceType(sourceType: string): DataFlow['sources'][number]['type'] {
  if (
    sourceType === 'user_input' ||
    sourceType === 'storage' ||
    sourceType === 'network' ||
    sourceType === 'other'
  ) {
    return sourceType;
  }
  // Legacy first-pass marker ('url') and anything unexpected map to safe defaults.
  return sourceType === 'url' ? 'user_input' : 'other';
}

export async function analyzeDataFlowWithTaint(code: string): Promise<DataFlow> {
  const graph: DataFlow['graph'] = { nodes: [], edges: [] };
  const sources: DataFlow['sources'] = [];
  const sinks: DataFlow['sinks'] = [];
  const taintPaths: DataFlow['taintPaths'] = [];

  const taintMap = new Map<string, { sourceType: string; sourceLine: number }>();

  const sinkSites: SinkSite[] = [];

  const sanitizers = new Set([
    'encodeURIComponent',
    'encodeURI',
    'escape',
    'decodeURIComponent',
    'decodeURI',
    'htmlentities',
    'htmlspecialchars',
    'escapeHtml',
    'escapeHTML',
    'he.encode',
    'he.escape',
    'validator.escape',
    'validator.unescape',
    'validator.stripLow',
    'validator.blacklist',
    'validator.whitelist',
    'validator.trim',
    'validator.isEmail',
    'validator.isURL',
    'validator.isInt',
    'DOMPurify.sanitize',
    'DOMPurify.addHook',
    'crypto.encrypt',
    'crypto.hash',
    'crypto.createHash',
    'crypto.createHmac',
    'CryptoJS.AES.encrypt',
    'CryptoJS.SHA256',
    'CryptoJS.MD5',
    'bcrypt.hash',
    'bcrypt.compare',
    'btoa',
    'atob',
    'Buffer.from',
    'db.prepare',
    'db.query',
    'mysql.escape',
    'pg.query',
    'xss',
    'sanitizeHtml',
    'parseInt',
    'parseFloat',
    'Number',
    'String',
    'JSON.stringify',
    'JSON.parse',
    'String.prototype.replace',
    'String.prototype.trim',
    'Array.prototype.filter',
    'Array.prototype.map',
    // Value-sinking builtins: these return a number/boolean derived from the
    // argument, dropping the taint identity (e.g. `Math.max(tainted, 0)` no
    // longer carries the source). Listing them here keeps the unknown-callee
    // pass-through from over-reporting on pure numeric helpers.
    'Math.max',
    'Math.min',
    'Math.floor',
    'Math.ceil',
    'Math.round',
    'Math.abs',
    'Math.trunc',
    'Math.sign',
    'Math.sqrt',
    'Math.pow',
    'Math.log',
    'Math.exp',
    'Math.random',
    'Math.hypot',
    'Math.fround',
    'Number.prototype.toString',
    'Number.prototype.toFixed',
    'Number.prototype.toPrecision',
  ]);

  try {
    const ast = parser.parse(code, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript'],
    });

    traverse(ast, {
      CallExpression(path) {
        const callee = path.node.callee;
        const line = /* istanbul ignore next */ path.node.loc?.start.line || 0;

        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
          const methodName = callee.property.name;

          if (['fetch', 'ajax', 'get', 'post', 'request', 'axios'].includes(methodName)) {
            const sourceId = `source-network-${line}`;
            sources.push({ type: 'network', location: { file: 'current', line } });
            graph.nodes.push({
              id: sourceId,
              name: `${methodName}()`,
              type: 'source',
              location: { file: 'current', line },
            });

            const parent = path.parent;
            if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) {
              taintMap.set(parent.id.name, { sourceType: 'user_input', sourceLine: line });
            }
          } else if (
            [
              'querySelector',
              'getElementById',
              'getElementsByClassName',
              'getElementsByTagName',
            ].includes(methodName)
          ) {
            const sourceId = `source-dom-${line}`;
            sources.push({ type: 'user_input', location: { file: 'current', line } });
            graph.nodes.push({
              id: sourceId,
              name: `${methodName}()`,
              type: 'source',
              location: { file: 'current', line },
            });
          }
        }

        if (t.isIdentifier(callee)) {
          const funcName = callee.name;

          if (['eval', 'Function', 'setTimeout', 'setInterval'].includes(funcName)) {
            const sinkId = `sink-eval-${line}`;
            sinks.push({ type: 'eval', location: { file: 'current', line } });
            graph.nodes.push({
              id: sinkId,
              name: `${funcName}()`,
              type: 'sink',
              location: { file: 'current', line },
            });

            checkTaintedArguments(path.node.arguments, taintMap, taintPaths, funcName, line);
            sinkSites.push({ args: path.node.arguments, sinkType: 'eval', line });
          }
        }

        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
          const methodName = callee.property.name;

          if (
            ['write', 'writeln'].includes(methodName) &&
            t.isIdentifier(callee.object) &&
            callee.object.name === 'document'
          ) {
            const sinkId = `sink-document-write-${line}`;
            sinks.push({ type: 'xss', location: { file: 'current', line } });
            graph.nodes.push({
              id: sinkId,
              name: `document.${methodName}()`,
              type: 'sink',
              location: { file: 'current', line },
            });
            checkTaintedArguments(path.node.arguments, taintMap, taintPaths, methodName, line);
            sinkSites.push({ args: path.node.arguments, sinkType: 'xss', line });
          }

          if (['query', 'execute', 'exec', 'run'].includes(methodName)) {
            const sinkId = `sink-sql-${line}`;
            sinks.push({ type: 'sql-injection', location: { file: 'current', line } });
            graph.nodes.push({
              id: sinkId,
              name: `${methodName}() (SQL)`,
              type: 'sink',
              location: { file: 'current', line },
            });
            checkTaintedArguments(path.node.arguments, taintMap, taintPaths, methodName, line);
            sinkSites.push({ args: path.node.arguments, sinkType: 'sql-injection', line });
          }

          if (['exec', 'spawn', 'execSync', 'spawnSync'].includes(methodName)) {
            const sinkId = `sink-command-${line}`;
            sinks.push({ type: 'other', location: { file: 'current', line } });
            graph.nodes.push({
              id: sinkId,
              name: `${methodName}() (Command)`,
              type: 'sink',
              location: { file: 'current', line },
            });
            checkTaintedArguments(path.node.arguments, taintMap, taintPaths, methodName, line);
            sinkSites.push({ args: path.node.arguments, sinkType: 'other', line });
          }

          if (
            ['readFile', 'writeFile', 'readFileSync', 'writeFileSync', 'open'].includes(methodName)
          ) {
            const sinkId = `sink-file-${line}`;
            sinks.push({ type: 'other', location: { file: 'current', line } });
            graph.nodes.push({
              id: sinkId,
              name: `${methodName}() (File)`,
              type: 'sink',
              location: { file: 'current', line },
            });
            checkTaintedArguments(path.node.arguments, taintMap, taintPaths, methodName, line);
            sinkSites.push({ args: path.node.arguments, sinkType: 'other', line });
          }
        }
      },

      MemberExpression(path) {
        const obj = path.node.object;
        const prop = path.node.property;
        const line = /* istanbul ignore next */ path.node.loc?.start.line || 0;

        if (t.isIdentifier(obj) && obj.name === 'location' && t.isIdentifier(prop)) {
          if (['href', 'search', 'hash', 'pathname'].includes(prop.name)) {
            const sourceId = `source-url-${line}`;
            sources.push({ type: 'user_input', location: { file: 'current', line } });
            graph.nodes.push({
              id: sourceId,
              name: `location.${prop.name}`,
              type: 'source',
              location: { file: 'current', line },
            });

            const parent = path.parent;
            if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) {
              taintMap.set(parent.id.name, { sourceType: 'user_input', sourceLine: line });
            }
          }
        }

        if (
          t.isIdentifier(obj) &&
          obj.name === 'document' &&
          t.isIdentifier(prop) &&
          prop.name === 'cookie'
        ) {
          const sourceId = `source-cookie-${line}`;
          sources.push({ type: 'storage', location: { file: 'current', line } });
          graph.nodes.push({
            id: sourceId,
            name: 'document.cookie',
            type: 'source',
            location: { file: 'current', line },
          });
        }

        if (t.isIdentifier(obj) && ['localStorage', 'sessionStorage'].includes(obj.name)) {
          const sourceId = `source-storage-${line}`;
          sources.push({ type: 'storage', location: { file: 'current', line } });
          graph.nodes.push({
            id: sourceId,
            name: `${obj.name}.getItem()`,
            type: 'source',
            location: { file: 'current', line },
          });
        }

        if (
          t.isIdentifier(obj) &&
          obj.name === 'window' &&
          t.isIdentifier(prop) &&
          prop.name === 'name'
        ) {
          const sourceId = `source-window-name-${line}`;
          sources.push({ type: 'user_input', location: { file: 'current', line } });
          graph.nodes.push({
            id: sourceId,
            name: 'window.name',
            type: 'source',
            location: { file: 'current', line },
          });
        }

        if (
          t.isIdentifier(obj) &&
          obj.name === 'event' &&
          t.isIdentifier(prop) &&
          prop.name === 'data'
        ) {
          const sourceId = `source-postmessage-${line}`;
          sources.push({ type: 'network', location: { file: 'current', line } });
          graph.nodes.push({
            id: sourceId,
            name: 'event.data (postMessage)',
            type: 'source',
            location: { file: 'current', line },
          });
        }

        if (
          t.isIdentifier(obj) &&
          obj.name === 'message' &&
          t.isIdentifier(prop) &&
          prop.name === 'data'
        ) {
          const sourceId = `source-websocket-${line}`;
          sources.push({ type: 'network', location: { file: 'current', line } });
          graph.nodes.push({
            id: sourceId,
            name: 'WebSocket message.data',
            type: 'source',
            location: { file: 'current', line },
          });
        }
      },

      AssignmentExpression(path) {
        const left = path.node.left;
        const right = path.node.right;
        const line = /* istanbul ignore next */ path.node.loc?.start.line || 0;

        if (t.isMemberExpression(left) && t.isIdentifier(left.property)) {
          const propName = left.property.name;
          if (['innerHTML', 'outerHTML'].includes(propName)) {
            const sinkId = `sink-dom-${line}`;
            sinks.push({ type: 'xss', location: { file: 'current', line } });
            graph.nodes.push({
              id: sinkId,
              name: propName,
              type: 'sink',
              location: { file: 'current', line },
            });

            sinkSites.push({ args: [right], sinkType: 'xss', line });

            if (t.isIdentifier(right) && taintMap.has(right.name)) {
              const taintInfo = taintMap.get(right.name)!;
              taintPaths.push({
                source: {
                  type: taintInfo.sourceType as DataFlow['sources'][0]['type'],
                  location: { file: 'current', line: taintInfo.sourceLine },
                },
                sink: { type: 'xss', location: { file: 'current', line } },
                path: [
                  { file: 'current', line: taintInfo.sourceLine },
                  { file: 'current', line },
                ],
              });
            }
          }
        }
      },
    });

    traverse(ast, {
      VariableDeclarator(path) {
        const id = path.node.id;
        const init = path.node.init;

        if (t.isIdentifier(id) && init) {
          if (t.isCallExpression(init) && checkSanitizer(init, sanitizers)) {
            const arg = init.arguments[0];
            if (t.isIdentifier(arg) && taintMap.has(arg.name)) {
              logger.debug(`Taint cleaned by sanitizer: ${arg.name} -> ${id.name}`);
              return;
            }
          }

          if (t.isIdentifier(init) && taintMap.has(init.name)) {
            const taintInfo = taintMap.get(init.name)!;
            taintMap.set(id.name, taintInfo);
          } else if (t.isBinaryExpression(init)) {
            const leftTainted = t.isIdentifier(init.left) && taintMap.has(init.left.name);
            const rightTainted = t.isIdentifier(init.right) && taintMap.has(init.right.name);

            if (leftTainted || rightTainted) {
              const taintInfo = leftTainted
                ? taintMap.get((init.left as t.Identifier).name)!
                : taintMap.get((init.right as t.Identifier).name)!;
              taintMap.set(id.name, taintInfo);
            }
          }
          // Call-expression propagation is handled by the summary-aware Pass 3
          // below, which distinguishes taint-passing helpers from sanitizers and
          // tracks non-first argument positions.
        }
      },

      AssignmentExpression(path) {
        const left = path.node.left;
        const right = path.node.right;

        if (t.isIdentifier(left) && t.isIdentifier(right) && taintMap.has(right.name)) {
          const taintInfo = taintMap.get(right.name)!;
          taintMap.set(left.name, taintInfo);
        }
      },
    });

    // --- Pass 3: interprocedural + member-chain propagation, then sink re-scan ---
    // Additive only: extends the (flat, module-scoped) taintMap using per-function
    // summaries and member-chain access, then re-checks every recorded sink site
    // against the enriched map. This surfaces taint that flows through helpers and
    // property chains — paths the first two passes emit too late (sinks are scanned
    // before propagation completes) or not at all.
    const summaries = buildFunctionSummaries(ast, sanitizers, checkSanitizer);

    const moduleEval = (node: t.Node | null | undefined): SourceInfo | null => {
      if (!node) {
        return null;
      }
      if (t.isIdentifier(node)) {
        return taintMap.get(node.name) ?? null;
      }
      const source = identifySource(node);
      if (source) {
        return source;
      }
      if (t.isMemberExpression(node)) {
        return moduleEval(node.object);
      }
      if (t.isBinaryExpression(node)) {
        return (t.isExpression(node.left) ? moduleEval(node.left) : null) ?? moduleEval(node.right);
      }
      if (t.isCallExpression(node)) {
        if (checkSanitizer(node, sanitizers)) {
          return null;
        }
        const argInfos = node.arguments.map((arg) =>
          t.isExpression(arg) ? moduleEval(arg) : null,
        );
        const name = calleeName(node);
        if (name && summaries.has(name)) {
          const summary = summaries.get(name)!;
          for (const idx of summary.taintedParamIndices) {
            const argInfo = argInfos[idx];
            if (argInfo) {
              return argInfo;
            }
          }
          return summary.returnsSource;
        }
        // Unknown callee: conservatively pass through taint from any argument so
        // user helpers (`wrap(s)`) still propagate. Pure value-sinking builtins
        // that drop the taint identity (Math.*, parseInt, Number, ...) are listed
        // as sanitizers above and never reach this branch.
        for (const argInfo of argInfos) {
          if (argInfo) {
            return argInfo;
          }
        }
      }
      return null;
    };

    // Monotonic fixpoint over module-scope declarations/assignments (taint only
    // grows). Function bodies are skipped — they are captured by the summaries.
    let propagated = true;
    let guard = 0;
    while (propagated && guard < 100) {
      propagated = false;
      guard += 1;
      traverse(ast, {
        Function(path) {
          path.skip();
        },
        VariableDeclarator(path) {
          const id = path.node.id;
          if (t.isIdentifier(id) && !taintMap.has(id.name) && path.node.init) {
            const info = moduleEval(path.node.init);
            if (info) {
              taintMap.set(id.name, info);
              propagated = true;
            }
          }
        },
        AssignmentExpression(path) {
          const left = path.node.left;
          if (t.isIdentifier(left) && !taintMap.has(left.name)) {
            const info = moduleEval(path.node.right);
            if (info) {
              taintMap.set(left.name, info);
              propagated = true;
            }
          }
        },
      });
    }

    const seenPaths = new Set(
      taintPaths.map((p) => `${p.source.location.line}->${p.sink.location.line}:${p.sink.type}`),
    );
    for (const site of sinkSites) {
      for (const arg of site.args) {
        if (!t.isIdentifier(arg) || !taintMap.has(arg.name)) {
          continue;
        }
        const info = taintMap.get(arg.name)!;
        const key = `${info.sourceLine}->${site.line}:${site.sinkType}`;
        if (seenPaths.has(key)) {
          continue;
        }
        seenPaths.add(key);
        taintPaths.push({
          source: {
            type: normalizeSourceType(info.sourceType),
            location: { file: 'current', line: info.sourceLine },
          },
          sink: { type: site.sinkType, location: { file: 'current', line: site.line } },
          path: [
            { file: 'current', line: info.sourceLine },
            { file: 'current', line: site.line },
          ],
        });
      }
    }
  } catch (error) {
    logger.warn('Data flow analysis failed', error);
  }

  return {
    graph,
    sources,
    sinks,
    taintPaths,
  };
}

function checkTaintedArguments(
  args: Array<t.Expression | t.SpreadElement | t.ArgumentPlaceholder>,
  taintMap: Map<string, { sourceType: string; sourceLine: number }>,
  taintPaths: DataFlow['taintPaths'],
  _funcName: string,
  line: number,
): void {
  args.forEach((arg) => {
    if (t.isIdentifier(arg) && taintMap.has(arg.name)) {
      const taintInfo = taintMap.get(arg.name)!;
      taintPaths.push({
        source: {
          type: taintInfo.sourceType as DataFlow['sources'][0]['type'],
          location: { file: 'current', line: taintInfo.sourceLine },
        },
        sink: {
          type: 'eval',
          location: { file: 'current', line },
        },
        path: [
          { file: 'current', line: taintInfo.sourceLine },
          { file: 'current', line },
        ],
      });
    }
  });
}
