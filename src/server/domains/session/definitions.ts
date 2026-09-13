/**
 * Session domain tool definitions — session-scoped reverse-engineering
 * progress tracking (evidence coverage ledger).
 *
 * These tools give an agent a server-side, verifiable record of what has
 * already been covered during a reverse-engineering engagement (hooked
 * processes, hook points, protocol fields) so coverage gaps can be queried
 * instead of reconstructed from the client-side conversation.
 */
import type { Tool } from '@modelcontextprotocol/server';
import { tool } from '@server/registry/tool-builder';

const PROGRESS_KINDS = ['process', 'hook-point', 'protocol-field'] as const;

const KIND_DESCRIPTION =
  'Evidence category: `process` (a target process/binary), `hook-point` (a specific function/address hook location), `protocol-field` (a decoded protocol message field)';

const SESSION_ID_DESCRIPTION =
  "Logical engagement bucket for this progress entry. Defaults to `'default'` when omitted; " +
  'use one sessionId per reverse-engineering target to keep coverage ledgers isolated';

const SESSION_NOTE =
  'State is per-server in-memory only (tied to the MCP server process lifetime): ' +
  'it is NOT persisted and is lost when the server restarts.';

export const sessionToolDefinitions: Tool[] = [
  tool('session_progress_record', (t) =>
    t
      .desc(
        'Record a piece of reverse-engineering progress evidence for the current session ' +
          '(a hooked process, a hook point, or a decoded protocol field). Recording the same ' +
          '(kind, key) pair again is idempotent: it updates `metadata` in place without ' +
          'creating a duplicate entry. Use session_progress_coverage to audit what has been ' +
          `recorded and find coverage gaps. ${SESSION_NOTE} Each (sessionId, kind) bucket holds ` +
          'at most 500 entries; a record that would exceed the cap is rejected.',
      )
      .enum('kind', PROGRESS_KINDS, KIND_DESCRIPTION)
      .string(
        'key',
        'Stable identifier of the evidence item, e.g. `pid:4210`, `libfoo.so!0x12345`, or `TLS.handshake.client_random`',
        { pattern: '.+' },
      )
      .string('sessionId', SESSION_ID_DESCRIPTION)
      .prop('metadata', {
        type: 'object',
        description:
          'Optional structured details for this entry (e.g. { module, offset, notes }); ' +
          'replaced wholesale when the same (kind, key) is re-recorded',
        additionalProperties: true,
      })
      .required('kind', 'key')
      .idempotent(),
  ),
  tool('session_progress_coverage', (t) =>
    t
      .desc(
        'Query the session progress ledger: per-kind entry counts plus the matching entries ' +
          'sorted newest-first (by first-recorded time). Use it to audit reverse-engineering ' +
          'coverage and surface uncovered areas. Pass `kind` to inspect a single evidence ' +
          `category. ${SESSION_NOTE}`,
      )
      .string('sessionId', SESSION_ID_DESCRIPTION)
      .enum('kind', PROGRESS_KINDS, 'Restrict returned entries to this evidence category')
      .query(),
  ),
  tool('session_progress_clear', (t) =>
    t
      .desc(
        'Clear session progress entries. With no `kind`, the entire session bucket is reset ' +
          'to an empty ledger; with `kind`, only that evidence category is cleared. Returns ' +
          'the number of removed entries. ' +
          `${SESSION_NOTE}`,
      )
      .string('sessionId', SESSION_ID_DESCRIPTION)
      .enum('kind', PROGRESS_KINDS, 'Restrict the clear to this evidence category')
      .resettable(),
  ),
];
