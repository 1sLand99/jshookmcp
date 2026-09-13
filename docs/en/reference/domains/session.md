# Session Progress

Domain: `session`

Session-scoped reverse-engineering coverage ledger: record hooked processes, hook points, and decoded protocol fields, then audit coverage and surface gaps. In-memory, server-lifetime state.

## Profiles

- workflow
- full

## Typical scenarios

- Record progress evidence
- Audit coverage and surface gaps
- Switch or reset session ledgers

## Common combinations

- session + coordination
- session + instrumentation
- session + protocol-analysis

## Full tool list (3)

| Tool | Description |
| --- | --- |
| `session_progress_record` | Record a piece of reverse-engineering progress evidence for the current session (a hooked process, a hook point, or a decoded protocol field). Recording the same (kind, key) pair again is idempotent: it updates `metadata` in place without creating a duplicate entry. Use session_progress_coverage to audit what has been recorded and find coverage gaps. State is per-server in-memory only (tied to the MCP server process lifetime): it is NOT persisted and is lost when the server restarts. Each (sessionId, kind) bucket holds at most 500 entries; a record that would exceed the cap is rejected. |
| `session_progress_coverage` | Query the session progress ledger: per-kind entry counts plus the matching entries sorted newest-first (by first-recorded time). Use it to audit reverse-engineering coverage and surface uncovered areas. Pass `kind` to inspect a single evidence category. State is per-server in-memory only (tied to the MCP server process lifetime): it is NOT persisted and is lost when the server restarts. |
| `session_progress_clear` | Clear session progress entries. With no `kind`, the entire session bucket is reset to an empty ledger; with `kind`, only that evidence category is cleared. Returns the number of removed entries. State is per-server in-memory only (tied to the MCP server process lifetime): it is NOT persisted and is lost when the server restarts. |
