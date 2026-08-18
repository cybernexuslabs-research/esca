# Tasks: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Derived from `design.md` § Task Breakdown. Status is the source of truth in `state.json`; this file is the human-readable mirror — the orchestrator keeps both in sync.

- [x] 1. HTTP server, universal request lifecycle (including stdlib-rejection logging), and logging core
- [x] 2. Session-aware JSON-RPC dispatch: initialize, notifications/initialized, ping, and the -32600/-32602/-32603 error paths
- [x] 3. Fake tool catalog + tools/list + tools/call + -32602 argument validation
- [x] 4. CLI finishing touches, safety self-check, and README
