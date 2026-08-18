# Final Report: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Purpose: A decoy MCP server that appears to expose useful tools, logs everything a client does, and never performs any real action. Intended for observing how LLM agents and automated scanners interact with untrusted MCP servers.

Scope for v1: Single file, stdlib plus at most one small dependency. No database, no web UI, no alerting. Getting complete, well-structured logs is the only goal.

Protocol surface: Serve MCP over streamable HTTP on a configurable host/port (default 127.0.0.1:8000). Handle enough JSON-RPC 2.0 to keep a real client talking: initialize (return protocolVersion, serverInfo, capabilities [tools only]), notifications/initialized, tools/list (return the fake tool catalog), tools/call (return canned fake results), ping. Any unknown method returns a well-formed JSON-RPC error rather than crashing or closing the connection. Malformed JSON gets a -32700 parse error and is still logged.

Fake tool catalog: Four tools with realistic names, descriptions, and JSON Schemas -- plausible enough that an agent would try them, e.g. a file reader, a database query runner, a credential/secret lookup, and an outbound email sender. Each returns static or templated fake data. Nothing touches the filesystem, network, shell, or any real service.

Logging: Append one JSON object per line to a JSONL file (default ./honeypot.jsonl): ISO 8601 UTC timestamp; source IP and port; request HTTP headers (at minimum User-Agent); session identifier, if the client provides one; the raw request body as received; the parsed method name, and for tools/call the tool name and full arguments; the response the honeypot returned. Log before responding so nothing is lost if a handler raises. Also mirror a one-line human-readable summary to stderr.

Safety rules (non-negotiable): Never eval, exec, subprocess, or import anything derived from client input. Never make outbound network requests. Never read or write files outside the log path. Log file is append-only; treat every logged value as untrusted text.

Deliverables: The honeypot source file. A one-paragraph README: how to run it, where logs go, how to point an MCP client at it for testing.

**Branch:** `goal/mcp-honeypot`
**Status:** completed

## Summary

Built `mcp_honeypot.py`, a single-file, stdlib-only Python MCP honeypot server. It serves MCP over a single `POST /mcp` streamable-HTTP endpoint (plain JSON request/response, no SSE), handling `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call` over JSON-RPC 2.0, with well-formed JSON-RPC errors (-32700/-32600/-32601/-32602/-32603) for every malformed or unrecognized input rather than crashing. It exposes four fake tools — `read_file`, `query_database`, `get_credential`, `send_email` — each a pure, argument-echoing function with zero real filesystem, network, or shell access, validated against realistic JSON Schemas (including a bool-vs-integer type-confusion fix). Every request is logged as one JSON object per line to `honeypot.jsonl` (default), including HTTP-level rejections (404/405/411/413/400) and stdlib-level rejections (malformed/oversized request lines, blank leading lines, connection stalls) that a normal server would otherwise drop silently — precisely the scanner/probe traffic a honeypot most wants to capture. Logging happens before the response is sent, and a sanitized one-line summary is mirrored to stderr. Resource-exhaustion guardrails (connection cap, per-read socket timeout, body-size cap, session-store cap, bounded blank-line tolerance) protect the server itself from being used as a foothold. `README.md` documents how to run it, where logs go, how to point an MCP client at it, and explicit operator caveats around exposure risk and unbounded log growth.

The plan-review loop took 4 rounds to converge, driven mostly by security review finding progressively subtler gaps in "log everything" (HTTP-level rejections, then stdlib-level rejections, then a blank-request-line edge case that bypassed even the stdlib-rejection hook) — each was closed with a corresponding code-level fix rather than a documentation caveat. The code-review loop caught one more real issue after all four build tasks were otherwise approved: the stdlib's own default `log_message` was writing a second, unsanitized/uncapped line to stderr on every request, undermining the project's core "sanitized logs only" invariant; this was found and fixed in task 4's round 2. QA (57 tests, stdlib `unittest`) passed on the first run.

## Plan Review

- Rounds run: 4
- Final verdict: approved (both loop-plan-reviewer and loop-security APPROVED at round 4)

Round-by-round: round 1 — both CHANGES REQUESTED (thread/session exhaustion, exception-handling gaps, HTTP-rejection logging gap, session-id plumbing, missing -32602 coverage, non-dict JSON crash risk). Round 2 — security APPROVED, plan-quality CHANGES REQUESTED (incomplete "two named exceptions" claim re: stdlib-level HTTP rejections, bool/int validation gap, chunked/duplicate-header conflation). Round 3 — security APPROVED, plan-quality CHANGES REQUESTED (blank-request-line bypass of the round-2 fix, found via live CPython behavior testing). Round 4 — both APPROVED.

## Tasks

| # | Title | Status | Review Rounds |
|---|---|---|---|
| 1 | HTTP server, universal request lifecycle (including stdlib-rejection logging), and logging core | done | 1 (both approved) |
| 2 | Session-aware JSON-RPC dispatch: initialize, notifications/initialized, ping, and the -32600/-32602/-32603 error paths | done | 1 (both approved) |
| 3 | Fake tool catalog + tools/list + tools/call + -32602 argument validation | done | 1 (both approved) |
| 4 | CLI finishing touches, safety self-check, and README | done | 2 (round 1: code approved, security changes requested; round 2: both approved) |

## Security Findings

### Plan phase

- Round 1 (CHANGES REQUESTED, 3 major + 2 minor): no connection/read timeout or concurrent-connection cap (slowloris risk); unbounded in-memory SESSIONS dict; the required catch-all exception handler only wrapped `dispatch()`, not the earlier body-read/JSON-parse steps; unbounded JSONL disk growth undocumented; implicit reliance on stdlib header limits undocumented. All resolved in the round-1 design revision (socket timeout + BoundedSemaphore connection cap, capped/evicting SESSIONS OrderedDict, outer try/except around the full request lifecycle).
- Round 2 (APPROVED): all round-1 fixes verified genuinely resolved against the actual design mechanics, not just claimed.
- Round 3 (APPROVED, 3 minor notes): verified the round-2 `log_error()` stdlib-rejection interception didn't introduce a new log-flooding vector, and that `_emergency_fallback` correctly reuses the same lock-guarded log writer.
- Round 4 (APPROVED): verified the round-3 `handle_one_request()` blank-line-skip override doesn't enable request smuggling, doesn't bypass the connection cap or socket timeout, and correctly bounds the skip loop.

### Code phase

- Tasks 1-3: each approved on round 1, with only minor/non-blocking notes (e.g. `raw.isdigit()` accepting non-ASCII Unicode digits, framing-rejection branches not draining pending body bytes, `json.dumps` permitting non-standard NaN/Infinity tokens — all logged as minor, none blocking).
- Task 4, round 1 (CHANGES REQUESTED, 1 major): `BaseHTTPRequestHandler`'s default `log_message()` — reached via both `log_request()` on normal completions and the project's own `log_error()` override on stdlib rejections — wrote a second, unsanitized/uncapped line straight to stderr, bypassing `sanitize_for_stderr` entirely and contradicting the module's own stated invariant. Verified empirically with an ANSI-escape-sequence injection test.
- Task 4, round 2 (APPROVED): fixed with a no-op `log_message` override; independently re-verified via a fresh injection test that stderr now contains only sanitized, capped output on every code path.

No blocking or major findings remained unresolved at the end of either the plan-review or code-review loops.

## QA

- Rounds run: 1
- Final verdict: passed (57/57 tests)

Coverage: JSON-RPC envelope handling and all documented error codes; the full fake tool catalog including the bool/int schema-validation edge case; universal logging across every documented HTTP/JSON-RPC outcome (200/202/404/405/411/413/400) plus stdlib-rejection cases (blank leading lines, malformed/oversized request lines, pre-request-line stalls); the connection-cap semaphore and session-cap eviction; log-write concurrency integrity under 40 simultaneous requests; and runtime (not just source-grep) verification of the safety invariants via monkeypatched `open`/`socket.socket` during tool-handler execution.

## Documentation Updated

- `README.md`: added a "Running it" section (how to run, where logs go, how to point an MCP client at it, operator caveats around exposure risk/resource limits/unbounded log growth/framing rejections/the three narrow structurally-unlogged cases) during task 4, plus a "Testing" section during the docs phase pointing at `test_mcp_honeypot.py`. The original one-line project description was preserved, not replaced.
- `mcp_honeypot.py`: module docstring states the four non-negotiable safety invariants (verified adequate during the docs phase, no changes needed).

## Unresolved Items

None. Plan review converged at round 4 of 5; every task's code review converged at or before round 2 of 5; QA passed on round 1 of 5.

## Next Steps

- Review the diff on `goal/mcp-honeypot` (11 commits since branching off `main`) and merge/open a PR when satisfied — nothing has been pushed or merged automatically.
- Consider whether to expose the server beyond `127.0.0.1` for real decoy use; the README's operator caveats cover what that entails (unbounded log growth including rejected/scanner traffic, fixed non-CLI-tunable resource limits, three narrow cases that remain unlogged).
- `honeypot.jsonl` has no rotation/retention in v1 — an operator running this for real should plan log rotation externally before extended exposure.
