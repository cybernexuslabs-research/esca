# Test Plan: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Purpose: A decoy MCP server that appears to expose useful tools, logs everything a client does, and never performs any real action. Intended for observing how LLM agents and automated scanners interact with untrusted MCP servers.

Scope for v1: Single file, stdlib plus at most one small dependency. No database, no web UI, no alerting. Getting complete, well-structured logs is the only goal.

Protocol surface: Serve MCP over streamable HTTP on a configurable host/port (default 127.0.0.1:8000). Handle enough JSON-RPC 2.0 to keep a real client talking: initialize (return protocolVersion, serverInfo, capabilities [tools only]), notifications/initialized, tools/list (return the fake tool catalog), tools/call (return canned fake results), ping. Any unknown method returns a well-formed JSON-RPC error rather than crashing or closing the connection. Malformed JSON gets a -32700 parse error and is still logged.

Fake tool catalog: Four tools with realistic names, descriptions, and JSON Schemas -- plausible enough that an agent would try them, e.g. a file reader, a database query runner, a credential/secret lookup, and an outbound email sender. Each returns static or templated fake data. Nothing touches the filesystem, network, shell, or any real service.

Logging: Append one JSON object per line to a JSONL file (default ./honeypot.jsonl): ISO 8601 UTC timestamp; source IP and port; request HTTP headers (at minimum User-Agent); session identifier, if the client provides one; the raw request body as received; the parsed method name, and for tools/call the tool name and full arguments; the response the honeypot returned. Log before responding so nothing is lost if a handler raises. Also mirror a one-line human-readable summary to stderr.

Safety rules (non-negotiable): Never eval, exec, subprocess, or import anything derived from client input. Never make outbound network requests. Never read or write files outside the log path. Log file is append-only; treat every logged value as untrusted text.

Deliverables: The honeypot source file. A one-paragraph README: how to run it, where logs go, how to point an MCP client at it for testing.

## Test Strategy

The accumulated acceptance criteria across all 4 tasks in `design.md`'s Task Breakdown are the closest thing to a full behavioral spec, so test cases are derived from those criteria, not from reading `mcp_honeypot.py`'s implementation choices.

Three layers of testing are used, matching the design's own Testability Notes (`design.md` § Testability Notes explicitly calls out `dispatch()`, `validate_arguments`, `_classify_content_length`, `headers_to_dict`, `sanitize_for_stderr`, `build_log_record`/`build_stdlib_rejection_record` as pure functions meant to be exercised directly):

1. **Unit tests (pure functions, no server, no socket)** -- `dispatch()`, `validate_arguments` (including the `[RN2-2]` bool/int exclusion edge case), `_classify_content_length`, `headers_to_dict`, `sanitize_for_stderr`, session-cap eviction. These are fast, deterministic, and isolate protocol/logging logic from I/O exactly along the seam the design says exists (`import mcp_honeypot` has zero side effects; `dispatch(msg, ctx)` takes plain dicts/dataclasses).
2. **Integration / end-to-end tests against a live server** -- a real `HoneypotHTTPServer` + `HoneypotRequestHandler` is started in-process on an OS-assigned free port (against a temp JSONL log file), and driven via `http.client` (well-formed requests) and raw `socket` connections (malformed/adversarial framing that `http.client` itself would refuse to construct, e.g. duplicate headers, blank leading request lines, oversized request lines). This is necessary because several acceptance criteria are specifically about the HTTP/TCP framing layer (`_classify_content_length`'s duplicate-header/chunked branches, the `log_error`/`handle_one_request` stdlib-rejection overrides, the connection-cap semaphore) which cannot be exercised by calling Python functions directly.
3. **Runtime safety-invariant checks** -- rather than trusting a source grep alone, tests monkeypatch `builtins.open` and `socket.socket` to raise during a direct `dispatch()` call for every fake tool, confirming the call path genuinely never touches either, and confirm `read_file` against a real file with known secret content never returns that content and never touches the file (size/mtime/content unchanged, no new files created in the same directory). A source-grep regression test (mirroring the design's own literal Task 3/4 acceptance grep) is included as a backstop, not a replacement.

A subprocess-level smoke test (`python3 mcp_honeypot.py --help`, and one full round-trip against a live subprocess) additionally exercises the CLI/`main()`/`argparse` path, which the in-process server fixture (which calls `HoneypotHTTPServer`/`HoneypotRequestHandler` directly, bypassing `main()`) does not cover.

Concurrency correctness (the `threading.Lock`-guarded JSONL writer) is tested by firing N concurrent POSTs via a thread pool and asserting the resulting log has exactly N well-formed, non-interleaved JSON lines.

## Test Cases

| ID | Description | Type | Expected Result |
|---|---|---|---|
| U1 | `headers_to_dict` merges duplicate header names with `, ` in received order | Unit | Duplicate `X-Foo: a` / `X-Foo: b` merge to `"a, b"`; single headers pass through unchanged |
| U2 | `_classify_content_length` five-way branch coverage (`ok`, `chunked`, `duplicate_transfer_encoding`, `duplicate_content_length`, `missing_or_invalid`) | Unit | Each constructed `email.message.Message` maps to the documented `(outcome, length)` tuple; duplicate detection precedes single-value interpretation for both headers |
| U3 | `_classify_content_length` oversized `Content-Length` (> `MAX_BODY_BYTES`) | Unit | Returns `("missing_or_invalid", None)` |
| U4 | `sanitize_for_stderr` strips control characters/newlines and truncates long input | Unit | No `\x00`-`\x1f`/`\x7f` byte survives; output over `max_len` is truncated with a `...(truncated)` marker |
| U5 | `validate_arguments` bool-exclusion regression `[RN2-2]` | Unit | `{"type": "integer"}` schema + `True`/`False` value raises `InvalidParamsError`; the same schema + literal `0`/`1` does not raise |
| U6 | `validate_arguments` missing required argument | Unit | Raises `InvalidParamsError` |
| U7 | `validate_arguments` wrong type for a non-bool mismatch (e.g. number where string expected) | Unit | Raises `InvalidParamsError` |
| U8 | `dispatch()` unknown method (with `id`) | Unit | Returns `DispatchResult.response` with `error.code == -32601` |
| U9 | `dispatch()` notification (no `id`) still executes and returns `response=None` | Unit | `handle_ping`-style call with no `id` returns `DispatchResult(response=None, ...)` |
| U10 | `dispatch()` `initialize` mints a session id each call and stores it in `SESSIONS` | Unit | Fresh `uuid4().hex`-shaped id every call, distinct across calls |
| U11 | Session-cap eviction `[SEC-2]` | Unit | With `MAX_SESSIONS` monkeypatched small (e.g. 3), 5 `initialize` calls leave `len(SESSIONS) == 3` with the two earliest ids evicted |
| U12 | `build_log_record`/`build_stdlib_rejection_record` shape | Unit | All documented fields present; `tool_name`/`tool_arguments` populated only for `tools/call`; `stdlib_rejection: true` record has `http_status: null` |
| E1 | `initialize` golden path | Integration | HTTP 200, `protocolVersion`/`serverInfo`/`capabilities.tools` present, fresh `Mcp-Session-Id` response header |
| E2 | `notifications/initialized` (no `id`) | Integration | HTTP 202, empty body, one JSONL line with `response: "202 Accepted (notification)"` |
| E3 | `ping` | Integration | HTTP 200, `result: {}` |
| E4 | Unknown method with `id` | Integration | HTTP 200, `-32601` error body, one JSONL line |
| E5 | Non-dict/non-JSON-RPC-shaped top-level JSON (`42`, `[1,2,3]`, `true`, `{"id":1}` w/o method) | Integration | Each returns HTTP 200 + `-32600 Invalid Request`, one JSONL line each, no crash/traceback |
| E6 | Malformed JSON body | Integration | HTTP 200 + `-32700 Parse error`, logged |
| E7 | `GET /mcp` and `DELETE /mcp` | Integration | HTTP 405, empty body, `Allow: POST` header, one JSONL line each (`http_status: 405`, `response: null`) -- regression for `[RN-1]` |
| E8 | Bogus path | Integration | HTTP 404, empty body, one JSONL line |
| E9 | Body larger than `MAX_BODY_BYTES` (oversized `Content-Length` header only, body not actually sent in full) | Integration | HTTP 413, logged with the `"missing, invalid, or oversized Content-Length"` marker, not the raw body |
| E10 | `Transfer-Encoding: chunked` | Integration | HTTP 411 (not 413), logged with its distinct marker -- regression for `[RN2-3]` |
| E11 | Duplicate `Content-Length` headers | Integration | HTTP 400 (not 413), logged with its distinct marker -- regression for `[RN2-4]` |
| E12 | Duplicate `Transfer-Encoding` headers | Integration | HTTP 400 (not 411/200), logged with its distinct marker -- regression for `[RN3-2]` |
| E13 | Log-line-per-request invariant across E1-E12 | Integration | JSONL line count increases by exactly 1 per request, never 0 or 2 |
| E14 | `tools/list` | Integration | Exactly 4 tools, each with non-empty `name`/`description` and a JSON Schema `inputSchema` (`required` + `properties`) |
| E15 | `tools/call` golden path, all 4 tools | Integration | HTTP 200, `result.content[0].text` echoes back a caller-supplied argument, `isError: false` |
| E16 | `tools/call` missing required argument | Integration | HTTP 200 + `-32602`, `tool_name`/`tool_arguments` populated in the log from the request (not the response) |
| E17 | `tools/call` wrong-typed required argument | Integration | HTTP 200 + `-32602` |
| E18 | `tools/call` bool where `integer`/`number` declared, and companion real-integer success `[RN2-2]` | Integration | Bool -> `-32602`; `0`/`1` -> success, end-to-end regression matching U5 |
| E19 | `tools/call` unrecognized tool name | Integration | HTTP 200, `result.isError: true` (not a JSON-RPC error object), connection stays alive |
| R1 | Raw socket: client stalls before sending any request line past the (test-shortened) socket timeout | Integration (raw socket) | Connection closes, one JSONL line with `stdlib_rejection: true` -- regression for `[RN2-1]` |
| R2 | Raw socket: non-HTTP-conforming request line | Integration (raw socket) | One JSONL line with `stdlib_rejection: true` and a `detail` naming the rejection |
| R3 | Raw socket: request line > 65536 bytes | Integration (raw socket) | One JSONL line with `stdlib_rejection: true` (414-equivalent path) |
| R4 | Raw socket: one blank leading request line (`b"\r\n"`) followed by a real, well-formed request on the same connection | Integration (raw socket) | Two JSONL lines: one `stdlib_rejection: true` for the blank line, one normal record for the real request -- regression for `[RN3-1]`, confirms the request is no longer silently dropped |
| R5 | Raw socket: `MAX_LEADING_BLANK_REQUEST_LINES + 1` consecutive blank lines, no real request ever sent | Integration (raw socket) | Exactly `MAX_LEADING_BLANK_REQUEST_LINES` `stdlib_rejection: true` records, then the connection closes with no record for the final, bound-exceeding blank line -- the documented bounded-by-design residual |
| R6 | Monkeypatch `build_stdlib_rejection_record` to raise, then trigger a stdlib-rejection case | Integration | `super().log_error(...)`'s own stderr diagnostic still fires, no unhandled/unsanitized traceback reaches stderr, server keeps serving subsequent requests -- regression for `[SEC3-a]` |
| C1 | Connection-cap semaphore: a connection opened beyond a (small, test-injected) `max_concurrent` limit while others are held open | Integration (raw socket) | The over-cap connection is closed immediately with no response and no log line (structurally-unloggable case, by design); server continues serving ordinary requests afterward |
| N1 | N concurrent POSTs via a thread pool | Integration (concurrency) | Resulting JSONL file has exactly N well-formed, parseable lines -- no interleaved/corrupted lines, confirming the `threading.Lock`-guarded writer |
| S1 | Tool handlers never call `open()` | Runtime safety | `builtins.open` monkeypatched to raise during a direct `dispatch()` call for `tools/call` against each of the 4 tools (including a path-traversal-shaped argument); no exception is raised, all 4 calls succeed normally |
| S2 | Tool handlers never construct a `socket.socket` | Runtime safety | `socket.socket` monkeypatched to raise during a direct `dispatch()` call for a `tools/call`; no exception, call succeeds |
| S3 | `read_file` never reads real file contents or touches the filesystem | Runtime safety | Given a real temp file with known "secret" content, `tools/call` `read_file` against its path returns text that does **not** contain the real content; the file's own content/mtime is unchanged after the call, and no new file appears in its directory |
| S4 | Source-level safety backstop grep (mirrors the design's own literal Task 3/4 acceptance criterion) | Static | `eval\(|exec\(|subprocess|urllib|socket\.socket|importlib` matches nothing in `mcp_honeypot.py`; exactly one `open(` call site exists in the whole file (the log-file open in `main()`) |
| CLI1 | `python3 mcp_honeypot.py --help` | Subprocess | Documents exactly `--host`, `--port`, `--log-file` with their stated defaults |
| CLI2 | Fresh subprocess run + one curl-equivalent round trip + termination | Subprocess | Only `honeypot.jsonl` (already gitignored) is written to disk; no other file appears |
| M1 | `import mcp_honeypot` has zero side effects | Unit | No socket opened, no file created merely by importing the module |

## Coverage Notes

- **Not covered: the two genuinely structurally-unloggable cases** (a connection refused at the `MAX_CONCURRENT_CONNECTIONS`/semaphore cap producing *no* JSONL line at all -- covered positively via C1's "no line" assertion -- and a client that opens a TCP connection and cleanly closes it having sent zero bytes). The zero-byte-clean-close case is explicitly called out in `design.md` as having "genuinely nothing to log even in principle"; a test for it would only assert an absence of a log line after a bare connect+close, which is low-value to automate given the same absence-of-effect is already exercised by C1. Not included as a separate test case.
- **Not covered: exact production-scale `MAX_CONCURRENT_CONNECTIONS` (200) / `MAX_BODY_BYTES` (1 MiB) constants at full scale.** C1 exercises the connection-cap *mechanism* using `HoneypotHTTPServer`'s documented `max_concurrent` constructor parameter set to a small number (the same approach the Testability Notes recommend for `MAX_SESSIONS`), rather than opening 205 real sockets, since the mechanism (semaphore acquire/release, drop-with-no-log) is identical regardless of the numeric cap and testing at full scale would only add runtime, not confidence. E9 similarly tests the oversized-body *rejection path* via the `Content-Length` header alone, without actually transmitting a multi-megabyte body, since the design specifies the check happens before the body is read.
- **Not covered: TLS/auth/rate-limiting.** Explicitly out of scope per `plan.md`.
- **Not covered: real MCP SDK client interop.** The plan treats "a real client or scanner" as satisfied by correct JSON-RPC-over-HTTP behavior; no MCP SDK is a project dependency (by design), so tests drive the wire protocol directly via `http.client`/raw sockets rather than pulling in an SDK as a test-only dependency.
- **Not covered: log rotation/retention.** Explicitly out of scope per `plan.md`/`design.md` ("no rotation ... in v1").
- **Not covered: `emergency_fallback`'s exact double-send/zero-send unit-level regression** (`[RN2-5]`, monkeypatching `_send_response` to raise mid-write) is not implemented as a dedicated test in this round; R6 exercises a closely related fault-injection path (`build_stdlib_rejection_record` raising) end-to-end and is judged sufficient signal for this round. Flagged here as a gap that could be added in a later round if the builder's fix set touches `_emergency_fallback`.
