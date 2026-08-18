# Test Results: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Purpose: A decoy MCP server that appears to expose useful tools, logs everything a client does, and never performs any real action. Intended for observing how LLM agents and automated scanners interact with untrusted MCP servers.

Scope for v1: Single file, stdlib plus at most one small dependency. No database, no web UI, no alerting. Getting complete, well-structured logs is the only goal.

Protocol surface: Serve MCP over streamable HTTP on a configurable host/port (default 127.0.0.1:8000). Handle enough JSON-RPC 2.0 to keep a real client talking: initialize (return protocolVersion, serverInfo, capabilities [tools only]), notifications/initialized, tools/list (return the fake tool catalog), tools/call (return canned fake results), ping. Any unknown method returns a well-formed JSON-RPC error rather than crashing or closing the connection. Malformed JSON gets a -32700 parse error and is still logged.

Fake tool catalog: Four tools with realistic names, descriptions, and JSON Schemas -- plausible enough that an agent would try them, e.g. a file reader, a database query runner, a credential/secret lookup, and an outbound email sender. Each returns static or templated fake data. Nothing touches the filesystem, network, shell, or any real service.

Logging: Append one JSON object per line to a JSONL file (default ./honeypot.jsonl): ISO 8601 UTC timestamp; source IP and port; request HTTP headers (at minimum User-Agent); session identifier, if the client provides one; the raw request body as received; the parsed method name, and for tools/call the tool name and full arguments; the response the honeypot returned. Log before responding so nothing is lost if a handler raises. Also mirror a one-line human-readable summary to stderr.

Safety rules (non-negotiable): Never eval, exec, subprocess, or import anything derived from client input. Never make outbound network requests. Never read or write files outside the log path. Log file is append-only; treat every logged value as untrusted text.

Deliverables: The honeypot source file. A one-paragraph README: how to run it, where logs go, how to point an MCP client at it for testing.

Results from `loop-qa`, appended one `## Round N` section per run.

## Round 1 — loop-qa

**Command run:** `python3 -m unittest test_mcp_honeypot -v` (also verified stable across 3 consecutive full-suite runs; no flakiness observed)

Test code: `/Users/jason/Documents/home/projects/esca/test_mcp_honeypot.py` (57 tests, stdlib `unittest`, no new dependencies). Test plan: `/Users/jason/Documents/home/projects/esca/.loop/mcp-honeypot/qa/test-plan.md`.

| Test | Result | Notes |
|---|---|---|
| U1 `headers_to_dict` duplicate-header comma-join | pass | |
| U2 `_classify_content_length` 5-way branch coverage (ok/chunked/dup-TE/dup-CL/missing-invalid) | pass | includes `[RN2-3]`/`[RN2-4]`/`[RN3-2]` regressions |
| U3 oversized `Content-Length` classification | pass | |
| U4 `sanitize_for_stderr` control-char strip + truncation | pass | |
| U5 `validate_arguments` bool/int exclusion `[RN2-2]` | pass | bool rejected for integer field; real `0`/`1` accepted |
| U6 `validate_arguments` missing required arg | pass | |
| U7 `validate_arguments` wrong type (non-bool) | pass | |
| U8 `dispatch()` unknown method -> -32601 | pass | |
| U9 `dispatch()` notification (no id) -> response=None | pass | |
| U10 `dispatch()` initialize mints fresh session ids | pass | |
| U11 `MAX_SESSIONS` cap + oldest-first eviction `[SEC-2]` | pass | |
| U12 `build_log_record`/`build_stdlib_rejection_record` shape | pass | |
| M1 `import mcp_honeypot` has zero side effects | pass | verified via subprocess in an empty temp dir |
| E1 `initialize` golden path + fresh `Mcp-Session-Id` per call | pass | |
| E2 `notifications/initialized` -> 202, logged | pass | |
| E3 `ping` | pass | |
| E4 unknown method with id -> -32601, logged | pass | |
| E5 non-conforming top-level JSON (`42`,`[1,2,3]`,`true`,`{"id":1}`) -> -32600 x4 | pass | |
| E6 malformed JSON -> -32700, logged | pass | |
| E7 `GET`/`DELETE /mcp` -> 405, `Allow: POST`, logged `[RN-1]` | pass | |
| E8 bogus path -> 404, logged | pass | |
| E9 oversized `Content-Length` -> 413, logged with marker | pass | |
| E10 `Transfer-Encoding: chunked` -> 411 `[RN2-3]` | pass | |
| E11 duplicate `Content-Length` -> 400 `[RN2-4]` | pass | |
| E12 duplicate `Transfer-Encoding` -> 400 `[RN3-2]` | pass | |
| E14 `tools/list` returns 4 well-formed tools | pass | |
| E15 `tools/call` golden path, all 4 tools, argument echoed | pass | |
| E16 `tools/call` missing required arg -> -32602, tool fields logged from request | pass | |
| E17 `tools/call` wrong-typed arg -> -32602 | pass | |
| E18 bool-for-integer rejected, real int accepted `[RN2-2]` end-to-end | pass | |
| E19 unknown tool name -> `isError: true` result, connection stays alive | pass | |
| R1 stall before request line -> `stdlib_rejection: true` `[RN2-1]` | pass | ran with a shortened handler timeout to keep the suite fast |
| R2 malformed request line -> `stdlib_rejection: true` | pass | |
| R3 oversized (>65536B) request line -> `stdlib_rejection: true` | pass | |
| R4 one blank leading line + real request on same connection -> 2 log lines `[RN3-1]` | pass | fixed an off-by-one `Content-Length` bug in the test's own crafted raw bytes during development (see note below); not an implementation defect |
| R5 `MAX_LEADING_BLANK_REQUEST_LINES + 1` consecutive blank lines -> exactly the bound logged | pass | |
| R6 `build_stdlib_rejection_record` monkeypatched to raise -> stdlib diagnostic still fires, server keeps serving `[SEC3-a]` | pass | |
| C1 connection-cap semaphore drops over-cap connection with no response/log | pass | used `HoneypotHTTPServer`'s `max_concurrent` constructor param at a small value (mechanism-level test, not full 200-connection scale, per test-plan Coverage Notes) |
| N1 40 concurrent POSTs -> exactly 40 well-formed, non-interleaved JSONL lines | pass | verifies the `threading.Lock`-guarded writer |
| S1 tool handlers never call `open()` (all 4 tools, path-traversal-shaped arg) | pass | runtime monkeypatch of `builtins.open`, not source-reading |
| S2 tool handlers never construct a `socket.socket` | pass | runtime monkeypatch |
| S3 `read_file` never reads/touches a real file's contents | pass | real temp file with a marker secret string; response never contains the marker; file mtime/content/directory listing unchanged after the call |
| S4 source-grep backstop (design's literal Task 3/4 grep, applied per-line excluding comments/docstring) | pass | see note below re: the literal grep string as written in design.md |
| S4b AST-based backstop (no forbidden imports/`eval`/`exec`/`socket.socket()` calls) | pass | stronger than grep, immune to comment/docstring false positives |
| CLI1 `--help` documents `--host`/`--port`/`--log-file` and defaults | pass | |
| CLI2 fresh subprocess run + one round trip + terminate -> only `honeypot.jsonl` on disk | pass | |

**Summary:** 57 passed, 0 failed, 0 pre-existing failures (no prior test suite existed in this repo before this round).

**Verdict:** PASSED

**Notes for the record (not failures, no code changes made):**

1. **Test-authoring bug found and fixed during development, not a product bug.** An early draft of test R4 (blank-leading-line + real request) crafted a raw HTTP request with `Content-Length: 46` for a JSON body that was actually 45 bytes. This correctly caused `mcp_honeypot.py`'s `_handle_request` to block on `self.rfile.read(46)` waiting for a byte that would never arrive, correctly hit the socket read timeout, and correctly fall through to `_emergency_fallback` (500 response, `internal_fault: true` log record) — i.e. the implementation behaved exactly as designed under a malformed test input. Fixed by computing `Content-Length` from the actual body length in the test. Documented here per the instruction to report anything that looked like a bug even if it turned out not to be one.
2. **`design.md`'s literal Task 3/4 acceptance-criterion grep command does not, as literally written, match nothing against the approved code — but this is a spec/wording nit, not a security defect.** `grep -nE "eval\(|exec\(|subprocess|urllib|socket\.socket|importlib" mcp_honeypot.py` (the exact command given in design.md's Task 3 and Task 4 acceptance criteria) matches line 4 of `mcp_honeypot.py`:
   `  - Never eval, exec, subprocess, or import anything derived from client input.`
   This is the safety-invariant comment block that Task 4 itself explicitly required be added near the top of the file ("add a short comment block near the top of `mcp_honeypot.py` stating the non-negotiable safety invariants"). The word "subprocess" appears in prose describing what must never happen, not as an actual import or call. This is a self-referential conflict in design.md's own acceptance criteria (the required safety comment necessarily trips the required literal grep), not a defect in `mcp_honeypot.py`'s actual behavior. QA's S4 test replicates the grep but skips comment/docstring lines to test the actual spirit of the criterion (no forbidden identifiers in *code*), and S4b adds an AST-based structural check (no forbidden imports, no `eval(`/`exec(`/`socket.socket(` calls anywhere in the parsed module) as a stronger, comment-proof backstop. No action needed on `mcp_honeypot.py`; flagging only so the orchestrator/builder are aware the literal grep string in `design.md` will "fail" if run verbatim, in case a future round's tooling does that naively.

**Coverage gap carried forward (see test-plan.md Coverage Notes):** `_emergency_fallback`'s exact double-send/zero-send regression (`[RN2-5]`, monkeypatching `_send_response` to raise mid-write) was not implemented as a dedicated unit test this round; R6 exercises a closely related fault-injection path end-to-end. Can be added in a later round if needed.
