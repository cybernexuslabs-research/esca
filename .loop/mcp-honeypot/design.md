# Design: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Purpose: A decoy MCP server that appears to expose useful tools, logs everything a client does, and never performs any real action. Intended for observing how LLM agents and automated scanners interact with untrusted MCP servers.

Scope for v1: Single file, stdlib plus at most one small dependency. No database, no web UI, no alerting. Getting complete, well-structured logs is the only goal.

Protocol surface: Serve MCP over streamable HTTP on a configurable host/port (default 127.0.0.1:8000). Handle enough JSON-RPC 2.0 to keep a real client talking: initialize (return protocolVersion, serverInfo, capabilities [tools only]), notifications/initialized, tools/list (return the fake tool catalog), tools/call (return canned fake results), ping. Any unknown method returns a well-formed JSON-RPC error rather than crashing or closing the connection. Malformed JSON gets a -32700 parse error and is still logged.

Fake tool catalog: Four tools with realistic names, descriptions, and JSON Schemas -- plausible enough that an agent would try them, e.g. a file reader, a database query runner, a credential/secret lookup, and an outbound email sender. Each returns static or templated fake data. Nothing touches the filesystem, network, shell, or any real service.

Logging: Append one JSON object per line to a JSONL file (default ./honeypot.jsonl): ISO 8601 UTC timestamp; source IP and port; request HTTP headers (at minimum User-Agent); session identifier, if the client provides one; the raw request body as received; the parsed method name, and for tools/call the tool name and full arguments; the response the honeypot returned. Log before responding so nothing is lost if a handler raises. Also mirror a one-line human-readable summary to stderr. **Round 1 revision:** "one record per HTTP request" is literal -- every request that reaches `_handle_request` (including 404s, 405s, and 413s) produces exactly one JSONL record. **Round 2 revision:** logging completeness now extends *below* `_handle_request` too -- a narrow `log_error` override on the HTTP handler (see § Architecture Overview and § Data Flow) captures the stdlib's own pre-dispatch rejections (malformed/oversized request lines, unsupported HTTP versions, unimplemented verbs, and a client that stalls before ever completing a request line), closing what Round 2 review found to be an undercounted "two named exceptions" claim. **Round 3 revision:** one further gap in the Round 2 fix itself was found and closed -- a blank/whitespace-only first request line causes CPython's `parse_request()` to return `False` without ever calling `send_error()`/`log_error()`, so that specific case was structurally invisible to the `log_error` override (verified empirically against live CPython 3.14). A second, narrower `handle_one_request()` override now catches it directly. After both fixes, two cases remain genuinely structurally unloggable (no stdlib hook fires at all, ever) and one further case is deliberately bounded-by-design rather than eliminated -- see § Data Flow, "Universal logging: what's covered and what genuinely isn't" for the precise, current three-item list.

Safety rules (non-negotiable): Never eval, exec, subprocess, or import anything derived from client input. Never make outbound network requests. Never read or write files outside the log path. Log file is append-only; treat every logged value as untrusted text.

Deliverables: The honeypot source file. A one-paragraph README: how to run it, where logs go, how to point an MCP client at it for testing.

---

**Review disposition.** This revision resolves all 9 `review-notes.md` Round 1 findings, all 5 `security-plan-review.md` Round 1 findings, all 5 `review-notes.md` Round 2 findings, all 2 `review-notes.md` Round 3 findings, and folds in all 3 `security-plan-review.md` Round 2 minor notes plus 2 of the 3 `security-plan-review.md` Round 3 minor notes (Round 2 and Round 3 security verdicts were both APPROVED; all of these notes were explicitly non-blocking, and cheap enough to fold in except the third Round 3 note, which the security review itself flagged as documentation-only with no action needed). Per-finding summaries are at the end of this document; findings are referenced inline as `[RN-#]`/`[SEC-#]` (Round 1), `[RN2-#]`/`[SEC2-x]` (Round 2), and `[RN3-#]`/`[SEC3-x]` (Round 3) at the point each is resolved.

## Architecture Overview

This is a greenfield addition to an otherwise-empty repo (`.claude/`, `.loop-templates/`, `.gitignore`, and a one-paragraph `README.md` are the only existing files; there is no prior Python code or toolchain to fit into -- confirmed via `find . -maxdepth 3`). No scaffolding phase is needed beyond the file itself: this is a stdlib-only, single-file Python 3.10+ program, so there is no package manager, build system, or lint config to initialize -- `python3 mcp_honeypot.py` is the entire toolchain, and `python3 -m py_compile mcp_honeypot.py` / `python3 -c "import ast; ast.parse(open('mcp_honeypot.py').read())"` stand in for a "build" step during development.

The whole system is one process, one file, three logical layers stacked inside it, in this order:

1. **Transport layer** -- a `HoneypotHTTPServer(ThreadingHTTPServer)` subclass that adds a bounded concurrent-connection cap, plus a `HoneypotRequestHandler(BaseHTTPRequestHandler)` subclass that owns the socket, HTTP method/path routing, a per-connection read timeout, request-body reading with a hard size cap, and writing the HTTP response. **Every** request that reaches a `do_*` method is funneled through one shared method, `_handle_request(self, http_method: str)`, so logging there is universal rather than conditional on reaching the JSON-RPC dispatcher `[RN-1] [SEC-3]`. **New in Round 2:** requests that *never* reach a `do_*` method -- because the stdlib itself rejected them while parsing the request line/headers, or because the client stalled before sending a request line at all -- are now also captured, via a narrow override of `HoneypotRequestHandler.log_error()` (the stdlib's own single internal hook for exactly these cases; see § Data Flow, "Universal logging via a `log_error` override"). This closes the gap Round 2 review found in the "two named exceptions" framing `[RN2-1] [SEC2-b]`. **New in Round 3:** one specific stdlib-rejection case -- a blank/whitespace-only first request line -- turned out to bypass the `log_error` override entirely, since CPython's `parse_request()` returns `False` for it without calling `send_error()`/`log_error()` at all (empirically verified against live CPython 3.14: raw `b"\r\n"` produces zero response bytes and zero `log_error` calls). A second, narrower override of `HoneypotRequestHandler.handle_one_request()` now detects this specific case directly (rather than via `log_error`, since `log_error` is provably never called here) and logs it before falling through to normal parsing `[RN3-1]`; see § Data Flow, "Universal logging via a `handle_one_request` override." Neither layer interprets the body as anything other than bytes/JSON.
2. **Protocol/dispatch layer** -- pure(ish) functions that take a parsed JSON-RPC message plus a small immutable request-context object and return a `DispatchResult` (see § Data Flow). This layer has no socket access and does no I/O of its own; it is the seam the design keeps free of `BaseHTTPRequestHandler` so it can be exercised directly.
3. **Logging layer** -- a small `JSONLogWriter` class wrapping a single already-open file handle plus a `threading.Lock`, and a `sanitize_for_stderr` helper. The transport layer calls this *after* building the full response object but *before* writing bytes to the client socket, satisfying "log before responding." The log write itself is individually fault-tolerant: a failure to write (disk full, permission error, etc.) is caught locally and never prevents the HTTP response from being sent `[RN-6]`. **Every** code path that logs anything -- the normal `_handle_request` flow, the new `log_error` override, and `_emergency_fallback` -- calls through this *same* `JSONLogWriter.write()` instance and therefore the *same* lock; none of them opens a second file handle or writes to the file directly `[SEC2-c]` (see § Data Flow, `_emergency_fallback`).

There are no other components, no external services, no persistence beyond the JSONL file, and no dependencies beyond the Python 3 standard library (`http`, `http.server`, `socketserver`, `json`, `argparse`, `threading`, `uuid`, `datetime`, `re`, `dataclasses`, `collections`, `email.message`, `sys`). This matches the plan's stack decision exactly; nothing in the repo contradicts or constrains it. **New in Round 3:** `http` (specifically `http.HTTPStatus`) is now imported directly by the module's own code, not just used implicitly via `http.server`'s internals, since the new `handle_one_request()` override reproduces two of the stdlib's own `HTTPStatus`-using `send_error()` calls.

**Stated reliance on a stdlib-enforced limit `[SEC-5]`.** One protection in this design is enforced by the Python standard library rather than by code we write, and is called out explicitly here so a future maintainer doesn't accidentally swap in a handler base class that lacks it: **HTTP header count/line-length limits.** `http.server`'s request parsing goes through `http.client.parse_headers()`, which enforces `http.client._MAXHEADERS` (100 headers) and per-line length limits before `do_*` is ever invoked. We do **not** additionally cap header count/size ourselves in v1; the stdlib ceiling is judged sufficient given the honeypot's threat model (a header-flood attack at that scale is a pathological stress case rather than realistic scanner/agent traffic, and it still can't crash the process or bypass the body-size cap). **Round 2 change:** in Round 1, a request that tripped this limit was one of the "two named exceptions" to universal logging -- rejected by the stdlib *and* unlogged. As of this revision it is still rejected by the stdlib (we still don't reimplement the limit itself), but the rejection **is now logged**, via the same `log_error` override described above `[RN2-1]`. The stdlib enforces the ceiling; our code now observes and records every time it fires.

**Total-duration vs. per-read timeout, an accepted tradeoff `[SEC2-a]`.** `SOCKET_TIMEOUT_SECONDS` (see § Components) is a per-I/O-operation idle timeout (`socket.settimeout`, reset on every partial read), not a wall-clock budget for the whole connection. A client that trickles bytes at just under one byte per `SOCKET_TIMEOUT_SECONDS` never trips it and can hold one of the `MAX_CONCURRENT_CONNECTIONS` slots open indefinitely. This is a deliberate v1 scope decision, not an oversight: the `MAX_CONCURRENT_CONNECTIONS` semaphore already bounds the blast radius (worst case is `MAX_CONCURRENT_CONNECTIONS` permanently-slow-trickled connections, not unbounded thread growth -- this was independently verified by security review as non-blocking), and a true wall-clock watchdog would require a second background thread per connection (or a monitor thread scanning connection-start timestamps and forcibly closing sockets from outside the handler thread) purely to defend against a residual, already-bounded slow-POST variant. That complexity is judged not worth adding in v1 given the existing cap; if a future round of traffic shows this being exploited in practice, a start-time field on `HoneypotRequestHandler` plus a periodic sweep in a dedicated watchdog thread is the natural extension point, not a redesign.

## Components / Modules

Everything lives in one new file at the repo root: **`mcp_honeypot.py`**. Internally it is organized top-to-bottom as (this ordering is also the build order in Task Breakdown below):

- **CLI / entrypoint** -- `build_arg_parser() -> argparse.ArgumentParser` (`--host` default `127.0.0.1`, `--port` default `8000`, `--log-file` default `./honeypot.jsonl` -- no new flags added; all new v1 hardening constants below are code-level, not CLI-configurable, to keep the CLI surface exactly matching plan.md) and `main(argv: list[str] | None = None) -> int`. All server-starting side effects live inside `main()`, guarded by `if __name__ == "__main__":` -- importing the module (e.g. from a future test or the QA phase) must never open a socket or a file. This is the primary testability seam for the whole design.
- **Module-level constants** (new, named, near the top of the file so an operator can tune them by editing the file): `MAX_BODY_BYTES = 1_048_576` (1 MiB request body cap), `SOCKET_TIMEOUT_SECONDS = 10` (per-connection idle/read timeout `[RN-8] [SEC-1]`, see the accepted-tradeoff note above `[SEC2-a]`), `MAX_CONCURRENT_CONNECTIONS = 200` (hard cap on simultaneously-handled connections `[SEC-1]`), `MAX_SESSIONS = 10_000` (cap on the in-memory session store, oldest evicted first `[SEC-2]`), `MAX_LEADING_BLANK_REQUEST_LINES = 5` (new in Round 3 -- bounds how many consecutive blank/whitespace-only leading request lines the `handle_one_request()` override will log-and-skip per connection before giving up, so the fix for `[RN3-1]` can't itself become an unbounded read/log loop; see § Data Flow).
- **Logging core** -- `JSONLogWriter` (holds the open file handle + `threading.Lock`, exposes `write(record: dict) -> None`; this is the *single* writer instance used by every logging call site in the file `[SEC2-c]`), `build_log_record(...) -> dict` (pure function assembling the record shape below, including `http_method`/`path` since every HTTP request that reaches `_handle_request` is logged), `build_stdlib_rejection_record(...) -> dict` (new `[RN2-1]` -- pure function assembling a record for the stdlib-rejection cases the `log_error` override captures; see § Data Flow), `headers_to_dict(msg: email.message.Message) -> dict[str, str]` (duplicate-header comma-join policy `[RN-7]`), `sanitize_for_stderr(text: str, max_len: int = 300) -> str`, and `emit_stderr_summary(record: dict) -> None`.
- **HTTP server** -- `HoneypotHTTPServer(ThreadingHTTPServer)` (adds a `threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)` acquired in an overridden `process_request()` and released in an overridden `process_request_thread()`, so more than `MAX_CONCURRENT_CONNECTIONS` simultaneous connections are refused (socket closed immediately, no thread spun up, no response, no log line -- this remains one of the structurally-unloggable cases named in § Data Flow's now three-item "what's covered and what genuinely isn't" list) `[SEC-1]`. `ThreadingHTTPServer` already sets `daemon_threads = True` by default (confirmed against the stdlib source), so the process can still exit cleanly even if a handler thread is stuck; no change needed there.
- **HTTP handler** -- `HoneypotRequestHandler(BaseHTTPRequestHandler)` with class attribute `timeout = SOCKET_TIMEOUT_SECONDS` (stdlib's `socketserver.StreamRequestHandler.setup()` automatically applies this as a socket-level read timeout on every connection -- the slowloris mitigation `[RN-8] [SEC-1]`). Implements `do_GET`, `do_POST`, `do_PUT`, `do_PATCH`, `do_DELETE`, `do_HEAD`, `do_OPTIONS`, each a one-line call to the shared `_handle_request(self, http_method)`. This method owns: path check (`/mcp` vs. 404), HTTP-method check (`POST` vs. 405 with `Allow: POST`), body framing classification (`Content-Length` present/absent/duplicate/oversized, or `Transfer-Encoding: chunked` -- see § Data Flow, five distinct outcomes and status codes `[RN2-3] [RN2-4] [RN3-2]`), body read with `errors="replace"` decoding, JSON parse attempt, top-level shape validation, building the `RequestContext`, calling `dispatch()`, calling the logging core (fault-tolerant), and writing the HTTP response via `_send_response`, which also sets `self._response_sent = True` immediately after the write completes `[RN2-5]`. The entire `_handle_request` method body is wrapped in one outer `try/except Exception` with an `_emergency_fallback()` path `[RN-6] [SEC-3]` -- see § Data Flow for the exact lifecycle. **New in Round 2 -- `log_error` override:** `HoneypotRequestHandler` also overrides `log_error(self, format, *args)`, the stdlib's single internal hook that fires for every pre-`do_*` rejection (malformed/oversized request line, unsupported HTTP version, oversized headers, an unimplemented HTTP verb, or a stall before any request line arrives). The override builds and writes a `build_stdlib_rejection_record(...)` through the same `log_writer` before delegating to `super().log_error(...)` so the stdlib's own stderr diagnostic line is preserved unchanged `[RN2-1]`. Full mechanism and the resulting, now-precise list of what's still genuinely unlogged is in § Data Flow. **New in Round 3 -- defensive hardening of `log_error`, plus a `handle_one_request` override:** `log_error()`'s entire body (not just the `log_writer.write()` call) is now wrapped in one `try/except Exception: pass`, so a failure anywhere in `build_stdlib_rejection_record`/`headers_to_dict`/the `format % args` formatting can never prevent `super().log_error(...)` from running or leak an unsanitized traceback to stderr via `socketserver`'s generic `handle_error()` `[SEC3-a]`. Separately, `HoneypotRequestHandler` also overrides `handle_one_request()` itself (a near-verbatim copy of the stdlib version with one inserted check) to catch the one case `log_error()` structurally cannot see -- a blank/whitespace-only first request line, where `parse_request()` returns `False` without calling `send_error()`/`log_error()` at all `[RN3-1]`. A new module-level constant, `MAX_LEADING_BLANK_REQUEST_LINES = 5`, bounds how many consecutive leading blank lines this override will log-and-skip before giving up and falling through to the stdlib's original (silent) behavior for that connection, so the fix itself can't become an unbounded per-connection read/log loop. Full mechanism in § Data Flow, "Universal logging via a `handle_one_request` override."
- **Session store** -- module-level `SESSIONS: OrderedDict[str, dict]` (insertion-ordered so the oldest entry is always `next(iter(SESSIONS))`) + `SESSIONS_LOCK: threading.Lock`, written to only from inside `dispatch()` when a `method == "initialize"` call succeeds: a new `uuid.uuid4().hex` id is minted, and if `len(SESSIONS) >= MAX_SESSIONS` the oldest entry is evicted (`SESSIONS.popitem(last=False)`) before the new one is inserted, all under `SESSIONS_LOCK` `[SEC-2]`. **v1 does not attempt to correlate header-less follow-up requests back to a previously-issued session** -- `RequestContext.session_id` is populated strictly from the `Mcp-Session-Id` request header when present, `None` otherwise, with no IP-based or other fallback lookup `[RN-5]`.
- **JSON-RPC dispatch** -- `dispatch(msg: dict, ctx: RequestContext) -> DispatchResult` (see exact signature in § Data Flow), a `METHODS: dict[str, Callable]` table, and one handler function per method: `handle_initialize`, `handle_notifications_initialized`, `handle_ping`, `handle_tools_list`, `handle_tools_call`. Wrapped in one `try/except InvalidParamsError` (→ `-32602`, `[RN-3]`) then `except Exception` (→ `-32603`) inside `dispatch()` itself, so *any* handler bug or bad-params condition becomes a well-formed JSON-RPC error object, never an unhandled exception reaching the transport layer.
- **Fake tool catalog** -- `TOOLS: list[dict]` (the four `tools/list` entries: name, description, `inputSchema`) and `TOOL_HANDLERS: dict[str, Callable[[dict], dict]]` mapping tool name to a pure function that builds the fake `tools/call` result content. `validate_arguments(schema: dict, arguments: dict) -> None` (pure function, raises `InvalidParamsError`) checks arguments against each tool's `inputSchema` before its handler runs. **Round 2 fix `[RN2-2]`:** the `"integer"`/`"number"` type checks now explicitly exclude `bool` (`isinstance(value, bool)` is checked *before*, and takes precedence over, `isinstance(value, int)`), since Python's `bool` is a subclass of `int` and would otherwise let a JSON `true`/`false` incorrectly satisfy an `"integer"`/`"number"` schema field -- see exact logic in § Data Flow. No tool handler imports or calls anything from `os`, `subprocess`, `socket`, `urllib`, `builtins.eval`, `builtins.exec`, or `importlib`/dynamic `import`.
- **README.md** (existing file at repo root, extended not replaced) -- gets the run/log-location/client-pointing paragraph the plan calls for, plus explicit caveats about unbounded JSONL growth (including that rejected/malformed traffic now contributes to it too, new in Round 3 `[SEC3-b]`), the read-timeout/connection-cap mitigations and their limits (including the accepted per-read-vs-total-duration tradeoff `[SEC2-a]`), and the now-precise three-item list of what remains unlogged -- two genuinely structurally-unloggable cases plus one bounded-by-design residual (see Task 4).
- **.gitignore** (existing file at repo root) -- gains a `/honeypot.jsonl` entry; the current `.gitignore` already has a `# Python` section (`__pycache__/`, `*.py[cod]`, `.venv/`, etc.) but no honeypot-specific log entry, so this is a one-line addition, not a new section.

## Data Flow / Interfaces

**Request lifecycle (every HTTP request that reaches a `do_*` method):**

```
socket bytes
  -> HoneypotRequestHandler.{do_GET,do_POST,do_PUT,do_PATCH,do_DELETE,do_HEAD,do_OPTIONS}(self)
       each is: def do_X(self): self._handle_request("X")

  -> _handle_request(self, http_method: str) -> None:        # ONE try/except Exception wraps this whole body
       self._response_sent = False                            # [RN2-5]: initialized at the very top, before
                                                                 # anything can raise, so _emergency_fallback
                                                                 # always has a defined value to check.
       try:
           ctx = self._build_context()          # RequestContext: client_ip, client_port,
                                                  #   headers = headers_to_dict(self.headers), session_id
           path = self.path
           raw_body: str | None = None
           parsed: object | None = None          # NOTE: object, not dict -- see shape check below
           response_obj: dict | None = None
           session_id_to_issue: str | None = None

           if path != "/mcp":
               http_status = 404                  # empty body, no headers beyond Content-Length: 0
           elif http_method != "POST":
               http_status = 405                  # empty body, Allow: POST header, no JSON-RPC body
           else:
               outcome, length = _classify_content_length(self.headers)   # [RN2-3][RN2-4][RN3-2]: see below --
                                                                            # "ok" | "chunked" |
                                                                            # "duplicate_content_length" |
                                                                            # "duplicate_transfer_encoding" |
                                                                            # "missing_or_invalid"
               if outcome == "chunked":
                   http_status = 411               # Transfer-Encoding: chunked -- not supported in v1
                   raw_body = "(Transfer-Encoding: chunked not supported)"
               elif outcome == "duplicate_content_length":
                   http_status = 400               # >1 Content-Length header -- ambiguous, rejected outright
                   raw_body = "(duplicate Content-Length headers)"
               elif outcome == "duplicate_transfer_encoding":
                   http_status = 400               # >1 Transfer-Encoding header -- same ambiguity, rejected
                   raw_body = "(duplicate Transfer-Encoding headers)"     # outright regardless of agreement [RN3-2]
               elif outcome == "missing_or_invalid":
                   http_status = 413               # absent / non-numeric / negative / over MAX_BODY_BYTES
                   raw_body = "(missing, invalid, or oversized Content-Length)"
               else:  # "ok"
                   body_bytes = self.rfile.read(length)      # bounded by validated length; may raise
                                                               # socket.timeout if the client stalls past
                                                               # SOCKET_TIMEOUT_SECONDS -- caught by the outer
                                                               # try/except below, not handled here
                   raw_body = body_bytes.decode("utf-8", errors="replace")
                   try:
                       parsed = json.loads(raw_body)
                   except json.JSONDecodeError:
                       parsed = None

                   if parsed is None:
                       response_obj = _build_error(id_=None, code=-32700, message="Parse error")
                       http_status = 200
                   elif not isinstance(parsed, dict) or not isinstance(parsed.get("method"), str):
                       # [RN-4]: validated BEFORE any dict-only operation on `parsed`; a JSON body that
                       # parses fine but isn't a JSON-RPC-shaped object (e.g. `42`, `"hi"`, `[1,2,3]`,
                       # `true`, or `{"id": 1}` with no "method") never reaches dispatch() or does a
                       # bare `"id" not in parsed`.
                       safe_id = parsed.get("id") if isinstance(parsed, dict) else None
                       response_obj = _build_error(id_=safe_id, code=-32600, message="Invalid Request")
                       http_status = 200
                   else:
                       dr = dispatch(parsed, ctx)             # dr: DispatchResult -- see signature below
                       session_id_to_issue = dr.session_id
                       if dr.response is None:
                           response_obj, http_status = None, 202     # notification: no "id" in parsed
                       else:
                           response_obj, http_status = dr.response, 200

           record = build_log_record(ctx, http_method, path, raw_body, parsed, response_obj, http_status)

           try:
               log_writer.write(record)            # append json.dumps(record) + "\n", flush, lock-guarded
           except Exception as log_err:             # [RN-6]: log failure must never block the response
               sys.stderr.write(
                   f"[honeypot] WARNING: log write failed: "
                   f"{sanitize_for_stderr(repr(log_err))}\n"
               )
           emit_stderr_summary(record)              # best-effort; wrapped internally, never raises out

           self._send_response(http_status, response_obj, session_id_to_issue, allow_header=(http_status == 405))
           # ^ _send_response sets self._response_sent = True immediately after the socket write completes
           #   -- see "Response-sent tracking" below [RN2-5].
       except Exception:
           self._emergency_fallback(http_method)     # [RN-6] [SEC-3]: catches EVERYTHING upstream of/including
                                                       # the log write -- body-read errors, decode errors,
                                                       # RecursionError from pathological JSON, dispatch bugs
                                                       # that somehow escape dispatch()'s own try/except, etc.
```

`_emergency_fallback(self, http_method: str) -> None` is the last line of defense. It is not a code path that reaches `_handle_request`'s own body -- it runs when that body has already raised. It:

1. **Checks `self._response_sent`** (see "Response-sent tracking" below `[RN2-5]`). Only if it is `False` does it attempt to send a generic `HTTP 500` with a minimal `{"jsonrpc": "2.0", "id": null, "error": {"code": -32603, "message": "Internal error"}}` body, and only then sets `self._response_sent = True` (mirroring the exact same convention `_send_response` uses on its own success path).
2. **Attempts a best-effort JSONL record** (`{"...": "...", "internal_fault": true}`) via **`log_writer.write(record)`** -- the *same* `JSONLogWriter` instance and therefore the *same* `threading.Lock` used by every other logging call site in the file, never a separate or unlocked file handle `[SEC2-c]`. This is stated explicitly here (not left implicit) because it is exactly the property that prevents two concurrently-failing requests, or a normal write racing an emergency-fallback write, from interleaving/corrupting a JSONL line on the one code path where forensic log integrity matters most.
3. **Attempts a plain stderr line.**

Each of (1), (2), and (3) is individually wrapped in its own `try/except Exception: pass` so a failure inside the fallback itself can never re-raise and crash the handler thread. This directly satisfies plan.md's "catch-all exception handler around each request" for the *entire* request lifecycle, not just inside `dispatch()` `[SEC-3]`.

**Response-sent tracking, exact mechanism `[RN2-5]`:**

```python
class HoneypotRequestHandler(BaseHTTPRequestHandler):
    # self._response_sent is a plain instance attribute, not a class attribute --
    # it must be per-request-invocation state, re-initialized at the top of every
    # _handle_request() call (a single handler instance serves one connection,
    # and in principle one connection could serve more than one request if
    # keep-alive were ever enabled, though v1's protocol_version = "HTTP/1.0"
    # default makes that unlikely -- resetting per call is correct regardless).

    def _handle_request(self, http_method: str) -> None:
        self._response_sent = False        # set BEFORE the try block, so it's always
                                             # defined even if an exception fires before
                                             # any response-related code runs at all
        try:
            ...
            self._send_response(http_status, response_obj, session_id_to_issue, ...)
        except Exception:
            self._emergency_fallback(http_method)

    def _send_response(self, http_status, response_obj, session_id_to_issue, allow_header=False) -> None:
        # ... writes status line, headers (incl. Allow/Mcp-Session-Id as applicable), body bytes ...
        self._response_sent = True   # set ONLY after the write actually completes; if an
                                       # exception occurs mid-write, this line is never
                                       # reached, so _emergency_fallback correctly still
                                       # sees _response_sent == False and attempts its own.

    def _emergency_fallback(self, http_method: str) -> None:
        if not getattr(self, "_response_sent", False):
            try:
                self._send_minimal_500()   # writes a minimal status line + JSON-RPC -32603 body directly
                self._response_sent = True  # same convention as _send_response, set only after the write
            except Exception:
                pass
        try:
            log_writer.write(build_log_record(..., internal_fault=True))   # [SEC2-c]: same lock-guarded writer
        except Exception:
            pass
        try:
            sys.stderr.write(...)
        except Exception:
            pass
```

There is exactly one flag, set in exactly two places (both immediately after, never before, a real write completes), and exactly one reader of it (`_emergency_fallback`'s guard). No ambiguity about double-sending or zero-sending a response remains.

**Universal logging via a `log_error` override (new in Round 2) `[RN2-1] [SEC2-b]`:**

Round 1's design claimed "two named exceptions to universal logging": (1) HTTP verbs outside the seven implemented `do_*` methods, and (2) requests that trip the stdlib's header-count/line-length limits. Round 2 review, reading the actual CPython `BaseHTTPRequestHandler` source, found this undercounted three more cases that also never reach `_handle_request`: a malformed/non-conforming request line, an oversized (>65536-byte) request line, and a client that stalls before completing its request line at all (distinct from the already-covered "slow body" case, which *does* go through `_handle_request`'s own `SOCKET_TIMEOUT_SECONDS`-bounded `rfile.read()`).

Reading the stdlib source (`http.server.BaseHTTPRequestHandler`, verified against the installed Python 3.14 stdlib during this design revision -- behavior is unchanged in this respect since at least 3.10) shows all five of these cases funnel through exactly **one** internal hook:

- `parse_request()` calls `self.send_error(code, message)` for: a request line that doesn't parse as `METHOD SP PATH SP HTTP/x.y` (400), an unsupported HTTP major version (505), and oversized/too-many headers (431, via `http.client.LineTooLong`/`HTTPException`).
- `handle_one_request()` itself calls `self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)` directly for a >65536-byte request line (414), and `self.send_error(HTTPStatus.NOT_IMPLEMENTED)` for an unimplemented verb (501) -- this is Round 1's exception (1), now also captured by the same mechanism.
- **`send_error()`'s very first action, before it writes anything to the socket, is `self.log_error("code %d, message %s", code, message)`.**
- Separately, `handle_one_request()` wraps its entire body in `except TimeoutError as e: self.log_error("Request timed out: %r", e); ...; return` -- this is the case of a client stalling before (or during, though that variant is intercepted earlier by our own code) completing a request line. Critically, this branch calls `self.log_error(...)` directly, **not** `self.send_error(...)` (no response is sent for a bare request-line timeout, matching real-world server behavior of just dropping the connection).

**One override closes essentially all of it:**

```python
def log_error(self, format: str, *args) -> None:
    """Stdlib's BaseHTTPRequestHandler calls log_error() from exactly two
    places: send_error() (itself invoked by parse_request() for a malformed
    request line, an oversized request line, an unsupported HTTP version,
    oversized/too-many headers, or an unimplemented HTTP verb) and
    handle_one_request()'s own `except TimeoutError` branch (a client
    stalling before completing its request line). Overriding this single,
    narrow hook means every one of those cases now produces one JSONL
    record + stderr line, built from whatever partial request-line state
    the stdlib had already captured -- self.command/self.path/self.headers
    may be None, '', or not-yet-set, so every field access here is
    defensive.

    [SEC3-a, Round 3] The ENTIRE body below is wrapped in one
    try/except Exception: pass, mirroring _handle_request's own
    outer-try-except pattern, rather than only wrapping the
    log_writer.write() call as in the Round 2 version. A bug anywhere in
    build_stdlib_rejection_record()/headers_to_dict()/the `format % args`
    formatting can therefore never prevent super().log_error(...) from
    running (which would otherwise silently drop the stdlib's own
    operator-facing diagnostic line), and can never escape into
    socketserver's generic handle_error(), which prints an UNSANITIZED
    traceback straight to stderr -- bypassing sanitize_for_stderr
    entirely, on a code path where `detail`/the request line can contain
    attacker-controlled bytes. super().log_error(...) is called
    unconditionally afterward, outside the try, so it always fires
    exactly once regardless of what happens above it."""
    try:
        detail = format % args
        record = build_stdlib_rejection_record(
            client_ip=self.client_address[0],
            client_port=self.client_address[1],
            http_method=getattr(self, "command", None) or None,
            path=getattr(self, "path", None) or None,
            headers=headers_to_dict(self.headers) if getattr(self, "headers", None) else {},
            detail=detail,
        )
        try:
            log_writer.write(record)          # same lock-guarded writer as every other call site
        except Exception as log_err:
            sys.stderr.write(f"[honeypot] WARNING: log write failed: {sanitize_for_stderr(repr(log_err))}\n")
        emit_stderr_summary(record)
    except Exception:
        pass
    super().log_error(format, *args)
```

This override does **not** interfere with normal-request logging: `_handle_request` never calls `self.send_error()` or `self.log_error()` on any of its own paths (404/405/411/400/413/200/202 are all built and sent via the honeypot's own `_send_response`), so there is no double-logging between the two mechanisms. It also, as a side effect, means Round 1's exception (1) (unimplemented HTTP verbs) is **no longer an exception at all** -- it is captured by this same override, since `handle_one_request()` routes it through `send_error(501)` → `log_error(...)` exactly like the other cases.

**Universal logging via a `handle_one_request` override, closing the blank-request-line gap (new in Round 3) `[RN3-1]`:**

Round 3 review verified the `log_error` fix above against live CPython 3.14 behavior rather than taking the design's own claims on faith, and found one case the fix cannot see: `parse_request()`'s very first branch,

```python
words = requestline.split()
if len(words) == 0:
    return False
```

fires for a blank or whitespace-only first request line (e.g. a bare `\r\n` sent before the real request line -- RFC 7230 SS3.5 explicitly recommends servers tolerate exactly this) and returns `False` **without calling `self.send_error()` or `self.log_error()` at all**. `handle_one_request()` then just `return`s on the strength of a comment ("An error code has been sent, just exit") that is false on this specific path. Verified empirically, not just by reading source: a bare `BaseHTTPRequestHandler` with a `log_error` override that prints on every call, sent a raw socket connection containing only `b"\r\n"`, produced zero response bytes and zero `log_error` calls. Practically, this means a client that (per RFC 7230's own leniency recommendation) sends one leading blank line before its actual request loses the **entire subsequent request** with zero trace, not just the blank line -- exactly the scanner/probe pattern this honeypot most wants to capture.

`log_error()` cannot be the interception point for this case, since it is provably never called. Instead, `HoneypotRequestHandler` overrides `handle_one_request()` itself -- a near-verbatim reproduction of the stdlib version (reproduced here in full, since CPython doesn't factor the request-line read out into an independently overridable method), with exactly one inserted check. This override needs `HTTPStatus` in scope; add `from http import HTTPStatus` to the file's imports (see the updated stdlib module list in § Architecture Overview):

```python
def handle_one_request(self) -> None:
    """Overrides BaseHTTPRequestHandler.handle_one_request() wholesale.
    Identical to the stdlib version except for the ONE block marked
    below, which detects and logs a blank/whitespace-only leading
    request line before it reaches parse_request() -- the one case
    log_error() structurally cannot observe (see above). Bounded to
    MAX_LEADING_BLANK_REQUEST_LINES consecutive skips so a client can't
    turn this into an unbounded per-connection read/log loop; each
    skipped read is still bounded by SOCKET_TIMEOUT_SECONDS same as any
    other read on this connection, so a stalling client between blank
    lines is still caught by the existing except TimeoutError branch
    below, unchanged."""
    try:
        blank_lines_skipped = 0
        while True:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if (self.raw_requestline.strip()
                    or blank_lines_skipped >= MAX_LEADING_BLANK_REQUEST_LINES):
                break
            # [RN3-1] blank/whitespace-only line where a request line was
            # expected -- parse_request() would silently `return False`
            # here with no send_error()/log_error() call at all. Log it
            # ourselves, then loop to read the real request line, per
            # RFC 7230 SS3.5's "SHOULD ignore" leading-CRLF guidance.
            blank_lines_skipped += 1
            self._log_blank_request_line()

        if not self.parse_request():
            # An error code has been sent, just exit
            return
        mname = 'do_' + self.command
        if not hasattr(self, mname):
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED,
                "Unsupported method (%r)" % self.command)
            return
        method = getattr(self, mname)
        method()
        self.wfile.flush()   # actually send the response if not already done.
    except TimeoutError as e:
        # a read or a write timed out.  Discard this connection
        self.log_error("Request timed out: %r", e)
        self.close_connection = True
        return

def _log_blank_request_line(self) -> None:
    """Builds and writes a build_stdlib_rejection_record for a blank/
    whitespace-only first request line -- the one case log_error() cannot
    see. Wrapped entirely in its own try/except Exception: pass, same
    defensive pattern as the Round 3 log_error() fix [SEC3-a], so a
    failure here can never prevent handle_one_request() from continuing
    on to read the real, following request line."""
    try:
        record = build_stdlib_rejection_record(
            client_ip=self.client_address[0],
            client_port=self.client_address[1],
            http_method=None,
            path=None,
            headers={},
            detail="blank request line (RFC 7230 SS3.5 leading CRLF tolerance)",
        )
        try:
            log_writer.write(record)
        except Exception as log_err:
            sys.stderr.write(f"[honeypot] WARNING: log write failed: {sanitize_for_stderr(repr(log_err))}\n")
        emit_stderr_summary(record)
    except Exception:
        pass
```

This does not double-log against `log_error()`: the blank-line case never reaches `parse_request()`/`send_error()`/`log_error()` in the first place (that's the entire bug being fixed), and every *other* rejection path (malformed line, oversized line, bad version, oversized headers, unimplemented verb, pre-request-line timeout) is completely unchanged by this override -- it falls straight through to the unmodified `parse_request()`/`send_error()`/`log_error()` chain exactly as in Round 2, so no case is logged twice.

**Universal logging: what's covered and what genuinely isn't (updated, Round 3).** After the `log_error()` and `handle_one_request()` overrides above, exactly **two** cases remain genuinely structurally unloggable -- no stdlib hook fires at all, ever, regardless of how this code is written -- plus **one** further case that is deliberately *bounded by design* rather than eliminated outright:

**Genuinely structurally unloggable (no hook exists, in principle, to intercept):**

1. **Connections refused at the `MAX_CONCURRENT_CONNECTIONS` semaphore cap.** `HoneypotHTTPServer.process_request` closes the socket immediately, before `handle_one_request` (and therefore before any of the above, including the new blank-line check) ever runs. This is an accepted, unchanged-since-Round-1 `[SEC-1]` design choice: logging it would require adding a code path at the raw-`accept()` layer for a case that, by construction, never got far enough to exchange any HTTP-level data.
2. **A client that opens a TCP connection and sends zero bytes before an ordinary clean close/reset (not a timeout).** `self.rfile.readline(65537)` simply returns `b''` on EOF; `handle_one_request()`'s response is `self.close_connection = True; return` -- no exception, no `send_error`, no `log_error` call, and (as of this revision) still no bytes for the new blank-line check to act on either, since it only fires once a non-empty line has actually been read. There is genuinely nothing to log here even in principle (not even a partial request line), short of instrumenting `rfile.readline` itself purely to detect "a TCP connection existed briefly," which was judged not worth the complexity for the near-zero forensic value of that signal on its own.

**Bounded by design, not structurally impossible (new in Round 3):**

3. **More than `MAX_LEADING_BLANK_REQUEST_LINES` (default 5) consecutive blank/whitespace-only leading lines before a real request line ever arrives.** Unlike cases 1 and 2, a hook *does* exist and *is* used here (`_log_blank_request_line()`) -- but only up to the bound, so this connection isn't turned into an unbounded per-connection read/log loop under attacker control. Once the bound is exhausted, `handle_one_request()`'s override falls through to the stdlib's own unmodified `parse_request()` call for that still-blank line, which silently returns `False` exactly as in the pre-fix (Round 2 and earlier) behavior -- so the *final* line in a run of more than `MAX_LEADING_BLANK_REQUEST_LINES` consecutive blank lines is unlogged, though every blank line up to the bound was logged individually. In practice this requires a client to send strictly more than five consecutive blank lines before ever sending a real request line -- meaningfully rarer than, and a deliberate superset of, the single-leading-CRLF pattern RFC 7230 SS3.5 actually recommends tolerating (which this fix fully and precisely resolves).

These three items -- not two -- are the complete, current, and precisely-derived list of what remains unlogged after this revision; nothing else in `parse_request()`, `handle_one_request()`, or `handle_expect_100()` returns/exits without going through either `send_error()`/`log_error()` or one of the two genuinely-structural gaps above (re-verified against the CPython 3.14 stdlib source as part of this revision, per review-notes.md Round 3's specific charge to check this empirically rather than by re-assertion).

**400 / 404 / 405 / 411 / 413 response shapes `[RN-9] [RN2-3] [RN2-4] [RN3-2]`:** all five are empty-body HTTP responses (`Content-Length: 0`), no JSON-RPC envelope, matching plan.md's "Transport-level problems ... use HTTP status codes with no JSON-RPC body" -- duplicate/ambiguous `Content-Length` (400), duplicate `Transfer-Encoding` (400, same treatment for the same reason, as of this revision `[RN3-2]`), and unsupported `Transfer-Encoding: chunked` (411) are all transport-level framing problems in exactly the same sense as an oversized body (413), so extending the same "status code, no body" treatment to them is consistent with, not a departure from, the plan's split. The 405 response additionally sets `Allow: POST`. None of the five set `Content-Type: application/json` since there is no body to type.

**Duplicate/chunked `Content-Length`/`Transfer-Encoding` classification, exact logic `[RN2-3] [RN2-4] [RN3-2]`:**

```python
def _classify_content_length(
    headers: email.message.Message, max_body_bytes: int = MAX_BODY_BYTES
) -> tuple[str, int | None]:
    """Pure function over a parsed header set. Returns (outcome, length):
      ("ok", N)                          -- exactly one Content-Length header, a valid
                                             non-negative base-10 integer, N <= max_body_bytes,
                                             and Transfer-Encoding is absent or a single
                                             "identity" occurrence.
      ("chunked", None)                  -- exactly one Transfer-Encoding header present with
                                             a value other than "identity" (case-insensitive) --
                                             v1 has no chunked-decoding support at all. Checked
                                             BEFORE Content-Length, so a request that illegally
                                             sends both is still classified by Transfer-Encoding,
                                             per RFC 7230 SS3.3.3's guidance that Transfer-Encoding
                                             takes precedence when both are present.
      ("duplicate_transfer_encoding", None)
                                          -- [RN3-2] more than one Transfer-Encoding header
                                             (checked via headers.get_all("Transfer-Encoding"),
                                             the same fix already applied to Content-Length in
                                             Round 2 -- headers.get(...) on email.message.Message
                                             silently returns only the FIRST occurrence, which
                                             would let a "Transfer-Encoding: identity" followed by
                                             a second "Transfer-Encoding: chunked" header slip
                                             through misclassified as non-chunked). Rejected
                                             outright as ambiguous, the same policy already
                                             applied to duplicate Content-Length, regardless of
                                             whether the repeated values happen to agree.
      ("duplicate_content_length", None) -- more than one Content-Length header (checked via
                                             headers.get_all("Content-Length")) -- rejected
                                             outright as ambiguous per RFC 7230 SS3.3.2, regardless
                                             of whether the repeated values happen to agree.
      ("missing_or_invalid", None)       -- zero Content-Length headers, or the single value
                                             present isn't a valid non-negative base-10 integer,
                                             or it exceeds max_body_bytes.

    Checked in this order: Transfer-Encoding duplicates, then Transfer-Encoding value,
    then Content-Length duplicates, then Content-Length value -- duplicate-detection always
    precedes single-value interpretation for BOTH headers, consistent by construction.
    """
    te_values = headers.get_all("Transfer-Encoding") or []
    if len(te_values) > 1:
        return ("duplicate_transfer_encoding", None)
    if len(te_values) == 1 and te_values[0].strip().lower() not in ("", "identity"):
        return ("chunked", None)

    cl_values = headers.get_all("Content-Length") or []
    if len(cl_values) > 1:
        return ("duplicate_content_length", None)
    if len(cl_values) == 0:
        return ("missing_or_invalid", None)
    raw = cl_values[0].strip()
    if not raw.isdigit():
        return ("missing_or_invalid", None)
    length = int(raw)
    if length > max_body_bytes:
        return ("missing_or_invalid", None)
    return ("ok", length)
```

**Duplicate HTTP header policy `[RN-7]`:**

```python
def headers_to_dict(msg: email.message.Message) -> dict[str, str]:
    """RFC 7230 SS3.2.2-style merge: repeated header names are joined with ', '
    in the order received, rather than silently keeping only the last value."""
    result: dict[str, str] = {}
    for key, value in msg.items():
        result[key] = f"{result[key]}, {value}" if key in result else value
    return result
```

**Core function signatures:**

```python
@dataclass(frozen=True)
class RequestContext:
    client_ip: str
    client_port: int
    headers: dict[str, str]      # via headers_to_dict(); duplicates joined with ", "
    session_id: str | None       # from Mcp-Session-Id request header, else None -- no fallback correlation in v1

@dataclass(frozen=True)
class DispatchResult:
    response: dict | None        # full JSON-RPC result/error object if `msg` had an "id", else None (notification)
    session_id: str | None       # newly-minted Mcp-Session-Id if this call was a successful "initialize", else None

class InvalidParamsError(Exception):
    """Raised by a method handler (currently only handle_tools_call) to signal
    a -32602 Invalid params condition. Caught inside dispatch(), never escapes it."""

def dispatch(msg: dict, ctx: RequestContext) -> DispatchResult:
    """`msg` is already known to be a dict with a string "method" (the caller,
    _handle_request, validates this before calling dispatch -- dispatch never
    needs to guard against non-dict/non-object top-level input).
    Looks up msg["method"] in METHODS; on a match, calls handler(msg.get("params") or {}, ctx)
    inside try/except InvalidParamsError (-> -32602) / except Exception (-> -32603).
    On no match: -32601 Method not found.
    If method == "initialize" and no error occurred, mints a new session id and
    records it in SESSIONS (capped/evicting -- see Session store) regardless of
    whether msg has an "id" (a client could in principle send initialize as a
    notification; unlikely but handled uniformly).
    If "id" not in msg: returns DispatchResult(response=None, session_id=<see above>).
    Else: returns DispatchResult(response={"jsonrpc": "2.0", "id": msg["id"], **result_or_error}, session_id=<see above>).
    Never raises."""

def handle_initialize(params: dict, ctx: RequestContext) -> dict: ...      # -> result dict (no session-id logic here; dispatch() owns that)
def handle_notifications_initialized(params: dict, ctx: RequestContext) -> dict: ...  # -> {} (no-op, side-effect free)
def handle_ping(params: dict, ctx: RequestContext) -> dict: ...            # -> {}
def handle_tools_list(params: dict, ctx: RequestContext) -> dict: ...      # -> {"tools": TOOLS}
def handle_tools_call(params: dict, ctx: RequestContext) -> dict:
    """Raises InvalidParamsError if params["name"] is missing/not a string, or
    params["arguments"] is present but not an object, or the arguments fail
    validate_arguments() against the matched tool's inputSchema. Returns an
    isError:true result (not a raised error) for an unrecognized tool name --
    that's a valid-but-unsatisfiable request, not a malformed one."""

ToolHandler = Callable[[dict], dict]     # args -> {"content": [{"type": "text", "text": str}], "isError": bool}
TOOL_HANDLERS: dict[str, ToolHandler]    # keys match TOOLS[i]["name"]

_SCHEMA_TYPE_CHECKS: dict[str, Callable[[object], bool]] = {
    # [RN2-2]: bool is a subclass of int in Python, so "integer"/"number" checks
    # must explicitly exclude bool -- checked here, not left to a bare isinstance(v, int).
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}

def validate_arguments(schema: dict, arguments: dict) -> None:
    """Pure function. Checks every name in schema.get("required", []) is present
    in `arguments`, and for every key present in both `arguments` and
    schema["properties"], checks its JSON-Schema-declared "type" against the
    Python value's type using _SCHEMA_TYPE_CHECKS above -- notably, a JSON
    `true`/`false` value is accepted ONLY where the schema declares
    "type": "boolean", and is explicitly rejected for "integer"/"number"
    fields even though Python's bool passes a bare isinstance(v, int) check.
    Raises InvalidParamsError with a message naming the first violation
    found; returns None if all checks pass."""

def build_log_record(ctx: RequestContext, http_method: str, path: str, raw_body: str | None,
                      parsed: object | None, response_obj: dict | None, http_status: int,
                      internal_fault: bool = False) -> dict: ...

def build_stdlib_rejection_record(client_ip: str, client_port: int, http_method: str | None,
                                   path: str | None, headers: dict[str, str], detail: str) -> dict:
    """[RN2-1] Pure function. Builds a record for a request rejected by the
    stdlib's own request-line/header parsing or its own request-line-level
    timeout, i.e. one intercepted via the log_error() override rather than
    _handle_request(). Every _handle_request-only field (session_id, raw_body,
    parsed method, response, a definite http_status) is either None or a
    fixed marker, since none of that state exists yet at this point in the
    stdlib's own request handling -- see record shape below."""

class JSONLogWriter:
    def __init__(self, fh: TextIO) -> None: ...   # fh is opened once by main(), append mode, utf-8
    def write(self, record: dict) -> None: ...      # json.dumps + "\n", flush, all under self._lock

def sanitize_for_stderr(text: str, max_len: int = 300) -> str: ...

def headers_to_dict(msg: email.message.Message) -> dict[str, str]: ...   # see policy above

def _classify_content_length(headers: email.message.Message, max_body_bytes: int = MAX_BODY_BYTES) -> tuple[str, int | None]: ...   # see logic above
```

**Log record shape** (one JSON object per line, per plan, covering every HTTP request that reaches `_handle_request`): `ts` (ISO 8601 UTC), `client_ip`, `client_port`, `http_method` (`"GET"`/`"POST"`/etc.), `path` (e.g. `"/mcp"`, `"/"`), `headers` (dict, values as opaque strings, duplicates comma-joined), `session_id` (string or `null`), `raw_body` (decoded with `errors="replace"`, or `null` for verb/path rejections where no body was read, or one of the distinct marker strings above for 411/400/413 -- never buffered in full when over cap), `method` (parsed JSON-RPC `method` or `null`), `tool_name` / `tool_arguments` (populated only when `method == "tools/call"`, taken from the *parsed* request params, not from the tool handler's output), `response` (the exact JSON-RPC body sent, `null` for 404/405/411/400/413, or `"202 Accepted (notification)"` for notifications), `http_status` (int), `internal_fault` (bool, `true` only on records built by `_emergency_fallback`, absent/`false` otherwise).

**Stdlib-rejection log record shape** (new in Round 2, built by `build_stdlib_rejection_record` and written from both the `log_error` override and (new in Round 3) the `handle_one_request` override's `_log_blank_request_line()` helper -- a distinct, narrower shape from the one above, since most `_handle_request`-only fields don't exist yet at this point in request handling): `ts`, `client_ip`, `client_port`, `http_method` (may be `null` if the request line never parsed as `METHOD PATH VERSION` at all -- always `null` for the blank-request-line case), `path` (may be `null`, same reason), `headers` (`{}` if header parsing was never reached), `session_id: null`, `raw_body: null` (body-reading is never reached for any case this hook covers), `method: null`, `response: null`, `http_status: null` (the stdlib's own status code isn't reliably recoverable from inside `log_error`; the human-readable `detail` string below names it instead, e.g. `"code 400, message Bad request syntax (...)"`, `"Request timed out: ..."`, or `"blank request line (RFC 7230 SS3.5 leading CRLF tolerance)"`), `stdlib_rejection: true` (distinguishes this narrower record shape from a normal `_handle_request` record at a glance), `detail` (the exact `format % args` string passed to `log_error`, or the fixed blank-line description for the `handle_one_request` override's own call site).

**`initialize` result shape:** `{"protocolVersion": "2025-06-18", "serverInfo": {"name": "<honeypot's advertised name>", "version": "1.0.0"}, "capabilities": {"tools": {}}}`. `2025-06-18` is the design's chosen protocol-version string (most recent MCP spec revision date at design time) per the plan's Open Question; the honeypot advertises it unconditionally regardless of what the client requested, since the goal is to log the handshake attempt, not to negotiate correctly.

**Session-id issuance, end-to-end (concrete, no ambiguity `[RN-2]`):**
1. `_handle_request` calls `dr = dispatch(parsed, ctx)`.
2. `dispatch()`, on a successful `initialize`, mints `session_id = uuid.uuid4().hex`, stores it in `SESSIONS` (with cap/eviction -- see Components), and sets `DispatchResult.session_id` to that value. Every other method call returns `DispatchResult.session_id = None`.
3. `_handle_request` reads `dr.session_id` into `session_id_to_issue` and passes it to `self._send_response(http_status, response_obj, session_id_to_issue, ...)`.
4. `_send_response` sets the `Mcp-Session-Id` response header if and only if `session_id_to_issue is not None`, then writes status line, headers, and body bytes, then sets `self._response_sent = True`.

There is no tuple threaded through `dispatch`'s declared return type, no side channel, and no asymmetric contract between `initialize` and other methods -- `DispatchResult` is dispatch's one and only return type for every method, always.

**Connection-cap and timeout mechanics `[SEC-1]`:**

```python
class HoneypotHTTPServer(ThreadingHTTPServer):
    def __init__(self, *args, max_concurrent: int = MAX_CONCURRENT_CONNECTIONS, **kwargs):
        super().__init__(*args, **kwargs)
        self._conn_semaphore = threading.BoundedSemaphore(max_concurrent)

    def process_request(self, request, client_address):
        if not self._conn_semaphore.acquire(blocking=False):
            try:
                request.close()          # over capacity: dropped before any request line is read,
            except OSError:              # so this connection is NOT logged (nothing was parsed yet) --
                pass                     # this is structurally-unlogged case (1), see § Data Flow above
            return
        super().process_request(request, client_address)   # spawns the usual handler thread

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_semaphore.release()

class HoneypotRequestHandler(BaseHTTPRequestHandler):
    timeout = SOCKET_TIMEOUT_SECONDS   # applied automatically by socketserver.StreamRequestHandler.setup();
                                        # a stalled client's rfile.read()/readline() raises socket.timeout,
                                        # which either (a) propagates into _handle_request's outer try/except
                                        # if the stall happens mid-body (handled by _emergency_fallback), or
                                        # (b) is caught by handle_one_request's own except TimeoutError if the
                                        # stall happens before a request line is complete -- now logged via
                                        # the log_error override [RN2-1], not silently dropped as in Round 1.
```

## Testability Notes

- **No test suite is a required deliverable** (plan explicitly leaves this to design/QA discretion and marks it out of scope as a *mandate*). Given that, this design still keeps the code trivially testable without committing to writing tests as a task, by enforcing structural rules the QA phase can rely on if it chooses to add `unittest`-based tests:
  1. **Importing `mcp_honeypot` must have zero side effects.** All socket/file opening happens inside `main()`, gated by `if __name__ == "__main__":`. `python3 -c "import mcp_honeypot"` must succeed instantly and open nothing.
  2. **Protocol logic is separable from I/O.** `dispatch(msg, ctx)` and every `handle_*`/`TOOL_HANDLERS[...]` function take plain dicts/dataclasses and return plain dicts/`DispatchResult` -- no `self.rfile`/`self.wfile`, no file handle, no network. A test (or a human at a REPL) can call `dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {...}}, RequestContext(...))` directly and assert on the returned `DispatchResult` with no server running.
- **`build_log_record`, `build_stdlib_rejection_record`, `sanitize_for_stderr`, `headers_to_dict`, `_classify_content_length`, and `validate_arguments` are pure functions** over their inputs -- straightforward to test with adversarial strings (newlines, ANSI escapes, huge values, duplicate header names, malformed/wrongly-typed tool arguments, `email.message.Message` objects with repeated `Content-Length`/`Transfer-Encoding` headers) without touching the filesystem or a running server.
- **`validate_arguments`'s bool-exclusion fix is directly testable** `[RN2-2]`: calling it with a schema declaring `{"type": "integer"}` and an `arguments` value of `True`/`False` must raise `InvalidParamsError`; the same schema with an actual `int` (including `0`/`1`, which are the values most likely to be mistaken for bools) must not raise.
- **`_classify_content_length` is directly testable without a socket** `[RN2-3] [RN2-4] [RN3-2]`: construct an `email.message.Message`, call `.add_header("Content-Length", "10")` twice to get a duplicate, call `.add_header("Transfer-Encoding", "identity")` then `.add_header("Transfer-Encoding", "chunked")` to get a duplicate Transfer-Encoding (asserting it returns `"duplicate_transfer_encoding"`, not `"chunked"` or `"ok"`, confirming `.get_all()` rather than `.get()` is actually being used), or a single `.add_header("Transfer-Encoding", "chunked")`, and assert the returned `(outcome, length)` tuple for each of the five branches.
- **`-32600`/`-32602` coverage is a pure-function concern.** Non-dict top-level JSON (`42`, `"x"`, `[1,2,3]`, `true`) and missing/wrong-typed `tools/call` arguments can both be exercised without a running server: the former by calling `_handle_request`'s shape-check logic directly (or, if extracted, a standalone `classify_top_level(parsed) -> "ok" | "invalid_request"` helper), the latter by calling `handle_tools_call(params, ctx)` and asserting `InvalidParamsError` is raised.
- **The log-write failure path is testable via monkeypatching.** Since `log_writer.write` is a single method call site inside `_handle_request` (and the `log_error` override, and `_emergency_fallback` -- all three call the *same* instance), a test can substitute a `JSONLogWriter`-like object whose `write()` raises, and assert (a) the HTTP response/behavior on each of those three paths is still correct and (b) a `[honeypot] WARNING: log write failed` line appears on stderr each time.
- **The `log_error` override is testable in three ways `[RN2-1] [SEC3-a]`:** (a) directly -- instantiate a `HoneypotRequestHandler`-like object with a stubbed `client_address`/`command`/`path`/`headers`, call `.log_error("code %d, message %s", 400, "Bad request syntax")` on it, and assert `build_stdlib_rejection_record` was called with the right fields and `log_writer.write` received a record with `stdlib_rejection: true`; (b) end-to-end -- open a raw `socket.socket()` against the running server and send bytes that don't parse as an HTTP request line (e.g. `b"not an http request at all\r\n\r\n"`), or a request line over 65536 bytes, or nothing at all for longer than `SOCKET_TIMEOUT_SECONDS`, and assert `honeypot.jsonl` gains one `stdlib_rejection: true` line each time; (c) **new `[SEC3-a]`** -- monkeypatch `build_stdlib_rejection_record` (or `headers_to_dict`) to raise, call `.log_error(...)` directly, and assert `super().log_error(...)`'s effect (the stdlib's own stderr diagnostic) still occurs and no unsanitized exception/traceback reaches stderr -- confirms the full-body `try/except` wrap actually prevents a broken custom-logic path from suppressing the stdlib's own error response.
- **The `handle_one_request` blank-request-line fix is testable end-to-end `[RN3-1]`:** open a raw socket against the running server, send `b"\r\n"` immediately followed by a real, well-formed request line + headers + body on the *same* connection, and assert (a) `honeypot.jsonl` gains one `stdlib_rejection: true` record with `detail` naming the blank line, AND (b) a second, normal record for the real request that follows -- confirming the request is no longer silently dropped. A companion test sending `MAX_LEADING_BLANK_REQUEST_LINES + 1` consecutive blank lines before any real request line should observe exactly `MAX_LEADING_BLANK_REQUEST_LINES` logged blank-line records followed by the connection closing with no further record for the final (bound-exceeding) blank line -- the one documented, bounded-by-design residual gap (see § Data Flow).
- **The emergency-fallback path is testable by forcing an exception upstream of dispatch**, e.g. monkeypatching `self.rfile.read` to raise, and asserting the handler still returns *some* HTTP response, `self._response_sent` ends up `True`, and the process doesn't crash.
- **Response-sent double-send/zero-send regressions are directly testable `[RN2-5]`:** monkeypatch `_send_response` to raise partway through (after starting to write headers but before completing), call `_handle_request`, and assert `_emergency_fallback` still attempts (and that the test can observe) exactly one attempted response -- not two, not zero.
- **End-to-end smoke testing** (manual or QA-added) is straightforward via stdlib `http.client` or `curl` against `127.0.0.1:<port>` since the transport is plain HTTP/JSON -- no SSE, no auth, no TLS to negotiate.
- **Concurrency correctness** (the `threading.Lock` around the log writer and session dict, and the `BoundedSemaphore` connection cap) is awkward to unit-test meaningfully; the practical approach is a smoke test that fires N concurrent POSTs (e.g. via `concurrent.futures.ThreadPoolExecutor` driving `http.client` calls) and asserts the resulting `honeypot.jsonl` has exactly N well-formed JSON lines (no interleaved/corrupted lines), and a separate smoke test that opens `MAX_CONCURRENT_CONNECTIONS + a few` raw sockets without sending a request line, confirming the server continues to serve ordinary requests rather than exhausting threads.
- **Session-cap eviction is directly testable** by temporarily monkeypatching `MAX_SESSIONS` to a small number (e.g. 3) in a test process, issuing more than that many `initialize` calls through `dispatch()` directly (no server needed), and asserting `len(SESSIONS) == MAX_SESSIONS` with the earliest-issued id evicted.
- **Safety-constraint verification is largely static, not runtime-testable in the traditional sense** -- the strongest check is `grep`/read-through confirming the forbidden identifiers (`eval(`, `exec(`, `subprocess`, `socket.socket`, `urllib`, `importlib`, `open(` outside the one log-file call site) don't appear in tool handlers or dispatch code. This is called out explicitly as an acceptance criterion in Tasks 3 and 4 so the code-review and security-review passes have something concrete to grep for, not just prose to trust.

## Task Breakdown

1. **HTTP server, universal request lifecycle (including stdlib-rejection logging), and logging core.** Create `mcp_honeypot.py` at the repo root with:
   - `build_arg_parser`/`main` (CLI flags `--host` 127.0.0.1, `--port` 8000, `--log-file` ./honeypot.jsonl, all side effects gated behind `if __name__ == "__main__":`); no additional CLI flags.
   - Module-level constants `MAX_BODY_BYTES = 1_048_576`, `SOCKET_TIMEOUT_SECONDS = 10`, `MAX_CONCURRENT_CONNECTIONS = 200`, `MAX_SESSIONS = 10_000` (the last one is wired in Task 2, but declare it here alongside the others), `MAX_LEADING_BLANK_REQUEST_LINES = 5` (new in Round 3, wired into the `handle_one_request` override below `[RN3-1]`).
   - `HoneypotHTTPServer(ThreadingHTTPServer)` with the `BoundedSemaphore`-based connection cap (`process_request`/`process_request_thread` overrides, exactly as specified in § Data Flow).
   - `HoneypotRequestHandler(BaseHTTPRequestHandler)` with `timeout = SOCKET_TIMEOUT_SECONDS`, and `do_GET`/`do_POST`/`do_PUT`/`do_PATCH`/`do_DELETE`/`do_HEAD`/`do_OPTIONS` all delegating to one shared `_handle_request(self, http_method: str)`.
   - `_handle_request` implementing the full lifecycle from § Data Flow: `self._response_sent = False` set first; path check (non-`/mcp` -> 404, empty body); method check (`/mcp` + non-`POST` -> 405, empty body, `Allow: POST`); `_classify_content_length(self.headers)` five-way branch (`"ok"` -> read+decode body; `"chunked"` -> 411 with its distinct marker `[RN2-3]`; `"duplicate_content_length"` -> 400 with its distinct marker `[RN2-4]`; `"duplicate_transfer_encoding"` -> 400 with its own distinct marker, same treatment as duplicate Content-Length `[RN3-2]`; `"missing_or_invalid"` -> 413 with its distinct marker); UTF-8 decode with `errors="replace"`; `json.loads` attempt producing `parsed: object | None`; a shape check that runs `isinstance(parsed, dict) and isinstance(parsed.get("method"), str)` **before** any dict-only operation on `parsed`, routing non-conforming-but-valid JSON to a `-32600 Invalid Request` response built directly (not via `dispatch()`); `RequestContext` dataclass; `headers_to_dict` (duplicate headers comma-joined).
   - `dispatch()` as a stub in this task only (always returns `DispatchResult(response=_build_error(..., -32601, "Method not found"), session_id=None)` for any method, or the `-32700`/`-32600` paths handled above it) -- full method table lands in Task 2, but `_handle_request` must already call `dispatch()` with its final signature (`msg: dict, ctx: RequestContext) -> DispatchResult`) so Task 2 doesn't have to touch the transport layer.
   - `JSONLogWriter` (single file handle opened once in `main()`, `threading.Lock`-guarded `write()` that appends one `json.dumps(record) + "\n"` and flushes before returning; this is the **one and only** instance that `_handle_request`, the `log_error` override, and `_emergency_fallback` all write through `[SEC2-c]`); `build_log_record` (including `http_method`/`path`/`internal_fault` fields); `build_stdlib_rejection_record` (new, per § Data Flow); `sanitize_for_stderr` (strips `[\x00-\x1f\x7f]` control chars, truncates to a bounded length); `emit_stderr_summary`.
   - The log-then-respond glue: build `response_obj` → `build_log_record` → `log_writer.write(record)` wrapped in its own local `try/except Exception` (on failure, print a `[honeypot] WARNING: log write failed: ...` sanitized stderr line, then continue) → `emit_stderr_summary(record)` → `_send_response(...)` which sets `self._response_sent = True` immediately after its write completes `[RN2-5]`.
   - One outer `try/except Exception` wrapping the *entire* `_handle_request` body (context build through response send), with `_emergency_fallback(self, http_method)` as the except-branch handler: checks `self._response_sent` before attempting its own send (setting it `True` only after that send succeeds), writes its best-effort record through the *same* `log_writer`, and writes a plain stderr line -- each of the three independently wrapped in its own `try/except Exception: pass`, exactly as specified in § Data Flow.
   - override `log_error(self, format: str, *args) -> None` on `HoneypotRequestHandler` exactly as specified in § Data Flow ("Universal logging via a `log_error` override") -- builds and writes a `build_stdlib_rejection_record(...)` through `log_writer`, calls `emit_stderr_summary`, then delegates to `super().log_error(format, *args)` `[RN2-1]`. **New in Round 3:** the entire body of `log_error()` (not just the `log_writer.write()` call) is wrapped in one `try/except Exception: pass`, so `super().log_error(...)` always runs regardless of what fails above it `[SEC3-a]`.
   - **New in Round 3 `[RN3-1]`:** override `handle_one_request(self) -> None` on `HoneypotRequestHandler` and add a private `_log_blank_request_line(self) -> None` helper, exactly as specified in § Data Flow ("Universal logging via a `handle_one_request` override") -- catches the one case `log_error()` structurally cannot see (a blank/whitespace-only first request line), logs it, and loops to read the real request line, bounded by `MAX_LEADING_BLANK_REQUEST_LINES`. Requires adding `from http import HTTPStatus` to the file's imports (see updated stdlib module list in § Architecture Overview).
   - Add `/honeypot.jsonl` to `.gitignore` (repo root, next to the existing `# Python` section).

   **Acceptance:**
   - `python3 mcp_honeypot.py` starts and binds `127.0.0.1:8000`.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -d '{"jsonrpc":"2.0","id":1,"method":"x"}'` returns HTTP 200 with a JSON-RPC `-32601` body; `honeypot.jsonl` gains exactly one well-formed JSON line with `http_method: "POST"`, `path: "/mcp"`, `http_status: 200`.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -d '42'`, `-d '[1,2,3]'`, `-d 'true'`, and `-d '{"id":1}'` (no `"method"`) each return HTTP 200 with a `-32600 Invalid Request` body, no server crash/traceback, and each produces one JSONL line.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -d 'not json'` returns a `-32700` body and is logged.
   - `curl -X GET http://127.0.0.1:8000/mcp` and `curl -X DELETE http://127.0.0.1:8000/mcp` each return 405 with empty body and an `Allow: POST` header, **and each produces one JSONL line** (`http_status: 405`, `response: null`) -- this is the concrete regression test for `[RN-1]`.
   - A bogus path (e.g. `curl http://127.0.0.1:8000/nope`) returns 404 with empty body **and produces one JSONL line** (`http_status: 404`).
   - A body larger than `MAX_BODY_BYTES` returns 413 without the process reading the full body into memory, and is still logged with the `"missing, invalid, or oversized Content-Length"` marker instead of the raw body.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -H "Transfer-Encoding: chunked" --data-binary '...'` (or `http.client` with `Transfer-Encoding: chunked` set manually) returns **HTTP 411**, not 413, and is logged with the `"Transfer-Encoding: chunked not supported"` marker -- concrete regression test for `[RN2-3]`.
   - A raw request with two `Content-Length` headers (constructible via `http.client.HTTPConnection.putheader` called twice, or a raw socket) returns **HTTP 400**, not 413, and is logged with the `"duplicate Content-Length headers"` marker -- concrete regression test for `[RN2-4]`.
   - A raw request with two `Transfer-Encoding` headers (e.g. `identity` then `chunked`, constructible via a raw socket or `http.client.HTTPConnection.putheader` called twice) returns **HTTP 400**, not 411/200, and is logged with the `"duplicate Transfer-Encoding headers"` marker -- concrete regression test for `[RN3-2]`.
   - `wc -l honeypot.jsonl` after each of the above requests increases by exactly 1 each time -- no request in this task's test matrix is silently dropped.
   - Stderr prints one sanitized single-line summary per request with no raw newlines/control chars even when the request body/headers contain them.
   - A client that opens a raw TCP connection to the port and sends nothing for longer than `SOCKET_TIMEOUT_SECONDS` causes that connection to be closed by the server, **and produces one JSONL line with `stdlib_rejection: true`** (concrete regression test for `[RN2-1]`'s "stall before any request line" case) -- verify via `socket.timeout`-triggered cleanup (handler thread count / open-fd count returns to baseline) without hanging the server or blocking other requests.
   - A raw socket sending a non-HTTP-conforming line (e.g. `b"garbage not a request\r\n\r\n"`) or a request line over 65536 bytes produces one JSONL line with `stdlib_rejection: true` and a `detail` string naming the stdlib's own rejection reason -- concrete regression test for `[RN2-1]`'s other two cases.
   - A raw socket that sends `b"\r\n"` (a blank leading request line) immediately followed by a real, well-formed request on the same connection produces **two** JSONL lines: one `stdlib_rejection: true` record for the blank line, and one normal record for the real request that follows -- concrete regression test for `[RN3-1]`, confirming the real request is no longer silently dropped.
   - A raw socket sending `MAX_LEADING_BLANK_REQUEST_LINES + 1` consecutive blank lines before any real request line produces exactly `MAX_LEADING_BLANK_REQUEST_LINES` `stdlib_rejection: true` records, then the connection closes with no further record for the final, bound-exceeding blank line -- concrete regression test for the documented bounded-by-design residual (see § Data Flow).
   - Monkeypatching `build_stdlib_rejection_record` to raise and then triggering any stdlib-rejection case (e.g. a >65536-byte request line) still results in `super().log_error(...)`'s own stderr diagnostic being printed, no unhandled exception/unsanitized traceback reaching stderr, and the server continuing to serve subsequent requests normally -- concrete regression test for `[SEC3-a]`.
   - Opening `MAX_CONCURRENT_CONNECTIONS + 5` raw sockets simultaneously (without completing a request) does not exhaust threads or crash the server; the extra connections beyond the cap are closed by the server without a response and without a log line (one of the two genuinely structurally-unloggable cases named in § Data Flow's updated three-item list).
   - `python3 -c "import mcp_honeypot"` opens no sockets/files (no `honeypot.jsonl` created by import alone).

2. **Session-aware JSON-RPC dispatch: initialize, notifications/initialized, ping, and the -32600/-32602/-32603 error paths.** Replace the Task 1 dispatch stub with the real `dispatch(msg: dict, ctx: RequestContext) -> DispatchResult` and `METHODS` table (per the exact signature and behavior specified in § Data Flow). Implement:
   - `handle_initialize` (returns `protocolVersion: "2025-06-18"`, `serverInfo`, `capabilities: {"tools": {}}}` -- no session-id logic in the handler itself; `dispatch()` owns minting/storing the session id after a successful call).
   - `handle_notifications_initialized` (no-op, returns `{}`, side-effect free).
   - `handle_ping` (returns `{}`).
   - `SESSIONS: OrderedDict[str, dict]` + `SESSIONS_LOCK`, with `dispatch()` minting `uuid.uuid4().hex` on a successful `initialize`, evicting the oldest entry via `SESSIONS.popitem(last=False)` when `len(SESSIONS) >= MAX_SESSIONS` before inserting the new one, all under `SESSIONS_LOCK`.
   - `InvalidParamsError` exception class and `dispatch()`'s `try/except InvalidParamsError` (→ `-32602`) / `except Exception` (→ `-32603`) wrapping around each handler call (no handler raises `InvalidParamsError` yet in this task -- that lands in Task 3 with `handle_tools_call` -- but the plumbing must exist and be exercised by a temporary/throwaway manual test during this task).
   - Notification handling: any parsed message lacking `"id"` still gets dispatched for side effects (`DispatchResult.response = None`); `_handle_request` (from Task 1, unmodified) maps that to HTTP 202 empty body, logged with `response = "202 Accepted (notification)"`.
   - `Mcp-Session-Id` response header set by `_handle_request` from `dr.session_id` whenever it's not `None` (Task 1's `_send_response` already accepts this parameter -- wire the real value through now).

   **Acceptance:**
   - `initialize` request returns a well-formed result with the fields above and an `Mcp-Session-Id` response header containing a fresh `uuid4().hex` value on every call (not reused).
   - A follow-up `notifications/initialized` (no `"id"`) returns HTTP 202 with empty body and is still logged.
   - `ping` returns `{"jsonrpc":"2.0","id":<echoed>,"result":{}}`.
   - A request with an unknown method (and an `"id"`) returns a `-32601` JSON-RPC error, HTTP 200.
   - Issuing more than `MAX_SESSIONS` `initialize` calls in a row (test with a monkeypatched small `MAX_SESSIONS`, e.g. 3, per the Testability Notes approach) keeps `len(SESSIONS)` capped at the limit with the earliest-issued session id evicted first.
   - The `-32600` regression tests from Task 1 (non-dict/non-object top-level JSON) still pass unchanged now that real `dispatch()` wiring is in place, confirming the shape-check-before-dispatch ordering from `[RN-4]` holds end-to-end.
   - The server process never exits/crashes across any of the above, including when a handler is temporarily made to raise during manual testing (confirms `-32603` still fires correctly; remove any such debug hook before finishing the task).

3. **Fake tool catalog + tools/list + tools/call + -32602 argument validation.** Define `TOOLS` (four entries -- a file reader e.g. `read_file`, a database query runner e.g. `query_database`, a credential/secret lookup e.g. `get_credential`, an outbound email sender e.g. `send_email` -- each with a realistic `name`, `description`, and a JSON Schema `inputSchema` that declares `"type": "object"`, a non-empty `"required"` list, and `"properties"` with per-argument `"type"`) and `TOOL_HANDLERS` (pure functions, one per tool, each takes only the parsed `arguments` dict and returns an MCP `tools/call` content result -- `{"content": [{"type": "text", "text": "..."}], "isError": false}` -- built purely from string formatting/echoing the caller's arguments; explicitly no `open()`, `subprocess`, `socket`, `urllib`, `eval`, `exec`, or dynamic `import` anywhere in these functions or their call path; the "secret" returned by `get_credential` must be an obviously-synthetic placeholder value, not something realistic-looking).

   Implement `_SCHEMA_TYPE_CHECKS` and `validate_arguments(schema, arguments)` (pure, per § Data Flow signature -- **including the `[RN2-2]` bool-exclusion fix**: `"integer"`/`"number"` checks must explicitly reject `bool` values via `isinstance(v, bool)` checked before/instead-of a bare `isinstance(v, int)`) and `handle_tools_list` (returns `{"tools": TOOLS}`) and `handle_tools_call` (validates `params["name"]` is a string and `params.get("arguments", {})` is an object, raising `InvalidParamsError` on violation *before* any tool lookup; looks up the tool -- unknown name returns a JSON-RPC **result** with `isError: true` and an explanatory message, not an error/exception; a known tool's arguments are checked with `validate_arguments` against its `inputSchema`, raising `InvalidParamsError` -- and therefore surfacing as `-32602` via `dispatch()`'s existing wiring from Task 2 -- on a missing required argument or a wrongly-typed one (including a bool passed where `"integer"`/`"number"` is declared); on success, calls the matched `TOOL_HANDLERS[name](arguments)`).

   Extend `build_log_record` (from Task 1) so that when `method == "tools/call"`, `tool_name` and `tool_arguments` are populated straight from the parsed request `params`, never from the tool's fabricated output.

   **Acceptance:**
   - `tools/list` returns exactly 4 tools, each with a non-empty `name`/`description` and a valid JSON Schema object (with `required` and `properties`) under `inputSchema`.
   - `tools/call` against each of the 4 tools, with all required arguments present and correctly typed, returns a `content` array whose text echoes back at least one caller-supplied argument.
   - `tools/call` with a required argument omitted returns HTTP 200 with a `-32602 Invalid params` JSON-RPC error (not `isError: true`, not a crash), and is logged with `tool_name`/`tool_arguments` populated from the request.
   - `tools/call` with a required argument present but the wrong JSON-Schema-declared type (e.g. a number where `"type": "string"` is declared) also returns `-32602`.
   - **New `[RN2-2]`:** `tools/call` with a required argument declared `"type": "integer"` (or `"number"`) but supplied as a JSON `true`/`false` returns `-32602`, not a success -- concrete regression test for the bool-subclass-of-int fix. A companion test with an actual `0`/`1` integer for the same field must succeed, confirming the fix doesn't over-reject real integers.
   - `tools/call` with an unrecognized tool name returns a well-formed `isError:true` result (HTTP 200, `result` not `error`), connection stays alive.
   - `grep -nE "eval\(|exec\(|subprocess|urllib|socket\.socket|importlib" mcp_honeypot.py` matches nothing inside the tool-handler section (and none of the tool handler functions call `open()`).

4. **CLI finishing touches, safety self-check, and README.** Finalize `--host`/`--port`/`--log-file` argparse help text and defaults (confirm log path resolves relative to CWD at start, per plan); confirm the log file is opened once in append mode in `main()` and the handle is reused for the process lifetime (not reopened per request); confirm `MAX_BODY_BYTES`, `SOCKET_TIMEOUT_SECONDS`, `MAX_CONCURRENT_CONNECTIONS`, `MAX_SESSIONS`, `MAX_LEADING_BLANK_REQUEST_LINES` are all named module-level constants (not magic numbers scattered through the file); do a full read-through/grep pass over the finished file confirming no forbidden identifiers (`eval(`, `exec(`, `subprocess`, `socket.socket`, `urllib`, `importlib`, `open(` outside the single log-file open call in `main()`) appear anywhere; add a short comment block near the top of `mcp_honeypot.py` stating the non-negotiable safety invariants (no real I/O beyond the log file, no outbound network, no dynamic execution of client-derived data).

   Update root `README.md` (currently a one-line stub) by adding one paragraph covering: how to run it (`python3 mcp_honeypot.py [--host H] [--port P] [--log-file PATH]`); where logs go (JSONL at `--log-file`, default `./honeypot.jsonl` relative to CWD, plus the sanitized stderr mirror); how to point an MCP client at it (`http://<host>:<port>/mcp`, streamable-HTTP transport, single-request/response only -- no SSE); and the following explicit caveats (not silent gaps `[SEC-4]`):
   - Default bind (`127.0.0.1`) is safe for local testing; rebinding to `0.0.0.0` to expose it as a real decoy is an explicit opt-in risk.
   - Built-in resource-exhaustion mitigations that do exist in v1 -- a `SOCKET_TIMEOUT_SECONDS` (10s) **per-read** timeout per connection (explicitly note this is a per-I/O idle timeout, not a total-connection-duration budget `[SEC2-a]`) and a `MAX_CONCURRENT_CONNECTIONS` (200) hard cap -- and that these are fixed constants near the top of the source file, not CLI flags, if an operator needs to tune them.
   - `honeypot.jsonl` has **no rotation, size cap, or retention limit** in v1; unbounded disk growth under sustained traffic is an explicit operator responsibility, not something the tool manages `[SEC-4]`. **New in Round 3 `[SEC3-b]`:** this includes rejected/malformed traffic, not just successfully-dispatched requests -- the `log_error`/`handle_one_request` overrides (see below) mean garbage/scanner traffic that the stdlib itself rejects (bad request lines, oversized headers, blank leading lines, etc.) now also writes and flushes a JSONL line each, so disk growth tracks *all* inbound connection attempts, not only well-formed JSON-RPC ones.
   - `Transfer-Encoding: chunked` requests are rejected outright (HTTP 411), and duplicate `Content-Length` or duplicate `Transfer-Encoding` headers are each rejected outright (HTTP 400) -- v1's scope is simple JSON-RPC-over-POST, not general-purpose HTTP framing `[RN2-3] [RN2-4] [RN3-2]`.
   - Three narrow, named cases remain where "every request is logged" doesn't fully hold, precisely enumerated rather than approximated: two are genuinely structurally unloggable (connections refused at the `MAX_CONCURRENT_CONNECTIONS` cap, and a client that opens a connection and closes it again having sent zero bytes -- no timeout, no error, no stdlib hook fires at all in either case); the third is deliberately bounded rather than eliminated (more than `MAX_LEADING_BLANK_REQUEST_LINES`, default 5, consecutive blank/whitespace-only leading lines before a real request line ever arrives -- everything up to that bound is logged, only a run longer than it silently drops the final line). Everything else -- including malformed/oversized request lines, unsupported HTTP verbs/versions, oversized headers, a client stalling before completing a request line, and (new in Round 3) a single leading blank request line (the RFC 7230 SS3.5-recommended case, and the specific gap this revision closed) -- is now logged via the `log_error` and `handle_one_request` overrides `[RN2-1] [RN3-1]`.

   **Acceptance:**
   - `python3 mcp_honeypot.py --help` documents all three flags with their defaults (still exactly three -- no new flags added).
   - `README.md` contains the new paragraph(s) with run/log-location/client-URL/exposure-warning/disk-growth-including-rejected-traffic/chunked-and-duplicate-Content-Length-and-Transfer-Encoding/three-item-unlogged-cases content described above, appended to (not replacing) the existing project description.
   - The safety grep from Task 3's acceptance criterion, re-run against the complete file, still matches nothing.
   - A fresh clone + `python3 mcp_honeypot.py` + one `curl` round-trip + `Ctrl-C` leaves behind only `honeypot.jsonl` (already gitignored) with no other file writes anywhere on disk.

---

## Round 1 finding disposition (summary)

**review-notes.md:**
1. Blocking -- universal logging now covers every HTTP request (404/405/413/200/202), with two explicitly named stdlib-layer exceptions; see § Architecture Overview, § Data Flow, Task 1.
2. Major -- `dispatch()` now has one concrete signature (`-> DispatchResult`) end-to-end; session-id issuance path fully specified in § Data Flow, "Session-id issuance, end-to-end."
3. Major -- `-32602` implemented via `InvalidParamsError` + `validate_arguments`, wired in `dispatch()` (Task 2) and exercised by `handle_tools_call` (Task 3) with explicit acceptance criteria.
4. Major -- `isinstance(parsed, dict)` (plus a `method`-is-string check) now runs before any dict-only access on `parsed`; non-conforming JSON routes to `-32600` instead of raising.
5. Major -- dropped the header-less-fallback-correlation claim from Components; `RequestContext.session_id` and the Session store bullet are now consistent (header-only, no fallback, stated explicitly).
6. Major -- log write wrapped in its own local try/except with a stderr fallback; the entire request lifecycle wrapped in one outer try/except with `_emergency_fallback`.
7. Minor -- `headers_to_dict` specifies and implements a comma-join policy for duplicate headers.
8. Minor -- `SOCKET_TIMEOUT_SECONDS = 10` class-attribute timeout specified and tasked.
9. Minor -- 404/405/413 response shapes specified precisely (empty body, 405 adds `Allow: POST`).

**security-plan-review.md:**
1. Major -- `SOCKET_TIMEOUT_SECONDS` timeout plus `MAX_CONCURRENT_CONNECTIONS` semaphore-bounded connection cap on `HoneypotHTTPServer`, both specified and tasked.
2. Major -- `SESSIONS` is now an `OrderedDict` capped at `MAX_SESSIONS` with oldest-first eviction.
3. Major -- outer try/except now wraps the entire `_handle_request` lifecycle (body read, decode, parse, dispatch, log, respond), not just `dispatch()`'s internals.
4. Minor -- unbounded JSONL growth stated explicitly as an operator responsibility in the README (Task 4), not left silent.
5. Minor -- reliance on stdlib header-count/line-length limits stated explicitly in § Architecture Overview.

## Round 2 finding disposition (summary)

**review-notes.md § Round 2:**

| # | Severity | Finding | Resolved in |
|---|---|---|---|
| 1 | major | "Two named exceptions to universal logging" undercounted three more structurally-loggable-but-unlogged cases (malformed/oversized request line, unsupported HTTP version/oversized headers, pre-request-line stall). | New `log_error` override on `HoneypotRequestHandler` intercepts all of these plus Round 1's "unimplemented verb" exception, via the stdlib's own single `log_error` hook (called by `send_error()` and by `handle_one_request()`'s `except TimeoutError` branch). New `build_stdlib_rejection_record` + `stdlib_rejection: true` log field. Exactly two cases remain, both now genuinely structurally unloggable (no stdlib hook fires at all) and precisely named: the `MAX_CONCURRENT_CONNECTIONS` semaphore-cap drop, and a zero-byte clean-EOF connection. See § Architecture Overview ("Every request..." bullet, "Stated reliance..." subsection), § Data Flow ("Universal logging via a `log_error` override" through "what's covered and what genuinely isn't"), § Components (HTTP handler bullet), Task 1 (implementation + 3 new acceptance criteria). |
| 2 | minor | `validate_arguments`'s `"integer"`/`"number"` type checks would incorrectly accept Python `bool` (a subclass of `int`). | `_SCHEMA_TYPE_CHECKS` dict now explicitly excludes `bool` from `"integer"`/`"number"` via `isinstance(v, bool)` checked ahead of/alongside `isinstance(v, int)`. See § Data Flow ("Core function signatures," `_SCHEMA_TYPE_CHECKS`), § Components (Fake tool catalog bullet), Task 3 (implementation + new acceptance criterion with both a rejected-bool and an accepted-real-integer test). |
| 3 | minor | `Transfer-Encoding: chunked` requests were conflated with oversized/invalid `Content-Length` under the same 413 marker. | New `_classify_content_length()` four-way classification (`"ok"`/`"chunked"`/`"duplicate"`/`"missing_or_invalid"`); chunked now gets its own HTTP 411 status and a distinct log marker, never bucketed with 413. See § Data Flow (request-lifecycle pseudocode, "400/404/405/411/413 response shapes," `_classify_content_length` code block), Task 1 (implementation + acceptance criterion), Task 4 (README caveat). |
| 4 | minor | Duplicate `Content-Length` headers were unaddressed, left to implicit stdlib behavior. | Same `_classify_content_length()` function's `"duplicate"` branch (via `headers.get_all(...)`, since `.get()` silently returns only the first value) now returns a distinct HTTP 400 with its own log marker, rejected outright per RFC 7230 SS3.3.2 guidance. See same locations as finding 3 above. |
| 5 | minor | `_emergency_fallback`'s "has a response been sent" tracking mechanism was unspecified. | Explicit `self._response_sent` instance attribute: initialized `False` at the top of every `_handle_request` call, set `True` only immediately after `_send_response`'s (or `_emergency_fallback`'s own) socket write actually completes, checked by `_emergency_fallback` before attempting its own send. See § Data Flow ("Response-sent tracking, exact mechanism"), § Components (HTTP handler bullet), Task 1 (implementation), Testability Notes (new direct-test bullet). |

**security-plan-review.md § Round 2 (verdict APPROVED; 3 non-blocking minor notes folded in as requested):**

| Note | Disposition |
|---|---|
| (a) `SOCKET_TIMEOUT_SECONDS` is per-I/O, not total-duration | Explicitly documented as an accepted v1 tradeoff rather than fixed with a new watchdog thread, given the existing `MAX_CONCURRENT_CONNECTIONS` cap already bounds the worst case (independently verified non-blocking by security review). See § Architecture Overview ("Total-duration vs. per-read timeout, an accepted tradeoff"), Task 4 (README caveat spelling out the per-read-not-total-duration distinction). |
| (b) incomplete "two named exceptions" list has the same root cause as review-notes.md finding 1 | Resolved by the same `log_error` override fix -- see review-notes.md finding 1's row above. |
| (c) whether `_emergency_fallback`'s JSONL write reuses the lock-guarded `JSONLogWriter.write()` | Made explicit: `_emergency_fallback` writes through the *same* `log_writer` instance (and therefore the same `threading.Lock`) as every other logging call site in the file -- stated as a named property, not left implicit. See § Architecture Overview (Logging layer bullet), § Data Flow (`_emergency_fallback` description, step 2), § Components (Logging core bullet), Task 1 (implementation note). |
## Round 3 finding disposition (summary)

**review-notes.md § Round 3:**

| # | Severity | Finding | Resolved in |
|---|---|---|---|
| 1 | major | The `log_error()` fix from Round 2 still missed one case: `parse_request()`'s `if len(words) == 0: return False` branch (a blank/whitespace-only first request line) returns `False` without ever calling `send_error()`/`log_error()`, so the Round 2 override can never see it -- verified empirically against live CPython 3.14 (`b"\r\n"` produces zero response bytes and zero `log_error` calls). RFC 7230 SS3.5 recommends servers tolerate exactly this leading-blank-line pattern, meaning the *entire subsequent request* was silently lost with zero trace, not just the blank line -- exactly the scanner/probe traffic this honeypot most wants to capture. | New `handle_one_request()` override (a near-verbatim reproduction of the stdlib version with one inserted check) detects a blank/whitespace-only leading request line directly -- since it cannot be caught via `log_error()` -- logs it via a new `_log_blank_request_line()` helper (reusing `build_stdlib_rejection_record`), then loops to read the real request line, mirroring RFC 7230 SS3.5's own "SHOULD ignore" guidance. Bounded by a new `MAX_LEADING_BLANK_REQUEST_LINES = 5` constant so the fix itself can't become an unbounded per-connection read/log loop. The "what's covered and what genuinely isn't" list is corrected from an asserted "two" to a precisely-derived three items: two genuinely structurally-unloggable (semaphore-cap drop, zero-byte clean EOF) plus one bounded-by-design residual (more than `MAX_LEADING_BLANK_REQUEST_LINES` consecutive blank lines). See § Architecture Overview (Transport layer bullet, HTTP handler bullet, stdlib module list), § Components (constants bullet), § Data Flow ("Universal logging via a `handle_one_request` override" through the updated "what's covered and what genuinely isn't"), Task 1 (implementation + 3 new acceptance criteria), Task 4 (README caveat rewritten to name three cases, not two). |
| 2 | minor | `_classify_content_length()`'s `Transfer-Encoding` check used `headers.get(...)` (first-occurrence only), inconsistent with the `get_all()` + explicit duplicate-detection already applied to `Content-Length`. A request with two `Transfer-Encoding` headers disagreeing on value could be misclassified. | `_classify_content_length()` now calls `headers.get_all("Transfer-Encoding")` and returns a new, distinct `"duplicate_transfer_encoding"` outcome (-> HTTP 400, own log marker, same "rejected outright regardless of agreement" policy already used for duplicate `Content-Length`) when more than one is present, checked before interpreting a single value. See § Data Flow (`_classify_content_length` code block, request-lifecycle pseudocode, "400/404/405/411/413 response shapes"), § Components, Task 1 (implementation + new acceptance criterion), Task 4 (README caveat), Testability Notes. |

**security-plan-review.md § Round 3 (verdict APPROVED; 3 minor notes, 2 folded in as requested, 1 documentation-only with no action needed):**

| Note | Disposition |
|---|---|
| (a) `log_error()` only wrapped the `log_writer.write()` call, not `build_stdlib_rejection_record`/`headers_to_dict`/`format % args` -- a bug in any of those could skip `super().log_error(...)` and leak an unsanitized traceback to stderr via `socketserver`'s generic `handle_error()`. | `log_error()`'s entire body is now wrapped in one `try/except Exception: pass`, mirroring `_handle_request`'s own outer-try-except pattern, with `super().log_error(format, *args)` called unconditionally afterward, outside the try, so it always runs exactly once regardless of what fails above it. See § Data Flow (`log_error` code block, `[SEC3-a]`), § Components (HTTP handler bullet), Task 1 (implementation + new acceptance criterion), Testability Notes. |
| (b) Task 4's README disk-growth caveat predates the `log_error` override and reads as if growth comes only from valid/dispatched traffic; should note rejected/malformed traffic also contributes now. | Task 4's disk-growth caveat now explicitly states that rejected/malformed traffic (stdlib-rejected bad request lines, oversized headers, blank leading lines, etc.) also writes and flushes a JSONL line each, alongside dispatched requests. See Task 4 README caveats, `[SEC3-b]`. |
| (c) `build_stdlib_rejection_record`'s `http_status: null` relies on a free-text `detail` string rather than a structured field -- a reasonable, already-acknowledged limitation, purely documentation, no action needed. | No design change made, per the security review's own assessment that this is documentation-only with no action needed. |

**Verdict tracking:** `review-notes.md` Round 3 verdict was CHANGES REQUESTED (1 major, 1 minor -- both resolved above); `security-plan-review.md` Round 3 verdict was APPROVED (3 non-blocking minor notes -- 2 folded in above, 1 needs no action per the security reviewer's own note).
