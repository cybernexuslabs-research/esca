# Design: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Purpose: A decoy MCP server that appears to expose useful tools, logs everything a client does, and never performs any real action. Intended for observing how LLM agents and automated scanners interact with untrusted MCP servers.

Scope for v1: Single file, stdlib plus at most one small dependency. No database, no web UI, no alerting. Getting complete, well-structured logs is the only goal.

Protocol surface: Serve MCP over streamable HTTP on a configurable host/port (default 127.0.0.1:8000). Handle enough JSON-RPC 2.0 to keep a real client talking: initialize (return protocolVersion, serverInfo, capabilities [tools only]), notifications/initialized, tools/list (return the fake tool catalog), tools/call (return canned fake results), ping. Any unknown method returns a well-formed JSON-RPC error rather than crashing or closing the connection. Malformed JSON gets a -32700 parse error and is still logged.

Fake tool catalog: Four tools with realistic names, descriptions, and JSON Schemas -- plausible enough that an agent would try them, e.g. a file reader, a database query runner, a credential/secret lookup, and an outbound email sender. Each returns static or templated fake data. Nothing touches the filesystem, network, shell, or any real service.

Logging: Append one JSON object per line to a JSONL file (default ./honeypot.jsonl): ISO 8601 UTC timestamp; source IP and port; request HTTP headers (at minimum User-Agent); session identifier, if the client provides one; the raw request body as received; the parsed method name, and for tools/call the tool name and full arguments; the response the honeypot returned. Log before responding so nothing is lost if a handler raises. Also mirror a one-line human-readable summary to stderr. **Revised in this round:** "one record per HTTP request" is now literal — every request that reaches the handler (including 404s for unknown paths, 405s for wrong methods, and 413s for oversized bodies) produces exactly one JSONL record and one stderr line, not just successfully-dispatched JSON-RPC exchanges. See § Data Flow / Interfaces for the two narrow, explicitly-named exceptions where this is enforced by the stdlib layer instead of our code.

Safety rules (non-negotiable): Never eval, exec, subprocess, or import anything derived from client input. Never make outbound network requests. Never read or write files outside the log path. Log file is append-only; treat every logged value as untrusted text.

Deliverables: The honeypot source file. A one-paragraph README: how to run it, where logs go, how to point an MCP client at it for testing.

---

**Round 1 review disposition.** This revision resolves all 9 `review-notes.md` findings and all 5 `security-plan-review.md` findings from Round 1. A per-finding summary is at the end of this document; the numbered findings are referenced inline as `[RN-#]` (review-notes.md) and `[SEC-#]` (security-plan-review.md) at the point each is resolved.

## Architecture Overview

This is a greenfield addition to an otherwise-empty repo (`.claude/`, `.loop-templates/`, `.gitignore`, and a one-paragraph `README.md` are the only existing files; there is no prior Python code or toolchain to fit into — confirmed via `find . -maxdepth 3`). No scaffolding phase is needed beyond the file itself: this is a stdlib-only, single-file Python 3.10+ program, so there is no package manager, build system, or lint config to initialize — `python3 mcp_honeypot.py` is the entire toolchain, and `python3 -m py_compile mcp_honeypot.py` / `python3 -c "import ast; ast.parse(open('mcp_honeypot.py').read())"` stand in for a "build" step during development.

The whole system is one process, one file, three logical layers stacked inside it, in this order:

1. **Transport layer** — a `HoneypotHTTPServer(ThreadingHTTPServer)` subclass that adds a bounded concurrent-connection cap, plus a `HoneypotRequestHandler(BaseHTTPRequestHandler)` subclass that owns the socket, HTTP method/path routing, a per-connection read timeout, request-body reading with a hard size cap, and writing the HTTP response. **Every** request this layer accepts — regardless of path, method, or outcome — is funneled through one shared method, `_handle_request(self, http_method: str)`, so logging is universal rather than conditional on reaching the JSON-RPC dispatcher `[RN-1] [SEC-3]`. It never interprets the body as anything other than bytes/JSON.
2. **Protocol/dispatch layer** — pure(ish) functions that take a parsed JSON-RPC message plus a small immutable request-context object and return a `DispatchResult` (see § Data Flow). This layer has no socket access and does no I/O of its own; it is the seam the design keeps free of `BaseHTTPRequestHandler` so it can be exercised directly.
3. **Logging layer** — a small `JSONLogWriter` class wrapping a single already-open file handle plus a `threading.Lock`, and a `sanitize_for_stderr` helper. The transport layer calls this *after* building the full response object but *before* writing bytes to the client socket, satisfying "log before responding." The log write itself is now individually fault-tolerant: a failure to write (disk full, permission error, etc.) is caught locally and never prevents the HTTP response from being sent `[RN-6]`.

There are no other components, no external services, no persistence beyond the JSONL file, and no dependencies beyond the Python 3 standard library (`http.server`, `socketserver`, `json`, `argparse`, `threading`, `uuid`, `datetime`, `re`, `dataclasses`, `collections`, `email.message`, `sys`). This matches the plan's stack decision exactly; nothing in the repo contradicts or constrains it.

**Stated reliance on stdlib-enforced limits `[SEC-5]`.** Two protections in this design are provided by the Python standard library rather than by code we write, and are called out explicitly here (not left implicit) so a future maintainer doesn't accidentally swap in a handler base class that lacks them:
- **HTTP header count/line-length limits.** `http.server`'s request parsing goes through `http.client.parse_headers()`, which enforces `http.client._MAXHEADERS` (100 headers) and per-line length limits before `do_*` is ever invoked. A request that trips this limit is rejected by the stdlib with its own error response *before* reaching our handler, and is therefore one of the two named exceptions to "every request is logged" (the other is documented in § Data Flow, "unsupported HTTP verbs"). This is an accepted, explicitly-documented v1 gap, not a silent one.
- We do **not** additionally cap header count/size ourselves in v1; the stdlib ceiling is judged sufficient given the honeypot's threat model (a header-flood attack at that scale is a pathological stress case rather than realistic scanner/agent traffic, and it still can't crash the process or bypass the body-size cap).

## Components / Modules

Everything lives in one new file at the repo root: **`mcp_honeypot.py`**. Internally it is organized top-to-bottom as (this ordering is also the build order in Task Breakdown below):

- **CLI / entrypoint** — `build_arg_parser() -> argparse.ArgumentParser` (`--host` default `127.0.0.1`, `--port` default `8000`, `--log-file` default `./honeypot.jsonl` — no new flags added; all new v1 hardening constants below are code-level, not CLI-configurable, to keep the CLI surface exactly matching plan.md) and `main(argv: list[str] | None = None) -> int`. All server-starting side effects live inside `main()`, guarded by `if __name__ == "__main__":` — importing the module (e.g. from a future test or the QA phase) must never open a socket or a file. This is the primary testability seam for the whole design.
- **Module-level constants** (new, named, near the top of the file so an operator can tune them by editing the file): `MAX_BODY_BYTES = 1_048_576` (1 MiB request body cap), `SOCKET_TIMEOUT_SECONDS = 10` (per-connection idle/read timeout `[RN-8] [SEC-1]`), `MAX_CONCURRENT_CONNECTIONS = 200` (hard cap on simultaneously-handled connections `[SEC-1]`), `MAX_SESSIONS = 10_000` (cap on the in-memory session store, oldest evicted first `[SEC-2]`).
- **Logging core** — `JSONLogWriter` (holds the open file handle + `threading.Lock`, exposes `write(record: dict) -> None`), `build_log_record(...) -> dict` (pure function assembling the record shape below, now including `http_method`/`path` since every HTTP request is logged, not just `POST /mcp` JSON-RPC exchanges), `headers_to_dict(msg: email.message.Message) -> dict[str, str]` (new — see duplicate-header policy below `[RN-7]`), `sanitize_for_stderr(text: str, max_len: int = 300) -> str`, and `emit_stderr_summary(record: dict) -> None`.
- **HTTP server** — `HoneypotHTTPServer(ThreadingHTTPServer)` (new class, replacing a bare `ThreadingHTTPServer` instance): adds a `threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)` acquired in an overridden `process_request()` and released in an overridden `process_request_thread()`, so more than `MAX_CONCURRENT_CONNECTIONS` simultaneous connections are refused (socket closed immediately, no thread spun up, no response) rather than growing threads unboundedly `[SEC-1]`. `ThreadingHTTPServer` already sets `daemon_threads = True` by default (confirmed against the stdlib source), so the process can still exit cleanly even if a handler thread is stuck; no change needed there.
- **HTTP handler** — `HoneypotRequestHandler(BaseHTTPRequestHandler)` with class attribute `timeout = SOCKET_TIMEOUT_SECONDS` (stdlib's `socketserver.StreamRequestHandler.setup()` automatically applies this as a socket-level read timeout on every connection — the slowloris mitigation `[RN-8] [SEC-1]`). Implements `do_GET`, `do_POST`, `do_PUT`, `do_PATCH`, `do_DELETE`, `do_HEAD`, `do_OPTIONS`, each a one-line call to the shared `_handle_request(self, http_method)`. This method owns: path check (`/mcp` vs. 404), HTTP-method check (`POST` vs. 405 with `Allow: POST`), body-size enforcement (413), body read with `errors="replace"` decoding, JSON parse attempt, top-level shape validation, building the `RequestContext`, calling `dispatch()`, calling the logging core (fault-tolerant), and writing the HTTP response. The entire method body is wrapped in one outer `try/except Exception` with an `_emergency_fallback()` path `[RN-6] [SEC-3]` — see § Data Flow for the exact lifecycle. **Named exception to universal logging:** only these seven verbs are implemented; any other HTTP verb (e.g. `TRACE`, a custom verb) falls through to `http.server`'s own default `501 Not Implemented` handling, which happens outside our code and is therefore unlogged. This is an accepted, stated v1 limitation, not silent — it is called out again in the README (Task 4).
- **Session store** — module-level `SESSIONS: OrderedDict[str, dict]` (insertion-ordered so the oldest entry is always `next(iter(SESSIONS))`) + `SESSIONS_LOCK: threading.Lock`, written to only from inside `dispatch()` when a `method == "initialize"` call succeeds: a new `uuid.uuid4().hex` id is minted, and if `len(SESSIONS) >= MAX_SESSIONS` the oldest entry is evicted (`SESSIONS.popitem(last=False)`) before the new one is inserted, all under `SESSIONS_LOCK` `[SEC-2]`. **v1 does not attempt to correlate header-less follow-up requests back to a previously-issued session** — `RequestContext.session_id` is populated strictly from the `Mcp-Session-Id` request header when present, `None` otherwise, with no IP-based or other fallback lookup. (The plan explicitly does not require enforcing session-id presence — this store exists purely for log correlation and is intentionally simple.) `[RN-5]`
- **JSON-RPC dispatch** — `dispatch(msg: dict, ctx: RequestContext) -> DispatchResult` (see exact signature in § Data Flow — this replaces the earlier, self-contradictory tuple-return description `[RN-2]`), a `METHODS: dict[str, Callable]` table, and one handler function per method: `handle_initialize`, `handle_notifications_initialized`, `handle_ping`, `handle_tools_list`, `handle_tools_call`. Wrapped in one `try/except InvalidParamsError` (→ `-32602`, new `[RN-3]`) then `except Exception` (→ `-32603`) inside `dispatch()` itself, so *any* handler bug or bad-params condition becomes a well-formed JSON-RPC error object, never an unhandled exception reaching the transport layer.
- **Fake tool catalog** — `TOOLS: list[dict]` (the four `tools/list` entries: name, description, `inputSchema`) and `TOOL_HANDLERS: dict[str, Callable[[dict], dict]]` mapping tool name to a pure function that builds the fake `tools/call` result content. `validate_arguments(schema: dict, arguments: dict) -> None` (new, pure function, raises `InvalidParamsError` — see § Data Flow) checks arguments against each tool's `inputSchema` before its handler runs. No tool handler imports or calls anything from `os`, `subprocess`, `socket`, `urllib`, `builtins.eval`, `builtins.exec`, or `importlib`/dynamic `import`.
- **README.md** (existing file at repo root, extended not replaced) — gets the run/log-location/client-pointing paragraph the plan calls for, plus explicit caveats about unbounded JSONL growth, the read-timeout/connection-cap mitigations and their limits, and the two named unlogged-request exceptions (see Task 4).
- **.gitignore** (existing file at repo root) — gains a `/honeypot.jsonl` entry; note the current `.gitignore` already has a `# Python` section (`__pycache__/`, `*.py[cod]`, `.venv/`, etc.) but no honeypot-specific log entry, so this is a one-line addition, not a new section.

## Data Flow / Interfaces

**Request lifecycle (every HTTP request, any of the seven implemented verbs, any path):**

```
socket bytes
  -> HoneypotRequestHandler.{do_GET,do_POST,do_PUT,do_PATCH,do_DELETE,do_HEAD,do_OPTIONS}(self)
       each is: def do_X(self): self._handle_request("X")

  -> _handle_request(self, http_method: str) -> None:        # ONE try/except Exception wraps this whole body
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
               length = self._validated_content_length()     # None if missing/invalid/over MAX_BODY_BYTES
               if length is None:
                   http_status = 413               # empty body; raw_body left as an oversized/invalid marker,
                   raw_body = "(oversized or invalid Content-Length)"   # body NOT read/buffered in full
               else:
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
       except Exception:
           self._emergency_fallback(http_method)     # [RN-6] [SEC-3]: catches EVERYTHING upstream of/including
                                                       # the log write -- body-read errors, decode errors,
                                                       # RecursionError from pathological JSON, dispatch bugs
                                                       # that somehow escape dispatch()'s own try/except, etc.
```

`_emergency_fallback(self, http_method: str) -> None` is the last line of defense: it independently (a) attempts, only if no response bytes have been sent yet, to send a generic `HTTP 500` with a minimal `{"jsonrpc": "2.0", "id": null, "error": {"code": -32603, "message": "Internal error"}}` body, and (b) attempts a best-effort JSONL record (`{"...": "...", "internal_fault": true}`) plus a plain stderr line — each of (a) and (b) individually wrapped in its own `try/except Exception: pass` so a failure inside the fallback itself can never re-raise and crash the handler thread. This directly satisfies plan.md's "catch-all exception handler around each request" for the *entire* request lifecycle, not just inside `dispatch()` `[SEC-3]`.

**405 / 404 / 413 response shapes `[RN-9]`:** all three are empty-body HTTP responses (`Content-Length: 0`), no JSON-RPC envelope, matching plan.md's "Transport-level problems ... use HTTP status codes with no JSON-RPC body." The 405 response additionally sets `Allow: POST`. None of the three set `Content-Type: application/json` since there is no body to type.

**Universal logging, with two named exceptions `[RN-1]`:** every request that reaches `_handle_request` — 404, 405, 413, `-32700`, `-32600`, `-32601`, `-32602`, `-32603`, a normal `200`/`202` JSON-RPC exchange, all of it — produces exactly one `build_log_record` call and one `log_writer.write` call before the response is sent. The two exceptions, both already named in § Architecture Overview and neither silent: (1) HTTP verbs outside the seven implemented `do_*` methods are rejected by `http.server`'s own default handling before `_handle_request` runs; (2) requests that trip the stdlib's own header-count/line-length limits are rejected during `parse_request()`, before any `do_*` method is invoked.

**Duplicate HTTP header policy `[RN-7]`:**

```python
def headers_to_dict(msg: email.message.Message) -> dict[str, str]:
    """RFC 7230 §3.2.2-style merge: repeated header names are joined with ', '
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

def validate_arguments(schema: dict, arguments: dict) -> None:
    """Pure function. Checks every name in schema.get("required", []) is present
    in `arguments`, and for every key present in both `arguments` and
    schema["properties"], checks its JSON-Schema-declared "type" against the
    Python value's type (string->str, integer->int, number->(int|float),
    boolean->bool, object->dict, array->list). Raises InvalidParamsError with a
    message naming the first violation found; returns None if all checks pass."""

def build_log_record(ctx: RequestContext, http_method: str, path: str, raw_body: str | None,
                      parsed: object | None, response_obj: dict | None, http_status: int) -> dict: ...

class JSONLogWriter:
    def __init__(self, fh: TextIO) -> None: ...   # fh is opened once by main(), append mode, utf-8
    def write(self, record: dict) -> None: ...      # json.dumps + "\n", flush, all under self._lock

def sanitize_for_stderr(text: str, max_len: int = 300) -> str: ...

def headers_to_dict(msg: email.message.Message) -> dict[str, str]: ...   # see policy above
```

**Log record shape** (one JSON object per line, per plan, now covering every HTTP request): `ts` (ISO 8601 UTC), `client_ip`, `client_port`, `http_method` (new: `"GET"`/`"POST"`/etc.), `path` (new: e.g. `"/mcp"`, `"/"`), `headers` (dict, values as opaque strings, duplicates comma-joined), `session_id` (string or `null`), `raw_body` (decoded with `errors="replace"`, or `null` for verb/path rejections where no body was read, or an oversized/invalid marker string when the 413 cap was hit — never buffered in full when over cap), `method` (parsed JSON-RPC `method` or `null`), `tool_name` / `tool_arguments` (populated only when `method == "tools/call"`, taken from the *parsed* request params, not from the tool handler's output), `response` (the exact JSON-RPC body sent, `null` for 404/405/413, or `"202 Accepted (notification)"` for notifications), `http_status` (int).

**`initialize` result shape:** `{"protocolVersion": "2025-06-18", "serverInfo": {"name": "<honeypot's advertised name>", "version": "1.0.0"}, "capabilities": {"tools": {}}}`. `2025-06-18` is the design's chosen protocol-version string (most recent MCP spec revision date at design time) per the plan's Open Question; the honeypot advertises it unconditionally regardless of what the client requested, since the goal is to log the handshake attempt, not to negotiate correctly.

**Session-id issuance, end-to-end (concrete, no ambiguity `[RN-2]`):**
1. `_handle_request` calls `dr = dispatch(parsed, ctx)`.
2. `dispatch()`, on a successful `initialize`, mints `session_id = uuid.uuid4().hex`, stores it in `SESSIONS` (with cap/eviction — see Components), and sets `DispatchResult.session_id` to that value. Every other method call returns `DispatchResult.session_id = None`.
3. `_handle_request` reads `dr.session_id` into `session_id_to_issue` and passes it to `self._send_response(http_status, response_obj, session_id_to_issue, ...)`.
4. `_send_response` sets the `Mcp-Session-Id` response header if and only if `session_id_to_issue is not None`, then writes status line, headers, and body bytes.

There is no tuple threaded through `dispatch`'s declared return type, no side channel, and no asymmetric contract between `initialize` and other methods — `DispatchResult` is dispatch's one and only return type for every method, always.

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
            except OSError:              # so this connection is NOT logged (nothing was parsed yet)
                pass
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
                                        # which propagates into _handle_request's outer try/except and is
                                        # handled by _emergency_fallback (best-effort; the socket may already
                                        # be unusable by the time we try to respond, which is acceptable --
                                        # the thread still terminates and its semaphore slot is released).
```

## Testability Notes

- **No test suite is a required deliverable** (plan explicitly leaves this to design/QA discretion and marks it out of scope as a *mandate*). Given that, this design still keeps the code trivially testable without committing to writing tests as a task, by enforcing structural rules the QA phase can rely on if it chooses to add `unittest`-based tests:
  1. **Importing `mcp_honeypot` must have zero side effects.** All socket/file opening happens inside `main()`, gated by `if __name__ == "__main__":`. `python3 -c "import mcp_honeypot"` must succeed instantly and open nothing.
  2. **Protocol logic is separable from I/O.** `dispatch(msg, ctx)` and every `handle_*`/`TOOL_HANDLERS[...]` function take plain dicts/dataclasses and return plain dicts/`DispatchResult` — no `self.rfile`/`self.wfile`, no file handle, no network. A test (or a human at a REPL) can call `dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {...}}, RequestContext(...))` directly and assert on the returned `DispatchResult` with no server running.
- **`build_log_record`, `sanitize_for_stderr`, `headers_to_dict`, and `validate_arguments` are pure functions** over their inputs — straightforward to test with adversarial strings (newlines, ANSI escapes, huge values, duplicate header names, malformed/wrongly-typed tool arguments) without touching the filesystem.
- **`-32600`/`-32602` coverage is a pure-function concern.** Non-dict top-level JSON (`42`, `"x"`, `[1,2,3]`, `true`) and missing/wrong-typed `tools/call` arguments can both be exercised without a running server: the former by calling `_handle_request`'s shape-check logic directly (or, if extracted, a standalone `classify_top_level(parsed) -> "ok" | "invalid_request"` helper), the latter by calling `handle_tools_call(params, ctx)` and asserting `InvalidParamsError` is raised.
- **The log-write failure path is testable via monkeypatching.** Since `log_writer.write` is a single method call site inside `_handle_request`, a test can substitute a `JSONLogWriter`-like object whose `write()` raises, and assert (a) the HTTP response is still sent with the correct status/body and (b) a `[honeypot] WARNING: log write failed` line appears on stderr.
- **The emergency-fallback path is testable by forcing an exception upstream of dispatch**, e.g. monkeypatching `self.rfile.read` to raise, and asserting the handler still returns *some* HTTP response and the process doesn't crash.
- **End-to-end smoke testing** (manual or QA-added) is straightforward via stdlib `http.client` or `curl` against `127.0.0.1:<port>` since the transport is plain HTTP/JSON — no SSE, no auth, no TLS to negotiate.
- **Concurrency correctness** (the `threading.Lock` around the log writer and session dict, and the new `BoundedSemaphore` connection cap) is awkward to unit-test meaningfully; the practical approach is a smoke test that fires N concurrent POSTs (e.g. via `concurrent.futures.ThreadPoolExecutor` driving `http.client` calls) and asserts the resulting `honeypot.jsonl` has exactly N well-formed JSON lines (no interleaved/corrupted lines), and a separate smoke test that opens `MAX_CONCURRENT_CONNECTIONS + a few` raw sockets without sending a request line, confirming the server continues to serve ordinary requests rather than exhausting threads.
- **Session-cap eviction is directly testable** by temporarily monkeypatching `MAX_SESSIONS` to a small number (e.g. 3) in a test process, issuing more than that many `initialize` calls through `dispatch()` directly (no server needed), and asserting `len(SESSIONS) == MAX_SESSIONS` with the earliest-issued id evicted.
- **Safety-constraint verification is largely static, not runtime-testable in the traditional sense** — the strongest check is `grep`/read-through confirming the forbidden identifiers (`eval(`, `exec(`, `subprocess`, `socket.socket`, `urllib`, `importlib`, `open(` outside the one log-file call site) don't appear in tool handlers or dispatch code. This is called out explicitly as an acceptance criterion in Tasks 3 and 4 so the code-review and security-review passes have something concrete to grep for, not just prose to trust.

## Task Breakdown

1. **HTTP server, universal request lifecycle, and logging core.** Create `mcp_honeypot.py` at the repo root with:
   - `build_arg_parser`/`main` (CLI flags `--host` 127.0.0.1, `--port` 8000, `--log-file` ./honeypot.jsonl, all side effects gated behind `if __name__ == "__main__":`); no additional CLI flags.
   - Module-level constants `MAX_BODY_BYTES = 1_048_576`, `SOCKET_TIMEOUT_SECONDS = 10`, `MAX_CONCURRENT_CONNECTIONS = 200`, `MAX_SESSIONS = 10_000` (the last one is wired in Task 2, but declare it here alongside the others).
   - `HoneypotHTTPServer(ThreadingHTTPServer)` with the `BoundedSemaphore`-based connection cap (`process_request`/`process_request_thread` overrides, exactly as specified in § Data Flow).
   - `HoneypotRequestHandler(BaseHTTPRequestHandler)` with `timeout = SOCKET_TIMEOUT_SECONDS`, and `do_GET`/`do_POST`/`do_PUT`/`do_PATCH`/`do_DELETE`/`do_HEAD`/`do_OPTIONS` all delegating to one shared `_handle_request(self, http_method: str)`.
   - `_handle_request` implementing the full lifecycle from § Data Flow: path check (non-`/mcp` → 404, empty body); method check (`/mcp` + non-`POST` → 405, empty body, `Allow: POST`); body-size cap enforcement via `Content-Length` (missing/invalid/over `MAX_BODY_BYTES` → 413, empty body, request still logged with an oversized/invalid marker instead of the body); UTF-8 decode with `errors="replace"`; `json.loads` attempt producing `parsed: object | None`; a shape check that runs `isinstance(parsed, dict) and isinstance(parsed.get("method"), str)` **before** any dict-only operation on `parsed`, routing non-conforming-but-valid JSON to a `-32600 Invalid Request` response built directly (not via `dispatch()`); `RequestContext` dataclass; `headers_to_dict` (duplicate headers comma-joined).
   - `dispatch()` as a stub in this task only (always returns `DispatchResult(response=_build_error(..., -32601, "Method not found"), session_id=None)` for any method, or the `-32700`/`-32600` paths handled above it) — full method table lands in Task 2, but `_handle_request` must already call `dispatch()` with its final signature (`msg: dict, ctx: RequestContext) -> DispatchResult`) so Task 2 doesn't have to touch the transport layer.
   - `JSONLogWriter` (single file handle opened once in `main()`, `threading.Lock`-guarded `write()` that appends one `json.dumps(record) + "\n"` and flushes before returning); `build_log_record` (including the new `http_method`/`path` fields); `sanitize_for_stderr` (strips `[\x00-\x1f\x7f]` control chars, truncates to a bounded length); `emit_stderr_summary`.
   - The log-then-respond glue: build `response_obj` → `build_log_record` → `log_writer.write(record)` wrapped in its own local `try/except Exception` (on failure, print a `[honeypot] WARNING: log write failed: ...` sanitized stderr line, then continue) → `emit_stderr_summary(record)` → send HTTP response.
   - One outer `try/except Exception` wrapping the *entire* `_handle_request` body (context build through response send), with `_emergency_fallback(self, http_method)` as the except-branch handler, exactly as specified in § Data Flow.
   - Add `/honeypot.jsonl` to `.gitignore` (repo root, next to the existing `# Python` section).

   **Acceptance:**
   - `python3 mcp_honeypot.py` starts and binds `127.0.0.1:8000`.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -d '{"jsonrpc":"2.0","id":1,"method":"x"}'` returns HTTP 200 with a JSON-RPC `-32601` body; `honeypot.jsonl` gains exactly one well-formed JSON line with `http_method: "POST"`, `path: "/mcp"`, `http_status: 200`.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -d '42'`, `-d '[1,2,3]'`, `-d 'true'`, and `-d '{"id":1}'` (no `"method"`) each return HTTP 200 with a `-32600 Invalid Request` body, no server crash/traceback, and each produces one JSONL line.
   - `curl -s -X POST http://127.0.0.1:8000/mcp -d 'not json'` returns a `-32700` body and is logged.
   - `curl -X GET http://127.0.0.1:8000/mcp` and `curl -X DELETE http://127.0.0.1:8000/mcp` each return 405 with empty body and an `Allow: POST` header, **and each produces one JSONL line** (`http_status: 405`, `response: null`) — this is the concrete regression test for `[RN-1]`.
   - A bogus path (e.g. `curl http://127.0.0.1:8000/nope`) returns 404 with empty body **and produces one JSONL line** (`http_status: 404`).
   - A body larger than `MAX_BODY_BYTES` returns 413 without the process reading the full body into memory, and is still logged with a marker instead of the raw body.
   - `wc -l honeypot.jsonl` after each of the above requests increases by exactly 1 each time — no request in this task's test matrix is silently dropped.
   - Stderr prints one sanitized single-line summary per request with no raw newlines/control chars even when the request body/headers contain them.
   - A client that opens a raw TCP connection to the port and sends nothing for longer than `SOCKET_TIMEOUT_SECONDS` causes that connection to be closed by the server (verify via `socket.timeout`-triggered cleanup — e.g. the handler thread count / open-fd count returns to baseline) without hanging the server or blocking other requests.
   - Opening `MAX_CONCURRENT_CONNECTIONS + 5` raw sockets simultaneously (without completing a request) does not exhaust threads or crash the server; the extra connections beyond the cap are closed by the server without a response (and, per design, without a log line, since no request line was ever read on them).
   - `python3 -c "import mcp_honeypot"` opens no sockets/files (no `honeypot.jsonl` created by import alone).

2. **Session-aware JSON-RPC dispatch: initialize, notifications/initialized, ping, and the -32600/-32602/-32603 error paths.** Replace the Task 1 dispatch stub with the real `dispatch(msg: dict, ctx: RequestContext) -> DispatchResult` and `METHODS` table (per the exact signature and behavior specified in § Data Flow). Implement:
   - `handle_initialize` (returns `protocolVersion: "2025-06-18"`, `serverInfo`, `capabilities: {"tools": {}}}` — no session-id logic in the handler itself; `dispatch()` owns minting/storing the session id after a successful call).
   - `handle_notifications_initialized` (no-op, returns `{}`, side-effect free).
   - `handle_ping` (returns `{}`).
   - `SESSIONS: OrderedDict[str, dict]` + `SESSIONS_LOCK`, with `dispatch()` minting `uuid.uuid4().hex` on a successful `initialize`, evicting the oldest entry via `SESSIONS.popitem(last=False)` when `len(SESSIONS) >= MAX_SESSIONS` before inserting the new one, all under `SESSIONS_LOCK`.
   - `InvalidParamsError` exception class and `dispatch()`'s `try/except InvalidParamsError` (→ `-32602`) / `except Exception` (→ `-32603`) wrapping around each handler call (no handler raises `InvalidParamsError` yet in this task — that lands in Task 3 with `handle_tools_call` — but the plumbing must exist and be exercised by a temporary/throwaway manual test during this task).
   - Notification handling: any parsed message lacking `"id"` still gets dispatched for side effects (`DispatchResult.response = None`); `_handle_request` (from Task 1, unmodified) maps that to HTTP 202 empty body, logged with `response = "202 Accepted (notification)"`.
   - `Mcp-Session-Id` response header set by `_handle_request` from `dr.session_id` whenever it's not `None` (Task 1's `_send_response` already accepts this parameter — wire the real value through now).

   **Acceptance:**
   - `initialize` request returns a well-formed result with the fields above and an `Mcp-Session-Id` response header containing a fresh `uuid4().hex` value on every call (not reused).
   - A follow-up `notifications/initialized` (no `"id"`) returns HTTP 202 with empty body and is still logged.
   - `ping` returns `{"jsonrpc":"2.0","id":<echoed>,"result":{}}`.
   - A request with an unknown method (and an `"id"`) returns a `-32601` JSON-RPC error, HTTP 200.
   - Issuing more than `MAX_SESSIONS` `initialize` calls in a row (test with a monkeypatched small `MAX_SESSIONS`, e.g. 3, per the Testability Notes approach) keeps `len(SESSIONS)` capped at the limit with the earliest-issued session id evicted first.
   - The `-32600` regression tests from Task 1 (non-dict/non-object top-level JSON) still pass unchanged now that real `dispatch()` wiring is in place, confirming the shape-check-before-dispatch ordering from `[RN-4]` holds end-to-end.
   - The server process never exits/crashes across any of the above, including when a handler is temporarily made to raise during manual testing (confirms `-32603` still fires correctly; remove any such debug hook before finishing the task).

3. **Fake tool catalog + tools/list + tools/call + -32602 argument validation.** Define `TOOLS` (four entries — a file reader e.g. `read_file`, a database query runner e.g. `query_database`, a credential/secret lookup e.g. `get_credential`, an outbound email sender e.g. `send_email` — each with a realistic `name`, `description`, and a JSON Schema `inputSchema` that declares `"type": "object"`, a non-empty `"required"` list, and `"properties"` with per-argument `"type"`) and `TOOL_HANDLERS` (pure functions, one per tool, each takes only the parsed `arguments` dict and returns an MCP `tools/call` content result — `{"content": [{"type": "text", "text": "..."}], "isError": false}` — built purely from string formatting/echoing the caller's arguments; explicitly no `open()`, `subprocess`, `socket`, `urllib`, `eval`, `exec`, or dynamic `import` anywhere in these functions or their call path; the "secret" returned by `get_credential` must be an obviously-synthetic placeholder value, not something realistic-looking).

   Implement `validate_arguments(schema, arguments)` (pure, per § Data Flow signature) and `handle_tools_list` (returns `{"tools": TOOLS}`) and `handle_tools_call` (validates `params["name"]` is a string and `params.get("arguments", {})` is an object, raising `InvalidParamsError` on violation *before* any tool lookup; looks up the tool — unknown name returns a JSON-RPC **result** with `isError: true` and an explanatory message, not an error/exception; a known tool's arguments are checked with `validate_arguments` against its `inputSchema`, raising `InvalidParamsError` — and therefore surfacing as `-32602` via `dispatch()`'s existing wiring from Task 2 — on a missing required argument or a wrongly-typed one; on success, calls the matched `TOOL_HANDLERS[name](arguments)`).

   Extend `build_log_record` (from Task 1) so that when `method == "tools/call"`, `tool_name` and `tool_arguments` are populated straight from the parsed request `params`, never from the tool's fabricated output.

   **Acceptance:**
   - `tools/list` returns exactly 4 tools, each with a non-empty `name`/`description` and a valid JSON Schema object (with `required` and `properties`) under `inputSchema`.
   - `tools/call` against each of the 4 tools, with all required arguments present and correctly typed, returns a `content` array whose text echoes back at least one caller-supplied argument.
   - `tools/call` with a required argument omitted returns HTTP 200 with a `-32602 Invalid params` JSON-RPC error (not `isError: true`, not a crash), and is logged with `tool_name`/`tool_arguments` populated from the request.
   - `tools/call` with a required argument present but the wrong JSON-Schema-declared type (e.g. a number where `"type": "string"` is declared) also returns `-32602`.
   - `tools/call` with an unrecognized tool name returns a well-formed `isError:true` result (HTTP 200, `result` not `error`), connection stays alive.
   - `grep -nE "eval\(|exec\(|subprocess|urllib|socket\.socket|importlib" mcp_honeypot.py` matches nothing inside the tool-handler section (and none of the tool handler functions call `open()`).

4. **CLI finishing touches, safety self-check, and README.** Finalize `--host`/`--port`/`--log-file` argparse help text and defaults (confirm log path resolves relative to CWD at start, per plan); confirm the log file is opened once in append mode in `main()` and the handle is reused for the process lifetime (not reopened per request); confirm `MAX_BODY_BYTES`, `SOCKET_TIMEOUT_SECONDS`, `MAX_CONCURRENT_CONNECTIONS`, `MAX_SESSIONS` are all named module-level constants (not magic numbers scattered through the file); do a full read-through/grep pass over the finished file confirming no forbidden identifiers (`eval(`, `exec(`, `subprocess`, `socket.socket`, `urllib`, `importlib`, `open(` outside the single log-file open call in `main()`) appear anywhere; add a short comment block near the top of `mcp_honeypot.py` stating the non-negotiable safety invariants (no real I/O beyond the log file, no outbound network, no dynamic execution of client-derived data).

   Update root `README.md` (currently a one-line stub) by adding one paragraph covering: how to run it (`python3 mcp_honeypot.py [--host H] [--port P] [--log-file PATH]`); where logs go (JSONL at `--log-file`, default `./honeypot.jsonl` relative to CWD, plus the sanitized stderr mirror); how to point an MCP client at it (`http://<host>:<port>/mcp`, streamable-HTTP transport, single-request/response only — no SSE); and the following explicit caveats (not silent gaps `[SEC-4]`):
   - Default bind (`127.0.0.1`) is safe for local testing; rebinding to `0.0.0.0` to expose it as a real decoy is an explicit opt-in risk.
   - Built-in resource-exhaustion mitigations that do exist in v1 — a `SOCKET_TIMEOUT_SECONDS` (10s) read timeout per connection and a `MAX_CONCURRENT_CONNECTIONS` (200) hard cap — and that these are fixed constants near the top of the source file, not CLI flags, if an operator needs to tune them.
   - `honeypot.jsonl` has **no rotation, size cap, or retention limit** in v1; unbounded disk growth under sustained traffic is an explicit operator responsibility, not something the tool manages `[SEC-4]`.
   - Two narrow, named exceptions to "every request is logged": HTTP verbs outside `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS`, and requests that trip the stdlib's own header-count/line-length limits before reaching the handler.

   **Acceptance:**
   - `python3 mcp_honeypot.py --help` documents all three flags with their defaults (still exactly three — no new flags added).
   - `README.md` contains the new paragraph(s) with run/log-location/client-URL/exposure-warning/disk-growth/unlogged-exceptions content described above, appended to (not replacing) the existing project description.
   - The safety grep from Task 3's acceptance criterion, re-run against the complete file, still matches nothing.
   - A fresh clone + `python3 mcp_honeypot.py` + one `curl` round-trip + `Ctrl-C` leaves behind only `honeypot.jsonl` (already gitignored) with no other file writes anywhere on disk.

---

## Round 1 finding disposition (summary)

**review-notes.md:**
1. Blocking — universal logging now covers every HTTP request (404/405/413/200/202), with two explicitly named stdlib-layer exceptions; see § Architecture Overview, § Data Flow, Task 1.
2. Major — `dispatch()` now has one concrete signature (`-> DispatchResult`) end-to-end; session-id issuance path fully specified in § Data Flow, "Session-id issuance, end-to-end."
3. Major — `-32602` implemented via `InvalidParamsError` + `validate_arguments`, wired in `dispatch()` (Task 2) and exercised by `handle_tools_call` (Task 3) with explicit acceptance criteria.
4. Major — `isinstance(parsed, dict)` (plus a `method`-is-string check) now runs before any dict-only access on `parsed`; non-conforming JSON routes to `-32600` instead of raising.
5. Major — dropped the header-less-fallback-correlation claim from Components; `RequestContext.session_id` and the Session store bullet are now consistent (header-only, no fallback, stated explicitly).
6. Major — log write wrapped in its own local try/except with a stderr fallback; the entire request lifecycle wrapped in one outer try/except with `_emergency_fallback`.
7. Minor — `headers_to_dict` specifies and implements a comma-join policy for duplicate headers.
8. Minor — `SOCKET_TIMEOUT_SECONDS = 10` class-attribute timeout specified and tasked.
9. Minor — 404/405/413 response shapes specified precisely (empty body, 405 adds `Allow: POST`).

**security-plan-review.md:**
1. Major — `SOCKET_TIMEOUT_SECONDS` timeout plus `MAX_CONCURRENT_CONNECTIONS` semaphore-bounded connection cap on `HoneypotHTTPServer`, both specified and tasked.
2. Major — `SESSIONS` is now an `OrderedDict` capped at `MAX_SESSIONS` with oldest-first eviction.
3. Major — outer try/except now wraps the entire `_handle_request` lifecycle (body read, decode, parse, dispatch, log, respond), not just `dispatch()`'s internals.
4. Minor — unbounded JSONL growth stated explicitly as an operator responsibility in the README (Task 4), not left silent.
5. Minor — reliance on stdlib header-count/line-length limits stated explicitly in § Architecture Overview.
