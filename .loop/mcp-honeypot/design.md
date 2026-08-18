# Design: Build a minimal MCP (Model Context Protocol) honeypot in Python.

Purpose: A decoy MCP server that appears to expose useful tools, logs everything a client does, and never performs any real action. Intended for observing how LLM agents and automated scanners interact with untrusted MCP servers.

Scope for v1: Single file, stdlib plus at most one small dependency. No database, no web UI, no alerting. Getting complete, well-structured logs is the only goal.

Protocol surface: Serve MCP over streamable HTTP on a configurable host/port (default 127.0.0.1:8000). Handle enough JSON-RPC 2.0 to keep a real client talking: initialize (return protocolVersion, serverInfo, capabilities [tools only]), notifications/initialized, tools/list (return the fake tool catalog), tools/call (return canned fake results), ping. Any unknown method returns a well-formed JSON-RPC error rather than crashing or closing the connection. Malformed JSON gets a -32700 parse error and is still logged.

Fake tool catalog: Four tools with realistic names, descriptions, and JSON Schemas -- plausible enough that an agent would try them, e.g. a file reader, a database query runner, a credential/secret lookup, and an outbound email sender. Each returns static or templated fake data. Nothing touches the filesystem, network, shell, or any real service.

Logging: Append one JSON object per line to a JSONL file (default ./honeypot.jsonl): ISO 8601 UTC timestamp; source IP and port; request HTTP headers (at minimum User-Agent); session identifier, if the client provides one; the raw request body as received; the parsed method name, and for tools/call the tool name and full arguments; the response the honeypot returned. Log before responding so nothing is lost if a handler raises. Also mirror a one-line human-readable summary to stderr.

Safety rules (non-negotiable): Never eval, exec, subprocess, or import anything derived from client input. Never make outbound network requests. Never read or write files outside the log path. Log file is append-only; treat every logged value as untrusted text.

Deliverables: The honeypot source file. A one-paragraph README: how to run it, where logs go, how to point an MCP client at it for testing.

## Architecture Overview

This is a greenfield addition to an otherwise-empty repo (`.claude/`, `.loop-templates/`, `.gitignore`, and a one-paragraph `README.md` are the only existing files; there is no prior Python code or toolchain to fit into — confirmed via `find . -maxdepth 3`). No scaffolding phase is needed beyond the file itself: this is a stdlib-only, single-file Python 3.10+ program, so there is no package manager, build system, or lint config to initialize — `python3 mcp_honeypot.py` is the entire toolchain, and `python3 -m py_compile mcp_honeypot.py` / `python3 -c "import ast; ast.parse(open('mcp_honeypot.py').read())"` stand in for a "build" step during development.

The whole system is one process, one file, three logical layers stacked inside it, in this order:

1. **Transport layer** — `ThreadingHTTPServer` + a `BaseHTTPRequestHandler` subclass that owns the socket, HTTP method/path routing (`POST /mcp` is the only real endpoint; everything else is a well-formed HTTP-level rejection), request-body reading with a hard size cap, and writing the HTTP response. It never interprets the body as anything other than bytes/JSON.
2. **Protocol/dispatch layer** — pure(ish) functions that take a parsed JSON-RPC message plus a small immutable request-context object and return a JSON-RPC result/error dict (or `None` for notifications). This layer has no socket access and does no I/O of its own; it is the seam the design keeps free of `BaseHTTPRequestHandler` so it can be exercised directly.
3. **Logging layer** — a small `JSONLogWriter` class wrapping a single already-open file handle plus a `threading.Lock`, and a `sanitize_for_stderr` helper. The transport layer calls this *after* building the full response object but *before* writing bytes to the client socket, satisfying "log before responding."

There are no other components, no external services, no persistence beyond the JSONL file, and no dependencies beyond the Python 3 standard library (`http.server`, `json`, `argparse`, `threading`, `uuid`, `datetime`, `re`, `dataclasses`, `sys`). This matches the plan's stack decision exactly; nothing in the repo contradicts or constrains it.

## Components / Modules

Everything lives in one new file at the repo root: **`mcp_honeypot.py`**. Internally it is organized top-to-bottom as (this ordering is also the build order in Task Breakdown below):

- **CLI / entrypoint** — `build_arg_parser() -> argparse.ArgumentParser` (`--host` default `127.0.0.1`, `--port` default `8000`, `--log-file` default `./honeypot.jsonl`) and `main(argv: list[str] | None = None) -> int`. All server-starting side effects live inside `main()`, guarded by `if __name__ == "__main__":` — importing the module (e.g. from a future test or the QA phase) must never open a socket or a file. This is the primary testability seam for the whole design.
- **Logging core** — `JSONLogWriter` (holds the open file handle + `threading.Lock`, exposes `write(record: dict) -> None`), `build_log_record(...) -> dict` (pure function assembling the record shape below), and `sanitize_for_stderr(text: str, max_len: int = 300) -> str` plus `emit_stderr_summary(record: dict) -> None`.
- **HTTP handler** — `HoneypotRequestHandler(BaseHTTPRequestHandler)` implementing `do_POST`, `do_GET`, `do_DELETE` (and inheriting the 501 default for anything else). Owns: path check (`/mcp` vs. 404), body-size enforcement (413), body read with `errors="replace"` decoding, JSON parse attempt, building the `RequestContext`, calling `dispatch()`, calling the logging core, and writing the HTTP response (status, `Content-Type: application/json`, optional `Mcp-Session-Id` header, body bytes).
- **Session store** — module-level `SESSIONS: dict[str, dict]` + `SESSIONS_LOCK: threading.Lock`, written to only from the `initialize` handler, read from the handler when logging to attach a `session_id` if the client didn't send `Mcp-Session-Id` on a later call but did on `initialize`. (Plan explicitly does not require enforcing session-id presence — this is purely for log correlation.)
- **JSON-RPC dispatch** — `dispatch(msg: dict, ctx: RequestContext) -> dict | None`, a `METHODS: dict[str, Callable]` table, and one handler function per method: `handle_initialize`, `handle_notifications_initialized`, `handle_ping`, `handle_tools_list`, `handle_tools_call`. Wrapped in one `try/except Exception` inside `dispatch()` itself so *any* handler bug becomes a `-32603 Internal error` JSON-RPC object, never an unhandled exception reaching the transport layer.
- **Fake tool catalog** — `TOOLS: list[dict]` (the four `tools/list` entries: name, description, `inputSchema`) and `TOOL_HANDLERS: dict[str, Callable[[dict], dict]]` mapping tool name to a pure function that builds the fake `tools/call` result content. No tool handler imports or calls anything from `os`, `subprocess`, `socket`, `urllib`, `builtins.eval`, `builtins.exec`, or `importlib`/dynamic `import`.
- **README.md** (existing file at repo root, extended not replaced) — gets the run/log-location/client-pointing paragraph the plan calls for.
- **.gitignore** (existing file at repo root) — gains a `/honeypot.jsonl` entry; note the current `.gitignore` already has a `# Python` section (`__pycache__/`, `*.py[cod]`, `.venv/`, etc.) but no honeypot-specific log entry, so this is a one-line addition, not a new section.

## Data Flow / Interfaces

**Request lifecycle (one HTTP POST /mcp):**

```
socket bytes
  -> HoneypotRequestHandler.do_POST()
       - reject non-/mcp path: 404, no body, log skipped (transport-level, not a JSON-RPC exchange)
       - check Content-Length against MAX_BODY_BYTES; if missing/invalid or over cap -> 413, log a
         record with method=None, response="413 Payload Too Large", raw_body omitted/marked oversized
       - read exactly the declared length (bounded read), decode with errors="replace" -> raw_body: str
       - json.loads(raw_body); on failure -> parsed = None
  -> ctx = RequestContext(client_ip, client_port, headers, session_id_from_header)
  -> if parsed is None:
         response_obj = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
         http_status = 200
     elif "id" not in parsed:                      # JSON-RPC notification, must not be answered
         dispatch(parsed, ctx)                       # side effects only (e.g. session bookkeeping); return value ignored
         response_obj = None
         http_status = 202
     else:
         response_obj = dispatch(parsed, ctx)        # always returns a dict when "id" present (dispatch guarantees this)
         http_status = 200
  -> record = build_log_record(ctx, raw_body, parsed, response_obj_or_202_marker)
  -> log_writer.write(record)          # append + flush, lock-protected -- happens BEFORE the next line
  -> emit_stderr_summary(record)       # sanitized one-liner to stderr
  -> handler writes HTTP status + headers (+ Mcp-Session-Id if this exchange is/continues a session) + body bytes
```

`do_GET` and `do_DELETE` on `/mcp` short-circuit straight to `405 Method Not Allowed` with no JSON-RPC body (per plan's transport-vs-JSON-RPC split); any other path on any method is `404`. These are still logged as HTTP-level events is *not* required by the plan (only JSON-RPC exchange attempts are logged per the plan's log-record definition) — 404/405/413 are transport-level rejections and are handled entirely inside `do_GET`/`do_DELETE`/the path check without invoking `build_log_record`/`dispatch`, consistent with "Transport-level problems ... use HTTP status codes with no JSON-RPC body" in the plan. (413 is the one exception the plan calls out for a defensive reason — the oversized-body path still writes a log record, per the Risks section on memory-exhaustion DoS, so an operator can see the attempt — see Task 1.)

**Core function signatures:**

```python
@dataclass(frozen=True)
class RequestContext:
    client_ip: str
    client_port: int
    headers: dict[str, str]      # raw header values, opaque strings, never interpreted
    session_id: str | None       # from Mcp-Session-Id request header, else None

def dispatch(msg: dict, ctx: RequestContext) -> dict | None:
    """msg is a parsed JSON-RPC object known to be a dict. Returns a full JSON-RPC
    response dict (result or error) if msg has an 'id' key, else performs any side
    effects (e.g. recording the session on 'initialize') and returns None.
    Never raises -- internal handler exceptions are caught here and converted to
    a -32603 error response."""

def handle_initialize(params: dict, ctx: RequestContext) -> dict: ...      # -> result dict
def handle_ping(params: dict, ctx: RequestContext) -> dict: ...            # -> {}
def handle_tools_list(params: dict, ctx: RequestContext) -> dict: ...      # -> {"tools": TOOLS}
def handle_tools_call(params: dict, ctx: RequestContext) -> dict: ...      # -> MCP tool result dict

ToolHandler = Callable[[dict], dict]     # args -> {"content": [{"type": "text", "text": str}], "isError": bool}
TOOL_HANDLERS: dict[str, ToolHandler]    # keys match TOOLS[i]["name"]

def build_log_record(ctx: RequestContext, raw_body: str, parsed: dict | None,
                      response_obj: dict | None, http_status: int) -> dict: ...

class JSONLogWriter:
    def __init__(self, fh: TextIO) -> None: ...   # fh is opened once by main(), append mode, utf-8
    def write(self, record: dict) -> None: ...      # json.dumps + "\n", flush, all under self._lock

def sanitize_for_stderr(text: str, max_len: int = 300) -> str: ...
```

**Log record shape** (one JSON object per line, per plan): `ts` (ISO 8601 UTC), `client_ip`, `client_port`, `headers` (dict, values as opaque strings), `session_id` (string or `null`), `raw_body` (decoded with `errors="replace"`, or `null`/an "(oversized, N bytes)" marker string when the 413 cap was hit — never buffered in full when over cap), `method` (parsed JSON-RPC `method` or `null`), `tool_name` / `tool_arguments` (populated only when `method == "tools/call"`, taken from the *parsed* request params, not from the tool handler's output), `response` (the exact JSON-RPC body sent, or a transport-status string like `"202 Accepted (notification)"` / `"413 Payload Too Large"`), `http_status` (int).

**`initialize` result shape:** `{"protocolVersion": "2025-06-18", "serverInfo": {"name": "<honeypot's advertised name>", "version": "1.0.0"}, "capabilities": {"tools": {}}}`. `2025-06-18` is the design's chosen protocol-version string (most recent MCP spec revision date at design time) per the plan's Open Question; the honeypot advertises it unconditionally regardless of what the client requested, since the goal is to log the handshake attempt, not to negotiate correctly — a client that insists on a different version will still have its full request logged even if it then disconnects.

**Session-id issuance:** on a successful `initialize` request (one with an `"id"`), `dispatch` generates `session_id = uuid.uuid4().hex`, stores `SESSIONS[session_id] = {"created_at": ..., "client_ip": ...}` under `SESSIONS_LOCK`, and the HTTP handler sets the `Mcp-Session-Id` response header from the value `handle_initialize` returns via a side channel (simplest: `handle_initialize` stashes the new id into `ctx`-adjacent state by returning it as part of a small internal tuple `(result_dict, new_session_id)` that only `do_POST` unpacks; `dispatch()`'s public contract for every other method stays "returns the response dict directly" — this one asymmetry is documented in a code comment at the `dispatch` call site so the builder doesn't need to invent it ad hoc).

## Testability Notes

- **No test suite is a required deliverable** (plan explicitly leaves this to design/QA discretion and marks it out of scope as a *mandate*). Given that, this design still keeps the code trivially testable without committing to writing tests as a task, by enforcing two structural rules the QA phase can rely on if it chooses to add `unittest`-based tests:
  1. **Importing `mcp_honeypot` must have zero side effects.** All socket/file opening happens inside `main()`, gated by `if __name__ == "__main__":`. `python3 -c "import mcp_honeypot"` must succeed instantly and open nothing.
  2. **Protocol logic is separable from I/O.** `dispatch(msg, ctx)` and every `handle_*`/`TOOL_HANDLERS[...]` function take plain dicts/dataclasses and return plain dicts — no `self.rfile`/`self.wfile`, no file handle, no network. A test (or a human at a REPL) can call `dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {...}}, RequestContext(...))` directly and assert on the returned dict with no server running.
- **`build_log_record` and `sanitize_for_stderr` are pure functions** over their inputs — straightforward to test with adversarial strings (newlines, ANSI escapes, huge values) without touching the filesystem.
- **End-to-end smoke testing** (manual or QA-added) is straightforward via stdlib `http.client` or `curl` against `127.0.0.1:<port>` since the transport is plain HTTP/JSON — no SSE, no auth, no TLS to negotiate.
- **Concurrency correctness** (the `threading.Lock` around the log writer and session dict) is the one area that's awkward to unit-test meaningfully; if QA wants coverage here, the practical approach is a smoke test that fires N concurrent POSTs (e.g. via `concurrent.futures.ThreadPoolExecutor` driving `http.client` calls) and then asserts the resulting `honeypot.jsonl` has exactly N well-formed JSON lines (i.e., no interleaved/corrupted lines) rather than trying to unit-test the lock itself.
- **Safety-constraint verification is largely static, not runtime-testable in the traditional sense** — the strongest check is `grep`/read-through confirming the forbidden identifiers (`eval(`, `exec(`, `subprocess`, `socket.socket`, `urllib`, `importlib`, `open(` outside the one log-file call site) don't appear in tool handlers or dispatch code. This is called out explicitly as an acceptance criterion in Task 4 so the code-review and security-review passes have something concrete to grep for, not just prose to trust.

## Task Breakdown

1. **HTTP server + JSON-RPC envelope + logging core.** Create `mcp_honeypot.py` at the repo root with: `build_arg_parser`/`main` (CLI flags `--host` 127.0.0.1, `--port` 8000, `--log-file` ./honeypot.jsonl, all side effects gated behind `if __name__ == "__main__":`); `ThreadingHTTPServer` + `HoneypotRequestHandler` wired to it; routing so only `POST /mcp` is handled meaningfully (`GET`/`DELETE` on `/mcp` -> 405, any other path -> 404, no JSON-RPC body on either); body-size cap (`MAX_BODY_BYTES = 1_048_576`) enforced via `Content-Length` check before/while reading, returning 413 for oversized or missing/invalid `Content-Length`, with the request still logged (raw_body replaced by an "(oversized, N bytes)" marker, not buffered in full); UTF-8 decode with `errors="replace"`; `json.loads` attempt producing `parsed: dict | None`; `RequestContext` dataclass; `JSONLogWriter` (single file handle opened once in `main()`, `threading.Lock`-guarded `write()` that appends one `json.dumps(record) + "\n"` and flushes before returning); `build_log_record`; `sanitize_for_stderr` (strips `[\x00-\x1f\x7f]` control chars including bare ESC-sequence bytes, truncates to a bounded length) and `emit_stderr_summary`; the log-before-respond glue (build response object -> log it -> then write HTTP response bytes). At this stage `dispatch()` can be a stub that always returns a `-32601 Method not found` error (or `-32700` for unparseable JSON) — full method handling comes in Task 2. Also add `/honeypot.jsonl` to `.gitignore` (repo root, next to the existing `# Python` section). **Acceptance:** `python3 mcp_honeypot.py` starts and binds `127.0.0.1:8000`; `curl -s -X POST http://127.0.0.1:8000/mcp -d '{"jsonrpc":"2.0","id":1,"method":"x"}'` returns HTTP 200 with a JSON-RPC `-32601` (or `-32700` for invalid JSON) body; `honeypot.jsonl` gains exactly one well-formed JSON line per request, flushed immediately (`wc -l` after each curl matches); stderr prints one sanitized single-line summary per request with no raw newlines/control chars even when the request body contains them; `curl -X GET .../mcp` and `curl -X DELETE .../mcp` return 405 with empty body; a bogus path returns 404; a body larger than the cap (e.g. `dd`/python-generated >1MiB payload) returns 413 without the process reading the full body into memory and is still logged with a truncated marker; `python3 -c "import mcp_honeypot"` opens no sockets/files (no `honeypot.jsonl` created by import alone).

2. **JSON-RPC protocol methods: initialize, notifications/initialized, ping, and error handling.** Replace the Task 1 dispatch stub with the real `dispatch(msg, ctx) -> dict | None` and `METHODS` table. Implement `handle_initialize` (returns `protocolVersion: "2025-06-18"`, `serverInfo`, `capabilities: {"tools": {}}`; generates and stores a new `Mcp-Session-Id` via `uuid.uuid4().hex` in `SESSIONS`/`SESSIONS_LOCK`, surfaced back to `do_POST` so it can set the response header); `handle_notifications_initialized` (no-op side effect only); `handle_ping` (returns `{}`); the notification path (any parsed message lacking `"id"` is dispatched for side effects only, then answered with HTTP 202 and empty body, logged with `response = "202 Accepted (notification)"`); unknown methods -> `-32601`; malformed JSON already produces `-32700` from Task 1 wiring, confirm it flows through unchanged; wrap the entire per-method call inside `dispatch()` in `try/except Exception` producing `-32603 Internal error` on any handler exception (never letting one escape to crash the handler thread or hang the connection). **Acceptance:** `initialize` request returns a well-formed result with the fields above and an `Mcp-Session-Id` response header; a follow-up `notifications/initialized` (no `"id"`) returns HTTP 202 with empty body and is still logged; `ping` returns `{"jsonrpc":"2.0","id":<echoed>,"result":{}}`; a request with an unknown method (and an `"id"`) returns a `-32601` JSON-RPC error, HTTP 200; a hand-crafted request that would trigger a handler exception (e.g. monkeypatch or a deliberately malformed `params` type during manual testing) yields a `-32603` error instead of a stack trace or dropped connection; the server process never exits/crashes across any of the above.

3. **Fake tool catalog + tools/list + tools/call.** Define `TOOLS` (four entries — a file reader e.g. `read_file`, a database query runner e.g. `query_database`, a credential/secret lookup e.g. `get_credential`, an outbound email sender e.g. `send_email` — each with a realistic `name`, `description`, and JSON Schema `inputSchema`) and `TOOL_HANDLERS` (pure functions, one per tool, each takes only the parsed `arguments` dict and returns an MCP `tools/call` content result — `{"content": [{"type": "text", "text": "..."}], "isError": false}` — built purely from string formatting/echoing the caller's arguments; explicitly no `open()`, `subprocess`, `socket`, `urllib`, `eval`, `exec`, or dynamic `import` anywhere in these functions or their call path; the "secret" returned by `get_credential` must be an obviously-synthetic placeholder value, not something realistic-looking). Implement `handle_tools_list` (returns `{"tools": TOOLS}`) and `handle_tools_call` (looks up `params["name"]` in `TOOL_HANDLERS`; unknown tool name returns a JSON-RPC result with `isError: true` and an explanatory message rather than crashing or emitting a raw exception; on success returns the handler's result). Extend `build_log_record` (from Task 1) so that when `method == "tools/call"`, `tool_name` and `tool_arguments` are populated straight from the parsed request `params`, never from the tool's fabricated output. **Acceptance:** `tools/list` returns exactly 4 tools, each with a non-empty `name`/`description` and a valid JSON Schema object under `inputSchema`; `tools/call` against each of the 4 tools returns a `content` array whose text echoes back at least one caller-supplied argument (proving no real I/O occurred while still looking responsive); `tools/call` with an unrecognized tool name returns a well-formed error/`isError:true` result, HTTP 200, connection stays alive; the corresponding `honeypot.jsonl` line for any `tools/call` request has non-null `tool_name` and `tool_arguments` matching what was sent; `grep -nE "eval\(|exec\(|subprocess|urllib|socket\.socket|importlib" mcp_honeypot.py` matches nothing inside the tool-handler section (and none of the tool handler functions call `open()`).

4. **CLI finishing touches, safety self-check, and README.** Finalize `--host`/`--port`/`--log-file` argparse help text and defaults (confirm log path resolves relative to CWD at start, per plan); confirm the log file is opened once in append mode in `main()` and the handle is reused for the process lifetime (not reopened per request); do a full read-through/grep pass over the finished file confirming no forbidden identifiers (`eval(`, `exec(`, `subprocess`, `socket.socket`, `urllib`, `importlib`, `open(` outside the single log-file open call in `main()`) appear anywhere, and add a short comment block near the top of `mcp_honeypot.py` stating the non-negotiable safety invariants (no real I/O beyond the log file, no outbound network, no dynamic execution of client-derived data) so future edits are guided by an explicit in-file marker. Update root `README.md` (currently a one-line stub) by adding one paragraph covering: how to run it (`python3 mcp_honeypot.py [--host H] [--port P] [--log-file PATH]`), where logs go (JSONL at `--log-file`, default `./honeypot.jsonl` relative to CWD, plus the sanitized stderr mirror), how to point an MCP client at it (`http://<host>:<port>/mcp`, streamable-HTTP transport, single-request/response only — no SSE), and an explicit warning that the default bind (`127.0.0.1`) is safe for local testing but rebinding to `0.0.0.0` to expose it as a real decoy removes the only implicit protection against `ThreadingHTTPServer`'s lack of connection/thread limits. **Acceptance:** `python3 mcp_honeypot.py --help` documents all three flags with their defaults; `README.md` contains the new paragraph with run/log-location/client-URL/exposure-warning content described above, appended to (not replacing) the existing one-line project description; the safety grep from Task 3's acceptance criterion, re-run against the complete file, still matches nothing; a fresh clone + `python3 mcp_honeypot.py` + one `curl` round-trip + `Ctrl-C` leaves behind only `honeypot.jsonl` (already gitignored) with no other file writes anywhere on disk.
