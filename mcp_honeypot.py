"""mcp_honeypot.py -- a minimal decoy MCP (Model Context Protocol) server.

Safety invariants (non-negotiable, verify any change against these):
  - Never eval, exec, subprocess, or import anything derived from client input.
  - Never make outbound network requests.
  - Never read or write files outside the configured log path.
  - The log file is append-only; treat every logged value as untrusted text
    (the JSONL write is structurally safe via json.dumps; the stderr mirror
    must always go through sanitize_for_stderr).

This module has zero import-time side effects: no socket is opened, no file
is opened, and no server is started merely by `import mcp_honeypot`. All of
that happens inside main(), gated by `if __name__ == "__main__":`.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TextIO

MAX_BODY_BYTES = 1_048_576
SOCKET_TIMEOUT_SECONDS = 10
MAX_CONCURRENT_CONNECTIONS = 200
MAX_SESSIONS = 10_000
MAX_LEADING_BLANK_REQUEST_LINES = 5


@dataclass(frozen=True)
class RequestContext:
    client_ip: str
    client_port: int
    headers: dict
    session_id: str | None


@dataclass(frozen=True)
class DispatchResult:
    response: dict | None
    session_id: str | None


def headers_to_dict(msg) -> dict:
    """RFC 7230 SS3.2.2-style merge: repeated header names are joined with
    ', ' in the order received, rather than silently keeping only the last
    value."""
    result: dict = {}
    for key, value in msg.items():
        result[key] = f"{result[key]}, {value}" if key in result else value
    return result


def _classify_content_length(headers, max_body_bytes: int = MAX_BODY_BYTES):
    """Pure function over a parsed header set. Returns (outcome, length):
      ("ok", N)                            -- exactly one Content-Length header,
                                               a valid non-negative base-10
                                               integer, N <= max_body_bytes, and
                                               Transfer-Encoding absent or a
                                               single "identity" occurrence.
      ("chunked", None)                    -- exactly one Transfer-Encoding
                                               header present with a value other
                                               than "identity" (case-insensitive).
      ("duplicate_transfer_encoding", None) -- more than one Transfer-Encoding
                                               header.
      ("duplicate_content_length", None)   -- more than one Content-Length
                                               header.
      ("missing_or_invalid", None)         -- zero Content-Length headers, or
                                               the single value present isn't a
                                               valid non-negative base-10
                                               integer, or it exceeds
                                               max_body_bytes.

    Checked in this order: Transfer-Encoding duplicates, then
    Transfer-Encoding value, then Content-Length duplicates, then
    Content-Length value.
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


def _build_error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


class InvalidParamsError(Exception):
    """Raised by a method handler to signal a -32602 Invalid params
    condition. Caught inside dispatch(), never escapes it. No handler
    raises this yet (that lands with handle_tools_call's argument
    validation); the plumbing exists here regardless."""


SESSIONS: "OrderedDict[str, dict]" = OrderedDict()
SESSIONS_LOCK = threading.Lock()


def _issue_session_id() -> str:
    session_id = uuid.uuid4().hex
    with SESSIONS_LOCK:
        if len(SESSIONS) >= MAX_SESSIONS:
            SESSIONS.popitem(last=False)
        SESSIONS[session_id] = {}
    return session_id


def handle_initialize(params: dict, ctx: RequestContext) -> dict:
    return {
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": "mcp-honeypot", "version": "1.0.0"},
        "capabilities": {"tools": {}},
    }


def handle_notifications_initialized(params: dict, ctx: RequestContext) -> dict:
    return {}


def handle_ping(params: dict, ctx: RequestContext) -> dict:
    return {}


METHODS = {
    "initialize": handle_initialize,
    "notifications/initialized": handle_notifications_initialized,
    "ping": handle_ping,
}


def dispatch(msg: dict, ctx: RequestContext) -> DispatchResult:
    """`msg` is already known to be a dict with a string "method" (the
    caller, _handle_request, validates this before calling dispatch --
    dispatch never needs to guard against non-dict/non-object top-level
    input).

    Looks up msg["method"] in METHODS; on a match, calls
    handler(msg.get("params") or {}, ctx) inside
    try/except InvalidParamsError (-> -32602) / except Exception (-> -32603).
    On no match: -32601 Method not found.

    If method == "initialize" and no error occurred, mints a new session id
    and records it in SESSIONS (capped/evicting), regardless of whether msg
    has an "id". Every other method call leaves session_id as None.

    Never raises.
    """
    method = msg.get("method")
    params = msg.get("params") or {}
    handler = METHODS.get(method)
    session_id = None

    if handler is None:
        result_or_error = {"error": {"code": -32601, "message": "Method not found"}}
    else:
        try:
            result = handler(params, ctx)
            result_or_error = {"result": result}
            if method == "initialize":
                session_id = _issue_session_id()
        except InvalidParamsError as exc:
            result_or_error = {"error": {"code": -32602, "message": str(exc)}}
        except Exception:
            result_or_error = {"error": {"code": -32603, "message": "Internal error"}}

    if "id" not in msg:
        return DispatchResult(response=None, session_id=session_id)
    return DispatchResult(
        response={"jsonrpc": "2.0", "id": msg["id"], **result_or_error},
        session_id=session_id,
    )


def build_log_record(
    ctx: RequestContext,
    http_method: str,
    path: str,
    raw_body,
    parsed,
    response_obj,
    http_status,
    internal_fault: bool = False,
) -> dict:
    method = parsed.get("method") if isinstance(parsed, dict) else None
    tool_name = None
    tool_arguments = None
    if method == "tools/call" and isinstance(parsed, dict):
        params = parsed.get("params")
        if isinstance(params, dict):
            tool_name = params.get("name")
            tool_arguments = params.get("arguments")

    logged_response = response_obj
    if http_status == 202 and response_obj is None:
        logged_response = "202 Accepted (notification)"

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "client_ip": ctx.client_ip,
        "client_port": ctx.client_port,
        "http_method": http_method,
        "path": path,
        "headers": ctx.headers,
        "session_id": ctx.session_id,
        "raw_body": raw_body,
        "method": method,
        "tool_name": tool_name,
        "tool_arguments": tool_arguments,
        "response": logged_response,
        "http_status": http_status,
    }
    if internal_fault:
        record["internal_fault"] = True
    return record


def build_stdlib_rejection_record(
    client_ip,
    client_port,
    http_method,
    path,
    headers: dict,
    detail: str,
) -> dict:
    """Builds a record for a request rejected by the stdlib's own
    request-line/header parsing or its own request-line-level timeout, i.e.
    one intercepted via the log_error() or handle_one_request() overrides
    rather than _handle_request()."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "client_port": client_port,
        "http_method": http_method,
        "path": path,
        "headers": headers,
        "session_id": None,
        "raw_body": None,
        "method": None,
        "tool_name": None,
        "tool_arguments": None,
        "response": None,
        "http_status": None,
        "stdlib_rejection": True,
        "detail": detail,
    }


def sanitize_for_stderr(text: str, max_len: int = 300) -> str:
    stripped = "".join(ch for ch in text if not (ch <= "\x1f" or ch == "\x7f"))
    if len(stripped) > max_len:
        return stripped[:max_len] + "...(truncated)"
    return stripped


def emit_stderr_summary(record: dict) -> None:
    try:
        if record.get("stdlib_rejection"):
            summary = (
                f"[honeypot] {record.get('client_ip')}:{record.get('client_port')} "
                f"stdlib_rejection detail={record.get('detail')}"
            )
        else:
            summary = (
                f"[honeypot] {record.get('client_ip')}:{record.get('client_port')} "
                f"{record.get('http_method')} {record.get('path')} "
                f"-> {record.get('http_status')} method={record.get('method')}"
            )
        sys.stderr.write(sanitize_for_stderr(summary) + "\n")
    except Exception:
        pass


class JSONLogWriter:
    def __init__(self, fh: TextIO) -> None:
        self._fh = fh
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = json.dumps(record) + "\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()


log_writer: JSONLogWriter | None = None


class HoneypotHTTPServer(ThreadingHTTPServer):
    def __init__(self, *args, max_concurrent: int = MAX_CONCURRENT_CONNECTIONS, **kwargs):
        super().__init__(*args, **kwargs)
        self._conn_semaphore = threading.BoundedSemaphore(max_concurrent)

    def process_request(self, request, client_address):
        if not self._conn_semaphore.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_semaphore.release()


class HoneypotRequestHandler(BaseHTTPRequestHandler):
    timeout = SOCKET_TIMEOUT_SECONDS
    server_version = "mcp-honeypot/1.0"

    def handle_one_request(self) -> None:
        """Near-verbatim reproduction of BaseHTTPRequestHandler's own
        handle_one_request(), with one inserted block that detects and logs
        a blank/whitespace-only leading request line before it reaches
        parse_request() -- the one case log_error() structurally cannot
        observe, since CPython's parse_request() returns False for it
        without ever calling send_error()/log_error(). Bounded by
        MAX_LEADING_BLANK_REQUEST_LINES consecutive skips."""
        try:
            blank_lines_skipped = 0
            while True:
                self.raw_requestline = self.rfile.readline(65537)
                if len(self.raw_requestline) > 65536:
                    self.requestline = ""
                    self.request_version = ""
                    self.command = ""
                    self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                    return
                if not self.raw_requestline:
                    self.close_connection = True
                    return
                if (
                    self.raw_requestline.strip()
                    or blank_lines_skipped >= MAX_LEADING_BLANK_REQUEST_LINES
                ):
                    break
                blank_lines_skipped += 1
                self._log_blank_request_line()

            if not self.parse_request():
                return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(
                    HTTPStatus.NOT_IMPLEMENTED,
                    "Unsupported method (%r)" % self.command,
                )
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush()
        except TimeoutError as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    def _log_blank_request_line(self) -> None:
        """Logs a blank/whitespace-only first request line -- the one case
        log_error() cannot see. Wrapped entirely in its own
        try/except Exception: pass so a failure here can never prevent
        handle_one_request() from continuing on to read the real,
        following request line."""
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
                sys.stderr.write(
                    f"[honeypot] WARNING: log write failed: "
                    f"{sanitize_for_stderr(repr(log_err))}\n"
                )
            emit_stderr_summary(record)
        except Exception:
            pass

    def log_error(self, format: str, *args) -> None:
        """Stdlib's BaseHTTPRequestHandler calls log_error() from exactly
        two places: send_error() (itself invoked by parse_request() for a
        malformed request line, an oversized request line, an unsupported
        HTTP version, oversized/too-many headers, or an unimplemented HTTP
        verb) and handle_one_request()'s own `except TimeoutError` branch (a
        client stalling before completing its request line). The entire
        body is wrapped in one try/except Exception: pass so a bug anywhere
        above can never prevent super().log_error(...) from running or leak
        an unsanitized traceback to stderr."""
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
                log_writer.write(record)
            except Exception as log_err:
                sys.stderr.write(
                    f"[honeypot] WARNING: log write failed: "
                    f"{sanitize_for_stderr(repr(log_err))}\n"
                )
            emit_stderr_summary(record)
        except Exception:
            pass
        super().log_error(format, *args)

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def do_PUT(self) -> None:
        self._handle_request("PUT")

    def do_PATCH(self) -> None:
        self._handle_request("PATCH")

    def do_DELETE(self) -> None:
        self._handle_request("DELETE")

    def do_HEAD(self) -> None:
        self._handle_request("HEAD")

    def do_OPTIONS(self) -> None:
        self._handle_request("OPTIONS")

    def _build_context(self) -> RequestContext:
        headers = headers_to_dict(self.headers)
        session_id = headers.get("Mcp-Session-Id")
        return RequestContext(
            client_ip=self.client_address[0],
            client_port=self.client_address[1],
            headers=headers,
            session_id=session_id,
        )

    def _handle_request(self, http_method: str) -> None:
        self._response_sent = False
        try:
            ctx = self._build_context()
            path = self.path
            raw_body = None
            parsed = None
            response_obj = None
            session_id_to_issue = None
            http_status = None

            if path != "/mcp":
                http_status = 404
            elif http_method != "POST":
                http_status = 405
            else:
                outcome, length = _classify_content_length(self.headers)
                if outcome == "chunked":
                    http_status = 411
                    raw_body = "(Transfer-Encoding: chunked not supported)"
                elif outcome == "duplicate_content_length":
                    http_status = 400
                    raw_body = "(duplicate Content-Length headers)"
                elif outcome == "duplicate_transfer_encoding":
                    http_status = 400
                    raw_body = "(duplicate Transfer-Encoding headers)"
                elif outcome == "missing_or_invalid":
                    http_status = 413
                    raw_body = "(missing, invalid, or oversized Content-Length)"
                else:
                    body_bytes = self.rfile.read(length)
                    raw_body = body_bytes.decode("utf-8", errors="replace")
                    try:
                        parsed = json.loads(raw_body)
                    except json.JSONDecodeError:
                        parsed = None

                    if parsed is None:
                        response_obj = _build_error(None, -32700, "Parse error")
                        http_status = 200
                    elif not isinstance(parsed, dict) or not isinstance(
                        parsed.get("method"), str
                    ):
                        safe_id = parsed.get("id") if isinstance(parsed, dict) else None
                        response_obj = _build_error(safe_id, -32600, "Invalid Request")
                        http_status = 200
                    else:
                        dr = dispatch(parsed, ctx)
                        session_id_to_issue = dr.session_id
                        if dr.response is None:
                            response_obj, http_status = None, 202
                        else:
                            response_obj, http_status = dr.response, 200

            record = build_log_record(
                ctx, http_method, path, raw_body, parsed, response_obj, http_status
            )

            try:
                log_writer.write(record)
            except Exception as log_err:
                sys.stderr.write(
                    f"[honeypot] WARNING: log write failed: "
                    f"{sanitize_for_stderr(repr(log_err))}\n"
                )
            emit_stderr_summary(record)

            self._send_response(
                http_status, response_obj, session_id_to_issue, allow_header=(http_status == 405)
            )
        except Exception:
            self._emergency_fallback(http_method)

    def _send_response(
        self, http_status: int, response_obj, session_id_to_issue, allow_header: bool = False
    ) -> None:
        if response_obj is not None:
            body = json.dumps(response_obj).encode("utf-8")
        else:
            body = b""

        self.send_response(http_status)
        if allow_header:
            self.send_header("Allow", "POST")
        if session_id_to_issue is not None:
            self.send_header("Mcp-Session-Id", session_id_to_issue)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        self._response_sent = True

    def _send_minimal_500(self) -> None:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": "Internal error"},
            }
        ).encode("utf-8")
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _emergency_fallback(self, http_method: str) -> None:
        if not getattr(self, "_response_sent", False):
            try:
                self._send_minimal_500()
                self._response_sent = True
            except Exception:
                pass
        try:
            ctx = RequestContext(
                client_ip=self.client_address[0],
                client_port=self.client_address[1],
                headers={},
                session_id=None,
            )
            record = build_log_record(
                ctx, http_method, getattr(self, "path", None), None, None, None, 500,
                internal_fault=True,
            )
            log_writer.write(record)
        except Exception:
            pass
        try:
            sys.stderr.write("[honeypot] WARNING: internal fault handling request\n")
        except Exception:
            pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp_honeypot.py",
        description="A minimal decoy MCP (Model Context Protocol) server.",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host/IP to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port to bind to (default: 8000)"
    )
    parser.add_argument(
        "--log-file",
        default="./honeypot.jsonl",
        help="Path to the JSONL log file (default: ./honeypot.jsonl)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    global log_writer

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    fh = open(args.log_file, "a", encoding="utf-8")
    log_writer = JSONLogWriter(fh)

    server = HoneypotHTTPServer((args.host, args.port), HoneypotRequestHandler)
    print(f"[honeypot] listening on {args.host}:{args.port}, logging to {args.log_file}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
