"""QA test suite for mcp_honeypot.py.

Independent test authorship: derived from .loop/mcp-honeypot/plan.md and
design.md's Task Breakdown acceptance criteria, not from reading how
mcp_honeypot.py happens to be implemented.

Uses stdlib unittest only, matching the project's own stdlib-only
philosophy. Run with:

    python3 -m unittest test_mcp_honeypot -v

or

    python3 test_mcp_honeypot.py -v
"""

from __future__ import annotations

import contextlib
import email.message
import http.client
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

import mcp_honeypot as hp  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _dummy_ctx(session_id=None) -> hp.RequestContext:
    return hp.RequestContext(
        client_ip="127.0.0.1", client_port=54321, headers={}, session_id=session_id
    )


class LiveServer:
    """Starts a real HoneypotHTTPServer + HoneypotRequestHandler on an
    OS-assigned free port, backed by a temp JSONL log file, and swaps in a
    dedicated JSONLogWriter for the module-global `hp.log_writer` for the
    duration of its lifetime. Intended for use as a per-TestCase-class
    fixture (setUpClass/tearDownClass)."""

    def __init__(self, max_concurrent=None, handler_timeout=None):
        fd, self.log_path = tempfile.mkstemp(suffix=".jsonl", prefix="qa-honeypot-")
        os.close(fd)
        self._fh = open(self.log_path, "a", encoding="utf-8")
        self._prev_log_writer = hp.log_writer
        hp.log_writer = hp.JSONLogWriter(self._fh)

        self._prev_timeout = hp.HoneypotRequestHandler.timeout
        if handler_timeout is not None:
            hp.HoneypotRequestHandler.timeout = handler_timeout

        kwargs = {}
        if max_concurrent is not None:
            kwargs["max_concurrent"] = max_concurrent
        self.server = hp.HoneypotHTTPServer(
            ("127.0.0.1", 0), hp.HoneypotRequestHandler, **kwargs
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Give the accept loop a moment to actually be listening/selecting.
        time.sleep(0.05)

    def read_log_lines(self):
        self._fh.flush()
        with open(self.log_path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self._fh.close()
        hp.log_writer = self._prev_log_writer
        hp.HoneypotRequestHandler.timeout = self._prev_timeout
        try:
            os.unlink(self.log_path)
        except OSError:
            pass


def http_request(port, method, path, body=None, headers=None, timeout=5):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def raw_request(port, raw_bytes: bytes, idle_timeout=1.0, overall_timeout=5.0) -> bytes:
    """Sends raw bytes over a fresh TCP connection and accumulates whatever
    the server sends back until either the connection closes or no new
    data arrives for `idle_timeout` seconds."""
    chunks = []
    deadline = time.monotonic() + overall_timeout
    with socket.create_connection(("127.0.0.1", port), timeout=idle_timeout) as s:
        s.sendall(raw_bytes)
        while time.monotonic() < deadline:
            s.settimeout(idle_timeout)
            try:
                data = s.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# U-series: pure-function unit tests, no server, no socket
# ---------------------------------------------------------------------------


class HeadersToDictTests(unittest.TestCase):
    def test_u1_duplicate_headers_comma_joined_in_order(self):
        msg = email.message.Message()
        msg.add_header("X-Foo", "a")
        msg.add_header("X-Foo", "b")
        msg.add_header("User-Agent", "test-client/1.0")
        result = hp.headers_to_dict(msg)
        self.assertEqual(result["X-Foo"], "a, b")
        self.assertEqual(result["User-Agent"], "test-client/1.0")


class ClassifyContentLengthTests(unittest.TestCase):
    def _msg(self, headers):
        m = email.message.Message()
        for k, v in headers:
            m.add_header(k, v)
        return m

    def test_u2_ok(self):
        outcome, length = hp._classify_content_length(self._msg([("Content-Length", "10")]))
        self.assertEqual((outcome, length), ("ok", 10))

    def test_u2_chunked(self):
        outcome, length = hp._classify_content_length(
            self._msg([("Transfer-Encoding", "chunked")])
        )
        self.assertEqual((outcome, length), ("chunked", None))

    def test_u2_identity_transfer_encoding_is_not_chunked(self):
        outcome, length = hp._classify_content_length(
            self._msg([("Transfer-Encoding", "identity"), ("Content-Length", "3")])
        )
        self.assertEqual((outcome, length), ("ok", 3))

    def test_u2_duplicate_transfer_encoding(self):
        outcome, length = hp._classify_content_length(
            self._msg(
                [("Transfer-Encoding", "identity"), ("Transfer-Encoding", "chunked")]
            )
        )
        self.assertEqual((outcome, length), ("duplicate_transfer_encoding", None))

    def test_u2_duplicate_content_length_even_if_values_agree(self):
        outcome, length = hp._classify_content_length(
            self._msg([("Content-Length", "5"), ("Content-Length", "5")])
        )
        self.assertEqual((outcome, length), ("duplicate_content_length", None))

    def test_u2_missing_content_length(self):
        outcome, length = hp._classify_content_length(self._msg([]))
        self.assertEqual((outcome, length), ("missing_or_invalid", None))

    def test_u2_non_numeric_content_length(self):
        outcome, length = hp._classify_content_length(self._msg([("Content-Length", "abc")]))
        self.assertEqual((outcome, length), ("missing_or_invalid", None))

    def test_u3_oversized_content_length(self):
        outcome, length = hp._classify_content_length(
            self._msg([("Content-Length", str(hp.MAX_BODY_BYTES + 1))])
        )
        self.assertEqual((outcome, length), ("missing_or_invalid", None))


class SanitizeForStderrTests(unittest.TestCase):
    def test_u4_strips_control_chars_and_newlines(self):
        text = "abc\x1b[31mRED\x1b[0m\x07\ndef\x00ghi"
        out = hp.sanitize_for_stderr(text)
        for ch in out:
            self.assertFalse(ch <= "\x1f" or ch == "\x7f", f"control char leaked: {ch!r}")
        self.assertIn("abc", out)
        self.assertIn("def", out)

    def test_u4_truncates_long_input(self):
        out = hp.sanitize_for_stderr("x" * 1000, max_len=50)
        self.assertTrue(out.endswith("...(truncated)"))
        self.assertLessEqual(len(out), 50 + len("...(truncated)"))


class ValidateArgumentsTests(unittest.TestCase):
    INT_SCHEMA = {
        "type": "object",
        "required": ["n"],
        "properties": {"n": {"type": "integer"}},
    }

    def test_u5_bool_rejected_for_integer_field(self):
        with self.assertRaises(hp.InvalidParamsError):
            hp.validate_arguments(self.INT_SCHEMA, {"n": True})
        with self.assertRaises(hp.InvalidParamsError):
            hp.validate_arguments(self.INT_SCHEMA, {"n": False})

    def test_u5_real_integers_zero_and_one_accepted(self):
        hp.validate_arguments(self.INT_SCHEMA, {"n": 0})  # must not raise
        hp.validate_arguments(self.INT_SCHEMA, {"n": 1})  # must not raise

    def test_u6_missing_required_argument_raises(self):
        with self.assertRaises(hp.InvalidParamsError):
            hp.validate_arguments(self.INT_SCHEMA, {})

    def test_u7_wrong_type_non_bool_raises(self):
        schema = {
            "type": "object",
            "required": ["s"],
            "properties": {"s": {"type": "string"}},
        }
        with self.assertRaises(hp.InvalidParamsError):
            hp.validate_arguments(schema, {"s": 42})


class DispatchUnitTests(unittest.TestCase):
    def setUp(self):
        self._sessions_snapshot = hp.SESSIONS.copy()
        hp.SESSIONS.clear()

    def tearDown(self):
        hp.SESSIONS.clear()
        hp.SESSIONS.update(self._sessions_snapshot)

    def test_u8_unknown_method_with_id_is_32601(self):
        dr = hp.dispatch({"jsonrpc": "2.0", "id": 1, "method": "nope"}, _dummy_ctx())
        self.assertIsNotNone(dr.response)
        self.assertEqual(dr.response["error"]["code"], -32601)

    def test_u9_notification_without_id_returns_none_response(self):
        dr = hp.dispatch({"jsonrpc": "2.0", "method": "ping"}, _dummy_ctx())
        self.assertIsNone(dr.response)

    def test_u10_initialize_mints_fresh_session_ids(self):
        dr1 = hp.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, _dummy_ctx())
        dr2 = hp.dispatch({"jsonrpc": "2.0", "id": 2, "method": "initialize"}, _dummy_ctx())
        self.assertIsNotNone(dr1.session_id)
        self.assertIsNotNone(dr2.session_id)
        self.assertNotEqual(dr1.session_id, dr2.session_id)
        self.assertIn(dr1.session_id, hp.SESSIONS)
        self.assertIn(dr2.session_id, hp.SESSIONS)

    def test_u11_session_cap_eviction(self):
        original_max = hp.MAX_SESSIONS
        hp.MAX_SESSIONS = 3
        try:
            ids = []
            for i in range(5):
                dr = hp.dispatch(
                    {"jsonrpc": "2.0", "id": i, "method": "initialize"}, _dummy_ctx()
                )
                ids.append(dr.session_id)
            self.assertEqual(len(hp.SESSIONS), 3)
            # earliest two evicted, most recent three retained
            self.assertNotIn(ids[0], hp.SESSIONS)
            self.assertNotIn(ids[1], hp.SESSIONS)
            for sid in ids[2:]:
                self.assertIn(sid, hp.SESSIONS)
        finally:
            hp.MAX_SESSIONS = original_max

    def test_u12_build_log_record_shape_and_tool_fields(self):
        ctx = _dummy_ctx()
        parsed = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/x"}},
        }
        record = hp.build_log_record(ctx, "POST", "/mcp", "{}", parsed, {"result": {}}, 200)
        for field in (
            "ts",
            "client_ip",
            "client_port",
            "http_method",
            "path",
            "headers",
            "session_id",
            "raw_body",
            "method",
            "tool_name",
            "tool_arguments",
            "response",
            "http_status",
        ):
            self.assertIn(field, record)
        self.assertEqual(record["tool_name"], "read_file")
        self.assertEqual(record["tool_arguments"], {"path": "/x"})

    def test_u12_build_log_record_no_tool_fields_for_non_tools_call(self):
        ctx = _dummy_ctx()
        parsed = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        record = hp.build_log_record(ctx, "POST", "/mcp", "{}", parsed, {"result": {}}, 200)
        self.assertIsNone(record["tool_name"])
        self.assertIsNone(record["tool_arguments"])

    def test_u12_build_stdlib_rejection_record_shape(self):
        record = hp.build_stdlib_rejection_record(
            client_ip="1.2.3.4",
            client_port=9999,
            http_method=None,
            path=None,
            headers={},
            detail="blank request line",
        )
        self.assertTrue(record["stdlib_rejection"])
        self.assertIsNone(record["http_status"])
        self.assertIsNone(record["response"])
        self.assertEqual(record["detail"], "blank request line")


class ImportSideEffectTests(unittest.TestCase):
    def test_m1_import_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as d:
            before = set(os.listdir(d))
            result = subprocess.run(
                [sys.executable, "-c", "import mcp_honeypot"],
                cwd=d,
                env={**os.environ, "PYTHONPATH": REPO_ROOT},
                capture_output=True,
                timeout=10,
            )
            after = set(os.listdir(d))
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(before, after, "import created unexpected files")


# ---------------------------------------------------------------------------
# E-series: end-to-end tests against a live in-process server
# ---------------------------------------------------------------------------


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = LiveServer()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def _post_json(self, obj, headers=None):
        body = json.dumps(obj)
        status, hdrs, data = http_request(
            self.srv.port,
            "POST",
            "/mcp",
            body=body,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        return status, hdrs, data

    def test_e1_initialize_golden_path(self):
        before = len(self.srv.read_log_lines())
        status, hdrs, data = self._post_json({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(status, 200)
        body = json.loads(data)
        result = body["result"]
        self.assertIn("protocolVersion", result)
        self.assertIn("serverInfo", result)
        self.assertIn("tools", result["capabilities"])
        self.assertIn("Mcp-Session-Id", hdrs)
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertEqual(after[-1]["http_status"], 200)

    def test_e1_initialize_session_id_is_fresh_each_time(self):
        _, hdrs1, _ = self._post_json({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        _, hdrs2, _ = self._post_json({"jsonrpc": "2.0", "id": 2, "method": "initialize"})
        self.assertNotEqual(hdrs1["Mcp-Session-Id"], hdrs2["Mcp-Session-Id"])

    def test_e2_notification_returns_202_and_is_logged(self):
        before = len(self.srv.read_log_lines())
        status, hdrs, data = self._post_json(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        self.assertEqual(status, 202)
        self.assertEqual(data, b"")
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertEqual(after[-1]["response"], "202 Accepted (notification)")

    def test_e3_ping(self):
        status, _, data = self._post_json({"jsonrpc": "2.0", "id": 5, "method": "ping"})
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["result"], {})
        self.assertEqual(body["id"], 5)

    def test_e4_unknown_method(self):
        before = len(self.srv.read_log_lines())
        status, _, data = self._post_json({"jsonrpc": "2.0", "id": 1, "method": "bogus/method"})
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], -32601)
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)

    def test_e5_non_conforming_top_level_json(self):
        for payload in ("42", "[1,2,3]", "true", json.dumps({"id": 1})):
            with self.subTest(payload=payload):
                before = len(self.srv.read_log_lines())
                status, hdrs, data = http_request(
                    self.srv.port, "POST", "/mcp", body=payload
                )
                self.assertEqual(status, 200)
                body = json.loads(data)
                self.assertEqual(body["error"]["code"], -32600)
                after = self.srv.read_log_lines()
                self.assertEqual(len(after), before + 1)

    def test_e6_malformed_json(self):
        before = len(self.srv.read_log_lines())
        status, _, data = http_request(self.srv.port, "POST", "/mcp", body="not json")
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], -32700)
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)

    def test_e7_wrong_http_method_returns_405_and_is_logged(self):
        for method in ("GET", "DELETE"):
            with self.subTest(method=method):
                before = len(self.srv.read_log_lines())
                status, hdrs, data = http_request(self.srv.port, method, "/mcp")
                self.assertEqual(status, 405)
                self.assertEqual(data, b"")
                self.assertEqual(hdrs.get("Allow"), "POST")
                after = self.srv.read_log_lines()
                self.assertEqual(len(after), before + 1)
                self.assertEqual(after[-1]["http_status"], 405)
                self.assertIsNone(after[-1]["response"])

    def test_e8_bogus_path_returns_404_and_is_logged(self):
        before = len(self.srv.read_log_lines())
        status, _, data = http_request(self.srv.port, "GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(data, b"")
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertEqual(after[-1]["http_status"], 404)

    def test_e9_oversized_content_length_returns_413(self):
        before = len(self.srv.read_log_lines())
        oversized = hp.MAX_BODY_BYTES + 1
        status, _, data = http_request(
            self.srv.port,
            "POST",
            "/mcp",
            body=b"",
            headers={"Content-Length": str(oversized)},
        )
        self.assertEqual(status, 413)
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertIn("oversized", after[-1]["raw_body"])

    def test_e10_chunked_transfer_encoding_returns_411(self):
        before = len(self.srv.read_log_lines())
        raw = (
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"0\r\n\r\n"
        )
        response = raw_request(self.srv.port, raw)
        self.assertIn(b" 411 ", response.split(b"\r\n", 1)[0])
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertIn("chunked", after[-1]["raw_body"])
        self.assertEqual(after[-1]["http_status"], 411)

    def test_e11_duplicate_content_length_returns_400(self):
        before = len(self.srv.read_log_lines())
        raw = (
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 5\r\n"
            b"Content-Length: 5\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"{}\r\n\r\n"
        )
        response = raw_request(self.srv.port, raw)
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertIn("duplicate Content-Length", after[-1]["raw_body"])
        self.assertEqual(after[-1]["http_status"], 400)

    def test_e12_duplicate_transfer_encoding_returns_400(self):
        before = len(self.srv.read_log_lines())
        raw = (
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Transfer-Encoding: identity\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        response = raw_request(self.srv.port, raw)
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertIn("duplicate Transfer-Encoding", after[-1]["raw_body"])
        self.assertEqual(after[-1]["http_status"], 400)

    def test_e14_tools_list_returns_four_well_formed_tools(self):
        status, _, data = self._post_json({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(status, 200)
        tools = json.loads(data)["result"]["tools"]
        self.assertEqual(len(tools), 4)
        for tool in tools:
            self.assertTrue(tool.get("name"))
            self.assertTrue(tool.get("description"))
            schema = tool.get("inputSchema")
            self.assertIsInstance(schema, dict)
            self.assertIn("required", schema)
            self.assertIn("properties", schema)

    TOOL_CALLS = {
        "read_file": {"path": "/etc/hosts"},
        "query_database": {"database": "prod", "query": "SELECT 1"},
        "get_credential": {"name": "aws-secret-key"},
        "send_email": {"to": "a@b.com", "subject": "hi", "body": "there"},
    }

    def test_e15_tools_call_golden_path_all_four_tools(self):
        for name, args in self.TOOL_CALLS.items():
            with self.subTest(tool=name):
                status, _, data = self._post_json(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": args},
                    }
                )
                self.assertEqual(status, 200)
                body = json.loads(data)
                self.assertIn("result", body)
                self.assertFalse(body["result"]["isError"])
                text = body["result"]["content"][0]["text"]
                # response echoes back at least one caller-supplied argument
                echoed_any = any(str(v) in text for v in args.values())
                self.assertTrue(echoed_any, f"no argument echoed in: {text!r}")

    def test_e16_tools_call_missing_required_argument(self):
        before = len(self.srv.read_log_lines())
        status, _, data = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}},
            }
        )
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], -32602)
        after = self.srv.read_log_lines()
        self.assertEqual(after[-1]["tool_name"], "read_file")
        self.assertEqual(after[-1]["tool_arguments"], {})

    def test_e17_tools_call_wrong_typed_argument(self):
        status, _, data = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": 12345}},
            }
        )
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], -32602)

    def test_e18_bool_for_integer_field_rejected_real_int_accepted(self):
        status, _, data = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "query_database",
                    "arguments": {"database": "d", "query": "q", "limit": True},
                },
            }
        )
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], -32602)

        status, _, data = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "query_database",
                    "arguments": {"database": "d", "query": "q", "limit": 0},
                },
            }
        )
        body = json.loads(data)
        self.assertIn("result", body)
        self.assertFalse(body["result"]["isError"])

    def test_e19_unknown_tool_name_returns_is_error_result(self):
        status, _, data = self._post_json(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "delete_everything", "arguments": {}},
            }
        )
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertIn("result", body)
        self.assertTrue(body["result"]["isError"])
        # connection/server still alive afterward
        status2, _, _ = http_request(self.srv.port, "GET", "/nope")
        self.assertEqual(status2, 404)


# ---------------------------------------------------------------------------
# R-series: raw-socket / stdlib-rejection tests
# ---------------------------------------------------------------------------


class StdlibRejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Shortened handler timeout so the stall test doesn't take 10s.
        cls.srv = LiveServer(handler_timeout=1)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_r1_stall_before_request_line_is_logged(self):
        before = len(self.srv.read_log_lines())
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) as s:
            time.sleep(1.5)  # exceed the 1s handler timeout without sending anything
        # allow the server thread a moment to log + close
        deadline = time.monotonic() + 3
        after = []
        while time.monotonic() < deadline:
            after = self.srv.read_log_lines()
            if len(after) > before:
                break
            time.sleep(0.1)
        self.assertEqual(len(after), before + 1)
        self.assertTrue(after[-1].get("stdlib_rejection"))

    def test_r2_malformed_request_line_is_logged(self):
        before = len(self.srv.read_log_lines())
        raw_request(self.srv.port, b"GARBAGE\r\n\r\n")
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertTrue(after[-1].get("stdlib_rejection"))

    def test_r3_oversized_request_line_is_logged(self):
        before = len(self.srv.read_log_lines())
        raw = b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n"
        raw_request(self.srv.port, raw)
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 1)
        self.assertTrue(after[-1].get("stdlib_rejection"))

    def test_r4_single_blank_leading_line_then_real_request(self):
        before = len(self.srv.read_log_lines())
        ping_body = b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}'
        raw = (
            b"\r\n"
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(ping_body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + ping_body
        )
        response = raw_request(self.srv.port, raw)
        self.assertIn(b" 200 ", response.split(b"\r\n", 1)[0])
        after = self.srv.read_log_lines()
        self.assertEqual(len(after), before + 2)
        self.assertTrue(after[-2].get("stdlib_rejection"))
        self.assertIn("blank request line", after[-2]["detail"])
        self.assertFalse(after[-1].get("stdlib_rejection", False))
        self.assertEqual(after[-1]["method"], "ping")

    def test_r5_more_than_bound_consecutive_blank_lines(self):
        before = len(self.srv.read_log_lines())
        n = hp.MAX_LEADING_BLANK_REQUEST_LINES + 1
        raw = b"\r\n" * n
        raw_request(self.srv.port, raw)
        after = self.srv.read_log_lines()
        new_records = after[before:]
        self.assertEqual(len(new_records), hp.MAX_LEADING_BLANK_REQUEST_LINES)
        for rec in new_records:
            self.assertTrue(rec.get("stdlib_rejection"))
            self.assertIn("blank request line", rec["detail"])

    def test_r6_broken_rejection_record_builder_does_not_suppress_stdlib_diagnostic(self):
        original = hp.build_stdlib_rejection_record
        calls = []

        def boom(*a, **kw):
            calls.append((a, kw))
            raise RuntimeError("synthetic failure")

        stderr_capture = io.StringIO()
        hp.build_stdlib_rejection_record = boom
        try:
            with contextlib.redirect_stderr(stderr_capture):
                raw_request(self.srv.port, b"GARBAGE\r\n\r\n")
        finally:
            hp.build_stdlib_rejection_record = original

        self.assertTrue(calls, "expected build_stdlib_rejection_record to be invoked")
        stderr_text = stderr_capture.getvalue()
        # The stdlib's own diagnostic (via super().log_error -> log_message,
        # which this project overrides to a no-op) must not itself crash the
        # handler thread, and no raw traceback should leak.
        self.assertNotIn("Traceback (most recent call last)", stderr_text)

        # Server must still serve subsequent requests normally.
        status, _, _ = http_request(self.srv.port, "GET", "/nope")
        self.assertEqual(status, 404)


# ---------------------------------------------------------------------------
# C-series: connection-cap semaphore
# ---------------------------------------------------------------------------


class ConnectionCapTests(unittest.TestCase):
    def test_c1_over_cap_connection_is_dropped_without_response_or_log(self):
        srv = LiveServer(max_concurrent=2)
        try:
            before = len(srv.read_log_lines())
            held = []
            try:
                for _ in range(2):
                    s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
                    held.append(s)
                time.sleep(0.2)  # let the accept loop register both connections

                # This third connection should exceed the cap and be closed
                # immediately by the server without any request/response.
                with socket.create_connection(("127.0.0.1", srv.port), timeout=2) as extra:
                    extra.settimeout(2)
                    data = extra.recv(65536)
                    self.assertEqual(data, b"", "over-cap connection should get no bytes back")

                after = srv.read_log_lines()
                self.assertEqual(
                    len(after), before, "over-cap connection must not produce a log line"
                )
            finally:
                for s in held:
                    s.close()

            # Server must continue serving ordinary requests afterward.
            status, _, _ = http_request(srv.port, "GET", "/nope")
            self.assertEqual(status, 404)
        finally:
            srv.close()


# ---------------------------------------------------------------------------
# N-series: concurrency / log integrity
# ---------------------------------------------------------------------------


class ConcurrencyTests(unittest.TestCase):
    def test_n1_concurrent_requests_produce_exactly_n_well_formed_lines(self):
        srv = LiveServer()
        try:
            before = len(srv.read_log_lines())
            n = 40

            def do_one(i):
                return http_request(
                    srv.port,
                    "POST",
                    "/mcp",
                    body=json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping"}),
                )

            with ThreadPoolExecutor(max_workers=20) as pool:
                results = list(pool.map(do_one, range(n)))

            for status, _, _ in results:
                self.assertEqual(status, 200)

            after = srv.read_log_lines()
            self.assertEqual(len(after), before + n)
        finally:
            srv.close()


# ---------------------------------------------------------------------------
# S-series: runtime safety-invariant checks
# ---------------------------------------------------------------------------


class SafetyInvariantTests(unittest.TestCase):
    TOOL_CALLS = {
        "read_file": {"path": "/etc/passwd"},
        "query_database": {"database": "prod", "query": "SELECT * FROM users"},
        "get_credential": {"name": "aws-secret-key"},
        "send_email": {"to": "a@b.com", "subject": "hi", "body": "there"},
    }

    def test_s1_tool_handlers_never_call_open(self):
        import builtins

        real_open = builtins.open

        def guard_open(*a, **kw):
            raise AssertionError(f"open() called during dispatch: args={a!r}")

        for name, args in self.TOOL_CALLS.items():
            with self.subTest(tool=name):
                msg = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                }
                builtins.open = guard_open
                try:
                    dr = hp.dispatch(msg, _dummy_ctx())
                finally:
                    builtins.open = real_open
                self.assertIn("result", dr.response)
                self.assertFalse(dr.response["result"]["isError"])

    def test_s2_tool_handlers_never_construct_a_socket(self):
        real_socket_cls = socket.socket

        def guard_socket(*a, **kw):
            raise AssertionError("socket.socket() constructed during dispatch")

        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": self.TOOL_CALLS["send_email"]},
        }
        socket.socket = guard_socket
        try:
            dr = hp.dispatch(msg, _dummy_ctx())
        finally:
            socket.socket = real_socket_cls
        self.assertIn("result", dr.response)

    def test_s3_read_file_never_touches_real_filesystem(self):
        with tempfile.TemporaryDirectory() as d:
            secret_path = os.path.join(d, "secret.txt")
            marker = "REAL_SECRET_CONTENT_MARKER_12345"
            with open(secret_path, "w", encoding="utf-8") as f:
                f.write(marker)
            mtime_before = os.stat(secret_path).st_mtime_ns
            entries_before = sorted(os.listdir(d))

            msg = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": secret_path}},
            }
            dr = hp.dispatch(msg, _dummy_ctx())
            text = dr.response["result"]["content"][0]["text"]
            self.assertNotIn(marker, text)

            entries_after = sorted(os.listdir(d))
            self.assertEqual(entries_before, entries_after, "no new files should appear")
            mtime_after = os.stat(secret_path).st_mtime_ns
            self.assertEqual(mtime_before, mtime_after, "file must not be touched")
            with open(secret_path, encoding="utf-8") as f:
                self.assertEqual(f.read(), marker, "file content must be unchanged")

    def test_s4_source_grep_backstop(self):
        """Mirrors design.md's own literal Task 3/4 acceptance criterion
        (`grep -nE "eval\\(|exec\\(|subprocess|urllib|socket\\.socket|importlib"
        mcp_honeypot.py` must match nothing), but applied per-line while
        skipping comment/docstring lines. The literal grep as specified in
        design.md, run against real code, matches the safety-invariant
        comment block at the top of the file itself ("Never eval, exec,
        subprocess, or import ...") -- a false positive against prose that
        Task 4 itself required be added, not a real forbidden call. See
        test-results.md for this noted as a design/acceptance-criterion
        wording nit, not a code defect."""
        source_path = hp.__file__
        with open(source_path, "r", encoding="utf-8") as f:
            source = f.read()

        forbidden = re.compile(r"eval\(|exec\(|subprocess|urllib|socket\.socket|importlib")
        in_docstring = False
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                # crude but adequate for this single-file module: toggle
                # docstring state; module docstring is the only multi-line
                # triple-quoted block containing prose that mentions these words.
                in_docstring = not in_docstring
                continue
            if in_docstring or stripped.startswith("#"):
                continue
            match = forbidden.search(line)
            self.assertIsNone(
                match, f"forbidden identifier found in actual code at line {lineno}: {line!r}"
            )

        open_call_count = len(re.findall(r"(?<![\w.])open\(", source))
        self.assertEqual(
            open_call_count,
            1,
            "expected exactly one open() call site (the log-file open in main())",
        )

    def test_s4b_no_forbidden_imports_or_calls_via_ast(self):
        """Stronger structural backstop than the line-based grep above:
        parses the module and walks the AST for actual Import/ImportFrom
        nodes and Call nodes, which cannot be fooled by comments/strings
        in either direction."""
        import ast

        source_path = hp.__file__
        with open(source_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=source_path)

        forbidden_modules = {"subprocess", "urllib", "importlib", "os", "socket"}
        # `socket`/`os` are not on the plan's explicit forbidden-import list,
        # but importing either at module scope would be a smell worth a human
        # look for a tool that must never touch the real filesystem/network;
        # http.server internally depends on socket, but mcp_honeypot.py's own
        # top-level imports should not need to import it directly.
        allowed_socket_like = set()  # nothing is allowed to import these directly

        found_imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in forbidden_modules and top not in allowed_socket_like:
                        found_imports.append((node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    if top in forbidden_modules and top not in allowed_socket_like:
                        found_imports.append((node.lineno, node.module))

        self.assertEqual(found_imports, [], f"forbidden imports found: {found_imports}")

        forbidden_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                    forbidden_calls.append((node.lineno, func.id))
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "socket"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "socket"
                ):
                    forbidden_calls.append((node.lineno, "socket.socket("))
        self.assertEqual(forbidden_calls, [], f"forbidden calls found: {forbidden_calls}")


# ---------------------------------------------------------------------------
# CLI-series: subprocess-level smoke tests
# ---------------------------------------------------------------------------


class CliTests(unittest.TestCase):
    def test_cli1_help_documents_three_flags(self):
        result = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "mcp_honeypot.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        out = result.stdout
        for flag in ("--host", "--port", "--log-file"):
            self.assertIn(flag, out)
        self.assertIn("127.0.0.1", out)
        self.assertIn("8000", out)

    def test_cli2_fresh_process_round_trip_only_writes_log_file(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = os.path.join(d, "honeypot.jsonl")
            free_port = _get_free_port()
            proc = subprocess.Popen(
                [
                    sys.executable,
                    os.path.join(REPO_ROOT, "mcp_honeypot.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(free_port),
                    "--log-file",
                    log_path,
                ],
                cwd=d,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                _wait_for_port(free_port, timeout=5)
                status, _, data = http_request(
                    free_port,
                    "POST",
                    "/mcp",
                    body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
                )
                self.assertEqual(status, 200)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

            entries = os.listdir(d)
            self.assertEqual(entries, ["honeypot.jsonl"], f"unexpected artifacts: {entries}")
            with open(log_path, encoding="utf-8") as f:
                lines = [json.loads(l) for l in f if l.strip()]
            self.assertGreaterEqual(len(lines), 1)


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"server on port {port} never became reachable")


if __name__ == "__main__":
    unittest.main()
