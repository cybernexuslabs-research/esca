# Security Review: Task 2 — Session-aware JSON-RPC dispatch: initialize, notifications/initialized, ping, and the -32600/-32602/-32603 error paths

Findings from `loop-security` (code-phase), appended one `## Round N` section per round. See `code-review.md` in this same task directory for the parallel code-quality findings on the same rounds.

## Round 1 — loop-security (code-phase)

Reviewed: `git diff -- mcp_honeypot.py` (task 2 diff on top of the already-approved task 1 transport/logging layer) — the real `dispatch()`, `handle_initialize`/`handle_notifications_initialized`/`handle_ping`, the `SESSIONS` store/`_issue_session_id()`, and the `-32602`/`-32603` error wrapping. Cross-checked against the non-negotiable safety rules in `plan.md` §Risks.

| Severity | Finding | Location |
|---|---|---|
| minor | `InvalidParamsError`'s `str(exc)` is surfaced verbatim in the `-32602` response (`result_or_error = {"error": {"code": -32602, "message": str(exc)}}`). No handler in this diff raises it yet (dead code path per the docstring), so there is no live vulnerability today, but when task 3/4 wires this up for `tools/call` argument validation, whoever raises `InvalidParamsError` must pass a hand-authored, non-sensitive message rather than propagating raw exception text (e.g. from a `KeyError`/`TypeError`) — flagging now so it's caught in the next round rather than assumed safe by precedent. | mcp_honeypot.py:182-183 |
| minor | `params = msg.get("params") or {}` is passed to handlers without checking it's actually a `dict` (a client could send `"params": "x"` or `"params": [1,2]`). None of the three handlers in this diff read `params`, so it's inert today, but future handlers (e.g. `tools/call`) must not assume `params` is a mapping without an explicit `isinstance` check — otherwise a malformed-but-not-crashing input could produce an unhandled `AttributeError`/`TypeError` (which would still be caught by the outer `except Exception` and safely reduced to a generic `-32603`, so this is hardening, not an exploitable gap). | mcp_honeypot.py:170, 178 |

**Verified against the task's explicit checklist:**
- **SESSIONS cap under concurrency:** `_issue_session_id()` performs the `len(SESSIONS) >= MAX_SESSIONS` check, the `popitem(last=False)` eviction, and the `SESSIONS[session_id] = {}` insertion all inside one single `with SESSIONS_LOCK:` block (mcp_honeypot.py:120-126) — genuinely atomic, no TOCTOU window. Size is provably bounded at `MAX_SESSIONS` (10,000) regardless of concurrent `initialize` calls from `ThreadingHTTPServer` worker threads.
- **Session-id generation:** `uuid.uuid4().hex` is CSPRNG-backed (CPython's `uuid4()` uses `os.urandom`), which is more than adequate for a honeypot bearer-style identifier where nothing real sits behind it and the only theoretical concern (predictability enabling hijack of another fake session) is a non-issue either way per the plan's threat model.
- **Error message leakage:** the `-32603` path (`except Exception: result_or_error = {"error": {"code": -32603, "message": "Internal error"}}`, mcp_honeypot.py:184-185) sends a fixed, generic string — no traceback, exception repr, or internal state is ever placed in the JSON-RPC response body. Confirmed no `str(exc)`/`repr(exc)`/`traceback` usage on this path.
- **Forbidden identifiers:** `grep -n "eval(\|exec(\|subprocess\|socket\.socket\|urllib\|importlib\|open("` over the full file returns only the safety-rule docstring text (line 4, prose, not code) and the one legitimate `open(args.log_file, "a", ...)` call in `main()` for the configured log path (line 629, pre-existing from task 1, not part of this diff). No new forbidden identifiers introduced. No `subprocess`, `eval`/`exec`, outbound-network calls (`socket.socket`/`urllib`), or dynamic `import`/`importlib` anywhere in the diff's added code.
- **Filesystem/network scope:** the task-2 diff adds no file I/O and no network I/O of any kind — it only touches in-memory dict state (`SESSIONS`) and pure functions building JSON-serializable dicts.

`python3 -c "import mcp_honeypot"` succeeds with no import-time side effects, consistent with the module's stated invariant.

**Verdict:** APPROVED
