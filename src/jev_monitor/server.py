"""Local HTTP server the Claude Code mod asks before each tool call.

Same hardening as jev_router / jev_scan: binds to 127.0.0.1 only, every request needs the header
`X-Jev-Monitor: 1` (a web page cannot add it without a CORS preflight, which this server never
approves) and a matching Host header (DNS rebinding).

Endpoints: GET /health, GET /status, POST /check, POST /result, POST /describe, POST /results, POST /intent, POST /mode, POST /reset, POST /allow, POST /report,
POST /shutdown. The control endpoints (mode, reset, allow) are the user's; the monitor-tamper rule flags a
tool call that tries to reach them, but a determined agent with a shell could still find a way (see docs).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jev_core
from jev_core import JudgeConfigError, default_judge
from jev_core.config import var_path
from jev_core.localserver import GuardedHandler

from .engine import Monitor
from .log import MonitorLog, read_records, would_block_report
from .policy import default_policy_path, load_policy
from .rules import MONITOR_PORT
from .state import State
from .types import CLASSES, Call, tool_class

DEFAULT_PORT = MONITOR_PORT
HEADER = "X-Jev-Monitor"
MAX_BODY_BYTES = 4_000_000  # a tool result can be large; the policy's results.max_chars bounds what is scanned
_SOURCE_DIRS = [Path(__file__).parent, Path(jev_core.__file__).parent]


def code_version() -> str:
    digest = hashlib.sha256()
    for folder in _SOURCE_DIRS:
        for path in sorted(folder.glob("*.py")):
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def build_monitor(var_dir: Path | str | None = None, with_judge: bool = True) -> Monitor:
    """Raises PolicyError for a broken policy file: the server must not start with weaker rules."""
    var = Path(var_dir) if var_dir else var_path()
    pfile = default_policy_path(var)
    policy = load_policy(pfile if pfile.exists() else None)
    judge = None
    if with_judge and policy.judge_enabled and os.environ.get("JEV_MONITOR_JUDGE", "").lower() != "off":
        try:
            judge = default_judge(var_dir=var, tag="monitor", timeout=policy.judge_timeout_s, max_retries=0)
        except JudgeConfigError:
            judge = None  # no key: rules alone decide
    return Monitor(policy, State(var / "monitor-state.json"), MonitorLog(var / "monitor-log.jsonl"), judge)


def call_from_body(body: dict[str, Any]) -> Call | None:
    tool, inp = body.get("tool"), body.get("input")
    if not isinstance(tool, str) or not isinstance(inp, dict):
        return None
    cwd = body.get("cwd") if isinstance(body.get("cwd"), str) and body.get("cwd") else os.getcwd()
    root = body.get("root") if isinstance(body.get("root"), str) and body.get("root") else cwd
    sess, agent = body.get("session"), body.get("agent_id")
    return Call(tool, inp, str(cwd), str(root), sess if isinstance(sess, str) else None, agent if isinstance(agent, str) else None)


def health_payload(m: Monitor, started: str) -> dict[str, Any]:
    mode = m.state.mode_override() or m.policy.mode
    return {
        "ok": True,
        "mode": mode,
        "class_modes": {c: m.policy.class_mode(c, mode) for c in CLASSES},
        "fail": {c: m.policy.fail_for(c) for c in CLASSES},
        "latched": m.state.latch() is not None,
        "judge": m.second.judge.name if m.second else None,
        "results": m.results_enabled(),
        "code_version": started,
        "stale": code_version() != started,
    }


def make_handler(m: Monitor, var_dir: Path) -> type[BaseHTTPRequestHandler]:
    started = code_version()

    class Handler(GuardedHandler):
        HEADER = HEADER
        MAX_BODY_BYTES = MAX_BODY_BYTES

        def do_GET(self) -> None:
            if self.path not in ("/health", "/status"):
                self._send(404, {"ok": False})
            elif self._allowed():
                payload = health_payload(m, started)
                if self.path == "/status":
                    payload["state"] = m.state.snapshot()
                self._send(200, payload)

        def do_POST(self) -> None:
            raw = self._read_body()
            if raw is None or not self._allowed():
                return
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = None
            if not isinstance(body, dict):
                self._send(400, {"ok": False, "error": "body must be a JSON object"})
                return
            path = self.path
            try:
                if path == "/check":
                    call = call_from_body(body)
                    if call is None:
                        self._send(200, {"ok": False, "error": "tool and input required", "class": tool_class(str(body.get("tool", "")))})
                        return
                    self._send(200, m.check(call).to_dict())
                elif path in ("/result", "/describe"):
                    tool = body.get("tool")
                    text = body.get("text" if path == "/result" else "description")
                    if not isinstance(tool, str) or not isinstance(text, str):
                        self._send(200, {"ok": False, "error": "tool and text required"})
                        return
                    sess = body.get("session") if isinstance(body.get("session"), str) else None
                    self._send(200, m.check_text("result" if path == "/result" else "description", tool, text, sess))
                elif path == "/results":
                    on = body.get("on")
                    if not isinstance(on, bool):
                        self._send(400, {"ok": False, "error": "on must be true or false"})
                        return
                    m.state.set_results(on)
                    m.log.event("results_switch", on=on, by="user")
                    self._send(200, {"ok": True, "results": on})
                elif path == "/intent":
                    text = body.get("text")
                    if isinstance(text, str) and text.strip():
                        m.state.set_intent(text, body.get("session") if isinstance(body.get("session"), str) else None)
                    self._send(200, {"ok": True})
                elif path == "/mode":
                    mode = body.get("mode")
                    if mode not in ("monitor", "enforce"):
                        self._send(400, {"ok": False, "error": "mode must be monitor or enforce"})
                        return
                    m.state.set_mode(mode)
                    m.log.event("mode_change", mode=mode, by="user")
                    self._send(200, {"ok": True, "mode": mode})
                elif path == "/reset":
                    was = m.state.reset()
                    m.log.event("latch_reset", was_latched=was, by="user")
                    self._send(200, {"ok": True, "was_latched": was})
                elif path == "/allow":
                    sess = body.get("session") if isinstance(body.get("session"), str) else None
                    self._send(200, {"ok": m.allow_last(sess)})
                elif path == "/report":
                    self._send(200, {"ok": True, "text": would_block_report(read_records(var_dir / "monitor-log.jsonl"))})
                elif path == "/shutdown":
                    self._send(200, {"ok": True})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                else:
                    self._send(404, {"ok": False})
            except Exception as err:  # noqa: BLE001 - always answer; the mod decides by class policy
                self._send(200, {"ok": False, "error": f"internal {type(err).__name__}"})


    return Handler


def serve(port: int = DEFAULT_PORT, var_dir: str | Path | None = None) -> None:
    var = Path(var_dir).resolve() if var_dir else var_path()
    monitor = build_monitor(var)  # a broken policy raises here: no server, the mod fails closed (when enforcing)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(monitor, var))
    print(
        f"jev_monitor listening on 127.0.0.1:{port} (mode {monitor.state.mode_override() or monitor.policy.mode}, "
        f"judge={monitor.second.judge.name if monitor.second else 'none'}, code {code_version()})",
        flush=True,
    )
    server.serve_forever()
