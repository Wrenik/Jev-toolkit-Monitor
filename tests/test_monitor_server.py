"""Step 4: the HTTP server (hardening, check, control endpoints) and the CLI / classic hook."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from jev_monitor import __main__ as cli
from jev_monitor.engine import Monitor
from jev_monitor.log import MonitorLog
from jev_monitor.policy import Policy
from jev_monitor.server import HEADER, build_monitor, make_handler
from jev_monitor.state import State


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    m = Monitor(Policy(), State(tmp_path / "state.json"), MonitorLog(tmp_path / "monitor-log.jsonl"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(m, tmp_path))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], m, tmp_path
    httpd.shutdown()


def call(port, path, body=None, headers=None, host=None, method=None):
    h = {HEADER: "1", "Content-Type": "application/json", **(headers or {})}
    if host:
        h["Host"] = host
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=h,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_hardening(server):
    port, _, _ = server
    assert call(port, "/health", headers={HEADER: "0"})[0] == 403
    assert call(port, "/health", host="evil.example")[0] == 403
    assert call(port, "/check", {"tool": "Bash", "input": {}}, host="rebind.example:8767")[0] == 403
    assert call(port, "/nope")[0] == 404
    assert call(port, "/health")[1]["mode"] == "monitor"


def test_check_roundtrip_and_fields(server, tmp_path):
    port, _, _ = server
    code, d = call(
        port,
        "/check",
        {
            "tool": "Bash",
            "input": {"command": "echo x > CLAUDE.md"},
            "cwd": str(tmp_path),
            "root": str(tmp_path),
            "session": "s",
        },
    )
    assert code == 200 and d["action"] == "warn" and d["would"] == "block" and "instruction-file-change" in d["rules"]
    assert call(port, "/check", {"tool": "Bash"})[1]["ok"] is False
    code, h = call(port, "/health")
    assert h["fail"]["shell"] == "closed" and h["fail"]["read"] == "open"


def test_control_endpoints(server, tmp_path):
    port, m, _ = server
    assert call(port, "/mode", {"mode": "enforce"})[1]["mode"] == "enforce"
    assert call(port, "/mode", {"mode": "yolo"})[0] == 400
    body = {
        "tool": "Bash",
        "input": {"command": "echo x > CLAUDE.md"},
        "cwd": str(tmp_path),
        "root": str(tmp_path),
        "session": "s",
    }
    assert call(port, "/check", body)[1]["action"] == "ask" or call(port, "/check", body)[1]["action"] == "block"
    assert call(port, "/allow", {"session": "s"})[1]["ok"] is True
    assert call(port, "/check", body)[1]["action"] == "allow"
    m.state.set_latch("test", 5, "s")
    assert call(port, "/reset", {})[1]["was_latched"] is True
    call(port, "/intent", {"text": "fix the failing test in parser.py", "session": "s"})
    assert m.state.intent()["summary"].startswith("fix the failing")
    assert "decisions" in call(port, "/report", {})[1]["text"]
    assert "mode_change" in (tmp_path / "monitor-log.jsonl").read_text()


def test_build_monitor_refuses_a_broken_policy(tmp_path, monkeypatch):
    (tmp_path / "monitor-policy.toml").write_text('mode = "nonsense"')
    from jev_monitor.policy import PolicyError

    with pytest.raises(PolicyError):
        build_monitor(tmp_path)
    (tmp_path / "monitor-policy.toml").write_text('mode = "enforce"\n[judge]\nenabled = false\n')
    assert build_monitor(tmp_path).policy.mode == "enforce"


# ---- classic hook ---------------------------------------------------------------------------------------------------
def hook(tmp_path, monkeypatch, payload, mode="enforce"):
    monkeypatch.setattr(cli, "VAR", tmp_path / "var")
    monkeypatch.setattr(cli, "_post_server", lambda *a, **k: None)  # force the in-process path
    monkeypatch.setenv("JEV_MONITOR_JUDGE", "off")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    (tmp_path / "var").mkdir(exist_ok=True)
    State(tmp_path / "var" / "monitor-state.json").set_mode(mode)
    return cli.hook_main(json.dumps(payload))


def test_classic_hook_deny_and_allow(tmp_path, monkeypatch):
    base = {"cwd": str(tmp_path), "session_id": "s"}
    code, out, _err = hook(
        tmp_path, monkeypatch, {**base, "tool_name": "Bash", "tool_input": {"command": "echo x > CLAUDE.md"}}
    )
    o = json.loads(out)
    assert code == 0 and o["hookSpecificOutput"]["permissionDecision"] == "deny"
    code, out, _ = hook(tmp_path, monkeypatch, {**base, "tool_name": "Bash", "tool_input": {"command": "git status"}})
    assert code == 0 and out == ""
    code, out, _ = hook(
        tmp_path, monkeypatch, {**base, "tool_name": "Bash", "tool_input": {"command": "echo x > $UNSET/f"}}
    )
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_classic_hook_monitor_mode_only_adds_context(tmp_path, monkeypatch):
    base = {"cwd": str(tmp_path), "session_id": "s"}
    code, out, _ = hook(
        tmp_path,
        monkeypatch,
        {**base, "tool_name": "Bash", "tool_input": {"command": "echo x > CLAUDE.md"}},
        mode="monitor",
    )
    o = json.loads(out)
    assert (
        code == 0
        and "permissionDecision" not in o["hookSpecificOutput"]
        and "would" in o["hookSpecificOutput"]["additionalContext"]
    )


def test_classic_hook_garbage_input_fails_closed_only_when_enforcing(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "VAR", tmp_path / "var")
    (tmp_path / "var").mkdir(exist_ok=True)
    State(tmp_path / "var" / "monitor-state.json").set_mode("enforce")
    assert cli.hook_main("{not json")[0] == 0  # tool unknown -> class 'other' -> fail open (with a stderr line)
    code, _out, err = cli.hook_main(json.dumps({"tool_name": "Bash", "tool_input": "not-a-dict-at-all"}))
    assert code == 2 and "fail closed" in err
    State(tmp_path / "var" / "monitor-state.json").set_mode("monitor")
    assert cli.hook_main(json.dumps({"tool_name": "Bash", "tool_input": "x"}))[0] == 0


def test_cli_reset_works_without_a_server(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "VAR", tmp_path)
    State(tmp_path / "monitor-state.json").set_latch("x", 10, None)
    assert cli.main(["reset"]) == 0 and "cleared" in capsys.readouterr().out
    assert State(tmp_path / "monitor-state.json").latch() is None
    assert cli.main(["mode", "enforce"]) == 0 and cli.main(["mode"]) == 0
    assert "enforce" in capsys.readouterr().out
