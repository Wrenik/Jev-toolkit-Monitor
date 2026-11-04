"""python -m jev_monitor serve [port] | hook | hook-snippet | check TOOL JSON | version | status | mode monitor|enforce | reset | report | policy-check | eval

`reset`, `mode` and `status` work on the state file directly, so they work from a plain terminal even when a
session is latched and the server is busy or gone. `hook` is the entry point for a classic Claude Code
`PreToolUse` hook (settings.json) and uses the same engine as the mod.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .log import read_records, would_block_report
from .policy import PolicyError, default_policy_path, load_policy
from .server import DEFAULT_PORT, HEADER, build_monitor, call_from_body, serve
from .state import State
from .types import tool_class

from jev_core.config import var_path

# JEV_MONITOR_VAR overrides; otherwise the shared data folder (JEV_HOME/var, default ~/.jev-toolkit/var).
VAR = Path(os.environ["JEV_MONITOR_VAR"]) if os.environ.get("JEV_MONITOR_VAR") else var_path()


def _post_server(path: str, body: dict, port: int = DEFAULT_PORT, timeout: float = 4.0) -> dict | None:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
        headers={HEADER: "1", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None


def hook_main(stdin_text: str) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) for a classic PreToolUse hook. Never raises."""
    tool = "?"
    try:
        data = json.loads(stdin_text)
        tool, inp = str(data["tool_name"]), data.get("tool_input") or {}
        body = {"tool": tool, "input": inp, "cwd": data.get("cwd"), "root": data.get("cwd"), "session": data.get("session_id"),
                "agent_id": data.get("agent_id")}
        d = _post_server("/check", body)
        if d is None or not d.get("ok", True):
            call = call_from_body(body)
            assert call is not None
            d = build_monitor(VAR).check(call).to_dict()  # in-process: rate/kill counters do not persist between calls
            d["note"] = "server not reachable; checked in-process"
    except Exception as err:  # noqa: BLE001 - decided below by class policy
        return _hook_failure(tool, f"{type(err).__name__}: {err}")
    action, reason = d["action"], d.get("reason", "")
    if action == "allow" or action == "log":
        return 0, "", ""
    if action == "warn":
        return 0, json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": reason}}), ""
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask" if action == "ask" else "deny", "permissionDecisionReason": reason}}
    if action == "kill":
        out["continue"] = False
        out["stopReason"] = reason
    return 0, json.dumps(out), ""


def _hook_failure(tool: str, why: str) -> tuple[int, str, str]:
    """The hook itself broke. Fail closed for sensitive classes only while enforcing; otherwise open, loudly."""
    tclass = tool_class(tool)
    try:
        pfile = default_policy_path(VAR)
        policy = load_policy(pfile if pfile.exists() else None)
        mode = State(VAR / "monitor-state.json").mode_override() or policy.mode
        closed = policy.fail_for(tclass) == "closed" and policy.class_mode(tclass, mode) == "enforce"
    except PolicyError:
        closed = tclass not in ("read", "other")  # a broken policy file must not weaken anything
    if closed:
        return 2, "", f"jev-monitor could not check this {tool} call ({why}); {tclass} tools fail closed.\n"
    return 0, "", f"jev-monitor: check failed for {tool} ({why}); allowed because {tclass} tools fail open here.\n"


def main(argv: list[str]) -> int:  # noqa: C901
    cmd = argv[0] if argv else ""
    if cmd == "serve":
        try:
            serve(int(argv[1]) if len(argv) > 1 else DEFAULT_PORT, VAR)
        except PolicyError as err:
            print(f"POLICY INVALID, not starting: {err}")
            return 2
        return 0
    if cmd == "hook":
        code, out, err = hook_main(sys.stdin.read())
        if out:
            print(out)
        if err:
            print(err, end="", file=sys.stderr)
        return code
    if cmd == "reset":
        was = State(VAR / "monitor-state.json").reset()
        print("latch cleared." if was else "monitor was not latched (nothing to clear).")
        return 0
    if cmd == "mode":
        st = State(VAR / "monitor-state.json")
        if len(argv) == 2 and argv[1] in ("monitor", "enforce"):
            st.set_mode(argv[1])
            print(f"mode: {argv[1]} (takes effect on the next tool call)")
            return 0
        print(f"mode: {st.mode_override() or 'policy default'}")
        return 0
    if cmd == "status":
        pfile = default_policy_path(VAR)
        try:
            policy = load_policy(pfile if pfile.exists() else None)
        except PolicyError as err:
            print(f"policy INVALID: {err}")
            return 2
        snap = State(VAR / "monitor-state.json").snapshot()
        files = {"policy": str(pfile) if pfile.exists() else "(none: built-in defaults)", "log": str(VAR / "monitor-log.jsonl"), "state": str(VAR / "monitor-state.json")}
        print(json.dumps({"policy_mode": policy.mode, **snap, "files": files}, indent=1, default=str))
        return 0
    if cmd == "report":
        print(would_block_report(read_records(VAR / "monitor-log.jsonl")))
        return 0
    if cmd == "policy-check":
        pfile = default_policy_path(VAR)
        try:
            p = load_policy(pfile if pfile.exists() else None)
        except PolicyError as err:
            print(f"INVALID: {err}")
            return 2
        print(f"OK ({'file ' + str(pfile) if pfile.exists() else 'built-in defaults'}): mode={p.mode}, hosts={len(p.allow_hosts)}")
        return 0
    if cmd == "check" and len(argv) == 3:
        try:
            tool_input = json.loads(argv[2])
        except ValueError as err:
            print(f"the second argument must be JSON, e.g. '{{\"command\": \"ls\"}}' ({err})")
            return 2
        if not isinstance(tool_input, dict):
            print("the JSON must be an object, e.g. '{\"command\": \"ls\"}'")
            return 2
        m = build_monitor(VAR, with_judge=False)
        call = call_from_body({"tool": argv[1], "input": tool_input, "cwd": os.getcwd()})
        print(json.dumps(m.check(call).to_dict(), indent=1))
        return 0
    if cmd == "hook-snippet":
        # Printed, never written: you paste it into .claude/settings.json (project) or ~/.claude/settings.json (all projects).
        hook = {"type": "command", "command": f'"{sys.executable}" -m jev_monitor hook', "timeout": 10, "onFailure": "block"}
        print(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch", "hooks": [hook]}]}}, indent=2))
        return 0
    if cmd in ("-V", "--version", "version"):
        from importlib.metadata import PackageNotFoundError, version

        try:
            print("jev-toolkit-monitor", version("jev-toolkit-monitor"))
        except PackageNotFoundError:
            print("jev-toolkit-monitor (not installed as a package)")
        return 0
    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if cmd == "eval":
        from .evaluate import main as eval_main

        return eval_main(argv[1:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
