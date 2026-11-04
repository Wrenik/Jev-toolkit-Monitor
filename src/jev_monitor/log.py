"""Append-only JSONL decision log.

Holds hashes, rule ids and one short REDACTED summary of the call (needed to judge a "would block"
line later). Never raw prompts, never file contents. Lives in `var/` (git-ignored).
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .redact import short
from .types import Call, Decision


class MonitorLog:
    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.Lock()

    def _append(self, record: dict[str, Any]) -> None:
        if self.path is None:
            return
        line = json.dumps(record, ensure_ascii=True)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def decision(self, call: Call, d: Decision) -> None:
        summary = (
            call.input.get("command")
            or call.input.get("file_path")
            or call.input.get("url")
            or call.input.get("path")
            or ""
        )
        blob = json.dumps(call.input, sort_keys=True, default=str)
        self._append(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "event": "decision",
                "session": call.session,
                "agent": call.agent_id,
                "tool": call.tool,
                "class": d.tool_class,
                "input_sha256": hashlib.sha256(blob.encode()).hexdigest(),
                "summary": short(str(summary), 160),
                "action": d.action,
                "would": d.would,
                "mode": d.mode,
                "severity": d.max_severity,
                "rules": [f.rule for f in d.findings],
                "judge": d.judge,
                "failed": d.failed,
                "latency_ms": d.latency_ms,
            }
        )

    def event(self, name: str, **fields: Any) -> None:
        """Mode switches, resets, latches, overrides: everything the person did or the monitor escalated."""
        self._append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": name, **fields})


def read_records(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        pass
    return out


def would_block_report(records: list[dict[str, Any]]) -> str:
    """What the monitor WOULD have stopped had it been enforcing: the page to read before switching modes."""
    decisions = [r for r in records if r.get("event") == "decision"]
    flagged = [r for r in decisions if r.get("would") in ("ask", "block", "kill")]
    warned = [r for r in decisions if r.get("would") == "warn"]
    lines = [
        (
            f"{len(decisions)} decisions: {len(flagged)} would be held or blocked, {len(warned)} warned, "
            f"{len(decisions) - len(flagged) - len(warned)} passed"
        )
    ]
    by_rule = Counter(rule for r in flagged for rule in r.get("rules", []))
    if by_rule:
        lines.append("would-block by rule: " + ", ".join(f"{k} x{v}" for k, v in by_rule.most_common()))
    for r in flagged[-20:]:
        lines.append(
            f"  {r.get('ts', '')[:19]} {r.get('tool')}: {r.get('would')} [{','.join(r.get('rules', []))}] {r.get('summary', '')}"
        )
    if not flagged:
        lines.append("nothing would have been blocked.")
    return "\n".join(lines)
