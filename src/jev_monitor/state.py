"""Monitor state kept OUTSIDE the agent's context: mode switch, kill latch, task intent, one-shot allows.

One small JSON file (`var/monitor-state.json`) so that `python -m jev_monitor reset` works from a
plain terminal while the session is latched. The file is re-read on every call (it is tiny), so a
reset or a mode switch takes effect on the very next tool call without restarting the server.

Privacy: the task intent is stored as a hash plus a short redacted summary, never the raw prompt.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .redact import short

INTENT_SUMMARY_CHARS = 80
ALLOW_TTL_S = 600


def call_hash(tool: str, tool_input: dict[str, Any]) -> str:
    blob = json.dumps({"t": tool, "i": tool_input}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class State:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    # ---- file access -------------------------------------------------
    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    def _update(self, fn) -> Any:
        with self._lock:
            data = self._read()
            out = fn(data)
            self._write(data)
            return out

    # ---- mode --------------------------------------------------------
    def mode_override(self) -> str | None:
        m = self._read().get("mode")
        return m if m in ("monitor", "enforce") else None

    def set_mode(self, mode: str) -> None:
        if mode not in ("monitor", "enforce"):
            raise ValueError("mode must be monitor or enforce")
        self._update(lambda d: d.__setitem__("mode", mode))

    # ---- kill latch --------------------------------------------------
    def latch(self) -> dict[str, Any] | None:
        latch = self._read().get("latch")
        if isinstance(latch, dict) and float(latch.get("until", 0)) > time.time():
            return latch
        return None

    def set_latch(self, reason: str, minutes: int, session: str | None) -> None:
        now = time.time()
        self._update(lambda d: d.__setitem__("latch", {"since": now, "until": now + minutes * 60, "reason": reason, "session": session}))

    def reset(self) -> bool:
        """Clear the latch. Works from any process; returns whether a latch was active."""
        was = self.latch() is not None
        self._update(lambda d: d.pop("latch", None))
        return was

    # ---- task intent -------------------------------------------------
    def set_intent(self, text: str, session: str | None) -> None:
        sha = hashlib.sha256(text.encode()).hexdigest()
        rec = {"sha256": sha, "summary": short(text, INTENT_SUMMARY_CHARS), "ts": time.time(), "session": session}
        self._update(lambda d: d.__setitem__("intent", rec))

    def intent(self) -> dict[str, Any] | None:
        i = self._read().get("intent")
        return i if isinstance(i, dict) else None

    # ---- one-shot allows (the person's decision, logged by the caller) ---
    def add_allow(self, sha: str, session: str | None, limit: int) -> bool:
        def go(d: dict[str, Any]) -> bool:
            now = time.time()
            allows = [a for a in d.get("allows", []) if a.get("exp", 0) > now]
            used = sum(1 for a in allows if a.get("session") == session)
            if used >= limit:
                d["allows"] = allows
                return False
            allows.append({"sha": sha, "session": session, "exp": now + ALLOW_TTL_S})
            d["allows"] = allows
            return True

        return self._update(go)

    def consume_allow(self, sha: str, session: str | None) -> bool:
        def go(d: dict[str, Any]) -> bool:
            now = time.time()
            allows = [a for a in d.get("allows", []) if a.get("exp", 0) > now]
            for i, a in enumerate(allows):
                if a.get("sha") == sha and a.get("session") == session:
                    del allows[i]
                    d["allows"] = allows
                    return True
            d["allows"] = allows
            return False

        return self._update(go)

    def snapshot(self) -> dict[str, Any]:
        d = self._read()
        latch = self.latch()
        return {"mode_override": d.get("mode"), "latched": latch is not None, "latch": latch, "intent": self.intent()}
