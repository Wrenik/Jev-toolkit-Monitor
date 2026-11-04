"""Tool RESULTS and MCP tool DESCRIPTIONS: text the agent reads that somebody else wrote.

Opt-in (policy `[results] enabled = true`, or `python -m jev_monitor results on`): every result is sent to the local server, which is
a cost and a privacy decision, so it is off by default. When on, the text goes through `jev_scan` if that package is installed
(an optional import, no hard dependency), otherwise through the small built-in heuristics below.

What this is and is not: a tripwire for the loud cases (instructions aimed at the agent, hidden characters, a request to read a
secret and send it, download-and-run lines, secrets that appear in a result). It does not understand meaning; a paraphrased
injection passes, and a security tutorial that quotes injections can warn. A `warn` is a note added to the result; in enforce
mode a high finding withholds the result from the model. Nothing here stores the text: logs get a hash and rule ids.
"""

from __future__ import annotations

import re
from typing import Any

from . import catalog
from .policy import Policy
from .types import HIGH, LOW, MEDIUM, Finding, tool_class

# (category, pattern). Two different categories, or any "coerce" hit, make a finding high.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override", re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?|guidelines|constraints)\b")),
    ("override", re.compile(r"(?i)\byou (?:are|must) now\b|\bnew (?:system )?instructions?\s*:|(?:^|\n)\s*(?:system|assistant)\s*:\s|<\s*/?\s*(?:system|important|instructions?|admin)\s*>|\[/?INST\]|<\|im_start\|>")),
    ("conceal", re.compile(r"(?i)\b(?:do not|don'?t|never)\s+(?:tell|mention|inform|reveal|show|let)\b[^.\n]{0,50}\b(?:user|human|operator|anyone)\b|\bwithout\s+(?:telling|informing|asking|notifying)\s+the\s+user\b|\bsilently\b[^.\n]{0,40}\b(?:run|send|read|call|execute)\b")),
    ("coerce", re.compile(r"(?i)\b(?:read|cat|send|upload|post|exfiltrate|email|copy|forward|include)\b[^.\n]{0,80}(?:~/\.ssh|id_rsa|\.env\b|\.aws|credentials|api[_ -]?keys?|passwords?|secrets?|tokens?)\b[^.\n]{0,100}\b(?:to|at|via|into)\b[^.\n]{0,30}(?:https?://|@|\bserver\b|\bendpoint\b)")),
    ("coerce", re.compile(r"(?i)\b(?:curl|wget|iwr|irm)\b[^\n|]{0,160}\|\s*(?:ba|z)?sh\b|\bbefore (?:using|calling|running) this tool\b[^.\n]{0,100}\b(?:read|cat|open|include)\b")),
    ("coerce", re.compile(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s=]+=[^)\s]*\)")),  # a markdown image whose URL carries data
)
_scanner: Any = None
_scanner_tried = False


def _jev_scan() -> Any:
    """The scanner from the sibling package, or None. Imported on first use; any failure means 'not installed'."""
    global _scanner, _scanner_tried
    if not _scanner_tried:
        _scanner_tried = True
        try:
            from jev_scan.scanner import Scanner

            _scanner = Scanner()
        except Exception:  # noqa: BLE001 - missing package, broken data file, anything: fall back to the built-in set
            _scanner = None
    return _scanner


def reset_scanner_cache() -> None:  # for tests
    global _scanner, _scanner_tried
    _scanner, _scanner_tried = None, False


def heuristics(text: str, kind: str) -> list[Finding]:
    out: list[Finding] = []
    cats: dict[str, str] = {}
    for cat, rx in _PATTERNS:
        m = rx.search(text)
        if m and cat not in cats:
            cats[cat] = re.sub(r"\s+", " ", m.group(0))[:80]
    if cats:
        high = len(cats) >= 2 or "coerce" in cats
        what = "; ".join(f"{c}: {s!r}" for c, s in cats.items())
        label = "tool description" if kind == "description" else "tool result"
        out.append(Finding("result-injection", HIGH if high else MEDIUM, f"the {label} contains text that reads like instructions to the agent ({what})"))
    if m := catalog.HIDDEN_CHARS.search(text.lstrip("﻿")):
        out.append(Finding("result-hidden-unicode", MEDIUM, f"the text contains invisible or bidirectional control characters (U+{ord(m.group(0)):04X})"))
    return out


def scan_text(text: str, policy: Policy, kind: str = "result") -> tuple[list[Finding], str]:
    """(findings, engine) where engine is 'jev_scan' or 'builtin'. Findings never carry the text itself."""
    text = text[: policy.results_max_chars]
    if policy.results_use_scanner and (sc := _jev_scan()) is not None:
        try:
            res = sc.scan(text, source="mcp" if kind == "description" else "web")
            found: list[Finding] = []
            if res.action != "allow" or res.risk >= 0.5:
                sev = HIGH if res.action == "block" or res.risk >= 0.8 else MEDIUM
                why = "; ".join(str(r) for r in res.reasons[:2])[:140]
                found.append(Finding("result-injection", sev, f"jev_scan: risk {res.risk:.2f} ({why})"))
            return found + [f for f in heuristics(text, kind) if f.rule == "result-hidden-unicode" and not found], "jev_scan"
        except Exception:  # noqa: BLE001, S110 - a scanner that crashes must not hide the built-in checks
            pass
    return heuristics(text, kind), "builtin"


def secret_literals(text: str) -> list[str]:
    return [m.group(0) for m in catalog.SECRET_LITERAL.finditer(text[:200_000])][:8]


def cap_for(tool: str, findings: list[Finding]) -> list[Finding]:
    """A local file read (Read, Grep, Glob) is the user's own content far more often than an attack: it can warn, never hold."""
    if tool_class(tool) != "read":
        return findings
    return [Finding(f.rule, min(f.severity, MEDIUM), f.detail, f.hint) for f in findings]


LOW_SECRET = Finding("result-contains-secret", LOW, "a secret-looking literal appears in a tool result; later uploads in this session are watched")
