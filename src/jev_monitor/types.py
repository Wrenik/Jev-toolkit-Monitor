"""Plain data types shared by every part of the monitor. No I/O here."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Severity of a single finding. The response ladder maps it to an action (policy [ladder]).
INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
SEVERITY_NAMES = {INFO: "info", LOW: "low", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical"}

# Actions, weakest first. "ask" sits between warn and block: the call is held until the person agrees.
ACTIONS = ("allow", "log", "warn", "ask", "block", "kill")

# Tool classes. The policy decides per class: monitor/enforce, and fail closed/open.
CLASSES = ("read", "write", "shell", "network", "mcp", "agent", "other")

_READ = {"Read", "Grep", "Glob", "LS", "NotebookRead", "ToolSearch", "TodoWrite", "TaskList", "TaskGet"}
_WRITE = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
_SHELL = {"Bash", "PowerShell", "BashOutput", "KillShell", "KillBash"}
_NETWORK = {"WebFetch", "WebSearch"}
_AGENT = {"Agent", "Task"}


def tool_class(tool: str) -> str:
    if tool in _READ:
        return "read"
    if tool in _WRITE:
        return "write"
    if tool in _SHELL:
        return "shell"
    if tool in _NETWORK:
        return "network"
    if tool.startswith("mcp__"):
        return "mcp"
    if tool in _AGENT:
        return "agent"
    return "other"


@dataclass(frozen=True)
class Call:
    """One tool call as the agent made it. `root` is the project root, `cwd` the shell's directory."""

    tool: str
    input: dict[str, Any]
    cwd: str
    root: str
    session: str | None = None
    agent_id: str | None = None  # set when a subagent made the call


@dataclass(frozen=True)
class Finding:
    rule: str  # stable id, e.g. "instruction-file-write"
    severity: int
    detail: str  # short, no raw file content
    # What a person could do about a false alarm; shown with the block.
    hint: str = ""
    # The call could not be understood (an expansion only the live shell knows): the ladder's
    # `opaque_action` applies instead of the severity mapping.
    opaque: bool = False


@dataclass
class Decision:
    action: str  # what the hook does now (after mode: monitor turns block/ask/kill into warn)
    would: str  # what the ladder decided before mode was applied
    mode: str  # monitor | enforce (effective for this tool class)
    tool_class: str
    findings: list[Finding] = field(default_factory=list)
    judge: dict[str, Any] | None = None
    reason: str = ""  # text for the model / the person
    latency_ms: int = 0
    failed: str | None = None  # monitor error text when a check crashed

    @property
    def max_severity(self) -> int:
        return max((f.severity for f in self.findings), default=INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "action": self.action,
            "would": self.would,
            "mode": self.mode,
            "class": self.tool_class,
            "reason": self.reason,
            "rules": [f.rule for f in self.findings],
            "severity": SEVERITY_NAMES[self.max_severity],
            "judge": self.judge,
            "latency_ms": self.latency_ms,
        }
