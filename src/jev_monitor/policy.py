"""The one small policy file. Defaults are built in; a TOML file overrides single values.

Default location: `var/monitor-policy.toml` (or JEV_MONITOR_POLICY). A broken file is an error,
never a silent fall-back to weaker rules: the server refuses to start, and the hook then fails
closed for the sensitive classes (when enforcing).

The policy lives outside the agent's context, so compaction cannot touch it. It does live on
disk where the agent could write it; the self-protection rule watches for that and the docs
say plainly that this detects, it does not prevent.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .types import CLASSES

MODES = ("monitor", "enforce")
FAILS = ("closed", "open")
LADDER_ACTIONS = ("log", "warn", "ask", "block")


class PolicyError(ValueError):
    pass


# Files that steer the agent. A write, delete, rename or `git checkout` of any of these is high severity.
DEFAULT_INSTRUCTION_FILES = [
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".claude/**",
    "~/.claude/**",
    ".mcp.json",
    ".claude.json",
    "~/.claude.json",
    ".git/hooks/**",
    ".github/copilot-instructions.md",
    "**/.cursor/mcp.json",
    "**/.cursor/rules/**",
    "**/.vscode/mcp.json",
    "**/claude_desktop_config.json",
    "**/.codeium/windsurf/mcp_config.json",
]
# The monitor's own policy, state and logs: tampering is critical.
DEFAULT_MONITOR_FILES = [
    "var/monitor-*",
    "**/monitor-policy.toml",
    "**/monitor-state.json",
    "**/monitor-log.jsonl",
    "**/.jev-toolkit/var/monitor-*",
]
# The monitor's code and mod. Protected too, unless `dev_mode` (you are developing the monitor itself).
DEFAULT_MONITOR_CODE = ["**/src/jev_monitor/**", "**/claude-mod/jev-monitor/**"]
DEFAULT_SECRET_FILES = [
    ".env",
    ".env.*",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.netrc",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.config/gh/**",
    "~/.docker/config.json",
    "~/.kube/config",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/*.pem",
    "**/*.pfx",
    "**/credentials.json",
    "**/*.kdbx",
    "**/.bash_history",
    "**/.zsh_history",
    "**/ConsoleHost_history.txt",
    "~/.config/gcloud/**",
    "~/.azure/**",
]
SECRET_EXEMPT = [".env.example", ".env.sample", ".env.template", ".env.dist"]
# Files inside secret folders that hold no secrets: reading them is ordinary (`Get-Content ~/.ssh/config`).
SECRET_EXEMPT_GLOBS = [
    "~/.ssh/config",
    "~/.ssh/known_hosts*",
    "~/.ssh/*.pub",
    "**/*.pub",
    "~/.aws/config",
    "**/.env.example",
    "**/.env.sample",
    "**/.env.template",
    "**/.env.dist",
]
DEFAULT_ALLOW_HOSTS = [
    "localhost",
    "127.0.0.1",
    "::1",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "www.npmjs.com",
    "crates.io",
    "static.crates.io",
    "docs.python.org",
    "developer.mozilla.org",
    "docs.anthropic.com",
    "code.claude.com",
    "docs.claude.com",
    "stackoverflow.com",
    "huggingface.co",
    "docs.rs",
    "doc.rust-lang.org",
    "pkg.go.dev",
    "proxy.golang.org",
    "golang.org",
    "go.dev",
    "nodejs.org",
    "learn.microsoft.com",
    "en.wikipedia.org",
    "readthedocs.io",
    "rfc-editor.org",
]


@dataclass(frozen=True)
class ClassPolicy:
    mode: str | None = None  # None: use the global mode
    fail: str = "closed"


DEFAULT_CLASSES = {
    "read": ClassPolicy(fail="open"),
    "write": ClassPolicy(fail="closed"),
    "shell": ClassPolicy(fail="closed"),
    "network": ClassPolicy(fail="closed"),
    "mcp": ClassPolicy(fail="closed"),
    "agent": ClassPolicy(fail="closed"),
    "other": ClassPolicy(fail="open"),
}


@dataclass(frozen=True)
class Policy:
    mode: str = "monitor"
    classes: dict[str, ClassPolicy] = field(default_factory=lambda: dict(DEFAULT_CLASSES))
    instruction_files: list[str] = field(default_factory=lambda: list(DEFAULT_INSTRUCTION_FILES))
    monitor_files: list[str] = field(default_factory=lambda: list(DEFAULT_MONITOR_FILES))
    monitor_code: list[str] = field(default_factory=lambda: list(DEFAULT_MONITOR_CODE))
    dev_mode: bool = False
    secret_files: list[str] = field(default_factory=lambda: list(DEFAULT_SECRET_FILES))
    extra_write_dirs: list[str] = field(default_factory=list)  # besides the project root and the temp dir
    allow_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOW_HOSTS))
    canary_paths: list[str] = field(default_factory=list)
    canary_tokens: list[str] = field(default_factory=list)  # literal strings that must never appear in a call
    # rate / volume: per session, sliding window
    rate_window_s: int = 60
    rate_max_calls: int = 150
    rate_max_write_bytes: int = 3_000_000
    rate_max_hosts: int = 10
    # severity -> action
    ladder: dict[str, str] = field(
        default_factory=lambda: {"low": "log", "medium": "warn", "high": "block", "critical": "block"}
    )
    kill_after_blocks: int = 3
    kill_window_s: int = 600
    latch_minutes: int = 15
    # opaque shell (cannot be parsed) in a sensitive class: what the ladder does
    opaque_action: str = "ask"
    # Jev second opinion
    judge_enabled: bool = True
    judge_timeout_s: float = 3.0
    judge_deadline_s: float = 3.5
    judge_downgrade_p: float = 0.9  # P(consistent) at or above this lets a medium finding drop to log
    judge_upgrade_p: float = 0.2  # P(consistent) at or below this (and suspicion high) lets a medium one become high
    allow_overrides_per_session: int = 5
    # tool RESULTS and MCP tool descriptions (opt-in: every result is sent to the local server, so it is off until asked for)
    results_enabled: bool = False
    results_use_scanner: bool = True  # use jev_scan when it is installed
    results_max_chars: int = 60_000
    # cross-call taint: how long a read of a secret file marks the session
    taint_window_s: int = 3600

    def class_mode(self, tool_class: str, global_mode: str) -> str:
        cp = self.classes.get(tool_class)
        return cp.mode if cp and cp.mode else global_mode

    def fail_for(self, tool_class: str) -> str:
        return self.classes.get(tool_class, ClassPolicy()).fail


def default_policy_path(var_dir: str | Path | None = None) -> Path:
    env = os.environ.get("JEV_MONITOR_POLICY")
    if env:
        return Path(env)
    from jev_core.config import var_path

    return (Path(var_dir) if var_dir else var_path()) / "monitor-policy.toml"


def _strs(table: dict[str, Any], key: str, where: str) -> list[str]:
    value = table[key]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}.{key} must be a list of strings")
    return value


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as err:
        raise PolicyError(f"cannot read policy {path}: {err}") from err
    return policy_from_dict(data)


def policy_from_dict(data: dict[str, Any]) -> Policy:
    known = {
        "mode",
        "classes",
        "protected",
        "scope",
        "network",
        "canary",
        "rate",
        "ladder",
        "judge",
        "results",
        "taint",
    }
    unknown = set(data) - known
    if unknown:
        raise PolicyError(f"unknown policy section(s): {', '.join(sorted(unknown))}")
    p = Policy()
    mode = data.get("mode", p.mode)
    if mode not in MODES:
        raise PolicyError(f"mode must be one of {MODES}")
    p = replace(p, mode=mode)

    classes = dict(DEFAULT_CLASSES)
    for name, tbl in data.get("classes", {}).items():
        if name not in CLASSES:
            raise PolicyError(f"unknown tool class {name!r}; known: {', '.join(CLASSES)}")
        if not isinstance(tbl, dict) or set(tbl) - {"mode", "fail"}:
            raise PolicyError(f"classes.{name} accepts only mode and fail")
        cmode = tbl.get("mode")
        if cmode is not None and cmode not in MODES:
            raise PolicyError(f"classes.{name}.mode must be one of {MODES}")
        fail = tbl.get("fail", classes[name].fail)
        if fail not in FAILS:
            raise PolicyError(f"classes.{name}.fail must be one of {FAILS}")
        classes[name] = ClassPolicy(cmode, fail)
    p = replace(p, classes=classes)

    prot = data.get("protected", {})
    for key in ("instruction_files", "monitor_files", "monitor_code", "secret_files"):
        if key in prot:
            p = replace(p, **{key: _strs(prot, key, "protected")})  # type: ignore[arg-type]
    if "dev_mode" in prot:
        p = replace(p, dev_mode=bool(prot["dev_mode"]))
    scope = data.get("scope", {})
    if "extra_write_dirs" in scope:
        p = replace(p, extra_write_dirs=_strs(scope, "extra_write_dirs", "scope"))
    net = data.get("network", {})
    if "allow_hosts" in net:
        p = replace(p, allow_hosts=[h.lower() for h in _strs(net, "allow_hosts", "network")])
    can = data.get("canary", {})
    if "paths" in can:
        p = replace(p, canary_paths=_strs(can, "paths", "canary"))
    if "tokens" in can:
        p = replace(p, canary_tokens=_strs(can, "tokens", "canary"))
    rate = data.get("rate", {})
    for key, attr in (
        ("window_s", "rate_window_s"),
        ("max_calls", "rate_max_calls"),
        ("max_write_bytes", "rate_max_write_bytes"),
        ("max_hosts", "rate_max_hosts"),
    ):
        if key in rate:
            if not isinstance(rate[key], int) or rate[key] < 1:
                raise PolicyError(f"rate.{key} must be a positive integer")
            p = replace(p, **{attr: rate[key]})
    lad = data.get("ladder", {})
    ladder = dict(p.ladder)
    for sev in ("low", "medium", "high", "critical"):
        if sev in lad:
            if lad[sev] not in LADDER_ACTIONS:
                raise PolicyError(f"ladder.{sev} must be one of {LADDER_ACTIONS}")
            ladder[sev] = lad[sev]
    p = replace(p, ladder=ladder)
    for key in ("kill_after_blocks", "kill_window_s", "latch_minutes"):
        if key in lad:
            if not isinstance(lad[key], int) or lad[key] < 1:
                raise PolicyError(f"ladder.{key} must be a positive integer")
            p = replace(p, **{key: lad[key]})
    if "opaque_action" in lad:
        if lad["opaque_action"] not in LADDER_ACTIONS:
            raise PolicyError(f"ladder.opaque_action must be one of {LADDER_ACTIONS}")
        p = replace(p, opaque_action=lad["opaque_action"])
    j = data.get("judge", {})
    for key, attr, typ in (
        ("enabled", "judge_enabled", bool),
        ("timeout_s", "judge_timeout_s", (int, float)),
        ("deadline_s", "judge_deadline_s", (int, float)),
        ("downgrade_p", "judge_downgrade_p", (int, float)),
        ("upgrade_p", "judge_upgrade_p", (int, float)),
    ):
        if key in j:
            if not isinstance(j[key], typ):
                raise PolicyError(f"judge.{key} has the wrong type")
            p = replace(p, **{attr: j[key]})
    r = data.get("results", {})
    if set(r) - {"enabled", "use_scanner", "max_chars"}:
        raise PolicyError("results accepts only enabled, use_scanner and max_chars")
    rtypes: tuple[tuple[str, str, type], ...] = (
        ("enabled", "results_enabled", bool),
        ("use_scanner", "results_use_scanner", bool),
        ("max_chars", "results_max_chars", int),
    )
    for key, attr, rtyp in rtypes:
        if key in r:
            if not isinstance(r[key], rtyp) or (rtyp is int and (isinstance(r[key], bool) or r[key] < 100)):
                raise PolicyError(f"results.{key} has the wrong type or value")
            p = replace(p, **{attr: r[key]})
    tn = data.get("taint", {})
    if set(tn) - {"window_s"}:
        raise PolicyError("taint accepts only window_s")
    if "window_s" in tn:
        if not isinstance(tn["window_s"], int) or isinstance(tn["window_s"], bool) or tn["window_s"] < 1:
            raise PolicyError("taint.window_s must be a positive integer")
        p = replace(p, taint_window_s=tn["window_s"])
    return p
