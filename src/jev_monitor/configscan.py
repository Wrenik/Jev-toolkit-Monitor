"""Files whose contents are commands that run later: package.json scripts, dev-container hooks, pre-commit entries, CI pipelines,
compose files, editor settings and MCP server lists. Pure functions: path + text in, commands or verdicts out.

The checker runs each extracted command line through the same shell analysis a typed command gets, so the rules are the
ones already tested; this module only finds the command lines inside the formats.
"""

from __future__ import annotations

import json
import re
from typing import Any

from . import catalog

_LIFECYCLE = re.compile(r"(?i)^(?:pre|post)?(?:install|prepare|publish|pack|uninstall|version)$|^(?:pre|post)\w+$")
_YAML_KEYS = r"run|script|before_script|after_script|entry|command|cmd|sh|bat|pwsh|powershell|shell|init|exec"
_LINE_PREFIX = re.compile(rf"^\s*(?:-\s+)*(?:(?:{_YAML_KEYS})\s*:\s*[|>]?-?\s*)?")
_JENKINS = re.compile(r"""\b(?:sh|bat|powershell|pwsh)\s*\(?\s*(['"])(.+?)\1""")
MAX_CMDS = 60
MAX_CHARS = 60_000

VSCODE_RISK = re.compile(
    r"(?i)terminal\.integrated\.(?:profiles|defaultProfile|shell|automation|env|inheritEnv)|task\.allowAutomaticTasks|"
    r"\"[\w.-]*\.(?:path|exe|executable|binary|command|args)\"\s*:|\.(?:sh|ps1|bat|cmd|exe)\b|"
    r"\b(?:curl|wget|iex|irm|iwr|powershell|bash\s+-c|cmd\s+/c)\b"
)
COMPOSE_RISK = re.compile(
    r"(?im)^\s*(?:privileged:\s*true|pid:\s*[\"']?host|network_mode:\s*[\"']?host|ipc:\s*[\"']?host|-\s*[\"']?(?:/|~|\$HOME)[\"']?:[\"']?/|"
    r"-\s*[\"']?/var/run/docker\.sock|-\s*[\"']?(?:~|\$HOME|%USERPROFILE%)/\.(?:ssh|aws|kube|gnupg)|cap_add:.*sys_admin|-\s*sys_admin)"
)

_MCP_OK_PACKAGES = (
    "@modelcontextprotocol/",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "mcp-server-git",
    "mcp-server-fetch",
    "mcp-server-time",
    "@azure/mcp",
    "@github/mcp-server",
)
_MCP_FILES = {".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json", ".claude.json"}


def classify(path: str) -> str | None:
    p = path.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    if catalog.CI_FILES.search(p) or re.search(
        r"(?i)(?:^|/)(?:\.travis\.ya?ml|\.drone\.ya?ml|\.github/actions/[^/]+/action\.ya?ml)$", p
    ):
        return "ci"
    if base == "package.json":
        return "package"
    if re.search(r"(?:^|/)\.devcontainer(?:/[^/]+)?/devcontainer\.json$|(?:^|/)\.devcontainer\.json$", p):
        return "devcontainer"
    if re.search(r"(?:^|/)\.(?:husky|githooks)/[^/]+$", p):
        return "hook"
    if base in (".pre-commit-config.yaml", ".pre-commit-config.yml", "lefthook.yml", ".lefthook.yml", ".gitpod.yml"):
        return "hook"
    if re.match(r"(?i)^(?:docker-)?compose[\w.-]*\.ya?ml$", base):
        return "compose"
    return None


def is_mcp_config(path: str) -> bool:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower() in _MCP_FILES


def _flatten(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return (
            [" ".join(x for x in value if isinstance(x, str))]
            if all(isinstance(x, str) for x in value)
            else [s for x in value for s in _flatten(x)]
        )
    if isinstance(value, dict):
        return [s for x in value.values() for s in _flatten(x)]
    return []


def _lines(text: str) -> list[str]:
    out: list[str] = []
    for raw in text[:MAX_CHARS].splitlines():
        if not raw.strip() or raw.lstrip().startswith(("#", "//")):
            continue
        m = _JENKINS.search(raw)
        line = m.group(2) if m else _LINE_PREFIX.sub("", raw, count=1).strip().strip("\"'")
        if line:
            out.append(line)
    return out


def commands(kind: str, text: str) -> list[tuple[str, bool]]:
    """(command line, uncapped) pairs. `uncapped` marks places where a command runs without anyone asking for it
    (install hooks, dev-container hooks, pre-commit entries): their findings keep their full severity."""
    out: list[tuple[str, bool]] = []
    data: Any = None
    if kind in ("package", "devcontainer"):
        try:
            data = json.loads(text[:MAX_CHARS])
        except ValueError:
            data = None
    if kind == "package" and isinstance(data, dict):
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for name, value in scripts.items():
                out += [(s, bool(_LIFECYCLE.match(str(name)))) for s in _flatten(value)]
    elif kind == "devcontainer" and isinstance(data, dict):
        for key, value in data.items():
            if key.endswith("Command"):
                out += [(s, True) for s in _flatten(value)]
    else:
        out += [(s, kind in ("hook", "package", "devcontainer")) for s in _lines(text)]
    return out[:MAX_CMDS]


def mcp_servers_benign(text: str, host_ok) -> bool:
    """True only for a complete, parseable server list in which every entry is a well-known package run through npx/uvx or a
    URL on a trusted host. Anything partial, unusual or with a shell in it is not benign."""
    try:
        data = json.loads(text)
    except ValueError:
        return False
    if not isinstance(data, dict) or set(data) - {"mcpServers", "servers", "inputs", "$schema"}:
        return False
    servers = data.get("mcpServers", data.get("servers"))
    if not isinstance(servers, dict) or not servers:
        return False
    for cfg in servers.values():
        if not isinstance(cfg, dict):
            return False
        if "url" in cfg:
            from .shell import host_of

            h = host_of(str(cfg["url"]))
            if not h or not host_ok(h):
                return False
            continue
        cmd = (
            str(cfg.get("command", ""))
            .replace("\\", "/")
            .rsplit("/", 1)[-1]
            .lower()
            .removesuffix(".exe")
            .removesuffix(".cmd")
        )
        args = [str(x) for x in cfg.get("args", [])] if isinstance(cfg.get("args", []), list) else None
        if cmd not in ("npx", "uvx", "bunx") or args is None:
            return False
        names = [x for x in args if not x.startswith("-")]
        if (
            not names
            or not names[0].startswith(_MCP_OK_PACKAGES)
            or any(x in ("-c", "-e", "--eval", "-p") for x in args)
        ):
            return False
    return True
