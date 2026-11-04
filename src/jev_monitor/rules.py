"""Deterministic checks. Each returns findings; none of them calls a model.

Order of importance (DESIGN 6.4): changes to the agent's own instructions and to the monitor, canaries,
then scope, outbound traffic, secret exfiltration shape, exploitable shell shapes, rate/volume.
"""

from __future__ import annotations

import ipaddress
import json
import re
import tempfile
import time
from functools import lru_cache
from collections import defaultdict, deque

from . import paths
from .policy import SECRET_EXEMPT_GLOBS, Policy
from .shell import Analysis, analyze
from .types import CRITICAL, HIGH, LOW, MEDIUM, Call, Finding, tool_class

MONITOR_PORT = 8767
DEFAULT_CANARY = re.compile(r"JEVCANARY-[A-Za-z0-9]{6,}")
_PERSISTENCE = [
    "~/.bashrc", "~/.bash_profile", "~/.bash_login", "~/.bash_logout", "~/.profile", "~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin",
    "~/.config/fish/**", "~/.ssh/authorized_keys", "~/.ssh/authorized_keys2", "~/.ssh/config", "~/.ssh/rc", "~/.gitconfig", "~/.config/git/**",
    "~/.config/systemd/**", "~/.config/autostart/**", "~/.local/share/systemd/**", "~/Library/LaunchAgents/**",
    "/etc/**", "/usr/**", "/bin/**", "/sbin/**", "/lib/**", "/opt/**", "/boot/**", "/root/**", "/var/spool/**", "/var/lib/systemd/**",
    "/Library/LaunchAgents/**", "/Library/LaunchDaemons/**", "/Library/StartupItems/**", "/System/**",
    "**/.vscode/tasks.json", "**/.vscode/settings.json", "**/.vscode/launch.json",
    "**/crontab", "**/Microsoft.PowerShell_profile.ps1", "**/Microsoft.VSCode_profile.ps1", "**/profile.ps1", "**/Start Menu/Programs/Startup/**",
    "c:/windows/**", "c:/program files/**", "c:/program files (x86)/**", "c:/programdata/**",
]
_TAMPER_CMD = re.compile(
    r"(?i)jev_monitor\s+(reset|mode|serve|shutdown|allow|policy)\b|"
    r"(127\.0\.0\.1|localhost)(:|%3a)" + str(MONITOR_PORT) + r"|X-Jev-Monitor|"
    r"(pkill|killall|taskkill|stop-process|kill)\b[^;|&\n]*(jev|monitor)"
)
_ENV_DUMP = {"env", "printenv", "get-childitem", "gci", "dir", "ls"}
_METADATA = {"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "metadata.google.internal", "metadata", "100.100.100.200", "metadata.azure.com"}


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def ip_kind(host: str) -> str:
    """public | loopback | private | link-local | none (not an IP). Decimal/hex/octal IPv4 forms are decoded first."""
    h = host.strip("[]").lower()
    try:
        if re.fullmatch(r"0x[0-9a-f]+|\d{5,}", h):
            h = str(ipaddress.ip_address(int(h, 16 if h.startswith("0x") else 10)))
        elif re.fullmatch(r"[0-9a-fx.]+", h) and h.count(".") == 3 and any(p.startswith("0") and len(p) > 1 for p in h.split(".")):
            h = ".".join(str(int(p, 16 if p.startswith("0x") else 8 if p.startswith("0") and len(p) > 1 else 10)) for p in h.split("."))
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "none"
    if ip.is_loopback or str(ip) == "0.0.0.0":
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if any(ip in net for net in _INTERNAL_NETS):
        return "private"
    return "public"  # includes the documentation ranges (203.0.113.0/24 ...), which Python calls private



@lru_cache(maxsize=1)
def _temp_roots() -> tuple[str, ...]:
    """Scratch folders count as in scope. Computed once: resolving `/dev/shm` & co. on Windows costs ~0.5 s each."""
    out = [paths.canon(tempfile.gettempdir(), "/", resolve=True).path]
    out += [paths.canon(r, "/", resolve=False).path for r in ("/tmp", "/var/tmp", "/dev/shm")]
    return tuple(dict.fromkeys(out))


class Tracker:
    """Per-session rate and volume memory (in the server's RAM; a restart forgets it, which is fine)."""

    def __init__(self) -> None:
        self.events: dict[str, deque] = defaultdict(deque)  # session -> (ts, bytes, host|None)
        self.blocks: dict[str, deque] = defaultdict(deque)  # session -> ts of enforced-or-would-be blocks
        self.criticals: dict[str, deque] = defaultdict(deque)

    def record(self, session: str | None, nbytes: int, hosts: list[str], policy: Policy, now: float | None = None) -> list[Finding]:
        now = time.time() if now is None else now
        q = self.events[session or "-"]
        q.append((now, nbytes, hosts))
        while q and q[0][0] < now - policy.rate_window_s:
            q.popleft()
        out: list[Finding] = []
        if len(q) > policy.rate_max_calls:
            out.append(Finding("rate-calls", MEDIUM, f"{len(q)} tool calls in {policy.rate_window_s}s (limit {policy.rate_max_calls})"))
        total = sum(b for _, b, _ in q)
        if total > policy.rate_max_write_bytes:
            out.append(Finding("rate-write-volume", MEDIUM, f"{total} bytes written in {policy.rate_window_s}s (limit {policy.rate_max_write_bytes})"))
        distinct = {h for _, _, hs in q for h in hs}
        if len(distinct) > policy.rate_max_hosts:
            out.append(Finding("rate-hosts", MEDIUM, f"{len(distinct)} distinct hosts in {policy.rate_window_s}s (limit {policy.rate_max_hosts})"))
        return out

    def note(self, store: dict[str, deque], session: str | None, window: int, now: float | None = None) -> int:
        now = time.time() if now is None else now
        q = store[session or "-"]
        q.append(now)
        while q and q[0] < now - window:
            q.popleft()
        return len(q)


def host_allowed(host: str, policy: Policy) -> bool:
    host = host.lower().strip(".")
    return any(host == a or host.endswith("." + a) for a in policy.allow_hosts)


def _ops_of(call: Call, a: Analysis | None) -> list[tuple[str, str, str, str, bool]]:
    """(kind, raw path, cwd, via, recursive) for every file the call writes, deletes or reads."""
    ops: list[tuple[str, str, str, str, bool]] = []
    inp = call.input
    if call.tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = inp.get("file_path") or inp.get("notebook_path") or inp.get("path")
        if isinstance(p, str):
            ops.append(("write", p, call.cwd, call.tool, False))
    elif call.tool in ("Read", "NotebookRead"):
        p = inp.get("file_path") or inp.get("notebook_path")
        if isinstance(p, str):
            ops.append(("read", p, call.cwd, call.tool, False))
    elif call.tool in ("Grep", "Glob", "LS"):
        p = inp.get("path")
        if isinstance(p, str):
            ops.append(("read", p, call.cwd, call.tool, True))
    if a is not None:
        for o in a.ops:
            if o.kind in ("write", "delete", "read"):
                ops.append((o.kind, o.target, o.cwd, o.via, o.recursive))
    return ops


def _written_bytes(call: Call) -> int:
    inp = call.input
    n = 0
    for key in ("content", "new_string", "new_source"):
        v = inp.get(key)
        if isinstance(v, str):
            n += len(v)
    for e in inp.get("edits", []) if isinstance(inp.get("edits"), list) else []:
        if isinstance(e, dict) and isinstance(e.get("new_string"), str):
            n += len(e["new_string"])
    return n


def analyse_call(call: Call) -> Analysis | None:
    if call.tool in ("Bash", "PowerShell"):
        cmd = call.input.get("command")
        if isinstance(cmd, str):
            return analyze(cmd, call.cwd, powershell=call.tool == "PowerShell")
    return None


def check(call: Call, policy: Policy, tracker: Tracker, analysis: Analysis | None = None, now: float | None = None) -> list[Finding]:  # noqa: C901
    a = analysis if analysis is not None else analyse_call(call)
    findings: list[Finding] = []
    add = findings.append
    if call.tool in ("Bash", "PowerShell") and a is None:
        add(Finding("opaque-shell", HIGH, "the shell command is missing or not text, so it cannot be checked", opaque=True))
    elif tool_class(call.tool) == "other":
        add(Finding("unknown-tool", LOW, f"tool {call.tool[:40]!r} is not one the monitor knows (logged, not judged)"))
    root = paths.canon(call.root or call.cwd, call.cwd).path
    home = paths.canon("~", call.cwd).path
    temps = list(_temp_roots())
    extras = [paths.canon(d, call.cwd).path for d in policy.extra_write_dirs]

    def classify(raw: str, cwd: str) -> paths.Canon:
        return paths.canon(raw, cwd or call.cwd)

    seen_rules: set[tuple[str, str]] = set()

    def once(f: Finding, key: str) -> None:
        if (f.rule, key) not in seen_rules:
            seen_rules.add((f.rule, key))
            add(f)

    # ---- opaque shell --------------------------------------------------------------
    if a is not None:
        for why in a.opaque:
            once(Finding("opaque-shell", HIGH, f"cannot tell what this touches: {why}", "Write the path out literally, or run it yourself.", opaque=True), why)

    # ---- file operations -----------------------------------------------------------
    for kind, raw, cwd, via, recursive in _ops_of(call, a):
        c = classify(raw, cwd)
        label = raw if len(raw) < 80 else raw[:77] + "..."
        if c.ambiguous:
            if kind != "read":
                once(Finding("opaque-path", HIGH, f"{via}: path cannot be resolved ({c.why})", opaque=True), raw)
            continue
        p = c.path
        if paths.matches_any(p, policy.canary_paths):
            once(Finding("canary-touched", CRITICAL, f"{via} touches a canary file ({label})"), p)
            continue
        if kind in ("write", "delete"):
            if paths.matches_any(p, policy.monitor_files):
                once(Finding("monitor-tamper", CRITICAL, f"{via} changes the monitor's own policy/state/log ({label})"), p)
                continue
            if not policy.dev_mode and paths.matches_any(p, policy.monitor_code):
                once(Finding("monitor-code-change", HIGH, f"{via} changes the monitor's code ({label})"), p)
                continue
            if (kind == "delete" or recursive) and _catastrophic(raw, p, home):
                once(Finding("destructive-delete", HIGH, f"{via} {'deletes' if kind == 'delete' else 'recursively changes'} your home folder, a drive root or the filesystem root ({label})",
                             "Name the exact folder you mean."), p)
                continue
            hit = paths.matches_any(p, policy.instruction_files)
            if hit is None and kind == "delete" or (hit is None and recursive):
                hit = _ancestor_hit(p, root, home, policy)
            if hit is not None:
                once(Finding("instruction-file-change", HIGH, f"{via} {'deletes' if kind == 'delete' else 'writes'} an instruction file ({label}, matches {hit})",
                             "Instruction files steer the agent; change them yourself."), p)
                continue
            persist = paths.matches_any(p, _PERSISTENCE) or paths.matches_any(re.sub(r"^[a-z]:", "", p), [x for x in _PERSISTENCE if x.startswith("/")])
            if persist:
                once(Finding("persistence-file", HIGH, f"{via} writes a startup/system file ({label})"), p)
            elif not (paths.under(p, root) or any(paths.under(p, t) for t in temps + extras)):
                sev = HIGH if kind == "delete" and recursive else MEDIUM
                once(Finding("write-outside-scope", sev, f"{via} {kind}s outside the project ({label})", "Add the folder to [scope] extra_write_dirs."), p)
            if via in ("chmod", "chown", "chgrp") and recursive and not paths.under(p, root):
                once(Finding("destructive-permission-change", HIGH, f"{via} -R changes permissions or owners outside the project ({label})"), p)
        elif kind == "read" and _is_secret(p, policy):
            once(Finding("secret-file-access", MEDIUM, f"{via} reads a likely secret file ({label})"), p)

    # ---- words in shell commands: canary and secret paths ---------------------------
    secret_touch = False
    if a is not None:
        for w in a.words[:150]:
            if not re.search(r"[/\\.~]", w):
                continue
            c = classify(w, a.ops[0].cwd if a.ops else call.cwd)
            if c.ambiguous:
                continue
            if paths.matches_any(c.path, policy.canary_paths):
                once(Finding("canary-touched", CRITICAL, f"command mentions a canary file ({w[:60]})"), c.path)
            elif _is_secret(c.path, policy):
                secret_touch = True
                once(Finding("secret-file-access", MEDIUM, f"command touches a likely secret file ({w[:60]})"), c.path)
        if any(cmd in ("printenv", "env-dump") for cmd in a.commands):
            secret_touch = True
    elif call.tool in ("Read", "Grep"):
        pass

    # ---- canary tokens anywhere in the call -------------------------------------------
    blob = json.dumps(call.input, default=str)
    if a is not None:
        blob += "\n" + "\n".join(a.mentions)
    for tok in policy.canary_tokens:
        if tok and tok in blob:
            once(Finding("canary-token", CRITICAL, "a canary token appears in the call"), tok)
    if DEFAULT_CANARY.search(blob):
        once(Finding("canary-token", CRITICAL, "a canary token appears in the call"), "default")

    # ---- the monitor itself ---------------------------------------------------------------
    if call.tool in ("Bash", "PowerShell") and _TAMPER_CMD.search(str(call.input.get("command", "")) + "\n" + "\n".join(a.mentions if a else [])):
        once(Finding("monitor-tamper", CRITICAL, "command talks to, controls or stops the monitor"), "cmd")

    # ---- outbound traffic ------------------------------------------------------------------
    hosts: list[str] = []

    def net_finding(host: str, via: str, upload: bool, supply: bool) -> bool:
        """Adds the finding for one destination; True when it is something that leaves the trusted set."""
        h = host.lower().strip(".")
        kind = ip_kind(h)
        if h in _METADATA or (kind == "link-local"):
            once(Finding("ssrf-metadata", HIGH, f"{via} reaches a cloud metadata / link-local address ({h}), the usual way to steal cloud credentials"), h)
            return True
        if host_allowed(h, policy):
            return False
        if kind == "loopback":
            return False
        if kind == "private":
            once(Finding("outbound-private-network", HIGH, f"{via} reaches an internal network address ({h}), a possible SSRF target", "Add a LAN host you trust to [network] allow_hosts."), h)
        elif kind == "public":
            once(Finding("outbound-raw-ip", HIGH, f"{via} talks to a raw public IP address ({h})"), h)
        elif supply:
            once(Finding("supply-chain-source", HIGH, f"{via} takes packages or code from unlisted source {h}", "Add the host to [network] allow_hosts if you trust it."), h)
        elif upload:
            once(Finding("outbound-upload-unlisted", HIGH, f"{via} sends data to unlisted host {h}", "Add the host to [network] allow_hosts."), h)
        else:
            once(Finding("outbound-unlisted-host", MEDIUM, f"{via} reaches unlisted host {h}", "Add the host to [network] allow_hosts."), h)
        return True
    if call.tool == "WebFetch":
        from .shell import host_of

        url = str(call.input.get("url", ""))
        h = host_of(url if "://" in url else "http://" + url)
        if h:
            hosts.append(h)
            net_finding(h, "WebFetch", False, False)
        else:
            once(Finding("outbound-unlisted-host", MEDIUM, "WebFetch URL could not be parsed"), url)
    net_present = False
    if a is not None:
        for o in a.ops:
            if o.kind == "listen":
                once(Finding("opens-listener", HIGH, f"{o.via} opens a listening socket"), o.via)
            if o.kind != "net":
                continue
            hosts.append(o.target)
            if net_finding(o.target, o.via, o.upload, o.supply):
                net_present = True
    if secret_touch and net_present:
        once(Finding("secret-exfil-shape", HIGH, "a secret file or the environment is read in the same command as network access"), "exfil")

    # ---- exploitable shell shapes -------------------------------------------------------------
    if a is not None:
        for why in a.pipe_exec:
            once(Finding("remote-code-exec", HIGH, why), why)
        for why in a.persist:
            if why.startswith(("container ", "antivirus", "PowerShell execution", "the Windows firewall", "the firewall", "SELinux", "macOS system", "git TLS", "npm TLS")):
                once(Finding("container-escape" if why.startswith("container ") else "security-setting-change", HIGH, why), why)
            else:
                once(Finding("persistence-command", HIGH, why), why)
        if "git-hooks-path" in a.mentions:
            once(Finding("instruction-file-change", HIGH, "git config core.hooksPath redirects git hooks"), "hooks")
        for why in a.bulk:
            once(Finding("bulk-change", LOW, f"{why} can rewrite many files"), why)
        if any(c in ("sudo", "doas") for c in a.commands):
            once(Finding("privilege-escalation", MEDIUM, "command uses sudo"), "sudo")

    # ---- rate / volume -----------------------------------------------------------------------------
    for f in tracker.record(call.session, _written_bytes(call), hosts, policy, now):
        add(f)
    return findings


def _is_secret(p: str, policy: Policy) -> bool:
    return bool(paths.matches_any(p, policy.secret_files)) and not paths.matches_any(p, SECRET_EXEMPT_GLOBS)


def _catastrophic(raw: str, p: str, home: str) -> bool:
    """Home folder, filesystem root, a drive root, or their `/*` forms."""
    if p in ("/", home) or re.fullmatch(r"[a-z]:/?", p) or p == paths.canon("/", "/").path:
        return True
    return bool(re.fullmatch(r"(/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|[A-Za-z]:[\\/]?)[\\/]?\*?", raw.strip("\"'")))


def _ancestor_hit(p: str, root: str, home: str, policy: Policy) -> str | None:
    """Deleting or replacing a folder that CONTAINS an instruction file is as bad as touching the file."""
    candidates = []
    for pat in policy.instruction_files:
        if any(ch in pat for ch in "*?["):
            base = pat.split("/**")[0]
            base = base[:-1] if base.endswith("/") else base
            if base and not any(ch in base for ch in "*?["):
                candidates.append((pat, base))
        else:
            candidates.append((pat, pat))
    for pat, rel in candidates:
        for anchor in (root, home):
            cp = paths.canon(rel if rel.startswith("~") else anchor + "/" + rel, anchor, resolve=False).path
            if paths.under(cp, p):
                return pat
    if p == root or p == home:
        return "the project/home folder"
    return None
