"""Deterministic checks. Each returns findings; none of them calls a model.

Order of importance (DESIGN 6.4): changes to the agent's own instructions and to the monitor, canaries,
then scope, outbound traffic, secret exfiltration shape, exploitable shell shapes, rate/volume.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
from collections import defaultdict, deque
from functools import lru_cache

from . import catalog, configscan, paths
from .policy import SECRET_EXEMPT_GLOBS, Policy
from .shell import NET_COMMANDS, Analysis, analyze, host_of, urls_in
from .types import CRITICAL, HIGH, LOW, MEDIUM, Call, Finding, tool_class

MONITOR_PORT = 8767
TAINT_PER_SESSION = 32
TAINT_SESSIONS = 256
_EDIT_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
DEFAULT_CANARY = re.compile(r"JEVCANARY-[A-Za-z0-9]{6,}")
_PERSISTENCE = [
    "~/.bashrc", "~/.bash_profile", "~/.bash_login", "~/.bash_logout", "~/.profile", "~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin",
    "~/.config/fish/**", "~/.ssh/authorized_keys", "~/.ssh/authorized_keys2", "~/.ssh/config", "~/.ssh/rc", "~/.gitconfig", "~/.config/git/**",
    "~/.config/systemd/**", "~/.config/autostart/**", "~/.local/share/systemd/**", "~/Library/LaunchAgents/**",
    "/etc/**", "/usr/**", "/bin/**", "/sbin/**", "/lib/**", "/opt/**", "/boot/**", "/root/**", "/var/spool/**", "/var/lib/systemd/**",
    "/Library/LaunchAgents/**", "/Library/LaunchDaemons/**", "/Library/StartupItems/**", "/System/**",
    "**/.vscode/tasks.json", "**/.vscode/settings.json", "**/.vscode/launch.json",
    "**/crontab", "**/Microsoft.PowerShell_profile.ps1", "**/Microsoft.VSCode_profile.ps1", "**/profile.ps1", "**/Start Menu/Programs/Startup", "**/Start Menu/Programs/Startup/**",
    "c:/windows/**", "c:/program files/**", "c:/program files (x86)/**", "c:/programdata/**",
]
_TAMPER_CMD = re.compile(
    r"(?i)jev_monitor\s+(reset|mode|serve|shutdown|allow|policy)\b|"
    r"(127\.0\.0\.1|localhost)(:|%3a)" + str(MONITOR_PORT) + r"|X-Jev-Monitor|"
    r"(pkill|killall|taskkill|stop-process|kill)\b[^;|&\n]*(jev|monitor)"
)
_LOG_FILES = ["**/.bash_history", "**/.zsh_history", "**/.history", "**/ConsoleHost_history.txt", "/var/log/**", "c:/windows/system32/winevt/**"]
_PKG_CONF = {".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmrc", "pip.conf", "pip.ini", ".pypirc", ".condarc", "nuget.config", "settings.xml", "uv.toml", ".bunfig.toml", "bunfig.toml", ".gemrc"}
_METADATA_WORD = re.compile(r"(?i)169\.254\.\d{1,3}\.\d{1,3}|fd00:ec2::254|metadata\.google\.internal|100\.100\.100\.200")
_HISTORY_READ = re.compile(r"(?i)HistorySavePath|ConsoleHost_history")
_PROC_ENV = re.compile(r"/proc/(?:self|\d+|\*)/environ")
_ENV_DUMP = {"env", "printenv", "get-childitem", "gci", "dir", "ls"}
_METADATA = {"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "metadata.google.internal", "metadata", "100.100.100.200", "metadata.azure.com",
             "instance-data", "instance-data.ec2.internal", "metadata.tencentyun.com", "metadata.platformequinix.com", "metadata.packet.net"}
_EMBEDDED_IP = re.compile(r"(?<![\d])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})(?![\d])")  # 169.254.169.254.nip.io, 10-0-0-5.sslip.io
# MCP tool inputs: which keys hold paths, commands and URLs, and which tool-name words mean write / delete
_MCP_PATH_KEYS = {"path", "paths", "file", "files", "file_path", "filepath", "filename", "source", "src", "destination", "dest", "dst", "target", "directory", "dir", "folder", "from", "to", "notebook_path"}
_MCP_CMD_KEYS = {"command", "cmd", "script", "shell", "commandline", "command_line"}
_MCP_URL_KEYS = {"url", "urls", "uri", "endpoint", "href", "link", "base_url", "webhook", "webhook_url"}
_MCP_WRITE = re.compile(r"(?i)write|create|edit|update|append|save|put|upload|replace|patch|insert|set|touch|mkdir|copy|move|rename|apply|commit")
_MCP_DELETE = re.compile(r"(?i)delete|remove|rm|unlink|trash|drop|erase|clear|purge")


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
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # [::ffff:169.254.169.254] is the same address as 169.254.169.254
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
        # session -> {hash of a secret file's path (or of a secret literal): time it was read}. Hashes only, 32 per session, 256 sessions.
        self.taint: dict[str, dict[str, float]] = {}

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

    def taint_add(self, session: str | None, what: str, now: float) -> None:
        key = hashlib.sha256(what.encode("utf-8", "replace")).hexdigest()[:12]
        sess = self.taint.setdefault(session or "-", {})
        sess.pop(key, None)
        sess[key] = now
        while len(sess) > TAINT_PER_SESSION:
            sess.pop(next(iter(sess)))
        while len(self.taint) > TAINT_SESSIONS:
            self.taint.pop(next(iter(self.taint)))

    def taint_live(self, session: str | None, now: float, window: int) -> list[float]:
        sess = self.taint.get(session or "-", {})
        for k in [k for k, ts in sess.items() if ts < now - window]:
            del sess[k]
        return list(sess.values())

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
    elif tool_class(call.tool) == "mcp":
        ops.extend(_mcp_ops(call))
    if a is not None:
        for o in a.ops:
            if o.kind in ("write", "delete", "read"):
                ops.append((o.kind, o.target, o.cwd, o.via, o.recursive))
    return ops


def _looks_like_path(v: str) -> bool:
    return 0 < len(v) < 1000 and ("/" in v or "\\" in v or v.startswith("~") or re.match(r"^[A-Za-z]:", v) is not None or re.search(r"\.\w{1,6}$", v) is not None)


def _mcp_ops(call: Call) -> list[tuple[str, str, str, str, bool]]:
    """File operations an MCP tool (or any tool the monitor does not know) seems to perform, judged by its name and its argument keys."""
    verb = call.tool.split("__")[-1]
    kind = "delete" if _MCP_DELETE.search(verb) else "write" if _MCP_WRITE.search(verb) else "read"
    ops: list[tuple[str, str, str, str, bool]] = []
    for key, val in call.input.items():
        k = key.lower()
        if k not in _MCP_PATH_KEYS:
            continue
        vals = val if isinstance(val, list) else [val]
        for v in vals[:20]:
            if isinstance(v, str) and _looks_like_path(v):
                this = "read" if k in ("source", "src", "from") and re.search(r"(?i)copy", verb) else "delete" if k in ("source", "src", "from") and re.search(r"(?i)move|rename", verb) else kind
                ops.append((this, v, call.cwd, call.tool, False))
    return ops


def _strings(obj, depth: int = 0):
    """Every string inside a tool input (values only), shallow-limited."""
    if isinstance(obj, str):
        yield obj
    elif depth < 4 and isinstance(obj, dict):
        for v in list(obj.values())[:50]:
            yield from _strings(v, depth + 1)
    elif depth < 4 and isinstance(obj, list):
        for v in obj[:50]:
            yield from _strings(v, depth + 1)


def _mcp_urls(call: Call) -> list[str]:
    out: list[str] = []
    for key, val in call.input.items():
        if key.lower() in _MCP_URL_KEYS:
            for v in (val if isinstance(val, list) else [val])[:10]:
                if isinstance(v, str) and v:
                    out.append(v)
    return out


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
    elif tool_class(call.tool) == "mcp":  # an MCP tool that takes a command line is a shell by another name
        cmds = [v for k, v in call.input.items() if k.lower() in _MCP_CMD_KEYS and isinstance(v, str)]
        if cmds:
            return analyze("\n".join(cmds), call.cwd, powershell=False)
    return None


class _Checker:
    """One run of the deterministic checks for one call. Each `_section` method adds findings; `run` calls them in the
    order of importance (instruction files and the monitor first, rate last). `once` drops repeats of the same rule+key."""

    def __init__(self, call: Call, policy: Policy, tracker: Tracker, analysis: Analysis | None, now: float | None) -> None:
        self.call, self.policy, self.tracker, self.now = call, policy, tracker, now
        self.a = analysis if analysis is not None else analyse_call(call)
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str]] = set()
        self.root = paths.canon(call.root or call.cwd, call.cwd).path
        self.home = paths.canon("~", call.cwd).path
        self.temps = list(_temp_roots())
        self.extras = [paths.canon(d, call.cwd).path for d in policy.extra_write_dirs]
        self.secret_touch = False
        self._secret_keys: set[str] = set()
        self.hosts: list[str] = []
        self.net_present = False
        self.published = False
        self._blob: str | None = None

    # -- helpers
    def once(self, f: Finding, key: str) -> None:
        if (f.rule, key) not in self._seen:
            self._seen.add((f.rule, key))
            self.findings.append(f)

    def touch(self, key: str) -> None:
        self.secret_touch = True
        if len(self._secret_keys) < 8:
            self._secret_keys.add(key)

    def classify(self, raw: str, cwd: str) -> paths.Canon:
        return paths.canon(raw, cwd or self.call.cwd)

    @property
    def blob(self) -> str:
        """Everything the call says, as one string: the raw input plus heredoc and inline-code text found by the shell analysis."""
        if self._blob is None:
            self._blob = json.dumps(self.call.input, default=str) + (("\n" + "\n".join(self.a.mentions)) if self.a is not None else "")
        return self._blob

    def run(self) -> list[Finding]:
        call, a = self.call, self.a
        if call.tool in ("Bash", "PowerShell") and a is None:
            self.findings.append(Finding("opaque-shell", HIGH, "the shell command is missing or not text, so it cannot be checked", opaque=True))
        elif tool_class(call.tool) == "other":
            self.findings.append(Finding("unknown-tool", LOW, f"tool {call.tool[:40]!r} is not one the monitor knows (logged, not judged)"))
        for section in (self._opaque, self._file_ops, self._shell_words, self._canary_tokens, self._monitor_tamper, self._outbound, self._shell_shapes, self._content_checks, self._combos, self._taint):
            section()
        self.findings.extend(self.tracker.record(call.session, _written_bytes(call), self.hosts, self.policy, self.now))
        return self.findings

    # -- sections
    def _opaque(self) -> None:
        if self.a is not None:
            for why in self.a.opaque:
                self.once(Finding("opaque-shell", HIGH, f"cannot tell what this touches: {why}", "Write the path out literally, or run it yourself.", opaque=True), why)

    def _file_ops(self) -> None:
        for kind, raw, cwd, via, recursive in _ops_of(self.call, self.a):
            c = self.classify(raw, cwd)
            label = raw if len(raw) < 80 else raw[:77] + "..."
            if c.ambiguous:
                if kind != "read":
                    self.once(Finding("opaque-path", HIGH, f"{via}: path cannot be resolved ({c.why})", opaque=True), raw)
                continue
            p = c.path
            if paths.matches_any(p, self.policy.canary_paths):
                self.once(Finding("canary-touched", CRITICAL, f"{via} touches a canary file ({label})"), p)
            elif kind in ("write", "delete"):
                self._write_op(kind, raw, p, via, recursive, label)
            elif kind == "read" and _is_secret(p, self.policy):
                self.touch(p)
                self.once(Finding("secret-file-access", MEDIUM, f"{via} reads a likely secret file ({label})"), p)

    def _write_op(self, kind: str, raw: str, p: str, via: str, recursive: bool, label: str) -> None:
        """One write or delete, tested against the protected sets from most to least serious; the first hit decides."""
        policy, once, home, root = self.policy, self.once, self.home, self.root
        if paths.matches_any(p, policy.monitor_files):
            once(Finding("monitor-tamper", CRITICAL, f"{via} changes the monitor's own policy/state/log ({label})"), p)
            return
        if not policy.dev_mode and paths.matches_any(p, policy.monitor_code):
            once(Finding("monitor-code-change", HIGH, f"{via} changes the monitor's code ({label})"), p)
            return
        if (kind == "delete" or recursive) and _catastrophic(raw, p, home):
            once(Finding("destructive-delete", HIGH, f"{via} {'deletes' if kind == 'delete' else 'recursively changes'} your home folder, a drive root or the filesystem root ({label})",
                         "Name the exact folder you mean."), p)
            return
        hit = paths.matches_any(p, policy.instruction_files)
        if hit is None and (kind == "delete" or recursive):
            hit = _ancestor_hit(p, root, home, policy)
        if hit is not None and via in _EDIT_TOOLS and kind == "write" and configscan.is_mcp_config(p) and configscan.mcp_servers_benign(self._written_text(), lambda h: host_allowed(h, policy) or ip_kind(h) == "loopback"):
            once(Finding("mcp-config-change", MEDIUM, f"{via} edits an MCP server list ({label}); every server is a well-known package or a trusted host"), p)
            return
        if hit is not None:
            once(Finding("instruction-file-change", HIGH, f"{via} {'deletes' if kind == 'delete' else 'writes'} an instruction file ({label}, matches {hit})",
                         "Instruction files steer the agent; change them yourself."), p)
            return
        if paths.matches_any(p, _LOG_FILES):
            once(Finding("log-tamper", HIGH, f"{via} changes a shell history or system log file ({label})"), p)
        elif self._persistence_hit(p, via):
            once(Finding("persistence-file", HIGH, f"{via} writes a startup/system file ({label})"), p)
        elif not (paths.under(p, root) or any(paths.under(p, t) for t in self.temps + self.extras)):
            sev = HIGH if kind == "delete" and recursive else MEDIUM
            once(Finding("write-outside-scope", sev, f"{via} {kind}s outside the project ({label})", "Add the folder to [scope] extra_write_dirs."), p)
        if via in ("chmod", "chown", "chgrp") and recursive and not paths.under(p, root):
            once(Finding("destructive-permission-change", HIGH, f"{via} -R changes permissions or owners outside the project ({label})"), p)
        if kind == "write" and via in _EDIT_TOOLS:
            self._config_contents(p, via, label)
        if kind == "write" and catalog.CI_FILES.search(p):
            text = "\n".join(_strings({k: v for k, v in self.call.input.items() if k != "file_path"}))
            if catalog.CI_RISK.search(text):
                once(Finding("ci-pipeline-risk", MEDIUM, f"{via} writes a CI pipeline file ({label}) with a risky construct (remote script, secrets sent out, pull_request_target)"), p)
        if kind == "write" and (os.path.basename(p) in _PKG_CONF or p.endswith("/.cargo/config.toml")):
            for h in urls_in(self.blob):
                if not host_allowed(h, policy) and ip_kind(h) != "loopback":
                    once(Finding("supply-chain-source", HIGH, f"{via} points the package manager config ({os.path.basename(p)}) at unlisted source {h}",
                                 "Add the host to [network] allow_hosts if you trust it."), h)

    def _written_text(self) -> str:
        return "\n".join(_strings({k: v for k, v in self.call.input.items() if k not in ("file_path", "notebook_path", "path", "old_string")}))

    def _persistence_hit(self, p: str, via: str) -> bool:
        hit = (paths.matches_any(p, _PERSISTENCE) or paths.matches_any(p + "/", _PERSISTENCE)
               or paths.matches_any(re.sub(r"^[a-z]:", "", p), [x for x in _PERSISTENCE if x.startswith("/")]))
        if hit and p.endswith("/.vscode/settings.json") and via in _EDIT_TOOLS:  # ordinary editor preferences are fine; keys that run programs are not
            return bool(configscan.VSCODE_RISK.search(self._written_text()))
        return bool(hit)

    def _config_contents(self, p: str, via: str, label: str) -> None:
        """Files that hold commands for later (package scripts, dev-container hooks, pre-commit entries, CI, compose): the commands
        inside go through the same analysis a typed command gets."""
        kind = configscan.classify(p)
        if kind is None:
            return
        text = self._written_text()
        if kind == "compose":
            if m := configscan.COMPOSE_RISK.search(text):
                self.once(Finding("container-config-risk", MEDIUM, f"{via} writes a compose file ({label}) that gives a container host-level access ({m.group(0).strip()[:40]})"), p)
            return
        strong = {"remote-code-exec", "secret-exfil-shape", "secret-literal-egress", "persistence-command", "destructive-system", "destructive-delete",
                  "security-setting-change", "container-escape", "secret-harvest", "agent-permission-bypass", "agent-config-change", "outbound-raw-ip", "ssrf-metadata"}
        for cmd, uncapped in configscan.commands(kind, text):
            sub = _Checker(Call("Bash", {"command": cmd}, self.call.cwd, self.call.root, None), self.policy, Tracker(), None, self.now).run()
            for f in sub:
                if f.opaque or f.severity < MEDIUM or f.rule in ("rate-calls", "rate-write-volume", "rate-hosts", "secret-file-access", "credential-store-read", "write-outside-scope"):
                    continue
                sev = f.severity if (uncapped or f.rule in strong) else min(f.severity, MEDIUM)
                self.once(Finding("config-runs-risky-command", sev, f"{via} writes {label}, which contains a command that raises [{f.rule}]: {f.detail[:100]}"), f.rule + cmd[:40])

    def _shell_words(self) -> None:
        """Literal path-like words in a shell command: canary and secret paths. Secret-named variables count as a secret touch too."""
        a = self.a
        if a is None:
            return
        for w in a.words[:150]:
            if not re.search(r"[/\\.~]", w):
                continue
            c = self.classify(w, a.ops[0].cwd if a.ops else self.call.cwd)
            if c.ambiguous:
                continue
            if paths.matches_any(c.path, self.policy.canary_paths):
                self.once(Finding("canary-touched", CRITICAL, f"command mentions a canary file ({w[:60]})"), c.path)
            elif _is_secret(c.path, self.policy):
                self.touch(c.path)
                self.once(Finding("secret-file-access", MEDIUM, f"command touches a likely secret file ({w[:60]})"), c.path)
        for why in a.cred:
            self.touch(why)
            self.once(Finding("credential-store-read", MEDIUM, why), why)
        if a.archives or a.publish:  # copying or publishing a whole secret folder (`cp -r ~/.ssh`, `rclone copy ~/.aws`)
            for w in a.words[:150]:
                if re.search(r"[/\.~]", w):
                    c = self.classify(w, self.call.cwd)
                    if not c.ambiguous and (_is_secret(c.path + "/x", self.policy) or _is_secret(c.path, self.policy)):
                        self.touch(c.path)
        if any(cmd in ("printenv", "env-dump") for cmd in a.commands) or any(m.startswith("secret-var:") for m in a.mentions):
            self.touch("environment")
        if self.call.tool in ("Bash", "PowerShell") and (m := _HISTORY_READ.search(self.blob) or _PROC_ENV.search(self.blob)):
            self.touch(m.group(0).lower())
            self.once(Finding("secret-file-access", MEDIUM, f"command reads shell history or another process's environment ({m.group(0)[:40]})"), "histread")

    def _canary_tokens(self) -> None:
        for tok in self.policy.canary_tokens:
            if tok and tok in self.blob:
                self.once(Finding("canary-token", CRITICAL, "a canary token appears in the call"), tok)
        if DEFAULT_CANARY.search(self.blob):
            self.once(Finding("canary-token", CRITICAL, "a canary token appears in the call"), "default")

    def _monitor_tamper(self) -> None:
        if self.call.tool in ("Bash", "PowerShell") and _TAMPER_CMD.search(str(self.call.input.get("command", "")) + "\n" + "\n".join(self.a.mentions if self.a else [])):
            self.once(Finding("monitor-tamper", CRITICAL, "command talks to, controls or stops the monitor"), "cmd")

    def _net_finding(self, host: str, via: str, upload: bool, supply: bool) -> bool:
        """Adds the finding for one destination; True when it is something that leaves the trusted set."""
        h = host.lower().strip(".")
        if "$" in h or "%" in h:  # `169.254.170.2$VAR`: judge the part before the expansion when it is an address
            base = re.split(r"[$%`]", h)[0].rstrip(".:/")
            if base in _METADATA or ip_kind(base) != "none":
                h = base
        kind, once = ip_kind(h), self.once
        if kind == "none" and (m := _EMBEDDED_IP.search(h)):  # a name that resolves to an address it spells out (nip.io, sslip.io, ...)
            emb = ".".join(m.groups())
            if ip_kind(emb) in ("link-local", "private", "loopback") or emb in _METADATA:
                h, kind = emb, ip_kind(emb)
        if h in _METADATA or kind == "link-local":
            once(Finding("ssrf-metadata", HIGH, f"{via} reaches a cloud metadata / link-local address ({h}), the usual way to steal cloud credentials"), h)
            return True
        if host_allowed(h, self.policy) or kind == "loopback":
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

    def _outbound(self) -> None:
        call, a, once = self.call, self.a, self.once
        if call.tool == "WebFetch":
            url = str(call.input.get("url", ""))
            h = host_of(url if "://" in url else "http://" + url)
            if h:
                self.hosts.append(h)
                if self._net_finding(h, "WebFetch", False, False):
                    self.net_present = True
            else:
                once(Finding("outbound-unlisted-host", MEDIUM, "WebFetch URL could not be parsed"), url)
        if tool_class(call.tool) == "mcp":
            for url in _mcp_urls(call):
                h = host_of(url if "://" in url else "http://" + url)
                if h:
                    self.hosts.append(h)
                    if self._net_finding(h, call.tool.split("__")[-1], False, False):
                        self.net_present = True
        if a is None:
            return
        if a.publish:  # a publishing command is a way out even to a trusted host
            self.net_present = True
            self.published = True
        for o in a.ops:
            if o.kind == "listen":
                once(Finding("opens-listener", HIGH, f"{o.via} opens a listening socket"), o.via)
            elif o.kind == "net":
                self.hosts.append(o.target)
                if self._net_finding(o.target, o.via, o.upload, o.supply):
                    self.net_present = True
        if set(a.commands) & NET_COMMANDS:
            for w in a.words:  # `curl --resolve x.test:80:169.254.169.254 ...`: a metadata address hidden in an option value
                m = _METADATA_WORD.search(w)
                if m:
                    self._net_finding(m.group(0), "a network command", False, False)
                    self.net_present = True
        if self.secret_touch and self.net_present:
            once(Finding("secret-exfil-shape", HIGH, "a secret file, a secret-named variable or the environment is read in the same command as network access"), "exfil")

    def _shell_shapes(self) -> None:
        a, once = self.a, self.once
        if a is None:
            return
        for why in a.pipe_exec:
            once(Finding("remote-code-exec", HIGH, why), why)
        for why in a.persist:
            if why.startswith(("container ", "antivirus", "PowerShell execution", "the Windows firewall", "the firewall", "SELinux", "macOS system", "git TLS", "npm TLS")):
                once(Finding("container-escape" if why.startswith("container ") else "security-setting-change", HIGH, why), why)
            else:
                once(Finding("persistence-command", HIGH, why), why)
        for why in a.system:
            once(Finding("destructive-system", HIGH, why), why)
        if "git-hooks-path" in a.mentions:
            once(Finding("instruction-file-change", HIGH, "git config core.hooksPath redirects git hooks"), "hooks")
        for why in a.bulk:
            once(Finding("bulk-change", LOW, f"{why} can rewrite many files"), why)
        for rule, why in a.high:
            once(Finding(rule, HIGH, why), why)
        for rule, why in a.medium:
            once(Finding(rule, MEDIUM, why), why)
        for m in a.mentions:
            if m.startswith("redirect-var:"):
                key, _, val = m[len("redirect-var:"):].partition("=")
                h = host_of(val if "://" in val else "http://" + val.strip("'\""))
                if h and not host_allowed(h, self.policy) and ip_kind(h) != "loopback":
                    once(Finding("traffic-redirect", MEDIUM, f"{key} sends this client's or the shell's traffic to unlisted host {h}", "Add the host to [network] allow_hosts."), key)
        if any(c in ("sudo", "doas") for c in a.commands):
            once(Finding("privilege-escalation", MEDIUM, "command uses sudo"), "sudo")

    def _content_checks(self) -> None:
        """Text the agent writes or sends: invisible characters, a sub-agent briefed to do something unsafe."""
        call, once = self.call, self.once
        for text in _strings(call.input):
            if len(text) > 4 and (m := catalog.HIDDEN_CHARS.search(text.lstrip("﻿"))):
                once(Finding("hidden-unicode", MEDIUM, f"the call contains invisible or bidirectional control characters (U+{ord(m.group(0)):04X}), used to hide instructions or code"), "hidden")
                break
        if tool_class(call.tool) == "agent":
            text = "\n".join(_strings(call.input))
            m = catalog.SUBAGENT_RISK.search(text)
            if m or catalog.SECRET_LITERAL.search(text):
                once(Finding("subagent-risky-prompt", MEDIUM, f"the brief for a sub-agent asks for something the monitor would hold if the agent did it itself ({(m.group(0) if m else 'a secret')[:50]!r})"), "agent")

    def _combos(self) -> None:
        """Findings that need facts from several sections: secrets leaving through a literal, a harvest, a sweep."""
        a, once = self.a, self.once
        blob = self.blob.replace(chr(92) * 2, chr(92))  # json doubled the backslashes of Windows paths
        if self.net_present and (m := catalog.SECRET_LITERAL.search(blob)):
            once(Finding("secret-literal-egress", HIGH, f"a secret-looking literal ({m.group(0)[:6]}...) appears in a call that reaches an unlisted host or publishes data"), "literal")
        if a is None:
            return
        if not a.pipe_exec and (m := catalog.DROPPER_TEXT.search(blob)):
            targets = [o.target for o in a.ops if o.kind == "write"]
            if targets:
                script = any("." not in os.path.basename(x) or x.lower().endswith(catalog.SCRIPT_EXT) for x in targets)
                once(Finding("remote-code-exec", HIGH if script else MEDIUM, f"a download-and-run line is written into {os.path.basename(targets[0])[:40]}, to be run later"), "dropper")
        secret_text = bool(catalog.SECRET_TEXT.search(blob)) or self.secret_touch
        if a.archives and secret_text:
            stage = catalog.STAGE_TEXT.search(blob) or any(o.kind == "write" and not self._in_scope(o.target, o.cwd) for o in a.ops)
            if stage:
                once(Finding("secret-harvest", HIGH, "secret files or folders are copied or archived to a temp, download or outside location"), "harvest")
        if a.sweeps and any(w in ("/", "~") or re.fullmatch(r"[A-Za-z]:[\/]?|/home|/Users|\$HOME", w) for w in a.words) and catalog.SECRET_PATTERN.search(blob):
            heavy = a.archives or any(c in ("xargs", "nested") for c in a.commands) or any(o.kind == "write" for o in a.ops)
            once(Finding("secret-sweep", HIGH if heavy else MEDIUM, "a search over the whole disk or home folder for key, token or credential files" + (", with the hits copied or saved" if heavy else "")), "sweep")

    def _egress(self) -> str:
        """The command that sends data out, even to a trusted host: a publishing command or an upload. Plain git and loopback do not count."""
        a = self.a
        if a is None:
            return ""
        if a.publish:
            return a.publish[0]
        for o in a.ops:
            if o.kind == "net" and o.upload and not o.via.startswith("git ") and ip_kind(o.target) != "loopback" and o.target not in ("localhost", ""):
                return o.via
        return ""

    def _taint(self) -> None:
        """Cross-call memory: reading a secret file marks the session (hash of the path, in RAM, bounded); a later upload or publish,
        even to a trusted host, is a warning. A call that reads and sends in one go is already `secret-exfil-shape`."""
        now = self.now if self.now is not None else time.time()
        sess = self.call.session
        via = self._egress()
        if self.secret_touch and not self.net_present:
            for key in self._secret_keys:
                self.tracker.taint_add(sess, key, now)
            if via:  # read and sent in one command, to a host that is trusted: not the exfil shape, but not nothing
                self.once(Finding("taint-egress", MEDIUM, f"{via} sends data out in the same command that reads a secret"), "taint-same")
            return
        if via:
            live = self.tracker.taint_live(sess, now, self.policy.taint_window_s)
            if live:
                age = max(0, int((now - max(live)) / 60))
                self.once(Finding("taint-egress", MEDIUM, f"{via} sends data out, and {len(live)} secret file(s) were read earlier in this session (last {age} min ago)"), "taint")

    def _in_scope(self, target: str, cwd: str) -> bool:
        c = self.classify(target, cwd)
        return c.ambiguous or paths.under(c.path, self.root) or any(paths.under(c.path, t) for t in self.extras)


def _split_checks_placeholder() -> None:  # pragma: no cover - keeps the diff readable
    pass


def check(call: Call, policy: Policy, tracker: Tracker, analysis: Analysis | None = None, now: float | None = None) -> list[Finding]:
    """All deterministic findings for one call, most important first (see the module docstring)."""
    return _Checker(call, policy, tracker, analysis, now).run()


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
            base = base.removesuffix("/")
            if base and not any(ch in base for ch in "*?["):
                candidates.append((pat, base))
        else:
            candidates.append((pat, pat))
    for pat, rel in candidates:
        for anchor in (root, home):
            cp = paths.canon(rel if rel.startswith("~") else anchor + "/" + rel, anchor, resolve=False).path
            if paths.under(cp, p):
                return pat
    if p in (root, home):
        return "the project/home folder"
    return None
