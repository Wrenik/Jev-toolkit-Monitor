"""A small static analyser for shell command lines (bash-ish and PowerShell-ish).

It answers four questions about a command string WITHOUT running it:
  * which files would it write or delete (redirects, tee, cp, mv, sed -i, dd, git checkout --,
    Set-Content, Out-File, inline `python -c "open(...)"`, ...)?
  * which hosts would it talk to, and would it upload something?
  * does it pipe downloaded or decoded text into an interpreter?
  * is it OPAQUE: does a target depend on something only the running shell knows (an unset
    variable, `$(...)`, a script it generates, `eval` of a computed string)?

It is a tokenizer plus a table of commands, not a shell. Whatever it cannot resolve it reports
as `opaque` instead of guessing; the policy then asks (sensitive classes) rather than allows.
Things it cannot catch at all are listed in docs/AGENT_MONITOR.md (a script file that writes
the file later, a binary that does it, `source`d files, aliases and functions defined earlier in
the session).
"""

from __future__ import annotations

import glob as globlib
import os
import posixpath
import re
from dataclasses import dataclass, field

MAX_DEPTH = 3
MAX_WORDS = 400


@dataclass
class Tok:
    text: str
    dyn: bool = False  # contains an expansion the shell would evaluate ($x, $(..), `..`)
    glob: bool = False  # unquoted * ? [
    quoted: bool = False


@dataclass
class ShellOp:
    kind: str  # write | delete | read | net | listen
    target: str  # path or host
    cwd: str
    via: str  # command that does it
    upload: bool = False  # net: sends local data out
    recursive: bool = False  # delete/write of a whole tree
    supply: bool = False  # net: a package/index/registry source (supply-chain step)


@dataclass
class Analysis:
    ops: list[ShellOp] = field(default_factory=list)
    opaque: list[str] = field(default_factory=list)
    pipe_exec: list[str] = field(default_factory=list)  # "curl | sh" style findings
    persist: list[str] = field(default_factory=list)  # cron, schtasks, Run keys, services, launch agents
    words: list[str] = field(default_factory=list)  # literal path-ish arguments, for secret/canary scans
    bulk: list[str] = field(default_factory=list)  # git reset --hard, checkout . ...
    commands: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)  # raw text pieces worth a substring scan

    def merge(self, other: "Analysis") -> None:
        self.ops += other.ops
        self.opaque += other.opaque
        self.pipe_exec += other.pipe_exec
        self.persist += other.persist
        self.words += other.words
        self.bulk += other.bulk
        self.commands += other.commands
        self.mentions += other.mentions


@dataclass
class Segment:
    words: list[Tok] = field(default_factory=list)
    redirects: list[tuple[str, Tok]] = field(default_factory=list)
    piped_from_prev: bool = False
    piped_to_next: bool = False
    heredoc: str | None = None
    substs: list[str] = field(default_factory=list)  # text inside $( ) / backticks / <( )


# ------------------------------------------------------------------ tokenizer
def _match_paren(text: str, i: int) -> int:
    """Index of the ')' closing the '(' at text[i]; len(text) if unbalanced."""
    depth, q = 0, ""
    j = i
    while j < len(text):
        c = text[j]
        if q:
            if c == q:
                q = ""
            elif c == "\\" and q == '"':
                j += 1
        elif c in "'\"":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return len(text)


def tokenize(text: str, ps: bool = False) -> list[Segment]:
    segs: list[Segment] = [Segment()]
    word: list[str] = []
    state = {"dyn": False, "glob": False, "quoted": False, "has": False}
    pending_heredocs: list[tuple[str, bool]] = []  # (delimiter, strip tabs)
    redirect_op: str | None = None
    i, n = 0, len(text)
    esc = "`" if ps else "\\"

    def flush() -> None:
        nonlocal redirect_op
        if not state["has"]:
            return
        tok = Tok("".join(word), state["dyn"], state["glob"], state["quoted"])
        word.clear()
        state.update(dyn=False, glob=False, quoted=False, has=False)
        if redirect_op is not None:
            segs[-1].redirects.append((redirect_op, tok))
            redirect_op = None
        else:
            segs[-1].words.append(tok)

    def new_segment(pipe: bool = False) -> None:
        flush()
        if pipe:
            segs[-1].piped_to_next = True
        seg = Segment(piped_from_prev=pipe)
        segs.append(seg)

    while i < n:
        c = text[i]
        if c in " \t\r":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            if pending_heredocs:
                i += 1
                for delim, strip in pending_heredocs:
                    body: list[str] = []
                    while i < n:
                        j = text.find("\n", i)
                        line = text[i:] if j == -1 else text[i:j]
                        i = n if j == -1 else j + 1
                        if (line.strip("\t") if strip else line).rstrip("\r") == delim:
                            break
                        body.append(line)
                    segs[-1].heredoc = ("\n".join(body))
                pending_heredocs.clear()
                new_segment()
                continue
            new_segment()
            i += 1
            continue
        if c == "#" and not state["has"] and (i == 0 or text[i - 1] in " \t\n;&|("):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "'" and not ps or (c == "'" and ps):
            j = text.find("'", i + 1)
            j = n if j == -1 else j
            chunk = text[i + 1 : j]
            if ps:
                chunk = chunk.replace("''", "'")
            word.append(chunk)
            state["has"] = state["quoted"] = True
            i = j + 1
            continue
        if c == '"':
            state["has"] = state["quoted"] = True
            i += 1
            while i < n and text[i] != '"':
                d = text[i]
                if d == esc and i + 1 < n and (ps or text[i + 1] in '"\\$`\n'):
                    word.append(text[i + 1])
                    i += 2
                    continue
                if d == "$" and text.startswith("$(", i):
                    end = _match_paren(text, i + 1)
                    segs[-1].substs.append(text[i + 2 : end])
                    word.append(text[i : end + 1])
                    state["dyn"] = True
                    i = end + 1
                    continue
                if d == "$" or d == "`":
                    state["dyn"] = True
                    if d == "`":
                        j = text.find("`", i + 1)
                        j = n if j == -1 else j
                        segs[-1].substs.append(text[i + 1 : j])
                        word.append(text[i : j + 1])
                        i = j + 1
                        continue
                word.append(d)
                i += 1
            i += 1
            continue
        if c == esc and i + 1 < n:
            word.append(text[i + 1])
            state["has"] = True
            i += 2
            continue
        if c == "$" and text.startswith("$(", i):
            end = _match_paren(text, i + 1)
            segs[-1].substs.append(text[i + 2 : end])
            word.append(text[i : end + 1])
            state.update(dyn=True, has=True)
            i = end + 1
            continue
        if c == "`" and not ps:
            j = text.find("`", i + 1)
            j = n if j == -1 else j
            segs[-1].substs.append(text[i + 1 : j])
            word.append(text[i : j + 1])
            state.update(dyn=True, has=True)
            i = j + 1
            continue
        if c in "<>" and text.startswith(("<(", ">("), i):
            end = _match_paren(text, i + 1)
            segs[-1].substs.append(text[i + 2 : end])
            word.append(text[i : end + 1])
            state.update(dyn=True, has=True)
            i = end + 1
            continue
        if c in "<>" or (c == "&" and text.startswith("&>", i)):
            # a bare digit word right before is an fd number: 2> file
            if state["has"] and "".join(word).isdigit() and not state["quoted"]:
                word.clear()
                state.update(dyn=False, glob=False, quoted=False, has=False)
            else:
                flush()
            op = ""
            for cand in ("<<<", "<<-", "<<", ">>", ">|", "&>>", "&>", ">&", "<&", ">", "<"):
                if text.startswith(cand, i):
                    op = cand
                    break
            i += len(op)
            if op in ("<<", "<<-"):
                j = i
                while j < n and text[j] in " \t":
                    j += 1
                k = j
                dq = ""
                if k < n and text[k] in "'\"":
                    dq = text[k]
                    k = text.find(dq, k + 1)
                    delim = text[j + 1 : k if k != -1 else n]
                    i = (k + 1) if k != -1 else n
                else:
                    while k < n and text[k] not in " \t\n;&|<>()":
                        k += 1
                    delim = text[j:k]
                    i = k
                pending_heredocs.append((delim, op == "<<-"))
                continue
            redirect_op = op
            continue
        if ps and c == "(" and (segs[-1].words or state["has"] or redirect_op is not None):
            end = _match_paren(text, i)
            segs[-1].substs.append(text[i + 1 : end])
            word.append(text[i : end + 1])
            state.update(dyn=True, has=True)
            i = end + 1
            continue
        if c in ";|&()" or (c in "{}" and ps):
            if c == "|" and text.startswith("||", i):
                new_segment()
                i += 2
            elif c == "&" and text.startswith("&&", i):
                new_segment()
                i += 2
            elif c == "|":
                flush()
                i += 2 if text.startswith("|&", i) else 1
                new_segment(pipe=True)
            else:
                flush()
                i += 1
                new_segment()
            continue
        if c in "{}" and not ps and not state["has"] and (i + 1 >= n or text[i + 1].isspace() or text[i + 1] == ";"):
            i += 1  # a lone { or } is shell grouping, not an argument
            continue
        if c == "$" or (ps and c == "@"):
            state.update(dyn=True, has=True)
            if text.startswith("${", i):
                j = text.find("}", i)
                j = n if j == -1 else j
                word.append(text[i : j + 1])
                i = j + 1
                continue
        if c in "*?[" and not ps or (ps and c in "*?[" ):
            state["glob"] = True
        word.append(c)
        state["has"] = True
        i += 1
    flush()
    return [s for s in segs if s.words or s.redirects or s.heredoc]


# ------------------------------------------------------------------ command tables
_WRAPPERS = {"sudo", "doas", "nohup", "time", "command", "builtin", "exec", "nice", "setsid", "stdbuf", "ionice", "chronic", "unbuffer"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"}
_PS_SHELLS = {"powershell", "pwsh"}
_INTERPRETERS = _SHELLS | _PS_SHELLS | {"python", "python2", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "iex", "invoke-expression", "source", ".", "eval", "cmd"}
_DECODERS = {"base64", "xxd", "openssl", "gunzip", "zcat", "gzip", "unzip", "uudecode", "certutil"}
_NET_FETCH = {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "fetch", "aria2c", "http", "https", "xh", "start-bitstransfer"}
_NET_RAW = {"nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "ftp", "tftp", "rsync", "mosh", "test-netconnection", "tnc"}
_NET_DNS = {"nslookup", "dig", "host", "ping", "resolve-dnsname", "tracert", "traceroute"}
_RM = {"rm", "rmdir", "unlink", "shred", "del", "erase", "rd", "remove-item", "ri", "trash", "srm"}
_PS_WRITE_FIRST = {"set-content", "sc", "add-content", "ac", "out-file", "clear-content", "clc", "new-item", "ni", "tee-object", "export-csv", "export-clixml", "set-itemproperty", "write-output"}
_PS_COPYMOVE = {"copy-item", "cpi", "move-item", "mi", "rename-item", "rni", "copy", "move", "cp", "mv", "ren"}
_PS_PATH_PARAMS = {"-path", "-filepath", "-literalpath", "-destination", "-outfile", "-target", "-value"}
_PKG = {"pip", "pip3", "npm", "npx", "yarn", "pnpm", "cargo", "go", "gem", "bundle", "uv", "poetry", "conda", "brew", "apt", "apt-get", "choco", "winget", "scoop"}
_CODE_WRITE = [
    re.compile(r"""open\(\s*(?P<q>['"])(?P<p>[^'"]+)(?P=q)\s*,\s*['"][^'"]*[wax+][^'"]*['"]"""),
    re.compile(r"""(?:Path|pathlib\.Path)\(\s*(?P<q>['"])(?P<p>[^'"]+)(?P=q)\s*\)\s*\.\s*(?:write_text|write_bytes|unlink|rename|replace|touch)"""),
    re.compile(r"""(?:os\.(?:remove|unlink|rename|replace|truncate)|shutil\.(?:copy|copyfile|copy2|move|rmtree))\(\s*(?:[^,'")]+,\s*)?(?P<q>['"])(?P<p>[^'"]+)(?P=q)"""),
    re.compile(r"""(?:fs\.)?(?:writeFileSync|writeFile|appendFileSync|appendFile|rmSync|unlinkSync|unlink|renameSync|copyFileSync|createWriteStream)\(\s*(?P<q>['"`])(?P<p>[^'"`]+)(?P=q)"""),
    re.compile(r"""\[(?:System\.)?IO\.File\]::(?:Write\w*|Append\w*|Delete|Copy|Move|Create\w*|Replace)\(\s*(?P<q>['"])(?P<p>[^'"]+)(?P=q)"""),
    re.compile(r"""File\.(?:write|open|delete|rename|binwrite)\(\s*(?P<q>['"])(?P<p>[^'"]+)(?P=q)"""),
    re.compile(r"""file_put_contents\(\s*(?P<q>['"])(?P<p>[^'"]+)(?P=q)"""),
]
_CODE_WRITE_VERBS = re.compile(
    r"open\([^)]*['\"][wax+]|\.write_text|\.write_bytes|os\.(remove|unlink|rename|replace|truncate)|shutil\.(copy|move|rmtree)|"
    r"writeFile|appendFile|rmSync|unlinkSync|renameSync|createWriteStream|IO\.File\]::(Write|Append|Delete|Copy|Move)|file_put_contents|File\.(write|delete)"
)
_URL = re.compile(r"""(?i)\b(?:[a-z][a-z0-9+.-]*)://(?:[^/\s'"@]*@)?(?P<host>\[[0-9a-f:]+\]|[^/\s:'"?#]+)""")
_HOSTLIKE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$|^\d{1,3}(?:\.\d{1,3}){3}$|^localhost$")
_ENCODED_PS = re.compile(r"(?i)(^|\s)-e(nc|ncodedcommand)?\b")


_SAFE_VARS = {"home", "userprofile", "temp", "tmp", "tmpdir", "appdata", "localappdata"}


def _unresolvable(text: str) -> bool:
    """Does `text` hold an expansion the monitor cannot resolve itself? HOME-like variables it can."""
    if "`" in text or "$(" in text or "<(" in text:
        return True
    names = [next(g for g in m.groups() if g) for m in re.finditer(r"\$env:(\w+)|\$\{(\w+)\}|\$(\w+)|%(\w+)%", text, flags=re.I)]
    if re.search(r"\$[^\w{(e]", text):
        return True
    return any(n.lower() not in _SAFE_VARS for n in names)


def _name(tok: Tok) -> str:
    base = tok.text.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def host_of(url_or_host: str) -> str | None:
    m = _URL.search(url_or_host)
    if m:
        return m.group("host").strip("[]").lower()
    t = url_or_host.strip()
    if "@" in t and ":" in t and "/" not in t.split(":", 1)[0]:  # user@host:path (scp)
        t = t.split("@", 1)[1].split(":", 1)[0]
    elif t.count(":") == 1 and "/" not in t.split(":", 1)[0] and not t.startswith(("-", ".", "/")):
        t = t.split(":", 1)[0]
    return t.lower() if _HOSTLIKE.match(t) else None


class _Walker:
    def __init__(self, cwd: str, depth: int, ps: bool, env: dict[str, str]):
        self.a = Analysis()
        self.cwd = cwd
        self.depth = depth
        self.ps = ps
        self.env = env
        self.last_args: list[Tok] = []

    # -- helpers -----------------------------------------------------------
    def sub(self, tok: Tok) -> Tok:
        """Substitute variables assigned earlier in the same command line."""
        text = tok.text
        if "$" not in text and "%" not in text:
            return tok
        dyn = tok.dyn

        def rep(m: re.Match) -> str:
            nonlocal dyn
            name = next(g for g in m.groups() if g)
            for k, v in self.env.items():
                if k.lower() == name.lower():
                    return v
            return m.group(0)

        new = re.sub(r"\$env:(\w+)|\$\{(\w+)\}|\$(\w+)|%(\w+)%", rep, text, flags=re.I)
        if new != text and not re.search(r"\$[A-Za-z_{(]|%\w+%", new):
            dyn = False if "$(" not in new and "`" not in new else dyn
        return Tok(new, dyn, tok.glob, tok.quoted)

    def target(self, tok: Tok, kind: str, via: str, recursive: bool = False, upload: bool = False) -> None:
        tok = self.sub(tok)
        text = tok.text
        if not text or text in ("-", "/dev/null", "nul", "NUL", "$null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty"):
            return
        if text.startswith("&") and text[1:].isdigit():
            return
        if tok.dyn and _unresolvable(text):
            self.a.opaque.append(f"{via}: {kind} target depends on an expansion ({text[:40]})")
            return
        if not self.cwd and not re.match(r"^([A-Za-z]:)?[/\\~]", text) and kind in ("write", "delete"):
            self.a.opaque.append(f"{via}: relative {kind} target after cd into a computed folder ({text[:40]})")
            return
        if tok.glob and not tok.quoted and re.fullmatch(r"(/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|[A-Za-z]:)[\/]?\*", text):
            self.a.ops.append(ShellOp(kind, text, self.cwd, via, upload, True))  # `rm -rf /*`: keep it as one catastrophic target
            return
        if tok.glob and not tok.quoted:
            hits = globlib.glob(text if os.path.isabs(text) else os.path.join(self.cwd, text))
            if not hits:
                self.a.words.append(text)
                return
            for h in hits[:50]:
                self.a.ops.append(ShellOp(kind, h, self.cwd, via, upload, recursive))
            return
        self.a.ops.append(ShellOp(kind, text, self.cwd, via, upload, recursive))

    def note_words(self, args: list[Tok]) -> None:
        for t in args:
            t = self.sub(t)
            text = t.text
            if text.startswith("-") and "=" in text:
                text = text.split("=", 1)[1]
            elif "=@" in text:
                text = text.split("=@", 1)[1]
            text = text.lstrip("@")
            if len(self.a.words) < MAX_WORDS and text and not t.dyn:
                self.a.words.append(text)

    # -- main loop -----------------------------------------------------------
    def walk(self, text: str) -> None:
        segs = tokenize(text, self.ps)
        prev: Segment | None = None
        chain: list[tuple[Segment, str]] = []
        for seg in segs:
            if not seg.piped_from_prev:
                chain = []
            cmd = self.segment(seg)
            chain.append((seg, cmd))
            if seg.piped_from_prev and cmd in _INTERPRETERS | {"iex", "invoke-expression"} and not self._has_script(self.last_args, cmd):
                up = [c for _, c in chain[:-1]]
                if any(c in _NET_FETCH for c in up):
                    self.a.pipe_exec.append(f"downloaded text is piped into {cmd}")
                elif any(c in _DECODERS for c in up) or any(c == "echo" or c == "printf" for c in up) and any(c in _DECODERS for c in up):
                    self.a.pipe_exec.append(f"decoded text is piped into {cmd}")
            prev = seg
        _ = prev

    def _has_script(self, args: list[Tok], cmd: str) -> bool:
        """A shell reading stdin has no file argument; `bash script.sh` is not a pipe-exec."""
        args = [w for w in args if not w.text.startswith("-")]
        return bool(args) and cmd not in ("iex", "invoke-expression")

    def segment(self, seg: Segment) -> str:
        words = list(seg.words)
        # NAME=value prefix and PowerShell $name = value
        while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0].text) and not words[0].quoted:
            k, _, v = words[0].text.partition("=")
            self._assign(k, Tok(v, words[0].dyn, words[0].glob, words[0].quoted))
            words.pop(0)
        if self.ps and words and re.match(r"^\$(env:)?\w+$", words[0].text) and len(words) >= 3 and words[1].text == "=":
            self._assign(words[0].text.lstrip("$").removeprefix("env:"), Tok(" ".join(w.text for w in words[2:]), any(w.dyn for w in words[2:])))
            words = []  # the whole segment was an assignment
        for op, tok in seg.redirects:
            if op in (">", ">>", ">|", "&>", "&>>"):
                self.target(tok, "write", f"redirect {op}")
            elif op == "<":
                self.target(tok, "read", "redirect <")
        for inner in seg.substs:
            self.sub_analyze(inner, seg)
        if seg.heredoc is not None:
            self.a.mentions.append(seg.heredoc)
        if not words:
            return ""
        # unwrap
        while words:
            n = _name(words[0])
            if n in _WRAPPERS:
                if n in ("sudo", "doas"):
                    self.a.commands.append(n)
                words.pop(0)
                if n == "nice":
                    while words and words[0].text.startswith("-"):
                        words.pop(0)
                continue
            if n == "env":
                words.pop(0)
                while words and (words[0].text.startswith("-") or "=" in words[0].text):
                    t = words.pop(0)
                    if "=" in t.text and not t.text.startswith("-"):
                        k, _, v = t.text.partition("=")
                        self._assign(k, Tok(v))
                if not words:
                    self.a.commands.append("env-dump")
                continue
            if n == "timeout" and len(words) > 1:
                words.pop(0)
                while words and (words[0].text.startswith("-") or re.match(r"^\d", words[0].text)):
                    words.pop(0)
                continue
            break
        if not words:
            return ""
        head = words[0]
        if head.dyn:
            self.a.opaque.append(f"command name comes from an expansion ({head.text[:40]})")
            return "?"
        cmd = _name(self.sub(head))
        args = words[1:]
        self.last_args = args
        self.a.commands.append(cmd)
        self.note_words(args)
        self.dispatch(cmd, args, seg)
        return cmd

    def _assign(self, key: str, tok: Tok) -> None:
        tok = self.sub(tok)
        if tok.dyn:  # still holds an expansion after substitution: the value is only known to the running shell
            self.env.pop(key, None)
        else:
            self.env[key] = tok.text

    def sub_analyze(self, inner: str, seg: Segment) -> None:
        if self.depth >= MAX_DEPTH:
            self.a.opaque.append("substitution nested too deep to analyse")
            return
        w = _Walker(self.cwd, self.depth + 1, self.ps, dict(self.env))
        w.walk(inner)
        # An executed substitution that downloads is itself the finding when its result is executed.
        self.a.merge(w.a)
        if any(c in _NET_FETCH for c in w.a.commands):
            for tok in seg.words[:1]:
                if _name(tok) in _INTERPRETERS | {"eval", "source", "."}:
                    self.a.pipe_exec.append(f"output of a download is executed by {_name(tok)}")

    def recurse(self, code: str, ps: bool) -> None:
        if self.depth >= MAX_DEPTH:
            self.a.opaque.append("nested shell too deep to analyse")
            return
        w = _Walker(self.cwd, self.depth + 1, ps, dict(self.env))
        w.walk(code)
        self.a.merge(w.a)

    # -- the command table -----------------------------------------------------
    def dispatch(self, cmd: str, args: list[Tok], seg: Segment) -> None:  # noqa: C901 - a table, readable as one
        pos = [a for a in args if not a.text.startswith("-") or a.text == "-"]
        flags = [a.text for a in args if a.text.startswith("-")]

        if cmd in ("cd", "pushd", "set-location", "sl", "chdir"):
            t = pos[0] if pos else None
            if t is None or t.dyn or t.text in ("-",):
                self.cwd = ""  # unknown from here on
                self.a.mentions.append("cwd-unknown")
            else:
                t = self.sub(t)
                self.cwd = _join(self.cwd, t.text) if self.cwd else ""
            return
        if cmd in ("export", "declare", "local", "set", "typeset", "readonly"):
            for a in args:
                if "=" in a.text and not a.text.startswith("-"):
                    k, _, v = a.text.partition("=")
                    self._assign(k, Tok(v, a.dyn))
            return
        if cmd in _SHELLS or cmd in _PS_SHELLS or cmd == "cmd":
            self._shell_c(cmd, args)
            return
        if cmd in ("eval", "iex", "invoke-expression"):
            lit = [a for a in args if not a.dyn]
            if args and len(lit) == len(args):
                self.recurse(" ".join(self.sub(a).text for a in args), self.ps or cmd != "eval")
            elif args or cmd == "eval":
                self.a.opaque.append(f"{cmd} of a computed string")
            return
        if cmd in ("source", ".") and pos:
            self.target(pos[0], "read", cmd)
            self.a.opaque.append("sourced file is not analysed")
            return
        if cmd in ("tee", "tee-object"):
            for t in pos:
                self.target(t, "write", cmd)
            return
        if cmd in ("cp", "mv", "install", "ln", "rsync", "scp", "copy-item", "move-item", "rename-item", "copy", "move", "cpi", "mi", "rni", "ren", "mcopy", "ditto", "robocopy", "xcopy"):
            self._copy_like(cmd, args, pos)
            return
        if cmd in _RM:
            for t in pos:
                self.target(t, "delete", cmd, recursive=any(f in ("-r", "-R", "-rf", "-fr", "-recurse", "--recursive", "/s", "-Recurse") for f in flags) or cmd in ("rmdir", "rd"))
            if self.ps:
                self._ps_named(args, "delete", cmd)
            return
        if cmd == "find":
            self._find(args)
            return
        if cmd == "xargs":
            self._xargs(args)
            return
        if cmd in ("sed", "gsed"):
            if any(re.match(r"^-[a-zA-Z]*i", f) or f.startswith("--in-place") for f in flags):
                files = pos[1:] if not any(f in ("-e", "-f") for f in flags) else pos
                for t in files:
                    self.target(t, "write", "sed -i")
            return
        if cmd == "perl" or cmd == "ruby":
            if any(re.match(r"^-[a-zA-Z]*i", f) for f in flags):
                for t in pos[1:] if flags and "-e" in flags else pos:
                    self.target(t, "write", f"{cmd} -i")
            self._inline(cmd, args)
            return
        if cmd in ("truncate", "touch", "chmod", "chown", "chgrp", "chattr", "setfacl", "icacls", "attrib", "set-acl", "mkdir", "shred", "fallocate"):
            skip = 1 if cmd in ("chmod", "chown", "chgrp", "chattr") and pos else 0
            rec = any(f in ("-R", "-r", "--recursive", "/s", "/t", "-Recurse") or (f.startswith("-") and not f.startswith("--") and "R" in f[1:]) for f in flags)
            for t in pos[skip:]:
                self.target(t, "write", cmd, recursive=rec)
            return
        if cmd == "dd":
            for a in args:
                if a.text.startswith("of="):
                    self.target(Tok(a.text[3:], a.dyn, a.glob, a.quoted), "write", "dd")
            return
        if cmd == "git":
            self._git(args, pos)
            return
        if cmd in ("python", "python2", "python3", "py", "node", "nodejs", "deno", "bun", "php", "lua"):
            self._inline(cmd, args, seg)
            return
        if cmd in _NET_FETCH:
            self._fetch(cmd, args)
            return
        if cmd in _NET_RAW:
            self._raw_net(cmd, args, pos)
            return
        if cmd in _NET_DNS:
            for t in pos:
                h = host_of(self.sub(t).text)
                if h:
                    self.a.ops.append(ShellOp("net", h, self.cwd, cmd))
            return
        if self._persistence(cmd, args, flags):
            return
        if self._weakening(cmd, args):
            return
        if cmd in ("docker", "podman", "nerdctl") and args and args[0].text in ("run", "create", "exec"):
            self._container(args)
            return
        if cmd in _PKG:
            for t in args:
                text = self.sub(t).text
                if "://" in text:
                    h = host_of(text.split("=", 1)[1] if text.startswith("-") and "=" in text else text.removeprefix("git+"))
                    if h:
                        self.a.ops.append(ShellOp("net", h, self.cwd, cmd, supply=True))
            return
        if cmd in _PS_WRITE_FIRST:
            self._ps_write(cmd, args)
            return
        if cmd in ("out-file", "set-content", "add-content"):
            self._ps_write(cmd, args)
            return
        if cmd in ("python-m",):
            return
        if cmd in ("base64", "xxd", "openssl", "certutil") and ("-d" in flags or "--decode" in flags or "-r" in flags or "-decode" in flags):
            self.a.mentions.append("decoder")
        if cmd in ("tar", "zip", "7z", "unzip", "gzip", "gunzip", "compress-archive", "expand-archive"):
            extracting = cmd in ("unzip", "expand-archive", "7z", "gunzip") or any(f.startswith("-x") for f in flags)
            if not extracting and pos:
                self.target(pos[0], "write", cmd)  # the archive being created
            return
        if cmd == "gh" or cmd == "git-lfs":
            return

    # -- command families -----------------------------------------------------
    def _persistence(self, cmd: str, args: list[Tok], flags: list[str]) -> bool:
        """Commands that make something run later or at login. Listing/querying is fine; creating is not."""
        words = " ".join(self.sub(a).text.lower() for a in args)
        low = [f.lower() for f in flags]
        if cmd == "crontab" and not any(f in ("-l", "-v") for f in low):
            self.a.persist.append("crontab installs or edits a scheduled job")
        elif cmd == "schtasks" and any(a.text.lower().startswith(("/create", "/change", "/run")) for a in args):
            self.a.persist.append("schtasks creates or changes a scheduled task")
        elif cmd in ("reg", "reg.exe") and args and args[0].text.lower() in ("add", "import", "copy"):
            if re.search(r"\\(run|runonce|runservices|winlogon|services|image file execution options|environment)\b|\\policies\\", words):
                self.a.persist.append("reg adds a startup/service registry value")
        elif cmd == "sc" and args and args[0].text.lower() in ("create", "config"):
            self.a.persist.append("sc creates or reconfigures a Windows service")
        elif cmd in ("register-scheduledtask", "new-scheduledtask", "new-service", "set-service", "register-wmievent", "register-objectevent"):
            self.a.persist.append(f"{cmd} creates something that runs later")
        elif cmd in ("set-itemproperty", "new-itemproperty", "set-itemproperty") and re.search(r"\\(run|runonce|winlogon|services)\b", words):
            self.a.persist.append(f"{cmd} writes a startup registry value")
        elif cmd == "systemctl" and any(a.text.lower() in ("enable", "link", "mask", "edit", "daemon-reload") for a in args):
            self.a.persist.append("systemctl enables or changes a unit")
        elif cmd == "launchctl" and any(a.text.lower() in ("load", "bootstrap", "submit", "enable") for a in args):
            self.a.persist.append("launchctl loads a launch agent/daemon")
        elif cmd in ("at", "batch") and args:
            self.a.persist.append("at schedules a job")
        elif cmd == "wmic" and re.search(r"\b(process call create|startup)\b", words):
            self.a.persist.append("wmic starts a process or edits startup entries")
        else:
            return False
        return True

    def _weakening(self, cmd: str, args: list[Tok]) -> bool:
        """Switching off protections: antivirus exclusions, execution policy, firewall, SELinux, TLS verification."""
        words = " ".join(self.sub(a).text.lower() for a in args)
        why = ""
        if cmd in ("add-mppreference", "set-mppreference") and re.search(r"exclusion|disable", words):
            why = "antivirus exclusions or real-time protection are changed"
        elif cmd == "set-executionpolicy" and re.search(r"bypass|unrestricted", words):
            why = "PowerShell execution policy is weakened"
        elif cmd == "netsh" and re.search(r"advfirewall.*(off|disable)|firewall.*disable", words):
            why = "the Windows firewall is switched off"
        elif cmd == "ufw" and "disable" in words:
            why = "the firewall is switched off"
        elif cmd in ("setenforce",) and re.search(r"\b0\b|permissive", words):
            why = "SELinux is set to permissive"
        elif cmd in ("csrutil", "spctl") and re.search(r"disable", words):
            why = "macOS system protection is disabled"
        elif cmd == "git" and re.search(r"http\.sslverify\s+false|http\.sslverify=false", words):
            why = "git TLS verification is switched off"
        elif cmd in ("npm", "yarn", "pnpm") and re.search(r"strict-ssl\s+false", words):
            why = "npm TLS verification is switched off"
        else:
            return False
        self.a.persist.append(why)
        return True

    def _container(self, args: list[Tok]) -> None:
        """docker run with the host's root, home, secrets or the docker socket mounted, or --privileged: a container escape shape."""
        texts = [self.sub(a).text for a in args]
        for i, t in enumerate(texts):
            low = t.lower()
            if low in ("--privileged", "--pid=host", "--userns=host", "--ipc=host") or low.startswith("--cap-add=sys_admin") or (low == "--cap-add" and i + 1 < len(texts) and texts[i + 1].lower() in ("sys_admin", "all")):
                self.a.persist.append(f"container started with {t} (host-level access)")
            vol = None
            if t in ("-v", "--volume", "--mount") and i + 1 < len(texts):
                vol = texts[i + 1]
            elif t.startswith(("-v=", "--volume=", "--mount=")):
                vol = t.split("=", 1)[1]
            elif t.startswith("-v") and len(t) > 2 and t[2] in "/~":
                vol = t[2:]
            if vol:
                src = vol.split(",")[0].removeprefix("type=bind").split(":")[0] if "source=" not in vol else re.search(r"source=([^,]+)", vol).group(1)  # type: ignore[union-attr]
                src = src.removeprefix("src=")
                if re.fullmatch(r"/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|[A-Za-z]:[\\/]?", src) or re.match(r"^(/etc|/root|/var/run|/run/|/proc|/sys|/usr|~/\.ssh|~/\.aws|\$HOME/\.ssh|\$HOME/\.aws)", src) or "docker.sock" in src:
                    self.a.persist.append(f"container mounts {src} from the host")

    def _shell_c(self, cmd: str, args: list[Tok]) -> None:
        texts = [a for a in args]
        for idx, a in enumerate(texts):
            low = a.text.lower()
            if low in ("-c", "-command", "/c", "/k", "-lc", "-ic", "-ec", "-cl") or (low.startswith("-") and low.endswith("c") and len(low) <= 4 and cmd in _SHELLS):
                if idx + 1 < len(texts):
                    code = texts[idx + 1:]
                    if "{}" in code[0].text or "<xargs>" in code[0].text:
                        self.a.opaque.append(f"{cmd} -c script receives arguments from find/xargs")
                    elif any(t.dyn for t in code[:1]) and re.search(r"\$\(|`|<\(", code[0].text):
                        # `bash -c "$(curl ...)"`: the substitution was already analysed; flag executing it
                        self.a.opaque.append(f"{cmd} runs a computed script")
                    else:
                        joined = " ".join(t.text for t in code) if cmd == "cmd" or cmd in _PS_SHELLS else code[0].text
                        self.recurse(joined, cmd in _PS_SHELLS)
                return
            if cmd in _PS_SHELLS and _ENCODED_PS.search(" " + a.text):
                self.a.pipe_exec.append("PowerShell -EncodedCommand hides the script")
                self.a.opaque.append("encoded PowerShell command")
                return
        for a in texts:
            if not a.text.startswith("-"):
                self.target(a, "read", cmd)
                break

    def _copy_like(self, cmd: str, args: list[Tok], pos: list[Tok]) -> None:
        if self.ps and cmd in ("copy-item", "move-item", "rename-item", "cpi", "mi", "rni", "copy", "move", "ren", "cp", "mv") and any(a.text.startswith("-") and a.text.lower().rstrip(":") in _PS_PATH_PARAMS | {"-name", "-newname"} for a in args):
            named = self._ps_named_map(args)
            src, dst = named.get("-path") or named.get("-literalpath"), named.get("-destination") or named.get("-newname") or named.get("-name")
            if dst is None and len(pos) >= 1:
                dst = pos[-1]
            if src is None and pos:
                src = pos[0] if dst is not pos[0] else None
            if dst is not None:
                self.target(dst, "write", cmd)
            if src is not None and cmd in ("move-item", "mi", "rename-item", "rni", "move", "ren", "mv"):
                self.target(src, "delete", cmd)
            return
        tdir = None
        for i, a in enumerate(args):
            if a.text in ("-t", "--target-directory") and i + 1 < len(args):
                tdir = args[i + 1]
            elif a.text.startswith("--target-directory="):
                tdir = Tok(a.text.split("=", 1)[1])
        srcs = [p for p in pos if p is not tdir]
        if tdir is not None:
            for s in srcs:
                self.target(Tok(posixpath.join(self.sub(tdir).text, posixpath.basename(self.sub(s).text.replace("\\", "/"))), s.dyn or tdir.dyn), "write", cmd)
            return
        if len(pos) < 2:
            return
        if cmd in ("rsync", "scp"):
            # remote forms are network; a local last argument is a write
            for t in pos:
                if "@" in t.text or re.match(r"^[\w.-]+:", t.text) and not re.match(r"^[A-Za-z]:[\\/]", t.text):
                    h = host_of(t.text)
                    if h:
                        self.a.ops.append(ShellOp("net", h, self.cwd, cmd, upload=t is not pos[-1] or True))
        dst = pos[-1]
        self.target(dst, "write", cmd)
        d = self.sub(dst).text
        for s in pos[:-1]:
            st = self.sub(s)
            # copying INTO a folder writes folder/<name>; only guessed when the destination is (or looks like) a folder
            into_dir = dst.text.endswith(("/", "\\")) or len(pos) > 2 or os.path.isdir(d if os.path.isabs(d) else os.path.join(self.cwd or ".", d))
            if not st.dyn and into_dir:
                self.a.ops.append(ShellOp("write", posixpath.join(d.replace("\\", "/"), posixpath.basename(st.text.replace("\\", "/"))), self.cwd, cmd)) if not dst.dyn else None
            if cmd in ("mv", "move-item", "mi", "move", "ren"):
                self.target(s, "delete", cmd)

    def _ps_named_map(self, args: list[Tok]) -> dict[str, Tok]:
        out: dict[str, Tok] = {}
        i = 0
        while i < len(args):
            t = args[i].text
            if t.startswith("-") and len(t) > 1:
                key, sep, val = t.partition(":")
                key = key.lower()
                if sep and val:
                    out[key] = Tok(val, args[i].dyn)
                elif i + 1 < len(args) and not args[i + 1].text.startswith("-"):
                    out[key] = args[i + 1]
                    i += 1
            i += 1
        return out

    def _ps_named(self, args: list[Tok], kind: str, via: str) -> None:
        named = self._ps_named_map(args)
        for k in ("-path", "-literalpath"):
            if k in named:
                self.target(named[k], kind, via)

    def _ps_write(self, cmd: str, args: list[Tok]) -> None:
        if cmd == "write-output":
            return
        named = self._ps_named_map(args)
        dst = named.get("-path") or named.get("-literalpath") or named.get("-filepath")
        if dst is None:
            pos = []
            skip = False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a.text.startswith("-"):
                    skip = a.text.lower() in ("-value", "-encoding", "-itemtype", "-name", "-width", "-stream", "-delimiter", "-inputobject") and ":" not in a.text
                    continue
                pos.append(a)
            dst = pos[0] if pos else None
        if dst is not None:
            self.target(dst, "write", cmd)

    def _find(self, args: list[Tok]) -> None:
        roots = []
        for a in args:
            if a.text.startswith("-") or a.text in ("(", ")", "!"):
                break
            roots.append(a)
        texts = [a.text for a in args]
        if "-delete" in texts:
            names = [texts[i + 1] for i, t in enumerate(texts) if t in ("-name", "-iname", "-path", "-ipath", "-wholename") and i + 1 < len(texts)]
            if names:
                for r in roots or [Tok(".")]:
                    for nm in names:
                        self.target(Tok(posixpath.join(self.sub(r).text, nm.lstrip("./")), r.dyn, True), "delete", "find -delete")
            else:
                for r in roots or [Tok(".")]:
                    self.target(r, "delete", "find -delete", recursive=True)
        for i, t in enumerate(texts):
            if t in ("-exec", "-execdir", "-ok") and i + 1 < len(args):
                j = i + 1
                nested: list[Tok] = []
                while j < len(args) and args[j].text not in (";", "\\;", "+"):
                    nested.append(Tok("{}", True) if args[j].text == "{}" else args[j])
                    j += 1
                self._nested(nested)

    def _xargs(self, args: list[Tok]) -> None:
        i = 0
        while i < len(args) and args[i].text.startswith("-"):
            i += 2 if args[i].text in ("-I", "-n", "-P", "-d", "-L", "-s") else 1
        nested = args[i:] + [Tok("<xargs>", True)]
        if args[i:]:
            self._nested(nested)

    def _nested(self, nested: list[Tok]) -> None:
        if not nested:
            return
        seg = Segment(words=nested)
        self.a.commands.append("nested")
        w = _Walker(self.cwd, self.depth + 1, self.ps, dict(self.env))
        if self.depth >= MAX_DEPTH:
            self.a.opaque.append("nested command too deep")
            return
        w.segment(seg)
        self.a.merge(w.a)

    def _git(self, args: list[Tok], pos: list[Tok]) -> None:
        # skip global options: -C dir, -c k=v, --git-dir=..
        a = list(args)
        cwd = self.cwd
        while a and a[0].text.startswith("-"):
            if a[0].text == "-C" and len(a) > 1:
                cwd = _join(cwd, self.sub(a[1]).text) if cwd else ""
                a = a[2:]
            elif a[0].text in ("-c", "--exec-path") and len(a) > 1:
                a = a[2:]
            else:
                a = a[1:]
        if not a:
            return
        sub, rest = a[0].text, a[1:]
        saved = self.cwd
        self.cwd = cwd
        try:
            restpos = [t for t in rest if not t.text.startswith("-")]
            if sub in ("checkout", "restore", "rm", "mv", "mergetool"):
                if "--" in [t.text for t in rest]:
                    idx = [t.text for t in rest].index("--")
                    files = rest[idx + 1:]
                elif sub == "restore":
                    files = restpos
                elif sub == "checkout":
                    files = [] if len(restpos) <= 1 else restpos[1:]
                    if len(restpos) == 1 and any(t.text == "." for t in restpos):
                        self.a.bulk.append("git checkout .")
                else:
                    files = restpos
                for t in files:
                    if t.text == ".":
                        self.a.bulk.append(f"git {sub} .")
                    else:
                        self.target(t, "write" if sub != "rm" else "delete", f"git {sub}", recursive=sub == "rm")
            elif sub in ("reset",) and any(t.text == "--hard" for t in rest):
                self.a.bulk.append("git reset --hard")
            elif sub in ("clean",) and any(t.text.startswith("-") and "f" in t.text for t in rest):
                self.a.bulk.append("git clean -f")
            elif sub in ("stash", "pull", "merge", "rebase", "cherry-pick", "revert"):
                if sub in ("pull",):
                    for t in restpos:
                        h = host_of(t.text) if "://" in t.text else None
                        if h:
                            self.a.ops.append(ShellOp("net", h, self.cwd, "git pull"))
                else:
                    self.a.bulk.append(f"git {sub}")
            elif sub in ("clone", "fetch", "push", "ls-remote", "submodule", "remote"):
                remote_target = sub == "remote" and bool(rest) and rest[0].text in ("add", "set-url")
                for t in rest:
                    h = host_of(self.sub(t).text) if ("://" in t.text or "@" in t.text) else None
                    if h:
                        self.a.ops.append(ShellOp("net", h, self.cwd, f"git {sub}", upload=sub == "push" or remote_target))
            elif sub in ("apply", "am"):
                self._patch_targets([t for t in restpos])
            elif sub == "config":
                if any(t.text in ("core.hooksPath", "core.hookspath") for t in rest):
                    self.a.mentions.append("git-hooks-path")
                joined = " ".join(self.sub(t).text for t in rest)
                if re.search(r"(^|\s)!|core\.(sshcommand|pager|editor|fsmonitor)\b|diff\.external|credential\.helper\s+!", joined, re.I):
                    self.a.persist.append("git config sets a command that git will run later")
                if re.search(r"http\.sslverify\s*[ =]\s*false", joined, re.I):
                    self.a.persist.append("git TLS verification is switched off")
        finally:
            self.cwd = saved

    def _patch_targets(self, files: list[Tok]) -> None:
        """`git apply x.patch`: read the patch (if it exists and is small) and treat its target files as written."""
        for t in files[:3]:
            path = self.sub(t).text
            full = path if os.path.isabs(path) else os.path.join(self.cwd or ".", path)
            try:
                if os.path.getsize(full) > 2_000_000:
                    self.a.bulk.append(f"git apply of a large patch ({path})")
                    continue
                body = open(full, encoding="utf-8", errors="replace").read()
            except OSError:
                continue  # the command will fail by itself
            for m in re.finditer(r"^\+\+\+ (?:[ab]/)?(\S+)", body, re.M):
                if m.group(1) != "/dev/null":
                    self.target(Tok(m.group(1)), "write", "git apply")

    def _inline(self, cmd: str, args: list[Tok], seg: Segment | None = None) -> None:
        code_args: list[str] = []
        for i, a in enumerate(args):
            if a.text in ("-c", "-e", "-r", "-p", "-eval", "--eval", "-E") and i + 1 < len(args):
                if args[i + 1].dyn and re.search(r"\$\(|`", args[i + 1].text):
                    self.a.opaque.append(f"{cmd} inline code is computed")
                else:
                    code_args.append(args[i + 1].text)
        if seg is not None and seg.heredoc and any(t.text == "-" for t in args) or (seg is not None and seg.heredoc and not code_args and not [a for a in args if not a.text.startswith("-")]):
            code_args.append(seg.heredoc or "")
        for code in code_args:
            self.scan_code(code, cmd)
        # `python script.py` runs a file this analyser does not read: a documented limit, not a finding

    def scan_code(self, code: str, via: str) -> None:
        found = 0
        for rx in _CODE_WRITE:
            for m in rx.finditer(code):
                found += 1
                self.target(Tok(m.group("p")), "write", f"{via} inline code")
        if _CODE_WRITE_VERBS.search(code) and not found:
            self.a.opaque.append(f"{via} inline code writes files but the path is not a literal")
        for m in _URL.finditer(code):
            self.a.ops.append(ShellOp("net", m.group("host").strip("[]").lower(), self.cwd, f"{via} inline code"))
        # string literals are candidate paths: an inline script that opens ~/.ssh/id_rsa or .env is a secret touch
        for lit in re.findall(r"""['"]([^'"
]{1,120})['"]""", code):
            if len(self.a.words) < MAX_WORDS and "://" not in lit:
                self.a.words.append(lit)
        if re.search(r"\b(?:exec|eval|compile)\s*\(|__import__\(|base64\.b64decode|subprocess|os\.system|child_process", code):
            self.a.mentions.append("inline-code-exec")
        self.a.mentions.append(code)

    def _fetch(self, cmd: str, args: list[Tok]) -> None:
        upload = False
        outs: list[Tok] = []
        urls: list[Tok] = []
        i = 0
        while i < len(args):
            t = args[i].text
            low = t.lower()
            if low in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-f", "--form", "-t", "--upload-file", "--json", "--post-data", "--post-file", "--body-data", "--body-file", "-body", "-infile", "--data-ascii") or low.startswith(("--data", "--form", "--post-")):
                upload = True
            if low in ("-x", "--request", "-method", "--method") and i + 1 < len(args) and args[i + 1].text.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                upload = True
            if low in ("-o", "--output", "-outfile", "-destination", "-O") or t == "-O":
                if i + 1 < len(args) and (low != "-o" or cmd != "wget" or True):
                    outs.append(args[i + 1])
            if low.startswith("--output="):
                outs.append(Tok(t.split("=", 1)[1]))
            if low in ("-p", "--directory-prefix") and cmd == "wget" and i + 1 < len(args):
                outs.append(args[i + 1])
            if not t.startswith("-") and (("://" in t) or _HOSTLIKE.match(t.split("/")[0]) or t.startswith("localhost")):
                urls.append(args[i])
            i += 1
        for u in urls:
            text = self.sub(u).text
            h = host_of(text if "://" in text else "http://" + text)
            if h:
                self.a.ops.append(ShellOp("net", h, self.cwd, cmd, upload=upload))
            elif u.dyn:
                self.a.opaque.append(f"{cmd} URL depends on an expansion")
        if not urls and any(a.dyn for a in args):
            self.a.opaque.append(f"{cmd} URL depends on an expansion")
        for o in outs:
            self.target(o, "write", cmd)

    def _raw_net(self, cmd: str, args: list[Tok], pos: list[Tok]) -> None:
        hosts = []
        for t in pos:
            h = host_of(self.sub(t).text)
            if h:
                hosts.append(h)
        if cmd in ("nc", "ncat", "netcat", "socat") and any(a.text in ("-l", "-lp", "-lvp", "-k") or (a.text.startswith("-") and "l" in a.text[1:] and not a.text.startswith("--")) for a in args):
            self.a.ops.append(ShellOp("listen", "0.0.0.0", self.cwd, cmd))
            return
        if cmd in ("nc", "ncat", "netcat", "telnet", "tnc", "test-netconnection") and pos and not hosts:
            h = self.sub(pos[0]).text.lower()
            if re.match(r"^[a-z0-9.-]+$", h):
                hosts.append(h)
        if cmd in ("ssh", "scp", "sftp", "mosh") and pos and not hosts:
            h = self.sub(pos[0]).text
            h = h.split("@", 1)[-1].split(":", 1)[0].lower()
            if h:
                hosts.append(h)
        tunnel = cmd in ("ssh", "mosh") and any(a.text[:2] in ("-R", "-L", "-D", "-w") for a in args)
        for h in hosts:
            self.a.ops.append(ShellOp("net", h, self.cwd, cmd, upload=tunnel or cmd in ("scp", "rsync", "ftp", "tftp", "nc", "ncat", "netcat", "socat")))


def _join(cwd: str, rel: str) -> str:
    rel = rel.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/|^/|^~", rel):
        return rel
    return cwd.rstrip("/\\") + "/" + rel


MAX_COMMAND_CHARS = 100_000


def analyze(command: str, cwd: str, powershell: bool = False) -> Analysis:
    w = _Walker(cwd.replace("\\", "/"), 0, powershell, {})
    if len(command) > MAX_COMMAND_CHARS:
        w.a.opaque.append(f"command is {len(command)} characters, too large to analyse")
        return w.a
    w.walk(command)
    if re.search(r"(?i)(reg(\.exe)?\s+add|set-itemproperty|new-itemproperty)[^\n;|]*\\(run|runonce|winlogon|services)\b", command):
        w.a.persist.append("a startup/service registry value is written")
    # PowerShell-only constructs inside a posix-looking line and vice versa: a regex pass for .NET calls
    if powershell or "IO.File" in command or "::" in command:
        for rx in _CODE_WRITE[4:5]:
            for m in rx.finditer(command):
                w.target(Tok(m.group("p")), "write", ".NET file call")
    low = command.lower()
    if re.search(r"\b(iex|invoke-expression)\b", low) and re.search(r"downloadstring|downloadfile|\biwr\b|invoke-webrequest|\birm\b|invoke-restmethod|\bcurl\b|\bwget\b|frombase64string", low):
        w.a.pipe_exec.append("PowerShell executes downloaded or decoded text (iex)")
    if re.search(r"downloadstring|downloadfile|downloaddata|webclient", low):
        for m in _URL.finditer(command):
            w.a.ops.append(ShellOp("net", m.group("host").strip("[]").lower(), w.cwd, "WebClient"))
    return w.a
