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
    system: list[str] = field(default_factory=list)  # disk wipes, log clearing, shutdown, setuid bits
    commands: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)  # raw text pieces worth a substring scan

    def merge(self, other: "Analysis") -> None:
        self.ops += other.ops
        self.opaque += other.opaque
        self.pipe_exec += other.pipe_exec
        self.persist += other.persist
        self.words += other.words
        self.bulk += other.bulk
        self.system += other.system
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
    call: bool = False  # PowerShell: started by the call operator `&`, so a leading $variable IS the command


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


class _Lexer:
    """One pass over the command text. Each `_try_*` method consumes input and returns True, or returns False untouched."""

    def __init__(self, text: str, ps: bool) -> None:
        self.text, self.n, self.ps = text, len(text), ps
        self.esc = "`" if ps else "\\"
        self.i = 0
        self.segs: list[Segment] = [Segment()]
        self.word: list[str] = []
        self.dyn = self.glob = self.quoted = self.has = False
        self.pending_heredocs: list[tuple[str, bool]] = []  # (delimiter, strip tabs)
        self.redirect_op: str | None = None

    # -- word and segment bookkeeping
    def _reset_word(self) -> None:
        self.word.clear()
        self.dyn = self.glob = self.quoted = self.has = False

    def flush(self) -> None:
        if not self.has:
            return
        tok = Tok("".join(self.word), self.dyn, self.glob, self.quoted)
        self._reset_word()
        if self.redirect_op is not None:
            self.segs[-1].redirects.append((self.redirect_op, tok))
            self.redirect_op = None
        else:
            self.segs[-1].words.append(tok)

    def new_segment(self, pipe: bool = False) -> None:
        self.flush()
        if pipe:
            self.segs[-1].piped_to_next = True
        self.segs.append(Segment(piped_from_prev=pipe))

    def _subst(self, start: int, body_from: int, end: int) -> None:
        """A $( ), backtick or <( ) piece text[start:end+1]: remember its body, keep the raw text in the word."""
        self.segs[-1].substs.append(self.text[body_from:end])
        self.word.append(self.text[start : end + 1])

    # -- handlers, tried in this order
    def _try_blank(self) -> bool:
        if self.text[self.i] not in " \t\r":
            return False
        self.flush()
        self.i += 1
        return True

    def _read_heredocs(self) -> None:
        text, n = self.text, self.n
        for delim, strip in self.pending_heredocs:
            body: list[str] = []
            while self.i < n:
                j = text.find("\n", self.i)
                line = text[self.i :] if j == -1 else text[self.i : j]
                self.i = n if j == -1 else j + 1
                if (line.strip("\t") if strip else line).rstrip("\r") == delim:
                    break
                body.append(line)
            self.segs[-1].heredoc = "\n".join(body)
        self.pending_heredocs.clear()

    def _try_newline(self) -> bool:
        if self.text[self.i] != "\n":
            return False
        self.flush()
        self.i += 1
        if self.pending_heredocs:
            self._read_heredocs()
        self.new_segment()
        return True

    def _try_comment(self) -> bool:
        i, text = self.i, self.text
        if text[i] != "#" or self.has or not (i == 0 or text[i - 1] in " \t\n;&|("):
            return False
        while self.i < self.n and text[self.i] != "\n":
            self.i += 1
        return True

    def _try_single_quote(self) -> bool:
        if self.text[self.i] != "'":
            return False
        j = self.text.find("'", self.i + 1)
        j = self.n if j == -1 else j
        chunk = self.text[self.i + 1 : j]
        self.word.append(chunk.replace("''", "'") if self.ps else chunk)
        self.has = self.quoted = True
        self.i = j + 1
        return True

    def _try_double_quote(self) -> bool:
        text, n = self.text, self.n
        if text[self.i] != '"':
            return False
        self.has = self.quoted = True
        self.i += 1
        while self.i < n and text[self.i] != '"':
            i, d = self.i, text[self.i]
            if d == self.esc and i + 1 < n and (self.ps or text[i + 1] in '"\\$`\n'):
                self.word.append(text[i + 1])
                self.i += 2
            elif d == "$" and text.startswith("$(", i):
                end = _match_paren(text, i + 1)
                self._subst(i, i + 2, end)
                self.dyn = True
                self.i = end + 1
            elif d == "`":
                j = text.find("`", i + 1)
                j = n if j == -1 else j
                self._subst(i, i + 1, j)
                self.dyn = True
                self.i = j + 1
            else:
                if d == "$":
                    self.dyn = True
                self.word.append(d)
                self.i += 1
        self.i += 1
        return True

    def _try_escape(self) -> bool:
        if self.text[self.i] != self.esc or self.i + 1 >= self.n:
            return False
        self.word.append(self.text[self.i + 1])
        self.has = True
        self.i += 2
        return True

    def _try_substitution(self) -> bool:
        text, i = self.text, self.i
        c = text[i]
        if c == "$" and text.startswith("$(", i):
            end, body = _match_paren(text, i + 1), i + 2
        elif c == "`" and not self.ps:
            j = text.find("`", i + 1)
            end, body = (self.n if j == -1 else j), i + 1
        elif c in "<>" and text.startswith(("<(", ">("), i):
            end, body = _match_paren(text, i + 1), i + 2
        else:
            return False
        self._subst(i, body, end)
        self.dyn = self.has = True
        self.i = end + 1
        return True

    def _heredoc_delimiter(self) -> str:
        """Parses the delimiter after `<<` / `<<-`; leaves self.i behind it."""
        text, n = self.text, self.n
        j = self.i
        while j < n and text[j] in " \t":
            j += 1
        k = j
        if k < n and text[k] in "'\"":
            k = text.find(text[k], k + 1)
            delim = text[j + 1 : k if k != -1 else n]
            self.i = (k + 1) if k != -1 else n
        else:
            while k < n and text[k] not in " \t\n;&|<>()":
                k += 1
            delim = text[j:k]
            self.i = k
        return delim

    def _try_redirect(self) -> bool:
        text, i = self.text, self.i
        c = text[i]
        if not (c in "<>" or (c == "&" and text.startswith("&>", i))):
            return False
        if self.has and "".join(self.word).isdigit() and not self.quoted:
            self._reset_word()  # a bare digit word right before is an fd number: 2> file
        else:
            self.flush()
        op = next((cand for cand in ("<<<", "<<-", "<<", ">>", ">|", "&>>", "&>", ">&", "<&", ">", "<") if text.startswith(cand, i)), "")
        self.i += len(op)
        if op in ("<<", "<<-"):
            self.pending_heredocs.append((self._heredoc_delimiter(), op == "<<-"))
        else:
            self.redirect_op = op
        return True

    def _try_ps_paren(self) -> bool:
        if not (self.ps and self.text[self.i] == "(" and (self.segs[-1].words or self.has or self.redirect_op is not None)):
            return False
        end = _match_paren(self.text, self.i)
        self._subst(self.i, self.i + 1, end)
        self.dyn = self.has = True
        self.i = end + 1
        return True

    def _try_operator(self) -> bool:
        text, i = self.text, self.i
        c = text[i]
        if not (c in ";|&()" or (c in "{}" and self.ps)):
            return False
        if c == "|" and text.startswith("||", i):
            self.new_segment()
            self.i += 2
        elif c == "&" and text.startswith("&&", i):
            self.new_segment()
            self.i += 2
        elif c == "|":
            self.flush()
            self.i += 2 if text.startswith("|&", i) else 1
            self.new_segment(pipe=True)
        elif c == "&" and self.ps:
            self.new_segment()
            self.segs[-1].call = True
            self.i += 1
        else:
            self.flush()
            self.i += 1
            self.new_segment()
        return True

    def _try_lone_brace(self) -> bool:
        text, i = self.text, self.i
        if text[i] in "{}" and not self.ps and not self.has and (i + 1 >= self.n or text[i + 1].isspace() or text[i + 1] == ";"):
            self.i += 1  # a lone { or } is shell grouping, not an argument
            return True
        return False

    def _try_variable(self) -> bool:
        """`${...}` is taken whole. A bare `$` (or PowerShell `@`) only marks the word dynamic; the plain-character case appends it."""
        text, i = self.text, self.i
        if not (text[i] == "$" or (self.ps and text[i] == "@")):
            return False
        self.dyn = self.has = True
        if not text.startswith("${", i):
            return False
        j = text.find("}", i)
        j = self.n if j == -1 else j
        self.word.append(text[i : j + 1])
        self.i = j + 1
        return True

    _HANDLERS = ("_try_blank", "_try_newline", "_try_comment", "_try_single_quote", "_try_double_quote", "_try_escape", "_try_substitution",
                 "_try_redirect", "_try_ps_paren", "_try_operator", "_try_lone_brace", "_try_variable")

    def run(self) -> list[Segment]:
        handlers = [getattr(self, h) for h in self._HANDLERS]
        while self.i < self.n:
            if any(h() for h in handlers):
                continue
            c = self.text[self.i]
            if c in "*?[":
                self.glob = True
            self.word.append(c)
            self.has = True
            self.i += 1
        self.flush()
        return [s for s in self.segs if s.words or s.redirects or s.heredoc]


def tokenize(text: str, ps: bool = False) -> list[Segment]:
    return _Lexer(text, ps).run()


# ------------------------------------------------------------------ command tables
_WRAPPERS = {"sudo", "doas", "nohup", "time", "command", "builtin", "exec", "nice", "setsid", "stdbuf", "ionice", "chronic", "unbuffer"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"}
_PS_SHELLS = {"powershell", "pwsh"}
_INTERPRETERS = _SHELLS | _PS_SHELLS | {"python", "python2", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "iex", "invoke-expression", "source", ".", "eval", "cmd"}
_DECODERS = {"base64", "xxd", "openssl", "gunzip", "zcat", "gzip", "unzip", "uudecode", "certutil", "rev", "tr", "basenc"}
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
_URL = re.compile(r"""(?i)\b(?:[a-z][a-z0-9+.-]*)://(?:[^/\s'"@]*@)?(?P<host>\[[0-9a-f:.]+\]|[^/\s:'"?#]+)""")
_HOSTLIKE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$|^\d{1,3}(?:\.\d{1,3}){3}$|^localhost$")
_ENCODED_PS = re.compile(r"(?i)(^|\s)-e(nc|ncodedcommand)?\b")


_SECRET_VAR = re.compile(r"(?i)(?:\$\{?(?:env:)?|%)\w*(?:token|secret|passw(?:or)?d|api_?key|private_?key|credential|access_?key)\w*")
_DEV_TCP = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"]+)/")
_SOURCE_OK = {"activate", "activate.sh", "activate.fish", "activate.ps1", "nvm.sh", "conda.sh"}  # sourcing these is routine
_WIN_SWITCH = re.compile(r"^/(?:[A-Za-z?](?::\S*)?|grant|deny|remove|inheritance|reset|save|restore|setowner|findsid|verify|substitute)$", re.I)
_WIN_CMDS = {"del", "erase", "rd", "rmdir", "xcopy", "robocopy", "attrib", "icacls", "cacls", "takeown"}
_TEXT_ONLY = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "awk", "sed", "cat", "head", "tail", "less", "more", "wc", "diff", "tr", "sort", "uniq", "cut",
              "write-host", "write-output", "write-error", "select-string", "findstr", "ls", "dir", "type", "true", "false", "test", "[", "open", "xdg-open", "start", "man", "which", "where"}
_CODE_FETCHERS = {"certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "msiexec", "cscript", "wscript", "msbuild", "installutil"}  # fetch or run remote code
_PKG_SOURCE_FLAGS = {"--index-url", "-i", "--extra-index-url", "--trusted-host", "--registry", "--source", "--find-links", "--index", "--default-index", "--proxy", "--repository-url", "--git", "--registry-url"}
_RUNNABLE = (".sh", ".bash", ".zsh", ".ps1", ".py", ".pl", ".rb", ".js", ".mjs", ".bat", ".cmd", ".php", ".vbs", ".exe", ".msi", ".run", ".bin")
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


NET_COMMANDS = _NET_FETCH | _NET_RAW


def urls_in(text: str) -> list[str]:
    """Host names of every scheme://host URL in `text`."""
    return [m.group("host").strip("[]").lower() for m in _URL.finditer(text)]


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


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
        self.downloaded: set[str] = set()  # base names of files a fetch command saved, to catch "download, then run it"

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
                if kind in ("write", "delete"):  # nothing matches HERE, but the pattern's folder still says where it would act
                    self.a.ops.append(ShellOp(kind, text, self.cwd, via, upload, recursive))
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
            if t.dyn and _SECRET_VAR.search(t.text):
                self.a.mentions.append("secret-var:" + t.text[:40])

    # -- main loop -----------------------------------------------------------
    def walk(self, text: str) -> None:
        segs = tokenize(text, self.ps)
        chain: list[tuple[Segment, str]] = []
        for seg in segs:
            if not seg.piped_from_prev:
                chain = []
            cmd = self.segment(seg)
            chain.append((seg, cmd))
            if self.downloaded and (cmd in self.downloaded or (cmd in _INTERPRETERS and any(_basename(w.text) in self.downloaded for w in self.last_args if not w.text.startswith("-")))):
                self.a.pipe_exec.append("a file downloaded earlier in this command is executed")
            if seg.piped_from_prev and cmd in _INTERPRETERS | {"iex", "invoke-expression"} and not self._has_script(self.last_args, cmd):
                up = [c for _, c in chain[:-1]]
                if any(c in _NET_FETCH for c in up):
                    self.a.pipe_exec.append(f"downloaded text is piped into {cmd}")
                elif any(c in _DECODERS for c in up) or any(c == "echo" or c == "printf" for c in up) and any(c in _DECODERS for c in up):
                    self.a.pipe_exec.append(f"decoded text is piped into {cmd}")
                elif any(c in ("echo", "printf") and any(re.search(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\\u[0-9a-fA-F]{4}", w.text) for w in s.words) for s, c in chain[:-1]):
                    self.a.pipe_exec.append(f"escape-encoded text is piped into {cmd}")

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
        elif self.ps and len(words) == 1 and (m := re.match(r"^\$(?:env:)?(\w+)[-+*/]?=(.*)$", words[0].text)):
            self._assign(m.group(1), Tok(m.group(2), words[0].dyn and "$" in m.group(2)))
            words = []  # `$ErrorActionPreference='Stop'` written without spaces
        if self.ps and words and not seg.call and words[0].dyn and words[0].text[:1] in "$[" and not words[0].text.startswith("$("):
            # a PowerShell expression statement (`$env:PATH -split ';'`, `[IO.File]::ReadAllText(..)`), not a command to run
            self.scan_code(" ".join(w.text for w in words), "PowerShell expression")
            words = []
        for tok in [r[1] for r in seg.redirects] + seg.words:
            m = _DEV_TCP.search(tok.text)
            if m:
                self.a.ops.append(ShellOp("net", m.group(1).lower(), self.cwd, "/dev/tcp", upload=True))
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
        if cmd in _WIN_CMDS or (cmd in ("copy", "move", "ren") and self.ps is False):
            # cmd.exe switches (/q /s /E /grant) are not paths; keep them as flags so they do not become targets
            args = [Tok("-" + a.text[1:], a.dyn, a.glob, a.quoted) if _WIN_SWITCH.match(a.text) else a for a in args]
        pos = [a for a in args if not a.text.startswith("-") or a.text == "-"]
        flags = [a.text for a in args if a.text.startswith("-")]
        win_rec = cmd in _WIN_CMDS and any(f.lower() in ("-s", "-t", "-r") for f in flags)  # /S /T /R switches

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
            if _name(Tok(self.sub(pos[0]).text.replace("\\", "/"))) not in _SOURCE_OK and not self.sub(pos[0]).text.replace("\\", "/").endswith(tuple("/" + n for n in _SOURCE_OK)):
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
                self.target(t, "delete", cmd, recursive=win_rec or any(f in ("-r", "-R", "-rf", "-fr", "-recurse", "--recursive", "/s", "-Recurse") for f in flags) or cmd in ("rmdir", "rd"))
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
        if cmd in ("truncate", "touch", "chmod", "chown", "chgrp", "chattr", "setfacl", "icacls", "takeown", "attrib", "set-acl", "mkdir", "shred", "fallocate"):
            skip = 1 if cmd in ("chmod", "chown", "chgrp", "chattr") and pos else 0
            rec = win_rec or any(f in ("-R", "-r", "--recursive", "/s", "/t", "-Recurse") or (f.startswith("-") and not f.startswith("--") and "R" in f[1:]) for f in flags)
            if cmd == "chmod" and pos and re.search(r"^[0-7]?[2-7][0-7]{3}$|^[ugoa]*[+=][rwxXt]*s", self.sub(pos[0]).text):
                self.a.system.append("chmod sets the setuid/setgid bit")
            for t in pos[skip:]:
                self.target(t, "write", cmd, recursive=rec)
            return
        if cmd == "dd":
            for a in args:
                if a.text.startswith("of="):
                    self.target(Tok(a.text[3:], a.dyn, a.glob, a.quoted), "write", "dd")
                    if re.match(r"^/dev/(sd|hd|vd|xvd|nvme|mmcblk|disk|rdisk)", a.text[3:]):
                        self.a.system.append("dd writes to a raw disk device")
            return
        if self._system(cmd, args, pos, flags):
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
                text = self.sub(t).text
                h = host_of(text)
                if h:
                    self.a.ops.append(ShellOp("net", h, self.cwd, cmd))
                elif t.dyn and (m := re.search(r"[)`}]\.((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})$", text)):
                    self.a.ops.append(ShellOp("net", m.group(1).lower(), self.cwd, cmd, upload=True))  # data in the name: DNS exfiltration
            return
        if self._persistence(cmd, args, flags):
            return
        if self._weakening(cmd, args):
            return
        if cmd in ("docker", "podman", "nerdctl") and args and args[0].text in ("run", "create", "exec"):
            self._container(args)
            return
        if cmd in _PKG:
            self._package_sources(cmd, args)
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
        if cmd not in _TEXT_ONLY:
            # any other program given a URL: certutil, mshta, regsvr32 /i:http://..., a project CLI, ... (code-fetching tools count as a supply step)
            for t in args:
                text = self.sub(t).text
                m = _URL.search(text)
                if m:
                    self.a.ops.append(ShellOp("net", m.group("host").strip("[]").lower(), self.cwd, cmd, supply=cmd in _CODE_FETCHERS))

    def _package_sources(self, cmd: str, args: list[Tok]) -> None:
        """Package managers: every URL, index/registry/proxy flag value and (for go) module path names a place code comes from."""
        texts = [self.sub(t).text for t in args]
        sub = next((t for t in texts if not t.startswith("-")), "")
        for i, text in enumerate(texts):
            val = None
            if "://" in text:
                val = text.split("=", 1)[1] if text.startswith("-") and "=" in text else text.removeprefix("git+")
            elif text.split("=", 1)[0] in _PKG_SOURCE_FLAGS:
                val = text.split("=", 1)[1] if "=" in text else (texts[i + 1] if i + 1 < len(texts) else None)
            elif cmd == "go" and sub in ("get", "install", "run") and re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+/", text):
                val = text
            if val:
                h = host_of(val if "://" in val else "https://" + val)
                if h:
                    self.a.ops.append(ShellOp("net", h, self.cwd, cmd, supply=True))

    def _system(self, cmd: str, args: list[Tok], pos: list[Tok], flags: list[str]) -> bool:
        """Commands that wipe disks, clear logs or history, stop the machine, or hand out capabilities."""
        words = " ".join(self.sub(a).text.lower() for a in args)
        why = ""
        disk = (cmd.startswith("mkfs") or cmd in ("wipefs", "diskpart", "format-volume", "clear-disk", "initialize-disk")
                or (cmd in ("fdisk", "sfdisk", "parted") and "-l" not in flags) or (cmd == "cipher" and ("/w" in words or "-w" in words))
                or (cmd == "vssadmin" and "delete" in words) or (cmd == "diskutil" and re.search(r"erase|partition", words)))
        if disk:
            why = f"{cmd} can wipe or repartition a disk"
        elif cmd == "format" and any(re.fullmatch(r"[a-z]:", self.sub(t).text.lower()) for t in pos):
            why = "format erases a drive"
        elif cmd in ("shutdown", "reboot", "halt", "poweroff", "stop-computer", "restart-computer") and not (cmd == "shutdown" and "-c" in flags):
            why = f"{cmd} stops or restarts the machine"
        elif cmd == "kill" and re.search(r"(^|\s)-1(\s|$)", words):
            why = "kill -1 signals every process"
        elif cmd == "history" and ("-c" in flags or "-w" in flags):
            why = "shell history is cleared"
        elif cmd in ("clear-eventlog", "remove-eventlog", "clear-history") or (cmd == "wevtutil" and re.search(r"\b(cl|clear-log)\b", words)) or (cmd == "auditpol" and "clear" in words):
            why = "event logs or history are cleared"
        elif cmd == "setcap" and "cap_" in words:
            why = "setcap grants file capabilities"
        elif cmd in ("pip", "pip3", "pipx", "uv", "npm", "claude") and re.search(r"\b(uninstall|remove|disable)\b[^\n;|&]*jev", words):
            why = "uninstalls or disables a jev tool (the monitor itself)"
        else:
            return False
        self.a.system.append(why)
        return True

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
        elif cmd == "wmic" and re.search(r"\b(process call create|startup|__eventfilter|__eventconsumer|__filtertoconsumerbinding|subscription|call create)\b", words):
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
                if a[0].text == "-c":
                    self._git_config_pair(self.sub(a[1]).text)
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
            elif sub in ("init", "clone") and any(t.text.startswith("--template") for t in rest):
                self.a.persist.append("git is given a template folder, which can install hooks that run later")
            elif sub in ("apply", "am"):
                self._patch_targets([t for t in restpos])
            elif sub == "config":
                self._git_config_pair(" ".join(self.sub(t).text for t in rest))
        finally:
            self.cwd = saved

    def _git_config_pair(self, joined: str) -> None:
        """`git config <key> <value>` or `git -c key=value`: keys that make git run a program or switch off checks."""
        if re.search(r"core\.hookspath", joined, re.I):
            self.a.mentions.append("git-hooks-path")
        if re.search(r"(^|\s)!|core\.(sshcommand|pager|editor|fsmonitor|askpass)\b|diff\.external|credential\.helper[\s=]+!|protocol\.ext\.allow", joined, re.I):
            self.a.persist.append("git config sets a command that git will run later")
        if re.search(r"http\.sslverify\s*[ =]\s*false", joined, re.I):
            self.a.persist.append("git TLS verification is switched off")

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
        if re.search(r"(?:\bexec|\beval|\bFunction)\b\s*\(?.{0,120}?(?:b64decode|atob|fromhex|unhexlify|decompress|decode_base64|from_base64|base64_decode|FromBase64|Buffer\.from)", code, re.S):
            self.a.pipe_exec.append(f"{via} inline code executes decoded text")
        if re.search(r"\b(?:system|popen|exec|execSync|spawn|spawnSync|shell_exec|passthru|run|call|check_output|Popen)\s*\(|child_process", code):
            for lit in re.findall(r"""['"]([^'"\n]{6,300})['"]""", code)[:6]:
                if " " in lit and "://" not in lit.split(" ")[0]:
                    self.recurse(lit, False)  # a string handed to the system shell: analyse it as a command line
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
            is_output_value = i > 0 and (args[i - 1].text.lower() in ("-o", "--output", "-outfile", "-destination", "-p", "--directory-prefix", "-d", "--data", "--data-binary", "-t", "--upload-file", "-x", "--request", "-h", "--header", "-u", "--user", "-a", "--user-agent", "-e", "--referer", "-b", "--cookie", "-method", "-headers", "-body", "-infile", "-useragent", "-contenttype") or args[i - 1].text == "-O")
            if not t.startswith("-") and not is_output_value and (("://" in t) or _HOSTLIKE.match(t.split("/")[0]) or t.startswith("localhost")):
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
            name = _basename(self.sub(o).text)
            if name.endswith(_RUNNABLE):
                self.downloaded.add(name)

    def _raw_net(self, cmd: str, args: list[Tok], pos: list[Tok]) -> None:
        if cmd in ("ssh", "scp", "sftp", "mosh", "rsync"):  # option values (-o StrictHostKeyChecking=no, -i key, -p 22) are not hosts
            skip = {i + 1 for i, a in enumerate(args) if a.text in ("-o", "-i", "-p", "-P", "-l", "-F", "-J", "-b", "-c", "-E", "-e", "-m", "-S", "-W", "-B", "-D", "-L", "-R", "-w")}
            pos = [a for i, a in enumerate(args) if i not in skip and (not a.text.startswith("-") or a.text == "-")]
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
