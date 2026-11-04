"""Round-3 additions to the shell analyser, kept out of shell.py so that file stays a command table.

Everything here only *records* facts on the walker's `Analysis` (`high`, `medium`, `publish`, `archives`, `sweeps`, ...);
the checker in rules.py turns them into findings, because only it knows the policy (secret files, allowed hosts).

Covered: scripts the command line does not show (`python x.py`, `./x.sh`, `npm run x`, `make x` are read and analysed when
the file exists), unreadable programs run from temp/download folders, agent CLIs started with their safety off, credential
stores, environment dumps to files, publishing commands, destructive remote operations, typosquatted package names,
unvetted `npx -y` runs, local-account changes and traffic-redirecting variables.
"""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING

from . import catalog

if TYPE_CHECKING:
    from .shell import Tok, _Walker

MAX_SCRIPT_BYTES = 200_000
MAX_SCRIPT_TOTAL = 600_000
_SHELL_INTERP = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
_PS_INTERP = {"powershell", "pwsh"}
_CODE_INTERP = {"python", "python2", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua"}
_NPM_RUNNERS = {"npm", "yarn", "pnpm", "bun"}
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly")
_TEMPISH = re.compile(r"(?i)^(?:/tmp/|/var/tmp/|/dev/shm/|[a-z]:/users/public/|.*/(?:downloads|appdata/local/temp|temp)/)")
_COPYLIKE = {"cp", "mv", "rsync", "tar", "zip", "7z", "7za", "compress-archive", "robocopy", "xcopy", "copy-item", "cpi", "copy", "cpio", "ditto", "install", "move-item"}
_SWEEPERS = {"find", "grep", "egrep", "fgrep", "rg", "ag", "fd", "locate", "get-childitem", "gci", "dir", "ls", "select-string"}


# ---------------------------------------------------------------------------------------------------------------
def read_script(w: "_Walker", raw: str) -> tuple[str, str] | None:
    """(text, path) of a small readable text file, or None. Counts against a shared byte budget."""
    path = raw.replace("\\", "/")
    full = os.path.expanduser(path) if path.startswith("~") else (path if os.path.isabs(path) or re.match(r"^[A-Za-z]:/", path) else os.path.join(w.cwd or ".", path))
    try:
        size = os.path.getsize(full)
        if size > MAX_SCRIPT_BYTES or w.shared["bytes"] + size > MAX_SCRIPT_TOTAL or not os.path.isfile(full):
            return None
        with open(full, "rb") as fh:
            head = fh.read(size)
    except OSError:
        return None
    if b"\x00" in head[:512]:
        return None  # a binary
    w.shared["bytes"] += size
    return head.decode("utf-8", errors="replace"), full


def analyse_text(w: "_Walker", text: str, kind: str, label: str) -> None:
    """Analyse script text as `kind` (sh, ps, code) in a child walker. Findings about unknowns (opaque) are dropped: a script's
    `$1` or `$(dirname $0)` is not the agent's problem, and reporting it would make every build script a false alarm."""
    from .shell import _Walker  # noqa: PLC0415 - circular at import time

    if w.depth >= 3:
        return
    child = _Walker(w.cwd, w.depth + 1, kind == "ps", dict(w.env), w.shared)
    if kind == "code":
        child.scan_code(text, label)
    else:
        child.walk(text)
    child.a.opaque = []
    w.a.merge(child.a)
    w.a.mentions.append(f"script:{label}")


def run_file(w: "_Walker", raw: str, interp: str | None) -> bool:
    """`bash x.sh`, `python x.py`, `./x.sh`: read the file and analyse it; a missing/binary program in a temp or download folder is a finding."""
    got = read_script(w, raw)
    norm = raw.replace("\\", "/")
    if got is None:
        if norm.lstrip("./").rsplit("/", 1)[-1] in w.chmodded or _TEMPISH.match(norm.lower()) or re.match(r"(?i)^(?:~/downloads/|\$(?:env:)?(?:temp|tmp|tmpdir)\b|%temp%)", norm):
            w.a.medium.append(("run-unreadable-binary", f"runs {norm[:60]} from a temp or download folder, and its contents cannot be read"))
        return False
    text, _ = got
    base = norm.rsplit("/", 1)[-1].lower()
    first = text.split("\n", 1)[0]
    if interp in _CODE_INTERP or base.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".lua")) or re.match(r"#!.*(python|node|ruby|perl|php|deno|bun)", first):
        analyse_text(w, text, "code", f"script {base}")
    elif interp in _PS_INTERP or base.endswith((".ps1", ".psm1", ".bat", ".cmd")):
        analyse_text(w, text, "ps", f"script {base}")
    else:
        analyse_text(w, text, "sh", f"script {base}")
    return True


def _package_scripts(w: "_Walker", names: list[str]) -> None:
    got = read_script(w, "package.json")
    if got is None:
        return
    try:
        scripts = json.loads(got[0]).get("scripts", {})
    except (ValueError, AttributeError):
        return
    if not isinstance(scripts, dict):
        return
    for n in names:
        for key in (f"pre{n}", n, f"post{n}"):
            if isinstance(scripts.get(key), str):
                analyse_text(w, scripts[key], "sh", f"package.json script {key}")


def _make_recipes(text: str, targets: list[str]) -> list[str]:
    rules: dict[str, tuple[list[str], list[str]]] = {}
    order: list[str] = []
    cur: list[str] | None = None
    for line in text.replace("\\\n", " ").split("\n"):
        if line.startswith("\t") and cur is not None:
            cur.append(re.sub(r"^[\t@+\-\s]+", "", line).replace("$$", "$"))
        elif (m := re.match(r"^([A-Za-z0-9_.\-/%]+)\s*:(?!=)\s*([^#]*)", line)) and not line.startswith("."):
            name, pre = m.group(1), m.group(2).split()
            rules[name] = (pre, [])
            order.append(name)
            cur = rules[name][1]
        elif line.strip() and not line.startswith("#"):
            cur = None
    want = targets or order[:1]
    out: list[str] = []
    seen: set[str] = set()

    def visit(t: str, d: int) -> None:
        if t in seen or t not in rules or d > 2:
            return
        seen.add(t)
        for p in rules[t][0]:
            visit(p, d + 1)
        out.extend(rules[t][1])

    for t in want:
        visit(t, 0)
    return out


def script_runners(w: "_Walker", cmd: str, args: list["Tok"], pos: list["Tok"]) -> None:
    """Interpreter + file, package-manager scripts, make."""
    if cmd in _SHELL_INTERP | _PS_INTERP | _CODE_INTERP:
        files = [a for a in pos if not a.dyn]
        if cmd in _PS_INTERP:
            for i, a in enumerate(args):
                if a.text.lower() in ("-file", "-f") and i + 1 < len(args):
                    files = [args[i + 1]]
        if files and not any(a.text in ("-c", "-e", "-command", "-r", "-m") for a in args):
            run_file(w, w.sub(files[0]).text, cmd)
    elif cmd in _NPM_RUNNERS and pos:
        sub = w.sub(pos[0]).text
        if sub in ("run", "run-script", "rum") and len(pos) > 1:
            _package_scripts(w, [w.sub(pos[1]).text])
        elif sub in ("test", "t", "start", "stop", "restart"):
            _package_scripts(w, ["test" if sub == "t" else sub])
        elif sub in ("install", "i", "ci", "add", "rebuild", "publish", "pack"):
            _package_scripts(w, [h for h in _INSTALL_HOOKS if h not in ("prepublishOnly",)] if sub != "publish" else ["prepublishOnly", "prepack", "publish", "postpublish"])
        elif cmd in ("yarn", "bun") and not sub.startswith("-") and sub not in ("add", "remove", "dlx", "create", "x"):
            _package_scripts(w, [sub])
    elif cmd == "make" or cmd == "gmake":
        for name in ("Makefile", "makefile", "GNUmakefile"):
            got = read_script(w, name)
            if got:
                targets = [w.sub(a).text for a in pos if "=" not in a.text]
                for recipe in _make_recipes(got[0], targets)[:60]:
                    analyse_text(w, recipe, "sh", f"{name} recipe")
                break


def direct_exec(w: "_Walker", head: "Tok") -> None:
    """The command word itself is a path (`./x.sh`, `/tmp/p`, `C:\\x\\y.exe`)."""
    text = w.sub(head).text
    if head.dyn or not re.match(r"^(?:\.{1,2}[/\\]|/|~[/\\]|[A-Za-z]:[/\\]|\$(?:env:)?(?:temp|tmp|tmpdir|home)\b|%temp%)", text, re.I):
        return
    run_file(w, text, None)


# ---------------------------------------------------------------------------------------------------------------
def _flat(args: list["Tok"], w: "_Walker") -> list[str]:
    return [w.sub(a).text for a in args]


def _install_names(texts: list[str], value_flags: set[str]) -> list[str]:
    out, skip = [], False
    for t in texts:
        if skip:
            skip = False
            continue
        if t.startswith("-"):
            skip = t in value_flags
            continue
        if "/" in t or "\\" in t or "://" in t or t.startswith((".", "~", "@", "git+")) or ":" in t or t.endswith((".txt", ".whl", ".tgz", ".zip", ".json", ".toml")):
            continue
        out.append(re.split(r"[<>=!~;\[@]", t, maxsplit=1)[0] if not t.startswith("@") else t)
    return [n for n in out if n]


def catalogue(w: "_Walker", cmd: str, args: list["Tok"], pos: list["Tok"], seg) -> None:  # noqa: C901 - a table of command shapes
    texts = _flat(args, w)
    low = [t.lower() for t in texts]
    joined = " ".join(low)
    sub = next((t for t in low if not t.startswith("-")), "")
    flagset = {t for t in low if t.startswith("-")}
    a = w.a

    if cmd == "chmod" and any(re.match(r"^[ugoa]*\+[rwst]*x|^[0-7]?[0-7][0-7][1357]$", t) for t in low):
        w.chmodded.update(t.replace("\\", "/").rsplit("/", 1)[-1] for t in texts if not t.startswith("-") and not re.match(r"^[ugoa]*[+=]|^[0-7]+$", t))

    # --- archives / copies (secret harvesting is decided in the checker, which knows the secret list)
    if cmd in _COPYLIKE and not (cmd == "tar" and any(re.match(r"^-?[a-z]*x", t) for t in low[:1])):
        a.archives.append(cmd)
    if cmd in _SWEEPERS:
        a.sweeps.append(cmd)

    # --- publishing through an allow-listed channel
    pub = False
    if cmd == "gh":
        pub = (sub in ("gist", "issue", "pr", "release", "repo", "secret", "variable", "workflow") and any(t in low for t in ("create", "comment", "edit", "upload", "review", "set", "fork", "run")))
        if sub == "api":
            pub = bool(flagset & {"-f", "-F", "--field", "--raw-field", "--input"}) or bool(re.search(r"-(?:x|-method)\s*(?:=|\s)\s*(?:post|put|patch)", joined))
    elif cmd == "aws":
        pub = bool(re.search(r"\bs3\s+(cp|sync|mv)\b|s3api\s+put-|\bsecretsmanager\s+put|\bssm\s+put-parameter|\bsns\s+publish|\bsqs\s+send", joined))
    elif cmd in ("gsutil", "azcopy", "mc", "rclone", "s3cmd", "megacmd", "mega-put", "transfer", "wrangler", "firebase"):
        pub = cmd != "rclone" or sub in ("copy", "sync", "move", "copyto", "moveto", "rcat", "mount")
    elif cmd == "az":
        pub = "upload" in joined
    elif cmd in ("scp", "sftp"):
        pub = True
    if pub:
        a.publish.append(f"{cmd} {sub}".strip())

    # --- publishing a package
    if (cmd in ("npm", "pnpm", "yarn") and sub == "publish" or cmd == "twine" and sub == "upload" or cmd == "cargo" and sub == "publish"
            or cmd == "gem" and sub == "push" or cmd == "docker" and sub == "push" or cmd in ("vsce", "ovsx") and sub == "publish"
            or cmd == "poetry" and sub == "publish" or cmd == "uv" and sub == "publish" or cmd == "dotnet" and "nuget" in low and "push" in low) and "--dry-run" not in flagset and "-n" not in flagset:
        a.medium.append(("publish-package", f"{cmd} {sub} publishes a package or image that other people will install"))

    # --- destructive operations on shared or remote state
    d = ""
    if cmd == "git" and sub == "push":
        if any(t in ("--force", "-f", "--delete", "-d", "--mirror", "--prune") for t in low) or any(re.match(r"^(\+\S|:\S)", t) for t in low[1:]):
            d = "git push --force/--delete rewrites or removes remote history"
    elif cmd in ("terraform", "tofu", "pulumi", "cdk"):
        if sub == "destroy" or ("-auto-approve" in low and sub in ("apply", "up")) or "--yes" in low and sub == "up":
            d = f"{cmd} {sub} changes or destroys real infrastructure without confirmation"
    elif cmd == "kubectl" and sub in ("delete", "drain", "cordon", "scale") and (sub != "scale" or "--replicas=0" in low):
        d = f"kubectl {sub} removes workloads or resources from a cluster"
    elif cmd == "helm" and sub in ("uninstall", "delete"):
        d = "helm uninstall removes a release"
    elif cmd in ("docker", "podman") and re.search(r"\bsystem\s+prune|\bvolume\s+(rm|prune)|\bimage\s+prune\s+-a|\brm\s+(-f|--force)\b|\bcontainer\s+prune", joined):
        d = f"{cmd} removes containers, volumes or images in bulk"
    elif cmd == "aws" and re.search(r"\bs3\s+(rm|rb)\b|\b(delete|terminate|deregister|remove|purge)-[a-z-]+|\bdelete-", joined):
        d = "aws deletes cloud resources"
    elif cmd in ("gcloud", "az", "heroku", "fly", "flyctl", "vercel", "netlify", "doctl", "supabase") and re.search(r"\b(delete|destroy|remove|rm)\b|db\s+reset", joined):
        d = f"{cmd} deletes cloud resources"
    elif cmd in ("psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "sqlcmd", "clickhouse-client") and re.search(r"\bdrop\s+(database|table|schema)|\btruncate\b|\bflush(all|db)\b|\bdelete\s+from\s+\w+\s*(;|\"|'|$)", joined):
        d = f"{cmd} runs a statement that drops or empties data"
    elif cmd in ("dropdb", "dropuser") or cmd == "gh" and sub in ("repo", "release") and "delete" in low or cmd == "npm" and sub in ("unpublish", "deprecate"):
        d = f"{cmd} {sub} removes something shared"
    elif cmd in ("prisma", "rails", "rake", "alembic", "sequelize", "knex") and re.search(r"migrate\s+reset|db:(drop|reset)|downgrade\s+base|migrate:rollback", joined):
        d = f"{cmd} resets or drops the database"
    if d:
        a.medium.append(("destructive-remote-op", d))

    # --- agent CLIs with their safety switched off, or changing their own configuration
    if cmd in catalog.AGENT_CLIS:
        if flagset & catalog.AGENT_BYPASS_FLAGS or "bypasspermissions" in joined.replace(" ", "").replace("-", "").replace("_", ""):
            a.high.append(("agent-permission-bypass", f"{cmd} is started with its permission checks switched off"))
        if re.search(r"\b(mcp|plugin|plugins|hooks?|config|settings|marketplace)\b\s+(add|add-json|add-from-claude-desktop|install|set|edit|import|enable|disable|remove|uninstall)", joined):
            a.high.append(("agent-config-change", f"{cmd} {sub} changes the agent's own tools or settings"))

    # --- credential stores
    for name, first, rx in catalog.CRED_READ:
        if cmd == name and (first is None or sub == first) and re.search(rx, joined):
            a.cred.append(f"{cmd} reads stored credentials or tokens")
            break
    if cmd == "git" and sub == "credential" and any(t in ("fill", "get") for t in low):
        a.cred.append("git credential fill reads stored credentials")

    # --- environment dump written to a file
    dump = ((cmd == "printenv" and not [t for t in low if not t.startswith("-")]) or (cmd == "env" and not texts) or (cmd in ("export", "declare", "typeset") and ("-p" in low or not texts))
            or (cmd == "set" and not texts and not w.ps) or (cmd in ("get-childitem", "gci", "dir", "ls") and any(re.match(r"^env:\\?$", t) for t in low)))
    if dump and (any(op in (">", ">>", ">|", "&>") for op, _ in seg.redirects) or seg.piped_to_next):
        a.medium.append(("env-dump-to-file", "the whole environment (which holds tokens and keys) is dumped to a file or pipe"))

    # --- local accounts and root shells
    if cmd in ("useradd", "adduser", "usermod", "userdel", "passwd", "chpasswd", "groupadd", "gpasswd", "visudo", "new-localuser", "add-localgroupmember", "dscl", "sysadminctl") or (
            cmd == "net" and sub in ("user", "localgroup")) or (cmd == "su"):
        a.persist.append(f"{cmd} creates or changes a local account or switches user")

    # --- package names
    install = (cmd in ("pip", "pip3", "pipx", "uv", "poetry", "conda") and sub in ("install", "add")) or (cmd == "uv" and sub == "pip" and "install" in low) \
        or (cmd in ("npm", "pnpm", "yarn", "bun") and sub in ("install", "i", "add")) or (cmd == "cargo" and sub in ("add", "install")) or (cmd == "gem" and sub == "install")
    if cmd in ("python", "python3", "py") and low[:3] == ["-m", "pip", "install"]:
        install, texts = True, texts[3:]
    if install:
        npm = cmd in ("npm", "pnpm", "yarn", "bun")
        values = {"-r", "-c", "-e", "-i", "-t", "--target", "--prefix", "--index-url", "--extra-index-url", "--find-links", "-f", "--registry", "--python", "-p", "--constraint", "--requirement", "--editable", "--root", "--cache-dir"}
        idx = next((i for i, t in enumerate(texts) if t.lower() in ("install", "i", "add")), -1)
        for n in _install_names(texts[idx + 1:] if idx >= 0 else texts, values)[:12]:
            hit = catalog.typosquat_of(n, catalog.NPM_POPULAR if npm else catalog.PIP_POPULAR)
            if hit:
                a.medium.append(("typosquat-package", f"{n!r} is one typo away from the popular package {hit!r}"))

    # --- run-without-installing
    if (cmd in ("npx", "bunx", "uvx", "pipx") or (cmd in ("pnpm", "yarn") and sub in ("dlx", "exec")) or (cmd == "npm" and sub == "exec")) and not (cmd == "pipx" and sub != "run"):
        if cmd == "npx" and not (flagset & {"-y", "--yes"}):
            return
        names = [t for t in texts if not t.startswith("-")]
        if cmd in ("pnpm", "yarn", "npm", "pipx"):
            names = names[1:]
        if names:
            n = re.split(r"@(?=[\d^~]|latest)", names[0], maxsplit=1)[0]
            if n.lower() not in catalog.KNOWN_RUNNERS and not n.startswith(("create-", "@")) and not os.path.exists(os.path.join(w.cwd or ".", "node_modules", ".bin", n)):
                a.medium.append(("unvetted-package-run", f"{cmd} downloads and runs {n!r}, which is not a well-known tool"))


def note_assignment(w: "_Walker", key: str, value: str) -> None:
    """Variables that send an AI client's or the shell's traffic somewhere else; the checker decides if the host is trusted."""
    if catalog.REDIRECT_VARS.match(key) and value:
        w.a.mentions.append(f"redirect-var:{key}={value}")
