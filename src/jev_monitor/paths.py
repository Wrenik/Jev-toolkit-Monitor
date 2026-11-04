"""Path normalisation: the part where deterministic monitors usually fail.

`canon()` turns whatever the agent wrote (relative, `..`, `~`, `$HOME`, `%USERPROFILE%`,
back slashes, git-bash `/c/...`, symlinks, junctions, mixed case, 8.3 short names) into one
comparison form: forward slashes, absolute, symlinks resolved, case-folded on Windows.
When it cannot be sure (an unknown `$VAR`, an unresolvable `PROGRA~1` segment) it says so
via `ambiguous` and the caller must treat the path as possibly anything.

What it cannot see: hard links (two names, one file), bind mounts, and files that become
links after the check (TOCTOU). These are listed in docs/AGENT_MONITOR.md.
"""

from __future__ import annotations

import contextlib
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from functools import lru_cache

IS_WINDOWS = os.name == "nt"
# Default macOS volumes are case-insensitive too: `claude.md` is `CLAUDE.md` there.
FOLD_CASE = IS_WINDOWS or sys.platform == "darwin"

_VAR = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)|\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)%", re.IGNORECASE)
_SHORT83 = re.compile(r"(^|/)[^/]{1,6}~\d+(\.[^/]{0,3})?(?=/|$)")
_GITBASH = re.compile(r"^/([a-zA-Z])(/|$)")
MAX_PATH_CHARS = 4096
_HOME_VARS = {"home": "HOME", "userprofile": "USERPROFILE"}


@dataclass(frozen=True)
class Canon:
    path: str  # comparison form
    ambiguous: bool = False  # an unresolved variable or short name: could be any path
    why: str = ""


def home_dir(env: dict[str, str] | None = None) -> str:
    env = env if env is not None else dict(os.environ)
    return env.get("USERPROFILE") or env.get("HOME") or os.path.expanduser("~")


def _expand(raw: str, env: dict[str, str], win: bool) -> tuple[str, str]:
    """Expand ~ and variables. Returns (text, name of the first unknown variable or '')."""
    home = home_dir(env)
    if raw == "~" or raw.startswith(("~/", "~\\")):
        raw = home + raw[1:]
    unknown = ""

    def sub(m: re.Match) -> str:
        nonlocal unknown
        name = next(g for g in m.groups() if g)
        low = name.lower()
        if low in ("home", "userprofile"):
            return home
        for key, val in env.items():
            if key.lower() == low:
                return val
        unknown = unknown or name
        return m.group(0)

    return _VAR.sub(sub, raw), unknown


@lru_cache(maxsize=512)
def _long_name(path: str) -> str:
    """Windows: expand 8.3 short names of an existing path. Elsewhere: unchanged."""
    if not IS_WINDOWS or "~" not in path:
        return path
    try:
        import ctypes

        buf = ctypes.create_unicode_buffer(32768)
        n = ctypes.windll.kernel32.GetLongPathNameW(path, buf, 32768)
        return buf.value if 0 < n < 32768 else path
    except Exception:  # noqa: BLE001
        return path


def canon(raw: str, cwd: str, env: dict[str, str] | None = None, win: bool | None = None, resolve: bool = True) -> Canon:
    """Normalise `raw` as seen from `cwd`. `win` forces Windows or POSIX rules (tests)."""
    win = IS_WINDOWS if win is None else win
    if len(raw) > MAX_PATH_CHARS:
        return Canon(raw[:80], True, "path is absurdly long")
    env = env if env is not None else dict(os.environ)
    text, unknown = _expand(raw.strip().strip("\"'"), env, win)
    if unknown:
        return Canon(raw, True, f"unresolved variable {unknown}")
    if "$(" in text or "`" in text:
        return Canon(raw, True, "command substitution")
    if win:
        text = text.replace("\\", "/")
        wsl = re.match(r"^/mnt/([a-zA-Z])(/|$)", text)  # WSL's view of a Windows drive
        if wsl:
            text = f"{wsl.group(1)}:/" + text[wsl.end():]
        m = _GITBASH.match(text)
        if m and len(text) > 1 and not os.path.exists(text):
            text = f"{m.group(1)}:/" + text[m.end():]
    if win and text.startswith("/") and not text.startswith("//"):
        # a rooted path without a drive means "the root of the current drive" (git-bash /usr, /etc, /tmp land here too)
        m = re.match(r"^[a-zA-Z]:", cwd.replace("\\", "/")) or re.match(r"^[a-zA-Z]:", os.getcwd())
        text = (m.group(0) if m else "c:") + text
    if not _is_abs(text, win):
        base = cwd.replace("\\", "/") if win else cwd
        text = base.rstrip("/") + "/" + text
    if win:
        text = _long_name(text.replace("/", "\\")).replace("\\", "/")
        text = posixpath.normpath(text)
    else:
        text = posixpath.normpath(text)
    # `//host/share` style paths keep two leading slashes through normpath on POSIX only.
    if resolve and (win == IS_WINDOWS):
        with contextlib.suppress(OSError):
            text = os.path.realpath(text).replace("\\", "/") if win else os.path.realpath(text)
    if win or (FOLD_CASE and win == IS_WINDOWS):
        text = text.casefold()
    if win:
        text = text.removeprefix("//?/")
    ambiguous = bool(_SHORT83.search(text)) and win
    return Canon(text, ambiguous, "unresolved 8.3 short name" if ambiguous else "")


def _is_abs(text: str, win: bool) -> bool:
    if win:
        return bool(re.match(r"^[a-zA-Z]:/", text)) or text.startswith("//")
    return text.startswith("/")


def under(path: str, root: str) -> bool:
    """Is `path` equal to or inside `root` (both canonical)?"""
    root = root.rstrip("/")
    return path == root or path.startswith(root + "/")


@lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        out.append("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def glob_match(path: str, pattern: str, cwd: str = "", win: bool | None = None, env: dict[str, str] | None = None) -> bool:
    """Match canonical `path` against a policy glob.

    Absolute and `~/` patterns are anchored; a relative pattern such as `CLAUDE.md` or `.claude/**`
    matches at any depth. `**` crosses folders, `*` does not.
    """
    win = IS_WINDOWS if win is None else win
    pat, _ = _expand(pattern, env if env is not None else dict(os.environ), win)
    pat = pat.replace("\\", "/")
    if win or (FOLD_CASE and win == IS_WINDOWS):
        pat = pat.casefold()
    if not _is_abs(pat, win) and not pat.startswith("**") and not (win and pat.startswith("/") and not pat.startswith("//")):
        pat = "**/" + pat
    return bool(_glob_regex(pat).match(path))


def matches_any(path: str, patterns: list[str], win: bool | None = None, env: dict[str, str] | None = None) -> str | None:
    """First pattern that matches, else None. A pattern that matches a parent folder also counts
    for a path inside it when it ends in `/**`."""
    for p in patterns:
        if glob_match(path, p, win=win, env=env):
            return p
    return None
