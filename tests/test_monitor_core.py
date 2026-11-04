"""Step 1: path normalisation, policy loading, state file (latch, mode, intent, allows)."""

import os
import time

import pytest

from jev_monitor import paths
from jev_monitor.policy import Policy, PolicyError, load_policy, policy_from_dict
from jev_monitor.state import State


# ---- paths: POSIX rules (explicit, independent of the host) ----------------
def P(raw, cwd="/work/proj", **kw):
    return paths.canon(raw, cwd, env=kw.pop("env", {"HOME": "/home/u"}), win=False, resolve=False, **kw).path


def W(raw, cwd="C:/Work/Proj", env=None):
    return paths.canon(raw, cwd, env=env or {"USERPROFILE": "C:\\Users\\U"}, win=True, resolve=False)


def test_dotdot_and_relative():
    assert P("sub/../CLAUDE.md") == "/work/proj/CLAUDE.md"
    assert P("../proj/./CLAUDE.md") == "/work/proj/CLAUDE.md"
    assert P("../../etc/passwd") == "/etc/passwd"


def test_home_expansion_forms():
    assert P("~/.claude/settings.json") == "/home/u/.claude/settings.json"
    assert P("$HOME/.claude/x") == "/home/u/.claude/x"
    assert P("${HOME}/.claude/x") == "/home/u/.claude/x"
    assert W("%USERPROFILE%\\.claude\\x").path == "c:/users/u/.claude/x"
    assert W("$env:USERPROFILE/.claude/x").path == "c:/users/u/.claude/x"
    assert W("~\\.ssh\\id_rsa").path == "c:/users/u/.ssh/id_rsa"


def test_unknown_variable_is_ambiguous():
    c = paths.canon("$TARGET/file", "/work", env={}, win=False, resolve=False)
    assert c.ambiguous and "TARGET" in c.why
    assert paths.canon("$(pwd)/x", "/work", env={}, win=False, resolve=False).ambiguous


def test_windows_case_slashes_and_gitbash_drive():
    assert W("C:\\WORK\\proj\\claude.MD").path == "c:/work/proj/claude.md"
    assert W("c:/Work/Proj/../Proj/CLAUDE.md").path == "c:/work/proj/claude.md"
    assert W("/c/Work/Proj/CLAUDE.md").path == "c:/work/proj/claude.md"
    assert W("sub\\file.txt").path == "c:/work/proj/sub/file.txt"


def test_short_name_83_is_flagged_when_unresolvable():
    c = W("C:/PROGRA~1/tool/x")
    assert c.ambiguous and "8.3" in c.why
    assert not W("C:/Work/Proj/CLAUDE.md").ambiguous


@pytest.mark.skipif(os.name != "nt", reason="Windows long-name expansion")
def test_short_name_expands_on_real_windows(tmp_path):
    long = tmp_path / "Averylongfoldername"
    long.mkdir()
    (long / "CLAUDE.md").write_text("x")
    import ctypes

    buf = ctypes.create_unicode_buffer(500)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(long), buf, 500) or "~" not in buf.value:
        pytest.skip("8.3 names are disabled on this volume")
    got = paths.canon(buf.value + "\\CLAUDE.md", str(tmp_path)).path
    assert got.endswith("averylongfoldername/claude.md")


def test_symlink_resolves(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    (target / "CLAUDE.md").write_text("x")
    link = tmp_path / "alias"
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    a = paths.canon(str(link / "CLAUDE.md"), str(tmp_path)).path
    b = paths.canon(str(target / "CLAUDE.md"), str(tmp_path)).path
    assert a == b


def test_glob_anchoring_and_depth():
    gm = lambda p, pat: paths.glob_match(p, pat, win=False, env={"HOME": "/home/u"})
    assert gm("/work/proj/CLAUDE.md", "CLAUDE.md")
    assert gm("/work/proj/sub/deep/CLAUDE.md", "CLAUDE.md")
    assert gm("/work/proj/.claude/hooks/x.sh", ".claude/**")
    assert gm("/home/u/.claude/settings.json", "~/.claude/**")
    assert not gm("/work/proj/notCLAUDE.md", "CLAUDE.md")
    assert not gm("/work/proj/src/a.py", ".claude/**")
    assert gm("/work/proj/.env", ".env") and gm("/work/proj/.env.local", ".env.*")


def test_under():
    assert paths.under("/a/b/c", "/a/b") and paths.under("/a/b", "/a/b")
    assert not paths.under("/a/bc", "/a/b")


# ---- policy -----------------------------------------------------------------
def test_defaults_are_monitor_mode_and_fail_closed_for_sensitive():
    p = Policy()
    assert p.mode == "monitor"
    assert p.fail_for("shell") == "closed" and p.fail_for("write") == "closed" and p.fail_for("network") == "closed"
    assert p.fail_for("read") == "open"


def test_per_class_override(tmp_path):
    f = tmp_path / "p.toml"
    f.write_text('mode = "monitor"\n[classes.shell]\nmode = "enforce"\nfail = "closed"\n[classes.read]\nfail = "open"\n')
    p = load_policy(f)
    assert p.class_mode("shell", "monitor") == "enforce"
    assert p.class_mode("write", "monitor") == "monitor"


@pytest.mark.parametrize(
    "text",
    [
        'mode = "loud"',
        "[classes.bogus]\nmode='enforce'",
        "[ladder]\nhigh = 'explode'",
        "[rate]\nmax_calls = 0",
        "[nonsense]\nx = 1",
        "[network]\nallow_hosts = 'github.com'",
        "this is not toml",
    ],
)
def test_broken_policy_is_an_error_not_a_default(tmp_path, text):
    f = tmp_path / "p.toml"
    f.write_text(text)
    with pytest.raises(PolicyError):
        load_policy(f)


def test_missing_policy_file_is_an_error(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.toml")


def test_policy_from_dict_overrides_values():
    p = policy_from_dict({"network": {"allow_hosts": ["Example.COM"]}, "canary": {"tokens": ["CANARY-1"]}, "protected": {"dev_mode": True}})
    assert p.allow_hosts == ["example.com"] and p.canary_tokens == ["CANARY-1"] and p.dev_mode


# ---- state ------------------------------------------------------------------
def test_latch_expires_and_resets_from_another_instance(tmp_path):
    s = State(tmp_path / "state.json")
    assert s.latch() is None
    s.set_latch("canary touched", 15, "s1")
    assert s.latch()["reason"] == "canary touched"
    assert State(tmp_path / "state.json").reset() is True  # a second process (the CLI)
    assert s.latch() is None
    s.set_latch("x", 1, None)
    data = s._read()
    data["latch"]["until"] = time.time() - 1
    s._write(data)
    assert s.latch() is None  # expired by itself


def test_mode_override_roundtrip(tmp_path):
    s = State(tmp_path / "state.json")
    assert s.mode_override() is None
    s.set_mode("enforce")
    assert State(tmp_path / "state.json").mode_override() == "enforce"
    with pytest.raises(ValueError):
        s.set_mode("yolo")


def test_intent_is_hashed_and_redacted(tmp_path):
    s = State(tmp_path / "state.json")
    s.set_intent("please fix the bug, my password: hunter2hunter2 is in the file " + "x" * 300, "s1")
    i = s.intent()
    assert len(i["sha256"]) == 64
    assert "hunter2" not in i["summary"] and len(i["summary"]) <= 80
    assert "hunter2" not in (tmp_path / "state.json").read_text()


def test_allow_is_one_shot_and_limited(tmp_path):
    s = State(tmp_path / "state.json")
    assert s.add_allow("h1", "s", 2) and s.add_allow("h2", "s", 2)
    assert not s.add_allow("h3", "s", 2)
    assert s.consume_allow("h1", "s") and not s.consume_allow("h1", "s")
    assert not s.consume_allow("h2", "other-session")
