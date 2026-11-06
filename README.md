# Jev-toolkit-Monitor (EXPERIMENTAL)

[![tests](https://github.com/Wrenik/Jev-toolkit-Monitor/actions/workflows/tests.yml/badge.svg)](https://github.com/Wrenik/Jev-toolkit-Monitor/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![status](https://img.shields.io/badge/status-experimental-red)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An outside monitor for a Claude Code agent, in the spirit of a firewall / IDS / IPS. It watches what the **agent** does (its tool calls, never your typing) and compares that with your instructions and a small policy file: edits to the agent's own instruction files, writes outside the project, outbound network targets that are not on a list, persistence, secret reads followed by uploads, rate and volume spikes, and shell shapes it cannot analyse. The response ladder is **log, warn, block, kill**; kill is the last rung and is always logged. The rules live outside the agent's context, so context compaction cannot touch them. Deterministic checks decide first; an optional judgement model ([TypeSafe Jev](https://docs.typesafe.ai)) is a bounded second opinion for inconclusive cases only.

## Status and limits

This is a **learning project, not a security product**. **A monitor reduces risk. It does not make an agent safe.** Honest numbers, from [docs/AGENT_MONITOR.md](docs/AGENT_MONITOR.md):

* It ships in **`monitor` mode**: it logs and warns, it blocks nothing, until you type `/jevmonitor mode enforce`. `python -m jev_monitor report` lists what it *would* have stopped.
* **You cannot be locked out**: only the agent's tool calls are judged, never your prompts or slash commands. If the agent was stopped, `/jevmonitor reset` or `python -m jev_monitor reset` from any terminal clears it, and the latch expires by itself.
* **What it protects, in one line:** the *obvious* routes of a misbehaving or prompt-injected agent through its own tool calls (editing its instructions, persistence, secret reads plus upload, cloud-metadata and internal-network calls, unlisted package sources, download-and-run, git hooks, disk/log damage). **What it does not:** anything a script file, a binary or an allow-listed host does for the agent, and anything outside the tool calls. Use a sandbox or container as the real boundary; this is a tripwire on top.
* On the scenarios the rules were tuned on: 32/32 attacks caught, 0 false alarms. **First runs on frozen held-out sets** (attacks caught, benign clean): 26/28 and 21/24; 19/30 and 20/20; 105/140 and 218/235 (6 false alarms); 45/51 and 50/51 (0 false alarms; written after the last fixes, so the only fresh number). After the generic fixes each round the same sets read 27/28, 29/30, 140/140 and 50/51, but those are no longer clean. Benign "heavy day" of 200 calls: 0 held or blocked. The author wrote both the rules and the scenarios, so all of this flatters the monitor.
* The policy, state and log live in a folder the agent can write to; the guarantee is "detects and logs the obvious routes", not "prevents". Known bypasses (script files, allowlisted-host exfiltration, MCP and subagent paths, DNS exfiltration, mass harvesting, no view of the model's thinking ...) are listed in the doc.
* Verified in a real **headless** Claude Code session (block, note and kill all behaved as designed). Not verified: desktop pop-ups, typed `/jevmonitor` commands, subagent and parallel calls, long sessions, real WebFetch/MCP traffic. The doc has a 5-minute checklist.

## Install

Want all six tools? Use [the install script](https://github.com/Wrenik/Jev-toolkit-usage/blob/main/docs/INSTALL_ALL.md) (`scripts/install_all.ps1` or `.sh` in Jev-toolkit-usage) instead of the steps below.

Requires Python 3.11+ and the base package [Jev-toolkit-usage](https://github.com/Wrenik/Jev-toolkit-usage) (the judge layer, settings and data location).

```bash
python -m venv .venv
.venv/Scripts/python -m pip install "git+https://github.com/Wrenik/Jev-toolkit-Monitor.git"   # Windows; use .venv/bin/python elsewhere
# development, from clones side by side:
#   pip install -e ../Jev-toolkit-usage && pip install -e ".[dev]"
```

Data (policy, state, log, the optional TypeSafe key in `.env`) lives in `JEV_HOME` (default `~/.jev-toolkit`), shared with the other tools; `JEV_MONITOR_VAR` overrides the folder for this tool, and a `.env` or `var/` folder in the current directory wins during development.

## Quick try (offline, no key)

```bash
python -m jev_monitor check Bash '{"command": "echo x >> CLAUDE.md"}'   # what would it say? (instruction-file change)
python -m jev_monitor eval                                               # the hand-built scenario sets, with counts
python -m jev_monitor policy-check                                       # validates your policy file, if you have one
python -m pytest                                                         # all tests, offline (needs pytest, see above)
```

Sample output of the first command (shortened; in the default monitor mode the call is allowed with a note, `would` is what enforce mode would do):

```json
{ "action": "warn", "would": "block", "mode": "monitor", "class": "shell",
  "reason": "jev-monitor note on Bash: this would change a file that steers the agent ... (monitor mode: enforce mode would block this).",
  "rules": ["instruction-file-change"], "severity": "high" }
```

## Without the Claude Code mod: a plain hook

`python -m jev_monitor hook-snippet` prints a `PreToolUse` block for `.claude/settings.json` (project) or `~/.claude/settings.json` (all projects); paste it in yourself, nothing is written for you. It uses the interpreter you ran it with and sets `"onFailure": "block"` (a hook that crashes does not block otherwise). Where things are: `python -m jev_monitor status` prints the policy, log and state file paths; `python -m jev_monitor report` summarises the log (what it would have stopped, by rule). Before switching to enforce, read the report for a week of your own work.

## The Claude Code mod (`jev-monitor`)

Needs Claude Code with mod support (`claude plugin --help`) and `python` on PATH with this package installed (set `JEV_PYTHON` or the mod's `python` option to use another interpreter). The mod starts `python -m jev_monitor serve` (127.0.0.1:8767) itself and needs no path to a checkout.

```
/plugin marketplace add Wrenik/Jev-toolkit-Monitor
/plugin install jev-monitor --marketplace Wrenik/Jev-toolkit-Monitor
```

or load it from a clone via `CLAUDE_CODE_PLUGIN_DIRS=<clone>/claude-mod/jev-monitor`. `/jevmonitor` shows status, `mode monitor|enforce`, `allow` (let the last held call through once), `reset`, `report` and `off`/`on`. Mod tests: `claude plugin test claude-mod/jev-monitor`.

## Layout

```
src/jev_monitor/        rules.py, shell.py (static bash/PowerShell analysis), paths.py, engine.py (ladder, modes,
                        kill latch), policy.py, state.py, log.py, judge2.py, server.py, evaluate.py + evalset/
claude-mod/jev-monitor/ the Claude Code mod (TypeScript), example policy, and its tests
docs/AGENT_MONITOR.md   design, hooks verified vs not, checks, path matrix, evaluation, known bypasses, prior art
```

## Privacy

Everything runs on your machine except the optional second opinion: for inconclusive (medium-severity) calls only, a redacted one-line summary of the call plus a redacted 80-character summary of your task is sent to TypeSafe. No raw prompts are stored or sent. `[judge] enabled = false` in the policy file, or `JEV_MONITOR_JUDGE=off`, keeps everything local, and without a key nothing is ever sent. **Jev is used because, as of today, it is the only model of its kind on the market, not because sending data to a US company is the goal. The plan is to replace it with a local model or a European provider** through the `Judge` interface in `jev_core`; this repository never imports the TypeSafe SDK. Jev's data location is not stated in its documentation (checked 2026-10-30).

## Prior art

Credited in detail in the doc ("Prior art"): Claude Code hooks and permissions, Anthropic's auto mode, community PreToolUse guards, Meta's LlamaFirewall / AlignmentCheck, CaMeL, Invariant Labs Guardrails, Falco and IDS/IPS in general. No third-party code or rule list is copied; every rule and scenario is hand-written.

## The Jev toolkit family

| Repository | What it is | Depends on |
|---|---|---|
| [Jev-toolkit-usage](https://github.com/Wrenik/Jev-toolkit-usage) | `jev_core` (judge interface, Jev adapter, cache, decision log, redaction, settings and data location) and the model/effort router | - |
| [Jev-toolkit-Compiler](https://github.com/Wrenik/Jev-toolkit-Compiler) | context log, search and a compact/clear advisor | usage |
| [Jev-toolkit-Scanner](https://github.com/Wrenik/Jev-toolkit-Scanner) | prompt-injection scanner (experimental) | usage |
| **Jev-toolkit-Monitor** (this one) | agent monitor (experimental) | usage |
| [Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck) | fact checker with hover evidence | usage (Scanner optional) |
| [Jev-toolkit-Sources](https://github.com/Wrenik/Jev-toolkit-Sources) | source restriction (allowlist policy) | usage, FactCheck |

All six on one machine: [docs/INSTALL_ALL.md](https://github.com/Wrenik/Jev-toolkit-usage/blob/main/docs/INSTALL_ALL.md) (a script does it). The other tools are published one by one; their links work as each goes public.

## Contributing, security, license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Bypasses and false alarms (with inert examples) are the most useful reports.

Licensed under the [MIT License](LICENSE).
