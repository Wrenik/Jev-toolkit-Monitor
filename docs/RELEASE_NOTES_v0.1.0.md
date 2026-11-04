# jev-toolkit-monitor v0.1.0 (EXPERIMENTAL)

An outside monitor for a Claude Code agent: it checks the agent's own tool calls against deterministic rules and a small policy file, and answers log, warn, ask, block or kill. It is a tripwire, not a sandbox.

## What you get
* `python -m jev_monitor check|hook|hook-snippet|report|status|mode|reset|eval|serve`.
* The `jev-monitor` Claude Code mod (starts its own local server on 127.0.0.1:8767).
* Ships in **monitor mode**: it logs and warns, blocks nothing, until you switch to enforce. You cannot be locked out: your own prompts are never judged, and `python -m jev_monitor reset` clears a latch.

## Honest numbers (author wrote rules and scenarios)
| Set | Attacks caught | Benign clean | False alarms |
|---|---|---|---|
| tuned on | 32/32 | 24/24 | 0 |
| held-out 1, first run | 26/28 | 21/24 | 2 |
| held-out 2, first run | 19/30 | 20/20 | 0 |
| held-out 3, first run | 105/140 | 218/235 | 6 |
| held-out 4, first run (written after the last fixes) | 45/51 | 50/51 | 0 |
| 200-call benign day | n/a | 199 | 0 |

After fixes the first three sets read 27/28, 29/30 and 140/140, but they are then tuned-on. Expect roughly 85-90% detection on unseen routes and an occasional nuisance warning (for example `sudo`).

## Limits
Not a sandbox. Blind to what a script file, binary or allow-listed host does for the agent, to the model's thinking, to MCP and subagent internals. Policy, state and log sit in a folder the agent can write. Verified in a headless Claude Code session only; desktop pop-ups, typed slash commands and long sessions are unverified. See docs/AGENT_MONITOR.md, "Known bypasses".

## Privacy
Local by default. Only medium-severity calls may send a redacted one-line summary to TypeSafe Jev (optional, needs a key; `[judge] enabled = false` or `JEV_MONITOR_JUDGE=off` disables it).
