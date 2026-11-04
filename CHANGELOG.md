# Changelog

## 0.1.0 (unreleased, EXPERIMENTAL)

First public version, cut from the jev-toolkit monorepo and then reviewed in two rounds.

* Deterministic checks on an agent's tool calls: instruction-file edits, monitor tampering, canaries, writes outside the project, persistence, cloud-metadata and internal-network calls, unlisted hosts and package sources, secret read plus upload, download-and-run, git hook tricks, disk and log damage, rate and volume spikes, shell shapes it cannot analyse.
* Response ladder log, warn, ask, block, kill; ships in monitor mode (nothing is blocked). Optional second opinion from a judgement model on medium findings only.
* Claude Code mod `jev-monitor`, plus a classic hook (`python -m jev_monitor hook`, `hook-snippet` prints the settings block).
* Review round 2: 190 new held-out scenarios; first-run detection 105/140 and 45/51, false alarms 6 and 0; generic fixes (cmd.exe switches, PowerShell expressions, metadata address variants, package-source flags, setuid bits, LOLBins, inline-code exec, `/dev/tcp`, download-then-run, DNS-name exfiltration, secret-named variables, disk/log damage).
* Tokenizer and the rule checker split into small methods (behaviour checked identical on 500 command lines and by the full test suite).
* CLI: `hook-snippet`, `version`, friendly errors for `check`, file locations in `status`.
* Fixes: a 5000-segment path no longer takes seconds to resolve; `curl -o file.ext` no longer counts the file as a host.
