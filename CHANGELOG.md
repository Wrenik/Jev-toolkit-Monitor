# Changelog

## 0.1.0 (unreleased, EXPERIMENTAL)

First public version, cut from the jev-toolkit monorepo and then reviewed in two rounds.

* Deterministic checks on an agent's tool calls: instruction-file edits, monitor tampering, canaries, writes outside the project, persistence, cloud-metadata and internal-network calls, unlisted hosts and package sources, secret read plus upload, download-and-run, git hook tricks, disk and log damage, rate and volume spikes, shell shapes it cannot analyse.
* Response ladder log, warn, ask, block, kill; ships in monitor mode (nothing is blocked). Optional second opinion from a judgement model on medium findings only.
* Claude Code mod `jev-monitor`, plus a classic hook (`python -m jev_monitor hook`, `hook-snippet` prints the settings block).
* Review round 2: 190 new held-out scenarios; first-run detection 105/140 and 45/51, false alarms 6 and 0; generic fixes (cmd.exe switches, PowerShell expressions, metadata address variants, package-source flags, setuid bits, LOLBins, inline-code exec, `/dev/tcp`, download-then-run, DNS-name exfiltration, secret-named variables, disk/log damage).
* Review round 2b: held-out set 5 from the OWASP Agentic Top 10 / MITRE ATLAS / incident taxonomies (first run 27/81 attacks, 49/52 benign, 0 false alarms; 81/81 after generic fixes), a 476-command benign corpus (0 held), MCP and sub-agent argument rules, script, `package.json` and `Makefile` reading, publish-with-secret, harvesting, embedded-address hostnames, hidden Unicode, CI-file risks, agent-CLI bypass flags, credential stores, typosquats, destructive remote operations; `hook-snippet` matcher now covers MCP and sub-agent tools; `_Walker.dispatch` split; `docs/PRIOR_ART.md`; mod verified with `claude plugin validate`, `claude plugin test` (18/18) and a live headless monitor/enforce pair.
* Tokenizer and the rule checker split into small methods (behaviour checked identical on 500 command lines and by the full test suite).
* CLI: `hook-snippet`, `version`, friendly errors for `check`, file locations in `status`.
* Fixes: a 5000-segment path no longer takes seconds to resolve; `curl -o file.ext` no longer counts the file as a host.
