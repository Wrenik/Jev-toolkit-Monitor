# Security policy

This is an experimental learning project: a monitor for a Claude Code agent's own tool calls. It **reduces risk and does not make an agent safe**, and it is documented to miss routes (see docs/AGENT_MONITOR.md, "Known bypasses"). Do not rely on it as your only defence.

## Reporting a problem

* A **bypass** (a tool call the monitor lets through that it should flag) or a **false alarm** is welcome as a normal issue: please use inert, made-up examples only (canary strings, `.invalid` addresses, `example.test` hosts), never a live payload or real secrets.
* A wrong or missing redaction pattern for text sent to the judge is handled in the Jev-toolkit-usage repository (`jev_core.redact`).
* A vulnerability in the code itself (for example a way to make the local server read files, run commands, or change its mode without the control header): use GitHub's **private vulnerability reporting** (the repository's Security tab, "Report a vulnerability") instead of a public issue. If that button is missing, open an issue that says only that you have a security report and do not include details; I will answer with a private way to send it.

## What is and is not in scope

* In scope: the Python package in `src/`, the mod in `claude-mod/`, and the documentation claims about them.
* Out of scope: TypeSafe's service, Claude Code itself, and attacks that need an attacker who already controls your machine. The doc already states that anything that can write the monitor's data folder or run arbitrary code can get around it.

## Secrets

Never put your `TYPESAFE_API_KEY` in an issue, a log excerpt or a screenshot. `.env` and `var/` are git-ignored, and by default the tools keep their data outside any repository in `~/.jev-toolkit` (`JEV_HOME`); the monitor logs a hash and a short redacted summary of your task, never your prompt text, but redaction is best effort.
