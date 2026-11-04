"""Round-3 command shapes: Windows administration, WSL, kubectl/docker/helm misuse, git history and credential helpers,
cloud CLIs (aws, gcloud, az), history switches, DNS-carried data, editor extensions.

Like shell_extra.py this only *records* facts on the walker's `Analysis`; the checker in rules.py turns them into findings.
Every rule here is a table row keyed on a command and a verb, not on a particular host, path or file name.
"""

from __future__ import annotations

import re
import shlex
from typing import TYPE_CHECKING

from . import shell_extra

if TYPE_CHECKING:
    from .shell import Tok, _Walker

_SECURITY_SERVICES = r"windefend|sense\b|mpssvc|wscsvc|eventlog|securityhealthservice|wdfilter|sysmon|wuauserv|bits\b"
_K8S_HOST = r"privileged|hostpid|hostnetwork|hostipc|hostpath|allowprivilegeescalation|sys_admin|--as=system:admin"
_K8S_FORMATS = r"-o\s*(?:yaml|json|jsonpath|go-template|custom-columns)|--output[ =](?:yaml|json|jsonpath|go-template)|view-secret"

# (pattern, severity, why); severity: high = a finding on its own, cred = reads a credential store, medium = a warning
_AWS = (
    (r"\biam\s+(?:attach-(?:user|role|group)-policy|put-(?:user|role|group)-policy|create-(?:access-key|user|login-profile|policy-version)|update-(?:assume-role-policy|login-profile)|add-user-to-group|set-default-policy-version)", "high", "grants cloud permissions or creates credentials"),
    (r"\bec2\s+authorize-security-group-ingress\b[^\n]*0\.0\.0\.0/0", "high", "opens a cloud firewall to the whole internet"),
    (r"\bcloudtrail\s+(?:stop-logging|delete-trail)|\bguardduty\s+delete|\bconfig\s+stop-configuration-recorder|\bkms\s+schedule-key-deletion", "high", "switches off cloud audit or deletes keys"),
    (r"\bsecretsmanager\s+get-secret-value|\bssm\s+get-parameters?(?:-by-path)?\b[^\n]*--with-decryption|\bkms\s+decrypt|\bsts\s+get-(?:session|federation)-token", "cred", "reads cloud secrets or mints temporary credentials"),
    (r"\bsts\s+assume-role\b|\blambda\s+update-function-(?:code|configuration)|\bssm\s+(?:start-session|send-command)|\bec2\s+modify-instance-attribute\b[^\n]*user-?data", "medium", "changes what runs in the cloud or switches to another role"),
)
_GCLOUD = (
    (r"\b(?:projects|organizations|folders)\s+(?:add-iam-policy-binding|set-iam-policy)|\biam\s+service-accounts\s+(?:keys\s+create|add-iam-policy-binding|set-iam-policy)|\biam\s+roles\s+create|\bcompute\s+project-info\s+add-metadata\b[^\n]*ssh-keys|\blogging\s+sinks\s+(?:delete|update)", "high", "grants cloud permissions or creates credentials"),
    (r"\bsecrets\s+versions\s+access|\bkms\s+decrypt|print-(?:access|identity)-token", "cred", "reads cloud secrets or tokens"),
    (r"\bcompute\s+(?:ssh|scp)\b|\bfunctions\s+deploy\b", "medium", "runs commands on, or deploys code to, cloud machines"),
)
_AZ = (
    (r"\brole\s+(?:assignment|definition)\s+create|\bad\s+sp\s+(?:create-for-rbac|credential\s+reset)|\bad\s+app\s+credential\s+(?:reset|new)|\bkeyvault\s+set-policy|\bmonitor\s+diagnostic-settings\s+delete", "high", "grants cloud permissions or creates credentials"),
    (r"\bkeyvault\s+secret\s+(?:show|download)|\bstorage\s+account\s+(?:keys\s+list|show-connection-string)|list-publishing-credentials|get-access-token", "cred", "reads cloud secrets or tokens"),
    (r"\bvm\s+run-command\b|\bfunctionapp\s+deployment\b", "medium", "runs commands on, or deploys code to, cloud machines"),
)
_HISTORY_OFF = re.compile(r"(?i)\+o\s+history|\bunset\s+histfile|histfile=(?:/dev/null)?(?:\s|$)|hist(?:file)?size=0|set-psreadlineoption\b[^\n]*savenothing|disable-history")
_TRUSTED_PUBLISHERS = ("ms-", "github.", "redhat.", "golang.", "rust-lang.", "dbaeumer.", "esbenp.", "charliermarsh.", "anthropic.", "eamodio.", "hashicorp.", "vue.", "bradlc.", "editorconfig.", "streetsidesoftware.")
_DNS_TOOLS = {"nslookup", "dig", "host", "resolve-dnsname", "drill", "ping", "tracert", "test-netconnection"}
_DYNAMIC = re.compile(r"\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_]\w*|`[^`]*`|%\w+%|\$env:\w+", re.IGNORECASE)


def _table(w: _Walker, rows: tuple, joined: str, who: str) -> None:
    for pattern, kind, why in rows:
        if re.search(pattern, joined):
            line = f"{who} {why}"
            if kind == "high":
                w.a.high.append(("cloud-privilege-change", line))
            elif kind == "cred":
                w.a.cred.append(line)
            else:
                w.a.medium.append(("cloud-change", line))
            return


def _wsl_inner(texts: list[str]) -> list[str] | None:
    low = [t.lower() for t in texts]
    if "--" in texts:
        return texts[texts.index("--") + 1:]
    for i, t in enumerate(low):
        if t in ("-e", "--exec", "/e", "-exec"):
            return texts[i + 1:]
    if any(t in ("--list", "-l", "--install", "--import", "--export", "--unregister", "--shutdown", "--terminate", "-t", "--status", "--update", "--version", "--help", "--set-default", "-s", "--set-version", "--mount", "--unmount") for t in low[:1]):
        return None
    skip = False
    for i, t in enumerate(texts):
        if skip:
            skip = False
            continue
        if low[i] in ("-d", "--distribution", "-u", "--user", "--cd", "--shell-type"):
            skip = True
            continue
        if t.startswith("-"):
            continue
        return texts[i:]
    return None


def cloud(w: _Walker, cmd: str, args: list[Tok], pos: list[Tok], seg) -> None:
    a = w.a
    texts = [w.sub(t).text for t in args]
    low = [t.lower() for t in texts]
    joined = " ".join(low)
    sub = next((t for t in low if not t.startswith("-")), "")

    # --- Windows administration the older tables did not name
    if cmd == "bcdedit" and low and low[0] not in ("/enum", "/v", "-enum"):
        a.system.append("bcdedit changes the boot configuration")
    elif cmd in ("start-process", "saps", "start") and re.search(r"-verb\s+runas", joined):
        a.system.append(f"{cmd} starts a program with elevated rights (UAC)")
    elif cmd == "runas" and "/user" in joined:
        a.system.append("runas starts a program as another user")
    elif cmd in ("sc", "net", "stop-service", "set-service") and re.search(rf"\b(?:stop|delete|disabled|config)\b[^\n]*(?:{_SECURITY_SERVICES})|(?:{_SECURITY_SERVICES})[^\n]*(?:disabled|-startuptype)", joined):
        a.system.append(f"{cmd} stops or disables a security or logging service")

    # --- WSL: the part after the options is a command line for the Linux side
    if cmd == "wsl":
        inner = _wsl_inner(texts)
        if inner:
            w.recurse(" ".join(shlex.quote(t) if re.search(r"[\s|;&<>$`'\"]", t) else t for t in inner), False)
        elif low[:1] == ["--unregister"]:
            a.medium.append(("destructive-remote-op", "wsl --unregister deletes a Linux distribution and its files"))
        elif low[:1] in (["--import"], ["--install"]):
            a.medium.append(("supply-chain-source", "wsl imports or installs a Linux image"))

    # --- kubernetes
    if cmd in ("kubectl", "oc"):
        if sub in ("create", "apply", "patch", "set", "replace") and re.search(r"clusterrolebinding|rolebinding|clusterrole\b|--clusterrole|\bcluster-admin\b|\"?verbs\"?\s*[:=]\s*\[?\"?\*", joined):
            a.high.append(("cluster-privilege-grant", f"{cmd} {sub} grants cluster permissions (role binding or cluster-admin)"))
        if sub in ("run", "create", "apply", "debug", "patch", "replace") and re.search(_K8S_HOST, joined) or sub == "debug" and "node/" in joined:
            a.persist.append(f"container started through {cmd} with host-level settings (privileged, host PID/network or a host path)")
        if sub == "create" and "token" in low[1:3]:
            a.cred.append(f"{cmd} create token mints a service-account token")
        if re.search(r"\bsecrets?\b|view-secret", joined) and sub in ("get", "describe", "view-secret", "krew"):
            if re.search(_K8S_FORMATS, joined) and (seg.piped_to_next or any(op in (">", ">>", ">|", "&>") for op, _ in seg.redirects)):
                a.high.append(("cluster-secret-dump", f"{cmd} dumps cluster secrets to a file or pipe"))
            else:
                a.cred.append(f"{cmd} reads cluster secrets")
    # --- containers and registries
    if cmd in ("docker", "podman", "nerdctl", "helm", "az", "skopeo", "crane", "oras") and sub == "login" and any(
            t in ("-p", "--password") or t.startswith("--password=") for t in low) and not re.search(r"-p\s+\$|--password[ =]\$", joined):
        a.medium.append(("credential-on-command-line", f"{cmd} login passes a password on the command line (it lands in history and process lists)"))

    # --- git: history rewriting, plaintext credential store, URL rewriting
    if cmd == "git":
        if sub in ("filter-branch", "filter-repo") or (sub == "reflog" and "expire" in low and any("now" in t for t in low)) or (sub == "gc" and any(t.startswith("--prune=now") for t in low)) or (
                sub == "update-ref" and "-d" in low):
            a.medium.append(("history-rewrite", f"git {sub} rewrites or erases repository history"))
        if "credential.helper" in joined and re.search(r"credential\.helper\W+(?:store|cache\s+--timeout[ =]\d{6,})", joined):
            a.medium.append(("credential-plaintext", "git credential.helper store keeps passwords in a plain file"))
        if "insteadof" in joined:
            from .shell import ShellOp, host_of

            for t in texts:
                h = host_of(t) if "://" in t else None
                if h:
                    a.ops.append(ShellOp("net", h, w.cwd, "git url rewrite", upload=True, supply=True))

    # --- cloud CLIs
    if cmd == "aws":
        _table(w, _AWS, joined, "aws")
        words = [t for t in low if not t.startswith("-")]
        downloads = re.search(r"\bs3\s+(?:sync|cp)\b", joined) and len(words) >= 4 and words[-2].startswith("s3://") and not words[-1].startswith("s3://")
        if downloads and re.match(r"(?:/tmp/|/var/tmp/|/dev/shm/|[a-z]:/users/public|%temp%|\$temp|~/downloads)", words[-1].replace("\\", "/")):
            a.medium.append(("bulk-download", "aws downloads bucket contents into a temp folder"))
    elif cmd == "gcloud":
        _table(w, _GCLOUD, joined, "gcloud")
    elif cmd == "az":
        _table(w, _AZ, joined, "az")

    # --- shell history switched off
    if cmd in ("set", "export", "unset", "declare", "typeset", "set-psreadlineoption", "disable-history") and _HISTORY_OFF.search(joined):
        a.medium.append(("log-tamper", "shell history is switched off for this session"))

    # --- names that carry data out through DNS
    if cmd in _DNS_TOOLS:
        from .shell import ShellOp

        for t in texts:
            if re.search(r"[$`%]", t):
                rest = _DYNAMIC.sub("", t).strip(".")
                if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", rest.lower()):
                    a.ops.append(ShellOp("net", rest.lower(), w.cwd, f"{cmd} (data in the name)", upload=True))

    # --- editor extensions run code inside the editor
    if cmd in ("code", "code-insiders", "cursor", "windsurf", "codium") and "--install-extension" in low:
        for i, t in enumerate(low):
            if t == "--install-extension" and i + 1 < len(low) and not low[i + 1].startswith(_TRUSTED_PUBLISHERS):
                a.medium.append(("editor-extension-install", f"{cmd} installs the extension {texts[i + 1][:50]!r}, which runs code inside the editor"))

    # --- package scripts set from the command line are analysed like the file would be
    if cmd in ("npm", "pnpm", "yarn") and low[:2] == ["pkg", "set"]:
        for t in texts[2:]:
            key, _, value = t.partition("=")
            if key.lower().startswith("scripts.") and value:
                shell_extra.analyse_text(w, value, "sh", f"npm pkg set {key[:30]}")
