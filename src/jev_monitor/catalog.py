"""Static lists and small pure helpers for the round-3 rules: popular package names, known runners, secret-looking
literals, secret-bearing path text. No I/O, no policy; the shell analyser and the checker both import from here."""

from __future__ import annotations

import re

# --- package typosquatting -------------------------------------------------------------------------------------
PIP_POPULAR = frozenset(
    [
        "requests",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "flask",
        "django",
        "fastapi",
        "pydantic",
        "pytest",
        "setuptools",
        "wheel",
        "boto3",
        "botocore",
        "urllib3",
        "certifi",
        "idna",
        "charset-normalizer",
        "cryptography",
        "pyyaml",
        "jinja2",
        "markupsafe",
        "click",
        "colorama",
        "attrs",
        "packaging",
        "typing-extensions",
        "six",
        "python-dateutil",
        "pytz",
        "sqlalchemy",
        "psycopg2",
        "aiohttp",
        "httpx",
        "beautifulsoup4",
        "lxml",
        "pillow",
        "scikit-learn",
        "tensorflow",
        "torch",
        "transformers",
        "openai",
        "anthropic",
        "langchain",
        "uvicorn",
        "gunicorn",
        "celery",
        "redis",
        "pymongo",
        "selenium",
        "playwright",
        "black",
        "ruff",
        "mypy",
        "pylint",
        "flake8",
        "tox",
        "poetry",
        "pipenv",
        "virtualenv",
        "twine",
        "cffi",
        "pycparser",
        "rsa",
        "pyasn1",
        "protobuf",
        "grpcio",
        "google-auth",
        "awscli",
        "azure-core",
        "tqdm",
        "rich",
        "typer",
        "tabulate",
        "docker",
        "paramiko",
        "fabric",
        "openpyxl",
        "xlrd",
        "pyjwt",
        "bcrypt",
        "passlib",
        "werkzeug",
        "tornado",
        "starlette",
        "alembic",
        "sphinx",
        "coverage",
        "pytest-cov",
        "hypothesis",
        "numba",
        "keras",
        "jupyter",
        "ipython",
    ]
)

NPM_POPULAR = frozenset(
    [
        "react",
        "react-dom",
        "lodash",
        "express",
        "axios",
        "moment",
        "chalk",
        "commander",
        "debug",
        "typescript",
        "webpack",
        "babel-core",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "vue",
        "angular",
        "next",
        "nuxt",
        "svelte",
        "vite",
        "rollup",
        "tailwindcss",
        "postcss",
        "autoprefixer",
        "dotenv",
        "uuid",
        "yargs",
        "request",
        "async",
        "bluebird",
        "underscore",
        "jquery",
        "body-parser",
        "cors",
        "mongoose",
        "sequelize",
        "passport",
        "jsonwebtoken",
        "bcrypt",
        "bcryptjs",
        "socket.io",
        "ws",
        "redux",
        "react-redux",
        "rxjs",
        "zod",
        "prisma",
        "fs-extra",
        "glob",
        "rimraf",
        "mkdirp",
        "semver",
        "minimist",
        "inquirer",
        "ora",
        "nodemon",
        "concurrently",
        "cross-env",
        "husky",
        "lint-staged",
        "ts-node",
        "tsx",
        "vitest",
        "cypress",
        "playwright",
        "puppeteer",
        "node-fetch",
        "cheerio",
        "dayjs",
        "date-fns",
        "classnames",
        "styled-components",
        "formik",
        "yup",
        "immer",
        "swr",
        "graphql",
        "apollo-server",
        "electron",
    ]
)

# programs that are routinely launched through npx/bunx/uvx/dlx without being installed first
KNOWN_RUNNERS = frozenset(
    [
        "prettier",
        "eslint",
        "tsc",
        "typescript",
        "vite",
        "jest",
        "vitest",
        "mocha",
        "next",
        "nuxt",
        "nx",
        "turbo",
        "tsx",
        "ts-node",
        "playwright",
        "cypress",
        "degit",
        "rimraf",
        "serve",
        "http-server",
        "concurrently",
        "npm-check-updates",
        "ncu",
        "tailwindcss",
        "prisma",
        "drizzle-kit",
        "nodemon",
        "husky",
        "lint-staged",
        "biome",
        "wrangler",
        "vercel",
        "netlify-cli",
        "expo",
        "storybook",
        "create-react-app",
        "create-next-app",
        "create-vite",
        "create-vue",
        "create-t3-app",
        "ruff",
        "black",
        "mypy",
        "pytest",
        "pip-audit",
        "uv",
        "poetry",
        "tox",
        "httpie",
        "pre-commit",
        "cowsay",
        "yarn",
        "pnpm",
        "npm",
        "playwright-core",
        "eslint_d",
        "stylelint",
        "markdownlint-cli",
        "tsup",
        "esbuild",
        "rollup",
        "webpack",
        "astro",
        "sv",
        "svelte-kit",
        "gatsby",
    ]
)


def _one_edit(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance exactly 1: one insert, delete, replace or adjacent swap."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    s, t = (a, b) if la < lb else (b, a)
    return any(t[:i] + t[i + 1 :] == s for i in range(len(t)))


def typosquat_of(name: str, popular: frozenset[str]) -> str | None:
    """The popular package this name is one typo away from, or None. Short names are skipped (too many real neighbours)."""
    n = name.lower().replace("_", "-").replace(".", "-")
    if len(n) < 5 or n in popular:
        return None
    for p in popular:
        if len(p) >= 5 and _one_edit(n, p):
            return p
    return None


# --- literals and path text -------------------------------------------------------------------------------------
SECRET_LITERAL = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b|sk-ant-[A-Za-z0-9_-]{20,}|"
    r"\bsk-[A-Za-z0-9]{32,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b|\bnpm_[A-Za-z0-9]{36}\b|\bglpat-[A-Za-z0-9_-]{20}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----|\bhf_[A-Za-z0-9]{34}\b|\bpypi-[A-Za-z0-9_-]{50,}"
)

_HOME = r"(?:~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|%USERPROFILE%|/home/[\w.-]+|/Users/[\w.-]+|[A-Za-z]:[\\/]Users[\\/][\w.-]+)"
SECRET_TEXT = re.compile(
    rf"{_HOME}[\\/]\.(?:ssh|aws|gnupg|docker|kube|azure|config[\\/]gh|config[\\/]gcloud|npmrc|netrc|pypirc|git-credentials)\b|"
    r"(?<![\w.-])\.env(?:\.(?!example|sample|template|dist)[\w-]+)?(?![\w./-])|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.(?:pem|pfx|p12|kdbx)\b|credentials\.json|\bapplication_default_credentials"
)
SECRET_PATTERN = re.compile(
    r"(?i)\.pem\b|id_rsa|id_ed25519|\.kdbx|\.pfx|\.env\b|credentials|private key|password|secret|token|\.npmrc|\.netrc|AKIA|api[_-]?key"
)
STAGE_TEXT = re.compile(
    r"(?i)(?:^|[\s'\"=:(])(?:/tmp/|/var/tmp/|/dev/shm/|\$TEMP\b|\$env:TEMP\b|%TEMP%|%TMP%|\$TMPDIR|[A-Za-z]:[\\/]Users[\\/]Public\b|~/Downloads|\$HOME/Downloads)|[\\/]Temp[\\/]"
)
REDIRECT_VARS = re.compile(
    r"(?i)^(?:(?:ANTHROPIC|OPENAI|GOOGLE|GEMINI|MISTRAL|COHERE)_(?:BASE_URL|API_BASE|API_URL|ENDPOINT)|https?_proxy|all_proxy)$"
)

HIDDEN_CHARS = re.compile("[\u200b\u2060\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
CI_FILES = re.compile(
    r"(?i)(?:^|/)(?:\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|\.circleci/config\.ya?ml|bitbucket-pipelines\.ya?ml)$"
)
CI_RISK = re.compile(
    r"(?i)pull_request_target|(?:curl|wget|iwr|irm)[^\n]*\|\s*(?:ba|z)?sh\b|toJSON\(\s*secrets\s*\)|secrets\.[A-Z0-9_]+[^\n]*(?:curl|wget|nc |base64)|"
    r"(?:curl|wget)[^\n]*secrets\.|echo\s+[^\n]*secrets\.[A-Z0-9_]+[^\n]*>>?\s*\S|webhook\.site|requestbin|pipedream\.net|ngrok"
)

AGENT_CLIS = frozenset(
    {
        "claude",
        "gemini",
        "codex",
        "q",
        "amazon-q",
        "cursor-agent",
        "aider",
        "opencode",
        "goose",
        "qwen",
        "copilot",
        "crush",
    }
)
AGENT_BYPASS_FLAGS = frozenset(
    {
        "--dangerously-skip-permissions",
        "--yolo",
        "--trust-all-tools",
        "--dangerously-bypass-approvals-and-sandbox",
        "--allow-all-tools",
        "--auto-approve",
        "--dangerously-allow-all",
        "--allow-dangerously-skip-permissions",
        "--yes-always",
    }
)
SUBAGENT_RISK = re.compile(
    r"(?i)(?:curl|wget|iwr|irm)[^\n]{0,200}\|\s*(?:ba|z)?sh\b|rm\s+-rf?\s+(?:~|/|\$HOME)\b|"
    r"(?:disable|stop|kill|turn\s+off|bypass|uninstall|silence)\s+(?:the\s+)?(?:jev[- ]?)?(?:monitor|hooks?|guard|safety)|"
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+(?:instructions|rules)|(?:delete|clear|wipe)\s+(?:the\s+)?(?:logs?|history)\b|"
    r"169\.254\.169\.254|--dangerously-skip-permissions|(?:upload|send|post|exfiltrate|curl)[^\n]{0,80}(?:\.ssh|\.aws|id_rsa|\.env\b)"
)

CRED_READ = (
    ("cmdkey", None, r"/list|/l\b"),
    ("vaultcmd", None, r"/list"),
    ("security", None, r"find-(?:generic|internet)-password|dump-keychain"),
    ("gh", "auth", r"\btoken\b|--show-token|\s-t\b"),
    ("aws", None, r"configure\s+(?:get|export)|export-credentials|get-session-token"),
    ("secret-tool", None, r"lookup|search"),
    ("pass", "show", r""),
    ("op", None, r"\bread\b|item\s+get|--reveal"),
    ("gcloud", None, r"print-(?:access|identity)-token"),
    ("az", None, r"get-access-token"),
    ("keyctl", None, r"print|read"),
    ("vault", None, r"\bread\b|kv\s+get"),
    ("lazagne", None, r""),
    ("mimikatz", None, r""),
    ("get-storedcredential", None, r""),
)

# a download-and-run line sitting inside text (an echo into a script, a heredoc): not executed now, but written down to run later
DROPPER_TEXT = re.compile(
    r"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(?:iex|(?:ba|z)?sh|python3?|powershell|pwsh)\b"
)
SCRIPT_EXT = (
    ".sh",
    ".bash",
    ".zsh",
    ".bat",
    ".cmd",
    ".ps1",
    ".py",
    ".js",
    ".vbs",
    ".rb",
    ".pl",
    ".yml",
    ".yaml",
    ".json",
)
