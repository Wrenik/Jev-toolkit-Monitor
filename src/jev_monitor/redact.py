"""Redaction before text is logged or leaves the machine for the judge: the shared `jev_core.redact`.

Best effort, not a guarantee.
"""

from __future__ import annotations

from jev_core.redact import redact as _redact


def redact(text: str) -> str:
    return _redact(text)[0]


def short(text: str, limit: int = 160) -> str:
    """One redacted line, clipped. For logs and judge prompts."""
    one = " ".join(redact(text).split())
    return one if len(one) <= limit else one[: limit - 3] + "..."
