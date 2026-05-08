from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ("AuthenticationContext",)


@dataclass(slots=True)
class AuthenticationContext:
    """Shared per-connection state passed to authentication mechanisms.

    The JWKS cache is populated by later security-plugin chapters. Until then it
    remains optional so custom mechanisms can depend on the context contract
    without requiring token-verification infrastructure.
    """

    jwks_cache: Any | None = None
    """Shared JWKS cache for token-verifying mechanisms."""
    settings: Any = None
    """Security plugin settings shared by all mechanisms for the connection."""
    _extras: dict[str, Any] = field(default_factory=dict)
    """Internal scratch space for mechanisms that need to share per-connection data."""
