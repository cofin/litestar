from __future__ import annotations

__all__ = ("OPT_AUTH_MECHANISM", "OPT_EXCLUDE_FROM_AUTH")

OPT_AUTH_MECHANISM = "auth_mechanism"
"""Route handler ``opt`` key that forces a specific authentication mechanism."""

OPT_EXCLUDE_FROM_AUTH = "exclude_from_auth"
"""Route handler ``opt`` key that excludes a route from security authentication."""
