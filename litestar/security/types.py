from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ("AuthenticationResult",)


@dataclass
class AuthenticationResult:
    """The result of an authentication mechanism.

    Returned from :class:`AuthMechanism <litestar.security.AuthMechanism>` implementations
    when a request has been successfully authenticated. The values are written onto the
    ASGI scope as ``scope["user"]`` and ``scope["auth"]`` and become available on the
    connection as :attr:`connection.user <litestar.connection.ASGIConnection.user>` and
    :attr:`connection.auth <litestar.connection.ASGIConnection.auth>`.
    """

    __slots__ = ("auth", "user")

    user: Any
    """The user model. Any value identifying the authenticated principal."""
    auth: Any
    """The credential that proved the authentication, e.g. a decoded JWT or session id."""
