from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.openapi.spec import Components, SecurityRequirement
    from litestar.security._context import AuthenticationContext
    from litestar.security.types import AuthenticationResult

__all__ = ("AuthMechanism",)


@runtime_checkable
class AuthMechanism(Protocol):
    """A single authentication mechanism plugged into ``SecurityPlugin``.

    Mechanisms are tried in order on each request. Returning ``None`` declines
    the request and lets the next mechanism try. Raising a Litestar authentication
    exception is reserved for credentials that matched this mechanism but failed
    validation.
    """

    __slots__ = ()

    name: ClassVar[str]
    """Stable identifier for per-route mechanism selection."""

    async def authenticate(
        self,
        connection: ASGIConnection,
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        """Try to authenticate the connection.

        Args:
            connection: The current ASGI connection.
            context: Per-connection state shared across mechanisms.

        Returns:
            An authentication result when the mechanism succeeds, or ``None`` to decline.
        """
        ...

    def openapi_components(self) -> Components | None:
        """Return OpenAPI components contributed by this mechanism.

        Returns:
            Components containing security schemes, or ``None`` when no components are contributed.
        """
        ...

    def openapi_security_requirement(self) -> SecurityRequirement | None:
        """Return the OpenAPI security requirement contributed by this mechanism.

        Returns:
            A security requirement for protected operations, or ``None`` when no requirement is contributed.
        """
        ...
