from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from litestar.security import AuthenticationResult

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.openapi.spec import Components, SecurityRequirement
    from litestar.security import AuthenticationContext


class StubAuthMechanism:
    __slots__ = ("calls", "result")

    name: ClassVar[str] = "stub"

    def __init__(self, result: AuthenticationResult | None = None, *, should_decline: bool = False) -> None:
        self.result = (
            None
            if should_decline
            else result or AuthenticationResult(user={"id": "stub-user"}, auth={"scheme": self.name})
        )
        self.calls: list[tuple[ASGIConnection[Any, Any, Any, Any], AuthenticationContext]] = []

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        self.calls.append((connection, context))
        return self.result

    def openapi_components(self) -> Components | None:
        return None

    def openapi_security_requirement(self) -> SecurityRequirement | None:
        return None


class MissingNameAuthMechanism:
    __slots__ = ()

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        return None

    def openapi_components(self) -> Components | None:
        return None

    def openapi_security_requirement(self) -> SecurityRequirement | None:
        return None


class MissingAuthenticateAuthMechanism:
    __slots__ = ()

    name: ClassVar[str] = "missing-authenticate"

    def openapi_components(self) -> Components | None:
        return None

    def openapi_security_requirement(self) -> SecurityRequirement | None:
        return None
