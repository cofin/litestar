from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Generic, cast

from typing_extensions import TypeVar

from litestar.exceptions import NotAuthorizedException
from litestar.middleware.session.base import BaseBackendConfig, BaseSessionBackendT
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.security.types import AuthenticationResult
from litestar.types import Empty
from litestar.utils import ensure_async_callable

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from litestar.connection import ASGIConnection
    from litestar.middleware.base import DefineMiddleware
    from litestar.security import AuthenticationContext
    from litestar.types import SyncOrAsyncUnion

__all__ = ("SessionMechanism",)

UserType = TypeVar("UserType")


@dataclass(slots=True)
class SessionMechanism(Generic[UserType, BaseSessionBackendT]):
    """Session authentication mechanism for :class:`SecurityPlugin <litestar.security.SecurityPlugin>`."""

    name: ClassVar[str] = "session"

    session_backend_config: BaseBackendConfig[BaseSessionBackendT]
    retrieve_user_handler: Callable[
        [dict[str, Any], ASGIConnection[Any, Any, Any, Any]], SyncOrAsyncUnion[UserType | None]
    ]
    openapi_security_scheme_name: str = "sessionCookie"
    description: str = "Session cookie authentication."
    _retrieve_user_handler: Callable[
        [dict[str, Any], ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]
    ] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self._retrieve_user_handler = cast(
            "Callable[[dict[str, Any], ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]]",
            ensure_async_callable(self.retrieve_user_handler),
        )

    @property
    def middleware(self) -> DefineMiddleware:
        """Return the session middleware required to load ``connection.session`` before authentication."""
        return self.session_backend_config.middleware

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        """Authenticate a connection using session data loaded by session middleware."""
        del context
        session = connection.session
        if session is Empty or not session:
            connection.scope["session"] = Empty
            raise NotAuthorizedException("no session data found")

        user = await self._retrieve_user_handler(session, connection)
        if user is None:
            connection.scope["session"] = Empty
            raise NotAuthorizedException("no user correlating to session found")
        return AuthenticationResult(user=user, auth=session)

    def openapi_components(self) -> Components:
        """Return this mechanism's OpenAPI session-cookie security scheme."""
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="apiKey",
                    name=self.session_backend_config.key,
                    security_scheme_in="cookie",
                    description=self.description,
                )
            }
        )

    def openapi_security_requirement(self) -> SecurityRequirement:
        """Return this mechanism's OpenAPI security requirement."""
        return {self.openapi_security_scheme_name: []}
