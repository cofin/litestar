from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, cast

from typing_extensions import TypeVar

from litestar.exceptions import NotAuthorizedException
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.security.types import AuthenticationResult
from litestar.utils import ensure_async_callable

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from litestar.connection import ASGIConnection
    from litestar.security import AuthenticationContext
    from litestar.types import SyncOrAsyncUnion

__all__ = ("APIKey", "APIKeyLocation", "APIKeyMechanism")

UserType = TypeVar("UserType")

_WWW_AUTHENTICATE_API_KEY = {"WWW-Authenticate": "ApiKey"}


class APIKeyLocation(StrEnum):
    """Supported API key extraction locations."""

    HEADER = "header"
    QUERY = "query"
    COOKIE = "cookie"


@dataclass(frozen=True, slots=True)
class APIKey:
    """Authenticated API key metadata."""

    value: str
    """Raw API key value."""
    location: APIKeyLocation
    """Location from which the API key was extracted."""
    name: str
    """Header, query parameter, or cookie name used for extraction."""


@dataclass(slots=True)
class APIKeyMechanism(Generic[UserType]):
    """API key authentication mechanism for :class:`SecurityPlugin <litestar.security.SecurityPlugin>`."""

    name: ClassVar[str] = "api_key"

    validate_key_handler: Callable[[str, ASGIConnection[Any, Any, Any, Any]], SyncOrAsyncUnion[UserType | None]]
    location: APIKeyLocation = APIKeyLocation.HEADER
    key_name: str = ""
    openapi_security_scheme_name: str = "APIKey"
    description: str = "API key authentication."
    _validate_key_handler: Callable[[str, ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self.location = APIKeyLocation(self.location)
        if not self.key_name:
            self.key_name = "X-API-Key" if self.location is APIKeyLocation.HEADER else "api_key"
        self._validate_key_handler = cast(
            "Callable[[str, ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]]",
            ensure_async_callable(self.validate_key_handler),
        )

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        """Authenticate a connection using an API key from the configured location."""
        del context
        api_key = self.get_api_key(connection)
        if not api_key:
            return None

        user = await self._validate_key_handler(api_key, connection)
        if user is None:
            raise NotAuthorizedException("Invalid API key", headers=_WWW_AUTHENTICATE_API_KEY)
        return AuthenticationResult(user=user, auth=APIKey(value=api_key, location=self.location, name=self.key_name))

    def get_api_key(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Extract the API key from the configured connection location."""
        if self.location is APIKeyLocation.HEADER:
            return connection.headers.get(self.key_name)
        if self.location is APIKeyLocation.QUERY:
            return connection.query_params.get(self.key_name)
        return connection.cookies.get(self.key_name)

    def openapi_components(self) -> Components:
        """Return this mechanism's OpenAPI API key security scheme."""
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="apiKey",
                    name=self.key_name,
                    security_scheme_in=self._openapi_location(),
                    description=self.description,
                )
            }
        )

    def openapi_security_requirement(self) -> SecurityRequirement:
        """Return this mechanism's OpenAPI security requirement."""
        return {self.openapi_security_scheme_name: []}

    def _openapi_location(self) -> Literal["query", "header", "cookie"]:
        if self.location is APIKeyLocation.HEADER:
            return "header"
        if self.location is APIKeyLocation.QUERY:
            return "query"
        return "cookie"
