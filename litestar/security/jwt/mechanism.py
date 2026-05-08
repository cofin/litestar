from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, cast

import jwt
from typing_extensions import TypeVar

from litestar.datastructures import Cookie
from litestar.enums import MediaType
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.response import Response
from litestar.security.jwt.jwks import JWKSCache, OIDCProvider, invoke_validation_error_hook
from litestar.security.jwt.token import Token
from litestar.security.types import AuthenticationResult
from litestar.status_codes import HTTP_201_CREATED
from litestar.types import Empty
from litestar.utils import ensure_async_callable

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from litestar.connection import ASGIConnection
    from litestar.security import AuthenticationContext
    from litestar.types import SyncOrAsyncUnion

__all__ = ("JWTCookieMechanism", "JWTMechanism")

UserType = TypeVar("UserType")
TokenT = TypeVar("TokenT", bound=Token, default=Token)

_AUTH_SCHEME = "Bearer"


def _default_token_cls() -> type[Token]:
    return Token


@dataclass(slots=True)
class JWTMechanism(Generic[UserType, TokenT]):
    """JWT authentication mechanism for :class:`SecurityPlugin <litestar.security.SecurityPlugin>`."""

    name: ClassVar[str] = "jwt"

    retrieve_user_handler: Callable[[TokenT, ASGIConnection[Any, Any, Any, Any]], SyncOrAsyncUnion[UserType | None]]
    token_secret: str | bytes | None = None
    revoked_token_handler: Callable[[TokenT, ASGIConnection[Any, Any, Any, Any]], SyncOrAsyncUnion[bool]] | None = None
    oidc_provider: OIDCProvider | None = None
    algorithm: str = "HS256"
    auth_header: str = "Authorization"
    default_token_expiration: timedelta = field(default_factory=lambda: timedelta(days=1))
    openapi_security_scheme_name: str = "BearerToken"
    description: str = "JWT bearer authentication and authorization."
    token_cls: type[TokenT] = field(default_factory=lambda: cast("type[TokenT]", _default_token_cls()))
    accepted_audiences: Sequence[str] | str | None = None
    accepted_issuers: Sequence[str] | str | None = None
    require_claims: Sequence[str] | None = None
    verify_expiry: bool = True
    verify_not_before: bool = True
    strict_audience: bool = False
    leeway: float | timedelta = 0
    _retrieve_user_handler: Callable[[TokenT, ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]] = field(
        init=False,
        repr=False,
    )
    _revoked_token_handler: Callable[[TokenT, ASGIConnection[Any, Any, Any, Any]], Awaitable[bool]] | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.token_secret is None and self.oidc_provider is None:
            raise ImproperlyConfiguredException("JWTMechanism requires either 'token_secret' or 'oidc_provider'")
        self._retrieve_user_handler = cast(
            "Callable[[TokenT, ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]]",
            ensure_async_callable(self.retrieve_user_handler),
        )
        if self.revoked_token_handler is not None:
            self._revoked_token_handler = cast(
                "Callable[[TokenT, ASGIConnection[Any, Any, Any, Any]], Awaitable[bool]]",
                ensure_async_callable(self.revoked_token_handler),
            )

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        """Authenticate a connection using a bearer token from the configured header."""
        encoded_token = self.get_encoded_token(connection)
        if encoded_token is None:
            return None
        return await self.authenticate_token(encoded_token=encoded_token, connection=connection, context=context)

    async def authenticate_token(
        self,
        encoded_token: str,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext | None = None,
    ) -> AuthenticationResult:
        """Decode a JWT, load the user, and return an authentication result."""
        token = await self.decode_token(encoded_token=encoded_token, context=context)
        user = await self._retrieve_user_handler(token, connection)
        token_revoked = await self._revoked_token_handler(token, connection) if self._revoked_token_handler else False
        if user is None or token_revoked:
            raise NotAuthorizedException("Invalid token")
        return AuthenticationResult(user=user, auth=token)

    async def decode_token(self, encoded_token: str, context: AuthenticationContext | None = None) -> TokenT:
        """Decode a JWT using either a configured secret or OIDC JWKS provider."""
        provider = self.oidc_provider
        try:
            if provider is not None:
                jwks_cache = self._resolve_jwks_cache(context)
                jwks_uri = await provider.resolve_jwks_uri(jwks_cache)
                signing_key = await jwks_cache.get_signing_key(
                    encoded_token,
                    jwks_uri,
                    algorithms=provider.algorithms,
                    ttl=provider.cache_ttl,
                )
                algorithm = cast("str", jwt.get_unverified_header(encoded_token)["alg"])
                return self.token_cls.decode(
                    encoded_token=encoded_token,
                    secret=signing_key.key,
                    algorithm=algorithm,
                    audience=provider.audience,
                    issuer=provider.normalized_issuer,
                    require_claims=self.require_claims,
                    verify_exp=self.verify_expiry,
                    verify_nbf=self.verify_not_before,
                    strict_audience=self.strict_audience,
                    leeway=provider.clock_skew,
                )

            return self.token_cls.decode(
                encoded_token=encoded_token,
                secret=self._get_token_secret(),
                algorithm=self.algorithm,
                audience=self.accepted_audiences,
                issuer=self.accepted_issuers,
                require_claims=self.require_claims,
                verify_exp=self.verify_expiry,
                verify_nbf=self.verify_not_before,
                strict_audience=self.strict_audience,
                leeway=self.leeway,
            )
        except NotAuthorizedException as exc:
            if provider and provider.on_validation_error:
                await invoke_validation_error_hook(provider.on_validation_error, provider.issuer, exc)
            raise
        except Exception as exc:
            if provider and provider.on_validation_error:
                await invoke_validation_error_hook(provider.on_validation_error, provider.issuer, exc)
            raise NotAuthorizedException("Invalid token") from exc

    def get_encoded_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Extract an encoded JWT from the configured header."""
        return self._extract_bearer_token(connection.headers.get(self.auth_header))

    def create_token(
        self,
        identifier: str,
        token_expiration: timedelta | None = None,
        token_issuer: str | None = None,
        token_audience: str | Sequence[str] | None = None,
        token_unique_jwt_id: str | None = None,
        token_extras: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> str:
        """Create and encode a JWT for a subject identifier."""
        token = self.token_cls(
            sub=identifier,
            exp=datetime.now(UTC) + (token_expiration or self.default_token_expiration),
            iss=token_issuer,
            aud=token_audience,
            jti=token_unique_jwt_id,
            extras=token_extras or {},
            **kwargs,
        )
        return token.encode(secret=self._get_token_secret(), algorithm=self.algorithm, headers=headers)

    def login(
        self,
        identifier: str,
        *,
        response_body: Any = Empty,
        response_media_type: str | MediaType = MediaType.JSON,
        response_status_code: int = HTTP_201_CREATED,
        token_expiration: timedelta | None = None,
        token_issuer: str | None = None,
        token_audience: str | Sequence[str] | None = None,
        token_unique_jwt_id: str | None = None,
        token_extras: dict[str, Any] | None = None,
        send_token_as_response_body: bool = False,
    ) -> Response[Any]:
        """Create a login response carrying a JWT in the configured auth header."""
        encoded_token = self.create_token(
            identifier=identifier,
            token_expiration=token_expiration,
            token_issuer=token_issuer,
            token_audience=token_audience,
            token_unique_jwt_id=token_unique_jwt_id,
            token_extras=token_extras,
        )
        return self.create_login_response(
            encoded_token=encoded_token,
            response_body=response_body,
            response_media_type=response_media_type,
            response_status_code=response_status_code,
            send_token_as_response_body=send_token_as_response_body,
        )

    def create_login_response(
        self,
        *,
        encoded_token: str,
        response_body: Any = Empty,
        response_media_type: str | MediaType = MediaType.JSON,
        response_status_code: int = HTTP_201_CREATED,
        send_token_as_response_body: bool = False,
    ) -> Response[Any]:
        """Build a response for login helpers."""
        if response_body is not Empty:
            body = response_body
        elif send_token_as_response_body:
            body = {"token": encoded_token}
        else:
            body = None

        return Response(
            content=body,
            headers={self.auth_header: self.format_auth_header(encoded_token)},
            media_type=response_media_type,
            status_code=response_status_code,
        )

    def format_auth_header(self, encoded_token: str) -> str:
        """Format a token for use in the configured auth header."""
        return f"{_AUTH_SCHEME} {encoded_token}"

    def openapi_components(self) -> Components:
        """Return this mechanism's OpenAPI security scheme."""
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="http",
                    scheme="bearer",
                    bearer_format="JWT",
                    description=self.description,
                )
            }
        )

    def openapi_security_requirement(self) -> SecurityRequirement:
        """Return this mechanism's OpenAPI security requirement."""
        return {self.openapi_security_scheme_name: []}

    @property
    def uses_jwks(self) -> bool:
        """Return whether this mechanism needs a shared JWKS cache."""
        return self.oidc_provider is not None

    def _get_token_secret(self) -> str | bytes:
        if self.token_secret is None:
            raise ImproperlyConfiguredException("JWTMechanism requires 'token_secret' when no OIDC provider is set")
        return self.token_secret

    @staticmethod
    def _resolve_jwks_cache(context: AuthenticationContext | None) -> JWKSCache:
        if context is not None and isinstance(context.jwks_cache, JWKSCache):
            return context.jwks_cache
        return JWKSCache()

    @staticmethod
    def _extract_bearer_token(auth_value: str | None) -> str | None:
        if auth_value is None:
            return None
        scheme, separator, encoded_token = auth_value.partition(" ")
        if not separator or scheme.lower() != _AUTH_SCHEME.lower():
            raise NotAuthorizedException("Invalid token")
        encoded_token = encoded_token.strip()
        if not encoded_token:
            raise NotAuthorizedException("Invalid token")
        return encoded_token


@dataclass(slots=True)
class JWTCookieMechanism(JWTMechanism[UserType, TokenT]):
    """JWT mechanism that accepts bearer headers or a JWT-bearing cookie."""

    name: ClassVar[str] = "jwt-cookie"

    key: str = "token"
    path: str = "/"
    domain: str | None = None
    secure: bool | None = None
    samesite: Literal["lax", "strict", "none"] = "lax"
    description: str = "JWT cookie authentication and authorization."
    openapi_security_scheme_name: str = "CookieToken"

    def get_encoded_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Extract an encoded JWT from the auth header or configured cookie."""
        header_token = self._extract_bearer_token(connection.headers.get(self.auth_header))
        if header_token is not None:
            return header_token
        if self.key not in connection.cookies:
            return None
        return self._extract_cookie_token(connection.cookies[self.key])

    def create_login_response(
        self,
        *,
        encoded_token: str,
        response_body: Any = Empty,
        response_media_type: str | MediaType = MediaType.JSON,
        response_status_code: int = HTTP_201_CREATED,
        send_token_as_response_body: bool = False,
    ) -> Response[Any]:
        """Build a login response carrying the JWT in a header and HTTP-only cookie."""
        response = super(JWTCookieMechanism, self).create_login_response(
            encoded_token=encoded_token,
            response_body=response_body,
            response_media_type=response_media_type,
            response_status_code=response_status_code,
            send_token_as_response_body=send_token_as_response_body,
        )
        response.set_cookie(
            Cookie(
                key=self.key,
                path=self.path,
                value=encoded_token,
                max_age=int(self.default_token_expiration.total_seconds()),
                domain=self.domain,
                secure=self.secure,
                httponly=True,
                samesite=self.samesite,
            )
        )
        return response

    def openapi_components(self) -> Components:
        """Return this mechanism's OpenAPI cookie security scheme."""
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="apiKey",
                    name=self.key,
                    security_scheme_in="cookie",
                    description=self.description,
                )
            }
        )

    @staticmethod
    def _extract_cookie_token(cookie_value: str) -> str:
        cookie_value = cookie_value.strip()
        if not cookie_value:
            raise NotAuthorizedException("Invalid token")

        scheme, separator, encoded_token = cookie_value.partition(" ")
        if separator and scheme.lower() == _AUTH_SCHEME.lower():
            cookie_value = encoded_token.strip()
        if not cookie_value:
            raise NotAuthorizedException("Invalid token")
        return cookie_value
