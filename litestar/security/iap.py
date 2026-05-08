from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Generic, cast

import jwt
from jwt.exceptions import PyJWTError
from typing_extensions import TypeVar

from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, PermissionDeniedException
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.response import Response
from litestar.security.jwt import JWKSCache, JWKSError, JWTMechanism, Token
from litestar.security.types import AuthenticationResult
from litestar.status_codes import HTTP_201_CREATED
from litestar.types import Empty
from litestar.utils import ensure_async_callable

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence
    from datetime import timedelta

    from litestar.connection import ASGIConnection, Request
    from litestar.security import AuthenticationContext
    from litestar.types import SyncOrAsyncUnion

__all__ = (
    "IAP_AUTH_HEADER_KEY",
    "IAP_ISSUER",
    "IAP_JWKS_URI",
    "IAPMechanism",
    "IAPSessionHandler",
    "IAPToken",
    "iap_session_handler",
)

IAP_AUTH_HEADER_KEY = "X-Goog-IAP-JWT-Assertion"
IAP_ISSUER = "https://cloud.google.com/iap"
IAP_JWKS_URI = "https://www.gstatic.com/iap/verify/public_key-jwk"

UserType = TypeVar("UserType")


@dataclass
class IAPToken(Token):
    """JWT token with Google IAP claims."""

    email: str | None = None
    """Email asserted by Google IAP."""
    azp: str | None = None
    """Authorized party OAuth client id."""
    provider: str = "iap"
    """Authentication provider identifier."""


@dataclass(slots=True)
class IAPMechanism(Generic[UserType]):
    """Google Identity-Aware Proxy authentication mechanism."""

    name: ClassVar[str] = "iap"

    audience: str | Sequence[str]
    retrieve_user_handler: Callable[[IAPToken, ASGIConnection[Any, Any, Any, Any]], SyncOrAsyncUnion[UserType | None]]
    allowed_domains: Sequence[str] = ()
    allowed_emails: Sequence[str] = ()
    auth_header: str = IAP_AUTH_HEADER_KEY
    clock_skew: float | timedelta = 30
    jwks_uri: str = IAP_JWKS_URI
    jwks_cache_ttl: int = 3600
    openapi_security_scheme_name: str = "IAPToken"
    description: str = "Google Identity-Aware Proxy JWT authentication."
    _retrieve_user_handler: Callable[[IAPToken, ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]] = (
        field(
            init=False,
            repr=False,
        )
    )
    _allowed_domains: frozenset[str] = field(init=False, repr=False)
    _allowed_emails: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.audience:
            raise ImproperlyConfiguredException("IAPMechanism requires a non-empty audience")
        self._retrieve_user_handler = cast(
            "Callable[[IAPToken, ASGIConnection[Any, Any, Any, Any]], Awaitable[UserType | None]]",
            ensure_async_callable(self.retrieve_user_handler),
        )
        self._allowed_domains = frozenset(domain.lower() for domain in self.allowed_domains)
        self._allowed_emails = frozenset(email.lower() for email in self.allowed_emails)

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        """Authenticate the connection with an IAP assertion header."""
        raw_token = connection.headers.get(self.auth_header)
        if not raw_token:
            return None

        token = await self.decode_token(raw_token, context=context)
        self._enforce_email_policy(token)
        user = await self._retrieve_user_handler(token, connection)
        if user is None:
            raise NotAuthorizedException("Invalid IAP token")
        return AuthenticationResult(user=user, auth=token)

    async def decode_token(self, raw_token: str, context: AuthenticationContext | None = None) -> IAPToken:
        """Decode and validate an IAP JWT."""
        jwks_cache = self._resolve_jwks_cache(context)
        try:
            signing_key = await jwks_cache.get_signing_key(
                raw_token,
                self.jwks_uri,
                algorithms=("ES256",),
                ttl=self.jwks_cache_ttl,
            )
            algorithm = cast("str", jwt.get_unverified_header(raw_token)["alg"])
            return IAPToken.decode(
                encoded_token=raw_token,
                secret=signing_key.key,
                algorithm=algorithm,
                audience=self.audience,
                issuer=IAP_ISSUER,
                require_claims=("aud",),
                leeway=self.clock_skew,
            )
        except NotAuthorizedException:
            raise
        except (JWKSError, PyJWTError, KeyError, TypeError, ValueError) as exc:
            raise NotAuthorizedException("Invalid IAP token") from exc

    def openapi_components(self) -> Components:
        """Return this mechanism's OpenAPI header security scheme."""
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="apiKey",
                    name=self.auth_header,
                    security_scheme_in="header",
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
        return True

    def _enforce_email_policy(self, token: IAPToken) -> None:
        if not self._allowed_domains and not self._allowed_emails:
            return
        if not token.email:
            raise NotAuthorizedException("IAP token missing email claim")

        email = token.email.lower()
        _, separator, domain = email.rpartition("@")
        email_allowed = email in self._allowed_emails
        domain_allowed = bool(separator and domain in self._allowed_domains)
        if not email_allowed and not domain_allowed:
            raise PermissionDeniedException("IAP email not allowed")

    @staticmethod
    def _resolve_jwks_cache(context: AuthenticationContext | None) -> JWKSCache:
        if context is not None and isinstance(context.jwks_cache, JWKSCache):
            return context.jwks_cache
        return JWKSCache()


@dataclass(slots=True)
class IAPSessionHandler(Generic[UserType]):
    """Route-handler helper that exchanges an authenticated IAP token for a local JWT."""

    jwt_mechanism: JWTMechanism[UserType]
    session_backend: Any | None = None

    async def __call__(self, request: Request[UserType, IAPToken, Any]) -> Response[dict[str, Any]]:
        """Create a local session response from the current IAP-authenticated request."""
        session_data = None
        if self.session_backend is not None and hasattr(self.session_backend, "create_session"):
            session_data = self.session_backend.create_session(request.user, request.auth)
            if inspect.isawaitable(session_data):
                session_data = await session_data
            self.store_session_data(request, session_data)
        return self.create_response(auth=request.auth, user=request.user, session_data=session_data)

    def create_response(
        self,
        *,
        auth: Any,
        user: UserType,
        session_data: Any | None = None,
    ) -> Response[dict[str, Any]]:
        """Create the response body for an IAP session exchange."""
        if not isinstance(auth, IAPToken):
            raise PermissionDeniedException("IAP authentication required")

        user_id = str(getattr(user, "id", auth.sub))
        access_token = self.jwt_mechanism.create_token(
            identifier=user_id,
            token_extras={
                "auth_method": "iap",
                "amr": ["iap"],
                "email": auth.email,
            },
        )
        content: dict[str, Any] = {
            "authenticated": True,
            "provider": auth.provider,
            "user_id": user_id,
            "email": auth.email,
            "access_token": access_token,
        }
        if session_data is not None:
            content["session"] = session_data
        return Response(content, status_code=HTTP_201_CREATED)

    @staticmethod
    def store_session_data(request: Request[UserType, IAPToken, Any], session_data: Any) -> None:
        """Persist session backend output into ``request.session`` when session middleware is installed."""
        if isinstance(session_data, Mapping):
            session_payload = dict(session_data)
        else:
            session_payload = {"session_id": str(session_data)}

        if not session_payload:
            return

        try:
            session = request.session
        except ImproperlyConfiguredException:
            return
        if session is Empty:
            return
        session.update(session_payload)


def iap_session_handler(
    *,
    jwt_mechanism: JWTMechanism[UserType],
    session_backend: Any | None = None,
) -> IAPSessionHandler[UserType]:
    """Return a route handler that exchanges verified IAP auth for local session material."""
    return IAPSessionHandler(jwt_mechanism=jwt_mechanism, session_backend=session_backend)
