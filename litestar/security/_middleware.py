from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.connection import ASGIConnection
from litestar.enums import HttpMethod, ScopeType
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException
from litestar.middleware._utils import build_exclude_path_pattern, should_bypass_middleware
from litestar.security._context import AuthenticationContext
from litestar.security.constants import OPT_AUTH_MECHANISM, OPT_EXCLUDE_FROM_AUTH

if TYPE_CHECKING:
    from collections.abc import Sequence
    from re import Pattern

    from litestar.security._mechanism import AuthMechanism
    from litestar.security.types import AuthenticationResult
    from litestar.types import ASGIApp, Method, Receive, Scope, Send

__all__ = ("SecurityMiddleware",)

_WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"


class SecurityMiddleware:
    """ASGI middleware that authenticates a connection with ordered mechanisms."""

    __slots__ = (
        "app",
        "exclude_http_methods",
        "exclude_path_pattern",
        "jwks_cache",
        "mechanism_by_name",
        "mechanisms",
        "settings",
    )

    exclude_http_methods: tuple[Method, ...]
    exclude_path_pattern: Pattern | None
    mechanism_by_name: dict[str, AuthMechanism]

    def __init__(
        self,
        app: ASGIApp,
        mechanisms: Sequence[AuthMechanism],
        *,
        exclude: str | list[str] | None = None,
        exclude_http_methods: Sequence[Method] | None = None,
        jwks_cache: Any | None = None,
        settings: Any = None,
    ) -> None:
        """Initialize the security middleware.

        Args:
            app: The next ASGI app in the middleware stack.
            mechanisms: Ordered authentication mechanisms.
            exclude: Path pattern or patterns to bypass authentication.
            exclude_http_methods: HTTP methods that bypass authentication.
            jwks_cache: Shared JWKS cache passed into each per-connection context.
            settings: Plugin settings passed into each per-connection context.
        """
        self.app = app
        self.exclude_http_methods = tuple(exclude_http_methods or (HttpMethod.OPTIONS,))
        self.exclude_path_pattern = build_exclude_path_pattern(exclude=exclude, middleware_cls=type(self))
        self.mechanisms = tuple(mechanisms)
        self.mechanism_by_name = {mechanism.name: mechanism for mechanism in self.mechanisms}
        self.jwks_cache = jwks_cache
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Authenticate HTTP and WebSocket scopes and forward the connection to the wrapped app."""
        if should_bypass_middleware(
            exclude_http_methods=self.exclude_http_methods,
            exclude_opt_key=OPT_EXCLUDE_FROM_AUTH,
            exclude_path_pattern=self.exclude_path_pattern,
            scope=scope,
            scopes={ScopeType.HTTP, ScopeType.WEBSOCKET},
        ):
            await self.app(scope, receive, send)
            return

        context = AuthenticationContext(jwks_cache=self.jwks_cache, settings=self.settings)
        auth_result = await self._authenticate_connection(
            ASGIConnection(scope),
            context,
            mechanisms=self._select_mechanisms(self._get_forced_mechanism_name(scope)),
        )
        if auth_result is not None:
            scope["user"] = auth_result.user
            scope["auth"] = auth_result.auth

        await self.app(scope, receive, send)

    async def _authenticate_connection(
        self,
        connection: ASGIConnection,
        context: AuthenticationContext,
        *,
        mechanisms: Sequence[AuthMechanism] | None = None,
    ) -> AuthenticationResult | None:
        for mechanism in mechanisms or self.mechanisms:
            try:
                auth_result = await mechanism.authenticate(connection, context)
            except NotAuthorizedException as exc:
                self._ensure_www_authenticate_header(exc)
                raise
            if auth_result is not None:
                return auth_result
        return None

    @staticmethod
    def _ensure_www_authenticate_header(exc: NotAuthorizedException) -> None:
        headers = exc.headers
        if headers is None:
            exc.headers = {_WWW_AUTHENTICATE_HEADER: "Bearer"}
            return
        if not any(header.lower() == "www-authenticate" for header in headers):
            headers[_WWW_AUTHENTICATE_HEADER] = "Bearer"

    @staticmethod
    def _get_forced_mechanism_name(scope: Scope) -> str | None:
        route_handler = scope.get("route_handler")
        forced_name = getattr(route_handler, "opt", {}).get(OPT_AUTH_MECHANISM) if route_handler is not None else None
        return forced_name if isinstance(forced_name, str) else None

    def _select_mechanisms(self, forced_name: str | None) -> tuple[AuthMechanism, ...]:
        if forced_name is None:
            return self.mechanisms
        try:
            return (self.mechanism_by_name[forced_name],)
        except KeyError as exc:
            raise ImproperlyConfiguredException(f"Unknown auth mechanism {forced_name!r}") from exc
