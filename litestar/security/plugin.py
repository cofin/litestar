from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.enums import HttpMethod
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware import DefineMiddleware
from litestar.plugins import InitPlugin, OpenAPIContributorPlugin
from litestar.security._middleware import SecurityMiddleware
from litestar.security.constants import OPT_AUTH_MECHANISM, OPT_EXCLUDE_FROM_AUTH
from litestar.utils import is_class_and_subclass

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from litestar.config.app import AppConfig
    from litestar.handlers import BaseRouteHandler
    from litestar.handlers.http_handlers import HTTPRouteHandler
    from litestar.openapi.spec import Components, SecurityRequirement
    from litestar.router import Router
    from litestar.security._mechanism import AuthMechanism
    from litestar.types import ControllerRouterHandler, Method

__all__ = ("SecurityPlugin",)


class SecurityPlugin(InitPlugin, OpenAPIContributorPlugin):
    """Application plugin that installs security authentication middleware."""

    __slots__ = ("_jwks_cache", "exclude", "exclude_http_methods", "mechanisms")

    _jwks_cache: Any | None
    exclude: str | list[str] | None
    exclude_http_methods: tuple[Method, ...]
    mechanisms: tuple[AuthMechanism, ...]

    def __init__(
        self,
        mechanisms: Sequence[AuthMechanism],
        *,
        exclude: str | list[str] | None = None,
        exclude_http_methods: Sequence[Method] | None = None,
        jwks_cache: Any | None = None,
    ) -> None:
        """Initialize ``SecurityPlugin``.

        Args:
            mechanisms: Ordered authentication mechanisms used by the security middleware.
            exclude: Path pattern or patterns to exclude from authentication in a later chapter.
            exclude_http_methods: HTTP methods to exclude from authentication in a later chapter.
            jwks_cache: Shared JWKS cache passed into authentication context for mechanisms that need key discovery.

        Raises:
            ImproperlyConfiguredException: If no mechanisms are configured, or mechanism names are duplicated.
        """
        mechanism_tuple = tuple(mechanisms)
        if not mechanism_tuple:
            raise ImproperlyConfiguredException("SecurityPlugin requires at least one mechanism")

        names = [mechanism.name for mechanism in mechanism_tuple]
        if len(set(names)) != len(names):
            raise ImproperlyConfiguredException(f"Duplicate mechanism names: {names}")

        self.mechanisms = mechanism_tuple
        self.exclude = exclude
        self.exclude_http_methods = tuple(exclude_http_methods or (HttpMethod.OPTIONS,))
        self._jwks_cache = self._create_jwks_cache(mechanism_tuple) if jwks_cache is None else jwks_cache

    @property
    def middleware(self) -> DefineMiddleware:
        """Create the middleware definition installed during application init."""
        return DefineMiddleware(
            SecurityMiddleware,
            exclude=self.exclude,
            exclude_http_methods=self.exclude_http_methods,
            mechanisms=self.mechanisms,
            jwks_cache=self._jwks_cache,
            settings=self,
        )

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Insert the security middleware into the application middleware stack."""
        self._validate_route_handler_overrides(app_config.route_handlers)
        app_config.middleware.insert(0, self.middleware)
        for middleware in reversed(tuple(self._iter_mechanism_middleware())):
            app_config.middleware.insert(0, middleware)
        return app_config

    def get_openapi_components(self) -> Components | None:
        """Return OpenAPI security schemes contributed by configured mechanisms."""
        from litestar.openapi.spec import Components

        security_schemes = {}
        for mechanism in self.mechanisms:
            components = mechanism.openapi_components()
            if components and components.security_schemes:
                security_schemes.update(components.security_schemes)
        return Components(security_schemes=security_schemes) if security_schemes else None

    def get_openapi_security_requirements(
        self, route_handler: HTTPRouteHandler
    ) -> Sequence[SecurityRequirement] | None:
        """Return OpenAPI security requirements for protected route handlers."""
        if route_handler.opt.get(OPT_EXCLUDE_FROM_AUTH):
            return None

        security_requirements: list[SecurityRequirement] = []
        for mechanism in self._get_route_handler_mechanisms(route_handler):
            if security_requirement := mechanism.openapi_security_requirement():
                security_requirements.append(security_requirement)
        return security_requirements or None

    def _get_route_handler_mechanisms(self, route_handler: HTTPRouteHandler) -> Sequence[AuthMechanism]:
        if forced_name := route_handler.opt.get(OPT_AUTH_MECHANISM):
            return tuple(mechanism for mechanism in self.mechanisms if mechanism.name == forced_name)
        return self.mechanisms

    def _validate_route_handler_overrides(self, route_handlers: Sequence[ControllerRouterHandler]) -> None:
        known_names = {mechanism.name for mechanism in self.mechanisms}
        for route_handler in self._iter_route_handlers(route_handlers):
            forced_name = route_handler.opt.get(OPT_AUTH_MECHANISM)
            if forced_name is not None and forced_name not in known_names:
                raise ImproperlyConfiguredException(
                    f"Unknown auth mechanism {forced_name!r}; expected one of {sorted(known_names)!r}"
                )

    @staticmethod
    def _create_jwks_cache(mechanisms: Sequence[AuthMechanism]) -> Any | None:
        if not any(getattr(mechanism, "uses_jwks", False) for mechanism in mechanisms):
            return None
        from litestar.security.jwt import JWKSCache

        return JWKSCache()

    def _iter_mechanism_middleware(self) -> Iterator[DefineMiddleware]:
        for mechanism in self.mechanisms:
            middleware = getattr(mechanism, "middleware", None)
            if isinstance(middleware, DefineMiddleware):
                yield middleware

    @classmethod
    def _iter_route_handlers(
        cls,
        route_handlers: Sequence[ControllerRouterHandler],
        bases: tuple[Router, ...] = (),
    ) -> Iterator[BaseRouteHandler]:
        from litestar.controller import Controller
        from litestar.handlers import BaseRouteHandler
        from litestar.router import Router

        for route_handler in route_handlers:
            if isinstance(route_handler, Router):
                yield from cls._iter_route_handlers(route_handler.route_handlers, bases=(route_handler, *bases))
            elif is_class_and_subclass(route_handler, Controller):
                router = route_handler().as_router()
                yield from cls._iter_route_handlers(router.route_handlers, bases=(router, *bases))
            elif isinstance(route_handler, BaseRouteHandler):
                yield route_handler.merge(*bases)
