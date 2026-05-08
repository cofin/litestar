from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

import pytest

from litestar import Litestar, Request, WebSocket, get, websocket
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Components
from litestar.openapi.spec.security_scheme import SecurityScheme
from litestar.security import OPT_AUTH_MECHANISM, OPT_EXCLUDE_FROM_AUTH, AuthenticationResult
from litestar.status_codes import HTTP_401_UNAUTHORIZED
from litestar.testing import create_test_client

from .helpers import StubAuthMechanism

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.security import AuthenticationContext


class JWTStubAuthMechanism(StubAuthMechanism):
    __slots__ = ()

    name: ClassVar[str] = "jwt"


class APIKeyStubAuthMechanism(StubAuthMechanism):
    __slots__ = ()

    name: ClassVar[str] = "apikey"


class JWTOpenAPIStubAuthMechanism(JWTStubAuthMechanism):
    __slots__ = ()

    def openapi_components(self) -> Components:
        return Components(security_schemes={"jwt": SecurityScheme(type="http", scheme="bearer")})

    def openapi_security_requirement(self) -> dict[str, list[str]]:
        return {"jwt": []}


class APIKeyOpenAPIStubAuthMechanism(APIKeyStubAuthMechanism):
    __slots__ = ()

    def openapi_components(self) -> Components:
        return Components(
            security_schemes={"apikey": SecurityScheme(type="apiKey", name="x-api-key", security_scheme_in="header")}
        )

    def openapi_security_requirement(self) -> dict[str, list[str]]:
        return {"apikey": []}


class RejectingStubAuthMechanism(StubAuthMechanism):
    __slots__ = ()

    name: ClassVar[str] = "rejecting"

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        self.calls.append((connection, context))
        raise NotAuthorizedException("bad token")


class WebSocketStubAuthMechanism(StubAuthMechanism):
    __slots__ = ("seen_header_value", "seen_query_value")

    name: ClassVar[str] = "websocket"
    seen_header_value: str | None
    seen_query_value: str | None

    def __init__(self, result: AuthenticationResult | None = None) -> None:
        super().__init__(result)
        self.seen_header_value = None
        self.seen_query_value = None

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        self.seen_header_value = connection.headers.get("x-api-key")
        self.seen_query_value = connection.query_params.get("token")
        return await super().authenticate(connection, context)


def test_security_plugin_inserts_middleware_and_authenticates_request() -> None:
    from litestar.security.plugin import SecurityPlugin

    expected_user = {"id": "plugin-user"}
    expected_auth = {"scheme": "stub"}
    mechanism = StubAuthMechanism(AuthenticationResult(user=expected_user, auth=expected_auth))

    @get("/")
    async def handler(request: Request) -> dict[str, Any]:
        return {"user": request.user, "auth": request.auth}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"user": expected_user, "auth": expected_auth}
    assert len(mechanism.calls) == 1


def test_security_plugin_requires_at_least_one_mechanism() -> None:
    from litestar.security.plugin import SecurityPlugin

    with pytest.raises(ImproperlyConfiguredException, match="SecurityPlugin requires at least one mechanism"):
        SecurityPlugin([])


def test_security_plugin_rejects_duplicate_mechanism_names() -> None:
    from litestar.security.plugin import SecurityPlugin

    with pytest.raises(ImproperlyConfiguredException, match="Duplicate mechanism names"):
        SecurityPlugin([StubAuthMechanism(), StubAuthMechanism()])


def has_authenticated_user(request: Request) -> dict[str, bool]:
    return {"has_user": "user" in request.scope, "has_auth": "auth" in request.scope}


def test_security_plugin_excludes_matching_path_patterns() -> None:
    from litestar.security.plugin import SecurityPlugin

    mechanism = StubAuthMechanism()

    @get("/public")
    async def public_handler(request: Request) -> dict[str, bool]:
        return has_authenticated_user(request)

    @get("/private")
    async def private_handler(request: Request) -> dict[str, bool]:
        return has_authenticated_user(request)

    with create_test_client(
        [public_handler, private_handler],
        plugins=[SecurityPlugin([mechanism], exclude=["/public"])],
    ) as client:
        public_response = client.get("/public")
        private_response = client.get("/private")

    assert public_response.json() == {"has_user": False, "has_auth": False}
    assert private_response.json() == {"has_user": True, "has_auth": True}
    assert len(mechanism.calls) == 1


def test_security_plugin_excludes_route_handler_opt() -> None:
    from litestar.security.plugin import SecurityPlugin

    mechanism = StubAuthMechanism()

    @get("/public", opt={OPT_EXCLUDE_FROM_AUTH: True})
    async def public_handler(request: Request) -> dict[str, bool]:
        return has_authenticated_user(request)

    @get("/private")
    async def private_handler(request: Request) -> dict[str, bool]:
        return has_authenticated_user(request)

    with create_test_client([public_handler, private_handler], plugins=[SecurityPlugin([mechanism])]) as client:
        public_response = client.get("/public")
        private_response = client.get("/private")

    assert public_response.json() == {"has_user": False, "has_auth": False}
    assert private_response.json() == {"has_user": True, "has_auth": True}
    assert len(mechanism.calls) == 1


def test_security_plugin_excludes_options_requests_by_default() -> None:
    from litestar.security.plugin import SecurityPlugin

    mechanism = StubAuthMechanism()

    @get("/")
    async def handler(request: Request) -> dict[str, bool]:
        return has_authenticated_user(request)

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        options_response = client.options("/")
        get_response = client.get("/")

    assert options_response.is_success
    assert get_response.json() == {"has_user": True, "has_auth": True}
    assert len(mechanism.calls) == 1


def test_security_plugin_authenticates_websocket_connections() -> None:
    from litestar.security.plugin import SecurityPlugin

    expected_user = {"id": "ws-user"}
    expected_auth = {"scheme": "websocket"}
    mechanism = WebSocketStubAuthMechanism(AuthenticationResult(user=expected_user, auth=expected_auth))

    @websocket("/ws")
    async def handler(socket: WebSocket[Any, Any, Any]) -> None:
        await socket.accept()
        await socket.send_json({"user": socket.user, "auth": socket.auth})
        await socket.close()

    with (
        create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client,
        client.websocket_connect("/ws?token=query-token", headers={"x-api-key": "header-token"}) as ws,
    ):
        assert ws.receive_json() == {"user": expected_user, "auth": expected_auth}

    assert len(mechanism.calls) == 1
    assert mechanism.seen_header_value == "header-token"
    assert mechanism.seen_query_value == "query-token"


def test_security_plugin_excludes_websocket_route_handler_opt() -> None:
    from litestar.security.plugin import SecurityPlugin

    mechanism = WebSocketStubAuthMechanism()

    @websocket("/public", opt={OPT_EXCLUDE_FROM_AUTH: True})
    async def public_handler(socket: WebSocket[Any, Any, Any]) -> None:
        await socket.accept()
        await socket.send_json({"has_user": "user" in socket.scope, "has_auth": "auth" in socket.scope})
        await socket.close()

    with (
        create_test_client([public_handler], plugins=[SecurityPlugin([mechanism])]) as client,
        client.websocket_connect("/public") as ws,
    ):
        assert ws.receive_json() == {"has_user": False, "has_auth": False}

    assert mechanism.calls == []
    assert mechanism.seen_header_value is None
    assert mechanism.seen_query_value is None


def test_security_plugin_not_authorized_short_circuits_mechanism_iteration() -> None:
    from litestar.security.plugin import SecurityPlugin

    rejecting = RejectingStubAuthMechanism()
    fallback = APIKeyStubAuthMechanism()

    @get("/")
    async def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([rejecting, fallback])]) as client:
        response = client.get("/")

    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "bad token"
    assert response.headers["www-authenticate"] == "Bearer"
    assert len(rejecting.calls) == 1
    assert fallback.calls == []


def test_security_plugin_route_opt_uses_named_mechanism_only() -> None:
    from litestar.security.plugin import SecurityPlugin

    jwt = JWTStubAuthMechanism()
    apikey = APIKeyStubAuthMechanism(
        AuthenticationResult(user={"id": "apikey-user"}, auth={"scheme": "apikey"}),
    )

    @get("/", opt={OPT_AUTH_MECHANISM: "apikey"})
    async def handler(request: Request) -> dict[str, Any]:
        return {"user": request.user, "auth": request.auth}

    with create_test_client([handler], plugins=[SecurityPlugin([jwt, apikey])]) as client:
        response = client.get("/")

    assert response.json() == {"user": {"id": "apikey-user"}, "auth": {"scheme": "apikey"}}
    assert jwt.calls == []
    assert len(apikey.calls) == 1


def test_security_plugin_rejects_unknown_route_opt_mechanism_name() -> None:
    from litestar.security.plugin import SecurityPlugin

    @get("/", opt={OPT_AUTH_MECHANISM: "apikey"})
    async def handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match="Unknown auth mechanism"):
        Litestar(route_handlers=[handler], plugins=[SecurityPlugin([JWTStubAuthMechanism()])])


def test_security_plugin_contributes_generated_openapi_security() -> None:
    from litestar.security.plugin import SecurityPlugin

    @get("/private")
    async def private_handler() -> dict[str, str]:
        return {"status": "private"}

    @get("/public", opt={OPT_EXCLUDE_FROM_AUTH: True})
    async def public_handler() -> dict[str, str]:
        return {"status": "public"}

    app = Litestar(
        route_handlers=[private_handler, public_handler],
        plugins=[SecurityPlugin([JWTOpenAPIStubAuthMechanism(), APIKeyOpenAPIStubAuthMechanism()])],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    schema = app.openapi_schema.to_schema()

    assert schema["components"]["securitySchemes"] == {
        "apikey": {"type": "apiKey", "name": "x-api-key", "in": "header"},
        "jwt": {"type": "http", "scheme": "bearer"},
    }
    assert schema["paths"]["/private"]["get"]["security"] == [{"jwt": []}, {"apikey": []}]
    assert "security" not in schema["paths"]["/public"]["get"]


def test_security_plugin_route_opt_limits_generated_openapi_security_to_named_mechanism() -> None:
    from litestar.security.plugin import SecurityPlugin

    @get("/", opt={OPT_AUTH_MECHANISM: "apikey"})
    async def handler() -> dict[str, str]:
        return {"status": "ok"}

    app = Litestar(
        route_handlers=[handler],
        plugins=[SecurityPlugin([JWTOpenAPIStubAuthMechanism(), APIKeyOpenAPIStubAuthMechanism()])],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    schema = app.openapi_schema.to_schema()

    assert schema["components"]["securitySchemes"] == {
        "apikey": {"type": "apiKey", "name": "x-api-key", "in": "header"},
        "jwt": {"type": "http", "scheme": "bearer"},
    }
    assert schema["paths"]["/"]["get"]["security"] == [{"apikey": []}]


def test_security_plugin_route_security_opt_overrides_generated_openapi_security() -> None:
    from litestar.security.plugin import SecurityPlugin

    @get("/", opt={"security": [{"manual": []}]})
    async def handler() -> dict[str, str]:
        return {"status": "ok"}

    app = Litestar(
        route_handlers=[handler],
        plugins=[SecurityPlugin([JWTOpenAPIStubAuthMechanism(), APIKeyOpenAPIStubAuthMechanism()])],
        openapi_config=OpenAPIConfig(
            title="Test",
            version="1.0.0",
            components=Components(
                security_schemes={"manual": SecurityScheme(type="http", scheme="bearer")},
            ),
        ),
    )

    schema = app.openapi_schema.to_schema()

    assert schema["components"]["securitySchemes"] == {
        "apikey": {"type": "apiKey", "name": "x-api-key", "in": "header"},
        "jwt": {"type": "http", "scheme": "bearer"},
        "manual": {"type": "http", "scheme": "bearer"},
    }
    assert schema["paths"]["/"]["get"]["security"] == [{"manual": []}]


def test_security_plugin_route_security_opt_empty_removes_generated_openapi_security() -> None:
    from litestar.security.plugin import SecurityPlugin

    @get("/", opt={"security": []})
    async def handler() -> dict[str, str]:
        return {"status": "ok"}

    app = Litestar(
        route_handlers=[handler],
        plugins=[SecurityPlugin([JWTOpenAPIStubAuthMechanism(), APIKeyOpenAPIStubAuthMechanism()])],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    schema = app.openapi_schema.to_schema()

    assert "security" not in schema["paths"]["/"]["get"]
