from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

from litestar import Litestar, Request, WebSocket, get, websocket
from litestar.openapi.config import OpenAPIConfig
from litestar.security import SecurityPlugin
from litestar.security.api_key import APIKey, APIKeyLocation, APIKeyMechanism
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import create_test_client

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection


@dataclass
class User:
    id: str


async def validate_api_key(key: str, _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return User(id=key) if key in {"alpha", "bravo"} else None


def create_api_key_mechanism(**kwargs: Any) -> APIKeyMechanism[User]:
    return APIKeyMechanism[User](validate_key_handler=validate_api_key, **kwargs)


@pytest.mark.parametrize(
    ("location", "path", "headers", "cookies"),
    (
        (APIKeyLocation.HEADER, "/", {"X-API-Key": "alpha"}, None),
        (APIKeyLocation.QUERY, "/?api_key=alpha", None, None),
        (APIKeyLocation.COOKIE, "/", None, {"api_key": "alpha"}),
    ),
)
def test_api_key_mechanism_authenticates_each_location(
    location: APIKeyLocation,
    path: str,
    headers: dict[str, str] | None,
    cookies: dict[str, str] | None,
) -> None:
    mechanism = create_api_key_mechanism(location=location)

    @get("/")
    def handler(request: Request[User, APIKey, Any]) -> dict[str, str]:
        return {
            "user": request.user.id,
            "key": request.auth.value,
            "location": request.auth.location,
            "name": request.auth.name,
        }

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        if cookies:
            client.cookies = cookies
        response = client.get(path, headers=headers)

    assert response.status_code == HTTP_200_OK
    assert response.json() == {
        "user": "alpha",
        "key": "alpha",
        "location": location,
        "name": mechanism.key_name,
    }


def test_api_key_mechanism_rejects_invalid_key_without_fallback() -> None:
    mechanism = create_api_key_mechanism()

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"X-API-Key": "invalid"})

    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_api_key_mechanism_declines_when_key_is_missing() -> None:
    mechanism = create_api_key_mechanism()

    @get("/")
    def handler(request: Request[Any, Any, Any]) -> dict[str, bool]:
        return {"has_user": "user" in request.scope, "has_auth": "auth" in request.scope}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/")

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"has_user": False, "has_auth": False}


async def test_api_key_mechanism_uses_scope_aware_validator() -> None:
    seen_path: str | None = None

    async def validate_scoped_key(key: str, connection: ASGIConnection[Any, Any, Any, Any]) -> User | None:
        nonlocal seen_path
        seen_path = connection.url.path
        if key == "bravo" and connection.headers.get("X-Scope") == "admin":
            return User(id="scoped")
        return None

    mechanism = APIKeyMechanism[User](validate_key_handler=validate_scoped_key)

    @get("/admin")
    def handler(request: Request[User, APIKey, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/admin", headers={"X-API-Key": "bravo", "X-Scope": "admin"})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "scoped"}
    assert seen_path == "/admin"


def test_api_key_query_location_authenticates_websocket() -> None:
    mechanism = create_api_key_mechanism(location=APIKeyLocation.QUERY, key_name="token")

    @websocket("/ws")
    async def handler(socket: WebSocket[User, APIKey, Any]) -> None:
        await socket.accept()
        await socket.send_json({"user": socket.user.id, "key": socket.auth.value})
        await socket.close()

    with (
        create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client,
        client.websocket_connect("/ws?token=alpha") as ws,
    ):
        assert ws.receive_json() == {"user": "alpha", "key": "alpha"}


def test_api_key_mechanism_openapi_contribution() -> None:
    mechanism = create_api_key_mechanism(
        location=APIKeyLocation.COOKIE,
        key_name="app_api_key",
        openapi_security_scheme_name="AppAPIKey",
    )

    assert mechanism.openapi_components().to_schema() == {
        "schemas": {},
        "securitySchemes": {
            "AppAPIKey": {
                "type": "apiKey",
                "description": "API key authentication.",
                "name": "app_api_key",
                "in": "cookie",
            }
        },
    }
    assert mechanism.openapi_security_requirement() == {"AppAPIKey": []}

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    app = Litestar(
        [handler],
        plugins=[SecurityPlugin([mechanism])],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    schema = app.openapi_schema.to_schema()
    assert schema["components"]["securitySchemes"]["AppAPIKey"]["in"] == "cookie"
    assert schema["paths"]["/"]["get"]["security"] == [{"AppAPIKey": []}]
