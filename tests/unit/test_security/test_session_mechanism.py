from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

import msgspec

from litestar import Litestar, Request, delete, get, post
from litestar.middleware.session.server_side import ServerSideSessionBackend, ServerSideSessionConfig
from litestar.openapi.config import OpenAPIConfig
from litestar.security import SecurityPlugin
from litestar.security.session import SessionMechanism
from litestar.status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_204_NO_CONTENT, HTTP_401_UNAUTHORIZED
from litestar.testing import RequestFactory, create_test_client
from litestar.types import Empty
from tests.models import User, UserFactory

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection


user_instance = UserFactory.build()


def retrieve_user_handler(session_data: dict[str, Any], _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    if session_data["id"] == str(user_instance.id):
        return User(**session_data)
    return None


def create_session_mechanism(
    session_backend_config: ServerSideSessionConfig,
) -> SessionMechanism[User, ServerSideSessionBackend]:
    return SessionMechanism[User, ServerSideSessionBackend](
        retrieve_user_handler=retrieve_user_handler,
        session_backend_config=session_backend_config,
    )


def test_session_mechanism_authenticates_with_security_plugin(
    session_backend_config_memory: ServerSideSessionConfig,
) -> None:
    session_mechanism = create_session_mechanism(session_backend_config_memory)

    @post("/login")
    def login_handler(request: Request[Any, Any, Any], data: User) -> None:
        request.set_session(msgspec.to_builtins(data))

    @delete("/user/{user_id:str}")
    def delete_user_handler(request: Request[User, dict[str, Any], Any]) -> None:
        request.clear_session()

    @get("/user/{user_id:str}")
    def get_user_handler(request: Request[User, dict[str, Any], Any]) -> User:
        return request.user

    with create_test_client(
        route_handlers=[login_handler, delete_user_handler, get_user_handler],
        plugins=[SecurityPlugin([session_mechanism], exclude=["/login"])],
    ) as client:
        response = client.get(f"user/{user_instance.id}")
        assert response.status_code == HTTP_401_UNAUTHORIZED, response.json()

        response = client.post("/login", json={"id": str(user_instance.id), "name": user_instance.name})
        assert response.status_code == HTTP_201_CREATED, response.json()

        response = client.get(f"user/{user_instance.id}")
        assert response.status_code == HTTP_200_OK, response.json()

        response = client.delete(f"user/{user_instance.id}")
        assert response.status_code == HTTP_204_NO_CONTENT, response.json()

        response = client.get(f"user/{user_instance.id}")
        assert response.status_code == HTTP_401_UNAUTHORIZED, response.json()

        response = client.post("/login", json={"id": str(uuid4()), "name": user_instance.name})
        assert response.status_code == HTTP_201_CREATED, response.json()

        response = client.get(f"user/{user_instance.id}")
        assert response.status_code == HTTP_401_UNAUTHORIZED, response.json()


def test_session_mechanism_openapi_contribution(session_backend_config_memory: ServerSideSessionConfig) -> None:
    session_mechanism = create_session_mechanism(session_backend_config_memory)

    assert session_mechanism.openapi_components().to_schema() == {
        "schemas": {},
        "securitySchemes": {
            "sessionCookie": {
                "type": "apiKey",
                "description": "Session cookie authentication.",
                "name": session_backend_config_memory.key,
                "in": "cookie",
            }
        },
    }
    assert session_mechanism.openapi_security_requirement() == {"sessionCookie": []}

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    app = Litestar(
        [handler],
        plugins=[SecurityPlugin([session_mechanism])],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    schema = app.openapi_schema.to_schema()
    assert schema["components"]["securitySchemes"]["sessionCookie"]["name"] == session_backend_config_memory.key
    assert schema["paths"]["/"]["get"]["security"] == [{"sessionCookie": []}]


def test_session_property_can_return_empty() -> None:
    request = RequestFactory().get("/")
    request.scope["session"] = Empty

    assert request.session is Empty
