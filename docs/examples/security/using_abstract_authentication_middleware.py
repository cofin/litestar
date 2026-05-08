from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from litestar import Litestar, Request, WebSocket, get, websocket
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.security import AuthenticationContext, AuthenticationResult, SecurityPlugin

API_KEY_HEADER = "X-API-KEY"

TOKEN_USER_DATABASE = {"1": "user_authorized"}


@dataclass(frozen=True, slots=True)
class MyUser:
    name: str


@dataclass(frozen=True, slots=True)
class MyToken:
    api_key: str


@dataclass(slots=True)
class CustomAPIKeyMechanism:
    name: ClassVar[str] = "custom-api-key"

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        context: AuthenticationContext,
    ) -> AuthenticationResult | None:
        del context
        auth_header = connection.headers.get(API_KEY_HEADER)
        if not auth_header:
            return None

        token = MyToken(api_key=auth_header)
        user_name = TOKEN_USER_DATABASE.get(token.api_key)
        if user_name is None:
            raise NotAuthorizedException()
        return AuthenticationResult(user=MyUser(name=user_name), auth=token)

    def openapi_components(self) -> Components:
        return Components(
            security_schemes={
                "CustomAPIKey": SecurityScheme(
                    type="apiKey",
                    name=API_KEY_HEADER,
                    security_scheme_in="header",
                    description="Custom API key authentication.",
                )
            }
        )

    def openapi_security_requirement(self) -> SecurityRequirement:
        return {"CustomAPIKey": []}


def requires_user(connection: ASGIConnection[Any, Any, Any, Any], _route_handler: BaseRouteHandler) -> None:
    if "user" not in connection.scope:
        raise NotAuthorizedException()


@get("/", guards=[requires_user], sync_to_thread=False)
def my_http_handler(request: Request[MyUser, MyToken, Any]) -> dict[str, str]:
    user = request.user
    auth = request.auth
    return {"user": user.name, "api_key": auth.api_key}


@websocket("/ws", guards=[requires_user])
async def my_ws_handler(socket: WebSocket[MyUser, MyToken, Any]) -> None:
    await socket.accept()
    await socket.send_json({"user": socket.user.name, "api_key": socket.auth.api_key})
    await socket.close()


@get(path="/public", exclude_from_auth=True, sync_to_thread=False)
def site_index() -> dict[str, str]:
    return {"status": "public"}


async def my_dependency(request: Request[MyUser, MyToken, Any]) -> dict[str, str]:
    return {"user": request.user.name, "api_key": request.auth.api_key}


custom_auth = CustomAPIKeyMechanism()

app = Litestar(
    route_handlers=[site_index, my_http_handler, my_ws_handler],
    plugins=[SecurityPlugin([custom_auth])],
)
