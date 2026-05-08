import secrets
from os import environ
from typing import Any
from uuid import UUID

from pydantic import BaseModel, EmailStr

from litestar import Litestar, Request, Response, get, post
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler
from litestar.openapi.config import OpenAPIConfig
from litestar.security import SecurityPlugin
from litestar.security.jwt import JWTMechanism, Token


class User(BaseModel):
    id: UUID
    name: str
    email: EmailStr


MOCK_DB: dict[str, User] = {}


async def retrieve_user_handler(token: Token, _connection: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return MOCK_DB.get(token.sub)


def requires_user(connection: ASGIConnection[Any, Any, Any, Any], _route_handler: BaseRouteHandler) -> None:
    if "user" not in connection.scope:
        raise NotAuthorizedException()


oauth2_auth = JWTMechanism[User](
    retrieve_user_handler=retrieve_user_handler,
    token_secret=environ.get("JWT_SECRET", secrets.token_hex()),
)


@post("/login")
async def login_handler(data: User) -> Response[dict[str, str]]:
    MOCK_DB[str(data.id)] = data
    return oauth2_auth.login(identifier=str(data.id), send_token_as_response_body=True)


@get("/some-path", sync_to_thread=False, guards=[requires_user])
def some_route_handler(request: Request[User, Token, Any]) -> Any:
    assert isinstance(request.user, User)
    assert isinstance(request.auth, Token)


openapi_config = OpenAPIConfig(
    title="My API",
    version="1.0.0",
)

app = Litestar(
    route_handlers=[login_handler, some_route_handler],
    plugins=[SecurityPlugin([oauth2_auth])],
    openapi_config=openapi_config,
)
