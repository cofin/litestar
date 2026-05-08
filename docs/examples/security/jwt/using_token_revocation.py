from os import environ
from typing import Any
from uuid import UUID, uuid4

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
BLOCKLIST: dict[str, str] = {}


async def retrieve_user_handler(token: Token, _connection: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return MOCK_DB.get(token.sub)


async def revoked_token_handler(token: Token, _connection: ASGIConnection[Any, Any, Any, Any]) -> bool:
    return token.jti is not None and token.jti in BLOCKLIST


def requires_user(connection: ASGIConnection[Any, Any, Any, Any], _route_handler: BaseRouteHandler) -> None:
    if "user" not in connection.scope:
        raise NotAuthorizedException()


jwt_auth = JWTMechanism[User](
    retrieve_user_handler=retrieve_user_handler,
    revoked_token_handler=revoked_token_handler,
    token_secret=environ.get("JWT_SECRET", "abcd123abcd123abcd123abcd123abcd"),
)


@post("/login")
async def login_handler(data: User) -> Response[User]:
    MOCK_DB[str(data.id)] = data
    return jwt_auth.login(
        identifier=str(data.id),
        token_unique_jwt_id=uuid4().hex,
        token_extras={"email": data.email},
        response_body=data,
    )


@post("/logout", guards=[requires_user])
async def logout_handler(request: Request[User, Token, Any]) -> dict[str, str]:
    if request.auth.jti:
        BLOCKLIST[request.auth.jti] = "revoked"
        return {"message": "Token has been revoked."}
    return {"message": "No valid token found."}


@get("/some-path", sync_to_thread=False, guards=[requires_user])
def some_route_handler(request: Request[User, Token, Any]) -> Any:
    assert isinstance(request.user, User)
    assert isinstance(request.auth, Token)


openapi_config = OpenAPIConfig(
    title="My API",
    version="1.0.0",
)

app = Litestar(
    route_handlers=[login_handler, logout_handler, some_route_handler],
    plugins=[SecurityPlugin([jwt_auth])],
    openapi_config=openapi_config,
)
