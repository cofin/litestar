import dataclasses
import secrets
from typing import Any

from litestar import Litestar, Request, get
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler
from litestar.security import SecurityPlugin
from litestar.security.jwt import JWTMechanism, Token


@dataclasses.dataclass
class User:
    id: str


async def retrieve_user_handler(token: Token, _connection: ASGIConnection[Any, Any, Any, Any]) -> User:
    return User(id=token.sub)


def requires_user(connection: ASGIConnection[Any, Any, Any, Any], _route_handler: BaseRouteHandler) -> None:
    if "user" not in connection.scope:
        raise NotAuthorizedException()


jwt_auth = JWTMechanism[User](
    token_secret=secrets.token_hex(),
    retrieve_user_handler=retrieve_user_handler,
    accepted_audiences=["https://api.testserver.local"],
    accepted_issuers=["https://auth.testserver.local"],
)


@get("/", guards=[requires_user])
def handler(request: Request[User, Token, Any]) -> dict[str, Any]:
    return {"id": request.user.id}


app = Litestar([handler], plugins=[SecurityPlugin([jwt_auth])])
