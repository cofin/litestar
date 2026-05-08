from typing import Any

from litestar import Litestar, Request, get
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler
from litestar.security import SecurityPlugin
from litestar.security.jwt import JWTMechanism, OIDCProvider, Token


async def retrieve_user_handler(token: Token, _connection: ASGIConnection[Any, Any, Any, Any]) -> dict[str, Any]:
    return {"id": token.sub, **token.extras}


def requires_user(connection: ASGIConnection[Any, Any, Any, Any], _route_handler: BaseRouteHandler) -> None:
    if "user" not in connection.scope:
        raise NotAuthorizedException()


oidc_auth = JWTMechanism[dict[str, Any]](
    retrieve_user_handler=retrieve_user_handler,
    oidc_provider=OIDCProvider(
        issuer="https://accounts.example.com",
        audience="api://my-service",
        algorithms=("RS256",),
    ),
)


@get("/profile", guards=[requires_user])
def profile(request: Request[dict[str, Any], Token, Any]) -> dict[str, Any]:
    return request.user


app = Litestar(route_handlers=[profile], plugins=[SecurityPlugin([oidc_auth])])
