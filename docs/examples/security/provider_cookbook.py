from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from litestar import Litestar, Request, WebSocket, get, post, websocket
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Components, SecurityScheme
from litestar.response import Response
from litestar.security import SecurityPlugin
from litestar.security.api_key import APIKey, APIKeyLocation, APIKeyMechanism
from litestar.security.iap import IAPMechanism, IAPToken, iap_session_handler
from litestar.security.jwt import JWKSCache, JWTMechanism, OIDCProvider, Token

TEST_DISCOVERY_URL = "https://issuer.example.test/.well-known/openid-configuration"
TEST_JWKS_URI = "https://issuer.example.test/.well-known/jwks.json"
TEST_JWKS = {"keys": []}


@dataclass(frozen=True, slots=True)
class User:
    id: str
    email: str


async def retrieve_user_from_jwt(token: Token, _connection: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return User(id=token.sub, email=str(token.extras.get("email", "")))


async def retrieve_user_from_iap(token: IAPToken, _connection: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    if token.email is None:
        return None
    return User(id=token.sub, email=token.email)


async def validate_demo_key(key: str, _connection: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    if key == "demo-key" or key == "auth.demo-key":
        return User(id="websocket-user", email="ws@example.com")
    return None


def requires_user(connection: ASGIConnection[Any, Any, Any, Any], _route_handler: BaseRouteHandler) -> None:
    if "user" not in connection.scope:
        raise NotAuthorizedException()


@get("/profile", guards=[requires_user], sync_to_thread=False)
def profile(request: Request[User, Token | IAPToken | APIKey, Any]) -> dict[str, str]:
    return {"id": request.user.id, "email": request.user.email}


def openapi_config(title: str) -> OpenAPIConfig:
    return OpenAPIConfig(title=title, version="1.0.0")


class RawHeaderJWTMechanism(JWTMechanism[User]):
    """JWT mechanism for providers that forward a raw JWT in a trusted proxy header."""

    __slots__ = ()

    name: ClassVar[str] = "raw-header-jwt"

    def get_encoded_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        return connection.headers.get(self.auth_header)

    def openapi_components(self) -> Components:
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="apiKey",
                    name=self.auth_header,
                    security_scheme_in="header",
                    description=self.description,
                )
            }
        )


class AWSALBMechanism(RawHeaderJWTMechanism):
    __slots__ = ()

    name: ClassVar[str] = "aws-alb"


class CloudflareAccessMechanism(RawHeaderJWTMechanism):
    __slots__ = ()

    name: ClassVar[str] = "cloudflare-access"


# start-auth0
def create_auth0_app() -> Litestar:
    auth0 = JWTMechanism[User](
        retrieve_user_handler=retrieve_user_from_jwt,
        oidc_provider=OIDCProvider(
            issuer="https://tenant.us.auth0.com/",
            audience="https://api.example.com",
            algorithms=("RS256",),
        ),
        openapi_security_scheme_name="Auth0Bearer",
        description="Auth0 JWT bearer token.",
    )
    app = Litestar(
        route_handlers=[profile],
        plugins=[SecurityPlugin([auth0])],
        openapi_config=openapi_config("Auth0 API"),
    )
    return app


# end-auth0


# start-keycloak
def create_keycloak_app() -> Litestar:
    keycloak = JWTMechanism[User](
        retrieve_user_handler=retrieve_user_from_jwt,
        oidc_provider=OIDCProvider(
            issuer="https://keycloak.example.com/realms/acme",
            audience="account",
            algorithms=("RS256",),
        ),
        openapi_security_scheme_name="KeycloakBearer",
        description="Keycloak JWT bearer token.",
    )
    app = Litestar(
        route_handlers=[profile],
        plugins=[SecurityPlugin([keycloak])],
        openapi_config=openapi_config("Keycloak API"),
    )
    return app


# end-keycloak


# start-entra
def create_entra_app() -> Litestar:
    entra = JWTMechanism[User](
        retrieve_user_handler=retrieve_user_from_jwt,
        oidc_provider=OIDCProvider(
            issuer="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
            audience="api://00000000-0000-0000-0000-000000000000",
            algorithms=("RS256",),
        ),
        openapi_security_scheme_name="EntraBearer",
        description="Microsoft Entra ID JWT bearer token.",
    )
    app = Litestar(
        route_handlers=[profile],
        plugins=[SecurityPlugin([entra])],
        openapi_config=openapi_config("Entra API"),
    )
    return app


# end-entra


# start-iap
def create_iap_app() -> Litestar:
    iap = IAPMechanism[User](
        audience="/projects/123456789/global/backendServices/987654321",
        retrieve_user_handler=retrieve_user_from_iap,
        allowed_domains=("example.com",),
    )
    app = Litestar(
        route_handlers=[profile],
        plugins=[SecurityPlugin([iap])],
        openapi_config=openapi_config("IAP API"),
    )
    return app


# end-iap


# start-aws-alb
def create_aws_alb_app() -> Litestar:
    aws_alb = AWSALBMechanism(
        retrieve_user_handler=retrieve_user_from_jwt,
        oidc_provider=OIDCProvider(
            issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
            audience="client-id",
            algorithms=("ES256",),
        ),
        auth_header="X-Amzn-Oidc-Data",
        openapi_security_scheme_name="AWSALBToken",
        description="AWS Application Load Balancer OIDC token header.",
    )
    app = Litestar(
        route_handlers=[profile],
        plugins=[SecurityPlugin([aws_alb])],
        openapi_config=openapi_config("AWS ALB API"),
    )
    return app


# end-aws-alb


# start-cloudflare-access
def create_cloudflare_access_app() -> Litestar:
    cloudflare_access = CloudflareAccessMechanism(
        retrieve_user_handler=retrieve_user_from_jwt,
        oidc_provider=OIDCProvider(
            issuer="https://team.cloudflareaccess.com",
            audience="application-audience-tag",
            jwks_uri="https://team.cloudflareaccess.com/cdn-cgi/access/certs",
            algorithms=("RS256",),
        ),
        auth_header="Cf-Access-Jwt-Assertion",
        openapi_security_scheme_name="CloudflareAccessToken",
        description="Cloudflare Access JWT assertion header.",
    )
    app = Litestar(
        route_handlers=[profile],
        plugins=[SecurityPlugin([cloudflare_access])],
        openapi_config=openapi_config("Cloudflare Access API"),
    )
    return app


# end-cloudflare-access


USERS_BY_EMAIL: dict[str, User] = {}


async def retrieve_or_provision_iap_user(
    token: IAPToken, _connection: ASGIConnection[Any, Any, Any, Any]
) -> User | None:
    if token.email is None:
        return None
    return USERS_BY_EMAIL.setdefault(token.email, User(id=token.sub, email=token.email))


# start-iap-auto-provision
def create_iap_auto_provision_app() -> Litestar:
    iap = IAPMechanism[User](
        audience="/projects/123456789/global/backendServices/987654321",
        retrieve_user_handler=retrieve_or_provision_iap_user,
        allowed_domains=("example.com",),
    )
    local_jwt = JWTMechanism[User](
        retrieve_user_handler=retrieve_user_from_jwt,
        token_secret="local-secret-that-is-at-least-32-characters",
    )

    @post("/iap/session", opt={"auth_mechanism": "iap"})
    async def exchange_iap_session(request: Request[User, IAPToken, Any]) -> Response[dict[str, Any]]:
        return await iap_session_handler(jwt_mechanism=local_jwt)(request)

    app = Litestar(
        route_handlers=[exchange_iap_session, profile],
        plugins=[SecurityPlugin([iap, local_jwt])],
        openapi_config=openapi_config("IAP Session API"),
    )
    return app


# end-iap-auto-provision


@websocket("/ws")
async def websocket_profile(socket: WebSocket[User, APIKey, Any]) -> None:
    await socket.accept()
    await socket.send_json({"user": socket.user.id, "token": socket.auth.value})
    await socket.close()


# start-websocket-query
websocket_query_auth = APIKeyMechanism[User](
    validate_key_handler=validate_demo_key,
    location=APIKeyLocation.QUERY,
    key_name="token",
    openapi_security_scheme_name="WebSocketQueryToken",
)
websocket_query_app = Litestar(
    route_handlers=[websocket_profile],
    plugins=[SecurityPlugin([websocket_query_auth])],
)
# end-websocket-query


# start-websocket-subprotocol
websocket_subprotocol_auth = APIKeyMechanism[User](
    validate_key_handler=validate_demo_key,
    location=APIKeyLocation.HEADER,
    key_name="Sec-WebSocket-Protocol",
    openapi_security_scheme_name="WebSocketSubprotocolToken",
)
websocket_subprotocol_app = Litestar(
    route_handlers=[websocket_profile],
    plugins=[SecurityPlugin([websocket_subprotocol_auth])],
)
# end-websocket-subprotocol


# start-jwks-cache
async def build_test_jwks_cache() -> JWKSCache:
    cache = JWKSCache()
    await cache.set_json_document(TEST_DISCOVERY_URL, {"jwks_uri": TEST_JWKS_URI})
    await cache.set_jwks(TEST_JWKS_URI, TEST_JWKS)
    return cache


# end-jwks-cache
