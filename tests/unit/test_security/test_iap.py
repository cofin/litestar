from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from litestar import Request, get, post
from litestar.exceptions import PermissionDeniedException
from litestar.response import Response
from litestar.security import AuthenticationContext, SecurityPlugin
from litestar.security.iap import IAP_AUTH_HEADER_KEY, IAP_ISSUER, IAP_JWKS_URI, IAPMechanism, IAPToken
from litestar.security.jwt import JWKSCache, JWTMechanism, Token
from litestar.status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from litestar.testing import RequestFactory, create_test_client
from litestar.types import Empty

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection


@dataclass
class User:
    id: str
    email: str


@dataclass
class IAPKey:
    kid: str
    private_key: ec.EllipticCurvePrivateKey
    jwk: dict[str, Any]


def create_iap_key(kid: str = "iap-key") -> IAPKey:
    private_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "ES256"
    return IAPKey(kid=kid, private_key=private_key, jwk=jwk)


def create_iap_token(
    key: IAPKey,
    *,
    audience: str = "/projects/123/global/backendServices/456",
    email: str = "user@example.com",
    subject: str = "accounts.google.com:user",
) -> str:
    return jwt.encode(
        {
            "iss": IAP_ISSUER,
            "aud": audience,
            "sub": subject,
            "email": email,
            "azp": "client-id",
            "iat": datetime.now(UTC) - timedelta(minutes=1),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        key.private_key,
        algorithm="ES256",
        headers={"kid": key.kid},
    )


async def retrieve_iap_user_handler(token: IAPToken, _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return User(id=token.sub, email=token.email or "")


async def retrieve_local_user_handler(token: Token, _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return User(id=token.sub, email="local@example.com") if token.sub == "local-user" else None


async def create_cache(key: IAPKey) -> JWKSCache:
    cache = JWKSCache()
    await cache.set_jwks(IAP_JWKS_URI, {"keys": [key.jwk]}, ttl=60)
    return cache


def create_iap_mechanism(**kwargs: Any) -> IAPMechanism[User]:
    return IAPMechanism[User](
        audience="/projects/123/global/backendServices/456",
        retrieve_user_handler=retrieve_iap_user_handler,
        **kwargs,
    )


async def test_iap_mechanism_declines_when_iap_header_is_missing() -> None:
    key = create_iap_key()
    mechanism = create_iap_mechanism()

    result = await mechanism.authenticate(
        RequestFactory().get("/"),
        AuthenticationContext(jwks_cache=await create_cache(key)),
    )

    assert result is None


async def test_iap_mechanism_authenticates_valid_iap_token() -> None:
    key = create_iap_key()
    mechanism = create_iap_mechanism()

    @get("/")
    def handler(request: Request[User, IAPToken, Any]) -> dict[str, str | None]:
        return {"user": request.user.id, "email": request.auth.email, "provider": request.auth.provider}

    with create_test_client(
        [handler], plugins=[SecurityPlugin([mechanism], jwks_cache=await create_cache(key))]
    ) as client:
        response = client.get("/", headers={IAP_AUTH_HEADER_KEY: create_iap_token(key)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "accounts.google.com:user", "email": "user@example.com", "provider": "iap"}


async def test_iap_mechanism_rejects_wrong_audience() -> None:
    key = create_iap_key()
    mechanism = create_iap_mechanism()

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client(
        [handler], plugins=[SecurityPlugin([mechanism], jwks_cache=await create_cache(key))]
    ) as client:
        response = client.get("/", headers={IAP_AUTH_HEADER_KEY: create_iap_token(key, audience="wrong")})

    assert response.status_code == HTTP_401_UNAUTHORIZED


async def test_iap_mechanism_enforces_allowed_domains_and_emails() -> None:
    key = create_iap_key()
    mechanism = create_iap_mechanism(allowed_domains=("example.com",), allowed_emails=("admin@other.com",))

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client(
        [handler], plugins=[SecurityPlugin([mechanism], jwks_cache=await create_cache(key))]
    ) as client:
        domain_response = client.get("/", headers={IAP_AUTH_HEADER_KEY: create_iap_token(key, email="user@other.com")})
        allowlisted_domain_response = client.get(
            "/", headers={IAP_AUTH_HEADER_KEY: create_iap_token(key, email="user@example.com")}
        )
        allowlisted_email_response = client.get(
            "/", headers={IAP_AUTH_HEADER_KEY: create_iap_token(key, email="admin@other.com")}
        )

    assert domain_response.status_code == HTTP_403_FORBIDDEN
    assert allowlisted_domain_response.status_code == HTTP_200_OK
    assert allowlisted_email_response.status_code == HTTP_200_OK


async def test_iap_mechanism_reuses_jwks_cache_for_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    old_key = create_iap_key("old-key")
    new_key = create_iap_key("new-key")
    cache = await create_cache(old_key)
    mechanism = create_iap_mechanism()

    async def fetch_json_document(_: JWKSCache, __: str) -> dict[str, Any]:
        return {"keys": [new_key.jwk]}

    monkeypatch.setattr(JWKSCache, "_fetch_json_document", fetch_json_document)

    @get("/")
    def handler(request: Request[User, IAPToken, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism], jwks_cache=cache)]) as client:
        response = client.get("/", headers={IAP_AUTH_HEADER_KEY: create_iap_token(new_key)})

    assert response.status_code == HTTP_200_OK
    assert cache.stats()["refreshes"] == 1


def test_iap_mechanism_composes_with_jwt_fallback() -> None:
    local_jwt = JWTMechanism[User](
        token_secret="local-secret-that-is-at-least-32", retrieve_user_handler=retrieve_local_user_handler
    )
    iap = create_iap_mechanism()
    encoded_token = local_jwt.create_token("local-user")

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id, "email": request.user.email}

    with create_test_client([handler], plugins=[SecurityPlugin([iap, local_jwt])]) as client:
        response = client.get("/", headers={"Authorization": local_jwt.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "local-user", "email": "local@example.com"}


async def test_iap_session_handler_returns_local_jwt() -> None:
    from litestar.security.iap import iap_session_handler

    key = create_iap_key()
    iap = create_iap_mechanism()
    local_jwt = JWTMechanism[User](
        token_secret="local-secret-that-is-at-least-32", retrieve_user_handler=retrieve_local_user_handler
    )

    @post("/iap-session")
    async def session_handler(request: Request[User, IAPToken, Any]) -> Response[dict[str, Any]]:
        return await iap_session_handler(jwt_mechanism=local_jwt)(request)

    with create_test_client(
        [session_handler], plugins=[SecurityPlugin([iap], jwks_cache=await create_cache(key))]
    ) as client:
        response = client.post("/iap-session", headers={IAP_AUTH_HEADER_KEY: create_iap_token(key)})

    assert response.status_code == HTTP_201_CREATED
    assert response.json()["authenticated"] is True
    assert response.json()["provider"] == "iap"
    assert response.json()["access_token"]


async def test_iap_session_handler_stores_session_backend_data() -> None:
    from litestar.security.iap import iap_session_handler

    class SessionBackend:
        async def create_session(self, user: User, auth: IAPToken) -> dict[str, str]:
            return {"session_id": f"{auth.provider}:{user.id}"}

    local_jwt = JWTMechanism[User](
        token_secret="local-secret-that-is-at-least-32",
        retrieve_user_handler=retrieve_local_user_handler,
    )
    request = RequestFactory().get("/")
    request.scope["user"] = User("iap-user", "user@example.com")
    request.scope["auth"] = IAPToken(
        exp=datetime.now(UTC) + timedelta(minutes=5),
        sub="iap-user",
        email="user@example.com",
    )
    request.set_session({})

    response = await iap_session_handler(jwt_mechanism=local_jwt, session_backend=SessionBackend())(request)

    session = request.session
    assert session is not Empty
    assert session["session_id"] == "iap:iap-user"
    assert response.content["session"] == {"session_id": "iap:iap-user"}


def test_iap_session_handler_rejects_non_iap_auth() -> None:
    from litestar.security.iap import iap_session_handler

    local_jwt = JWTMechanism[User](
        token_secret="local-secret-that-is-at-least-32", retrieve_user_handler=retrieve_local_user_handler
    )
    handler = iap_session_handler(jwt_mechanism=local_jwt)

    with pytest.raises(PermissionDeniedException):
        handler.create_response(
            auth=Token(exp=datetime.now(UTC) + timedelta(minutes=5), sub="local-user"),
            user=User("local-user", "local@example.com"),
        )
