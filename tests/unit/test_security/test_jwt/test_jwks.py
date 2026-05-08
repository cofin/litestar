from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from jwt.utils import base64url_encode

from litestar import Request, get
from litestar.security import SecurityPlugin
from litestar.security.jwt import JWKSCache, JWKSError, JWTMechanism, OIDCProvider, Token
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import create_test_client

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

ISSUER = "https://issuer.example.test"
JWKS_URL = f"{ISSUER}/jwks"
KID = "test-key"
SECRET = b"shared-secret-that-is-at-least-32-bytes"


class User:
    __slots__ = ("id",)

    def __init__(self, id: str) -> None:
        self.id = id


async def retrieve_user_handler(token: Token, _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return User(id=token.sub) if token.sub == "user-1" else None


def create_hs256_jwk(secret: bytes = SECRET, kid: str = KID) -> dict[str, str]:
    return {
        "kty": "oct",
        "kid": kid,
        "k": base64url_encode(secret).decode("ascii"),
        "alg": "HS256",
    }


def create_oidc_token(
    *,
    kid: str = KID,
    issuer: str = ISSUER,
    audience: str = "api",
    secret: bytes = SECRET,
) -> str:
    return jwt.encode(
        {
            "sub": "user-1",
            "iss": issuer,
            "aud": audience,
            "iat": datetime.now(UTC) - timedelta(minutes=1),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        secret,
        algorithm="HS256",
        headers={"kid": kid},
    )


async def test_jwks_cache_fetches_once_under_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = JWKSCache()
    call_count = 0
    gate = asyncio.Event()

    async def fetch_json_document(_: JWKSCache, __: str) -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        await gate.wait()
        return {"keys": [create_hs256_jwk()]}

    monkeypatch.setattr(JWKSCache, "_fetch_json_document", fetch_json_document)

    token = create_oidc_token()
    tasks = [asyncio.create_task(cache.get_signing_key(token, JWKS_URL, algorithms=("HS256",))) for _ in range(5)]
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(*tasks)

    assert all(result.key == SECRET for result in results)
    assert call_count == 1
    assert cache.stats()["refreshes"] == 1


async def test_jwks_cache_negative_caches_unknown_kid(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = JWKSCache()
    call_count = 0

    async def fetch_json_document(_: JWKSCache, __: str) -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        return {"keys": [create_hs256_jwk(kid="other-key")]}

    monkeypatch.setattr(JWKSCache, "_fetch_json_document", fetch_json_document)

    with pytest.raises(JWKSError, match="not found"):
        await cache.get_signing_key(create_oidc_token(kid="missing-key"), JWKS_URL, algorithms=("HS256",))
    with pytest.raises(JWKSError, match="cached negative"):
        await cache.get_signing_key(create_oidc_token(kid="missing-key"), JWKS_URL, algorithms=("HS256",))

    assert call_count == 1
    assert cache.stats()["negative_hits"] == 1


async def test_jwks_cache_serves_stale_key_and_schedules_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = JWKSCache(cache_ttl=10, stale_grace_seconds=60)
    monkeypatch.setattr(time, "monotonic", lambda: 0.0)
    await cache.set_jwks(JWKS_URL, {"keys": [create_hs256_jwk()]}, ttl=10)

    refresh_started = asyncio.Event()

    async def fetch_json_document(_: JWKSCache, __: str) -> dict[str, Any]:
        refresh_started.set()
        return {"keys": [create_hs256_jwk()]}

    monkeypatch.setattr(JWKSCache, "_fetch_json_document", fetch_json_document)
    monkeypatch.setattr(time, "monotonic", lambda: 30.0)

    key = await cache.get_signing_key(create_oidc_token(), JWKS_URL, algorithms=("HS256",))
    await asyncio.wait_for(refresh_started.wait(), timeout=1)

    assert key.key == SECRET
    assert cache.stats()["stale_serves"] == 1


async def test_jwks_cache_stats_are_snapshots() -> None:
    cache = JWKSCache()
    snapshot = cache.stats()
    snapshot["hits"] = 999

    assert cache.stats()["hits"] == 0


async def test_oidc_provider_uses_discovery_and_shared_security_plugin_cache() -> None:
    cache = JWKSCache()
    await cache.set_json_document(
        f"{ISSUER}/.well-known/openid-configuration",
        {"jwks_uri": JWKS_URL},
        ttl=60,
    )
    await cache.set_jwks(JWKS_URL, {"keys": [create_hs256_jwk()]}, ttl=60)
    mechanism = JWTMechanism[User](
        retrieve_user_handler=retrieve_user_handler,
        oidc_provider=OIDCProvider(issuer=ISSUER, audience="api", algorithms=("HS256",)),
    )

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism], jwks_cache=cache)]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(create_oidc_token())})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1"}
    assert cache.stats()["hits"] == 1


async def test_oidc_provider_invokes_validation_error_hook() -> None:
    errors: list[tuple[str, str]] = []
    cache = JWKSCache()
    await cache.set_jwks(JWKS_URL, {"keys": [create_hs256_jwk()]}, ttl=60)
    provider = OIDCProvider(
        issuer=ISSUER,
        audience="api",
        jwks_uri=JWKS_URL,
        algorithms=("HS256",),
        on_validation_error=lambda issuer, exc: errors.append((issuer, type(exc).__name__)),
    )
    mechanism = JWTMechanism[User](retrieve_user_handler=retrieve_user_handler, oidc_provider=provider)

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism], jwks_cache=cache)]) as client:
        response = client.get(
            "/",
            headers={"Authorization": mechanism.format_auth_header(create_oidc_token(audience="wrong"))},
        )

    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert errors and errors[0][0] == ISSUER
