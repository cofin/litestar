from __future__ import annotations

import dataclasses
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from litestar import Request, get
from litestar.exceptions import NotAuthorizedException
from litestar.security import AuthenticationContext, SecurityPlugin
from litestar.security.jwt import JWTCookieMechanism, JWTMechanism, Token
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import RequestFactory, create_test_client

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection


@dataclasses.dataclass
class User:
    id: str
    name: str = "Jane"


async def retrieve_user_handler(token: Token, _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
    return User(id=token.sub) if token.sub == "user-1" else None


def create_jwt_mechanism(**kwargs: Any) -> JWTMechanism[User, Token]:
    return JWTMechanism[User](
        token_secret=kwargs.pop("token_secret", secrets.token_hex()),
        retrieve_user_handler=retrieve_user_handler,
        **kwargs,
    )


def create_jwt_cookie_mechanism(**kwargs: Any) -> JWTCookieMechanism[User, Token]:
    return JWTCookieMechanism[User](
        token_secret=kwargs.pop("token_secret", secrets.token_hex()),
        retrieve_user_handler=retrieve_user_handler,
        **kwargs,
    )


def serialize_private_key(key: Any) -> bytes:
    return cast(
        "bytes",
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def serialize_public_key(key: Any) -> bytes:
    return cast(
        "bytes",
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def create_rsa_key_pair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return serialize_private_key(key), serialize_public_key(key)


def create_ec_key_pair() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    return serialize_private_key(key), serialize_public_key(key)


def create_eddsa_key_pair() -> tuple[bytes, bytes]:
    key = ed25519.Ed25519PrivateKey.generate()
    return serialize_private_key(key), serialize_public_key(key)


def create_raw_jwt(
    *,
    secret: str | bytes,
    algorithm: str,
    subject: str = "user-1",
    issuer: str | None = None,
    audience: str | list[str] | None = None,
    expires_delta: timedelta = timedelta(minutes=5),
    extra_claims: dict[str, Any] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": datetime.now(UTC) - timedelta(minutes=1),
        "exp": datetime.now(UTC) + expires_delta,
        **(extra_claims or {}),
    }
    if issuer:
        payload["iss"] = issuer
    if audience:
        payload["aud"] = audience
    return jwt.encode(payload=payload, key=secret, algorithm=algorithm)


def test_jwt_package_exports_mechanisms_and_removes_old_config_names() -> None:
    import litestar.security.jwt as jwt_security

    assert jwt_security.JWTMechanism is JWTMechanism
    assert jwt_security.JWTCookieMechanism is JWTCookieMechanism
    assert jwt_security.Token is Token
    for old_name in (
        "BaseJWTAuth",
        "JWTAuth",
        "JWTCookieAuth",
        "OAuth2PasswordBearerAuth",
        "JWTAuthenticationMiddleware",
        "JWTCookieAuthenticationMiddleware",
    ):
        assert not hasattr(jwt_security, old_name)


async def test_jwt_mechanism_declines_when_authorization_header_is_missing() -> None:
    mechanism = create_jwt_mechanism()
    request = RequestFactory().get("/")

    assert await mechanism.authenticate(request, AuthenticationContext()) is None


def test_jwt_mechanism_authenticates_bearer_token_with_security_plugin() -> None:
    mechanism = create_jwt_mechanism()
    encoded_token = mechanism.create_token("user-1")

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id, "subject": request.auth.sub}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1", "subject": "user-1"}


@pytest.mark.parametrize(
    ("algorithm", "private_key", "public_key"),
    [
        ("HS256", "shared-secret-that-is-at-least-32-bytes", "shared-secret-that-is-at-least-32-bytes"),
        ("RS256", *create_rsa_key_pair()),
        ("ES256", *create_ec_key_pair()),
        ("EdDSA", *create_eddsa_key_pair()),
    ],
)
def test_jwt_mechanism_authenticates_supported_algorithms(
    algorithm: str,
    private_key: str | bytes,
    public_key: str | bytes,
) -> None:
    mechanism = create_jwt_mechanism(token_secret=public_key, algorithm=algorithm)
    encoded_token = create_raw_jwt(secret=private_key, algorithm=algorithm)

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1"}


@pytest.mark.parametrize("header_value", ["not-a-jwt", "Bearer", "Bearer "])
def test_jwt_mechanism_rejects_malformed_authorization_header(header_value: str) -> None:
    mechanism = create_jwt_mechanism()

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": header_value})

    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert response.headers["www-authenticate"] == "Bearer"


def test_jwt_mechanism_rejects_revoked_token() -> None:
    async def revoked_token_handler(_: Token, __: ASGIConnection[Any, Any, Any, Any]) -> bool:
        return True

    mechanism = create_jwt_mechanism(revoked_token_handler=revoked_token_handler)
    encoded_token = mechanism.create_token("user-1")

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_jwt_mechanism_decodes_token_with_leeway() -> None:
    token_secret = secrets.token_hex()
    encoded_token = jwt.encode(
        payload={
            "sub": "user-1",
            "iat": datetime.now(UTC) - timedelta(minutes=1),
            "exp": datetime.now(UTC) - timedelta(seconds=1),
        },
        key=token_secret,
        algorithm="HS256",
    )
    mechanism = create_jwt_mechanism(token_secret=token_secret, leeway=timedelta(seconds=5))

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1"}


def test_jwt_mechanism_uses_custom_token_class() -> None:
    @dataclasses.dataclass
    class CustomToken(Token):
        random_field: int = 1

    async def retrieve_custom_user_handler(token: CustomToken, _: ASGIConnection[Any, Any, Any, Any]) -> User | None:
        return User(id=token.sub) if token.random_field == 2 else None

    mechanism: JWTMechanism[User, CustomToken] = JWTMechanism(
        token_secret=secrets.token_hex(),
        retrieve_user_handler=retrieve_custom_user_handler,
        token_cls=CustomToken,
    )
    encoded_token = mechanism.create_token("user-1", random_field="2")

    @get("/")
    def handler(request: Request[User, Any, Any]) -> dict[str, int | str]:
        return {"user": request.user.id, "random_field": request.auth.random_field}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1", "random_field": 2}


@pytest.mark.parametrize(
    ("accepted_issuers", "token_issuer", "expected_status_code"),
    [
        (["issuer-a"], "issuer-a", HTTP_200_OK),
        (["issuer-a", "issuer-b"], "issuer-b", HTTP_200_OK),
        (["issuer-b"], "issuer-a", HTTP_401_UNAUTHORIZED),
    ],
)
def test_jwt_mechanism_verifies_issuer(
    accepted_issuers: list[str],
    token_issuer: str,
    expected_status_code: int,
) -> None:
    token_secret = secrets.token_hex()
    mechanism = create_jwt_mechanism(token_secret=token_secret, accepted_issuers=accepted_issuers)
    encoded_token = create_raw_jwt(secret=token_secret, algorithm="HS256", issuer=token_issuer)

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == expected_status_code


@pytest.mark.parametrize(
    ("accepted_audiences", "token_audience", "expected_status_code"),
    [
        (["audience-a"], "audience-a", HTTP_200_OK),
        (["audience-a", "audience-b"], "audience-b", HTTP_200_OK),
        (["audience-b"], "audience-a", HTTP_401_UNAUTHORIZED),
    ],
)
def test_jwt_mechanism_verifies_audience(
    accepted_audiences: list[str],
    token_audience: str,
    expected_status_code: int,
) -> None:
    token_secret = secrets.token_hex()
    mechanism = create_jwt_mechanism(token_secret=token_secret, accepted_audiences=accepted_audiences)
    encoded_token = create_raw_jwt(secret=token_secret, algorithm="HS256", audience=token_audience)

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == expected_status_code


@pytest.mark.parametrize(
    ("require_claims", "extra_claims", "expected_status_code"),
    [
        (["azp"], {"azp": "client"}, HTTP_200_OK),
        (["azp"], {}, HTTP_401_UNAUTHORIZED),
        ([], {}, HTTP_200_OK),
    ],
)
def test_jwt_mechanism_requires_claims(
    require_claims: list[str],
    extra_claims: dict[str, Any],
    expected_status_code: int,
) -> None:
    token_secret = secrets.token_hex()
    mechanism = create_jwt_mechanism(token_secret=token_secret, require_claims=require_claims)
    encoded_token = create_raw_jwt(secret=token_secret, algorithm="HS256", extra_claims=extra_claims)

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == expected_status_code


def test_jwt_mechanism_can_disable_expiration_verification() -> None:
    token_secret = secrets.token_hex()
    mechanism = create_jwt_mechanism(token_secret=token_secret, verify_expiry=False)
    encoded_token = create_raw_jwt(secret=token_secret, algorithm="HS256", expires_delta=timedelta(minutes=-1))

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        response = client.get("/", headers={"Authorization": mechanism.format_auth_header(encoded_token)})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1"}


def test_jwt_mechanism_openapi_contribution() -> None:
    mechanism = create_jwt_mechanism()

    assert mechanism.openapi_components().to_schema() == {
        "schemas": {},
        "securitySchemes": {
            "BearerToken": {
                "type": "http",
                "description": "JWT bearer authentication and authorization.",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        },
    }
    assert mechanism.openapi_security_requirement() == {"BearerToken": []}


def test_jwt_cookie_mechanism_accepts_bearer_prefixed_cookie() -> None:
    mechanism = create_jwt_cookie_mechanism()
    encoded_token = mechanism.create_token("user-1")

    @get("/")
    def handler(request: Request[User, Token, Any]) -> dict[str, str]:
        return {"user": request.user.id}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        client.cookies = {mechanism.key: mechanism.format_auth_header(encoded_token)}
        response = client.get("/")

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"user": "user-1"}


@pytest.mark.parametrize("cookie_value", ["", "Bearer", "Bearer "])
def test_jwt_cookie_mechanism_rejects_empty_cookie_token(cookie_value: str) -> None:
    mechanism = create_jwt_cookie_mechanism()

    @get("/")
    def handler() -> dict[str, str]:
        return {"status": "ok"}

    with create_test_client([handler], plugins=[SecurityPlugin([mechanism])]) as client:
        client.cookies = {mechanism.key: cookie_value}
        response = client.get("/")

    assert response.status_code == HTTP_401_UNAUTHORIZED


def test_jwt_cookie_mechanism_sets_cookie_on_login_response() -> None:
    mechanism = create_jwt_cookie_mechanism()

    response = mechanism.login("user-1", response_body={"ok": True})

    assert response.status_code == 201
    assert response.headers["Authorization"].startswith("Bearer ")
    assert response.cookies[0].key == mechanism.key
    assert response.cookies[0].httponly is True


async def test_jwt_mechanism_authenticate_token_rejects_missing_user() -> None:
    mechanism = create_jwt_mechanism()
    encoded_token = mechanism.create_token("missing-user")

    with pytest.raises(NotAuthorizedException):
        await mechanism.authenticate_token(encoded_token, RequestFactory().get("/"))
