from __future__ import annotations

import pytest
from docs.examples.security import provider_cookbook
from docs.examples.security.using_abstract_authentication_middleware import app as custom_auth_app

from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import TestClient


@pytest.mark.parametrize(
    ("factory_name", "scheme_name"),
    (
        ("create_auth0_app", "Auth0Bearer"),
        ("create_keycloak_app", "KeycloakBearer"),
        ("create_entra_app", "EntraBearer"),
        ("create_iap_app", "IAPToken"),
        ("create_aws_alb_app", "AWSALBToken"),
        ("create_cloudflare_access_app", "CloudflareAccessToken"),
    ),
)
def test_provider_cookbook_apps_register_security_schemes(factory_name: str, scheme_name: str) -> None:
    app = getattr(provider_cookbook, factory_name)()

    schema = app.openapi_schema.to_schema()

    assert scheme_name in schema["components"]["securitySchemes"]


def test_provider_cookbook_websocket_query_token() -> None:
    with (
        TestClient(provider_cookbook.websocket_query_app) as client,
        client.websocket_connect("/ws?token=demo-key") as ws,
    ):
        assert ws.receive_json() == {"user": "websocket-user", "token": "demo-key"}


def test_provider_cookbook_websocket_subprotocol_token() -> None:
    with (
        TestClient(provider_cookbook.websocket_subprotocol_app) as client,
        client.websocket_connect("/ws", subprotocols=["auth.demo-key"]) as ws,
    ):
        assert ws.receive_json() == {"user": "websocket-user", "token": "auth.demo-key"}


async def test_provider_cookbook_jwks_cache_fixture() -> None:
    cache = await provider_cookbook.build_test_jwks_cache()

    document = await cache.get_json_document(provider_cookbook.TEST_DISCOVERY_URL)

    assert document["jwks_uri"] == provider_cookbook.TEST_JWKS_URI
    assert cache.stats()["hits"] == 0


def test_custom_auth_mechanism_example_uses_security_plugin() -> None:
    with TestClient(custom_auth_app) as client:
        response = client.get("/", headers={"X-API-KEY": "1"})
        assert response.status_code == HTTP_200_OK

        response = client.get("/")
        assert response.status_code == HTTP_401_UNAUTHORIZED
