from __future__ import annotations

from dataclasses import fields, is_dataclass

from litestar.security import AuthenticationResult
from litestar.testing import RequestFactory

from .helpers import MissingAuthenticateAuthMechanism, MissingNameAuthMechanism, StubAuthMechanism


def test_security_package_exports_auth_mechanism_and_context() -> None:
    from litestar.security import AuthenticationContext, AuthMechanism

    assert AuthMechanism is not None
    assert AuthenticationContext is not None


def test_auth_mechanism_protocol_accepts_complete_stub() -> None:
    from litestar.security import AuthMechanism

    assert isinstance(StubAuthMechanism(), AuthMechanism)


def test_auth_mechanism_protocol_rejects_missing_name() -> None:
    from litestar.security import AuthMechanism

    assert not isinstance(MissingNameAuthMechanism(), AuthMechanism)


def test_auth_mechanism_protocol_rejects_missing_authenticate() -> None:
    from litestar.security import AuthMechanism

    assert not isinstance(MissingAuthenticateAuthMechanism(), AuthMechanism)


async def test_stub_auth_mechanism_returns_fixed_authentication_result() -> None:
    from litestar.security import AuthenticationContext

    result = AuthenticationResult(user={"id": "user-1"}, auth={"token": "abc"})
    mechanism = StubAuthMechanism(result=result)
    connection = RequestFactory().get()
    context = AuthenticationContext(settings={"issuer": "test"})

    assert await mechanism.authenticate(connection, context) is result
    assert mechanism.calls == [(connection, context)]


def test_authentication_context_is_dataclass_with_slots() -> None:
    from litestar.security import AuthenticationContext

    assert is_dataclass(AuthenticationContext)
    assert AuthenticationContext.__slots__ == ("jwks_cache", "settings", "_extras")
    assert {field.name for field in fields(AuthenticationContext)} == {"jwks_cache", "settings", "_extras"}


def test_authentication_context_defaults_are_per_instance() -> None:
    from litestar.security import AuthenticationContext

    context = AuthenticationContext(settings={"issuer": "test"})
    other_context = AuthenticationContext(settings={"issuer": "other"})

    assert context.jwks_cache is None
    assert context.settings == {"issuer": "test"}
    assert context._extras == {}
    context._extras["mechanism"] = "stub"
    assert other_context._extras == {}
