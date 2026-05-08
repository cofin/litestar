"""Tests for ``litestar.security.types`` — the canonical home of ``AuthenticationResult``.

T1 of the security-plugin foundation (litestar-dn1) moves ``AuthenticationResult`` out of
``litestar.middleware.authentication`` and into ``litestar.security.types``. The old
import path must be gone.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass

import pytest


def test_authentication_result_importable_from_security_package() -> None:
    from litestar.security import AuthenticationResult

    assert AuthenticationResult is not None


def test_authentication_result_importable_from_security_types() -> None:
    from litestar.security.types import AuthenticationResult

    assert AuthenticationResult is not None


def test_security_package_and_types_module_export_same_object() -> None:
    from litestar.security import AuthenticationResult as from_package
    from litestar.security.types import AuthenticationResult as from_types

    assert from_package is from_types


def test_authentication_result_is_dataclass_with_user_and_auth_fields() -> None:
    from litestar.security.types import AuthenticationResult

    assert is_dataclass(AuthenticationResult)
    field_names = {f.name for f in fields(AuthenticationResult)}
    assert field_names == {"user", "auth"}


def test_authentication_result_uses_slots() -> None:
    from litestar.security.types import AuthenticationResult

    assert AuthenticationResult.__slots__ == ("auth", "user")


def test_authentication_result_no_longer_exported_from_middleware_authentication() -> None:
    import litestar.middleware.authentication as middleware_authentication

    assert not hasattr(middleware_authentication, "AuthenticationResult")
    assert "AuthenticationResult" not in getattr(middleware_authentication, "__all__", ())


def test_authentication_result_no_longer_exported_from_litestar_middleware() -> None:
    import litestar.middleware as middleware_pkg

    assert "AuthenticationResult" not in getattr(middleware_pkg, "__all__", ())


def test_old_import_path_raises_import_error() -> None:
    with pytest.raises(ImportError):
        exec("from litestar.middleware.authentication import AuthenticationResult")


def test_old_abstract_security_imports_are_removed() -> None:
    import litestar.middleware as middleware_pkg
    import litestar.middleware.authentication as middleware_authentication
    import litestar.security as security_pkg

    assert not hasattr(security_pkg, "AbstractSecurityConfig")
    assert "AbstractSecurityConfig" not in security_pkg.__all__
    assert not hasattr(middleware_pkg, "AbstractAuthenticationMiddleware")
    assert "AbstractAuthenticationMiddleware" not in middleware_pkg.__all__
    assert not hasattr(middleware_authentication, "AbstractAuthenticationMiddleware")
    assert "AbstractAuthenticationMiddleware" not in getattr(middleware_authentication, "__all__", ())

    with pytest.raises(ImportError):
        exec("from litestar.security import AbstractSecurityConfig")
    with pytest.raises(ImportError):
        exec("from litestar.middleware import AbstractAuthenticationMiddleware")
    with pytest.raises(ImportError):
        exec("from litestar.middleware.authentication import AbstractAuthenticationMiddleware")


def test_security_plugin_foundation_public_exports() -> None:
    from litestar.security import AuthenticationContext, AuthenticationResult, AuthMechanism, SecurityPlugin

    assert AuthMechanism is not None
    assert AuthenticationContext is not None
    assert AuthenticationResult is not None
    assert SecurityPlugin is not None

    import litestar.security as security_pkg

    assert security_pkg.__all__ == (
        "OPT_AUTH_MECHANISM",
        "OPT_EXCLUDE_FROM_AUTH",
        "AuthMechanism",
        "AuthenticationContext",
        "AuthenticationResult",
        "SecurityPlugin",
    )
