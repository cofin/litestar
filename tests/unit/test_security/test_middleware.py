from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from litestar.connection.base import empty_receive, empty_send
from litestar.exceptions import ImproperlyConfiguredException
from litestar.security import AuthenticationResult
from litestar.testing import RequestFactory

from .helpers import StubAuthMechanism

if TYPE_CHECKING:
    from litestar.types import Receive, Scope, Send


class ScopeRecorder:
    __slots__ = ("scope",)

    def __init__(self) -> None:
        self.scope: Scope | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.scope = scope


def create_unauthenticated_request() -> Any:
    request = RequestFactory().get()
    scope = cast("dict[str, Any]", request.scope)
    scope.pop("user", None)
    scope.pop("auth", None)
    return request


async def test_security_middleware_uses_first_success_after_declines() -> None:
    from litestar.security._middleware import SecurityMiddleware

    result = AuthenticationResult(user={"id": "user-1"}, auth={"token": "abc"})
    first = StubAuthMechanism(should_decline=True)
    second = StubAuthMechanism(result=result)
    recorder = ScopeRecorder()
    request = create_unauthenticated_request()

    await SecurityMiddleware(app=recorder, mechanisms=[first, second])(request.scope, empty_receive, empty_send)

    assert recorder.scope is request.scope
    assert request.scope["user"] == result.user
    assert request.scope["auth"] == result.auth
    assert len(first.calls) == 1
    assert len(second.calls) == 1
    assert first.calls[0][1] is second.calls[0][1]


async def test_security_middleware_stops_after_first_success() -> None:
    from litestar.security._middleware import SecurityMiddleware

    result = AuthenticationResult(user={"id": "user-1"}, auth={"token": "abc"})
    first = StubAuthMechanism(result=result)
    second = StubAuthMechanism()
    request = create_unauthenticated_request()

    await SecurityMiddleware(app=ScopeRecorder(), mechanisms=[first, second])(request.scope, empty_receive, empty_send)

    assert request.scope["user"] == result.user
    assert request.scope["auth"] == result.auth
    assert len(first.calls) == 1
    assert second.calls == []


async def test_security_middleware_leaves_scope_unauthenticated_when_all_mechanisms_decline() -> None:
    from litestar.security._middleware import SecurityMiddleware

    first = StubAuthMechanism(should_decline=True)
    second = StubAuthMechanism(should_decline=True)
    request = create_unauthenticated_request()

    await SecurityMiddleware(app=ScopeRecorder(), mechanisms=[first, second])(request.scope, empty_receive, empty_send)

    assert "user" not in request.scope
    assert "auth" not in request.scope
    assert len(first.calls) == 1
    assert len(second.calls) == 1
    with pytest.raises(ImproperlyConfiguredException):
        request.user
