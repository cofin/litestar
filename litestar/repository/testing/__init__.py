from typing import TYPE_CHECKING

from litestar.utils import warn_deprecation

__all__ = (
    "GenericAsyncMockRepository",
    "GenericSyncMockRepository",
)


def __getattr__(attr_name: str) -> "object":
    if attr_name in __all__:
        from litestar.repository.testing import generic_mock_repository as _module

        value = getattr(_module, attr_name)
        warn_deprecation(
            deprecated_name=f"litestar.repository.testing.{attr_name}",
            version="3.0.0b0",
            kind="import",
            removal_in="3.0.0",
            info=(
                f"importing {attr_name} from 'litestar.repository.testing' is deprecated. "
                "There is no replacement; the generic mock repository is removed at 3.0.0 GA "
                "without a migration target. Rewrite tests against a real repository or use "
                "the testing utilities provided by 'advanced_alchemy'."
            ),
        )
        globals()[attr_name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


if TYPE_CHECKING:
    from litestar.repository.testing.generic_mock_repository import (
        GenericAsyncMockRepository,
        GenericSyncMockRepository,
    )
