from typing import TYPE_CHECKING

from litestar.utils import warn_deprecation

__all__ = (
    "AbstractAsyncRepository",
    "AbstractSyncRepository",
)


def _resolve(attr_name: str) -> "object":
    if attr_name == "AbstractAsyncRepository":
        from litestar.repository.abc._async import AbstractAsyncRepository

        return AbstractAsyncRepository
    from litestar.repository.abc._sync import AbstractSyncRepository

    return AbstractSyncRepository


def __getattr__(attr_name: str) -> "object":
    if attr_name in __all__:
        warn_deprecation(
            deprecated_name=f"litestar.repository.abc.{attr_name}",
            version="3.0.0b0",
            kind="import",
            removal_in="3.0.0",
            info=(
                f"importing {attr_name} from 'litestar.repository.abc' is deprecated. "
                "There is no direct replacement; adopt 'advanced_alchemy.repository."
                "SQLAlchemyAsyncRepository' / 'SQLAlchemySyncRepository' directly. "
                "The litestar.repository module is removed at 3.0.0 GA."
            ),
        )
        value = globals()[attr_name] = _resolve(attr_name)
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


if TYPE_CHECKING:
    from litestar.repository.abc._async import AbstractAsyncRepository
    from litestar.repository.abc._sync import AbstractSyncRepository
