from typing import TYPE_CHECKING

from litestar.utils import warn_deprecation

__all__ = (
    "AbstractAsyncRepository",
    "AbstractSyncRepository",
    "ConflictError",
    "FilterTypes",
    "NotFoundError",
    "RepositoryError",
)

_ALTERNATIVES = {
    "AbstractAsyncRepository": "advanced_alchemy.repository.SQLAlchemyAsyncRepository",
    "AbstractSyncRepository": "advanced_alchemy.repository.SQLAlchemySyncRepository",
    "ConflictError": "advanced_alchemy.exceptions.IntegrityError",
    "NotFoundError": "advanced_alchemy.exceptions.NotFoundError",
    "RepositoryError": "advanced_alchemy.exceptions.RepositoryError",
    "FilterTypes": "advanced_alchemy.filters.FilterTypes",
}


def _resolve(attr_name: str) -> "object":
    if attr_name == "AbstractAsyncRepository":
        from litestar.repository.abc._async import AbstractAsyncRepository

        return AbstractAsyncRepository
    if attr_name == "AbstractSyncRepository":
        from litestar.repository.abc._sync import AbstractSyncRepository

        return AbstractSyncRepository
    if attr_name in {"ConflictError", "NotFoundError", "RepositoryError"}:
        try:
            from advanced_alchemy import exceptions as _ae_exc

            mapping = {
                "ConflictError": _ae_exc.IntegrityError,
                "NotFoundError": _ae_exc.NotFoundError,
                "RepositoryError": _ae_exc.RepositoryError,
            }
            return mapping[attr_name]
        except ImportError:
            from litestar.repository import _exceptions

            return getattr(_exceptions, attr_name)
    if attr_name == "FilterTypes":
        try:
            from advanced_alchemy.filters import FilterTypes

            return FilterTypes
        except ImportError:
            from litestar.repository._filters import FilterTypes

            return FilterTypes
    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


def __getattr__(attr_name: str) -> "object":
    if attr_name in __all__:
        warn_deprecation(
            deprecated_name=f"litestar.repository.{attr_name}",
            version="3.0.0b0",
            kind="import",
            removal_in="3.0.0",
            alternative=_ALTERNATIVES[attr_name],
            info=("The litestar.repository module is removed at 3.0.0 GA. Migrate to advanced_alchemy directly."),
        )
        value = globals()[attr_name] = _resolve(attr_name)
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


if TYPE_CHECKING:
    from litestar.repository._exceptions import ConflictError, NotFoundError, RepositoryError
    from litestar.repository._filters import FilterTypes
    from litestar.repository.abc._async import AbstractAsyncRepository
    from litestar.repository.abc._sync import AbstractSyncRepository
