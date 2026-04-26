from typing import TYPE_CHECKING

from litestar.utils import warn_deprecation

__all__ = (
    "BeforeAfter",
    "CollectionFilter",
    "FilterTypes",
    "LimitOffset",
    "NotInCollectionFilter",
    "NotInSearchFilter",
    "OnBeforeAfter",
    "OrderBy",
    "SearchFilter",
)


def _resolve(attr_name: str) -> "object":
    try:
        from advanced_alchemy import filters as _ae_filters

        return getattr(_ae_filters, attr_name)
    except ImportError:  # pragma: no cover
        from litestar.repository import _filters

        return getattr(_filters, attr_name)


def __getattr__(attr_name: str) -> "object":
    if attr_name in __all__:
        warn_deprecation(
            deprecated_name=f"litestar.repository.filters.{attr_name}",
            version="3.0.0b0",
            kind="import",
            removal_in="3.0.0",
            alternative=f"advanced_alchemy.filters.{attr_name}",
            info=(
                "The litestar.repository module is removed at 3.0.0 GA. Migrate to advanced_alchemy.filters directly."
            ),
        )
        value = globals()[attr_name] = _resolve(attr_name)
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


if TYPE_CHECKING:
    from litestar.repository._filters import (
        BeforeAfter,
        CollectionFilter,
        FilterTypes,
        LimitOffset,
        NotInCollectionFilter,
        NotInSearchFilter,
        OnBeforeAfter,
        OrderBy,
        SearchFilter,
    )
