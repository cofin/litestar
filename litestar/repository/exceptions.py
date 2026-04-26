from typing import TYPE_CHECKING

from litestar.utils import warn_deprecation

__all__ = ("ConflictError", "NotFoundError", "RepositoryError")

_ALTERNATIVES = {
    "ConflictError": "advanced_alchemy.exceptions.IntegrityError",
    "NotFoundError": "advanced_alchemy.exceptions.NotFoundError",
    "RepositoryError": "advanced_alchemy.exceptions.RepositoryError",
}


def _resolve(attr_name: str) -> "object":
    try:
        from advanced_alchemy import exceptions as _ae_exc

        mapping = {
            "ConflictError": _ae_exc.IntegrityError,
            "NotFoundError": _ae_exc.NotFoundError,
            "RepositoryError": _ae_exc.RepositoryError,
        }
        return mapping[attr_name]
    except ImportError:  # pragma: no cover
        from litestar.repository import _exceptions

        return getattr(_exceptions, attr_name)


def __getattr__(attr_name: str) -> "object":
    if attr_name in __all__:
        warn_deprecation(
            deprecated_name=f"litestar.repository.exceptions.{attr_name}",
            version="3.0.0b0",
            kind="import",
            removal_in="3.0.0",
            alternative=_ALTERNATIVES[attr_name],
            info=(
                "The litestar.repository module is removed at 3.0.0 GA. "
                "Migrate to advanced_alchemy.exceptions directly."
            ),
        )
        value = globals()[attr_name] = _resolve(attr_name)
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


if TYPE_CHECKING:
    from litestar.repository._exceptions import ConflictError, NotFoundError, RepositoryError
