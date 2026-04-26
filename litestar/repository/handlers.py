# ruff: noqa: F401
from typing import TYPE_CHECKING

from litestar.utils import warn_deprecation

__all__ = ("on_app_init", "signature_namespace_values")


def __getattr__(attr_name: str) -> "object":
    if attr_name in __all__:
        from litestar.repository._handlers import on_app_init, signature_namespace_values

        warn_deprecation(
            deprecated_name=f"litestar.repository.handlers.{attr_name}",
            version="3.0.0b0",
            kind="import",
            removal_in="3.0.0",
            info=(
                f"importing {attr_name} from 'litestar.repository.handlers' is deprecated. "
                "There is no direct replacement; wire the filter signature namespace yourself, "
                "or use 'advanced_alchemy.extensions.litestar.SQLAlchemyPlugin' which registers "
                "it for you. The litestar.repository module is removed at 3.0.0 GA."
            ),
        )
        value = globals()[attr_name] = locals()[attr_name]
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {attr_name!r}")  # pragma: no cover


if TYPE_CHECKING:
    from litestar.repository._handlers import on_app_init, signature_namespace_values
