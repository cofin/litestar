# pyright: reportUnnecessaryTypeIgnoreComment=false
# Internal resolver for repository exceptions. Mirrors the historical
# ``litestar.repository.exceptions`` runtime semantics (advanced_alchemy if
# available, fallback stubs otherwise) without emitting DeprecationWarning so
# in-package callers can use these symbols safely.

try:
    from advanced_alchemy.exceptions import IntegrityError as ConflictError
    from advanced_alchemy.exceptions import NotFoundError, RepositoryError
except ImportError:  # pragma: no cover
    from litestar.repository._exceptions_stubs import (  # type: ignore[assignment]
        ConflictError,
        NotFoundError,
        RepositoryError,
    )


__all__ = ("ConflictError", "NotFoundError", "RepositoryError")
