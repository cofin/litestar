__all__ = ("ConflictError", "NotFoundError", "RepositoryError")


class RepositoryError(Exception):  # pragma: no cover
    """Base repository exception type."""


class ConflictError(RepositoryError):  # pragma: no cover
    """Data integrity error."""


class NotFoundError(RepositoryError):  # pragma: no cover
    """An identity does not exist."""
