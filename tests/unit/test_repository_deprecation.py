"""Assert every public symbol under ``litestar.repository.*`` fires
``DeprecationWarning`` on access and that the warning text names the
``advanced_alchemy`` replacement (or "no replacement").

The whole module is removed at 3.0.0 GA via the ``pre-ga-shim-removal`` PR.
"""

import importlib
from typing import Any

import pytest

CASES: list[tuple[str, str, str]] = [
    ("litestar.repository", "AbstractAsyncRepository", "advanced_alchemy.repository.SQLAlchemyAsyncRepository"),
    ("litestar.repository", "AbstractSyncRepository", "advanced_alchemy.repository.SQLAlchemySyncRepository"),
    ("litestar.repository", "ConflictError", "advanced_alchemy.exceptions.IntegrityError"),
    ("litestar.repository", "NotFoundError", "advanced_alchemy.exceptions.NotFoundError"),
    ("litestar.repository", "RepositoryError", "advanced_alchemy.exceptions.RepositoryError"),
    ("litestar.repository", "FilterTypes", "advanced_alchemy.filters.FilterTypes"),
    ("litestar.repository.exceptions", "ConflictError", "advanced_alchemy.exceptions.IntegrityError"),
    ("litestar.repository.exceptions", "NotFoundError", "advanced_alchemy.exceptions.NotFoundError"),
    ("litestar.repository.exceptions", "RepositoryError", "advanced_alchemy.exceptions.RepositoryError"),
    ("litestar.repository.filters", "BeforeAfter", "advanced_alchemy.filters.BeforeAfter"),
    ("litestar.repository.filters", "CollectionFilter", "advanced_alchemy.filters.CollectionFilter"),
    ("litestar.repository.filters", "FilterTypes", "advanced_alchemy.filters.FilterTypes"),
    ("litestar.repository.filters", "LimitOffset", "advanced_alchemy.filters.LimitOffset"),
    ("litestar.repository.filters", "NotInCollectionFilter", "advanced_alchemy.filters.NotInCollectionFilter"),
    ("litestar.repository.filters", "NotInSearchFilter", "advanced_alchemy.filters.NotInSearchFilter"),
    ("litestar.repository.filters", "OnBeforeAfter", "advanced_alchemy.filters.OnBeforeAfter"),
    ("litestar.repository.filters", "OrderBy", "advanced_alchemy.filters.OrderBy"),
    ("litestar.repository.filters", "SearchFilter", "advanced_alchemy.filters.SearchFilter"),
    ("litestar.repository.abc", "AbstractAsyncRepository", "no direct replacement"),
    ("litestar.repository.abc", "AbstractSyncRepository", "no direct replacement"),
    ("litestar.repository.handlers", "on_app_init", "no direct replacement"),
    ("litestar.repository.handlers", "signature_namespace_values", "no direct replacement"),
    ("litestar.repository.testing", "GenericAsyncMockRepository", "no replacement"),
    ("litestar.repository.testing", "GenericSyncMockRepository", "no replacement"),
]


@pytest.mark.parametrize(("module_name", "symbol", "expected_in_message"), CASES)
def test_symbol_emits_deprecation_warning(module_name: str, symbol: str, expected_in_message: str) -> None:
    module = importlib.import_module(module_name)
    module.__dict__.pop(symbol, None)
    with pytest.warns(DeprecationWarning, match=expected_in_message):
        obj: Any = getattr(module, symbol)
    assert obj is not None


def test_package_import_is_silent() -> None:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        importlib.import_module("litestar.repository")
        importlib.import_module("litestar.repository.exceptions")
        importlib.import_module("litestar.repository.filters")
        importlib.import_module("litestar.repository.handlers")
        importlib.import_module("litestar.repository.abc")
        importlib.import_module("litestar.repository.testing")
