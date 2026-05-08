from __future__ import annotations

import asyncio
import inspect
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

import httpx
import jwt
from jwt.exceptions import PyJWTError

if TYPE_CHECKING:
    from datetime import timedelta

__all__ = ("JWKSCache", "JWKSError", "OIDCProvider", "ValidationErrorHook", "invoke_validation_error_hook")

ValidationErrorHook = Callable[[str, BaseException], None | Awaitable[None]]

_logger = logging.getLogger(__name__)


class JWKSError(Exception):
    """Error fetching or resolving a JWKS signing key."""


def _initial_stats() -> dict[str, int]:
    return {"hits": 0, "misses": 0, "refreshes": 0, "failures": 0, "stale_serves": 0, "negative_hits": 0}


@dataclass(frozen=True, slots=True)
class OIDCProvider:
    """OIDC provider configuration for JWT validation."""

    issuer: str
    audience: str | Sequence[str] | None = None
    jwks_uri: str | None = None
    discovery_url: str | None = None
    algorithms: Sequence[str] = ("RS256",)
    cache_ttl: int = 3600
    clock_skew: float | timedelta = 30
    on_validation_error: ValidationErrorHook | None = None

    @property
    def normalized_issuer(self) -> str:
        """Return the issuer URL without a trailing slash."""
        return self.issuer.rstrip("/")

    @property
    def resolved_discovery_url(self) -> str:
        """Return the configured or default OpenID discovery document URL."""
        return self.discovery_url or f"{self.normalized_issuer}/.well-known/openid-configuration"

    async def resolve_jwks_uri(self, cache: JWKSCache) -> str:
        """Resolve the JWKS URI from explicit config or OIDC discovery."""
        if self.jwks_uri:
            return self.jwks_uri
        discovery = await cache.get_json_document(self.resolved_discovery_url, ttl=self.cache_ttl)
        try:
            return cast("str", discovery["jwks_uri"])
        except KeyError as exc:
            raise JWKSError("OIDC discovery document is missing 'jwks_uri'") from exc


@dataclass(slots=True)
class _DocumentEntry:
    expires_at: float
    document: dict[str, Any]


@dataclass(slots=True)
class _JWKSEntry:
    expires_at: float
    stale_expires_at: float
    keys: dict[str, jwt.PyJWK]


@dataclass(slots=True)
class JWKSCache:
    """Async JWKS and OIDC discovery cache with TTL, SWR, single-flight, and stats."""

    cache_ttl: int = 3600
    timeout: float = 10.0
    stale_grace_seconds: int = 300
    negative_cache_ttl: int = 60
    _documents: dict[str, _DocumentEntry] = field(default_factory=dict, init=False, repr=False)
    _jwks: dict[str, _JWKSEntry] = field(default_factory=dict, init=False, repr=False)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict, init=False, repr=False)
    _missing_kids: dict[tuple[str, str], float] = field(default_factory=dict, init=False, repr=False)
    _refresh_tasks: dict[str, asyncio.Task[None]] = field(default_factory=dict, init=False, repr=False)
    _stats: dict[str, int] = field(default_factory=_initial_stats, init=False, repr=False)

    async def get_json_document(self, url: str, *, ttl: int | None = None) -> dict[str, Any]:
        """Return a cached JSON document, fetching it once on a cold miss."""
        now = time.monotonic()
        entry = self._documents.get(url)
        if entry is not None and entry.expires_at > now:
            return entry.document

        async with self._lock_for(url):
            now = time.monotonic()
            entry = self._documents.get(url)
            if entry is not None and entry.expires_at > now:
                return entry.document
            document = await self._fetch_json_document(url)
            await self.set_json_document(url, document, ttl=ttl or self.cache_ttl)
            return document

    async def set_json_document(self, url: str, document: dict[str, Any], *, ttl: int | None = None) -> None:
        """Seed or update a JSON document cache entry."""
        self._documents[url] = _DocumentEntry(expires_at=time.monotonic() + (ttl or self.cache_ttl), document=document)

    async def set_jwks(self, url: str, document: dict[str, Any], *, ttl: int | None = None) -> None:
        """Seed or update a JWKS cache entry."""
        self._set_jwks(url, document, ttl=ttl or self.cache_ttl)

    async def get_signing_key(
        self,
        token: str,
        jwks_uri: str,
        *,
        algorithms: Sequence[str],
        ttl: int | None = None,
    ) -> jwt.PyJWK:
        """Return the JWKS signing key matching a token header."""
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        algorithm = header.get("alg")
        if not isinstance(kid, str) or not kid:
            raise JWKSError("JWT header is missing 'kid'")
        if not isinstance(algorithm, str) or algorithm not in algorithms:
            raise JWKSError(f"JWT uses unsupported algorithm: {algorithm}")

        missing_key = (jwks_uri, kid)
        now = time.monotonic()
        if (negative_expiry := self._missing_kids.get(missing_key)) is not None and negative_expiry > now:
            self._stats["negative_hits"] += 1
            raise JWKSError(f"Key '{kid}' not found in JWKS (cached negative)")

        async with self._lock_for(jwks_uri):
            key = self._get_cached_key(jwks_uri, kid)
            if key is not None:
                return key

            self._stats["misses"] += 1
            await self._refresh_jwks(jwks_uri, ttl=ttl or self.cache_ttl)
            entry = self._jwks[jwks_uri]
            if kid not in entry.keys:
                self._missing_kids[missing_key] = time.monotonic() + self.negative_cache_ttl
                raise JWKSError(f"Key '{kid}' not found in JWKS")
            return entry.keys[kid]

    def stats(self) -> dict[str, int]:
        """Return a defensive copy of cache counters."""
        return dict(self._stats)

    def clear(self) -> None:
        """Clear all cached documents, JWKS entries, negative entries, locks, and counters."""
        self._documents.clear()
        self._jwks.clear()
        self._locks.clear()
        self._missing_kids.clear()
        self._refresh_tasks.clear()
        self._stats = _initial_stats()

    async def _fetch_json_document(self, url: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            return cast("dict[str, Any]", response.json())

    def _get_cached_key(self, jwks_uri: str, kid: str) -> jwt.PyJWK | None:
        now = time.monotonic()
        entry = self._jwks.get(jwks_uri)
        if entry is None or kid not in entry.keys:
            return None
        if entry.expires_at > now:
            self._stats["hits"] += 1
            return entry.keys[kid]
        if entry.stale_expires_at > now:
            self._stats["stale_serves"] += 1
            self._schedule_background_refresh(jwks_uri)
            return entry.keys[kid]
        return None

    async def _refresh_jwks(self, jwks_uri: str, *, ttl: int) -> None:
        try:
            document = await self._fetch_json_document(jwks_uri)
        except (httpx.HTTPError, PyJWTError, KeyError, TypeError, ValueError):
            self._stats["failures"] += 1
            raise
        self._set_jwks(jwks_uri, document, ttl=ttl)
        self._stats["refreshes"] += 1

    def _set_jwks(self, jwks_uri: str, document: dict[str, Any], *, ttl: int) -> None:
        keys = {key["kid"]: jwt.PyJWK(key) for key in document.get("keys", []) if "kid" in key}
        now = time.monotonic()
        self._jwks[jwks_uri] = _JWKSEntry(
            expires_at=now + ttl,
            stale_expires_at=now + ttl + self.stale_grace_seconds,
            keys=keys,
        )
        self._missing_kids = {
            (url, kid): expires_at
            for (url, kid), expires_at in self._missing_kids.items()
            if url != jwks_uri or kid not in keys
        }

    def _schedule_background_refresh(self, jwks_uri: str) -> None:
        refresh_task = self._refresh_tasks.get(jwks_uri)
        if refresh_task is not None and not refresh_task.done():
            return
        self._refresh_tasks[jwks_uri] = asyncio.create_task(self._background_refresh(jwks_uri))

    async def _background_refresh(self, jwks_uri: str) -> None:
        try:
            async with self._lock_for(jwks_uri):
                await self._refresh_jwks(jwks_uri, ttl=self.cache_ttl)
        except (httpx.HTTPError, PyJWTError, KeyError, TypeError, ValueError):
            _logger.warning("jwks.background_refresh.failed", exc_info=True)

    def _lock_for(self, url: str) -> asyncio.Lock:
        return self._locks.setdefault(url, asyncio.Lock())


async def invoke_validation_error_hook(hook: ValidationErrorHook, issuer: str, exc: BaseException) -> None:
    """Invoke a sync or async validation hook without letting hook failures affect auth."""
    try:
        result = hook(issuer, exc)
        if inspect.isawaitable(result):
            await result
    except Exception:
        _logger.exception("on_validation_error hook raised for issuer %s", issuer)
