from litestar.middleware.base import ASGIMiddleware
from litestar.middleware.constraints import MiddlewareConstraints
from litestar.middleware.session.base import SessionMiddleware


class CachingMiddleware(ASGIMiddleware):
    constraints = MiddlewareConstraints(after=(SessionMiddleware,))
