=================================
Excluding and Selecting Endpoints
=================================

:class:`~litestar.security.SecurityPlugin` can skip authentication for paths, HTTP
methods, or individual route handlers. It can also pin a route handler to one named
mechanism when an application has multiple mechanisms configured.

Path exclusions
---------------

The ``exclude`` argument accepts a regex string or list of regex strings matched against
the full path. Patterns are not implicitly anchored. Use ``^`` when a pattern should
only match the beginning of the path.

.. danger::

    Passing ``/`` disables authentication for every route because it matches every path.

.. code-block:: python

    security = SecurityPlugin(
        [session_mechanism],
        exclude=[r"^/login", r"^/signup", r"^/schema"],
    )


HTTP method exclusions
----------------------

``OPTIONS`` requests are excluded by default. Override ``exclude_http_methods`` when an
application needs a different policy.

.. code-block:: python

    security = SecurityPlugin(
        [jwt_mechanism],
        exclude_http_methods=["OPTIONS", "HEAD"],
    )


Route-level exclusions
----------------------

Set ``exclude_from_auth=True`` on a route handler to skip authentication for that route.
The same option also removes plugin-generated operation security from the OpenAPI
operation.

.. code-block:: python

    @get("/secured")
    def secured_route() -> dict[str, str]:
        return {"status": "secured"}


    @get("/public", exclude_from_auth=True)
    def public_route() -> dict[str, str]:
        return {"status": "public"}


Selecting one mechanism
-----------------------

When multiple mechanisms are configured, the default is first-match composition. To
force one route to use one configured mechanism, set ``opt={"auth_mechanism": "<name>"}``.

.. code-block:: python

    security = SecurityPlugin([session_mechanism, jwt_mechanism, api_key_mechanism])


    @get("/browser/profile", opt={"auth_mechanism": "session"})
    def browser_profile() -> dict[str, str]:
        return {"status": "session only"}


    @get("/api/profile", opt={"auth_mechanism": "jwt"})
    def api_profile() -> dict[str, str]:
        return {"status": "jwt only"}


Unknown mechanism names are rejected during application initialization so deployment
does not silently fall back to the wrong authentication policy.
