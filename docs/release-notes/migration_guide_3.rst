===================
3.0 Migration Guide
===================

Security
--------

Litestar 3.0 replaces the old per-backend security configuration classes with
:class:`~litestar.security.SecurityPlugin` and authentication mechanisms. The main
branch is a clean break: compatibility shims remain a v2 migration concern and are not
present in 3.0.

+-------------------------------------------+------------------------------------------------------------+
| 2.x                                       | 3.x                                                        |
+===========================================+============================================================+
| ``JWTAuth``                               | ``SecurityPlugin([JWTMechanism(...)])``                    |
+-------------------------------------------+------------------------------------------------------------+
| ``JWTCookieAuth``                         | ``SecurityPlugin([JWTCookieMechanism(...)])``              |
+-------------------------------------------+------------------------------------------------------------+
| ``OAuth2PasswordBearerAuth``              | ``JWTMechanism.login(send_token_as_response_body=True)``   |
+-------------------------------------------+------------------------------------------------------------+
| ``SessionAuth``                           | ``SecurityPlugin([SessionMechanism(...)])``                |
+-------------------------------------------+------------------------------------------------------------+
| ``AbstractSecurityConfig``                | ``SecurityPlugin``                                         |
+-------------------------------------------+------------------------------------------------------------+
| ``AbstractAuthenticationMiddleware``      | A custom ``AuthMechanism`` installed by ``SecurityPlugin`` |
+-------------------------------------------+------------------------------------------------------------+

JWT bearer authentication
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    jwt_mechanism = JWTMechanism(
        retrieve_user_handler=retrieve_user_handler,
        token_secret=settings.jwt_secret,
    )

    app = Litestar(
        route_handlers=[login, profile],
        plugins=[SecurityPlugin([jwt_mechanism])],
    )


JWT cookie authentication
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    jwt_cookie_mechanism = JWTCookieMechanism(
        retrieve_user_handler=retrieve_user_handler,
        token_secret=settings.jwt_secret,
        key="token",
        secure=True,
        samesite="lax",
    )

    app = Litestar(
        route_handlers=[login, profile],
        plugins=[SecurityPlugin([jwt_cookie_mechanism])],
    )


Bearer token response
~~~~~~~~~~~~~~~~~~~~~

Use :meth:`~litestar.security.jwt.JWTMechanism.login` with
``send_token_as_response_body=True`` when a client expects an OAuth2-style bearer token
payload.

.. code-block:: python

    @post("/login")
    async def login(data: LoginPayload) -> Response[dict[str, str]]:
        user = await authenticate_user(data)
        return jwt_mechanism.login(
            identifier=str(user.id),
            send_token_as_response_body=True,
        )


Session authentication
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    session_mechanism = SessionMechanism(
        retrieve_user_handler=retrieve_user_handler,
        session_backend_config=ServerSideSessionConfig(),
    )

    app = Litestar(
        route_handlers=[login, signup, profile],
        plugins=[
            SecurityPlugin(
                [session_mechanism],
                exclude=[r"^/login", r"^/signup", r"^/schema"],
            )
        ],
    )


Multiple mechanisms
~~~~~~~~~~~~~~~~~~~

Pass mechanisms in the order they should be tried. Use ``opt={"auth_mechanism":
"<name>"}`` when a route should use one mechanism instead of the default ordered list.

.. code-block:: python

    security = SecurityPlugin([session_mechanism, jwt_mechanism, api_key_mechanism])


    @get("/browser/profile", opt={"auth_mechanism": "session"})
    def browser_profile() -> dict[str, str]:
        return {"status": "session only"}


    @get("/api/profile", opt={"auth_mechanism": "jwt"})
    def api_profile() -> dict[str, str]:
        return {"status": "jwt only"}


Custom authentication
~~~~~~~~~~~~~~~~~~~~~

Replace custom ``AbstractAuthenticationMiddleware`` subclasses with an object that
implements :class:`~litestar.security.AuthMechanism`. See
:doc:`/usage/security/abstract-authentication-middleware` for a complete example.

Provider-specific examples
~~~~~~~~~~~~~~~~~~~~~~~~~~

Auth0, Keycloak, Microsoft Entra ID, Google IAP, AWS ALB, Cloudflare Access,
WebSocket, and JWKS test fixtures are covered in
:doc:`/usage/security/provider-cookbook`.
