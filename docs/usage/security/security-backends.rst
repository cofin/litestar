==============================
Security Plugin and Mechanisms
==============================

Litestar's first-party authentication entry point is
:class:`~litestar.security.SecurityPlugin`. The plugin installs a single authentication
middleware and runs one or more ordered authentication mechanisms for HTTP and WebSocket
connections.

Mechanisms load identity. Guards authorize access. A mechanism that cannot find its
credential should usually return ``None`` so the next mechanism can try. A mechanism
that found a credential but rejected it should raise a Litestar authentication exception.
Route handlers that must require an authenticated identity should use a guard that checks
``connection.scope["user"]`` or ``connection.user``.

Built-in mechanisms
-------------------

Litestar ships these mechanisms:

- :class:`~litestar.security.jwt.JWTMechanism` for bearer JWTs.
- :class:`~litestar.security.jwt.JWTCookieMechanism` for bearer JWTs carried by an
  HTTP-only cookie.
- :class:`~litestar.security.api_key.APIKeyMechanism` for header, query parameter, or
  cookie API keys.
- :class:`~litestar.security.session.SessionMechanism` for Litestar session middleware.
- :class:`~litestar.security.iap.IAPMechanism` for Google Identity-Aware Proxy headers.

Session authentication
----------------------

Session authentication is configured by pairing
:class:`~litestar.security.session.SessionMechanism` with a Litestar session backend.

.. dropdown:: Click to see an example of using session authentication

    .. literalinclude:: /examples/security/using_session_auth.py
        :language: python
        :caption: Using SessionMechanism


Multiple mechanisms
-------------------

Mechanisms are tried in the order they are passed to :class:`~litestar.security.SecurityPlugin`.
This lets one application support browser sessions, bearer tokens, edge proxy tokens, and
API keys without stacking separate authentication middleware.

.. code-block:: python

    security = SecurityPlugin(
        [
            session_mechanism,
            jwt_mechanism,
            api_key_mechanism,
        ],
        exclude=[r"^/login", r"^/signup", r"^/schema"],
    )


Use ``opt={"auth_mechanism": "name"}`` on a route handler when a route must use one
specific mechanism instead of the full ordered list.

Provider cookbook
-----------------

For Auth0, Keycloak, Microsoft Entra ID, Google IAP, AWS ALB, Cloudflare Access,
WebSocket, and test-mode JWKS examples, see :doc:`/usage/security/provider-cookbook`.

Custom mechanisms
-----------------

For custom authentication, implement the
:class:`~litestar.security.AuthMechanism` protocol and install it through
:class:`~litestar.security.SecurityPlugin`. See
:doc:`/usage/security/abstract-authentication-middleware` for a complete example.
