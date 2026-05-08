=================
Provider Cookbook
=================

This page collects executable :class:`~litestar.security.SecurityPlugin` examples for
common identity providers and edge authentication deployments. The examples live in
``docs/examples/security/provider_cookbook.py`` and are imported by the test suite.

Auth0
-----

Use :class:`~litestar.security.jwt.JWTMechanism` with
:class:`~litestar.security.jwt.OIDCProvider`. If ``jwks_uri`` is omitted, Litestar uses
OpenID discovery from ``issuer``.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-auth0
    :end-before: # end-auth0
    :caption: Auth0 OIDC JWT validation


Keycloak
--------

Keycloak realm issuers work the same way. The audience should match the client or API
audience expected by the realm.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-keycloak
    :end-before: # end-keycloak
    :caption: Keycloak OIDC JWT validation


Microsoft Entra ID
------------------

For Microsoft Entra ID, use the tenant-specific v2 issuer and the API application ID
URI as the audience.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-entra
    :end-before: # end-entra
    :caption: Microsoft Entra ID JWT validation


Google Identity-Aware Proxy
---------------------------

:class:`~litestar.security.iap.IAPMechanism` validates the
``X-Goog-IAP-JWT-Assertion`` header, enforces the IAP audience, and can restrict access
by email address or email domain.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-iap
    :end-before: # end-iap
    :caption: Google IAP authentication


IAP auto-provisioning
^^^^^^^^^^^^^^^^^^^^^

User provisioning is intentionally application-owned. Put first-login creation in the
``retrieve_user_handler`` passed to :class:`~litestar.security.iap.IAPMechanism`, then
use :func:`~litestar.security.iap.iap_session_handler` when you want to exchange the
IAP identity for local session material.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-iap-auto-provision
    :end-before: # end-iap-auto-provision
    :caption: IAP first-login provisioning and local session exchange


AWS Application Load Balancer
-----------------------------

AWS ALB OIDC authentication forwards a raw JWT in ``X-Amzn-Oidc-Data``. The example
subclasses :class:`~litestar.security.jwt.JWTMechanism` to read the raw trusted proxy
header instead of a bearer header.

.. warning::

    Only use raw proxy-header JWT mechanisms behind a trusted proxy that strips the
    same incoming header from untrusted clients.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-aws-alb
    :end-before: # end-aws-alb
    :caption: AWS ALB raw JWT header validation


Cloudflare Access
-----------------

Cloudflare Access forwards a raw JWT in ``Cf-Access-Jwt-Assertion``. Configure the team
issuer, application audience tag, and Access certificates URL.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-cloudflare-access
    :end-before: # end-cloudflare-access
    :caption: Cloudflare Access JWT assertion validation


WebSocket authentication
------------------------

Browsers cannot set arbitrary WebSocket headers. Use
:class:`~litestar.security.api_key.APIKeyMechanism` with a query parameter when the
token can be exposed in the URL, or with ``Sec-WebSocket-Protocol`` when a subprotocol
token is more appropriate.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-websocket-query
    :end-before: # end-websocket-query
    :caption: WebSocket token in the query string

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-websocket-subprotocol
    :end-before: # end-websocket-subprotocol
    :caption: WebSocket token in Sec-WebSocket-Protocol


Step-up authentication
----------------------

Use route-level mechanism selection when a sensitive route needs a stronger mechanism
than the rest of the application.

.. code-block:: python

    security = SecurityPlugin([session_mechanism, mfa_api_key_mechanism])


    @post("/billing/export", opt={"auth_mechanism": "api_key"})
    def export_billing_data() -> dict[str, str]:
        return {"status": "queued"}


Testing JWKS integrations
-------------------------

Seed :class:`~litestar.security.jwt.JWKSCache` in tests and pass it to
:class:`~litestar.security.SecurityPlugin` with ``jwks_cache=cache``. This avoids
network calls and makes key rotation tests deterministic.

.. literalinclude:: /examples/security/provider_cookbook.py
    :language: python
    :start-after: # start-jwks-cache
    :end-before: # end-jwks-cache
    :caption: Test JWKS cache fixture


Testing without external providers
----------------------------------

For handler tests that do not need JWT validation, inject a small test mechanism that
returns :class:`~litestar.security.AuthenticationResult` for a known header or cookie.
The custom mechanism pattern is the same as the example in
:doc:`/usage/security/abstract-authentication-middleware`.
