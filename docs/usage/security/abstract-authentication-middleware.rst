=============================================
Implementing Custom Authentication Mechanisms
=============================================

Custom authentication for :class:`~litestar.security.SecurityPlugin` is implemented by
providing an object that satisfies the :class:`~litestar.security.AuthMechanism`
protocol.

An authentication mechanism has three responsibilities:

- Return :class:`~litestar.security.AuthenticationResult` when it can authenticate the
  connection.
- Return ``None`` when its credential is absent so another mechanism can try.
- Raise a Litestar authentication exception when the credential belongs to that
  mechanism but is invalid.

The example below implements API-key authentication as a custom mechanism. It also adds
a guard because authentication mechanisms load identity, while guards decide whether a
route requires that identity.

.. literalinclude:: /examples/security/using_abstract_authentication_middleware.py
    :language: python
    :caption: Custom AuthMechanism installed with SecurityPlugin


OpenAPI integration
-------------------

Mechanisms can contribute OpenAPI security scheme metadata with
``openapi_components()`` and operation requirements with
``openapi_security_requirement()``. :class:`~litestar.security.SecurityPlugin`
aggregates those contributions for protected route handlers.

If a route should use a hand-written OpenAPI security requirement, set
``opt={"security": [...]}`` on the route handler. Use ``opt={"security": []}`` to
remove operation-level security from a route while keeping authentication behavior
controlled by the normal security settings.
