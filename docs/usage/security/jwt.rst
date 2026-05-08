JWT Security
============

Litestar offers optional JWT based security mechanisms. To use these make sure to install the
`pyjwt <https://pyjwt.readthedocs.io/en/stable/>`_ and `cryptography <https://github.com/pyca/cryptography>`_
packages, or simply install Litestar with the ``jwt``
`extra <https://packaging.python.org/en/latest/specifications/dependency-specifiers/#extras>`_:

.. code-block:: shell
    :caption: Install Litestar with JWT extra

    pip install 'litestar[jwt]'

:class:`JWT Mechanism <.security.jwt.JWTMechanism>`
---------------------------------------------------

This is the base JWT mechanism. It sends the JWT token using a header and expects requests to send the JWT token using
the same header key.

.. dropdown:: Click to see the code

    .. literalinclude:: /examples/security/jwt/using_jwt_auth.py
        :language: python
        :caption: Using JWT Mechanism

:class:`JWT Cookie Mechanism <.security.jwt.JWTCookieMechanism>`
----------------------------------------------------------------

This mechanism accepts the normal bearer header or a configured cookie.

.. dropdown:: Click to see the code

    .. literalinclude:: /examples/security/jwt/using_jwt_cookie_auth.py
        :language: python
        :caption: Using JWT Cookie Mechanism

Bearer token response
---------------------

Login handlers can return the token in the response body for clients that expect a bearer token payload.

.. dropdown:: Click to see the code

    .. literalinclude:: /examples/security/jwt/using_oauth2_password_bearer.py
       :language: python
       :caption: Returning a bearer token

OIDC providers
--------------

JWT mechanisms can validate tokens against an OIDC provider. If ``jwks_uri`` is not set explicitly, the mechanism uses
the provider's OpenID discovery document to find the JWKS endpoint.

.. literalinclude:: /examples/security/jwt/using_oidc_provider.py
   :language: python
   :caption: Using an OIDC provider


For Auth0, Keycloak, Microsoft Entra ID, AWS ALB, and Cloudflare Access examples, see
:doc:`/usage/security/provider-cookbook`.


Using a custom token class
--------------------------

The token class used can be customized with arbitrary fields, by creating a subclass of
:class:`~.security.jwt.Token`, and specifying it on the mechanism:

.. literalinclude:: /examples/security/jwt/custom_token_cls.py
   :language: python
   :caption: Using a custom token


The token will be converted from JSON into the appropriate type, including basic type
conversions.

.. important::
    Complex type conversions, especially those including third libraries such as
    Pydantic or attrs, as well as any custom ``type_decoders`` are not available for
    converting the token. To support more complex conversions, the
    :meth:`~.security.jwt.Token.encode` and :meth:`~.security.jwt.Token.decode` methods
    must be overwritten in the subclass.


Verifying issuer and audience
-----------------------------

To verify the JWT ``iss`` (*issuer*) and ``aud`` (*audience*) claim, a list of accepted
issuers or audiences can be set on the JWT mechanism. When a JWT is decoded,
the issuer or audience on the token is compared to the list of accepted issuers /
audiences. If the value in the token does not match any value in the respective list,
a :exc:`NotAuthorizedException` will be raised, returning a response with a
``401 Unauthorized`` status.


.. literalinclude:: /examples/security/jwt/verify_issuer_audience.py
   :language: python
   :caption: Verifying issuer and audience


Customizing token validation
----------------------------

Token decoding / validation can be further customized by overriding the
:meth:`~.security.jwt.Token.decode_payload` method. It will be called by
:meth:`~.security.jwt.Token.decode` with the encoded token string, and must return a
dictionary representing the decoded payload, which will then used by
:meth:`~.security.jwt.Token.decode` to construct an instance of the token class.


.. literalinclude:: /examples/security/jwt/custom_decode_payload.py
   :language: python
   :caption: Customizing payload decoding


Using token revocation
----------------------
Token revocation can be implemented by maintaining a list of revoked tokens and checking against this list during authentication.
When a token is revoked, it should be added to the list, and any subsequent requests with that token should be denied.

.. dropdown:: Click to see the code

    .. literalinclude:: /examples/security/jwt/using_token_revocation.py
        :language: python
        :caption: Implementing token revocation
