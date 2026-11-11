PASETO Usage Examples
=====================

The following is a simple sample code using PySETO:

.. code-block:: pycon

    >>> import pyseto
    >>> from pyseto import Key
    >>> private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
    >>> public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
    >>> private_key = Key.new(version=4, purpose="public", key=private_key_pem)
    >>> token = pyseto.encode(
    ...     private_key,
    ...     b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
    ... )
    >>> token
    B'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
    >>> public_key = Key.new(version=4, purpose="public", key=public_key_pem)
    >>> decoded = pyseto.decode(public_key, token)
    >>> decoded.payload
    B'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

This page shows various examples to use PySETO.

.. contents::
   :local:

v4.public
---------

Asymmetric Authentication (Public-Key Signatures) with Ed25519 (EdDSA over Curve25519).


You can create an Ed25519 key pair by using openssl as follows:

.. code-block:: console

    $ openssl genpkey -algorithm ed25519 -out private_key.pem
    $ openssl pkey -in private_key.pem -pubout -out public_key.pem


Use the key pair to generate and consume `v4.public` PASETO tokens as follows:

.. code-block:: python

    import pyseto
    from pyseto import Key

    with open("./private_key.pem") as key_file:
        private_key = Key.new(4, "public", key_file.read())
    token = pyseto.encode(
        private_key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
        implicit_assertion=b"xyz",  # Optional
    )

    with open("./public_key.pem") as key_file:
        public_key = Key.new(4, "public", key_file.read())
    decoded = pyseto.decode(public_key, token, implicit_assertion=b"xyz")

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v4"
    assert decoded.purpose == "public"


v4.local
--------

Authenticated Encryption with XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC).

.. code-block:: python

    import pyseto
    from pyseto import Key

    key = Key.new(version=4, purpose="local", key=b"our-secret")
    token = pyseto.encode(
        key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
        implicit_assertion=b"xyz",  # Optional
    )

    decoded = pyseto.decode(key, token, implicit_assertion=b"xyz")

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v4"
    assert decoded.purpose == "local"

v3.public
---------

Asymmetric Authentication (Public-Key Signatures) with ECDSA over NIST P-384,
with SHA-384, using RFC 6979 deterministic k-values.

You can create an ECDSA over NIST P-384 key pair by using openssl as follows:

.. code-block:: console

    $ openssl ecparam -genkey -name secp384r1 -noout -out private_key.pem
    $ openssl ec -in private_key.pem -pubout -out public_key.pem

Use the key pair to generate and consume v3.public PASETO tokens as follows:

.. code-block:: python

    import pyseto
    from pyseto import Key

    with open("./private_key.pem") as key_file:
        private_key = Key.new(3, "public", key_file.read())
    token = pyseto.encode(
        private_key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
        implicit_assertion=b"xyz",  # Optional
    )

    with open("./public_key.pem") as key_file:
        public_key = Key.new(3, "public", key_file.read())
    decoded = pyseto.decode(public_key, token, implicit_assertion=b"xyz")

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v3"
    assert decoded.purpose == "public"

v3.local
--------

Symmetric Authenticated Encryption with AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).

.. code-block:: python

    import pyseto
    from pyseto import Key

    key = Key.new(version=3, purpose="local", key=b"our-secret")
    token = pyseto.encode(
        key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
        implicit_assertion=b"xyz",  # Optional
    )

    decoded = pyseto.decode(key, token, implicit_assertion=b"xyz")

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v3"
    assert decoded.purpose == "local"


v2.public
---------

Asymmetric Authentication (Public-Key Signatures) with Ed25519.


Create an Ed25519 key pair by using openssl as follows:

.. code-block:: console

    $ openssl genpkey -algorithm ed25519 -out private_key.pem
    $ openssl pkey -in private_key.pem -pubout -out public_key.pem


Use the key pair to generate and consume v2.public PASETO tokens as follows:

.. code-block:: python

    import pyseto
    from pyseto import Key

    with open("./private_key.pem") as key_file:
        private_key = Key.new(2, "public", key_file.read())
    token = pyseto.encode(
        private_key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
    )

    with open("./public_key.pem") as key_file:
        public_key = Key.new(2, "public", key_file.read())
    decoded = pyseto.decode(public_key, token)

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v2"
    assert decoded.purpose == "public"


v2.local
--------

Symmetric Authenticated Encryption with XChaCha20-Poly1305 (192-bit nonce,
256-bit key and 128-bit authentication tag).


In this case, you must use 32 byte key as follows:

.. code-block:: python

    import pyseto
    from pyseto import Key
    from secrets import token_bytes

    key = Key.new(version=2, purpose="local", key=token_bytes(32))
    token = pyseto.encode(
        key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
    )

    decoded = pyseto.decode(key, token)

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v2"
    assert decoded.purpose == "local"


v1.public
---------

Asymmetric Authentication (Public-Key Signatures) with RSASSA-PSS 2048-bit key,
SHA384 hashing and MGF1+SHA384.


Create an RSA key pair by using openssl as follows:

.. code-block:: console

    $ openssl genrsa -out private_key.pem 2048
    $ openssl rsa -in private_key.pem -outform PEM -pubout -out public_key.pem


Use the key pair to generate and consume v1.public PASETO tokens as follows:

.. code-block:: python

    import pyseto
    from pyseto import Key

    with open("./private_key.pem") as key_file:
        private_key = Key.new(1, "public", key_file.read())
    token = pyseto.encode(
        private_key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
    )

    with open("./public_key.pem") as key_file:
        public_key = Key.new(1, "public", key_file.read())
    decoded = pyseto.decode(public_key, token)

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v1"
    assert decoded.purpose == "public"


v1.local
--------

Symmetric Authenticated Encryption with AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).

.. code-block:: python

    import pyseto
    from pyseto import Key
    from secrets import token_bytes

    key = Key.new(version=1, purpose="local", key=b"our-secret")
    token = pyseto.encode(
        key,
        payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        footer=b"This is a footer",  # Optional
    )

    decoded = pyseto.decode(key, token)

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b"This is a footer"
    assert decoded.version == "v1"
    assert decoded.purpose == "local"

Using serializer/deserializer for payload and footer
----------------------------------------------------

By using `serializer` and `deserializer`, you can encode/decode a dict-typed payload and footer included in PASETO tokens into an arbitrary format.
The following example shows that the payload and the footer in a PASETO token are encoded/decoded as JSON formatted data.
When specifing dict-typed payload, exp parameter can be used to set the expiration time (seconds) of the token.

.. code-block:: python

    import json
    import pyseto
    from pyseto import Key

    private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
    public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

    private_key = Key.new(version=4, purpose="public", key=private_key_pem)
    public_key = Key.new(version=4, purpose="public", key=public_key_pem)

    token = pyseto.encode(
        private_key,
        {"data": "this is a signed message"},
        footer={"kid": public_key.to_paserk_id()},
        serializer=json,
        exp=3600,
    )

    decoded = pyseto.decode(public_key, token, deserializer=json)
    assert decoded.payload["data"] == "this is a signed message"
    assert decoded.payload["exp"] == "2021-11-11T00:00:00+00:00"
    assert decoded.footer["kid"] == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"

Using Paseto class for handling registered claims
---------------------------------------------------

By using `Paseto` class, you can change the default value of `exp` (the expiration date ot tokens), whether to include an `iat` claim, and other settings.

Note that `pyseto.encode()` and `pyseto.decode()` are aliases to the `encode()` and `decode()` of the global "Paseto" class instance created with the default settings.


.. code-block:: python

    import json
    import pyseto
    from pyseto import Key, Paseto

    private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
    public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

    private_key = Key.new(version=4, purpose="public", key=private_key_pem)
    paseto = Paseto.new(
        exp=3600, include_iat=True
    )  # Default values are exp=0(not specified) and including_iat=False
    token = paseto.encode(
        private_key,
        {"data": "this is a signed message"},
        serializer=json,
    )
    public_key = Key.new(version=4, purpose="public", key=public_key_pem)
    decoded = pyseto.decode(public_key, token, deserializer=json)

    assert decoded.payload["data"] == "this is a signed message"
    assert decoded.payload["iat"] == "2021-11-11T00:00:00+00:00"
    assert decoded.payload["exp"] == "2021-11-11T01:00:00+00:00"


Stable Token Identifier (``token_id``)
--------------------------------------

A PASETO token is text, but several different Base64URL spellings can decode
to the same authenticated bytes. The parser accepts all of them:

- Padding characters ``=`` may be appended to the payload or footer segment
  (the canonical PASETO encoding omits them).
- Both the URL-safe alphabet (``-``/``_``) and the standard Base64 alphabet
  (``+``/``/``) are accepted, even mixed within one segment.
- When the segment length is a multiple of four, non-alphabet characters such
  as spaces or newlines are silently discarded while decoding.
- A token without a footer can be written with three segments or with an
  empty fourth segment (a trailing ``.``); both mean an empty footer.

Storing the raw token string as a revocation key therefore risks missing an
alias of a revoked token. ``Token.token_id`` solves this: it is a stable
identifier computed from the *authenticated binary components*, so every
accepted spelling of one token maps to the same value.

.. code-block:: python

    import pyseto
    from pyseto import Key, VerifyError

    key = Key.new(4, "local", b"our-secret")
    token = pyseto.encode(key, b'{"sub":"alice"}')

    decoded = pyseto.decode(key, token)
    revocation_key = decoded.token_id  # e.g. "pstid1.k6Lf..."

The identifier is defined as::

    "pstid1." + base64url_nopad(SHA-256(PAE([
        header,                 # b"v4.local." / b"v4.public." / ...
        raw_payload,            # authenticated bytes from the token text
        raw_footer,             # authenticated footer bytes (b"" if absent)
        implicit_assertion,     # b"" for v1/v2
    ])))

Input contract and guarantees:

- ``raw_payload`` is the payload segment exactly as authenticated, before
  decryption or signature stripping: nonce + ciphertext + tag for ``local``
  and message + signature for ``public``. The decrypted claims are never an
  input, so two tokens with identical claims but different signatures,
  encryption nonces, footers or implicit assertions get different
  identifiers.
- The implicit assertion is part of the identifier for ``v3``/``v4`` because
  it is authenticated. Verifying the same token under a different assertion
  fails rather than producing another identifier.
- ``token_id`` is only populated after ``pyseto.decode()`` has successfully
  decrypted or verified the token. On a merely parsed object
  (``Token.new()``) or after any failed verification, accessing it raises
  ``VerifyError``; no value is ever returned that could be treated as a
  verified identity without authentication.
- Mutating ``payload`` or ``footer`` on a decoded ``Token`` does not change
  the identifier, since it was computed over the original authenticated bytes.

Compatibility policy:

- The ``pstid1.`` prefix identifies this exact hash and PAE layout. If the
  algorithm or its inputs ever change, a new prefix (``pstid2.``, ...) is
  introduced; old and new identifiers never collide and remain distinguishable.
- Identifiers are deterministic across PySETO versions, language bindings and
  platforms (SHA-256 and PAE are fixed primitives), which makes them safe to
  persist in revocation lists or databases.

``token_id`` is not a user id or a session id. A user id identifies a subject
across many tokens; a session id is an application-level claim stored inside
the payload. The same user (or even the same claims) produces a distinct
``token_id`` for every distinct signed/encrypted token, while every textual
alias of one concrete token shares it. It answers precisely "is this concrete
authenticated token the one I recorded?", which is what revocation needs.
