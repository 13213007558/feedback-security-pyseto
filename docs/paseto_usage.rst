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

Selecting a key with a pre-indexed KeySet
-----------------------------------------

When a service holds many verification keys, passing a plain list to
``pyseto.decode()`` tries every header-matching key in turn, which means a
real cryptographic verification (or decryption) for each one. A
:class:`pyseto.KeySet` is an immutable, pre-indexed collection that maps each
key's PASERK ID (``key.to_paserk_id()``) to the key itself.

If the token's JSON footer carries a ``kid`` member, it is used purely as a
lookup hint to select a single candidate. The hint is unauthenticated at lookup
time, so it never proves anything on its own: the selected key still verifies
the complete token, including its version, purpose and the very footer that
carried the hint. A forged or unknown hint cannot make the wrong key pass.

.. code-block:: python

    import json
    import pyseto
    from pyseto import Key, KeySet

    # Build once and reuse; the set is a defensive copy and never changes.
    public_keys = KeySet(
        [
            Key.new(4, "public", public_key_pem_1),
            Key.new(4, "public", public_key_pem_2),
            Key.new(3, "public", ecdsa_public_key_pem),
        ]
    )

    # The signer names its key in the (JSON) footer.
    token = pyseto.encode(
        private_key,
        b"this is a signed message",
        footer=json.dumps({"kid": public_key.to_paserk_id()}),
    )

    # Exactly one candidate key is verified, instead of the whole list.
    decoded = pyseto.decode(public_keys, token)
    assert decoded.payload == b"this is a signed message"

Behavior summary:

- A known ``kid`` whose key matches the token header verifies that single key.
- An unknown ``kid``, or one whose key disagrees on version/purpose, raises a
  ``ValueError`` deterministically; the decoder never guesses or falls back to
  a full scan.
- A missing or non-JSON footer (or one without a string ``kid``) means "no
  hint": every header-matching key is tried in first-seen order, matching the
  list-based behavior.
- Re-adding the same key is a no-op, so it is never verified twice; identical
  material under different versions gets distinct, version-namespaced PASERK
  IDs and is indexed separately.
- Decoding performs no network access; the hint is read from the local footer.
