"""Deterministic test keys.

One Ed25519 keypair is loaded under BOTH PASETO versions so that old and new
tokens share the same raw key material while producing distinct PASERK ids and
version headers. No network or account service is involved.
"""

from dataclasses import dataclass

import pyseto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Fixed 32-byte seed: reproducible test material only, never use in production.
TEST_SEED = bytes(range(32))


@dataclass(frozen=True)
class KeyMaterial:
    v2_secret: pyseto.KeyInterface
    v2_public: pyseto.KeyInterface
    v4_secret: pyseto.KeyInterface
    v4_public: pyseto.KeyInterface

    @property
    def v2_paserk_pid(self) -> str:
        return self.v2_public.to_paserk_id()

    @property
    def v4_paserk_pid(self) -> str:
        return self.v4_public.to_paserk_id()


def load_test_keys(seed: bytes = TEST_SEED) -> KeyMaterial:
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyMaterial(
        v2_secret=pyseto.Key.new(2, "public", priv_pem),
        v2_public=pyseto.Key.new(2, "public", pub_pem),
        v4_secret=pyseto.Key.new(4, "public", priv_pem),
        v4_public=pyseto.Key.new(4, "public", pub_pem),
    )
