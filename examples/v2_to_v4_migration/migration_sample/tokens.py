"""Token issuance and the two migration entry points.

LegacyV2Entry (old business surface):
    Accepts ONLY v2.public tokens. v2 has no implicit-assertion slot in its
    signing input, so tenant/purpose inside the payload are ordinary claims,
    not a cryptographic binding. This entry stays alive only during the
    migration window and never grants the new, strongly bound business route.

StrictV4Entry (new business surface):
    Accepts ONLY v4.public tokens whose signature verifies against the
    tenant+purpose implicit assertion reconstructed by the caller. A token
    signed with another assertion, or without one, fails signature
    verification before any claim is inspected.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pyseto

from .assertions import AssertionContext, canonical_assertion
from .errors import BindingError, RejectedByEntry, UnsupportedVersion
from .keys import KeyMaterial

V2_HEADER = b"v2.public."
V4_HEADER = b"v4.public."


def _expiry(ttl_seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()


def issue_legacy_v2(keys: KeyMaterial, claims: dict, ttl_seconds: int = 3600) -> bytes:
    """Mint the old token shape. No implicit assertion is possible on v2."""
    payload = dict(claims)
    payload.setdefault("exp", _expiry(ttl_seconds))
    token = pyseto.encode(keys.v2_secret, payload, serializer=json)
    if not token.startswith(V2_HEADER):
        raise RuntimeError("issuer produced an unexpected token header")
    return token


def issue_strict_v4(
    keys: KeyMaterial, ctx: AssertionContext, claims: dict, ttl_seconds: int = 3600
) -> bytes:
    """Mint the new token shape. Tenant/purpose are bound via implicit assertion."""
    payload = dict(claims)
    # Mirror the bound values inside the payload as defense in depth; the real
    # guarantee is the implicit assertion in the Ed25519 signing input.
    payload["tid"] = ctx.tenant
    payload["purpose"] = ctx.purpose
    payload.setdefault("exp", _expiry(ttl_seconds))
    token = pyseto.encode(
        keys.v4_secret,
        payload,
        implicit_assertion=canonical_assertion(ctx),
        serializer=json,
    )
    if not token.startswith(V4_HEADER):
        raise RuntimeError("issuer produced an unexpected token header")
    return token


@dataclass(frozen=True)
class Principal:
    tenant: str
    purpose: str
    claims: dict
    token_version: str
    paserk_pid: str


class LegacyV2Entry:
    """Compatibility surface. Verifies signatures, cannot assert a tenant binding."""

    accepted_header = V2_HEADER

    def __init__(self, keys: KeyMaterial):
        self._keys = keys

    def verify(self, token: bytes) -> Principal:
        if not token.startswith(self.accepted_header):
            raise UnsupportedVersion(
                f"legacy entry accepts only v2.public; got {token[:10].decode('utf-8', 'replace')}"
            )
        try:
            decoded = pyseto.decode(self._keys.v2_public, token, deserializer=json)
        except Exception as err:  # pyseto.VerifyError / ValueError
            raise RejectedByEntry(f"legacy verification failed: {err}") from err

        claims = decoded.payload
        # The payload claims are advisory on v2: nothing cryptographically pins
        # them to the signing input. Callers must treat them as unbound.
        return Principal(
            tenant=claims.get("tid", ""),
            purpose=claims.get("purpose", ""),
            claims=claims,
            token_version="v2",
            paserk_pid=self._keys.v2_paserk_pid,
        )


class StrictV4Entry:
    """New business surface. Tenant/purpose are cryptographically required."""

    accepted_header = V4_HEADER

    def __init__(self, keys: KeyMaterial, ctx: AssertionContext):
        self._keys = keys
        self._ctx = ctx
        self._assertion = canonical_assertion(ctx)

    def verify(self, token: bytes) -> Principal:
        if not token.startswith(self.accepted_header):
            raise UnsupportedVersion(
                f"strict entry accepts only v4.public; got {token[:10].decode('utf-8', 'replace')}"
            )
        try:
            # A missing/wrong assertion (including the empty default) makes the
            # Ed25519 check fail here, before any claim is trusted.
            decoded = pyseto.decode(
                self._keys.v4_public,
                token,
                implicit_assertion=self._assertion,
                deserializer=json,
            )
        except Exception as err:
            raise BindingError(
                f"v4 verification failed for assertion "
                f"{self._assertion.decode('utf-8')}: {err}"
            ) from err

        claims = decoded.payload
        for field, expected in (("tid", self._ctx.tenant), ("purpose", self._ctx.purpose)):
            if field not in claims:
                raise BindingError(f"missing required claim '{field}'")
            if claims[field] != expected:
                raise BindingError(
                    f"claim '{field}'={claims[field]!r} does not match bound value {expected!r}"
                )
        return Principal(
            tenant=self._ctx.tenant,
            purpose=self._ctx.purpose,
            claims=claims,
            token_version="v4",
            paserk_pid=self._keys.v4_paserk_pid,
        )
