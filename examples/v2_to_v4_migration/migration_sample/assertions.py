"""Canonical implicit assertion binding tenant and purpose.

The assertion is never stored in the token. For v4.public it is fed into the
Ed25519 signing input through PAE, so a token is only verifiable when the
verifier reconstructs the exact same assertion.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AssertionContext:
    tenant: str
    purpose: str

    def __post_init__(self) -> None:
        if not self.tenant or not self.purpose:
            raise ValueError("tenant and purpose must both be non-empty.")


def canonical_assertion(ctx: AssertionContext) -> bytes:
    return f"tid={ctx.tenant};purpose={ctx.purpose}".encode("utf-8")
