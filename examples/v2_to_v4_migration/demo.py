"""End-to-end, offline demonstration of the v2 -> v4 migration.

Run:  python3 demo.py
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from migration_sample import (  # noqa: E402
    AssertionContext,
    BindingError,
    LegacyV2Entry,
    RejectedByEntry,
    StrictV4Entry,
    UnsupportedVersion,
    canonical_assertion,
    issue_legacy_v2,
    issue_strict_v4,
    load_test_keys,
)
from migration_sample.business import legacy_route, new_bound_route  # noqa: E402

TENANT_A = AssertionContext("tenant-a", "billing")
TENANT_B = AssertionContext("tenant-b", "billing")
OTHER_PURPOSE = AssertionContext("tenant-a", "analytics")


def main() -> None:
    keys = load_test_keys()
    legacy = LegacyV2Entry(keys)
    strict_a = StrictV4Entry(keys, TENANT_A)

    print("== same Ed25519 key material, different PASERK ids ==")
    print(" v2 pid:", keys.v2_paserk_pid)
    print(" v4 pid:", keys.v4_paserk_pid)
    assert keys.v2_paserk_pid != keys.v4_paserk_pid

    old_token = issue_legacy_v2(keys, {"sub": "user-1", "tid": "tenant-a", "purpose": "billing"})
    new_token = issue_strict_v4(keys, TENANT_A, {"sub": "user-1"})
    print("\n== token headers ==")
    print(" old:", old_token[:24].decode())
    print(" new:", new_token[:24].decode())
    print(" assertion used at mint/verify:", canonical_assertion(TENANT_A).decode())

    print("\n== acceptance matrix (entry x token) ==")
    matrix = build_matrix(keys, old_token, new_token)
    for row in matrix:
        print(f" {row[0]:<34} | {row[1]:<10} | {row[2]}")

    print("\n== business routing ==")
    old_principal = legacy.verify(old_token)
    new_principal = strict_a.verify(new_token)
    print(" old token ->", legacy_route(old_principal))
    print(" old token ->", new_bound_route(old_principal))
    print(" new token ->", new_bound_route(new_principal))

    print("\n== v2 silently ignores any implicit assertion ==")
    # PySETO accepts the parameter on v2 but it never enters the signing input.
    import pyseto  # noqa: E402

    decoded = pyseto.decode(keys.v2_public, old_token, implicit_assertion=b"anything")
    print(" v2 decoded with bogus assertion:", json.loads(decoded.payload)["tid"])

    print("\n== cross-wiring attempts all fail ==")
    expect_unsupported(lambda: strict_a.verify(old_token), "v2 token at strict v4 entry")
    expect_unsupported(lambda: legacy.verify(new_token), "v4 token at legacy v2 entry")
    expect_binding(lambda: StrictV4Entry(keys, TENANT_B).verify(new_token), "wrong tenant assertion")
    expect_binding(lambda: StrictV4Entry(keys, OTHER_PURPOSE).verify(new_token), "wrong purpose assertion")
    expect_binding(lambda: StrictV4Entry(keys, TENANT_A).verify(issue_unbound_v4(keys)), "missing assertion at mint")
    expect_reject(lambda: strict_a.verify(rewrite_header(new_token)), "version header changed v4->v2")
    expect_binding(lambda: strict_a.verify(expired_v4(keys)), "expired token")

    print("\nAll migration invariants hold.")


def issue_unbound_v4(keys) -> bytes:
    # A v4 token minted with the empty assertion: the strict entry always passes
    # a non-empty tenant assertion, so signature verification fails.
    import pyseto

    return pyseto.encode(
        keys.v4_secret,
        json.dumps({"sub": "user-1", "tid": "tenant-a", "purpose": "billing"}).encode(),
    )


def rewrite_header(token: bytes) -> bytes:
    return b"v2.public." + token[len(b"v4.public.") :]


def expired_v4(keys) -> bytes:
    import pyseto

    past = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    return pyseto.encode(
        keys.v4_secret,
        json.dumps({"sub": "user-1", "tid": "tenant-a", "purpose": "billing", "exp": past}).encode(),
        implicit_assertion=canonical_assertion(TENANT_A),
    )


def build_matrix(keys, old_token: bytes, new_token: bytes) -> list[tuple]:
    rows = []
    strict_a = StrictV4Entry(keys, TENANT_A)
    strict_b = StrictV4Entry(keys, TENANT_B)
    legacy = LegacyV2Entry(keys)

    def outcome(fn) -> str:
        try:
            fn()
        except UnsupportedVersion as err:
            return f"REJECT version ({str(err).split(';')[0]})"
        except BindingError as err:
            return "REJECT binding"
        except RejectedByEntry:
            return "REJECT"
        return "ACCEPT"

    rows.append(("legacy v2 entry / old v2 token", "v2", outcome(lambda: legacy.verify(old_token))))
    rows.append(("legacy v2 entry / new v4 token", "v4", outcome(lambda: legacy.verify(new_token))))
    rows.append(("strict v4 entry / new v4 token (A)", "v4", outcome(lambda: strict_a.verify(new_token))))
    rows.append(("strict v4 entry / new v4 token (B)", "v4", outcome(lambda: strict_b.verify(new_token))))
    rows.append(("strict v4 entry / old v2 token", "v2", outcome(lambda: strict_a.verify(old_token))))
    return rows


def expect_unsupported(fn, label: str) -> None:
    try:
        fn()
    except UnsupportedVersion:
        print(f" OK  {label}: UnsupportedVersion")
        return
    raise AssertionError(label)


def expect_binding(fn, label: str) -> None:
    try:
        fn()
    except BindingError:
        print(f" OK  {label}: BindingError")
        return
    raise AssertionError(label)


def expect_reject(fn, label: str) -> None:
    try:
        fn()
    except RejectedByEntry:
        print(f" OK  {label}: rejected")
        return
    raise AssertionError(label)


if __name__ == "__main__":
    main()
