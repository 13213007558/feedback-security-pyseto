"""Migration invariants: old compatibility path cannot reach the bound new route."""

import json
from datetime import datetime, timedelta, timezone

import pyseto
import pytest

from migration_sample import (
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
from migration_sample.business import guard_new_route, legacy_route, new_bound_route

TENANT_A = AssertionContext("tenant-a", "billing")
TENANT_B = AssertionContext("tenant-b", "billing")
OTHER_PURPOSE = AssertionContext("tenant-a", "analytics")


@pytest.fixture(scope="module")
def keys():
    return load_test_keys()


@pytest.fixture(scope="module")
def old_token(keys):
    return issue_legacy_v2(keys, {"sub": "user-1", "tid": "tenant-a", "purpose": "billing"})


@pytest.fixture(scope="module")
def new_token(keys):
    return issue_strict_v4(keys, TENANT_A, {"sub": "user-1"})


@pytest.fixture(scope="module")
def legacy(keys):
    return LegacyV2Entry(keys)


@pytest.fixture(scope="module")
def strict(keys):
    return StrictV4Entry(keys, TENANT_A)


class TestSameKeyDifferentIdentity:
    def test_paserk_ids_differ_across_versions(self, keys):
        assert keys.v2_paserk_pid.startswith("k2.pid.")
        assert keys.v4_paserk_pid.startswith("k4.pid.")
        assert keys.v2_paserk_pid != keys.v4_paserk_pid

    def test_token_headers_pin_the_version(self, old_token, new_token):
        assert old_token.startswith(b"v2.public.")
        assert new_token.startswith(b"v4.public.")


class TestLegacyV2SurvivalConditions:
    def test_v2_token_lives_only_at_legacy_entry(self, legacy, old_token):
        principal = legacy.verify(old_token)
        assert principal.token_version == "v2"
        assert principal.tenant == "tenant-a"
        assert principal.paserk_pid.startswith("k2.pid.")

    def test_v2_has_no_implicit_assertion_binding(self, keys, old_token):
        # Any assertion string is accepted because v2's signing input has no
        # assertion slot: payload tenant is an advisory claim, not a binding.
        for bogus in (b"", b"tid=tenant-b;purpose=billing", b"anything"):
            decoded = pyseto.decode(keys.v2_public, old_token, implicit_assertion=bogus)
            assert json.loads(decoded.payload)["tid"] == "tenant-a"

    def test_legacy_entry_rejects_v4_header(self, legacy, new_token):
        with pytest.raises(UnsupportedVersion, match="only v2.public"):
            legacy.verify(new_token)


class TestStrictV4RejectionRules:
    def test_bound_token_accepted_with_matching_assertion(self, strict, new_token):
        principal = strict.verify(new_token)
        assert principal.token_version == "v4"
        assert principal.tenant == "tenant-a"
        assert principal.purpose == "billing"
        assert principal.paserk_pid.startswith("k4.pid.")

    def test_wrong_tenant_assertion_rejected(self, keys, new_token):
        with pytest.raises(BindingError, match="verification failed"):
            StrictV4Entry(keys, TENANT_B).verify(new_token)

    def test_wrong_purpose_assertion_rejected(self, keys, new_token):
        with pytest.raises(BindingError, match="verification failed"):
            StrictV4Entry(keys, OTHER_PURPOSE).verify(new_token)

    def test_token_minted_without_assertion_rejected(self, keys):
        unbound = pyseto.encode(
            keys.v4_secret,
            json.dumps({"sub": "user-1", "tid": "tenant-a", "purpose": "billing"}).encode(),
        )
        with pytest.raises(BindingError, match="verification failed"):
            StrictV4Entry(keys, TENANT_A).verify(unbound)

    def test_v2_token_rejected_at_strict_entry(self, strict, old_token):
        with pytest.raises(UnsupportedVersion, match="only v4.public"):
            strict.verify(old_token)

    def test_version_header_change_breaks_verification(self, strict, new_token):
        forged = b"v2.public." + new_token[len(b"v4.public.") :]
        with pytest.raises(RejectedByEntry):
            strict.verify(forged)

    def test_missing_required_claim_rejected_after_signature_ok(self, keys):
        token = pyseto.encode(
            keys.v4_secret,
            json.dumps({"sub": "user-1"}).encode(),
            implicit_assertion=canonical_assertion(TENANT_A),
        )
        with pytest.raises(BindingError, match="missing required claim 'tid'"):
            StrictV4Entry(keys, TENANT_A).verify(token)

    def test_payload_claim_contradicting_assertion_rejected(self, keys):
        token = pyseto.encode(
            keys.v4_secret,
            json.dumps({"sub": "user-1", "tid": "tenant-b", "purpose": "billing"}).encode(),
            implicit_assertion=canonical_assertion(TENANT_A),
        )
        with pytest.raises(BindingError, match="does not match bound value"):
            StrictV4Entry(keys, TENANT_A).verify(token)

    def test_expired_token_rejected(self, keys):
        past = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        token = pyseto.encode(
            keys.v4_secret,
            json.dumps({"sub": "user-1", "tid": "tenant-a", "purpose": "billing", "exp": past}).encode(),
            implicit_assertion=canonical_assertion(TENANT_A),
        )
        with pytest.raises(BindingError, match="Token expired"):
            StrictV4Entry(keys, TENANT_A).verify(token)


class TestNoLoopbackToBoundRoute:
    def test_legacy_principal_denied_new_route(self, legacy, old_token):
        principal = legacy.verify(old_token)
        decision = new_bound_route(principal)
        assert decision.allowed is False
        with pytest.raises(RejectedByEntry, match="requires a v4.public bound principal"):
            guard_new_route(principal)

    def test_legacy_route_does_not_upgrade_v4_principal(self, strict, new_token):
        principal = strict.verify(new_token)
        assert legacy_route(principal).allowed is False

    def test_verifying_old_token_nowhere_creates_binding(self, legacy, old_token):
        # Re-verification succeeds at the legacy entry forever, but the principal
        # remains version v2 and therefore can never pass the new-route guard.
        again = legacy.verify(old_token)
        assert again.token_version == "v2"
        with pytest.raises(RejectedByEntry):
            guard_new_route(again)
