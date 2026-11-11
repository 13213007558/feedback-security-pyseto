import json

import pytest

import pyseto
from pyseto import Key, KeySet, VerifyError, extract_kid

from .utils import load_key


def make_counting(key):
    """
    Wraps a real key instance so each cryptographic verify/decrypt call is
    counted, without changing the key's type or PASERK identity.
    """
    key.calls = 0
    original_verify = key.verify
    original_decrypt = key.decrypt

    def count_verify(payload, footer=b"", implicit_assertion=b""):
        key.calls += 1
        return original_verify(payload, footer, implicit_assertion)

    def count_decrypt(payload, footer=b"", implicit_assertion=b""):
        key.calls += 1
        return original_decrypt(payload, footer, implicit_assertion)

    key.verify = count_verify
    key.decrypt = count_decrypt
    return key


def v4_secret():
    return Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))


def v4_public():
    return Key.new(4, "public", load_key("keys/public_key_ed25519.pem"))


def v4_public_2():
    return Key.new(4, "public", load_key("keys/public_key_ed25519_2.pem"))


def v2_public():
    return Key.new(2, "public", load_key("keys/public_key_ed25519.pem"))


def mixed_public_keys():
    return [
        Key.new(1, "public", load_key("keys/public_key_rsa.pem")),
        v2_public(),
        Key.new(3, "public", load_key("keys/public_key_ecdsa_p384.pem")),
        v4_public(),
    ]


class TestKeySetConstruction:
    def test_new_is_alias_of_constructor(self):
        keys = mixed_public_keys()
        assert [k.version for k in KeySet.new(keys)] == [k.version for k in KeySet(keys)]

    def test_rejects_non_list(self):
        with pytest.raises(ValueError) as err:
            KeySet(v4_public())
        assert "keys should be a list" in str(err.value)

    def test_rejects_non_key_elements(self):
        with pytest.raises(ValueError) as err:
            KeySet([v4_public(), "not-a-key"])
        assert "KeyInterface" in str(err.value)

    def test_empty_set_is_usable(self):
        ks = KeySet([])
        assert len(ks) == 0
        assert list(ks) == []
        assert ks.lookup("k4.pid.anything") is None

    def test_duplicate_identical_key_is_indexed_once(self):
        key = v4_public()
        ks = KeySet([key, key, key])
        assert len(ks) == 1
        assert ks.lookup(key.to_paserk_id()) is key

    def test_two_distinct_keys_have_distinct_ids(self):
        a, b = v4_public(), v4_public_2()
        assert a.to_paserk_id() != b.to_paserk_id()
        ks = KeySet([a, b])
        assert len(ks) == 2
        assert ks.lookup(a.to_paserk_id()) is a
        assert ks.lookup(b.to_paserk_id()) is b

    def test_same_material_different_versions_are_distinct(self):
        # The two Ed25519 keys are built from the same PEM material but are
        # interpreted under different PASETO versions; their PASERK IDs are
        # version-namespaced so they never collide.
        v2, v4 = v2_public(), v4_public()
        assert v2.to_paserk_id().startswith("k2.pid.")
        assert v4.to_paserk_id().startswith("k4.pid.")
        assert v2.to_paserk_id() != v4.to_paserk_id()
        ks = KeySet([v2, v4])
        assert len(ks) == 2
        assert ks.lookup(v2.to_paserk_id()) is v2
        assert ks.lookup(v4.to_paserk_id()) is v4

    def test_contains_uses_paserk_identity(self):
        key = v4_public()
        ks = KeySet([key])
        assert key in ks
        assert v4_public_2() not in ks
        assert "not-a-key" not in ks


class TestKeySetImmutability:
    def test_mutating_source_list_does_not_change_set(self):
        source = mixed_public_keys()
        ks = KeySet(source)
        assert len(ks) == 4
        source.append(v4_public_2())
        source.clear()
        assert len(ks) == 4
        assert isinstance(ks.keys, tuple)

    def test_keys_property_is_a_snapshot(self):
        ks = KeySet(mixed_public_keys())
        snapshot = ks.keys
        with pytest.raises(AttributeError):
            ks.keys = ()  # type: ignore[misc]
        assert snapshot == ks.keys

    def test_iteration_order_is_first_seen(self):
        keys = mixed_public_keys()
        assert [k.version for k in KeySet(keys)] == [1, 2, 3, 4]


class TestCandidates:
    def test_no_hint_returns_all_header_matches_in_order(self):
        ks = KeySet(mixed_public_keys())
        candidates = ks.candidates(b"v4.public.")
        assert [k.to_paserk_id() for k in candidates] == [v4_public().to_paserk_id()]

    def test_no_hint_returns_empty_on_header_mismatch(self):
        ks = KeySet(mixed_public_keys())
        assert ks.candidates(b"v4.local.") == []

    def test_known_hint_returns_single_candidate(self):
        keys = mixed_public_keys()
        ks = KeySet(keys)
        target = next(k for k in keys if k.version == 4)
        candidates = ks.candidates(b"v4.public.", target.to_paserk_id())
        assert candidates == [target]

    def test_unknown_hint_returns_empty(self):
        ks = KeySet(mixed_public_keys())
        assert ks.candidates(b"v4.public.", "k4.pid.unknown") == []

    def test_hint_whose_key_header_disagrees_returns_empty(self):
        # The id exists but names a v2 key while the token is v4.
        ks = KeySet(mixed_public_keys())
        assert ks.candidates(b"v4.public.", v2_public().to_paserk_id()) == []

    def test_invalid_arguments(self):
        ks = KeySet(mixed_public_keys())
        with pytest.raises(ValueError):
            ks.candidates("v4.public.")
        with pytest.raises(ValueError):
            ks.candidates(b"v4.public.", 123)  # type: ignore[arg-type]


class TestExtractKid:
    def test_extracts_string_kid(self):
        assert extract_kid(b'{"kid": "k4.pid.abc"}') == "k4.pid.abc"

    def test_empty_footer_means_no_hint(self):
        assert extract_kid(b"") == ""

    def test_non_json_footer_means_no_hint(self):
        assert extract_kid(b"plain-bytes-footer") == ""

    def test_json_non_object_means_no_hint(self):
        assert extract_kid(b"[1, 2, 3]") == ""

    def test_missing_kid_means_no_hint(self):
        assert extract_kid(b'{"other": "value"}') == ""

    def test_non_string_kid_means_no_hint(self):
        assert extract_kid(b'{"kid": 12345}') == ""
        assert extract_kid(b'{"kid": ["a"]}') == ""


class TestDecodeWithKeySet:
    def test_decode_with_matching_hint(self):
        sk = v4_secret()
        ks = KeySet(mixed_public_keys())
        footer = json.dumps({"kid": v4_public().to_paserk_id()}).encode()
        token = pyseto.encode(sk, b"Hello world!", footer=footer)
        decoded = pyseto.decode(ks, token)
        assert decoded.payload == b"Hello world!"
        assert decoded.version == "v4"
        assert decoded.purpose == "public"

    def test_decode_without_hint_scans_all_matching_keys(self):
        sk = v4_secret()
        ks = KeySet(mixed_public_keys())
        token = pyseto.encode(sk, b"Hello world!")
        decoded = pyseto.decode(ks, token)
        assert decoded.payload == b"Hello world!"

    def test_decode_unknown_hint_raises_deterministically(self):
        sk = v4_secret()
        ks = KeySet(mixed_public_keys())
        footer = json.dumps({"kid": "k4.pid.unknown"}).encode()
        token = pyseto.encode(sk, b"Hello world!", footer=footer)
        with pytest.raises(ValueError) as err:
            pyseto.decode(ks, token)
        assert "No key matching the kid hint" in str(err.value)

    def test_decode_hint_version_mismatch_raises(self):
        sk = v4_secret()
        ks = KeySet([v2_public(), v4_public()])
        # Token is v4 but the hint points at the v2 key sharing the material.
        footer = json.dumps({"kid": v2_public().to_paserk_id()}).encode()
        token = pyseto.encode(sk, b"Hello world!", footer=footer)
        with pytest.raises(ValueError) as err:
            pyseto.decode(ks, token)
        assert "No key matching the kid hint" in str(err.value)

    def test_decode_malformed_footer_hint_falls_back_to_scan(self):
        sk = v4_secret()
        ks = KeySet(mixed_public_keys())
        token = pyseto.encode(sk, b"Hello world!", footer=b"not-json")
        decoded = pyseto.decode(ks, token)
        assert decoded.payload == b"Hello world!"

    def test_forged_hint_cannot_make_wrong_key_pass(self):
        # Sign with key A but put key B's id in the (unauthenticated) footer.
        # Both keys are in the set, so lookup succeeds and B is selected, but B
        # cannot verify A's signature and must not fall back to A.
        sk_a = v4_secret()
        pk_a, pk_b = v4_public(), v4_public_2()
        ks = KeySet([pk_a, pk_b])
        forged_footer = json.dumps({"kid": pk_b.to_paserk_id()}).encode()
        token = pyseto.encode(sk_a, b"secret", footer=forged_footer)
        with pytest.raises(VerifyError):
            pyseto.decode(ks, token)

    def test_tampered_footer_fails_even_with_correct_hint(self):
        sk = v4_secret()
        pk = v4_public()
        ks = KeySet([pk])
        footer = json.dumps({"kid": pk.to_paserk_id()}).encode()
        token = pyseto.encode(sk, b"Hello world!", footer=footer)
        # Flip a byte in the signed token's footer segment.
        raw = token if isinstance(token, bytes) else token.encode("utf-8")
        parts = raw.split(b".")
        footer_b64 = bytearray(parts[3])
        footer_b64[0] = ord("A") if footer_b64[0] != ord("A") else ord("B")
        parts[3] = bytes(footer_b64)
        tampered = b".".join(parts)
        with pytest.raises((VerifyError, ValueError)):
            pyseto.decode(ks, tampered)

    def test_empty_key_set_raises_not_found(self):
        sk = v4_secret()
        token = pyseto.encode(sk, b"Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode(KeySet([]), token)
        assert "key is not found for verifying the token." in str(err.value)

    def test_hint_selects_single_cryptographic_verification(self):
        sk = v4_secret()
        counters = [make_counting(k) for k in mixed_public_keys()]
        ks = KeySet(counters)
        target = next(c for c in counters if c.version == 4)
        footer = json.dumps({"kid": target.to_paserk_id()}).encode()
        token = pyseto.encode(sk, b"Hello world!", footer=footer)
        pyseto.decode(ks, token)
        assert target.calls == 1
        assert sum(c.calls for c in counters) == 1

    def test_without_hint_only_matching_header_is_verified(self):
        sk = v4_secret()
        counters = [make_counting(k) for k in mixed_public_keys()]
        ks = KeySet(counters)
        token = pyseto.encode(sk, b"Hello world!")
        pyseto.decode(ks, token)
        target = next(c for c in counters if c.version == 4)
        # Only the single v4 key shares the token header; the v1/v2/v3 keys are
        # skipped by header before any cryptographic verification runs.
        assert target.calls == 1
        assert sum(c.calls for c in counters) == 1

    def test_duplicate_key_in_set_is_verified_only_once(self):
        sk = v4_secret()
        pk = make_counting(v4_public())
        ks = KeySet([pk, pk])
        footer = json.dumps({"kid": pk.to_paserk_id()}).encode()
        token = pyseto.encode(sk, b"Hello world!", footer=footer)
        pyseto.decode(ks, token)
        assert pk.calls == 1


class TestDecodeBackwardCompatibility:
    def test_single_key_still_works(self):
        sk = v4_secret()
        token = pyseto.encode(sk, b"Hello world!")
        assert pyseto.decode(v4_public(), token).payload == b"Hello world!"

    def test_list_of_keys_still_works(self):
        sk = v4_secret()
        token = pyseto.encode(sk, b"Hello world!")
        decoded = pyseto.decode(mixed_public_keys(), token)
        assert decoded.payload == b"Hello world!"

    def test_rejects_unsupported_keys_type(self):
        sk = v4_secret()
        token = pyseto.encode(sk, b"Hello world!")
        with pytest.raises(ValueError):
            pyseto.decode({"k": v4_public()}, token)
