import pytest

import pyseto
from pyseto import Key, VerifyError
from pyseto.token import TOKEN_ID_PREFIX, Token
from pyseto.utils import base64url_decode, base64url_encode

from .utils import load_key


class TestToken:
    """
    Tests for Token.
    """

    def test_token_new(self):
        token = Token.new(
            b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.version == "v1"
        assert token.purpose == "local"
        assert token.payload == base64url_decode(
            "WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.footer == b""

    def test_token_new_with_str(self):
        token = Token.new(
            "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.version == "v1"
        assert token.purpose == "local"
        assert token.payload == base64url_decode(
            "WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.footer == b""

    def test_token_setter_payload(self):
        token = Token.new(
            b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        token.payload = b"updated-payload"
        assert token.payload == b"updated-payload"

    def test_token_setter_footer(self):
        token = Token.new(
            b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        token.footer = b"updated-footer"
        assert token.footer == b"updated-footer"

    @pytest.mark.parametrize(
        "token, msg",
        [
            ("v1", "token is invalid."),
            ("v1.", "token is invalid."),
            ("v1.local", "token is invalid."),
            ("v1.local.", "Empty payload."),
            ("v1.local.p.f.x", "token is invalid."),
            ("v1.local.p.f.x.y", "token is invalid."),
        ],
    )
    def test_token_new_with_invalid_token(self, token, msg):
        with pytest.raises(ValueError) as err:
            Token.new(token)
            pytest.fail("Token.new() should fail.")
        assert msg in str(err.value)


def _b64_aliases(token: bytes) -> list[bytes]:
    parts = token.decode("utf-8").split(".")
    payload = parts[2]
    padding = "=" * ((4 - len(payload) % 4) % 4)
    aliases = [
        token,
        ".".join(parts[:2] + [payload + padding] + parts[3:]).encode("utf-8"),
        token.replace(b"-", b"+").replace(b"_", b"/"),
    ]
    if len(parts) == 3:
        aliases.append(token + b".")
    return aliases


class TestTokenId:
    """
    Tests for the stable token identifier (Token.token_id).
    """

    def _v4_keys(self):
        sk = Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))
        pk = Key.new(4, "public", load_key("keys/public_key_ed25519.pem"))
        return sk, pk

    def test_token_id_unavailable_before_verification(self):
        token = Token.new(b"v4.public." + base64url_encode(b"not-a-real-token"))
        with pytest.raises(VerifyError) as err:
            token.token_id
        assert "successful verification" in str(err.value)

    def test_token_id_format(self):
        sk, pk = self._v4_keys()
        token = pyseto.encode(sk, b"hello")
        decoded = pyseto.decode(pk, token)
        assert decoded.token_id.startswith(TOKEN_ID_PREFIX)
        assert len(decoded.token_id) == len(TOKEN_ID_PREFIX) + 43

    def test_token_id_stable_across_base64_aliases_public(self):
        sk, pk = self._v4_keys()
        token = pyseto.encode(sk, b'{"sub":"alice"}', footer=b"kid-1", implicit_assertion=b"ia")
        ids = {pyseto.decode(pk, alias, implicit_assertion=b"ia").token_id for alias in _b64_aliases(token)}
        assert len(ids) == 1

    def test_token_id_stable_across_base64_aliases_local(self):
        key = Key.new(4, "local", b"our-secret")
        token = pyseto.encode(key, b'{"sub":"alice"}', nonce=b"\x01" * 32, footer=b"kid-1")
        ids = {pyseto.decode(key, alias).token_id for alias in _b64_aliases(token)}
        assert len(ids) == 1

    def test_token_id_differs_for_different_signature(self):
        sk, pk = self._v4_keys()
        sk2 = Key.new(4, "public", load_key("keys/private_key_ed25519_2.pem"))
        pk2 = Key.new(4, "public", load_key("keys/public_key_ed25519_2.pem"))
        t1 = pyseto.encode(sk, b'{"sub":"alice"}')
        t2 = pyseto.encode(sk2, b'{"sub":"alice"}')
        assert pyseto.decode(pk, t1).token_id != pyseto.decode(pk2, t2).token_id

    def test_token_id_differs_for_different_footer(self):
        sk, pk = self._v4_keys()
        t1 = pyseto.encode(sk, b'{"sub":"alice"}', footer=b"kid-1")
        t2 = pyseto.encode(sk, b'{"sub":"alice"}', footer=b"kid-2")
        assert pyseto.decode(pk, t1).token_id != pyseto.decode(pk, t2).token_id

    def test_token_id_differs_for_local_nonce(self):
        key = Key.new(4, "local", b"our-secret")
        t1 = pyseto.encode(key, b'{"sub":"alice"}', nonce=b"\x01" * 32)
        t2 = pyseto.encode(key, b'{"sub":"alice"}', nonce=b"\x02" * 32)
        assert pyseto.decode(key, t1).token_id != pyseto.decode(key, t2).token_id

    def test_token_id_includes_implicit_assertion(self):
        raw = b"v4.public." + base64url_encode(b"some-authenticated-bytes")
        token = Token.new(raw)
        id_a = token.mark_verified(token.payload, token.footer, b"ia-a")
        token_b = Token.new(raw)
        id_b = token_b.mark_verified(token_b.payload, token_b.footer, b"ia-b")
        assert id_a != id_b

    def test_token_id_not_derived_from_claims_or_mutation(self):
        sk, pk = self._v4_keys()
        token = pyseto.encode(sk, b'{"sub":"alice"}')
        decoded = pyseto.decode(pk, token)
        expected = decoded.token_id
        decoded.payload = {"sub": "tampered"}
        decoded.footer = b"tampered-footer"
        assert decoded.token_id == expected

    def test_token_id_not_returned_on_failed_verification(self):
        sk, pk = self._v4_keys()
        token = bytearray(pyseto.encode(sk, b"hello"))
        token[-1] ^= 0x01
        with pytest.raises(VerifyError):
            pyseto.decode(pk, bytes(token))

    def test_token_id_not_returned_on_failed_decryption(self):
        key = Key.new(4, "local", b"our-secret")
        other = Key.new(4, "local", b"others-secret")
        token = pyseto.encode(key, b"hello")
        with pytest.raises(pyseto.DecryptError):
            pyseto.decode(other, token)

    def test_mark_verified_is_idempotent(self):
        sk, pk = self._v4_keys()
        decoded = pyseto.decode(pk, pyseto.encode(sk, b"hello"))
        first = decoded.token_id
        assert decoded.mark_verified(b"x", b"y", b"z") == first
