import hashlib
from typing import Any

from .exceptions import VerifyError
from .utils import base64url_decode, base64url_encode, pae

#: A version tag prefix of the stable token identifier (``token_id``).
#: If the hash algorithm or its input layout ever changes, a new prefix
#: (``"pstid2."`` and so on) will be introduced so that identifiers issued
#: under different schemes never collide and remain distinguishable.
TOKEN_ID_PREFIX = "pstid1."


class Token:
    """
    The parsed token object which is a return value of :func:`pyseto.decode <pyseto.decode>`.
    """

    def __init__(
        self,
        version: str,
        purpose: str,
        payload: bytes | dict[str, Any],
        footer: bytes | dict[str, Any] = b"",
    ):
        self._version = version
        self._purpose = purpose
        self._payload = payload
        self._footer = footer
        self._header = (version + "." + purpose + ".").encode("utf-8")
        self._token_id: str | None = None

    def mark_verified(self, payload: bytes, footer: bytes, implicit_assertion: bytes = b"") -> str:
        """
        Computes the stable token identifier over the authenticated bytes of
        the token and marks the token as verified.

        This is intended to be called by the PASETO processor only, right
        after the AEAD tag or the signature has been successfully checked.
        Parsing a token alone (``Token.new()``) never produces an identifier:
        accessing ``token_id`` before this method runs raises ``VerifyError``,
        so an unverified or rejected token can never be mistaken for a
        verified identity.

        Args:
            payload (bytes): The raw, still authenticated payload bytes as
                carried by the token (for ``local``: nonce, ciphertext and
                tag; for ``public``: message and signature), before any
                decryption, signature stripping or deserialization.
            footer (bytes): The raw authenticated footer bytes (an empty byte
                string when the token has no footer).
            implicit_assertion (bytes): The implicit assertion that was
                supplied to the successful verification. It is authenticated
                in ``v3``/``v4`` and is therefore part of the identifier; it
                is an empty byte string for ``v1``/``v2``.
        Returns:
            str: The stable token identifier.
        """
        if self._token_id is None:
            digest = hashlib.sha256(pae([self._header, payload, footer, implicit_assertion])).digest()
            self._token_id = TOKEN_ID_PREFIX + base64url_encode(digest).decode("utf-8")
        return self._token_id

    @classmethod
    def new(cls, token: bytes | str) -> "Token":
        token = token if isinstance(token, str) else token.decode("utf-8")
        t = token.split(".")
        if len(t) != 3 and len(t) != 4:
            raise ValueError("token is invalid.")
        if not t[2]:
            raise ValueError("Empty payload.")
        p = base64url_decode(t[2])
        f = base64url_decode(t[3]) if len(t) == 4 else b""
        return cls(t[0], t[1], p, f)

    @property
    def version(self) -> str:
        """
        The version of the token. It will be ``"v1"``, ``"v2"``, ``"v3"`` or ``"v4"``.
        """
        return self._version

    @property
    def purpose(self) -> str:
        """
        The purpose of the token. It will be ``"local"`` or ``"public"``.
        """
        return self._purpose

    @property
    def header(self) -> bytes:
        """
        The header of the token. It will be ``"<version>.<type>."``.
        For example, ``"v1.local."``.
        """
        return self._header

    @property
    def payload(self) -> bytes | dict[str, Any]:
        """
        The payload of the token which is a decoded binary string. It's not Base64 encoded data.
        """
        return self._payload

    @payload.setter
    def payload(self, payload: bytes | dict[str, Any]) -> None:
        """
        A setter of the payload.
        """
        self._payload = payload
        return

    @property
    def footer(self) -> bytes | dict[str, Any]:
        """
        The footer of the token which is a decoded binary string. It's not Base64 encoded data.
        """
        return self._footer

    @footer.setter
    def footer(self, footer: bytes | dict[str, Any]) -> None:
        """
        A setter of the footer.
        """
        self._footer = footer
        return

    @property
    def token_id(self) -> str:
        """
        The stable token identifier, available only after the token has been
        successfully decrypted/verified via :func:`pyseto.decode <pyseto.decode>`.

        It is derived from the authenticated binary components of the token
        (header, raw payload, raw footer and the implicit assertion), not from
        the original token text or the decrypted claims. Consequently:

        * Textual aliases that decode to the same authenticated bytes
          (Base64 padding, the ``+``/``-`` and ``/``/``_`` alphabets or an
          empty 4th footer segment) yield the same identifier.
        * Different signatures, encryption nonces, footers or implicit
          assertions always yield different identifiers, even when the
          decrypted claims are identical.

        Accessing this property on a merely parsed (not yet verified) token
        raises ``VerifyError``, so a failed verification never returns an
        identifier that could be mistaken for a verified identity.
        """
        if self._token_id is None:
            raise VerifyError("token_id is only available after successful verification.")
        return self._token_id
