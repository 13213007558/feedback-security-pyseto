import json
from typing import Iterator, Optional

from .key_interface import KeyInterface


class KeySet:
    """
    An immutable, pre-indexed read-only collection of PASETO keys.

    A ``KeySet`` is built once from a list of keys and then never changes.
    Each key is indexed by its PASERK ID (see
    :func:`pyseto.KeyInterface.to_paserk_id
    <pyseto.key_interface.KeyInterface.to_paserk_id>`), so a token that carries
    a key ID hint in its footer can be matched to a single candidate key
    instead of being tried against every key in turn.

    Security model:

    - The key ID hint lives in the token's **unauthenticated** footer. It is
      used only as a lookup hint to select candidate keys. It never authenticates
      anything on its own; the selected key still has to verify the complete
      token, including its version, purpose and the footer the hint came from.
    - An unknown, malformed or missing hint never bypasses verification. An
      unknown hint raises immediately; a malformed or missing hint falls back to
      trying every key whose header matches the token.

    The collection is a defensive copy: mutating the list passed to the
    constructor (or mutating any element in it) after construction has no effect
    on the set.
    """

    def __init__(self, keys: list[KeyInterface]):
        """
        Creates a read-only key set from a list of keys.

        Args:
            keys (list[KeyInterface]): Keys to index. The list is copied, so
                later changes to it do not affect the set.
        Raise:
            ValueError: Invalid arguments.
        """
        if not isinstance(keys, list):
            raise ValueError("keys should be a list of KeyInterface.")

        ordered: list[KeyInterface] = []
        by_id: dict[str, KeyInterface] = {}
        for key in keys:
            if not isinstance(key, KeyInterface):
                raise ValueError("Each element of keys should be a KeyInterface.")
            kid = key.to_paserk_id()
            # A PASERK ID is a deterministic fingerprint of (version, purpose,
            # material). Re-adding the same key is a no-op so it can never be
            # verified against twice; two distinct keys cannot share an ID.
            if kid not in by_id:
                by_id[kid] = key
                ordered.append(key)

        self._keys: tuple[KeyInterface, ...] = tuple(ordered)
        self._by_id: dict[str, KeyInterface] = by_id

    @classmethod
    def new(cls, keys: list[KeyInterface]) -> "KeySet":
        """
        Constructor of a read-only key set. It is an alias of ``__init__``.

        Args:
            keys (list[KeyInterface]): Keys to index.
        Returns:
            KeySet: A read-only key set.
        Raise:
            ValueError: Invalid arguments.
        """
        return cls(keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __iter__(self) -> Iterator[KeyInterface]:
        return iter(self._keys)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, KeyInterface):
            return False
        return key.to_paserk_id() in self._by_id

    @property
    def keys(self) -> tuple[KeyInterface, ...]:
        """
        The keys in the set, in their first-seen order. The returned tuple is a
        snapshot and cannot be used to mutate the set.
        """
        return self._keys

    def lookup(self, kid: str) -> Optional[KeyInterface]:
        """
        Returns the key whose PASERK ID equals ``kid``, or ``None`` if the set
        holds no such key.

        Args:
            kid (str): A PASERK ID used as a lookup hint.
        Returns:
            Optional[KeyInterface]: The matching key, or ``None`` when unknown.
        """
        return self._by_id.get(kid)

    def candidates(self, header: bytes, kid: str = "") -> list[KeyInterface]:
        """
        Selects the candidate keys to verify a token against.

        When ``kid`` is a non-empty string it is treated as an unauthenticated
        lookup hint:

        - if it identifies a known key whose header matches the token, that key
          is the sole candidate;
        - if it identifies a known key whose header does not match, there are no
          candidates (the hint and the token disagree on version/purpose);
        - if it is unknown, an empty list is returned rather than guessing.

        When ``kid`` is empty, every key whose header matches is returned in
        first-seen order, preserving the behavior of trying all matching keys.

        Args:
            header (bytes): The token header, e.g. ``b"v4.public."``.
            kid (str): An optional PASERK ID hint taken from the token footer.
        Returns:
            list[KeyInterface]: Candidate keys, possibly empty.
        Raise:
            ValueError: Invalid arguments.
        """
        if not isinstance(header, bytes):
            raise ValueError("header should be bytes.")
        if not isinstance(kid, str):
            raise ValueError("kid should be a str.")

        if kid:
            key = self._by_id.get(kid)
            if key is None:
                return []
            return [key] if key.header == header else []

        return [key for key in self._keys if key.header == header]


def extract_kid(footer: bytes) -> str:
    """
    Extracts a key ID hint from an unauthenticated token footer.

    The hint is read from the ``kid`` member of a JSON object footer, following
    the PASETO convention of placing a key identifier there. Because the footer
    is not authenticated at this stage, the returned value must only ever be used
    as a lookup hint, never as proof of identity.

    Any footer that is absent, not a JSON object, or has no string ``kid``
    member yields an empty string, meaning "no usable hint". This function does
    not raise on malformed data and performs no network or other side-effecting
    access.

    Args:
        footer (bytes): The raw, base64url-decoded token footer.
    Returns:
        str: The ``kid`` hint, or ``""`` when no usable hint is present.
    """
    if not footer:
        return ""
    try:
        parsed = json.loads(footer.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    kid = parsed.get("kid", "")
    return kid if isinstance(kid, str) else ""
