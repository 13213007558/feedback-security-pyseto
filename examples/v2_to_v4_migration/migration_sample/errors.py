"""Error taxonomy for the two migration entry points."""


class RejectedByEntry(Exception):
    """A token was refused at an entry point."""


class UnsupportedVersion(RejectedByEntry):
    """The token's PASETO version header is not accepted by this entry."""


class BindingError(RejectedByEntry):
    """Signature verified but the tenant/purpose binding is absent or wrong."""
