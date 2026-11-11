"""Business routes and the guard that keeps the legacy path from looping back."""

from dataclasses import dataclass

from .errors import RejectedByEntry
from .tokens import Principal


@dataclass(frozen=True)
class RouteDecision:
    route: str
    allowed: bool
    reason: str


def legacy_route(principal: Principal) -> RouteDecision:
    """The old surface. Reachable by v2 principals during the migration window."""
    if principal.token_version != "v2":
        return RouteDecision("legacy", False, "legacy route is reserved for v2.public tokens")
    return RouteDecision(
        "legacy",
        True,
        "v2 signature valid; tenant/purpose remain UNBOUND advisory claims",
    )


def new_bound_route(principal: Principal) -> RouteDecision:
    """The new surface. Only a v4 principal that passed implicit-assertion binding enters."""
    if principal.token_version != "v4":
        return RouteDecision(
            "new-bound",
            False,
            f"{principal.token_version}.public has no implicit-assertion binding; refused",
        )
    return RouteDecision(
        "new-bound",
        True,
        f"bound to tid={principal.tenant};purpose={principal.purpose} via v4 implicit assertion",
    )


def guard_new_route(verify_result: object) -> RouteDecision:
    """Single choke point: anything that is not a verified v4 Principal is rejected."""
    if not isinstance(verify_result, Principal) or verify_result.token_version != "v4":
        raise RejectedByEntry("new business entry requires a v4.public bound principal")
    return new_bound_route(verify_result)
