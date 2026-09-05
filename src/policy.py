"""Pure authorization policy evaluation.

Deliberately free of I/O so every branch of the decision matrix is testable
without mocking a network. `signals.py` gathers evidence; this module decides
what the evidence means.
"""

from __future__ import annotations

from dataclasses import dataclass, field

UNKNOWN = "unknown"

# Ascending privilege. `none` is a real answer (actor has no access at all);
# `unknown` means we could not find out, which is never treated as evidence.
PERMISSION_RANK = {
    "none": 0,
    "read": 1,
    "triage": 2,
    "write": 3,
    "maintain": 4,
    "admin": 5,
}


@dataclass(frozen=True)
class Signals:
    """Everything resolved about the actor. Any field may be `unknown`."""

    org_role: str = UNKNOWN            # admin | member | outside | unknown
    teams_matched: tuple[str, ...] = ()
    teams_resolved: bool = False       # False when the team lookup was inconclusive
    repo_permission: str = UNKNOWN     # none | read | triage | write | maintain | admin | unknown
    enterprise_owner: str = UNKNOWN    # "true" | "false" | unknown


@dataclass(frozen=True)
class Policy:
    """What the caller asked us to enforce."""

    allow_org_admin: bool = True
    required_teams: tuple[str, ...] = ()
    required_repo_permission: str = ""
    enterprise_enabled: bool = False
    require_enterprise_owner: bool = False
    require_all: bool = False
    trusted_app_slugs: tuple[str, ...] = ()


@dataclass
class Decision:
    authorized: bool
    reason: str
    checks: dict[str, bool | None] = field(default_factory=dict)


def _check_org_admin(signals: Signals) -> bool | None:
    if signals.org_role == UNKNOWN:
        return None
    return signals.org_role == "admin"


def _check_teams(signals: Signals) -> bool | None:
    if not signals.teams_resolved:
        return None
    return bool(signals.teams_matched)


def _check_repo_permission(signals: Signals, required: str) -> bool | None:
    if signals.repo_permission == UNKNOWN:
        return None
    have = PERMISSION_RANK.get(signals.repo_permission)
    want = PERMISSION_RANK.get(required.strip().lower())
    if have is None or want is None:
        return None
    return have >= want


def _check_enterprise(signals: Signals) -> bool | None:
    if signals.enterprise_owner == UNKNOWN:
        return None
    return signals.enterprise_owner == "true"


def is_trusted_app_actor(actor: str, trusted_app_slugs: tuple[str, ...]) -> bool:
    """Return whether ``actor`` is exactly one configured App bot identity."""
    return actor.endswith("[bot]") and actor[:-5] in trusted_app_slugs


def evaluate(signals: Signals, policy: Policy, actor: str = "") -> Decision:
    """Resolve signals plus policy into an allow/deny decision.

    `None` in `checks` means the signal was unresolvable. An unresolved check
    never counts as a pass, and in `require_all` mode it denies outright --
    "we could not tell" must never read as "permitted".
    """
    checks: dict[str, bool | None] = {}

    if actor.endswith("[bot]"):
        if policy.require_all:
            return Decision(
                False,
                "Trusted App authorization is disabled in require_all mode.",
                {"trusted_app": None},
            )
        if is_trusted_app_actor(actor, policy.trusted_app_slugs):
            return Decision(True, "Actor is a configured trusted GitHub App.", {"trusted_app": True})
        return Decision(False, "GitHub App actor is not in the trusted App slug allowlist.", {"trusted_app": False})

    if policy.allow_org_admin:
        checks["org_admin"] = _check_org_admin(signals)
    if policy.required_teams:
        checks["teams"] = _check_teams(signals)
    if policy.required_repo_permission:
        checks["repo_permission"] = _check_repo_permission(
            signals, policy.required_repo_permission
        )
    if policy.enterprise_enabled:
        checks["enterprise_owner"] = _check_enterprise(signals)

    if policy.require_enterprise_owner:
        result = checks.get("enterprise_owner")
        if result is True:
            return Decision(True, "Actor is an enterprise owner.", checks)
        if result is None:
            return Decision(
                False,
                "Enterprise ownership could not be verified. The token must belong "
                "to an enterprise owner and carry admin:enterprise.",
                checks,
            )
        return Decision(False, "Actor is not an enterprise owner.", checks)

    if not checks:
        return Decision(
            False,
            "No authorization rule is enabled, so nothing could satisfy this policy.",
            checks,
        )

    passed = [name for name, value in checks.items() if value is True]
    inconclusive = [name for name, value in checks.items() if value is None]

    if policy.require_all:
        if inconclusive:
            return Decision(
                False,
                f"Inconclusive signal(s) in require_all mode: {', '.join(sorted(inconclusive))}.",
                checks,
            )
        if len(passed) == len(checks):
            return Decision(True, f"All required checks passed: {', '.join(sorted(passed))}.", checks)
        failed = [name for name, value in checks.items() if value is False]
        return Decision(False, f"Failed required check(s): {', '.join(sorted(failed))}.", checks)

    if passed:
        return Decision(True, f"Satisfied via: {', '.join(sorted(passed))}.", checks)
    if inconclusive:
        return Decision(
            False,
            f"No check passed and signal(s) were inconclusive: {', '.join(sorted(inconclusive))}.",
            checks,
        )
    return Decision(False, "Actor satisfied none of the configured checks.", checks)
