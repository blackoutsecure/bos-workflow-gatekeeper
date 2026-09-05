"""Policy decision matrix.

The fail-OPEN cases are the ones that matter: a bug here means someone's
release gate silently stops gating, which looks identical to a gate that
passed. Every `unknown` path is asserted explicitly.
"""

import pytest

from policy import UNKNOWN, Policy, Signals, evaluate


def sig(**kwargs) -> Signals:
    return Signals(**kwargs)


# --------------------------------------------------------------------------
# Organization role
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("role", "expected"),
    [("admin", True), ("member", False), ("outside", False), (UNKNOWN, False)],
)
def test_org_admin_only(role, expected):
    decision = evaluate(sig(org_role=role), Policy(allow_org_admin=True))
    assert decision.authorized is expected


def test_unknown_org_role_is_inconclusive_not_denied_silently():
    decision = evaluate(sig(org_role=UNKNOWN), Policy(allow_org_admin=True))
    assert decision.authorized is False
    assert decision.checks["org_admin"] is None
    assert "inconclusive" in decision.reason.lower()


# --------------------------------------------------------------------------
# Teams
# --------------------------------------------------------------------------
def test_team_match_authorizes():
    decision = evaluate(
        sig(org_role="member", teams_matched=("release",), teams_resolved=True),
        Policy(allow_org_admin=False, required_teams=("release",)),
    )
    assert decision.authorized is True


def test_no_team_match_denies():
    decision = evaluate(
        sig(org_role="member", teams_matched=(), teams_resolved=True),
        Policy(allow_org_admin=False, required_teams=("release",)),
    )
    assert decision.authorized is False


def test_unresolved_team_lookup_never_passes():
    decision = evaluate(
        sig(teams_matched=(), teams_resolved=False),
        Policy(allow_org_admin=False, required_teams=("release",)),
    )
    assert decision.authorized is False
    assert decision.checks["teams"] is None


# --------------------------------------------------------------------------
# Repository permission
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("have", "want", "expected"),
    [
        ("admin", "write", True),
        ("maintain", "write", True),
        ("write", "write", True),
        ("triage", "write", False),
        ("read", "write", False),
        ("none", "read", False),
        ("read", "read", True),
        (UNKNOWN, "write", False),
    ],
)
def test_repo_permission_threshold(have, want, expected):
    decision = evaluate(
        sig(repo_permission=have),
        Policy(allow_org_admin=False, required_repo_permission=want),
    )
    assert decision.authorized is expected


def test_unrecognised_permission_is_inconclusive():
    decision = evaluate(
        sig(repo_permission="galactic-overlord"),
        Policy(allow_org_admin=False, required_repo_permission="write"),
    )
    assert decision.checks["repo_permission"] is None
    assert decision.authorized is False


# --------------------------------------------------------------------------
# Enterprise ownership
# --------------------------------------------------------------------------
def test_enterprise_owner_authorizes_in_any_mode():
    decision = evaluate(
        sig(org_role="member", enterprise_owner="true"),
        Policy(allow_org_admin=True, enterprise_enabled=True),
    )
    assert decision.authorized is True


def test_require_enterprise_owner_ignores_other_passing_checks():
    decision = evaluate(
        sig(org_role="admin", enterprise_owner="false"),
        Policy(allow_org_admin=True, enterprise_enabled=True, require_enterprise_owner=True),
    )
    assert decision.authorized is False, "org admin must not bypass an enterprise-only policy"


def test_require_enterprise_owner_with_unknown_denies():
    decision = evaluate(
        sig(org_role="admin", enterprise_owner=UNKNOWN),
        Policy(allow_org_admin=True, enterprise_enabled=True, require_enterprise_owner=True),
    )
    assert decision.authorized is False
    assert "could not be verified" in decision.reason


# --------------------------------------------------------------------------
# Composition: OR (default) vs AND (require_all)
# --------------------------------------------------------------------------
def test_or_mode_one_pass_is_enough():
    decision = evaluate(
        sig(org_role="admin", teams_matched=(), teams_resolved=True),
        Policy(allow_org_admin=True, required_teams=("release",)),
    )
    assert decision.authorized is True


def test_require_all_needs_every_check():
    policy = Policy(allow_org_admin=True, required_teams=("release",), require_all=True)
    assert evaluate(
        sig(org_role="admin", teams_matched=(), teams_resolved=True), policy
    ).authorized is False
    assert evaluate(
        sig(org_role="admin", teams_matched=("release",), teams_resolved=True), policy
    ).authorized is True


def test_require_all_denies_on_any_inconclusive_signal():
    decision = evaluate(
        sig(org_role=UNKNOWN, teams_matched=("release",), teams_resolved=True),
        Policy(allow_org_admin=True, required_teams=("release",), require_all=True),
    )
    assert decision.authorized is False
    assert "require_all" in decision.reason


def test_or_mode_allows_when_another_check_gives_positive_evidence():
    # One signal unresolved, but a different check positively passed.
    decision = evaluate(
        sig(org_role="admin", teams_resolved=False),
        Policy(allow_org_admin=True, required_teams=("release",)),
    )
    assert decision.authorized is True


# --------------------------------------------------------------------------
# Degenerate configuration
# --------------------------------------------------------------------------
def test_no_rules_enabled_denies():
    decision = evaluate(sig(org_role="admin"), Policy(allow_org_admin=False))
    assert decision.authorized is False
    assert "No authorization rule is enabled" in decision.reason


def test_every_signal_unknown_denies():
    decision = evaluate(
        Signals(),
        Policy(allow_org_admin=True, required_teams=("x",), required_repo_permission="write",
               enterprise_enabled=True),
    )
    assert decision.authorized is False
    assert all(v is None for v in decision.checks.values())


def test_exact_trusted_app_actor_authorizes_without_org_membership():
    decision = evaluate(
        Signals(),
        Policy(trusted_app_slugs=("blackoutsecure-gatewall-aut-c172c5",)),
        "blackoutsecure-gatewall-aut-c172c5[bot]",
    )
    assert decision.authorized is True


@pytest.mark.parametrize("actor", ["blackoutsecure-gatewall-aut-c172c5-extra[bot]", "other-app[bot]"])
def test_untrusted_or_malformed_app_actor_denies(actor):
    decision = evaluate(
        Signals(org_role="admin"),
        Policy(trusted_app_slugs=("blackoutsecure-gatewall-aut-c172c5",)),
        actor,
    )
    assert decision.authorized is False


def test_trusted_app_shortcut_is_disabled_in_require_all_mode():
    decision = evaluate(
        Signals(),
        Policy(
            require_all=True,
            trusted_app_slugs=("blackoutsecure-gatewall-aut-c172c5",),
        ),
        "blackoutsecure-gatewall-aut-c172c5[bot]",
    )
    assert decision.authorized is False
