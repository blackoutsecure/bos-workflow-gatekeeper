"""Action entrypoint: read inputs, gather signals, enforce the decision."""

from __future__ import annotations

import os
import sys

from policy import Policy, evaluate
from runtime import append_github_output, append_step_summary, env_bool, env_csv
from signals import Client, gather


def _bool(name: str, default: bool) -> bool:
    return env_bool(os.environ, name, default)


def _csv(name: str) -> tuple[str, ...]:
    return env_csv(os.environ, name)


def emit(**pairs: str) -> None:
    append_github_output(os.environ, **pairs)


def write_summary(lines: list[str]) -> None:
    append_step_summary(os.environ, lines)


def main() -> int:
    event_name = os.environ.get("EVENT_NAME", "")
    restrict = _csv("RESTRICT_TO_EVENTS")
    fail_closed = _bool("FAIL_CLOSED", True)
    actor = os.environ.get("ACTOR", "").strip()
    organization = os.environ.get("ORGANIZATION", "").strip()
    token = os.environ.get("TOKEN", "")

    if restrict and "*" not in restrict and event_name not in restrict:
        emit(authorized="true", reason=f"Event '{event_name}' is not gated.", enforced="false")
        print(f"::notice title=Gatekeeper::Event '{event_name}' is not gated; passing through.")
        return 0

    policy = Policy(
        allow_org_admin=_bool("ALLOW_ORG_ADMIN", True),
        required_teams=_csv("REQUIRED_TEAMS"),
        required_repo_permission=os.environ.get("REQUIRED_REPO_PERMISSION", "").strip(),
        enterprise_enabled=bool(os.environ.get("ENTERPRISE_SLUG", "").strip()),
        require_enterprise_owner=_bool("REQUIRE_ENTERPRISE_OWNER", False),
        require_all=_bool("REQUIRE_ALL", False),
    )

    if not token or not actor or not organization:
        missing = "token" if not token else ("actor" if not actor else "organization")
        reason = (
            f"Missing required input: {missing}. The default GITHUB_TOKEN cannot resolve "
            "organization role, team membership, or enterprise ownership."
        )
        return _finish(False, reason, {}, None, policy, fail_closed, actor)

    client = Client(
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        graphql_url=os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
        token=token,
        enterprise_token=os.environ.get("ENTERPRISE_TOKEN", ""),
    )
    resolved = gather(
        client,
        actor=actor,
        organization=organization,
        repository=os.environ.get("REPOSITORY", "").strip(),
        wanted_teams=policy.required_teams,
        enterprise_slug=os.environ.get("ENTERPRISE_SLUG", "").strip(),
        need_org_role=policy.allow_org_admin,
        need_repo_permission=bool(policy.required_repo_permission),
    )
    decision = evaluate(resolved, policy)
    return _finish(
        decision.authorized, decision.reason, decision.checks, resolved, policy, fail_closed, actor
    )


def _finish(authorized, reason, checks, resolved, policy, fail_closed, actor) -> int:
    emit(
        authorized="true" if authorized else "false",
        reason=reason,
        enforced="true",
        org_role=getattr(resolved, "org_role", "unknown"),
        teams=",".join(getattr(resolved, "teams_matched", ()) or ()),
        repo_permission=getattr(resolved, "repo_permission", "unknown"),
        enterprise_owner=getattr(resolved, "enterprise_owner", "unknown"),
    )

    if os.environ.get("SUMMARY", "true").lower() != "false":
        rows = [
            "### Workflow Gatekeeper",
            "",
            f"Actor: `@{actor or 'unknown'}` &nbsp;&nbsp; Mode: "
            f"`{'require_all' if policy.require_all else 'any'}`",
            "",
            "| Check | Result |",
            "| --- | --- |",
        ]
        for name, value in sorted(checks.items()):
            state = "pass" if value is True else ("fail" if value is False else "inconclusive")
            rows.append(f"| `{name}` | {state} |")
        if not checks:
            rows.append("| _none enabled_ | — |")
        rows += ["", f"**Decision:** {'authorized' if authorized else 'denied'}", "", reason]
        write_summary(rows)

    if authorized:
        print(f"::notice title=Access Granted::@{actor} authorized. {reason}")
        return 0
    if fail_closed:
        print(f"::error title=Access Denied::@{actor} is not authorized. {reason}")
        return 1
    print(f"::warning title=Access Denied (not enforced)::@{actor} is not authorized. {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
