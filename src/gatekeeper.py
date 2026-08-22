"""Action entrypoint: read inputs, gather signals, enforce the decision."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from policy import Policy, evaluate
from runtime import append_github_output, append_step_summary, env_bool, env_csv
from signals import Client, gather


@dataclass(frozen=True)
class Handoff:
    workflow: str = ""
    repository: str = ""
    ref: str = ""
    dispatch: bool = False


def _bool(name: str, default: bool) -> bool:
    return env_bool(os.environ, name, default)


def _csv(name: str) -> tuple[str, ...]:
    return env_csv(os.environ, name)


def _caller_valid() -> tuple[str, str]:
    expected_workflow = os.environ.get("CALLER_WORKFLOW", "").strip()
    expected_repository = os.environ.get("CALLER_REPOSITORY", "").strip()
    if not expected_workflow and not expected_repository:
        return "unknown", ""

    actual_workflow = os.environ.get("GITHUB_WORKFLOW", "").strip()
    actual_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "").strip()
    actual_repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    matches = True
    if expected_repository:
        matches = matches and expected_repository == actual_repository
    if expected_workflow:
        workflow_match = expected_workflow == actual_workflow
        workflow_match = workflow_match or f"/.github/workflows/{expected_workflow}@" in actual_workflow_ref
        matches = matches and workflow_match
    return ("true" if matches else "false"), (
        "Configured caller matches the running workflow."
        if matches
        else "Configured caller does not match the running workflow."
    )


def _handoff() -> tuple[Handoff, str | None]:
    workflow = os.environ.get("HANDOFF_WORKFLOW", "").strip()
    repository = os.environ.get("HANDOFF_REPOSITORY", "").strip()
    ref = os.environ.get("HANDOFF_REF", "").strip()
    dispatch = _bool("DISPATCH_HANDOFF", False)
    if not dispatch:
        return Handoff(workflow, repository, ref, False), None
    if not workflow:
        return Handoff(workflow, repository, ref, True), (
            "dispatch_handoff is enabled but handoff_workflow is empty."
        )
    if not repository or not ref:
        return Handoff(workflow, repository, ref, True), (
            "A handoff requires handoff_repository and handoff_ref."
        )
    if any(char in workflow for char in "\r\n?") or any(char in repository for char in "\r\n?"):
        return Handoff(workflow, repository, ref, True), "Handoff identifiers contain invalid characters."
    current_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    current_workflow = os.environ.get("GITHUB_WORKFLOW", "")
    if repository == os.environ.get("GITHUB_REPOSITORY", "") and (
        workflow == current_workflow
        or f"/.github/workflows/{workflow}@" in current_workflow_ref
    ):
        return Handoff(workflow, repository, ref, True), (
            "The handoff workflow resolves to the current workflow; refusing a loop."
        )
    return Handoff(workflow, repository, ref, True), None


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
    caller_state, caller_reason = _caller_valid()
    handoff, handoff_error = _handoff()

    if caller_state == "false" and not _bool("SUPPRESS_CALLER_WARNING", False):
        print(f"::warning title=Gatekeeper caller::{caller_reason}")
    if caller_state == "false" and _bool("CALLER_CHECK_FAIL", False):
        return _finish(False, caller_reason, {}, None, Policy(), fail_closed, actor, handoff, caller_state)
    if handoff_error:
        return _finish(False, handoff_error, {}, None, Policy(), fail_closed, actor, handoff, caller_state)

    if restrict and "*" not in restrict and event_name not in restrict:
        emit(authorized="true", reason=f"Event '{event_name}' is not gated.", enforced="false", caller_valid=caller_state, handoff_requested="true" if handoff.workflow else "false", handoff_dispatched="false", handoff_workflow=handoff.workflow, handoff_repository=handoff.repository, handoff_ref=handoff.ref)
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

    if not actor or not organization or (not token and (policy.allow_org_admin or policy.required_teams or policy.required_repo_permission or policy.enterprise_enabled or handoff.dispatch)):
        missing = "actor" if not actor else ("organization" if not organization else "token")
        reason = (
            f"Missing required input: {missing}. The default GITHUB_TOKEN cannot resolve "
            "organization role, team membership, or enterprise ownership."
        )
        return _finish(False, reason, {}, None, policy, fail_closed, actor, handoff, caller_state)

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
    if decision.authorized and handoff.dispatch:
        if client.dispatch_workflow(handoff.repository, handoff.workflow, handoff.ref):
            handoff_dispatched = True
        else:
            return _finish(False, "Authorization passed, but the handoff workflow could not be dispatched.", decision.checks, resolved, policy, fail_closed, actor, handoff, caller_state)
    else:
        handoff_dispatched = False
    return _finish(
        decision.authorized,
        decision.reason,
        decision.checks,
        resolved,
        policy,
        fail_closed,
        actor,
        handoff,
        caller_state,
        handoff_dispatched,
    )


def _finish(authorized, reason, checks, resolved, policy, fail_closed, actor, handoff, caller_state, handoff_dispatched=False) -> int:
    emit(
        authorized="true" if authorized else "false",
        reason=reason,
        enforced="true",
        org_role=getattr(resolved, "org_role", "unknown"),
        teams=",".join(getattr(resolved, "teams_matched", ()) or ()),
        repo_permission=getattr(resolved, "repo_permission", "unknown"),
        enterprise_owner=getattr(resolved, "enterprise_owner", "unknown"),
        caller_valid=caller_state,
        handoff_requested="true" if handoff.workflow else "false",
        handoff_dispatched="true" if handoff_dispatched else "false",
        handoff_workflow=handoff.workflow,
        handoff_repository=handoff.repository,
        handoff_ref=handoff.ref,
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
