"""Action entrypoint: read inputs, gather signals, enforce the decision."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

from policy import Policy, Signals, evaluate, is_trusted_app_actor
from runtime import append_github_output, append_step_summary, env_bool, env_csv
from signals import Client, gather


@dataclass(frozen=True)
class Handoff:
    workflow: str = ""
    repository: str = ""
    ref: str = ""
    dispatch: bool = False
    inputs: dict[str, str] = field(default_factory=dict)


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


def _handoff_audit_mode() -> str:
    mode = os.environ.get("HANDOFF_AUDIT", "warn").strip().lower()
    if mode not in {"off", "warn", "block"}:
        print(f"::warning title=Gatekeeper handoff audit::Unknown handoff_audit '{mode}'; defaulting to 'warn'.")
        return "warn"
    return mode


def _handoff() -> tuple[Handoff, str | None]:
    workflow = os.environ.get("HANDOFF_WORKFLOW", "").strip()
    repository = os.environ.get("HANDOFF_REPOSITORY", "").strip()
    ref = os.environ.get("HANDOFF_REF", "").strip()
    dispatch = _bool("DISPATCH_HANDOFF", False)
    raw_inputs = os.environ.get("HANDOFF_INPUTS", "").strip()
    inputs: dict[str, str] = {}
    if raw_inputs:
        try:
            parsed = json.loads(raw_inputs)
        except json.JSONDecodeError:
            return Handoff(workflow, repository, ref, dispatch), "handoff_inputs is not valid JSON."
        if not isinstance(parsed, dict):
            return Handoff(workflow, repository, ref, dispatch), "handoff_inputs must be a JSON object."
        # GitHub's own `-f`/API inputs are strings; coerce JSON booleans to
        # lowercase so a forwarded `true`/`false` matches a workflow_dispatch
        # boolean input's expected literal instead of Python's "True"/"False".
        inputs = {
            str(k): ("true" if v is True else "false" if v is False else str(v))
            for k, v in parsed.items()
        }
    if not dispatch:
        return Handoff(workflow, repository, ref, False, inputs), None
    if not workflow:
        return Handoff(workflow, repository, ref, True, inputs), (
            "dispatch_handoff is enabled but handoff_workflow is empty."
        )
    if not repository or not ref:
        return Handoff(workflow, repository, ref, True, inputs), (
            "A handoff requires handoff_repository and handoff_ref."
        )
    if any(char in workflow for char in "\r\n?") or any(char in repository for char in "\r\n?"):
        return Handoff(workflow, repository, ref, True, inputs), "Handoff identifiers contain invalid characters."
    current_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    current_workflow = os.environ.get("GITHUB_WORKFLOW", "")
    if repository == os.environ.get("GITHUB_REPOSITORY", "") and (
        workflow == current_workflow
        or f"/.github/workflows/{workflow}@" in current_workflow_ref
    ):
        return Handoff(workflow, repository, ref, True, inputs), (
            "The handoff workflow resolves to the current workflow; refusing a loop."
        )
    return Handoff(workflow, repository, ref, True, inputs), None


def emit(**pairs: str) -> None:
    append_github_output(os.environ, **pairs)


def write_summary(lines: list[str]) -> None:
    append_step_summary(os.environ, lines)


def _allowlist_check() -> tuple[str, str]:
    """Optional, domain-agnostic policy check: is `allowlist_value` present in
    a JSON array read from `allowlist_config_path`/`allowlist_config_key`?

    This deliberately knows nothing about any particular org's config schema
    — `allowlist_config_key` is a plain dot-path (e.g.
    `organization.kicker_fanout.enabled_kickers`) into whatever JSON file is
    at `allowlist_config_path`, so it's reusable for any "is this requested
    value in the configured allowlist" policy, not just this repo's.

    Returns `(status, reason)`:
      * `skipped`      — `allowlist_config_path` is empty; not configured.
      * `unknown`      — configured but `allowlist_value` is empty. Denied
                          when `allowlist_fail_open` is `false`.
      * `unrestricted` — file missing, invalid JSON, or the key resolves to
                          an empty/non-list value. Fails OPEN by default:
                          this is an additive narrowing control layered on
                          top of actor authorization, not a standalone
                          boundary, so a missing or malformed config must
                          not lock everyone out. Set `allowlist_fail_open:
                          false` to treat an inconclusive config the same as
                          a hard `denied` instead — appropriate when the
                          config file itself is access-controlled (branch
                          protection / CODEOWNERS) and a missing/corrupted
                          file is more likely tampering than a rollout gap.
      * `allowed` / `denied` — the key resolved to a non-empty list and
                          `allowlist_value` was, or was not, found in it.
    """
    path = os.environ.get("ALLOWLIST_CONFIG_PATH", "").strip()
    if not path:
        return "skipped", ""
    status, reason = _allowlist_lookup(path)
    if status in {"unrestricted", "unknown"} and not _bool("ALLOWLIST_FAIL_OPEN", True):
        return "denied", f"{reason} (allowlist_fail_open is false: an inconclusive result denies.)"
    return status, reason


def _allowlist_lookup(path: str) -> tuple[str, str]:
    key_path = os.environ.get("ALLOWLIST_CONFIG_KEY", "").strip()
    value = os.environ.get("ALLOWLIST_VALUE", "").strip()
    if not value:
        return "unknown", "allowlist_value is empty; nothing to check."

    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return "unrestricted", f"'{path}' is missing or not valid JSON; no additional restriction."

    node = data
    for segment in (s for s in key_path.split(".") if s):
        if not isinstance(node, dict) or segment not in node:
            return "unrestricted", f"'{key_path}' not found in '{path}'; no additional restriction."
        node = node[segment]

    if not isinstance(node, list) or not node:
        return "unrestricted", f"'{key_path}' in '{path}' is empty or not a list; no additional restriction."

    allowed_values = {str(item) for item in node}
    if value in allowed_values:
        return "allowed", f"'{value}' is in '{key_path}'."
    return "denied", (
        f"'{value}' is not in '{key_path}' ({', '.join(sorted(allowed_values))}) read from '{path}'."
    )


def _run_allowlist_only() -> int:
    """Check `allowlist_value` against the config allowlist with no actor,
    organization, or handoff involved. For callers that only want this one
    policy primitive (e.g. "is the requested operation still enabled?").
    """
    fail_closed = _bool("FAIL_CLOSED", True)
    status, reason = _allowlist_check()
    authorized = status != "denied"
    return _finish(
        authorized, reason or "allowlist_only is set but allowlist_config_path is empty; nothing to check.",
        {}, None, Policy(), fail_closed, "", Handoff(), "unknown",
        allowlist_status=status, allowlist_reason=reason,
    )


def _run_handoff_only() -> int:
    """Dispatch (and audit) the handoff workflow with no actor/org authorization.

    For system-triggered dynamic chaining (schedule/push callers with no
    human actor to authorize) that still wants the handoff-target audit.
    """
    fail_closed = _bool("FAIL_CLOSED", True)
    allowlist_status, allowlist_reason = _allowlist_check()
    if allowlist_status == "denied":
        return _finish(
            False, allowlist_reason, {}, None, Policy(), fail_closed, "", Handoff(), "unknown",
            allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
        )
    handoff, handoff_error = _handoff()
    if handoff_error:
        return _finish(
            False, handoff_error, {}, None, Policy(), fail_closed, "", handoff, "unknown",
            allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
        )
    if not handoff.dispatch:
        return _finish(
            True, "handoff_only is set but dispatch_handoff is not enabled; nothing to do.",
            {}, None, Policy(), fail_closed, "", handoff, "unknown",
            allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
        )

    client = Client(
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        graphql_url=os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
        token=os.environ.get("TOKEN", ""),
    )
    audit_mode = _handoff_audit_mode()
    audit_status, audit_reason = (
        ("skipped", "handoff_audit is off.")
        if audit_mode == "off"
        else client.audit_workflow_dispatch_target(handoff.repository, handoff.ref, handoff.workflow)
    )
    if audit_status == "insecure":
        if audit_mode == "block":
            return _finish(
                False, f"Handoff blocked by audit: {audit_reason}", {}, None, Policy(), fail_closed, "", handoff, "unknown",
                handoff_audit_status=audit_status, handoff_audit_reason=audit_reason,
                allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
            )
        print(f"::warning title=Gatekeeper handoff audit::{audit_reason}")

    if client.dispatch_workflow(handoff.repository, handoff.workflow, handoff.ref, handoff.inputs):
        return _finish(
            True, "Handoff workflow dispatched.", {}, None, Policy(), fail_closed, "", handoff, "unknown",
            handoff_dispatched=True, handoff_audit_status=audit_status, handoff_audit_reason=audit_reason,
            allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
        )
    return _finish(
        False, "handoff_only dispatch failed: the handoff workflow could not be dispatched.",
        {}, None, Policy(), fail_closed, "", handoff, "unknown",
        handoff_audit_status=audit_status, handoff_audit_reason=audit_reason,
        allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
    )


def main() -> int:
    if _bool("PREFLIGHT_ONLY", False):
        return 0
    if _bool("ALLOWLIST_ONLY", False):
        return _run_allowlist_only()
    if _bool("HANDOFF_ONLY", False):
        return _run_handoff_only()
    event_name = os.environ.get("EVENT_NAME", "")
    restrict = _csv("RESTRICT_TO_EVENTS")
    fail_closed = _bool("FAIL_CLOSED", True)
    actor = os.environ.get("ACTOR", "").strip()
    trusted_app_slugs = _csv("TRUSTED_APP_SLUGS")
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
        emit(authorized="true", reason=f"Event '{event_name}' is not gated.", enforced="false", caller_valid=caller_state, handoff_requested="true" if handoff.workflow else "false", handoff_dispatched="false", handoff_workflow=handoff.workflow, handoff_repository=handoff.repository, handoff_ref=handoff.ref, handoff_audit_status="skipped", handoff_audit_reason="", allowlist_status="skipped", allowlist_reason="")
        print(f"::notice title=Gatekeeper::Event '{event_name}' is not gated; passing through.")
        return 0

    policy = Policy(
        allow_org_admin=_bool("ALLOW_ORG_ADMIN", True),
        required_teams=_csv("REQUIRED_TEAMS"),
        required_repo_permission=os.environ.get("REQUIRED_REPO_PERMISSION", "").strip(),
        enterprise_enabled=bool(os.environ.get("ENTERPRISE_SLUG", "").strip()),
        require_enterprise_owner=_bool("REQUIRE_ENTERPRISE_OWNER", False),
        require_all=_bool("REQUIRE_ALL", False),
        trusted_app_slugs=trusted_app_slugs,
    )

    trusted_app = is_trusted_app_actor(actor, trusted_app_slugs)
    if not actor or not organization or (not token and ((not trusted_app) or handoff.dispatch) and (policy.allow_org_admin or policy.required_teams or policy.required_repo_permission or policy.enterprise_enabled or handoff.dispatch)):
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
    resolved = Signals() if trusted_app else gather(
        client,
        actor=actor,
        organization=organization,
        repository=os.environ.get("REPOSITORY", "").strip(),
        wanted_teams=policy.required_teams,
        enterprise_slug=os.environ.get("ENTERPRISE_SLUG", "").strip(),
        need_org_role=policy.allow_org_admin,
        need_repo_permission=bool(policy.required_repo_permission),
    )
    decision = evaluate(resolved, policy, actor)
    allowlist_status, allowlist_reason = _allowlist_check()
    if allowlist_status == "denied":
        return _finish(
            False, allowlist_reason, decision.checks, resolved, policy, fail_closed, actor, handoff, caller_state,
            allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
        )
    audit_status, audit_reason = "skipped", ""
    if decision.authorized and handoff.dispatch:
        audit_mode = _handoff_audit_mode()
        if audit_mode != "off":
            audit_status, audit_reason = client.audit_workflow_dispatch_target(
                handoff.repository, handoff.ref, handoff.workflow
            )
            if audit_status == "insecure":
                title = "Gatekeeper handoff audit"
                if audit_mode == "block":
                    return _finish(
                        False,
                        f"Handoff blocked by audit: {audit_reason}",
                        decision.checks, resolved, policy, fail_closed, actor, handoff, caller_state,
                        handoff_audit_status=audit_status, handoff_audit_reason=audit_reason,
                        allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
                    )
                print(f"::warning title={title}::{audit_reason}")
        if client.dispatch_workflow(handoff.repository, handoff.workflow, handoff.ref, handoff.inputs):
            handoff_dispatched = True
        else:
            return _finish(
                False,
                "Authorization passed, but the handoff workflow could not be dispatched.",
                decision.checks, resolved, policy, fail_closed, actor, handoff, caller_state,
                handoff_audit_status=audit_status, handoff_audit_reason=audit_reason,
                allowlist_status=allowlist_status, allowlist_reason=allowlist_reason,
            )
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
        handoff_audit_status=audit_status,
        handoff_audit_reason=audit_reason,
        allowlist_status=allowlist_status,
        allowlist_reason=allowlist_reason,
    )


def _finish(
    authorized, reason, checks, resolved, policy, fail_closed, actor, handoff, caller_state,
    handoff_dispatched=False, handoff_audit_status="skipped", handoff_audit_reason="",
    allowlist_status="skipped", allowlist_reason="",
) -> int:
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
        handoff_audit_status=handoff_audit_status,
        handoff_audit_reason=handoff_audit_reason,
        allowlist_status=allowlist_status,
        allowlist_reason=allowlist_reason,
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
