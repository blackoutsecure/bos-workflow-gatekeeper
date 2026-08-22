"""GitHub API lookups that resolve an actor's standing.

Every function returns `unknown` rather than raising when the API cannot give
a definitive answer, so `policy.evaluate` can distinguish "denied" from
"could not tell" and fail closed on the latter.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from policy import UNKNOWN, Signals

USER_AGENT = "bos-workflow-gatekeeper"
_WORKFLOW_DISPATCH_RE = re.compile(r"(?m)^\s*workflow_dispatch\s*:")
# A real step, not a comment or a prose mention: this repo's source is public,
# so "does the string 'bos-workflow-gatekeeper' appear anywhere" is trivially
# spoofed by anyone who can read this file — a `# uses: .../bos-workflow-
# gatekeeper@x` comment, or a docs link, would satisfy that check without any
# authorization actually running. Requiring an actual `uses:` line pinned to
# a ref raises the bar to "an authorization step really executes," which is
# what the audit is meant to attest to.
_GUARD_STEP_RE = re.compile(r"(?im)^[ \t]*(?:-[ \t]*)?uses:[ \t]*\S*bos-workflow-gatekeeper@\S+")


class Client:
    def __init__(self, api_url: str, graphql_url: str, token: str, enterprise_token: str = ""):
        self.api_url = api_url.rstrip("/")
        self.graphql_url = graphql_url
        self.token = token
        self.enterprise_token = enterprise_token or token

    def request(
        self, url: str, *, data: bytes | None = None, token: str | None = None
    ) -> tuple[int, dict | list | None]:
        # Reject anything that is not HTTPS before it reaches urllib: a
        # poisoned GITHUB_API_URL must not be able to smuggle in file: or a
        # custom scheme and have the result read as an authorization answer.
        if not url.startswith("https://"):
            return 0, None
        req = urllib.request.Request(url, data=data)  # noqa: S310
        req.add_header("Authorization", f"Bearer {token or self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", USER_AGENT)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            # Host comes from GITHUB_API_URL/GITHUB_GRAPHQL_URL, not user input.
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                body = resp.read().decode("utf-8")
                return resp.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                return exc.code, (json.loads(raw) if raw else None)
            except json.JSONDecodeError:
                return exc.code, None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return 0, None

    def org_role(self, org: str, actor: str) -> str:
        status, payload = self.request(f"{self.api_url}/orgs/{org}/memberships/{actor}")
        if status == 200 and isinstance(payload, dict):
            if payload.get("state") != "active":
                return "outside"
            role = str(payload.get("role", "member"))
            return role if role in {"admin", "member"} else "member"
        if status == 404:
            return "outside"
        return UNKNOWN

    def teams(self, org: str, actor: str, wanted: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
        """Return (matched teams, resolved). `resolved` is False on API trouble."""
        matched: list[str] = []
        resolved = True
        for team in wanted:
            status, payload = self.request(
                f"{self.api_url}/orgs/{org}/teams/{team}/memberships/{actor}"
            )
            if status == 200 and isinstance(payload, dict):
                if payload.get("state") == "active":
                    matched.append(team)
            elif status != 404:
                resolved = False
        return tuple(matched), resolved

    def repo_permission(self, repository: str, actor: str) -> str:
        status, payload = self.request(
            f"{self.api_url}/repos/{repository}/collaborators/{actor}/permission"
        )
        if status == 200 and isinstance(payload, dict):
            # `role_name` is the precise role; `permission` is the coarse legacy field.
            role = str(payload.get("role_name") or payload.get("permission") or "").lower()
            return role or UNKNOWN
        if status in (403, 404):
            return "none"
        return UNKNOWN

    def enterprise_owner(self, slug: str, actor: str) -> str:
        query = {
            "query": (
                "query($slug:String!){enterprise(slug:$slug)"
                "{ownerInfo{admins(first:100,role:OWNER){nodes{login}}}}}"
            ),
            "variables": {"slug": slug},
        }
        status, payload = self.request(
            self.graphql_url,
            data=json.dumps(query).encode("utf-8"),
            token=self.enterprise_token,
        )
        if status != 200 or not isinstance(payload, dict) or payload.get("errors"):
            return UNKNOWN
        try:
            nodes = payload["data"]["enterprise"]["ownerInfo"]["admins"]["nodes"]
        except (KeyError, TypeError):
            return UNKNOWN
        logins = {str(n.get("login", "")).lower() for n in nodes if isinstance(n, dict)}
        return "true" if actor.lower() in logins else "false"

    def dispatch_workflow(self, repository: str, workflow: str, ref: str, inputs: dict[str, str] | None = None) -> bool:
        """Dispatch a workflow and return whether GitHub accepted the request."""
        endpoint = (
            f"{self.api_url}/repos/{urllib.parse.quote(repository, safe='/')}/actions/"
            f"workflows/{urllib.parse.quote(workflow, safe='')}/dispatches"
        )
        body: dict[str, object] = {"ref": ref}
        if inputs:
            body["inputs"] = inputs
        status, _ = self.request(endpoint, data=json.dumps(body).encode("utf-8"))
        return status == 204

    def audit_workflow_dispatch_target(self, repository: str, ref: str, workflow: str) -> tuple[str, str]:
        """Best-effort check: can the handoff target be triggered directly, unguarded?

        Returns `(status, reason)` where `status` is one of `secure`,
        `insecure`, or `unknown`. `insecure` means the target file declares its
        own `workflow_dispatch:` trigger with no detected `uses:` step pinned
        to `bos-workflow-gatekeeper@<ref>` of its own, so anyone with dispatch
        access to that repository could trigger it directly, bypassing the
        gate that led to this handoff. This is a static text scan of the
        target's YAML, not a full parse or a proof the step actually runs
        unconditionally — it favors cheap and conservative over exhaustive.
        """
        path = workflow if "/" in workflow else f".github/workflows/{workflow}"
        if workflow.isdigit():
            status, payload = self.request(f"{self.api_url}/repos/{repository}/actions/workflows/{workflow}")
            if status != 200 or not isinstance(payload, dict) or not payload.get("path"):
                return "unknown", f"Could not resolve numeric workflow ID '{workflow}' to a file path."
            path = str(payload["path"])

        status, payload = self.request(
            f"{self.api_url}/repos/{urllib.parse.quote(repository, safe='/')}/contents/"
            f"{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}"
        )
        if status != 200 or not isinstance(payload, dict) or not payload.get("content"):
            return "unknown", f"Could not fetch `{path}` from `{repository}@{ref}` to audit."

        try:
            content = base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return "unknown", f"Could not decode `{path}` contents for audit."

        has_dispatch = bool(_WORKFLOW_DISPATCH_RE.search(content))
        guarded = bool(_GUARD_STEP_RE.search(content))
        if has_dispatch and not guarded:
            return "insecure", (
                f"`{path}` declares its own `workflow_dispatch:` trigger with no `uses:` step "
                "pinned to bos-workflow-gatekeeper, so it can be triggered directly, bypassing "
                "this gate."
            )
        return "secure", f"`{path}` has no unguarded `workflow_dispatch:` exposure."


def gather(
    client: Client,
    *,
    actor: str,
    organization: str,
    repository: str = "",
    wanted_teams: tuple[str, ...] = (),
    enterprise_slug: str = "",
    need_org_role: bool = True,
    need_repo_permission: bool = False,
) -> Signals:
    """Resolve only the signals the policy actually needs."""
    role = client.org_role(organization, actor) if need_org_role else UNKNOWN
    matched, resolved = client.teams(organization, actor, wanted_teams) if wanted_teams else ((), False)
    permission = (
        client.repo_permission(repository, actor)
        if need_repo_permission and repository
        else UNKNOWN
    )
    owner = client.enterprise_owner(enterprise_slug, actor) if enterprise_slug else UNKNOWN
    return Signals(
        org_role=role,
        teams_matched=matched,
        teams_resolved=resolved,
        repo_permission=permission,
        enterprise_owner=owner,
    )
