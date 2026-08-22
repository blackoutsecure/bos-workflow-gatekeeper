# Blackout Secure Workflow Gatekeeper

Copyright © 2025-2026 Blackout Secure | Apache License 2.0

[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-blue?logo=github)](https://github.com/marketplace/actions/blackout-secure-workflow-gatekeeper)
[![GitHub release](https://img.shields.io/github/v/release/blackoutsecure/bos-workflow-gatekeeper)](https://github.com/blackoutsecure/bos-workflow-gatekeeper/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Made by BlackoutSecure](https://img.shields.io/badge/made%20by-BlackoutSecure-1f1f1f)](https://github.com/blackoutsecure)

A composite GitHub Action that resolves the triggering actor against an
explicit authorization policy and denies the job when the actor is not
authorized.

## ✨ Features

- **Four composable checks** — organization role, team membership, repository
  permission, and enterprise ownership. Each is disabled until configured.
- **AND / OR composition** — by default any enabled check authorizes the
  run. `require_all: true` demands every enabled check, expressing policies
  such as *"a repository admin **and** on the release-managers team"* that
  no single-signal action can state.
- **Fail-closed by design** — every signal resolves to a definitive answer
  or `unknown`, and `unknown` is never treated as a pass. A missing token,
  a 5xx, a timeout, or an unreadable enterprise response denies rather than
  silently permitting.
- **Direct enforcement** — emits a GitHub Actions error annotation and exits
  non-zero on denial. Downstream jobs can depend on the authorization job.
- **Re-run safe** — uses `github.triggering_actor`, which identifies the user
  who initiated the current run or re-run.
- **Event scoping** — `restrict_to_events` enforces only on the triggers you
  choose and passes everything else through with zero API calls.
- **Audit trail** — a decision table lands in the job summary showing the
  actor, every resolved signal, the mode, and the reason.
- **Pure-stdlib Python core** — no third-party runtime dependencies. Nothing
  else belongs in an authorization path.

## 📖 Table of Contents

- [Blackout Secure Workflow Gatekeeper](#blackout-secure-workflow-gatekeeper)
  - [✨ Features](#-features)
  - [📖 Table of Contents](#-table-of-contents)
  - [📋 Prerequisites](#-prerequisites)
  - [🚀 Quick start](#-quick-start)
    - [Composing checks](#composing-checks)
    - [Version pinning](#version-pinning)
  - [⚙️ Action inputs](#️-action-inputs)
  - [📤 Action outputs](#-action-outputs)
  - [🧰 Runner preflight](#-runner-preflight)
  - [🔗 Workflow handoff](#-workflow-handoff)
  - [🔒 Tokens and credentials](#-tokens-and-credentials)
  - [🧮 Decision semantics](#-decision-semantics)
  - [⚠️ Runtime and repository notes](#️-runtime-and-repository-notes)
  - [🧪 Hub development validation](#-hub-development-validation)
  - [💻 Local usage (tests)](#-local-usage-tests)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)

## 📋 Prerequisites

- A credential that can read organization membership when an authorization
  check is enabled. The token input is optional for pass-through events and
  caller-only validation, but a gated policy that needs API evidence fails
  closed without one.
- A GitHub App with `Organization permissions → Members: Read-only`
  (recommended), or a PAT with `read:org`.
- For the optional enterprise check only: a PAT with `admin:enterprise`
  belonging to an enterprise owner. See
  [Tokens and credentials](#-tokens-and-credentials) before enabling it.

## 🚀 Quick start

```yaml
jobs:
  authorize:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v3
        id: token
        with:
          app-id: ${{ vars.GITHUB_APP_ID }}
          private-key: ${{ secrets.GITHUB_APP_PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}

      - uses: blackoutsecure/bos-workflow-gatekeeper@v1
        with:
          actor: ${{ github.triggering_actor }}
          organization: ${{ github.repository_owner }}
          required_teams: release-managers
          token: ${{ steps.token.outputs.token }}

  deploy:
    needs: authorize          # an unauthorized dispatch never reaches this
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

### Composing checks

Any enabled check passing authorizes the run. Switch to AND with
`require_all`:

```yaml
- uses: blackoutsecure/bos-workflow-gatekeeper@v1
  with:
    actor: ${{ github.triggering_actor }}
    organization: ${{ github.repository_owner }}
    required_teams: release-managers
    required_repo_permission: admin
    require_all: true         # on the team AND a repository admin
    token: ${{ steps.token.outputs.token }}
```

### Version pinning

Pin to a major tag for automatic patches, or to a commit SHA for a fully
reproducible supply chain:

```yaml
# Floating major — receives fixes automatically.
- uses: blackoutsecure/bos-workflow-gatekeeper@v1

# Immutable — recommended for security-critical pipelines.
- uses: blackoutsecure/bos-workflow-gatekeeper@<commit-sha> # v1.0.0
```

## ⚙️ Action inputs

<!-- BEGIN action-inputs -->
| Input | Default | Description |
| --- | --- | --- |
| `actor` | *(none)* | Login to authorize. Use `github.triggering_actor`, not `github.actor` — on a re-run `actor` stays the original dispatcher while `triggering_actor` is whoever pressed re-run. |
| `organization` | *(none)* | Organization login that owns the repository. |
| `token` | *(none)* | Credential for organization, team, and repository lookups. Prefer a GitHub App installation token with `members: read` (short-lived). A PAT with `read:org` also works. The default GITHUB_TOKEN cannot resolve organization role, team membership, or enterprise ownership. |
| `repository` | *(none)* | `owner/repo` for the repository-permission check. Required only when `required_repo_permission` is set. |
| `event_name` | *(none)* | Event that triggered the run. Compared against `restrict_to_events`. |
| `restrict_to_events` | `workflow_dispatch` | Comma-separated events to enforce on. Other events pass through without any API call. Use `*` to gate every event. |
| `required_teams` | *(none)* | Comma-separated team slugs whose active members are authorized. Empty disables the check. |
| `required_repo_permission` | *(none)* | Minimum repository permission: `read`, `triage`, `write`, `maintain`, or `admin`. Empty disables the check. |
| `allow_org_admin` | `true` | Treat organization owners as authorized. |
| `enterprise_slug` | *(none)* | Enterprise slug for the owner lookup. Empty disables the check. Requires `enterprise_token`; see the README security note before enabling. |
| `enterprise_token` | *(none)* | PAT with `admin:enterprise` belonging to an enterprise owner. No GitHub App installation token can read `enterprise.ownerInfo`. Falls back to `token`. |
| `require_enterprise_owner` | `false` | Only enterprise owners are authorized; every other check is ignored as a grant path. |
| `require_all` | `false` | Require every enabled check to pass (AND). Default is any (OR). |
| `fail_closed` | `true` | Fail the job when the actor is unauthorized or a signal is inconclusive. Set `false` to annotate without enforcing during rollout. |
| `summary` | `true` | Write the decision table to the job summary. |
| `caller_workflow` | *(none)* | Expected caller workflow file or workflow name. A mismatch emits a warning but does not fail unless caller_check_fail is true. |
| `caller_repository` | *(none)* | Expected caller repository as `owner/repo`; empty skips the repository check. |
| `caller_check_fail` | `false` | Fail when the configured caller identity does not match the running workflow. |
| `suppress_caller_warning` | `false` | Suppress the notification emitted when the configured caller identity does not match. |
| `handoff_workflow` | *(none)* | Workflow file or workflow ID to dispatch after authorization. Empty disables handoff. A workflow is required when dispatch_handoff is true. |
| `handoff_repository` | *(none)* | Repository receiving the workflow dispatch; defaults to the current repository. |
| `handoff_ref` | *(none)* | Git ref for the handoff workflow; defaults to the current ref. |
| `dispatch_handoff` | `false` | Dispatch the configured handoff workflow after authorization succeeds. |
| `preflight_spec` | *(none)* | JSON dependency specification for runner preflight. Supports required_commands, min_versions, version_args, required_python_packages, and fail_on_missing. Empty skips capability checks. |
| `preflight_gate_level` | `standard` | Label shown in the preflight summary, such as low, standard, or high. |
| `preflight_only` | `false` | Run only runner preflight and skip actor authorization. Intended for workflow orchestration. |
<!-- END action-inputs -->

> The table above is auto-generated from `action.yml` by
> [`scripts/render_readme_inputs.py`](scripts/render_readme_inputs.py).
> Edit `action.yml` and run `python3 scripts/render_readme_inputs.py --write`.

## 📤 Action outputs

<!-- BEGIN action-outputs -->
| Output | Description |
| --- | --- |
| `authorized` | `true` when the actor satisfied the policy. |
| `reason` | Human-readable explanation of the decision. |
| `enforced` | `false` when the event was outside `restrict_to_events` and no check ran. |
| `org_role` | admin, member, outside, or unknown. |
| `teams` | Comma-separated matched team slugs. |
| `repo_permission` | Resolved repository permission, or unknown. |
| `enterprise_owner` | true, false, or unknown. |
| `caller_valid` | `true` when the configured caller identity matches; `unknown` when no caller check is configured. |
| `handoff_requested` | `true` when a handoff workflow was configured. |
| `handoff_dispatched` | `true` when the handoff workflow was dispatched successfully. |
| `handoff_workflow` | Workflow file or ID selected for the handoff. |
| `handoff_repository` | Repository selected for the handoff. |
| `handoff_ref` | Git ref selected for the handoff. |
| `preflight_satisfied` | `true` when every declared runner requirement was met. |
| `preflight_missing` | Comma-separated list of unmet runner requirements. |
<!-- END action-outputs -->

## 🧰 Runner preflight

Set `preflight_spec` when the gated operation depends on tools or Python
distributions being available. Preflight runs before authorization and does
not receive the authorization token. A missing requirement fails before the
workflow can continue; set `fail_on_missing` to `false` in the spec for a
warning-only rollout.

```yaml
- uses: blackoutsecure/bos-workflow-gatekeeper@v1
  with:
    actor: ${{ github.triggering_actor }}
    organization: ${{ github.repository_owner }}
    token: ${{ secrets.GATEKEEPER_AUTHZ_PAT }}
    preflight_gate_level: high
    preflight_spec: >-
      {"required_commands":["docker","jq"],"min_versions":{"docker":"24.0"},"required_python_packages":["requests>=2.31"]}
```

The hub's standalone preflight action remains available for larger workflows
that need runner checks independent of actor authorization. The Marketplace
action includes this small capability for callers that want one portable step.

## 🔗 Workflow handoff

The recommended pattern is to keep this action in a small authorization job
and let the caller own the next workflow or action:

```yaml
jobs:
  authorize:
    runs-on: ubuntu-latest
    steps:
      - id: gate
        uses: blackoutsecure/bos-workflow-gatekeeper@v1
        with:
          actor: ${{ github.triggering_actor }}
          organization: ${{ github.repository_owner }}
          required_teams: release-managers
          token: ${{ secrets.GATEKEEPER_AUTHZ_PAT }}

  deploy:
    needs: authorize
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

For callers that need the gatekeeper to start another workflow, set
`dispatch_handoff: true`, `handoff_workflow`, `handoff_repository`, and
`handoff_ref`. The target workflow must be different from the current workflow;
same-workflow dispatch is rejected to prevent loops. The dispatch requires a
token with permission to run workflows in the target repository.

Set `caller_workflow` and optionally `caller_repository` to identify the
expected caller. A mismatch emits a warning notification by default and does
not fail the job. Set `caller_check_fail: true` for strict enforcement, or
`suppress_caller_warning: true` to silence the advisory.

An empty `handoff_workflow` with `dispatch_handoff: true` is always an error.
Authorization is evaluated first; no handoff occurs after a denial.

## 🔒 Tokens and credentials

Credentials are split so the most privileged one is used for as little as
possible.

| You need | Credential | Scope |
| --- | --- | --- |
| Organization role, teams, repository permission | GitHub App installation token | `Organization permissions → Members: Read-only` |
| The same, without an App | Classic or fine-grained PAT | `read:org` |
| Enterprise ownership | PAT owned by an enterprise owner | `admin:enterprise` |

The App path is preferred: `actions/create-github-app-token` mints a token
that expires in about an hour, rather than storing a credential that never
does.

> **Before enabling the enterprise check.** `enterprise.ownerInfo` is
> readable only by an enterprise owner, so no GitHub App installation token
> can satisfy it — the check requires storing a highly privileged PAT in
> Actions secrets. Many security teams will not accept that trade. Leave
> `enterprise_slug` empty and gate on organization role plus team membership
> unless you specifically need it.

Tokens are optional at the manifest level so non-gated events and caller-only
checks can run without credentials. They are still required at runtime when an
enabled policy needs organization, team, repository, or enterprise evidence,
and when a handoff must be dispatched. A GitHub App installation token with
organization Members read access is the preferred credential; use a PAT only
when the required API surface cannot be provided by an App.

## 🧮 Decision semantics

Every signal resolves to a definitive answer or `unknown`. **`unknown` is
never treated as a pass.**

| Situation | Result |
| --- | --- |
| Missing or empty `token` | Denied |
| API returns 5xx, times out, or is unreachable | Signal becomes `unknown` |
| `unknown` signal with `require_all: true` | Denied |
| `unknown` signal in OR mode, another check passed | Authorized — positive evidence exists |
| `unknown` signal in OR mode, nothing passed | Denied as inconclusive |
| GraphQL error or unreadable enterprise response | `unknown`, never `false` |
| No check enabled at all | Denied — nothing could satisfy the policy |
| Event outside `restrict_to_events` | Passes through, `enforced: false`, no API calls |

Set `fail_closed: false` during rollout to annotate without failing; the
denial is still reported in the outputs and the job summary.

## ⚠️ Runtime and repository notes

- **Use `github.triggering_actor`.** On a re-run, `github.actor` stays the
  original dispatcher. Authorizing it would let any user with write access
  replay a privileged dispatch under someone else's identity.
- **Only required lookups run.** Disabled checks issue no API call, so a
  team-only policy never touches the repository-permission endpoint.
- **Non-HTTPS is refused before it reaches `urllib`.** A poisoned
  `GITHUB_API_URL` cannot smuggle in a `file:` or custom scheme and have the
  result read as an authorization answer.
- **Pending invitations are not membership.** An org or team membership in
  `pending` state resolves as not-a-member.
- **This is not a policy language.** For rich rule composition use OPA or
  Cedar. For deployment approval use GitHub Environments and native
  deployment protection rules. This action authorizes an actor and stops the
  job.

## 🧪 Hub development validation

The hub owns runner and toolchain preflight because those checks describe the
workflow being run, not the actor being authorized. This action intentionally
does not execute arbitrary caller commands as part of authorization.

For manual validation of the development branch through the hub, run
[`hub-dev-validation.yml`](.github/workflows/hub-dev-validation.yml). It calls
the hub's reusable security, action-test, and Marketplace workflows directly.
It is manual-only and does not call a kicker or dispatch this repository's own
workflow, so it cannot recursively trigger itself.

Consumer repositories should use the managed kicker workflows for normal event
routing. Do not add a gatekeeper kicker to this repository: the Marketplace
action is the authorization primitive, while the hub owns the central
orchestration front door.

## 💻 Local usage (tests)

The decision logic in `src/policy.py` performs no I/O, so the full matrix is
testable without a network:

```bash
pip install -e ".[dev]"

# Full suite
pytest test/ -v

# Decision matrix only
pytest test/test_policy.py -v

# Lint
ruff check src test

# Metadata drift and README table sync
python3 scripts/check_action_sync.py
python3 scripts/render_readme_inputs.py --check
```

## 🤝 Contributing

Issues and PRs are welcome on `dev`. Run the tests with:

```bash
pip install -e ".[dev]"
pytest test/ -v
ruff check src test
python3 scripts/check_action_sync.py
python3 scripts/render_readme_inputs.py --check
```

## 📜 License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
