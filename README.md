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
    - [Auditing the handoff target](#auditing-the-handoff-target)
    - [Dynamic chaining with no human actor](#dynamic-chaining-with-no-human-actor)
  - [📋 Config-driven allowlists](#-config-driven-allowlists)
  - [🔐 Securing the files that drive this action](#-securing-the-files-that-drive-this-action)
  - [🧩 Recommended kicker workflow template](#-recommended-kicker-workflow-template)
  - [🔒 Tokens and credentials](#-tokens-and-credentials)
    - [PAT or GitHub App? Recommendation and why](#pat-or-github-app-recommendation-and-why)
    - [Creating the recommended GitHub App](#creating-the-recommended-github-app)
  - [🧮 Decision semantics](#-decision-semantics)
  - [🏢 Organization-wide hardening](#-organization-wide-hardening)
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
| `handoff_inputs` | *(none)* | JSON object of `workflow_dispatch` inputs to forward to the handoff workflow, e.g. `{"mode":"check"}`. Values are coerced to strings, same as GitHub's own dispatch inputs. Empty dispatches with no inputs. |
| `dispatch_handoff` | `false` | Dispatch the configured handoff workflow after authorization succeeds. |
| `handoff_audit` | `warn` | Before dispatching `handoff_workflow`, check whether it declares its own `workflow_dispatch:` trigger with no detectable `bos-workflow-gatekeeper` authorization step of its own — meaning anyone with dispatch access could invoke it directly, bypassing this gate. `warn` (default) logs a `::warning::` and still dispatches; `block` refuses to dispatch and fails the run when the target looks insecure; `off` skips the check (and its GitHub API call) entirely. |
| `preflight_spec` | *(none)* | JSON dependency specification for runner preflight. Supports required_commands, min_versions, version_args, required_python_packages, and fail_on_missing. Empty skips capability checks. |
| `preflight_gate_level` | `standard` | Label shown in the preflight summary, such as low, standard, or high. |
| `preflight_only` | `false` | Run only runner preflight and skip actor authorization. Intended for workflow orchestration. |
| `handoff_only` | `false` | Dispatch (and audit) `handoff_workflow` and skip actor/organization authorization entirely. For system-triggered dynamic chaining — schedule or push callers with no human actor to authorize — that still wants the `handoff_audit` security check. Requires `dispatch_handoff: true` and a `token` with permission to dispatch workflows in `handoff_repository`. |
| `allowlist_config_path` | *(none)* | Path to a local JSON file. When set, `allowlist_value` must appear in the array at `allowlist_config_key`, or the run is denied. Domain- agnostic: this repository's config schema is not baked in — point it at any JSON file. Empty (default) skips the check entirely. |
| `allowlist_config_key` | *(none)* | Dot-path to the array inside `allowlist_config_path`, e.g. `organization.kicker_fanout.enabled_kickers`. A missing path, invalid JSON, or an empty/non-array value fails OPEN (treated as "no restriction") — this is an additive narrowing control layered on top of actor authorization, not a standalone boundary. |
| `allowlist_value` | *(none)* | The value to check for membership in the configured allowlist, e.g. `${{ inputs.kicker }}`. |
| `allowlist_only` | `false` | Check `allowlist_value` against the config allowlist and skip actor, organization, and handoff entirely. For callers that only want this one policy primitive with nothing else attached. |
| `allowlist_fail_open` | `true` | When the allowlist config is missing, invalid, or resolves to an empty/non-array value, `true` (default) treats it as unrestricted and allows the run; `false` denies it instead. Set `false` when the config file itself is access-controlled (branch protection / CODEOWNERS) and a missing/corrupted file is more likely tampering than a rollout gap. |
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
| `handoff_audit_status` | `secure`, `insecure`, `unknown`, or `skipped` (handoff_audit was off, or no handoff was requested). |
| `handoff_audit_reason` | Human-readable explanation of the handoff audit result. |
| `allowlist_status` | `allowed`, `denied`, `unrestricted`, `unknown`, or `skipped` (allowlist_config_path was empty). |
| `allowlist_reason` | Human-readable explanation of the allowlist check result. |
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

### Auditing the handoff target

Dispatching a workflow via the REST API means the target must declare its own
`workflow_dispatch:` trigger — and GitHub does not let a workflow restrict who
may call that trigger. If the target has no authorization step of its own,
anyone with dispatch access to that repository can invoke it directly,
completely bypassing whatever gate led to this handoff.

`handoff_audit` (default `warn`) checks for exactly that before dispatching. It
fetches the target workflow file and flags it `insecure` when it declares
`workflow_dispatch:` with no `uses:` step pinned to `bos-workflow-gatekeeper@<ref>`
of its own (a text scan, not a full YAML parse — cheap and conservative rather
than exhaustive). It's deliberately stricter than "does the string appear
anywhere": this repo's source is public, so a check that just grepped for the
name would be trivially spoofed by a comment or a docs link mentioning it
without ever calling it. Requiring a real `uses:` step line raises the bar to
"an authorization step actually exists in the job graph," though it still
can't prove that step runs unconditionally on every trigger — treat a `secure`
result as "looks guarded," not a formal proof:

| Mode | Behavior when the target looks insecure |
| --- | --- |
| `warn` (default) | Logs `::warning::` and still dispatches. |
| `block` | Refuses to dispatch; the job fails with `handoff_dispatched: false`. |
| `off` | Skips the check (and its API call) entirely. |

Read `handoff_audit_status` (`secure`, `insecure`, `unknown`, or `skipped`) and
`handoff_audit_reason` downstream when you want to react to the result instead
of only relying on the log/warning. `unknown` (file unreadable, or a numeric
workflow ID that couldn't be resolved) never blocks a dispatch on its own —
only a confirmed `insecure` finding does, and only in `block` mode. The
straightforward way to make a target audit-`secure`: give it its own
`authorize` job that calls this action with `caller_workflow`/
`caller_repository` set to the dispatching workflow, the same pattern shown
above.

### Dynamic chaining with no human actor

`dispatch_handoff` above assumes a human dispatched the *current* run, so
there's an actor to authorize before starting the next one. Some chains have
no actor at all — a `schedule` or `push`-triggered workflow that decides,
system-to-system, which workflow runs next. Requiring `actor`/`organization`
there would mean inventing a fake identity just to satisfy the authorization
check.

`handoff_only: true` skips actor/organization authorization entirely and only
dispatches (and audits) `handoff_workflow`:

```yaml
jobs:
  chain-next:
    runs-on: ubuntu-latest
    permissions:
      actions: write
    steps:
      - uses: blackoutsecure/bos-workflow-gatekeeper@v1
        with:
          handoff_only: true
          dispatch_handoff: true
          handoff_workflow: bos-org-kicker-fanout.yml
          handoff_repository: ${{ github.repository }}
          handoff_ref: ${{ github.ref_name }}
          handoff_inputs: '{"kicker": "sync", "dry_run": "false"}'
          token: ${{ github.token }}
```

`handoff_audit` still applies in this mode with the same `warn`/`block`/`off`
semantics. `dispatch_handoff: false` with `handoff_only: true` is a no-op that
exits `0` — useful for a single step that's conditionally a chain link.
`caller_workflow`/`caller_check_fail` are ignored in this mode; there's no
actor-authorization pass to attach a caller check to. `handoff_inputs` (a JSON
object) forwards `workflow_dispatch` inputs to the target the same way
`gh workflow run -f key=value` would; values are coerced to the strings a
dispatch input expects (JSON `true`/`false` become the literals `"true"`/
`"false"`, not Python's `"True"`/`"False"`).

## 📋 Config-driven allowlists

`type: choice` `workflow_dispatch` inputs already cap what a caller can select
— GitHub renders that dropdown from the static `options:` list in the YAML, so
a config file can never widen it at dispatch time. What a config file *can*
do is narrow that ceiling further, at runtime, from a single editable place
instead of a workflow-file change:

```yaml
- uses: blackoutsecure/bos-workflow-gatekeeper@v1
  with:
    allowlist_only: true
    allowlist_config_path: .github/bos-universal-config.json
    allowlist_config_key: organization.kicker_fanout.enabled_kickers
    allowlist_value: ${{ inputs.kicker }}
```

`allowlist_config_key` is a plain dot-path into whatever JSON file
`allowlist_config_path` points at — this action has no opinion on any
particular config schema, so it works with any org's config, not just this
repo's. `allowlist_only: true` runs just this check with no actor,
organization, or handoff involved; drop it to run the allowlist check
alongside full actor authorization (or a `handoff_only` dispatch) in the same
step instead.

The check fails **open**, not closed, by default when the config can't
answer the question — missing file, invalid JSON, missing key path, or an
empty/non-array value all resolve to `allowlist_status: unrestricted` and the
run proceeds. That's deliberate: this is an additive narrowing control
layered on top of actor authorization (or nothing at all, in `allowlist_only`
mode), not a replacement for it, so a stale or malformed config file must not
accidentally lock out every caller. Read `allowlist_status`
(`allowed`/`denied`/`unrestricted`/`unknown`/`skipped`) and `allowlist_reason`
downstream to react to the result explicitly.

Set `allowlist_fail_open: false` to invert that default — an inconclusive
result (`unrestricted` or `unknown`) becomes `denied` instead of a pass. Do
this once the config file is itself access-controlled (see
[Securing the files that drive this action](#-securing-the-files-that-drive-this-action)
below): at that point a missing or corrupted config is more likely tampering
than an ordinary rollout gap, and failing closed is the safer default. A real
match in the list still allows regardless of this setting — it only changes
what happens when the check *can't* reach a definitive answer.

## 🔐 Securing the files that drive this action

This action's authorization decision is only as trustworthy as the files it
reads. Two are worth calling out specifically:

- **The workflow file itself** (wherever `bos-workflow-gatekeeper` is
  `uses:`d). Anyone who can edit it can remove the gate entirely.
- **The allowlist config** (`allowlist_config_path`), if you use it. Anyone
  who can edit *that* can widen — or, with `allowlist_fail_open: true`
  (default), silently disable — the narrowing control by deleting or
  corrupting the file.

Neither of those is something this action can protect against from inside
the job that's already running with the compromised config — protecting them
is a repository-configuration problem, not an input to this action. What
actually works:

| Control | What it does |
| --- | --- |
| **[`CODEOWNERS`](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)** on `.github/workflows/` and the allowlist config path | Requires a named reviewer's approval before either can change, regardless of who opened the PR. |
| **Branch protection** (or a repository ruleset) on the default branch | `Require a pull request before merging` + `Require review from Code Owners` turns the CODEOWNERS entry into an enforced gate, not a suggestion — pair with `Do not allow bypassing the above settings` so admins aren't a silent bypass path. |
| **[Organization-wide rulesets](https://docs.github.com/en/enterprise-cloud@latest/repositories/rules/about-rulesets)** targeting `.github/workflows/**` across every repo | Applies the same review requirement centrally, so a new repo doesn't start unprotected and a per-repo admin can't quietly weaken it. This is the highest-leverage single control if you have more than a handful of repos. |
| `allowlist_fail_open: false` | Once the config path above is protected, treat a missing/corrupted file as `denied` rather than `unrestricted` — see [Config-driven allowlists](#-config-driven-allowlists). |

None of this is specific to this action — it's the same answer for any file
a workflow trusts (config, scripts, `action.yml` in a local composite). This
action's own contribution is `allowlist_fail_open` and the
[handoff audit](#auditing-the-handoff-target): both assume the *rest* of your
repo-write-access story is handled the ordinary way, by branch protection and
review, not by anything this action does at runtime.



## 🧩 Recommended kicker workflow template

A "kicker" is a single `workflow_dispatch` front door for a repository:
one job authorizes the actor, one input picks the operation, and every
operation routes to its own backend. This is the pattern every example above
builds toward — here's the complete, copy-pasteable version. The full file
also lives at [`examples/kicker.yml`](examples/kicker.yml) (config at
[`examples/kicker-policy.json`](examples/kicker-policy.json)) so you can copy
the actual file instead of extracting it from Markdown.

```yaml
name: Kicker

on:
  workflow_dispatch:
    inputs:
      operation:
        description: Which pipeline to run.
        required: true
        type: choice
        options: [deploy, maintenance]
        default: deploy

permissions:
  contents: read

jobs:
  authorize:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/create-github-app-token@v3
        id: token
        with:
          app-id: ${{ vars.GATEKEEPER_APP_ID }}
          private-key: ${{ secrets.GATEKEEPER_APP_PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}

      - uses: blackoutsecure/bos-workflow-gatekeeper@v1
        with:
          actor: ${{ github.triggering_actor }}
          organization: ${{ github.repository_owner }}
          required_teams: release-managers
          token: ${{ steps.token.outputs.token }}
          allowlist_config_path: .github/kicker-policy.json
          allowlist_config_key: kicker.enabled_operations
          allowlist_value: ${{ inputs.operation }}

  deploy:
    needs: authorize
    if: inputs.operation == 'deploy'
    uses: ./.github/workflows/deploy.yml
    secrets: inherit

  maintenance:
    needs: authorize
    if: inputs.operation == 'maintenance'
    uses: ./.github/workflows/maintenance.yml
    secrets: inherit
```

Three things worth calling out about the shape of this template, not just its
content:

- **Routing is `workflow_call`, not a second dispatch.** `uses: ./.github/
  workflows/deploy.yml` can only ever be reached from this workflow's job
  graph — GitHub enforces that structurally, so there's no unguarded
  `workflow_dispatch:` on the backend to audit or spoof. Reach for
  `dispatch_handoff`/`handoff_only` (see
  [Dynamic chaining with no human actor](#dynamic-chaining-with-no-human-actor))
  only when the next workflow's identity truly isn't static — a computed
  name, a different repository, or a system-triggered caller with no actor
  at all. Prefer `workflow_call` whenever the target is known at authoring
  time; it's the smaller attack surface by construction, not by policy.
- **The allowlist check is optional narrowing, not the authorization
  boundary.** `required_teams` (or whatever policy you configure) is what
  actually authorizes the actor; `allowlist_config_*` only narrows which
  `operation` values are currently enabled, from a file instead of a
  workflow-file edit — e.g. drop `deploy` from
  [`examples/kicker-policy.json`](examples/kicker-policy.json) during an
  incident without touching this workflow. Delete those three inputs
  entirely if you don't need that knob.
- **One `authorize` job, `needs:` everywhere else.** Every backend job
  depends on `authorize` and nothing else does its own authorization —
  the same actor check and the same allowlist config apply no matter which
  `operation` was requested, so there is exactly one place a policy change
  has to happen.

### Publishing this as an org-wide starter workflow

Marketplace itself has no bundled-template mechanism beyond the README you're
reading — the code block and the [`examples/`](examples/) directory above
*are* the Marketplace-appropriate way to ship a template. If your
organization wants this kicker to additionally appear as a **suggested
workflow** in every repo's Actions → New workflow page (a separate GitHub
feature from Marketplace), add it to your org's special `.github` repository
under `workflow-templates/`, with a matching `.properties.json`:

```text
.github/                                 (the org's own .github repo)
└── workflow-templates/
    ├── kicker.yml                       # same content as examples/kicker.yml
    └── kicker.properties.json
```

```json
{
  "name": "Blackout Secure Kicker",
  "description": "workflow_dispatch front door: authorize, allowlist-narrow, and route to a backend workflow.",
  "categories": ["Deployment", "Utilities"]
}
```

Omit `iconName` unless you also ship a matching `<name>.svg` in the same
`workflow-templates/` folder — GitHub falls back to a generic icon when it's
absent, but a name with no matching file is a broken reference.

That repository-discovery mechanism is unrelated to (and doesn't require)
publishing on the Marketplace — it only requires the org's `.github`
repository to exist and to define `workflow-templates/`, and it applies only
within that organization.

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

### PAT or GitHub App? Recommendation and why

**Prefer a GitHub App.** In order of preference:

1. **GitHub App installation token** (via
   [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token))
   — expires in about an hour, is scoped to exactly the permissions the App
   was granted, is revocable by uninstalling the App (no separate token to
   rotate), and audit-logs actions as the App's own identity rather than a
   human's. This is what every example in this README uses.
2. **Fine-grained PAT** — only when an App genuinely can't cover the need
   (today, that's the enterprise-owner check below). Set an explicit
   expiration, scope it to the minimum permission and the minimum repository
   list, and — at the organization level — turn on **Require administrator
   approval** for fine-grained PAT access
   ([org Settings → Personal access tokens → Settings](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization))
   so a token can't reach your repos until an admin explicitly approves it.
3. **Classic PAT** — last resort. No per-repo scoping, no expiration unless
   you set one by convention, and no organization-level approval gate.
   Disable classic PAT creation/access for the organization if you can
   ([org Settings → Personal access tokens → Restrict access](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)).
4. **The default `GITHUB_TOKEN`** cannot do any of this — it can't read
   organization role, team membership, repository permission for another
   user, or enterprise ownership. It's sufficient only for `dispatch_handoff`
   within the same repository (see
   [Dynamic chaining with no human actor](#dynamic-chaining-with-no-human-actor)).

> **Before enabling the enterprise check.** `enterprise.ownerInfo` is
> readable only by an enterprise owner, so no GitHub App installation token
> can satisfy it — the check requires storing a highly privileged PAT in
> Actions secrets. Many security teams will not accept that trade. Leave
> `enterprise_slug` empty and gate on organization role plus team membership
> unless you specifically need it.

### Creating the recommended GitHub App

An App is only worth recommending if creating one is actually easy — the
[`app-setup/`](app-setup/) folder in this repository is a small, fully
static page (no server, nothing to deploy beyond static hosting) that walks
through GitHub's
[App manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest):
fill in your organization name, click through to GitHub to create the App
with the recommended permissions pre-filled, and the page exchanges the
resulting one-time code for your App's ID and private key entirely in your
browser — nothing is ever sent to a server this project controls, because
there isn't one. See [`app-setup/README.md`](app-setup/README.md) for exactly
what it does and how to run or host it yourself.

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

## 🏢 Organization-wide hardening

This action authorizes one dispatch in one workflow. It's one control in a
larger picture — the checklist below is what actually determines whether an
attacker who compromises one repository, one contributor account, or one
leaked token can reach the rest of the organization. None of it is specific
to this action; it's general GitHub organization hygiene that makes every
control in this README (and everything else in your org) worth more.

| Control | Where | Why it matters here |
| --- | --- | --- |
| Require 2FA for all members | Org Settings → Authentication security | The actor/team/permission checks in this action are only as strong as the accounts behind them. |
| Organization-wide [rulesets](https://docs.github.com/en/enterprise-cloud@latest/repositories/rules/about-rulesets) requiring PR review + Code Owner review on default branches | Org Settings → Repository → Rulesets | Applies branch protection centrally instead of per-repo, so a new or under-configured repo doesn't start out unprotected. See [Securing the files that drive this action](#-securing-the-files-that-drive-this-action). |
| **Require administrator approval** for fine-grained PAT access | Org Settings → Personal access tokens | A token can't touch org repos until an admin explicitly approves it — closes the gap a stolen or over-scoped PAT would otherwise exploit immediately. |
| Restrict classic PAT access, or disable it entirely | Org Settings → Personal access tokens | Classic PATs can't be scoped to specific repos or given the approval gate above. |
| Actions permissions: allow only selected/verified actions | Org Settings → Actions → General | Limits the blast radius of a compromised or malicious third-party action anywhere in the org, independent of this action's own supply chain. |
| Require approval for first-time contributor workflow runs | Org/repo Settings → Actions → General | Stops an untrusted PR from running a workflow (and touching secrets) before a maintainer looks at it. |
| Secret scanning + push protection, enabled by default for new repos | Org Settings → Code security | Catches a leaked App private key or PAT before or immediately after it reaches a repo, rather than relying on rotation after the fact. |
| Environments with required reviewers for anything that dispatches or publishes | Repo Settings → Environments | Adds a human approval step in front of the credential this action (or its handoff target) uses, for the highest-privilege operations specifically. |

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
