# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## What this is

**This repository is security-critical.** `bos-workflow-gatekeeper` is the authorization gate that guards privileged workflow dispatch across the `blackoutsecure` organization. A regression here does not break a build — it silently stops gating, which from the outside looks identical to a gate that passed. Treat every change to `src/policy.py`, `src/signals.py`, `src/gatekeeper.py`, and `action.yml` as a change to an access-control boundary.

It is a composite GitHub Action published to the Marketplace. It resolves the triggering actor against an explicit policy built from four composable checks — organization role, team membership, repository permission, and enterprise ownership — and denies the job when the actor is not authorized. Each check is disabled until configured. Any enabled check authorizes by default (OR); `require_all: true` demands all of them (AND). Every signal resolves to a definitive answer or `unknown`, and `unknown` is never a pass.

It is consumed through the "kicker" pattern: a repository exposes one `workflow_dispatch` front door whose first job is `authorize`, and every privileged backend job declares `needs: authorize`. The org-wide instance lives in `.github/workflows/bos-universal-gatekeeper-kicker.yml` (hub-distributed) — it mints a short-lived App token, resolves a `gate_level` from the requested operation, calls this action pinned to a commit SHA, and only then lets `sync-check`/`parse-config` and the release backends run. `examples/kicker.yml` is the copy-pasteable consumer template, with `examples/kicker-policy.json` as its allowlist config.

Stack: Python `>=3.10`, pure standard library at runtime — zero third-party runtime dependencies, deliberately, because nothing else belongs in an authorization path. Packaging is `hatchling>=1.27` via `pyproject.toml` (version `1.0.2`, mirrored in `src/_version.py`). Dev extras: `PyYAML>=6.0`, `pytest>=8.0`, `ruff>=0.6`. CI lints and tests on Python `3.12`, and matrixes `3.10`–`3.13` through the hub.

## Commands

```bash
pip install -e ".[dev]"                            # dev install (editable, dev extras)

pytest test/ -v                                    # full suite
pytest test/test_policy.py -v                      # single file (decision matrix)
pytest test/test_gatekeeper.py::test_missing_token_denies_and_exits_nonzero -v

ruff check src test                                # lint
python3 scripts/check_action_sync.py               # action.yml / pyproject / _version drift
python3 scripts/render_readme_inputs.py --check    # README tables stale? (CI mode)
python3 scripts/render_readme_inputs.py --write    # regenerate after editing action.yml

python3 -m http.server --directory app-setup 8000  # serve the App-setup page locally
```

`pyproject.toml` sets `pythonpath = ["src"]` and `test/conftest.py` prepends `src/`, so `pytest` works without the editable install. `app-setup/index.html` also works opened directly as `file://`.

## Validating changes

CI, in order:

1. `self-test.yml` (`push`/`pull_request` on `main` and `dev`) — job `lint-and-test`: `ruff check src test`, `check_action_sync.py`, `render_readme_inputs.py --check`, `pytest test/ -v`. Then job `self-check` runs the action against itself with `restrict_to_events: workflow_dispatch` on a non-dispatch event and asserts the pass-through contract (`enforced=false`, `authorized=true`).
2. The hub's reusable `bos-universal-security.yml`, reported as one required check.
3. `hub-dev-validation.yml` — manual-only, `dev` only, calls the hub's security, action-test, and Marketplace reusable workflows directly. It never dispatches a kicker, so it cannot recursively trigger itself.
4. `deploy-app-setup-pages.yml` — publishes `app-setup/` to GitHub Pages on `push` to `main` under `app-setup/**`, or manually.

Locally, narrowest first: the single test for the branch you touched, then `pytest test/test_policy.py -v` if the decision matrix moved, then the full suite, then `ruff check src test`, then both `scripts/` checks.

What the tests prove and do not prove: `src/policy.py` performs no I/O, so the decision matrix is exhaustively testable and is. `test/test_signals.py` stubs `Client.request` entirely — **no test in this repository makes a real GitHub API call.** They cannot prove real organization, team, repository-permission, or enterprise API behaviour, nor that a token carries the scopes it needs, nor that `enterprise.ownerInfo` is readable. Those only fail in a live run. Anything that changes how a signal is resolved needs a real dispatch on a throwaway repository before it is trusted.

## Architecture

```text
action.yml                      Composite manifest: 34 inputs, 19 outputs, two steps.
src/preflight.py                Runner capability checks. Step 1, no authorization token.
src/gatekeeper.py               Entrypoint: reads env, orchestrates, enforces, emits.
src/policy.py                   Pure decision logic. No I/O. Signals + Policy -> Decision.
src/signals.py                  GitHub REST/GraphQL lookups. Returns `unknown`, never raises.
src/runtime.py                  env_bool / env_csv / GITHUB_OUTPUT / GITHUB_STEP_SUMMARY.
src/_version.py                 __version__, in lockstep with pyproject.toml.
scripts/check_action_sync.py    Drift guard: action.yml, pyproject.toml, _version.py.
scripts/render_readme_inputs.py Generates the README input/output tables from action.yml.
test/conftest.py                Puts src/ on sys.path.
test/test_policy.py             Decision matrix; every `unknown` path asserted explicitly.
test/test_gatekeeper.py         Exit codes, event scoping, outputs, handoff, allowlist.
test/test_signals.py            API-response handling against a scripted fake client.
test/test_preflight.py          Spec parsing, missing commands, version comparison.
examples/kicker.yml             Consumer kicker template (workflow_call routing).
examples/kicker-policy.json     Allowlist config the template points at.
app-setup/                      Static GitHub App manifest helper. Presentation only.
.github/bos-universal-config.json  Repo-owned overrides on the hub's global config.
```

Decision flow, end to end:

1. **Step `preflight`** always runs first, before any credential is in scope. Its `env:` block carries only `PREFLIGHT_SPEC`, `PREFLIGHT_GATE_LEVEL`, `PREFLIGHT_ONLY` — the token is deliberately absent. `required_commands` must match `^[A-Za-z0-9][A-Za-z0-9._+-]*$` and `version_args` rejects `-c`, `-e`, `--eval`, `--exec`, `--command`, so a spec cannot smuggle in arbitrary execution.
2. **Step `gate`** (skipped when `preflight_only`) branches into one of four modes: `preflight_only` (exit 0), `allowlist_only`, `handoff_only`, or full authorization.
3. Full mode resolves the caller check and parses the handoff, then event-scopes. If `event_name` is not in `restrict_to_events` (default `workflow_dispatch`; `*` gates everything), it emits `enforced=false`, `authorized=true` and returns with **zero API calls**.
4. A missing `actor`, `organization`, or `token` denies immediately when any enabled check or a dispatch needs API evidence.
5. `signals.gather` issues **only** the lookups the policy enables. `Client.request` refuses any URL not starting with `https://` before it reaches `urllib`, so a poisoned `GITHUB_API_URL` cannot smuggle a `file:` scheme into an authorization answer. A 5xx, timeout, or unparseable body becomes `unknown`. Membership in `pending` state is not membership.
6. `policy.evaluate` composes: `None` (unresolvable) never counts as a pass and denies outright under `require_all`. No enabled check at all is a denial, not a default-allow.
7. The allowlist check runs after the decision; `denied` overrides an authorized decision.
8. Handoff audit and dispatch run only after an authorized decision.
9. `_finish` writes every output, optionally writes the summary table, and returns `1` on denial when `fail_closed` (default `true`), or `0` with a `::warning::` when it is `false`.

Token selection: `token` should be a GitHub App installation token minted by `actions/create-github-app-token` from `vars.GATEKEEPER_APP_ID` and `secrets.GATEKEEPER_APP_PRIVATE_KEY`, carrying only organization `Members: Read-only`. The hub kicker falls back to `secrets.GATEKEEPER_AUTHZ_PAT` (`read:org`) when no App is configured. `enterprise_token` is a separate input because no App installation token can read `enterprise.ownerInfo`; it needs `admin:enterprise` held by an enterprise owner, and falls back to `token`. The default `GITHUB_TOKEN` can do none of these — it suffices only for a same-repository `dispatch_handoff`.

Allowlist config: `allowlist_config_path` plus a dot-path `allowlist_config_key` into any JSON file (`.github/kicker-policy.json` in the examples; `organization.kicker_fanout.enabled_kickers` in hub configs). It is **additive narrowing layered on top of actor authorization, not a boundary**, and therefore fails **open** by default: missing file, invalid JSON, missing key, or an empty/non-array value all resolve to `unrestricted`. `allowlist_fail_open: false` inverts that to `denied` — correct once the config path is itself protected by CODEOWNERS and branch protection.

Action contract: every input and output is enumerated in `action.yml` and mirrored into the README by `scripts/render_readme_inputs.py`. Inputs group as identity (`actor`, `organization`, `repository`, `token`), scoping (`event_name`, `restrict_to_events`), policy (`required_teams`, `required_repo_permission`, `allow_org_admin`, `enterprise_slug`, `enterprise_token`, `require_enterprise_owner`, `require_all`, `fail_closed`, `summary`), caller identity (`caller_workflow`, `caller_repository`, `caller_check_fail`, `suppress_caller_warning`), handoff (`handoff_workflow`, `handoff_repository`, `handoff_ref`, `handoff_inputs`, `dispatch_handoff`, `handoff_audit`, `handoff_only`), preflight (`preflight_spec`, `preflight_gate_level`, `preflight_only`), and allowlist (`allowlist_config_path`, `allowlist_config_key`, `allowlist_value`, `allowlist_only`, `allowlist_fail_open`). Outputs cover the decision (`authorized`, `reason`, `enforced`), each resolved signal, `caller_valid`, seven `handoff_*` fields, two `allowlist_*` fields, and two `preflight_*` fields. `preflight_satisfied`/`preflight_missing` come from the `preflight` step; everything else comes from `gate`. All of it is published Marketplace surface.

`app-setup/` is presentation only: a single static `index.html` that builds a GitHub App manifest, POSTs it to GitHub's own App-creation page, and exchanges the returned one-time `?code=` for the App ID and private key entirely in browser memory. There is no backend anywhere in that flow, and credentials are never written to `localStorage`, a cookie, or any server. It contains no authorization logic and must never acquire any.

## Security invariants

These are non-negotiable. Violating one is a security defect, not a style disagreement.

- The `authorize` job must run **before** any job that touches secrets, holds write permission, or publishes. Privileged jobs declare `needs: authorize`; the gate job itself holds only `contents: read`.
- Use `github.triggering_actor`, never `github.actor`. On a re-run `github.actor` stays the original dispatcher, so authorizing it would let anyone with write access replay a privileged dispatch under someone else's identity.
- `unknown` is never a pass. A missing token, 5xx, timeout, GraphQL error, or unreadable enterprise response must resolve to `unknown` and deny — never to `false`-as-evidence, never to an implicit allow.
- Never make an authorization path silently fail open. The one deliberate fail-open here is the allowlist check, and it is explicit, documented in `action.yml` and the README, tested, and overridable via `allowlist_fail_open: false`. Any new fail-open needs the same three things before it merges.
- Never widen a token's scope to simplify code. Organization checks stay at `Members: Read-only`. `enterprise_token` exists precisely so `admin:enterprise` is not required for the common path, and must not be collapsed back into `token`.
- Prefer App installation tokens over PATs. Apps expire in about an hour, are revocable by uninstall, and audit as their own identity. A PAT is acceptable only where an App cannot work at all (today: the enterprise-owner check).
- Never log, echo, `print`, or write to the job summary any token, private key, App credential, or fragment of one. Reasons and summary rows carry decisions, not secrets.
- Preflight runs before credentials enter scope. Its `env:` block must stay free of `TOKEN`/`ENTERPRISE_TOKEN`; do not add the token there to "simplify" the manifest.
- Non-HTTPS URLs are rejected in `Client.request` before `urllib` sees them. Keep that check first.
- Same-workflow handoff is refused to prevent dispatch loops, and handoff identifiers containing `\r`, `\n`, or `?` are rejected. Do not relax either.
- `handoff_audit` requires a real `uses: ...bos-workflow-gatekeeper@<ref>` step line, not a bare string match — this repository's source is public, so a looser check would be trivially spoofed by a comment or a docs link. A `secure` result means "looks guarded", never a proof.
- Keep the runtime pure standard library. Adding a third-party runtime dependency to an authorization path is a supply-chain decision, not a convenience.

## Conventions

Python targets `py310`, `line-length = 100`, ruff rules `E,F,W,I,B,UP,S,SIM` with `E501` and `S101` ignored and `S`/`B` relaxed under `test/`. Modules are flat and single-purpose: decision logic never does I/O, and I/O never decides. Comments explain why a non-obvious security choice exists, not what the line does. Functions returning a status/reason pair enumerate every possible status in their docstring. Prefer a sentinel over raising, so a caller can distinguish "denied" from "could not tell":

```python
def _check_org_admin(signals: Signals) -> bool | None:
    if signals.org_role == UNKNOWN:
        return None
    return signals.org_role == "admin"
```

Edit `action.yml` first, then regenerate the README tables with `python3 scripts/render_readme_inputs.py --write`; never hand-edit between the `<!-- BEGIN action-inputs -->` / `<!-- END action-inputs -->` markers. Bump `version` in `pyproject.toml` and `__version__` in `src/_version.py` together or `scripts/check_action_sync.py` fails. Keep `action.yml::description` at or under 125 characters.

## Blackout Secure conventions

These apply to every repository in the `blackoutsecure` organization.

### Branch model

- `dev` is the default branch and where all work lands.
- `main` is the promoted stable runtime that consumers reference through `@main`.
- Version tags (`vX.Y.Z` and a floating `vX`) point at promoted runtime commits.
- Promotion is driven from `bos-automation-hub` (`release-promote.yml`). Do not push
  directly to `main` and do not move tags by hand.

### Centrally managed files - do not hand-edit here

`blackoutsecure/bos-automation-hub` distributes these through
`bos-managed-file-sync-action`. Change the source under the hub's `sync-files/`, never the
copy in this repository:

- `LICENSE`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`
- `.github/FUNDING.yml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/`
- `.github/workflows/bos-universal-gatekeeper-kicker.yml`
- the `# >>> managed-file-sync:<service> >>> ... # <<< managed-file-sync:<service> <<<`
  delimited blocks inside `.editorconfig`, `.markdownlint.yaml`, `.shellcheckrc`,
  `.yamllint.yml`, `.gitignore`, and `README.md`

`.github/bos-universal-config.json` is repo-owned. It holds this repository's overrides on
top of the hub's global config and is the right place to change gate behaviour.

### CI gate

Pushes and pull requests run the hub's reusable `bos-universal-security.yml`, reported as a
single required check. It runs markdownlint, yamllint, shellcheck, and actionlint; ESLint,
Prettier, Ruff, pytest, and Bats where the repository has them; `bos-code-scanning-kit`
(secret scan, SAST, GHAS posture) and CodeQL; dependency review; and compliance checks for
the canonical README header and a conventional-commit PR title
(`feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert: subject`).

Every `uses:` reference in a workflow must be a commit SHA with a trailing version comment,
for example `actions/checkout@<sha> # v4.2.2`.

## Boundaries

### Always

- Run `ruff check src test`, `pytest test/ -v`, `python3 scripts/check_action_sync.py`, and `python3 scripts/render_readme_inputs.py --check` before considering a change done.
- Add a test for every new `unknown`/inconclusive path, asserting the deny and not just the happy path.
- Regenerate the README tables from `action.yml` rather than editing them.
- Keep `src/policy.py` free of I/O and `src/signals.py` free of policy decisions.
- Pin every `uses:` to a commit SHA with a trailing version comment.

### Ask first

- Any change to authorization semantics: the meaning of a signal, OR/AND composition, how `unknown` is treated, or what counts as evidence.
- Any change to a default failure mode — `fail_closed`, `allowlist_fail_open`, `handoff_audit` — or introducing a new fail-open anywhere.
- Any change to the action contract: renaming, removing, or repurposing an input or output, or changing a default. This is published Marketplace surface.
- Adding a runtime dependency, a new API endpoint, or a new token/scope requirement.
- Changing what `app-setup/` requests in its App manifest; widening `default_permissions` widens what a leaked private key can do.
- Editing `.github/workflows/bos-universal-gatekeeper-kicker.yml` or anything else listed as centrally managed.

### Never

- Weaken or bypass the gate to make a workflow pass, including switching to `github.actor`, removing `needs: authorize`, or granting write permission to the authorize job.
- Log, echo, or persist token material, App private keys, or their fragments.
- Put the authorization token into the preflight step's environment.
- Treat `unknown` as authorized, or add an implicit allow when no check is enabled.
- Push directly to `main` or move version tags by hand.
- Add a real network call to the test suite, or land an authorization change on the strength of mocked tests alone.
