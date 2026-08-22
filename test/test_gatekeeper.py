"""Entrypoint behaviour: exit codes, event scoping, and output contract."""

import pytest

import gatekeeper
from policy import Signals


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for key in list(gatekeeper.os.environ):
        if key in {
            "EVENT_NAME", "RESTRICT_TO_EVENTS", "FAIL_CLOSED", "ACTOR", "ORGANIZATION",
            "TOKEN", "REQUIRED_TEAMS", "ALLOW_ORG_ADMIN", "REQUIRE_ALL",
            "REQUIRE_ENTERPRISE_OWNER", "ENTERPRISE_SLUG", "REQUIRED_REPO_PERMISSION",
            "REPOSITORY", "SUMMARY",
            "CALLER_WORKFLOW", "CALLER_REPOSITORY", "CALLER_CHECK_FAIL",
            "SUPPRESS_CALLER_WARNING", "HANDOFF_WORKFLOW", "HANDOFF_REPOSITORY",
            "HANDOFF_REF", "DISPATCH_HANDOFF", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF",
            "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_API_URL",
        }:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "sum"))
    monkeypatch.setenv("SUMMARY", "false")


def outputs(tmp_path) -> dict:
    text = (tmp_path / "out").read_text(encoding="utf-8")
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def test_missing_token_denies_and_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["authorized"] == "false"


def test_missing_token_with_fail_closed_false_exits_zero(monkeypatch, tmp_path):
    monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    monkeypatch.setenv("FAIL_CLOSED", "false")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["authorized"] == "false", (
        "fail_closed=false must still report the denial, only not enforce it"
    )


def test_ungated_event_passes_through_without_api_calls(monkeypatch, tmp_path):
    monkeypatch.setenv("EVENT_NAME", "push")
    monkeypatch.setenv("RESTRICT_TO_EVENTS", "workflow_dispatch")
    assert gatekeeper.main() == 0
    result = outputs(tmp_path)
    assert result["authorized"] == "true"
    assert result["enforced"] == "false"


def test_wildcard_restrict_gates_every_event(monkeypatch, tmp_path):
    monkeypatch.setenv("EVENT_NAME", "push")
    monkeypatch.setenv("RESTRICT_TO_EVENTS", "*")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    assert gatekeeper.main() == 1, "wildcard must not fall through the pass-through branch"


def test_authorized_path_exits_zero(monkeypatch, tmp_path):
    monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    monkeypatch.setenv("TOKEN", "x")
    monkeypatch.setattr(gatekeeper, "gather", lambda *a, **k: Signals(org_role="admin"))
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["authorized"] == "true"


def test_bool_parsing_accepts_common_spellings(monkeypatch):
    for raw, expected in [("true", True), ("TRUE", True), ("1", True), ("yes", True),
                          ("false", False), ("0", False), ("no", False)]:
        monkeypatch.setenv("REQUIRE_ALL", raw)
        assert gatekeeper._bool("REQUIRE_ALL", not expected) is expected


def test_bool_falls_back_to_default_on_garbage(monkeypatch):
    monkeypatch.setenv("REQUIRE_ALL", "maybe")
    assert gatekeeper._bool("REQUIRE_ALL", True) is True
    assert gatekeeper._bool("REQUIRE_ALL", False) is False


def test_csv_trims_and_drops_blanks(monkeypatch):
    monkeypatch.setenv("REQUIRED_TEAMS", " a , ,b,, c ")
    assert gatekeeper._csv("REQUIRED_TEAMS") == ("a", "b", "c")


def test_caller_mismatch_warns_without_failing(monkeypatch, capsys):
    monkeypatch.setenv("EVENT_NAME", "push")
    monkeypatch.setenv("RESTRICT_TO_EVENTS", "workflow_dispatch")
    monkeypatch.setenv("CALLER_WORKFLOW", "trusted.yml")
    monkeypatch.setenv("GITHUB_WORKFLOW", "other.yml")
    assert gatekeeper.main() == 0
    assert "Gatekeeper caller" in capsys.readouterr().out


def test_caller_mismatch_can_fail(monkeypatch):
    monkeypatch.setenv("CALLER_WORKFLOW", "trusted.yml")
    monkeypatch.setenv("GITHUB_WORKFLOW", "other.yml")
    monkeypatch.setenv("CALLER_CHECK_FAIL", "true")
    assert gatekeeper.main() == 1


def test_dispatch_requires_workflow(monkeypatch):
    monkeypatch.setenv("DISPATCH_HANDOFF", "true")
    monkeypatch.setenv("TOKEN", "x")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    assert gatekeeper.main() == 1


def test_dispatch_rejects_current_workflow_loop(monkeypatch):
    monkeypatch.setenv("DISPATCH_HANDOFF", "true")
    monkeypatch.setenv("HANDOFF_WORKFLOW", "deploy.yml")
    monkeypatch.setenv("HANDOFF_REPOSITORY", "acme/app")
    monkeypatch.setenv("HANDOFF_REF", "main")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "acme/app/.github/workflows/deploy.yml@refs/heads/main")
    assert gatekeeper.main() == 1


def test_authorized_dispatches_handoff(monkeypatch):
    monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    monkeypatch.setenv("TOKEN", "x")
    monkeypatch.setenv("DISPATCH_HANDOFF", "true")
    monkeypatch.setenv("HANDOFF_WORKFLOW", "deploy.yml")
    monkeypatch.setenv("HANDOFF_REPOSITORY", "acme/app")
    monkeypatch.setenv("HANDOFF_REF", "main")
    monkeypatch.setattr(gatekeeper, "gather", lambda *a, **k: Signals(org_role="admin"))
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0
