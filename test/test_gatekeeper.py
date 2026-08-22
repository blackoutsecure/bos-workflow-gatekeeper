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
            "HANDOFF_REF", "DISPATCH_HANDOFF", "HANDOFF_AUDIT", "HANDOFF_ONLY", "HANDOFF_INPUTS",
            "ALLOWLIST_CONFIG_PATH", "ALLOWLIST_CONFIG_KEY", "ALLOWLIST_VALUE", "ALLOWLIST_ONLY", "ALLOWLIST_FAIL_OPEN",
            "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF",
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
    monkeypatch.setenv("HANDOFF_AUDIT", "off")
    monkeypatch.setattr(gatekeeper, "gather", lambda *a, **k: Signals(org_role="admin"))
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0


# --------------------------------------------------------------------------
# handoff audit
# --------------------------------------------------------------------------
def _authorized_dispatch_env(monkeypatch):
    monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    monkeypatch.setenv("TOKEN", "x")
    monkeypatch.setenv("DISPATCH_HANDOFF", "true")
    monkeypatch.setenv("HANDOFF_WORKFLOW", "deploy.yml")
    monkeypatch.setenv("HANDOFF_REPOSITORY", "acme/app")
    monkeypatch.setenv("HANDOFF_REF", "main")
    monkeypatch.setattr(gatekeeper, "gather", lambda *a, **k: Signals(org_role="admin"))


def test_handoff_audit_defaults_to_warn_and_still_dispatches(monkeypatch, capsys):
    _authorized_dispatch_env(monkeypatch)
    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", lambda *a, **k: ("insecure", "exposed"))
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0
    assert "Gatekeeper handoff audit" in capsys.readouterr().out


def test_handoff_audit_block_mode_prevents_dispatch(monkeypatch, tmp_path):
    _authorized_dispatch_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "block")
    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", lambda *a, **k: ("insecure", "exposed"))
    dispatched = {"called": False}

    def _fail_if_called(*a, **k):
        dispatched["called"] = True
        return True

    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", _fail_if_called)
    assert gatekeeper.main() == 1
    assert dispatched["called"] is False
    result = outputs(tmp_path)
    assert result["handoff_dispatched"] == "false"
    assert result["handoff_audit_status"] == "insecure"


def test_handoff_audit_off_skips_the_check_entirely(monkeypatch):
    _authorized_dispatch_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "off")

    def _boom(*a, **k):
        raise AssertionError("audit must not run when handoff_audit is off")

    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", _boom)
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0


def test_handoff_audit_secure_dispatches_without_warning(monkeypatch, tmp_path, capsys):
    _authorized_dispatch_env(monkeypatch)
    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", lambda *a, **k: ("secure", "guarded"))
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0
    assert "Gatekeeper handoff audit" not in capsys.readouterr().out
    assert outputs(tmp_path)["handoff_audit_status"] == "secure"


def test_handoff_audit_unknown_mode_falls_back_to_warn(monkeypatch, capsys):
    _authorized_dispatch_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "maybe")
    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", lambda *a, **k: ("insecure", "exposed"))
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0
    out = capsys.readouterr().out
    assert "defaulting to 'warn'" in out
    assert "Gatekeeper handoff audit::exposed" in out


# --------------------------------------------------------------------------
# handoff_only (dynamic chaining with no human actor)
# --------------------------------------------------------------------------
def _handoff_only_env(monkeypatch):
    monkeypatch.setenv("HANDOFF_ONLY", "true")
    monkeypatch.setenv("DISPATCH_HANDOFF", "true")
    monkeypatch.setenv("HANDOFF_WORKFLOW", "deploy.yml")
    monkeypatch.setenv("HANDOFF_REPOSITORY", "acme/app")
    monkeypatch.setenv("HANDOFF_REF", "main")


def test_handoff_only_requires_no_actor_or_organization(monkeypatch, tmp_path):
    _handoff_only_env(monkeypatch)
    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", lambda *a, **k: ("secure", "guarded"))
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: True)
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["handoff_dispatched"] == "true"


def test_handoff_only_without_dispatch_handoff_is_a_no_op(monkeypatch, tmp_path):
    monkeypatch.setenv("HANDOFF_ONLY", "true")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["handoff_dispatched"] == "false"


def test_handoff_only_rejects_loop(monkeypatch):
    monkeypatch.setenv("HANDOFF_ONLY", "true")
    monkeypatch.setenv("DISPATCH_HANDOFF", "true")
    monkeypatch.setenv("HANDOFF_WORKFLOW", "deploy.yml")
    monkeypatch.setenv("HANDOFF_REPOSITORY", "acme/app")
    monkeypatch.setenv("HANDOFF_REF", "main")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "acme/app/.github/workflows/deploy.yml@refs/heads/main")
    assert gatekeeper.main() == 1


def test_handoff_only_block_mode_prevents_dispatch(monkeypatch, tmp_path):
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "block")
    monkeypatch.setattr(gatekeeper.Client, "audit_workflow_dispatch_target", lambda *a, **k: ("insecure", "exposed"))
    dispatched = {"called": False}

    def _fail_if_called(*a, **k):
        dispatched["called"] = True
        return True

    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", _fail_if_called)
    assert gatekeeper.main() == 1
    assert dispatched["called"] is False
    assert outputs(tmp_path)["handoff_audit_status"] == "insecure"


def test_handoff_only_dispatch_failure_is_reported(monkeypatch, tmp_path):
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "off")
    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", lambda *a, **k: False)
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["handoff_dispatched"] == "false"


# --------------------------------------------------------------------------
# handoff_inputs
# --------------------------------------------------------------------------
def test_handoff_inputs_are_forwarded_to_dispatch(monkeypatch):
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "off")
    monkeypatch.setenv("HANDOFF_INPUTS", '{"kicker": "sync", "dry_run": "false"}')
    calls = []
    monkeypatch.setattr(
        gatekeeper.Client, "dispatch_workflow",
        lambda self, repository, workflow, ref, inputs=None: calls.append(inputs) or True,
    )
    assert gatekeeper.main() == 0
    assert calls == [{"kicker": "sync", "dry_run": "false"}]


def test_handoff_inputs_invalid_json_is_an_error(monkeypatch):
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_INPUTS", "{not json")
    assert gatekeeper.main() == 1


def test_handoff_inputs_must_be_an_object(monkeypatch):
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_INPUTS", "[1, 2, 3]")
    assert gatekeeper.main() == 1


def test_handoff_inputs_coerces_values_to_strings(monkeypatch):
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("HANDOFF_AUDIT", "off")
    monkeypatch.setenv("HANDOFF_INPUTS", '{"force": true, "count": 3}')
    calls = []
    monkeypatch.setattr(
        gatekeeper.Client, "dispatch_workflow",
        lambda self, repository, workflow, ref, inputs=None: calls.append(inputs) or True,
    )
    assert gatekeeper.main() == 0
    assert calls == [{"force": "true", "count": "3"}]


# --------------------------------------------------------------------------
# allowlist_only / config-driven allowlist
# --------------------------------------------------------------------------
def _write_config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(__import__("json").dumps(data), encoding="utf-8")
    return str(path)


def test_allowlist_skipped_when_path_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "skipped"


def test_allowlist_allows_listed_value(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {"kicker_fanout": {"enabled_kickers": ["sync", "security"]}}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "allowed"


def test_allowlist_denies_unlisted_value(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {"kicker_fanout": {"enabled_kickers": ["sync"]}}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "launchpad")
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["allowlist_status"] == "denied"


def test_allowlist_fails_open_on_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", str(tmp_path / "does-not-exist.json"))
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "unrestricted"


def test_allowlist_fails_open_on_invalid_json(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", str(bad))
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "unrestricted"


def test_allowlist_fails_open_on_missing_key(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "unrestricted"


def test_allowlist_fails_open_on_empty_list(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {"kicker_fanout": {"enabled_kickers": []}}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "unrestricted"


def test_allowlist_fail_open_false_denies_on_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_FAIL_OPEN", "false")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", str(tmp_path / "does-not-exist.json"))
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["allowlist_status"] == "denied"


def test_allowlist_fail_open_false_denies_on_empty_value(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {"kicker_fanout": {"enabled_kickers": ["sync"]}}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_FAIL_OPEN", "false")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["allowlist_status"] == "denied"


def test_allowlist_fail_open_false_still_allows_a_real_match(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {"kicker_fanout": {"enabled_kickers": ["sync"]}}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_FAIL_OPEN", "false")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "sync")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "allowed"


def test_allowlist_only_requires_a_value(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"organization": {"kicker_fanout": {"enabled_kickers": ["sync"]}}})
    monkeypatch.setenv("ALLOWLIST_ONLY", "true")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "organization.kicker_fanout.enabled_kickers")
    assert gatekeeper.main() == 0
    assert outputs(tmp_path)["allowlist_status"] == "unknown"


def test_allowlist_denial_blocks_full_authorize_flow(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"kickers": ["sync"]})
    monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("ACTOR", "alice")
    monkeypatch.setenv("ORGANIZATION", "acme")
    monkeypatch.setenv("TOKEN", "x")
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "launchpad")
    monkeypatch.setattr(gatekeeper, "gather", lambda *a, **k: Signals(org_role="admin"))
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["allowlist_status"] == "denied"
    assert outputs(tmp_path)["authorized"] == "false"


def test_allowlist_denial_blocks_handoff_only(monkeypatch, tmp_path):
    config_path = _write_config(tmp_path, {"kickers": ["sync"]})
    _handoff_only_env(monkeypatch)
    monkeypatch.setenv("ALLOWLIST_CONFIG_PATH", config_path)
    monkeypatch.setenv("ALLOWLIST_CONFIG_KEY", "kickers")
    monkeypatch.setenv("ALLOWLIST_VALUE", "launchpad")

    def _fail_if_called(*a, **k):
        raise AssertionError("dispatch must not run when the allowlist denies")

    monkeypatch.setattr(gatekeeper.Client, "dispatch_workflow", _fail_if_called)
    assert gatekeeper.main() == 1
    assert outputs(tmp_path)["allowlist_status"] == "denied"
    assert outputs(tmp_path)["handoff_dispatched"] == "false"
