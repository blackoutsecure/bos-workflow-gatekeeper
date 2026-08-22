"""Runner capability preflight tests."""

import json

import preflight


def set_outputs(monkeypatch, tmp_path):
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    return output, summary


def test_empty_spec_succeeds(monkeypatch, tmp_path):
    output, _ = set_outputs(monkeypatch, tmp_path)
    monkeypatch.delenv("PREFLIGHT_SPEC", raising=False)
    assert preflight.main() == 0
    assert "preflight_satisfied=true" in output.read_text()


def test_invalid_spec_fails(monkeypatch, tmp_path):
    set_outputs(monkeypatch, tmp_path)
    monkeypatch.setenv("PREFLIGHT_SPEC", "not-json")
    assert preflight.main() == 1


def test_missing_command_fails_closed(monkeypatch, tmp_path):
    output, summary = set_outputs(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "PREFLIGHT_SPEC",
        json.dumps({"required_commands": ["command-that-does-not-exist"]}),
    )
    assert preflight.main() == 1
    assert "preflight_satisfied=false" in output.read_text()
    assert "command:command-that-does-not-exist" in output.read_text()
    assert "Gatekeeper preflight" in summary.read_text()


def test_missing_requirement_can_warn(monkeypatch, tmp_path):
    output, _ = set_outputs(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "PREFLIGHT_SPEC",
        json.dumps(
            {
                "required_commands": ["command-that-does-not-exist"],
                "fail_on_missing": False,
            }
        ),
    )
    assert preflight.main() == 0
    assert "preflight_satisfied=false" in output.read_text()
