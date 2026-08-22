"""Validate declared runner capabilities before authorization and handoff."""

from __future__ import annotations

import importlib.metadata as metadata
import json
import os
import re
import shutil
import subprocess

from runtime import append_github_output, append_step_summary

COMMAND_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
FORBIDDEN_VERSION_ARGS = {"-c", "-e", "--eval", "--exec", "--command"}


def parse_version(text: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", text or "")
    return tuple(int(number) for number in numbers[:4]) or (0,)


def probe_version(command: str, args: list[str]) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - command and arguments come from validated spec
            [command, *args], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", f"{result.stdout}\n{result.stderr}")
    return match.group(1) if match else ""


def main() -> int:
    raw_spec = os.environ.get("PREFLIGHT_SPEC", "").strip()
    gate_level = os.environ.get("PREFLIGHT_GATE_LEVEL", "standard")
    if not raw_spec:
        append_github_output(
            os.environ, preflight_satisfied="true", preflight_missing=""
        )
        print("::notice title=Preflight::No dependency spec configured; nothing to verify.")
        return 0

    try:
        spec = json.loads(raw_spec)
    except json.JSONDecodeError as error:
        print(f"::error title=Preflight::Dependency spec is not valid JSON: {error}")
        return 1
    if not isinstance(spec, dict):
        print("::error title=Preflight::Dependency spec must be a JSON object.")
        return 1

    commands = spec.get("required_commands") or []
    minimum_versions = spec.get("min_versions") or {}
    packages = spec.get("required_python_packages") or []
    version_args = spec.get("version_args") or {}
    fail_on_missing = spec.get("fail_on_missing", True) is not False
    for command in commands:
        if not isinstance(command, str) or not COMMAND_NAME.fullmatch(command):
            print("::error title=Preflight::required_commands must contain executable names only.")
            return 1
    for command, args in version_args.items():
        if not isinstance(args, list) or any(str(argument) in FORBIDDEN_VERSION_ARGS for argument in args):
            print(f"::error title=Preflight::Unsafe version_args for command: {command}")
            return 1
    missing: list[str] = []
    rows = [
        "### Gatekeeper preflight",
        "",
        f"Gate level: `{gate_level}`",
        "",
        "| Requirement | Kind | Found | Status |",
        "| --- | --- | --- | --- |",
    ]

    for command in commands:
        name = str(command)
        if not shutil.which(name):
            missing.append(f"command:{name}")
            rows.append(f"| `{name}` | command | — | missing |")
            continue
        required = minimum_versions.get(command)
        if not required:
            rows.append(f"| `{name}` | command | present | ok |")
            continue
        args = version_args.get(command) or ["--version"]
        found = probe_version(name, [str(argument) for argument in args])
        if not found:
            missing.append(f"version-unknown:{name}")
            rows.append(f"| `{name}` | version | unreadable | missing |")
        elif parse_version(found) < parse_version(str(required)):
            missing.append(f"version:{name}<{required}")
            rows.append(f"| `{name}` >= `{required}` | version | `{found}` | too old |")
        else:
            rows.append(f"| `{name}` >= `{required}` | version | `{found}` | ok |")

    for distribution in packages:
        requirement = str(distribution)
        name = re.split(r"[<>=!~\[]", requirement, maxsplit=1)[0].strip()
        bound = re.search(r">=\s*([0-9][0-9.]*)", requirement)
        wanted = bound.group(1) if bound else ""
        try:
            found = metadata.version(name)
        except metadata.PackageNotFoundError:
            missing.append(f"python:{name}")
            rows.append(f"| `{requirement}` | python | — | missing |")
            continue
        if wanted and parse_version(found) < parse_version(wanted):
            missing.append(f"python:{name}<{wanted}")
            rows.append(f"| `{requirement}` | python | `{found}` | too old |")
        else:
            rows.append(f"| `{requirement}` | python | `{found}` | ok |")

    satisfied = not missing
    rows.extend(["", "All requirements satisfied." if satisfied else f"**Unsatisfied:** {', '.join(missing)}"])
    append_step_summary(os.environ, rows)
    append_github_output(
        os.environ,
        preflight_satisfied="true" if satisfied else "false",
        preflight_missing=",".join(missing),
    )
    if satisfied:
        print("::notice title=Preflight::All declared dependencies are available.")
        return 0
    detail = ", ".join(missing)
    if fail_on_missing:
        print(f"::error title=Preflight failed::Runner is missing: {detail}")
        return 1
    print(f"::warning title=Preflight::Runner is missing (not enforced): {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
