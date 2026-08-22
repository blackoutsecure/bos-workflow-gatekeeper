"""Shared runtime helpers for environment parsing and GitHub output files."""

from __future__ import annotations

from collections.abc import Mapping


def env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if raw in {"true", "1", "yes"}:
        return True
    if raw in {"false", "0", "no"}:
        return False
    return default


def env_csv(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in env.get(name, "").split(",") if part.strip())


def append_github_output(env: Mapping[str, str], **pairs: str) -> None:
    path = env.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in pairs.items():
            handle.write(f"{key}={value}\n")


def append_step_summary(env: Mapping[str, str], lines: list[str]) -> None:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
