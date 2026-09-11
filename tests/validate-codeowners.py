#!/usr/bin/env python3
"""Validate canonical release-sensitive CODEOWNERS and independent reviewers."""

import argparse
import json
import pathlib
import shlex
import sys

REQUIRED_PATTERNS = [
    "/.github/", "/install.sh", "/rust-toolchain.toml",
    "/scripts/confirm-required-check.sh", "/scripts/github-release-protections.sh",
    "/tests/check-release-admission.sh", "/tests/check-release-eligibility.sh",
    "/tests/github-protection-contract-tests.py", "/tests/integration-installer.sh",
    "/tests/linux-integration-inventory.tsv", "/tests/release-assets-tests.py",
    "/tests/release-contract-tests.py", "/tests/resolve-dumpbin.ps1",
    "/tests/run-linux-integrations.sh", "/tests/validate-codeowners.py",
    "/tests/validate-github-protections.py", "/tests/validate-release-metadata.py",
    "/tests/verify-release-assets.py", "/tests/workflow-contract.rb",
]


def validate(text: str, collaborators: list[dict], authority: str) -> None:
    entries: dict[str, list[str]] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        tokens = shlex.split(raw, comments=True)
        if not tokens:
            continue
        if len(tokens) < 2 or not all(owner.startswith("@") and len(owner) > 1 for owner in tokens[1:]):
            raise ValueError(f"invalid CODEOWNERS entry on line {number}")
        if tokens[0] in entries:
            raise ValueError(f"duplicate CODEOWNERS pattern: {tokens[0]}")
        entries[tokens[0]] = [owner[1:] for owner in tokens[1:]]
    if sorted(entries) != sorted(REQUIRED_PATTERNS):
        missing = sorted(set(REQUIRED_PATTERNS) - set(entries))
        extra = sorted(set(entries) - set(REQUIRED_PATTERNS))
        raise ValueError(f"CODEOWNERS inventory differs; missing={missing}, extra={extra}")

    push_logins = {
        item.get("login") for item in collaborators
        if isinstance(item, dict) and isinstance(item.get("permissions"), dict)
        and item["permissions"].get("push") is True
    }
    authority_key = authority.casefold()
    for pattern, owners in entries.items():
        if authority_key not in {owner.casefold() for owner in owners}:
            raise ValueError(f"release authority is not an owner for {pattern}")
        independent = [
            owner for owner in owners
            if owner.casefold() != authority_key
            and any(owner.casefold() == login.casefold() for login in push_logins if isinstance(login, str))
        ]
        if not independent:
            raise ValueError(f"no independent non-authority code owner with push access applies to {pattern}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codeowners", type=pathlib.Path, required=True)
    parser.add_argument("--collaborators", type=pathlib.Path, required=True)
    parser.add_argument("--authority", required=True)
    args = parser.parse_args()
    try:
        collaborators = json.loads(args.collaborators.read_text(encoding="utf-8"))
        if not isinstance(collaborators, list):
            raise ValueError("collaborators JSON must be an array")
        validate(args.codeowners.read_text(encoding="utf-8"), collaborators, args.authority)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"CODEOWNERS audit: {error}", file=sys.stderr)
        return 1
    print("CODEOWNERS audit: every protected pattern has an independent push-capable owner")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
