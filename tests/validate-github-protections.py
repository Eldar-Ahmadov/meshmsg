#!/usr/bin/env python3
"""Validate the complete canonical GitHub release-tag protection policy."""

import argparse
import json
import pathlib
import sys

IMMUTABLE_NAME = "meshmsg-immutable-v-tags"
CREATION_NAME = "meshmsg-release-tag-authority"


def read(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def validate(immutable: dict, creation: dict, authority_id: int) -> None:
    tag_condition = {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}}
    immutable_view = {
        "name": immutable.get("name"),
        "target": immutable.get("target"),
        "enforcement": immutable.get("enforcement"),
        "bypass_actors": immutable.get("bypass_actors"),
        "conditions": immutable.get("conditions"),
        "rule_types": sorted(rule.get("type") for rule in immutable.get("rules", [])),
    }
    expected_immutable = {
        "name": IMMUTABLE_NAME,
        "target": "tag",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": tag_condition,
        "rule_types": ["deletion", "update"],
    }
    if immutable_view != expected_immutable:
        raise ValueError("immutable v* tag ruleset differs from canonical policy")

    creation_view = {
        "name": creation.get("name"),
        "target": creation.get("target"),
        "enforcement": creation.get("enforcement"),
        "bypass_actors": creation.get("bypass_actors"),
        "conditions": creation.get("conditions"),
        "rule_types": [rule.get("type") for rule in creation.get("rules", [])],
    }
    expected_creation = {
        "name": CREATION_NAME,
        "target": "tag",
        "enforcement": "active",
        "bypass_actors": [
            {"actor_id": authority_id, "actor_type": "User", "bypass_mode": "always"}
        ],
        "conditions": tag_condition,
        "rule_types": ["creation"],
    }
    if creation_view != expected_creation:
        raise ValueError("v* creation authority differs from canonical policy")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--immutable", type=pathlib.Path, required=True)
    parser.add_argument("--creation", type=pathlib.Path, required=True)
    parser.add_argument("--authority-id", type=int, required=True)
    args = parser.parse_args()
    try:
        validate(read(args.immutable), read(args.creation), args.authority_id)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"GitHub protection audit: {error}", file=sys.stderr)
        return 1
    print("GitHub protection audit: canonical release-tag policy active")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
