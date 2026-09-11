#!/usr/bin/env python3
"""Validate the complete canonical GitHub release-protection policy."""

import argparse
import json
import pathlib
import sys

CHECK = "Required verification"
ACTIONS_APP_ID = 15368
IMMUTABLE_NAME = "meshmsg-immutable-v-tags"
CREATION_NAME = "meshmsg-release-tag-authority"


def read(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def enabled(value: object) -> object:
    return value.get("enabled") if isinstance(value, dict) else None


def validate(immutable: dict, creation: dict, main: dict, authority_id: int) -> None:
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
        "name": IMMUTABLE_NAME, "target": "tag", "enforcement": "active", "bypass_actors": [],
        "conditions": tag_condition, "rule_types": ["deletion", "update"],
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
        "name": CREATION_NAME, "target": "tag", "enforcement": "active",
        "bypass_actors": [{"actor_id": authority_id, "actor_type": "User", "bypass_mode": "always"}],
        "conditions": tag_condition, "rule_types": ["creation"],
    }
    if creation_view != expected_creation:
        raise ValueError("v* creation authority differs from canonical policy")

    status = main.get("required_status_checks") or {}
    reviews = main.get("required_pull_request_reviews") or {}
    main_view = {
        "status_strict": status.get("strict"),
        "status_contexts": status.get("contexts"),
        "status_checks": status.get("checks"),
        "enforce_admins": enabled(main.get("enforce_admins")),
        "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews"),
        "require_code_owner_reviews": reviews.get("require_code_owner_reviews"),
        "require_last_push_approval": reviews.get("require_last_push_approval"),
        "required_approving_review_count": reviews.get("required_approving_review_count"),
        "restrictions": main.get("restrictions"),
        "required_linear_history": enabled(main.get("required_linear_history")),
        "allow_force_pushes": enabled(main.get("allow_force_pushes")),
        "allow_deletions": enabled(main.get("allow_deletions")),
        "block_creations": enabled(main.get("block_creations")),
        "required_conversation_resolution": enabled(main.get("required_conversation_resolution")),
        "lock_branch": enabled(main.get("lock_branch")),
        # GitHub normalizes allow_fork_syncing to false while lock_branch=false.
        "allow_fork_syncing": enabled(main.get("allow_fork_syncing")),
    }
    expected_main = {
        "status_strict": True,
        "status_contexts": [CHECK],
        "status_checks": [{"context": CHECK, "app_id": ACTIONS_APP_ID}],
        "enforce_admins": True,
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "require_last_push_approval": True,
        "required_approving_review_count": 1,
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": False,
        "required_conversation_resolution": True,
        "lock_branch": False,
        "allow_fork_syncing": False,
    }
    if main_view != expected_main:
        differing = sorted(key for key in expected_main if main_view.get(key) != expected_main[key])
        raise ValueError(f"main protection differs in canonical fields: {', '.join(differing)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--immutable", type=pathlib.Path, required=True)
    parser.add_argument("--creation", type=pathlib.Path, required=True)
    parser.add_argument("--main", type=pathlib.Path, required=True)
    parser.add_argument("--authority-id", type=int, required=True)
    args = parser.parse_args()
    try:
        validate(read(args.immutable), read(args.creation), read(args.main), args.authority_id)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"GitHub protection audit: {error}", file=sys.stderr)
        return 1
    print("GitHub protection audit: canonical policy active")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
