#!/usr/bin/env python3
"""Mutation coverage for every canonical release-tag protection invariant."""

import copy
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "protection_validator", ROOT / "tests/validate-github-protections.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
AUTHORITY = 1690591

immutable = {
    "name": "meshmsg-immutable-v-tags",
    "target": "tag",
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "update"}, {"type": "deletion"}],
}
creation = {
    "name": "meshmsg-release-tag-authority",
    "target": "tag",
    "enforcement": "active",
    "bypass_actors": [
        {"actor_id": AUTHORITY, "actor_type": "User", "bypass_mode": "always"}
    ],
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "creation"}],
}
module.validate(immutable, creation, AUTHORITY)

mutations = []


def mutate(label, area, function):
    mutations.append((label, area, function))


for field, bad in (
    ("name", "wrong"),
    ("target", "branch"),
    ("enforcement", "disabled"),
    ("bypass_actors", [{"actor_id": 1}]),
):
    mutate(
        f"immutable {field}",
        "immutable",
        lambda value, f=field, b=bad: value.__setitem__(f, b),
    )
mutate(
    "immutable include",
    "immutable",
    lambda value: value["conditions"]["ref_name"].__setitem__(
        "include", ["refs/tags/x*"]
    ),
)
mutate(
    "immutable exclude",
    "immutable",
    lambda value: value["conditions"]["ref_name"].__setitem__(
        "exclude", ["refs/tags/v1"]
    ),
)
mutate("immutable update", "immutable", lambda value: value["rules"].pop(0))
mutate("immutable deletion", "immutable", lambda value: value["rules"].pop())

for field, bad in (
    ("name", "wrong"),
    ("target", "branch"),
    ("enforcement", "disabled"),
):
    mutate(
        f"creation {field}",
        "creation",
        lambda value, f=field, b=bad: value.__setitem__(f, b),
    )
mutate(
    "creation authority",
    "creation",
    lambda value: value["bypass_actors"][0].__setitem__("actor_id", 7),
)
mutate(
    "creation actor type",
    "creation",
    lambda value: value["bypass_actors"][0].__setitem__("actor_type", "Team"),
)
mutate(
    "creation bypass mode",
    "creation",
    lambda value: value["bypass_actors"][0].__setitem__(
        "bypass_mode", "pull_request"
    ),
)
mutate(
    "creation include",
    "creation",
    lambda value: value["conditions"]["ref_name"].__setitem__(
        "include", ["refs/tags/*"]
    ),
)
mutate(
    "creation exclude",
    "creation",
    lambda value: value["conditions"]["ref_name"].__setitem__(
        "exclude", ["refs/tags/v2"]
    ),
)
mutate("creation rule", "creation", lambda value: value.__setitem__("rules", []))

for label, area, function in mutations:
    values = [copy.deepcopy(immutable), copy.deepcopy(creation)]
    function(values[{"immutable": 0, "creation": 1}[area]])
    try:
        module.validate(*values, AUTHORITY)
    except ValueError:
        continue
    raise AssertionError(f"protection mutation was accepted: {label}")

print(f"GitHub release-tag protection contract fixtures: ok ({len(mutations)} mutations)")
