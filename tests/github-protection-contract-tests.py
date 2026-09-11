#!/usr/bin/env python3
"""Mutation coverage for every canonical GitHub protection invariant."""

import copy
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("protection_validator", ROOT / "tests/validate-github-protections.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
codeowners_spec = importlib.util.spec_from_file_location("codeowners_validator", ROOT / "tests/validate-codeowners.py")
codeowners_module = importlib.util.module_from_spec(codeowners_spec)
assert codeowners_spec.loader is not None
codeowners_spec.loader.exec_module(codeowners_module)
AUTHORITY = 1690591

immutable = {
    "name": "meshmsg-immutable-v-tags",
    "target": "tag", "enforcement": "active", "bypass_actors": [],
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "update"}, {"type": "deletion"}],
}
creation = {
    "name": "meshmsg-release-tag-authority",
    "target": "tag", "enforcement": "active",
    "bypass_actors": [{"actor_id": AUTHORITY, "actor_type": "User", "bypass_mode": "always"}],
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "creation"}],
}
main = {
    "required_status_checks": {
        "strict": True, "contexts": ["Required verification"],
        "checks": [{"context": "Required verification", "app_id": 15368}],
    },
    "enforce_admins": {"enabled": True},
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True, "require_code_owner_reviews": True,
        "require_last_push_approval": True, "required_approving_review_count": 1,
    },
    "restrictions": None,
    "required_linear_history": {"enabled": False},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
    "block_creations": {"enabled": False},
    "required_conversation_resolution": {"enabled": True},
    "lock_branch": {"enabled": False},
    "allow_fork_syncing": {"enabled": False},
}
module.validate(immutable, creation, main, AUTHORITY)

mutations = []
def mutate(label, area, function):
    mutations.append((label, area, function))

for field, bad in (("name", "wrong"), ("target", "branch"), ("enforcement", "disabled"), ("bypass_actors", [{"actor_id": 1}])):
    mutate(f"immutable {field}", "immutable", lambda value, f=field, b=bad: value.__setitem__(f, b))
mutate("immutable include", "immutable", lambda value: value["conditions"]["ref_name"].__setitem__("include", ["refs/tags/x*"]))
mutate("immutable exclude", "immutable", lambda value: value["conditions"]["ref_name"].__setitem__("exclude", ["refs/tags/v1"]))
mutate("immutable update", "immutable", lambda value: value["rules"].pop(0))
mutate("immutable deletion", "immutable", lambda value: value["rules"].pop())

for field, bad in (("name", "wrong"), ("target", "branch"), ("enforcement", "disabled")):
    mutate(f"creation {field}", "creation", lambda value, f=field, b=bad: value.__setitem__(f, b))
mutate("creation authority", "creation", lambda value: value["bypass_actors"][0].__setitem__("actor_id", 7))
mutate("creation actor type", "creation", lambda value: value["bypass_actors"][0].__setitem__("actor_type", "Team"))
mutate("creation bypass mode", "creation", lambda value: value["bypass_actors"][0].__setitem__("bypass_mode", "pull_request"))
mutate("creation include", "creation", lambda value: value["conditions"]["ref_name"].__setitem__("include", ["refs/tags/*"]))
mutate("creation exclude", "creation", lambda value: value["conditions"]["ref_name"].__setitem__("exclude", ["refs/tags/v2"]))
mutate("creation rule", "creation", lambda value: value.__setitem__("rules", []))

main_paths = {
    "status strict": ("required_status_checks", "strict"),
    "status contexts": ("required_status_checks", "contexts"),
    "status checks": ("required_status_checks", "checks"),
    "enforce admins": ("enforce_admins", "enabled"),
    "dismiss stale": ("required_pull_request_reviews", "dismiss_stale_reviews"),
    "code owners": ("required_pull_request_reviews", "require_code_owner_reviews"),
    "last push": ("required_pull_request_reviews", "require_last_push_approval"),
    "approval count": ("required_pull_request_reviews", "required_approving_review_count"),
    "linear history": ("required_linear_history", "enabled"),
    "force pushes": ("allow_force_pushes", "enabled"),
    "deletions": ("allow_deletions", "enabled"),
    "block creations": ("block_creations", "enabled"),
    "conversation resolution": ("required_conversation_resolution", "enabled"),
    "lock branch": ("lock_branch", "enabled"),
    "fork syncing normalization": ("allow_fork_syncing", "enabled"),
}
for label, path in main_paths.items():
    def change(value, p=path):
        current = value[p[0]][p[1]]
        value[p[0]][p[1]] = 0 if current == 1 else not current if isinstance(current, bool) else []
    mutate(label, "main", change)
mutate("restrictions", "main", lambda value: value.__setitem__("restrictions", {"users": []}))

for label, area, function in mutations:
    values = [copy.deepcopy(immutable), copy.deepcopy(creation), copy.deepcopy(main)]
    function(values[{"immutable": 0, "creation": 1, "main": 2}[area]])
    try:
        module.validate(*values, AUTHORITY)
    except ValueError:
        continue
    raise AssertionError(f"protection mutation was accepted: {label}")

patterns = codeowners_module.REQUIRED_PATTERNS
canonical_codeowners = "\n".join(f"{pattern} @Eldar-Ahmadov @reviewer" for pattern in patterns) + "\n"
push_reviewer = [{"login": "reviewer", "permissions": {"push": True}}]
codeowners_module.validate(canonical_codeowners, push_reviewer, "Eldar-Ahmadov")
codeowner_negatives = {
    "collaborator-but-not-code-owner": ("\n".join(f"{p} @Eldar-Ahmadov" for p in patterns), push_reviewer),
    "code-owner-without-push": (canonical_codeowners, [{"login": "reviewer", "permissions": {"push": False}}]),
    "different-push-collaborator": (canonical_codeowners, [{"login": "other", "permissions": {"push": True}}]),
    "missing-pattern": ("\n".join(f"{p} @Eldar-Ahmadov @reviewer" for p in patterns[:-1]), push_reviewer),
    "extra-pattern": (canonical_codeowners + "/unexpected @Eldar-Ahmadov @reviewer\n", push_reviewer),
    "duplicate-pattern": (canonical_codeowners + f"{patterns[0]} @Eldar-Ahmadov @reviewer\n", push_reviewer),
    "authority-absent": (canonical_codeowners.replace("@Eldar-Ahmadov ", "", 1), push_reviewer),
}
for label, (text, collaborators) in codeowner_negatives.items():
    try:
        codeowners_module.validate(text, collaborators, "Eldar-Ahmadov")
    except ValueError:
        continue
    raise AssertionError(f"CODEOWNERS mutation was accepted: {label}")

print(f"GitHub protection contract fixtures: ok ({len(mutations)} policy and {len(codeowner_negatives)} CODEOWNERS mutations)")
