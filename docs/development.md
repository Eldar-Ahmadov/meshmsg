# Development

## Authoritative checks

`.github/workflows/verification.yml` is the only GitHub Actions definition of the
branch and release quality gates. `ci.yml` and `release.yml` call it; release
packaging cannot start until verification succeeds for the exact event SHA.
The reusable aggregate appears in Actions as
`verification / Reusable verification aggregate`. CI deliberately follows it
with a tiny caller-owned aggregate named **`Required verification`**. That stable,
prefix-free caller name is the only status configured in main branch protection,
so reusable-workflow display-name changes cannot silently weaken or deadlock the
repository rule.

The pinned toolchain in `rust-toolchain.toml` is used locally and in Actions. Run
the non-networked/static and Rust portions with:

```sh
ruby tests/workflow-contract.rb
python3 tests/release-contract-tests.py
python3 tests/release-assets-tests.py --bin target/debug/meshmsg
python3 tests/github-protection-contract-tests.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
bash -n install.sh tests/*.sh scripts/*.sh
python3 -m py_compile tests/*.py
node --check src/web/app.js
node --check src/web/settings.js
node --check tests/web-ui.cjs
node tests/web-ui.cjs
bash tests/integration-installer.sh target/debug/meshmsg
```

Authoritative verification installs actionlint v1.7.12 from immutable upstream
commit `914e7df21a07ef503a81201c76d2b11c789d3fca` and runs it over all workflows.
For local use, install that exact commit with Go or verify the published Linux
archive against SHA-256
`8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8`.

The complete Linux integration inventory is parsed from
`tests/linux-integration-inventory.tsv` by one driver:

```sh
bash tests/run-linux-integrations.sh target/debug/meshmsg
```

It includes CLI errors, fake/real web, peer directory, five-peer, attachments,
direct messages, published IPC compatibility, idempotency, checksum-pinned
v0.1.18 boundaries, persistent-state migration/restart, and a generated-archive/
mock-download installer test. The per-command budgets total under 97 minutes.
The workflow allows 130 minutes,
including setup/build/cleanup, while the driver rejects an inventory above its
115-minute command budget.

The networking harnesses require working Iroh networking and download
checksum-pinned historical artifacts. The Node UI check uses a DOM mock, not a
mobile browser. No harness changes Tailscale configuration. See
[web validation limits](web.md#tests-and-validation-limits).

Dependency policy uses pinned tool versions:

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo install cargo-deny --version 0.20.2 --locked
cargo audit
cargo deny check advisories bans licenses sources
```

Every main push, pull request, and release tag runs formatting, locked tests and
builds, warnings-denied Clippy, installer/shell/Python/JavaScript syntax checks,
the complete Linux integration inventory, native Windows tests/Clippy/build, and
dependency audit/policy checks.

### Workflow contract defenses and limits

`tests/workflow-contract.rb` uses parsed YAML objects—not comments or broad file
substrings—to assert triggers, permissions, exact action pins, exact step IDs and
commands, gate dependencies/order, artifact smoke-before-upload ordering, and the
stable aggregate names. It runs mutations proving that omitted/commented,
disabled, renamed, reordered, and removed gates fail. actionlint independently
checks GitHub expression/workflow semantics. Release metadata and archive tools
have adversarial fixture tests for malformed commands, wrong checkouts/worktrees,
duplicate notes, extra artifacts, and archive structure.

These checks are defense in depth, not a substitute for GitHub enforcement: an
administrator can change repository settings or replace both a policy and its
tests in one reviewed change. Branch/ruleset settings therefore have a separate
API-backed audit below, and reviewers must treat changes to workflows, scripts,
`rust-toolchain.toml`, and protection documentation as security-sensitive.

## Releases

A release tag must be exactly `vMAJOR.MINOR.PATCH`. Initial admission fetches
`origin/main` and the remote tag afresh and requires the remote tag, checked-out
`HEAD`, full `github.sha`, and current `origin/main` tip to be the same commit. A workflow rerun may use historical-main semantics only after the
read-only Actions API proves that this same run ID/SHA had a successful
**Initial release admission** in an earlier attempt.

Immediately before draft creation and immediately before making the draft
public, eligibility is fetched again and requires:

- the unchanged remote tag, checked-out `HEAD`, and full event SHA to resolve to
  the originally admitted commit;
- that commit to remain on current `origin/main` first-parent history,
  allowing normal main advancement without bricking an admitted run or proved
  rerun while rejecting rewritten/divergent history;
- no worktree differences in package/lock/release-note metadata;
- `Cargo.toml`, `Cargo.lock`, and release notes extracted with `git show` from
  that commit to match the tag;
- exactly one canonical fenced install command:

```sh
cargo install --git https://github.com/Eldar-Ahmadov/meshmsg \
  --tag vX.Y.Z --locked --force
```

Duplicate, contradictory, one-line, unfenced, wrong-repository, wrong-tag, or
extra-argument variants fail. The publisher also extracts the notes from the
commit and creates/edits the release with `--target <exact SHA>`.

Final GNU, musl, and static-CRT Windows builds are packaged first, then extracted
and inspected before artifact upload. The runner executes each platform's
packaged binary and requires exact `meshmsg X.Y.Z` output. Windows resolves `dumpbin`
through canonical `vswhere` discovery plus `vcvars64.bat`, exercises that exact
lookup during regular Windows verification, and uses the resolved executable's
`/dependents` output to reject dynamic MSVC runtime dependencies. The
publisher downloads only `release-linux` and `release-windows` by exact name,
rejects unexpected files, validates one archive root and every member, requires
the binary, complete docs, README, and both licenses, and checks that packaged
binaries equal the final runner builds. It then generates the unchanged three-
archive `SHA256SUMS` layout. Published releases are never overwritten; reruns may
replace only a draft.

## GitHub release-tag protections

GitHub settings are external state, so `scripts/github-release-protections.sh`
provides an auditable setup and drift check for the release-tag rulesets. It uses
GitHub's documented [repository rulesets](https://docs.github.com/rest/repos/rules)
API, never invokes interactive login, and never widens credentials:

```sh
# Read-only verification (recommended before creating a release tag):
scripts/github-release-protections.sh --check

# Intentional idempotent administration change for the tag rulesets:
scripts/github-release-protections.sh --apply
```

The canonical release-tag policy is:

- `meshmsg-immutable-v-tags`: no bypass actors; update and deletion of
  `refs/tags/v*` are prohibited;
- `meshmsg-release-tag-authority`: creation of `refs/tags/v*` is prohibited
  except for the configured release authority (`Eldar-Ahmadov` by default).

The rules remain layered: creation authority cannot bypass immutability.
`tests/validate-github-protections.py` compares the normalized tag policy and its
mutation fixtures change every relevant field. The release workflow relies on
GitHub enforcing these rules at tag creation and independently binds admission,
verification, artifacts, notes, and publication to the exact immutable tag SHA.
It does not require main branch protection, a pull request, CODEOWNERS approval,
or an additional protection-audit secret.

`main` is intentionally unprotected and may be updated directly. Pull-request CI
still exposes `Required verification` as a useful aggregate, but it is not a
branch-protection prerequisite.

Override repository/authority only for an intentional fork administration
operation with `GITHUB_REPOSITORY` and `MESHMSG_RELEASE_AUTHORITY`. If auth or API
scope fails, stop and have an authorized administrator apply the canonical tag
policy; never log in interactively in CI or weaken the immutable tag rules.
