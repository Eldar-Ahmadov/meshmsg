#!/usr/bin/env python3
"""Adversarial fixtures for tagged release metadata and checkout binding."""

import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tests/validate-release-metadata.py"
ELIGIBILITY = ROOT / "tests/check-release-eligibility.sh"
ADMISSION = ROOT / "tests/check-release-admission.sh"
TAG = "v1.2.3"
VERSION = "1.2.3"
CANONICAL_NOTES = f"""# meshmsg {TAG}

Release fixture.

```sh
cargo install --git https://github.com/Eldar-Ahmadov/meshmsg \\
  --tag {TAG} --locked --force
```
"""
CARGO = f'[package]\nname = "meshmsg"\nversion = "{VERSION}"\n'
LOCK = f'version = 4\n\n[[package]]\nname = "meshmsg"\nversion = "{VERSION}"\n'


def run(
    *args: str, cwd: pathlib.Path | None = None, ok: bool = True, env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    result = subprocess.run(args, cwd=cwd, env=process_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (result.returncode == 0) != ok:
        raise AssertionError(
            f"unexpected exit {result.returncode} for {' '.join(args)}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def write_metadata(root: pathlib.Path, notes: str = CANONICAL_NOTES) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    cargo = root / "Cargo.toml"
    lock = root / "Cargo.lock"
    note = root / ".github/release-notes" / f"{TAG}.md"
    note.parent.mkdir(parents=True, exist_ok=True)
    cargo.write_text(CARGO, encoding="utf-8")
    lock.write_text(LOCK, encoding="utf-8")
    note.write_text(notes, encoding="utf-8")
    return cargo, lock, note


def validate_fixture(root: pathlib.Path, notes: str, ok: bool) -> None:
    cargo, lock, note = write_metadata(root, notes)
    run(
        "python3", str(VALIDATOR), "--tag", TAG, "--cargo", str(cargo),
        "--lock", str(lock), "--notes", str(note), ok=ok,
    )


def metadata_tests(base: pathlib.Path) -> None:
    cases = {
        "valid": (CANONICAL_NOTES, True),
        "duplicate": (CANONICAL_NOTES + "\n" + CANONICAL_NOTES.split("\n", 2)[2], False),
        "contradictory-tag": (CANONICAL_NOTES + "\nUse --tag v9.9.9 instead.\n", False),
        "wrong-repository": (CANONICAL_NOTES.replace("Eldar-Ahmadov/meshmsg", "attacker/meshmsg"), False),
        "missing-fence": (CANONICAL_NOTES.replace("```sh\n", "").replace("\n```\n", "\n"), False),
        "extra-argument": (CANONICAL_NOTES.replace("--locked --force", "--locked --force --root /tmp/x"), False),
        "one-line": (CANONICAL_NOTES.replace(" \\\n  --tag", " --tag"), False),
        "wrong-heading": (CANONICAL_NOTES.replace(f"# meshmsg {TAG}", "# meshmsg v9.9.9"), False),
    }
    for name, (notes, expected) in cases.items():
        fixture = base / f"metadata-{name}"
        fixture.mkdir()
        validate_fixture(fixture, notes, expected)


def eligibility_tests(base: pathlib.Path) -> None:
    remote = base / "remote.git"
    repo = base / "repo"
    run("git", "init", "--bare", str(remote))
    run("git", "init", "-b", "main", str(repo))
    run("git", "config", "user.name", "Release Contract", cwd=repo)
    run("git", "config", "user.email", "release@example.invalid", cwd=repo)
    write_metadata(repo)
    run("git", "add", ".", cwd=repo)
    run("git", "commit", "-m", "release", cwd=repo)
    release_sha = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
    run("git", "tag", TAG, cwd=repo)
    run("git", "remote", "add", "origin", str(remote), cwd=repo)
    run("git", "push", "origin", "main", TAG, cwd=repo)
    run("bash", str(ELIGIBILITY), "admission", TAG, release_sha, cwd=repo)
    run("bash", str(ELIGIBILITY), "recheck", TAG, release_sha, cwd=repo)

    # A dirty metadata worktree must not substitute content for the tagged commit.
    (repo / "Cargo.toml").write_text(CARGO.replace(VERSION, "9.9.9"), encoding="utf-8")
    run("bash", str(ELIGIBILITY), "admission", TAG, release_sha, cwd=repo, ok=False)
    run("git", "restore", "Cargo.toml", cwd=repo)

    # A checkout of another commit is rejected even if the tag remains on main.
    (repo / "README.md").write_text("later\n", encoding="utf-8")
    run("git", "add", "README.md", cwd=repo)
    run("git", "commit", "-m", "later", cwd=repo)
    run("git", "push", "origin", "main", cwd=repo)
    run("bash", str(ELIGIBILITY), "recheck", TAG, release_sha, cwd=repo, ok=False)

    # Normal first-parent advancement rejects a fresh admission but does not
    # brick an already-admitted in-flight release or a proved rerun.
    run("git", "checkout", "--detach", release_sha, cwd=repo)
    run("bash", str(ELIGIBILITY), "admission", TAG, release_sha, cwd=repo, ok=False)
    run("bash", str(ELIGIBILITY), "recheck", TAG, release_sha, cwd=repo)

    mock_bin = base / "mock-bin"
    mock_bin.mkdir()
    mock_gh = mock_bin / "gh"
    mock_gh.write_text("""#!/usr/bin/env python3
import json, os, sys
endpoint = sys.argv[-1]
if endpoint.endswith('/actions/runs/4242'):
    print(json.dumps({'event': 'push', 'head_sha': os.environ['MOCK_HEAD']}))
elif '/attempts/1/jobs' in endpoint:
    conclusion = 'success' if os.environ.get('MOCK_ADMISSION') == 'success' else 'failure'
    print(json.dumps({'jobs': [{'name': 'Initial release admission', 'status': 'completed', 'conclusion': conclusion}]}))
else:
    raise SystemExit(2)
""", encoding="utf-8")
    mock_gh.chmod(0o755)
    rerun_env = {
        "PATH": f"{mock_bin}{os.pathsep}{os.environ['PATH']}", "GH_TOKEN": "fixture",
        "GITHUB_REPOSITORY": "fixture/meshmsg", "MOCK_HEAD": release_sha,
        "MOCK_ADMISSION": "success",
    }
    run("bash", str(ADMISSION), TAG, release_sha, "4242", "2", cwd=repo, env=rerun_env)
    run("bash", str(ADMISSION), TAG, release_sha, "4242", "2", cwd=repo,
        env={**rerun_env, "MOCK_ADMISSION": "failure"}, ok=False)
    run("bash", str(ADMISSION), TAG, release_sha, "4242", "2", cwd=repo,
        env={**rerun_env, "MOCK_HEAD": "0" * 40}, ok=False)

    # Every phase still binds the remote immutable tag to the event commit.
    later_sha = run("git", "rev-parse", "origin/main", cwd=repo).stdout.strip()
    run("git", "tag", "--force", TAG, later_sha, cwd=repo)
    run("git", "push", "--force", "origin", TAG, cwd=repo)
    run("bash", str(ELIGIBILITY), "recheck", TAG, release_sha, cwd=repo, ok=False)

    # Restoring the tag is insufficient if protected main history was rewritten.
    run("git", "tag", "--force", TAG, release_sha, cwd=repo)
    run("git", "push", "--force", "origin", TAG, cwd=repo)
    tree = run("git", "rev-parse", f"{release_sha}^{{tree}}", cwd=repo).stdout.strip()
    rewritten = run("git", "commit-tree", tree, cwd=repo).stdout.strip()
    run("git", "push", "--force", "origin", f"{rewritten}:refs/heads/main", cwd=repo)
    run("bash", str(ELIGIBILITY), "recheck", TAG, release_sha, cwd=repo, ok=False)


with tempfile.TemporaryDirectory(prefix="meshmsg-release-contract-") as directory:
    base = pathlib.Path(directory)
    metadata_tests(base)
    eligibility_tests(base)
print("release contract fixtures: ok")
