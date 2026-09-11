#!/usr/bin/env python3
"""Validate version and release-note metadata extracted from one Git commit."""

import argparse
import pathlib
import re
import sys

REPOSITORY = "https://github.com/Eldar-Ahmadov/meshmsg"


def fail(message: str) -> None:
    raise ValueError(message)


def validate(tag: str, cargo_path: pathlib.Path, lock_path: pathlib.Path, notes_path: pathlib.Path) -> None:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        fail(f"release tag must have form vMAJOR.MINOR.PATCH: {tag}")
    version = tag[1:]
    cargo = cargo_path.read_text(encoding="utf-8")
    package_sections = re.findall(r"(?ms)^\[package\][ \t]*\n(.*?)(?=^\[|\Z)", cargo)
    if len(package_sections) != 1:
        fail("Cargo.toml must contain exactly one [package] section")
    package_versions = re.findall(r'^version[ \t]*=[ \t]*"([^"]+)"[ \t]*$', package_sections[0], re.MULTILINE)
    if package_versions != [version]:
        fail(f"tag {tag} does not match one exact Cargo.toml package version")

    lock = lock_path.read_text(encoding="utf-8")
    package_blocks = re.findall(r"(?ms)^\[\[package\]\][ \t]*\n(.*?)(?=^\[\[package\]\]|\Z)", lock)
    meshmsg_versions = []
    for block in package_blocks:
        names = re.findall(r'^name[ \t]*=[ \t]*"([^"]+)"[ \t]*$', block, re.MULTILINE)
        versions = re.findall(r'^version[ \t]*=[ \t]*"([^"]+)"[ \t]*$', block, re.MULTILINE)
        if names == ["meshmsg"]:
            meshmsg_versions.extend(versions)
    if meshmsg_versions != [version]:
        fail(f"tag {tag} does not match one exact meshmsg Cargo.lock package version")

    notes = notes_path.read_text(encoding="utf-8")
    lines = notes.splitlines()
    if not lines or lines[0] != f"# meshmsg {tag}":
        fail(f"release notes must start with '# meshmsg {tag}'")

    canonical = (
        f"cargo install --git {REPOSITORY} \\\n"
        f"  --tag {tag} --locked --force"
    )
    fenced = re.findall(r"^```(?:sh|bash)?[ \t]*\n(.*?)^```[ \t]*$", notes, re.MULTILINE | re.DOTALL)
    canonical_blocks = [body.rstrip("\n") for body in fenced if body.rstrip("\n") == canonical]
    if len(canonical_blocks) != 1:
        fail("release notes must contain exactly one canonical fenced cargo-install command")
    if notes.count("cargo install") != 1:
        fail("release notes contain duplicate or contradictory cargo-install commands")
    # Any other tag argument is contradictory even if it is not attached to a
    # cargo command (for example a malformed copied installation snippet).
    tag_args = re.findall(r"(?:^|\s)--tag\s+(\S+)", notes)
    if tag_args != [tag]:
        fail(f"release notes must contain exactly one --tag argument equal to {tag}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--cargo", type=pathlib.Path, required=True)
    parser.add_argument("--lock", type=pathlib.Path, required=True)
    parser.add_argument("--notes", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        validate(args.tag, args.cargo, args.lock, args.notes)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"release metadata: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
