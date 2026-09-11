#!/usr/bin/env python3
"""Fixture coverage for strict release archive validation and consolidation."""

import argparse
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tests/verify-release-assets.py"
TARGETS = (
    ("x86_64-unknown-linux-gnu", ".tar.gz", "meshmsg"),
    ("x86_64-unknown-linux-musl", ".tar.gz", "meshmsg"),
    ("x86_64-pc-windows-msvc", ".zip", "meshmsg.exe"),
)


def run(args: list[str], ok: bool = True) -> None:
    result = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"unexpected result {result.returncode}: {args}\n{result.stdout}\n{result.stderr}")


def make_archive(dist: pathlib.Path, binary_root: pathlib.Path, source_binary: pathlib.Path,
                 tag: str, target: str, suffix: str, binary: str) -> None:
    name = f"meshmsg-{tag}-{target}"
    tree = dist.parent / f"tree-{target}" / name
    (tree / "docs").mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_binary, tree / binary)
    (tree / binary).chmod(0o755)
    for item in ("README.md", "LICENSE-MIT", "LICENSE-APACHE"):
        shutil.copy2(ROOT / item, tree / item)
    shutil.copytree(ROOT / "docs", tree / "docs", dirs_exist_ok=True)
    built = binary_root / target / "release" / binary
    built.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_binary, built)
    archive = dist / f"{name}{suffix}"
    if suffix == ".tar.gz":
        with tarfile.open(archive, "w:gz") as package:
            package.add(tree, arcname=name)
    else:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            for path in tree.rglob("*"):
                package.write(path, pathlib.Path(name) / path.relative_to(tree))


parser = argparse.ArgumentParser()
parser.add_argument("--bin", type=pathlib.Path, default=ROOT / "target/debug/meshmsg")
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="meshmsg-release-assets-") as directory:
    base = pathlib.Path(directory)
    source_binary = args.bin.resolve()
    if not source_binary.is_file():
        source_binary = base / "meshmsg"
        source_binary.write_text("#!/bin/sh\nprintf 'meshmsg 1.2.3\\n'\n", encoding="utf-8")
        source_binary.chmod(0o755)
    tag = "v" + subprocess.check_output([str(source_binary), "--version"], text=True).split()[1]
    dist, binary_root = base / "dist", base / "target"
    dist.mkdir()
    for target, suffix, binary in TARGETS:
        make_archive(dist, binary_root, source_binary, tag, target, suffix, binary)
    windows = dist / f"meshmsg-{tag}-x86_64-pc-windows-msvc.zip"
    windows_hold = base / windows.name
    windows.rename(windows_hold)
    run(["python3", str(VERIFIER), "--platform", "linux", "--tag", tag,
         "--source", str(ROOT), "--dist", str(dist), "--binary-root", str(binary_root), "--execute"])
    windows_hold.rename(windows)

    # Exact members are enforced, not only the archive filename/root.
    gnu_tree = base / "tree-x86_64-unknown-linux-gnu" / f"meshmsg-{tag}-x86_64-unknown-linux-gnu"
    (gnu_tree / "EXTRA").write_text("unexpected", encoding="utf-8")
    make_archive(dist, binary_root, source_binary, tag, *TARGETS[0])
    run(["python3", str(VERIFIER), "--platform", "linux", "--tag", tag,
         "--source", str(ROOT), "--dist", str(dist), "--binary-root", str(binary_root)], ok=False)
    (gnu_tree / "EXTRA").unlink()
    make_archive(dist, binary_root, source_binary, tag, *TARGETS[0])

    incoming = base / "incoming"
    (incoming / "linux").mkdir(parents=True)
    (incoming / "windows").mkdir()
    for archive in dist.iterdir():
        destination = incoming / ("linux" if archive.name.endswith(".tar.gz") else "windows") / archive.name
        shutil.copy2(archive, destination)
    consolidated = base / "consolidated"
    run(["python3", str(VERIFIER), "--platform", "all", "--tag", tag,
         "--source", str(ROOT), "--incoming", str(incoming), "--dist", str(consolidated)])

    (incoming / "linux/EXTRA").write_text("unexpected", encoding="utf-8")
    run(["python3", str(VERIFIER), "--platform", "all", "--tag", tag,
         "--source", str(ROOT), "--incoming", str(incoming), "--dist", str(base / "bad")], ok=False)

print("release asset fixtures: ok")
