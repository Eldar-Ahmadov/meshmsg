#!/usr/bin/env python3
"""Fail-closed validation and consolidation of meshmsg release archives."""

import argparse
import hashlib
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

TARGETS = (
    ("x86_64-unknown-linux-gnu", ".tar.gz", "meshmsg"),
    ("x86_64-unknown-linux-musl", ".tar.gz", "meshmsg"),
    ("x86_64-pc-windows-msvc", ".zip", "meshmsg.exe"),
)
ROOT_FILES = {"README.md", "LICENSE-MIT", "LICENSE-APACHE"}


def fail(message: str) -> None:
    raise ValueError(message)


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def expected_files(source: pathlib.Path, root: str, binary: str) -> set[str]:
    docs = {
        f"{root}/{path.relative_to(source).as_posix()}"
        for path in (source / "docs").rglob("*") if path.is_file() and not path.is_symlink()
    }
    return {f"{root}/{name}" for name in ROOT_FILES | {binary}} | docs


def validate_members(names: list[str], files: set[str], expected: set[str], root: str) -> None:
    normalized = [name.rstrip("/") for name in names]
    if len(normalized) != len(set(normalized)):
        fail(f"{root}: duplicate archive member")
    allowed_directories = {root}
    for name in expected:
        parent = pathlib.PurePosixPath(name).parent
        while parent.as_posix() != ".":
            allowed_directories.add(parent.as_posix())
            parent = parent.parent
    for name in normalized:
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != root:
            fail(f"{root}: unsafe or wrong archive root: {name}")
        if name not in expected and name not in allowed_directories:
            fail(f"{root}: unexpected archive member: {name}")
    if files != expected:
        fail(f"{root}: archive files differ: missing={sorted(expected-files)} extra={sorted(files-expected)}")


def inspect_archive(archive: pathlib.Path, source: pathlib.Path, tag: str, target: str,
                    suffix: str, binary: str, execute: bool, binary_root: pathlib.Path | None) -> None:
    root = f"meshmsg-{tag}-{target}"
    expected = expected_files(source, root, binary)
    with tempfile.TemporaryDirectory(prefix="meshmsg-archive-") as directory:
        extracted = pathlib.Path(directory)
        if suffix == ".tar.gz":
            with tarfile.open(archive, "r:gz") as package:
                members = package.getmembers()
                if any(not (member.isfile() or member.isdir()) for member in members):
                    fail(f"{archive.name}: links and special members are forbidden")
                files = {member.name for member in members if member.isfile()}
                validate_members([member.name for member in members], files, expected, root)
                binary_member = next(member for member in members if member.name == f"{root}/{binary}")
                if not binary_member.mode & stat.S_IXUSR:
                    fail(f"{archive.name}: binary is not executable")
                package.extractall(extracted)
        else:
            with zipfile.ZipFile(archive) as package:
                infos = package.infolist()
                files = {info.filename for info in infos if not info.is_dir()}
                validate_members([info.filename for info in infos], files, expected, root)
                package.extractall(extracted)
        packaged_binary = extracted / root / binary
        if not packaged_binary.is_file() or packaged_binary.is_symlink():
            fail(f"{archive.name}: expected binary is absent or a link")
        if binary_root is not None:
            built = binary_root / target / "release" / binary
            if digest(packaged_binary) != digest(built):
                fail(f"{archive.name}: packaged binary differs from final built binary")
        if execute:
            if suffix == ".tar.gz":
                packaged_binary.chmod(0o755)
            result = subprocess.run([str(packaged_binary), "--version"], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            expected_version = f"meshmsg {tag[1:]}"
            if result.returncode != 0 or result.stdout.strip() != expected_version or result.stderr:
                fail(f"{archive.name}: version smoke test failed: {result.stdout!r} {result.stderr!r}")


def expected_name(tag: str, target: str, suffix: str) -> str:
    return f"meshmsg-{tag}-{target}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("linux", "windows", "all"), required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--dist", type=pathlib.Path, required=True)
    parser.add_argument("--incoming", type=pathlib.Path)
    parser.add_argument("--binary-root", type=pathlib.Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        selected = [item for item in TARGETS if args.platform == "all" or
                    (args.platform == "linux") == item[0].startswith("x86_64-unknown-linux")]
        if args.platform == "all":
            if args.incoming is None:
                fail("--incoming is required for publisher consolidation")
            linux_dir, windows_dir = args.incoming / "linux", args.incoming / "windows"
            linux_expected = {expected_name(args.tag, *item[:2]) for item in TARGETS[:2]}
            windows_expected = {expected_name(args.tag, *TARGETS[2][:2])}
            for directory, expected in ((linux_dir, linux_expected), (windows_dir, windows_expected)):
                actual = {path.name for path in directory.iterdir()} if directory.is_dir() else set()
                if actual != expected or any(not path.is_file() for path in directory.iterdir()):
                    fail(f"artifact {directory.name} contents differ: expected={sorted(expected)} actual={sorted(actual)}")
            args.dist.mkdir(parents=True, exist_ok=True)
            if any(args.dist.iterdir()):
                fail("publisher dist directory must start empty")
            for directory in (linux_dir, windows_dir):
                for path in directory.iterdir():
                    shutil.copy2(path, args.dist / path.name)
        actual_names = {path.name for path in args.dist.iterdir()} if args.dist.is_dir() else set()
        expected_names = {expected_name(args.tag, target, suffix) for target, suffix, _ in selected}
        if actual_names != expected_names:
            fail(f"dist archive set differs: expected={sorted(expected_names)} actual={sorted(actual_names)}")
        for target, suffix, binary in selected:
            inspect_archive(args.dist / expected_name(args.tag, target, suffix), args.source, args.tag,
                            target, suffix, binary, args.execute, args.binary_root)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"release assets: {error}", file=sys.stderr)
        return 1
    print("release assets: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
