"""Built-in installers for tools that do not have a reliable package-manager path."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import site
import stat
import sys
import tempfile
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from secscan.tools.base import ToolBase

_DEPENDENCY_CHECK_VERSION_URL = "https://dependency-check.github.io/DependencyCheck/current.txt"
_DEPENDENCY_CHECK_DOWNLOAD_URL = (
    "https://github.com/dependency-check/DependencyCheck/releases/download/"
    "v{version}/dependency-check-{version}-release.zip"
)
_COMPOSER_PHAR_URL = "https://getcomposer.org/composer-stable.phar"
_KUBE_BENCH_RELEASE_API = "https://api.github.com/repos/aquasecurity/kube-bench/releases/latest"
_CARGO_AUDIT_RELEASE_API = "https://api.github.com/repos/rustsec/cargo-audit/releases/latest"


def _user_script_dir() -> Path:
    user_base = Path(site.getuserbase())
    script_dir = user_base / ("Scripts" if os.name == "nt" else "bin")
    script_dir.mkdir(parents=True, exist_ok=True)
    return script_dir


def _tool_root() -> Path:
    root = Path(site.getuserbase()) / "secscan-tools"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url) as response, destination.open("wb") as fh:
        shutil.copyfileobj(response, fh)


def _write_windows_launcher(target: Path, script_dir: Path) -> None:
    launcher = script_dir / "dependency-check.cmd"
    content = f'@echo off\r\ncall "{target}" %*\r\n'
    launcher.write_text(content, encoding="utf-8")


def _write_posix_launcher(target: Path, script_dir: Path) -> None:
    launcher = script_dir / "dependency-check"
    content = f'#!/bin/sh\n"{target}" "$@"\n'
    launcher.write_text(content, encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _machine_name() -> str:
    machine = os.environ.get("PROCESSOR_ARCHITECTURE", "") or os.uname().machine
    return machine.lower()


def install_dependency_check() -> int:
    print("Resolving latest OWASP Dependency-Check version...")
    with urllib.request.urlopen(_DEPENDENCY_CHECK_VERSION_URL) as response:
        version = response.read().decode("utf-8").strip()
    if not version:
        raise RuntimeError("Could not determine the latest Dependency-Check version.")

    download_url = _DEPENDENCY_CHECK_DOWNLOAD_URL.format(version=version)
    install_root = _tool_root() / "dependency-check" / version
    archive_dir = install_root / "_archive"
    extract_dir = install_root / "payload"

    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    archive_path = archive_dir / f"dependency-check-{version}.zip"
    print(f"Downloading Dependency-Check {version}...")
    _download(download_url, archive_path)

    print("Extracting archive...")
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(extract_dir)

    target_name = "dependency-check.bat" if os.name == "nt" else "dependency-check.sh"
    matches = list(extract_dir.rglob(target_name))
    if not matches:
        raise RuntimeError(f"Could not find {target_name} after extraction.")
    target = matches[0]

    script_dir = _user_script_dir()
    if os.name == "nt":
        _write_windows_launcher(target, script_dir)
    else:
        _write_posix_launcher(target, script_dir)

    print(f"Installed Dependency-Check {version} to {install_root}")
    print(f"Launcher created in {script_dir}")
    return 0


def install_composer() -> int:
    php_path = ToolBase._resolve_executable("php")
    if not php_path:
        raise RuntimeError("PHP was not found. Install PHP first so Composer can run.")

    install_root = _tool_root() / "composer"
    install_root.mkdir(parents=True, exist_ok=True)
    phar_path = install_root / "composer.phar"

    print("Downloading Composer...")
    _download(_COMPOSER_PHAR_URL, phar_path)

    script_dir = _user_script_dir()
    if os.name == "nt":
        launcher = script_dir / "composer.cmd"
        launcher.write_text(
            f'@echo off\r\n"{php_path}" "{phar_path}" %*\r\n',
            encoding="utf-8",
        )
    else:
        launcher = script_dir / "composer"
        launcher.write_text(
            f'#!/bin/sh\n"{php_path}" "{phar_path}" "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Installed Composer launcher in {script_dir}")
    return 0


def install_kube_bench() -> int:
    if os.name == "nt":
        raise RuntimeError("kube-bench does not provide a supported Windows CLI build.")

    with urllib.request.urlopen(_KUBE_BENCH_RELEASE_API) as response:
        release = json.load(response)

    tag = str(release.get("tag_name") or "").strip()
    version = tag.lstrip("v")
    if not version:
        raise RuntimeError("Could not determine the latest kube-bench version.")

    platform_key = "darwin" if sys.platform == "darwin" else "linux"
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(_machine_name())
    if not arch:
        raise RuntimeError(f"Unsupported architecture for kube-bench: {_machine_name()}")

    asset_name = f"kube-bench_{version}_{platform_key}_{arch}.tar.gz"
    asset = next(
        (item for item in release.get("assets", []) if item.get("name") == asset_name),
        None,
    )
    if not asset or not asset.get("browser_download_url"):
        raise RuntimeError(f"Could not find a kube-bench asset named {asset_name}.")

    install_root = _tool_root() / "kube-bench" / version
    archive_dir = install_root / "_archive"
    extract_dir = install_root / "payload"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    archive_path = archive_dir / asset_name
    print(f"Downloading kube-bench {version}...")
    _download(str(asset["browser_download_url"]), archive_path)

    print("Extracting archive...")
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(extract_dir)

    matches = list(extract_dir.rglob("kube-bench"))
    if not matches:
        raise RuntimeError("Could not find the kube-bench binary after extraction.")
    target = matches[0]
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    script_dir = _user_script_dir()
    _write_posix_launcher(target, script_dir)
    print(f"Installed kube-bench {version} to {install_root}")
    print(f"Launcher created in {script_dir}")
    return 0


def install_cargo_audit() -> int:
    with urllib.request.urlopen(_CARGO_AUDIT_RELEASE_API) as response:
        release = json.load(response)

    tag = str(release.get("tag_name") or "").strip()
    version = tag.split("/")[-1]
    if not version:
        raise RuntimeError("Could not determine the latest cargo-audit version.")

    if os.name != "nt":
        raise RuntimeError("The built-in cargo-audit downloader is currently only used on Windows.")

    arch_map = {
        "x86_64": "x86_64-pc-windows-msvc",
        "amd64": "x86_64-pc-windows-msvc",
    }
    target = arch_map.get(_machine_name())
    if not target:
        raise RuntimeError(f"Unsupported Windows architecture for cargo-audit: {_machine_name()}")

    asset_name = f"cargo-audit-{target}-{version}.zip"
    asset = next(
        (item for item in release.get("assets", []) if item.get("name") == asset_name),
        None,
    )
    if not asset or not asset.get("browser_download_url"):
        raise RuntimeError(f"Could not find a cargo-audit asset named {asset_name}.")

    install_root = _tool_root() / "cargo-audit" / version
    archive_dir = install_root / "_archive"
    extract_dir = install_root / "payload"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    archive_path = archive_dir / asset_name
    print(f"Downloading cargo-audit {version}...")
    _download(str(asset["browser_download_url"]), archive_path)

    print("Extracting archive...")
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(extract_dir)

    matches = list(extract_dir.rglob("cargo-audit.exe"))
    if not matches:
        raise RuntimeError("Could not find cargo-audit.exe after extraction.")

    script_dir = _user_script_dir()
    destination = script_dir / "cargo-audit.exe"
    shutil.copy2(matches[0], destination)
    print(f"Installed cargo-audit {version} to {destination}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecScan built-in tool installers")
    parser.add_argument("tool", choices=["cargo-audit", "composer", "dependency-check", "kube-bench"])
    args = parser.parse_args(argv)

    if args.tool == "dependency-check":
        return install_dependency_check()
    if args.tool == "cargo-audit":
        return install_cargo_audit()
    if args.tool == "composer":
        return install_composer()
    if args.tool == "kube-bench":
        return install_kube_bench()
    return 1


if __name__ == "__main__":
    sys.exit(main())
