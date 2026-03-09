# SPDX-License-Identifier: MIT
# Copyright (c) SecScan Contributors
# See LICENSE and SECURITY.md for usage terms
"""Helpers for importing GitHub repositories for scanning."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from urllib.parse import urlsplit, urlunsplit


def clone_or_update_github_repo(
    repo_url: str,
    dest_root: str,
    branch: str = "",
    token: str = "",
) -> tuple[str, str]:
    """Clone or update a repository under *dest_root*.

    Returns:
        (local_repo_path, action_message)
    """
    if not shutil.which("git"):
        raise RuntimeError("Git is not installed or not found in PATH.")

    clean_url = (repo_url or "").strip()
    auth_token = (token or "").strip()
    try:
        if not clean_url:
            raise RuntimeError("Repository URL is required.")

        clean_url = _normalize_repo_url(clean_url)
        repo_name = _repo_name_from_url(clean_url)
        os.makedirs(dest_root, exist_ok=True)
        dest_path = os.path.join(dest_root, repo_name)

        if os.path.isdir(os.path.join(dest_path, ".git")):
            _set_origin_url(dest_path, clean_url)
            _run(["git", "-C", dest_path, "fetch", "--all", "--prune"], auth_token, clean_url)
            if branch:
                _run(["git", "-C", dest_path, "checkout", branch], auth_token, clean_url)
                _run(["git", "-C", dest_path, "pull", "origin", branch], auth_token, clean_url)
            else:
                _run(["git", "-C", dest_path, "pull", "--ff-only"], auth_token, clean_url)
            return dest_path, "Repository updated."

        clone_cmd = ["git", "clone", clean_url, dest_path]
        if branch:
            clone_cmd = ["git", "clone", "--branch", branch, "--single-branch", clean_url, dest_path]
        _run(clone_cmd, auth_token, clean_url)
        _set_origin_url(dest_path, clean_url)
        return dest_path, "Repository cloned."
    finally:
        auth_token = ""


def _run(args: list[str], token: str, repo_url: str = "") -> None:
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=1800,
        env=_git_env(token, repo_url),
    )
    if proc.returncode == 0:
        return

    stderr = _mask_secret((proc.stderr or "").strip(), token)
    stdout = _mask_secret((proc.stdout or "").strip(), token)
    msg = stderr or stdout or f"Command failed with exit code {proc.returncode}"
    raise RuntimeError(msg)


def _normalize_repo_url(repo_url: str) -> str:
    text = repo_url.strip()
    if text.startswith("http://") or text.startswith("https://") or text.startswith("git@"):
        return _strip_auth_from_url(text)
    # Support shorthand: owner/repo
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text):
        return f"https://github.com/{text}.git"
    raise RuntimeError("Invalid GitHub repository URL.")


def _repo_name_from_url(repo_url: str) -> str:
    text = repo_url.rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    name = text.split("/")[-1] or "repo"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name


def _set_origin_url(dest_path: str, repo_url: str) -> None:
    subprocess.run(
        ["git", "-C", dest_path, "remote", "set-url", "origin", repo_url],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _git_env(token: str, repo_url: str) -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")

    tok = (token or "").strip()
    if not tok:
        return env
    if not repo_url.startswith("https://"):
        return env

    parts = urlsplit(repo_url)
    host = parts.netloc.split("@")[-1]
    base_url = urlunsplit((parts.scheme, host, "/", "", ""))
    auth_url = urlunsplit((parts.scheme, f"x-access-token:{tok}@{host}", "/", "", ""))

    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = f"url.{auth_url}.insteadOf"
    env["GIT_CONFIG_VALUE_0"] = base_url
    return env


def _strip_auth_from_url(repo_url: str) -> str:
    if not repo_url.startswith(("http://", "https://")):
        return repo_url

    parts = urlsplit(repo_url)
    host = parts.netloc.split("@")[-1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _mask_secret(text: str, token: str) -> str:
    tok = (token or "").strip()
    if not tok:
        return text
    return text.replace(tok, "***")
