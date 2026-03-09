"""GitHub OAuth Device Flow helpers for desktop login."""

from __future__ import annotations

import json
import os
import time
from typing import Optional

import requests

_DEVICE_CODE_URL = "https://github.com/login/device/code"
_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_API_URL = "https://api.github.com/user"
_SCOPES = "repo read:user"

_SERVICE_NAME = "secscan"
_TOKEN_ACCOUNT = "github_oauth_token"
_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".secscan")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "github_oauth.json")


def load_oauth_client_id() -> str:
    """Load OAuth client id from env or local config."""
    env_id = os.environ.get("GITHUB_OAUTH_CLIENT_ID", "").strip()
    if env_id:
        return env_id
    data = _load_config()
    return str(data.get("client_id", "")).strip()


def save_oauth_client_id(client_id: str) -> None:
    """Save OAuth client id for future runs."""
    data = _load_config()
    data["client_id"] = (client_id or "").strip()
    _save_config(data)


def start_device_flow(client_id: str) -> dict:
    """Start GitHub device flow and return device payload."""
    cid = (client_id or "").strip()
    if not cid:
        raise RuntimeError("GitHub OAuth Client ID is required.")

    resp = requests.post(
        _DEVICE_CODE_URL,
        headers={"Accept": "application/json"},
        data={"client_id": cid, "scope": _SCOPES},
        timeout=20,
    )
    if resp.status_code >= 400:
        raise RuntimeError(_extract_error(resp))

    payload = resp.json()
    if "device_code" not in payload:
        raise RuntimeError(f"Unexpected GitHub response: {payload}")
    return payload


def poll_device_flow(client_id: str, device_code: str, interval: int, expires_in: int) -> str:
    """Poll GitHub until an OAuth access token is issued."""
    cid = (client_id or "").strip()
    dcode = (device_code or "").strip()
    if not cid or not dcode:
        raise RuntimeError("Invalid OAuth device code state.")

    start = time.time()
    wait_s = max(int(interval or 5), 1)
    timeout_s = max(int(expires_in or 900), 30)

    while (time.time() - start) < timeout_s:
        resp = requests.post(
            _ACCESS_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": cid,
                "device_code": dcode,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            timeout=20,
        )
        if resp.status_code >= 400:
            raise RuntimeError(_extract_error(resp))

        payload = resp.json()
        token = payload.get("access_token")
        if token:
            return str(token)

        err = str(payload.get("error", ""))
        if err == "authorization_pending":
            time.sleep(wait_s)
            continue
        if err == "slow_down":
            wait_s += 5
            time.sleep(wait_s)
            continue
        if err == "expired_token":
            raise RuntimeError("GitHub device code expired. Please sign in again.")
        if err == "access_denied":
            raise RuntimeError("GitHub sign-in denied.")
        if err:
            raise RuntimeError(err.replace("_", " ").capitalize())

        time.sleep(wait_s)

    raise RuntimeError("GitHub sign-in timed out. Please try again.")


def fetch_github_username(token: str) -> str:
    """Return authenticated GitHub username for a token."""
    tok = (token or "").strip()
    if not tok:
        raise RuntimeError("Missing GitHub access token.")

    resp = requests.get(
        _USER_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {tok}",
        },
        timeout=20,
    )
    if resp.status_code >= 400:
        raise RuntimeError(_extract_error(resp))
    payload = resp.json()
    login = str(payload.get("login", "")).strip()
    if not login:
        raise RuntimeError("Could not read GitHub username from token.")
    return login


def save_access_token(token: str) -> None:
    """Store access token in keyring if available, else local file."""
    tok = (token or "").strip()
    if not tok:
        return

    if _try_keyring_set(tok):
        return

    data = _load_config()
    data["access_token"] = tok
    _save_config(data)


def load_access_token() -> str:
    """Load saved access token."""
    token = _try_keyring_get()
    if token:
        return token
    data = _load_config()
    return str(data.get("access_token", "")).strip()


def clear_access_token() -> None:
    """Delete saved access token."""
    _try_keyring_delete()
    data = _load_config()
    if "access_token" in data:
        del data["access_token"]
        _save_config(data)


def _extract_error(resp: requests.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict):
            msg = str(data.get("error_description") or data.get("message") or "")
            if msg:
                return msg
    except Exception:
        pass
    return f"HTTP {resp.status_code}: {resp.text[:300]}"


def _load_config() -> dict:
    try:
        if not os.path.isfile(_CONFIG_FILE):
            return {}
        with open(_CONFIG_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_config(data: dict) -> None:
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _try_keyring_set(token: str) -> bool:
    try:
        import keyring  # type: ignore
        keyring.set_password(_SERVICE_NAME, _TOKEN_ACCOUNT, token)
        return True
    except Exception:
        return False


def _try_keyring_get() -> str:
    try:
        import keyring  # type: ignore
        value = keyring.get_password(_SERVICE_NAME, _TOKEN_ACCOUNT)
        return str(value).strip() if value else ""
    except Exception:
        return ""


def _try_keyring_delete() -> None:
    try:
        import keyring  # type: ignore
        keyring.delete_password(_SERVICE_NAME, _TOKEN_ACCOUNT)
    except Exception:
        return
