"""Abstract base class for all scanner tool adapters."""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Callable, ClassVar, List, Optional

from secscan.core.schema import Finding


class ToolBase(ABC):
    """Every scanner adapter must subclass this and implement the interface."""

    # Human-readable name shown in the UI
    name: str = "Unknown Tool"

    # Short description
    description: str = ""

    # The CLI command used to check installation
    cli_command: str = ""

    # Mapping of CLI name -> pip package for tools installable in Python env.
    _PIP_INSTALL_MAP = {
        "checkov": "checkov",
        "semgrep": "semgrep",
        "pip-audit": "pip-audit",
        "safety": "safety",
        "sqlmap": "sqlmap",
        "bandit": "bandit",
    }
    _live_log_callback: ClassVar[Optional[Callable[[str], None]]] = None
    _live_log_enabled: ClassVar[bool] = False

    # ------------------------------------------------------------------ #
    def is_installed(self) -> bool:
        """Return True if the external tool binary is available on PATH."""
        if not self.cli_command:
            return True  # Pure-Python tools need no external binary
        return self._resolve_executable(self.cli_command) is not None

    @abstractmethod
    def is_applicable(self, project_path: str) -> bool:
        """Return True if this tool should be offered for the given project."""
        ...

    def install_instructions(self) -> str:
        """Human-readable instructions to install the external tool."""
        return f"Please install '{self.cli_command}' and make sure it is on your PATH."

    def install_commands(self) -> List[List[str]]:
        """Return command candidates that can auto-install this tool.

        Commands are tried in order until the tool is detected on PATH.
        """
        cmd = (self.cli_command or "").strip().lower()
        if not cmd:
            return []

        is_windows = os.name == "nt"
        has = lambda name: shutil.which(name) is not None

        pip_pkg = self._PIP_INSTALL_MAP.get(cmd)
        if pip_pkg:
            return [[sys.executable, "-m", "pip", "install", pip_pkg]]

        if cmd in ("npm", "npx"):
            if has("npm"):
                return []
            commands: List[List[str]] = []
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "OpenJS.NodeJS.LTS",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if is_windows and has("choco"):
                commands.append(["choco", "install", "-y", "nodejs-lts"])
            return commands

        if cmd == "gitleaks":
            commands = []
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "Gitleaks.Gitleaks",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if is_windows and has("choco"):
                commands.append(["choco", "install", "-y", "gitleaks"])
            if has("brew"):
                commands.append(["brew", "install", "gitleaks"])
            return commands

        if cmd == "trivy":
            commands = []
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "AquaSecurity.Trivy",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if is_windows and has("choco"):
                commands.append(["choco", "install", "-y", "trivy"])
            if has("brew"):
                commands.append(["brew", "install", "trivy"])
            return commands

        if cmd == "grype":
            commands = []
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "Anchore.Grype",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if is_windows and has("choco"):
                commands.append(["choco", "install", "-y", "grype"])
            if has("brew"):
                commands.append(["brew", "install", "grype"])
            return commands

        if cmd == "osv-scanner":
            commands = []
            if has("go"):
                commands.append(
                    [
                        "go", "install",
                        "github.com/google/osv-scanner/cmd/osv-scanner@latest",
                    ]
                )
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "Google.OSVScanner",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if is_windows and has("choco"):
                commands.append(["choco", "install", "-y", "osv-scanner"])
            if has("brew"):
                commands.append(["brew", "install", "osv-scanner"])
            return commands

        if cmd == "amass":
            commands = []
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "OWASP.Amass",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if is_windows and has("choco"):
                commands.append(["choco", "install", "-y", "amass"])
            if has("brew"):
                commands.append(["brew", "install", "amass"])
            return commands

        if cmd == "dependency-check":
            commands = []
            if is_windows and has("winget"):
                commands.append(
                    [
                        "winget", "install",
                        "--id", "OWASP.DependencyCheck",
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]
                )
            if has("brew"):
                commands.append(["brew", "install", "dependency-check"])
            return commands

        return []

    def supports_auto_install(self) -> bool:
        """Return True if this tool has at least one auto-install command."""
        return bool(self.install_commands())

    @abstractmethod
    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        """Execute the scan and return normalized findings."""
        ...

    # ------------------------------------------------------------------ #
    # Helpers for subclasses
    # ------------------------------------------------------------------ #
    @staticmethod
    def _run_cmd(
        args: List[str],
        cwd: Optional[str] = None,
        timeout: int = 300,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess, capturing stdout and stderr."""
        if args:
            resolved = ToolBase._resolve_executable(args[0])
            if resolved:
                args = [resolved] + args[1:]
        proc = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if ToolBase._live_log_enabled and ToolBase._live_log_callback:
            try:
                cmd_text = " ".join(args)
                ToolBase._live_log_callback(f"[cmd] {cmd_text}")
                if proc.stdout:
                    for line in proc.stdout.splitlines():
                        ToolBase._live_log_callback(line)
                if proc.stderr:
                    for line in proc.stderr.splitlines():
                        ToolBase._live_log_callback(f"[stderr] {line}")
            except Exception:
                pass
        return proc

    @classmethod
    def configure_live_logging(
        cls, callback: Optional[Callable[[str], None]], enabled: bool
    ) -> None:
        """Set shared callback for full subprocess logs."""
        cls._live_log_callback = callback
        cls._live_log_enabled = enabled

    @staticmethod
    def _resolve_executable(command: str) -> Optional[str]:
        """Resolve a CLI name to an executable path.

        On Windows, also search Winget package directories where portable binaries
        may be installed without being added to PATH.
        """
        if not command:
            return None

        found = shutil.which(command)
        if found:
            return found

        # Also check the active interpreter's script directory (venv-safe).
        exe_dir = os.path.dirname(sys.executable)
        candidates = [command]
        if os.name == "nt":
            lower = command.lower()
            if not lower.endswith(".exe"):
                candidates.append(f"{command}.exe")
            if not lower.endswith(".cmd"):
                candidates.append(f"{command}.cmd")
            if not lower.endswith(".bat"):
                candidates.append(f"{command}.bat")
        for cand in candidates:
            full = os.path.join(exe_dir, cand)
            if os.path.isfile(full):
                return full

        if os.name != "nt":
            return None

        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if not local_app_data:
            return None

        winget_packages = os.path.join(
            local_app_data, "Microsoft", "WinGet", "Packages"
        )
        if not os.path.isdir(winget_packages):
            return None

        exe_name = command if command.lower().endswith(".exe") else f"{command}.exe"
        pattern = os.path.join(winget_packages, "*", exe_name)
        matches = glob.glob(pattern)
        if not matches:
            return None

        # Pick most recently modified candidate to prefer latest package version.
        matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return matches[0]

    @staticmethod
    def _save_raw(raw_dir: str, filename: str, content: str) -> str:
        """Persist raw tool output for debugging."""
        if not raw_dir:
            return ""
        os.makedirs(raw_dir, exist_ok=True)
        path = os.path.join(raw_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path
