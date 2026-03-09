"""Tool installer manager and worker for background auto-install flows."""

from __future__ import annotations

import subprocess
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal


class InstallWorker(QObject):
    """Install tools sequentially in a worker thread."""

    log = Signal(str)
    progress = Signal(int)
    finished = Signal(object)

    def __init__(self, tools: list, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._tools = tools
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        summary = {
            "installed": [],
            "failed": [],
            "skipped": [],
        }

        total = max(len(self._tools), 1)
        for idx, tool in enumerate(self._tools):
            if self._stopped:
                break

            self.progress.emit(int((idx / total) * 100))

            if tool.is_installed():
                summary["skipped"].append(tool.name)
                self.log.emit(f"Skipping {tool.name} (already installed).")
                continue

            commands = tool.install_commands()
            if not commands:
                summary["failed"].append((tool.name, "No auto-install command available."))
                self.log.emit(f"No auto-install command for {tool.name}.")
                continue

            installed = False
            last_error = "Unknown error"

            for args in commands:
                if self._stopped:
                    break

                cmd_text = " ".join(args)
                self.log.emit(f"Installing {tool.name}: {cmd_text}")

                try:
                    proc = subprocess.run(
                        args,
                        capture_output=True,
                        text=True,
                        timeout=1800,
                    )
                except Exception as exc:
                    last_error = str(exc)
                    self.log.emit(f"Failed to run installer for {tool.name}: {exc}")
                    continue

                if proc.returncode == 0 and tool.is_installed():
                    installed = True
                    summary["installed"].append(tool.name)
                    self.log.emit(f"Installed {tool.name}.")
                    break

                stderr = (proc.stderr or "").strip()
                stdout = (proc.stdout or "").strip()
                if stderr:
                    last_error = stderr.splitlines()[-1]
                elif stdout:
                    last_error = stdout.splitlines()[-1]
                else:
                    last_error = f"Command exited with code {proc.returncode}."

            if not installed and not self._stopped:
                summary["failed"].append((tool.name, last_error))
                self.log.emit(f"Could not auto-install {tool.name}: {last_error}")

        self.progress.emit(100)
        self.finished.emit(summary)


class InstallManager(QObject):
    """Manage InstallWorker + QThread lifecycle."""

    log = Signal(str)
    progress = Signal(int)
    finished = Signal(object)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._thread: Optional[QThread] = None
        self._worker: Optional[InstallWorker] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def start(self, tools: list):
        if self.is_running:
            return

        self._thread = QThread()
        self._worker = InstallWorker(tools)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self.log.emit)
        self._worker.progress.connect(self.progress.emit)
        self._worker.finished.connect(self._on_finished)

        self._thread.start()

    def stop(self):
        if self._worker:
            self._worker.stop()

    def _on_finished(self, summary: dict):
        self.finished.emit(summary)
        if self._thread:
            self._thread.quit()
            self._thread.wait()
            self._thread = None
            self._worker = None
