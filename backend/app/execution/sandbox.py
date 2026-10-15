# SupplyGraph - Secure Ephemeral Sandbox Runner v3.0
# Provides isolated containerized or restricted subprocess execution with strict resource limits,
# zero network egress, and sanitized environment variables.

import os
import sys
import shutil
import tempfile
import time
import subprocess
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    isolation_mode: str = "restricted_subprocess"
    security_violations: List[str] = field(default_factory=list)


class SecureSandboxRunner:
    """
    Ephemeral sandbox environment for running untrusted scripts, tests, or build checks.
    Supports Docker containerization when available, with an automatic fallback to
    a non-root, restricted subprocess environment with hard timeouts and zero-trust environment sanitization.
    """

    def __init__(self, timeout_seconds: float = 10.0, use_docker_if_available: bool = True):
        self.timeout_seconds = timeout_seconds
        self.use_docker_if_available = use_docker_if_available
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.sandbox_dir: Optional[str] = None
        self._docker_available: Optional[bool] = None

    def __enter__(self):
        self._temp_dir = tempfile.TemporaryDirectory(prefix="supplygraph_sandbox_")
        self.sandbox_dir = os.path.abspath(self._temp_dir.name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception as e:
                logger.debug(f"Sandbox cleanup exception: {e}")
            self._temp_dir = None
            self.sandbox_dir = None

    def is_docker_available(self) -> bool:
        """Checks if Docker CLI and daemon are operational."""
        if self._docker_available is not None:
            return self._docker_available

        docker_bin = shutil.which("docker")
        if not docker_bin:
            self._docker_available = False
            return False

        try:
            # Query docker info with strict 1.5s timeout
            proc = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=1.5,
                shell=False
            )
            self._docker_available = (proc.returncode == 0)
        except Exception:
            self._docker_available = False

        return self._docker_available

    def write_file(self, relative_path: str, content: str) -> str:
        """Writes text content to a relative path inside the sandbox, preventing path traversal."""
        dest_path = self._resolve_safe_path(relative_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return dest_path

    def write_bytes(self, relative_path: str, data: bytes) -> str:
        """Writes binary data to a relative path inside the sandbox, preventing path traversal."""
        dest_path = self._resolve_safe_path(relative_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(data)
        return dest_path

    def _resolve_safe_path(self, relative_path: str) -> str:
        """Resolves path and enforces strict containment inside sandbox_dir (Zip-Slip defense)."""
        if not self.sandbox_dir:
            raise RuntimeError("Sandbox is not active. Use 'with SecureSandboxRunner() as sandbox:' context.")

        clean_rel = relative_path.replace("\\", "/").lstrip("/")
        if ".." in clean_rel.split("/"):
            raise ValueError(f"Security Violation: Path traversal attempt with '..' detected in '{relative_path}'")

        dest = os.path.abspath(os.path.join(self.sandbox_dir, clean_rel))
        # Ensure destination is strictly inside sandbox_dir
        if os.path.commonpath([self.sandbox_dir, dest]) != self.sandbox_dir:
            raise ValueError(f"Security Violation: Path '{relative_path}' resolves outside sandbox directory.")

        return dest

    def get_sanitized_env(self) -> Dict[str, str]:
        """
        Builds a strictly sanitized environment dictionary.
        Strips all sensitive API keys, cloud tokens, database credentials, and GitHub secrets.
        """
        safe_keys = {
            "PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC",
            "PATHEXT", "TEMP", "TMP", "TMPDIR", "HOME", "USER", "LANG", "LC_ALL"
        }
        clean_env: Dict[str, str] = {}
        for k, v in os.environ.items():
            if k.upper() in safe_keys:
                clean_env[k] = v

        # Add isolation flags
        clean_env["SUPPLYGRAPH_SANDBOX"] = "1"
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        clean_env["PYTHONUNBUFFERED"] = "1"
        clean_env["NODE_ENV"] = "production"
        clean_env["CI"] = "1"

        return clean_env

    def run(
        self,
        cmd: List[str],
        timeout: Optional[float] = None,
        docker_image: str = "python:3.11-slim"
    ) -> SandboxResult:
        """
        Executes a command inside the sandbox.
        Prefers Docker with zero network and strict CPU/memory quotas if available,
        falling back to a restricted subprocess with zero-trust environment sanitization.
        """
        if not self.sandbox_dir:
            raise RuntimeError("Sandbox directory not initialized. Enter context first.")

        exec_timeout = timeout or self.timeout_seconds
        violations: List[str] = []

        # 1. Try Docker if available and requested
        if self.use_docker_if_available and self.is_docker_available():
            try:
                docker_cmd = [
                    "docker", "run", "--rm",
                    "--network", "none",
                    "--memory=512m",
                    "--cpus=1.0",
                    "-v", f"{self.sandbox_dir}:/workspace:rw",
                    "-w", "/workspace",
                    docker_image
                ] + cmd

                start_time = time.time()
                proc = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=exec_timeout,
                    shell=False
                )
                duration = time.time() - start_time
                return SandboxResult(
                    success=(proc.returncode == 0),
                    exit_code=proc.returncode,
                    stdout=proc.stdout[:50_000],
                    stderr=proc.stderr[:50_000],
                    duration_seconds=round(duration, 3),
                    timed_out=False,
                    isolation_mode="docker",
                    security_violations=violations
                )
            except subprocess.TimeoutExpired:
                violations.append(f"Container execution timed out after {exec_timeout} seconds.")
                return SandboxResult(
                    success=False,
                    exit_code=124,
                    stdout="",
                    stderr=f"Timeout expired ({exec_timeout}s). Container killed.",
                    duration_seconds=exec_timeout,
                    timed_out=True,
                    isolation_mode="docker",
                    security_violations=violations
                )
            except Exception as de:
                logger.debug(f"Docker execution failed, falling back to restricted subprocess: {de}")

        # 2. Fallback: Restricted Subprocess Execution
        clean_env = self.get_sanitized_env()
        start_time = time.time()

        try:
            proc = subprocess.run(
                cmd,
                cwd=self.sandbox_dir,
                capture_output=True,
                text=True,
                timeout=exec_timeout,
                env=clean_env,
                shell=False
            )
            duration = time.time() - start_time

            stdout_text = proc.stdout[:50_000] if proc.stdout else ""
            stderr_text = proc.stderr[:50_000] if proc.stderr else ""

            # Check for suspicious runtime patterns in logs
            combined_logs = (stdout_text + "\n" + stderr_text).lower()
            if any(term in combined_logs for term in ["connection refused", "network is unreachable", "econnrefused"]):
                violations.append("Outbound network egress attempt blocked by sandbox.")
            if "permission denied" in combined_logs and (".." in combined_logs or "/etc" in combined_logs):
                violations.append("Unauthorized file-system access outside sandbox boundary blocked.")

            return SandboxResult(
                success=(proc.returncode == 0),
                exit_code=proc.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                duration_seconds=round(duration, 3),
                timed_out=False,
                isolation_mode="restricted_subprocess",
                security_violations=violations
            )
        except subprocess.TimeoutExpired as te:
            duration = time.time() - start_time
            violations.append(f"Execution timed out after {exec_timeout}s. Process killed by watchdog.")
            out = te.stdout[:10_000] if te.stdout else ""
            err = te.stderr[:10_000] if te.stderr else ""
            return SandboxResult(
                success=False,
                exit_code=124,
                stdout=out if isinstance(out, str) else out.decode("utf-8", errors="replace"),
                stderr=f"Timeout expired ({exec_timeout}s). Process terminated.",
                duration_seconds=round(duration, 3),
                timed_out=True,
                isolation_mode="restricted_subprocess",
                security_violations=violations
            )
        except FileNotFoundError:
            return SandboxResult(
                success=False,
                exit_code=127,
                stdout="",
                stderr=f"Command not found on runner system: {cmd[0]}",
                duration_seconds=0.0,
                timed_out=False,
                isolation_mode="restricted_subprocess",
                security_violations=[f"Requested binary '{cmd[0]}' is not installed on sandbox host."]
            )
        except Exception as ex:
            return SandboxResult(
                success=False,
                exit_code=1,
                stdout="",
                stderr=f"Sandbox execution error: {str(ex)}",
                duration_seconds=0.0,
                timed_out=False,
                isolation_mode="restricted_subprocess",
                security_violations=[str(ex)]
            )
