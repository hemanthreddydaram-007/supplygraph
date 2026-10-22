# SupplyGraph - Automated Test Suite & Post-Install Detonation Engine v3.0
# Verifies runtime stability via sandboxed test runs and performs live detonation
# of installation lifecycle hooks to catch supply-chain tampering and exfiltration.

import os
import sys
import json
import re
import time
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from app.execution.sandbox import SecureSandboxRunner, SandboxResult
from app.models.core import UploadedFile

logger = logging.getLogger(__name__)


@dataclass
class DetonationReport:
    hook_name: str
    command: str
    status: str  # "clean", "suspicious", "violation", "error"
    alerts: List[str] = field(default_factory=list)
    exit_code: int = 0
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""


@dataclass
class TestSuiteReport:
    framework: str  # "pytest", "npm_test", "none"
    passed: bool
    total_tests: int = 0
    duration_seconds: float = 0.0
    output: str = ""
    error_message: Optional[str] = None



# Patterns for outbound-tool interception (Fix #5: Mock curl/wget blocking)
_BLOCKED_EXFIL_TOOLS = [
    "curl", "wget", "nc", "netcat", "ncat",
    "python -c", "python3 -c", "python -m http",
    "certutil", "bitsadmin", "scp", "rsync",
    "ftp", "tftp", "telnet",
]

# Regex patterns that match dangerous execution flows
_BLOCKED_PIPE_PATTERNS = [
    re.compile(r'curl\s+.*\|\s*(bash|sh|python|node|ruby|perl)', re.IGNORECASE),
    re.compile(r'wget\s+.*-O\s*-?\s*\|', re.IGNORECASE),
    re.compile(r'bash\s+-c\s+["\'].*curl', re.IGNORECASE),
    re.compile(r'eval\s*\(\s*(curl|wget)', re.IGNORECASE),
]


def _intercept_blocked_command(cmd_str: str) -> List[str]:
    """
    Pre-execution command scanner. Returns a list of block-reason strings
    if the command should NOT be executed (contains known exfil tools/patterns).
    Empty list means command is safe to attempt execution.
    """
    blocked: List[str] = []
    cmd_lower = cmd_str.lower()

    for tool in _BLOCKED_EXFIL_TOOLS:
        if tool in cmd_lower:
            blocked.append(
                f"[BLOCKED] Sandbox watchdog intercepted outbound command containing '{tool}'. "
                f"Network exfiltration tools are disabled in the sandboxed environment."
            )
            break  # One block message is sufficient

    for pattern in _BLOCKED_PIPE_PATTERNS:
        if pattern.search(cmd_str):
            blocked.append(
                f"[BLOCKED] Sandbox watchdog intercepted remote-script-pipe pattern "
                f"(e.g. `curl | bash`). This is a known supply-chain attack vector."
            )
            break

    return blocked


class DetonationService:
    """
    Executes automated test runner suites and simulates installation lifecycle hook detonation
    inside a secure, isolated sandbox to detect malicious post-install behavior.
    """

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    def detonate_raw_script(self, script_content: str, filename: str = "script.sh") -> DetonationReport:
        """
        Fix #4: Detonate a raw script string (no manifest) in the sandbox.
        Performs static interception of outbound tools + safe execution.
        """
        ext = os.path.splitext(filename)[1].lower()
        alerts: List[str] = []
        violations: List[str] = []

        # Phase 1: Static pre-execution analysis
        for line in script_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue
            blocked = _intercept_blocked_command(line_stripped)
            if blocked:
                violations.extend(blocked)

        # Phase 2: Dangerous pattern regex scan on full content
        for pattern in _BLOCKED_PIPE_PATTERNS:
            if pattern.search(script_content):
                violations.append(
                    "[BLOCKED] Remote-execution pipe pattern detected in script body "
                    "(curl/wget piped to shell interpreter)."
                )
                break

        # Phase 3: Execute the script in sandbox (if no critical blocks)
        stdout_log = ""
        stderr_log = ""
        exit_code = 0
        duration = 0.0

        if violations:
            # Don't execute — just report what was blocked
            stdout_log = "\n".join(violations)
            status = "violation"
        else:
            with SecureSandboxRunner(timeout_seconds=self.timeout_seconds) as sandbox:
                sandbox.write_file(filename, script_content)
                if ext in (".py",):
                    cmd = ["python", filename]
                elif ext in (".sh", ".bash"):
                    cmd = ["bash", filename]
                elif ext in (".js",):
                    cmd = ["node", filename]
                else:
                    # Try sh for unknown/no extension
                    cmd = ["sh", filename]

                start = time.time()
                res = sandbox.run(cmd, timeout=self.timeout_seconds)
                duration = time.time() - start

                stdout_log = res.stdout
                stderr_log = res.stderr
                exit_code = res.exit_code
                violations.extend(res.security_violations)
                alerts.extend(res.security_violations)
                status = "violation" if violations else ("error" if not res.success else "clean")

        return DetonationReport(
            hook_name=f"raw_script:{filename}",
            command=f"sandbox exec {filename}",
            status=status,
            alerts=alerts,
            exit_code=exit_code,
            duration_seconds=round(duration, 3),
            stdout=stdout_log,
            stderr=stderr_log,
        )

    def detonate_project_hooks(self, files: List[UploadedFile]) -> List[DetonationReport]:
        """
        Extracts and detonates package lifecycle hooks (e.g. preinstall, postinstall)
        inside an isolated sandbox environment.
        """
        reports: List[DetonationReport] = []

        # Find package.json
        pkg_file = next((f for f in files if os.path.basename(f.path).lower() == "package.json"), None)
        if not pkg_file:
            # Check setup.py for custom install commands
            setup_file = next((f for f in files if os.path.basename(f.path).lower() == "setup.py"), None)
            if setup_file and "cmdclass" in setup_file.content:
                reports.append(
                    DetonationReport(
                        hook_name="setup.py:cmdclass",
                        command="python setup.py install",
                        status="suspicious",
                        alerts=["Custom install command (`cmdclass`) detected in setup.py."],
                        stdout="Static AST flagged custom install hook override."
                    )
                )
            return reports

        try:
            pkg_data = json.loads(pkg_file.content)
            scripts = pkg_data.get("scripts", {})
        except Exception:
            return reports

        lifecycle_hooks = ["preinstall", "install", "postinstall", "prepublish"]

        with SecureSandboxRunner(timeout_seconds=self.timeout_seconds) as sandbox:
            # Write all project files to sandbox
            for f in files:
                sandbox.write_file(f.path, f.content)

            for hook in lifecycle_hooks:
                if hook not in scripts:
                    continue

                cmd_str = str(scripts[hook]).strip()
                alerts: List[str] = []

                # Static inspection of hook command
                if any(x in cmd_str.lower() for x in ["curl", "wget", "http://", "https://"]):
                    alerts.append(f"Lifecycle hook `{hook}` attempts outbound network communication: '{cmd_str}'")
                if any(x in cmd_str.lower() for x in ["base64", "openssl", "certutil"]):
                    alerts.append(f"Lifecycle hook `{hook}` uses payload decoding utilities: '{cmd_str}'")
                if any(x in cmd_str.lower() for x in ["powershell", "cmd.exe", "sh -c", "bash -c"]):
                    alerts.append(f"Lifecycle hook `{hook}` spawns dynamic subshells: '{cmd_str}'")
                if any(x in cmd_str.lower() for x in ["rm -rf", "del /f", "format"]):
                    alerts.append(f"Lifecycle hook `{hook}` contains destructive file deletion commands: '{cmd_str}'")

                # Fix #5: Pre-execution watchdog intercept — block curl/wget/nc before execution
                pre_block = _intercept_blocked_command(cmd_str)
                if pre_block:
                    alerts.extend(pre_block)
                    all_alerts = alerts
                    reports.append(
                        DetonationReport(
                            hook_name=hook,
                            command=cmd_str,
                            status="violation",
                            alerts=all_alerts,
                            exit_code=1,
                            duration_seconds=0.0,
                            stdout="\n".join(pre_block),
                            stderr=""
                        )
                    )
                    continue  # Skip actual execution

                # Tokenize simple command
                cmd_tokens = cmd_str.split()
                start_time = time.time()
                run_res = sandbox.run(cmd_tokens, timeout=self.timeout_seconds)
                duration = time.time() - start_time

                # Combine alerts with sandbox security violations
                all_alerts = alerts + run_res.security_violations
                status = "violation" if all_alerts else ("clean" if run_res.success else "error")

                reports.append(
                    DetonationReport(
                        hook_name=hook,
                        command=cmd_str,
                        status=status,
                        alerts=all_alerts,
                        exit_code=run_res.exit_code,
                        duration_seconds=round(duration, 3),
                        stdout=run_res.stdout,
                        stderr=run_res.stderr
                    )
                )

        return reports

    def run_automated_tests(self, files: List[UploadedFile]) -> TestSuiteReport:
        """
        Auto-detects test suites (pytest or npm test) and executes them
        within the isolated sandbox.
        """
        has_python_tests = any(
            f.path.endswith("_test.py") or f.path.startswith("test_") or "tests/" in f.path or "/test/" in f.path
            for f in files
        )
        has_package_json = any(os.path.basename(f.path).lower() == "package.json" for f in files)

        if not has_python_tests and not has_package_json:
            return TestSuiteReport(
                framework="none",
                passed=True,
                total_tests=0,
                output="No automated test suites (pytest or npm test) detected in project files."
            )

        with SecureSandboxRunner(timeout_seconds=self.timeout_seconds) as sandbox:
            for f in files:
                sandbox.write_file(f.path, f.content)

            # 1. Python Pytest Test Runner
            if has_python_tests:
                start_time = time.time()
                res = sandbox.run([sys.executable, "-m", "pytest", "--tb=short", "-q"], timeout=self.timeout_seconds)
                duration = time.time() - start_time

                # Parse test counts from output
                total_tests = 0
                match = re.search(r'(\d+)\s+passed', res.stdout)
                if match:
                    total_tests += int(match.group(1))
                match_fail = re.search(r'(\d+)\s+failed', res.stdout)
                if match_fail:
                    total_tests += int(match_fail.group(1))

                return TestSuiteReport(
                    framework="pytest",
                    passed=res.success,
                    total_tests=total_tests,
                    duration_seconds=round(duration, 3),
                    output=(res.stdout + "\n" + res.stderr).strip(),
                    error_message=None if res.success else "One or more pytest test assertions failed in sandbox."
                )

            # 2. Node npm test runner
            elif has_package_json:
                start_time = time.time()
                res = sandbox.run(["npm", "test"], timeout=self.timeout_seconds)
                duration = time.time() - start_time

                return TestSuiteReport(
                    framework="npm_test",
                    passed=res.success,
                    total_tests=1 if res.success else 0,
                    duration_seconds=round(duration, 3),
                    output=(res.stdout + "\n" + res.stderr).strip(),
                    error_message=None if res.success else "npm test failed in sandbox."
                )

        return TestSuiteReport(framework="none", passed=True, output="Tests completed.")
