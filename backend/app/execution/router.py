# SupplyGraph - Multi-Format File Parser & Interpreter Router v3.0
# Dispatches incoming files, archives, manifests, and binaries to the appropriate
# secure sandboxed execution or static analysis pipeline with Zip-Slip defense.

import os
import sys
import re
import json
import base64
import zipfile
import tarfile
import uuid
import logging
from typing import List, Dict, Optional, Any, Tuple
from app.models.core import SandboxExecutionRequest, SandboxExecutionResponse, UploadedFile
from app.execution.sandbox import SecureSandboxRunner, SandboxResult

logger = logging.getLogger(__name__)


class ExecutionRouter:
    """
    Multi-format file interpreter router.
    Routes source code scripts, build manifests, binary files, and archives
    to appropriate secure analysis and execution pipelines.
    """

    BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".bin", ".dylib", ".wasm", ".o", ".a"}
    SCRIPT_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".ps1", ".cmd", ".bat"}
    MANIFEST_NAMES = {"package.json", "pyproject.toml", "cargo.toml", "pom.xml", "go.mod", "requirements.txt", "setup.py"}
    ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".whl"}

    def __init__(self):
        pass

    def route_and_execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResponse:
        """
        Main entry point for sandbox execution request.
        Dispatches files to specific handlers based on target file or contents.
        """
        exec_id = f"sbx_{uuid.uuid4().hex[:12]}"

        # 1. Handle Archive Upload (base64 zip/tar.gz/whl)
        if request.archive_base64:
            return self._handle_archive_payload(exec_id, request)

        # 2. If files provided, identify primary target file or manifest
        if not request.files:
            return SandboxExecutionResponse(
                execution_id=exec_id,
                status="warning",
                isolation_mode="static_safe",
                target_type="empty",
                logs="No files or archive payload provided to sandbox.",
                security_violations=[]
            )

        target_file_name = request.target_file
        if not target_file_name:
            # Auto-detect target file: manifest first, then entry scripts, then first file
            for f in request.files:
                basename = os.path.basename(f.path).lower()
                if basename in self.MANIFEST_NAMES:
                    target_file_name = f.path
                    break
            if not target_file_name:
                for f in request.files:
                    ext = os.path.splitext(f.path)[1].lower()
                    if ext in self.SCRIPT_EXTENSIONS or ext in self.BINARY_EXTENSIONS:
                        target_file_name = f.path
                        break
            if not target_file_name:
                target_file_name = request.files[0].path

        # Dispatch based on detected target file type
        ext = os.path.splitext(target_file_name)[1].lower()
        basename = os.path.basename(target_file_name).lower()

        if basename in self.MANIFEST_NAMES:
            return self._handle_manifest(exec_id, request, target_file_name)
        elif ext in self.BINARY_EXTENSIONS:
            return self._handle_binary_file(exec_id, request, target_file_name)
        elif ext == ".py":
            return self._handle_python_script(exec_id, request, target_file_name)
        elif ext in [".js", ".ts", ".jsx", ".tsx"]:
            return self._handle_node_script(exec_id, request, target_file_name)
        elif ext in [".sh", ".bash"]:
            return self._handle_shell_script(exec_id, request, target_file_name)
        else:
            return self._handle_generic_files(exec_id, request, target_file_name)

    # ============================================================
    # 1. ARCHIVE HANDLER (ZIP-SLIP DEFENSE)
    # ============================================================
    def _handle_archive_payload(self, exec_id: str, request: SandboxExecutionRequest) -> SandboxExecutionResponse:
        """Safely extracts zip, tar.gz, or wheel archive with strict Zip-Slip protection."""
        violations: List[str] = []
        filename = request.archive_filename or "archive.zip"

        try:
            raw_bytes = base64.b64decode(request.archive_base64)
        except Exception as e:
            return SandboxExecutionResponse(
                execution_id=exec_id,
                status="error",
                isolation_mode="static_safe",
                target_type="archive_bundle",
                logs=f"Failed to base64-decode archive payload: {e}",
                security_violations=["Corrupt or invalid base64 archive payload."]
            )

        with SecureSandboxRunner(timeout_seconds=request.timeout_seconds) as sandbox:
            archive_path = sandbox.write_bytes(filename, raw_bytes)
            extract_dir = os.path.join(sandbox.sandbox_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            extracted_files: List[str] = []

            # A. Safe ZIP Extraction
            if filename.lower().endswith(".zip") or filename.lower().endswith(".whl"):
                try:
                    with zipfile.ZipFile(archive_path, "r") as zf:
                        for member in zf.infolist():
                            member_name = member.filename
                            # Zip-Slip check: Reject paths with '..' or absolute roots
                            if ".." in member_name.replace("\\", "/").split("/") or member_name.startswith(("/", "\\")) or ":" in member_name:
                                violations.append(f"Zip-Slip Path Traversal Blocked: '{member_name}'")
                                continue

                            dest = os.path.abspath(os.path.join(extract_dir, member_name))
                            if os.path.commonpath([extract_dir, dest]) != extract_dir:
                                violations.append(f"Zip-Slip Boundary Escape Blocked: '{member_name}'")
                                continue

                            zf.extract(member, extract_dir)
                            extracted_files.append(member_name)
                except Exception as ze:
                    violations.append(f"Zip extraction exception: {ze}")

            # B. Safe TAR / TGZ Extraction
            elif any(filename.lower().endswith(t) for t in [".tar", ".tar.gz", ".tgz"]):
                try:
                    with tarfile.open(archive_path, "r:*") as tf:
                        for member in tf.getmembers():
                            if ".." in member.name.replace("\\", "/").split("/") or member.name.startswith(("/", "\\")):
                                violations.append(f"Tar Path Traversal Blocked: '{member.name}'")
                                continue

                            dest = os.path.abspath(os.path.join(extract_dir, member.name))
                            if os.path.commonpath([extract_dir, dest]) != extract_dir:
                                violations.append(f"Tar Boundary Escape Blocked: '{member.name}'")
                                continue

                            tf.extract(member, extract_dir)
                            extracted_files.append(member.name)
                except Exception as te:
                    violations.append(f"Tar extraction exception: {te}")

            status = "violation" if violations else "success"
            logs = f"Safely inspected and unpacked archive '{filename}'.\n"
            logs += f"Extracted {len(extracted_files)} files safely with Zip-Slip path validation."
            if violations:
                logs += f"\nSecurity Violations Caught ({len(violations)}):\n" + "\n".join(f" - {v}" for v in violations)

            return SandboxExecutionResponse(
                execution_id=exec_id,
                status=status,
                isolation_mode="restricted_subprocess",
                target_type="archive_bundle",
                exit_code=0 if not violations else 1,
                logs=logs,
                security_violations=violations,
                manifest_summary={
                    "archive_filename": filename,
                    "extracted_count": len(extracted_files),
                    "sample_files": extracted_files[:15]
                }
            )

    # ============================================================
    # 2. BINARY & COMPILED FORMAT HANDLER (STATIC SAFE INSPECTION)
    # ============================================================
    def _handle_binary_file(self, exec_id: str, request: SandboxExecutionRequest, target_file: str) -> SandboxExecutionResponse:
        """
        NEVER executes raw machine code directly on host system!
        Performs static magic byte header inspection and printable string extraction.
        """
        violations: List[str] = [
            "Raw machine code execution is strictly prohibited by host sandboxing rules."
        ]
        file_obj = next((f for f in request.files if f.path == target_file), None)
        raw_content = file_obj.content if file_obj else ""
        raw_bytes = raw_content.encode("utf-8", errors="replace")

        # 1. Header & Magic Byte Inspection
        header_desc = "Unknown Binary Format"
        if raw_bytes.startswith(b"MZ"):
            header_desc = "Windows Portable Executable (PE / EXE / DLL)"
        elif raw_bytes.startswith(b"\x7fELF"):
            header_desc = "Linux Executable and Linkable Format (ELF)"
        elif raw_bytes.startswith(b"\x00asm"):
            header_desc = "WebAssembly Bytecode (WASM)"
        elif any(raw_bytes.startswith(m) for m in [b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]):
            header_desc = "Mach-O Executable / Dynamic Library (macOS)"

        # 2. Printable String Extraction (>= 4 printable characters)
        printable_strings = re.findall(rb'[\x20-\x7e]{4,}', raw_bytes)
        decoded_strings = [s.decode("ascii", errors="ignore") for s in printable_strings[:500]]

        # 3. Categorize Extracted Strings
        extracted_urls = [s for s in decoded_strings if re.match(r'^https?://[a-zA-Z0-9_\-\.]+', s)]
        extracted_ips = [s for s in decoded_strings if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s)]
        suspicious_symbols = [
            s for s in decoded_strings
            if any(sym.lower() in s.lower() for sym in [
                "virtualalloc", "createremotethread", "writeprocessmemory",
                "socket", "connect", "cmd.exe", "powershell", "system", "dlopen", "mprotect"
            ])
        ]

        if extracted_urls:
            violations.append(f"Embedded external URLs detected in binary: {', '.join(extracted_urls[:3])}")
        if suspicious_symbols:
            violations.append(f"Suspicious native system APIs detected: {', '.join(suspicious_symbols[:5])}")

        logs = f"=== STATIC BINARY INSPECTION: {target_file} ===\n"
        logs += f"Detected Format: {header_desc}\n"
        logs += f"Extracted Printable Strings: {len(decoded_strings)}\n"
        logs += f"Embedded URLs Found: {len(extracted_urls)}\n"
        logs += f"Suspicious System Calls: {len(suspicious_symbols)}\n"

        return SandboxExecutionResponse(
            execution_id=exec_id,
            status="violation" if violations else "success",
            isolation_mode="static_safe",
            target_type="binary_executable",
            exit_code=0,
            duration_seconds=0.015,
            logs=logs,
            security_violations=violations,
            extracted_strings=extracted_urls + extracted_ips + suspicious_symbols[:10],
            manifest_summary={
                "format": header_desc,
                "file_size_bytes": len(raw_bytes),
                "urls_count": len(extracted_urls),
                "suspicious_symbols_count": len(suspicious_symbols)
            }
        )

    # ============================================================
    # 3. BUILD & PACKAGE MANIFEST HANDLER
    # ============================================================
    def _handle_manifest(self, exec_id: str, request: SandboxExecutionRequest, target_file: str) -> SandboxExecutionResponse:
        """Parses manifests, inspects pre/postinstall hooks, and runs safe dry-run resolutions."""
        file_obj = next((f for f in request.files if f.path == target_file), None)
        content = file_obj.content if file_obj else ""
        basename = os.path.basename(target_file).lower()
        violations: List[str] = []
        alerts: List[str] = []
        summary: Dict[str, Any] = {}

        logs = f"=== BUILD MANIFEST ANALYSIS: {target_file} ===\n"

        if basename == "package.json":
            try:
                pkg_data = json.loads(content)
                scripts = pkg_data.get("scripts", {})
                dependencies = pkg_data.get("dependencies", {})
                dev_dependencies = pkg_data.get("devDependencies", {})
                overrides = pkg_data.get("overrides", {})

                # Inspect lifecycle hooks for malicious behavior
                dangerous_hooks = ["preinstall", "install", "postinstall", "prepublish"]
                for hook in dangerous_hooks:
                    if hook in scripts:
                        hook_cmd = str(scripts[hook])
                        alerts.append(f"Lifecycle hook `{hook}` configured: '{hook_cmd}'")
                        if any(term in hook_cmd.lower() for term in ["curl", "wget", "powershell", "base64", "sh -c", "eval"]):
                            violations.append(f"Suspicious command execution in lifecycle hook `{hook}`: '{hook_cmd}'")

                summary = {
                    "package_name": pkg_data.get("name", "unknown"),
                    "version": pkg_data.get("version", "0.0.0"),
                    "direct_dependencies_count": len(dependencies),
                    "dev_dependencies_count": len(dev_dependencies),
                    "has_overrides": len(overrides) > 0,
                    "lifecycle_hooks": [h for h in dangerous_hooks if h in scripts]
                }
                logs += f"Package Name: {summary['package_name']}@{summary['version']}\n"
                logs += f"Dependencies: {len(dependencies)} direct, {len(dev_dependencies)} dev\n"
                logs += f"Lifecycle Hooks Found: {len(summary['lifecycle_hooks'])}\n"
            except Exception as pe:
                violations.append(f"Invalid package.json syntax: {pe}")

        elif basename == "requirements.txt":
            req_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            summary = {
                "requirements_count": len(req_lines),
                "packages": [l.split("==")[0].split(">=")[0].strip() for l in req_lines[:15]]
            }
            logs += f"Parsed requirements.txt with {len(req_lines)} dependencies.\n"

        # Safe dry-run resolution inside sandbox runner
        with SecureSandboxRunner(timeout_seconds=request.timeout_seconds) as sandbox:
            for f in request.files:
                sandbox.write_file(f.path, f.content)

            # Test manifest syntax in sandbox
            if basename == "package.json":
                npm_check = sandbox.run(["node", "-e", "JSON.parse(require('fs').readFileSync('package.json'))"])
                if not npm_check.success and "Command not found" not in npm_check.stderr:
                    violations.append(f"package.json validation error in node runtime: {npm_check.stderr.strip()}")

        status = "violation" if violations else ("warning" if alerts else "success")
        return SandboxExecutionResponse(
            execution_id=exec_id,
            status=status,
            isolation_mode="restricted_subprocess",
            target_type="package_manifest",
            exit_code=0 if not violations else 1,
            logs=logs,
            security_violations=violations,
            detonation_alerts=alerts,
            manifest_summary=summary
        )

    # ============================================================
    # 4. SCRIPT INTERPRETER HANDLERS (PYTHON, JS, SHELL)
    # ============================================================
    def _handle_python_script(self, exec_id: str, request: SandboxExecutionRequest, target_file: str) -> SandboxExecutionResponse:
        """Executes syntax check and isolated run of Python script in sandbox."""
        with SecureSandboxRunner(timeout_seconds=request.timeout_seconds) as sandbox:
            for f in request.files:
                sandbox.write_file(f.path, f.content)

            # 1. Syntax check via py_compile
            compile_res = sandbox.run([sys.executable, "-m", "py_compile", target_file])
            if not compile_res.success:
                return SandboxExecutionResponse(
                    execution_id=exec_id,
                    status="error",
                    isolation_mode=compile_res.isolation_mode,
                    target_type="python_script",
                    exit_code=compile_res.exit_code,
                    duration_seconds=compile_res.duration_seconds,
                    logs=f"Python syntax compilation failed for {target_file}:\n{compile_res.stderr}",
                    security_violations=["SyntaxError: Script fails Python bytecode compilation."]
                )

            # 2. Run target file if requested or auto mode
            run_res = sandbox.run([sys.executable, target_file], timeout=request.timeout_seconds)
            status = "violation" if run_res.security_violations else ("error" if not run_res.success else "success")

            return SandboxExecutionResponse(
                execution_id=exec_id,
                status=status,
                isolation_mode=run_res.isolation_mode,
                target_type="python_script",
                exit_code=run_res.exit_code,
                duration_seconds=run_res.duration_seconds,
                logs=f"=== SANDBOX EXECUTION: {target_file} ===\n" + (run_res.stdout or run_res.stderr or "Executed successfully with 0 output."),
                security_violations=run_res.security_violations
            )

    def _handle_node_script(self, exec_id: str, request: SandboxExecutionRequest, target_file: str) -> SandboxExecutionResponse:
        """Executes syntax check of JavaScript/TypeScript in sandbox."""
        with SecureSandboxRunner(timeout_seconds=request.timeout_seconds) as sandbox:
            for f in request.files:
                sandbox.write_file(f.path, f.content)

            node_res = sandbox.run(["node", "--check", target_file])
            logs = f"=== NODE.JS SYNTAX CHECK: {target_file} ===\n"
            if node_res.success:
                logs += "Syntax verification passed cleanly (node --check)."
            else:
                logs += node_res.stderr or node_res.stdout

            status = "violation" if node_res.security_violations else ("error" if not node_res.success else "success")
            return SandboxExecutionResponse(
                execution_id=exec_id,
                status=status,
                isolation_mode=node_res.isolation_mode,
                target_type="node_script",
                exit_code=node_res.exit_code,
                duration_seconds=node_res.duration_seconds,
                logs=logs,
                security_violations=node_res.security_violations
            )

    def _handle_shell_script(self, exec_id: str, request: SandboxExecutionRequest, target_file: str) -> SandboxExecutionResponse:
        """Static safety linting and syntax check for shell scripts."""
        file_obj = next((f for f in request.files if f.path == target_file), None)
        content = file_obj.content if file_obj else ""
        violations: List[str] = []

        # Check for catastrophic shell commands
        dangerous_shell_patterns = [
            (r'rm\s+-rf\s+/', "Catastrophic command: Recursive root deletion (`rm -rf /`)"),
            (r'curl\s+.*\|\s*bash', "Insecure execution: Remote script pipe to shell (`curl | bash`)"),
            (r'>\s*/dev/sd[a-z]', "Disk tampering: Direct write to block device (`/dev/sd*`)"),
            (r':\(\)\{\s*:\|:&\s*\};:', "Denial of Service: Fork bomb pattern"),
            (r'chmod\s+-R\s+777\s+/', "Permission destruction: Blanket world-writable root permissions")
        ]
        for pattern, desc in dangerous_shell_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                violations.append(desc)

        logs = f"=== SHELL SCRIPT INSPECTION: {target_file} ===\n"
        if violations:
            logs += "Security violations detected during shell static analysis:\n" + "\n".join(f" - {v}" for v in violations)
        else:
            logs += "Shell script static analysis passed. No destructive commands detected."

        return SandboxExecutionResponse(
            execution_id=exec_id,
            status="violation" if violations else "success",
            isolation_mode="static_safe",
            target_type="shell_script",
            exit_code=0 if not violations else 1,
            duration_seconds=0.01,
            logs=logs,
            security_violations=violations
        )

    def _handle_generic_files(self, exec_id: str, request: SandboxExecutionRequest, target_file: str) -> SandboxExecutionResponse:
        """Fallback handler for generic text/config files."""
        return SandboxExecutionResponse(
            execution_id=exec_id,
            status="success",
            isolation_mode="static_safe",
            target_type="generic_file",
            exit_code=0,
            duration_seconds=0.005,
            logs=f"File '{target_file}' inspected. No active execution required for this format.",
            security_violations=[]
        )
