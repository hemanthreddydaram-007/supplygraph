# SupplyGraph - Universal Static AST & Code Security Analyzer
# Analyzes Python (AST), JavaScript, TypeScript (AST patterns), detecting RCE, injection sinks, and hardcoded secrets.
from app.models.core import EvidenceItem, EvidenceClassification, EvidenceSource, SourceLocation
import ast
import re
import uuid
import datetime
from typing import List

# Pre-compiled high-risk regexes for JavaScript/TypeScript and cross-language static analysis
_JS_EVAL_PATTERN = re.compile(r'\b(?:eval\s*\(|new\s+Function\s*\(|execScript\s*\()')
_JS_CMD_INJECTION = re.compile(r'\b(?:child_process|cp)\.(?:exec|execSync|spawn|spawnSync)\s*\(')
_JS_XSS_SINK = re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:')
_JS_PROTO_POLLUTION = re.compile(r'(?:\.__proto__|\[["\']__proto__["\']\])')
_SECRET_PATTERNS = [
    (re.compile(r'(?:AKIA[0-9A-Z]{16})'), "AWS Access Key ID"),
    (re.compile(r'(?:ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})'), "GitHub Personal Access Token"),
    (re.compile(r'(?:sk-[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9_]{32,})'), "AI Provider API Key (OpenAI/Anthropic)"),
    (re.compile(r'-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY-----'), "Private Cryptographic Key"),
    (re.compile(r'(?:password|secret|apiKey|api_key|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{24,})["\']', re.IGNORECASE), "Hardcoded Secret / Token")
]


class ASTVisitor(ast.NodeVisitor):
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.findings: List[EvidenceItem] = []

    def _add_finding(self, description: str, node: ast.AST, evidence_type: str = "CODE_FINDING"):
        finding = EvidenceItem(
            id=str(uuid.uuid4()),
            source=EvidenceSource.AST,
            evidence_type=evidence_type,
            classification=EvidenceClassification.HEURISTIC,
            description=description,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            confidence_contribution=0.90,
            is_simulated=False,
            source_location=SourceLocation(
                file=self.file_name,
                line=getattr(node, 'lineno', 1),
                column=getattr(node, 'col_offset', 0)
            ),
            raw_data={"type": "ast_pattern_match", "file": self.file_name}
        )
        self.findings.append(finding)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        try:
            func_name = ast.unparse(node.func)
        except Exception:
            pass

        if func_name in ("eval", "exec"):
            self._add_finding(f"Dangerous dynamic code execution detected: {func_name}()", node, "AST-EVAL-RCE")

        if func_name in ("base64.b64decode", "b64decode"):
            self._add_finding(f"Obfuscated Base64 decoding detected: {func_name}()", node, "AST-OBFUSCATION")

        if func_name in ("subprocess.call", "subprocess.Popen", "subprocess.run"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add_finding(f"Command execution sink with shell=True detected: {func_name}", node, "AST-COMMAND-INJECTION")

        # Detect sensitive os.environ.get('AWS_...')
        if func_name in ("os.environ.get", "environ.get"):
            if node.args and isinstance(node.args[0], ast.Constant):
                val = str(node.args[0].value).upper()
                if any(sec in val for sec in ("AWS_", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY")):
                    self._add_finding(f"Sensitive environment credential accessed: {val}", node, "AST-CREDENTIAL-ACCESS")

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        try:
            val_name = ast.unparse(node.value)
            if val_name in ("os.environ", "environ"):
                if isinstance(node.slice, ast.Constant):
                    val = str(node.slice.value).upper()
                    if any(sec in val for sec in ("AWS_", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY")):
                        self._add_finding(f"Sensitive environment credential accessed: {val}", node, "AST-CREDENTIAL-ACCESS")
        except Exception:
            pass
        self.generic_visit(node)


class ASTAnalyzer:
    """Universal Static Code & AST Analyzer across Python, JavaScript, and TypeScript."""

    def analyze(self, file_name: str, file_content: str) -> List[EvidenceItem]:
        findings: List[EvidenceItem] = []
        is_python = file_name.endswith('.py')
        is_js_ts = any(file_name.endswith(ext) for ext in ('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'))

        # 1. Python AST parsing
        if is_python:
            try:
                tree = ast.parse(file_content)
                visitor = ASTVisitor(file_name)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # 2. Line-by-line static inspection for Secrets & JS/TS Injection Sinks
        lines = file_content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue

            # Hardcoded Secrets detection (both Python and JS/TS)
            for sec_regex, sec_label in _SECRET_PATTERNS:
                if sec_regex.search(line):
                    findings.append(EvidenceItem(
                        id=str(uuid.uuid4()),
                        source=EvidenceSource.AST,
                        evidence_type="AST-HARDCODED-SECRET",
                        classification=EvidenceClassification.HEURISTIC,
                        description=f"Hardcoded sensitive credential detected ({sec_label}) in '{file_name}' at line {idx}.",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        confidence_contribution=0.95,
                        is_simulated=False,
                        source_location=SourceLocation(file=file_name, line=idx),
                        raw_data={"secret_type": sec_label, "file": file_name, "line": idx}
                    ))
                    break

            # JavaScript / TypeScript sinks
            if is_js_ts:
                if _JS_EVAL_PATTERN.search(line):
                    findings.append(EvidenceItem(
                        id=str(uuid.uuid4()),
                        source=EvidenceSource.AST,
                        evidence_type="AST-EVAL-RCE",
                        classification=EvidenceClassification.HEURISTIC,
                        description=f"Dangerous dynamic code execution (eval / Function) detected in '{file_name}' at line {idx}.",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        confidence_contribution=0.90,
                        is_simulated=False,
                        source_location=SourceLocation(file=file_name, line=idx),
                        raw_data={"sink": "eval/Function", "file": file_name, "line": idx}
                    ))

                if _JS_CMD_INJECTION.search(line):
                    findings.append(EvidenceItem(
                        id=str(uuid.uuid4()),
                        source=EvidenceSource.AST,
                        evidence_type="AST-COMMAND-INJECTION",
                        classification=EvidenceClassification.HEURISTIC,
                        description=f"Command execution sink (child_process) detected in '{file_name}' at line {idx}.",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        confidence_contribution=0.85,
                        is_simulated=False,
                        source_location=SourceLocation(file=file_name, line=idx),
                        raw_data={"sink": "child_process", "file": file_name, "line": idx}
                    ))

                if _JS_XSS_SINK.search(line):
                    findings.append(EvidenceItem(
                        id=str(uuid.uuid4()),
                        source=EvidenceSource.AST,
                        evidence_type="AST-XSS-INJECTION",
                        classification=EvidenceClassification.HEURISTIC,
                        description=f"Dangerous unescaped HTML sink (dangerouslySetInnerHTML) in '{file_name}' at line {idx}.",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        confidence_contribution=0.80,
                        is_simulated=False,
                        source_location=SourceLocation(file=file_name, line=idx),
                        raw_data={"sink": "dangerouslySetInnerHTML", "file": file_name, "line": idx}
                    ))

                if _JS_PROTO_POLLUTION.search(line):
                    findings.append(EvidenceItem(
                        id=str(uuid.uuid4()),
                        source=EvidenceSource.AST,
                        evidence_type="AST-PROTOTYPE-POLLUTION",
                        classification=EvidenceClassification.HEURISTIC,
                        description=f"Direct prototype modification (__proto__) detected in '{file_name}' at line {idx}.",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        confidence_contribution=0.80,
                        is_simulated=False,
                        source_location=SourceLocation(file=file_name, line=idx),
                        raw_data={"sink": "__proto__", "file": file_name, "line": idx}
                    ))

        return findings
