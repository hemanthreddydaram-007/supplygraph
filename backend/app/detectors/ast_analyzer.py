# SupplyGraph - AST Analyzer
from app.models.core import EvidenceItem, EvidenceClassification, EvidenceSource, SourceLocation
import ast
import uuid
import datetime
from typing import List

class ASTVisitor(ast.NodeVisitor):
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.findings: List[EvidenceItem] = []

    def _add_finding(self, description: str, node: ast.AST):
        finding = EvidenceItem(
            id=str(uuid.uuid4()),
            source=EvidenceSource.AST,
            evidence_type="CODE_FINDING",
            classification=EvidenceClassification.HEURISTIC,
            description=description,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            confidence_contribution=1.0,
            is_simulated=False,
            source_location=SourceLocation(
                file=self.file_name,
                line=node.lineno,
                column=node.col_offset
            ),
            raw_data={"type": "ast_pattern_match"}
        )
        self.findings.append(finding)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        try:
            func_name = ast.unparse(node.func)
        except Exception:
            pass

        if func_name in ("eval", "exec"):
            self._add_finding(f"Dangerous function call detected: {func_name}()", node)

        if func_name in ("base64.b64decode", "b64decode"):
            self._add_finding(f"Base64 decoding detected: {func_name}()", node)

        if func_name in ("subprocess.call", "subprocess.Popen", "subprocess.run"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add_finding(f"Command execution with shell=True detected: {func_name}", node)

        # Detect os.environ.get('AWS_...')
        if func_name in ("os.environ.get", "environ.get"):
            if node.args and isinstance(node.args[0], ast.Constant):
                val = str(node.args[0].value).upper()
                if any(sec in val for sec in ("AWS_", "SECRET", "TOKEN")):
                    self._add_finding(f"Sensitive environment variable accessed: {val}", node)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # os.environ["AWS_..."]
        try:
            val_name = ast.unparse(node.value)
            if val_name in ("os.environ", "environ"):
                if isinstance(node.slice, ast.Constant):
                    val = str(node.slice.value).upper()
                    if any(sec in val for sec in ("AWS_", "SECRET", "TOKEN")):
                        self._add_finding(f"Sensitive environment variable accessed: {val}", node)
        except Exception:
            pass
        self.generic_visit(node)

class ASTAnalyzer:
    def analyze(self, file_name: str, file_content: str) -> List[EvidenceItem]:
        try:
            tree = ast.parse(file_content)
            visitor = ASTVisitor(file_name)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            return []
