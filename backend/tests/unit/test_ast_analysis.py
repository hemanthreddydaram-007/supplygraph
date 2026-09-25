import pytest
from app.detectors.ast_analyzer import ASTAnalyzer
from app.models.core import EvidenceClassification, EvidenceSource

class TestASTAnalyzer:
    def test_subprocess_shell_true(self, suspicious_python_code):
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze("logger.py", suspicious_python_code)
        
        subprocess_finding = next((f for f in findings if "subprocess" in f.description.lower()), None)
        assert subprocess_finding is not None
        assert subprocess_finding.classification == EvidenceClassification.HEURISTIC
        assert subprocess_finding.source == EvidenceSource.AST
        assert subprocess_finding.source_location.file == "logger.py"
        assert subprocess_finding.source_location.line > 0

    def test_base64_decode(self, suspicious_python_code):
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze("logger.py", suspicious_python_code)
        
        b64_finding = next((f for f in findings if "base64" in f.description.lower()), None)
        assert b64_finding is not None
        assert b64_finding.source_location.line > 0

    def test_eval_usage(self, suspicious_python_code):
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze("logger.py", suspicious_python_code)
        
        eval_finding = next((f for f in findings if "eval" in f.description.lower()), None)
        assert eval_finding is not None
        assert eval_finding.source_location.line > 0

    def test_env_access(self, suspicious_python_code):
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze("logger.py", suspicious_python_code)
        
        env_finding = next((f for f in findings if "environ" in f.description.lower() or "secret" in f.description.lower() or "aws" in f.description.lower()), None)
        assert env_finding is not None
        assert env_finding.source_location.line > 0

    def test_clean_code_no_findings(self, clean_python_code):
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze("math.py", clean_python_code)
        assert len(findings) == 0
