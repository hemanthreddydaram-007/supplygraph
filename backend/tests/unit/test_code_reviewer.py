# Tests for CodeReviewerService
import pytest
from app.services.code_reviewer import CodeReviewerService
from app.models.core import CodeReviewItem


class TestCodeReviewerService:
    def setup_method(self):
        self.reviewer = CodeReviewerService()

    def test_python_mutable_default_detected(self):
        code = "def process_data(items=[]):\n    items.append(1)\n    return items\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="utils.py")
        assert len(results) >= 1
        found = any("Mutable Default" in r.title for r in results)
        assert found
        item = next(r for r in results if "Mutable Default" in r.title)
        assert item.buggy_code
        assert item.corrected_code
        assert "items=None" in item.corrected_code

    def test_python_subprocess_shell_detected(self):
        code = "import subprocess\ndef run_cmd(user_arg):\n    subprocess.run('ls ' + user_arg, shell=True)\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="cmd.py")
        assert len(results) >= 1
        found = any("shell=True" in r.title or "Command Injection" in r.title for r in results)
        assert found
        item = next(r for r in results if "shell=True" in r.title or "Command Injection" in r.title)
        assert item.severity == "CRITICAL"
        assert item.category == "Security Vulnerability"
        assert "shell=False" in item.corrected_code

    def test_python_hardcoded_secret_detected(self):
        code = "API_KEY = 'AKIAIOSFODNN7EXAMPLE123'\nDATABASE_PASSWORD = 'supersecretpasswords123'\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="config.py")
        assert len(results) >= 1
        found = any("Hardcoded" in r.title for r in results)
        assert found
        item = next(r for r in results if "Hardcoded" in r.title)
        assert "os.environ.get" in item.corrected_code

    def test_javascript_eval_detected(self):
        code = "function execute(input) {\n    return eval(input);\n}\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="runner.js")
        assert len(results) >= 1
        found = any("eval" in r.title.lower() for r in results)
        assert found
        item = next(r for r in results if "eval" in r.title.lower())
        assert item.severity == "CRITICAL"
        assert "JSON.parse" in item.corrected_code

    def test_javascript_dangerously_set_inner_html_detected(self):
        code = "export function Component({ content }) {\n    return <div dangerouslySetInnerHTML={{ __html: content }} />;\n}\n"
        results = self.reviewer.review_snippet(code, language="typescript", file_path="Component.tsx")
        assert len(results) >= 1
        found = any("dangerouslySetInnerHTML" in r.title for r in results)
        assert found
        item = next(r for r in results if "dangerouslySetInnerHTML" in r.title)
        assert "DOMPurify" in item.corrected_code

    def test_yaml_unpinned_action_detected(self):
        code = "name: CI\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v2\n"
        results = self.reviewer.review_snippet(code, language="yaml", file_path=".github/workflows/ci.yml")
        assert len(results) >= 1
        found = any("Unpinned" in r.title for r in results)
        assert found
        item = next(r for r in results if "Unpinned" in r.title)
        assert "uses: actions/checkout@" in item.corrected_code

    def test_commented_eval_not_flagged(self):
        code = "// const result = eval(userString);\nconst doc = 'Never call eval(payload) in code';\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="safe.js")
        assert not any("eval" in r.title.lower() for r in results)

    def test_commented_loose_equality_not_flagged(self):
        code = "// Note: checking if x == y\nconst msg = 'Does a == b here?';\nif (val == null) { return; }\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="safe.js")
        assert not any("Loose Equality" in r.title for r in results)
