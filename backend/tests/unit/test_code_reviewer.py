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

    def test_yaml_surgical_diff_and_sha_mapping(self):
        code = """name: Book Workflow
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repo
        uses: actions/checkout@v4
      - name: Set up Python 3.10
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'
"""
        results = self.reviewer.review_snippet(code, language="yaml", file_path=".github/workflows/book.yml")
        assert len(results) == 2

        # Check setup-python item
        py_item = next(r for r in results if "setup-python" in r.title)
        assert py_item.line_number == 9
        # Fix 2: Check accurate SHA
        assert "42375524e23c412d93fb67b49958b491fce71c38" in py_item.corrected_code
        # Fix 3: Check indentation preserved
        assert "        uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0" in py_item.corrected_code
        assert "        # Pinned to full immutable commit SHA" in py_item.corrected_code

        # Fix 1 & 4: Check surgical unified diff preserves context lines without marking them '-'
        diff = py_item.unified_diff
        assert diff is not None
        assert "--- a/.github/workflows/book.yml" in diff
        assert "+++ b/.github/workflows/book.yml" in diff
        assert "@@ -7,5 +7,6 @@" in diff
        # Context lines MUST be prefixed with space ' '
        assert "       - name: Set up Python 3.10" in diff
        assert "         with:" in diff
        assert "           python-version: '3.10'" in diff
        # Only target line is marked '-'
        assert "-        uses: actions/setup-python@v5" in diff
        # Added lines are marked '+'
        assert "+        uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0" in diff

        # Check checkout item has different SHA
        checkout_item = next(r for r in results if "checkout" in r.title)
        assert "11bd71901bbe5b1630ceea73d27597364c9af683" in checkout_item.corrected_code
        assert checkout_item.corrected_code != py_item.corrected_code

    def test_yaml_step_hyphen_prefix_preserved(self):
        code = """name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        results = self.reviewer.review_snippet(code, language="yaml", file_path=".github/workflows/ci.yml")
        assert len(results) == 1
        item = results[0]
        # Hyphen prefix must be preserved on uses: line
        assert "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2" in item.corrected_code
        # Comment must be aligned with step
        assert "      # Pinned to full immutable commit SHA" in item.corrected_code

    def test_already_pinned_action_with_comment_skipped(self):
        code = """name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
"""
        results = self.reviewer.review_snippet(code, language="yaml", file_path=".github/workflows/ci.yml")
        assert len(results) == 0

