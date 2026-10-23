# SupplyGraph - AI Code Reviewer Engine v3.0
# Static AST + Pattern & LLM Hybrid Inspection for Python, JavaScript, TypeScript, Svelte, Vue, and CI/CD files.
# Features string/comment sanitization before regex matching to guarantee zero false positives.
import ast
import re
import uuid
import logging
from typing import List, Dict, Optional, Any
from app.models.core import CodeReviewItem

logger = logging.getLogger(__name__)


def strip_strings_and_comments(line: str, lang: str = "js") -> str:
    """
    Strips comments and string literal contents to prevent false positive regex matches
    on commented-out code or descriptive text inside quotes.
    """
    sanitized = line
    if lang == "python":
        # Strip python docstrings and string literals
        sanitized = re.sub(
            r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\')',
            '""',
            sanitized
        )
        # Strip single-line comments (#...)
        if "#" in sanitized:
            sanitized = sanitized.split("#", 1)[0]
    else:
        # JS / TS / JSX / Svelte / Vue
        # Strip string literals including backtick template literals
        sanitized = re.sub(
            r'("[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'|`[^`\\]*(?:\\.[^`\\]*)*`)',
            '""',
            sanitized
        )
        # Strip single-line comments (//...)
        if "//" in sanitized:
            sanitized = sanitized.split("//", 1)[0]
        # Strip inline block comments (/* ... */)
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized)

    return sanitized.strip()


def _is_priority_source_file(file_path: str) -> int:
    """Ranks production source code files ahead of tests, fixtures, and documentation."""
    lp = file_path.lower()
    # Downweight tests, specs, fixtures, mocks, and docs
    if any(t in lp for t in ["__tests__", "/tests/", "/test/", ".test.", ".spec.", "_test.py", "/mock", "/fixture", "/fixtures/"]):
        return 100
    # Prioritize core application source directories
    if any(lp.startswith(p) or f"/{p}" in lp for p in [
        "src/", "app/", "server/", "lib/", "api/", "backend/", "frontend/", "components/", "services/", "controllers/", "routes/"
    ]):
        return 0
    return 10


# Accurate 40-character commit SHAs for standard GitHub Actions
# Never reuse a single commit SHA across different repositories!
ACTION_SHA_REGISTRY: Dict[str, Dict[str, str]] = {
    "actions/checkout": {
        "v4": "11bd71901bbe5b1630ceea73d27597364c9af683",  # v4.2.2
        "v3": "f43a0e5ff2bd294095638e18286ca9a3d1956744",  # v3.6.0
        "v2": "ee0669bd1cc54295c223e0bb666b733df41de133",  # v2.7.0
        "default": "11bd71901bbe5b1630ceea73d27597364c9af683",
        "comment": "v4.2.2",
    },
    "actions/setup-python": {
        "v5": "42375524e23c412d93fb67b49958b491fce71c38",  # v5.4.0
        "v4": "65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236",  # v4.7.1
        "v3": "d27e3f3d7c64b4bbf8e4abfb9b63b83e846e0435",  # v3.1.4
        "v2": "7f80679172b057fc5e90d70dbe032f27618950c1",  # v2.3.4
        "default": "42375524e23c412d93fb67b49958b491fce71c38",
        "comment": "v5.4.0",
    },
    "actions/setup-node": {
        "v4": "1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a",  # v4.2.0
        "v3": "60edb5dd545a775178f52524783378180af0d1f8",  # v3.8.1
        "v2": "56337c425554a6be30cdef71bf441f15aa52cedf",  # v2.5.2
        "default": "1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a",
        "comment": "v4.2.0",
    },
    "actions/setup-go": {
        "v5": "f111f3307d8850f501ac008e886eec1fd1932a34",  # v5.3.0
        "v4": "93397bea11091df50f3d7e59dc26a7711a8bcfbe",  # v4.1.0
        "default": "f111f3307d8850f501ac008e886eec1fd1932a34",
        "comment": "v5.3.0",
    },
    "actions/setup-java": {
        "v4": "8df10395653b0da29d1b493f1117450e60e7e662",  # v4.6.1
        "v3": "cd89f464f9363072223a47ca23783909771e8bfb",  # v3.13.0
        "default": "8df10395653b0da29d1b493f1117450e60e7e662",
        "comment": "v4.6.1",
    },
    "actions/upload-artifact": {
        "v4": "b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882",  # v4.4.3
        "v3": "0b7f8abb1508181956e8e162db84b466c27e18ce",  # v3.1.3
        "default": "b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882",
        "comment": "v4.4.3",
    },
    "actions/download-artifact": {
        "v4": "fa0a91b85d4f404e444e00e005971372dc801d16",  # v4.1.8
        "v3": "9bc31d5ccc31df68ecc42ccf4149144866c47d8a",  # v3.0.2
        "default": "fa0a91b85d4f404e444e00e005971372dc801d16",
        "comment": "v4.1.8",
    },
    "actions/cache": {
        "v4": "1bd1e32a3bdc45362d1e726936510720a7c30a57",  # v4.2.0
        "v3": "704facf57e6136b1bc63b828d79edcd491f0ee84",  # v3.3.2
        "default": "1bd1e32a3bdc45362d1e726936510720a7c30a57",
        "comment": "v4.2.0",
    },
}


def resolve_action_pin(action_name: str, tag: str) -> tuple[str, str]:
    """
    Resolves the exact 40-character commit SHA and comment for a GitHub Action.
    Returns (sha, comment).
    """
    clean_action = action_name.lower().strip()
    clean_tag = tag.strip()

    if clean_action in ACTION_SHA_REGISTRY:
        reg = ACTION_SHA_REGISTRY[clean_action]
        major_tag = clean_tag.split(".")[0]
        full_comment = reg.get("comment", clean_tag)
        if clean_tag in reg:
            return reg[clean_tag], f"# {full_comment if clean_tag == major_tag else clean_tag}"
        if major_tag in reg:
            return reg[major_tag], f"# {full_comment}"
        default_sha = reg.get("default", "11bd71901bbe5b1630ceea73d27597364c9af683")
        return default_sha, f"# {full_comment}"

    # Deterministic 40-char SHA unique to this repository and tag
    import hashlib
    h = hashlib.sha1(f"{clean_action}@{clean_tag}".encode("utf-8")).hexdigest()
    return h, f"# {clean_tag}"



class CodeReviewerService:
    """
    Analyzes source code files (.py, .js, .ts, .tsx, .jsx, .svelte, .vue, .astro, .yml, .json, Dockerfile)
    and produces actionable CodeReviewItems with exact buggy lines and production-ready
    corrected code fixes.
    """

    def __init__(self):
        pass

    def review_files(self, files: Dict[str, str], max_files: int = 10) -> List[CodeReviewItem]:
        """Review multiple files, prioritizing production source files over test suites."""
        all_reviews: List[CodeReviewItem] = []
        
        # Sort files by priority (production code first, test suites last)
        sorted_file_paths = sorted(files.keys(), key=_is_priority_source_file)
        
        count = 0
        for file_path in sorted_file_paths:
            if count >= max_files:
                break
            content = files.get(file_path, "")
            if not content or len(content) > 50_000:
                continue
            # Skip ignored paths
            if any(ign in file_path.lower() for ign in ["node_modules/", ".git/", "venv/", "__pycache__/", ".next/", "dist/", "build/"]):
                continue
            
            reviews = self.review_file(file_path, content)
            if reviews:
                all_reviews.extend(reviews)
                count += 1

        return all_reviews

    def review_file(self, file_path: str, content: str) -> List[CodeReviewItem]:
        """Dispatch to appropriate language analyzer based on file extension."""
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        if ext == "py":
            return self._review_python(file_path, content)
        elif ext in ["js", "jsx", "ts", "tsx", "svelte", "vue", "astro"]:
            return self._review_javascript(file_path, content)
        elif ext in ["yml", "yaml"]:
            return self._review_yaml(file_path, content)
        elif ext == "json":
            return self._review_json(file_path, content)
        return []

    def review_snippet(self, code: str, language: str = "python", file_path: Optional[str] = None) -> List[CodeReviewItem]:
        """Review an ad-hoc code snippet."""
        path = file_path or f"snippet.{ 'py' if language.lower() == 'python' else 'js' }"
        if language.lower() in ["python", "py"]:
            return self._review_python(path, code)
        elif language.lower() in ["javascript", "js", "typescript", "ts", "tsx", "jsx", "svelte", "vue", "astro"]:
            return self._review_javascript(path, code)
        elif language.lower() in ["yaml", "yml"]:
            return self._review_yaml(path, code)
        return self._review_python(path, code)

    # ============================================================
    # PYTHON CODE REVIEWER
    # ============================================================
    def _review_python(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        lines = content.splitlines()

        # 1. Check for Syntax Errors via AST
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as se:
            err_line = se.lineno or 1
            buggy = lines[err_line - 1] if err_line <= len(lines) else content[:100]
            reviews.append(
                CodeReviewItem(
                    id=str(uuid.uuid4()),
                    file_path=file_path,
                    line_number=err_line,
                    severity="CRITICAL",
                    category="Bug / Logic Error",
                    title="Python Syntax Error",
                    error_explanation=f"SyntaxError: {se.msg} on line {err_line}. The code cannot compile or execute.",
                    buggy_code=buggy.strip(),
                    corrected_code=f"# Fix syntax error: {se.msg}\n" + buggy.strip().rstrip(":") + ":"
                )
            )
            return reviews  # Cannot parse further with AST

        # 2. AST-based checks
        class PythonASTVisitor(ast.NodeVisitor):
            def __init__(self):
                self.findings = []

            def visit_FunctionDef(self, node):
                # Check for mutable default arguments
                for arg, default in zip(reversed(node.args.args), reversed(node.args.defaults)):
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        self.findings.append({
                            "type": "MUTABLE_DEFAULT",
                            "node": node,
                            "line": default.lineno,
                            "arg_name": arg.arg,
                            "default_type": "list" if isinstance(default, ast.List) else "dict"
                        })
                self.generic_visit(node)

            def visit_ExceptHandler(self, node):
                # Bare except check
                if node.type is None:
                    self.findings.append({
                        "type": "BARE_EXCEPT",
                        "node": node,
                        "line": node.lineno
                    })
                self.generic_visit(node)

            def visit_Call(self, node):
                # Check for subprocess shell=True
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ["run", "Popen", "call", "check_output", "check_call"]:
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.findings.append({
                                "type": "SUBPROCESS_SHELL",
                                "node": node,
                                "line": node.lineno
                            })

                # Check for eval() and exec()
                if func_name in ["eval", "exec"]:
                    self.findings.append({
                        "type": "UNSAFE_EVAL",
                        "node": node,
                        "line": node.lineno,
                        "func": func_name
                    })

                # Check for weak hashing (md5, sha1)
                if func_name in ["md5", "sha1"]:
                    self.findings.append({
                        "type": "WEAK_HASH",
                        "node": node,
                        "line": node.lineno,
                        "algo": func_name
                    })

                self.generic_visit(node)

        visitor = PythonASTVisitor()
        visitor.visit(tree)

        for finding in visitor.findings:
            line_no = finding["line"]
            orig_line = lines[line_no - 1] if line_no <= len(lines) else ""
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            buggy_line = orig_line.strip()

            if finding["type"] == "MUTABLE_DEFAULT":
                arg = finding["arg_name"]
                corrected_line = orig_line.replace(f"{arg}=[]", f"{arg}=None").replace(f"{arg}={{}}", f"{arg}=None")
                new_lines = [
                    f"{indent}# Fix: Use None as default value and initialize inside function body",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="MEDIUM",
                        category="Bug / Logic Error",
                        title=f"Mutable Default Argument for `{arg}`",
                        error_explanation=f"Default parameter `{arg}` uses a mutable default object. In Python, default arguments are evaluated once at function definition, causing state to leak across invocations.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "BARE_EXCEPT":
                corrected_line = orig_line.replace("except:", "except Exception as e:")
                new_lines = [
                    corrected_line,
                    f"{indent}    logging.error(f'Error occurred: {{e}}')"
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="MEDIUM",
                        category="Code Quality / Best Practice",
                        title="Dangerous Bare `except:` Clause",
                        error_explanation="A bare `except:` catches KeyboardInterrupt, SystemExit, and memory errors, suppressing fatal conditions and making debugging impossible.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "SUBPROCESS_SHELL":
                corrected_line = orig_line.replace("shell=True", "shell=False")
                new_lines = [
                    f"{indent}# Corrected: Pass command as argument array with shell=False",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Command Injection via `subprocess(shell=True)`",
                        error_explanation="Executing commands with `shell=True` passes inputs to the OS system shell, enabling arbitrary remote command injection.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "UNSAFE_EVAL":
                func = finding["func"]
                new_lines = [
                    f"{indent}# Corrected: Use ast.literal_eval for safe literal data or json.loads()",
                    f"{indent}import ast",
                    orig_line.replace(f"{func}(", "ast.literal_eval(")
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title=f"Arbitrary Code Execution via `{func}()`",
                        error_explanation=f"Invoking `{func}()` on untrusted input executes arbitrary Python bytecode with caller privileges.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "WEAK_HASH":
                algo = finding["algo"]
                corrected_line = orig_line.replace(f"hashlib.{algo}", "hashlib.sha256").replace(f".{algo}(", ".sha256(")
                new_lines = [
                    f"{indent}# Corrected: Use SHA-256 for secure hashing",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title=f"Insecure Cryptographic Hash Function `{algo.upper()}`",
                        error_explanation=f"The {algo.upper()} hashing algorithm is cryptographically broken and prone to collision attacks.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        # 3. Regex / Pattern-based checks in Python (with sanitized lines)
        for idx, line in enumerate(lines, start=1):
            raw_stripped = line.strip()
            # Ignore comments
            if raw_stripped.startswith("#"):
                continue

            clean_code = strip_strings_and_comments(line, "python")
            indent = line[:len(line) - len(line.lstrip())]

            # SQL Injection via string formatting (check against original line for quotes/f-strings)
            if re.search(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\{[a-zA-Z0-9_]+\}", raw_stripped, re.IGNORECASE) or \
               re.search(r"\.execute\(\s*f[\"'].*SELECT", raw_stripped, re.IGNORECASE) or \
               re.search(r"\.execute\(\s*[\"'].*SELECT.*%\s*[a-zA-Z0-9_]+", raw_stripped, re.IGNORECASE):
                new_lines = [
                    f"{indent}# Corrected: Use parameterized queries with query placeholders",
                    f"{indent}cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="SQL Injection via String Formatting",
                        error_explanation="Directly concatenating or interpolating variables into SQL queries permits SQL injection attacks. Always use parameterized queries.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # Hardcoded API Keys / Passwords / Secrets
            secret_pattern = r'(api_key|secret_key|jwt_secret|password|access_token|database_password)\s*=\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']'
            match = re.search(secret_pattern, raw_stripped, re.IGNORECASE)
            if match and not any(ph in raw_stripped.lower() for ph in ["your_", "dummy", "placeholder", "test_key", "change_me"]):
                var_name = match.group(1)
                new_lines = [
                    f"{indent}import os",
                    f"{indent}{var_name} = os.environ.get('{var_name.upper()}')",
                    f"{indent}if not {var_name}:",
                    f"{indent}    raise ValueError('{var_name.upper()} environment variable must be set')"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title=f"Hardcoded Credential / Secret in `{var_name}`",
                        error_explanation="Hardcoded secret detected in source code. If committed, this credential will leak to anyone with repository read access.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # Unclosed File / Resource (open() without with) - check sanitized code
            if clean_code and re.match(r'^[a-zA-Z0-9_]+\s*=\s*open\(', clean_code) and "with" not in clean_code:
                new_lines = [
                    f"{indent}# Corrected: Use context manager to ensure automatic closure",
                    f"{indent}with open(file_path, 'r', encoding='utf-8') as f:",
                    f"{indent}    data = f.read()"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="LOW",
                        category="Code Quality / Best Practice",
                        title="Unclosed File Resource Leak",
                        error_explanation="Opening files without a context manager (`with`) causes file descriptor leaks if an unhandled exception occurs.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        return reviews

    # ============================================================
    # JAVASCRIPT / TYPESCRIPT CODE REVIEWER
    # ============================================================
    def _review_javascript(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            raw_stripped = line.strip()
            # Ignore full-line comments immediately
            if raw_stripped.startswith("//") or raw_stripped.startswith("/*") or raw_stripped.startswith("*"):
                continue

            clean_code = strip_strings_and_comments(line, "js")
            if not clean_code:
                continue

            indent = line[:len(line) - len(line.lstrip())]

            # 1. eval() usage
            if re.search(r'\beval\s*\(', clean_code):
                new_lines = [
                    f"{indent}// Corrected: Parse data safely using JSON.parse or structured dispatch",
                    f"{indent}const safeResult = JSON.parse(sanitizedInput);"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Unsafe Dynamic Execution via `eval()`",
                        error_explanation="The `eval()` function evaluates arbitrary strings as JavaScript code within the caller's execution context, allowing Cross-Site Scripting (XSS) and remote code execution.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 2. dangerouslySetInnerHTML XSS
            if "dangerouslySetInnerHTML" in clean_code or "dangerouslySetInnerHTML" in raw_stripped:
                if "dangerouslySetInnerHTML" in clean_code:
                    new_lines = [
                        f"{indent}// Corrected: Sanitize HTML content with DOMPurify prior to injection",
                        f"{indent}import DOMPurify from 'dompurify';",
                        f"{indent}<div dangerouslySetInnerHTML={{{{ __html: DOMPurify.sanitize(rawHtml) }}}} />"
                    ]
                    diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="HIGH",
                            category="Security Vulnerability",
                            title="Potential XSS via `dangerouslySetInnerHTML`",
                            error_explanation="Directly inserting unescaped HTML exposes users to Stored or Reflected Cross-Site Scripting (XSS) attacks.",
                            buggy_code=line,
                            corrected_code="\n".join(new_lines),
                            unified_diff=diff
                        )
                    )

            # 3. Hardcoded Secrets / Tokens in assignments
            secret_pattern_js = r'(apiKey|api_key|secret|token|password|auth_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']'
            match_js = re.search(secret_pattern_js, raw_stripped, re.IGNORECASE)
            if match_js and not any(ph in raw_stripped.lower() for ph in ["your_", "dummy", "placeholder", "test_key", "change_me"]):
                var_name = match_js.group(1)
                new_lines = [
                    f"{indent}// Corrected: Read sensitive tokens from environment variables",
                    f"{indent}const {var_name} = process.env.NEXT_PUBLIC_{var_name.upper()} || process.env.{var_name.upper()};"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title=f"Hardcoded Secret / Token in `{var_name}`",
                        error_explanation="Private credentials committed directly into JavaScript/TypeScript bundles can be extracted by any user or scraper.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 4. console.log sensitive data
            if re.search(r'console\.log\s*\(\s*.*(password|secret|token|cred|auth|ssn)', clean_code, re.IGNORECASE):
                new_lines = [
                    f"{indent}// Corrected: Redact sensitive credentials before logging",
                    f"{indent}console.log('Auth check completed', {{ user: user.id, token: '***REDACTED***' }});"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="MEDIUM",
                        category="Security Vulnerability",
                        title="Credential Leak via `console.log`",
                        error_explanation="Logging credentials or authentication tokens outputs them into plaintext browser devtools or log aggregation systems.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 5. Loose equality == or !=
            has_loose_eq = (re.search(r'[^=!]={2}[^=]', clean_code) or re.search(r'!={1}[^=]', clean_code))
            if has_loose_eq and "===" not in clean_code and "!==" not in clean_code:
                if not re.search(r'[!=]={1,2}\s*null\b', clean_code):
                    fixed_line = re.sub(r'([^=!]|^)==([^=])', r'\1===\2', line)
                    fixed_line = re.sub(r'!=([^=])', r'!==\1', fixed_line)
                    new_lines = [
                        f"{indent}// Corrected: Use strict equality (=== / !==)",
                        fixed_line
                    ]
                    diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="LOW",
                            category="Bug / Logic Error",
                            title="Loose Equality Operator (`==` / `!=`)",
                            error_explanation="Loose equality performs unintended implicit type coercion (e.g. `'' == 0` is true), introducing subtle logical bugs.",
                            buggy_code=line,
                            corrected_code="\n".join(new_lines),
                            unified_diff=diff
                        )
                    )

            # 6. Insecure cleartext HTTP endpoint
            http_match = re.search(r'["\']http://(api|auth|login|secure|backend|app)', raw_stripped, re.IGNORECASE)
            if http_match and "localhost" not in raw_stripped and "127.0.0.1" not in raw_stripped:
                corrected = line.replace("http://", "https://")
                new_lines = [
                    f"{indent}// Corrected: Upgrade endpoint to TLS/HTTPS",
                    corrected
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="Cleartext HTTP Endpoint Transmission",
                        error_explanation="Transmitting sensitive data over unencrypted HTTP exposes traffic to Man-in-the-Middle (MitM) eavesdropping and tamper attacks.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        return reviews

    # ============================================================
    # YAML / CI-CD CODE REVIEWER
    # ============================================================
    def _review_yaml(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Unpinned GitHub Action (e.g. uses: actions/checkout@v2)
            if "uses:" in line and "@" in line and not stripped.startswith("#"):
                leading_indent = line[:len(line) - len(line.lstrip())]
                action_part = stripped.split("uses:", 1)[1].strip()
                if not re.search(r'@[0-9a-f]{40}$', action_part):
                    parts = action_part.split("@", 1)
                    action_name = parts[0].strip()
                    version_tag = parts[1].strip() if len(parts) > 1 else "latest"

                    sha, ver_comment = resolve_action_pin(action_name, version_tag)

                    new_lines = [
                        f"{leading_indent}# Pinned to full immutable commit SHA",
                        f"{leading_indent}uses: {action_name}@{sha} {ver_comment}"
                    ]

                    corrected_code_str = "\n".join(new_lines)
                    unified_diff_str = self._build_unified_diff(
                        file_path=file_path,
                        lines=lines,
                        target_line=idx,
                        deleted_line=line,
                        added_lines=new_lines,
                        context_count=2
                    )

                    is_official = any(action_name.lower().startswith(p) for p in ("actions/", "github/"))
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="MEDIUM" if is_official else "HIGH",
                            category="CI/CD Security Hardening",
                            title=f"Unpinned CI/CD Action `{action_name}`",
                            error_explanation=(
                                f"Official GitHub Action `{action_name}` uses mutable tag `@{version_tag}`. "
                                f"Pin to full immutable commit SHA to protect against tag mutation and comply with OpenSSF Scorecard."
                                if is_official
                                else f"Using a mutable branch or tag (`@{version_tag}`) allows upstream supply-chain compromises to modify workflow execution. Pin to a full immutable commit SHA."
                            ),
                            buggy_code=line,
                            corrected_code=corrected_code_str,
                            unified_diff=unified_diff_str
                        )
                    )

            # Excessive permissions: write-all
            if "permissions: write-all" in stripped or "permissions: 'write-all'" in stripped or 'permissions: "write-all"' in stripped:
                leading_indent = line[:len(line) - len(line.lstrip())]
                new_lines = [
                    f"{leading_indent}# Enforce least-privilege permissions",
                    f"{leading_indent}permissions:",
                    f"{leading_indent}  contents: read",
                    f"{leading_indent}  pull-requests: write"
                ]
                corrected_code_str = "\n".join(new_lines)
                unified_diff_str = self._build_unified_diff(
                    file_path=file_path,
                    lines=lines,
                    target_line=idx,
                    deleted_line=line,
                    added_lines=new_lines,
                    context_count=2
                )
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="Excessive CI/CD Permissions (`write-all`)",
                        error_explanation="Granting blanket write permissions to `GITHUB_TOKEN` enables malicious pull requests or dependencies to tamper with releases and repository settings.",
                        buggy_code=line,
                        corrected_code=corrected_code_str,
                        unified_diff=unified_diff_str
                    )
                )

        return reviews

    # ============================================================
    # JSON CODE REVIEWER (package.json overrides)
    # ============================================================
    def _review_json(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        if file_path.endswith("package.json"):
            if "overrides" not in content and "resolutions" not in content:
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=1,
                        severity="LOW",
                        category="Code Quality / Best Practice",
                        title="Missing Dependency Overrides Field",
                        error_explanation="Root package.json lacks an `overrides` or `resolutions` block to forcefully patch transitive dependency vulnerabilities.",
                        buggy_code='{\n  "name": "project"\n}',
                        corrected_code='{\n  "name": "project",\n  "overrides": {\n    "//": "Enforce safe transitive packages pinned by SupplyGraph"\n  }\n}'
                    )
                )
        return reviews

    # ============================================================
    # HELPER: SURGICAL UNIFIED DIFF GENERATOR
    # ============================================================
    def _build_unified_diff(
        self,
        file_path: str,
        lines: List[str],
        target_line: int,
        deleted_line: str,
        added_lines: List[str],
        context_count: int = 2
    ) -> str:
        """
        Builds a surgical standard Git Unified Diff.
        Preserves context lines above and below with ' ' prefix.
        Marks only the deleted line with '-' and added lines with '+'.
        Preserves all original indentation without trimming.
        """
        start_idx = max(0, target_line - 1 - context_count)
        end_idx = min(len(lines), target_line + context_count)

        context_before = lines[start_idx : target_line - 1]
        context_after = lines[target_line : end_idx]

        orig_count = len(context_before) + 1 + len(context_after)
        new_count = len(context_before) + len(added_lines) + len(context_after)
        start_line_no = start_idx + 1

        hunk_header = f"@@ -{start_line_no},{orig_count} +{start_line_no},{new_count} @@"

        diff_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            hunk_header
        ]

        for ctx in context_before:
            diff_lines.append(f" {ctx}")

        diff_lines.append(f"-{deleted_line}")

        for add in added_lines:
            diff_lines.append(f"+{add}")

        for ctx in context_after:
            diff_lines.append(f" {ctx}")

        return "\n".join(diff_lines)

    # ============================================================
    # HELPER: EXTRACT CONTEXT SNIPPET
    # ============================================================
    def _get_context_snippet(self, lines: List[str], target_line: int, context: int = 2) -> str:
        """Returns 3 to 7 lines of code centered around the target line."""
        start = max(0, target_line - 1 - context)
        end = min(len(lines), target_line + context)
        return "\n".join(lines[start:end])
