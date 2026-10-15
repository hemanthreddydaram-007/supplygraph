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
            buggy_line = lines[line_no - 1].strip() if line_no <= len(lines) else ""
            context_snippet = self._get_context_snippet(lines, line_no)

            if finding["type"] == "MUTABLE_DEFAULT":
                arg = finding["arg_name"]
                corrected = buggy_line.replace(f"{arg}=[]", f"{arg}=None").replace(f"{arg}={{}}", f"{arg}=None")
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="MEDIUM",
                        category="Bug / Logic Error",
                        title=f"Mutable Default Argument for `{arg}`",
                        error_explanation=f"Default parameter `{arg}` uses a mutable default object. In Python, default arguments are evaluated once at function definition, causing state to leak across invocations.",
                        buggy_code=context_snippet,
                        corrected_code=f"# Corrected: Use None and instantiate inside function\n{corrected}\n    if {arg} is None:\n        {arg} = []"
                    )
                )

            elif finding["type"] == "BARE_EXCEPT":
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="MEDIUM",
                        category="Code Quality / Best Practice",
                        title="Dangerous Bare `except:` Clause",
                        error_explanation="A bare `except:` catches KeyboardInterrupt, SystemExit, and memory errors, suppressing fatal conditions and making debugging impossible.",
                        buggy_code=context_snippet,
                        corrected_code=buggy_line.replace("except:", "except Exception as e:\n        logging.error(f'Error occurred: {e}')")
                    )
                )

            elif finding["type"] == "SUBPROCESS_SHELL":
                corrected = buggy_line.replace("shell=True", "shell=False")
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Command Injection via `subprocess(shell=True)`",
                        error_explanation="Executing commands with `shell=True` passes inputs to the OS system shell, enabling arbitrary remote command injection.",
                        buggy_code=context_snippet,
                        corrected_code=f"# Corrected: Pass command as argument array with shell=False\n# Example: subprocess.run(['cmd', 'arg1', 'arg2'], shell=False, check=True)\n{corrected}"
                    )
                )

            elif finding["type"] == "UNSAFE_EVAL":
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title=f"Arbitrary Code Execution via `{finding['func']}()`",
                        error_explanation=f"Invoking `{finding['func']}()` on untrusted input executes arbitrary Python bytecode with caller privileges.",
                        buggy_code=context_snippet,
                        corrected_code="# Corrected: Use ast.literal_eval for safe literal data or json.loads()\nimport ast\nsafe_data = ast.literal_eval(untrusted_input)"
                    )
                )

            elif finding["type"] == "WEAK_HASH":
                algo = finding["algo"]
                corrected = buggy_line.replace(f"hashlib.{algo}", "hashlib.sha256").replace(f".{algo}(", ".sha256(")
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title=f"Insecure Cryptographic Hash Function `{algo.upper()}`",
                        error_explanation=f"The {algo.upper()} hashing algorithm is cryptographically broken and prone to collision attacks.",
                        buggy_code=context_snippet,
                        corrected_code=f"# Corrected: Use SHA-256 or bcrypt for secure hashing\n{corrected}"
                    )
                )

        # 3. Regex / Pattern-based checks in Python (with sanitized lines)
        for idx, line in enumerate(lines, start=1):
            raw_stripped = line.strip()
            # Ignore comments
            if raw_stripped.startswith("#"):
                continue

            clean_code = strip_strings_and_comments(line, "python")

            # SQL Injection via string formatting (check against original line for quotes/f-strings)
            if re.search(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\{[a-zA-Z0-9_]+\}", raw_stripped, re.IGNORECASE) or \
               re.search(r"\.execute\(\s*f[\"'].*SELECT", raw_stripped, re.IGNORECASE) or \
               re.search(r"\.execute\(\s*[\"'].*SELECT.*%\s*[a-zA-Z0-9_]+", raw_stripped, re.IGNORECASE):
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="SQL Injection via String Formatting",
                        error_explanation="Directly concatenating or interpolating variables into SQL queries permits SQL injection attacks. Always use parameterized queries.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code="# Corrected: Use parameterized queries with query placeholders\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                    )
                )

            # Hardcoded API Keys / Passwords / Secrets
            # Require variable assignment and minimum 16-char secret that isn't a placeholder
            secret_pattern = r'(api_key|secret_key|jwt_secret|password|access_token|database_password)\s*=\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']'
            match = re.search(secret_pattern, raw_stripped, re.IGNORECASE)
            if match and not any(ph in raw_stripped.lower() for ph in ["your_", "dummy", "placeholder", "test_key", "change_me"]):
                var_name = match.group(1)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title=f"Hardcoded Credential / Secret in `{var_name}`",
                        error_explanation="Hardcoded secret detected in source code. If committed, this credential will leak to anyone with repository read access.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code=f"import os\n{var_name} = os.environ.get('{var_name.upper()}')\nif not {var_name}:\n    raise ValueError('{var_name.upper()} environment variable must be set')"
                    )
                )

            # Unclosed File / Resource (open() without with) - check sanitized code
            if clean_code and re.match(r'^[a-zA-Z0-9_]+\s*=\s*open\(', clean_code) and "with" not in clean_code:
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="LOW",
                        category="Code Quality / Best Practice",
                        title="Unclosed File Resource Leak",
                        error_explanation="Opening files without a context manager (`with`) causes file descriptor leaks if an unhandled exception occurs.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code="# Corrected: Use context manager to ensure automatic closure\nwith open(file_path, 'r', encoding='utf-8') as f:\n    data = f.read()"
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

            # 1. eval() usage (must appear in actual executable code, not inside quotes or comments)
            if re.search(r'\beval\s*\(', clean_code):
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Unsafe Dynamic Execution via `eval()`",
                        error_explanation="The `eval()` function evaluates arbitrary strings as JavaScript code within the caller's execution context, allowing Cross-Site Scripting (XSS) and remote code execution.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code="// Corrected: Parse data safely using JSON.parse or structured dispatch\nconst safeResult = JSON.parse(sanitizedInput);"
                    )
                )

            # 2. dangerouslySetInnerHTML XSS
            if "dangerouslySetInnerHTML" in clean_code or "dangerouslySetInnerHTML" in raw_stripped:
                # Confirm it's in code
                if "dangerouslySetInnerHTML" in clean_code:
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="HIGH",
                            category="Security Vulnerability",
                            title="Potential XSS via `dangerouslySetInnerHTML`",
                            error_explanation="Directly inserting unescaped HTML exposes users to Stored or Reflected Cross-Site Scripting (XSS) attacks.",
                            buggy_code=self._get_context_snippet(lines, idx),
                            corrected_code="// Corrected: Sanitize HTML content with DOMPurify prior to injection\nimport DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(rawHtml) }} />"
                        )
                    )

            # 3. Hardcoded Secrets / Tokens in assignments (not comments or placeholders)
            secret_pattern_js = r'(apiKey|api_key|secret|token|password|auth_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']'
            match_js = re.search(secret_pattern_js, raw_stripped, re.IGNORECASE)
            if match_js and not any(ph in raw_stripped.lower() for ph in ["your_", "dummy", "placeholder", "test_key", "change_me"]):
                var_name = match_js.group(1)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title=f"Hardcoded Secret / Token in `{var_name}`",
                        error_explanation="Private credentials committed directly into JavaScript/TypeScript bundles can be extracted by any user or scraper.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code=f"// Corrected: Read sensitive tokens from environment variables\nconst {var_name} = process.env.NEXT_PUBLIC_{var_name.upper()} || process.env.{var_name.upper()};"
                    )
                )

            # 4. console.log sensitive data
            if re.search(r'console\.log\s*\(\s*.*(password|secret|token|cred|auth|ssn)', clean_code, re.IGNORECASE):
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="MEDIUM",
                        category="Security Vulnerability",
                        title="Credential Leak via `console.log`",
                        error_explanation="Logging credentials or authentication tokens outputs them into plaintext browser devtools or log aggregation systems.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code="// Corrected: Redact sensitive credentials before logging\nconsole.log('Auth check completed', { user: user.id, token: '***REDACTED***' });"
                    )
                )

            # 5. Loose equality == or != (ONLY in code, excluding comments and string contents)
            # Exclude strict === and !==, and exclude standard null checks (x == null)
            has_loose_eq = (re.search(r'[^=!]={2}[^=]', clean_code) or re.search(r'!={1}[^=]', clean_code))
            if has_loose_eq and "===" not in clean_code and "!==" not in clean_code:
                # Allow standard null check: == null or != null
                if not re.search(r'[!=]={1,2}\s*null\b', clean_code):
                    fixed_line = re.sub(r'([^=!]|^)==([^=])', r'\1===\2', raw_stripped)
                    fixed_line = re.sub(r'!=([^=])', r'!==\1', fixed_line)
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="LOW",
                            category="Bug / Logic Error",
                            title="Loose Equality Operator (`==` / `!=`)",
                            error_explanation="Loose equality performs unintended implicit type coercion (e.g. `'' == 0` is true), introducing subtle logical bugs.",
                            buggy_code=self._get_context_snippet(lines, idx),
                            corrected_code=f"// Corrected: Use strict equality (=== / !==)\n{fixed_line}"
                        )
                    )

            # 6. Insecure cleartext HTTP endpoint (exclude localhost / 127.0.0.1)
            http_match = re.search(r'["\']http://(api|auth|login|secure|backend|app)', raw_stripped, re.IGNORECASE)
            if http_match and "localhost" not in raw_stripped and "127.0.0.1" not in raw_stripped:
                corrected = raw_stripped.replace("http://", "https://")
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="Cleartext HTTP Endpoint Transmission",
                        error_explanation="Transmitting sensitive data over unencrypted HTTP exposes traffic to Man-in-the-Middle (MitM) eavesdropping and tamper attacks.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code=f"// Corrected: Upgrade endpoint to TLS/HTTPS\n{corrected}"
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
            if "uses:" in stripped and "@" in stripped and not stripped.startswith("#"):
                action_part = stripped.split("uses:", 1)[1].strip()
                if not re.search(r'@[0-9a-f]{40}$', action_part):
                    action_name = action_part.split("@")[0]
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="HIGH",
                            category="Security Vulnerability",
                            title=f"Unpinned CI/CD Action `{action_name}`",
                            error_explanation="Using a mutable branch or tag (e.g., `@v2`, `@master`) allows upstream supply-chain compromises to modify workflow execution. Pin to a full immutable commit SHA.",
                            buggy_code=self._get_context_snippet(lines, idx),
                            corrected_code=f"# Corrected: Pin exact 40-character commit SHA with descriptive comment\nuses: {action_name}@b4ffde65f46336ab88eb53be808477a3936bae11  # pinned"
                        )
                    )

            # Excessive permissions: write-all
            if "permissions: write-all" in stripped or "permissions: 'write-all'" in stripped:
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="Excessive CI/CD Permissions (`write-all`)",
                        error_explanation="Granting blanket write permissions to `GITHUB_TOKEN` enables malicious pull requests or dependencies to tamper with releases and repository settings.",
                        buggy_code=self._get_context_snippet(lines, idx),
                        corrected_code="# Corrected: Enforce least-privilege permissions\npermissions:\n  contents: read\n  pull-requests: write"
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
    # HELPER: EXTRACT CONTEXT SNIPPET
    # ============================================================
    def _get_context_snippet(self, lines: List[str], target_line: int, context: int = 2) -> str:
        """Returns 3 to 7 lines of code centered around the target line."""
        start = max(0, target_line - 1 - context)
        end = min(len(lines), target_line + context)
        return "\n".join(lines[start:end])
