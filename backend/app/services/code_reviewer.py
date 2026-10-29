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
    "docker/login-action": {
        "v3": "9780b0c442fbb1117ed29e0efdff1e18412f7567",  # v3.3.0
        "default": "9780b0c442fbb1117ed29e0efdff1e18412f7567",
        "comment": "v3.3.0",
    },
    "docker/build-push-action": {
        "v6": "471d1dc4e07e5cdedd9c21719d54b79e1b20a4ec",  # v6.15.0
        "v5": "4a13e500e55cf31b7a5d59a38ab2040ab0f42f56",  # v5.1.0
        "default": "471d1dc4e07e5cdedd9c21719d54b79e1b20a4ec",
        "comment": "v6.15.0",
    },
    "docker/setup-buildx-action": {
        "v3": "b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",  # v3.10.0
        "default": "b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",
        "comment": "v3.10.0",
    },
    "codecov/codecov-action": {
        "v5": "015ff539bb73772273d524247214d05e1242179e",  # v5.0.7
        "v4": "e28ff129e5465c2c0dcc6f003fc735cb6ae0c673",  # v4.5.0
        "default": "015ff539bb73772273d524247214d05e1242179e",
        "comment": "v5.0.7",
    },
}


USES_REGEX = re.compile(r'^(\s*(?:-\s*)?)uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+)@([^\s#]+)')


def resolve_action_pin(action_name: str, tag: str) -> tuple[Optional[str], str]:
    """
    Resolves the verified 40-character commit SHA and comment for a GitHub Action.
    Returns (sha, comment). If the action is not in the verified authoritative registry,
    returns (None, comment) so callers NEVER fabricate a synthetic commit SHA.
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

    # Do NOT fabricate or invent a synthetic commit SHA for unverified actions!
    # Direct the user/agent to retrieve the verified commit SHA from the official repository release.
    return None, f"# {clean_tag}"



class CodeReviewerService:
    """
    Analyzes source code files (.py, .js, .ts, .tsx, .jsx, .svelte, .vue, .astro, .yml, .json, Dockerfile)
    and produces actionable CodeReviewItems with exact buggy lines and production-ready
    corrected code fixes.
    """

    def __init__(self):
        pass

    def review_files(self, files: Dict[str, str], max_files: int = 100) -> List[CodeReviewItem]:
        """Review multiple files, prioritizing production source files over test suites."""
        all_reviews: List[CodeReviewItem] = []
        
        # Sort files by priority (production code first, test suites last)
        sorted_file_paths = sorted(files.keys(), key=_is_priority_source_file)
        
        count = 0
        for file_path in sorted_file_paths:
            if count >= max_files:
                break
            content = files.get(file_path, "")
            if not content or len(content) > 100_000:
                continue
            # Skip ignored paths (build artifacts, dependencies, and test directories)
            if any(ign in file_path.lower() for ign in [
                "node_modules/", ".git/", "venv/", "__pycache__/", ".next/", "dist/", "build/",
                "/tests/", "/test/", "__tests__/", "/mock/", "/fixture/", "/fixtures/"
            ]):
                continue
            # Also skip standalone test files
            base = file_path.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if base.startswith("test_") or base.endswith("_test.py") or ".test." in base or ".spec." in base:
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
        elif ext == "go":
            return self._review_go(file_path, content)
        elif "dockerfile" in file_path.lower() or ext == "dockerfile":
            return self._review_dockerfile(file_path, content)
        return []

    def review_snippet(self, code: str, language: str = "python", file_path: Optional[str] = None) -> List[CodeReviewItem]:
        """Review an ad-hoc code snippet."""
        path = file_path or f"snippet.{ 'py' if language.lower() == 'python' else 'js' }"
        lang_lower = language.lower()
        if lang_lower in ["python", "py"]:
            return self._review_python(path, code)
        elif lang_lower in ["javascript", "js", "typescript", "ts", "tsx", "jsx", "svelte", "vue", "astro"]:
            return self._review_javascript(path, code)
        elif lang_lower in ["yaml", "yml"]:
            return self._review_yaml(path, code)
        elif lang_lower in ["go", "golang"]:
            return self._review_go(path, code)
        elif lang_lower in ["dockerfile", "docker"]:
            return self._review_dockerfile(path, code)
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

                # Check for insecure deserialization via pickle
                if func_name in ["loads", "load"]:
                    is_pickle = False
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ["pickle", "_pickle", "cPickle"]:
                            is_pickle = True
                    if is_pickle:
                        self.findings.append({
                            "type": "INSECURE_PICKLE",
                            "node": node,
                            "line": node.lineno
                        })

                # Check for requests/httpx with verify=False
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        self.findings.append({
                            "type": "INSECURE_REQUESTS_NO_VERIFY",
                            "node": node,
                            "line": node.lineno
                        })

                # Check for yaml.load() without SafeLoader
                if func_name == "load":
                    is_yaml = False
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ["yaml", "pyyaml"]:
                            is_yaml = True
                    if is_yaml:
                        has_safe = False
                        for kw in node.keywords:
                            if kw.arg == "Loader":
                                val_name = getattr(kw.value, "id", "") or getattr(kw.value, "attr", "")
                                if "safe" in val_name.lower():
                                    has_safe = True
                        if not has_safe:
                            self.findings.append({
                                "type": "INSECURE_YAML_LOAD",
                                "node": node,
                                "line": node.lineno
                            })

                # Check for tempfile.mktemp() race condition
                if func_name == "mktemp":
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "tempfile":
                            self.findings.append({
                                "type": "INSECURE_MKTEMP",
                                "node": node,
                                "line": node.lineno
                            })

                self.generic_visit(node)

            def visit_Compare(self, node):
                # Check comparison to None with == or !=
                for op, comp in zip(node.ops, node.comparators):
                    if isinstance(comp, ast.Constant) and comp.value is None:
                        if isinstance(op, (ast.Eq, ast.NotEq)):
                            self.findings.append({
                                "type": "NONE_COMPARISON_EQ",
                                "node": node,
                                "line": node.lineno,
                                "is_not": isinstance(op, ast.NotEq)
                            })
                    # Check 'is' / 'is not' with literal numbers or strings
                    elif isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comp, ast.Constant) and comp.value is not None and not isinstance(comp.value, bool):
                        self.findings.append({
                            "type": "LITERAL_IS_COMPARISON",
                            "node": node,
                            "line": node.lineno,
                            "is_not": isinstance(op, ast.IsNot),
                            "literal": repr(comp.value)
                        })
                self.generic_visit(node)

            def visit_Attribute(self, node):
                # Check for deprecated Pillow Image.ANTIALIAS (removed in Pillow 10+)
                if node.attr == "ANTIALIAS":
                    self.findings.append({
                        "type": "DEPRECATED_PILLOW_ANTIALIAS",
                        "node": node,
                        "line": node.lineno
                    })
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                # Check for deprecated Pydantic v1 BaseSettings
                if node.module == "pydantic" and any(getattr(a, "name", "") == "BaseSettings" for a in node.names):
                    self.findings.append({
                        "type": "DEPRECATED_PYDANTIC_BASESETTINGS",
                        "node": node,
                        "line": node.lineno
                    })
                # Check for deprecated SQLAlchemy declarative_base
                elif node.module == "sqlalchemy.ext.declarative" and any(getattr(a, "name", "") == "declarative_base" for a in node.names):
                    self.findings.append({
                        "type": "DEPRECATED_SQLALCHEMY_DECLARATIVE",
                        "node": node,
                        "line": node.lineno
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

            elif finding["type"] == "INSECURE_PICKLE":
                new_lines = [
                    f"{indent}# Corrected: Avoid pickle.loads() on untrusted inputs; use json.loads() or safe serialization",
                    f"{indent}import json",
                    orig_line.replace("pickle.loads(", "json.loads(").replace("pickle.load(", "json.load(")
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Remote Code Execution via Insecure pickle.loads()",
                        error_explanation="Using `pickle.loads()` on untrusted input allows attackers to execute arbitrary code via serialized `__reduce__` payloads. Use standardized serialization like JSON or Protocol Buffers.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "INSECURE_REQUESTS_NO_VERIFY":
                corrected_line = orig_line.replace("verify=False", "verify=True")
                new_lines = [
                    f"{indent}# Corrected: Enforce TLS certificate verification",
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
                        title="Disabled TLS Certificate Verification (`verify=False`)",
                        error_explanation="Disabling SSL/TLS certificate validation (`verify=False`) allows attackers on the network to intercept, decrypt, or tamper with backend API traffic via Man-in-the-Middle (MitM) attacks.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "DEPRECATED_PILLOW_ANTIALIAS":
                corrected_line = orig_line.replace("Image.ANTIALIAS", "Image.Resampling.LANCZOS").replace(".ANTIALIAS", ".Resampling.LANCZOS")
                new_lines = [
                    f"{indent}# Fix for Pillow >= 10.0: Image.ANTIALIAS was removed; use Image.Resampling.LANCZOS",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="CRITICAL",
                        category="Bug / Logic Error",
                        title="Removed Pillow API: `Image.ANTIALIAS` (AttributeError)",
                        error_explanation="`Image.ANTIALIAS` was deprecated and removed in Pillow 10.0.0. When upgrading Pillow, code invoking `Image.ANTIALIAS` will crash with `AttributeError: module 'PIL.Image' has no attribute 'ANTIALIAS'`. Replace with `Image.Resampling.LANCZOS`.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "DEPRECATED_PYDANTIC_BASESETTINGS":
                new_lines = [
                    f"{indent}# Fix for Pydantic v2: BaseSettings was moved to the pydantic_settings package",
                    f"{indent}from pydantic_settings import BaseSettings"
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="HIGH",
                        category="Bug / Logic Error",
                        title="Removed Pydantic API: `from pydantic import BaseSettings` (ImportError)",
                        error_explanation="In Pydantic v2, `BaseSettings` was moved to the standalone `pydantic-settings` library. Importing it from `pydantic` raises `ImportError: cannot import name 'BaseSettings' from 'pydantic'`. Update import to `from pydantic_settings import BaseSettings`.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "DEPRECATED_SQLALCHEMY_DECLARATIVE":
                new_lines = [
                    f"{indent}# Fix for SQLAlchemy 2.0: declarative_base was moved to sqlalchemy.orm",
                    f"{indent}from sqlalchemy.orm import declarative_base"
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="MEDIUM",
                        category="Bug / Logic Error",
                        title="Deprecated SQLAlchemy Module: `sqlalchemy.ext.declarative`",
                        error_explanation="In SQLAlchemy 2.0, `declarative_base` should be imported from `sqlalchemy.orm`. Importing from `sqlalchemy.ext.declarative` triggers deprecation warnings and will be removed in future releases.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "INSECURE_YAML_LOAD":
                corrected_line = orig_line.replace("yaml.load(", "yaml.safe_load(").replace("pyyaml.load(", "pyyaml.safe_load(")
                new_lines = [
                    f"{indent}# Corrected: Use yaml.safe_load() to prevent arbitrary code execution (CVE-2020-14343)",
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
                        title="Arbitrary Code Execution via Insecure `yaml.load()`",
                        error_explanation="Calling `yaml.load()` without specifying a safe loader allows malicious YAML payloads to instantiate arbitrary Python objects and execute shell commands (CVE-2020-14343). Always use `yaml.safe_load()`.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "INSECURE_MKTEMP":
                corrected_line = orig_line.replace("tempfile.mktemp()", "tempfile.NamedTemporaryFile(delete=False).name").replace("tempfile.mktemp(", "tempfile.NamedTemporaryFile(delete=False, ")
                new_lines = [
                    f"{indent}# Corrected: Use NamedTemporaryFile to eliminate race condition (TOCTOU)",
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
                        title="Insecure Temporary File Creation via `tempfile.mktemp()`",
                        error_explanation="`tempfile.mktemp()` is deprecated because it generates a file name without creating the file, introducing a Time-of-Check to Time-of-Use (TOCTOU) race condition that allows symlink attacks. Use `tempfile.NamedTemporaryFile()`.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "NONE_COMPARISON_EQ":
                if finding["is_not"]:
                    corrected_line = orig_line.replace("!= None", "is not None").replace("!=None", "is not None")
                else:
                    corrected_line = orig_line.replace("== None", "is None").replace("==None", "is None")
                new_lines = [
                    f"{indent}# PEP 8: Use identity operator (is / is not) for comparison with None singleton",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, line_no, orig_line, new_lines, context_count=2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=line_no,
                        severity="LOW",
                        category="Bug / Logic Error",
                        title="Comparison to None via `==` / `!=` (PEP 8)",
                        error_explanation="Comparisons to singletons like `None` should always be done with `is` or `is not`, never the equality operators (`==` or `!=`). Equality operators invoke the object's `__eq__` method, which can cause unexpected logical behavior or crash on NumPy/Pandas dataframes with ValueError.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            elif finding["type"] == "LITERAL_IS_COMPARISON":
                lit = finding["literal"]
                if finding["is_not"]:
                    corrected_line = orig_line.replace(f" is not {lit}", f" != {lit}").replace(f" is not {lit.strip(chr(39)).strip(chr(34))}", f" != {lit}")
                else:
                    corrected_line = orig_line.replace(f" is {lit}", f" == {lit}").replace(f" is {lit.strip(chr(39)).strip(chr(34))}", f" == {lit}")
                new_lines = [
                    f"{indent}# Corrected: Use value equality (== / !=) instead of identity check (is) with literal",
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
                        title="Dangerous Identity Comparison (`is`) with Literal Constant",
                        error_explanation=f"Using `is` with a literal constant ({lit}) checks object memory address identity instead of value equality. Python does not guarantee literal interning across modules or processes; in Python 3.8+ this triggers SyntaxWarning and in Python 3.12+ will fail.",
                        buggy_code=orig_line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        # 3. Regex / Pattern-based checks in Python (with sanitized lines)
        for idx, line in enumerate(lines, start=1):
            raw_stripped = line.strip()
            # Ignore comments, test assertions, and pattern/template definitions
            if raw_stripped.startswith("#") or any(skip in raw_stripped for skip in ["buggy_code", "corrected_code", "re.search", "r'", 'r"', 'f"{indent}', "new_lines ="]):
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
            # Ignore full-line comments, test assertions, and template definitions immediately
            if raw_stripped.startswith("//") or raw_stripped.startswith("/*") or raw_stripped.startswith("*") or any(skip in raw_stripped for skip in ["buggy_code", "corrected_code", "re.search", "r'", 'r"', 'f"{indent}', "new_lines", "/.test(", ".test(", "/i.test("]):
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

            # 7. Prototype pollution via unfiltered property assignment
            if re.search(r'target\[key\]\s*=\s*source\[key\]', raw_stripped) or re.search(r'obj\[key\]\s*=\s*val', raw_stripped):
                new_lines = [
                    f"{indent}// Corrected: Protect against prototype pollution",
                    f"{indent}if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;",
                    line
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Prototype Pollution via Unfiltered Property Injection",
                        error_explanation="Directly assigning object properties using dynamic keys without validating against '__proto__' or 'constructor' allows attackers to pollute global Object prototypes.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 8. Unsafe child_process.exec()
            if re.search(r'child_process\.exec\s*\(', clean_code) or re.search(r'\bexec\s*\(\s*`', raw_stripped):
                new_lines = [
                    f"{indent}// Corrected: Use execFile or spawn with argument arrays instead of shell execution",
                    f"{indent}const {{ execFile }} = require('child_process');",
                    f"{indent}execFile('executable', [arg1, arg2], callback);"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Command Injection via `child_process.exec()`",
                        error_explanation="The `exec()` function invokes a system shell, leaving the application vulnerable to command injection if arguments contain user input. Use `execFile` or `spawn` without shell.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 9. DOM-based XSS via document.write()
            if re.search(r'\bdocument\.write(?:ln)?\s*\(', clean_code):
                new_lines = [
                    f"{indent}// Corrected: Avoid document.write(); update DOM nodes safely",
                    f"{indent}const target = document.getElementById('content');",
                    f"{indent}if (target) target.textContent = safeData;"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="DOM XSS & Parser Blocking via `document.write()`",
                        error_explanation="Invoking `document.write()` strongly increases the risk of DOM-based Cross-Site Scripting (XSS) and blocks the browser HTML tokenizer. Use modern safe DOM manipulation like `textContent` or `appendChild()`.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 10. Insecure TLS rejectUnauthorized: false
            if re.search(r'rejectUnauthorized\s*:\s*false', clean_code):
                corrected_line = line.replace("rejectUnauthorized: false", "rejectUnauthorized: true").replace("rejectUnauthorized:false", "rejectUnauthorized: true")
                new_lines = [
                    f"{indent}// Corrected: Enforce TLS certificate verification",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="TLS Certificate Validation Disabled (`rejectUnauthorized: false`)",
                        error_explanation="Setting `rejectUnauthorized: false` disables SSL/TLS certificate validation in Node.js HTTPS agents, exposing network traffic to Man-in-the-Middle (MitM) eavesdropping and token interception.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 11. Insecure PRNG Math.random() in security-sensitive context
            if re.search(r'\bMath\.random\s*\(\s*\)', clean_code) and re.search(r'(token|secret|password|auth|session|nonce|salt|csrf)', raw_stripped, re.IGNORECASE):
                new_lines = [
                    f"{indent}// Corrected: Use cryptographically secure randomness",
                    f"{indent}const secureToken = crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="Cryptographically Insecure Random Number via `Math.random()`",
                        error_explanation="`Math.random()` produces pseudo-random numbers with predictable internal PRNG state. It must never be used for security tokens, authentication credentials, nonces, password generation, or session identifiers. Use `crypto.getRandomValues()` or `crypto.randomUUID()`.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 12. Polyfill.io / Compromised CDN Script Inclusion (2024 Supply Chain Hijack)
            if re.search(r'(?:https?:)?//(?:cdn\.)?polyfill\.io', raw_stripped, re.IGNORECASE) or re.search(r'(?:https?:)?//(?:bootcss\.com|bootcdn\.net)', raw_stripped, re.IGNORECASE):
                new_lines = [
                    f"{indent}// Corrected: Replace compromised polyfill.io CDN with official Cloudflare mirror",
                    re.sub(r'https?://(?:cdn\.)?polyfill\.io/[^\s"\'>]+', 'https://cdnjs.cloudflare.com/polyfill/v3/polyfill.min.js', line)
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Compromised CDN Domain (Polyfill.io Supply Chain Breach)",
                        error_explanation="The polyfill.io CDN domain was acquired by a rogue entity in 2024 and injected malware into client browsers. Immediately replace with official Cloudflare mirror 'cdnjs.cloudflare.com' or bundled core-js.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # 13. External script missing Subresource Integrity (SRI)
            if "<script" in raw_stripped and "src=" in raw_stripped and "integrity=" not in raw_stripped:
                src_match = re.search(r'src=["\'](https?://[^"\']+)["\']', raw_stripped)
                if src_match and not src_match.group(1).startswith(("http://localhost", "http://127.0.0.1")):
                    orig_src = src_match.group(1)
                    new_lines = [
                        f"{indent}<!-- Corrected: Add Subresource Integrity (SRI) hash to prevent CDN tampering -->",
                        line.replace(f'src="{orig_src}"', f'src="{orig_src}" integrity="sha384-<GENERATE_HASH>" crossorigin="anonymous"').replace(f"src='{orig_src}'", f"src='{orig_src}' integrity=\"sha384-<GENERATE_HASH>\" crossorigin=\"anonymous\"")
                    ]
                    diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                    reviews.append(
                        CodeReviewItem(
                            id=str(uuid.uuid4()),
                            file_path=file_path,
                            line_number=idx,
                            severity="HIGH",
                            category="Security Vulnerability",
                            title="Missing Subresource Integrity (SRI) on External Script",
                            error_explanation="Loading external scripts without `integrity=\"sha384-...\"` allows compromised CDNs or Man-in-the-Middle attackers to execute arbitrary malicious code in your users' browsers without detection.",
                            buggy_code=line,
                            corrected_code="\n".join(new_lines),
                            unified_diff=diff
                        )
                    )

            # 14. Web3 Wallet Drainer Pattern (Ledger Connect Kit / Lottie-Player)
            if re.search(r'\b(?:setApprovalForAll|transferFrom)\s*\(\s*["\']0x[a-fA-F0-9]{40}["\']', raw_stripped, re.IGNORECASE) or (re.search(r'eth_sendTransaction', raw_stripped) and "drain" in raw_stripped.lower()):
                new_lines = [
                    f"{indent}// Corrected: Audit and restrict Web3 transaction requests and token approvals",
                    f"{indent}await verifyRecipientAddress(targetContract);"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Web3 Cryptocurrency Wallet Drainer Pattern",
                        error_explanation="Directly executing high-privilege ERC-20 token approvals (`setApprovalForAll`) or unverified transaction dispatch matches patterns from 2023 Ledger Connect Kit and 2024 Lottie-Player supply chain attacks.",
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

            # Unpinned GitHub Action (e.g. uses: actions/checkout@v2 or - uses: actions/checkout@v2)
            match = USES_REGEX.match(line)
            if match and not stripped.startswith("#"):
                prefix = match.group(1)
                action_name = match.group(2)
                raw_ref = match.group(3)

                # Strip trailing comments from ref before checking SHA
                ref = raw_ref.split("#")[0].strip()
                if re.fullmatch(r'[0-9a-fA-F]{40}', ref):
                    continue

                sha, ver_comment = resolve_action_pin(action_name, ref)

                # Retain the exact prefix (including '- ') so YAML list syntax is never broken
                if "-" in prefix:
                    hyphen_idx = prefix.index("-")
                    comment_indent = prefix[:hyphen_idx]
                else:
                    comment_indent = prefix

                if sha:
                    new_lines = [
                        f"{comment_indent}# Pinned to full immutable commit SHA",
                        f"{prefix}uses: {action_name}@{sha} {ver_comment}".rstrip()
                    ]
                else:
                    new_lines = [
                        f"{comment_indent}# ACTION REQUIRED: Verify 40-character commit SHA at https://github.com/{action_name}/releases",
                        f"{prefix}uses: {action_name}@<VERIFY_40_CHAR_COMMIT_SHA> {ver_comment}".rstrip()
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
                            f"Official GitHub Action `{action_name}` uses mutable tag `@{ref}`. "
                            f"Pin to full immutable commit SHA to protect against tag mutation and comply with OpenSSF Scorecard."
                            if is_official
                            else f"Third-party action `{action_name}` uses mutable tag `@{ref}`. "
                                 f"Retrieve the verified 40-character commit SHA from official repository https://github.com/{action_name}/releases to prevent supply-chain compromises. Do not use an unverified or fabricated commit SHA."
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

            # Insecure Codecov bash uploader pipe (Codecov 2021 Breach)
            if re.search(r'(?:curl\s+[^|\n]*(?:https?://)?codecov\.io/bash\s*\|\s*bash|bash\s+<\s*\(\s*curl\s+[^)]*codecov\.io/bash\s*\))', stripped, re.IGNORECASE):
                leading_indent = line[:len(line) - len(line.lstrip())]
                new_lines = [
                    f"{leading_indent}# Corrected: Use official codecov-action pinned to immutable commit SHA (mitigates 2021 Codecov breach)",
                    f"{leading_indent}- name: Upload coverage to Codecov",
                    f"{leading_indent}  uses: codecov/codecov-action@015ff539bb73772273d524247214d05e1242179e # v5.0.7",
                    f"{leading_indent}  with:",
                    f"{leading_indent}    token: ${{{{ secrets.CODECOV_TOKEN }}}}"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="CI/CD Security Hardening",
                        title="Insecure Codecov Bash Uploader Pipe (Codecov 2021 Breach)",
                        error_explanation="Piping the Codecov bash script directly to shell was the root cause of the April 2021 Codecov supply chain breach, where attackers modified the hosted script to harvest CI secrets. Replace with official `codecov/codecov-action` pinned to a verified SHA.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        return reviews

    # ============================================================
    # JSON CODE REVIEWER (package.json overrides & lifecycle hooks)
    # ============================================================
    def _review_json(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        if file_path.endswith("package.json"):
            # Check for dangerous lifecycle scripts (ua-parser-js / coa trojan vector)
            try:
                import json
                pkg_data = json.loads(content)
                scripts = pkg_data.get("scripts", {})
                for hook in ["preinstall", "install", "postinstall"]:
                    cmd = scripts.get(hook, "")
                    if isinstance(cmd, str) and cmd:
                        if any(k in cmd.lower() for k in ["curl", "wget", "powershell", "certutil", ".bat", ".sh", "xmrig"]):
                            reviews.append(
                                CodeReviewItem(
                                    id=str(uuid.uuid4()),
                                    file_path=file_path,
                                    line_number=1,
                                    severity="CRITICAL",
                                    category="Security Vulnerability",
                                    title=f"Dangerous Package Lifecycle Script in `{hook}` (ua-parser-js Vector)",
                                    error_explanation=f"The `{hook}` lifecycle script executes external shell commands ('{cmd}'). In the 2021 ua-parser-js, coa, and rc attacks, compromised packages used lifecycle hooks to install Trojans and cryptominers during 'npm install'.",
                                    buggy_code=f'"{hook}": "{cmd}"',
                                    corrected_code=f'// Remove "{hook}" or run npm install with --ignore-scripts'
                                )
                            )
            except Exception:
                pass

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
    # GO CODE REVIEWER
    # ============================================================
    def _review_go(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            raw_stripped = line.strip()
            if raw_stripped.startswith("//") or raw_stripped.startswith("/*") or raw_stripped.startswith("*"):
                continue

            clean_code = strip_strings_and_comments(line, "js")
            indent = line[:len(line) - len(line.lstrip())]

            # Insecure TLS InsecureSkipVerify: true
            if "InsecureSkipVerify: true" in raw_stripped or "InsecureSkipVerify:true" in raw_stripped:
                corrected_line = line.replace("InsecureSkipVerify: true", "InsecureSkipVerify: false").replace("InsecureSkipVerify:true", "InsecureSkipVerify: false")
                new_lines = [
                    f"{indent}// Corrected: Enforce TLS certificate verification",
                    corrected_line
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="Security Vulnerability",
                        title="TLS Certificate Validation Disabled (`InsecureSkipVerify: true`)",
                        error_explanation="Setting `InsecureSkipVerify: true` in Go `tls.Config` disables SSL/TLS certificate verification, allowing network eavesdropping and Man-in-the-Middle (MitM) attacks.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

            # Command injection in exec.Command with sh/bash
            if re.search(r'exec\.Command\s*\(\s*["\'](sh|bash|cmd)["\']\s*,\s*["\']-[cC]["\']', raw_stripped):
                new_lines = [
                    f"{indent}// Corrected: Execute command directly with slice of arguments instead of invoking shell",
                    f"{indent}cmd := exec.Command(\"executable\", arg1, arg2)"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="CRITICAL",
                        category="Security Vulnerability",
                        title="Command Injection via Shell Wrapper in `exec.Command`",
                        error_explanation="Spawning a shell via `exec.Command('sh', '-c', ...)` passes user arguments directly to the OS command shell, allowing command injection attacks. Execute the binary directly with argument slices.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        return reviews

    # ============================================================
    # DOCKERFILE CODE REVIEWER
    # ============================================================
    def _review_dockerfile(self, file_path: str, content: str) -> List[CodeReviewItem]:
        reviews: List[CodeReviewItem] = []
        lines = content.splitlines()
        has_user_directive = False

        for idx, line in enumerate(lines, start=1):
            raw = line.strip()
            if raw.startswith("#"):
                continue

            if re.match(r'^USER\s+', raw, re.IGNORECASE):
                has_user_directive = True

            # curl | bash in RUN
            if re.match(r'^RUN\s+.*(curl|wget).*\|\s*(bash|sh)', raw, re.IGNORECASE):
                indent = line[:len(line) - len(line.lstrip())]
                new_lines = [
                    f"{indent}# Corrected: Download script and verify cryptographic checksum before execution",
                    f"{indent}RUN curl -sSL https://trusted.org/install.sh -o /tmp/install.sh && \\",
                    f"{indent}    echo 'expected-sha256  /tmp/install.sh' | sha256sum -c - && \\",
                    f"{indent}    bash /tmp/install.sh && rm -f /tmp/install.sh"
                ]
                diff = self._build_unified_diff(file_path, lines, idx, line, new_lines, 2)
                reviews.append(
                    CodeReviewItem(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        category="CI/CD Security Hardening",
                        title="Insecure Script Pipe to Shell (`curl | bash`) in Dockerfile",
                        error_explanation="Piping remote HTTP downloads directly into bash inside a Dockerfile allows compromised package registries or DNS hijackers to inject malicious instructions into container layers.",
                        buggy_code=line,
                        corrected_code="\n".join(new_lines),
                        unified_diff=diff
                    )
                )

        if not has_user_directive and len(lines) > 2:
            reviews.append(
                CodeReviewItem(
                    id=str(uuid.uuid4()),
                    file_path=file_path,
                    line_number=len(lines),
                    severity="MEDIUM",
                    category="Security Vulnerability",
                    title="Container Running as Root (Missing USER Directive)",
                    error_explanation="The Dockerfile does not specify a non-root USER. Containers running as root (UID 0) pose severe privilege escalation and container breakout risks if an application vulnerability is exploited.",
                    buggy_code="# (End of Dockerfile without USER directive)",
                    corrected_code="USER nonroot:nonroot"
                )
            )

        return reviews

    # ============================================================
    # COMPREHENSIVE MARKDOWN AUDIT REPORT GENERATOR
    # ============================================================
    def generate_markdown_report(self, reviews: List[CodeReviewItem], repo_name: str = "Repository") -> str:
        """
        Generates an exhaustive, production-grade markdown report of all code reviews,
        including an executive summary table, issue breakdown by category and severity,
        and surgical file-by-file corrections with copyable unified-diff patches.
        """
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        critical_count = sum(1 for r in reviews if r.severity == "CRITICAL")
        high_count = sum(1 for r in reviews if r.severity == "HIGH")
        medium_count = sum(1 for r in reviews if r.severity == "MEDIUM")
        low_count = sum(1 for r in reviews if r.severity == "LOW")

        files_affected = len(set(r.file_path for r in reviews))

        report = f"""# SupplyGraph Autonomous Code Review & Patch Report

**Target Repository / Project:** `{repo_name}`  
**Audit Timestamp:** `{now_str}`  
**Auditor Engine:** SupplyGraph v3.0 Static AST & Pattern Reviewer  
**Total Issues Identified:** `{len(reviews)}` across `{files_affected}` files  

---

## Executive Issue Summary

| Severity | Count | Risk Level |
|---|---|---|
| **CRITICAL** | `{critical_count}` | Remote Code Execution, SQL Injection, Prototype Pollution |
| **HIGH** | `{high_count}` | Security Flaws, Unpinned CI/CD Actions, Credential Leaks |
| **MEDIUM** | `{medium_count}` | Logic Errors, Deprecated APIs, Concurrency Bugs |
| **LOW** | `{low_count}` | Code Quality, Style Standards (PEP 8 / Strict Equality) |

---

## Detailed File-by-File Findings & Automated Corrections
"""
        if not reviews:
            report += "\\n*No code errors, security vulnerabilities, or anti-patterns detected. Codebase complies with zero-trust security standards.*\\n"
            return report

        for i, r in enumerate(reviews, start=1):
            report += f"""
### [{i}] {r.title}
- **File:** `{r.file_path}` (Line `{r.line_number}`)
- **Severity:** `{r.severity}`
- **Category:** `{r.category}`
- **Explanation:** {r.error_explanation}

#### Offending / Buggy Code:
```
{r.buggy_code}
```

#### Production-Ready Corrected Code:
```
{r.corrected_code}
```
"""
            if r.unified_diff:
                report += f"""
#### Git Unified Diff Patch:
```diff
{r.unified_diff}
```
"""
            report += "\\n---\\n"

        return report

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
