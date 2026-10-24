# SupplyGraph - GitHub Service
# Uses PyGithub to fetch repository metadata and files securely.
from github import Github, Auth
from github.GithubException import GithubException
from app.models.core import RepositoryModel
from app.core.config import get_settings
from typing import Optional, List, Dict, Tuple
import re
import time
from urllib.parse import urlparse

_FILE_CACHE: Dict[str, Tuple[float, Optional[str]]] = {}
_LIST_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_CACHE_TTL_SECONDS = 300.0  # 5 minutes in-memory cache to prevent GitHub rate limits


class GitHubService:
    def __init__(self):
        settings = get_settings()
        if settings.github_token:
            auth = Auth.Token(settings.github_token)
            self.github = Github(auth=auth)
        else:
            self.github = Github()

    def get_rate_limit_status(self) -> dict:
        """Returns the current remaining GitHub API rate limit for telemetry/warnings."""
        try:
            rate = self.github.get_rate_limit()
            core = rate.core
            reset_epoch = core.reset.timestamp() if core.reset else 0
            return {
                "remaining": core.remaining,
                "limit": core.limit,
                "reset_epoch": reset_epoch,
                "is_low": core.remaining < 10,
                "is_exceeded": core.remaining == 0
            }
        except Exception:
            return {"remaining": 60, "limit": 60, "reset_epoch": 0, "is_low": False, "is_exceeded": False}

    def _format_github_error(self, full_name: str, e: GithubException) -> str:
        msg = str(e.data.get("message", str(e)) if hasattr(e, "data") and isinstance(e.data, dict) else str(e))
        if e.status == 403 or "rate limit" in msg.lower():
            return (
                f"GitHub API rate limit reached for {full_name} (HTTP 403). "
                f"Tip: Set GITHUB_TOKEN on backend for 5,000 req/hr, or click '📂 Upload Folder' "
                f"to scan this repository locally with zero rate limits."
            )
        return f"Failed to access GitHub repository {full_name}: {msg}"

    def _extract_repo_name(self, repo_url: str) -> str:
        """Extracts owner/repo from a GitHub URL."""
        parsed = urlparse(repo_url)
        path = parsed.path.strip('/')
        if path.endswith('.git'):
            path = path[:-4]
        parts = path.split('/')
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

    def get_repo_metadata(self, repo_url: str) -> RepositoryModel:
        full_name = self._extract_repo_name(repo_url)
        try:
            repo = self.github.get_repo(full_name)
            owner, name = full_name.split('/')
            return RepositoryModel(
                github_url=repo_url,
                owner=owner,
                name=name,
                description=repo.description or "",
                default_branch=repo.default_branch,
                stars=repo.stargazers_count
            )
        except GithubException as e:
            raise ValueError(self._format_github_error(full_name, e))

    def get_file_content(self, repo_url: str, file_path: str, ref: str = None) -> Optional[str]:
        cache_key = f"{repo_url}:{file_path}:{ref or ''}"
        now = time.time()
        if cache_key in _FILE_CACHE:
            ts, cached_val = _FILE_CACHE[cache_key]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached_val

        full_name = self._extract_repo_name(repo_url)
        try:
            repo = self.github.get_repo(full_name)
            kwargs = {}
            if ref:
                kwargs['ref'] = ref
            
            content_file = repo.get_contents(file_path, **kwargs)
            if isinstance(content_file, list):
                raise ValueError(f"Path {file_path} is a directory, not a file.")
            
            res_content = content_file.decoded_content.decode('utf-8')
            _FILE_CACHE[cache_key] = (now, res_content)
            return res_content
        except GithubException as e:
            if e.status == 404:
                _FILE_CACHE[cache_key] = (now, None)
                return None
            raise ValueError(self._format_github_error(full_name, e))

    async def get_file_content_async(self, repo_url: str, file_path: str, ref: str = None, timeout: float = 4.0) -> Optional[str]:
        """Fetch raw file content asynchronously with a strict timeout."""
        import asyncio
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.get_file_content, repo_url, file_path, ref),
                timeout=timeout
            )
        except Exception:
            return None

    async def get_files_batch(self, repo_url: str, file_paths: List[str], ref: str = None, max_concurrency: int = 8, timeout: float = 4.0) -> dict:
        """Fetch multiple files concurrently using an asyncio Semaphore and strict per-request timeout."""
        import asyncio
        sem = asyncio.Semaphore(max_concurrency)

        async def _fetch(path: str):
            async with sem:
                try:
                    content = await asyncio.wait_for(
                        asyncio.to_thread(self.get_file_content, repo_url, path, ref),
                        timeout=timeout
                    )
                    return path, content
                except Exception:
                    return path, None

        tasks = [_fetch(p) for p in file_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = {}
        for res in results:
            if isinstance(res, tuple) and res[1] is not None:
                out[res[0]] = res[1]
        return out

    def list_files(self, repo_url: str, path: str = "", ref: str = None) -> List[str]:
        cache_key = f"{repo_url}:{path}:{ref or ''}"
        now = time.time()
        if cache_key in _LIST_CACHE:
            ts, cached_files = _LIST_CACHE[cache_key]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached_files

        full_name = self._extract_repo_name(repo_url)
        try:
            repo = self.github.get_repo(full_name)
            kwargs = {}
            if ref:
                kwargs['ref'] = ref

            # If requesting root, attempt recursive discovery for monorepos
            if path == "":
                branch = ref or repo.default_branch or "main"
                # 1. Attempt GitHub Git Trees API (recursive=True)
                try:
                    tree = repo.get_git_tree(sha=branch, recursive=True)
                    if tree and tree.tree:
                        tree_files = [item.path for item in tree.tree if item.type == "blob"]
                        if tree_files:
                            _LIST_CACHE[cache_key] = (now, tree_files)
                            return tree_files
                except Exception:
                    pass

                # 2. Fallback: inspect root and common monorepo subdirectories
                common_dirs = [
                    "", "frontend", "backend", "client", "server",
                    "web", "api", "app", ".github/workflows"
                ]
                discovered_files: List[str] = []
                for d in common_dirs:
                    try:
                        contents = repo.get_contents(d, **kwargs)
                        if not isinstance(contents, list):
                            contents = [contents]
                        for c in contents:
                            if c.type == "file" and c.path not in discovered_files:
                                discovered_files.append(c.path)
                    except Exception:
                        continue
                if discovered_files:
                    _LIST_CACHE[cache_key] = (now, discovered_files)
                    return discovered_files

            # Standard listing for specific non-root path or fallback
            contents = repo.get_contents(path, **kwargs)
            if not isinstance(contents, list):
                contents = [contents]
                
            res_files = [content.path for content in contents]
            _LIST_CACHE[cache_key] = (now, res_files)
            return res_files
        except GithubException as e:
            if e.status == 404:
                return []
            raise ValueError(self._format_github_error(full_name, e))
        except Exception:
            return []
