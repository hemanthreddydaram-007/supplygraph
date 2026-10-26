# SupplyGraph - GitHub Service
# Uses PyGithub to fetch repository metadata and files securely.
from github import Github, Auth
from github.GithubException import GithubException
from app.models.core import RepositoryModel
from app.core.config import get_settings
from typing import Optional, List, Dict, Tuple, Any
import re
import time
from urllib.parse import urlparse

_FILE_CACHE: Dict[str, Tuple[float, Optional[str]]] = {}
_LIST_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_REPO_BRANCH_CACHE: Dict[str, str] = {}
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
        if e.status in (403, 429) or "rate limit" in msg.lower() or "abuse" in msg.lower():
            return (
                f"GitHub API rate limit reached for {full_name} (HTTP {e.status}). "
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

    def _fetch_raw_github(self, full_name: str, file_path: str, ref: Optional[str] = None) -> Optional[str]:
        """Fetch raw content directly from raw.githubusercontent.com without exhausting API rate limits."""
        import urllib.request
        cached_branch = _REPO_BRANCH_CACHE.get(full_name)
        if ref:
            branches = [ref]
        elif cached_branch:
            branches = [cached_branch] + [b for b in ["main", "master", "HEAD"] if b != cached_branch]
        else:
            branches = ["main", "master", "HEAD"]

        clean_path = file_path.lstrip('/')
        settings = get_settings()
        req_headers = {"User-Agent": "SupplyGraph-Scanner/3.0"}
        if settings.github_token:
            req_headers["Authorization"] = f"token {settings.github_token}"

        for b in branches:
            url = f"https://raw.githubusercontent.com/{full_name}/{b}/{clean_path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers=req_headers
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        _REPO_BRANCH_CACHE[full_name] = b
                        return resp.read().decode('utf-8', errors='replace')
            except Exception:
                continue
        return None

    def _fetch_pygithub_content(self, full_name: str, file_path: str, ref: Optional[str] = None) -> Optional[str]:
        try:
            repo = self.github.get_repo(full_name)
            kwargs = {}
            if ref:
                kwargs['ref'] = ref
            try:
                cf = repo.get_contents(file_path, **kwargs)
            except GithubException as ge:
                if ge.status == 404 and ref and repo.default_branch and ref != repo.default_branch:
                    cf = repo.get_contents(file_path, ref=repo.default_branch)
                elif ge.status == 404 and ref:
                    cf = repo.get_contents(file_path)
                else:
                    return None
            if isinstance(cf, list):
                return None
            return cf.decoded_content.decode('utf-8', errors='replace')
        except Exception:
            return None

    def get_file_content(self, repo_url: str, file_path: str, ref: str = None) -> Optional[str]:
        cache_key = f"{repo_url}:{file_path}:{ref or ''}"
        now = time.time()
        if cache_key in _FILE_CACHE:
            ts, cached_val = _FILE_CACHE[cache_key]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached_val

        full_name = self._extract_repo_name(repo_url)

        # 1. Fast raw fetch via raw.githubusercontent.com (zero rate limit penalty & instantaneous)
        raw_val = self._fetch_raw_github(full_name, file_path, ref)
        if raw_val is not None:
            _FILE_CACHE[cache_key] = (now, raw_val)
            return raw_val

        # 2. Fallback to authenticated PyGithub
        try:
            repo = self.github.get_repo(full_name)
            kwargs = {}
            if ref:
                kwargs['ref'] = ref
            
            try:
                content_file = repo.get_contents(file_path, **kwargs)
            except GithubException as ge:
                # If 404 and ref was specified, fallback to default_branch or no ref
                if ge.status == 404 and ref and repo.default_branch and ref != repo.default_branch:
                    content_file = repo.get_contents(file_path, ref=repo.default_branch)
                elif ge.status == 404 and ref:
                    content_file = repo.get_contents(file_path)
                else:
                    raise ge
            if isinstance(content_file, list):
                raise ValueError(f"Path {file_path} is a directory, not a file.")
            
            res_content = content_file.decoded_content.decode('utf-8', errors='replace')
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

    async def get_files_batch(self, repo_url: str, file_paths: List[str], ref: str = None, max_concurrency: int = 15, timeout: float = 8.0) -> dict:
        """Fetch multiple files concurrently using httpx async client and fallback to get_file_content."""
        import asyncio
        import httpx
        full_name = self._extract_repo_name(repo_url)
        sem = asyncio.Semaphore(max_concurrency)
        cached_branch = _REPO_BRANCH_CACHE.get(full_name)
        if ref:
            branches = [ref]
        elif cached_branch:
            branches = [cached_branch] + [b for b in ["main", "master", "HEAD"] if b != cached_branch]
        else:
            branches = ["main", "master", "HEAD"]

        settings = get_settings()
        client_headers = {"User-Agent": "SupplyGraph-Scanner/3.0"}
        if settings.github_token:
            client_headers["Authorization"] = f"token {settings.github_token}"

        try:
            async with httpx.AsyncClient(timeout=timeout, headers=client_headers) as client:
                async def _fetch(path: str):
                    cache_key = f"{repo_url}:{path}:{ref or ''}"
                    now = time.time()
                    if cache_key in _FILE_CACHE:
                        ts, cached_val = _FILE_CACHE[cache_key]
                        if now - ts < _CACHE_TTL_SECONDS and cached_val is not None:
                            return path, cached_val

                    clean_path = path.lstrip('/')
                    async with sem:
                        # 1. Try raw github first across branches concurrently
                        try:
                            tasks = [
                                client.get(f"https://raw.githubusercontent.com/{full_name}/{b}/{clean_path}")
                                for b in branches
                            ]
                            responses = await asyncio.gather(*tasks, return_exceptions=True)
                            for i, resp in enumerate(responses):
                                if hasattr(resp, "status_code") and resp.status_code == 200:
                                    val = resp.text
                                    _REPO_BRANCH_CACHE[full_name] = branches[i]
                                    _FILE_CACHE[cache_key] = (now, val)
                                    return path, val
                        except Exception:
                            pass

                        # 2. Fallback to authenticated PyGithub
                        try:
                            content = await asyncio.to_thread(self._fetch_pygithub_content, full_name, clean_path, ref)
                            if content:
                                _FILE_CACHE[cache_key] = (now, content)
                                return path, content
                        except Exception:
                            pass
                        return path, None

                fetch_tasks = [_fetch(p) for p in file_paths]
                results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
                out = {}
                for res in results:
                    if isinstance(res, tuple) and res[1] is not None:
                        out[res[0]] = res[1]
                return out
        except Exception:
            # Complete fallback to synchronous retrieval
            out = {}
            for p in file_paths:
                c = self.get_file_content(repo_url, p, ref)
                if c is not None:
                    out[p] = c
            return out

    def list_files(self, repo_url: str, path: str = "", ref: str = None) -> List[str]:
        cache_key = f"{repo_url}:{path}:{ref or ''}"
        now = time.time()
        if cache_key in _LIST_CACHE:
            ts, cached_files = _LIST_CACHE[cache_key]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached_files

        full_name = self._extract_repo_name(repo_url)
        settings = get_settings()
        headers = {"User-Agent": "SupplyGraph-Scanner/3.0"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        # If requesting root, perform high-speed recursive discovery for monorepos (e.g. knadh/koanf)
        if path == "":
            branches_to_try = [ref] if ref else ["main", "master", "HEAD"]
            # 1. Direct Git Trees API via httpx (handles unauthenticated & authenticated with zero PyGithub overhead)
            import httpx
            for b in branches_to_try:
                try:
                    tree_url = f"https://api.github.com/repos/{full_name}/git/trees/{b}?recursive=1"
                    with httpx.Client(timeout=6.0, headers=headers) as client:
                        resp = client.get(tree_url)
                        if resp.status_code == 200:
                            data = resp.json()
                            tree_items = data.get("tree", [])
                            if tree_items:
                                file_paths = [item["path"] for item in tree_items if item.get("type") == "blob"]
                                if file_paths:
                                    _LIST_CACHE[cache_key] = (now, file_paths)
                                    return file_paths
                except Exception:
                    pass

        try:
            repo = self.github.get_repo(full_name)
            kwargs = {}
            if ref:
                kwargs['ref'] = ref

            # 2. PyGithub get_git_tree fallback
            if path == "":
                branch = ref or repo.default_branch or "main"
                try:
                    tree = repo.get_git_tree(sha=branch, recursive=True)
                    if tree and tree.tree:
                        tree_files = [item.path for item in tree.tree if item.type == "blob"]
                        if tree_files:
                            _LIST_CACHE[cache_key] = (now, tree_files)
                            return tree_files
                except Exception:
                    pass

                # Fallback: inspect root and common monorepo subdirectories
                common_dirs = [
                    "", "frontend", "backend", "client", "server",
                    "web", "api", "app", "providers", "parsers", "modules", ".github/workflows"
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

    def get_repo_security_advisories(self, repo_url: str) -> List[Dict[str, Any]]:
        """Fetch published first-party GitHub Security Advisories (GHSAs) for the target repository."""
        full_name = self._extract_repo_name(repo_url)
        settings = get_settings()
        headers = {"User-Agent": "SupplyGraph-Scanner/3.0"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        import httpx
        url = f"https://api.github.com/repos/{full_name}/security-advisories"
        try:
            with httpx.Client(timeout=5.0, headers=headers) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        return data
        except Exception:
            pass
        return []

    def get_dependabot_info(self, repo_url: str, all_repo_files: List[str]) -> Dict[str, Any]:
        """Inspect dependabot configuration and query open Dependabot PRs for benchmark comparison."""
        full_name = self._extract_repo_name(repo_url)
        settings = get_settings()
        headers = {"User-Agent": "SupplyGraph-Scanner/3.0"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        # 1. Check for dependabot configuration file
        dep_files = [".github/dependabot.yml", ".github/dependabot.yaml", "dependabot.yml", "dependabot.yaml"]
        found_config = next((f for f in all_repo_files if any(f.endswith(d) for d in dep_files)), None)

        # 2. Query open Dependabot PR count
        import httpx
        open_prs_count = 0
        search_url = f"https://api.github.com/search/issues?q=repo:{full_name}+is:pr+author:app/dependabot+is:open"
        try:
            with httpx.Client(timeout=4.0, headers=headers) as client:
                resp = client.get(search_url)
                if resp.status_code == 200:
                    open_prs_count = resp.json().get("total_count", 0)
        except Exception:
            pass

        return {
            "configured": found_config is not None,
            "file_path": found_config,
            "open_prs": open_prs_count
        }
