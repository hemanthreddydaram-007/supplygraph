# SupplyGraph - GitHub Service
# Uses PyGithub to fetch repository metadata and files securely.
from github import Github, Auth
from github.GithubException import GithubException
from app.models.core import RepositoryModel
from app.core.config import get_settings
from typing import Optional, List
import re
from urllib.parse import urlparse

class GitHubService:
    def __init__(self):
        settings = get_settings()
        if settings.github_token:
            auth = Auth.Token(settings.github_token)
            self.github = Github(auth=auth)
        else:
            self.github = Github()

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
                url=repo_url,
                owner=owner,
                name=name,
                description=repo.description or "",
                default_branch=repo.default_branch,
                stars=repo.stargazers_count
            )
        except GithubException as e:
            raise ValueError(f"Failed to fetch repository metadata for {full_name}: {e.data.get('message', str(e))}")

    def get_file_content(self, repo_url: str, file_path: str, ref: str = None) -> Optional[str]:
        full_name = self._extract_repo_name(repo_url)
        try:
            repo = self.github.get_repo(full_name)
            kwargs = {}
            if ref:
                kwargs['ref'] = ref
            
            content_file = repo.get_contents(file_path, **kwargs)
            if isinstance(content_file, list):
                raise ValueError(f"Path {file_path} is a directory, not a file.")
            
            return content_file.decoded_content.decode('utf-8')
        except GithubException as e:
            if e.status == 404:
                return None
            raise ValueError(f"Failed to fetch file content for {file_path}: {e.data.get('message', str(e))}")

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
                    return discovered_files

            # Standard listing for specific non-root path or fallback
            contents = repo.get_contents(path, **kwargs)
            if not isinstance(contents, list):
                contents = [contents]
                
            return [content.path for content in contents]
        except GithubException as e:
            if e.status == 404:
                return []
            raise ValueError(f"Failed to list files for {path}: {e.data.get('message', str(e))}")
        except Exception:
            return []
