from app.services.github_service import GitHubService
svc = GitHubService()
repo = svc.github.get_repo("chalk/chalk")
print("Default branch:", repo.default_branch)
