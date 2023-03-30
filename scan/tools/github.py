"""
    GitHub utils tools.
"""
from github import Github


def get_top_repos_by_query(query: str, _top_limit: int = 3) -> list[tuple[str, int]]:
    """
    Returns list of top repos by query (set(url, stars_count))
    """
    repos = Github().search_repositories(query=query, sort="stars", order="desc")
    return [
        (f"https://github.com/{repo.full_name}", repo.stargazers_count)
        for repo in repos[:_top_limit]
    ]
