"""
Repo Intel Tools — Safe, public repository intelligence gathering.

Provides:
  - repo_discovery()              : Discover public repos for domain/company
  - repo_metadata_collect()       : Collect metadata from discovered repos
  - public_repo_readme_intel()    : Extract intel from README files
  - repo_language_stack_summary() : Summarize tech stack from repo languages

All operations use public APIs only. No authentication or private access.
"""
import logging
import re
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
    "Accept": "application/json",
})
_TIMEOUT = 15


def repo_discovery(domain: str, company_name: str = "") -> Dict:
    """
    Discover public repositories associated with a domain or company.
    Uses GitHub search API (no auth required for basic searches).
    """
    try:
        repos = []
        search_terms = [domain]
        if company_name:
            search_terms.append(company_name)

        for term in search_terms[:2]:
            try:
                url = f"https://api.github.com/search/repositories?q={term}&sort=updated&per_page=10"
                resp = _SESSION.get(url, timeout=_TIMEOUT)
                if resp.status_code == 200:
                    results = resp.json().get("items", [])
                    for repo in results:
                        repos.append({
                            "full_name": repo.get("full_name", ""),
                            "html_url": repo.get("html_url", ""),
                            "description": (repo.get("description") or "")[:200],
                            "language": repo.get("language", ""),
                            "stars": repo.get("stargazers_count", 0),
                            "updated_at": repo.get("updated_at", ""),
                            "fork": repo.get("fork", False),
                        })
                elif resp.status_code == 403:
                    logger.warning("[RepoTools] GitHub rate limit hit")
                    break
            except requests.RequestException as e:
                logger.debug("[RepoTools] GitHub search failed for %s: %s", term, e)

        # Deduplicate by full_name
        seen = set()
        unique = []
        for r in repos:
            if r["full_name"] not in seen:
                seen.add(r["full_name"])
                unique.append(r)

        return {
            "success": True,
            "data": {
                "domain": domain,
                "company_name": company_name,
                "repos": unique[:20],
                "repo_count": len(unique),
            },
        }
    except Exception as e:
        logger.error("[RepoTools] repo_discovery failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def repo_metadata_collect(repos: List[Dict]) -> Dict:
    """
    Collect metadata summary from a list of discovered repos.
    Input: list of repo dicts from repo_discovery().
    """
    try:
        languages = {}
        total_stars = 0
        topics = set()

        for repo in repos:
            lang = repo.get("language", "")
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            total_stars += repo.get("stars", 0)

        return {
            "success": True,
            "data": {
                "repo_count": len(repos),
                "languages": languages,
                "primary_language": max(languages, key=languages.get) if languages else "unknown",
                "total_stars": total_stars,
                "has_forks": any(r.get("fork") for r in repos),
            },
        }
    except Exception as e:
        logger.error("[RepoTools] repo_metadata_collect failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def public_repo_readme_intel(repo_url: str) -> Dict:
    """
    Extract intelligence from a public repository's README.
    Looks for: tech stack, dependencies, deployment info, API references.
    """
    try:
        # Convert GitHub URL to raw README URL
        # e.g., https://github.com/org/repo → https://raw.githubusercontent.com/org/repo/main/README.md
        match = re.match(r'https?://github\.com/([^/]+/[^/]+)', repo_url)
        if not match:
            return {"success": False, "data": {}, "error": "Invalid GitHub URL"}

        repo_path = match.group(1)
        readme_content = ""

        for branch in ["main", "master"]:
            try:
                url = f"https://raw.githubusercontent.com/{repo_path}/{branch}/README.md"
                resp = _SESSION.get(url, timeout=_TIMEOUT)
                if resp.status_code == 200:
                    readme_content = resp.text[:20000]
                    break
            except requests.RequestException:
                continue

        if not readme_content:
            return {"success": True, "data": {"repo": repo_url, "readme_found": False}}

        # Extract tech clues
        tech_mentions = set()
        tech_keywords = [
            "docker", "kubernetes", "aws", "azure", "gcp", "nginx", "apache",
            "redis", "postgresql", "mysql", "mongodb", "elasticsearch",
            "react", "angular", "vue", "django", "flask", "spring", "express",
            "python", "java", "node", "golang", "rust", "php", "ruby",
        ]
        lower_content = readme_content.lower()
        for kw in tech_keywords:
            if kw in lower_content:
                tech_mentions.add(kw)

        # Look for URLs/endpoints in README
        urls_found = re.findall(r'https?://[^\s\)\"\'`]+', readme_content)

        return {
            "success": True,
            "data": {
                "repo": repo_url,
                "readme_found": True,
                "readme_length": len(readme_content),
                "tech_mentions": sorted(list(tech_mentions)),
                "urls_found": urls_found[:20],
            },
        }
    except Exception as e:
        logger.error("[RepoTools] public_repo_readme_intel failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def repo_language_stack_summary(repos: List[Dict]) -> Dict:
    """
    Summarize the technology stack from repository language distributions.
    """
    try:
        language_counts = {}
        for repo in repos:
            lang = repo.get("language", "")
            if lang:
                language_counts[lang] = language_counts.get(lang, 0) + 1

        # Sort by frequency
        sorted_langs = sorted(language_counts.items(), key=lambda x: -x[1])

        return {
            "success": True,
            "data": {
                "languages": dict(sorted_langs),
                "primary_language": sorted_langs[0][0] if sorted_langs else "unknown",
                "diversity_score": len(sorted_langs),
                "total_repos": len(repos),
            },
        }
    except Exception as e:
        logger.error("[RepoTools] repo_language_stack_summary failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}
