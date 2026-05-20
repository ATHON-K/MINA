"""
People Intel Tools — Safe, public-source people/contact intelligence.

Provides:
  - public_contact_harvest()         : Extract emails/contacts from public pages
  - about_team_page_harvest()        : Names/roles from public team/about pages
  - role_email_pattern_inference()   : Infer likely email format from harvested data

All operations are passive, public-source only. No invasive scraping.
"""
import logging
import re
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
    "Accept": "text/html, application/xhtml+xml, */*",
})
_TIMEOUT = 15

# Common email patterns
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def public_contact_harvest(domain: str) -> Dict:
    """
    Harvest publicly visible contact emails from the domain's main pages.
    Checks /, /contact, /about, /impressum.
    """
    try:
        emails = set()
        pages_checked = []

        paths = ["/", "/contact", "/about", "/impressum", "/contact-us"]
        for path in paths:
            url = f"https://{domain}{path}"
            try:
                resp = _SESSION.get(url, timeout=_TIMEOUT, allow_redirects=True)
                if resp.status_code == 200:
                    found = _EMAIL_RE.findall(resp.text[:50000])
                    # Filter to only emails matching the target domain or common providers
                    for email in found:
                        email_lower = email.lower()
                        if domain in email_lower or any(p in email_lower for p in
                                                         ["@gmail.", "@outlook.", "@yahoo.", "@proton."]):
                            emails.add(email_lower)
                    pages_checked.append({"url": url, "status": resp.status_code, "emails_found": len(found)})
            except requests.RequestException:
                pages_checked.append({"url": url, "status": 0, "emails_found": 0})

        return {
            "success": True,
            "data": {
                "domain": domain,
                "emails": sorted(list(emails)),
                "email_count": len(emails),
                "pages_checked": pages_checked,
            },
        }
    except Exception as e:
        logger.error("[PeopleTools] public_contact_harvest failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def about_team_page_harvest(domain: str) -> Dict:
    """
    Extract names and roles from public team/about pages.
    Only processes publicly visible HTML — no scraping behind auth.
    """
    try:
        people = []
        pages_checked = []

        team_paths = ["/about", "/team", "/about-us", "/our-team", "/people", "/leadership"]
        for path in team_paths:
            url = f"https://{domain}{path}"
            try:
                resp = _SESSION.get(url, timeout=_TIMEOUT, allow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 500:
                    # Simple name/title extraction from structured markup
                    html = resp.text[:100000]

                    # Look for common team page patterns
                    # Pattern: name in heading + role in nearby text
                    name_patterns = re.findall(
                        r'<(?:h[2-4]|strong|b)[^>]*>([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)?)</(?:h[2-4]|strong|b)>',
                        html
                    )
                    role_patterns = re.findall(
                        r'(?:CEO|CTO|CFO|COO|VP|Director|Manager|Engineer|Developer|Designer|Lead|Head of|Chief)',
                        html, re.I
                    )

                    for name in name_patterns[:20]:
                        if len(name) > 4 and len(name) < 60:
                            people.append({"name": name, "source": url})

                    pages_checked.append({"url": url, "status": resp.status_code, "names_found": len(name_patterns)})
            except requests.RequestException:
                pages_checked.append({"url": url, "status": 0, "names_found": 0})

        return {
            "success": True,
            "data": {
                "domain": domain,
                "people": people[:30],
                "people_count": len(people),
                "pages_checked": pages_checked,
            },
        }
    except Exception as e:
        logger.error("[PeopleTools] about_team_page_harvest failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def role_email_pattern_inference(domain: str, harvested_emails: List[str]) -> Dict:
    """
    Infer likely email format (first.last, f.last, firstl, etc.)
    from harvested emails. No brute-force or enumeration.
    """
    try:
        patterns_found = {}

        for email in harvested_emails:
            local = email.split("@")[0].lower()
            if "." in local:
                parts = local.split(".")
                if len(parts) == 2:
                    if len(parts[0]) == 1:
                        patterns_found.setdefault("f.last", 0)
                        patterns_found["f.last"] += 1
                    elif len(parts[1]) == 1:
                        patterns_found.setdefault("first.l", 0)
                        patterns_found["first.l"] += 1
                    else:
                        patterns_found.setdefault("first.last", 0)
                        patterns_found["first.last"] += 1
            elif re.match(r'^[a-z]+[0-9]*$', local):
                patterns_found.setdefault("first_only", 0)
                patterns_found["first_only"] += 1
            else:
                patterns_found.setdefault("other", 0)
                patterns_found["other"] += 1

        # Determine most likely pattern
        most_likely = max(patterns_found, key=patterns_found.get) if patterns_found else "unknown"

        return {
            "success": True,
            "data": {
                "domain": domain,
                "email_count_analyzed": len(harvested_emails),
                "patterns": patterns_found,
                "most_likely_pattern": most_likely,
                "note": "Inference only — no enumeration or brute-force attempted.",
            },
        }
    except Exception as e:
        logger.error("[PeopleTools] role_email_pattern_inference failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}
