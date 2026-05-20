"""
Web Surface Pipeline — fingerprint, enumerate and score HTTP endpoints.
"""
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Patterns that indicate interesting endpoints
INTERESTING_PATTERNS = [
    re.compile(r"admin|manager|console|panel", re.I),
    re.compile(r"api/v?\d|swagger|openapi|graphql", re.I),
    re.compile(r"login|signin|auth|oauth|sso", re.I),
    re.compile(r"upload|import|export|backup", re.I),
    re.compile(r"\.php|\.asp|\.aspx|\.jsp|\.do$", re.I),
    re.compile(r"debug|test|staging|dev\b", re.I),
    re.compile(r"config|setup|install|\.env|\.git", re.I),
]


@dataclass
class WebEndpoint:
    url: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    interesting_score: float = 0.0
    sources: list = field(default_factory=list)
    params: list = field(default_factory=list)


class WebSurfacePipeline:
    """6-step web surface scanner with configurable depth."""

    def __init__(self, target: str, spec: dict, session_dir=None):
        self.target = target.rstrip("/")
        self.spec = spec
        self.session_dir = session_dir
        self._base_url = self._normalize_base(target)
        self.endpoints: dict = {}   # url -> WebEndpoint
        self.stats = {
            "fingerprint": {}, "passive_paths": 0,
            "dir_enum": 0, "param_discovery": 0,
            "crawl": 0, "total_endpoints": 0
        }

    def run(self) -> dict:
        """Execute all 6 pipeline steps and return result dict."""
        try:
            # Step 1: Fingerprint
            fingerprint = self._fingerprint()
            self.stats["fingerprint"] = fingerprint

            # Step 2: Collect paths from passive sources
            self._passive_paths()

            # Step 3: Directory enumeration
            _feat = self.spec.get("features", {})
            if _feat.get("dir_enum", _feat.get("dirs", True)):
                self._dir_enum()

            # Step 4: Parameter discovery on found paths
            self._param_discovery()

            # Step 5: Light crawl
            if _feat.get("crawler", _feat.get("crawl", False)):
                self._crawl()

            # Step 6: Normalize & score
            normalized = self._normalize_endpoints()
            leads = self._emit_leads(normalized, fingerprint)

            self.stats["total_endpoints"] = len(normalized)

            return {
                "success": True,
                "target": self.target,
                "base_url": self._base_url,
                "fingerprint": fingerprint,
                "endpoints": [e.__dict__ for e in normalized],
                "leads": leads,
                "stats": self.stats,
            }
        except Exception as exc:
            logger.error("[WebSurface] Pipeline error on %s: %s", self.target, exc)
            return {"success": False, "target": self.target, "error": str(exc)}

    def _normalize_base(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"https://{target}"

    def _fingerprint(self) -> dict:
        """Step 1: Detect server, tech stack, WAF."""
        try:
            import requests
            resp = requests.get(self._base_url, timeout=10, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (MINA-Scanner)"})
            headers = dict(resp.headers)
            server = headers.get("Server", "")
            x_powered = headers.get("X-Powered-By", "")
            waf = _detect_waf(headers)
            title = _extract_title(resp.text)
            tech = _detect_tech(resp.text, headers)

            return {
                "status_code": resp.status_code,
                "server": server,
                "x_powered_by": x_powered,
                "waf": waf,
                "title": title,
                "tech": tech,
                "final_url": resp.url,
                "https": resp.url.startswith("https"),
            }
        except Exception as exc:
            logger.debug("[WebSurface] Fingerprint failed: %s", exc)
            return {"error": str(exc)}

    def _passive_paths(self):
        """Step 2: Known paths from tech fingerprint."""
        fp = self.stats.get("fingerprint", {})
        tech_paths = []

        for t in fp.get("tech", []):
            t_lower = t.lower()
            if "wordpress" in t_lower:
                tech_paths += ["/wp-admin/", "/wp-login.php", "/xmlrpc.php",
                               "/wp-json/", "/wp-content/"]
            elif "django" in t_lower:
                tech_paths += ["/admin/", "/api/", "/static/"]
            elif "laravel" in t_lower:
                tech_paths += ["/admin", "/api/", "/.env", "/storage/"]
            elif "express" in t_lower or "node" in t_lower:
                tech_paths += ["/api/", "/graphql", "/swagger-ui.html"]

        for path in set(tech_paths):
            url = urljoin(self._base_url, path)
            if url not in self.endpoints:
                self.endpoints[url] = WebEndpoint(url=url, sources=["passive"])
                self.stats["passive_paths"] += 1

    def _dir_enum(self):
        """Step 3: Directory brute-force with small wordlist."""
        from pathlib import Path
        import requests

        wordlist_path = Path(__file__).parent.parent / "wordlists" / "directories_small.txt"
        if not wordlist_path.exists():
            return

        with open(wordlist_path, encoding="utf-8") as fh:
            paths = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 (MINA-Scanner)"

        for path in paths:
            if not path.startswith("/"):
                path = "/" + path
            url = self._base_url + path
            if url in self.endpoints:
                continue
            try:
                resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code not in (404, 400, 403):
                    ep = WebEndpoint(
                        url=url,
                        status_code=resp.status_code,
                        content_type=resp.headers.get("Content-Type", ""),
                        content_length=len(resp.content),
                        server=resp.headers.get("Server", ""),
                        sources=["dir_enum"]
                    )
                    self.endpoints[url] = ep
                    self.stats["dir_enum"] += 1
                time.sleep(0.1)
            except Exception:
                pass

    def _param_discovery(self):
        """Step 4: Try common parameters on discovered paths."""
        COMMON_PARAMS = ["id", "page", "q", "search", "file", "path",
                         "url", "redirect", "token", "user", "action"]
        import requests

        session = requests.Session()
        for url, ep in list(self.endpoints.items()):
            if ep.status_code not in (200, 301, 302):
                continue
            for param in COMMON_PARAMS:
                test_url = f"{url}?{param}=MINA_TEST"
                try:
                    resp = session.get(test_url, timeout=4, verify=False,
                                       allow_redirects=False)
                    if resp.status_code == 200:
                        ep.params.append(param)
                        self.stats["param_discovery"] += 1
                except Exception:
                    pass

    def _crawl(self):
        """Step 5: Light link extraction from homepage."""
        import requests
        from html.parser import HTMLParser

        class LinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "a" and "href" in attrs:
                    self.links.append(attrs["href"])
                elif tag in ("script", "link") and "src" in attrs:
                    self.links.append(attrs["src"])
                elif tag == "form" and "action" in attrs:
                    self.links.append(attrs["action"])

        try:
            resp = requests.get(self._base_url, timeout=8, verify=False)
            parser = LinkParser()
            parser.feed(resp.text)

            base = urlparse(self._base_url)
            for href in parser.links:
                if not href or href.startswith(("#", "javascript:", "mailto:")):
                    continue
                full = urljoin(self._base_url, href)
                parsed = urlparse(full)
                if parsed.netloc and parsed.netloc != base.netloc:
                    continue
                if full not in self.endpoints:
                    self.endpoints[full] = WebEndpoint(url=full, sources=["crawl"])
                    self.stats["crawl"] += 1
        except Exception as exc:
            logger.debug("[WebSurface] Crawl error: %s", exc)

    def _normalize_endpoints(self) -> list:
        """Step 6: Score and deduplicate endpoints."""
        normalized = []
        for url, ep in self.endpoints.items():
            ep.interesting_score = _score_interesting(url, ep)
            normalized.append(ep)
        return sorted(normalized, key=lambda e: e.interesting_score, reverse=True)

    def _emit_leads(self, endpoints: list, fingerprint: dict) -> list:
        """Generate Lead dicts from high-interest endpoints."""
        leads = []
        for ep in endpoints:
            if ep.interesting_score < 0.4:
                continue
            leads.append({
                "type": "url",
                "value": ep.url,
                "confidence": ep.interesting_score,
                "source": "web_surface",
                "context": f"score={ep.interesting_score:.2f} status={ep.status_code} "
                           f"sources={ep.sources}",
            })
        return leads


def _detect_waf(headers: dict) -> Optional[str]:
    waf_headers = {
        "x-sucuri-id": "Sucuri",
        "x-firewall-protection": "Firewall",
        "cf-ray": "Cloudflare",
        "x-amzn-requestid": "AWS WAF",
        "x-akamai-request-id": "Akamai",
        "server": None,  # check value below
    }
    for h, waf in waf_headers.items():
        if h in {k.lower() for k in headers}:
            if waf:
                return waf
    server = headers.get("Server", "").lower()
    if "cloudflare" in server:
        return "Cloudflare"
    return None


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:120] if m else None


def _detect_tech(html: str, headers: dict) -> list:
    techs = []
    patterns = {
        "WordPress": [r"wp-content", r"wp-json"],
        "Drupal": [r"Drupal", r"/sites/default/"],
        "Joomla": [r"Joomla!", r"/components/com_"],
        "Laravel": [r"laravel_session"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "React": [r"__react_fiber", r"react-app"],
        "Angular": [r"ng-version", r"ng-reflect"],
        "Vue": [r"__vue__", r"vue-router"],
        "jQuery": [r"jquery[\./]"],
        "Bootstrap": [r"bootstrap[\./]"],
    }
    combined = html[:10000] + str(headers)
    for tech, pats in patterns.items():
        for pat in pats:
            if re.search(pat, combined, re.I):
                techs.append(tech)
                break
    return techs


def _score_interesting(url: str, ep: WebEndpoint) -> float:
    score = 0.0
    path = urlparse(url).path.lower()

    for pattern in INTERESTING_PATTERNS:
        if pattern.search(path):
            score += 0.15

    if ep.status_code == 200:
        score += 0.2
    elif ep.status_code in (301, 302):
        score += 0.1
    elif ep.status_code == 403:
        score += 0.15  # Forbidden often means something is there

    if ep.params:
        score += 0.1 * min(len(ep.params), 3)

    if "dir_enum" in ep.sources:
        score += 0.05

    return min(score, 1.0)
