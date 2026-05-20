"""
Document Intel Tools — Safe discovery and metadata extraction from public documents.

Provides:
  - public_document_discovery()       : Find public documents (PDF, DOCX, etc.) on a domain
  - document_metadata_extract()       : Extract metadata from public document URLs
  - public_document_tech_clue_extract() : Extract technology clues from documents

All operations are passive and public-source only.
"""
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
    "Accept": "text/html, application/xhtml+xml, */*",
})
_TIMEOUT = 15

# Document file extensions to search for
_DOC_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".xml"]


def public_document_discovery(domain: str) -> Dict:
    """
    Discover publicly accessible documents on a domain.
    Checks common paths and extracts document links from public pages.
    """
    try:
        documents = []
        pages_checked = []

        # Check common document paths
        doc_paths = [
            "/docs", "/documents", "/downloads", "/files", "/resources",
            "/assets", "/uploads", "/public", "/static",
        ]

        # Also check main page for document links
        try:
            resp = _SESSION.get(f"https://{domain}", timeout=_TIMEOUT, allow_redirects=True)
            if resp.status_code == 200:
                html = resp.text[:100000]
                # Find links to documents
                href_pattern = re.compile(r'href=["\']([^"\']+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|csv))', re.I)
                for match in href_pattern.finditer(html):
                    doc_url = match.group(1)
                    if not doc_url.startswith("http"):
                        doc_url = urljoin(f"https://{domain}", doc_url)
                    documents.append({
                        "url": doc_url,
                        "extension": doc_url.rsplit(".", 1)[-1].lower() if "." in doc_url else "",
                        "source_page": f"https://{domain}",
                    })
                pages_checked.append({"url": f"https://{domain}", "status": 200})
        except requests.RequestException:
            pages_checked.append({"url": f"https://{domain}", "status": 0})

        # Check document directories
        for path in doc_paths:
            url = f"https://{domain}{path}"
            try:
                resp = _SESSION.get(url, timeout=_TIMEOUT, allow_redirects=True)
                if resp.status_code == 200:
                    html = resp.text[:50000]
                    for ext in _DOC_EXTENSIONS:
                        pattern = re.compile(rf'href=["\']([^"\']+{re.escape(ext)})', re.I)
                        for match in pattern.finditer(html):
                            doc_url = match.group(1)
                            if not doc_url.startswith("http"):
                                doc_url = urljoin(url, doc_url)
                            documents.append({
                                "url": doc_url,
                                "extension": ext.lstrip("."),
                                "source_page": url,
                            })
                    pages_checked.append({"url": url, "status": resp.status_code})
            except requests.RequestException:
                pass

        # Deduplicate by URL
        seen = set()
        unique_docs = []
        for doc in documents:
            if doc["url"] not in seen:
                seen.add(doc["url"])
                unique_docs.append(doc)

        return {
            "success": True,
            "data": {
                "domain": domain,
                "documents": unique_docs[:50],
                "document_count": len(unique_docs),
                "pages_checked": pages_checked,
            },
        }
    except Exception as e:
        logger.error("[DocumentTools] public_document_discovery failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def document_metadata_extract(url: str) -> Dict:
    """
    Extract metadata from a public document URL.
    Only fetches HTTP headers (HEAD request) — does not download full content.
    """
    try:
        resp = _SESSION.head(url, timeout=_TIMEOUT, allow_redirects=True)

        metadata = {
            "url": url,
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": resp.headers.get("Content-Length", ""),
            "last_modified": resp.headers.get("Last-Modified", ""),
            "server": resp.headers.get("Server", ""),
            "etag": resp.headers.get("ETag", ""),
        }

        # Extract filename from Content-Disposition if available
        cd = resp.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            fn_match = re.search(r'filename[*]?=["\']?([^"\';\n]+)', cd)
            if fn_match:
                metadata["filename"] = fn_match.group(1).strip()

        return {
            "success": True,
            "data": metadata,
        }
    except Exception as e:
        logger.error("[DocumentTools] document_metadata_extract failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def public_document_tech_clue_extract(url: str) -> Dict:
    """
    Extract technology clues from a public document (metadata only, not full parsing).
    Uses HTTP response headers and URL patterns to infer tech stack.
    """
    try:
        clues = []

        resp = _SESSION.head(url, timeout=_TIMEOUT, allow_redirects=True)

        # Server info
        server = resp.headers.get("Server", "")
        if server:
            clues.append({"type": "server", "value": server, "source": "http_header"})

        # Powered-by
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            clues.append({"type": "framework", "value": powered, "source": "http_header"})

        # URL-based clues
        parsed = urlparse(url)
        path = parsed.path.lower()
        if "/wp-content/" in path or "/wp-includes/" in path:
            clues.append({"type": "cms", "value": "WordPress", "source": "url_pattern"})
        if "/sites/default/" in path:
            clues.append({"type": "cms", "value": "Drupal", "source": "url_pattern"})
        if "/joomla/" in path:
            clues.append({"type": "cms", "value": "Joomla", "source": "url_pattern"})

        return {
            "success": True,
            "data": {
                "url": url,
                "tech_clues": clues,
                "clue_count": len(clues),
            },
        }
    except Exception as e:
        logger.error("[DocumentTools] public_document_tech_clue_extract failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}
