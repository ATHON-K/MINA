from tools import web_tools


class DummyCookie:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class DummyResponse:
    def __init__(self, status_code=200, headers=None, text="", content=b"", url="https://example.com", cookies=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = content
        self.url = url
        self.cookies = cookies or []


def test_check_http_methods_flags_put(monkeypatch):
    def fake_options(url, **kwargs):
        return DummyResponse(status_code=200, headers={"Allow": "GET,POST,PUT"})

    def fake_request(method, url, **kwargs):
        if method in {"GET", "POST", "PUT", "HEAD", "OPTIONS"}:
            return DummyResponse(status_code=200, headers={})
        return DummyResponse(status_code=405, headers={})

    monkeypatch.setattr(web_tools.requests, "options", fake_options)
    monkeypatch.setattr(web_tools.requests, "request", fake_request)

    result = web_tools.check_http_methods("https://example.com")

    assert result["success"] is True
    assert "PUT" in result["data"]["methods_allowed"]
    assert any(x["method"] == "PUT" for x in result["data"]["dangerous_methods_found"])


def test_detect_waf_cloudflare_signature(monkeypatch):
    def fake_get(url, **kwargs):
        if "?id=1+AND+1=1--" in url:
            return DummyResponse(status_code=403, headers={"server": "cloudflare"}, text="blocked")
        return DummyResponse(
            status_code=200,
            headers={"cf-ray": "abc123", "server": "cloudflare"},
            text="ok",
            cookies=[DummyCookie("__cf_bm", "xyz")],
            url=url,
        )

    monkeypatch.setattr(web_tools.requests, "get", fake_get)

    result = web_tools.detect_waf("example.com")

    assert result["success"] is True
    assert result["data"]["waf_detected"] is True
    assert result["data"]["waf_product"] == "Cloudflare"


def test_enumerate_directories_finds_interesting_paths(monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("/admin"):
            return DummyResponse(status_code=403, headers={"Content-Length": "120"}, content=b"x" * 120)
        if url.endswith("/login"):
            return DummyResponse(status_code=200, headers={"Content-Length": "80"}, content=b"x" * 80)
        return DummyResponse(status_code=404, headers={"Content-Length": "0"}, content=b"")

    monkeypatch.setattr(web_tools.requests, "get", fake_get)

    result = web_tools.enumerate_directories(
        "https://example.com",
        wordlist_type="small",
        max_workers=4,
        rate_limit=0,
    )

    found_paths = {item["path"] for item in result["data"]["found"]}
    assert "/admin" in found_paths
    assert "/login" in found_paths


def test_enumerate_directories_uses_file_wordlist(monkeypatch, tmp_path):
    def fake_get(url, **kwargs):
        if url.endswith("/admin"):
            return DummyResponse(status_code=200, headers={"Content-Length": "10"}, content=b"x" * 10)
        return DummyResponse(status_code=404, headers={"Content-Length": "0"}, content=b"")

    monkeypatch.setattr(web_tools.requests, "get", fake_get)
    monkeypatch.setattr(web_tools, "_WORDLIST_FILE_MAP", {"small": "directories_small.txt", "medium": "directories_small.txt", "large": "directories_small.txt"})
    monkeypatch.setattr(web_tools, "_load_directory_wordlist_from_file", lambda t: ["admin", "login"])

    result = web_tools.enumerate_directories(
        "https://example.com",
        wordlist_type="small",
        max_workers=2,
        rate_limit=0,
    )

    assert result["success"] is True
    assert result["data"]["wordlist_source"].startswith("file:")
