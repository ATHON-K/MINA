import requests

from tools import report_tools


def test_calculate_risk_score_basic():
    entities = [
        {"type": "subdomain", "canonical_value": "api.example.com"},
        {"type": "ip", "canonical_value": "1.2.3.4"},
    ]
    vulns = [
        {"severity": "high", "title": "Exposed admin"},
        {"severity": "medium", "title": "Missing CSP"},
    ]

    result = report_tools.calculate_risk_score(entities, vulns)

    assert result["success"] is True
    assert result["data"]["overall_score"] > 0
    assert result["data"]["total_vulns"] == 2


def test_export_html_report_creates_html(tmp_path):
    md = "# Test Report\n\n## Findings\n\n- A\n- B\n"
    out_md = tmp_path / "report.md"

    html_path = report_tools.export_html_report(md, str(out_md))

    html_file = tmp_path / "report.html"
    assert html_path.endswith("report.html")
    assert html_file.exists()
    assert "Test Report" in html_file.read_text(encoding="utf-8")


def test_export_pdf_report_creates_pdf(tmp_path):
    md = "# Test PDF\n\n## Findings\n\n- Item A\n- Item B\n"
    out_md = tmp_path / "report.md"

    pdf_path = report_tools.export_pdf_report(md, str(out_md))

    pdf_file = tmp_path / "report.pdf"
    assert pdf_path.endswith("report.pdf")
    assert pdf_file.exists()
    content = pdf_file.read_bytes()
    assert content.startswith(b"%PDF-")


def test_classify_severity_without_api_key(monkeypatch):
    monkeypatch.setattr(report_tools, "_DEEPSEEK_KEY", "")

    result = report_tools.classify_severity({"title": "Missing HSTS"})

    assert result["success"] is False
    assert "DEEPSEEK_API_KEY" in result["error"]


def test_cve_lookup_handles_http_error(monkeypatch):
    class DummyResp:
        def raise_for_status(self):
            raise requests.HTTPError("boom")

    def fake_get(*args, **kwargs):
        return DummyResp()

    monkeypatch.setattr(report_tools, "_NVD_API_KEY", "dummy-key")
    monkeypatch.setattr(report_tools.requests, "get", fake_get)

    result = report_tools.cve_lookup("nginx", "1.18.0")

    assert result["success"] is False
    assert "NVD API error" in result["error"]
