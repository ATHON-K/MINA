"""
report_tools.py — Reporting utilities.

  cve_lookup(service, version)        : NVD API v2 CVE search
  classify_severity(finding)          : DeepSeek-powered CVSS v3.1 scoring
  calculate_risk_score(entities, vulns): Algorithmic risk aggregation
  export_html_report(markdown, path)  : Markdown → styled HTML file
    export_pdf_report(markdown, path)   : Markdown → plain PDF file

All functions return: {"success": bool, "data": {...}, "error": str | None}
"""

import json
import logging
import os
import time
import re
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

_DEEPSEEK_BASE   = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
_DEEPSEEK_KEY    = os.getenv("DEEPSEEK_API_KEY", "")
_DEEPSEEK_MODEL  = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
_NVD_API_KEY     = os.getenv("NVD_API_KEY", "")        # optional, increases rate limit
_NVD_BASE        = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ─────────────────────────────────────────────────────────────────────────────
# 1. CVE Lookup (NVD API v2)
# ─────────────────────────────────────────────────────────────────────────────

_CVSS_SEVERITY = {
    "CRITICAL": "Critical",  # CVSS >= 9.0
    "HIGH":     "High",      # 7.0–8.9
    "MEDIUM":   "Medium",    # 4.0–6.9
    "LOW":      "Low",       # 0.1–3.9
    "NONE":     "Info",
}


def cve_lookup(service: str, version: str = "") -> Dict[str, Any]:
    """
    Search the NVD CVE database for a given service name + optional version.
    Returns up to 5 most recent CVEs with CVSS v3 scores.

    Rate limits (no API key): 5 requests/30 s → we sleep 6 s between calls if no key.
    """
    keyword = f"{service} {version}".strip()
    params: Dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
    }
    headers: Dict[str, str] = {"Accept": "application/json"}
    if _NVD_API_KEY:
        headers["apiKey"] = _NVD_API_KEY
    else:
        time.sleep(6)

    try:
        resp = requests.get(_NVD_BASE, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        json_data = resp.json()

        cves: List[Dict] = []
        for item in json_data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id  = cve.get("id", "")
            desc    = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS v3.1 preferred, fallback to v3.0 then v2
            metrics = cve.get("metrics", {})
            cvss_score  = None
            cvss_vector = None
            severity    = "Unknown"

            for key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score  = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    severity = _CVSS_SEVERITY.get(
                        cvss_data.get("baseSeverity", ""), "Unknown"
                    )
                    break
            if cvss_score is None:
                for m in metrics.get("cvssMetricV2", []):
                    cvss_data = m.get("cvssData", {})
                    cvss_score  = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            cwes: List[str] = [
                wp.get("value", "")
                for ws in cve.get("weaknesses", [])
                for wp in ws.get("description", [])
                if wp.get("lang") == "en"
            ]

            cves.append({
                "cve_id":       cve_id,
                "description":  desc[:500],
                "cvss_v3_score": cvss_score,
                "cvss_v3_vector": cvss_vector,
                "severity":     severity,
                "published":    cve.get("published", ""),
                "nvd_url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cwe":          cwes,
            })

        return {
            "success": True,
            "data": {
                "query":       keyword,
                "total_found": json_data.get("totalResults", 0),
                "cves":        cves,
            },
            "error": None,
        }

    except requests.HTTPError as exc:
        return {"success": False, "data": {"query": keyword, "cves": []}, "error": f"NVD API error: {exc}"}
    except Exception as exc:
        logger.error("cve_lookup(%s %s): %s", service, version, exc)
        return {"success": False, "data": {"query": keyword, "cves": []}, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Severity Classifier (DeepSeek LLM)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_SYSTEM = """You are a CVSS v3.1 security scoring expert.
Given a vulnerability finding, return ONLY a valid JSON object with these fields:
{
  "severity": "Critical|High|Medium|Low|Info",
  "cvss_score": 0.0-10.0,
  "cvss_vector": "CVSS:3.1/...",
  "attack_vector": "Network|Adjacent|Local|Physical",
  "attack_complexity": "Low|High",
  "privileges_required": "None|Low|High",
  "user_interaction": "None|Required",
  "scope": "Unchanged|Changed",
  "confidentiality_impact": "None|Low|High",
  "integrity_impact": "None|Low|High",
  "availability_impact": "None|Low|High",
  "reasoning": "one-sentence explanation"
}
Return ONLY the JSON, no additional text."""


def classify_severity(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use DeepSeek to classify severity of a finding using CVSS v3.1.
    Accepts any dict with at minimum a 'description' or 'title' key.
    """
    if not _DEEPSEEK_KEY:
        return {"success": False, "data": {}, "error": "DEEPSEEK_API_KEY not configured"}

    finding_text = json.dumps(finding, ensure_ascii=False, indent=2)[:1500]

    try:
        resp = requests.post(
            f"{_DEEPSEEK_BASE}/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {_DEEPSEEK_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "model": _DEEPSEEK_MODEL,
                "messages": [
                    {"role": "system", "content": _SEVERITY_SYSTEM},
                    {"role": "user",   "content": f"Classify this finding:\n{finding_text}"},
                ],
                "temperature": 0.1,
                "max_tokens": 1024,
                "response_format": {"type": "json_object"},
            },
            timeout=30,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return {"success": True, "data": parsed, "error": None}

    except json.JSONDecodeError as exc:
        return {"success": False, "data": {}, "error": f"LLM returned invalid JSON: {exc}"}
    except Exception as exc:
        logger.error("classify_severity: %s", exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Risk Score Calculator (algorithmic, no LLM)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {
    "critical": 10,
    "high":      7,
    "medium":    4,
    "low":       1,
    "info":      0,
    "unknown":   2,
}

_SCORE_LABEL = [
    (90, "Critical"),
    (70, "High"),
    (40, "Medium"),
    (20, "Low"),
    ( 0, "Info"),
]


def calculate_risk_score(
    entities: List[Dict[str, Any]],
    vulns: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compute an aggregate risk score (0–100) from a list of entities and vulnerabilities.

    Inputs
    ------
    entities : list of {type, value, ...} objects
    vulns    : list of {severity, title/description, ...} objects
    """
    breakdown: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0
    }

    total_weight = 0
    max_weight   = 0
    top_risks: List[str] = []

    for v in vulns:
        raw_sev = str(v.get("severity", "unknown")).lower()
        sev_key = raw_sev if raw_sev in breakdown else "unknown"
        breakdown[sev_key] += 1
        weight = _SEVERITY_WEIGHT[sev_key]
        total_weight += weight
        max_weight   += _SEVERITY_WEIGHT["critical"]

        if sev_key in ("critical", "high") and len(top_risks) < 5:
            label = v.get("title") or v.get("description") or v.get("name") or str(v)
            top_risks.append(f"[{sev_key.upper()}] {str(label)[:80]}")

    # Normalise to 0–100; cap at 100
    if max_weight > 0:
        raw_score = (total_weight / max_weight) * 100
        # Apply a logarithmic amplifier for high-severity clusters
        if breakdown["critical"] >= 3:
            raw_score = min(100, raw_score * 1.3)
        elif breakdown["high"] >= 5:
            raw_score = min(100, raw_score * 1.15)
        score = round(min(100.0, raw_score), 1)
    else:
        score = 0.0

    # Determine label
    risk_level = "Info"
    for threshold, label in _SCORE_LABEL:
        if score >= threshold:
            risk_level = label
            break

    # Exposure factor: more exposed hosts → higher risk
    host_count = sum(1 for e in entities if e.get("type") in ("ip", "host", "subdomain"))
    exposure_factor = min(1 + (host_count / 20), 1.5)
    score = round(min(100.0, score * exposure_factor), 1)

    return {
        "success": True,
        "data": {
            "overall_score": score,
            "risk_level": risk_level,
            "breakdown": breakdown,
            "total_vulns": len(vulns),
            "total_entities": len(entities),
            "top_risks": top_risks,
        },
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. HTML Report Exporter
# ─────────────────────────────────────────────────────────────────────────────

_HTML_CSS = """
<style>
  :root {--accent:#2563eb;--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--danger:#ef4444;--warn:#f59e0b;--ok:#22c55e;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem;}
  .container{max-width:1000px;margin:auto;}
  h1{font-size:2rem;color:var(--accent);border-bottom:2px solid var(--accent);padding-bottom:.5rem;margin-bottom:1.5rem;}
  h2{font-size:1.4rem;color:var(--accent);margin:2rem 0 .8rem;border-left:4px solid var(--accent);padding-left:.8rem;}
  h3{font-size:1.1rem;color:var(--muted);margin:1.2rem 0 .4rem;}
  p,li{margin:.3rem 0;}
  ul,ol{padding-left:1.5rem;}
  a{color:var(--accent);text-decoration:none;}
  a:hover{text-decoration:underline;}
  code{background:var(--card);padding:.1rem .4rem;border-radius:4px;font-family:monospace;font-size:.9em;}
  pre{background:var(--card);padding:1rem;border-radius:8px;overflow-x:auto;margin:1rem 0;}
  pre code{padding:0;background:none;}
  table{width:100%;border-collapse:collapse;margin:1rem 0;}
  th{background:var(--card);color:var(--accent);padding:.6rem 1rem;text-align:left;border-bottom:2px solid var(--accent);}
  td{padding:.5rem 1rem;border-bottom:1px solid #334155;}
  tr:hover td{background:#1e293b50;}
  blockquote{border-left:4px solid var(--muted);padding:.5rem 1rem;background:var(--card);border-radius:0 8px 8px 0;margin:1rem 0;}
  .badge-critical{background:#fecaca;color:#991b1b;padding:.1rem .5rem;border-radius:9999px;font-size:.8em;}
  .badge-high{background:#fed7aa;color:#92400e;padding:.1rem .5rem;border-radius:9999px;font-size:.8em;}
  .badge-medium{background:#fef3c7;color:#78350f;padding:.1rem .5rem;border-radius:9999px;font-size:.8em;}
  .badge-low{background:#d1fae5;color:#065f46;padding:.1rem .5rem;border-radius:9999px;font-size:.8em;}
  hr{border:none;border-top:1px solid #334155;margin:2rem 0;}
  .footer{color:var(--muted);font-size:.8rem;text-align:center;margin-top:3rem;padding-top:1rem;border-top:1px solid #334155;}
</style>
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  {css}
</head>
<body>
  <div class="container">
    {body}
    <div class="footer">Generated by MINA Recon Framework &bull; {timestamp}</div>
  </div>
</body>
</html>"""


def export_html_report(markdown_content: str, output_path: str) -> str:
    """
    Convert a Markdown report to a styled HTML file and save it.

    Parameters
    ----------
    markdown_content : str  — full markdown string (report body)
    output_path      : str  — path for the .md file; HTML is saved as .html

    Returns
    -------
    str — absolute path of the generated HTML file
    """
    html_path = output_path.replace(".md", ".html")
    if not html_path.endswith(".html"):
        html_path += ".html"

    # Extract title from first heading
    import re
    title_match = re.search(r"^#\s+(.+)$", markdown_content, re.MULTILINE)
    title = title_match.group(1) if title_match else "MINA Security Report"

    # Convert markdown → HTML
    body_html = _markdown_to_html(markdown_content)

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    html_doc = _HTML_TEMPLATE.format(
        title=title,
        css=_HTML_CSS,
        body=body_html,
        timestamp=timestamp,
    )

    os.makedirs(os.path.dirname(os.path.abspath(html_path)), exist_ok=True)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    logger.info("HTML report saved to: %s", html_path)
    return html_path


def export_pdf_report(markdown_content: str, output_path: str) -> str:
    """
    Export Markdown content to a basic text PDF file.

    This implementation intentionally avoids external dependencies so export
    remains available in constrained environments.
    """
    pdf_path = output_path.replace(".md", ".pdf")
    if not pdf_path.endswith(".pdf"):
        pdf_path += ".pdf"

    plain_text = _markdown_to_plain_text(markdown_content)
    lines = [ln.rstrip() for ln in plain_text.splitlines()]
    if not lines:
        lines = ["MINA Security Report"]

    # PDF page geometry (A4-ish points)
    page_width = 595
    page_height = 842
    margin_x = 48
    top_y = 800
    line_height = 14
    max_lines_per_page = 50

    pages: List[List[str]] = []
    for i in range(0, len(lines), max_lines_per_page):
        pages.append(lines[i:i + max_lines_per_page])

    objects: List[bytes] = []

    # 1: Catalog, 2: Pages, 3: Font
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Count 0 /Kids [] >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_obj_ids: List[int] = []
    content_obj_ids: List[int] = []

    for page_lines in pages:
        text_ops = [f"BT /F1 10 Tf {margin_x} {top_y} Td".encode("ascii")]
        for idx, ln in enumerate(page_lines):
            safe = _pdf_escape(_normalize_pdf_text(ln))
            if idx == 0:
                text_ops.append(f"({safe}) Tj".encode("latin-1", errors="replace"))
            else:
                text_ops.append(f"0 -{line_height} Td ({safe}) Tj".encode("latin-1", errors="replace"))
        text_ops.append(b"ET")
        stream = b"\n".join(text_ops)

        content_obj_id = len(objects) + 1
        content_obj_ids.append(content_obj_id)
        objects.append(
            b"<< /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )

        page_obj_id = len(objects) + 1
        page_obj_ids.append(page_obj_id)
        objects.append(
            (
                "<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {page_width} {page_height}] "
                "/Resources << /Font << /F1 3 0 R >> >> "
                f"/Contents {content_obj_id} 0 R >>"
            ).encode("ascii")
        )

    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects[1] = f"<< /Type /Pages /Count {len(page_obj_ids)} /Kids [{kids}] >>".encode("ascii")

    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")
    offsets = [0]

    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{idx} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_pos = len(pdf)
    total_objects = len(objects)
    pdf.extend(f"xref\n0 {total_objects + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    pdf.extend(
        (
            "trailer\n"
            f"<< /Size {total_objects + 1} /Root 1 0 R >>\n"
            "startxref\n"
            f"{xref_pos}\n"
            "%%EOF\n"
        ).encode("ascii")
    )

    os.makedirs(os.path.dirname(os.path.abspath(pdf_path)), exist_ok=True)
    with open(pdf_path, "wb") as fh:
        fh.write(pdf)

    logger.info("PDF report saved to: %s", pdf_path)
    return pdf_path


def _markdown_to_html(md: str) -> str:
    """Convert Markdown to HTML — uses markdown2 if available, falls back to regex."""
    try:
        import markdown2  # type: ignore
        return markdown2.markdown(
            md,
            extras=["tables", "fenced-code-blocks", "header-ids", "strike"],
        )
    except ImportError:
        pass

    # Minimal regex-based fallback
    import re, html as html_mod

    lines = md.split("\n")
    out: List[str] = []
    in_code_block = False
    in_list = False

    for line in lines:
        raw = line

        # Code fences
        if line.startswith("```"):
            if in_code_block:
                out.append("</code></pre>")
                in_code_block = False
            else:
                lang = line[3:].strip()
                out.append(f'<pre><code class="language-{lang}">')
                in_code_block = True
            continue
        if in_code_block:
            out.append(html_mod.escape(line))
            continue

        # Close list if blank line
        if in_list and not line.strip():
            out.append("</ul>")
            in_list = False

        # Headings
        if line.startswith("### "):
            out.append(f"<h3>{html_mod.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{html_mod.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{html_mod.escape(line[2:])}</h1>")
        # Horizontal rule
        elif line.strip() in ("---", "***", "___"):
            out.append("<hr>")
        # Blockquote
        elif line.startswith("> "):
            out.append(f"<blockquote>{html_mod.escape(line[2:])}</blockquote>")
        # Unordered list
        elif line.startswith(("- ", "* ", "+ ")):
            if not in_list:
                out.append("<ul>")
                in_list = True
            line = line[2:]
            line = _inline_format(line)
            out.append(f"<li>{line}</li>")
        # Blank line → paragraph break
        elif not line.strip():
            out.append("<p></p>")
        else:
            line = _inline_format(line)
            out.append(f"<p>{line}</p>")

    if in_list:
        out.append("</ul>")
    if in_code_block:
        out.append("</code></pre>")

    return "\n".join(out)


def _markdown_to_plain_text(md: str) -> str:
    """Basic Markdown-to-text conversion for PDF text rendering."""
    text = md
    text = re.sub(r"```[\s\S]*?```", "", text)
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"\*(.*?)\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    text = re.sub(r"^\s*[-*+]\s+", "- ", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _normalize_pdf_text(text: str) -> str:
    """Limit glyphs to Latin-1 for the built-in Helvetica font."""
    return text.encode("latin-1", errors="replace").decode("latin-1", errors="replace")


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _inline_format(text: str) -> str:
    """Apply inline Markdown formatting: bold, italic, code, links."""
    import re
    import html as html_mod
    text = html_mod.escape(text)
    # Bold **…** or __…__
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"__(.+?)__",     r"<strong>\1</strong>", text)
    # Italic *…* or _…_
    text = re.sub(r"\*(.+?)\*",     r"<em>\1</em>", text)
    text = re.sub(r"_(.+?)_",       r"<em>\1</em>", text)
    # Inline code `…`
    text = re.sub(r"`(.+?)`",       r"<code>\1</code>", text)
    # Links [text](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text
