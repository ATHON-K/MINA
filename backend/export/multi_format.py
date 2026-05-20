"""
Multi-format table exporter — JSON, CSV, Markdown, HTML, PDF per table.
Exports each table separately in all requested formats.
"""
import csv
import io
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def export_table_all_formats(
    output_dir: Path,
    name: str,
    rows: list[dict],
    formats: tuple[str, ...] = ("json", "csv", "md", "html"),
) -> dict[str, Path]:
    """Export a single table in multiple formats. Returns format -> path mapping."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    if not rows:
        for fmt in formats:
            p = output_dir / f"{name}.{fmt}"
            p.write_text("", encoding="utf-8")
            paths[fmt] = p
        return paths

    fieldnames = list(rows[0].keys())

    # JSON
    if "json" in formats:
        p = output_dir / f"{name}.json"
        p.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
        paths["json"] = p

    # CSV
    if "csv" in formats:
        p = output_dir / f"{name}.csv"
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        p.write_text(buf.getvalue(), encoding="utf-8")
        paths["csv"] = p

    # Markdown
    if "md" in formats:
        p = output_dir / f"{name}.md"
        md = _render_md_table(name, fieldnames, rows)
        p.write_text(md, encoding="utf-8")
        paths["md"] = p

    # HTML
    if "html" in formats:
        p = output_dir / f"{name}.html"
        html = _render_html_table(name, fieldnames, rows)
        p.write_text(html, encoding="utf-8")
        paths["html"] = p

    # PDF (optional — requires weasyprint or pdfkit)
    if "pdf" in formats:
        try:
            p = output_dir / f"{name}.pdf"
            html_content = _render_html_table(name, fieldnames, rows)
            _write_pdf(p, html_content)
            paths["pdf"] = p
        except Exception as e:
            logger.warning("[MultiFormat] PDF export failed for %s: %s", name, e)

    return paths


def export_all_tables_multi_format(
    tables: dict[str, list[dict]],
    output_dir: Path,
    formats: tuple[str, ...] = ("json", "csv", "md", "html"),
) -> dict[str, dict[str, Path]]:
    """Export all tables in all formats. Returns table_name -> {format -> path}."""
    result: dict[str, dict[str, Path]] = {}
    for name, rows in tables.items():
        result[name] = export_table_all_formats(output_dir, name, rows, formats)
        logger.debug("[MultiFormat] %s: %d rows in %d formats", name, len(rows), len(result[name]))
    return result


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_md_table(title: str, fields: list[str], rows: list[dict]) -> str:
    """Render rows as a Markdown table."""
    lines = [f"# {title.replace('_', ' ').title()}", ""]
    if not rows:
        lines.append("_No data._")
        return "\n".join(lines)

    header = "| " + " | ".join(fields) + " |"
    sep = "| " + " | ".join("---" for _ in fields) + " |"
    lines += [header, sep]

    for row in rows:
        cells = []
        for f in fields:
            v = str(row.get(f, ""))
            cells.append(v.replace("|", "\\|").replace("\n", " ")[:120])
        lines.append("| " + " | ".join(cells) + " |")

    lines += ["", f"_Total: {len(rows)} rows_"]
    return "\n".join(lines)


def _render_html_table(title: str, fields: list[str], rows: list[dict]) -> str:
    """Render rows as a standalone HTML table."""
    import html as html_mod

    display_title = title.replace("_", " ").title()
    header_cells = "".join(f"<th>{html_mod.escape(f)}</th>" for f in fields)

    body_rows = []
    for row in rows:
        cells = "".join(
            f"<td>{html_mod.escape(str(row.get(f, '')))}</td>"
            for f in fields
        )
        body_rows.append(f"<tr>{cells}</tr>")
    body = "\n".join(body_rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>{html_mod.escape(display_title)}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; margin: 20px; color: #1e293b; }}
  h1 {{ color: #0f172a; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 6px 10px; text-align: left; font-size: 0.85em; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .footer {{ margin-top: 12px; color: #64748b; font-size: 0.85em; }}
</style></head>
<body>
<h1>{html_mod.escape(display_title)}</h1>
<table>
<thead><tr>{header_cells}</tr></thead>
<tbody>
{body}
</tbody>
</table>
<p class="footer">Total: {len(rows)} rows</p>
</body></html>"""


def _write_pdf(path: Path, html_content: str):
    """Write HTML as PDF. Tries weasyprint first, then pdfkit."""
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(path))
        return
    except ImportError:
        pass
    try:
        import pdfkit
        pdfkit.from_string(html_content, str(path))
        return
    except ImportError:
        pass
    raise ImportError("Neither weasyprint nor pdfkit available for PDF export")
