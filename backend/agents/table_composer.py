"""
Table Composer Node — dedicated step between Impact and Report.

V6: Runs export_all_tables() with standardized schemas, then exports
multi-format copies (JSON, CSV, MD, HTML) per table.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.state import MINAState
from export.table_exporter import export_all_tables
from export.multi_format import export_all_tables_multi_format

logger = logging.getLogger(__name__)


def table_composer_node(state: MINAState, config=None) -> MINAState:
    """
    LangGraph node: export structured inventory tables.

    1. Exports primary + supplementary tables (JSON + CSV) via table_exporter
    2. Exports per-table MD + HTML via multi_format
    3. Populates state["export_paths"]["tables"] for the reporter
    """
    spec = state["engagement_spec"]
    session_dir = Path(f"backend/output/sessions/{spec['session_id']}")
    tables_dir = session_dir / "tables"

    # Step 1: Export all tables (JSON + CSV)
    table_paths = export_all_tables(state, tables_dir)

    # Step 2: Load tables for multi-format export
    tables_data: dict[str, list[dict]] = {}
    for name, json_path in table_paths.items():
        if str(json_path).endswith(".json"):
            try:
                data = json.loads(Path(json_path).read_text(encoding="utf-8"))
                if isinstance(data, list):
                    tables_data[name] = data
            except Exception:
                pass

    # Step 3: Export multi-format (MD + HTML per table)
    multi_dir = tables_dir / "multi_format"
    multi_paths: dict = {}
    try:
        multi_paths = export_all_tables_multi_format(
            tables_data, multi_dir, formats=("md", "html")
        )
        logger.info("[TableComposer] Multi-format export: %d tables", len(multi_paths))
    except Exception as e:
        logger.warning("[TableComposer] Multi-format export failed: %s", e)

    # Store paths in state
    state["export_paths"] = state.get("export_paths", {})
    state["export_paths"]["tables"] = {
        name: str(p) for name, p in table_paths.items()
    }
    if multi_paths:
        state["export_paths"]["multi_format"] = {
            name: {fmt: str(p) for fmt, p in fmt_paths.items()}
            for name, fmt_paths in multi_paths.items()
        }

    total = len(table_paths)
    logger.info("[TableComposer] Exported %d tables to %s", total, tables_dir)

    _log = None
    if config:
        _log = (config if isinstance(config, dict) else {}).get("configurable", {}).get("log_callback")
    if _log:
        _log({"type": "phase", "phase": "table_compose", "status": "done",
              "tables_exported": total})

    state.setdefault("phase_log", []).append({
        "phase": "table_compose",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"Exported {total} tables in JSON/CSV/MD/HTML",
    })

    return state
