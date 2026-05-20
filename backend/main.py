"""
MINA FastAPI Server

Endpoints:
  POST /api/scan/start            — start a new scan
  GET  /api/scan/{scan_id}/status — get scan status
  GET  /api/scan/{scan_id}/results— get final results
    GET  /api/scan/{scan_id}/report — get Markdown report
        GET  /api/scan/{scan_id}/export/{fmt} — export (json | csv | md | html | pdf)
  WS   /ws/{scan_id}              — real-time log stream
"""

import asyncio
import csv
import io
import json
import logging
import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

# Add backend root to path
sys.path.insert(0, os.path.dirname(__file__))

from core.config import EngagementSpec, MAX_ITERATIONS
from core.graph import build_graph, build_initial_state


def _to_dict(obj):
    """Convert a Pydantic model (or dict) to a plain JSON-safe dict."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mina.server")

app = FastAPI(title="MINA — Multi Intelligence Network Agent", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory session store
# ---------------------------------------------------------------------------
_executor = ThreadPoolExecutor(max_workers=4)

class ScanSession:
    def __init__(self, scan_id: str, target: str):
        self.scan_id = scan_id
        self.target = target
        self.status = "pending"          # pending | running | complete | error
        self.log_queue: asyncio.Queue = asyncio.Queue()
        self.final_state: Dict = {}
        self.started_at = datetime.now().isoformat()
        self.finished_at: Optional[str] = None
        self.ws_clients: List[WebSocket] = []
        # Track how many items were already broadcast (state is cumulative with operator.add)
        self.last_phase_idx: int = 0    # tracks phase_log list
        self.last_vuln_idx: int = 0     # tracks findings list
        self.last_obs_idx: int = 0      # tracks observations list
        self.last_entity_idx: int = 0   # tracks entities list
        self.last_rel_idx: int = 0      # tracks relationships list

_sessions: Dict[str, ScanSession] = {}


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str = Field(..., description="Root domain to scan, e.g. example.com")
    company_name: str = Field("", description="Company name for context")
    allowed_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    active_recon_enabled: bool = True
    rate_limit: float = Field(2.0, ge=0.5, le=10.0)
    max_depth: int = Field(2, ge=1, le=5)
    max_iterations: int = Field(MAX_ITERATIONS, ge=1, le=20)
    scan_profile: str = Field("balanced", description="quick | balanced | deep")
    wordlist_profile: str = Field("small", description="small | medium | extended")
    agents_enabled: Dict[str, bool] = Field(default_factory=dict)
    # V4: unified feature toggles and per-tool options
    features: Dict[str, bool] = Field(default_factory=dict)
    tool_options: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    report_detail: str = Field("detailed", description="summary | detailed | full_inventory")


# Map phase/node names to frontend agent labels (matches core/graph.py add_node calls)
_PHASE_TO_AGENT = {
    # System / gate nodes
    "setup":                "System",
    "preflight":            "System",
    "policy_gate":          "Safety",
    "lead_quality_gate":    "LeadQualityGate",
    "stop_condition":       "StopCondition",
    "stop":                 "System",
    "conflict_resolution":  "ConflictResolver",
    # Orchestration
    "director":             "Director",
    # Specialised collectors — Phase 1
    "root_domain":          "RootDomain",
    "subdomain_intel":      "SubdomainIntel",
    "infra_network":        "InfraNetwork",
    "company_intel":        "CompanyIntel",
    "people_intel":         "PeopleIntel",
    "credentials_access":   "CredentialsAccess",
    "karma_passive":        "KarmaPassive",
    "osint_deep_dive":      "OSINTDeepDive",
    "service_surface":      "ServiceSurface",
    "web_surface":          "WebSurface",
    # Provenance
    "attach_provenance":    "Provenance",
    # Post-collection pipeline
    "normalize":            "Normalizer",
    "normalizer":           "Normalizer",
    "correlate":            "Correlator",
    "correlator":           "Correlator",
    "impact_analysis":      "ImpactAnalyst",
    "impact":               "ImpactAnalyst",
    "table_compose":        "TableComposer",
    "report":               "Reporter",
    "reporter":             "Reporter",
    # Legacy node names (backward compat for old sessions)
    "passive_recon":        "PassiveRecon",
    "osint":                "OSINTAgent",
    "active_recon":         "ActiveRecon",
    "merge_conflict_gate":  "System",
}

# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan_blocking(scan_id: str, initial_state: Dict, loop: asyncio.AbstractEventLoop) -> None:
    """Runs LangGraph graph synchronously in a thread pool."""
    session = _sessions.get(scan_id)
    if not session:
        return

    def log_callback(entry: Dict) -> None:
        """Thread-safe log dispatch to asyncio queue and connected WebSockets."""
        msg = {"type": "log", **entry}
        asyncio.run_coroutine_threadsafe(session.log_queue.put(msg), loop)
        asyncio.run_coroutine_threadsafe(_broadcast(session, msg), loop)

    config = {
        "configurable": {
            "thread_id": scan_id,
            "log_callback": log_callback,
        }
    }

    try:
        graph = build_graph()
        session.status = "running"

        final = None
        for event in graph.stream(initial_state, config, stream_mode="values"):
            final = event
            # LangGraph uses operator.add reducer — state is cumulative.
            # Only broadcast items that are NEW since the last event.

            # ── Stream phase_log entries as progress log events ───────────────
            all_phase = event.get("phase_log", [])
            new_phase = all_phase[session.last_phase_idx:]
            session.last_phase_idx = len(all_phase)
            for entry in new_phase:
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {
                        "type": "log",
                        "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                        "agent": _PHASE_TO_AGENT.get(entry.get("phase", ""), "System"),
                        "level": entry.get("level", "info"),
                        "message": entry.get("message", ""),
                    }), loop
                )

            # ── Stream new findings/vulns ─────────────────────────────────────
            all_vulns = event.get("findings", []) or event.get("vulns", [])
            new_vulns_slice = all_vulns[session.last_vuln_idx:]
            session.last_vuln_idx = len(all_vulns)
            for vuln in new_vulns_slice:
                # Convert Pydantic Finding → dict so .get() works
                vd = _to_dict(vuln) if not isinstance(vuln, dict) else vuln
                # Normalise vuln fields so frontend always gets consistent keys
                norm_vuln = {
                    "vuln_id":       vd.get("vuln_id", vd.get("finding_id", vd.get("id", ""))),
                    "title":         vd.get("title", vd.get("vulnerability", vd.get("name", ""))),
                    "severity":      vd.get("severity", vd.get("risk_level", vd.get("impact", "medium"))),
                    "category":      vd.get("category", vd.get("type", "finding")),
                    "target":        vd.get("target", vd.get("asset", "")),
                    "description":   vd.get("description", vd.get("vulnerability", "")),
                    "source_agent":  vd.get("source_agent", ""),
                    "recommendation":vd.get("recommendation", ""),
                    "evidence_ref":  vd.get("evidence_ref", vd.get("evidence_refs", "")),
                    # Legacy aliases for backward compat
                    "asset":         vd.get("asset", vd.get("target", "")),
                    "type":          vd.get("type", vd.get("category", "finding")),
                    "vulnerability": vd.get("vulnerability", vd.get("description", "")),
                    "impact":        vd.get("impact", vd.get("severity", vd.get("risk_level", "medium"))),
                }
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {"type": "vulnerability", "vuln": norm_vuln}), loop
                )

            # ── Stream new observations as intel_events ───────────────────────
            all_obs = event.get("observations", [])
            new_obs = all_obs[session.last_obs_idx:]
            session.last_obs_idx = len(all_obs)
            for obs in new_obs:
                obs_d = _to_dict(obs) if not isinstance(obs, dict) else obs
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {
                        "type": "intel_event",
                        "payload": {
                            "timestamp": obs_d.get("first_seen") or datetime.now().isoformat(),
                            "source_agent": obs_d.get("source", "passive_recon"),
                            "what": obs_d.get("type", "observation"),
                            "value": obs_d.get("value", ""),
                            "where": obs_d.get("context", ""),
                            "how": obs_d.get("extractor", ""),
                            "confidence": obs_d.get("confidence", 0.5),
                            "evidence_ref": obs_d.get("evidence_ref", ""),
                        },
                    }), loop
                )

            # ── Stream entity_update + graph_node when entity list grows ──────
            all_entities = event.get("entities", [])
            new_entities = all_entities[session.last_entity_idx:]
            session.last_entity_idx = len(all_entities)
            for ent in new_entities:
                ent_d = _to_dict(ent)
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {"type": "entity_update", "payload": ent_d}), loop
                )
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {
                        "type": "graph_node",
                        "node": {
                            "id": ent_d.get("entity_id", ent_d.get("canonical_value", "")),
                            "value": ent_d.get("canonical_value", ""),
                            "type": ent_d.get("type", "unknown"),
                            "risk_level": "low",
                            "is_root": ent_d.get("type") in ("domain",),
                        },
                    }), loop
                )

            # ── Stream new relationship edges incrementally ───────────────────
            all_rels = event.get("relationships", [])
            new_rels = all_rels[session.last_rel_idx:]
            session.last_rel_idx = len(all_rels)
            for rel in new_rels:
                from_id = getattr(rel, "from_entity_id", "")
                to_id = getattr(rel, "to_entity_id", "")
                rel_type = getattr(rel, "relation_type", "related_to")
                if from_id and to_id and from_id != to_id:
                    asyncio.run_coroutine_threadsafe(
                        _broadcast(session, {
                            "type": "graph_edge",
                            "edge": {
                                "source": from_id,
                                "target": to_id,
                                "relation_type": rel_type,
                            },
                        }), loop
                    )

            # ── Stream collector_stats updates ────────────────────────────────
            cstats = event.get("collector_stats")
            if cstats:
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {
                        "type": "collector_stats",
                        "payload": cstats,
                    }), loop
                )

        session.final_state = final or {}
        session.status = "complete"
        session.finished_at = datetime.now().isoformat()

        # Broadcast all relationship edges (normalizer stores them in state but
        # graph_edge messages may not have been emitted during streaming).
        final_entities = (final or {}).get("entities", [])
        final_rels = (final or {}).get("relationships", [])
        eid_map = {
            getattr(e, "canonical_value", ""):
            getattr(e, "entity_id", "")
            for e in final_entities
        }
        for rel in final_rels:
            from_id = getattr(rel, "from_entity_id", "")
            to_id = getattr(rel, "to_entity_id", "")
            rel_type = getattr(rel, "relation_type", "related_to")
            src = eid_map.get(from_id, from_id)
            tgt = eid_map.get(to_id, to_id)
            if src and tgt and src != tgt:
                asyncio.run_coroutine_threadsafe(
                    _broadcast(session, {
                        "type": "graph_edge",
                        "edge": {
                            "source": src,
                            "target": tgt,
                            "relation_type": rel_type,
                        },
                    }), loop
                )

        complete_msg = {
            "type": "scan_complete",
            "scan_id": scan_id,
            "stats": {
                "entities": len(session.final_state.get("entities", [])),
                "relationships": len(session.final_state.get("relationships", [])),
                "vulnerabilities": len(session.final_state.get("findings", []) or session.final_state.get("vulns", [])),
            },
        }
        asyncio.run_coroutine_threadsafe(session.log_queue.put(complete_msg), loop)
        asyncio.run_coroutine_threadsafe(_broadcast(session, complete_msg), loop)

    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        session.status = "error"
        session.finished_at = datetime.now().isoformat()
        err_msg = {"type": "error", "message": str(exc)}
        asyncio.run_coroutine_threadsafe(session.log_queue.put(err_msg), loop)
        asyncio.run_coroutine_threadsafe(_broadcast(session, err_msg), loop)


async def _broadcast(session: ScanSession, msg: Dict) -> None:
    """Send a message to all connected WebSocket clients of a session."""
    dead: List[WebSocket] = []
    for ws in list(session.ws_clients):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        try:
            session.ws_clients.remove(ws)
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {"service": "MINA Backend", "status": "online", "version": "2.0.0"}


@app.get("/health")
async def health():
    return {"status": "ok", "sessions": len(_sessions)}


@app.get("/api/version")
async def version_info():
    """Return build stamp, source root, python executable, and cwd for source verification."""
    import platform
    build_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return {
        "build_stamp": f"MINA-V2-{build_stamp}",
        "source_root": os.path.dirname(os.path.abspath(__file__)),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "cwd": os.getcwd(),
        "version": "2.0.0",
        "api": "FastAPI",
    }


@app.get("/api/tools/health")
async def tools_health():
    """Return health status of all external tools."""
    from core.tool_health import check_all_tools
    return check_all_tools()


@app.post("/api/scan/start")
async def start_scan(body: ScanRequest):
    scan_id = str(uuid.uuid4())

    spec = EngagementSpec(
        target_domain=body.target,
        company_name=body.company_name,
        allowed_scope=body.allowed_scope or [body.target],
        out_of_scope=body.out_of_scope,
        active_recon_enabled=body.active_recon_enabled,
        rate_limit=body.rate_limit,
        max_depth=body.max_depth,
        max_iterations=body.max_iterations,
        scan_profile=body.scan_profile,
        wordlist_profile=body.wordlist_profile,
        agents_enabled=body.agents_enabled or {
            "passive_recon": True,
            "active_recon": True,
            "normalizer": True,
            "reporter": True,
        },
        features=body.features,
        tool_options=body.tool_options,
        report_detail=body.report_detail,
    )

    initial_state = build_initial_state(
        target=body.target,
        engagement_spec=spec.to_graph_dict(),
        max_iterations=body.max_iterations,
    )

    session = ScanSession(scan_id=scan_id, target=body.target)
    _sessions[scan_id] = session

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        _run_scan_blocking,
        scan_id,
        dict(initial_state),
        loop,
    )

    logger.info("Scan %s started for %s", scan_id, body.target)
    return {"scan_id": scan_id, "target": body.target, "status": "pending"}


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "status": session.status,
        "target": session.target,
        "started_at": session.started_at,
        "finished_at": session.finished_at,
    }


@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    fs = session.final_state
    return {
        "scan_id": scan_id,
        "status": session.status,
        "target": session.target,
        "entities": [_to_dict(e) for e in fs.get("entities", [])],
        "relationships": [_to_dict(r) for r in fs.get("relationships", [])],
        "vulnerabilities": [_to_dict(v) for v in (fs.get("findings", []) or fs.get("vulns", []))],
        "intel_events": [
            {
                "timestamp": (od := _to_dict(o) if not isinstance(o, dict) else o).get("first_seen") or "",
                "source_agent": od.get("source", "passive_recon"),
                "what": od.get("type", "observation"),
                "value": od.get("value", ""),
                "where": od.get("context", ""),
                "how": od.get("extractor", ""),
                "confidence": od.get("confidence", 0.5),
                "evidence_ref": od.get("evidence_ref", ""),
            }
            for o in fs.get("observations", [])
        ],
        "entity_count": len(fs.get("entities", [])),
        "intel_event_count": len(fs.get("observations", [])),
        "collector_stats": fs.get("collector_stats", {}),
    }


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = session.final_state.get("report", "")
    if not report:
        raise HTTPException(status_code=404, detail="Report not yet available")
    return PlainTextResponse(content=report, media_type="text/markdown")


@app.get("/api/scan/{scan_id}/export/{fmt}")
async def export_results(scan_id: str, fmt: str):
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    fs = session.final_state
    entities = [_to_dict(e) for e in fs.get("entities", [])]
    vulns = [_to_dict(v) for v in (fs.get("findings", []) or fs.get("vulns", []))]
    rels = [_to_dict(r) for r in fs.get("relationships", [])]

    fmt = fmt.lower()

    if fmt == "json":
        payload = {
            "target": session.target,
            "generated_at": datetime.now().isoformat(),
            "entities": entities,
            "relationships": fs.get("relationships", []),
            "vulnerabilities": vulns,
        }
        return StreamingResponse(
            iter([json.dumps(payload, indent=2, ensure_ascii=False, default=str)]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="intel_{session.target}.json"'},
        )

    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["type", "canonical_value", "risk_level", "confidence", "sources"])
        for ent in entities:
            writer.writerow([
                ent.get("type", ""),
                ent.get("canonical_value", ""),
                ent.get("risk_level", "low"),
                ent.get("confidence", ""),
                "|".join(ent.get("sources", [])),
            ])
        csv_data = output.getvalue()
        return StreamingResponse(
            iter([csv_data]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="intel_{session.target}.csv"'},
        )

    elif fmt == "md":
        report = fs.get("report", "Report not available")
        return StreamingResponse(
            iter([report]),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="report_{session.target}.md"'},
        )

    elif fmt == "html":
        html_path = fs.get("report_html", "")
        html_content = ""

        # Prefer the HTML exported by reporter agent; if missing, build on-demand.
        if html_path and os.path.exists(html_path):
            try:
                with open(html_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception:
                html_content = ""

        if not html_content:
            report_md = fs.get("report", "")
            if not report_md:
                raise HTTPException(status_code=404, detail="Report not yet available")
            try:
                from tools.report_tools import export_html_report

                tmp_md_path = os.path.join(os.path.dirname(__file__), "output", f"report_{scan_id}.md")
                html_path = export_html_report(report_md, tmp_md_path)
                with open(html_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"HTML export failed: {exc}")

        return StreamingResponse(
            iter([html_content]),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="report_{session.target}.html"'},
        )

    elif fmt == "pdf":
        pdf_path = fs.get("report_pdf", "")

        if pdf_path and os.path.exists(pdf_path):
            try:
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"PDF read failed: {exc}")
        else:
            report_md = fs.get("report", "")
            if not report_md:
                raise HTTPException(status_code=404, detail="Report not yet available")
            try:
                from tools.report_tools import export_pdf_report

                tmp_md_path = os.path.join(os.path.dirname(__file__), "output", f"report_{scan_id}.md")
                pdf_path = export_pdf_report(report_md, tmp_md_path)
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"PDF export failed: {exc}")

        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="report_{session.target}.pdf"'},
        )

    elif fmt == "relationships-csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["from_entity", "relation_type", "to_entity", "confidence", "evidence"])
        for rel in rels:
            writer.writerow([
                rel.get("from_entity", ""),
                rel.get("relation_type", ""),
                rel.get("to_entity", ""),
                rel.get("confidence", ""),
                rel.get("evidence", ""),
            ])
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="relationships_{session.target}.csv"'},
        )

    elif fmt == "vulnerabilities-csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["title", "severity", "category", "target", "description", "source_agent", "recommendation", "evidence_ref"])
        for v in vulns:
            writer.writerow([
                v.get("title", v.get("vulnerability", "")),
                v.get("severity", v.get("impact", "medium")),
                v.get("category", v.get("type", "")),
                v.get("target", v.get("asset", "")),
                v.get("description", v.get("vulnerability", "")),
                v.get("source_agent", ""),
                v.get("recommendation", ""),
                v.get("evidence_ref", ""),
            ])
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="vulnerabilities_{session.target}.csv"'},
        )

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}. Use json|csv|md|html|pdf|relationships-csv|vulnerabilities-csv")


@app.get("/api/scans")
async def list_scans():
    return [
        {
            "scan_id": sid,
            "target": s.target,
            "status": s.status,
            "started_at": s.started_at,
        }
        for sid, s in _sessions.items()
    ]


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    session = _sessions.get(scan_id)
    if not session:
        await websocket.send_json({"type": "error", "message": "Scan not found"})
        await websocket.close()
        return

    session.ws_clients.append(websocket)
    logger.info("WS client connected for scan %s", scan_id)

    # If scan is already complete or running, replay state to the new client
    if session.status in ("complete", "running"):
        fs = session.final_state
        # Replay all observations as intel events
        for obs in fs.get("observations", []):
            obs_d = _to_dict(obs) if not isinstance(obs, dict) else obs
            await websocket.send_json({"type": "intel_event", "payload": {
                "timestamp": obs_d.get("first_seen") or datetime.now().isoformat(),
                "source_agent": obs_d.get("source", "passive_recon"),
                "what": obs_d.get("type", "observation"),
                "value": obs_d.get("value", ""),
                "where": obs_d.get("context", ""),
                "how": obs_d.get("extractor", ""),
                "confidence": obs_d.get("confidence", 0.5),
                "evidence_ref": obs_d.get("evidence_ref", ""),
            }})
        # Replay all entities + graph nodes
        for ent in fs.get("entities", []):
            ent_d = _to_dict(ent) if not isinstance(ent, dict) else ent
            await websocket.send_json({"type": "entity_update", "payload": ent_d})
            await websocket.send_json({"type": "graph_node", "node": {
                "id": ent_d.get("entity_id", ent_d.get("canonical_value", "")),
                "value": ent_d.get("canonical_value", ""),
                "type": ent_d.get("type", "unknown"),
                "risk_level": "low",
                "is_root": ent_d.get("type") in ("domain",),
            }})
        # Replay all vulns/findings
        for vln in (fs.get("findings", []) or fs.get("vulns", [])):
            vd = _to_dict(vln) if not isinstance(vln, dict) else vln
            await websocket.send_json({"type": "vulnerability", "vuln": {
                "vuln_id": vd.get("finding_id", vd.get("vuln_id", "")),
                "title": vd.get("title", ""),
                "severity": vd.get("risk_level", vd.get("severity", "medium")),
                "description": vd.get("description", ""),
                "target": vd.get("target", ""),
            }})
        if session.status == "complete":
            await websocket.send_json({
                "type": "scan_complete",
                "scan_id": scan_id,
                "stats": {
                    "entities": len(fs.get("entities", [])),
                    "relationships": len(fs.get("relationships", [])),
                    "vulnerabilities": len(fs.get("findings", []) or fs.get("vulns", [])),
                    "intel_events": len(fs.get("observations", [])),
                },
            })

    try:
        while True:
            try:
                # Short timeout so we can send server-side keepalive pings
                data = await asyncio.wait_for(websocket.receive_text(), timeout=20.0)
                try:
                    msg = json.loads(data)
                    if msg.get("type") in ("ping", "pong"):
                        # Client is alive — echo back pong
                        await websocket.send_json({"type": "pong"})
                except Exception:
                    pass
            except asyncio.TimeoutError:
                # No message from client for 20s — send a server-side ping
                # This prevents browser/proxy from closing the idle WS.
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break  # Client is gone
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.error("WS error for scan %s: %s", scan_id, exc)
    finally:
        try:
            session.ws_clients.remove(websocket)
        except ValueError:
            pass
        logger.info("WS client disconnected from scan %s", scan_id)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
