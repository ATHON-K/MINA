"""
OSINT Deep-Dive Agent — LLM-powered intelligence synthesis.

This node runs AFTER all passive collectors have deposited observations.
It performs:
  1. CVE lookup for discovered services (enrichment)
  2. Dork query hints for manual follow-up
  3. LLM synthesis of all OSINT data → new leads
  4. Wayback/JS endpoint enrichment (tools already run by other agents
     may be skipped if observations already exist)

This is the *analysis* complement to the *collection* agents.
"""
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from core.config import config as _cfg
from core.evidence_store import EvidenceStore
from core.schemas import Finding, Lead, Observation, normalize_lead_type
from core.scope import is_garbage_lead
from core.state import MINAState
from agents.extraction_helpers import (
    emit_log,
    get_evidence_store,
    get_log_callback,
    store_evidence,
    materialize_observations,
)
from prompts.recon_prompts import OSINT_ANALYSIS_PROMPT, OSINT_ANALYSIS_SYSTEM
from tools.osint_tools import (
    cve_lookup_for_service,
    github_dork_hints,
    google_dork_hints,
)

logger = logging.getLogger(__name__)

AGENT = "OSINTDeepDive"


def _safe_format(template: str, **kwargs) -> str:
    """str.replace-based formatting that ignores JSON literal braces."""
    for key, value in kwargs.items():
        template = template.replace('{' + key + '}', str(value))
    return template


# ── LLM helpers ──────────────────────────────────────────────────

def _get_client():
    """Lazy-import OpenAI — returns None if SDK not installed or no key configured."""
    try:
        from openai import OpenAI  # noqa: PLC0415
    except ImportError:
        return None
    api_key = _cfg.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        return None
    return OpenAI(
        api_key=api_key,
        base_url=_cfg.deepseek_base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
    )


def _extract_json(text: str) -> Optional[Dict]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


# ── Main node ────────────────────────────────────────────────────

def osint_deep_dive_node(state: MINAState, config=None) -> MINAState:
    """
    LangGraph node: OSINT Deep-Dive — enrichment + LLM synthesis.

    Reads existing observations/entities and performs:
      - CVE lookup for discovered services
      - Dork hints (informational)
      - LLM synthesis to generate new leads
    """
    log_cb = get_log_callback(config)
    spec = state.get("engagement_spec", {})

    # Guard
    if not spec.get("agents_enabled", {}).get("osint", True):
        emit_log(log_cb, AGENT, "OSINT disabled — skipping deep-dive", "warning")
        return state

    target = ""
    current_lead = state.get("current_lead")
    if current_lead:
        target = (current_lead.value if hasattr(current_lead, "value")
                  else (current_lead.get("value", "") if isinstance(current_lead, dict) else ""))
    if not target:
        target = spec.get("target", "")
    if not target:
        return state

    session_id = spec.get("session_id", "")
    evidence_store = get_evidence_store(state)
    company = spec.get("company_name") or target.split(".")[0]

    emit_log(log_cb, AGENT, f"OSINT deep-dive started for {target}")

    new_findings: List[Finding] = []
    new_leads: List[Lead] = []
    ev_refs: Dict[str, str] = {}

    # ── 1. CVE Lookup for discovered services ────────────────────
    entities = state.get("entities", [])
    discovered_services = []
    for ent in entities:
        ent_d = ent if isinstance(ent, dict) else (ent.model_dump() if hasattr(ent, "model_dump") else {})
        if ent_d.get("type") in ("service", "open_port"):
            svc = (ent_d.get("attributes") or {}).get("service", "")
            ver = (ent_d.get("attributes") or {}).get("version", "")
            if svc:
                discovered_services.append({"service": svc, "version": ver})

    if discovered_services:
        emit_log(log_cb, AGENT, f"CVE lookup for {len(discovered_services)} services...")
        for svc_info in discovered_services[:5]:
            svc = svc_info["service"]
            ver = svc_info.get("version", "")
            result = cve_lookup_for_service(svc, ver)
            if result.get("success") and result.get("data", {}).get("cves"):
                ev_id = store_evidence(evidence_store, f"osint/cve_{svc}", target, result)
                for cve in result["data"]["cves"][:3]:
                    score = float(cve.get("cvss", {}).get("score", 0) or 0)
                    if score >= 7.0:
                        new_findings.append(Finding(
                            session_id=session_id,
                            title=cve.get("id", "CVE"),
                            description=f"{svc} {ver}: {cve.get('summary', '')}",
                            risk_level="critical" if score >= 9 else "high",
                            category="infrastructure_exposure",
                            impact_category="infrastructure_exposure",
                            impact_items=[target],
                            evidence_refs=[ev_id],
                            confidence_score=0.85,
                            recommendation=f"Upgrade {svc} to latest stable version.",
                        ))
            time.sleep(1)

    # ── 2. Dork hints (informational) ────────────────────────────
    emit_log(log_cb, AGENT, "Generating dork queries...")
    github_dork_result = github_dork_hints(target, company)
    google_dork_result = google_dork_hints(target)
    ev_refs["dorks"] = store_evidence(
        evidence_store, "osint/dorks", target,
        {"github": github_dork_result, "google": google_dork_result},
    )

    # ── 3. LLM Synthesis ────────────────────────────────────────
    emit_log(log_cb, AGENT, "LLM synthesising OSINT intelligence...")

    # Gather summaries of raw data already in state
    karma_ip_summary = _summarise_collector(state, "karma_ip")
    karma_leaks_summary = _summarise_collector(state, "karma_leaks")
    karma_cve_summary = _summarise_collector(state, "karma_cve")
    zone_summary = _summarise_collector(state, "zone_transfer")
    js_summary = _summarise_collector(state, "js_endpoints")

    llm_new_leads: List[Dict] = []
    client = _get_client()
    try:
        if not client:
            raise ValueError("LLM client unavailable (missing SDK or API key) — skipping LLM synthesis")

        prompt = _safe_format(
            OSINT_ANALYSIS_PROMPT,
            target=target,
            zone_transfer_result=zone_summary[:1500],
            github_dork_result=json.dumps(github_dork_result, default=str)[:1000],
            google_dork_result=json.dumps(google_dork_result, default=str)[:1000],
            js_endpoints_result=js_summary[:2000],
            cve_lookup_result=json.dumps([], default=str)[:1500],
            karma_ip_result=karma_ip_summary[:1500],
            karma_leaks_result=karma_leaks_summary[:1500],
            karma_cve_result=karma_cve_summary[:1500],
        )
        response = client.chat.completions.create(
            model=_cfg.deepseek_model or "deepseek-chat",
            messages=[
                {"role": "system", "content": OSINT_ANALYSIS_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
        )
        content = response.choices[0].message.content or ""
        llm_findings = _extract_json(content) or {}
        emit_log(log_cb, AGENT, "LLM analysis complete", "success")
        llm_new_leads = llm_findings.get("new_leads", [])
    except Exception as exc:
        emit_log(log_cb, AGENT, f"LLM error: {exc}", "error")
        state.setdefault("error_log", []).append({
            "tool": "osint_deep_dive_llm", "error": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ── 4. Convert LLM leads to Lead objects ─────────────────────
    processed_keys = state.get("processed_lead_ids", set())
    for lead_data in llm_new_leads:
        val = (lead_data.get("value") or "").strip()
        ltype = lead_data.get("type", "subdomain")
        if not val or is_garbage_lead(val):
            continue
        dedup_key = f"{ltype}:{val.lower()}"
        if dedup_key in processed_keys:
            continue
        if ltype in ("subdomain", "domain"):
            root = target.split(".", 1)[-1] if "." in target else target
            if not val.lower().endswith(root) and root not in val.lower():
                continue
        new_leads.append(Lead(
            type=normalize_lead_type(ltype), value=val.lower(), raw_value=val,
            source="osint_deep_dive", confidence=float(lead_data.get("confidence", 0.7)),
            priority=0.6,
            depth=((current_lead.depth if hasattr(current_lead, "depth") else 0) + 1) if current_lead else 1,
            parent_lead_id=current_lead.lead_id if hasattr(current_lead, "lead_id") else None,
            discovered_by="osint_deep_dive",
        ))

    # ── Update state ─────────────────────────────────────────────
    state["findings"] = state.get("findings", []) + new_findings
    state["lead_queue"] = state.get("lead_queue", []) + new_leads

    state.setdefault("phase_log", []).append({
        "phase": "osint_deep_dive",
        "timestamp": datetime.now().isoformat(),
        "message": f"OSINT deep-dive done — {len(new_findings)} findings, {len(new_leads)} leads",
    })

    emit_log(log_cb, AGENT,
             f"OSINT deep-dive done — {len(new_findings)} findings, {len(new_leads)} leads",
             "success")
    return state


# ── Helpers ──────────────────────────────────────────────────────

def _summarise_collector(state: MINAState, tool_key: str) -> str:
    """Build a short JSON summary of raw_events from a specific collector."""
    relevant = []
    for re_item in state.get("raw_events", []):
        collector = getattr(re_item, "collector", "")
        if tool_key in collector:
            relevant.append(re_item if isinstance(re_item, dict)
                            else (re_item.model_dump() if hasattr(re_item, "model_dump") else {}))
    if not relevant:
        return "{}"
    return json.dumps(relevant[:3], default=str)
