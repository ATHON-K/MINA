"""
Impact Model — scoring rules + graph centrality for Finding priority.

V5: Impact bám bảng Category / Items Drop / Impact:
    - Service type → asset_value
    - Digital asset type → business_impact
    - Credential signal → very high risk
    - Admin/login exposure → high attention
    - Output clear reasoning per finding
"""
import logging
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from core.state import MINAState
from core.schemas import Finding, RiskLevel, FindingCategory, ImpactInsight

logger = logging.getLogger(__name__)

# ── V5: Service type → asset value ──────────────────────────────
SERVICE_ASSET_VALUE = {
    "database":   0.95,   # mysql, postgresql, mongodb, redis, mssql
    "admin":      0.90,   # admin panels, management interfaces
    "auth":       0.90,   # authentication services, SSO
    "email":      0.80,   # smtp, imap
    "storage":    0.85,   # S3, file servers, ftp
    "api":        0.80,   # REST/GraphQL endpoints
    "web":        0.65,   # standard web service
    "dns":        0.60,   # name servers
    "monitoring": 0.55,   # prometheus, grafana
    "default":    0.50,
}

# ── V5: Digital asset type → business impact ────────────────────
ASSET_BUSINESS_IMPACT = {
    "credential":     0.95,  # passwords, API keys, tokens
    "pii":            0.90,  # personal data
    "source_code":    0.85,  # repositories with code
    "configuration":  0.80,  # config files, .env
    "internal_doc":   0.75,  # internal documents
    "email_address":  0.60,  # harvested emails
    "public_info":    0.35,  # public docs, marketing
    "technology":     0.30,  # tech stack disclosure
    "default":        0.40,
}

# ── V5: Port → service category mapping ─────────────────────────
_PORT_TO_SERVICE_CATEGORY = {
    21: "storage", 22: "admin", 23: "admin", 25: "email",
    53: "dns", 80: "web", 110: "email", 143: "email",
    443: "web", 445: "storage", 993: "email", 995: "email",
    1433: "database", 1521: "database", 3306: "database",
    3389: "admin", 5432: "database", 5900: "admin",
    6379: "database", 8080: "web", 8443: "web",
    9200: "database", 11211: "database", 27017: "database",
}

# ── V5: Observation type → digital asset category ───────────────
_OBS_TYPE_TO_ASSET = {
    "credential_signal_found": "credential",
    "email_found":             "email_address",
    "repo_found":              "source_code",
    "document_found":          "internal_doc",
    "technology_found":        "technology",
    "person_found":            "pii",
}

# ---------------------------------------------------------------------------
# Impact rules: (entity_type, attribute_conditions) -> base_impact_score
# ---------------------------------------------------------------------------
IMPACT_RULES = [
    # Critical findings
    {"id": "rule_rce_vuln",    "category": "infrastructure_exposure",   "type_pattern": "vulnerability_found",
     "sev_min": "critical",    "exposure": 0.95, "impact": 0.95, "description": "Remote code execution vulnerability",
     "recommendation": "Apply vendor patch immediately and restrict network access."},
    {"id": "rule_sqli",        "category": "infrastructure_exposure",   "type_pattern": "vulnerability_found",
     "name_pattern": "sql",    "exposure": 0.85, "impact": 0.90, "description": "SQL injection vulnerability",
     "recommendation": "Use parameterized queries and input validation."},
    {"id": "rule_exposed_cred","category": "credential_exposure", "type_pattern": "credential_signal_found",
     "exposure": 0.95,         "impact": 0.95,  "description": "Exposed credentials",
     "recommendation": "Rotate exposed credentials and audit access logs."},
    # High findings
    {"id": "rule_high_port",   "category": "infrastructure_exposure", "type_pattern": "port_open",
     "port_set": {21, 23, 3389, 5900, 27017, 6379, 9200, 11211},
     "exposure": 0.85,         "impact": 0.75,  "description": "High-risk port exposed",
     "recommendation": "Restrict access via firewall rules or close unnecessary ports."},
    {"id": "rule_secret_leak", "category": "secret_leakage", "type_pattern": "credential_signal_found",
     "exposure": 0.90,         "impact": 0.85,  "description": "Secret or API key leaked in public source",
     "recommendation": "Rotate leaked secret immediately and scan for unauthorized usage."},
    {"id": "rule_cors_misconfig","category": "service_misconfiguration","type_pattern": "header_found",
     "name_pattern": "cors",   "exposure": 0.60, "impact": 0.65, "description": "CORS misconfiguration",
     "recommendation": "Configure CORS to allow only trusted origins."},
    {"id": "rule_admin_panel", "category": "admin_interface", "type_pattern": "endpoint_found",
     "name_pattern": "admin",  "exposure": 0.75, "impact": 0.70, "description": "Admin interface publicly accessible",
     "recommendation": "Restrict admin panel to internal network or VPN."},
    # Medium findings
    {"id": "rule_info_disclose","category": "technology_disclosure","type_pattern": "header_found",
     "name_pattern": "server", "exposure": 0.40, "impact": 0.35, "description": "Server header information disclosure",
     "recommendation": "Remove or obfuscate server version headers."},
    {"id": "rule_http_method", "category": "service_misconfiguration",  "type_pattern": "url_found",
     "method_pattern": "TRACE","exposure": 0.45, "impact": 0.40, "description": "Dangerous HTTP methods enabled",
     "recommendation": "Disable TRACE and other unnecessary HTTP methods."},
    {"id": "rule_email_harvest","category": "email_harvesting", "type_pattern": "email_found",
     "exposure": 0.50,         "impact": 0.45,  "description": "Email address publicly exposed",
     "recommendation": "Review public disclosure of email addresses; consider obfuscation."},
    {"id": "rule_repo_public", "category": "technology_disclosure", "type_pattern": "repo_found",
     "exposure": 0.55,         "impact": 0.50,  "description": "Public code repository found",
     "recommendation": "Audit repository for secrets, internal paths, and sensitive configurations."},
    # Low findings
    {"id": "rule_expired_cert","category": "service_misconfiguration",       "type_pattern": "cert_found",
     "exposure": 0.30,         "impact": 0.25,  "description": "Expired or weak TLS certificate",
     "recommendation": "Renew certificate and enforce strong TLS configuration."},
    {"id": "rule_tech_found",  "category": "technology_disclosure", "type_pattern": "technology_found",
     "exposure": 0.25,         "impact": 0.20,  "description": "Technology/framework version disclosed",
     "recommendation": "Minimize technology fingerprint in public-facing responses."},
]


def run_impact_analysis(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Run impact analysis, produce Findings + ImpactInsights."""
    _log = None
    if config and hasattr(config, "configurable"):
        _log = config.configurable.get("log_callback")

    entities = state.get("entities", [])
    observations = state.get("observations", [])
    relationships = state.get("relationships", [])
    session_id = state["engagement_spec"]["session_id"]
    if _log:
        _log({"type": "phase", "phase": "impact", "status": "started",
              "message": f"Running impact analysis on {len(entities)} entities"})

    # --- Build reverse map: observation_id -> list of entity_ids ---
    obs_to_entities: dict[str, list[str]] = defaultdict(list)
    for ent in entities:
        ent_d = ent if isinstance(ent, dict) else (ent.model_dump() if hasattr(ent, 'model_dump') else vars(ent))
        for obs_id in ent_d.get("observation_ids", []):
            obs_to_entities[obs_id].append(ent_d.get("entity_id", ""))

    centrality = calculate_graph_centrality(entities, relationships)
    new_findings = []

    # Match rules against observations
    for obs in observations:
        for rule in IMPACT_RULES:
            if not _rule_matches(rule, obs):
                continue

            # Resolve actual entity_ids via reverse map (fix: was observation_id)
            entity_ids = obs_to_entities.get(obs.observation_id, [])
            entity_centrality = max(
                (centrality.get(eid, 0.0) for eid in entity_ids), default=0.0
            )

            confidence = obs.confidence

            # V5: Lookup service asset value from port or rule category
            svc_category = _infer_service_category(obs)
            asset_value = SERVICE_ASSET_VALUE.get(svc_category, SERVICE_ASSET_VALUE["default"])

            # V5: Lookup digital asset business impact
            asset_type = _OBS_TYPE_TO_ASSET.get(obs.type, "default")
            biz_impact = ASSET_BUSINESS_IMPACT.get(asset_type, ASSET_BUSINESS_IMPACT["default"])

            # Use the higher of rule-defined impact and table-driven impact
            exposure = rule["exposure"]
            imp = max(rule["impact"], biz_impact)

            # V5: Credential signal → force very high
            if obs.type == "credential_signal_found":
                imp = max(imp, 0.95)
                exposure = max(exposure, 0.95)

            # V5: Admin/login endpoint → force high attention
            obs_text = ((obs.value or "") + (obs.context or "")).lower()
            if any(kw in obs_text for kw in ("admin", "login", "/wp-admin", "/phpmyadmin", "/manager")):
                imp = max(imp, 0.85)
                exposure = max(exposure, 0.80)

            cent = entity_centrality
            priority = _calculate_priority(exposure, imp, confidence, cent)
            risk = _priority_to_risk(priority)

            # V5: Build clear reasoning
            reason_parts = _build_impact_reasons(
                rule, obs, svc_category, asset_value, asset_type, biz_impact,
                exposure, imp, confidence, cent, priority
            )

            finding = Finding(
                session_id=session_id,
                title=rule["description"],
                category=rule["category"],
                risk_level=risk,
                description=_build_description(rule, obs),
                impact_category=rule["category"],
                impact_items=[obs.value],
                impact_note="; ".join(reason_parts),
                entity_ids=entity_ids,
                observation_ids=[obs.observation_id],
                evidence_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                confidence_score=confidence,
                exposure_score=exposure,
                business_impact_score=imp,
                graph_centrality_score=cent,
                priority_score=priority,
                recommendation=rule.get("recommendation", ""),
            )
            new_findings.append(finding)

    # Deduplicate findings by (category+title, primary affected asset)
    seen = {}
    for f in new_findings:
        key = f"{f.category}:{f.title}:{f.impact_items[0] if f.impact_items else ''}"
        if key not in seen or f.priority_score > seen[key].priority_score:
            seen[key] = f

    state["findings"] = state.get("findings", []) + list(seen.values())

    # ---- Build ImpactInsight per entity ----
    entity_insights: dict[str, ImpactInsight] = {}
    # Also build a map of entity_id -> entity object for metadata
    ent_map = {}
    for ent in entities:
        ent_d = ent if isinstance(ent, dict) else (ent.model_dump() if hasattr(ent, 'model_dump') else vars(ent))
        ent_map[ent_d.get("entity_id", "")] = ent_d

    for f in seen.values():
        for eid in (f.entity_ids or []):
            if eid not in entity_insights:
                ent_info = ent_map.get(eid, {})
                entity_insights[eid] = ImpactInsight(
                    entity_id=eid,
                    impact_category=f.impact_category,
                    summary=f"Impact on {ent_info.get('type', 'unknown')} "
                            f"'{ent_info.get('canonical_value', eid)}'",
                    suggested_action=f.recommendation,
                )
            ins = entity_insights[eid]
            ins.exposure_score = max(ins.exposure_score, f.exposure_score or 0)
            ins.impact_score = max(ins.impact_score, f.business_impact_score or 0)
            ins.confidence_score = max(ins.confidence_score, f.confidence_score or 0)
            ins.reasons.append(f.title)
            ins.evidence_refs.extend(f.evidence_refs or [])
            # Upgrade suggested action to match highest-priority finding
            if f.recommendation and f.priority_score > ins.priority_score:
                ins.suggested_action = f.recommendation
                ins.impact_category = f.impact_category

    for ins in entity_insights.values():
        cent_val = centrality.get(ins.entity_id, 0.0)
        cent_mult = 1.0 + cent_val  # centrality multiplier: 1.0 .. 2.0
        ins.priority_score = round(
            ins.exposure_score * ins.impact_score * ins.confidence_score * cent_mult * 10, 2
        )
        ins.priority_score = min(ins.priority_score, 10.0)
        ins.evidence_refs = list(set(ins.evidence_refs))
        # V5: Clear reasoning summary
        reason_str = "; ".join(ins.reasons[:5]) if ins.reasons else "no specific findings"
        ins.summary = (
            f"Impact on {ent_map.get(ins.entity_id, {}).get('type', 'unknown')} "
            f"'{ent_map.get(ins.entity_id, {}).get('canonical_value', ins.entity_id)}': "
            f"{len(ins.reasons)} finding(s), priority {ins.priority_score} — "
            f"scored because: {reason_str}"
        )

    state["impact_insights"] = state.get("impact_insights", []) + list(entity_insights.values())

    logger.info("[ImpactModel] +%d findings (after dedup=%d raw), %d impact insights",
                len(seen), len(new_findings), len(entity_insights))

    state.setdefault("phase_log", []).append({
        "phase": "impact",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"+{len(seen)} findings, {len(entity_insights)} impact insights"
    })
    if _log:
        _log({"type": "phase", "phase": "impact", "status": "done",
              "findings": len(seen), "impact_insights": len(entity_insights)})
    return state


def calculate_graph_centrality(entities: list, relationships: list) -> dict:
    """
    Simple degree centrality: normalized count of relationships per entity.
    Returns {entity_id: centrality_score}
    """
    degree: dict = defaultdict(int)
    for rel in relationships:
        rel_d = rel if isinstance(rel, dict) else (rel.model_dump() if hasattr(rel, 'model_dump') else vars(rel))
        degree[rel_d.get("from_entity_id", rel_d.get("source_entity_id", ""))] += 1
        degree[rel_d.get("to_entity_id", rel_d.get("target_entity_id", ""))] += 1

    if not degree:
        return {}

    max_degree = max(degree.values(), default=1)
    return {eid: round(d / max_degree, 4) for eid, d in degree.items()}


def _rule_matches(rule: dict, obs) -> bool:
    """Check if an observation matches a rule's conditions."""
    if obs.type != rule.get("type_pattern", ""):
        return False

    if "name_pattern" in rule:
        pattern = rule["name_pattern"].lower()
        obs_context = (obs.context or "").lower() + (obs.value or "").lower()
        if pattern not in obs_context:
            return False

    if "port_set" in rule and obs.attributes:
        port = obs.attributes.get("port")
        if port not in rule["port_set"]:
            return False

    if "sev_min" in rule and obs.attributes:
        sev = obs.attributes.get("severity", "").lower()
        sev_order = ["info", "low", "medium", "high", "critical"]
        min_sev = rule["sev_min"].lower()
        if sev_order.index(sev) < sev_order.index(min_sev) if sev in sev_order else True:
            return False

    return True


def _calculate_priority(exposure: float, impact: float,
                         confidence: float, centrality: float) -> float:
    """
    Priority formula (Word spec):
    priority = exposure * impact * confidence * centrality_multiplier * 10
    centrality_multiplier: 1.0 (isolated) .. 2.0 (most connected)
    """
    cent_mult = 1.0 + centrality  # 0..1 → multiplier 1..2
    score = exposure * impact * confidence * cent_mult * 10
    return round(min(score, 10.0), 2)


def _priority_to_risk(priority: float) -> str:
    if priority >= 8.0:
        return "critical"
    if priority >= 5.5:
        return "high"
    if priority >= 3.0:
        return "medium"
    if priority >= 1.0:
        return "low"
    return "info"


def _build_description(rule: dict, obs) -> str:
    context = obs.context or ""
    return f"{rule['description']}. Observed: {obs.value}. {context}".strip()


# ── V5 helpers ──────────────────────────────────────────────────

def _infer_service_category(obs) -> str:
    """Infer service category from observation port or context."""
    port = (obs.attributes or {}).get("port")
    if port and port in _PORT_TO_SERVICE_CATEGORY:
        return _PORT_TO_SERVICE_CATEGORY[port]

    obs_text = ((obs.value or "") + (obs.context or "")).lower()
    if any(kw in obs_text for kw in ("admin", "login", "management", "console", "dashboard")):
        return "admin"
    if any(kw in obs_text for kw in ("mysql", "postgres", "mongo", "redis", "elastic", "database")):
        return "database"
    if any(kw in obs_text for kw in ("api", "graphql", "rest")):
        return "api"
    if any(kw in obs_text for kw in ("smtp", "imap", "mail")):
        return "email"
    if any(kw in obs_text for kw in ("s3", "ftp", "storage", "bucket")):
        return "storage"
    return "default"


def _build_impact_reasons(rule, obs, svc_category, asset_value,
                          asset_type, biz_impact,
                          exposure, impact, confidence, centrality,
                          priority) -> list:
    """V5: Build clear, human-readable impact reasoning list."""
    reasons = []

    # What was found
    reasons.append(f"Matched rule '{rule['id']}': {rule['description']}")

    # Service context
    if svc_category != "default":
        reasons.append(f"Service category '{svc_category}' → asset value {asset_value:.2f}")

    # Asset type context
    if asset_type != "default":
        reasons.append(f"Digital asset '{asset_type}' → business impact {biz_impact:.2f}")

    # Special flags
    if obs.type == "credential_signal_found":
        reasons.append("Credential exposure detected → VERY HIGH risk")
    obs_text = ((obs.value or "") + (obs.context or "")).lower()
    if any(kw in obs_text for kw in ("admin", "login", "/wp-admin", "/phpmyadmin")):
        reasons.append("Admin/login interface exposed → HIGH attention")

    # Scoring breakdown
    reasons.append(
        f"Scores: exposure={exposure:.2f}, impact={impact:.2f}, "
        f"confidence={confidence:.2f}, centrality={centrality:.2f} → priority={priority:.2f}"
    )

    return reasons
