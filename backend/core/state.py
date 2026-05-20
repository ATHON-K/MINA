"""
MINA State — LangGraph TypedDict shared across all nodes.
Updated to Phase 0→5 evidence-first architecture.
"""
from typing import TypedDict, Optional
from datetime import datetime
from core.schemas import Lead, RawEvent, Observation, Entity, Relationship, Finding, ImpactInsight, IntelEvent


class EngagementSpec(TypedDict):
    """Quy chuẩn hoạt động của một scan session"""
    session_id: str
    target: str                         # target chính
    company_name: str                   # tên tổ chức (dùng cho company intel)
    allowed_scope: list                 # domains/IPs được phép
    blocked_scope: list                 # domains/IPs bị chặn tuyệt đối

    # Recon policy
    active_recon_enabled: bool
    passive_only: bool
    allowed_sources: list               # ["crt_sh", "shodan", "subfinder", ...]
    blocked_sources: list
    agents_enabled: dict                # {"active_recon": true, "karma_v2": false, ...}

    # Budget & limits
    max_depth: int                      # độ sâu tối đa của lead graph
    max_leads: int                      # tổng leads tối đa
    max_active_budget: int              # số lần gọi active tools tối đa
    max_iterations: int                 # vòng lặp director tối đa
    rate_limit_seconds: float           # sleep giữa requests
    time_budget_seconds: int            # tổng thời gian cho phép

    # Scan profile
    profile: str                        # "quick", "balanced", "deep"
    wordlist_profile: str               # "small", "medium", "extended"
    mode: str                           # "breadth_first", "depth_first", "hybrid"

    # V4: unified feature toggles and per-tool options
    features: dict                      # {"subfinder": True, "nuclei": False, ...}
    tool_options: dict                  # {"nmap": {"options": "-sV -sC"}, ...}
    report_detail: str                  # "summary" | "detailed" | "full_inventory"

    # Feature flags (phản ánh đúng .env)
    enable_secret_scanning: bool
    enable_repo_intel: bool
    enable_doc_intel: bool
    enable_endpoint_crawl: bool
    enable_karma_v2: bool

    started_at: str                     # ISO timestamp


class MINAState(TypedDict):
    """LangGraph state — được share qua tất cả nodes"""

    # === PHASE 0 ===
    engagement_spec: EngagementSpec

    # === PHASE 1 ===
    lead_queue: list                    # hàng đợi chính (sorted by priority)
    processed_lead_ids: set             # dedup set
    active_budget_used: int             # đếm active tool calls
    iteration_count: int
    last_yield_iteration: int           # khi nào lần cuối có lead mới

    # Staging cho collectors
    current_lead: Optional[Lead]
    passive_tasks: list
    active_tasks: list

    # === RAW DATA ===
    raw_events: list
    observations: list
    intel_events: list                  # IntelEvent[] — unified tool output

    # === PHASE 2 (Normalize) ===
    entities: list
    entity_index: dict                  # type:canonical_value → entity_id (Phase 2+); entity_id → entity_id (Phase 1)

    # === PHASE 3 (Correlate) ===
    relationships: list
    conflict_queue: list                # observations mâu thuẫn cần review

    # === PHASE 4 (Impact) ===
    findings: list
    impact_insights: list               # ImpactInsight per entity

    # === PHASE 5 (Export) ===
    report: str
    export_paths: dict                  # {"report_md": "...", "report_pdf": "..."}

    # === Metrics ===
    collector_stats: dict               # {collector_name: {runs, success, fails, ...}}
    phase_log: list                     # timeline của các phase
    tool_health_snapshot: dict          # V4: {tool_name: {available: bool, version: str}}

    # === Control ===
    stop_reason: Optional[str]          # lý do dừng
    error_log: list
