from pydantic import BaseModel, Field
from typing import Any, Optional
from datetime import datetime
import uuid


class RawEvent(BaseModel):
    """
    Tầng 1: Append-only raw output từ collector.
    KHÔNG BAO GIỜ sửa sau khi tạo.
    """
    event_id: str = Field(default_factory=lambda: f"raw_{uuid.uuid4().hex[:12]}")
    session_id: str
    lead_id: str                        # lead nào trigger collector này
    collector: str                      # tên collector (whois, crt_sh, nmap...)
    tool_version: Optional[str] = None

    # What/Where/How framework
    what: str                           # loại thông tin tìm được
    where: str                          # nguồn (crt.sh, shodan, nmap...)
    how: str                            # method (API call, subprocess, HTTP GET...)

    # Dữ liệu thô
    query: str                          # query/target đã gửi
    raw_response_path: str              # path đến file raw output
    raw_response_size: int = 0
    checksum: Optional[str] = None      # MD5/SHA256 của raw file

    # Metadata
    success: bool
    error_message: Optional[str] = None
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    scope_status: str = "in_scope"

    # Extracted summary (không phải raw, nhưng structured extract)
    extracted_count: int = 0            # số items extract được
    new_leads_count: int = 0           # số leads mới tạo ra

    class Config:
        frozen = True  # immutable sau khi tạo
