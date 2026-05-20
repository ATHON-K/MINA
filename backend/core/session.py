"""
SessionManager — Create, persist, and retrieve scan sessions.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.config import config


class SessionManager:
    """Manage scan session lifecycle and metadata persistence."""

    def __init__(self, sessions_dir: Optional[Path] = None):
        self.sessions_dir = sessions_dir or config.sessions_dir
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def create_session(self, target: str, engagement_spec: dict) -> dict:
        """
        Create a new scan session.
        Returns session metadata dict with session_id populated.
        """
        session_id = f"session_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        session_dir = self.sessions_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "evidence").mkdir(exist_ok=True)

        metadata = {
            "session_id": session_id,
            "target": target,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "created",
            "engagement_spec": {**engagement_spec, "session_id": session_id},
        }

        self._write_metadata(session_id, metadata)
        return metadata

    def get_session(self, session_id: str) -> Optional[dict]:
        """Load session metadata by ID."""
        meta_path = self.sessions_dir / session_id / "metadata.json"
        if not meta_path.exists():
            return None
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def update_status(self, session_id: str, status: str, extra: dict = None):
        """Update session status (running/complete/error)."""
        meta = self.get_session(session_id)
        if not meta:
            return
        meta["status"] = status
        if status == "complete":
            meta["completed_at"] = datetime.now(timezone.utc).isoformat()
        if extra:
            meta.update(extra)
        self._write_metadata(session_id, meta)

    def list_sessions(self, limit: int = 20) -> list:
        """List recent sessions sorted by creation time (newest first)."""
        sessions = []
        for path in sorted(self.sessions_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_dir():
                continue
            meta = self.get_session(path.name)
            if meta:
                sessions.append(meta)
            if len(sessions) >= limit:
                break
        return sessions

    def get_session_dir(self, session_id: str) -> Path:
        return self.sessions_dir / session_id

    def _write_metadata(self, session_id: str, metadata: dict):
        meta_path = self.sessions_dir / session_id / "metadata.json"
        meta_path.write_text(
            json.dumps(metadata, indent=2, default=str), encoding="utf-8"
        )
