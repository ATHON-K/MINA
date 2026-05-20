"""
Evidence Store — nơi lưu trữ và đánh index tất cả bằng chứng thô.
Mọi RawEvent phải có evidence_ref trỏ về đây.
"""
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone


class EvidenceStore:
    def __init__(self, session_dir: Path):
        self.raw_dir = session_dir / "evidence" / "raw"
        self.parsed_dir = session_dir / "evidence" / "parsed"
        self.index_path = session_dir / "evidence" / "index.jsonl"

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def store_raw(self, collector: str, query: str, content,
                  content_type: str = "text/plain") -> str:
        """Lưu raw evidence, return evidence_id"""
        evidence_id = f"ev_{hashlib.md5(f'{collector}_{query}_{datetime.now(timezone.utc)}'.encode()).hexdigest()[:12]}"

        raw_path = self.raw_dir / f"{evidence_id}.raw"
        if isinstance(content, bytes):
            raw_path.write_bytes(content)
        else:
            raw_path.write_text(content, encoding='utf-8')

        checksum = hashlib.sha256(
            content if isinstance(content, bytes) else content.encode()
        ).hexdigest()

        # Append vào index
        entry = {
            "evidence_id": evidence_id,
            "collector": collector,
            "query": query,
            "raw_path": str(raw_path),
            "content_type": content_type,
            "size": len(content),
            "checksum": checksum,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "redacted": False
        }
        with open(self.index_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')

        return evidence_id

    def get_evidence(self, evidence_id: str):
        """Lookup evidence từ index"""
        if not self.index_path.exists():
            return None
        with open(self.index_path) as f:
            for line in f:
                entry = json.loads(line)
                if entry['evidence_id'] == evidence_id:
                    return entry
        return None

    def redact(self, evidence_id: str) -> bool:
        """Đánh dấu evidence cần redact (cho secret scanning)"""
        entries = []
        found = False
        with open(self.index_path) as f:
            for line in f:
                entry = json.loads(line)
                if entry['evidence_id'] == evidence_id:
                    entry['redacted'] = True
                    found = True
                entries.append(entry)
        if found:
            with open(self.index_path, 'w') as f:
                for entry in entries:
                    f.write(json.dumps(entry) + '\n')
        return found
