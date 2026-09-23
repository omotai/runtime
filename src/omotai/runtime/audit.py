"""Append-only JSONL audit log with a SHA-256 hash chain. Tampering is detectable, not prevented."""

import hashlib
import json
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((prev + body).encode()).hexdigest()


class Audit:
    def __init__(
        self, 
        path: str | Path, 
        agent_key: str | None = None, 
        session_id: str | None = None
    ):
        self.path = Path(path)
        self.agent_key = agent_key
        self.session_id = session_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        self.prev = json.loads(lines[-1])["hash"] if lines else GENESIS

    def log(self, **event) -> None:
        record = {"ts": round(time.time(), 3), **event}
        record["prev"] = self.prev
        record["hash"] = _digest(self.prev, {k: v for k, v in record.items() if k != "prev"})

        if self.path.exists() and self.path.stat().st_size >= 5 * 1024 * 1024:
            self._rotate()

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            
        self.prev = record["hash"]
        
        # Save to SQLite
        try:
            from omotai.dashboard.db import get_connection
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_logs 
                    (agent_key, session_id, event, tool, url, verdict, rule, request_payload, 
                    response_payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.agent_key,
                        self.session_id,
                        event.get("event"),
                        event.get("tool"),
                        event.get("url"),
                        event.get("verdict"),
                        event.get("rule"),
                        json.dumps(event.get("request")) if "request" in event else None,
                        event.get("response")
                    )
                )
                conn.commit()
        except Exception:  # noqa: S110
            pass

    def _rotate(self):
        for i in range(4, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i}")
            dst = self.path.with_name(f"{self.path.name}.{i + 1}")
            if src.exists():
                src.rename(dst)
        if self.path.exists():
            self.path.rename(self.path.with_name(f"{self.path.name}.1"))


def verify(path: str | Path) -> bool:
    prev = GENESIS
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.pop("prev") != prev:
            return False
        digest = record.pop("hash")
        if _digest(prev, record) != digest:
            return False
        prev = digest
    return True
