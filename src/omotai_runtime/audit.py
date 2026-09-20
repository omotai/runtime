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
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        self.prev = json.loads(lines[-1])["hash"] if lines else GENESIS

    def log(self, **event) -> None:
        record = {"ts": round(time.time(), 3), **event}
        record["prev"] = self.prev
        record["hash"] = _digest(self.prev, {k: v for k, v in record.items() if k != "prev"})
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.prev = record["hash"]


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
