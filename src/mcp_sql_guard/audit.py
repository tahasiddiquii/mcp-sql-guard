"""A tamper-evident, append-only audit log of every query decision.

Each entry hashes the previous one, so any edit or removal of a past record is
detectable. Auditors care about exactly this property for a data-access path.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

GENESIS = "0" * 64


@dataclass
class AuditEntry:
    role: str
    action: str  # "allow" | "deny"
    sql: str
    reasons: list[str]
    row_count: int
    masked_columns: list[str]
    ts: float = field(default_factory=time.time)
    prev_hash: str = GENESIS
    entry_hash: str = ""

    def digest(self) -> str:
        payload = {
            "role": self.role,
            "action": self.action,
            "sql": self.sql,
            "reasons": self.reasons,
            "row_count": self.row_count,
            "masked_columns": self.masked_columns,
            "ts": round(self.ts, 6),
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def append(self, role: str, action: str, sql: str, reasons: list[str], row_count: int, masked: list[str]) -> AuditEntry:
        prev = self.entries[-1].entry_hash if self.entries else GENESIS
        entry = AuditEntry(
            role=role, action=action, sql=sql, reasons=reasons,
            row_count=row_count, masked_columns=masked, prev_hash=prev,
        )
        entry.entry_hash = entry.digest()
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = GENESIS
        for entry in self.entries:
            if entry.prev_hash != prev or entry.entry_hash != entry.digest():
                return False
            prev = entry.entry_hash
        return True

    def __len__(self) -> int:
        return len(self.entries)
