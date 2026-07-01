"""The guard: the single path a query takes from text to governed result."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_sql_guard import validator
from mcp_sql_guard.audit import AuditLog
from mcp_sql_guard.config import GovernancePolicy, default_policy
from mcp_sql_guard.engine import execute
from mcp_sql_guard.schema import build_warehouse


@dataclass
class GuardOutcome:
    allowed: bool
    columns: list[str] = field(default_factory=list)
    rows: list[list] = field(default_factory=list)
    sanitized_sql: str = ""
    reasons: list[str] = field(default_factory=list)
    masked_columns: list[str] = field(default_factory=list)
    truncated: bool = False


class SqlGuard:
    def __init__(self, policy: GovernancePolicy | None = None, audit: AuditLog | None = None) -> None:
        self.policy = policy or default_policy()
        self.con = build_warehouse()
        self.audit = audit or AuditLog()

    def run(self, role: str, sql: str) -> GuardOutcome:
        decision = validator.validate(sql, self.policy, role)
        if not decision.allow:
            self.audit.append(role, "deny", sql, decision.reasons, 0, [])
            return GuardOutcome(allowed=False, reasons=decision.reasons, sanitized_sql=sql)

        try:
            result = execute(self.con, decision.sanitized_sql, decision.mask_columns, self.policy)
        except Exception as exc:  # noqa: BLE001 - an execution error is a clean denial, not a crash
            reasons = [f"execution error: {exc}"]
            self.audit.append(role, "deny", decision.sanitized_sql, reasons, 0, [])
            return GuardOutcome(allowed=False, reasons=reasons, sanitized_sql=decision.sanitized_sql)

        masked = sorted(decision.mask_columns)
        self.audit.append(role, "allow", decision.sanitized_sql, ["ok"], len(result.rows), masked)
        return GuardOutcome(
            allowed=True,
            columns=result.columns,
            rows=result.rows,
            sanitized_sql=decision.sanitized_sql,
            reasons=["ok"],
            masked_columns=masked,
            truncated=result.truncated,
        )
