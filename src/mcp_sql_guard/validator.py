"""SQL validation and rewriting with sqlglot.

The validator is the safety core. It parses the statement to an AST and clears it
only if it is a single read-only SELECT over allow-listed tables, with no
forbidden functions. It enforces a LIMIT, and it computes which output columns
must be masked for the caller's role by analyzing the projection (including
`SELECT *` expansion and column aliases), so masking cannot be dodged by renaming.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from mcp_sql_guard.config import GovernancePolicy
from mcp_sql_guard.schema import TABLE_COLUMNS


@dataclass
class Decision:
    allow: bool
    reasons: list[str] = field(default_factory=list)
    sanitized_sql: str = ""
    mask_columns: set[str] = field(default_factory=set)


def validate(sql: str, policy: GovernancePolicy, role: str) -> Decision:
    reasons: list[str] = []

    try:
        statements = [s for s in sqlglot.parse(sql, read="duckdb") if s is not None]
    except Exception as exc:  # noqa: BLE001 - surface a parse failure as a clean denial
        return Decision(False, [f"could not parse SQL: {exc}"])

    if len(statements) != 1:
        return Decision(False, ["only a single statement is allowed"])
    stmt = statements[0]

    if not isinstance(stmt, exp.Select):
        return Decision(False, [f"only read-only SELECT is allowed, got {type(stmt).__name__.upper()}"])

    _check_tables(stmt, policy, reasons)
    _check_forbidden_functions(sql, policy, reasons)
    if reasons:
        return Decision(False, reasons)

    sanitized = _enforce_limit(stmt, policy)
    mask = set() if policy.can_read_pii(role) else _mask_plan(stmt, policy)
    return Decision(True, ["ok"], sanitized_sql=sanitized, mask_columns=mask)


def _cte_names(stmt: exp.Select) -> set[str]:
    return {cte.alias_or_name for cte in stmt.find_all(exp.CTE)}


def _query_tables(stmt: exp.Select) -> list[str]:
    ctes = _cte_names(stmt)
    return [t.name for t in stmt.find_all(exp.Table) if t.name not in ctes]


def _check_tables(stmt: exp.Select, policy: GovernancePolicy, reasons: list[str]) -> None:
    allowed = set(policy.allowed_tables)
    for name in _query_tables(stmt):
        if name not in allowed:
            reasons.append(f"table '{name}' is not allow-listed")


def _check_forbidden_functions(sql: str, policy: GovernancePolicy, reasons: list[str]) -> None:
    low = sql.lower()
    for fn in policy.forbidden_functions:
        if fn in low:
            reasons.append(f"forbidden function or keyword '{fn}'")


def _enforce_limit(stmt: exp.Select, policy: GovernancePolicy) -> str:
    limit = stmt.args.get("limit")
    if limit is None:
        stmt = stmt.limit(policy.max_limit)
    else:
        current = _limit_value(limit)
        if current is None or current > policy.max_rows:
            stmt = stmt.limit(policy.max_rows)
    return stmt.sql(dialect="duckdb")


def _limit_value(limit: exp.Expression) -> int | None:
    try:
        return int(limit.expression.name)
    except (AttributeError, ValueError):
        return None


def _mask_plan(stmt: exp.Select, policy: GovernancePolicy) -> set[str]:
    """Output column names whose values must be masked for a non-privileged role."""
    pii = policy.pii_set()
    tables = _query_tables(stmt)
    mask: set[str] = set()

    for proj in stmt.expressions:
        alias = proj.alias if isinstance(proj, exp.Alias) else None
        target = proj.this if isinstance(proj, exp.Alias) else proj

        if isinstance(target, exp.Column):
            col = target.name
            table = target.table or _resolve_table(col, tables)
            if table and f"{table}.{col}".lower() in pii:
                mask.add(alias or col)
        elif isinstance(target, exp.Star):
            for table in tables:
                for col in TABLE_COLUMNS.get(table, []):
                    if f"{table}.{col}".lower() in pii:
                        mask.add(col)
    return mask


def _resolve_table(column: str, tables: list[str]) -> str | None:
    """For an unqualified column, find the single table that owns it."""
    owners = [t for t in tables if column in TABLE_COLUMNS.get(t, [])]
    return owners[0] if len(owners) == 1 else None
