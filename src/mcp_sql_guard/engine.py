"""Query execution against the demo warehouse, with a hard row cap."""

from __future__ import annotations

from dataclasses import dataclass

import duckdb

from mcp_sql_guard.config import GovernancePolicy
from mcp_sql_guard.masking import mask_rows


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[list]
    truncated: bool


def execute(
    con: duckdb.DuckDBPyConnection,
    sanitized_sql: str,
    mask_columns: set[str],
    policy: GovernancePolicy,
) -> QueryResult:
    cur = con.execute(sanitized_sql)
    columns = [d[0] for d in cur.description]
    raw = cur.fetchall()
    truncated = len(raw) > policy.max_rows
    raw = raw[: policy.max_rows]
    rows = mask_rows(columns, raw, mask_columns)
    return QueryResult(columns=columns, rows=rows, truncated=truncated)
