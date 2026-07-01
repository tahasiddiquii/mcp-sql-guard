"""The live MCP server, built on FastMCP.

The caller's role comes from `SQLGUARD_ROLE`. The single `run_query` tool routes
every statement through the guard, so the model can only ever run governed,
read-only SQL and only ever sees PII it is entitled to. The `mcp` transport is
imported lazily so the guard and evals stay offline and testable.
"""

from __future__ import annotations

import os

from mcp_sql_guard.config import GovernancePolicy, default_policy
from mcp_sql_guard.guard import SqlGuard
from mcp_sql_guard.schema import TABLE_COLUMNS


def _format(outcome) -> str:
    if not outcome.allowed:
        return "blocked: " + "; ".join(outcome.reasons)
    header = ", ".join(outcome.columns)
    body = "\n".join(", ".join(str(v) for v in row) for row in outcome.rows[:50])
    note = f"\n(masked: {', '.join(outcome.masked_columns)})" if outcome.masked_columns else ""
    return f"{header}\n{body}{note}"


def build_server(role: str | None = None, policy: GovernancePolicy | None = None, guard: SqlGuard | None = None):
    from mcp.server.fastmcp import FastMCP  # lazy: keeps the core dependency-light

    role = role or os.environ.get("SQLGUARD_ROLE", "analyst")
    pol = policy or default_policy()
    gd = guard or SqlGuard(pol)
    server = FastMCP("mcp-sql-guard")

    @server.resource("sqlguard://schema")
    def schema() -> str:
        """The queryable schema, with PII columns marked."""
        pii = pol.pii_set()
        lines = []
        for table in pol.allowed_tables:
            cols = [f"{c}{' [pii]' if f'{table}.{c}'.lower() in pii else ''}" for c in TABLE_COLUMNS.get(table, [])]
            lines.append(f"{table}({', '.join(cols)})")
        return "\n".join(lines)

    @server.tool()
    def run_query(sql: str) -> str:
        """Run a governed, read-only SQL query. PII is masked unless your role permits it."""
        return _format(gd.run(role, sql))

    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
