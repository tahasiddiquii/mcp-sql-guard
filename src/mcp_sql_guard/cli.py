"""Command line interface: demo, query, eval, schema, serve."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mcp_sql_guard.config import default_policy
from mcp_sql_guard.evals import render_markdown, run_eval
from mcp_sql_guard.guard import SqlGuard
from mcp_sql_guard.schema import TABLE_COLUMNS

console = Console()

_DEMO = [
    ("analyst", "SELECT name, region FROM customers", "benign read"),
    ("analyst", "SELECT name, email FROM customers", "PII masked for analyst"),
    ("privacy_officer", "SELECT name, email FROM customers", "PII visible to privacy officer"),
    ("analyst", "DROP TABLE customers", "write blocked"),
    ("analyst", "SELECT * FROM read_csv('/etc/passwd')", "file access blocked"),
    ("analyst", "SELECT name FROM customers; DROP TABLE customers", "multi-statement blocked"),
]


def cmd_demo(args: argparse.Namespace) -> int:
    guard = SqlGuard(default_policy())
    table = Table(title="SQL guard demo", show_lines=True)
    table.add_column("role")
    table.add_column("scenario")
    table.add_column("verdict")
    table.add_column("result", overflow="fold")
    for role, sql, scenario in _DEMO:
        out = guard.run(role, sql)
        if out.allowed:
            preview = "; ".join(", ".join(str(v) for v in row) for row in out.rows[:2])
            verdict = "allowed" + (f" (masked {', '.join(out.masked_columns)})" if out.masked_columns else "")
        else:
            preview = "; ".join(out.reasons)
            verdict = "blocked"
        table.add_row(role, scenario, verdict, escape(preview[:90]))
    console.print(table)
    console.print(f"audit chain verified: {guard.audit.verify()} ({len(guard.audit)} entries)")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    out = SqlGuard(default_policy()).run(args.role, args.sql)
    if not out.allowed:
        console.print(f"[bold red]BLOCKED[/bold red]: {escape('; '.join(out.reasons))}")
        return 0
    table = Table(title=f"result (role={args.role})")
    for c in out.columns:
        table.add_column(c)
    for row in out.rows[:50]:
        table.add_row(*[escape(str(v)) for v in row])
    console.print(table)
    if out.masked_columns:
        console.print(f"masked columns: {', '.join(out.masked_columns)}")
    console.print(f"sanitized: {escape(out.sanitized_sql)}")
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    pol = default_policy()
    pii = pol.pii_set()
    table = Table(title="Queryable schema")
    table.add_column("table")
    table.add_column("columns")
    for t in pol.allowed_tables:
        cols = [f"{c}{' [pii]' if f'{t}.{c}'.lower() in pii else ''}" for c in TABLE_COLUMNS.get(t, [])]
        table.add_row(t, escape(", ".join(cols)))
    console.print(table)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    report = run_eval()
    d = report.as_dict()
    table = Table(title="Governance gate")
    table.add_column("metric")
    table.add_column("value")
    table.add_column("gate")
    table.add_row("unsafe_executed", str(d["unsafe_executed"]), "= 0")
    table.add_row("pii_exposed", str(d["pii_exposed"]), "= 0")
    table.add_row("privileged_pii_visible", str(d["privileged_pii_visible"]), "true")
    table.add_row("execution_accuracy", str(d["execution_accuracy"]), ">= 0.90")
    table.add_row("false_block_rate", str(d["false_block_rate"]), "<= 0.10")
    console.print(table)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(render_markdown(report))
        console.print(f"wrote {args.report}")
    if report.passed:
        console.print("[bold green]gate: PASS[/bold green]")
        return 0
    console.print("[bold red]gate: FAIL[/bold red]")
    return 1


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        from mcp_sql_guard.server import build_server
    except ImportError:
        console.print("install the transport first: pip install '.[mcp]'")
        return 1
    build_server(role=args.role).run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sqlguard", description="Governed read-only SQL server for MCP.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="narrated benign, masked, and blocked queries")
    sub.add_parser("schema", help="show the queryable schema with PII marked")

    p_query = sub.add_parser("query", help="run one governed query")
    p_query.add_argument("sql")
    p_query.add_argument("--role", default="analyst")

    p_eval = sub.add_parser("eval", help="run the governance gate")
    p_eval.add_argument("--report", default="reports/governance_report_example.md")

    p_serve = sub.add_parser("serve", help="run the live MCP server over stdio")
    p_serve.add_argument("--role", default="analyst")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "demo": cmd_demo,
        "schema": cmd_schema,
        "query": cmd_query,
        "eval": cmd_eval,
        "serve": cmd_serve,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
