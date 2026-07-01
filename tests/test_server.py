import pytest

pytest.importorskip("mcp")


def test_server_exposes_run_query_tool():
    from mcp_sql_guard.server import build_server

    server = build_server(role="analyst")
    assert server.name == "mcp-sql-guard"
    import anyio

    names = {t.name for t in anyio.run(server.list_tools)}
    assert "run_query" in names


def test_run_query_masks_for_analyst():
    import anyio

    from mcp_sql_guard.config import default_policy
    from mcp_sql_guard.guard import SqlGuard
    from mcp_sql_guard.server import build_server

    server = build_server(role="analyst", guard=SqlGuard(default_policy()))
    result = anyio.run(server.call_tool, "run_query", {"sql": "SELECT name, email FROM customers"})
    text = _text(result)
    assert "@example.com" not in text
    assert "masked" in text


def _text(result) -> str:
    # FastMCP returns (content_list, ...) or a content list depending on version
    content = result[0] if isinstance(result, tuple) else result
    parts = []
    for item in content:
        parts.append(getattr(item, "text", str(item)))
    return "\n".join(parts)
