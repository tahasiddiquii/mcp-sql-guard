from mcp_sql_guard.cli import main


def test_demo_runs(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "SQL guard demo" in out
    assert "audit chain verified" in out


def test_schema_marks_pii(capsys):
    assert main(["schema"]) == 0
    assert "pii" in capsys.readouterr().out


def test_query_blocks_ddl(capsys):
    assert main(["query", "DROP TABLE customers", "--role", "analyst"]) == 0
    assert "BLOCKED" in capsys.readouterr().out


def test_eval_passes_and_writes(tmp_path):
    report = tmp_path / "r.md"
    assert main(["eval", "--report", str(report)]) == 0
    assert "gate: PASS" in report.read_text()
