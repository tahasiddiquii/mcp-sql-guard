from mcp_sql_guard.evals import load_cases, render_markdown, run_eval


def test_gate_passes():
    report = run_eval()
    assert report.total >= 15
    assert report.unsafe_executed == 0
    assert report.pii_exposed == 0
    assert report.privileged_pii_visible
    assert report.execution_accuracy >= 0.90
    assert report.false_block_rate <= 0.10
    assert report.passed


def test_every_case_has_a_verdict():
    report = run_eval()
    ids = {c["id"] for c in load_cases()}
    assert set(report.per_case) == ids


def test_markdown_mentions_gate():
    md = render_markdown(run_eval())
    assert "gate: PASS" in md
    assert "unsafe_executed" in md
