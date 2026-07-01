import re

from mcp_sql_guard.config import default_policy
from mcp_sql_guard.guard import SqlGuard

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def guard():
    return SqlGuard(default_policy())


def test_benign_query_executes():
    out = guard().run("analyst", "SELECT name, region FROM customers")
    assert out.allowed
    assert out.columns == ["name", "region"]
    assert len(out.rows) >= 1


def test_analyst_never_sees_raw_pii():
    out = guard().run("analyst", "SELECT name, email FROM customers")
    assert out.allowed
    assert "email" in out.masked_columns
    assert not any(EMAIL.search(str(v)) for row in out.rows for v in row)


def test_star_masks_pii_for_analyst():
    out = guard().run("analyst", "SELECT * FROM customers")
    assert out.allowed
    assert not any(EMAIL.search(str(v)) for row in out.rows for v in row)


def test_privacy_officer_sees_pii():
    out = guard().run("privacy_officer", "SELECT name, email FROM customers")
    assert out.allowed
    assert any(EMAIL.search(str(v)) for row in out.rows for v in row)


def test_write_is_blocked_and_audited():
    g = guard()
    out = g.run("analyst", "DROP TABLE customers")
    assert not out.allowed
    assert g.audit.entries[-1].action == "deny"
    # the table is still intact afterward
    assert g.run("analyst", "SELECT count(*) FROM customers").allowed


def test_audit_chain_holds():
    g = guard()
    g.run("analyst", "SELECT name FROM customers")
    g.run("analyst", "DROP TABLE customers")
    g.run("privacy_officer", "SELECT email FROM customers")
    assert g.audit.verify()
