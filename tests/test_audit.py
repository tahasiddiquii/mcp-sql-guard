from mcp_sql_guard.audit import AuditLog


def test_chain_verifies():
    log = AuditLog()
    log.append("analyst", "allow", "SELECT 1", ["ok"], 1, [])
    log.append("analyst", "deny", "DROP TABLE x", ["blocked"], 0, [])
    assert log.verify()


def test_tampering_breaks_chain():
    log = AuditLog()
    log.append("analyst", "allow", "SELECT 1", ["ok"], 1, [])
    log.append("analyst", "allow", "SELECT 2", ["ok"], 1, [])
    log.entries[0].action = "deny"
    assert not log.verify()
