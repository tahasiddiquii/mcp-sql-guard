from mcp_sql_guard.config import default_policy
from mcp_sql_guard.validator import validate


def policy():
    return default_policy()


def test_select_is_allowed_and_limited():
    d = validate("SELECT name FROM customers", policy(), "analyst")
    assert d.allow
    assert "LIMIT" in d.sanitized_sql.upper()


def test_existing_limit_is_capped():
    d = validate("SELECT name FROM customers LIMIT 999999", policy(), "analyst")
    assert d.allow
    assert "100000" not in d.sanitized_sql  # capped, not the original huge value


def test_drop_is_blocked():
    assert not validate("DROP TABLE customers", policy(), "analyst").allow


def test_multi_statement_is_blocked():
    assert not validate("SELECT * FROM customers; DROP TABLE customers", policy(), "analyst").allow


def test_insert_and_update_blocked():
    assert not validate("INSERT INTO customers VALUES (9,'a','b','c','US','x')", policy(), "analyst").allow
    assert not validate("UPDATE customers SET email='x' WHERE id=1", policy(), "analyst").allow


def test_unknown_table_blocked():
    assert not validate("SELECT secret FROM secret_table", policy(), "analyst").allow


def test_file_functions_blocked():
    assert not validate("SELECT * FROM read_csv('/etc/passwd')", policy(), "analyst").allow
    assert not validate("COPY customers TO '/tmp/x.csv'", policy(), "analyst").allow


def test_union_to_metadata_blocked():
    assert not validate("SELECT name FROM customers UNION SELECT sql FROM sqlite_master", policy(), "analyst").allow


def test_mask_plan_covers_alias_and_star():
    assert validate("SELECT email AS contact FROM customers", policy(), "analyst").mask_columns == {"contact"}
    assert {"email", "phone"} <= validate("SELECT * FROM customers", policy(), "analyst").mask_columns


def test_privileged_role_has_no_mask():
    d = validate("SELECT name, email FROM customers", policy(), "privacy_officer")
    assert d.allow
    assert d.mask_columns == set()


def test_cte_reference_is_not_a_table_violation():
    d = validate("WITH c AS (SELECT name FROM customers) SELECT name FROM c", policy(), "analyst")
    assert d.allow
