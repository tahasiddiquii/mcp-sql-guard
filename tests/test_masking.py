from mcp_sql_guard.masking import MASK, mask_rows


def test_masks_selected_columns_only():
    columns = ["name", "email"]
    rows = [("Dana", "dana@example.com"), ("Sam", "sam@example.com")]
    out = mask_rows(columns, rows, {"email"})
    assert out == [["Dana", MASK], ["Sam", MASK]]


def test_no_mask_columns_is_identity():
    columns = ["name", "region"]
    rows = [("Dana", "US")]
    assert mask_rows(columns, rows, set()) == [["Dana", "US"]]
