"""Value masking for PII output columns."""

from __future__ import annotations

MASK = "***"


def mask_rows(columns: list[str], rows: list[tuple], mask_columns: set[str]) -> list[list]:
    if not mask_columns:
        return [list(r) for r in rows]
    mask_idx = {i for i, c in enumerate(columns) if c in mask_columns}
    masked: list[list] = []
    for row in rows:
        masked.append([MASK if i in mask_idx else v for i, v in enumerate(row)])
    return masked
