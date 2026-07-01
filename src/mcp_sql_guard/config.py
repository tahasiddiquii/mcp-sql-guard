"""Governance policy: what may be queried, by whom, and within what limits."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# DuckDB and file-access functions that must never appear in a governed query.
DEFAULT_FORBIDDEN = [
    "read_csv", "read_parquet", "read_json", "read_text", "read_blob",
    "glob", "copy", "attach", "detach", "install", "load", "pragma",
    "system", "getenv", "import", "export",
]


class GovernancePolicy(BaseModel):
    allowed_tables: list[str] = Field(default_factory=list)
    pii_columns: list[str] = Field(default_factory=list)
    """PII columns as `table.column`; masked unless the role has `read_pii`."""

    role_capabilities: dict[str, list[str]] = Field(default_factory=dict)
    max_limit: int = 100
    """LIMIT injected when a query has none."""

    max_rows: int = 1000
    """Hard cap; a larger LIMIT is reduced to this."""

    forbidden_functions: list[str] = Field(default_factory=lambda: list(DEFAULT_FORBIDDEN))

    def can_read_pii(self, role: str) -> bool:
        return "read_pii" in self.role_capabilities.get(role, [])

    def pii_set(self) -> set[str]:
        return {c.lower() for c in self.pii_columns}


def load_policy(source: str | Path | dict[str, Any]) -> GovernancePolicy:
    if isinstance(source, dict):
        return GovernancePolicy.model_validate(source)
    text = str(source)
    candidate = Path(text)
    if isinstance(source, Path) or candidate.exists():
        return GovernancePolicy.model_validate(yaml.safe_load(candidate.read_text()))
    return GovernancePolicy.model_validate(yaml.safe_load(text))


def default_policy() -> GovernancePolicy:
    return GovernancePolicy(
        allowed_tables=["customers", "orders", "products"],
        pii_columns=["customers.email", "customers.phone"],
        role_capabilities={"analyst": [], "privacy_officer": ["read_pii"]},
        max_limit=100,
        max_rows=1000,
    )
