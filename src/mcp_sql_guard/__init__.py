"""A governed text-to-SQL gateway for the Model Context Protocol.

The server gives an AI agent read access to a warehouse without the write risk,
injection, or data exposure that raw database access invites. Every statement is
parsed to an abstract syntax tree and cleared only if it is a single read-only,
allow-listed SELECT; a LIMIT is enforced; PII columns are masked unless the
caller's role is entitled to them; and every decision is written to a
tamper-evident audit log.
"""

from mcp_sql_guard.config import GovernancePolicy, default_policy, load_policy
from mcp_sql_guard.guard import GuardOutcome, SqlGuard

__all__ = ["GovernancePolicy", "GuardOutcome", "SqlGuard", "default_policy", "load_policy"]
__version__ = "0.1.0"
