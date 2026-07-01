"""Evaluation harness and CI gate for the governed SQL server.

Cases fall into four kinds: `allow` (benign, executes), `mask` (executes with PII
hidden for a non-privileged role), `reveal` (a privileged role legitimately sees
PII), and `block` (must be rejected). The gate encodes the governance contract:
no unsafe statement ever executes, and no raw PII ever reaches a role that lacks
`read_pii`. The numbers are produced by replaying every case through the guard.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mcp_sql_guard.config import default_policy
from mcp_sql_guard.guard import SqlGuard

MIN_EXECUTION_ACCURACY = 0.90
MAX_FALSE_BLOCK_RATE = 0.10

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_CANDIDATE = re.compile(r"[+\d][\d\-()\s]{7,}\d")


def cases_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "eval_cases.jsonl"


def load_cases(path: Path | None = None) -> list[dict]:
    src = path or cases_path()
    return [json.loads(line) for line in src.read_text().splitlines() if line.strip()]


def _looks_like_phone(text: str) -> bool:
    # Require 10 to 15 digits so ISO dates (8 digits) and small ids are not flagged.
    for m in _PHONE_CANDIDATE.finditer(text):
        digits = sum(c.isdigit() for c in m.group())
        if 10 <= digits <= 15:
            return True
    return False


def _has_pii(rows: list[list]) -> bool:
    for row in rows:
        for cell in row:
            text = str(cell)
            if _EMAIL.search(text) or _looks_like_phone(text):
                return True
    return False


@dataclass
class EvalReport:
    total: int
    unsafe_executed: int
    pii_exposed: int
    exec_cases: int
    exec_ok: int
    block_cases: int
    false_blocks: int
    privileged_pii_visible: bool
    per_case: dict[str, str] = field(default_factory=dict)

    @property
    def execution_accuracy(self) -> float:
        return 1.0 if self.exec_cases == 0 else self.exec_ok / self.exec_cases

    @property
    def false_block_rate(self) -> float:
        return 0.0 if self.exec_cases == 0 else self.false_blocks / self.exec_cases

    @property
    def passed(self) -> bool:
        return (
            self.unsafe_executed == 0
            and self.pii_exposed == 0
            and self.privileged_pii_visible
            and self.execution_accuracy >= MIN_EXECUTION_ACCURACY
            and self.false_block_rate <= MAX_FALSE_BLOCK_RATE
        )

    def as_dict(self) -> dict:
        d = asdict(self)
        d["execution_accuracy"] = round(self.execution_accuracy, 3)
        d["false_block_rate"] = round(self.false_block_rate, 3)
        d["passed"] = self.passed
        return d


def run_eval(cases: list[dict] | None = None) -> EvalReport:
    cases = cases if cases is not None else load_cases()
    guard = SqlGuard(default_policy())

    unsafe = pii_exposed = exec_cases = exec_ok = block_cases = false_blocks = 0
    privileged_pii_visible = False
    per_case: dict[str, str] = {}

    for case in cases:
        expect = case["expect"]
        out = guard.run(case["role"], case["sql"])
        verdict = "ok"

        if expect == "block":
            block_cases += 1
            if out.allowed:
                unsafe += 1
                verdict = "UNSAFE: a statement that must be blocked executed"
        else:
            exec_cases += 1
            if out.allowed:
                exec_ok += 1
            else:
                false_blocks += 1
                verdict = "FALSE BLOCK: benign query rejected"

            if expect in {"allow", "mask"} and _has_pii(out.rows):
                pii_exposed += 1
                verdict = "LEAK: raw PII reached a non-privileged role"
            if expect == "reveal" and out.allowed and _has_pii(out.rows):
                privileged_pii_visible = True

        per_case[case["id"]] = verdict

    return EvalReport(
        total=len(cases),
        unsafe_executed=unsafe,
        pii_exposed=pii_exposed,
        exec_cases=exec_cases,
        exec_ok=exec_ok,
        block_cases=block_cases,
        false_blocks=false_blocks,
        privileged_pii_visible=privileged_pii_visible,
        per_case=per_case,
    )


def render_markdown(report: EvalReport) -> str:
    d = report.as_dict()
    lines = [
        "# SQL governance report",
        "",
        f"Replayed {report.total} cases through the guard over the demo warehouse.",
        "",
        "| metric | value | gate |",
        "| --- | --- | --- |",
        f"| **unsafe_executed** | **{d['unsafe_executed']}** | = 0 |",
        f"| **pii_exposed** | **{d['pii_exposed']}** | = 0 |",
        f"| privileged_pii_visible | {d['privileged_pii_visible']} | true |",
        f"| execution_accuracy | {d['execution_accuracy']} | >= {MIN_EXECUTION_ACCURACY} |",
        f"| false_block_rate | {d['false_block_rate']} | <= {MAX_FALSE_BLOCK_RATE} |",
        "",
        f"**gate: {'PASS' if report.passed else 'FAIL'}**",
        "",
        "## Per-case verdicts",
        "",
    ]
    lines += [f"- `{cid}`: {verdict}" for cid, verdict in report.per_case.items()]
    return "\n".join(lines) + "\n"
