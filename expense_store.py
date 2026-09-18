"""Expense store: a dict, persisted to a JSON file.

No database, no migrations, no real money. The whole point of this repo is the
authorization story, so the data layer is deliberately trivial.

It does persist across restarts, though, and that is not a detail. An earlier
version held state only in memory, and every server restart silently rolled back
approvals made before it. Watching an assistant try to explain that -- it produced
three confident and wrong theories, because "someone restarted the process" is not
visible from inside the protocol -- was a good lesson about demos: state that
disappears between runs makes every transcript untrustworthy, including the ones
you screenshot.

Delete expenses.json (or set RESET_STORE=true) to start from the seed again.

The seed data is chosen to exercise the layer-3 rules added in Phase 3:
  - EXP-1004 belongs to mike, so he cannot approve it himself.
  - EXP-1005 is $7,500, over the $5,000 approval limit.
  - EXP-1002 is a $200 claim from andrea that mike can legitimately approve.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STORE_PATH = Path(os.environ.get("STORE_PATH", "expenses.json"))

# Seeded expenses, keyed by id.
_EXPENSES: dict[str, dict[str, Any]] = {}

# Simple counter for ids handed out by submit_expense.
_NEXT_ID = 1006


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _seed() -> None:
    global _EXPENSES
    _EXPENSES = {
        e["id"]: e
        for e in [
            {
                "id": "EXP-1001",
                "submitter": "andrea",
                "amount": 84.50,
                "currency": "USD",
                "category": "travel",
                "description": "Taxi to client office",
                "status": "pending",
                "created_at": "2026-09-01T09:12:00+00:00",
                "approved_by": None,
                "refunded_amount": 0.0,
            },
            {
                "id": "EXP-1002",
                "submitter": "andrea",
                "amount": 200.00,
                "currency": "USD",
                "category": "equipment",
                "description": "Mechanical keyboard",
                "status": "pending",
                "created_at": "2026-09-02T14:40:00+00:00",
                "approved_by": None,
                "refunded_amount": 0.0,
            },
            {
                "id": "EXP-1003",
                "submitter": "andrea",
                "amount": 1250.00,
                "currency": "USD",
                "category": "conference",
                "description": "PyCon ticket and hotel",
                "status": "approved",
                "created_at": "2026-08-20T11:05:00+00:00",
                "approved_by": "mike",
                "refunded_amount": 0.0,
            },
            {
                "id": "EXP-1004",
                "submitter": "mike",
                "amount": 430.00,
                "currency": "USD",
                "category": "client-dinner",
                "description": "Dinner with the Acme team",
                "status": "pending",
                "created_at": "2026-09-08T20:15:00+00:00",
                "approved_by": None,
                "refunded_amount": 0.0,
            },
            {
                "id": "EXP-1005",
                "submitter": "andrea",
                "amount": 7500.00,
                "currency": "USD",
                "category": "equipment",
                "description": "Replacement laptops for the design team",
                "status": "pending",
                "created_at": "2026-09-10T08:30:00+00:00",
                "approved_by": None,
                "refunded_amount": 0.0,
            },
        ]
    }


def _save() -> None:
    STORE_PATH.write_text(
        json.dumps({"next_id": _NEXT_ID, "expenses": _EXPENSES}, indent=2),
        encoding="utf-8",
    )


def _load() -> bool:
    """Restore a previous run. Returns False if there is nothing to restore."""
    global _EXPENSES, _NEXT_ID
    if os.environ.get("RESET_STORE", "").lower() == "true" or not STORE_PATH.exists():
        return False
    try:
        data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    _EXPENSES = data["expenses"]
    _NEXT_ID = data.get("next_id", 1006)
    return True


if not _load():
    _seed()
    _save()


def reset() -> None:
    """Restore the seed data. Used between demo runs so screenshots reproduce."""
    global _NEXT_ID
    _seed()
    _NEXT_ID = 1006
    _save()


def list_expenses(
    status: str | None = None, submitter: str | None = None
) -> list[dict[str, Any]]:
    rows = list(_EXPENSES.values())
    if status:
        rows = [e for e in rows if e["status"] == status]
    if submitter:
        rows = [e for e in rows if e["submitter"] == submitter]
    return sorted(rows, key=lambda e: e["id"])


def get_expense(expense_id: str) -> dict[str, Any] | None:
    return _EXPENSES.get(expense_id)


def create_expense(
    submitter: str, amount: float, category: str, description: str, currency: str = "USD"
) -> dict[str, Any]:
    global _NEXT_ID
    expense = {
        "id": f"EXP-{_NEXT_ID}",
        "submitter": submitter,
        "amount": round(float(amount), 2),
        "currency": currency,
        "category": category,
        "description": description,
        "status": "pending",
        "created_at": _now(),
        "approved_by": None,
        "refunded_amount": 0.0,
    }
    _NEXT_ID += 1
    _EXPENSES[expense["id"]] = expense
    _save()
    return expense


def mark_approved(expense_id: str, approver: str) -> dict[str, Any]:
    expense = _EXPENSES[expense_id]
    expense["status"] = "approved"
    expense["approved_by"] = approver
    expense["approved_at"] = _now()
    _save()
    return expense


def add_refund(expense_id: str, amount: float, reason: str) -> dict[str, Any]:
    expense = _EXPENSES[expense_id]
    expense["refunded_amount"] = round(expense["refunded_amount"] + float(amount), 2)
    expense["status"] = "refunded"
    expense["refund_reason"] = reason
    expense["refunded_at"] = _now()
    _save()
    return expense
