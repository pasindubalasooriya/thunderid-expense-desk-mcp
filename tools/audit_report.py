"""Render audit.jsonl as a table you can read.

    uv run python tools/audit_report.py
    uv run python tools/audit_report.py --deny-only
    uv run python tools/audit_report.py --layer rule
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import audit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layer", choices=["scope", "authzen", "rule"])
    parser.add_argument("--deny-only", action="store_true")
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args()

    rows = audit.read_all()
    if args.layer:
        rows = [r for r in rows if r.get("layer") == args.layer]
    if args.deny_only:
        rows = [r for r in rows if r.get("decision") == "deny"]

    if not rows:
        print(f"No audit entries in {audit.AUDIT_PATH}.")
        return 0

    rows = rows[-args.limit :]

    head = f"{'TIME (UTC)':21} {'WHO':20} {'TOOL':17} {'DECIDED BY':11} {'':5} REASON"
    print(head)
    print("-" * len(head))

    for r in rows:
        who = r.get("user") or r.get("sub") or "-"
        if r.get("act_sub"):
            # RFC 8693: an agent acting for a user. Both identities, one line.
            who = f"{who} for {r['act_sub']}"
        mark = "ALLOW" if r.get("decision") == "allow" else "DENY"
        reason = (r.get("reason") or "")[:72]
        print(
            f"{r.get('ts', '')[:19]:21} {who[:20]:20} {r.get('tool', '')[:17]:17} "
            f"{r.get('layer', ''):11} {mark:5} {reason}"
        )

    allows = sum(1 for r in rows if r.get("decision") == "allow")
    print()
    print(f"{len(rows)} decisions: {allows} allow, {len(rows) - allows} deny")
    by_layer = {}
    for r in rows:
        key = (r.get("layer"), r.get("decision"))
        by_layer[key] = by_layer.get(key, 0) + 1
    for layer in ("scope", "authzen", "rule"):
        a = by_layer.get((layer, "allow"), 0)
        d = by_layer.get((layer, "deny"), 0)
        if a or d:
            print(f"  {layer:8} {a} allow, {d} deny")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
