"""The audit trail: one JSON line per authorization decision.

Every decision lands here, tagged with the layer that made it, so the three layers
finally appear in one place. That matters more than it sounds: during the build, a
layer-3 refusal wrote nothing anywhere, while the decision log happily showed
`ALLOW layer=authzen` for the same call. Anyone reading the authorization logs would
have concluded the approval went through.

Fields, and why each is here:
  ts        when, in UTC
  sub       the token's subject -- ThunderID's identifier for the caller
  user      what this application calls that subject (see authz/principals.py)
  act_sub   the delegating party, when one identity is acting for another
  client_id which client the call came through, distinct from who is calling
  tool      the tool asked for
  decision  allow | deny
  layer     scope | authzen | rule -- which layer decided
  reason    in words, so the line is readable a month later
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("AUDIT_PATH", "audit.jsonl"))
ECHO = os.environ.get("AUDIT_ECHO", "true").lower() != "false"


def record(
    *,
    layer: str,
    decision: str,
    tool: str,
    subject: str | None = None,
    user: str | None = None,
    client_id: str | None = None,
    act_sub: str | None = None,
    reason: str = "",
) -> dict:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sub": subject,
        "user": user,
        "act_sub": act_sub,
        "client_id": client_id,
        "tool": tool,
        "decision": decision,
        "layer": layer,
        "reason": reason,
    }

    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as exc:
        # Never let auditing break a request, but never lose the fact either.
        print(f"[audit] could not write: {exc}", file=sys.stderr, flush=True)

    if ECHO:
        print(
            f"{entry['ts']}  {decision.upper():5}  layer={layer:7}  "
            f"tool={tool:16}  user={user or subject or '-'}  {reason}",
            file=sys.stderr,
            flush=True,
        )

    return entry


def read_all() -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    rows = []
    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows
