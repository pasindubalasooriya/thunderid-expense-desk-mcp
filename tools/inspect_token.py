"""Decode an access token and show the claims that decide access.

    uv run python tools/inspect_token.py <token>
    uv run python tools/inspect_token.py --agent          # fetch one first

The signature is shown truncated: this output is meant to be pasted into a blog
post or an issue, and a full JWT is a working credential until it expires.
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

INTERESTING = [
    ("iss", "who issued it"),
    ("aud", "which server it is for -- a token for another server will not work here"),
    ("sub", "who the caller is; stable, and safe to key your user table on"),
    ("sub_type", "user or agent"),
    ("scope", "what it is allowed to do"),
    ("client_id", "which client it came through"),
    ("act", "the delegating party, when one identity acts for another"),
    ("exp", "when it stops being true"),
]


def decode_segment(segment: str) -> dict:
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


def fetch_agent_token() -> str:
    import httpx
    from dotenv import load_dotenv

    load_dotenv()
    issuer = os.environ["THUNDERID_ISSUER"]
    r = httpx.post(
        f"{issuer}/oauth2/token",
        auth=(os.environ["AGENT_CLIENT_ID"], os.environ["AGENT_CLIENT_SECRET"]),
        data={
            "grant_type": "client_credentials",
            "scope": "expenses-read",
            "resource": os.environ["MCP_RESOURCE_ID"],
        },
        verify=os.environ.get("THUNDERID_VERIFY_TLS", "false").lower() == "true",
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("token", nargs="?")
    parser.add_argument("--agent", action="store_true", help="fetch the agent's own token")
    args = parser.parse_args()

    token = fetch_agent_token() if args.agent else args.token
    if not token:
        parser.error("pass a token, or --agent to fetch one")

    header_b64, payload_b64, signature = token.split(".")
    header = decode_segment(header_b64)
    claims = decode_segment(payload_b64)

    print(f"algorithm  {header.get('alg')}   key id  {header.get('kid', '')[:16]}...")
    print(f"type       {header.get('typ')}")
    print()

    width = max(len(k) for k, _ in INTERESTING)
    for key, note in INTERESTING:
        if key in claims:
            value = claims[key]
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            elif key == "exp":
                left = int(value) - int(datetime.now(timezone.utc).timestamp())
                when = datetime.fromtimestamp(int(value), timezone.utc)
                value = (
                    f"{when.isoformat(timespec='seconds')} "
                    f"({left // 60} min from now)"
                )
            print(f"{key:<{width}}  {value}")
            print(f"{'':<{width}}  -> {note}")
    print()

    shown = {k for k, _ in INTERESTING}
    other = {k: v for k, v in claims.items() if k not in shown}
    if other:
        print("other claims:", ", ".join(sorted(other)))
    print(f"signature  {signature[:24]}... (truncated -- this is a live credential)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
