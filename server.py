"""Expense Desk — an MCP server whose tools have real consequences.

Layer 1 is wired: ThunderID issues access tokens, this server validates them
offline against ThunderID's JWKS, and each tool requires a scope.

Set AUTH_ENABLED=false to run the server wide open, which is the state the blog
opens with (screenshot S01). Everything else stays identical, so the difference
between the two runs is the authorization, not the server.
"""

import os

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier

import audit
import expense_store as store
from authz import rules
from authz.middleware import ScopeMiddleware
from authz.principals import username_for
from authz.scopes import ALL_SCOPES

load_dotenv()

AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() != "false"

THUNDERID_ISSUER = os.environ.get("THUNDERID_ISSUER", "https://localhost:8095")
THUNDERID_JWKS_URI = os.environ.get(
    "THUNDERID_JWKS_URI", f"{THUNDERID_ISSUER}/oauth2/jwks"
)
MCP_RESOURCE_ID = os.environ.get("MCP_RESOURCE_ID", "http://localhost:8000/mcp")
VERIFY_TLS = os.environ.get("THUNDERID_VERIFY_TLS", "false").lower() == "true"

# Stand-in identity, used only when AUTH_ENABLED=false. With auth on, the acting
# user comes from the token's `sub` claim instead.
DEMO_USER = os.environ.get("DEMO_USER", "andrea")


def build_auth() -> RemoteAuthProvider | None:
    """Wire ThunderID as the authorization server for this resource server.

    JWTVerifier checks each token offline against ThunderID's JWKS: signature,
    issuer, expiry, and -- the part worth saying out loud -- the audience. A token
    minted for some other service does not work here, even though it is signed by
    the same ThunderID and is perfectly valid elsewhere. That is what binds this
    token to this server.

    RemoteAuthProvider serves the RFC 9728 protected-resource metadata and the
    401 + WWW-Authenticate challenge that points an unauthenticated client at
    ThunderID, which is how a client discovers where to log in without being
    configured with the answer in advance.
    """
    if not AUTH_ENABLED:
        return None

    # Local ThunderID uses a self-signed certificate. Local dev only -- never
    # ship a client that skips verification.
    http_client = httpx.AsyncClient(verify=VERIFY_TLS)

    verifier = JWTVerifier(
        jwks_uri=THUNDERID_JWKS_URI,
        issuer=THUNDERID_ISSUER,
        audience=MCP_RESOURCE_ID,
        http_client=http_client,
    )

    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[THUNDERID_ISSUER],
        base_url=MCP_RESOURCE_ID.removesuffix("/mcp"),
        resource_name="Expense Desk MCP",
        scopes_supported=ALL_SCOPES,
    )


def _audit_identity() -> dict:
    """Caller details for the audit trail, or a placeholder with auth off."""
    if not AUTH_ENABLED:
        return {"subject": None, "user": DEMO_USER, "client_id": None, "act_sub": None}

    from fastmcp.server.dependencies import get_access_token

    claims = getattr(get_access_token(), "claims", None) or {}
    subject = claims.get("sub")
    act = claims.get("act") or {}
    return {
        "subject": subject,
        "user": username_for(subject),
        "client_id": claims.get("client_id"),
        "act_sub": act.get("sub") if isinstance(act, dict) else None,
    }


def acting_user() -> str:
    """Who is making this call.

    With auth on, this is the `sub` claim of the validated token -- the identity
    ThunderID asserts, which the caller cannot choose for themselves. With auth
    off there is no token, so it falls back to DEMO_USER and anyone can be anyone.
    That gap is the whole point of the opening demo.
    """
    if not AUTH_ENABLED:
        return DEMO_USER

    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    claims = getattr(token, "claims", None) or {}
    subject = claims.get("sub") or getattr(token, "client_id", None)
    # The token says who ThunderID thinks this is; our own user table says what we
    # call them. Expense records are keyed by the latter.
    return username_for(subject)


mcp = FastMCP(
    name="Expense Desk",
    auth=build_auth(),
    instructions=(
        "Tools for triaging a finance team's expense claims. list_expenses and "
        "get_expense are read-only. submit_expense creates a claim. approve_expense "
        "and issue_refund move money and are restricted in later phases."
    ),
)


@mcp.tool
def list_expenses(status: str | None = None, submitter: str | None = None) -> dict:
    """List expense claims, optionally filtered by status or submitter.

    Args:
        status: Only return claims in this status (pending, approved, refunded).
        submitter: Only return claims submitted by this username.
    """
    rows = store.list_expenses(status=status, submitter=submitter)
    return {"count": len(rows), "expenses": rows}


@mcp.tool
def get_expense(expense_id: str) -> dict:
    """Fetch one expense claim with full detail.

    Args:
        expense_id: The claim id, for example EXP-1001.
    """
    expense = store.get_expense(expense_id)
    if expense is None:
        return {"error": "not_found", "message": f"No expense with id {expense_id}."}
    return expense


@mcp.tool
def submit_expense(
    amount: float, category: str, description: str, currency: str = "USD"
) -> dict:
    """Create a new expense claim on behalf of the current user.

    Args:
        amount: Claim amount.
        category: Spend category, for example travel or equipment.
        description: What the money was spent on.
        currency: ISO currency code. Defaults to USD.
    """
    if amount <= 0:
        return {"error": "invalid_amount", "message": "Amount must be greater than zero."}
    expense = store.create_expense(
        submitter=acting_user(),
        amount=amount,
        category=category,
        description=description,
        currency=currency,
    )
    return {"submitted": True, "expense": expense}


@mcp.tool
def approve_expense(expense_id: str, note: str | None = None) -> dict:
    """Approve a pending expense claim. This releases payment.

    Args:
        expense_id: The claim to approve.
        note: Optional note recorded with the approval.
    """
    approver = acting_user()

    verdict = rules.check_approval(expense_id, approver)
    if not verdict:
        audit.record(
            layer="rule", decision="deny", tool="approve_expense",
            reason=verdict.reason, **_audit_identity(),
        )
        # Returned, not raised: this is a business refusal, not an authorization
        # failure, and the model should relay the reason rather than retry.
        return {"error": "refused", "message": verdict.reason}

    approved = store.mark_approved(expense_id, approver=approver)
    audit.record(
        layer="rule", decision="allow", tool="approve_expense",
        reason=f"{expense_id} approved (${approved['amount']:,.2f}, "
               f"submitted by {approved['submitter']})",
        **_audit_identity(),
    )
    return {"approved": True, "note": note, "expense": approved}


@mcp.tool
def issue_refund(expense_id: str, amount: float, reason: str) -> dict:
    """Move money back to a customer against an expense claim.

    Args:
        expense_id: The claim the refund is booked against.
        amount: Refund amount.
        reason: Why the refund is being issued.
    """
    verdict = rules.check_refund(expense_id, amount)
    if not verdict:
        audit.record(
            layer="rule", decision="deny", tool="issue_refund",
            reason=verdict.reason, **_audit_identity(),
        )
        return {"error": "refused", "message": verdict.reason}

    refunded = store.add_refund(expense_id, amount=amount, reason=reason)
    audit.record(
        layer="rule", decision="allow", tool="issue_refund",
        reason=f"${amount:,.2f} refunded against {expense_id}",
        **_audit_identity(),
    )
    return {"refunded": True, "expense": refunded}


if __name__ == "__main__":
    if AUTH_ENABLED:
        mcp.add_middleware(ScopeMiddleware())
        print(f"Auth ON  - issuer {THUNDERID_ISSUER}, audience {MCP_RESOURCE_ID}")
    else:
        print("Auth OFF - every tool is callable by anyone who can reach the port.")

    mcp.run(
        transport="http",
        host=os.environ.get("MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MCP_PORT", "8000")),
    )
