"""Layer 1 enforcement, applied at the protocol boundary.

Two hooks, and the first one is the interesting half:

`on_list_tools` filters the tool list down to what the caller's scopes allow. A
tool the caller cannot use never appears as an option, so the model never plans
around it, never calls it, and never has to be told no. andrea does not get an
error from approve_expense -- she is never offered it.

`on_call_tool` still checks, because a filtered list is a convenience for the
client, not a control. Nothing stops a client from calling a tool it was never
shown, so the scope is enforced again before the handler runs -- before any part
of the tool has a chance to move money.
"""

import os

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext

import audit
from authz.authzen import AuthZenClient
from authz.principals import username_for
from authz.scopes import TOOL_SCOPES, granted_scopes

# Layer 2 runs only for the tools that actually move money. Reads stay on the
# token alone -- a PDP round trip per list_expenses would be a lot of latency to
# buy very little.
PDP_PROTECTED_TOOLS = {"approve_expense", "issue_refund"}


def _identity(token) -> dict:
    """Everything the audit trail wants to know about the caller."""
    claims = getattr(token, "claims", None) or {}
    subject = claims.get("sub")
    act = claims.get("act") or {}
    return {
        "subject": subject,
        "user": username_for(subject),
        "client_id": claims.get("client_id") or getattr(token, "client_id", None),
        # RFC 8693: when one identity acts for another, `act.sub` is the actor.
        "act_sub": act.get("sub") if isinstance(act, dict) else None,
    }


def _subject_id(token) -> str | None:
    """The identity the PDP should be asked about, from the validated token."""
    if token is None:
        return None
    claims = getattr(token, "claims", None) or {}
    return claims.get("sub")


def _current_token():
    try:
        return get_access_token()
    except Exception:
        return None


class ScopeMiddleware(Middleware):
    """Filters the tool list and enforces the required scope on each call.

    With AUTHORIZATION_MODE=authzen, money-moving tools additionally get a live
    policy decision before the handler runs.
    """

    def __init__(self):
        self.mode = os.environ.get("AUTHORIZATION_MODE", "scopes").lower()
        self.pdp = AuthZenClient() if self.mode == "authzen" else None

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        tools = await call_next(context)
        held = granted_scopes(_current_token())
        return [t for t in tools if TOOL_SCOPES.get(t.name) in held]

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool_name = context.message.name
        required = TOOL_SCOPES.get(tool_name)
        if required is not None:
            held = granted_scopes(_current_token())
            if required not in held:
                audit.record(
                    layer="scope", decision="deny", tool=tool_name,
                    reason=f"token does not carry '{required}'",
                    **_identity(_current_token()),
                )
                # Say which scope is missing. The model relays this to the user,
                # who can then ask for the right role -- rather than retrying.
                raise ToolError(
                    f"Not permitted: {tool_name} requires the '{required}' "
                    f"permission, which this access token does not carry."
                )

        # Layer 2. The token said yes; ask whether that is still true.
        if self.pdp is not None and tool_name in PDP_PROTECTED_TOOLS:
            token = _current_token()
            subject = _subject_id(token)
            subject_type = (getattr(token, "claims", None) or {}).get("sub_type", "user")
            if subject is None:
                raise ToolError("Not permitted: no subject to evaluate.")

            allowed, reason = await self.pdp.evaluate(
                subject, required, subject_type=subject_type
            )
            audit.record(
                layer="authzen", decision="allow" if allowed else "deny",
                tool=tool_name, reason=reason, **_identity(token),
            )
            if not allowed:
                raise ToolError(
                    f"Not permitted: {reason} Your token carries "
                    f"'{required}', but the policy decision point refused this "
                    f"call. Your access may have changed since you signed in."
                )

        if required is not None:
            audit.record(
                layer="scope", decision="allow", tool=tool_name,
                reason=f"token carries '{required}'",
                **_identity(_current_token()),
            )
        return await call_next(context)
