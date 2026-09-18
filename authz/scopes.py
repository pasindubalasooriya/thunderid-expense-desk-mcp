"""Layer 1: token scopes.

The scope strings below must match the permission handles registered on the MCP
resource server in ThunderID, character for character.

MCP resource servers use flat tool permissions: each permission sits directly on
the resource server, and for a top-level action the handle *is* the permission,
with no prefix and no delimiter applied. ThunderID derives the handle from the
name you type by lowercasing it and joining words with a hyphen, so the capability
named "Expenses Read" has the handle -- and therefore the scope -- `expenses-read`.

The colon form (`expenses:read`) belongs to hierarchical API resource servers,
where a permission is `{resource-handle}{delimiter}{action-handle}`. Using it here
would be a silent failure: a scope the token never carries, so a tool that never
appears.
"""

SCOPE_READ = "expenses-read"
SCOPE_SUBMIT = "expenses-submit"
SCOPE_APPROVE = "expenses-approve"
SCOPE_REFUND = "expenses-refund"

ALL_SCOPES = [SCOPE_READ, SCOPE_SUBMIT, SCOPE_APPROVE, SCOPE_REFUND]

# Which scope each tool requires. The tool list is filtered against this, so a
# caller without the scope does not merely fail the call -- they never see the tool.
TOOL_SCOPES: dict[str, str] = {
    "list_expenses": SCOPE_READ,
    "get_expense": SCOPE_READ,
    "submit_expense": SCOPE_SUBMIT,
    "approve_expense": SCOPE_APPROVE,
    "issue_refund": SCOPE_REFUND,
}


def granted_scopes(token) -> set[str]:
    """Return the scopes carried by a validated access token.

    FastMCP exposes the verified token's scopes on `.scopes`; some verifiers put
    the raw string on the `scope` claim instead, so both are accepted.
    """
    if token is None:
        return set()

    scopes = getattr(token, "scopes", None)
    if scopes:
        return set(scopes)

    claims = getattr(token, "claims", None) or {}
    raw = claims.get("scope") or claims.get("scp") or ""
    if isinstance(raw, str):
        return set(raw.split())
    return set(raw)


def has_scope(token, scope: str) -> bool:
    return scope in granted_scopes(token)


def visible_tools(token) -> set[str]:
    """The tool names this token may see, which is also the set it may call."""
    held = granted_scopes(token)
    return {tool for tool, scope in TOOL_SCOPES.items() if scope in held}
