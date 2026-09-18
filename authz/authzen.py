"""Layer 2: ask ThunderID at the moment of the call.

A token is a statement about the past. It says what was true when it was issued,
and it keeps saying that until it expires -- an hour here, longer in plenty of
deployments. Revoke someone's role at 10:00 and their 10:05 call still arrives
carrying a token that says they are an approver, correctly signed, not expired.

So for the tools that matter, we stop trusting the token's word and ask: can this
subject perform this action on this resource, right now? That question is what
AuthZEN standardises. Our MCP server is the policy enforcement point (PEP); the
ThunderID PDP answers.

The cost is a network call per protected tool call, which is why this is worth
switching on for approve and refund, and not for reads.
"""

import os

import httpx

# ThunderID advertises this at /.well-known/authzen-configuration as
# access_evaluation_endpoint.
EVALUATION_PATH = "/access/v1/evaluation"


class AuthZenClient:
    def __init__(
        self,
        issuer: str | None = None,
        direct_auth_secret: str | None = None,
        resource_id: str | None = None,
        verify_tls: bool | None = None,
    ):
        self.issuer = (issuer or os.environ["THUNDERID_ISSUER"]).rstrip("/")
        self.secret = direct_auth_secret or os.environ["THUNDERID_DIRECT_AUTH_SECRET"]
        self.resource_id = resource_id or os.environ["MCP_RESOURCE_ID"]
        if verify_tls is None:
            verify_tls = os.environ.get("THUNDERID_VERIFY_TLS", "false").lower() == "true"
        self._client = httpx.AsyncClient(verify=verify_tls, timeout=5.0)

    async def evaluate(
        self, subject_id: str, action: str, subject_type: str = "user"
    ) -> tuple[bool, str]:
        """Return (allowed, reason).

        `resource.type` is the resource server identifier -- the same string that
        is the token's audience. `action.name` is the permission handle, which for
        an MCP server is the flat scope string, e.g. `expenses-approve`.
        """
        payload = {
            "subject": {"type": subject_type, "id": subject_id},
            "resource": {"type": self.resource_id},
            "action": {"name": action},
        }

        try:
            response = await self._client.post(
                f"{self.issuer}{EVALUATION_PATH}",
                json=payload,
                headers={"Direct-Auth-Secret": self.secret},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # The PDP is unreachable or unhappy. Fail closed: a tool that moves
            # money does not run because the thing that authorises it is down.
            # Fail-open here would mean an outage silently removes the control.
            return False, f"Policy decision point unavailable ({exc.__class__.__name__})."

        body = response.json()
        allowed = bool(body.get("decision"))
        reason = (body.get("context") or {}).get("reason") or (
            "Allowed by policy." if allowed else "Denied by policy."
        )
        return allowed, reason

    async def aclose(self) -> None:
        await self._client.aclose()
