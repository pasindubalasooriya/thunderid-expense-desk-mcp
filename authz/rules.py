"""Layer 3: business rules, which live in your code and nowhere else.

Layers 1 and 2 answer questions about the caller: may this person use this tool,
and is that still true right now. Neither can answer a question about *this
particular call* -- whose claim it is, how much money it moves, whether the refund
exceeds what was charged. Those depend on the arguments and on your own data.

ThunderID's PDP evaluates roles and permissions. It does not know that an expense
has a submitter, and it should not: teach your identity provider your business
rules and you have two systems that must be changed together forever.

So these stay here. Each returns a refusal a model can explain to a person, which
is deliberate -- see the note in the module below.
"""

from dataclasses import dataclass

import expense_store as store
from authz.principals import is_known_username

# An approval above this goes to a human process we do not model here.
APPROVAL_LIMIT = 5000.0


@dataclass
class RuleResult:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


ALLOWED = RuleResult(True)


def check_approval(expense_id: str, approver: str) -> RuleResult:
    """Rules for approving a claim.

    Refusals name the rule and the number, so the assistant can tell the user what
    would have to change. A bare "permission denied" invites a model to retry, or
    to guess at a workaround; a specific reason ends the attempt and redirects the
    person to the process that can actually help them.
    """
    expense = store.get_expense(expense_id)
    if expense is None:
        return RuleResult(False, f"No expense with id {expense_id}.")

    # Fail closed on an unrecognised caller. Without this, an unmapped subject
    # gets its raw uuid as a username, which matches no submitter, and the
    # self-approval rule below passes for the wrong reason -- silently.
    if not is_known_username(approver):
        return RuleResult(
            False,
            f"This server does not recognise {approver} as a user it knows, so it "
            f"cannot tell whether {expense_id} is your own claim. Refusing rather "
            f"than guessing.",
        )

    if expense["status"] != "pending":
        return RuleResult(
            False, f"{expense_id} is already {expense['status']} and cannot be approved again."
        )

    if expense["submitter"] == approver:
        return RuleResult(
            False,
            f"{approver} submitted {expense_id}, and an approver cannot approve "
            f"their own claim. Someone else with the Approver role has to sign it off.",
        )

    if expense["amount"] > APPROVAL_LIMIT:
        return RuleResult(
            False,
            f"{expense_id} is ${expense['amount']:,.2f}, which is over the "
            f"${APPROVAL_LIMIT:,.0f} single-approval limit. It needs the "
            f"out-of-band sign-off process, which this tool does not perform.",
        )

    return ALLOWED


def check_refund(expense_id: str, amount: float) -> RuleResult:
    """A refund cannot exceed what is left on the original claim."""
    expense = store.get_expense(expense_id)
    if expense is None:
        return RuleResult(False, f"No expense with id {expense_id}.")

    if amount <= 0:
        return RuleResult(False, "A refund has to be greater than zero.")

    remaining = expense["amount"] - expense["refunded_amount"]
    if amount > remaining:
        return RuleResult(
            False,
            f"A refund of ${amount:,.2f} is more than the ${remaining:,.2f} "
            f"remaining on {expense_id} (original ${expense['amount']:,.2f}, "
            f"already refunded ${expense['refunded_amount']:,.2f}).",
        )

    return ALLOWED
