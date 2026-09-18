"""Mapping ThunderID subjects to application users.

An access token's `sub` is ThunderID's identifier for the caller -- a UUID. Our
expense records say `andrea` and `mike`. Something has to join the two, and that
something is the application, not the identity provider.

This is not a demo shortcut. Any real system keeps its own user record and stores
the IdP's subject as a foreign key, because the application needs rows of its own
to hang data off. Here that table is a dict loaded from the environment.

The practical warning for readers: join on `sub`, never on email or username. Those
are display attributes -- they change when someone marries, or gets a new address,
or when an admin fixes a typo -- and a claim you join on must be stable and never
reassigned. `sub` is the only claim ThunderID promises that about.
"""

import json
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def _principals() -> dict[str, str]:
    """{"<thunderid-sub-uuid>": "<application username>"}

    Read lazily, on first use, rather than at import time. Reading it at import
    time is a trap: any module that imports this one before load_dotenv() has run
    gets an empty map, username_for() silently returns the raw subject, and rules
    that compare a caller to a stored username stop matching -- without raising
    anything. We shipped that bug for exactly one demo run, and it let an approver
    approve his own claim.
    """
    return json.loads(os.environ.get("PRINCIPAL_MAP", "{}"))


def username_for(subject: str | None) -> str:
    """The application's name for this subject, or the raw subject if unknown."""
    if subject is None:
        return "unknown"
    return _principals().get(subject, subject)


def is_known(subject: str | None) -> bool:
    """True if this is a ThunderID subject we have a local user for."""
    return subject in _principals()


def is_known_username(username: str | None) -> bool:
    """True if this is one of our application usernames.

    Rules run after the subject has been mapped, so they hold a username, not a
    subject. An unmapped subject arrives here as its raw uuid and fails this
    check -- which is the point.
    """
    return username in set(_principals().values())
