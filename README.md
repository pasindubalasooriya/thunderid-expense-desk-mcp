# Expense Desk MCP

An expense-approval MCP server secured with [ThunderID](https://github.com/asgardeo/thunder).

Most MCP authorization writing stops at "check the scope". This repo goes further,
because its tools have real consequences — one of them moves money — and that forces
the question a scope cannot answer: *is this particular call legitimate?*

Three layers, each answering a different question:

| Layer | Question | Where it lives | Example |
|---|---|---|---|
| 1. Token scopes | May this caller use this tool at all? | ThunderID issues, this server checks | andrea has no `expenses-approve`, so `approve_expense` never appears in her tool list |
| 2. AuthZEN decision | Is that still true *right now*? | ThunderID's PDP, asked per call | mike loses the Approver role at 10:00; his 10:05 call is denied on a token that still says otherwise |
| 3. Application rules | Is this *specific* call legitimate? | [authz/rules.py](authz/rules.py) — always your own code | mike may approve, but not his own claim, and not over $5,000 |

## Tools and scopes

| Tool | What it does | Scope |
|---|---|---|
| `list_expenses` | List claims, optionally filtered | `expenses-read` |
| `get_expense` | Fetch one claim in full | `expenses-read` |
| `submit_expense` | Create a claim | `expenses-submit` |
| `approve_expense` | Approve a pending claim; releases payment | `expenses-approve` |
| `issue_refund` | Move money back to a customer | `expenses-refund` |

MCP resource servers use **flat** tool permissions: the handle *is* the scope, with
no prefix and no delimiter applied. That is why these read `expenses-read` and not
`expenses:read` — the colon form belongs to hierarchical API resource servers.

## Who sees what

| Principal | Role | Scopes | Tools visible |
|---|---|---|---|
| `andrea` | Expense Employee | read, submit | 3 |
| `mike` | Expense Approver | read, submit, approve | 4 |
| `expense-triage-bot` (agent) | Expense Triage Agent | read | 2 |

Nobody holds `expenses-refund`, so `issue_refund` is visible to no one. A permission
granted to no role is unreachable — a legitimate way to park a dangerous tool.

## Run it

Needs Python 3.12+, [uv](https://docs.astral.sh/uv/), and a local ThunderID.

```bash
uv sync
cp .env.example .env     # then fill in the values below
uv run python server.py
```

The server listens on `http://localhost:8000/mcp/`.

### ThunderID setup

1. Create a resource server: type **MCP**, identifier `http://localhost:8000/mcp`,
   delimiter `:`.
2. On **Capabilities**, add four **tool permissions**. Type only the Name and let
   ThunderID derive the handle: `Expenses Read` → `expenses-read`, and likewise for
   Submit, Approve and Refund. **Check each handle before saving** — it is the exact
   scope string this server checks, and it is immutable afterwards.
3. Create three roles granting those permissions (see the table above) and assign
   them to your users and agent.
4. Enable Dynamic Client Registration in ThunderID's `deployment.yaml` so MCP
   clients can self-register:

   ```yaml
   oauth:
     dcr:
       enabled: true
       insecure: true    # local dev only: lets any client register unauthenticated
   ```

[setup/thunderid-config.yaml](setup/thunderid-config.yaml) declares the resource
server, roles, users and agent for ThunderID's declarative import. The four tool
permissions are **not** in it — the importer can only express actions nested under a
resource, which yields hierarchical `expenses:read` strings. Add those four through
the console or the REST API; the file documents the calls.

### Connecting Claude Code

```bash
claude mcp add --transport http expense-desk http://localhost:8000/mcp/
```

Then `/mcp` → authenticate. ThunderID's local certificate is self-signed, so point
Node at it first:

```powershell
$env:NODE_EXTRA_CA_CERTS = "<thunderid>\config\certs\server.cert"
```

## Seeing the layers work

```bash
uv run python tools/audit_report.py       # every decision, tagged with the layer that made it
uv run python tools/inspect_token.py --agent   # what a token actually carries
```

Switch layer 2 on and off with `AUTHORIZATION_MODE=authzen|scopes`, and turn
authorization off entirely with `AUTH_ENABLED=false` to see the unprotected server
the blog post opens with.

## Troubleshooting

Every one of these cost us time while building it.

| Symptom | Cause | Fix |
|---|---|---|
| A tool never appears, no error anywhere | The scope string in code does not match the permission handle in ThunderID | Compare them character by character. A missing scope looks exactly like a tool that was never written |
| Tool list is empty after connecting | The role is registered but not **assigned**, so the scope is silently dropped from the token | Assign the role, then reconnect |
| Permissions look right but nothing matches | You typed `expenses:read` as the *name*; the console slugified it to handle `expenses-read` | The name is decoration, the handle is the contract. Handles are immutable — delete and recreate |
| `SDK auth failed: self signed certificate` | Node will not trust ThunderID's local certificate | `NODE_EXTRA_CA_CERTS=<thunderid>\config\certs\server.cert`. Do not reach for `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| `DCR rejected (400): An application with the same name already exists` | A previous connection attempt registered the client and then failed | Delete that application in the console and reconnect |
| `SDK auth failed: Unable to connect` | The **authorization server** is down, not the MCP server | Check ThunderID is running. The MCP server only points clients at it |
| `unauthorized_client` on the token endpoint | Client id and secret sent in the POST body | Send them as HTTP Basic (`curl -u id:secret`) |
| Rules never fire; `approved_by` shows a UUID | `PRINCIPAL_MAP` was read before `.env` loaded, so subjects never mapped to usernames | Read config lazily, and fail closed on an unrecognised caller |
| Approvals silently revert | An older version kept state in memory and lost it on restart | Fixed: state persists to `expenses.json`. Set `RESET_STORE=true` to reseed |

## Layout

```
server.py             FastMCP server, tools, ThunderID auth wiring
expense_store.py      seed data, persisted to expenses.json
audit.py              one JSON line per decision
authz/
  scopes.py           layer 1: the scope strings and the tool→scope map
  middleware.py       layer 1 enforcement + the layer 2 call
  authzen.py          layer 2: the PDP client
  rules.py            layer 3: business rules
  principals.py       maps a token subject to an application user
tools/
  audit_report.py     renders audit.jsonl as a table
  inspect_token.py    decodes a token's claims
setup/
  thunderid-config.yaml   declarative IAM setup
```

## License

MIT
