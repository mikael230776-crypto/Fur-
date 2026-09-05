# Step 7 administration foundation

Status: code review only; disabled and not deployed.

## Safety boundary

- `ENABLE_ADMIN_SYSTEM` must be exactly `true` before the handler is reachable.
- This change does not set that variable or any deployment setting.
- No administrator credential or token is included.
- `20260905_create_admin_foundation.sql` must not be applied during the Phase 6 hold.
- The handler uses only the server-side Supabase secret and never exposes it to a browser.
- NFC tools, tags, physical-authentication flags, and Phase 6 migrations are untouched.

## Authentication

The vendor-neutral credential configuration is supplied at runtime through
`ADMIN_PRINCIPALS_JSON`. Each entry contains an administrator identifier, a role,
and a lowercase SHA-256 digest of a bearer token. Plaintext tokens are not stored
in the configuration. Invalid or duplicate configuration fails closed.

Example shape (illustrative hashes only):

```json
[
  {
    "id": "operator@example.invalid",
    "role": "viewer",
    "tokenSha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }
]
```

Real credentials must be generated, stored, and enabled only in a separately
approved production-readiness step.

## Permission levels

| Role | Read products | Add | Update | Suspend | Read activity |
| --- | --- | --- | --- | --- | --- |
| viewer | Yes | No | No | No | Yes |
| editor | Yes | Yes | Yes | No | Yes |
| administrator | Yes | Yes | Yes | Yes | Yes |

Unknown roles and permissions are denied. Mutation permissions are checked in
both the API and the transactional database function.

## Product mutations

`POST /api/admin-products` accepts one operation: `add`, `update`, or `suspend`.
Requests reject unknown fields, validate lengths and formats, authenticate the
principal, verify the required permission, and then call only
`admin_mutate_product`. The database function changes the product and appends the
matching activity event in the same transaction.

Suspension is deliberate rather than deletion. Suspended products cannot be
updated or suspended again through the function.

## Append-only history

`admin_activity_history` records the actor identifier, actor role, action,
product, limited action details, and server timestamp. A trigger rejects every
update or delete. Row-level security is enabled, browser roles receive no table
privileges, and the mutation function is executable only by `service_role`.

## Review and verification

Automated tests cover:

- disabled-by-default behavior without network access;
- hashed bearer authentication and fail-closed configuration;
- role permission boundaries;
- strict product and suspension validation;
- transactional RPC request construction;
- static migration assertions for RLS, grants, append-only enforcement, and
  database-side role checks.

Run JavaScript tests in an environment with Node.js using `npm test`. Run the
existing Python safety suite using:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Do not merge without explicit approval.
