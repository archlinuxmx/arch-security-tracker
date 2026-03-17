# Tracker API v1

See the [OpenAPI schema](openapi-v1.yaml) for endpoints, fields and validation;
[catalogue reads](api-catalog.md) and [write workflows](api-workflow.md) cover usage.

## Setup

Existing installations must run `./trackerctl db upgrade` before starting the tracker.
Remote clients must use HTTPS; local examples use HTTP on loopback.

## Tokens

Log in and open `/tokens`. Active reporters can create and revoke their own
named tokens. Copy the secret once; only its SHA-256 digest is stored.
Tokens expire after 90 days and have one scope: `cves:create`, `cves:update`,
`groups:create`, `groups:update`, or `advisories:write`. The advisory scope
requires the Security Team or administrator role. Existing tokens remain
create-only. Use a separate token for each operation and replace it before expiry.

Send `Authorization: Bearer <token>`. Cookies cannot authorize API writes;
no CSRF token or browser session is needed. Token management uses CSRF-protected
forms. Revocation is immediate. Every protected request checks the owner's local
role and active flag; SSO group changes reach that account only on login.

## Reads

```sh
curl --fail 'http://127.0.0.1:5000/api/v1/cves?limit=50'
```

Collections return `items` and `next_cursor`; pass the cursor as `after`.
A null cursor ends enumeration. `limit` defaults to 50 and accepts 1–100;
unknown or repeated parameters return `400`.

CVE ordering is lexical by identifier. Pagination is not a snapshot or update
feed; later insertions before a saved cursor can be missed. Use `/changes`
for synchronization, not `updated` timestamps. Individual missing or invalid
identifiers return `404`. All CVE fields, including notes, are public; orphan
CVEs have empty group/package arrays. Timestamps use UTC with a trailing `Z`.

Public reads support `ETag`/`If-None-Match` and return `304` when unchanged.
Their cache policy is `public, no-cache`; drafts, writes and errors use `no-store`.

## Creating CVEs

Send a JSON object with `name`; omitted assessment fields default to `unknown`.
Text defaults to empty strings, references to `[]`, and CVSS to `null`.
Requests require a JSON media type and have a 64 KiB body limit.
The schema lists exact limits and enums. Unknown/read-only fields and explicit
nulls other than `cvss` are rejected. References are deduplicated HTTP(S) URLs;
the server does not fetch them. Identifier validation checks syntax, not CVE
assignment or package applicability. See [CVSS](cvss.md) for source assessments.

Use this synthetic record only in a disposable local tracker:

```python
from getpass import getpass

import requests

session = requests.Session()
session.trust_env = False  # Ignore proxy and netrc settings for this local example.
response = session.post(
    "http://127.0.0.1:5000/api/v1/cves",
    headers={"Authorization": f"Bearer {getpass('API token: ')}"},
    json={"name": "CVE-2099-99999999", "description": "Local API demonstration."},
    timeout=(5, 30),
    allow_redirects=False,
)
print(response.status_code, response.json())
```

Creation immediately publishes all fields, including notes, and attributes the
change to the token owner. Keep unreviewed candidates in the ingestion tool.
Private provenance and review reasons belong in the review workflow.
Success returns `201`, the record and `Location`. Duplicates return
`409 already_exists` without changing anything, including concurrent creates.
Validation precedes the duplicate check; writes are atomic. After a `409` or
uncertain timeout, GET the identifier and compare before retrying.

## Edits and errors

PATCH requires the exact quoted `ETag` from a fresh detail GET in `If-Match`.
Missing preconditions return `428`; stale tags return `412`. Refetch and review
before retrying; do not replace the tag automatically. Arrays replace their
previous contents. Advisory-linked CVEs/AVGs additionally require Security Team
membership. Drafts remain private; publication and deletion use the browser.

Errors have `{"error": {"code": "...", "message": "..."}}`. Field errors include
`fields`, mapping names to message arrays. See the schema for status codes.
A `401` includes a Bearer challenge. All errors are `no-store`.
