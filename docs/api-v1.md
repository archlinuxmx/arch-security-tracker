# Tracker API v1

See [OpenAPI](openapi-v1.yaml) for fields, limits and errors.
Existing installations must run `./trackerctl db upgrade` before starting the tracker.

## Tokens

Log in and open `/tokens`. Active reporters can issue and revoke their own tokens.
Copy the secret once; only its hash is stored. Tokens expire after 90 days.
Send `Authorization: Bearer <token>`; browser cookies cannot authorize API writes.
Revocation is immediate, and every request checks the owner's active flag and role.
Use HTTPS for remote access.

## Reads

```sh
curl --fail 'http://127.0.0.1:5000/api/v1/cves?limit=50'
```

Collections return `items` and `next_cursor`; pass the cursor as `after`.
A null cursor ends enumeration. `limit` accepts 1–100 and defaults to 50.
Identifiers sort lexically; pagination is not a snapshot or an update feed.
Missing identifiers return `404`. All CVE fields, including notes, are public.
Timestamps use UTC with a trailing `Z`.

## Creating CVEs

POST JSON to `/api/v1/cves` with a `name` and bearer token. For a disposable
local tracker, use a synthetic name such as `CVE-2099-99999999`.
Optional fields are `type`, `severity`, `vector`, `description`, `references`
and `notes`, plus a [source CVSS assessment](cvss.md); see the schema for limits and enums. References must use HTTP(S).
Bodies are limited to 64 KiB; unknown fields and nulls other than `cvss` are rejected.

Creation publishes the supplied fields and attributes the change to the token
owner. Keep unreviewed mail and private evidence outside public CVE fields.
Success returns `201`, the record and `Location`. A duplicate returns `409`
without changing the record. After a conflict or timeout, GET and compare before retrying.

Errors use `{"error": {"code": "...", "message": "..."}}`; field errors include `fields`.

## Token scopes

Tokens have one scope: `cves:create`, `cves:update`, `groups:create` or `groups:update`.
Use a separate token for each operation. Existing tokens remain create-only.
See [write workflows](api-workflow.md) for conditional edits and group creation.
