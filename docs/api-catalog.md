# Public catalogue API

All routes are under `/api/v1`. Collections return `items` and `next_cursor`.
Pass the cursor as `after` with unchanged filters; null ends enumeration.
`limit` defaults to 50 (range 1–100). Unknown/repeated parameters return `400`.
See the [OpenAPI schema](openapi-v1.yaml) for fields and filters.

## Packages

`GET /packages` returns one row per repository/architecture variant. Exact
filters are `name`, `base`, `repository`, and `architecture`; `q` searches literal
substrings in name, base and upstream URL. Compare versions with libalpm.

The cursor is an opaque decimal row ID. Package refreshes can replace rows
while paging; there is no snapshot guarantee. Periodically download the full
catalogue and replace the local cache only when the download completes.

## CVEs and groups

`GET /cves` supports `package`, `orphan=true|false`, `severity`, and `q` (literal
substring of identifier, description or notes). Filters combine with AND;
CVE cursors use lexical identifier order. Package links do not establish whether
the currently distributed version is vulnerable.

`GET /groups` supports exact `package`, `cve`, and lowercase `status` filters;
its cursor orders by numeric AVG ID. `GET /groups/AVG-123` returns one group.
`assessment` summarizes stored status as `unknown`, `affected`, or `not_affected`;
it does not interpret upstream version ranges. Modification timestamps are not
synchronization checkpoints.

## Published advisories

`GET /advisories` accepts exact `package` filtering and lexical ASA cursors.
`GET /advisories/ASA-202601-1` returns a published advisory. Scheduled drafts are
excluded and return `404`, even for logged-in users. Group metadata reflects the
current assessment; `content` is the stored publication text.

## Synchronization

1. GET `/changes` **before** enumerating CVEs, groups and published advisories.
   It returns empty `items` and a checkpoint in `next_cursor`.
2. Enumerate those resources, then GET `/changes?after=CHECKPOINT` to catch up.
   `after=0` replays retained history.
3. Refetch each item's detail route. Remove local records marked `deleted` or
   returning `404`. Apply the full page before saving its `next_cursor`.
4. Continue until `has_more` is false, including through empty pages.

Items identify `resource` (`cves`, `groups`, `advisories`), `name`, and `deleted`.
They invalidate current records; they are not historical snapshots. Refetches
may include later edits. Retries are harmless. `next_cursor` is always a
checkpoint; `limit` bounds scanned audit transactions, not returned items.
One transaction can affect many records; private edits can yield empty pages.

The feed includes Continuum relationship changes and deletions, sometimes with
conservative extra invalidations. Never-published draft IDs/content stay private;
withdrawn publications produce tombstones. Package refreshes are unversioned
and require a separate catalogue download.

Checkpoints rely on retained audit history and SQLite's serialized writes.
Do not prune history or switch to concurrent transaction-ID allocation without
redesigning checkpoints. Direct SQL/bulk writes bypassing Continuum are
unsupported. Rebuild client caches/checkpoints after restoring or replacing the
tracker database.

## Conditional reads

Public GET/HEAD responses return a strong ETag of the complete JSON and
`Cache-Control: public, no-cache`. Store the body/tag and send `If-None-Match`
to revalidate; unchanged responses return `304`. Relationship edits invalidate
tags even when legacy timestamps are unchanged. Errors, writes, drafts and
token management remain `no-store`.

Public reads check strong `If-Match` tags or `*` first; a mismatch returns a JSON
`412` error with `no-store`.
