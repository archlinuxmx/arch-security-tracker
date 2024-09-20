# Public catalogue API

All routes are under `/api/v1`. Collections return `items` and `next_cursor`.
Pass the cursor as `after` with unchanged filters; null ends enumeration.
`limit` defaults to 50 (range 1–100). Unknown/repeated parameters return `400`.

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
