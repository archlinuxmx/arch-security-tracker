# Reviewed API writes

Use a separate [scoped token](api-v1.md#tokens) for each operation.
See the [OpenAPI schema](openapi-v1.yaml) for complete request fields.

## Editing CVEs and groups

GET the detail URL, then PATCH it with the quoted response `ETag` in `If-Match`.
Only one exact strong tag is accepted; weak tags, `*`, and lists are rejected.
Missing preconditions return `428`; stale tags return `412`. Refetch and review
changes before retrying. Success includes the updated record and ETag.
Names cannot change; references and membership arrays replace the full lists.

API writes lock and compare the fetched representation. Browser forms compare
the saved modification timestamp and return `409` for stale edits; an explicit
override is available. Database revision checks also reject competing writes.

Reporter tokens cannot edit CVEs/AVGs linked to scheduled or published advisories;
Security Team tokens can. Edits refresh modification dates, group severity and
scheduled advisory issue types as needed.

## Groups

`POST /api/v1/groups` requires `groups:create`. For example:

```json
{
  "cves": ["CVE-2026-1234"],
  "packages": ["example"],
  "affected": "1.0-1",
  "fixed": "1.1-1",
  "assessment": "affected"
}
```

Packages must exist in the catalogue and share one package base. Missing CVEs
are created after identifier validation. `affected` is required; optional `fixed`
must compare newer using libalpm. `bug_ticket` accepts an empty string or an
HTTPS Arch packaging-project GitLab issue URL, such as
`https://gitlab.archlinux.org/archlinux/packaging/packages/example/-/issues/73`.

`assessment` is `unknown` (default), `affected`, or `not_affected`. The caller
must review applicability and the fix version; upstream disclosure or a newer
repository version alone establishes neither. The tracker derives status from
that assessment and package versions. `not_affected` clears advisory qualification.

Success returns `201`, the record and `Location`. Existing package/CVE links
return `409 already_grouped`; there is no force-create option.

PATCH requires `groups:update` and `If-Match`. Existing dropped packages can
remain attached; new packages must exist. Packages with advisories cannot be
removed. Computed status and severity are read-only. Omitting `bug_ticket` preserves
the stored reference. Submitted values must be GitLab URLs or empty; numeric IDs
are rejected, including unchanged ones. Archived browser references are read-only
until explicitly replaced.

## Advisory drafts

With an `advisories:write` token and Security Team membership:

1. POST `{}` to `/api/v1/groups/AVG-1234/advisory-drafts` to create one scheduled
   draft per package. Optional `type` overrides the type derived from CVEs.
2. GET `/api/v1/advisory-drafts/ASA-202608-1` for the draft and ETag.
3. PATCH with `If-Match` to change `type`, `workaround`, or `impact`.

Creation returns `201` and `items`. The group needs CVEs, packages, a supplied
fix version, `fixed` status and no existing advisory. Conflicts return `409`.
IDs use the current UTC month and next available number; after an allocation
conflict, fetch the group's state before retrying.

Content is generated from the existing template and current CVE/group data.
Drafts require authentication and cannot be cached. Generation sends no mail,
fetches no URLs and publishes nothing. Publication fields and arbitrary content
are not writable. Published advisories return `409 already_published` here;
review, send and publish through the existing team/browser workflow.
