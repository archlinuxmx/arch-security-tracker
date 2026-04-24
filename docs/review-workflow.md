# Review workflow

Run `./trackerctl db upgrade` on existing databases before deployment.
Active reporters use `/review` to assess CVEs/AVGs, recording the rationale,
actor and content revision. History is append-only; changed records show stale
assessments. Review text is private to active reporters and excluded from public
notes, feeds and logs. These workflows send no mail and publish no advisory.

Reporters can sign off a current assessment requiring no further review.
Signoffs are optional; no two-person or publication rule is imposed. Changes
to content, relationships, advisories or assessments invalidate them. AVG reviews
cover linked CVE content; CVE reviews cover package/applicability context, even
when relationship changes leave legacy timestamps unchanged.

## Disclosure queue

`/review/intake` stores immutable disclosures with a source reference and private
evidence; CVE IDs can be supplied later. Sources may identify archived messages
or mailbox/message IDs. Mail collection stays outside the tracker.

Decisions (pending, approved, rejected) retain author, reason and revision.
Correct an immutable disclosure by submitting a replacement and rejecting the
original. Proposed public descriptions/HTTP(S) references use separate fields.
Approval alone publishes nothing: a second action creates the public CVE and
marks it for applicability review. Private evidence/reasons are never copied.
Existing CVEs cause a conflict; promoted candidates retain their source history.

## Group merging

Preview source and destination at `/review/merge`. Their package sets,
affected/fixed versions, status, ticket, notes and advisory qualification must
match. Reconcile differences first. Neither group can have a scheduled or
published advisory.

The retained group receives the union of CVEs/references and needs fresh review.
The retired group and links are deleted atomically; version, assessment, signoff
and merge history remain. Public HTML/JSON/log URLs redirect to the retained
group; API clients receive a deletion through synchronization. Private review
pages retain links to retired history. Merge never reconciles assessments for you.

## Corrections

From a record's review page, select a saved transaction and give a reason.
Restoration writes scalar content as a new version, preserving creation dates
and history, and requires fresh review. It restores CVSS and recalculates group
severity after CVE severity changes.
Group restoration recalculates status from current repository versions.

Restoration cannot change relationships or resurrect deleted records. Different
historical CVE/group/package links cause a conflict. Advisory-linked records are
also blocked; correct them through normal editing. Review/signoff history is
never rolled back.
