import hashlib
import json
from datetime import datetime

from flask import abort
from flask_login import current_user

from tracker import db
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.enum import highest_severity
from tracker.model.review import ReviewEvent

CVE_FIELDS = ('issue_type', 'description', 'severity', 'remote', 'reference', 'notes',
              'cvss_version', 'cvss_score', 'cvss_vector', 'cvss_source')
GROUP_FIELDS = ('affected', 'fixed', 'status', 'bug_ticket', 'reference', 'notes', 'advisory_qualified')


def review_target(name):
    if name.startswith('CVE-'):
        return CVE.query.get_or_404(name)
    if name.startswith('AVG-') and name[4:].isdigit():
        return CVEGroup.query.get_or_404(int(name[4:]))
    abort(404)


def target_name(record):
    return record.id if isinstance(record, CVE) else record.name


def assessment_for(record):
    return ReviewEvent.query.filter(ReviewEvent.target == target_name(record),
                                    ReviewEvent.action.in_(('required', 'reviewed'))).order_by(
                                        ReviewEvent.id.desc()).first()


def record_advisories(record):
    query = Advisory.query.join(CVEGroupPackage)
    if isinstance(record, CVE):
        query = query.join(CVEGroup, CVEGroup.id == CVEGroupPackage.group_id).join(CVEGroupEntry).filter(
            CVEGroupEntry.cve_id == record.id)
    else:
        query = query.filter(CVEGroupPackage.group_id == record.id)
    return query.all()


def content_revision(record):
    fields = CVE_FIELDS if isinstance(record, CVE) else GROUP_FIELDS
    data = {field: str(getattr(record, field)) for field in fields}
    data['changed'] = str(record.changed)
    if isinstance(record, CVE):
        data['groups'] = [
            {'id': entry.group_id, 'changed': str(entry.group.changed),
             'packages': sorted(package.pkgname for package in entry.group.packages),
             'assessment': [str(getattr(entry.group, field)) for field in GROUP_FIELDS]}
            for entry in CVEGroupEntry.query.filter_by(cve_id=record.id).order_by(CVEGroupEntry.group_id)
        ]
    else:
        data['cves'] = [
            {column.name: str(getattr(entry.cve, column.name)) for column in CVE.__table__.columns}
            for entry in sorted(record.issues, key=lambda item: item.cve_id)
        ]
        data['packages'] = sorted(entry.pkgname for entry in record.packages)
    data['advisories'] = sorted((item.id, str(item.publication), str(item.changed))
                                for item in record_advisories(record))
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def review_revision(record):
    assessment = assessment_for(record)
    value = '{}:{}'.format(content_revision(record), assessment.id if assessment else 0)
    return hashlib.sha256(value.encode()).hexdigest()


def lock_record(record):
    # Obtain the write lock before checking content and relationship revisions.
    table = record.__table__
    result = db.session.execute(table.update().where(table.c.id == record.id).values(changed=table.c.changed))
    if result.rowcount != 1:
        abort(409, 'The record was removed. Reload before submitting.')
    db.session.expire_all()


def expect_revision(record, revision):
    lock_record(record)
    if review_revision(record) != revision:
        abort(409, 'The record or its assessment changed. Reload before submitting.')


def record_event(record, action, rationale, revision=None):
    event = ReviewEvent(target=target_name(record), action=action, rationale=rationale,
                        revision=revision or content_revision(record), user_id=current_user.id)
    db.session.add(event)
    return event



def merge_groups(source, destination, rationale):
    if source.id == destination.id:
        abort(409, 'Choose two different groups.')
    if record_advisories(source) or record_advisories(destination):
        abort(409, 'Groups with scheduled or published advisories cannot be merged.')
    source_packages = sorted(item.pkgname for item in source.packages)
    if source_packages != sorted(item.pkgname for item in destination.packages):
        abort(409, 'Package sets must match before merging.')
    for field in GROUP_FIELDS:
        if field != 'reference' and getattr(source, field) != getattr(destination, field):
            abort(409, 'Conflicting {} values must be reconciled before merging.'.format(field))
    references = list(dict.fromkeys((destination.reference or '').splitlines() + (source.reference or '').splitlines()))
    if len('\n'.join(references)) > CVEGroup.REFERENCES_LENGTH:
        abort(409, 'Combined references exceed the group limit.')
    previous_revision = content_revision(source)
    existing = {entry.cve_id for entry in destination.issues}
    for entry in source.issues:
        if entry.cve_id not in existing:
            destination.issues.append(CVEGroupEntry(cve=entry.cve))
    destination.reference = '\n'.join(references)
    destination.severity = highest_severity(entry.cve.severity for entry in destination.issues)
    destination.changed = datetime.utcnow()
    record_event(source, 'merged', json.dumps({'destination': destination.name, 'reason': rationale}),
                 revision=previous_revision)
    record_event(destination, 'required', 'Merged {}. {}'.format(source.name, rationale))
    db.session.delete(source)


def merged_destination(name):
    seen = set()
    while name not in seen:
        seen.add(name)
        if not name.startswith('AVG-') or not name[4:].isdigit():
            return None
        if CVEGroup.query.get(int(name[4:])):
            return name
        event = ReviewEvent.query.filter_by(target=name, action='merged').order_by(ReviewEvent.id.desc()).first()
        if not event:
            return None
        name = json.loads(event.rationale)['destination']
    return None
