"""Token-authenticated edits and the reviewed AVG/advisory workflow."""

from datetime import datetime
from hashlib import sha256

from flask import g
from flask import jsonify
from flask import request
from sqlalchemy import event
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.exceptions import NotFound

from tracker import db
from tracker import tracker
from tracker.api import APIError
from tracker.api import api
from tracker.api import error_response
from tracker.api import read_json
from tracker.api import serialize_cves
from tracker.api import token_required
from tracker.api import validate_content
from tracker.api import validate_cve
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.advisory import advisory_types
from tracker.model.enum import Publication
from tracker.model.enum import Status
from tracker.model.enum import group_status
from tracker.model.enum import highest_severity


@event.listens_for(Session, 'before_flush')
def touch_edited_records(session, flush_context, instances):
    for record in session.dirty:
        if isinstance(record, (CVE, CVEGroup, Advisory)) and session.is_modified(record):
            record.changed = datetime.utcnow()


def write_lock(model, identity):
    """Lock before reading: SQLite also serializes relationship writes here."""
    table = model.__table__
    result = db.session.execute(table.update().where(table.c.id == identity).values(id=table.c.id))
    if not result.rowcount:
        raise NotFound('Record not found.')
    db.session.expire_all()
    return db.session.query(model).filter_by(id=identity).one()


def require_match(payload):
    tag = request.headers.get('If-Match')
    if tag is None:
        raise APIError(428, 'precondition_required', 'Send the ETag from a fresh GET in If-Match.')
    expected = '"{}"'.format(sha256(jsonify(payload).get_data()).hexdigest())
    if tag != expected:
        raise APIError(412, 'precondition_failed', 'The record changed; fetch it and review your changes again.')


def record_response(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.set_etag(sha256(response.get_data()).hexdigest())
    return response


def require_edit_permission(advisories):
    # The browser also restricts reporters when a scheduled advisory exists.
    if advisories and not g.api_user.role.is_security_team:
        raise APIError(403, 'forbidden', 'Security Team membership is required to edit advisory-linked records.')


def group_advisories(group):
    return (Advisory.query.join(CVEGroupPackage)
            .filter(CVEGroupPackage.group_id == group.id).all())


def refresh_group(group, update_type=True):
    issues = [entry.cve for entry in group.issues]
    group.severity = highest_severity([cve.severity for cve in issues])
    types = set(cve.issue_type for cve in issues)
    issue_type = next(iter(types)) if len(types) == 1 else 'multiple issues'
    if issue_type not in advisory_types:
        issue_type = 'multiple issues'
    for advisory in group_advisories(group) if update_type else []:
        if advisory.publication == Publication.scheduled:
            advisory.advisory_type = issue_type


@api.errorhandler(StaleDataError)
def concurrent_write(error):
    db.session.rollback()
    return error_response(APIError(412, 'precondition_failed', 'The record changed; fetch it and review again.'))


@tracker.errorhandler(StaleDataError)
def concurrent_browser_write(error):
    from tracker.view.error import handle_error
    db.session.rollback()
    return handle_error('The record changed. Reload it and review your changes again.', 409)


@api.route('/cves/<name>', methods=['PATCH'])
@token_required(scope='cves:update')
def update_cve(name):
    data = read_json()
    if not data or set(data) - {'type', 'severity', 'vector', 'description', 'references', 'notes', 'cvss'}:
        raise APIError(422, 'validation_error', 'Supply at least one writable CVE field; name cannot be changed.')
    cve = write_lock(CVE, name)
    current = serialize_cves([cve])[0]
    require_match(current)
    groups = (CVEGroup.query.join(CVEGroupEntry)
              .filter(CVEGroupEntry.cve_id == name).order_by(CVEGroup.id).all())
    require_edit_permission([advisory for group in groups for advisory in group_advisories(group)])
    # Validate only supplied fields: legacy browser references may use FTP.
    values = validate_cve(dict(data, name=name))
    columns = {'type': 'issue_type', 'severity': 'severity', 'vector': 'remote',
               'description': 'description', 'references': 'reference', 'notes': 'notes'}
    old_type = cve.issue_type
    for field in data:
        keys = ('cvss_version', 'cvss_score', 'cvss_vector', 'cvss_source') if field == 'cvss' else (columns[field],)
        for key in keys:
            setattr(cve, key, values[key])
    for group in groups:
        refresh_group(group, update_type=old_type != cve.issue_type)
    db.session.commit()
    return record_response(serialize_cves([cve])[0])


def validate_group(data, group=None):
    from re import fullmatch

    from pyalpm import vercmp

    from tracker.api import valid_name
    from tracker.api import valid_text
    from tracker.model import Package
    from tracker.model.cvegroup import pkgname_regex
    from tracker.model.cvegroup import pkgver_regex
    from tracker.model.cvegroup import valid_bug_ticket
    from tracker.model.enum import Affected

    allowed = {'cves', 'packages', 'affected', 'fixed', 'assessment', 'bug_ticket',
               'references', 'notes', 'advisory_qualified'}
    if set(data) - allowed:
        raise APIError(422, 'validation_error', 'Unknown or read-only group fields.')
    fields = {}
    for field in ('cves', 'packages'):
        values = data.get(field)
        if not isinstance(values, list) or not values or not all(isinstance(item, str) for item in values):
            fields[field] = ['A nonempty array of identifiers is required.']
        elif field == 'cves' and not all(valid_name(item) for item in values):
            fields[field] = ['Invalid CVE identifier.']
        elif field == 'packages' and not all(len(item) <= 64 and fullmatch(pkgname_regex, item) for item in values):
            fields[field] = ['Invalid package name.']
    affected = data.get('affected')
    fixed = data.get('fixed')
    if fixed == '':
        fixed = None
    if not valid_text(affected, 32) or not fullmatch(pkgver_regex, affected):
        fields['affected'] = ['An Arch package version is required.']
    if fixed is not None and (not valid_text(fixed, 32) or not fullmatch(pkgver_regex, fixed)):
        fields['fixed'] = ['Invalid Arch package version.']
    if 'fixed' not in fields and 'affected' not in fields and fixed and vercmp(affected, fixed) >= 0:
        fields['fixed'] = ['Version must be newer than affected.']
    if data.get('assessment', 'unknown') not in ('unknown', 'affected', 'not_affected'):
        fields['assessment'] = ['Choose unknown, affected, or not_affected.']
    if not isinstance(data.get('advisory_qualified', True), bool):
        fields['advisory_qualified'] = ['Must be a boolean.']
    bug_ticket = data.get('bug_ticket', '')
    if not valid_text(bug_ticket, CVEGroup.BUG_TICKET_LENGTH) or (bug_ticket and not valid_bug_ticket(bug_ticket)):
        fields['bug_ticket'] = ['Use an Arch GitLab issue URL.']
    content = validate_content(data, fields)
    if fields:
        raise APIError(422, 'validation_error', 'Invalid group fields.', fields)
    packages = list(dict.fromkeys(data['packages']))
    known = Package.query.filter(Package.name.in_(packages)).all()
    existing = set(package.pkgname for package in group.packages) if group else set()
    missing = set(packages) - {package.name for package in known} - existing
    if missing:
        raise APIError(422, 'validation_error', 'Unknown packages: {}.'.format(', '.join(sorted(missing))))
    if len(set(package.base for package in known)) > 1:
        raise APIError(422, 'validation_error', 'All packages must share the same package base.')
    return dict(cves=list(dict.fromkeys(data['cves'])), packages=packages, affected=affected, fixed=fixed,
                assessment=Affected[data.get('assessment', 'unknown')], bug_ticket=bug_ticket,
                reference=content['reference'], notes=content['notes'],
                advisory_qualified=data.get('advisory_qualified', True))


def check_group_overlap(values, group=None):
    overlap = (CVEGroup.query.join(CVEGroupEntry).join(CVEGroupPackage)
               .filter(CVEGroupEntry.cve_id.in_(values['cves']), CVEGroupPackage.pkgname.in_(values['packages'])))
    if group:
        overlap = overlap.filter(CVEGroup.id != group.id)
    existing = overlap.first()
    if existing:
        raise APIError(409, 'already_grouped', 'A package/CVE association already exists in {}.'.format(existing.name))


def apply_group(group, values):
    cves = values.pop('cves')
    previous_cves = {entry.cve_id for entry in group.issues}
    packages = values.pop('packages')
    assessment = values.pop('assessment')
    previous_status = group.status if values['fixed'] == group.fixed else None
    for key, value in values.items():
        setattr(group, key, value)
    group.status = group_status(assessment, packages, group.fixed, previous_status)
    group.advisory_qualified = group.advisory_qualified and group.status != Status.not_affected
    for entry in list(group.issues):
        if entry.cve_id not in cves:
            group.issues.remove(entry)
    for name in cves:
        if not any(entry.cve_id == name for entry in group.issues):
            cve = CVE.query.filter_by(id=name).first()
            if cve is None:
                cve = CVE.new(name)
                db.session.add(cve)
            group.issues.append(CVEGroupEntry(cve=cve))
    for package in list(group.packages):
        if package.pkgname not in packages:
            if Advisory.query.filter_by(group_package_id=package.id).first():
                raise APIError(409, 'advisory_exists', 'Cannot remove a package with an advisory.')
            group.packages.remove(package)
    for name in packages:
        if not any(package.pkgname == name for package in group.packages):
            group.packages.append(CVEGroupPackage(pkgname=name))
    refresh_group(group, update_type=previous_cves != set(cves))


@api.route('/groups', methods=['POST'])
@token_required(scope='groups:create')
def create_group():
    from tracker.api_catalog import serialize_group
    from tracker.model.user import User

    data = read_json()
    # Acquire the SQLite write lock before duplicate checks. No user data changes.
    write_lock(User, g.api_user.id)
    values = validate_group(data)
    check_group_overlap(values)
    group = CVEGroup()
    db.session.add(group)
    with db.session.no_autoflush:
        apply_group(group, values)
    db.session.commit()
    response = record_response(serialize_group(group), 201)
    response.headers['Location'] = '/api/v1/groups/' + group.name
    return response


@api.route('/groups/<name>', methods=['PATCH'])
@token_required(scope='groups:update')
def update_group(name):
    from re import fullmatch

    from tracker.api_catalog import serialize_group

    if not fullmatch(r'AVG-[0-9]{1,18}', name):
        raise NotFound('Group not found.')
    data = read_json()
    if not data:
        raise APIError(422, 'validation_error', 'Supply at least one writable group field.')
    group = write_lock(CVEGroup, int(name[4:]))
    current = serialize_group(group)
    require_match(current)
    advisories = group_advisories(group)
    require_edit_permission(advisories)
    values = {key: current[key] for key in ('cves', 'packages', 'affected', 'fixed', 'assessment',
                                           'notes', 'advisory_qualified')}
    values.update(data)
    values = validate_group(values, group)
    if 'references' not in data:
        del values['reference']
    if 'bug_ticket' not in data:
        del values['bug_ticket']
    check_group_overlap(values, group)
    if any(advisory.group_package.pkgname not in values['packages'] for advisory in advisories):
        raise APIError(409, 'advisory_exists', 'Cannot remove a package with an advisory.')
    with db.session.no_autoflush:
        apply_group(group, values)
    db.session.commit()
    return record_response(serialize_group(group))


def serialize_draft(advisory):
    from tracker.advisory import generate_advisory

    group = advisory.group_package.group
    content = generate_advisory(advisory.id) if group.fixed and group.issues else ''
    return {'name': advisory.id, 'group': group.name, 'package': advisory.group_package.pkgname,
            'type': advisory.advisory_type, 'publication': advisory.publication.name,
            'workaround': advisory.workaround or '', 'impact': advisory.impact or '',
            'content': content, 'updated': advisory.changed.isoformat(timespec='microseconds') + 'Z'}


def get_draft(name, locked=False):
    advisory = write_lock(Advisory, name) if locked else Advisory.query.filter_by(id=name).first()
    if advisory is None:
        raise NotFound('Advisory draft not found.')
    if advisory.publication != Publication.scheduled:
        raise APIError(409, 'already_published', 'Published advisories cannot be changed through the draft API.')
    return advisory


@api.route('/groups/<name>/advisory-drafts', methods=['GET'])
@token_required(scope='advisories:write')
def list_advisory_drafts(name):
    from re import fullmatch

    if not fullmatch(r'AVG-[0-9]{1,18}', name):
        raise NotFound('Group not found.')
    group = CVEGroup.query.filter_by(id=int(name[4:])).first()
    if group is None:
        raise NotFound('Group not found.')
    drafts = (Advisory.query.join(CVEGroupPackage)
              .filter(CVEGroupPackage.group_id == group.id, Advisory.publication == Publication.scheduled)
              .order_by(CVEGroupPackage.pkgname).all())
    return record_response({'items': [serialize_draft(advisory) for advisory in drafts]})


@api.route('/groups/<name>/advisory-drafts', methods=['POST'])
@token_required(scope='advisories:write')
def create_advisory_drafts(name):
    from re import fullmatch

    from sqlalchemy.exc import IntegrityError

    from tracker.advisory import advisory_get_date_label
    from tracker.advisory import advisory_get_label
    from tracker.model.enum import Status

    if not fullmatch(r'AVG-[0-9]{1,18}', name):
        raise NotFound('Group not found.')
    data = read_json()
    if set(data) - {'type'} or ('type' in data and data['type'] not in advisory_types):
        raise APIError(422, 'validation_error', 'Only a valid advisory type can be supplied.')
    group = write_lock(CVEGroup, int(name[4:]))
    if group.status != Status.fixed or not group.fixed or not group.issues or not group.packages:
        raise APIError(409, 'group_not_fixed', 'An AVG with a reviewed fix, CVEs, and packages is required.')
    if group_advisories(group):
        raise APIError(409, 'already_exists', 'An advisory already exists for this group.')
    types = set(entry.cve.issue_type for entry in group.issues)
    default_type = next(iter(types)) if len(types) == 1 else 'multiple issues'
    if default_type not in advisory_types:
        default_type = 'multiple issues'
    label = advisory_get_date_label()
    prefix = 'ASA-{}-'.format(label)
    existing = Advisory.query.filter(Advisory.id.startswith(prefix)).all()
    number = max([int(advisory.id.rsplit('-', 1)[1]) for advisory in existing] or [0])
    drafts = []
    for package in sorted(group.packages, key=lambda package: package.pkgname):
        number += 1
        advisory = Advisory(id=advisory_get_label(label, number), group_package=package,
                            advisory_type=data.get('type', default_type), publication=Publication.scheduled)
        db.session.add(advisory)
        drafts.append(advisory)
    try:
        db.session.flush()
        response = record_response({'items': [serialize_draft(advisory) for advisory in drafts]}, 201)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise APIError(409, 'concurrent_creation', 'An advisory was created concurrently; fetch the group before retrying.')
    return response


@api.route('/advisory-drafts/<name>', methods=['GET'])
@token_required(scope='advisories:write')
def read_advisory_draft(name):
    return record_response(serialize_draft(get_draft(name)))


@api.route('/advisory-drafts/<name>', methods=['PATCH'])
@token_required(scope='advisories:write')
def update_advisory_draft(name):
    from tracker.api import valid_text

    data = read_json()
    if not data or set(data) - {'type', 'workaround', 'impact'}:
        raise APIError(422, 'validation_error', 'Supply type, workaround, or impact; publication is not writable.')
    if 'type' in data and data['type'] not in advisory_types:
        raise APIError(422, 'validation_error', 'Invalid advisory type.')
    for field in ('workaround', 'impact'):
        if field in data and not valid_text(data[field], 4096):
            raise APIError(422, 'validation_error', '{} must be Unicode text of at most 4096 characters.'.format(field))
    advisory = get_draft(name, locked=True)
    require_match(serialize_draft(advisory))
    for key, value in data.items():
        setattr(advisory, 'advisory_type' if key == 'type' else key, value)
    db.session.flush()
    response = record_response(serialize_draft(advisory))
    db.session.commit()
    return response
