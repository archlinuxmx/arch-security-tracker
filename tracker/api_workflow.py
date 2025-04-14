"""Token-authenticated CVE and group edits."""

from hashlib import sha256
from re import fullmatch

from flask import g
from flask import jsonify
from flask import request
from flask import url_for
from pyalpm import vercmp
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.exceptions import NotFound

from tracker import db
from tracker.api import APIError
from tracker.api import api
from tracker.api import error_response
from tracker.api import read_json
from tracker.api import serialize_cves
from tracker.api import token_required
from tracker.api import valid_name
from tracker.api import valid_text
from tracker.api import validate_content
from tracker.api import validate_cve
from tracker.api_catalog import serialize_group
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.cvegroup import group_advisories
from tracker.model.cvegroup import pkgname_regex
from tracker.model.cvegroup import pkgver_regex
from tracker.model.cvegroup import refresh_group
from tracker.model.cvegroup import valid_bug_ticket
from tracker.model.enum import Affected
from tracker.model.enum import Status
from tracker.model.enum import group_status
from tracker.model.user import User


def write_lock(model, identity):
    """Lock before reading: SQLite also serializes relationship writes here."""
    if not db.lock(model, model.id == identity):
        raise NotFound('Record not found.')
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


@api.errorhandler(StaleDataError)
def concurrent_write(error):
    db.session.rollback()
    return error_response(APIError(412, 'precondition_failed', 'The record changed; fetch it and review again.'))


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
    for field, column in columns.items():
        if field in data:
            setattr(cve, column, values[column])
    if 'cvss' in data:
        for column in ('cvss_version', 'cvss_score', 'cvss_vector', 'cvss_source'):
            setattr(cve, column, values[column])
    for group in groups:
        refresh_group(group, update_type=old_type != cve.issue_type)
    db.session.commit()
    return record_response(serialize_cves([cve])[0])


def validate_group(data, group=None):
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
    fixed = data.get('fixed') or None
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
    response.headers['Location'] = url_for('api_v1.get_group', name=group.name)
    return response


@api.route('/groups/<name>', methods=['PATCH'])
@token_required(scope='groups:update')
def update_group(name):
    if not fullmatch(r'AVG-[0-9]+', name):
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
