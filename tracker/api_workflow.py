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
from tracker.api import validate_cve
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.advisory import advisory_types
from tracker.model.enum import Publication
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
