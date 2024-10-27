"""Token-authenticated CVE edits."""

from hashlib import sha256

from flask import g
from flask import jsonify
from flask import request
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.exceptions import NotFound

from tracker import db
from tracker.api import APIError
from tracker.api import api
from tracker.api import error_response
from tracker.api import read_json
from tracker.api import serialize_cves
from tracker.api import token_required
from tracker.api import validate_cve
from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model.cvegroup import group_advisories
from tracker.model.cvegroup import refresh_group


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
