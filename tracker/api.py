"""Public CVE read endpoints."""

import json
import re
from collections import defaultdict

from flask import Blueprint
from flask import current_app
from flask import jsonify
from flask import request
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import NotFound

from tracker import db
from tracker.model import CVE
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.cve import cve_id_regex

api = Blueprint('api_v1', __name__, url_prefix='/api/v1')


def is_api_request():
    return request.path == '/api/v1' or request.path.startswith('/api/v1/')


def error_response(error, code=None):
    """Keep routing errors in JSON too, preserving headers such as Allow."""
    if isinstance(error, HTTPException):
        code = error.code
        response = error.get_response()
        message = error.description
        error_code = error.name.lower().replace(' ', '_')
    else:
        code = code or 500
        response = current_app.response_class(status=code)
        message = str(error)
        error_code = {404: 'not_found', 405: 'method_not_allowed'}.get(code, 'request_failed')
    if code >= 500:
        message = 'An internal error occurred.'
        error_code = 'internal_error'
    response.set_data(json.dumps({'error': {'code': error_code, 'message': message}}))
    response.content_type = 'application/json'
    response.headers['Cache-Control'] = 'no-store'
    return response


@api.errorhandler(HTTPException)
def handle_http_error(error):
    return error_response(error)


@api.errorhandler(Exception)
def handle_internal_error(error):
    db.session.rollback()
    current_app.logger.exception('CVE API request failed')
    return error_response(error, 500)


@api.after_request
def no_cache(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


def valid_name(name):
    return len(name) <= 64 and re.fullmatch(cve_id_regex, name, re.ASCII)


def serialize_cves(cves):
    """Fetch group and package links for the whole page in one query."""
    groups = defaultdict(set)
    packages = defaultdict(set)
    if cves:
        links = (db.session.query(CVEGroupEntry.cve_id, CVEGroupEntry.group_id, CVEGroupPackage.pkgname)
                 .outerjoin(CVEGroupPackage, CVEGroupPackage.group_id == CVEGroupEntry.group_id)
                 .filter(CVEGroupEntry.cve_id.in_([cve.id for cve in cves])).all())
        for cve_id, group_id, pkgname in links:
            groups[cve_id].add('AVG-{}'.format(group_id))
            if pkgname:
                packages[cve_id].add(pkgname)
    return [{
        'name': cve.id,
        'type': cve.issue_type or 'unknown',
        'severity': cve.severity.name,
        'vector': cve.remote.name,
        'description': cve.description or '',
        'references': cve.reference.splitlines() if cve.reference else [],
        'notes': cve.notes or '',
        'groups': sorted(groups[cve.id]),
        'packages': sorted(packages[cve.id]),
        'created': cve.created.isoformat(timespec='microseconds') + 'Z',
        'updated': cve.changed.isoformat(timespec='microseconds') + 'Z',
    } for cve in cves]


@api.route('/cves', methods=['GET'])
def list_cves():
    if (set(request.args) - {'limit', 'after'}
            or any(len(values) != 1 for key, values in request.args.lists())):
        raise BadRequest('Only one limit and one after parameter are accepted.')
    raw_limit = request.args.get('limit', '50')
    if not re.fullmatch(r'[0-9]{1,3}', raw_limit) or not 1 <= int(raw_limit) <= 100:
        raise BadRequest('limit must be an integer between 1 and 100.')
    limit = int(raw_limit)
    query = CVE.query.order_by(CVE.id)
    after = request.args.get('after')
    if after is not None:
        if not valid_name(after):
            raise BadRequest('after must be a CVE identifier.')
        query = query.filter(CVE.id > after)
    rows = query.limit(limit + 1).all()
    return jsonify(items=serialize_cves(rows[:limit]),
                   next_cursor=rows[limit - 1].id if len(rows) > limit else None)


@api.route('/cves/<name>', methods=['GET'])
def get_cve(name):
    cve = CVE.query.filter_by(id=name).first() if valid_name(name) else None
    if cve is None:
        raise NotFound('CVE not found.')
    return jsonify(serialize_cves([cve])[0])
