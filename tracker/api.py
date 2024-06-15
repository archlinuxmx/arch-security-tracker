"""Public CVE reads and token-authenticated creation."""

import json
import re
from collections import defaultdict
from datetime import datetime
from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint
from flask import current_app
from flask import g
from flask import jsonify
from flask import request
from flask import url_for
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import NotFound
from wtforms.validators import URL

from tracker import db
from tracker.model import CVE
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.apitoken import ApiToken
from tracker.model.cve import cve_id_regex
from tracker.model.cve import issue_types
from tracker.model.enum import Remote
from tracker.model.enum import Severity

api = Blueprint('api_v1', __name__, url_prefix='/api/v1')
MAX_BODY_BYTES = 64 * 1024


class APIError(HTTPException):
    def __init__(self, status, error_code, message, fields=None):
        super().__init__(description=message)
        self.code = status
        self.error_code = error_code
        self.fields = fields


def is_api_request():
    return request.path == '/api/v1' or request.path.startswith('/api/v1/')


def error_response(error, code=None):
    """Also used by application handlers for routing-level 404/405 errors."""
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
    body = {'code': getattr(error, 'error_code', error_code), 'message': message}
    if getattr(error, 'fields', None):
        body['fields'] = error.fields
    response.set_data(json.dumps({'error': body}))
    response.content_type = 'application/json'
    response.headers['Cache-Control'] = 'no-store'
    if code == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="arch-security-tracker"'
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
    return isinstance(name, str) and len(name) <= 64 and re.fullmatch(cve_id_regex, name, re.ASCII)


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


def token_required(func=None, *, scope=ApiToken.SCOPE):
    if func is None:
        return lambda target: token_required(target, scope=scope)

    @wraps(func)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get('Authorization', '').split()
        if (len(authorization) != 2 or authorization[0].lower() != 'bearer'
                or not re.fullmatch(r'ast_[A-Za-z0-9_-]{43}', authorization[1])):
            raise APIError(401, 'unauthorized', 'A valid Bearer token is required.')
        token_hash = ApiToken.digest(authorization[1])
        token = ApiToken.query.filter_by(token_hash=token_hash).first()
        if token is not None and request.method not in ('GET', 'HEAD', 'OPTIONS'):
            # Keep revocation and authorization ordered with the ensuing write.
            table = ApiToken.__table__
            db.session.execute(table.update().where(table.c.token_hash == token_hash).values(id=table.c.id))
            db.session.expire_all()
            token = ApiToken.query.filter_by(token_hash=token_hash).first()
        if token is None or token.expires_at <= datetime.utcnow() or token.user is None:
            raise APIError(401, 'unauthorized', 'A valid Bearer token is required.')
        if not token.user.active or not token.user.role.is_reporter or token.scope != scope:
            raise APIError(403, 'forbidden', 'This token does not permit this operation.')
        if scope == 'advisories:write' and not token.user.role.is_security_team:
            raise APIError(403, 'forbidden', 'Security Team membership is required.')
        # Continuum uses this request-local actor; no browser session is created.
        g.api_user = token.user
        try:
            return func(*args, **kwargs)
        finally:
            g.pop('api_user', None)
    return wrapped


def read_json():
    if not request.is_json:
        raise APIError(415, 'unsupported_media_type', 'Content-Type must be application/json.')
    if request.content_length is not None and request.content_length > MAX_BODY_BYTES:
        raise APIError(413, 'payload_too_large', 'Request body exceeds 64 KiB.')
    raw = request.stream.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        raise APIError(413, 'payload_too_large', 'Request body exceeds 64 KiB.')
    try:
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError, RecursionError):
        raise APIError(400, 'invalid_json', 'Request body must contain valid UTF-8 JSON.')
    if not isinstance(data, dict):
        raise APIError(400, 'invalid_json', 'Request body must be a JSON object.')
    return data


def valid_text(value, max_length):
    if not isinstance(value, str) or len(value) > max_length:
        return False
    try:
        value.encode('utf-8')
    except UnicodeError:
        return False
    return True


def validate_cve(data):
    fields = {}
    allowed = {'name', 'type', 'severity', 'vector', 'description', 'references', 'notes'}
    for name in sorted(set(data) - allowed):
        fields[name] = ['Unknown or read-only field.']
    if not valid_name(data.get('name')):
        fields['name'] = ['A CVE identifier of at most 64 characters is required.']
    for name, choices in [('type', issue_types), ('severity', Severity.__members__), ('vector', Remote.__members__)]:
        value = data.get(name, 'unknown')
        if not isinstance(value, str) or value not in choices:
            fields[name] = ['Must be one of: {}.'.format(', '.join(choices))]
    for name, length in [('description', CVE.DESCRIPTION_LENGTH), ('notes', CVE.NOTES_LENGTH)]:
        value = data.get(name, '')
        if not valid_text(value, length):
            fields[name] = ['Must be valid Unicode text of at most {} characters.'.format(length)]
    references = data.get('references', [])
    if not isinstance(references, list) or any(not isinstance(ref, str) for ref in references):
        fields['references'] = ['Must be an array of HTTP(S) URL strings.']
    else:
        url_pattern = URL().regex
        for ref in references:
            try:
                parsed = urlsplit(ref)
                valid = (valid_text(ref, CVE.REFERENCES_LENGTH)
                         and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in ref)
                         and parsed.scheme in ('http', 'https') and parsed.hostname
                         and (parsed.port is None or parsed.port <= 65535) and url_pattern.fullmatch(ref))
            except ValueError:
                valid = False
            if not valid:
                fields['references'] = ['Every reference must be an HTTP(S) URL without whitespace.']
                break
        references = list(dict.fromkeys(references))
        if len('\n'.join(references)) > CVE.REFERENCES_LENGTH:
            fields['references'] = ['Joined references must not exceed {} characters.'.format(CVE.REFERENCES_LENGTH)]
    if fields:
        raise APIError(422, 'validation_error', 'Invalid CVE fields.', fields)
    return dict(id=data['name'], issue_type=data.get('type', 'unknown'),
                severity=Severity[data.get('severity', 'unknown')],
                remote=Remote[data.get('vector', 'unknown')], description=data.get('description', ''),
                reference='\n'.join(references), notes=data.get('notes', ''))


@api.route('/cves', methods=['POST'])
@token_required
def create_cve():
    values = validate_cve(read_json())
    name = values['id']
    if CVE.query.filter_by(id=name).first() is not None:
        raise APIError(409, 'already_exists', 'This CVE already exists; no fields were changed.')
    cve = CVE(**values)
    db.session.add(cve)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # A concurrent web/API request may have inserted this identifier.
        if CVE.query.filter_by(id=name).first() is not None:
            raise APIError(409, 'already_exists', 'This CVE already exists; no fields were changed.')
        raise
    response = jsonify(serialize_cves([cve])[0])
    response.status_code = 201
    response.headers['Location'] = url_for('api_v1.get_cve', name=name)
    return response
