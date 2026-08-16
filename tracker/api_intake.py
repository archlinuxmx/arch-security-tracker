"""Private submissions from external ingestion tools."""

import json
import re
from hashlib import sha256

from flask import g
from flask import jsonify
from flask import request
from flask import url_for
from sqlalchemy.exc import IntegrityError

from tracker import db
from tracker.api import APIError
from tracker.api import api
from tracker.api import read_json
from tracker.api import token_required
from tracker.api import valid_name
from tracker.api import valid_text
from tracker.api import validate_content
from tracker.model.review import IntakeCandidate
from tracker.model.review import ReviewEvent


def intake_values(data):
    allowed = {'title', 'source', 'cve_name', 'evidence', 'description', 'references'}
    fields = {name: ['Unknown or read-only field.'] for name in sorted(set(data) - allowed)}
    for name, maximum in (('title', 255), ('source', 2048), ('evidence', 65536)):
        value = data.get(name, '')
        if not valid_text(value, maximum) or (name != 'evidence' and not value.strip()):
            fields[name] = ['Must be valid text of at most {} characters{}.'.format(
                maximum, ', and must not be empty' if name != 'evidence' else '')]
    cve_name = data.get('cve_name')
    if cve_name is not None and not valid_name(cve_name):
        fields['cve_name'] = ['Must be a CVE identifier or null.']
    public = validate_content(data, fields)
    if fields:
        raise APIError(422, 'validation_error', 'Invalid intake fields.', fields)
    return dict(title=data['title'].strip(), source=data['source'].strip(), cve_name=cve_name,
                evidence=data.get('evidence', ''), description=public['description'], reference=public['reference'])


def intake_response(candidate, status):
    location = url_for('tracker.review_intake_detail', candidate_id=candidate.id)
    response = jsonify(id=candidate.id, state=candidate.state, revision=candidate.revision,
                       cve_name=candidate.cve_name, promoted_cve=candidate.promoted_cve,
                       review_url=location, created=candidate.created.isoformat(timespec='microseconds') + 'Z')
    response.status_code = status
    response.headers['Location'] = location
    return response


def repeated_submission(candidate, payload_hash):
    if candidate.ingestion_hash != payload_hash:
        raise APIError(409, 'idempotency_conflict', 'This key was already used for different intake content.')
    return intake_response(candidate, 200)


@api.route('/intake', methods=['POST'])
@token_required(scope='intake:create')
def create_intake():
    key = request.headers.get('Idempotency-Key', '')
    if not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', key):
        raise APIError(400, 'invalid_idempotency_key', 'Supply an Idempotency-Key using 1–128 letters, digits, dots, underscores, colons or hyphens.')
    values = intake_values(read_json())
    ingestion_key = sha256(key.encode()).hexdigest()
    owner_id = g.api_user.id
    payload_hash = sha256(json.dumps(values, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    existing = IntakeCandidate.query.filter_by(ingestion_user_id=owner_id, ingestion_key=ingestion_key).first()
    if existing:
        return repeated_submission(existing, payload_hash)
    candidate = IntakeCandidate(**values, ingestion_user_id=owner_id, ingestion_key=ingestion_key, ingestion_hash=payload_hash)
    db.session.add(candidate)
    try:
        db.session.flush()
        db.session.add(ReviewEvent(target='INTAKE-{}'.format(candidate.id), action='intake-added',
                                   rationale='Added for review', revision=str(candidate.revision), user_id=g.api_user.id))
        response = intake_response(candidate, 201)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = IntakeCandidate.query.filter_by(ingestion_user_id=owner_id, ingestion_key=ingestion_key).first()
        if existing is None:
            raise
        return repeated_submission(existing, payload_hash)
    return response
