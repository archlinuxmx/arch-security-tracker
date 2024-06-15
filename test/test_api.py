from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from datetime import timedelta
from threading import Event
from threading import local

import pytest
from sqlalchemy import event
from sqlalchemy_continuum import version_class

from tracker import create_app
from tracker.model.apitoken import ApiToken
from tracker.model.cve import CVE
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import UserRole
from tracker.model.user import User

from .conftest import DEFAULT_ISSUE_ID
from .conftest import create_group
from .conftest import create_issue
from .conftest import logged_in

COLLECTION = '/api/v1/cves'


@pytest.fixture
def api_token(db):
    user = User(name='api-reporter', email='api@example.org', salt='test-salt',
                password='unused', role=UserRole.reporter, active=True)
    db.session.add(user)
    db.session.flush()
    token, secret = ApiToken.issue(user, 'Mail ingestion')
    db.session.add(token)
    db.session.commit()
    return token, {'Authorization': 'Bearer {}'.format(secret)}


def test_empty_collection(client):
    response = client.get(COLLECTION)
    assert response.status_code == 200
    assert response.get_json() == {'items': [], 'next_cursor': None}


@create_issue(description='Description', notes='Notes',
              issue_type='information disclosure', severity=Severity.high,
              remote=Remote.remote, reference='https://example.org/advisory\nhttps://example.org/fix')
def test_public_orphan_cve(db, client):
    # Older web-created records may have unset text fields.
    unset = CVE.new('CVE-2016-1338')
    unset.issue_type = unset.description = unset.notes = unset.reference = None
    db.session.add(unset)
    db.session.commit()

    response = client.get('{}/{}'.format(COLLECTION, DEFAULT_ISSUE_ID))
    assert response.status_code == 200
    record = response.get_json()
    assert record['name'] == DEFAULT_ISSUE_ID
    assert record['type'] == 'information disclosure'
    assert record['severity'] == 'high'
    assert record['vector'] == 'remote'
    assert record['description'] == 'Description'
    assert record['notes'] == 'Notes'
    assert record['references'] == ['https://example.org/advisory', 'https://example.org/fix']
    assert record['groups'] == record['packages'] == []
    for field in ('created', 'updated'):
        assert record[field].endswith('Z')
        datetime.fromisoformat(record[field].replace('Z', '+00:00'))
    unset_record = client.get(COLLECTION + '/CVE-2016-1338').get_json()
    assert unset_record['type'] == 'unknown'
    assert unset_record['description'] == unset_record['notes'] == ''
    assert unset_record['references'] == []
    assert client.get(COLLECTION).get_json() == {'items': [record, unset_record], 'next_cursor': None}


@create_issue
@create_group(id=42, packages=['foo', 'foo-doc'])
@create_group(id=43, packages=['foo'])
def test_group_and_package_references(db, client):
    record = client.get('{}/{}'.format(COLLECTION, DEFAULT_ISSUE_ID)).get_json()
    assert record['groups'] == ['AVG-42', 'AVG-43']
    assert record['packages'] == ['foo', 'foo-doc']
    assert client.get(COLLECTION).get_json()['items'] == [record]


def test_cursor_pagination(db, client):
    names = ['CVE-2024-{:04d}'.format(number) for number in range(105)]
    names.append('CVE-2024-000012345678')
    for name in reversed(names):
        db.session.add(CVE.new(name))
    db.session.commit()

    first = client.get(COLLECTION).get_json()
    assert len(first['items']) == 50
    assert first['next_cursor'] == first['items'][-1]['name']
    seen = [item['name'] for item in first['items']]
    cursor = first['next_cursor']
    while cursor:
        page = client.get(COLLECTION, query_string={'after': cursor, 'limit': 17}).get_json()
        assert 0 < len(page['items']) <= 17
        seen.extend(item['name'] for item in page['items'])
        cursor = page['next_cursor']
    assert seen == sorted(names)
    assert len(client.get(COLLECTION, query_string={'limit': 100}).get_json()['items']) == 100
    assert client.get(COLLECTION, query_string={'after': seen[-1]}).get_json() == {
        'items': [], 'next_cursor': None,
    }


def test_invalid_pagination(client):
    for query in ({'limit': 0}, {'limit': 101}, {'limit': 'many'}, {'after': 'not-a-cve'},
                  {'after': 'CVE-2024-0001\n'}, {'unknown': 'value'},
                  [('limit', '1'), ('limit', '2')]):
        response = client.get(COLLECTION, query_string=query)
        assert response.status_code == 400
        assert response.get_json()['error']['code'] == 'bad_request'


def test_api_errors_are_json(client, monkeypatch):
    for path in ('/api/v1/missing', COLLECTION + '/CVE-2024-0001', COLLECTION + '/invalid'):
        response = client.get(path)
        assert response.status_code == 404
        assert response.get_json()['error']['code'] == 'not_found'
    response = client.put(COLLECTION)
    assert response.status_code == 405
    assert response.get_json()['error']['code'] == 'method_not_allowed'
    assert 'GET' in response.headers['Allow']

    def fail(cves):
        raise RuntimeError('Internal database details')

    monkeypatch.setattr('tracker.api.serialize_cves', fail)
    response = client.get(COLLECTION)
    assert response.status_code == 500
    assert response.get_json() == {
        'error': {'code': 'internal_error', 'message': 'An internal error occurred.'},
    }


@logged_in(username='browser-administrator')
def test_create_cve_and_audit_owner(db, client, app, api_token, monkeypatch):
    token, headers = api_token
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    with client.session_transaction() as session:
        browser_login = session['_user_id']

    response = client.post(COLLECTION, json={'name': DEFAULT_ISSUE_ID}, headers=headers)
    assert response.status_code == 201
    record = response.get_json()
    assert record['name'] == DEFAULT_ISSUE_ID
    assert record['type'] == record['severity'] == record['vector'] == 'unknown'
    assert record['description'] == record['notes'] == ''
    assert record['references'] == record['groups'] == record['packages'] == []
    assert client.get(response.headers['Location']).get_json() == record
    assert db.session.query(version_class(CVE)).one().transaction.user_id == token.user_id
    with client.session_transaction() as session:
        assert session['_user_id'] == browser_login


@logged_in
def test_create_requires_valid_token_and_current_permissions(db, client, api_token):
    token, headers = api_token
    payload = {'name': DEFAULT_ISSUE_ID}
    response = client.post(COLLECTION, json=payload)
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'].startswith('Bearer')

    for owner, field, value in [(token.user, 'active', False), (token.user, 'role', UserRole.guest),
                                (token, 'scope', 'other')]:
        original = getattr(owner, field)
        setattr(owner, field, value)
        db.session.commit()
        assert client.post(COLLECTION, json=payload, headers=headers).status_code == 403
        setattr(owner, field, original)
        db.session.commit()

    token.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert client.post(COLLECTION, json=payload, headers=headers).status_code == 401
    db.session.delete(token)
    db.session.commit()
    assert client.post(COLLECTION, json=payload, headers=headers).status_code == 401
    assert CVE.query.count() == 0


@create_issue(description='Existing description', notes='Human triage', severity=Severity.high)
def test_create_conflict_preserves_existing_cve(db, client, api_token):
    _, headers = api_token
    before = client.get('{}/{}'.format(COLLECTION, DEFAULT_ISSUE_ID)).get_json()
    response = client.post(COLLECTION, json={'name': DEFAULT_ISSUE_ID, 'description': 'Replacement'}, headers=headers)
    assert response.status_code == 409
    assert response.get_json()['error']['code'] == 'already_exists'
    assert client.get('{}/{}'.format(COLLECTION, DEFAULT_ISSUE_ID)).get_json() == before
    assert db.session.query(version_class(CVE)).count() == 1


def test_create_rejects_invalid_requests(db, client, api_token):
    _, headers = api_token
    for payload in ({'name': None}, {'name': 'CVE-2025-0001\n'}, {'name': DEFAULT_ISSUE_ID, 'groups': []}):
        response = client.post(COLLECTION, json=payload, headers=headers)
        assert response.status_code == 422
        assert response.get_json()['error']['code'] == 'validation_error'
    assert client.post(COLLECTION, data='{}', headers=headers).status_code == 415
    assert client.post(COLLECTION, data='{"name":', content_type='application/json', headers=headers).status_code == 400
    assert client.post(COLLECTION, data='x' * 65537, content_type='application/json', headers=headers).status_code == 413
    assert CVE.query.count() == 0


def test_create_cve_metadata(db, client, api_token):
    _, headers = api_token
    payload = {
        'name': 'CVE-2026-123456789',
        'type': 'information disclosure',
        'severity': 'high',
        'vector': 'remote',
        'description': 'First paragraph.\n\nSecond paragraph: café.',
        'notes': 'Needs package investigation.',
        'references': ['https://example.org/advisory', 'https://example.org/fix', 'https://example.org/advisory'],
    }
    response = client.post(COLLECTION, json=payload, headers=headers)
    assert response.status_code == 201
    expected = dict(payload, references=payload['references'][:2])
    assert {field: response.get_json()[field] for field in expected} == expected
    assert client.get(response.headers['Location']).get_json() == response.get_json()
    assert CVE.query.one().reference == '\n'.join(expected['references'])


def test_invalid_metadata_is_atomic(db, client, api_token):
    _, headers = api_token
    reference = 'https://example.org/' + 'x' * (2048 - len('https://example.org/'))
    for fields in ({'severity': 'High'}, {'description': 'x' * 4097}, {'notes': None},
                   {'description': '\ud800'}, {'references': ['javascript:alert(1)']},
                   {'references': ['https://user@/']}, {'references': ['https://example.org:999999/']},
                   {'references': [reference, reference[:-1] + 'y']}):
        payload = dict({'name': DEFAULT_ISSUE_ID}, **fields)
        response = client.post(COLLECTION, json=payload, headers=headers)
        assert response.status_code == 422
        assert next(iter(fields)) in response.get_json()['error']['fields']
    assert CVE.query.count() == 0
    assert db.session.query(version_class(CVE)).count() == 0


@pytest.mark.parametrize('action, expected', [('demote', 403), ('disable', 403), ('revoke', 401)])
def test_api_creation_rechecks_revoked_permission(db, tmp_path, action, expected):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'api.sqlite'),
                      'TESTING': True, 'WTF_CSRF_ENABLED': False, 'SERVER_NAME': 'cyber.local'})
    with app.app_context():
        db.create_all()
        user = User(name='api', email='api@example.org', password='unused', salt='salt',
                    role=UserRole.reporter, active=True)
        token, secret = ApiToken.issue(user, 'Concurrent request')
        db.session.add_all([user, token])
        db.session.commit()
        user_id, token_id, engine = user.id, token.id, db.engine

    ready, revoked, worker = Event(), Event(), local()

    def before_write(connection, cursor, statement, parameters, context, executemany):
        if getattr(worker, 'creating', False) and statement.startswith(('INSERT ', 'UPDATE ', 'DELETE ')):
            worker.creating = False
            ready.set()
            assert revoked.wait(timeout=5)

    def create():
        worker.creating = True
        return app.test_client().post(COLLECTION, json={'name': 'CVE-2026-1234'},
                                      headers={'Authorization': 'Bearer ' + secret})

    event.listen(engine, 'before_cursor_execute', before_write)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(create)
            try:
                assert ready.wait(timeout=5)
                with app.app_context():
                    if action == 'revoke':
                        db.session.delete(ApiToken.query.filter_by(id=token_id).one())
                    else:
                        user = User.query.filter_by(id=user_id).one()
                        if action == 'demote':
                            user.role = UserRole.guest
                        else:
                            user.active = False
                    db.session.commit()
            finally:
                revoked.set()
            assert pending.result().status_code == expected
        with app.app_context():
            assert CVE.query.count() == 0
    finally:
        event.remove(engine, 'before_cursor_execute', before_write)
        engine.dispose()
