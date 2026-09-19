from datetime import timedelta
from re import search

import pytest

from tracker.model.apitoken import ApiToken
from tracker.model.enum import UserRole
from tracker.model.user import User

from .conftest import DEFAULT_USERNAME
from .conftest import create_user
from .conftest import logged_in


@logged_in(role=UserRole.reporter)
def test_token_creation_and_revocation(db, client, app, monkeypatch):
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    page = client.get('/tokens')
    csrf = search(r'name="csrf_token"[^>]*value="([^"]+)"', page.data.decode()).group(1)
    assert client.post('/tokens', data={'name': 'Mail ingestion'}).status_code == 400
    assert ApiToken.query.count() == 0

    response = client.post('/tokens', data={'name': '  Mail ingestion  ', 'scope': 'cves:create',
                                            'csrf_token': csrf})
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    secret = search(r'<code id="new-api-token">(ast_[^<]+)</code>', response.data.decode()).group(1)
    token = ApiToken.query.one()
    assert token.name == 'Mail ingestion'
    assert token.token_hash == ApiToken.digest(secret)
    assert token.scope == 'cves:create'
    assert token.expires_at - token.created == timedelta(days=90)
    assert secret not in repr(db.session.execute(ApiToken.__table__.select()).first())
    with client.session_transaction() as session:
        assert secret not in repr(dict(session))
    assert secret.encode() not in client.get('/tokens').data

    assert client.post('/tokens/' + '9' * 30 + '/revoke').status_code == 404
    revoke_url = '/tokens/{}/revoke'.format(token.id)
    assert client.get(revoke_url).status_code == 405
    assert client.post(revoke_url).status_code == 400
    assert ApiToken.query.count() == 1
    assert client.post(revoke_url, data={'csrf_token': csrf}).status_code == 302
    assert ApiToken.query.count() == 0


@pytest.mark.parametrize('role,active', [(UserRole.guest, True), (UserRole.reporter, False)])
@logged_in
def test_token_permissions(db, client, role, active):
    user = User.query.one()
    user.role = role
    user.active = active
    db.session.commit()
    assert client.get('/tokens').status_code == 403
    assert client.post('/tokens', data={'name': 'Disallowed'}).status_code == 403
    assert client.post('/tokens/1/revoke').status_code == 403
    assert ApiToken.query.count() == 0

    client.post('/logout')
    assert client.get('/tokens').status_code == 302
    assert client.post('/tokens', data={'name': 'Anonymous'}).status_code == 302
    assert ApiToken.query.count() == 0


@create_user(username='other-reporter')
@logged_in(role=UserRole.reporter)
def test_token_ownership_and_user_deletion(db, client):
    own = User.query.filter_by(name=DEFAULT_USERNAME).one()
    other = User.query.filter_by(name='other-reporter').one()
    own_token, _ = ApiToken.issue(own, 'Own token')
    other_token, _ = ApiToken.issue(other, 'Other token')
    db.session.add_all([own_token, other_token])
    db.session.commit()

    page = client.get('/tokens')
    assert b'Own token' in page.data
    assert b'Other token' not in page.data
    assert client.post('/tokens/{}/revoke'.format(other_token.id)).status_code == 404
    assert ApiToken.query.count() == 2
    db.session.delete(other)
    db.session.commit()
    assert ApiToken.query.one().id == own_token.id
