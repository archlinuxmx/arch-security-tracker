from re import findall
from re import search

import pytest

from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model.apitoken import ApiToken
from tracker.model.enum import UserRole
from tracker.model.user import User

from .conftest import DEFAULT_ISSUE_ID
from .conftest import create_group
from .conftest import create_package
from .conftest import create_user
from .conftest import logged_in


@create_package(name='foo', version='2.0-1')
@logged_in(role=UserRole.reporter)
def test_combined_token_creates_cve_and_group_without_other_permissions(db, client):
    response = client.post('/tokens', data={'name': 'Importer',
                                            'scope': ['groups:create', 'cves:create']})
    assert response.status_code == 200
    secret = search(r'<code id="new-api-token">(ast_[^<]+)</code>', response.data.decode()).group(1)
    token = ApiToken.query.one()
    assert token.scopes == ('cves:create', 'groups:create')
    headers = {'Authorization': 'Bearer ' + secret}

    response = client.post('/api/v1/cves', json={'name': DEFAULT_ISSUE_ID}, headers=headers)
    assert response.status_code == 201
    response = client.post('/api/v1/groups', headers=headers, json={
        'cves': [DEFAULT_ISSUE_ID], 'packages': ['foo'], 'affected': '1.0-1',
        'fixed': '2.0-1', 'assessment': 'affected',
    })
    assert response.status_code == 201
    group = response.get_json()['name']
    for path in ('/api/v1/cves/' + DEFAULT_ISSUE_ID, '/api/v1/groups/' + group):
        assert client.patch(path, json={'notes': 'Not allowed'}, headers=headers).status_code == 403
    assert client.post('/api/v1/intake', json={}, headers=headers).status_code == 403
    assert client.get('/api/v1/groups/' + group + '/advisory-drafts', headers=headers).status_code == 403
    assert CVE.query.one().notes == ''
    assert CVEGroup.query.one().notes == ''


@logged_in(role=UserRole.reporter)
def test_scope_selection_requires_explicit_permitted_choices(db, client):
    page = client.get('/tokens').data.decode()
    assert 'value="advisories:write"' not in page
    checkboxes = findall(r'<input[^>]*type="checkbox"[^>]*>', page)
    assert len(checkboxes) == 5
    assert all('required' not in checkbox for checkbox in checkboxes)
    assert [search(r'value="([^"]+)"', checkbox).group(1)
            for checkbox in checkboxes if 'checked' in checkbox] == ['cves:create']
    for scopes in (None, [], ['unknown'], ['cves:create', 'unknown'], ['cves:create', 'advisories:write']):
        data = {'name': 'Invalid selection'}
        if scopes is not None:
            data['scope'] = scopes
        assert client.post('/tokens', data=data).status_code == 400
        assert ApiToken.query.count() == 0


@create_user(role=UserRole.security_team)
@create_group
def test_combined_token_rechecks_current_account_permissions(db, client):
    user = User.query.one()
    token, secret = ApiToken.issue(user, 'Security automation', ['cves:create', 'advisories:write'])
    db.session.add(token)
    db.session.commit()
    headers = {'Authorization': 'Bearer ' + secret}
    path = '/api/v1/groups/AVG-1/advisory-drafts'
    assert client.get(path, headers=headers).status_code == 200

    user.role = UserRole.reporter
    db.session.commit()
    assert client.get(path, headers=headers).status_code == 403
    assert client.post('/api/v1/cves', json={'name': 'CVE-2026-12345'}, headers=headers).status_code == 201

    user.active = False
    db.session.commit()
    assert client.post('/api/v1/cves', json={'name': 'CVE-2026-12346'}, headers=headers).status_code == 403
    assert CVE.query.filter_by(id='CVE-2026-12346').first() is None


@create_user(role=UserRole.reporter)
def test_scope_validation_rejects_invalid_or_forbidden_grants(db):
    user = User.query.one()
    for scopes in ([], (), set(), '', None, ['unknown'], ['cves:create', 'unknown'],
                   ['cves:create', 'advisories:write']):
        with pytest.raises(ValueError):
            ApiToken.issue(user, 'Invalid grant', scopes)
    for scopes in (['groups:create', 'cves:create', 'groups:create'],
                   ('groups:create', 'cves:create'), {'groups:create', 'cves:create'}):
        token, _ = ApiToken.issue(user, 'Importer', scopes)
        assert token.scopes == ('cves:create', 'groups:create')
        assert token.has_scope('groups:create')
        assert not token.has_scope('create')
        assert not token.has_scope('groups')
        assert not token.has_scope('groups:update')


@create_user(role=UserRole.reporter)
def test_invalid_stored_scopes_fail_closed(db, client):
    token, secret = ApiToken.issue(User.query.one(), 'Importer', ['cves:create', 'groups:create'])
    db.session.add(token)
    db.session.commit()
    headers = {'Authorization': 'Bearer ' + secret}
    for value in ('', 'cves:create-other', 'cves:create unknown'):
        token.scope = value
        db.session.commit()
        assert client.post('/api/v1/cves', json={'name': DEFAULT_ISSUE_ID}, headers=headers).status_code == 403
    assert CVE.query.count() == 0
