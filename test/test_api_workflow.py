import pytest

from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import Package
from tracker.model.apitoken import ApiToken
from tracker.model.enum import Publication
from tracker.model.enum import Severity
from tracker.model.enum import UserRole
from tracker.model.user import User

from .conftest import DEFAULT_ISSUE_ID
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@pytest.fixture
def workflow_tokens(db):
    user = User(name='workflow', email='workflow@example.org', salt='salt', password='unused',
                role=UserRole.security_team, active=True)
    db.session.add(user)
    headers = {}
    for scope in ApiToken.SCOPES:
        token, secret = ApiToken.issue(user, scope, scope)
        db.session.add(token)
        headers[scope] = {'Authorization': 'Bearer ' + secret}
    db.session.commit()
    return headers


def match(client, path, headers):
    response = client.get(path)
    return dict(headers, **{'If-Match': response.headers['ETag']})


@create_issue
@create_group
@create_advisory
def test_cve_edit_permissions_revisions_and_group_severity(db, client, workflow_tokens):
    path = '/api/v1/cves/' + DEFAULT_ISSUE_ID
    headers = match(client, path, workflow_tokens['cves:update'])
    assert client.patch(path, json={'severity': 'high'}, headers=workflow_tokens['cves:create']).status_code == 403
    assert client.patch(path, json={'severity': 'high'}, headers=workflow_tokens['cves:update']).status_code == 428
    response = client.patch(path, json={'severity': 'high', 'type': 'information disclosure'}, headers=headers)
    assert response.status_code == 200
    assert CVEGroup.query.one().severity == Severity.high
    assert Advisory.query.one().advisory_type == 'information disclosure'
    fresh = match(client, path, workflow_tokens['cves:update'])
    assert client.patch(path, json={'type': 'unknown'}, headers=fresh).status_code == 200
    assert Advisory.query.one().advisory_type == 'multiple issues'
    assert client.patch(path, json={'notes': 'Stale change'}, headers=headers).status_code == 412
    CVE.query.one().reference = 'ftp://example.org/legacy-advisory'
    Advisory.query.one().advisory_type = 'denial of service'
    db.session.commit()
    headers = match(client, path, workflow_tokens['cves:update'])
    assert client.patch(path, json={'notes': 'Preserve unrelated fields'}, headers=headers).status_code == 200
    assert CVE.query.one().reference == 'ftp://example.org/legacy-advisory'
    assert Advisory.query.one().advisory_type == 'denial of service'
    user = User.query.filter_by(name='workflow').one()
    user.role = UserRole.reporter
    db.session.commit()
    headers = match(client, path, workflow_tokens['cves:update'])
    assert client.patch(path, json={'notes': 'Forbidden'}, headers=headers).status_code == 403


@create_issue
def test_cve_edit_detects_web_merge_without_explicit_timestamp(db, client, workflow_tokens):
    path = '/api/v1/cves/' + DEFAULT_ISSUE_ID
    headers = match(client, path, workflow_tokens['cves:update'])
    cve = CVE.query.one()
    before = cve.changed
    cve.description = 'Merged by another request'
    db.session.commit()
    assert cve.changed > before
    assert client.patch(path, json={'description': 'Stale overwrite'}, headers=headers).status_code == 412
    assert CVE.query.one().description == 'Merged by another request'


@create_package(name='foo', version='2.0-1')
def test_create_group_requires_explicit_assessment_and_detects_overlap(db, client, workflow_tokens):
    ticket = 'https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73'
    data = {'cves': [DEFAULT_ISSUE_ID], 'packages': ['foo'], 'affected': '1.0-1', 'fixed': '1.1-1',
            'bug_ticket': ticket}
    headers = workflow_tokens['groups:create']
    response = client.post('/api/v1/groups', json=data, headers=headers)
    assert response.status_code == 201
    assert response.get_json()['status'] == 'unknown'
    assert response.get_json()['bug_ticket'] == ticket
    assert CVE.query.one().id == DEFAULT_ISSUE_ID
    assert client.get(response.headers['Location']).get_json() == response.get_json()
    assert client.post('/api/v1/groups', json=data, headers=headers).status_code == 409
    assert CVEGroup.query.count() == 1
    data['cves'] = ['CVE-2026-9999']
    data['assessment'] = 'affected'
    for invalid in ('1234', ticket.replace('/foo/', '/./'), ticket.replace('/foo/', '/../')):
        data['bug_ticket'] = invalid
        assert client.post('/api/v1/groups', json=data, headers=headers).status_code == 422
    assert CVEGroup.query.count() == 1
    assert CVE.query.get('CVE-2026-9999') is None
    data['bug_ticket'] = ''
    assert client.post('/api/v1/groups', json=data, headers=headers).get_json()['status'] == 'fixed'


@create_package(name='foo', version='2.0-1')
@create_package(name='foo-doc', base='foo', version='1.0-1')
def test_group_status_covers_every_tracked_package(db, client, workflow_tokens):
    data = {'cves': [DEFAULT_ISSUE_ID], 'packages': ['foo', 'foo-doc'],
            'affected': '1.0-1', 'fixed': '2.0-1', 'assessment': 'affected'}
    response = client.post('/api/v1/groups', json=data, headers=workflow_tokens['groups:create'])
    assert response.status_code == 201
    assert response.get_json()['status'] == 'vulnerable'
    path = response.headers['Location']

    package = Package.query.filter_by(name='foo-doc').one()
    package.version = '2.0-1'
    package.database = 'extra-testing'
    db.session.commit()
    response = client.patch(path, json={'notes': 'The second package is in testing'},
                            headers=match(client, path, workflow_tokens['groups:update']))
    assert response.status_code == 200
    assert response.get_json()['status'] == 'testing'

    package.database = 'extra'
    db.session.commit()
    response = client.patch(path, json={'notes': 'Both packages have a stable fix'},
                            headers=match(client, path, workflow_tokens['groups:update']))
    assert response.status_code == 200
    assert response.get_json()['status'] == 'fixed'


@create_package(name='foo', version='2.0-1')
@create_issue
@create_group(reference='ftp://example.org/legacy-advisory', bug_ticket='1234')
def test_group_update_validates_versions_and_keeps_relationships(db, client, workflow_tokens):
    path = '/api/v1/groups/AVG-1'
    headers = match(client, path, workflow_tokens['groups:update'])
    response = client.patch(path, json={'notes': 'Keep the archived reference'}, headers=headers)
    assert response.status_code == 200
    assert response.get_json()['bug_ticket'] == '1234'
    headers = match(client, path, workflow_tokens['groups:update'])
    for invalid in ('1234', '5678'):
        assert client.patch(path, json={'bug_ticket': invalid}, headers=headers).status_code == 422
    assert client.patch(path, json={'fixed': '0.9-1'}, headers=headers).status_code == 422
    for field in ('affected', 'fixed'):
        for version in ('a' * 31 + '!', '١:1.1-1', '1.é-1', '1.1-１', '1.1/rc1-1'):
            response = client.patch(path, json={field: version}, headers=headers)
            assert response.status_code == 422
    ticket = 'https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73'
    invalid = ticket.replace('gitlab.archlinux.org', 'gitlab.archlinux.org.example.org')
    assert client.patch(path, json={'bug_ticket': invalid}, headers=headers).status_code == 422
    response = client.patch(path, json={'fixed': '1.1~rc1-1', 'assessment': 'affected',
                                       'bug_ticket': ticket}, headers=headers)
    assert response.status_code == 200
    assert response.get_json()['fixed'] == '1.1~rc1-1'
    assert response.get_json()['status'] == 'fixed'
    assert response.get_json()['bug_ticket'] == ticket
    assert response.get_json()['cves'] == [DEFAULT_ISSUE_ID]
    assert response.get_json()['references'] == ['ftp://example.org/legacy-advisory']
    assert client.patch(path, json={'notes': 'Old update'}, headers=headers).status_code == 412
    fresh = match(client, path, workflow_tokens['groups:update'])
    assert client.patch(path, json={'bug_ticket': '1234'}, headers=fresh).status_code == 422
    assert client.patch(path, json={'references': ['ftp://example.org/new']}, headers=fresh).status_code == 422
    response = client.patch(path, json={'references': ['https://example.org/fix']}, headers=fresh)
    assert response.status_code == 200
    assert response.get_json()['references'] == ['https://example.org/fix']
    fresh = match(client, path, workflow_tokens['groups:update'])
    response = client.patch(path, json={'assessment': 'not_affected'}, headers=fresh)
    assert response.status_code == 200
    assert response.get_json()['status'] == 'not_affected'
    assert response.get_json()['advisory_qualified'] is False
