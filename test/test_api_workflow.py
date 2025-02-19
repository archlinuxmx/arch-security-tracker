import pytest

from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
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
