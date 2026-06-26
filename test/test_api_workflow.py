import pytest

from tracker.advisory import generate_advisory
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import Package
from tracker.model.apitoken import ApiToken
from tracker.model.enum import Publication
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.enum import UserRole
from tracker.model.user import User
from tracker.user import hash_password

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
@create_package(name='foo-doc', base='foo', version='2.0-1')
@create_issue
@create_group(packages=['foo', 'foo-doc'], reference='ftp://example.org/legacy-advisory', bug_ticket='1234')
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
    for name in ('foo', 'foo-doc'):
        db.session.delete(Package.query.filter_by(name=name).one())
        db.session.commit()
        fresh = match(client, path, workflow_tokens['groups:update'])
        response = client.patch(path, json={'notes': name + ' removed'}, headers=fresh)
        assert response.status_code == 200
        assert response.get_json()['status'] == 'fixed'
    CVEGroup.query.one().status = Status.testing
    db.session.commit()
    fresh = match(client, path, workflow_tokens['groups:update'])
    response = client.patch(path, json={'notes': 'Keep last known status'}, headers=fresh)
    assert response.status_code == 200
    assert response.get_json()['status'] == 'testing'
    fresh = match(client, path, workflow_tokens['groups:update'])
    response = client.patch(path, json={'fixed': None}, headers=fresh)
    assert response.status_code == 200
    assert response.get_json()['status'] == 'vulnerable'
    fresh = match(client, path, workflow_tokens['groups:update'])
    response = client.patch(path, json={'assessment': 'not_affected'}, headers=fresh)
    assert response.status_code == 200
    assert response.get_json()['status'] == 'not_affected'
    assert response.get_json()['advisory_qualified'] is False


@create_package(name='foo', version='2.0-1')
@create_issue(description='The issue description', severity=Severity.high)
@create_issue(id='CVE-2026-0001', issue_type='information disclosure')
@create_group(fixed='1.1-1', issues=[DEFAULT_ISSUE_ID, 'CVE-2026-0001'],
              bug_ticket='https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73')
def test_advisory_drafts_generate_content_without_publishing(db, client, workflow_tokens, monkeypatch):
    headers = workflow_tokens['advisories:write']
    collection = '/api/v1/groups/AVG-1/advisory-drafts'
    assert client.get(collection).status_code == 401
    assert client.get(collection, headers=workflow_tokens['cves:create']).status_code == 403
    assert client.get(collection, headers=headers).get_json() == {'items': []}
    for name in ('AVG-2', 'AVG-' + '9' * 19, 'invalid'):
        assert client.get('/api/v1/groups/' + name + '/advisory-drafts', headers=headers).status_code == 404
    CVE.query.filter_by(id=DEFAULT_ISSUE_ID).one().issue_type = None
    db.session.commit()

    def failed_render(*args, **kwargs):
        raise RuntimeError('Unable to render draft')

    with monkeypatch.context() as patch:
        patch.setattr('tracker.advisory.generate_advisory', failed_render)
        response = client.post('/api/v1/groups/AVG-1/advisory-drafts', json={}, headers=headers)
        assert response.status_code == 500
        assert Advisory.query.count() == 0
    response = client.post('/api/v1/groups/AVG-1/advisory-drafts', json={}, headers=headers)
    assert response.status_code == 201
    listing = client.get(collection, headers=headers)
    assert listing.status_code == 200
    assert listing.get_json() == response.get_json()
    assert 'no-store' in listing.headers['Cache-Control']
    record = response.get_json()['items'][0]
    assert record['publication'] == 'scheduled'
    assert 'The issue description' in record['content']
    assert '{} (unknown)'.format(DEFAULT_ISSUE_ID) in record['content']
    assert CVE.query.filter_by(id=DEFAULT_ISSUE_ID).one().issue_type is None
    assert '\nhttps://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73\n' in record['content']
    path = '/api/v1/advisory-drafts/' + record['name']
    assert client.get(path).status_code == 401
    draft = client.get(path, headers=headers)
    edit_headers = dict(headers, **{'If-Match': draft.headers['ETag']})

    def failed_update_render(*args, **kwargs):
        if Advisory.query.one().impact == 'Failed update':
            raise RuntimeError('Unable to render changed draft')
        return generate_advisory(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr('tracker.advisory.generate_advisory', failed_update_render)
        response = client.patch(path, json={'impact': 'Failed update'}, headers=edit_headers)
        assert response.status_code == 500
        assert Advisory.query.one().impact is None
    assert client.get(path, headers=headers).headers['ETag'] == draft.headers['ETag']
    response = client.patch(path, json={'impact': 'unpublishedimpactmarker'}, headers=edit_headers)
    assert response.status_code == 200
    assert 'unpublishedimpactmarker' in response.get_json()['content']
    pages = ('/', '/advisories', '/advisories.json', '/advisories/feed.atom', '/todo', '/todo.json',
             '/log', '/' + DEFAULT_ISSUE_ID, '/' + DEFAULT_ISSUE_ID + '.json',
             '/AVG-1', '/AVG-1.json', '/package/foo', '/package/foo.json')

    def assert_private():
        for prefix in ('/', '/advisory/'):
            for suffix in ('', '/raw', '/generate', '/generate/raw', '/log'):
                response = client.get(prefix + record['name'] + suffix, follow_redirects=True)
                assert response.status_code == 404
        for page in pages:
            response = client.get(page)
            assert response.status_code == 200
            assert record['name'].encode() not in response.data
            assert b'unpublishedimpactmarker' not in response.data
        response = client.get('/stats.json')
        assert response.status_code == 418
        assert response.get_json()['advisories']['total'] == 0
        assert not any(response.get_json()['advisories']['type'].values())
        assert client.get('/stats').status_code == 418

    assert_private()
    assert client.patch(path, json={'impact': 'Stale update'}, headers=edit_headers).status_code == 412
    assert client.patch(path, json={'publication': 'published'}, headers=headers).status_code == 422
    assert client.post('/api/v1/groups/AVG-1/advisory-drafts', json={}, headers=headers).status_code == 409
    assert Advisory.query.one().publication == Publication.scheduled
    assert Advisory.query.one().reference is None
    user = User.query.filter_by(name='workflow').one()
    user.role = UserRole.reporter
    user.password = hash_password('workflow-password', user.salt)
    db.session.commit()
    assert client.get(path, headers=headers).status_code == 403
    assert client.get(collection, headers=headers).status_code == 403
    assert client.post('/login', data={'username': user.name, 'password': 'workflow-password'}).status_code == 302
    assert_private()
    response = client.get('/user/workflow/log')
    assert record['name'].encode() not in response.data
    assert b'unpublishedimpactmarker' not in response.data
    for role in (UserRole.security_team, UserRole.administrator):
        user.role = role
        db.session.commit()
        for suffix in ('/raw', '/log'):
            response = client.get('/' + record['name'] + suffix, follow_redirects=True)
            assert response.status_code == 200
            assert b'unpublishedimpactmarker' in response.data
            assert 'no-store' in response.headers['Cache-Control']
            assert 'Cookie' in response.vary
        assert record['name'].encode() in client.get('/todo.json').data
        assert b'unpublishedimpactmarker' in client.get('/user/workflow/log').data
        assert client.get('/stats.json').get_json()['advisories']['total'] == 1
    group_path = '/api/v1/groups/AVG-1'
    response = client.patch(group_path, json={'fixed': None},
                            headers=match(client, group_path, workflow_tokens['groups:update']))
    assert response.status_code == 200
    assert client.get(path, headers=headers).get_json()['content'] == ''
    for suffix in ('/generate', '/generate/raw', '/raw'):
        assert client.get('/' + record['name'] + suffix, follow_redirects=True).status_code == 409
    response = client.patch(group_path, json={'fixed': '1.1-1'},
                            headers=match(client, group_path, workflow_tokens['groups:update']))
    assert response.status_code == 200
    user.active = False
    db.session.commit()
    assert client.get(collection, headers=headers).status_code == 403
    assert_private()
    for suffix in ('/edit', '/delete', '/publish'):
        assert client.get('/' + record['name'] + suffix).status_code == 403
    advisory = Advisory.query.one()
    advisory.publication = Publication.published
    advisory.impact = 'publishedimpactmarker'
    advisory.content = generate_advisory(advisory.id)
    db.session.commit()
    client.get('/logout')
    for suffix in ('', '/raw', '/generate', '/generate/raw', '/log'):
        response = client.get('/' + record['name'] + suffix, follow_redirects=True)
        assert response.status_code == 200
        assert b'unpublishedimpactmarker' not in response.data
        assert b'publishedimpactmarker' in response.data
    assert b'unpublishedimpactmarker' not in client.get('/log').data
    assert client.get('/stats.json').get_json()['advisories']['total'] == 1


@create_issue
@create_group(fixed='1.1-1')
@create_advisory(publication=Publication.published)
def test_published_advisory_is_never_a_writable_draft(db, client, workflow_tokens):
    advisory = Advisory.query.one()
    response = client.patch('/api/v1/advisory-drafts/' + advisory.id,
                            json={'impact': 'Replacement'}, headers=workflow_tokens['advisories:write'])
    assert response.status_code == 409
    assert Advisory.query.one().impact is None
    assert Advisory.query.one().publication == Publication.published
    listing = client.get('/api/v1/groups/AVG-1/advisory-drafts', headers=workflow_tokens['advisories:write'])
    assert listing.status_code == 200
    assert listing.get_json() == {'items': []}
