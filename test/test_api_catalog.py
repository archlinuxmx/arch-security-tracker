from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model.enum import Publication
from tracker.model.enum import Severity

from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@create_package(name='foo', base='upstream', url='https://example.org/upstream')
@create_package(name='foo-doc', base='upstream', arch='x86_64', database='extra')
def test_package_catalogue(db, client):
    first = client.get('/api/v1/packages?limit=1').get_json()
    second = client.get('/api/v1/packages', query_string={'after': first['next_cursor']}).get_json()
    assert len(first['items']) == len(second['items']) == 1
    assert second['next_cursor'] is None
    assert {first['items'][0]['name'], second['items'][0]['name']} == {'foo', 'foo-doc'}
    matched = client.get('/api/v1/packages?q=example.org&base=upstream&architecture=any&repository=core').get_json()
    assert matched['items'][0]['name'] == 'foo'
    assert matched['items'][0]['version'] == '1.0-1'
    assert client.get('/api/v1/packages?q=%25').get_json()['items'] == []
    assert client.get('/api/v1/packages?after=bad').status_code == 400


@create_issue(description='Upstream parser fails', severity=Severity.high)
@create_group(packages=['foo', 'foo-doc'])
def test_cve_review_filters(db, client):
    db.session.add(CVE.new('CVE-2025-0001'))
    db.session.commit()
    matched = client.get('/api/v1/cves?package=foo&severity=high&q=parser&orphan=false').get_json()
    assert [item['name'] for item in matched['items']] == ['CVE-2016-1337']
    orphans = client.get('/api/v1/cves?orphan=true').get_json()
    assert [item['name'] for item in orphans['items']] == ['CVE-2025-0001']
    assert client.get('/api/v1/cves?orphan=maybe').status_code == 400
    assert client.get('/api/v1/cves?severity=severe').status_code == 400


@create_issue
@create_group(id=1, packages=['foo', 'foo-doc'])
@create_group(id=2, packages=['bar'])
def test_group_reads(db, client):
    first = client.get('/api/v1/groups?limit=1').get_json()
    assert first['items'][0]['name'] == 'AVG-1'
    assert first['next_cursor'] == '1'
    assert client.get('/api/v1/groups?after=1').get_json()['items'][0]['name'] == 'AVG-2'
    group = client.get('/api/v1/groups/AVG-1').get_json()
    assert group['packages'] == ['foo', 'foo-doc']
    assert group['cves'] == ['CVE-2016-1337']
    assert group['assessment'] == 'unknown'
    assert client.get('/api/v1/groups?package=foo&cve=CVE-2016-1337&status=unknown').get_json()['items'] == [group]
    assert client.get('/api/v1/groups/AVG-3').status_code == 404


@create_issue
@create_group(id=1)
@create_advisory(id='ASA-202601-1', publication=Publication.published, impact='Public impact')
@create_group(id=2, packages=['bar'])
@create_advisory(id='ASA-202601-2', group_package_id=2, impact='Unpublished impact')
def test_advisories_hide_drafts(db, client):
    response = client.get('/api/v1/advisories')
    assert response.status_code == 200
    assert [item['name'] for item in response.get_json()['items']] == ['ASA-202601-1']
    assert b'Unpublished' not in response.data
    record = client.get('/api/v1/advisories/ASA-202601-1').get_json()
    assert record['impact'] == 'Public impact'
    assert record['cves'] == ['CVE-2016-1337']
    assert client.get('/api/v1/advisories?package=bar').get_json()['items'] == []
    assert client.get('/api/v1/advisories/ASA-202601-2').status_code == 404
    Advisory.query.filter_by(id='ASA-202601-2').one().publication = Publication.published
    db.session.commit()
    first = client.get('/api/v1/advisories?limit=1').get_json()
    assert first['next_cursor'] == 'ASA-202601-1'
    assert client.get('/api/v1/advisories?after=ASA-202601-1').get_json()['items'][0]['name'] == 'ASA-202601-2'


@create_issue
@create_group(id=1)
@create_advisory(id='ASA-202601-1', publication=Publication.published)
@create_group(id=2, packages=['bar'])
@create_advisory(id='ASA-202601-2', group_package_id=2, impact='Draft')
def test_change_feed_tracks_relationships_deletions_and_publication(db, client):
    initial = client.get('/api/v1/changes').get_json()
    assert initial['items'] == []
    cursor = initial['next_cursor']
    issue = CVE.query.one()
    issue.notes = 'Browser-style update without changed maintenance'
    CVEGroup.query.filter_by(id=1).one().packages[0].pkgname = 'foo-new'
    # Remove the second group's link: the CVE must be invalidated as well.
    CVEGroup.query.filter_by(id=2).one().issues = []
    db.session.commit()
    first = client.get('/api/v1/changes', query_string={'after': cursor, 'limit': 1}).get_json()
    assert {'resource': 'cves', 'name': issue.id, 'deleted': False} in first['items']
    assert {'resource': 'groups', 'name': 'AVG-2', 'deleted': False} in first['items']
    assert {'resource': 'advisories', 'name': 'ASA-202601-1', 'deleted': False} in first['items']
    assert all(item['name'] != 'ASA-202601-2' for item in first['items'])
    published = Advisory.query.filter_by(id='ASA-202601-1').one()
    db.session.delete(published)
    db.session.delete(CVEGroup.query.filter_by(id=1).one())
    db.session.delete(issue)
    db.session.commit()
    removed = client.get('/api/v1/changes', query_string={'after': first['next_cursor']}).get_json()
    assert {'resource': 'cves', 'name': 'CVE-2016-1337', 'deleted': True} in removed['items']
    assert {'resource': 'groups', 'name': 'AVG-1', 'deleted': True} in removed['items']
    assert {'resource': 'advisories', 'name': 'ASA-202601-1', 'deleted': True} in removed['items']
    assert client.get('/api/v1/changes', query_string={'after': removed['next_cursor']}).get_json()['items'] == []
    assert client.get('/api/v1/changes?after=999999').status_code == 400


@create_issue
@create_group(id=1)
def test_public_conditional_reads_follow_relationship_edits(db, client):
    path = '/api/v1/cves/CVE-2016-1337'
    first = client.get(path)
    etag = first.headers['ETag']
    assert first.headers['Cache-Control'] == 'public, no-cache'
    unchanged = client.get(path, headers={'If-None-Match': etag})
    assert unchanged.status_code == 304
    assert unchanged.data == b''
    group_path = '/api/v1/groups/AVG-1'
    group_etag = client.get(group_path).headers['ETag']
    CVEGroup.query.one().packages[0].pkgname = 'foo-new'
    db.session.commit()
    modified = client.get(path, headers={'If-None-Match': etag})
    assert modified.status_code == 200
    assert modified.headers['ETag'] != etag
    assert modified.get_json()['packages'] == ['foo-new']
    assert client.get(group_path).headers['ETag'] != group_etag
    assert client.head(path).headers['ETag'] == modified.headers['ETag']
    error = client.get('/api/v1/cves/CVE-2026-9999')
    assert error.headers['Cache-Control'] == 'no-store'
    assert 'ETag' not in error.headers
    denied = client.post('/api/v1/cves', json={'name': 'CVE-2026-9999'})
    assert denied.headers['Cache-Control'] == 'no-store'


def test_public_read_preconditions_follow_etag_order(client):
    path = '/api/v1/cves'
    etag = client.get(path).headers['ETag']
    for method in ('GET', 'HEAD'):
        for value in ('*', etag, '"old", ' + etag):
            response = client.open(path, method=method, headers={'If-Match': value})
            assert response.status_code == 200
        for headers in ({'If-None-Match': etag}, {'If-None-Match': 'W/' + etag},
                        {'If-None-Match': '*'}, {'If-Match': etag, 'If-None-Match': etag}):
            response = client.open(path, method=method, headers=headers)
            assert response.status_code == 304
            assert response.data == b''
        for headers in ({'If-Match': '"old"'}, {'If-Match': 'W/' + etag},
                        {'If-Match': '"old"', 'If-None-Match': etag}):
            response = client.open(path, method=method, headers=headers)
            assert response.status_code == 412
            assert response.headers['Cache-Control'] == 'no-store'
            assert 'ETag' not in response.headers
            if method == 'GET':
                assert response.get_json()['error']['code'] == 'precondition_failed'
