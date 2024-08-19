from tracker.model import CVE
from tracker.model import Advisory
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
