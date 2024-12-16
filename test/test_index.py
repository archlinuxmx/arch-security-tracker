from flask import url_for

from tracker.model.enum import Publication

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_index(db, client):
    resp = client.get(url_for('tracker.index'), follow_redirects=True)
    assert 200 == resp.status_code
    assert 'text/html; charset=utf-8' == resp.content_type
    assert DEFAULT_GROUP_NAME not in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_vulnerable(db, client):
    resp = client.get(url_for('tracker.index_vulnerable'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_all(db, client):
    resp = client.get(url_for('tracker.index_all'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_json(db, client):
    resp = client.get(url_for('tracker.index_json', only_vulernable=False), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert 'application/json; charset=utf-8' == resp.content_type
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_GROUP_NAME
    assert data[0]['types'] == ['unknown']


@create_package(name='zeta', base='shared', database='extra')
@create_package(name='alpha', base='shared', database='extra')
@create_package(name='alpha', base='shared', database='extra-testing')
@create_group(packages=['alpha', 'zeta'], issues=['CVE-2026-9999', 'CVE-2026-10000'])
@create_advisory(publication=Publication.published)
def test_public_catalogue_orders_packages_and_deduplicates_advisories(db, client):
    entry = client.get('/all.json', follow_redirects=True).get_json()[0]
    assert entry['advisories'] == [DEFAULT_ADVISORY_ID]
    assert entry['packages'] == ['alpha', 'zeta']
    assert entry['issues'] == ['CVE-2026-10000', 'CVE-2026-9999']
    issue = client.get('/CVE-2026-9999.json', follow_redirects=True).get_json()
    assert issue['packages'] == ['alpha', 'zeta']


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_vulnerable_json(db, client):
    resp = client.get(url_for('tracker.index_vulnerable_json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_GROUP_NAME
    assert data[0]['types'] == ['unknown']


@create_package(name='foo')
@create_group(packages=['foo'], count=51)
def test_index_pagination_and_sorting(db, client):
    from datetime import datetime

    from tracker.model import CVEGroup

    first = CVEGroup.query.order_by(CVEGroup.id).first()
    first.created = datetime(2030, 1, 1)
    first.changed = datetime(2040, 1, 1)
    db.session.commit()
    for sort in ('created', 'changed'):
        page = client.get('/issues/all', query_string={'sort': sort}).data.decode()
        assert page.index('>AVG-1<') < page.index('>AVG-51<')
        assert 'page=2' in page
        page = client.get('/issues/all', query_string={'sort': sort, 'page': 2}).data.decode()
        assert '>AVG-2<' in page and '>AVG-1<' not in page
    assert client.get('/issues/all?page=3').status_code == 404
    assert client.get('/issues/all?sort=invalid').status_code == 400
    for page in ('9' * 100, 'invalid'):
        assert client.get('/issues/all', query_string={'page': page}).status_code == 400


@create_issue(id='CVE-2024-90001', notes='A parser overread')
@create_issue(id='CVE-2024-90002', description='A literal 50% limit')
@create_package(name='foo', description='Parser runtime')
@create_group(id=88, packages=['foo'], notes='Parser assessment')
def test_search_descriptions_and_literal_percent(db, client):
    page = client.get('/search?q=PARSER').data
    assert b'CVE-2024-90001' in page and b'AVG-88' in page and b'/package/foo' in page
    page = client.get('/search', query_string={'q': '%'}).data
    assert b'CVE-2024-90002' in page and b'CVE-2024-90001' not in page
    assert b'AVG-88' in client.get('/search?q=AVG-88').data
    for term in ('AVG-' + '9' * 100, 'AVG-²'):
        assert client.get('/search', query_string={'q': term}).status_code == 200
