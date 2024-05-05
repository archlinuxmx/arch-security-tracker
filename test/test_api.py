from datetime import datetime

from tracker.model.cve import CVE
from tracker.model.enum import Remote
from tracker.model.enum import Severity

from .conftest import DEFAULT_ISSUE_ID
from .conftest import create_group
from .conftest import create_issue

COLLECTION = '/api/v1/cves'


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
    response = client.post(COLLECTION)
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
