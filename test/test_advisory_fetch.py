from requests import Response

from config import TRACKER_MAILMAN_URL
from tracker.advisory import advisory_fetch_from_mailman
from tracker.model.enum import Publication
from tracker.model.enum import UserRole

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_package
from .conftest import default_advisory_dict
from .conftest import get_advisory
from .conftest import logged_in


def response(status=200, content=b'archive content'):
    result = Response()
    result.status_code = status
    result.encoding = 'utf-8'
    result._content = content
    result._content_consumed = True
    return result


def test_advisory_fetch_rejects_other_servers_and_paths(monkeypatch):
    calls = []

    def get(session, url, **kwargs):
        calls.append(url)
        return response()

    monkeypatch.setattr('tracker.advisory.Session.get', get)
    for url in ('http://127.0.0.1:8080/admin', 'http://169.254.169.254/latest/meta-data/',
                'https://lists.archlinux.org.attacker.invalid/archive',
                'https://lists.archlinux.org@attacker.invalid/archive',
                TRACKER_MAILMAN_URL.replace('https://', 'http://'),
                TRACKER_MAILMAN_URL.replace('https://', 'https://user:secret@'),
                TRACKER_MAILMAN_URL.replace('https://', 'ftp://'),
                TRACKER_MAILMAN_URL.replace('lists.archlinux.org/', 'lists.archlinux.org:0/', 1),
                TRACKER_MAILMAN_URL.replace('lists.archlinux.org/', 'lists.archlinux.org:8443/', 1),
                TRACKER_MAILMAN_URL + '../admin', TRACKER_MAILMAN_URL + '%2e%2e/admin',
                TRACKER_MAILMAN_URL + '%252e%252e/admin', 'https://lists.archlinux.org/admin'):
        assert advisory_fetch_from_mailman(url) is None
    assert calls == []


def test_advisory_fetch_bounds_responses_and_disables_redirects(monkeypatch):
    calls = []
    reply = response()

    def get(session, url, **kwargs):
        calls.append(url)
        assert kwargs == {'timeout': 10, 'allow_redirects': False, 'stream': True}
        return reply

    monkeypatch.setattr('tracker.advisory.Session.get', get)
    url = TRACKER_MAILMAN_URL + 'message/ABC/'
    assert advisory_fetch_from_mailman(url) == 'archive content'
    for destination in ('http://127.0.0.1/admin', 'https://attacker.invalid/data', url + 'redirect'):
        reply = response(302)
        reply.headers['Location'] = destination
        assert advisory_fetch_from_mailman(url) is None
    reply = response(content=b'A' * (1024 * 1024 + 1))
    assert advisory_fetch_from_mailman(url) is None
    assert calls == [url] * 5

    reply = response()
    reply.encoding = 'not-a-real-charset'
    assert advisory_fetch_from_mailman(url) == 'archive content'


def test_advisory_fetch_supports_configured_archives(monkeypatch):
    monkeypatch.setattr('tracker.advisory.TRACKER_MAILMAN_URL', 'https://archive.example.org:8443/security/')
    calls = []

    def get(session, url, **kwargs):
        calls.append(url)
        return response()

    monkeypatch.setattr('tracker.advisory.Session.get', get)
    assert advisory_fetch_from_mailman('https://archive.example.org:8443/security/message/ABC/') == 'archive content'
    assert advisory_fetch_from_mailman(TRACKER_MAILMAN_URL) is None
    assert len(calls) == 1


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID)
@logged_in(role=UserRole.security_team)
def test_advisory_forms_do_not_fetch_untrusted_references(db, client, monkeypatch):
    def get(*args, **kwargs):
        raise AssertionError('Untrusted reference was fetched')

    monkeypatch.setattr('tracker.advisory.Session.get', get)
    path = '/{}'.format(DEFAULT_ADVISORY_ID)
    reference = 'http://127.0.0.1:8080/admin'
    result = client.post(path + '/publish', data={'reference': reference})
    assert result.status_code == 200
    assert b'Failed to fetch advisory' in result.data
    assert get_advisory().publication == Publication.scheduled

    advisory = get_advisory()
    data = default_advisory_dict({'reference': reference, 'changed': str(advisory.changed)})
    result = client.post(path + '/edit', data=data)
    assert result.status_code == 200
    assert b'Failed to fetch advisory' in result.data
    assert advisory.reference is None

    advisory.publication = Publication.published
    advisory.reference = 'https://old-archive.example.org/security/advisory.html'
    advisory.content = 'Previously published content'
    db.session.commit()
    data.update(reference=advisory.reference, changed=str(advisory.changed), impact='Corrected impact')
    assert client.post(path + '/edit', data=data).status_code == 302
    assert advisory.impact == 'Corrected impact'
    assert advisory.content == 'Previously published content'
    assert advisory.reference == data['reference']
