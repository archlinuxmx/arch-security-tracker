from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model import CVEGroupPackage
from tracker.model.review import IntakeCandidate
from tracker.model.review import ReviewEvent
from tracker.model.user import User
from tracker.review import review_revision

from .conftest import create_group
from .conftest import create_issue
from .conftest import logged_in


@logged_in
@create_issue
def test_assessment_history_is_private_and_conflict_checked(db, client, app, monkeypatch):
    record = CVE.query.first()
    revision = review_revision(record)
    response = client.post('/review/' + record.id, data={'revision': revision, 'required': 'y', 'rationale': 'Check the backport'})
    assert response.status_code == 302
    assert ReviewEvent.query.one().action == 'required'
    assert client.post('/review/' + record.id, data={'revision': revision, 'rationale': 'Old form'}).status_code == 409
    assert b'Check the backport' in client.get('/review/' + record.id).data
    assert b'Check the backport' not in client.get('/' + record.id).data
    with monkeypatch.context() as patch:
        patch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
        assert client.post('/review/' + record.id, data={'revision': review_revision(record), 'rationale': 'Missing CSRF'}).status_code == 400
    assert ReviewEvent.query.count() == 1
    User.query.one().active = False
    db.session.commit()
    assert client.get('/review/' + record.id).status_code == 403
    client.get('/logout')
    assert client.get('/review/' + record.id).status_code == 302


@logged_in
@create_group
def test_signoff_applies_only_to_assessed_revision(db, client):
    record = CVE.query.first()
    response = client.get('/review/' + record.id, environ_overrides={'SCRIPT_NAME': '/tracker'})
    assert ('href="/tracker/{}">Public record'.format(record.id)).encode() in response.data
    client.post('/review/' + record.id, data={'revision': review_revision(record), 'rationale': 'Backport checked'})
    revision = review_revision(record)
    data = {'revision': revision, 'rationale': 'Confirmed'}
    assert client.post('/review/' + record.id + '/signoff', data=data).status_code == 302
    assert client.post('/review/' + record.id + '/signoff', data=data).status_code == 409
    assert b'(current)' in client.get('/review/' + record.id).data
    CVEGroup.query.one().packages.append(CVEGroupPackage(pkgname='foo-libs'))
    db.session.commit()
    assert b'(stale)' in client.get('/review/' + record.id).data
    assert client.post('/review/' + record.id + '/signoff', data=data).status_code == 409
    group = CVEGroup.query.one()
    response = client.get('/review/' + group.name, environ_overrides={'SCRIPT_NAME': '/tracker'})
    assert ('href="/tracker/{}">Public record'.format(group.name)).encode() in response.data
    alias = '/review/AVG-{:02d}'.format(group.id)
    assert client.post(alias, data={'revision': review_revision(group), 'rationale': 'Group checked'}).status_code == 302
    assert b'Group checked' in client.get(alias).data
    data = {'revision': review_revision(group), 'rationale': 'Confirmed'}
    assert client.post(alias + '/signoff', data=data).status_code == 302
    assert client.post(alias + '/signoff', data=data).status_code == 409
    assert client.post('/review/' + group.name + '/signoff', data=data).status_code == 409


@logged_in
def test_intake_requires_approval_and_preserves_private_evidence(db, client):
    for page in ('invalid', '9' * 100):
        assert client.get('/review/intake', query_string={'page': page}).status_code == 400
    for reference in ('https://example.org:99999/advisory', 'https://example.org/advisory\x7f'):
        response = client.post('/review/intake', data={'title': 'Invalid reference', 'source': 'mail:1',
                                                     'reference': reference})
        assert response.status_code == 400
        assert IntakeCandidate.query.count() == 0
    user_log = '/user/{}/log/page/'.format(User.query.one().name)
    assert client.get(user_log + '9' * 100).status_code == 404
    assert client.get(user_log + '9' * 18).status_code == 400
    response = client.post('/review/intake', data={'title': 'Upstream disclosure', 'source': 'imap:mailbox/message-1',
                                                 'evidence': 'Private source text', 'description': 'Public summary',
                                                 'reference': 'https://example.org/advisory'})
    assert response.status_code == 302
    candidate = IntakeCandidate.query.one()
    path = '/review/intake/{}'.format(candidate.id)
    assert client.post(path + '/promote', data={'revision': candidate.revision}).status_code == 409
    assert client.post(path, data={'revision': candidate.revision, 'state': 'approved', 'rationale': 'Confirmed source',
                                  'cve_name': 'CVE-2026-12345'}).status_code == 302
    revision = candidate.revision
    assert client.post(path + '/promote', data={'revision': revision}).status_code == 302
    record = CVE.query.one()
    assert record.description == 'Public summary'
    assert record.reference == 'https://example.org/advisory'
    assert 'Private source text' not in str(record.notes)
    assert candidate.promoted_cve == record.id
    response = client.get(path, environ_overrides={'SCRIPT_NAME': '/tracker'})
    assert ('href="/tracker/{}"'.format(record.id)).encode() in response.data
    assert client.post(path + '/promote', data={'revision': revision}).status_code == 409
    assert b'Private source text' in client.get(path).data
    response = client.post('/review/intake', data={'title': 'Optional fields omitted', 'source': 'mail:2'})
    assert response.status_code == 302
    empty = IntakeCandidate.query.order_by(IntakeCandidate.id.desc()).first()
    assert empty.description == empty.reference == empty.evidence == ''
