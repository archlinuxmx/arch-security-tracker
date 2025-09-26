from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model import CVEGroupPackage
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
