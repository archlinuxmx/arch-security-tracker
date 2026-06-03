from sqlalchemy_continuum import version_class

from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Status
from tracker.model.review import IntakeCandidate
from tracker.model.review import ReviewEvent
from tracker.model.user import User
from tracker.review import review_revision

from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package
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
    for name in ('AVG-9223372036854775808', 'AVG-' + '9' * 100, 'AVG-²'):
        assert client.get('/review/' + name).status_code == 404
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
    assert b': reviewed' in client.get('/review').data
    CVEGroup.query.one().packages.append(CVEGroupPackage(pkgname='foo-libs'))
    db.session.commit()
    assert b'(stale)' in client.get('/review/' + record.id).data
    index = client.get('/review').data
    assert b': required (record changed)' in index and b': reviewed' not in index
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
    for candidate_id in ('9223372036854775808', '9' * 100):
        path = '/review/intake/' + candidate_id
        assert client.get(path).status_code == 404
        assert client.post(path + '/promote', data={'revision': 1}).status_code == 404
    response = client.post('/review/intake', data={'title': 'Optional fields omitted', 'source': 'mail:2'})
    assert response.status_code == 302
    empty = IntakeCandidate.query.order_by(IntakeCandidate.id.desc()).first()
    assert empty.description == empty.reference == empty.evidence == ''


@logged_in
@create_group
def test_merge_preserves_history_and_blocks_advisory_groups(db, client):
    source = CVEGroup.query.first()
    destination = CVEGroup(affected=source.affected, fixed=source.fixed, status=source.status,
                           notes=source.notes, bug_ticket=source.bug_ticket, reference='https://example.org/fix')
    destination.packages.append(CVEGroupPackage(pkgname='foo'))
    destination.issues.append(CVEGroupEntry(cve=CVE.new('CVE-2026-54321')))
    db.session.add(destination)
    db.session.commit()
    source, destination = destination, source
    source_name = source.name
    data = {'source': source.name, 'destination': destination.name,
            'source_revision': review_revision(source), 'destination_revision': review_revision(destination),
            'rationale': 'Same affected versions'}
    assert client.get('/review/merge', query_string=data).status_code == 200
    response = client.get('/review/merge', query_string=data, environ_overrides={'SCRIPT_NAME': '/tracker'})
    for group in (source, destination):
        assert ('href="/tracker/{}"'.format(group.name)).encode() in response.data
    response = client.post('/review/merge', data=dict(data, rationale=''))
    assert response.status_code == 400
    assert b'This field is required.' in response.data
    assert client.post('/review/merge', data=data).status_code == 302
    assert len(destination.issues) == 2
    assert ReviewEvent.query.filter_by(target=source_name, action='merged').one()
    assert client.get('/' + source_name).status_code == 301
    assert client.get('/AVG-{:02d}'.format(source.id)).status_code == 301
    assert client.get('/AVG-9223372036854775808').status_code == 404
    assert client.get('/review/retired/' + source_name).status_code == 200
    response = client.get('/review/retired/' + source_name, environ_overrides={'SCRIPT_NAME': '/tracker'})
    assert ('href="/tracker/{}"'.format(destination.name)).encode() in response.data
    assert version_class(CVEGroup).query.filter_by(id=source.id).count() >= 2
    other = CVEGroup(affected=destination.affected, status=destination.status, notes=destination.notes,
                     bug_ticket=destination.bug_ticket)
    other.packages.append(CVEGroupPackage(pkgname='foo'))
    other.issues.append(CVEGroupEntry(cve=CVE.query.first()))
    db.session.add(other)
    db.session.flush()
    db.session.add(Advisory(id='ASA-202609-1', group_package=other.packages[0]))
    db.session.commit()
    data.update(source=other.name, source_revision=review_revision(other), destination_revision=review_revision(destination))
    assert client.post('/review/merge', data=data).status_code == 409
    assert CVEGroup.query.get(other.id)
    assert other.id > int(source_name[4:])
    assert client.get('/' + source_name).status_code == 301


@logged_in
@create_issue(description='Original description')
def test_revert_creates_new_version_and_keeps_history(db, client):
    record = CVE.query.first()
    record.cvss_version = '3.1'
    record.cvss_score = 0
    record.cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    record.cvss_source = 'https://example.org/original-cvss'
    db.session.commit()
    transaction_id = record.versions.order_by(None).order_by(version_class(CVE).transaction_id.desc()).first().transaction_id
    record.description = 'Incorrect edit'
    db.session.commit()
    before = record.versions.count()
    data = {'revision': review_revision(record), 'transaction_id': transaction_id, 'rationale': 'Correct mistaken edit'}
    response = client.get('/review/' + record.id + '/revert')
    assert response.status_code == 200
    assert b'CVSS version: 3.1' in response.data and b'score: 0.0' in response.data
    assert record.cvss_vector.encode() in response.data and record.cvss_source.encode() in response.data
    assert client.post('/review/' + record.id + '/revert', data=data).status_code == 302
    assert record.description == 'Original description'
    assert record.versions.count() == before + 1
    assert ReviewEvent.query.filter_by(target=record.id, action='reverted').one()
    assert client.post('/review/' + record.id + '/revert', data=data).status_code == 409


@logged_in
@create_group(bug_ticket='1234')
def test_group_revert_rejects_changed_relationships(db, client):
    record = CVEGroup.query.first()
    record.notes = 'First assessment'
    record.advisory_qualified = False
    db.session.commit()
    transaction_id = record.versions.order_by(None).order_by(version_class(CVEGroup).transaction_id.desc()).first().transaction_id
    record.notes = 'Incorrect assessment'
    db.session.commit()
    path = '/review/' + record.name + '/revert'
    response = client.get(path)
    assert b'Bug ticket: 1234' in response.data and b'Advisory qualified: No' in response.data
    assert client.post(path, data={'revision': review_revision(record), 'transaction_id': transaction_id,
                                   'rationale': 'Restore assessment'}).status_code == 409
    assert record.notes == 'Incorrect assessment'
    ticket = 'https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73'
    record.bug_ticket = ticket
    db.session.commit()
    response = client.post(path, data={'revision': review_revision(record), 'transaction_id': transaction_id,
                                       'rationale': 'Restore the old ticket'})
    assert response.status_code == 409
    assert b'Arch GitLab issue URL' in response.data
    assert record.bug_ticket == ticket
    transaction_id = record.versions.order_by(None).order_by(version_class(CVEGroup).transaction_id.desc()).first().transaction_id
    record.notes = 'Another assessment'
    db.session.commit()
    assert client.post(path, data={'revision': review_revision(record), 'transaction_id': transaction_id,
                                   'rationale': 'Restore assessment'}).status_code == 302
    assert record.notes == 'Incorrect assessment'
    record.issues.append(CVEGroupEntry(cve=CVE.new('CVE-2026-99999')))
    record.notes = 'New scope'
    db.session.commit()
    assert client.post(path, data={'revision': review_revision(record), 'transaction_id': transaction_id,
                                   'rationale': 'Would discard a CVE'}).status_code == 409
    assert len(record.issues) == 2
    assert record.notes == 'New scope'


@logged_in
@create_package(name='foo', version='2.0-1')
@create_group(fixed='2.0-1', status=Status.fixed)
def test_group_revert_uses_current_repository_versions(db, client):
    record = CVEGroup.query.one()
    record.notes = 'Confirmed the fix'
    db.session.commit()
    transaction_id = record.versions.order_by(None).order_by(version_class(CVEGroup).transaction_id.desc()).first().transaction_id

    Package.query.one().version = '1.5-1'
    record.status = Status.vulnerable
    record.notes = 'Incorrect replacement notes'
    db.session.commit()
    response = client.post('/review/' + record.name + '/revert',
                           data={'revision': review_revision(record), 'transaction_id': transaction_id,
                                 'rationale': 'Restore the original notes'})
    assert response.status_code == 302
    assert record.notes == 'Confirmed the fix'
    assert record.fixed == '2.0-1'
    assert record.status == Status.vulnerable
    response = client.post('/review/' + record.name + '/revert',
                           data={'revision': review_revision(record), 'transaction_id': transaction_id,
                                 'rationale': 'Repeat the restoration'})
    assert response.status_code == 409
    assert ReviewEvent.query.filter_by(target=record.name, action='reverted').count() == 1
