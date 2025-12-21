from flask import url_for
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound

from config import TRACKER_BUGTRACKER_URL
from tracker.model.advisory import Advisory
from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.cvegroup import CVEGroup
from tracker.model.cvegroupentry import CVEGroupEntry
from tracker.model.enum import Affected
from tracker.model.enum import Publication
from tracker.model.enum import Status
from tracker.model.enum import UserRole
from tracker.model.enum import affected_to_status
from tracker.model.package import Package
from tracker.view.add import ERROR_GROUP_WITH_ISSUE_EXISTS

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import DEFAULT_ISSUE_ID
from .conftest import ERROR_LOGIN_REQUIRED
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_package
from .conftest import default_group_dict
from .conftest import logged_in
from .util import AssertionHTMLParser


def set_and_assert_group_data(db, client, route, pkgnames=['foo'], issues=['CVE-1234-1234', 'CVE-2222-2222'],
                              affected='1.2.3-4', fixed='1.2.3-5', status=Affected.affected,
                              bug_ticket='https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73',
                              reference='https://security.archlinux.org', notes='the cacke\nis\na\nlie',
                              advisory_qualified=False, database='core'):
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        affected=affected,
        fixed=fixed,
        status=status.name,
        bug_ticket=bug_ticket,
        reference=reference,
        notes=notes,
        advisory_qualified='true' if advisory_qualified else None))

    resp = client.post(route, follow_redirects=True, data=data)
    assert 200 == resp.status_code

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == group.id
    assert affected == group.affected
    assert fixed == group.fixed
    assert Status.vulnerable == group.status
    assert bug_ticket == group.bug_ticket
    assert reference == group.reference
    assert notes == group.notes
    assert advisory_qualified == group.advisory_qualified

    assert list(sorted(issues)) == list(sorted([issue.cve.id for issue in group.issues]))
    assert list(sorted(pkgnames)) == list(sorted([pkg.pkgname for pkg in group.packages]))

    if bug_ticket:
        assert f'href="{bug_ticket}"' in resp.data.decode('utf-8')
    else:
        assert '/{}/ticket'.format(group.name) in resp.data.decode('utf-8')


@create_package(name='foo')
@logged_in(role=UserRole.reporter)
def test_reporter_can_add(db, client):
    resp = client.post(url_for('tracker.add_group'), follow_redirects=True,
                       data=default_group_dict(dict(pkgnames='foo', affected='1:1.0~rc1-1', fixed='1:1.1-1')))
    assert 200 == resp.status_code

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == group.id
    assert group.affected == '1:1.0~rc1-1'


@create_package(name='foo')
@create_group(packages=['foo'], bug_ticket='1234')
@logged_in(role=UserRole.reporter)
def test_reporter_can_copy(db, client):
    resp = client.get(url_for('tracker.copy_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    assert ERROR_LOGIN_REQUIRED not in resp.data.decode()
    field = next(line for line in resp.data.decode().splitlines() if 'name="bug_ticket"' in line)
    assert 'value=""' in field
    ticket = 'https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/73'
    CVEGroup.query.one().bug_ticket = ticket
    db.session.commit()
    assert f'value="{ticket}"' in client.get(url_for('tracker.copy_group', avg=DEFAULT_GROUP_NAME)).data.decode()


@create_package(name='foo')
@logged_in
def test_add_implicit_issue_creation(db, client):
    issue_id = 'CVE-4242-4242'
    resp = client.post(url_for('tracker.add_group'), follow_redirects=True,
                       data=default_group_dict(dict(pkgnames='foo', cve=issue_id)))
    assert 200 == resp.status_code

    cve = CVE.query.get(issue_id)
    assert issue_id == cve.id


@create_package(name='foo', version='1.2.3-4')
@logged_in
def test_add_group(db, client):
    response = client.post(url_for('tracker.add_group'),
                           data=default_group_dict(dict(pkgnames='foo', bug_ticket='1234')))
    assert b'Use an Arch GitLab issue URL.' in response.data
    assert CVEGroup.query.count() == 0
    assert CVE.query.count() == 0
    set_and_assert_group_data(db, client, url_for('tracker.add_group'))


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_edit_group(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME))


@create_package(name='alpha', base='shared', version='2.0-1')
@create_package(name='zeta', base='shared', version='1.0-1')
@logged_in
def test_browser_group_status_considers_each_package(db, client):
    data = default_group_dict(dict(pkgnames='alpha\nzeta', affected='1.0-1',
                                   fixed='2.0-1', status=Affected.affected.name))
    assert client.post('/avg/add', data=data).status_code == 302
    group = CVEGroup.query.one()
    assert group.status == Status.vulnerable

    package = Package.query.filter_by(name='zeta').one()
    package.version = '2.0-1'
    package.database = 'extra-testing'
    db.session.commit()
    data.update(changed=str(group.changed), notes='One package is only fixed in testing')
    assert client.post('/{}/edit'.format(group.name), data=data).status_code == 302
    assert group.status == Status.testing

    package.database = 'extra'
    db.session.commit()
    data.update(changed=str(group.changed), notes='Both packages are fixed')
    assert client.post('/{}/edit'.format(group.name), data=data).status_code == 302
    assert group.status == Status.fixed


@create_package(name='foo', version='2.0-1')
@create_group(packages=['foo'], affected='1.0-1', fixed='2.0-1')
@logged_in
def test_group_conflict_previews_the_derived_status(db, client):
    group = CVEGroup.query.one()
    data = default_group_dict(dict(pkgnames='foo', affected=group.affected, fixed=group.fixed,
                                   status=Affected.affected.name, changed=str(group.changed),
                                   notes='My notes'))
    group.notes = 'A concurrent edit'
    db.session.commit()
    path = '/{}/edit'.format(group.name)
    response = client.post(path, data=data)
    assert response.status_code == 409
    assert b'<td>Status</td>' not in response.data

    data['fixed'] = '3.0-1'
    response = client.post(path, data=data)
    assert response.status_code == 409
    assert b'<td>Status</td>' in response.data
    assert b'<td>Vulnerable</td>' in response.data
    data.update(fixed='2.0-1', status=Affected.not_affected.name, advisory_qualified=True)
    response = client.post(path, data=data)
    assert response.status_code == 409
    assert b'<td>Advisory qualified</td>' in response.data
    assert group.status == Status.fixed
    assert group.fixed == '2.0-1'
    assert group.notes == 'A concurrent edit'


@create_package(name='foo', version='2.0-1')
@create_group(packages=['foo'], affected='1.0-1', fixed='2.0-1')
@logged_in
def test_group_conflict_keeps_invalid_cves_in_the_form(db, client):
    group = CVEGroup.query.one()
    data = default_group_dict(dict(pkgnames='foo', affected=group.affected, fixed=group.fixed,
                                   changed=str(group.changed), notes='My notes'))
    group.notes = 'A concurrent edit'
    db.session.commit()
    current_changed = group.changed
    data.update(changed_latest=str(current_changed), force_update=True)

    for value in ('not-a-CVE', 'CVE-2026-nope'):
        data['cve'] = value
        response = client.post('/{}/edit'.format(group.name), data=data)
        assert response.status_code == 409
        assert b'Invalid issue' in response.data
        assert b'The remote data has changed!' in response.data
        assert value.encode() in response.data
        assert b'<td>Issues</td>' not in response.data
        assert group.notes == 'A concurrent edit'
        assert group.changed == current_changed
        assert [entry.cve_id for entry in group.issues] == [DEFAULT_ISSUE_ID]


@create_package(name='foo', version='1.2.3-4')
@logged_in
def test_edit_group_bug_url_core(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'), bug_ticket='')


@create_package(name='foo', version='1.2.3-4', database='extra')
@logged_in
def test_edit_group_bug_url_extra(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'), bug_ticket='', database='extra')


def test_add_needs_login(db, client):
    resp = client.get(url_for('tracker.add_group'), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_group
def test_edit_needs_login(db, client):
    resp = client.get(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_group
def test_copy_needs_login(db, client):
    resp = client.get(url_for('tracker.copy_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_show_group_not_found(db, client):
    resp = client.get(url_for('tracker.show_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code
    assert 'text/html; charset=utf-8' == resp.content_type


@logged_in
def test_edit_group_not_found(db, client):
    resp = client.get(url_for('tracker.edit_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4',
              issues=['CVE-1111-1234', 'CVE-1234-12345', 'CVE-1111-12345',
                      'CVE-1234-11112', 'CVE-1234-111111', 'CVE-1234-11111'])
@logged_in
def test_edit_sort_cve_entries(db, client):
    resp = client.get(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    html = AssertionHTMLParser()
    html.feed(resp.data.decode())
    assert ['CVE-1111-1234',
            'CVE-1111-12345',
            'CVE-1234-11111',
            'CVE-1234-11112',
            'CVE-1234-12345',
            'CVE-1234-111111'] == html.get_element_by_id('cve').data.split()


@logged_in
def test_copy_group_not_found(db, client):
    resp = client.get(url_for('tracker.copy_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_group_packge_dropped_from_repo(db, client):
    resp = client.get(url_for('tracker.show_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_warn_on_add_group_with_existing_issue(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222', DEFAULT_ISSUE_ID]
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames)))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_dont_warn_on_add_group_without_existing_issue(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames)))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) not in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_warn_on_add_group_with_package_already_having_open_group(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222', DEFAULT_ISSUE_ID]
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames)))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.0-1')
@logged_in
def test_add_group_fixed_version_older_then_affected(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        fixed='0.8-1'))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Version must be newer.' in resp.data.decode()


@create_package(name='foo')
@logged_in
def test_add_group_with_dot_in_pkgrel(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'), affected='1.2-3.4')


@create_package(name='foo')
@logged_in
def test_dont_add_group_with_dot_at_beginning_of_pkgrel(db, client):
    pkgnames = ['foo']
    issues = [DEFAULT_ISSUE_ID]
    affected = '1.3-.37'
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        affected=affected))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 'Invalid input.' in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in(role=UserRole.reporter)
def test_reporter_can_delete(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True,
                       data=dict(confirm=True))
    assert 200 == resp.status_code
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert avg is None


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in(role=UserRole.reporter)
def test_abort_delete(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True,
                       data=dict(abort=True))
    assert 200 == resp.status_code
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == avg.id


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
def test_delete_needs_login(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_delete_issue_not_found(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_forbid_delete_with_advisory(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert Forbidden.code == resp.status_code

@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4',
              issues=['CVE-1111-1234', 'CVE-1234-12345', 'CVE-1111-12345',
                      'CVE-1234-11112', 'CVE-1234-111111', 'CVE-1234-11111'])
@logged_in
def test_show_group_sort_cve_entries(db, client):
    resp = client.get(url_for('tracker.show_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    html = AssertionHTMLParser()
    html.feed(resp.data.decode())
    cves = []
    for e in html.get_elements_by_tag('a'):
        if len(e.attrs) == 1 and e.attrs[0][0] == 'href':
            if e.data.startswith("CVE") and e.attrs[0][1].startswith("/CVE"):
                cves.append(e.data.strip())
    assert ['CVE-1234-111111',
            'CVE-1234-12345',
            'CVE-1234-11112',
            'CVE-1234-11111',
            'CVE-1111-12345',
            'CVE-1111-1234'] == cves

@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_show_group(db, client):
    resp = client.get(url_for('tracker.show_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    assert 'text/html; charset=utf-8' == resp.content_type
    assert DEFAULT_GROUP_NAME in resp.data.decode()

@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_show_group_json(db, client):
    resp = client.get(url_for('tracker.show_group_json', avg=DEFAULT_GROUP_NAME, postfix='/json'), follow_redirects=True)
    assert 200 == resp.status_code
    assert 'application/json; charset=utf-8' == resp.content_type
    data = resp.get_json()
    assert data['name'] == DEFAULT_GROUP_NAME
    assert data['issues'] == [DEFAULT_ISSUE_ID]
    assert data['packages'] == ['foo']
    assert data['affected'] == '1.2.3-3'
    assert data['fixed'] == '1.2.3-4'

def test_show_group_json_not_found(db, client):
    resp = client.get(url_for('tracker.show_group_json', avg=DEFAULT_GROUP_NAME, postfix='/json'), follow_redirects=True)
    assert NotFound.code == resp.status_code
    assert 'application/json; charset=utf-8' == resp.content_type

@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_fixed(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.fixed

@create_package(name='foo', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_vulnerable(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.vulnerable

@create_package(name='foo', version='1.2.3-3', database='testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_vulnerable_testing(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.vulnerable

@create_package(name='foo', version='1.2.3-3')
@create_package(name='foo', version='1.2.3-4', database='testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_testing(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.testing

@create_package(name='foo', version='1.2.3-4', database='testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_testing_only(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.testing
    from tracker.model import Package
    testing = Package.query.filter_by(name='foo').one()
    stable = Package(**{column.name: getattr(testing, column.name)
                        for column in Package.__table__.columns if column.name != 'id'})
    stable.database = 'core'
    db.session.add(stable)
    db.session.commit()
    assert affected_to_status(Affected.affected, 'foo', avg.fixed) == Status.fixed

@create_package(name='foo', version='1.2.3-3', database='extra')
@create_package(name='foo', version='1.2.3-4', database='extra-testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_extra_testing(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.testing

@create_package(name='foo', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_unknown(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.unknown, 'foo', avg.fixed)
    assert status == Status.unknown

@create_package(name='foo', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_not_affected(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.not_affected, 'foo', avg.fixed)
    assert status == Status.not_affected

@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_unknown_package(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.vulnerable


@create_package(name='foopkg', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_non_relational_field_updates_changed_date(db, client):
    group_changed_old = CVEGroup.query.get(DEFAULT_GROUP_ID).changed

    data = default_group_dict(dict(notes='regular field change'))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed > group_changed_old

    Package.query.delete()
    group.status = Status.fixed
    group.fixed = '1.2.3-4'
    db.session.commit()
    data = default_group_dict(dict(status=Affected.affected.name, fixed=group.fixed,
                                   changed=str(group.changed), notes='Removed package notes'))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), data=data)
    assert resp.status_code == 302
    assert group.status == Status.fixed


@create_package(name='foopkg', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_relational_field_issues_updates_changed_date(db, client):
    group_changed_old = CVEGroup.query.get(DEFAULT_GROUP_ID).changed

    data = default_group_dict(dict(cve=' '.join(['CVE-1234-1111', 'CVE-1234-2222'])))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed > group_changed_old


@create_package(name='foopkg', version='1.2.3-4', base='foo')
@create_package(name='foopkg2', version='1.2.3-4', base='foo')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_relational_field_packages_updates_changed_date(db, client):
    group_changed_old = CVEGroup.query.get(DEFAULT_GROUP_ID).changed

    data = default_group_dict(dict(pkgnames=' '.join(['foopkg', 'foopkg2'])))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed > group_changed_old

    package = next(package for package in group.packages if package.pkgname == 'foopkg')
    advisory = db.create(Advisory, id=DEFAULT_ADVISORY_ID, group_package=package)
    db.session.commit()
    for publication in (Publication.scheduled, Publication.published):
        advisory.publication = publication
        db.session.commit()
        data.update(pkgnames='foopkg2', changed=str(group.changed), notes='Keep this input')
        response = client.post('/{}/edit'.format(group.name), data=data)
        assert response.status_code == 409
        assert b'Cannot remove a package with an advisory.' in response.data
        assert b'Keep this input' in response.data
        assert {package.pkgname for package in group.packages} == {'foopkg', 'foopkg2'}
        assert group.notes == ''


@create_package(name='foopkg', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_does_nothing_when_data_is_same(db, client):
    group_old = CVEGroup.query.get(DEFAULT_GROUP_ID)
    group_changed_old = group_old.changed

    data = default_group_dict(dict(status=Affected.affected.name))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' not in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed == group_changed_old


@create_package(name='libsigc++-docs', base='libsigc++')
@create_group(id=77, packages=['libsigc++-docs'], status=Status.vulnerable, bug_ticket='1234')
@logged_in
def test_gitlab_ticket_uses_package_base_and_short_url(db, client):
    page = client.get('/AVG-77/ticket').data
    assert b'/packages/libsigcplusplus/-/issues/new?' in page
    assert b'issue%5Btitle%5D=' in page
    assert b'detailed_desc=' not in page
    assert b'ticket-description' in page
    page = client.get('/package/libsigc++-docs').data
    assert b'/packages/libsigcplusplus/-/issues?state=opened' in page
    ticket = 'https://gitlab.archlinux.org/archlinux/packaging/packages/libsigcplusplus/-/issues/73'
    group = CVEGroup.query.get(77)
    page = client.get('/AVG-77/edit').data.decode()
    assert 'Archived ticket: 1234' in page
    field = next(line for line in page.splitlines() if 'name="bug_ticket"' in line)
    assert 'value=""' in field
    data = default_group_dict(dict(pkgnames='libsigc++-docs', status=Affected.affected.name,
                                   changed=str(group.changed), bug_ticket='', notes='Keep the archived reference'))
    response = client.post('/AVG-77/edit', data=data, follow_redirects=True)
    assert group.bug_ticket == '1234'
    assert group.notes == 'Keep the archived reference'
    assert TRACKER_BUGTRACKER_URL.format('1234') in response.data.decode()
    for invalid in ('1234', '5678'):
        data.update(changed=str(group.changed), bug_ticket=invalid)
        assert b'Use an Arch GitLab issue URL.' in client.post('/AVG-77/edit', data=data).data
        assert group.bug_ticket == '1234'
    data.update(changed=str(group.changed), bug_ticket=ticket, replace_ticket=True)
    response = client.post('/AVG-77/edit', data=data, follow_redirects=True)
    assert group.bug_ticket == ticket
    assert f'href="{ticket}"' in response.data.decode()
    data.update(changed=str(group.changed), notes='Keep the GitLab reference')
    del data['bug_ticket']
    assert client.post('/AVG-77/edit', data=data).status_code == 302
    assert group.bug_ticket == ticket
    for invalid in ('javascript:alert(1)', '1234'):
        data.update(changed=str(group.changed), bug_ticket=invalid)
        assert b'Use an Arch GitLab issue URL.' in client.post('/AVG-77/edit', data=data).data
        assert group.bug_ticket == ticket
    group.bug_ticket = '1234'
    db.session.commit()
    data.update(changed=str(group.changed), bug_ticket='', replace_ticket=True)
    assert client.post('/AVG-77/edit', data=data).status_code == 302
    assert group.bug_ticket == ''

    issue = CVE.query.one()
    issue.issue_type = None
    other = CVE.new('CVE-2026-12345')
    other.issue_type = 'arbitrary code execution'
    group.issues.append(CVEGroupEntry(cve=other))
    db.session.commit()
    response = client.get('/AVG-77/ticket')
    assert response.status_code == 200
    assert b'unknown' in response.data
    parser = AssertionHTMLParser()
    parser.feed(response.data.decode())
    description = parser.get_element_by_id('ticket-description').data
    for issue in (issue, other):
        assert f'https://security.archlinux.org/{issue.id}' in description.splitlines()
