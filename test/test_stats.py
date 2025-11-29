
from flask import url_for
from werkzeug.exceptions import ImATeapot

from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.enum import UserRole

from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package
from .conftest import create_user
from .conftest import logged_in


def test_stats_page(db, client):
    resp = client.get(url_for('tracker.stats'))
    assert ImATeapot.code == resp.status_code


def test_stats_data_status_empty(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()
    assert data

    for status in [Status.vulnerable.name, Status.fixed.name, 'total']:
        for severity in [severity.name for severity in Severity] + ['total']:
            assert 0 == data['issues']['severity'][status][severity]
            assert 0 == data['groups']['severity'][status][severity]
            assert 0 == data['packages']['severity'][status][severity]
            assert 0 == data['advisories']['severity'][severity]


def test_stats_data_type_empty(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()
    assert data

    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    for issue_type in issue_types:
        for status in [Status.vulnerable.name, Status.fixed.name, 'total']:
            assert 0 == data['issues']['type'][status][issue_type]
        assert 0 == data['advisories']['type'][issue_type]


def test_stats_data_misc_empty(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()

    assert data
    assert 0 == data['users']['team']
    assert 0 == data['users']['reporter']
    assert 0 == data['users']['total']
    assert 0 == data['tickets']['total']


@create_user(role=UserRole.security_team, username='SonGoku')
@create_user(role=UserRole.security_team, username='SasukeUchiha')
@create_user(role=UserRole.reporter, username='Alucard')
def test_stats_data_misc_users(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()

    assert 2 == data['users']['team']
    assert 1 == data['users']['reporter']
    assert 3 == data['users']['total']


@create_group(id=1, bug_ticket='https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/1337')
@create_group(id=2, bug_ticket='https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/1337')
@create_group(id=3, bug_ticket='https://gitlab.archlinux.org/archlinux/packaging/packages/foo/-/issues/4242')
def test_stats_data_misc_ticket(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()
    assert 2 == data['tickets']['total']


@create_package(name='morty', version='1.3-7')
@create_issue(id='CVE-0001-0001', severity=Severity.unknown)
@create_issue(id='CVE-0002-000', severity=Severity.low, count=2)
@create_issue(id='CVE-0003-000', severity=Severity.medium, count=3)
@create_issue(id='CVE-0004-000', severity=Severity.high, count=4)
@create_issue(id='CVE-0005-000', severity=Severity.critical, count=5)
@create_issue(id='CVE-0001-100', severity=Severity.unknown, count=6)
@create_issue(id='CVE-0002-100', severity=Severity.low, count=7)
@create_issue(id='CVE-0003-100', severity=Severity.medium, count=8)
@create_issue(id='CVE-0004-100', severity=Severity.high, remote=Remote.local, count=9)
@create_issue(id='CVE-0005-100', severity=Severity.critical, remote=Remote.remote, count=10)
@create_group(issues=list(map(lambda i: 'CVE-0001-100{}'.format(i), range(1, 7))) +
              list(map(lambda i: 'CVE-0002-100{}'.format(i), range(1, 8))) +
              list(map(lambda i: 'CVE-0003-100{}'.format(i), range(1, 9))) +
              list(map(lambda i: 'CVE-0004-100{}'.format(i), range(1, 10))) +
              list(map(lambda i: 'CVE-0005-100{}'.format(i), range(1, 11))),
              packages=['morty'], fixed='1.3-8')
def test_stats_data_status_issues(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()

    assert 0 == data['issues']['severity']['fixed'][Severity.unknown.name]
    assert 0 == data['issues']['severity']['fixed'][Severity.low.name]
    assert 0 == data['issues']['severity']['fixed'][Severity.medium.name]
    assert 0 == data['issues']['severity']['fixed'][Severity.high.name]
    assert 0 == data['issues']['severity']['fixed'][Severity.critical.name]
    assert 0 == data['issues']['severity']['fixed']['total']
    assert 15 == data['issues']['unassessed']

    assert 6 == data['issues']['severity']['vulnerable'][Severity.unknown.name]
    assert 7 == data['issues']['severity']['vulnerable'][Severity.low.name]
    assert 8 == data['issues']['severity']['vulnerable'][Severity.medium.name]
    assert 9 == data['issues']['severity']['vulnerable'][Severity.high.name]
    assert 10 == data['issues']['severity']['vulnerable'][Severity.critical.name]
    assert sum(list(range(6, 11))) == data['issues']['severity']['vulnerable']['total']

    assert 9 == data['issues']['severity']['local'][Severity.high.name]
    assert 10 == data['issues']['severity']['remote'][Severity.critical.name]

    assert 1 + 6 == data['issues']['severity']['total'][Severity.unknown.name]
    assert 2 + 7 == data['issues']['severity']['total'][Severity.low.name]
    assert 3 + 8 == data['issues']['severity']['total'][Severity.medium.name]
    assert 4 + 9 == data['issues']['severity']['total'][Severity.high.name]
    assert 5 + 10 == data['issues']['severity']['total'][Severity.critical.name]
    assert sum(list(range(1, 11))) == data['issues']['total']


@create_package(name='rick', version='1.3-7')
@create_issue(id='CVE-0001-0001', severity=Severity.unknown)
@create_issue(id='CVE-0002-0001', severity=Severity.low)
@create_issue(id='CVE-0003-0001', severity=Severity.medium)
@create_issue(id='CVE-0004-0001', severity=Severity.high)
@create_issue(id='CVE-0005-0001', severity=Severity.critical)
@create_group(id=10, issues=['CVE-0001-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=20, issues=['CVE-0002-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=30, issues=['CVE-0003-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=40, issues=['CVE-0004-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=50, issues=['CVE-0005-0001'], packages=['rick'], fixed='1.3-7')
@create_advisory(id='203012-01', group_package_id=1)
@create_advisory(id='203112-01', group_package_id=2)
@create_advisory(id='203212-01', group_package_id=3)
@create_advisory(id='203312-01', group_package_id=4)
@create_advisory(id='203412-01', group_package_id=5)
@logged_in
def test_stats_data_status_advisories(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()

    assert 1 == data['advisories']['severity'][Severity.unknown.name]
    assert 1 == data['advisories']['severity'][Severity.low.name]
    assert 1 == data['advisories']['severity'][Severity.medium.name]
    assert 1 == data['advisories']['severity'][Severity.high.name]
    assert 1 == data['advisories']['severity'][Severity.critical.name]
    assert 5 == data['advisories']['severity']['total']


@create_package(name='rick', version='1.3-7')
@create_issue(id='CVE-0001-0001', issue_type=issue_types[0])
@create_issue(id='CVE-0001-0002', issue_type=issue_types[0])
@create_issue(id='CVE-0002-0001', issue_type=issue_types[1])
@create_issue(id='CVE-0003-0001', issue_type=issue_types[2])
@create_issue(id='CVE-0004-0001', issue_type=issue_types[3])
@create_group(id=10, issues=['CVE-0003-0001'], packages=['rick'], fixed='1.0-7')
@create_group(id=20, issues=['CVE-0004-0001', 'CVE-0001-0002'], packages=['rick'])
def test_stats_data_type_issues(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()

    assert 0 == data['issues']['type']['fixed'][issue_types[0]]
    assert 1 == data['issues']['type']['vulnerable'][issue_types[0]]

    assert 0 == data['issues']['type']['fixed'][issue_types[1]]
    assert 0 == data['issues']['type']['vulnerable'][issue_types[1]]

    assert 1 == data['issues']['type']['fixed'][issue_types[2]]
    assert 0 == data['issues']['type']['vulnerable'][issue_types[2]]

    assert 0 == data['issues']['type']['fixed'][issue_types[3]]
    assert 1 == data['issues']['type']['vulnerable'][issue_types[3]]

    assert 0 == data['issues']['type']['fixed'][issue_types[6]]
    assert 0 == data['issues']['type']['vulnerable'][issue_types[6]]

    assert 2 == data['issues']['type']['vulnerable']['total']
    assert 1 == data['issues']['type']['fixed']['total']
    assert 2 == data['issues']['unassessed']

    assert 5 == data['issues']['type']['total']['total']
    assert 2 == data['issues']['type']['total'][issue_types[0]]
    assert 1 == data['issues']['type']['total'][issue_types[2]]
    assert 0 == data['issues']['type']['total'][issue_types[6]]

    issues = CVE.query.order_by(CVE.id).all()
    for issue in issues:
        issue.issue_type = None
    issues[0].remote = Remote.local
    issues[1].remote = Remote.remote
    db.session.commit()
    response = client.get('/stats.json')
    assert response.status_code == ImATeapot.code
    counts = response.get_json()['issues']['type']
    for category, count in (('total', 5), ('vulnerable', 2), ('fixed', 1), ('local', 1), ('remote', 1)):
        assert counts[category]['unknown'] == counts[category]['total'] == count
    assert all(issue.issue_type is None for issue in CVE.query.all())


@create_package(name='rick', version='1.3-7')
@create_issue(id='CVE-0001-0001', issue_type=issue_types[0])
@create_issue(id='CVE-0002-0001', issue_type=issue_types[1])
@create_issue(id='CVE-0003-0001', issue_type=issue_types[2])
@create_issue(id='CVE-0004-0001', issue_type=issue_types[3])
@create_group(id=10, issues=['CVE-0001-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=20, issues=['CVE-0002-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=30, issues=['CVE-0003-0001', 'CVE-0004-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=40, issues=['CVE-0003-0001', 'CVE-0004-0001'], packages=['rick'], fixed='1.3-7')
@create_advisory(id='203012-01', group_package_id=1)
@create_advisory(id='203112-01', group_package_id=2)
@create_advisory(id='203212-01', group_package_id=3)
@create_advisory(id='203312-01', group_package_id=4)
@logged_in
def test_stats_data_type_advisories(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = resp.get_json()

    assert 1 == data['advisories']['type'][issue_types[0]]
    assert 1 == data['advisories']['type'][issue_types[1]]
    assert 0 == data['advisories']['type'][issue_types[2]]
    assert 0 == data['advisories']['type'][issue_types[3]]
    assert 2 == data['advisories']['type']['multiple issues']
    assert 4 == data['advisories']['total']


@create_group(id=99, packages=['removed'], status=Status.vulnerable)
@create_package(name='zzz-present', version='2-1')
def test_removed_package_is_visible_without_changing_assessment(db, client):
    from tracker.maintenance import recalc_group_status
    from tracker.maintenance import update_group_status
    from tracker.model import CVEGroup
    from tracker.model import CVEGroupPackage
    from tracker.model.enum import Affected
    from tracker.model.enum import affected_to_status

    assert affected_to_status(Affected.affected, 'removed', None) == Status.vulnerable
    recalc_group_status()
    assert CVEGroup.query.get(99).status == Status.vulnerable
    assert b'AVG-99' not in client.get('/issues').data
    page = client.get('/issues?include_removed=1').data
    assert b'AVG-99' in page and b'(removed)' in page
    groups = client.get('/stats.json').get_json()['groups']
    assert groups['open_removed'] == 1 and groups['open_in_repositories'] == 0
    group = CVEGroup.query.get(99)
    group.packages.append(CVEGroupPackage(pkgname='zzz-present'))
    group.fixed = '2-1'
    db.session.commit()
    update_group_status()
    assert group.status == Status.fixed
    recalc_group_status()
    assert group.status == Status.fixed
