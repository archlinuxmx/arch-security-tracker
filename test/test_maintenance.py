import tarfile
from importlib import import_module
from types import SimpleNamespace

import pytest
from sqlalchemy import inspect
from sqlalchemy import text

from tracker import maintenance
from tracker import pacman
from tracker.cli import cli
from tracker.model import CVEGroup
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Severity
from tracker.model.enum import Status

from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@pytest.mark.parametrize('filter_arch', [False, True])
def test_pacman_search_keeps_distinct_package_names(monkeypatch, filter_arch):
    repository = SimpleNamespace(name='core')
    foo = SimpleNamespace(name='foo', version='1-1', db=repository, arch='x86_64')
    bar = SimpleNamespace(name='bar', version='1-1', db=repository, arch='x86_64')
    other_arch = SimpleNamespace(name='foo', version='1-1', db=repository, arch='aarch64')
    repository.search = lambda name: [foo, bar, foo, other_arch]
    handle = SimpleNamespace(get_syncdbs=lambda: [repository])
    monkeypatch.setattr(pacman, 'get_handle', lambda *args, **kwargs: handle)
    assert pacman.search('', sort_results=False, filter_arch=filter_arch) == (
        [foo, bar] if filter_arch else [foo, bar, other_arch])


@create_package(name='old')
def test_package_refresh_preserves_cache_on_empty_or_broken_input(db, client, monkeypatch, tmp_path):
    packages = []
    monkeypatch.setattr(maintenance, 'search', lambda *args, **kwargs: packages)
    with pytest.raises(ValueError, match='no packages'):
        maintenance.update_package_cache()
    assert Package.query.one().name == 'old'
    package = SimpleNamespace(name='new', base='new', version='2-1', desc='', url=None,
                              arch=None, db=SimpleNamespace(name='core'), filename='new.pkg',
                              sha256sum='hash', builddate=1)
    packages.append(package)
    with pytest.raises(ValueError, match='Incomplete package'):
        maintenance.update_package_cache()
    assert Package.query.one().name == 'old'
    package.arch = 'any'
    maintenance.update_package_cache()
    assert Package.query.one().name == 'new'

    Package.query.one().database = 'core-testing'
    db.session.commit()
    sync_path = tmp_path / 'sync'
    sync_path.mkdir()
    for name in ('core', 'core-testing'):
        with tarfile.open(sync_path / (name + '.db'), 'w'):
            pass
    databases = [SimpleNamespace(name='core', search=lambda name: packages),
                 SimpleNamespace(name='core-testing', search=lambda name: [])]
    handle = SimpleNamespace(dbpath=str(tmp_path), get_syncdbs=lambda: databases)
    monkeypatch.setattr(pacman, 'get_handle', lambda *args, **kwargs: handle)
    monkeypatch.setattr(maintenance, 'search', pacman.search)
    maintenance.update_package_cache()
    assert Package.query.one().database == 'core'
    for content in (None, b'broken archive'):
        if content is None:
            (sync_path / 'core-testing.db').unlink()
        else:
            (sync_path / 'core-testing.db').write_bytes(content)
        with pytest.raises(ValueError, match='Cannot read repository'):
            maintenance.update_package_cache()
        assert Package.query.one().name == 'new'
    databases.pop()
    Package.query.one().database = 'core-testing'
    db.session.commit()
    with pytest.raises(ValueError, match='Repositories missing from refresh'):
        maintenance.update_package_cache()
    assert Package.query.one().database == 'core-testing'


@create_issue(id='CVE-2026-10001', severity=Severity.high)
@create_issue(id='CVE-2026-10002', severity=Severity.low)
@create_group(id=1, issues=['CVE-2026-10001', 'CVE-2026-10002'])
@create_group(id=2, issues=['CVE-2026-10002'])
def test_recalculate_group_severity(db, app):
    runner = app.test_cli_runner()
    for option in ('--recalc-severity', '--recalc'):
        for group in CVEGroup.query.all():
            group.severity = Severity.critical
        db.session.commit()
        result = runner.invoke(cli, ['update', 'group', option])
        assert result.exit_code == 0, result.output
        assert CVEGroup.query.filter_by(id=1).one().severity == Severity.high
        assert CVEGroup.query.filter_by(id=2).one().severity == Severity.low


@create_package(name='foo', version='1-1')
@create_package(name='foo-doc', base='foo', version='1-1')
@create_group(id=1, packages=['foo'], status=Status.fixed, fixed='2-1')
@create_group(id=2, packages=['removed'], status=Status.fixed, fixed='2-1')
@create_group(id=3, packages=['foo'], status=Status.not_affected)
def test_refresh_reopens_fixed_groups_after_package_rollback(db, app):
    runner = app.test_cli_runner()
    result = runner.invoke(cli, ['update', 'group'])
    assert result.exit_code == 0, result.output
    assert CVEGroup.query.filter_by(id=1).one().status == Status.vulnerable
    assert CVEGroup.query.filter_by(id=2).one().status == Status.fixed
    assert CVEGroup.query.filter_by(id=3).one().status == Status.not_affected

    package = Package.query.filter_by(name='foo').one()
    package.version = '2-1'
    package.database = 'core-testing'
    db.session.commit()
    result = runner.invoke(cli, ['update', 'group'])
    assert result.exit_code == 0, result.output
    assert CVEGroup.query.filter_by(id=1).one().status == Status.testing

    group = CVEGroup.query.filter_by(id=1).one()
    group.packages.append(CVEGroupPackage(pkgname='foo-doc'))
    db.session.commit()
    maintenance.update_group_status()
    assert group.status == Status.vulnerable

    documentation = Package.query.filter_by(name='foo-doc').one()
    documentation.version = '2-1'
    documentation.database = 'core-testing'
    package.database = 'core'
    db.session.commit()
    maintenance.update_group_status()
    assert group.status == Status.testing

    documentation.database = 'core'
    db.session.commit()
    maintenance.update_group_status()
    assert group.status == Status.fixed


def test_database_maintenance_commands(app, db, monkeypatch):
    runner = app.test_cli_runner()
    for command in ('check', 'vacuum'):
        result = runner.invoke(cli, ['db', command])
        assert result.exit_code == 0, result.output

    db.session.execute(text('CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)'))
    db.session.commit()
    monkeypatch.setattr(import_module('tracker.cli.db'), 'stamp', lambda: None)
    try:
        result = runner.invoke(cli, ['db', 'initdb', '--purge'])
        assert result.exit_code == 0, result.output
        assert set(db.metadata.tables) <= set(inspect(db.engine).get_table_names())
    finally:
        db.session.execute(text('DROP TABLE alembic_version'))
        db.session.commit()


def test_development_server_debug_option(app, monkeypatch):
    states = []
    monkeypatch.setattr(app, 'debug', False)
    monkeypatch.setattr(import_module('tracker.cli.run'), 'set_debug_flag', lambda debug: None)
    monkeypatch.setattr('werkzeug.serving.run_simple',
                        lambda host, port, application, **options:
                        states.append((application.debug, options['use_debugger'])))
    runner = app.test_cli_runner()
    for option in ('--debug', '--no-debug'):
        result = runner.invoke(cli, ['run', option, '--no-reload'])
        assert result.exit_code == 0, result.output
    assert states == [(True, True), (False, False)]


def test_development_server_releases_request_sessions(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from click.testing import CliRunner
    from flask import has_app_context

    calls = []

    def serve(host, port, app, **kwargs):
        assert not has_app_context()
        app.teardown_appcontext(lambda error: calls.append(error))
        for _ in range(2):
            response = app.test_client().get('/api/v1/missing')
            assert response.status_code == 404
        assert len(calls) == 2

    monkeypatch.setattr('werkzeug.serving.run_simple', serve)
    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(CliRunner().invoke, cli, ['run', '--no-reload']).result()
    assert result.exit_code == 0, result.exception
    assert len(calls) == 2
