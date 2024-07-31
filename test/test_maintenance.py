from importlib import import_module

from sqlalchemy import inspect
from sqlalchemy import text

from tracker.cli import cli


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
