import json
import os
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import text

from deploy import entrypoint
from tracker import create_app

ROOT = Path(__file__).resolve().parent.parent
SECRET = 'a-long-random-example-secret-for-tests-1234567890'


def container_environment(tmp_path):
    env = {key: value for key, value in os.environ.items() if not key.startswith('TRACKER_')}
    env.update(TRACKER_CONFIG_LOCAL='false', TRACKER_PUBLIC_URL='https://security.example.org',
               TRACKER_DATA_DIR=str(tmp_path / 'data'), TRACKER_SECRET_KEY=SECRET)
    return env


def run_entrypoint(env, *args):
    return subprocess.run([sys.executable, str(ROOT / 'deploy/entrypoint.py'), *args],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)


def test_container_configuration(tmp_path):
    env = container_environment(tmp_path)
    secret = tmp_path / 'secret'
    secret.write_text(SECRET + '%literal\n')
    env.pop('TRACKER_SECRET_KEY')
    env['TRACKER_SECRET_KEY_FILE'] = str(secret)
    external = tmp_path / 'tracker.conf'
    external.write_text('[sso]\nenabled = yes\nclient_id = deployment-test\n')
    env['TRACKER_CONFIG_FILE'] = str(external)
    result = subprocess.run([sys.executable, '-c',
                             'import config, json; print(json.dumps({key: getattr(config, key) for key in '
                             '["SECRET_KEY", "SQLALCHEMY_DATABASE_URI", "TRACKER_ISSUE_URL", '
                             '"SESSION_COOKIE_SECURE", "SSO_CLIENT_ID", "PACMAN_CONFIG_PATH"]}))'],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    values = json.loads(result.stdout)
    assert values['SECRET_KEY'] == SECRET + '%literal'
    assert values['SESSION_COOKIE_SECURE'] is True
    assert values['SSO_CLIENT_ID'] == 'deployment-test'
    assert values['TRACKER_ISSUE_URL'] == 'https://security.example.org/{0}'
    assert values['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///' + str(tmp_path / 'data/tracker.db')
    assert values['PACMAN_CONFIG_PATH'] == str(tmp_path / 'data/pacman/pacman.conf')


@pytest.mark.parametrize('overrides', [
    {'TRACKER_SECRET_KEY': ''},
    {'TRACKER_SECRET_KEY': 'short'},
    {'TRACKER_SECRET_KEY': 'x' * 40},
    {'TRACKER_PUBLIC_URL': ''},
    {'TRACKER_PUBLIC_URL': 'http://security.example.org'},
    {'TRACKER_PUBLIC_URL': 'https://user:password@example.org'},
    {'TRACKER_PUBLIC_URL': 'https://example.org/path'},
    {'TRACKER_PUBLIC_URL': 'https://example.org:99999'},
    {'TRACKER_PROXY_HOPS': '-1'},
    {'TRACKER_DATA_DIR': 'relative'},
    {'TRACKER_CONFIG_FILE': '/does-not-exist.conf'},
])
def test_container_rejects_invalid_configuration(tmp_path, overrides):
    env = container_environment(tmp_path)
    env.update(overrides)
    result = run_entrypoint(env, 'init')
    assert result.returncode != 0
    assert not (tmp_path / 'data/tracker.db').exists()
    assert SECRET not in result.stderr


def test_container_initialization_preserves_data(tmp_path):
    env = container_environment(tmp_path)
    env['TRACKER_PUBLIC_URL'] = 'http://localhost:8080'
    result = run_entrypoint(env, 'init')
    assert result.returncode == 0, result.stderr
    database = tmp_path / 'data/tracker.db'
    assert database.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE deployment_marker (value TEXT)')
        connection.execute("INSERT INTO deployment_marker VALUES ('keep me')")
    result = run_entrypoint(env, 'init')
    assert result.returncode != 0
    assert 'Database already exists' in result.stderr
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT value FROM deployment_marker').fetchone() == ('keep me',)
    result = run_entrypoint(env, 'migrate')
    assert result.returncode == 0, result.stderr
    pacman = (tmp_path / 'data/pacman/pacman.conf').read_text()
    assert 'Architecture = x86_64' in pacman
    assert 'https://geo.mirror.pkgbuild.com/$repo/os/$arch' in pacman
    assert 'Include =' not in pacman
    assert str(tmp_path / 'data/pacman/arch/x86_64/db') in pacman


def test_container_migration_requires_existing_database(tmp_path):
    result = run_entrypoint(container_environment(tmp_path), 'migrate')
    assert result.returncode != 0
    assert 'use init' in result.stderr


def test_health_checks_report_database_revision(db, client):
    response = client.get('/healthz')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert client.get('/readyz').status_code == 503
    expected = ScriptDirectory(str(ROOT / 'migrations')).get_current_head()
    db.session.execute(text('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)'))
    db.session.execute(text('INSERT INTO alembic_version VALUES (:revision)'), {'revision': 'old'})
    db.session.commit()
    try:
        assert client.get('/readyz').status_code == 503
        db.session.execute(text('UPDATE alembic_version SET version_num = :revision'), {'revision': expected})
        db.session.commit()
        response = client.get('/readyz')
        assert response.status_code == 200
        assert response.headers['Cache-Control'] == 'no-store'
    finally:
        db.session.execute(text('DROP TABLE alembic_version'))
        db.session.commit()


@pytest.mark.parametrize('hops, expected', [(0, 'http'), (1, 'https')])
def test_proxy_trust_and_secure_cookies(hops, expected):
    from flask import request
    from flask import session

    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:', 'TESTING': True,
                      'TRACKER_PROXY_HOPS': hops, 'SESSION_COOKIE_SECURE': True})

    @app.get('/deployment-proxy-test')
    def proxy_test():
        session['check'] = True
        return request.scheme + ' ' + request.host

    with app.test_client() as client:
        response = client.get('/deployment-proxy-test', headers={'X-Forwarded-Proto': 'https',
                                                                 'X-Forwarded-Host': 'attacker.example'})
    assert response.text == expected + ' localhost'
    assert '; Secure;' in response.headers['Set-Cookie']


def test_refresh_lock_and_shutdown(tmp_path, monkeypatch):
    import fcntl

    called = []
    monkeypatch.setattr(entrypoint, 'run_tracker', lambda *args: called.append(args) or 0)
    with (tmp_path / 'refresh.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert entrypoint.refresh(tmp_path) == 1
        assert called == []
    assert entrypoint.refresh(tmp_path) == 0
    assert called == [('update', 'env')]

    class Child:
        def send_signal(self, signum):
            called.append(signum)

    monkeypatch.setattr(entrypoint, 'child', Child())
    entrypoint.stopping.clear()
    try:
        entrypoint.stop(signal.SIGTERM, None)
        assert entrypoint.stopping.is_set()
        assert called[-1] == signal.SIGTERM
    finally:
        entrypoint.stopping.clear()
