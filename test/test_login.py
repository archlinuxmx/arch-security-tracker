from concurrent.futures import ThreadPoolExecutor
from re import search
from threading import Event
from threading import local

from click.testing import CliRunner
from flask import url_for
from flask_login import current_user
from pytest import mark
from sqlalchemy import event
from werkzeug.exceptions import Unauthorized

from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import create_app
from tracker.cli.setup import user as create_account
from tracker.form.login import ERROR_ACCOUNT_DISABLED
from tracker.form.login import ERROR_INVALID_USERNAME_PASSWORD
from tracker.model import User
from tracker.model.enum import UserRole
from tracker.model.review import IntakeCandidate
from tracker.user import hash_password

from .conftest import DEFAULT_USERNAME
from .conftest import assert_logged_in
from .conftest import assert_not_logged_in
from .conftest import create_user
from .conftest import logged_in


def test_login_view(db, client):
    resp = client.get(url_for('tracker.login'))
    assert 200 == resp.status_code
    assert 'text/html; charset=utf-8' == resp.content_type


@create_user
def test_login_success(db, client):
    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=DEFAULT_USERNAME))
    assert_logged_in(resp)
    assert DEFAULT_USERNAME == current_user.name


@create_user
def test_login_invalid_credentials(db, client):
    resp = client.post(url_for('tracker.login'), data={'username': DEFAULT_USERNAME,
                                               'password': 'N' * TRACKER_PASSWORD_LENGTH_MIN})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert 'text/html; charset=utf-8' == resp.content_type
    assert ERROR_INVALID_USERNAME_PASSWORD in resp.data.decode()


@mark.parametrize('password', [' correct horse battery', 'correct horse battery ',
                              '  correct horse battery  ', ' ' * TRACKER_PASSWORD_LENGTH_MIN])
def test_login_preserves_password_whitespace(db, client, password):
    result = CliRunner().invoke(create_account, ['--username', DEFAULT_USERNAME,
                                               '--email', 'editor@example.org', '--password', password,
                                               '--role', 'reporter', '--active'])
    assert result.exit_code == 0, result.output

    response = client.post('/login', data=dict(username=DEFAULT_USERNAME, password=password))
    assert response.status_code == 302
    client.post('/logout')
    response = client.post('/login', data=dict(username=DEFAULT_USERNAME, password=password.strip()))
    assert response.status_code == Unauthorized.code


def test_login_invalid_form(db, client):
    resp = client.post(url_for('tracker.login'), data={'username': DEFAULT_USERNAME})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert 'This field is required.' in resp.data.decode()


@create_user(active=False)
def test_login_disabled(db, client):
    resp = client.post(url_for('tracker.login'), data={'username': DEFAULT_USERNAME, 'password': DEFAULT_USERNAME})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()


@logged_in
def test_login_logged_in_redirect(db, client):
    resp = client.post(url_for('tracker.login'), follow_redirects=False)
    assert 302 == resp.status_code
    assert resp.location.endswith('/')


@logged_in
def test_logout(db, client):
    cookie = client.get_cookie('session', domain='cyber.local').value
    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)
    db.session.remove()
    with client.application.app_context():
        replay = client.application.test_client()
        replay.set_cookie('session', cookie, domain='cyber.local')
        resp = replay.get('/tokens', follow_redirects=False)
    assert resp.status_code == 302
    assert '/login' in resp.location


def test_logout_not_logged_in(db, client):
    resp = client.post(url_for('tracker.logout'), follow_redirects=False)
    assert 302 == resp.status_code
    assert resp.location.endswith('/')


@logged_in
def test_logout_requires_csrf_protected_post(db, client, monkeypatch):
    monkeypatch.setitem(client.application.config, 'WTF_CSRF_ENABLED', True)
    token = User.query.one().token
    response = client.get('/logout')
    assert response.status_code == 200
    csrf = search(rb'name="csrf_token" type="hidden" value="([^"]+)"', response.data).group(1).decode()
    assert client.head('/logout').status_code == 200
    assert User.query.one().token == token
    for data in ({'confirm': 'y'}, {'confirm': 'y', 'csrf_token': 'invalid'}):
        assert client.post('/logout', data=data).status_code == 400
        assert User.query.one().token == token
    assert client.post('/logout', data={'abort': 'y', 'csrf_token': csrf}).status_code == 302
    assert User.query.one().token == token

    assert client.post('/logout', data={'confirm': 'y', 'csrf_token': csrf}).status_code == 302
    assert User.query.one().token is None
    with client.session_transaction() as session:
        assert '_user_id' not in session


@mark.parametrize('path,revocation', [('/review/intake', 'role'), ('/review/intake', 'active'),
                                    ('/review/intake', 'token'), ('/profile', 'active'),
                                    ('/profile', 'token')])
def test_browser_writes_recheck_session_and_permission(db, tmp_path, path, revocation):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'permissions.sqlite'),
                      'TESTING': True, 'WTF_CSRF_ENABLED': False, 'SERVER_NAME': 'cyber.local'})
    password = 'original-password-0123456789'
    with app.app_context():
        db.create_all()
        db.session.add(User(name='reporter', email='reporter@example.org', salt='salt',
                            password=hash_password(password, 'salt'), role=UserRole.reporter, active=True))
        db.session.commit()
        engine = db.engine
    client = app.test_client()
    assert client.post('/login', data=dict(username='reporter', password=password)).status_code == 302
    data = (dict(title='Private report', source='mail:1') if path == '/review/intake' else
            dict(password_current=password, password='new-password-0123456789',
                 password_repeat='new-password-0123456789'))
    revoked_values = {'role': UserRole.guest, 'active': False, 'token': None}
    ready = Event()
    revoked = Event()
    worker = local()

    def before_write(connection, cursor, statement, parameters, context, executemany):
        if getattr(worker, 'posting', False) and statement.startswith(('UPDATE user ', 'INSERT INTO intake_candidate ')):
            worker.posting = False
            ready.set()
            assert revoked.wait(timeout=5)

    def post():
        worker.posting = True
        return client.post(path, data=data)

    event.listen(engine, 'before_cursor_execute', before_write)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(post)
            try:
                assert ready.wait(timeout=5)
                with app.app_context():
                    db.session.execute(User.__table__.update().values(**{revocation: revoked_values[revocation]}))
                    db.session.commit()
            finally:
                revoked.set()
            assert pending.result().status_code == 403
        with app.app_context():
            assert IntakeCandidate.query.count() == 0
            user = User.query.one()
            assert user.password == hash_password(password, user.salt)
    finally:
        event.remove(engine, 'before_cursor_execute', before_write)
        engine.dispose()


@mark.parametrize('change', ['password', 'active'])
def test_login_rechecks_credentials_before_issuing_session(db, tmp_path, change):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'login.sqlite'),
                      'TESTING': True, 'WTF_CSRF_ENABLED': False, 'SERVER_NAME': 'cyber.local'})
    password = 'original-password-0123456789'
    with app.app_context():
        db.create_all()
        db.session.add(User(name='reporter', email='reporter@example.org', salt='salt',
                            password=hash_password(password, 'salt'), role=UserRole.reporter, active=True))
        db.session.commit()
        engine = db.engine
    client = app.test_client()
    ready = Event()
    changed = Event()
    worker = local()

    def before_write(connection, cursor, statement, parameters, context, executemany):
        if getattr(worker, 'logging_in', False) and statement.startswith('UPDATE user '):
            worker.logging_in = False
            ready.set()
            assert changed.wait(timeout=5)

    def login():
        worker.logging_in = True
        return client.post('/login', data=dict(username='reporter', password=password))

    event.listen(engine, 'before_cursor_execute', before_write)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(login)
            try:
                assert ready.wait(timeout=5)
                with app.app_context():
                    values = ({'password': hash_password('replacement-password-0123456789', 'salt')}
                              if change == 'password' else {'active': False})
                    db.session.execute(User.__table__.update().values(**values))
                    db.session.commit()
            finally:
                changed.set()
            response = pending.result()
        assert client.get('/tokens').status_code == 302
        with client.session_transaction() as session:
            assert '_user_id' not in session
        with app.app_context():
            assert User.query.one().token is None
        assert response.status_code == Unauthorized.code
    finally:
        event.remove(engine, 'before_cursor_execute', before_write)
        engine.dispose()
