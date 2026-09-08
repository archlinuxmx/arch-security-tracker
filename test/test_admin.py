from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from threading import Event
from threading import local

from flask import url_for
from flask_login import current_user
from pytest import mark
from sqlalchemy import event
from sqlalchemy_continuum import version_class
from sqlalchemy_continuum import versioning_manager
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound
from werkzeug.exceptions import Unauthorized

from tracker import create_app
from tracker.form.admin import ERROR_EMAIL_EXISTS
from tracker.form.admin import ERROR_USERNAME_EXISTS
from tracker.form.login import ERROR_ACCOUNT_DISABLED
from tracker.model import CVE
from tracker.model import User
from tracker.model.enum import UserRole
from tracker.user import hash_password
from tracker.user import random_string

from .conftest import DEFAULT_USERNAME
from .conftest import assert_logged_in
from .conftest import assert_not_logged_in
from .conftest import create_user
from .conftest import default_issue_dict
from .conftest import logged_in

USERNAME = 'cyberwehr87654321'
PASSWORD = random_string()
EMAIL = '{}@cyber.cyber'.format(USERNAME)


@create_user(username=USERNAME, password=PASSWORD, role=UserRole.administrator)
@logged_in
def test_delete_user(db, client):
    resp = client.post(url_for('tracker.delete_user', username=USERNAME), follow_redirects=True,
                       data=dict(confirm='confirm'))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD))
    assert_not_logged_in(resp, status_code=Unauthorized.code)


@logged_in
def test_delete_last_admin_fails(db, client):
    resp = client.post(url_for('tracker.delete_user', username=DEFAULT_USERNAME), follow_redirects=True,
                       data=dict(confirm='confirm'))
    assert resp.status_code == Forbidden.code
    for role, active in ((UserRole.administrator, False), (UserRole.reporter, True)):
        resp = client.post(url_for('tracker.edit_user', username=DEFAULT_USERNAME),
                           data=dict(username=DEFAULT_USERNAME, email=current_user.email,
                                     role=role.name, active='y' if active else ''))
        assert resp.status_code == Forbidden.code
        assert current_user.role == UserRole.administrator
        assert current_user.active


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_delete_user_preserves_audit_attribution(db, client):
    issue_id = 'CVE-2026-99887'
    with client.application.app_context():
        editor = client.application.test_client()
        assert editor.post('/login', data=dict(username=USERNAME, password=PASSWORD)).status_code == 302
        assert editor.post('/cve/add', data=default_issue_dict(dict(cve=issue_id))).status_code == 302
    user = User.query.filter_by(name=USERNAME).one()
    transaction = versioning_manager.transaction_cls.query.one()
    assert transaction.user_id == user.id
    version = version_class(CVE).query.filter_by(id=issue_id).one()
    assert version.transaction_id == transaction.id

    response = client.post(url_for('tracker.delete_user', username=USERNAME), data=dict(confirm='y'))
    assert response.status_code == Forbidden.code
    assert b'Deactivate the account instead' in response.data
    assert User.query.filter_by(name=USERNAME).one().id == user.id
    assert versioning_manager.transaction_cls.query.one().user_id == user.id
    assert version_class(CVE).query.filter_by(id=issue_id).one().transaction_id == transaction.id
    response = client.post(url_for('tracker.edit_user', username=USERNAME),
                           data=dict(username=USERNAME, email=user.email, role=user.role.name))
    assert response.status_code == 302
    assert not user.active
    assert versioning_manager.transaction_cls.query.one().user_id == user.id


@mark.parametrize('action,cross_account', [('edit', False), ('delete', False),
                                         ('edit', True), ('delete', True)])
def test_concurrent_admin_changes_preserve_an_administrator(db, tmp_path, action, cross_account):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'accounts.sqlite'),
                      'TESTING': True, 'WTF_CSRF_ENABLED': False, 'SERVER_NAME': 'cyber.local'})
    names = ('alpha', 'beta')
    password = 'test-password-0123456789'
    with app.app_context():
        db.create_all()
        for name in names:
            db.session.add(User(name=name, email=name + '@example.org', salt='salt',
                                password=hash_password(password, 'salt'),
                                role=UserRole.administrator, active=True))
        db.session.commit()
        engine = db.engine
    clients = [app.test_client() for name in names]
    for name, client in zip(names, clients):
        assert client.post('/login', data={'username': name, 'password': password}).status_code == 302

    gate = Barrier(2)
    worker = local()

    def before_write(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith(('UPDATE user ', 'DELETE FROM user ')) and not getattr(worker, 'started', False):
            worker.started = True
            gate.wait(timeout=5)

    def change(index):
        name = names[1 - index if cross_account else index]
        data = (dict(username=name, email=name + '@example.org', role='reporter', active='y')
                if action == 'edit' else dict(confirm='y'))
        return clients[index].post('/user/' + name + '/' + action, data=data).status_code

    event.listen(engine, 'before_cursor_execute', before_write)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(change, range(2)))
        assert responses.count(302) == 1
        assert all(status in (302, 403, 404) for status in responses)
        with app.app_context():
            assert User.query.filter_by(active=True, role=UserRole.administrator).count() == 1
    finally:
        event.remove(engine, 'before_cursor_execute', before_write)
        engine.dispose()


@logged_in
def test_delete_user_not_found(db, client):
    resp = client.post(url_for('tracker.delete_user', username='nobody'), follow_redirects=True,
                       data=dict(confirm='confirm'))
    assert resp.status_code == NotFound.code


@create_user(username=USERNAME, password=PASSWORD, role=UserRole.administrator)
@logged_in
def test_delete_form_invalid(db, client):
    resp = client.post(url_for('tracker.delete_user', username=USERNAME),
                       data=dict())
    assert resp.status_code != 200


@logged_in
def test_create_user(db, client):
    role = UserRole.security_team
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD,
                                 email=EMAIL, active=True, role=role.name))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD))
    assert_logged_in(resp)
    assert USERNAME == current_user.name
    assert EMAIL == current_user.email
    assert role == current_user.role


@logged_in
def test_account_passwords_preserve_whitespace(db, client):
    data = dict(username=USERNAME, email=EMAIL, password=' ',
                role=UserRole.reporter.name, active=True)
    assert client.post('/user/create', data=data).status_code == 200
    assert User.query.filter_by(name=USERNAME).count() == 0
    data['password'] = '  correct horse battery  '
    assert client.post('/user/create', data=data).status_code == 302
    user = User.query.filter_by(name=USERNAME).one()
    assert user.password == hash_password(data['password'], user.salt)
    previous_password = user.password
    data['password'] = ' '
    assert client.post(url_for('tracker.edit_user', username=USERNAME), data=data).status_code == 200
    assert user.password == previous_password
    data['password'] = ' another horse battery '
    assert client.post(url_for('tracker.edit_user', username=USERNAME), data=data).status_code == 302
    assert user.password == hash_password(data['password'], user.salt)
    client.post('/logout')
    assert client.post('/login', data=dict(username=USERNAME, password=data['password'])).status_code == 302


@logged_in
def test_account_links_and_redirects_keep_application_prefix(db, client):
    environ = {'SCRIPT_NAME': '/tracker'}
    data = dict(username=USERNAME, email=EMAIL, password=PASSWORD,
                role=UserRole.reporter.name, active=True)
    response = client.post('/user/create', data=data, environ_overrides=environ)
    assert response.status_code == 302
    assert response.location == '/tracker/user'

    page = client.get('/user', environ_overrides=environ).data
    assert b'href="/tracker/user/create"' in page
    for action in ('log', 'edit', 'delete'):
        assert f'href="/tracker/user/{USERNAME}/{action}"'.encode() in page

    response = client.post(f'/user/{USERNAME}/edit', data=data, environ_overrides=environ)
    assert response.status_code == 302
    assert response.location == '/tracker/user'
    page = client.get(f'/user/{USERNAME}/delete', environ_overrides=environ).data
    assert f'href="/tracker/user/{USERNAME}/edit"'.encode() in page
    for action in ('abort', 'confirm'):
        response = client.post(f'/user/{USERNAME}/delete', data={action: 'y'}, environ_overrides=environ)
        assert response.status_code == 302
        assert response.location == '/tracker/user'
    assert User.query.filter_by(name=USERNAME).count() == 0


@logged_in
def test_create_duplicate_user_fails(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=PASSWORD,
                                 email=EMAIL, active=True))
    assert resp.status_code == 200
    assert ERROR_USERNAME_EXISTS in resp.data.decode()


@logged_in
def test_create_duplicate_email_fails(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=USERNAME, password=PASSWORD,
                                 email=current_user.email, active=True))
    assert resp.status_code == 200
    assert ERROR_EMAIL_EXISTS in resp.data.decode()


@logged_in
def test_create_incomplete_form(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(email=EMAIL, active=True))
    assert resp.status_code == 200
    assert 'This field is required.' in resp.data.decode()


@logged_in
def test_create_user_in_password(db, client):
    resp = client.post(url_for('tracker.create_user'), follow_redirects=True,
                       data=dict(username=USERNAME,
                           password=USERNAME+PASSWORD, email=EMAIL,
                           active=True))
    assert resp.status_code == 200
    assert 'Password must not contain the username.' in resp.data.decode()


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_edit_user(db, client):
    for username, email, message in ((DEFAULT_USERNAME, EMAIL, ERROR_USERNAME_EXISTS),
                                     (USERNAME, current_user.email, ERROR_EMAIL_EXISTS)):
        resp = client.post(url_for('tracker.edit_user', username=USERNAME),
                           data=dict(username=username, email=email, role=UserRole.reporter.name, active=True))
        assert resp.status_code == 200
        assert message in resp.data.decode()
    new_password = random_string()
    new_email = '{}foo'.format(EMAIL)
    new_role = UserRole.security_team
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=new_email, password=new_password,
                       role=new_role.name, active=True))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data={'username': USERNAME, 'password': new_password})
    assert_logged_in(resp)
    assert USERNAME == current_user.name
    assert new_email == current_user.email
    assert new_role == current_user.role


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_get_edit_user(db, client):
    resp = client.get(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True)
    assert resp.status_code == 200
    assert 'Edit {}'.format(USERNAME) in resp.data.decode()


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_edit_preserves_password(db, client):
    new_email = '{}foo'.format(EMAIL)
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=new_email, active=True))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data={'username': USERNAME, 'password': PASSWORD})
    assert_logged_in(resp)
    assert USERNAME == current_user.name
    assert new_email == current_user.email


@create_user(username=USERNAME, password=PASSWORD)
@logged_in
def test_deactive_user(db, client):
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=EMAIL, password=PASSWORD))
    assert resp.status_code == 200

    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)

    resp = client.post(url_for('tracker.login'), data={'username': USERNAME, 'password': PASSWORD})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()


@create_user(username=USERNAME, password=PASSWORD)
@logged_in(role=UserRole.security_team)
def test_edit_requires_admin(db, client):
    resp = client.post(url_for('tracker.edit_user', username=USERNAME), follow_redirects=True,
                       data=dict(username=USERNAME, email=EMAIL, password=PASSWORD))
    assert resp.status_code == Forbidden.code
    assert 'text/html; charset=utf-8' == resp.content_type


@create_user(username=USERNAME, password=PASSWORD)
@logged_in(role=UserRole.security_team)
def test_list_user(db, client):
    resp = client.get(url_for('tracker.list_user'), follow_redirects=True)
    assert resp.status_code == 200
    assert 'text/html; charset=utf-8' == resp.content_type
    assert USERNAME in resp.data.decode()


def test_admin_creation_rechecks_revoked_permission(db, tmp_path):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'accounts.sqlite'),
                      'TESTING': True, 'WTF_CSRF_ENABLED': False, 'SERVER_NAME': 'cyber.local'})
    password = 'test-password-0123456789'
    with app.app_context():
        db.create_all()
        for name in ('alpha', 'beta'):
            db.session.add(User(name=name, email=name + '@example.org', salt='salt',
                                password=hash_password(password, 'salt'),
                                role=UserRole.administrator, active=True))
        db.session.commit()
        engine = db.engine
    creator, revoker = app.test_client(), app.test_client()
    for client, name in ((creator, 'alpha'), (revoker, 'beta')):
        assert client.post('/login', data=dict(username=name, password=password)).status_code == 302

    ready = Event()
    revoked = Event()
    worker = local()

    def before_write(connection, cursor, statement, parameters, context, executemany):
        if getattr(worker, 'creating', False) and statement.startswith(('INSERT INTO user ', 'UPDATE user ')):
            worker.creating = False
            ready.set()
            assert revoked.wait(timeout=5)

    def create():
        worker.creating = True
        return creator.post('/user/create', data=dict(username='newadmin', email='newadmin@example.org',
                                                     password=password, role='administrator', active='y'))

    event.listen(engine, 'before_cursor_execute', before_write)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(create)
            try:
                assert ready.wait(timeout=5)
                response = revoker.post('/user/alpha/edit', data=dict(username='alpha', email='alpha@example.org',
                                                                    role='reporter', active='y'))
                assert response.status_code == 302
            finally:
                revoked.set()
            assert pending.result().status_code == Forbidden.code
        with app.app_context():
            assert User.query.filter_by(name='newadmin').count() == 0
    finally:
        event.remove(engine, 'before_cursor_execute', before_write)
        engine.dispose()
