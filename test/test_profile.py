from datetime import datetime
from re import findall

from flask import url_for
from flask_login import current_user
from sqlalchemy_continuum import versioning_manager

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker.form.user import ERROR_PASSWORD_CONTAINS_USERNAME
from tracker.form.user import ERROR_PASSWORD_INCORRECT
from tracker.form.user import ERROR_PASSWORD_REPEAT_MISMATCHES
from tracker.model import CVE
from tracker.user import hash_password
from tracker.user import random_string

from .conftest import DEFAULT_USERNAME
from .conftest import assert_logged_in
from .conftest import assert_not_logged_in
from .conftest import logged_in


@logged_in
def test_change_password(db, client):
    cookie = client.get_cookie('session', domain='cyber.local').value
    new_password = DEFAULT_USERNAME[::-1]
    resp = client.post(url_for('tracker.edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password,
                                 password_current=DEFAULT_USERNAME))
    assert resp.status_code == 200
    assert_logged_in(resp)
    db.session.remove()
    with client.application.app_context():
        replay = client.application.test_client()
        replay.set_cookie('session', cookie, domain='cyber.local')
        stale = replay.get('/tokens', follow_redirects=False)
    assert stale.status_code == 302
    assert '/login' in stale.location

    # logout and test if new password was applied
    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)
    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=new_password))
    assert_logged_in(resp)
    assert DEFAULT_USERNAME == current_user.name


@logged_in
def test_password_change_preserves_whitespace(db, client):
    password = '  correct horse battery  '
    data = dict(password=password, password_repeat=password.strip(), password_current=DEFAULT_USERNAME)
    response = client.post('/profile', data=data)
    assert response.status_code == 200
    assert ERROR_PASSWORD_REPEAT_MISMATCHES.encode() in response.data

    data['password_repeat'] = password
    assert client.post('/profile', data=data).status_code == 302
    assert current_user.password == hash_password(password, current_user.salt)

    data = dict(password='a different horse battery', password_repeat='a different horse battery',
                password_current=password.strip())
    response = client.post('/profile', data=data)
    assert response.status_code == 200
    assert ERROR_PASSWORD_INCORRECT.encode() in response.data
    data['password_current'] = password
    assert client.post('/profile', data=data).status_code == 302

    spaces = ' ' * TRACKER_PASSWORD_LENGTH_MIN
    data = dict(password=spaces, password_repeat=spaces, password_current='a different horse battery')
    assert client.post('/profile', data=data).status_code == 302
    assert current_user.password == hash_password(spaces, current_user.salt)
    data = dict(password=password, password_repeat=password, password_current=spaces)
    assert client.post('/profile', data=data).status_code == 302


@logged_in
def test_password_change_redirect_keeps_application_prefix(db, client):
    password = DEFAULT_USERNAME[::-1]
    response = client.post('/profile', environ_overrides={'SCRIPT_NAME': '/tracker'},
                           data=dict(password=password, password_repeat=password,
                                     password_current=DEFAULT_USERNAME))
    assert response.status_code == 302
    assert response.location == '/tracker/'


@logged_in
def test_invalid_password_length(db, client):
    resp = client.post(url_for('tracker.edit_own_user_profile'), follow_redirects=True,
                       data=dict(password='1234', new_password='1234', password_current=DEFAULT_USERNAME))
    assert 'Field must be between {} and {} characters long.' \
           .format(TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX) in resp.data.decode()
    assert resp.status_code == 200


@logged_in
def test_password_must_not_contain_username(db, client):
    new_password = '{}123'.format(DEFAULT_USERNAME)
    resp = client.post(url_for('tracker.edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password,
                                 password_current=DEFAULT_USERNAME))
    assert resp.status_code == 200
    assert ERROR_PASSWORD_CONTAINS_USERNAME in resp.data.decode()


@logged_in
def test_password_repeat_mismatches(db, client):
    new_password = random_string()
    resp = client.post(url_for('tracker.edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password[::-1],
                                 password_current=DEFAULT_USERNAME))
    assert resp.status_code == 200
    assert ERROR_PASSWORD_REPEAT_MISMATCHES in resp.data.decode()


@logged_in
def test_current_password_incorrect(db, client):
    new_password = random_string()
    resp = client.post(url_for('tracker.edit_own_user_profile'), follow_redirects=True,
                       data=dict(password=new_password, password_repeat=new_password,
                                 password_current=new_password))
    assert resp.status_code == 200
    assert ERROR_PASSWORD_INCORRECT in resp.data.decode()


@logged_in
def test_user_log_orders_transactions_with_equal_timestamps(db, client):
    Transaction = versioning_manager.transaction_cls
    for index in range(12):
        issue = CVE.new('CVE-2026-{:04d}'.format(1000 + index))
        db.session.add(issue)
        db.session.commit()
    Transaction.query.update({'issued_at': datetime(2026, 9, 1), 'user_id': current_user.id})
    db.session.commit()

    def logged_issues(page):
        path = '/user/{}/log/page/{}'.format(DEFAULT_USERNAME, page)
        response = client.get(path)
        assert response.status_code == 200
        return findall(rb'href="/(CVE-2026-[0-9]+)"', response.data)

    assert logged_issues(1) == [f'CVE-2026-{number}'.encode() for number in range(1011, 1001, -1)]
    assert logged_issues(2) == [b'CVE-2026-1001', b'CVE-2026-1000']
