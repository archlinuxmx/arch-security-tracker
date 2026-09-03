from concurrent.futures import ThreadPoolExecutor
from threading import Event
from threading import local
from unittest.mock import patch

from authlib.integrations.base_client.errors import AuthlibBaseError
from flask_login import current_user
from pytest import mark
from sqlalchemy import event
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import Forbidden

from config import SSO_ADMINISTRATOR_GROUP
from config import SSO_REPORTER_GROUP
from config import SSO_SECURITY_TEAM_GROUP
from tracker import create_app
from tracker.form.login import ERROR_ACCOUNT_DISABLED
from tracker.model import User
from tracker.model.apitoken import ApiToken
from tracker.model.enum import UserRole
from tracker.user import get_user_role_from_idp_groups
from tracker.view.login import LOGIN_ERROR_EMAIL_ADDRESS_NOT_VERIFIED
from tracker.view.login import LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB
from tracker.view.login import \
    LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME
from tracker.view.login import LOGIN_ERROR_MISSING_EMAIL_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_GROUPS_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_USER_SUB_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_USERINFO_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_MISSING_USERNAME_FROM_TOKEN
from tracker.view.login import LOGIN_ERROR_PERMISSION_DENIED
from tracker.view.login import \
    LOGIN_ERROR_USERNAME_ASSOCIATE_WITH_DIFFERENT_EMAIL
from tracker.view.login import sso_auth

from .conftest import create_user

DEFAULTEMAIL = "cyberwehr12345678@cyber.cyber"
UPDATEDEMAIL = "cyberwehr1@cyber.cyber"
TESTINGSUB = "wasd"
TESTINGNAME = "Peter"


class MockedIdp(object):
    def __init__(self, username=TESTINGNAME, email=DEFAULTEMAIL, sub=TESTINGSUB, groups=["Administrator"],
                 verified=True, throws=None, has_userinfo=True):
        self.email = email
        self.sub = sub
        self.groups = groups
        self.verified = verified
        self.username = username
        self.throws = throws
        self.has_userinfo = has_userinfo

    def authorize_access_token(self):
        if self.throws:
            raise self.throws
        if self.has_userinfo:
            return {'userinfo': self.parse_id_token(None, None)}
        return {}

    def parse_id_token(self, token, nonce, claims_options=None, leeway=120):
        token = {}
        if self.sub is not None:
            token["sub"] = self.sub
        if self.email is not None:
            token["email"] = self.email
        if self.verified is not None:
            token["email_verified"] = self.verified
        if self.groups is not None:
            token["groups"] = self.groups
        if self.username is not None:
            token["preferred_username"] = self.username
        return token


@create_user(username=TESTINGNAME, email=DEFAULTEMAIL)
def test_successful_authentication_and_role_email_update(app, db):
    initial_user = User.query.all()[0]
    assert initial_user.email != UPDATEDEMAIL
    assert initial_user.role != UserRole.administrator
    assert initial_user.idp_id is None
    user_id = initial_user.id

    for email in (DEFAULTEMAIL, UPDATEDEMAIL):
        with app.app_context(), app.test_request_context('/login'), \
                patch('tracker.oauth.idp', MockedIdp(email=email), create=True):
            result = sso_auth()
            assert 302 == result.status_code
            assert User.query.count() == 1
            assert current_user.is_authenticated
            assert current_user.id == user_id
            assert current_user.idp_id == TESTINGSUB
            assert current_user.email == email
            assert current_user.role == UserRole.administrator

    with app.app_context(), app.test_request_context('/login'), \
            patch('tracker.oauth.idp', MockedIdp(email=UPDATEDEMAIL, sub='different-sub'), create=True):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB in result.data.decode()
        assert not current_user.is_authenticated
        assert User.query.one().idp_id == TESTINGSUB


@patch('tracker.oauth.idp', MockedIdp(email=DEFAULTEMAIL, sub="STONKS"), create=True)
@create_user(idp_id="wasd")
def test_impersonation_prevention(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_SUB in result.data.decode()

        assert not current_user.is_authenticated


@patch('tracker.oauth.idp', MockedIdp(email=UPDATEDEMAIL, sub="STONKS"), create=True)
@create_user(username=TESTINGNAME, idp_id="wasd")
def test_username_associated_with_different_email(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_USERNAME_ASSOCIATE_WITH_DIFFERENT_EMAIL in result.data.decode()

        assert not current_user.is_authenticated


@patch('tracker.oauth.idp', MockedIdp(email=UPDATEDEMAIL, sub="STONKS"), create=True)
@create_user(username="foobar", email=UPDATEDEMAIL)
def test_email_associated_with_different_username(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME in result.data.decode()

        assert not current_user.is_authenticated

    linked = User(name=TESTINGNAME, email=DEFAULTEMAIL, idp_id='STONKS', salt='salt',
                  password='unused', role=UserRole.reporter, active=True)
    db.session.add(linked)
    db.session.commit()
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ASSOCIATED_WITH_DIFFERENT_USERNAME in result.data.decode()
        assert not current_user.is_authenticated
        assert linked.email == DEFAULTEMAIL
        assert linked.role == UserRole.reporter
        assert linked.token is None


@patch('tracker.oauth.idp', MockedIdp(email=DEFAULTEMAIL), create=True)
def test_jit_provisioning(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert 302 == result.status_code

        assert current_user.is_authenticated
        assert current_user.email == DEFAULTEMAIL
        assert current_user.role == UserRole.administrator
        assert current_user.idp_id == TESTINGSUB
        assert current_user.name == TESTINGNAME
        assert current_user.active


@mark.parametrize('subject', [None, TESTINGSUB])
@mark.parametrize('groups', [['Administrator'], []])
@create_user(username=TESTINGNAME, email=DEFAULTEMAIL, active=False)
def test_disabled_account_cannot_sign_in_through_sso(app, db, subject, groups):
    user = User.query.one()
    user.idp_id = subject
    db.session.commit()
    with app.test_request_context('/login'), \
            patch('tracker.oauth.idp', MockedIdp(email=DEFAULTEMAIL, groups=groups), create=True):
        result = sso_auth()
        assert result.status_code == Forbidden.code
        message = ERROR_ACCOUNT_DISABLED if groups or subject else LOGIN_ERROR_PERMISSION_DENIED
        assert message in result.data.decode()
        assert not current_user.is_authenticated
        assert user.idp_id == subject
        assert user.role == UserRole.reporter
        assert user.token is None


@patch('tracker.oauth.idp', MockedIdp(verified=False), create=True)
def test_verified_email_requirement(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_EMAIL_ADDRESS_NOT_VERIFIED in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(groups=["foobar"]), create=True)
def test_permission_denied_lack_of_group(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert Forbidden.code == result.status_code
        assert LOGIN_ERROR_PERMISSION_DENIED in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()

@patch('tracker.oauth.idp', MockedIdp(has_userinfo=False), create=True)
def test_missing_userinfo_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_USERINFO_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()

@patch('tracker.oauth.idp', MockedIdp(sub=None), create=True)
def test_missing_sub_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_USER_SUB_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(email=None), create=True)
def test_missing_email_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_EMAIL_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(username=None), create=True)
def test_missing_username_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_USERNAME_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(groups=None), create=True)
def test_missing_group_from_token(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert LOGIN_ERROR_MISSING_GROUPS_FROM_TOKEN in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


@patch('tracker.oauth.idp', MockedIdp(throws=AuthlibBaseError(error="foo", description="foo bar error")), create=True)
def test_token_authorization_fails(app, db):
    with app.test_request_context('/login'):
        result = sso_auth()
        assert BadRequest.code == result.status_code
        assert "foo bar error" in result.data.decode()

        assert not current_user.is_authenticated
        assert not User.query.all()


def test_get_user_role_from_idp_groups_no_match():
    assert get_user_role_from_idp_groups(['random']) is None


def test_get_user_role_from_idp_groups_returns_highest_role():
    assert get_user_role_from_idp_groups([SSO_REPORTER_GROUP, SSO_ADMINISTRATOR_GROUP,
                                          SSO_SECURITY_TEAM_GROUP]).is_administrator


def test_get_user_role_from_idp_groups_same_multiple_times():
    assert get_user_role_from_idp_groups([SSO_REPORTER_GROUP, SSO_REPORTER_GROUP,
                                          "foo", "foo"]).is_reporter


@mark.parametrize('groups', [[], ['unrelated']])
@create_user(username=TESTINGNAME, email=DEFAULTEMAIL, idp_id=TESTINGSUB, role=UserRole.administrator)
def test_sso_group_removal_revokes_existing_access(app, db, client, groups):
    with patch('tracker.view.login.SSO_ENABLED', True), \
            patch('tracker.oauth.idp', MockedIdp(), create=True):
        assert client.get('/login?code=allowed').status_code == 302
    cookie = client.get_cookie('session', domain='cyber.local').value
    user = User.query.one()
    token, secret = ApiToken.issue(user, 'existing token')
    db.session.add(token)
    db.session.commit()
    headers = {'Authorization': 'Bearer ' + secret}
    assert client.post('/api/v1/cves', json={'name': 'CVE-2026-99881'}, headers=headers).status_code == 201

    with app.app_context(), app.test_request_context('/login'), \
            patch('tracker.oauth.idp', MockedIdp(groups=groups), create=True):
        result = sso_auth()
        assert result.status_code == Forbidden.code
        assert not current_user.is_authenticated
    db.session.expire_all()
    user = User.query.one()
    assert user.role == UserRole.guest
    assert user.token is None
    assert user.active
    assert client.post('/api/v1/cves', json={'name': 'CVE-2026-99882'}, headers=headers).status_code == 403
    with app.app_context():
        replay = app.test_client()
        replay.set_cookie('session', cookie, domain='cyber.local')
        assert replay.get('/tokens').status_code == 302

    with app.app_context(), app.test_request_context('/login'), \
            patch('tracker.oauth.idp', MockedIdp(), create=True):
        assert sso_auth().status_code == 302
        assert current_user.role == UserRole.administrator


@create_user(username=TESTINGNAME, email=DEFAULTEMAIL, role=UserRole.administrator)
def test_denied_sso_login_does_not_change_unlinked_account(app, db):
    with app.test_request_context('/login'), \
            patch('tracker.oauth.idp', MockedIdp(groups=[]), create=True):
        assert sso_auth().status_code == Forbidden.code
    user = User.query.one()
    assert user.role == UserRole.administrator
    assert user.idp_id is None


@mark.parametrize('subject,change', [(None, 'active'), (TESTINGSUB, 'active'), (None, 'idp_id')])
def test_sso_rechecks_account_before_issuing_session(db, tmp_path, subject, change):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'sso.sqlite'),
                      'TESTING': True, 'WTF_CSRF_ENABLED': False, 'SERVER_NAME': 'cyber.local'})
    with app.app_context():
        db.create_all()
        db.session.add(User(name=TESTINGNAME, email=DEFAULTEMAIL, salt='salt', password='unused',
                            role=UserRole.reporter, active=True, idp_id=subject))
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
        return client.get('/login?code=allowed')

    event.listen(engine, 'before_cursor_execute', before_write)
    try:
        with patch('tracker.view.login.SSO_ENABLED', True), \
                patch('tracker.oauth.idp', MockedIdp(), create=True), \
                ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(login)
            try:
                assert ready.wait(timeout=5)
                with app.app_context():
                    values = {'active': False} if change == 'active' else {'idp_id': 'another-subject'}
                    db.session.execute(User.__table__.update().values(**values))
                    db.session.commit()
            finally:
                changed.set()
            response = pending.result()
        with app.app_context():
            user = User.query.one()
            assert user.idp_id == ('another-subject' if change == 'idp_id' else subject)
            assert user.token is None
            assert user.role == UserRole.reporter
        with client.session_transaction() as session:
            assert '_user_id' not in session
        assert response.status_code == Forbidden.code
    finally:
        event.remove(engine, 'before_cursor_execute', before_write)
        engine.dispose()
