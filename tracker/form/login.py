from hmac import compare_digest

from wtforms import PasswordField
from wtforms import StringField
from wtforms import SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import InputRequired
from wtforms.validators import Length

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker.model.user import User
from tracker.user import hash_password
from tracker.user import random_string

from .base import BaseForm

ERROR_INVALID_USERNAME_PASSWORD = 'Invalid username or password.'
ERROR_ACCOUNT_DISABLED = 'Account is disabled.'
dummy_password = hash_password(random_string(), random_string())


class LoginForm(BaseForm):
    username = StringField(u'Username', validators=[DataRequired(), Length(max=User.NAME_LENGTH)])
    password = PasswordField(u'Password', validators=[InputRequired(), Length(min=TRACKER_PASSWORD_LENGTH_MIN, max=TRACKER_PASSWORD_LENGTH_MAX)])
    login = SubmitField(u'login')

    def validate(self, **kwargs):
        self.user = None
        rv = super().validate(**kwargs)
        if not rv:
            return False

        def fail():
            self.password.errors.append(ERROR_INVALID_USERNAME_PASSWORD)
            return False

        user = User.query.filter(User.name == self.username.data).first()
        if not user:
            compare_digest(dummy_password, hash_password(self.password.data, 'the cake is a lie!'))
            return fail()
        if not compare_digest(user.password, hash_password(self.password.data, user.salt)):
            return fail()
        if not user.active:
            self.username.errors.append(ERROR_ACCOUNT_DISABLED)
            return False

        # A reset or deactivation may have committed while the password was
        # checked. Hold the matching account through session-token issuance.
        table = User.__table__
        result = db.session.execute(table.update().where(
            table.c.id == user.id, table.c.name == user.name,
            table.c.password == user.password, table.c.salt == user.salt,
            table.c.active.is_(True)).values(id=table.c.id))
        if result.rowcount != 1:
            db.session.rollback()
            return fail()
        db.session.expire_all()
        self.user = user
        return True
