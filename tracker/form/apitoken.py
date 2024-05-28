from wtforms import StringField
from wtforms import SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import Length

from tracker.model.apitoken import ApiToken

from .base import BaseForm


class ApiTokenForm(BaseForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=ApiToken.NAME_LENGTH)])
    submit = SubmitField('Create token')


class ApiTokenRevokeForm(BaseForm):
    submit = SubmitField('Revoke')
