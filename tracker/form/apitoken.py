from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.widgets import CheckboxInput

from tracker.model.apitoken import ApiToken

from .base import BaseForm


class ApiTokenForm(BaseForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=ApiToken.NAME_LENGTH)])
    scope = SelectMultipleField('Scopes', default=[ApiToken.SCOPE],
                                choices=[(scope, scope) for scope in ApiToken.SCOPES],
                                validators=[DataRequired(message='Select at least one scope.')],
                                option_widget=CheckboxInput())
    submit = SubmitField('Create token')


class ApiTokenRevokeForm(BaseForm):
    submit = SubmitField('Revoke')
