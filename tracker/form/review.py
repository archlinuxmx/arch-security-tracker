from wtforms import BooleanField
from wtforms import HiddenField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms.validators import DataRequired
from wtforms.validators import Length

from tracker.form.base import BaseForm


class ReviewLookupForm(BaseForm):
    target = StringField('CVE or AVG', validators=[DataRequired(), Length(max=64)])
    submit = SubmitField('Open review')


class AssessmentForm(BaseForm):
    revision = HiddenField(validators=[DataRequired()])
    required = BooleanField('Further review required')
    rationale = TextAreaField('Assessment rationale (reporters only)', validators=[DataRequired(), Length(max=4096)])
    submit = SubmitField('Save assessment')


class SignoffForm(BaseForm):
    revision = HiddenField(validators=[DataRequired()])
    rationale = TextAreaField('Signoff comment', validators=[DataRequired(), Length(max=4096)])
    submit = SubmitField('Sign off this revision')
