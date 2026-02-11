from wtforms import BooleanField
from wtforms import HiddenField
from wtforms import IntegerField
from wtforms import SelectField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.validators import Optional
from wtforms.validators import Regexp
from wtforms.validators import ValidationError

from tracker.form.base import BaseForm
from tracker.util import valid_reference_url


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


class IntakeForm(BaseForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    source = StringField('Source reference (private)', validators=[DataRequired(), Length(max=2048)])
    cve_name = StringField('CVE identifier (optional)', validators=[Optional(), Regexp(r'^CVE-[0-9]{4}-[0-9]{4,}$'), Length(max=64)])
    evidence = TextAreaField('Source evidence (private)', validators=[Length(max=65536)])
    description = TextAreaField('Proposed public description', validators=[Length(max=4096)])
    reference = TextAreaField('Proposed public HTTP(S) references, one per line', validators=[Length(max=4096)])
    submit = SubmitField('Add candidate')

    def validate_reference(self, field):
        for value in (field.data or '').splitlines():
            if not valid_reference_url(value):
                raise ValidationError('Public references must be HTTP(S) URLs, one per line.')


class IntakeDecisionForm(BaseForm):
    revision = IntegerField('Revision', validators=[DataRequired()])
    cve_name = StringField('CVE identifier', validators=[Optional(), Regexp(r'^CVE-[0-9]{4}-[0-9]{4,}$'), Length(max=64)])
    state = SelectField('Decision', choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')])
    rationale = TextAreaField('Decision rationale (private)', validators=[DataRequired(), Length(max=4096)])
    submit = SubmitField('Save decision')


class IntakePromoteForm(BaseForm):
    revision = IntegerField('Revision', validators=[DataRequired()])
    submit = SubmitField('Create public CVE from approved candidate')


class MergeForm(BaseForm):
    source = StringField('Group to retire', validators=[DataRequired(), Regexp(r'^AVG-[0-9]+$')])
    destination = StringField('Group to retain', validators=[DataRequired(), Regexp(r'^AVG-[0-9]+$')])
    source_revision = HiddenField(validators=[DataRequired()])
    destination_revision = HiddenField(validators=[DataRequired()])
    rationale = TextAreaField('Merge rationale (private)', validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField('Merge groups')


class RevertForm(BaseForm):
    revision = HiddenField(validators=[DataRequired()])
    transaction_id = SelectField('Historical transaction', coerce=int, validators=[DataRequired()])
    rationale = TextAreaField('Correction rationale (private)', validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField('Restore content as a new revision')
