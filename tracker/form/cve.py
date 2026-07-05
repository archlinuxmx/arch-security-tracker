from wtforms import BooleanField
from wtforms import HiddenField
from wtforms import SelectField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.validators import Optional

from tracker.cvss import parse_cvss
from tracker.form.validators import ValidIssue
from tracker.form.validators import ValidURLs
from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.enum import Remote
from tracker.model.enum import Severity

from .base import BaseForm


class CVEForm(BaseForm):
    cve = StringField(u'CVE', validators=[DataRequired(), ValidIssue()])
    description = TextAreaField(u'Description', validators=[Optional(), Length(max=CVE.DESCRIPTION_LENGTH)])
    issue_type = SelectField(u'Type', choices=[(item, item.capitalize()) for item in issue_types], validators=[DataRequired()])
    severity = SelectField(u'Severity', choices=[(e.name, e.label) for e in [*Severity]], validators=[DataRequired()])
    remote = SelectField(u'Remote', choices=[(e.name, e.label) for e in [*Remote]], validators=[DataRequired()])
    reference = TextAreaField(u'References', validators=[Optional(), Length(max=CVE.REFERENCES_LENGTH), ValidURLs()])
    notes = TextAreaField(u'Notes', validators=[Optional(), Length(max=CVE.NOTES_LENGTH)])
    cvss_version = SelectField('CVSS version', choices=[('', 'None'), ('3.0', '3.0'), ('3.1', '3.1'), ('4.0', '4.0')], default='', validators=[Optional()])
    cvss_score = StringField('CVSS score', validators=[Optional(), Length(max=16)])
    cvss_vector = StringField('CVSS vector', validators=[Optional(), Length(max=256)])
    cvss_source = StringField('CVSS source', validators=[Optional(), Length(max=2048)])
    changed = HiddenField(u'Changed', validators=[Optional()])
    changed_latest = HiddenField(u'Latest Changed', validators=[Optional()])
    force_submit = BooleanField(u'Force update', default=False, validators=[Optional()])
    submit = SubmitField(u'submit')

    def __init__(self, edit=False):
        super().__init__()
        self.edit = edit
        self.cvss_values = {}
        if edit:
            self.cve.render_kw = {'readonly': True}

    def load_cvss(self, cve):
        for name in ('version', 'score', 'vector', 'source'):
            value = getattr(cve, 'cvss_' + name)
            getattr(self, 'cvss_' + name).data = str(value) if value is not None else ''

    def validate(self, **kwargs):
        if not super().validate(**kwargs):
            return False
        fields = {name: getattr(self, 'cvss_' + name) for name in ('version', 'score', 'vector', 'source')}
        if not any(field.raw_data for field in fields.values()):
            return True
        try:
            value = None
            if any(field.data for field in fields.values()):
                value = {name: field.data for name, field in fields.items()}
                try:
                    value['score'] = float(value['score'])
                except (ValueError, TypeError):
                    raise ValueError('CVSS score must be a number.')
            self.cvss_values = parse_cvss(value)
        except ValueError as error:
            self.cvss_score.errors.append(str(error))
            return False
        return True
