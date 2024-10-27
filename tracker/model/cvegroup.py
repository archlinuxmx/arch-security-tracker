from datetime import datetime

from tracker import db

from .advisory import Advisory
from .advisory import advisory_type_for
from .cvegrouppackage import CVEGroupPackage
from .enum import Publication
from .enum import Severity
from .enum import Status
from .enum import highest_severity

pkgname_regex = r'^([a-z\d@\.\_\+-]+)$'
pkgver_regex = r'^(\d+:)?([\w]+[\._+]*)+\-\d+(\.\d+)?$'
vulnerability_group_regex = r'^AVG-\d+$'


class CVEGroup(db.Model):

    REFERENCES_LENGTH = 4096
    NOTES_LENGTH = 4096

    __versioned__ = {}
    __tablename__ = 'cve_group'

    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    status = db.Column(Status.as_type(), nullable=False, default=Status.unknown, index=True)
    severity = db.Column(Severity.as_type(), nullable=False, default=Severity.unknown)
    affected = db.Column(db.String(32), nullable=False)
    fixed = db.Column(db.String(32))
    bug_ticket = db.Column(db.String(9))
    reference = db.Column(db.String(REFERENCES_LENGTH))
    notes = db.Column(db.String(NOTES_LENGTH))
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    changed = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    __mapper_args__ = {'version_id_col': changed, 'version_id_generator': False}

    advisory_qualified = db.Column(db.Boolean(), default=True, nullable=False)

    issues = db.relationship("CVEGroupEntry", back_populates="group", cascade="all,delete-orphan")
    packages = db.relationship("CVEGroupPackage", back_populates="group", cascade="all,delete-orphan")

    @property
    def name(self):
        return 'AVG-{}'.format(self.id)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<CVEGroup %r>' % (self.id)


def group_advisories(group):
    return (Advisory.query.join(CVEGroupPackage)
            .filter(CVEGroupPackage.group_id == group.id).all())


def refresh_group(group, update_type=True):
    issues = [entry.cve for entry in group.issues]
    group.severity = highest_severity([cve.severity for cve in issues])
    if not update_type:
        return
    issue_type = advisory_type_for(cve.issue_type for cve in issues)
    for advisory in group_advisories(group):
        if advisory.publication == Publication.scheduled:
            advisory.advisory_type = issue_type
