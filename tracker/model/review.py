from datetime import datetime

from tracker import db


class ReviewEvent(db.Model):
    """Append-only, reporter-only assessment and workflow history."""

    __tablename__ = 'review_event'
    id = db.Column(db.Integer(), primary_key=True)
    target = db.Column(db.String(64), nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False)
    revision = db.Column(db.String(64), nullable=False)
    rationale = db.Column(db.String(4096), nullable=False, default='')
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='SET NULL'))
    user = db.relationship('User')
    created = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)


class IntakeCandidate(db.Model):
    """A private, manually reviewed disclosure, independent of public CVEs."""

    __tablename__ = 'intake_candidate'
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    source = db.Column(db.String(2048), nullable=False)
    ingestion_user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='SET NULL'))
    ingestion_key = db.Column(db.String(64))
    ingestion_hash = db.Column(db.String(64))
    cve_name = db.Column(db.String(64), nullable=True)
    evidence = db.Column(db.Text(), nullable=False, default='')
    description = db.Column(db.String(4096), nullable=False, default='')
    reference = db.Column(db.String(4096), nullable=False, default='')
    state = db.Column(db.String(16), nullable=False, default='pending', index=True)
    promoted_cve = db.Column(db.String(64), nullable=True)
    revision = db.Column(db.Integer(), nullable=False, default=1)
    created = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)
    __table_args__ = (db.Index('ix_intake_candidate_ingestion', ingestion_user_id, ingestion_key, unique=True),)
    __mapper_args__ = {'version_id_col': revision}
