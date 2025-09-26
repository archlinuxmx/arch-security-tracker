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
