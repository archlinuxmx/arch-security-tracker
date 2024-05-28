from datetime import datetime
from datetime import timedelta
from hashlib import sha256
from secrets import token_urlsafe

from tracker import db


class ApiToken(db.Model):
    NAME_LENGTH = 64
    SCOPE = 'cves:create'
    LIFETIME = timedelta(days=90)

    __tablename__ = 'api_token'
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'),
                        index=True, nullable=False)
    user = db.relationship('User')
    name = db.Column(db.String(NAME_LENGTH), nullable=False)
    token_hash = db.Column(db.String(64), index=True, unique=True, nullable=False)
    scope = db.Column(db.String(32), nullable=False, default=SCOPE)
    created = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime(), nullable=False)

    @staticmethod
    def digest(raw):
        return sha256(raw.encode('utf-8')).hexdigest()

    @classmethod
    def issue(cls, user, name):
        """Return an unsaved token and its secret, which must only be shown once."""
        raw = 'ast_' + token_urlsafe(32)
        created = datetime.utcnow()
        token = cls(user=user, name=name, token_hash=cls.digest(raw), scope=cls.SCOPE,
                    created=created, expires_at=created + cls.LIFETIME)
        return token, raw
