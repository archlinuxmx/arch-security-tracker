from datetime import datetime
from datetime import timedelta
from hashlib import sha256
from secrets import token_urlsafe

from tracker import db


class ApiToken(db.Model):
    NAME_LENGTH = 64
    SCOPE = 'cves:create'
    SCOPES = ('cves:create', 'cves:update', 'groups:create', 'groups:update', 'advisories:write', 'intake:create')
    LIFETIME = timedelta(days=90)

    __tablename__ = 'api_token'
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'),
                        index=True, nullable=False)
    user = db.relationship('User')
    name = db.Column(db.String(NAME_LENGTH), nullable=False)
    token_hash = db.Column(db.String(64), index=True, unique=True, nullable=False)
    scope = db.Column(db.String(255), nullable=False, default=SCOPE)
    created = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime(), nullable=False)

    @staticmethod
    def digest(raw):
        return sha256(raw.encode('utf-8')).hexdigest()

    @property
    def scopes(self):
        return tuple((self.scope or '').split())

    def has_scope(self, scope):
        scopes = self.scopes
        return scope in scopes and all(value in self.SCOPES for value in scopes)

    @classmethod
    def issue(cls, user, name, scope=SCOPE):
        """Return an unsaved token and secret for one scope or a collection."""
        scopes = [scope] if isinstance(scope, str) else scope
        if (not isinstance(scopes, (list, tuple, set, frozenset)) or not scopes
                or any(value not in cls.SCOPES for value in scopes)):
            raise ValueError('Select at least one valid scope.')
        if 'advisories:write' in scopes and not user.role.is_security_team:
            raise ValueError('Scope is not available to this user.')
        scope = ' '.join(value for value in cls.SCOPES if value in scopes)
        raw = 'ast_' + token_urlsafe(32)
        created = datetime.utcnow()
        token = cls(user=user, name=name, token_hash=cls.digest(raw), scope=scope,
                    created=created, expires_at=created + cls.LIFETIME)
        return token, raw
