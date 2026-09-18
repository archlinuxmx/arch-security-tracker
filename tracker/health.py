from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from tracker import db


def register_health_checks(app):
    expected_heads = set(ScriptDirectory(app.config['SQLALCHEMY_MIGRATE_REPO']).get_heads())

    def response(body, status=200):
        return body + '\n', status, {'Cache-Control': 'no-store', 'Content-Type': 'text/plain'}

    @app.get('/healthz')
    def healthz():
        return response('ok')

    @app.get('/readyz')
    def readyz():
        try:
            with db.engine.connect() as connection:
                heads = set(connection.execute(text('SELECT version_num FROM alembic_version')).scalars())
        except SQLAlchemyError:
            return response('database unavailable', 503)
        if heads != expected_heads:
            return response('database upgrade required', 503)
        return response('ok')
