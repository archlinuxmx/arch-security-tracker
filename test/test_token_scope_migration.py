import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import downgrade
from flask_migrate import stamp
from flask_migrate import upgrade
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import inspect
from sqlalchemy import text

from tracker import create_app
from tracker.model.apitoken import ApiToken
from tracker.model.enum import UserRole
from tracker.model.user import User


def test_scope_migration_preserves_existing_tokens_and_rejects_lossy_downgrade(db, tmp_path):
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'tokens.sqlite'),
                      'TESTING': True})
    with app.app_context():
        previous = MetaData()
        for table in db.metadata.sorted_tables:
            table.to_metadata(previous)
        previous.tables['api_token'].c.scope.type = String(32)
        previous.create_all(db.engine)
        user = User(name='reporter', email='reporter@example.org', salt='salt', password='unused',
                    role=UserRole.reporter, active=True)
        token, secret = ApiToken.issue(user, 'Existing token', 'cves:create')
        db.session.add_all([user, token])
        db.session.commit()
        with db.engine.connect() as connection:
            before = connection.execute(text('SELECT * FROM api_token')).all()
        stamp(revision='f3170a42ce86')
        upgrade(revision='a73d04b17c62')
        db.session.remove()

        with db.engine.connect() as connection:
            assert connection.execute(text('SELECT * FROM api_token')).all() == before
            assert connection.execute(text('PRAGMA foreign_keys')).scalar() == 1
            assert connection.execute(text('PRAGMA foreign_key_check')).all() == []
            context = MigrationContext.configure(connection, opts={
                'include_object': lambda obj, name, kind, reflected, compare_to: name != 'sqlite_sequence'})
            assert compare_metadata(context, db.metadata) == []
        assert next(column for column in inspect(db.engine).get_columns('api_token')
                    if column['name'] == 'scope')['type'].length == 255
        client = app.test_client()
        headers = {'Authorization': 'Bearer ' + secret}
        assert client.post('/api/v1/cves', json={'name': 'CVE-2026-12345'}, headers=headers).status_code == 201
        assert client.post('/api/v1/groups', json={}, headers=headers).status_code == 403

        combined, _ = ApiToken.issue(User.query.one(), 'Combined token', ['cves:create', 'groups:create'])
        db.session.add(combined)
        db.session.commit()
        with pytest.raises(SystemExit) as error:
            downgrade(revision='f3170a42ce86')
        assert error.value.code == 1
        with db.engine.connect() as connection:
            assert connection.execute(text('SELECT version_num FROM alembic_version')).scalar() == 'a73d04b17c62'
        db.session.delete(combined)
        db.session.commit()
        downgrade(revision='f3170a42ce86')
        with db.engine.connect() as connection:
            assert connection.execute(text('SELECT * FROM api_token')).all() == before
        assert next(column for column in inspect(db.engine).get_columns('api_token')
                    if column['name'] == 'scope')['type'].length == 32
        db.session.remove()
        db.engine.dispose()
