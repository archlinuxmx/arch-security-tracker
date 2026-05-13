from datetime import datetime
from functools import partial

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask import Flask
from flask_migrate import stamp
from flask_migrate import upgrade
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import inspect
from sqlalchemy import text

from tracker import create_app
from tracker.model import CVEGroup
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.enum import UserRole


@pytest.mark.parametrize('relative', [False, True])
def test_production_upgrade_preserves_records_and_history(db, tmp_path, monkeypatch, relative):
    monkeypatch.setattr('tracker.Flask', partial(Flask, instance_path=str(tmp_path / 'instance')))
    monkeypatch.chdir(tmp_path)
    filename = 'production%copy.sqlite' if relative else str(tmp_path / 'production%copy.sqlite')
    migration_app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + filename,
                                'TESTING': True})
    with migration_app.app_context():
        # Reconstruct the schema at a18d5c9.
        baseline = MetaData()
        names = ('user', 'package', 'transaction', 'cve', 'cve_version', 'cve_group', 'cve_group_version',
                 'cve_group_entry', 'cve_group_entry_version', 'cve_group_package',
                 'cve_group_package_version', 'advisory', 'advisory_version')
        for name in names:
            table = db.metadata.tables[name].to_metadata(baseline)
            table.indexes.difference_update({index for index in table.indexes
                                            if index.name in {'ix_' + name + '_pk_transaction_id',
                                                              'ix_' + name + '_pk_validity'}})
            for column in list(table.columns):
                column.nullable = db.metadata.tables[name].c[column.name].nullable
                if column.name.startswith('cvss_'):
                    table._columns.remove(column)
            if 'bug_ticket' in table.c:
                table.c.bug_ticket.type = String(9)
        baseline.tables['cve_group'].dialect_options['sqlite']['autoincrement'] = False
        baseline.create_all(db.engine)
        now = datetime(2024, 1, 15, 12, 30)
        issue = dict(id='CVE-2024-10001', severity=Severity.high, remote=Remote.remote,
                     description='Retain this description.', created=now, changed=now)
        group = dict(id=1, status=Status.vulnerable, severity=Severity.high, affected='1.0-1',
                     bug_ticket='51322', notes='Retain this note.', created=now, changed=now, advisory_qualified=True)
        entries = {'user': [dict(id=7, name='admin', email='admin@example.org', salt='salt', password='hash',
                                 token='session-token', role=UserRole.administrator, active=True, idp_id='sso-id')],
                   'transaction': [dict(id=1, issued_at=now, user_id=7), dict(id=2, issued_at=now, user_id=7)],
                   'cve': [issue], 'cve_group': [group, dict(group, id=2, bug_ticket=''),
                                               dict(group, id=3, bug_ticket=None)],
                   'cve_group_entry': [dict(id=1, group_id=1, cve_id=issue['id'])],
                   'cve_group_package': [dict(id=1, group_id=1, pkgname='foo')],
                   'advisory': [dict(id='ASA-202401-1', group_package_id=1, content='Published text.',
                                     created=now, changed=now)]}
        for name in ('cve', 'cve_group', 'cve_group_entry', 'cve_group_package', 'advisory'):
            entries[name + '_version'] = [dict(row, transaction_id=1, operation_type=0) for row in entries[name]]
        entries['cve_group_version'].extend([
            dict(group, id=701, transaction_id=1, end_transaction_id=2, operation_type=0, bug_ticket_mod=True),
            dict(group, id=701, transaction_id=2, operation_type=2, bug_ticket_mod=False),
        ])
        with db.engine.begin() as connection:
            for table in baseline.sorted_tables:
                for row in entries.get(table.name, []):
                    connection.execute(table.insert(), row)
            before = {name: connection.execute(text('SELECT * FROM "{}"'.format(name))).fetchall() for name in names}
        stamp(revision='d0b4cb352ca1')
        upgrade()
        db.engine.dispose()
        with db.engine.connect() as connection:
            assert connection.execute(text('PRAGMA foreign_keys')).scalar() == 1
            assert connection.execute(text('PRAGMA foreign_key_check')).fetchall() == []
            assert connection.execute(text('PRAGMA integrity_check')).scalar() == 'ok'
            context = MigrationContext.configure(connection, opts={
                'include_object': lambda obj, name, kind, reflected, compare_to: name != 'sqlite_sequence'})
            assert compare_metadata(context, db.metadata) == []
            for name in names:
                columns = ', '.join('"{}"'.format(column.name) for column in baseline.tables[name].columns)
                after = connection.execute(text('SELECT {} FROM "{}"'.format(columns, name))).fetchall()
                assert sorted(after, key=repr) == sorted(before[name], key=repr), name
            assert connection.execute(text('SELECT cvss_score, cvss_score_mod FROM cve_version')).one() == (None, 0)
        assert {'api_token', 'review_event', 'intake_candidate'} <= set(inspect(db.engine).get_table_names())
        for name in ('cve_group', 'cve_group_version'):
            columns = {column['name']: column['type'] for column in inspect(db.engine).get_columns(name)}
            assert columns['bug_ticket'].length == 512
        new_group = CVEGroup(affected='2.0-1')
        db.session.add(new_group)
        db.session.commit()
        assert new_group.id == 702
        db.session.remove()
        db.engine.dispose()
        if relative:
            assert not (tmp_path / filename).exists()
