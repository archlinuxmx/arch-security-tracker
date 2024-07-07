"""add source-attributed CVSS assessments

Revision ID: 2bc8e014a6d9
Revises: 91760ee4797f
"""
import sqlalchemy as sa
from alembic import op

revision = '2bc8e014a6d9'
down_revision = '91760ee4797f'
branch_labels = None
depends_on = None


def upgrade():
    for table in ('cve', 'cve_version'):
        op.add_column(table, sa.Column('cvss_version', sa.String(8)))
        op.add_column(table, sa.Column('cvss_score', sa.Numeric(3, 1)))
        op.add_column(table, sa.Column('cvss_vector', sa.String(256)))
        op.add_column(table, sa.Column('cvss_source', sa.String(2048)))
    for name in ('version', 'score', 'vector', 'source'):
        op.add_column('cve_version', sa.Column('cvss_' + name + '_mod', sa.Boolean(), nullable=False,
                                             server_default=sa.false()))


def downgrade():
    for table in ('cve_version', 'cve'):
        with op.batch_alter_table(table) as batch:
            for name in ('cvss_source', 'cvss_vector', 'cvss_score', 'cvss_version'):
                if table == 'cve_version':
                    batch.drop_column(name + '_mod')
                batch.drop_column(name)
