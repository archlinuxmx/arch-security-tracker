"""Add Continuum version lookup indexes."""
import sqlalchemy as sa
from alembic import op

revision = 'c9a612d7084e'
down_revision = '8fd13b0e4ac2'
branch_labels = None
depends_on = None

tables = ('advisory_version', 'cve_version', 'cve_group_version',
          'cve_group_entry_version', 'cve_group_package_version')


def upgrade():
    for table in tables:
        op.create_index('ix_' + table + '_pk_transaction_id', table,
                        ['id', sa.text('transaction_id DESC')], if_not_exists=True)
        op.create_index('ix_' + table + '_pk_validity', table,
                        ['id', 'transaction_id', 'end_transaction_id'], if_not_exists=True)


def downgrade():
    for table in reversed(tables):
        op.drop_index('ix_' + table + '_pk_validity', table_name=table)
        op.drop_index('ix_' + table + '_pk_transaction_id', table_name=table)
