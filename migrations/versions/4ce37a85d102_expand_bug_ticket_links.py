"""Store GitLab issue URLs."""
import sqlalchemy as sa
from alembic import op

revision = '4ce37a85d102'
down_revision = '2bc8e014a6d9'
branch_labels = None
depends_on = None


def resize(previous, length):
    for table in ('cve_group', 'cve_group_version'):
        with op.batch_alter_table(table) as batch:
            batch.alter_column('bug_ticket', existing_type=sa.String(previous), type_=sa.String(length))


def upgrade():
    resize(9, 512)


def downgrade():
    for table in ('cve_group', 'cve_group_version'):
        if op.get_bind().scalar(sa.text('SELECT count(*) FROM ' + table + ' WHERE length(bug_ticket) > 9')):
            raise ValueError('GitLab issue URLs must be removed before downgrading.')
    resize(512, 9)
