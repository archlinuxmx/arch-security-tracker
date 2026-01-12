"""Preserve retired group identifiers."""
from alembic import op

revision = '8fd13b0e4ac2'
down_revision = '7e913b50c214'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('cve_group', recreate='always',
                             table_kwargs={'sqlite_autoincrement': True}):
        pass
    op.execute("DELETE FROM sqlite_sequence WHERE name = 'cve_group'")
    op.execute("""
        INSERT INTO sqlite_sequence (name, seq)
        SELECT 'cve_group', COALESCE(MAX(id), 0)
        FROM (SELECT id FROM cve_group UNION ALL SELECT id FROM cve_group_version)
    """)


def downgrade():
    with op.batch_alter_table('cve_group', recreate='always',
                             table_kwargs={'sqlite_autoincrement': False}):
        pass
